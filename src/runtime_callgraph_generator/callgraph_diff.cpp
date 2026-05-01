#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <functional>
#include <filesystem>
#include <optional>
#include <queue>
#include <set>
#include <sstream>
#include <stack>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

namespace
{
    struct Edge
    {
        std::string caller;
        std::string callee;

        bool operator<(const Edge &other) const
        {
            if (caller != other.caller)
            {
                return caller < other.caller;
            }
            return callee < other.callee;
        }
    };

    using CallGraph = std::unordered_map<std::string, std::unordered_set<std::string>>;

    struct TreeNode
    {
        std::string name;
        int level = 0;
        // `parentUid` stores the parent's node-unique id (not the function name).
        std::string parentUid;
        bool edgeTaken = false;
        // number of times the incoming edge (parent->this) was observed in runtime traces
        std::size_t hitCount = 0;
        std::size_t coveredChildren = 0;
        std::size_t uncoveredChildren = 0;
        bool hasChildren = false;
        // node-unique id used for HTML `data-uid` attributes
        std::string uid;
    };

    using TreeNodes = std::vector<TreeNode>;

    struct RuntimeContextData
    {
        std::string contextId;
        std::string entrypoint;
        std::size_t ordinal = 0U;
        std::size_t startEventIndex = 0U;
        std::size_t endEventIndex = 0U;
        std::unordered_map<std::string, std::size_t> edgeCounts;
    };

    struct RootStats
    {
        std::string name;
        std::size_t nodeCount = 0;
        std::size_t covered = 0;
        std::size_t uncovered = 0;
        double pct = 0.0;
        std::size_t runCount = 0;
        CallGraph subgraph;
        std::set<std::string> nodes;
        TreeNodes treeNodes;
    };

    struct AggregatedContextData
    {
        std::string entrypoint;
        std::vector<std::string> contextIds;
        std::size_t ordinal = 0U;
        std::size_t startEventIndex = 0U;
        std::size_t endEventIndex = 0U;
        std::unordered_map<std::string, std::size_t> edgeCounts;
    };

    llvm::cl::OptionCategory kCategory("callgraph-diff options");

    llvm::cl::opt<std::string> kStaticCallgraph(
        "static",
        llvm::cl::desc("Path to static callgraph JSON file"),
        llvm::cl::value_desc("path"),
        llvm::cl::init("out/callgraph.json"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kRuntimeCallgraph(
        "runtime",
        llvm::cl::desc("Path to runtime callgraph JSON file"),
        llvm::cl::value_desc("path"),
        llvm::cl::init("out/runtime-callgraph.json"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kEntryPoints(
        "entrypoints",
        llvm::cl::desc("Path to entrypoints file"),
        llvm::cl::value_desc("path"),
        llvm::cl::init("input/entrypoints.txt"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kOutput(
        "o",
        llvm::cl::desc("Path to output JSON file"),
        llvm::cl::value_desc("path"),
        llvm::cl::init("out/callgraph-diff.json"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kHtmlOutput(
        "html",
        llvm::cl::desc("Path to output HTML file"),
        llvm::cl::value_desc("path"),
        llvm::cl::init("out/callgraph-diff.html"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kTemplateDir(
        "template-dir",
        llvm::cl::desc("Directory containing callgraph diff templates"),
        llvm::cl::value_desc("path"),
        llvm::cl::init("src/runtime_callgraph_generator/templates/callgraph_diff"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<bool> kNoHtml(
        "no-html",
        llvm::cl::desc("Do not output HTML"),
        llvm::cl::init(false),
        llvm::cl::cat(kCategory));

    std::string joinPath(std::string_view lhs, std::string_view rhs)
    {
        if (lhs.empty())
        {
            return std::string(rhs);
        }
        std::filesystem::path p{std::string(lhs)};
        p /= std::string(rhs);
        return p.generic_string();
    }

    bool readTextFile(std::string_view path, std::string &content, std::string &error)
    {
        const std::filesystem::path filePath{std::string(path)};
        std::ifstream input(filePath, std::ios::binary);
        if (!input)
        {
            error = "failed to open file: " + filePath.string();
            return false;
        }

        std::error_code ec;
        const auto size = std::filesystem::file_size(filePath, ec);
        if (!ec)
        {
            content.resize(static_cast<std::size_t>(size));
            input.read(content.data(), static_cast<std::streamsize>(content.size()));
            if (input.gcount() == static_cast<std::streamsize>(content.size()))
            {
                return true;
            }
            error = "failed to read file fully: " + filePath.string();
            return false;
        }

        error = "failed to determine file size: " + filePath.string();
        return false;
    }

    bool writeTextFile(std::string_view path, const std::string &content, std::string &error)
    {
        const std::string filePath(path);
        std::ofstream output(filePath, std::ios::binary);
        if (!output)
        {
            error = "failed to open output file: " + filePath;
            return false;
        }
        output << content;
        if (!output)
        {
            error = "failed to write output file: " + filePath;
            return false;
        }
        return true;
    }

    std::string replaceAll(std::string text, std::string_view needle, std::string_view replacement)
    {
        if (needle.empty())
        {
            return text;
        }

        std::size_t pos = 0;
        while ((pos = text.find(needle, pos)) != std::string::npos)
        {
            text.replace(pos, needle.size(), replacement.data(), replacement.size());
            pos += replacement.size();
        }
        return text;
    }

    std::string escapeHtml(std::string_view text)
    {
        std::string escaped;
        escaped.reserve(text.size() + 16U);
        for (const char ch : text)
        {
            switch (ch)
            {
            case '&':
                escaped += "&amp;";
                break;
            case '<':
                escaped += "&lt;";
                break;
            case '>':
                escaped += "&gt;";
                break;
            case '"':
                escaped += "&quot;";
                break;
            case '\'':
                escaped += "&#39;";
                break;
            default:
                escaped.push_back(ch);
                break;
            }
        }
        return escaped;
    }

    bool loadTemplateBundle(std::string &htmlTemplate, std::string &cssTemplate, std::string &jsTemplate, std::string &error)
    {
        const std::string templateDir = kTemplateDir;
        if (!readTextFile(joinPath(templateDir, "report.html"), htmlTemplate, error))
        {
            error = "failed to load HTML template: " + error;
            return false;
        }
        if (!readTextFile(joinPath(templateDir, "report.css"), cssTemplate, error))
        {
            error = "failed to load CSS template: " + error;
            return false;
        }
        if (!readTextFile(joinPath(templateDir, "report.js"), jsTemplate, error))
        {
            error = "failed to load JS template: " + error;
            return false;
        }
        return true;
    }

    bool extractStaticEdges(const std::string &jsonPath, std::set<Edge> &edges, std::unordered_set<std::string> &nodes, std::string &error)
    {
        std::string content;
        if (!readTextFile(jsonPath, content, error))
        {
            error = "failed to open static callgraph file: " + jsonPath;
            return false;
        }

        llvm::Expected<llvm::json::Value> json = llvm::json::parse(content);
        if (!json)
        {
            error = "failed to parse static callgraph JSON: " + llvm::toString(json.takeError());
            return false;
        }

        const llvm::json::Object *root = json->getAsObject();
        if (!root)
        {
            error = "static callgraph JSON root is not an object";
            return false;
        }

        const llvm::json::Object *collapsed = root->getObject("collapsedCallGraph");
        const llvm::json::Array *edgeArray = nullptr;
        if (collapsed)
        {
            edgeArray = collapsed->getArray("edges");
        }
        if (!edgeArray)
        {
            edgeArray = root->getArray("edges");
        }
        if (!edgeArray)
        {
            error = "missing edges in static callgraph JSON";
            return false;
        }

        nodes.reserve(nodes.size() + edgeArray->size() * 2U);

        for (const llvm::json::Value &edgeValue : *edgeArray)
        {
            const llvm::json::Object *edgeObject = edgeValue.getAsObject();
            if (!edgeObject)
            {
                continue;
            }

            const std::optional<llvm::StringRef> callerOpt = edgeObject->getString("caller");
            const std::optional<llvm::StringRef> calleeOpt = edgeObject->getString("callee");
            if (!callerOpt || !calleeOpt)
            {
                continue;
            }

            Edge edge{callerOpt->str(), calleeOpt->str()};
            edges.insert(edge);
            nodes.insert(edge.caller);
            nodes.insert(edge.callee);
        }

        return true;
    }

    bool extractRuntimeEdges(const std::string &jsonPath, std::set<Edge> &edges, std::unordered_set<std::string> &nodes, std::vector<RuntimeContextData> &runtimeContexts, std::string &error)
    {
        std::string content;
        if (!readTextFile(jsonPath, content, error))
        {
            error = "failed to open runtime callgraph file: " + jsonPath;
            return false;
        }

        llvm::Expected<llvm::json::Value> json = llvm::json::parse(content);
        if (!json)
        {
            error = "failed to parse runtime callgraph JSON: " + llvm::toString(json.takeError());
            return false;
        }

        const llvm::json::Object *root = json->getAsObject();
        if (!root)
        {
            error = "runtime callgraph JSON root is not an object";
            return false;
        }

        const llvm::json::Object *contextProcessing = root->getObject("contextProcessing");
        if (!contextProcessing)
        {
            return true;
        }

        const llvm::json::Array *contexts = contextProcessing->getArray("contexts");
        if (!contexts)
        {
            return true;
        }

        std::size_t totalCalls = 0U;
        for (const llvm::json::Value &contextValue : *contexts)
        {
            const llvm::json::Object *contextObject = contextValue.getAsObject();
            if (!contextObject)
            {
                continue;
            }

            const llvm::json::Array *calls = contextObject->getArray("calls");
            if (calls)
            {
                totalCalls += calls->size();
            }
        }

        nodes.reserve(nodes.size() + totalCalls * 2U);
        runtimeContexts.reserve(contexts->size());

        for (const llvm::json::Value &contextValue : *contexts)
        {
            const llvm::json::Object *contextObject = contextValue.getAsObject();
            if (!contextObject)
            {
                continue;
            }

            const llvm::json::Array *calls = contextObject->getArray("calls");
            if (!calls)
            {
                continue;
            }

            RuntimeContextData runtimeContext;

            const std::optional<llvm::StringRef> contextIdOpt = contextObject->getString("contextId");
            if (contextIdOpt)
            {
                runtimeContext.contextId = contextIdOpt->str();
            }

            const std::optional<llvm::StringRef> entrypointOpt = contextObject->getString("entrypoint");
            if (entrypointOpt)
            {
                runtimeContext.entrypoint = entrypointOpt->str();
            }

            if (const std::optional<std::int64_t> ordinalValue = contextObject->getInteger("ordinal"))
            {
                runtimeContext.ordinal = static_cast<std::size_t>(*ordinalValue);
            }

            if (const std::optional<std::int64_t> startValue = contextObject->getInteger("startEventIndex"))
            {
                runtimeContext.startEventIndex = static_cast<std::size_t>(*startValue);
            }

            if (const std::optional<std::int64_t> endValue = contextObject->getInteger("endEventIndex"))
            {
                runtimeContext.endEventIndex = static_cast<std::size_t>(*endValue);
            }

            runtimeContext.edgeCounts.reserve(calls->size());

            for (const llvm::json::Value &callValue : *calls)
            {
                const llvm::json::Object *callObject = callValue.getAsObject();
                if (!callObject)
                {
                    continue;
                }

                const std::optional<llvm::StringRef> callerOpt = callObject->getString("caller");
                const std::optional<llvm::StringRef> calleeOpt = callObject->getString("callee");
                if (!callerOpt || !calleeOpt)
                {
                    continue;
                }

                std::size_t callerDepth = 0U;
                if (const std::optional<std::int64_t> callerDepthValue = callObject->getInteger("callerDepth"))
                {
                    callerDepth = static_cast<std::size_t>(*callerDepthValue);
                }

                const std::string caller = callerOpt->str();
                const std::string callee = calleeOpt->str();
                Edge edge{caller, callee};
                edges.insert(edge);
                nodes.insert(edge.caller);
                nodes.insert(edge.callee);

                if (runtimeContext.entrypoint.empty())
                {
                    runtimeContext.entrypoint = caller;
                }
                const std::string key = caller + "|" + callee;
                ++runtimeContext.edgeCounts[key];
            }

            runtimeContexts.push_back(std::move(runtimeContext));
        }

        return true;
    }

    bool loadEntryPoints(const std::string &path, std::set<std::string> &roots, std::string &error)
    {
        std::ifstream input(path);
        if (!input)
        {
            error = "failed to open entrypoints file: " + path;
            return false;
        }

        std::string line;
        while (std::getline(input, line))
        {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ' || line.back() == '\t'))
            {
                line.pop_back();
            }

            if (!line.empty())
            {
                roots.insert(line);
            }
        }

        return true;
    }

    void removeBackEdges(const std::set<Edge> &staticEdges, CallGraph &acyclicGraph, std::set<Edge> &acyclicEdges)
    {
        CallGraph adjacency;
        for (const Edge &edge : staticEdges)
        {
            adjacency[edge.caller].insert(edge.callee);
            adjacency[edge.callee];
        }

        enum class Color
        {
            White,
            Gray,
            Black
        };

        std::unordered_map<std::string, Color> color;
        std::unordered_set<std::string> active;

        std::function<void(const std::string &)> dfs = [&](const std::string &node)
        {
            color[node] = Color::Gray;
            active.insert(node);

            const auto it = adjacency.find(node);
            if (it != adjacency.end())
            {
                for (const std::string &child : it->second)
                {
                    if (active.count(child) != 0U)
                    {
                        continue;
                    }

                    if (color[child] == Color::White)
                    {
                        dfs(child);
                    }

                    acyclicGraph[node].insert(child);
                    acyclicEdges.insert({node, child});
                }
            }

            active.erase(node);
            color[node] = Color::Black;
        };

        for (const auto &entry : adjacency)
        {
            if (color[entry.first] == Color::White)
            {
                dfs(entry.first);
            }
        }
    }

    void buildSubgraphFromRoot(const std::string &root, const CallGraph &acyclicGraph, CallGraph &subgraph, std::set<std::string> &nodes)
    {
        std::unordered_set<std::string> visited;
        std::queue<std::string> worklist;
        worklist.push(root);

        while (!worklist.empty())
        {
            const std::string current = worklist.front();
            worklist.pop();

            if (!visited.insert(current).second)
            {
                continue;
            }

            nodes.insert(current);

            const auto it = acyclicGraph.find(current);
            if (it == acyclicGraph.end())
            {
                continue;
            }

            std::vector<std::string> children;
            children.reserve(it->second.size());
            children.insert(children.end(), it->second.begin(), it->second.end());
            std::sort(children.begin(), children.end());
            for (const std::string &child : children)
            {
                subgraph[current].insert(child);
                if (visited.count(child) == 0U)
                {
                    worklist.push(child);
                }
            }
        }
    }

    void buildTreeNodesForRoot(const std::string &root, const CallGraph &subgraph, const std::unordered_map<std::string, std::size_t> &runtimeEdgeCounts, TreeNodes &treeNodes)
    {
        struct StackEntry
        {
            std::string name;
            std::string parentUid;
            int level = 0;
            bool edgeTaken = false;
            std::size_t hitCount = 0U;
        };

        std::unordered_set<std::string> visited;
        std::stack<StackEntry> work;
        work.push({root, std::string{}, 0, true, 0U});

        std::size_t nextUid = 0U;

        while (!work.empty())
        {
            const StackEntry current = work.top();
            work.pop();

            if (!visited.insert(current.name).second)
            {
                continue;
            }

            TreeNode node;
            node.name = current.name;
            node.level = current.level;
            node.parentUid = current.parentUid;
            node.edgeTaken = current.edgeTaken;
            node.hitCount = current.hitCount;
            node.uid = std::to_string(nextUid++);

            const auto it = subgraph.find(current.name);
            if (it != subgraph.end())
            {
                std::vector<std::string> children;
                children.reserve(it->second.size());
                children.insert(children.end(), it->second.begin(), it->second.end());
                std::sort(children.begin(), children.end());

                node.hasChildren = !children.empty();
                for (const std::string &child : children)
                {
                    const std::string key = current.name + "|" + child;
                    const auto itc = runtimeEdgeCounts.find(key);
                    const std::size_t hits = (itc != runtimeEdgeCounts.end()) ? itc->second : 0U;
                    if (hits != 0U)
                    {
                        ++node.coveredChildren;
                    }
                    else
                    {
                        ++node.uncoveredChildren;
                    }
                }

                treeNodes.push_back(std::move(node));

                const std::string parentUid = treeNodes.back().uid;
                for (auto childIt = children.rbegin(); childIt != children.rend(); ++childIt)
                {
                    const std::string &child = *childIt;
                    const std::string key = current.name + "|" + child;
                    const auto itc = runtimeEdgeCounts.find(key);
                    const std::size_t hits = (itc != runtimeEdgeCounts.end()) ? itc->second : 0U;
                    work.push({child, parentUid, current.level + 1, hits != 0U, hits});
                }
                continue;
            }

            treeNodes.push_back(std::move(node));
        }
    }

    std::string buildSidebarHtml(const std::vector<std::string> &rootNames, const std::vector<double> &coveragePercents)
    {
        std::ostringstream html;
        html << "<div class=\"sidebar\">\n";
        html << "  <div class=\"sidebar-title\">Entry Points (" << rootNames.size() << ")</div>\n";
        html << "  <div class=\"sidebar-search\">\n";
        html << "    <input type=\"text\" id=\"sidebar-search\" placeholder=\"Filter entry points...\" oninput=\"filterSidebar(this.value)\">\n";
        html << "  </div>\n";
        html << "  <div class=\"entry-list\" id=\"entry-list\">\n";

        for (std::size_t index = 0; index < rootNames.size(); ++index)
        {
            const double pct = coveragePercents[index];
            const std::string pctClass = pct >= 75.0 ? "pct-high" : (pct >= 40.0 ? "pct-medium" : "pct-low");
            const std::string barColor = pct >= 75.0 ? "var(--green)" : (pct >= 40.0 ? "var(--yellow)" : "var(--red)");

            html << "    <div class=\"entry-card\" data-idx=\"" << index << "\">\n";
            html << "      <button type=\"button\" class=\"entry-item" << (index == 0U ? " active" : "")
                 << "\" data-idx=\"" << index << "\" onclick=\"selectRoot(" << index << ")\">\n";
            html << "        <span class=\"entry-name\" title=\"" << escapeHtml(rootNames[index]) << "\">" << escapeHtml(rootNames[index]) << "</span>\n";
            html << "        <span class=\"entry-pct " << pctClass << "\">" << static_cast<int>(pct) << "%</span>\n";
            html << "      </button>\n";
            html << "      <div class=\"entry-bar\">\n";
            html << "        <div class=\"entry-bar-fill\" style=\"width: " << pct << "%; background: " << barColor << "\"></div>\n";
            html << "      </div>\n";
            html << "    </div>\n";
        }

        html << "  </div>\n";
        html << "</div>\n";
        return html.str();
    }

    std::string buildTreeRowsHtml(const TreeNodes &treeNodes, std::size_t tabIndex)
    {
        std::ostringstream html;
        for (std::size_t index = 0; index < treeNodes.size(); ++index)
        {
            const TreeNode &node = treeNodes[index];
            const std::string uid = "t" + std::to_string(tabIndex) + "n" + node.uid;
            const std::string parentUid = node.parentUid.empty() ? std::string{} : std::string("t") + std::to_string(tabIndex) + "n" + node.parentUid;
            const bool hasChildren = node.hasChildren;
            const std::string edgeStatus = (node.level == 0 || node.edgeTaken) ? "covered" : "uncovered";

            std::string badgeClass;
            std::string badgeText;
            if (node.level == 0)
            {
                badgeClass = "badge-root";
                badgeText = "&diams; entry";
            }
            else if (node.coveredChildren + node.uncoveredChildren == 0U)
            {
                badgeClass = node.edgeTaken ? "badge-covered" : "badge-uncovered";
                badgeText = node.edgeTaken ? "&check; leaf" : "&times; leaf";
            }
            else
            {
                badgeClass = node.edgeTaken ? "badge-covered" : "badge-uncovered";
                badgeText = node.edgeTaken ? "&check; taken" : "&times; not taken";
            }

            html << "        <tr class=\"tree-node" << (node.level != 0 ? " tree-hidden" : "") << "\"";
            html << " data-uid=\"" << uid << "\"";
            html << " data-parent-uid=\"" << parentUid << "\"";
            html << " data-edge-status=\"" << edgeStatus << "\"";
            html << " data-name=\"" << escapeHtml(node.name) << "\">\n";
            html << "          <td>\n";
            html << "            <div class=\"node-cell\">\n";
            for (int level = 0; level < node.level; ++level)
            {
                html << "              <span class=\"ident-block\"></span>\n";
            }

            if (hasChildren)
            {
                html << "              <span class=\"tree-toggle\" data-toggle-uid=\"" << uid << "\" data-expanded=\"true\">&#9660;</span>\n";
            }
            else
            {
                html << "              <span class=\"tree-toggle no-children\">&#9675;</span>\n";
            }

            // show node name and, if present, the hit count for the incoming edge
            html << "              <span class=\"node-name" << (node.level == 0 ? " is-root" : "") << "\">" << escapeHtml(node.name) << "</span>\n";
            if (node.hitCount > 0U)
            {
                html << "              <span class=\"edge-hits\">(" << node.hitCount << ")</span>\n";
            }
            html << "            </div>\n";
            html << "          </td>\n";
            html << "          <td class=\"status-cell\">\n";
            html << "            <span class=\"badge " << badgeClass << "\">" << badgeText << "</span>\n";
            html << "          </td>\n";
            html << "        </tr>\n";
        }

        return html.str();
    }

    std::string buildMainHtml(const std::vector<RootStats> &rootStats)
    {
        std::ostringstream html;
        html << "<div class=\"main\">\n";
        for (std::size_t index = 0; index < rootStats.size(); ++index)
        {
            const RootStats &stats = rootStats[index];
            html << "  <div id=\"panel-" << index << "\" class=\"panel\" style=\"display:" << (index == 0U ? "flex" : "none") << "\">\n";
            html << "    <div class=\"panel-header\">\n";
            html << "      <div class=\"panel-title\">" << escapeHtml(stats.name) << "</div>\n";
            html << "      <div class=\"stats-row\">\n";
            html << "        <div class=\"stat-pill\"><span class=\"dot dot-total\"></span>" << stats.nodeCount << " nodes</div>\n";
            html << "        <div class=\"stat-pill\"><span class=\"dot dot-covered\"></span>" << stats.covered << " covered</div>\n";
            html << "        <div class=\"stat-pill\"><span class=\"dot dot-uncovered\"></span>" << stats.uncovered << " uncovered</div>\n";
            html << "      </div>\n";
            html << "    </div>\n";
            html << "    <div class=\"toolbar\">\n";
            html << "      <input type=\"text\" placeholder=\"Search functions...\" oninput=\"filterTree(this.value, " << index << ")\">\n";
            html << "      <button type=\"button\" class=\"toolbar-btn\" onclick=\"expandAll(" << index << ")\">Expand All</button>\n";
            html << "      <button type=\"button\" class=\"toolbar-btn\" onclick=\"collapseAll(" << index << ")\">Collapse All</button>\n";
            html << "      <div class=\"filter-group\">\n";
            html << "        <button type=\"button\" class=\"filter-btn active-all\" data-filter=\"all\" data-tab=\"" << index << "\" onclick=\"setFilter('all', " << index << ")\">All</button>\n";
            html << "        <button type=\"button\" class=\"filter-btn\" data-filter=\"covered\" data-tab=\"" << index << "\" onclick=\"setFilter('covered', " << index << ")\">Covered</button>\n";
            html << "        <button type=\"button\" class=\"filter-btn\" data-filter=\"uncovered\" data-tab=\"" << index << "\" onclick=\"setFilter('uncovered', " << index << ")\">Uncovered</button>\n";
            html << "      </div>\n";
            html << "    </div>\n";
            html << "    <div class=\"tree-wrap\">\n";
            html << "      <table>\n";
            html << "        <thead>\n";
            html << "          <tr>\n";
            html << "            <th>Function</th>\n";
            html << "            <th style=\"width:160px\">Status</th>\n";
            html << "          </tr>\n";
            html << "        </thead>\n";
            html << "        <tbody id=\"tbody-" << index << "\">\n";
            html << buildTreeRowsHtml(stats.treeNodes, index);
            html << "        </tbody>\n";
            html << "      </table>\n";
            html << "    </div>\n";
            html << "  </div>\n";
        }
        html << "</div>\n";
        return html.str();
    }

    bool writeHtmlFile(const std::string &path, const std::vector<RootStats> &rootStats, const std::set<Edge> &staticEdges, const std::set<Edge> &runtimeEdges, std::string &error)
    {
        if (path.empty())
        {
            return true;
        }

        std::string htmlTemplate;
        std::string cssTemplate;
        std::string jsTemplate;
        if (!loadTemplateBundle(htmlTemplate, cssTemplate, jsTemplate, error))
        {
            return false;
        }

        std::vector<std::string> rootNames;
        std::vector<double> coveragePercents;
        rootNames.reserve(rootStats.size());
        coveragePercents.reserve(rootStats.size());
        for (const RootStats &stats : rootStats)
        {
            rootNames.push_back(stats.name);
            coveragePercents.push_back(stats.pct);
        }

        std::size_t globalCovered = 0U;
        std::size_t globalUncovered = 0U;
        for (const RootStats &stats : rootStats)
        {
            globalCovered += stats.covered;
            globalUncovered += stats.uncovered;
        }
        const double globalPct = (globalCovered + globalUncovered) > 0U ? (100.0 * static_cast<double>(globalCovered)) / static_cast<double>(globalCovered + globalUncovered) : 0.0;

        std::string headerHtml;
        headerHtml.reserve(160U);
        headerHtml += "<div class=\"header\">\n";
        headerHtml += "  <div class=\"header-logo\">Callgraph Coverage Analysis</div>\n";
        headerHtml += "  <div class=\"header-right\">Static: ";
        headerHtml += std::to_string(staticEdges.size());
        headerHtml += " edges &nbsp;|&nbsp; Runtime: ";
        headerHtml += std::to_string(runtimeEdges.size());
        headerHtml += " edges &nbsp;|&nbsp; Coverage: ";
        headerHtml += std::to_string(globalPct);
        headerHtml += "%</div>\n";
        headerHtml += "</div>\n";

        std::string globalBarHtml;
        globalBarHtml.reserve(96U);
        globalBarHtml += "<div class=\"global-bar\">\n";
        globalBarHtml += "  <div class=\"global-bar-fill\" style=\"width: ";
        globalBarHtml += std::to_string(globalPct);
        globalBarHtml += "%\"></div>\n";
        globalBarHtml += "</div>\n";

        const std::string sidebarHtml = buildSidebarHtml(rootNames, coveragePercents);
        const std::string mainHtml = buildMainHtml(rootStats);

        std::string body;
        body.reserve(headerHtml.size() + globalBarHtml.size() + sidebarHtml.size() + mainHtml.size() + 64U);
        body += headerHtml;
        body += globalBarHtml;
        body += "<div class=\"layout\">\n";
        body += sidebarHtml;
        body += mainHtml;
        body += "</div>\n";

        std::string html = htmlTemplate;
        html = replaceAll(html, "{{TITLE}}", "Callgraph Coverage Analysis");
        html = replaceAll(html, "{{STYLE}}", cssTemplate);
        html = replaceAll(html, "{{BODY}}", body);
        html = replaceAll(html, "{{SCRIPT}}", jsTemplate);

        return writeTextFile(path, html, error);
    }

    bool writeJsonFile(const std::string &path, const std::set<Edge> &staticEdges, const std::set<Edge> &runtimeEdges, const std::set<Edge> &uncoveredEdges, std::size_t totalStaticNodes, std::size_t totalRuntimeNodes, std::string &error)
    {
        std::error_code ec;
        llvm::raw_fd_ostream output(path, ec);
        if (ec)
        {
            error = "failed to open JSON output: " + ec.message();
            return false;
        }

        llvm::json::Object root;
        root["kind"] = "uncovered-callgraph";

        llvm::json::Object summary;
        summary["staticEdgesTotal"] = static_cast<std::int64_t>(staticEdges.size());
        summary["runtimeEdgesTotal"] = static_cast<std::int64_t>(runtimeEdges.size());
        summary["uncoveredEdgesTotal"] = static_cast<std::int64_t>(uncoveredEdges.size());
        summary["staticNodesTotal"] = static_cast<std::int64_t>(totalStaticNodes);
        summary["runtimeNodesTotal"] = static_cast<std::int64_t>(totalRuntimeNodes);
        summary["coveragePercent"] = staticEdges.empty() ? 0.0 : (100.0 * static_cast<double>(staticEdges.size() - uncoveredEdges.size())) / static_cast<double>(staticEdges.size());
        root["summary"] = std::move(summary);

        llvm::json::Array uncoveredArray;
        std::unordered_set<std::string> uncoveredCallers;
        std::unordered_set<std::string> uncoveredCallees;
        for (const Edge &edge : uncoveredEdges)
        {
            llvm::json::Object edgeObject;
            edgeObject["caller"] = edge.caller;
            edgeObject["callee"] = edge.callee;
            uncoveredArray.push_back(std::move(edgeObject));
            uncoveredCallers.insert(edge.caller);
            uncoveredCallees.insert(edge.callee);
        }
        root["uncoveredEdges"] = std::move(uncoveredArray);

        llvm::json::Array uncoveredCallersArray;
        for (const std::string &caller : uncoveredCallers)
        {
            uncoveredCallersArray.push_back(caller);
        }
        root["uncoveredCallers"] = std::move(uncoveredCallersArray);

        llvm::json::Array uncoveredCalleesArray;
        for (const std::string &callee : uncoveredCallees)
        {
            uncoveredCalleesArray.push_back(callee);
        }
        root["uncoveredCallees"] = std::move(uncoveredCalleesArray);

        llvm::json::Value jsonValue(std::move(root));
        output << llvm::formatv("{0:2}", jsonValue);
        output << "\n";
        output.flush();
        return true;
    }
}

int main(int argc, const char **argv)
{
    llvm::cl::HideUnrelatedOptions(kCategory);
    llvm::cl::ParseCommandLineOptions(argc, argv, "callgraph-diff\n");

    std::set<Edge> staticEdges;
    std::unordered_set<std::string> staticNodes;
    std::string error;

    llvm::errs() << "[callgraph-diff] Loading static callgraph: " << kStaticCallgraph << "\n";
    if (!extractStaticEdges(kStaticCallgraph, staticEdges, staticNodes, error))
    {
        llvm::errs() << "[callgraph-diff] " << error << "\n";
        return 1;
    }

    std::set<Edge> runtimeEdges;
    std::unordered_set<std::string> runtimeNodes;
    std::vector<RuntimeContextData> runtimeContexts;
    llvm::errs() << "[callgraph-diff] Loading runtime callgraph: " << kRuntimeCallgraph << "\n";
    if (!extractRuntimeEdges(kRuntimeCallgraph, runtimeEdges, runtimeNodes, runtimeContexts, error))
    {
        llvm::errs() << "[callgraph-diff] " << error << "\n";
        return 1;
    }

    std::set<Edge> uncoveredEdges;
    std::set_difference(staticEdges.begin(), staticEdges.end(), runtimeEdges.begin(), runtimeEdges.end(), std::inserter(uncoveredEdges, uncoveredEdges.begin()));

    llvm::errs() << "[callgraph-diff] Static edges: " << staticEdges.size() << "\n";
    llvm::errs() << "[callgraph-diff] Runtime edges: " << runtimeEdges.size() << "\n";
    llvm::errs() << "[callgraph-diff] Uncovered edges: " << uncoveredEdges.size() << "\n";

    const double coverage = staticEdges.empty() ? 0.0 : 100.0 * static_cast<double>(staticEdges.size() - uncoveredEdges.size()) / static_cast<double>(staticEdges.size());
    llvm::errs() << "[callgraph-diff] Coverage: " << coverage << "%\n";

    if (!writeJsonFile(kOutput, staticEdges, runtimeEdges, uncoveredEdges, staticNodes.size(), runtimeNodes.size(), error))
    {
        llvm::errs() << "[callgraph-diff] " << error << "\n";
        return 1;
    }

    if (kNoHtml)
    {
        return 0;
    }

    std::set<std::string> roots;
    if (!loadEntryPoints(kEntryPoints, roots, error))
    {
        llvm::errs() << "[callgraph-diff] " << error << "\n";
        return 1;
    }

    CallGraph acyclicGraph;
    std::set<Edge> acyclicEdges;
    removeBackEdges(staticEdges, acyclicGraph, acyclicEdges);

    std::unordered_map<std::string, AggregatedContextData> aggregatedContexts;
    aggregatedContexts.reserve(runtimeContexts.size());
    for (const RuntimeContextData &runtimeContext : runtimeContexts)
    {
        if (runtimeContext.entrypoint.empty())
        {
            continue;
        }

        AggregatedContextData &aggregated = aggregatedContexts[runtimeContext.entrypoint];
        if (aggregated.entrypoint.empty())
        {
            aggregated.entrypoint = runtimeContext.entrypoint;
            aggregated.startEventIndex = runtimeContext.startEventIndex;
            aggregated.endEventIndex = runtimeContext.endEventIndex;
        }
        else
        {
            aggregated.startEventIndex = std::min(aggregated.startEventIndex, runtimeContext.startEventIndex);
            aggregated.endEventIndex = std::max(aggregated.endEventIndex, runtimeContext.endEventIndex);
        }

        if (!runtimeContext.contextId.empty())
        {
            aggregated.contextIds.push_back(runtimeContext.contextId);
        }
        ++aggregated.ordinal;

        for (const auto &edgeCount : runtimeContext.edgeCounts)
        {
            aggregated.edgeCounts[edgeCount.first] += edgeCount.second;
        }
    }

    std::vector<RootStats> rootStats;
    rootStats.reserve(aggregatedContexts.size());
    for (auto &entry : aggregatedContexts)
    {
        AggregatedContextData &runtimeContext = entry.second;

        if (!runtimeContext.entrypoint.empty() && roots.find(runtimeContext.entrypoint) == roots.end())
        {
            continue;
        }

        RootStats stats;
        stats.name = runtimeContext.entrypoint;
        if (runtimeContext.ordinal > 1U)
        {
            stats.name += " (" + std::to_string(runtimeContext.ordinal) + " runs)";
        }
        stats.runCount = runtimeContext.ordinal;

        buildSubgraphFromRoot(runtimeContext.entrypoint, acyclicGraph, stats.subgraph, stats.nodes);
        buildTreeNodesForRoot(runtimeContext.entrypoint, stats.subgraph, runtimeContext.edgeCounts, stats.treeNodes);
        for (const TreeNode &node : stats.treeNodes)
        {
            stats.covered += node.coveredChildren;
            stats.uncovered += node.uncoveredChildren;
        }
        stats.nodeCount = stats.treeNodes.size();
        stats.pct = (stats.covered + stats.uncovered) > 0U ? (100.0 * static_cast<double>(stats.covered)) / static_cast<double>(stats.covered + stats.uncovered) : 0.0;
        rootStats.push_back(std::move(stats));
    }

    if (!writeHtmlFile(kHtmlOutput, rootStats, staticEdges, runtimeEdges, error))
    {
        llvm::errs() << "[callgraph-diff] " << error << "\n";
        return 1;
    }

    return 0;
}
