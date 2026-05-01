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

    struct RuntimeCallData
    {
        std::size_t eventIndex = 0U;
        std::string caller;
        std::optional<std::size_t> callerDepth;
        std::string callee;
    };

    struct RuntimeContextData
    {
        std::string contextId;
        std::string entrypoint;
        std::size_t ordinal = 0U;
        std::size_t startEventIndex = 0U;
        std::size_t endEventIndex = 0U;
        std::unordered_map<std::string, std::size_t> edgeCounts;
        std::vector<RuntimeCallData> calls;
    };

    struct RuntimeOccurrenceNode
    {
        std::string name;
        std::size_t hitCount = 0U;
        std::vector<std::size_t> children;
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
            runtimeContext.calls.reserve(calls->size());

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

                std::optional<std::size_t> callerDepth;
                if (const std::optional<std::int64_t> callerDepthValue = callObject->getInteger("callerDepth"))
                {
                    callerDepth = static_cast<std::size_t>(*callerDepthValue);
                }

                std::size_t eventIndex = 0U;
                if (const std::optional<std::int64_t> eventIndexValue = callObject->getInteger("eventIndex"))
                {
                    eventIndex = static_cast<std::size_t>(*eventIndexValue);
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
                runtimeContext.calls.push_back(RuntimeCallData{eventIndex, caller, callerDepth, callee});
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

    std::vector<RuntimeOccurrenceNode> buildOccurrenceNodesForContext(const RuntimeContextData &runtimeContext)
    {
        std::vector<RuntimeOccurrenceNode> occurrenceNodes;
        occurrenceNodes.push_back({runtimeContext.entrypoint, 0U, {}});

        std::vector<const RuntimeCallData *> orderedCalls;
        orderedCalls.reserve(runtimeContext.calls.size());
        for (const RuntimeCallData &call : runtimeContext.calls)
        {
            orderedCalls.push_back(&call);
        }
        std::stable_sort(orderedCalls.begin(), orderedCalls.end(), [](const RuntimeCallData *lhs, const RuntimeCallData *rhs)
                         {
            if (lhs->eventIndex != rhs->eventIndex)
            {
                return lhs->eventIndex < rhs->eventIndex;
            }
            if (lhs->caller != rhs->caller)
            {
                return lhs->caller < rhs->caller;
            }
            return lhs->callee < rhs->callee; });

        std::vector<std::size_t> frameStack;
        frameStack.push_back(0U);

        const auto findCallerFrameIndex = [&](std::string_view callerName, const std::optional<std::size_t> &callerDepth) -> std::ptrdiff_t
        {
            if (callerDepth.has_value())
            {
                const std::size_t depth = *callerDepth;
                if (depth < frameStack.size())
                {
                    const std::size_t indexFromBottom = (frameStack.size() - 1U) - depth;
                    const std::size_t occurrenceIndex = frameStack[indexFromBottom];
                    if (occurrenceNodes[occurrenceIndex].name == callerName)
                    {
                        return static_cast<std::ptrdiff_t>(indexFromBottom);
                    }
                }
            }

            for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(frameStack.size()) - 1; i >= 0; --i)
            {
                if (occurrenceNodes[frameStack[static_cast<std::size_t>(i)]].name == callerName)
                {
                    return i;
                }
            }

            return -1;
        };

        for (const RuntimeCallData *call : orderedCalls)
        {
            const std::string &caller = call->caller.empty() ? runtimeContext.entrypoint : call->caller;
            std::ptrdiff_t callerFrameIndex = findCallerFrameIndex(caller, call->callerDepth);
            if (callerFrameIndex < 0)
            {
                callerFrameIndex = 0;
                frameStack.resize(1U);
            }
            else
            {
                frameStack.resize(static_cast<std::size_t>(callerFrameIndex) + 1U);
            }

            const std::size_t parentIndex = frameStack.back();
            const std::string calleeName = call->callee.empty() ? std::string("<unknown>") : call->callee;
            const std::size_t childIndex = occurrenceNodes.size();
            occurrenceNodes.push_back({calleeName, 1U, {}});
            occurrenceNodes[parentIndex].children.push_back(childIndex);
            frameStack.push_back(childIndex);
        }

        std::vector<RuntimeOccurrenceNode> compressedNodes;
        if (occurrenceNodes.empty())
        {
            return compressedNodes;
        }

        const std::function<std::size_t(const std::vector<std::size_t> &)> compressGroup =
            [&](const std::vector<std::size_t> &sourceIndices) -> std::size_t
        {
            if (sourceIndices.empty())
            {
                return 0U;
            }

            const RuntimeOccurrenceNode &representative = occurrenceNodes[sourceIndices.front()];
            const std::size_t compressedIndex = compressedNodes.size();
            compressedNodes.push_back({representative.name, 0U, {}});

            std::vector<std::string> childOrder;
            std::unordered_map<std::string, std::vector<std::size_t>> childGroups;
            for (const std::size_t sourceIndex : sourceIndices)
            {
                if (sourceIndex >= occurrenceNodes.size())
                {
                    continue;
                }

                const RuntimeOccurrenceNode &sourceNode = occurrenceNodes[sourceIndex];
                compressedNodes[compressedIndex].hitCount += sourceNode.hitCount;
                for (const std::size_t sourceChildIndex : sourceNode.children)
                {
                    if (sourceChildIndex >= occurrenceNodes.size())
                    {
                        continue;
                    }

                    const std::string &childName = occurrenceNodes[sourceChildIndex].name;
                    std::vector<std::size_t> &group = childGroups[childName];
                    if (group.empty())
                    {
                        childOrder.push_back(childName);
                    }
                    group.push_back(sourceChildIndex);
                }
            }

            for (const std::string &childName : childOrder)
            {
                const std::size_t compressedChildIndex = compressGroup(childGroups[childName]);
                compressedNodes[compressedIndex].children.push_back(compressedChildIndex);
            }
            return compressedIndex;
        };

        compressGroup({0U});
        return compressedNodes;
    }

    void mergeOccurrenceSubtree(
        std::vector<RuntimeOccurrenceNode> &mergedNodes,
        std::size_t mergedIndex,
        const std::vector<RuntimeOccurrenceNode> &sourceNodes,
        std::size_t sourceIndex)
    {
        if (mergedIndex >= mergedNodes.size() || sourceIndex >= sourceNodes.size())
        {
            return;
        }

        mergedNodes[mergedIndex].hitCount += sourceNodes[sourceIndex].hitCount;

        std::unordered_map<std::string, std::vector<std::size_t>> mergedChildrenByName;
        mergedChildrenByName.reserve(mergedNodes[mergedIndex].children.size());
        for (const std::size_t childIndex : mergedNodes[mergedIndex].children)
        {
            if (childIndex >= mergedNodes.size())
            {
                continue;
            }

            mergedChildrenByName[mergedNodes[childIndex].name].push_back(childIndex);
        }

        std::unordered_map<std::string, std::size_t> seenSourceChildrenByName;
        for (const std::size_t sourceChildIndex : sourceNodes[sourceIndex].children)
        {
            if (sourceChildIndex >= sourceNodes.size())
            {
                continue;
            }

            const std::string &sourceChildName = sourceNodes[sourceChildIndex].name;
            std::size_t &seenCount = seenSourceChildrenByName[sourceChildName];
            std::vector<std::size_t> &mergedCandidates = mergedChildrenByName[sourceChildName];

            std::size_t targetMergedChildIndex = 0U;
            if (seenCount < mergedCandidates.size())
            {
                targetMergedChildIndex = mergedCandidates[seenCount];
            }
            else
            {
                targetMergedChildIndex = mergedNodes.size();
                mergedNodes.push_back({sourceChildName, 0U, {}});
                mergedNodes[mergedIndex].children.push_back(targetMergedChildIndex);
                mergedCandidates.push_back(targetMergedChildIndex);
            }

            ++seenCount;
            mergeOccurrenceSubtree(mergedNodes, targetMergedChildIndex, sourceNodes, sourceChildIndex);
        }
    }

    void buildTreeNodesForContexts(const std::string &entrypoint, const std::vector<const RuntimeContextData *> &runtimeContexts, const CallGraph &subgraph, TreeNodes &treeNodes)
    {
        std::vector<RuntimeOccurrenceNode> occurrenceNodes;
        occurrenceNodes.push_back({entrypoint, 0U, {}});

        for (const RuntimeContextData *runtimeContext : runtimeContexts)
        {
            if (runtimeContext == nullptr)
            {
                continue;
            }

            std::vector<RuntimeOccurrenceNode> sourceNodes = buildOccurrenceNodesForContext(*runtimeContext);
            if (sourceNodes.empty())
            {
                continue;
            }

            occurrenceNodes[0].hitCount += 1U;
            mergeOccurrenceSubtree(occurrenceNodes, 0U, sourceNodes, 0U);
        }

        std::size_t nextUid = 0U;
        std::function<void(std::size_t, const std::string &, int, bool)> emitTree =
            [&](std::size_t occurrenceIndex, const std::string &parentUid, int level, bool edgeTaken)
        {
            if (occurrenceIndex >= occurrenceNodes.size())
            {
                return;
            }

            const std::string occurrenceName = occurrenceNodes[occurrenceIndex].name;
            const std::size_t occurrenceHitCount = occurrenceNodes[occurrenceIndex].hitCount;
            const std::vector<std::size_t> occurrenceChildren = occurrenceNodes[occurrenceIndex].children;
            TreeNode node;
            node.name = occurrenceName;
            node.level = level;
            node.parentUid = parentUid;
            node.edgeTaken = edgeTaken;
            node.hitCount = level > 0 ? occurrenceHitCount : 0U;
            node.uid = std::to_string(nextUid++);

            std::vector<std::string> staticChildren;
            const auto staticIt = subgraph.find(occurrenceName);
            if (staticIt != subgraph.end())
            {
                staticChildren.reserve(staticIt->second.size());
                staticChildren.insert(staticChildren.end(), staticIt->second.begin(), staticIt->second.end());
                std::sort(staticChildren.begin(), staticChildren.end());
            }

            std::unordered_set<std::string> coveredStaticChildren;
            coveredStaticChildren.reserve(occurrenceChildren.size());
            for (const std::size_t childIndex : occurrenceChildren)
            {
                if (childIndex >= occurrenceNodes.size())
                {
                    continue;
                }

                coveredStaticChildren.insert(occurrenceNodes[childIndex].name);
            }

            node.coveredChildren = 0U;
            node.uncoveredChildren = 0U;
            for (const std::string &childName : staticChildren)
            {
                if (coveredStaticChildren.find(childName) != coveredStaticChildren.end())
                {
                    ++node.coveredChildren;
                }
                else
                {
                    ++node.uncoveredChildren;
                }
            }
            node.hasChildren = !staticChildren.empty() || !occurrenceChildren.empty();

            treeNodes.push_back(std::move(node));
            const std::string currentUid = treeNodes.back().uid;

            for (const std::size_t childIndex : occurrenceChildren)
            {
                emitTree(childIndex, currentUid, level + 1, true);
            }

            for (const std::string &childName : staticChildren)
            {
                if (coveredStaticChildren.find(childName) != coveredStaticChildren.end())
                {
                    continue;
                }

                const std::size_t missingChildIndex = occurrenceNodes.size();
                occurrenceNodes.push_back({childName, 0U, {}});
                emitTree(missingChildIndex, currentUid, level + 1, false);
            }
        };

        emitTree(0U, std::string{}, 0, true);
    }

    std::string buildSidebarHtml(const std::vector<std::string> &rootNames, const std::vector<double> &coveragePercents)
    {
        std::ostringstream html;
        html << "<div class=\"sidebar\">\n";
        html << "  <div class=\"sidebar-title\">Contexts (" << rootNames.size() << ")</div>\n";
        html << "  <div class=\"sidebar-search\">\n";
        html << "    <input type=\"text\" id=\"sidebar-search\" placeholder=\"Filter contexts...\" oninput=\"filterSidebar(this.value)\">\n";
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

        std::size_t globallyCoveredStaticEdges = 0U;
        for (const Edge &edge : staticEdges)
        {
            if (runtimeEdges.find(edge) != runtimeEdges.end())
            {
                ++globallyCoveredStaticEdges;
            }
        }
        const double globalPct = staticEdges.empty() ? 0.0 : (100.0 * static_cast<double>(globallyCoveredStaticEdges)) / static_cast<double>(staticEdges.size());

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

    std::vector<const RuntimeContextData *> orderedContexts;
    orderedContexts.reserve(runtimeContexts.size());
    for (const RuntimeContextData &runtimeContext : runtimeContexts)
    {
        if (!runtimeContext.entrypoint.empty() && roots.find(runtimeContext.entrypoint) == roots.end())
        {
            continue;
        }

        orderedContexts.push_back(&runtimeContext);
    }

    std::sort(orderedContexts.begin(), orderedContexts.end(), [](const RuntimeContextData *lhs, const RuntimeContextData *rhs)
              {
        if (lhs->entrypoint != rhs->entrypoint)
        {
            return lhs->entrypoint < rhs->entrypoint;
        }
        if (lhs->ordinal != rhs->ordinal)
        {
            return lhs->ordinal < rhs->ordinal;
        }
        if (lhs->startEventIndex != rhs->startEventIndex)
        {
            return lhs->startEventIndex < rhs->startEventIndex;
        }
        return lhs->contextId < rhs->contextId; });

    std::unordered_map<std::string, std::vector<const RuntimeContextData *>> contextsByEntrypoint;
    contextsByEntrypoint.reserve(orderedContexts.size());
    std::vector<std::string> orderedEntrypoints;
    orderedEntrypoints.reserve(orderedContexts.size());
    for (const RuntimeContextData *runtimeContext : orderedContexts)
    {
        if (runtimeContext == nullptr || runtimeContext->entrypoint.empty())
        {
            continue;
        }

        std::vector<const RuntimeContextData *> &group = contextsByEntrypoint[runtimeContext->entrypoint];
        if (group.empty())
        {
            orderedEntrypoints.push_back(runtimeContext->entrypoint);
        }
        group.push_back(runtimeContext);
    }

    std::vector<RootStats> rootStats;
    rootStats.reserve(orderedEntrypoints.size());
    for (const std::string &entrypoint : orderedEntrypoints)
    {
        const auto groupIt = contextsByEntrypoint.find(entrypoint);
        if (groupIt == contextsByEntrypoint.end() || groupIt->second.empty())
        {
            continue;
        }

        const std::vector<const RuntimeContextData *> &contextGroup = groupIt->second;
        RootStats stats;
        stats.name = entrypoint;
        if (contextGroup.size() > 1U)
        {
            stats.name += " (" + std::to_string(contextGroup.size()) + " runs)";
        }
        stats.runCount = contextGroup.size();

        buildSubgraphFromRoot(entrypoint, acyclicGraph, stats.subgraph, stats.nodes);
        buildTreeNodesForContexts(entrypoint, contextGroup, stats.subgraph, stats.treeNodes);
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
