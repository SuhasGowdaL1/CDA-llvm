/**
 * @file runtime_callgraph_generator_main.cpp
 * @brief Generate execution-time callgraph from runtime logs with ambiguity scoring.
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include "serialization.h"

namespace
{

    enum class EventKind
    {
        Entry,
        Exit,
        Plain
    };

    struct Event
    {
        std::size_t lineNumber = 0U;
        std::string rawToken;
        EventKind kind = EventKind::Plain;
        std::string baseName;
    };

    struct EdgeKey
    {
        std::string caller;
        std::string callee;

        bool operator<(const EdgeKey &other) const
        {
            if (caller != other.caller)
            {
                return caller < other.caller;
            }
            return callee < other.callee;
        }
    };

    struct Assignment
    {
        std::size_t lineNumber = 0U;
        std::string token;
        std::vector<std::string> candidates;
        std::string chosenCaller;
        bool ambiguous = false;
        bool usedStaticEdge = false;
        double deltaScore = 0.0;
    };

    struct InferredFrame
    {
        std::string functionName;
        std::size_t nextExpectedCallIndex = 0U;
        std::size_t explicitDepthAnchor = 0U;
    };

    struct PathState
    {
        std::vector<std::string> contextStack;
        std::vector<InferredFrame> inferredStack;
        std::map<EdgeKey, std::size_t> edgeCounts;
        std::set<std::string> nodes;
        std::vector<Assignment> assignments;
        std::vector<std::string> warnings;
        double score = 0.0;
    };

    llvm::cl::OptionCategory kCategory("runtime-callgraph-generator options");

    llvm::cl::opt<std::string> kLogs(
        "logs",
        llvm::cl::desc("Path to runtime logs file"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("input/logs.txt"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kEntryPoints(
        "entrypoints",
        llvm::cl::desc("Path to entrypoint names file"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("input/entrypoints.txt"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kStaticCallGraph(
        "static-callgraph",
        llvm::cl::desc("Path to static callgraph JSON (out/callgraph.json)"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/callgraph.json"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kCfgAnalysis(
        "cfg-analysis",
        llvm::cl::desc("Path to CFG analysis JSON used for intra-function call order inference"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/cfg-analysis.json"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kOutput(
        "o",
        llvm::cl::desc("Output runtime callgraph JSON"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/runtime-callgraph.json"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kDotOutput(
        "dot-output",
        llvm::cl::desc("Output DOT path for best path"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/runtime-callgraph.dot"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<bool> kNoDot(
        "no-dot",
        llvm::cl::desc("Disable DOT output"),
        llvm::cl::init(false),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<unsigned> kTopK(
        "top-k",
        llvm::cl::desc("Keep top K candidate paths when ambiguity exists"),
        llvm::cl::value_desc("N"),
        llvm::cl::init(8),
        llvm::cl::cat(kCategory));

    std::string trimCopy(const std::string &text)
    {
        std::size_t begin = 0U;
        while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0)
        {
            ++begin;
        }

        std::size_t end = text.size();
        while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1U])) != 0)
        {
            --end;
        }

        return text.substr(begin, end - begin);
    }

    bool endsWith(const std::string &text, const std::string &suffix)
    {
        return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    std::string stripSuffix(const std::string &text, const std::string &suffix)
    {
        if (!endsWith(text, suffix))
        {
            return text;
        }
        return text.substr(0, text.size() - suffix.size());
    }

    bool loadNameList(const std::string &path, std::set<std::string> &names, std::string &error)
    {
        std::ifstream input(path);
        if (!input)
        {
            error = "failed to open file: " + path;
            return false;
        }

        std::string line;
        while (std::getline(input, line))
        {
            const std::size_t commentPos = line.find('#');
            if (commentPos != std::string::npos)
            {
                line = line.substr(0, commentPos);
            }
            const std::string trimmed = trimCopy(line);
            if (!trimmed.empty())
            {
                names.insert(trimmed);
            }
        }

        return true;
    }

    bool parseEvents(const std::string &logPath, const std::set<std::string> &entrypoints, std::vector<Event> &events, std::string &error)
    {
        std::ifstream input(logPath);
        if (!input)
        {
            error = "failed to open log file: " + logPath;
            return false;
        }

        std::size_t lineNo = 0U;
        std::string raw;
        while (std::getline(input, raw))
        {
            ++lineNo;
            const std::string token = trimCopy(raw);
            if (token.empty() || token[0] == '#')
            {
                continue;
            }

            Event event;
            event.lineNumber = lineNo;
            event.rawToken = token;
            event.kind = EventKind::Plain;
            event.baseName = token;

            if (endsWith(token, "_entry"))
            {
                const std::string base = stripSuffix(token, "_entry");
                if (entrypoints.find(base) != entrypoints.end())
                {
                    event.kind = EventKind::Entry;
                    event.baseName = base;
                }
            }
            else if (endsWith(token, "_exit"))
            {
                const std::string base = stripSuffix(token, "_exit");
                if (entrypoints.find(base) != entrypoints.end())
                {
                    event.kind = EventKind::Exit;
                    event.baseName = base;
                }
            }

            events.push_back(std::move(event));
        }

        return true;
    }

    bool loadStaticEdges(
        const std::string &callgraphPath,
        std::unordered_map<std::string, std::set<std::string>> &callersByCallee,
        std::string &error)
    {
        std::ifstream input(callgraphPath);
        if (!input)
        {
            error = "failed to open static callgraph file: " + callgraphPath;
            return false;
        }

        std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        llvm::Expected<llvm::json::Value> parsed = llvm::json::parse(text);
        if (!parsed)
        {
            error = "failed to parse static callgraph JSON: " + callgraphPath;
            return false;
        }

        const llvm::json::Object *root = parsed->getAsObject();
        if (root == nullptr)
        {
            error = "static callgraph root is not a JSON object";
            return false;
        }

        const llvm::json::Object *collapsed = root->getObject("collapsedCallGraph");
        if (collapsed == nullptr)
        {
            error = "missing collapsedCallGraph in static callgraph";
            return false;
        }

        const llvm::json::Array *edges = collapsed->getArray("edges");
        if (edges == nullptr)
        {
            error = "missing collapsedCallGraph.edges in static callgraph";
            return false;
        }

        for (const llvm::json::Value &edgeValue : *edges)
        {
            const llvm::json::Object *edge = edgeValue.getAsObject();
            if (edge == nullptr)
            {
                continue;
            }

            const std::optional<llvm::StringRef> caller = edge->getString("caller");
            const std::optional<llvm::StringRef> callee = edge->getString("callee");
            if (!caller.has_value() || !callee.has_value())
            {
                continue;
            }

            callersByCallee[callee->str()].insert(caller->str());
        }

        return true;
    }

    bool loadCfgDirectCallOrder(
        const std::string &cfgAnalysisPath,
        std::unordered_map<std::string, std::vector<std::string>> &orderedCalleesByFunction,
        std::string &error)
    {
        std::ifstream input(cfgAnalysisPath);
        if (!input)
        {
            error = "failed to open cfg analysis file: " + cfgAnalysisPath;
            return false;
        }

        std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        llvm::Expected<llvm::json::Value> parsed = llvm::json::parse(text);
        if (!parsed)
        {
            error = "failed to parse cfg analysis JSON: " + cfgAnalysisPath;
            return false;
        }

        const llvm::json::Object *root = parsed->getAsObject();
        if (root == nullptr)
        {
            error = "cfg analysis root is not a JSON object";
            return false;
        }

        const llvm::json::Array *functions = root->getArray("functions");
        if (functions == nullptr)
        {
            error = "missing functions in cfg analysis";
            return false;
        }

        for (const llvm::json::Value &functionValue : *functions)
        {
            const llvm::json::Object *functionObj = functionValue.getAsObject();
            if (functionObj == nullptr)
            {
                continue;
            }

            const std::optional<llvm::StringRef> functionName = functionObj->getString("name");
            if (!functionName.has_value() || functionName->empty())
            {
                continue;
            }

            const llvm::json::Object *attributes = functionObj->getObject("attributes");
            if (attributes == nullptr)
            {
                continue;
            }

            const llvm::json::Array *callSites = attributes->getArray("callSites");
            if (callSites == nullptr)
            {
                continue;
            }

            struct CallSiteRef
            {
                std::string directCallee;
                std::int64_t line = 0;
                std::int64_t column = 0;
            };

            std::vector<CallSiteRef> refs;
            for (const llvm::json::Value &callSiteValue : *callSites)
            {
                const llvm::json::Object *callSiteObj = callSiteValue.getAsObject();
                if (callSiteObj == nullptr)
                {
                    continue;
                }

                const std::optional<llvm::StringRef> directCallee = callSiteObj->getString("directCallee");
                if (!directCallee.has_value() || directCallee->empty())
                {
                    continue;
                }

                std::int64_t line = 0;
                std::int64_t column = 0;
                const llvm::json::Object *location = callSiteObj->getObject("location");
                if (location != nullptr)
                {
                    if (const std::optional<std::int64_t> value = location->getInteger("line"))
                    {
                        line = *value;
                    }
                    if (const std::optional<std::int64_t> value = location->getInteger("column"))
                    {
                        column = *value;
                    }
                }

                refs.push_back(CallSiteRef{directCallee->str(), line, column});
            }

            std::sort(refs.begin(), refs.end(), [](const CallSiteRef &lhs, const CallSiteRef &rhs)
                      {
                if (lhs.line != rhs.line)
                {
                    return lhs.line < rhs.line;
                }
                if (lhs.column != rhs.column)
                {
                    return lhs.column < rhs.column;
                }
                return lhs.directCallee < rhs.directCallee; });

            std::vector<std::string> ordered;
            ordered.reserve(refs.size());
            for (const CallSiteRef &ref : refs)
            {
                ordered.push_back(ref.directCallee);
            }
            orderedCalleesByFunction[functionName->str()] = std::move(ordered);
        }

        return true;
    }

    void cleanupInferredStack(PathState &path)
    {
        while (!path.inferredStack.empty() && path.inferredStack.back().explicitDepthAnchor > path.contextStack.size())
        {
            path.inferredStack.pop_back();
        }
    }

    void discardInferredFramesAtOrAboveDepth(PathState &path, std::size_t depth)
    {
        while (!path.inferredStack.empty() && path.inferredStack.back().explicitDepthAnchor >= depth)
        {
            path.inferredStack.pop_back();
        }
    }

    std::vector<std::string> buildActiveCallerOrder(const PathState &path)
    {
        std::vector<std::string> callers;
        callers.reserve(path.inferredStack.size() + path.contextStack.size());

        for (std::size_t i = path.inferredStack.size(); i > 0U; --i)
        {
            callers.push_back(path.inferredStack[i - 1U].functionName);
        }

        for (std::size_t i = path.contextStack.size(); i > 0U; --i)
        {
            callers.push_back(path.contextStack[i - 1U]);
        }

        return callers;
    }

    void alignInferredFrameForToken(
        PathState &path,
        const std::string &token,
        const std::unordered_map<std::string, std::vector<std::string>> &orderedCalleesByFunction)
    {
        cleanupInferredStack(path);
        while (!path.inferredStack.empty())
        {
            InferredFrame &top = path.inferredStack.back();
            const std::unordered_map<std::string, std::vector<std::string>>::const_iterator functionIt =
                orderedCalleesByFunction.find(top.functionName);
            if (functionIt == orderedCalleesByFunction.end() || functionIt->second.empty())
            {
                path.inferredStack.pop_back();
                continue;
            }

            const std::vector<std::string> &orderedCallees = functionIt->second;
            if (top.nextExpectedCallIndex >= orderedCallees.size())
            {
                path.inferredStack.pop_back();
                continue;
            }

            std::size_t scan = top.nextExpectedCallIndex;
            while (scan < orderedCallees.size() && orderedCallees[scan] != token)
            {
                ++scan;
            }

            if (scan == orderedCallees.size())
            {
                path.inferredStack.pop_back();
                continue;
            }

            top.nextExpectedCallIndex = scan;
            break;
        }
    }

    void updateInferredStackAfterAssignment(
        PathState &path,
        const std::string &chosenCaller,
        const std::string &chosenCallee,
        const std::set<std::string> &entrypoints,
        const std::unordered_map<std::string, std::vector<std::string>> &orderedCalleesByFunction)
    {
        cleanupInferredStack(path);

        if (!path.inferredStack.empty() && path.inferredStack.back().functionName == chosenCaller)
        {
            InferredFrame &top = path.inferredStack.back();
            const std::unordered_map<std::string, std::vector<std::string>>::const_iterator functionIt =
                orderedCalleesByFunction.find(top.functionName);
            if (functionIt != orderedCalleesByFunction.end())
            {
                const std::vector<std::string> &orderedCallees = functionIt->second;
                if (top.nextExpectedCallIndex < orderedCallees.size() && orderedCallees[top.nextExpectedCallIndex] == chosenCallee)
                {
                    ++top.nextExpectedCallIndex;
                }
                else
                {
                    std::size_t scan = top.nextExpectedCallIndex;
                    while (scan < orderedCallees.size() && orderedCallees[scan] != chosenCallee)
                    {
                        ++scan;
                    }
                    if (scan < orderedCallees.size())
                    {
                        top.nextExpectedCallIndex = scan + 1U;
                    }
                }

                if (top.nextExpectedCallIndex >= orderedCallees.size())
                {
                    path.inferredStack.pop_back();
                }
            }
        }

        // Keep explicit-frame events authoritative: entrypoints with explicit markers should not be inferred.
        if (entrypoints.find(chosenCallee) != entrypoints.end())
        {
            return;
        }

        const std::unordered_map<std::string, std::vector<std::string>>::const_iterator calleeIt =
            orderedCalleesByFunction.find(chosenCallee);
        if (calleeIt == orderedCalleesByFunction.end() || calleeIt->second.empty())
        {
            return;
        }

        InferredFrame frame;
        frame.functionName = chosenCallee;
        frame.nextExpectedCallIndex = 0U;
        frame.explicitDepthAnchor = path.contextStack.size();
        path.inferredStack.push_back(std::move(frame));
    }

    std::string pathTieBreakerKey(const PathState &path)
    {
        std::string key;
        key.reserve(path.assignments.size() * 8U + path.contextStack.size() * 8U);
        for (const Assignment &assignment : path.assignments)
        {
            key += assignment.chosenCaller;
            key += "->";
            key += assignment.token;
            key += ";";
        }
        key += "|stack:";
        for (const std::string &frame : path.contextStack)
        {
            key += frame;
            key += ";";
        }
        return key;
    }

    void pruneTopK(std::vector<PathState> &paths, std::size_t topK)
    {
        std::sort(paths.begin(), paths.end(), [](const PathState &lhs, const PathState &rhs)
                  {
            if (lhs.score != rhs.score)
            {
                return lhs.score < rhs.score;
            }
            return pathTieBreakerKey(lhs) < pathTieBreakerKey(rhs); });

        if (paths.size() > topK)
        {
            paths.resize(topK);
        }
    }

    void addEdge(PathState &path, const std::string &caller, const std::string &callee)
    {
        path.nodes.insert(caller);
        path.nodes.insert(callee);
        path.edgeCounts[EdgeKey{caller, callee}] += 1U;
    }

    llvm::json::Object assignmentToJson(const Assignment &assignment)
    {
        llvm::json::Object object;
        object["line"] = static_cast<std::int64_t>(assignment.lineNumber);
        object["token"] = assignment.token;
        object["chosenCaller"] = assignment.chosenCaller;
        object["ambiguous"] = assignment.ambiguous;
        object["usedStaticEdge"] = assignment.usedStaticEdge;
        object["deltaScore"] = assignment.deltaScore;

        llvm::json::Array candidates;
        for (const std::string &candidate : assignment.candidates)
        {
            candidates.push_back(candidate);
        }
        object["candidates"] = std::move(candidates);
        return object;
    }

    llvm::json::Object pathToJson(const PathState &path, std::size_t rank)
    {
        llvm::json::Object object;
        object["rank"] = static_cast<std::int64_t>(rank);
        object["score"] = path.score;

        llvm::json::Array edges;
        for (const std::pair<const EdgeKey, std::size_t> &entry : path.edgeCounts)
        {
            llvm::json::Object edge;
            edge["caller"] = entry.first.caller;
            edge["callee"] = entry.first.callee;
            edge["count"] = static_cast<std::int64_t>(entry.second);
            edges.push_back(std::move(edge));
        }
        object["edges"] = std::move(edges);

        llvm::json::Array assignments;
        for (const Assignment &assignment : path.assignments)
        {
            assignments.push_back(assignmentToJson(assignment));
        }
        object["assignments"] = std::move(assignments);

        llvm::json::Array warnings;
        for (const std::string &warning : path.warnings)
        {
            warnings.push_back(warning);
        }
        object["warnings"] = std::move(warnings);

        return object;
    }

    bool writeDot(
        const std::string &dotPath,
        const std::set<std::string> &nodes,
        const std::map<EdgeKey, std::size_t> &edgeCounts,
        std::string &error)
    {
        std::ofstream out(dotPath);
        if (!out)
        {
            error = "failed to open DOT output file: " + dotPath;
            return false;
        }

        out << "digraph RuntimeExecutionCallGraph {\n";
        out << "  rankdir=LR;\n";

        for (const std::string &node : nodes)
        {
            out << "  \"" << escapeDot(node) << "\";\n";
        }

        for (const std::pair<const EdgeKey, std::size_t> &entry : edgeCounts)
        {
            out << "  \"" << escapeDot(entry.first.caller) << "\" -> \"" << escapeDot(entry.first.callee)
                << "\" [label=\"" << entry.second << "\"];\n";
        }

        out << "}\n";
        return true;
    }

} // namespace

int main(int argc, const char **argv)
{
    llvm::cl::HideUnrelatedOptions(kCategory);
    llvm::cl::ParseCommandLineOptions(argc, argv, "Generate runtime callgraph with ambiguity scoring\n");

    std::set<std::string> entrypoints;
    std::string error;
    if (!loadNameList(kEntryPoints, entrypoints, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    std::unordered_map<std::string, std::set<std::string>> callersByCallee;
    if (!loadStaticEdges(kStaticCallGraph, callersByCallee, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    std::unordered_map<std::string, std::vector<std::string>> orderedCalleesByFunction;
    if (!loadCfgDirectCallOrder(kCfgAnalysis, orderedCalleesByFunction, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    std::vector<Event> events;
    if (!parseEvents(kLogs, entrypoints, events, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    std::vector<std::size_t> sameTokenRunLength(events.size(), 1U);
    for (std::size_t i = 0U; i < events.size(); ++i)
    {
        if (events[i].kind != EventKind::Plain)
        {
            sameTokenRunLength[i] = 0U;
            continue;
        }

        std::size_t j = i;
        while (j < events.size() &&
               events[j].kind == EventKind::Plain &&
               events[j].baseName == events[i].baseName)
        {
            ++j;
        }
        sameTokenRunLength[i] = j - i;
    }

    std::vector<PathState> activePaths(1U);
    std::size_t pathExpansionCount = 1U;

    for (std::size_t eventIndex = 0U; eventIndex < events.size(); ++eventIndex)
    {
        const Event &event = events[eventIndex];
        std::vector<PathState> nextPaths;
        for (const PathState &path : activePaths)
        {
            if (event.kind == EventKind::Entry)
            {
                PathState next = path;
                cleanupInferredStack(next);
                discardInferredFramesAtOrAboveDepth(next, next.contextStack.size());
                next.nodes.insert(event.baseName);
                if (!next.contextStack.empty())
                {
                    addEdge(next, next.contextStack.back(), event.baseName);
                }
                next.contextStack.push_back(event.baseName);
                nextPaths.push_back(std::move(next));
                continue;
            }

            if (event.kind == EventKind::Exit)
            {
                PathState next = path;
                cleanupInferredStack(next);
                if (next.contextStack.empty())
                {
                    next.score += 12.0;
                    next.warnings.push_back(
                        llvm::formatv("line {0}: unmatched exit marker '{1}'", event.lineNumber, event.rawToken).str());
                    nextPaths.push_back(std::move(next));
                    continue;
                }

                if (next.contextStack.back() == event.baseName)
                {
                    next.contextStack.pop_back();
                    cleanupInferredStack(next);
                    nextPaths.push_back(std::move(next));
                    continue;
                }

                bool found = false;
                while (!next.contextStack.empty())
                {
                    const std::string top = next.contextStack.back();
                    next.contextStack.pop_back();
                    next.score += 4.0;
                    next.warnings.push_back(
                        llvm::formatv("line {0}: context unwind '{1}' while handling '{2}'", event.lineNumber, top, event.rawToken).str());
                    if (top == event.baseName)
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    next.score += 8.0;
                    next.warnings.push_back(
                        llvm::formatv("line {0}: exit marker '{1}' did not match active context", event.lineNumber, event.rawToken).str());
                }

                cleanupInferredStack(next);

                nextPaths.push_back(std::move(next));
                continue;
            }

            // Plain function log.
            PathState prepared = path;
            alignInferredFrameForToken(prepared, event.baseName, orderedCalleesByFunction);
            const std::vector<std::string> activeCallers = buildActiveCallerOrder(prepared);
            std::set<std::string> inferredCallers;
            for (const InferredFrame &frame : prepared.inferredStack)
            {
                inferredCallers.insert(frame.functionName);
            }

            if (activeCallers.empty())
            {
                PathState next = prepared;
                next.nodes.insert(event.baseName);
                next.score += 10.0;
                next.warnings.push_back(
                    llvm::formatv("line {0}: token '{1}' has no active entry context", event.lineNumber, event.baseName).str());

                Assignment assignment;
                assignment.lineNumber = event.lineNumber;
                assignment.token = event.baseName;
                assignment.chosenCaller = "<no_context>";
                assignment.ambiguous = false;
                assignment.usedStaticEdge = false;
                assignment.deltaScore = 10.0;
                next.assignments.push_back(std::move(assignment));
                nextPaths.push_back(std::move(next));
                continue;
            }

            std::unordered_map<std::string, std::size_t> callerDepthByName;
            for (std::size_t depth = 0U; depth < activeCallers.size(); ++depth)
            {
                const std::string &candidate = activeCallers[depth];
                const auto insertResult = callerDepthByName.insert({candidate, depth});
                if (!insertResult.second)
                {
                    insertResult.first->second = std::min(insertResult.first->second, depth);
                }
            }

            std::vector<std::string> staticCandidates;
            std::vector<std::string> fallbackCandidates;

            const auto staticIt = callersByCallee.find(event.baseName);
            if (staticIt != callersByCallee.end())
            {
                for (const std::pair<const std::string, std::size_t> &entry : callerDepthByName)
                {
                    if (staticIt->second.find(entry.first) != staticIt->second.end())
                    {
                        staticCandidates.push_back(entry.first);
                    }
                }
            }

            for (const std::pair<const std::string, std::size_t> &entry : callerDepthByName)
            {
                fallbackCandidates.push_back(entry.first);
            }

            std::vector<std::string> candidates = !staticCandidates.empty() ? staticCandidates : fallbackCandidates;
            std::sort(candidates.begin(), candidates.end(), [&](const std::string &lhs, const std::string &rhs)
                      {
                const std::size_t dl = callerDepthByName[lhs];
                const std::size_t dr = callerDepthByName[rhs];
                if (dl != dr)
                {
                    return dl < dr;
                }
                return lhs < rhs; });

            const bool hasStaticCandidate = !staticCandidates.empty();
            const bool explicitContextAvailable = !prepared.contextStack.empty();
            const std::string explicitTopCaller = explicitContextAvailable ? prepared.contextStack.back() : "";
            const bool explicitTopSupportsToken =
                explicitContextAvailable &&
                staticIt != callersByCallee.end() &&
                staticIt->second.find(explicitTopCaller) != staticIt->second.end();
            const std::size_t plainRunLength = sameTokenRunLength[eventIndex];

            for (const std::string &caller : candidates)
            {
                PathState next = prepared;
                addEdge(next, caller, event.baseName);

                const double depthPenalty = static_cast<double>(callerDepthByName[caller]);
                const double fallbackPenalty = hasStaticCandidate ? 0.0 : 3.0;
                double inferencePenalty = 0.0;
                if (inferredCallers.find(caller) != inferredCallers.end() &&
                    explicitTopSupportsToken &&
                    plainRunLength <= 1U)
                {
                    // If there is only one plain token in this local run and the explicit caller
                    // also directly supports it, prefer explicit attribution over inferred nesting.
                    inferencePenalty = 1.5;
                }

                const double deltaScore = depthPenalty + fallbackPenalty + inferencePenalty;
                next.score += deltaScore;

                Assignment assignment;
                assignment.lineNumber = event.lineNumber;
                assignment.token = event.baseName;
                assignment.candidates = candidates;
                assignment.chosenCaller = caller;
                assignment.ambiguous = candidates.size() > 1U;
                assignment.usedStaticEdge = hasStaticCandidate;
                assignment.deltaScore = deltaScore;
                next.assignments.push_back(std::move(assignment));

                updateInferredStackAfterAssignment(
                    next,
                    caller,
                    event.baseName,
                    entrypoints,
                    orderedCalleesByFunction);

                nextPaths.push_back(std::move(next));
            }
        }

        pathExpansionCount += nextPaths.size();
        pruneTopK(nextPaths, std::max<std::size_t>(1U, static_cast<std::size_t>(kTopK)));
        activePaths.swap(nextPaths);
    }

    if (activePaths.empty())
    {
        llvm::errs() << "error: no valid runtime paths were produced\n";
        return 1;
    }

    pruneTopK(activePaths, std::max<std::size_t>(1U, static_cast<std::size_t>(kTopK)));
    const PathState &best = activePaths.front();
    const bool uniquelyDeduced =
        activePaths.size() == 1U || (activePaths.size() > 1U && best.score < activePaths[1].score);

    llvm::json::Object root;

    llvm::json::Object summary;
    summary["events"] = static_cast<std::int64_t>(events.size());
    summary["pathsKept"] = static_cast<std::int64_t>(activePaths.size());
    summary["pathExpansions"] = static_cast<std::int64_t>(pathExpansionCount);
    summary["singlePathDeduced"] = uniquelyDeduced;
    summary["bestScore"] = best.score;
    summary["bestWarnings"] = static_cast<std::int64_t>(best.warnings.size());
    root["summary"] = std::move(summary);

    root["bestPath"] = pathToJson(best, 1U);

    llvm::json::Array candidates;
    for (std::size_t i = 0; i < activePaths.size(); ++i)
    {
        candidates.push_back(pathToJson(activePaths[i], i + 1U));
    }
    root["candidatePaths"] = std::move(candidates);

    std::error_code ec;
    llvm::raw_fd_ostream out(kOutput, ec);
    if (ec)
    {
        llvm::errs() << "error: failed to open output JSON: " << kOutput << "\n";
        return 1;
    }
    out << llvm::formatv("{0:2}", llvm::json::Value(std::move(root))) << "\n";
    out.flush();

    if (!kNoDot)
    {
        if (!writeDot(kDotOutput, best.nodes, best.edgeCounts, error))
        {
            llvm::errs() << "error: " << error << "\n";
            return 1;
        }
    }

    llvm::outs() << "Wrote runtime callgraph JSON to: " << kOutput << "\n";
    if (!kNoDot)
    {
        llvm::outs() << "Wrote runtime callgraph DOT to: " << kDotOutput << "\n";
    }
    llvm::outs() << "Events: " << events.size() << "\n";
    llvm::outs() << "Candidate paths kept: " << activePaths.size() << "\n";
    llvm::outs() << "Single path deduced: " << (uniquelyDeduced ? "yes" : "no") << "\n";

    return 0;
}
