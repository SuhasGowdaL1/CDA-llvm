/**
 * @file runtime.cpp
 * @brief Implementation of runtime callgraph analysis and visualization functions.
 */

#include "runtime.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/raw_ostream.h"

#include "serialization.h"

// ============================================================================
// EdgeKey comparison
// ============================================================================

bool EdgeKey::operator<(const EdgeKey &other) const
{
    if (caller != other.caller)
    {
        return caller < other.caller;
    }
    return callee < other.callee;
}

// ============================================================================
// String utilities
// ============================================================================

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

std::string escapeJsString(const std::string &value)
{
    std::string escaped;
    escaped.reserve(value.size() + 8U);
    for (const char ch : value)
    {
        switch (ch)
        {
        case '\\':
            escaped += "\\\\";
            break;
        case '\'':
            escaped += "\\'";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            escaped.push_back(ch);
            break;
        }
    }

    return escaped;
}

std::string sanitizeForScriptTag(const std::string &jsonText)
{
    std::string sanitized;
    sanitized.reserve(jsonText.size() + 16U);
    for (const char ch : jsonText)
    {
        if (ch == '<')
        {
            sanitized += "\\u003c";
        }
        else if (ch == '&')
        {
            sanitized += "\\u0026";
        }
        else
        {
            sanitized.push_back(ch);
        }
    }

    return sanitized;
}

std::string jsonValueToString(const llvm::json::Value &value)
{
    std::string raw;
    llvm::raw_string_ostream stream(raw);
    stream << llvm::formatv("{0:2}", value);
    stream.flush();
    return sanitizeForScriptTag(raw);
}

std::string fileNameFromPath(const std::string &path)
{
    const std::size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos)
    {
        return path;
    }

    return path.substr(pos + 1U);
}

// ============================================================================
// File I/O and parsing
// ============================================================================

bool loadNameList(
    const std::string &path,
    std::set<std::string> &names,
    std::vector<std::string> &orderedNames,
    std::string &error)
{
    std::ifstream input(path);
    if (!input)
    {
        error = "failed to open file: " + path;
        return false;
    }

    names.clear();
    orderedNames.clear();
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
            const bool inserted = names.insert(trimmed).second;
            if (inserted)
            {
                orderedNames.push_back(trimmed);
            }
        }
    }

    return true;
}

bool parseEvents(
    const std::string &logPath,
    const std::set<std::string> &entrypoints,
    std::vector<Event> &events,
    std::string &error)
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

// ============================================================================
// Path state management
// ============================================================================

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

// ============================================================================
// Path analysis
// ============================================================================

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

// ============================================================================
// JSON serialization
// ============================================================================

llvm::json::Object assignmentToJson(const Assignment &assignment)
{
    llvm::json::Object object;
    object["line"] = static_cast<std::int64_t>(assignment.lineNumber);
    object["token"] = assignment.token;
    object["chosenCaller"] = assignment.chosenCaller;
    if (assignment.chosenCallerDepth.has_value())
    {
        object["chosenCallerDepth"] = static_cast<std::int64_t>(*assignment.chosenCallerDepth);
    }
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

llvm::json::Object contextCallToJson(const ContextCall &call)
{
    llvm::json::Object object;
    object["eventIndex"] = static_cast<std::int64_t>(call.eventIndex);
    object["line"] = static_cast<std::int64_t>(call.lineNumber);
    object["caller"] = call.caller;
    if (call.callerDepth.has_value())
    {
        object["callerDepth"] = static_cast<std::int64_t>(*call.callerDepth);
    }
    object["callee"] = call.callee;
    object["ambiguous"] = call.ambiguous;
    object["usedStaticEdge"] = call.usedStaticEdge;
    object["deltaScore"] = call.deltaScore;
    return object;
}

llvm::json::Object contextRunToJson(const ContextRun &run, std::size_t lane)
{
    llvm::json::Object object;
    object["contextId"] = run.contextId;
    object["entrypoint"] = run.entrypoint;
    object["ordinal"] = static_cast<std::int64_t>(run.ordinal);
    object["lane"] = static_cast<std::int64_t>(lane);
    object["startEventIndex"] = static_cast<std::int64_t>(run.startEventIndex);
    object["endEventIndex"] = static_cast<std::int64_t>(run.endEventIndex);

    llvm::json::Array segments;
    for (const ContextSegment &segment : run.executionSegments)
    {
        llvm::json::Object seg;
        seg["startEventIndex"] = static_cast<std::int64_t>(segment.startEventIndex);
        seg["endEventIndex"] = static_cast<std::int64_t>(segment.endEventIndex);
        seg["startsAtContextStart"] = segment.startsAtContextStart;
        seg["endsAtContextEnd"] = segment.endsAtContextEnd;
        segments.push_back(std::move(seg));
    }
    object["segments"] = std::move(segments);

    llvm::json::Array calls;
    for (const ContextCall &call : run.calls)
    {
        calls.push_back(contextCallToJson(call));
    }
    object["calls"] = std::move(calls);

    llvm::json::Array warnings;
    for (const std::string &warning : run.warnings)
    {
        warnings.push_back(warning);
    }
    object["warnings"] = std::move(warnings);
    return object;
}

// ============================================================================
// Context run building and visualization
// ============================================================================

std::vector<ContextRun> buildContextRunsFromBestPath(
    const std::vector<Event> &events,
    const PathState &best,
    std::vector<std::string> &warnings)
{
    std::vector<ContextRun> runs;
    std::vector<std::size_t> openRunIndices;
    const std::size_t kNoRun = static_cast<std::size_t>(-1);
    std::vector<std::size_t> ownerRunByEvent(events.size(), kNoRun);
    std::unordered_map<std::string, std::size_t> ordinalByEntrypoint;
    ordinalByEntrypoint.reserve(16U);

    const auto findOpenRunByEntrypoint = [&](const std::string &entrypoint) -> std::size_t
    {
        if (entrypoint.empty())
        {
            return kNoRun;
        }

        for (std::size_t i = openRunIndices.size(); i > 0U; --i)
        {
            const std::size_t runIndex = openRunIndices[i - 1U];
            if (runs[runIndex].entrypoint == entrypoint)
            {
                return runIndex;
            }
        }

        return kNoRun;
    };

    std::size_t assignmentIndex = 0U;
    for (std::size_t eventIndex = 0U; eventIndex < events.size(); ++eventIndex)
    {
        const Event &event = events[eventIndex];
        if (event.kind == EventKind::Entry)
        {
            const std::size_t ordinal = ++ordinalByEntrypoint[event.baseName];
            ContextRun run;
            run.entrypoint = event.baseName;
            run.ordinal = ordinal;
            run.startEventIndex = eventIndex;
            run.endEventIndex = eventIndex;
            run.contextId = event.baseName + "#" + std::to_string(ordinal) + "@" + std::to_string(eventIndex);
            openRunIndices.push_back(runs.size());
            runs.push_back(std::move(run));
            ownerRunByEvent[eventIndex] = openRunIndices.back();
            continue;
        }

        if (event.kind == EventKind::Exit)
        {
            if (openRunIndices.empty())
            {
                warnings.push_back(
                    llvm::formatv("line {0}: unmatched exit marker '{1}' while building context runs", event.lineNumber, event.rawToken).str());
                continue;
            }

            bool matched = false;
            std::size_t matchedRunIndex = kNoRun;
            while (!openRunIndices.empty())
            {
                const std::size_t runIndex = openRunIndices.back();
                openRunIndices.pop_back();
                ContextRun &run = runs[runIndex];
                run.endEventIndex = eventIndex;
                if (run.entrypoint == event.baseName)
                {
                    matched = true;
                    matchedRunIndex = runIndex;
                    break;
                }

                run.warnings.push_back(
                    llvm::formatv("line {0}: context '{1}' force-closed while resolving exit '{2}'", event.lineNumber, run.entrypoint, event.rawToken).str());
            }

            if (!matched)
            {
                warnings.push_back(
                    llvm::formatv("line {0}: exit marker '{1}' did not match any active context run", event.lineNumber, event.rawToken).str());
            }
            else
            {
                ownerRunByEvent[eventIndex] = matchedRunIndex;
            }
            continue;
        }

        if (assignmentIndex >= best.assignments.size())
        {
            warnings.push_back(
                llvm::formatv("line {0}: missing assignment record for runtime token '{1}'", event.lineNumber, event.baseName).str());
            continue;
        }

        const Assignment &assignment = best.assignments[assignmentIndex++];
        if (openRunIndices.empty())
        {
            continue;
        }

        std::size_t runIndex = findOpenRunByEntrypoint(assignment.chosenCaller);
        if (runIndex == kNoRun)
        {
            runIndex = openRunIndices.back();
        }
        ownerRunByEvent[eventIndex] = runIndex;
        ContextRun &run = runs[runIndex];
        run.endEventIndex = eventIndex;

        ContextCall call;
        call.eventIndex = eventIndex;
        call.lineNumber = assignment.lineNumber;
        call.caller = assignment.chosenCaller;
        call.callerDepth = assignment.chosenCallerDepth;
        call.callee = assignment.token;
        call.ambiguous = assignment.ambiguous;
        call.usedStaticEdge = assignment.usedStaticEdge;
        call.deltaScore = assignment.deltaScore;
        run.calls.push_back(std::move(call));
    }

    if (assignmentIndex < best.assignments.size())
    {
        warnings.push_back(
            llvm::formatv("assignment count mismatch: consumed {0}, total {1}", assignmentIndex, best.assignments.size()).str());
    }

    const std::size_t fallbackEnd = events.empty() ? 0U : (events.size() - 1U);
    while (!openRunIndices.empty())
    {
        const std::size_t runIndex = openRunIndices.back();
        openRunIndices.pop_back();
        ContextRun &run = runs[runIndex];
        run.endEventIndex = std::max(run.endEventIndex, fallbackEnd);
        run.warnings.push_back("context ended without explicit exit marker");
    }

    for (std::size_t runIndex = 0U; runIndex < runs.size(); ++runIndex)
    {
        ContextRun &run = runs[runIndex];
        bool inSegment = false;
        std::size_t segmentStart = 0U;
        for (std::size_t eventIndex = run.startEventIndex;
             eventIndex <= run.endEventIndex && eventIndex < ownerRunByEvent.size();
             ++eventIndex)
        {
            const bool ownsEvent = ownerRunByEvent[eventIndex] == runIndex;
            if (ownsEvent && !inSegment)
            {
                inSegment = true;
                segmentStart = eventIndex;
                continue;
            }

            if (!ownsEvent && inSegment)
            {
                ContextSegment segment;
                segment.startEventIndex = segmentStart;
                segment.endEventIndex = eventIndex - 1U;
                segment.startsAtContextStart = segment.startEventIndex == run.startEventIndex;
                segment.endsAtContextEnd = segment.endEventIndex == run.endEventIndex;
                run.executionSegments.push_back(std::move(segment));
                inSegment = false;
            }
        }

        if (inSegment)
        {
            ContextSegment segment;
            segment.startEventIndex = segmentStart;
            segment.endEventIndex = run.endEventIndex;
            segment.startsAtContextStart = segment.startEventIndex == run.startEventIndex;
            segment.endsAtContextEnd = segment.endEventIndex == run.endEventIndex;
            run.executionSegments.push_back(std::move(segment));
        }

        if (run.executionSegments.empty())
        {
            ContextSegment fallback;
            fallback.startEventIndex = run.startEventIndex;
            fallback.endEventIndex = run.endEventIndex;
            fallback.startsAtContextStart = true;
            fallback.endsAtContextEnd = true;
            run.executionSegments.push_back(std::move(fallback));
        }
    }

    return runs;
}

llvm::json::Object buildVisualizationData(
    const std::vector<Event> &events,
    const std::vector<ContextRun> &runs,
    const std::vector<std::string> &warnings,
    const std::vector<std::string> &entrypointPriority)
{
    llvm::json::Object root;
    root["eventCount"] = static_cast<std::int64_t>(events.size());

    llvm::json::Array priority;
    for (const std::string &entrypoint : entrypointPriority)
    {
        priority.push_back(entrypoint);
    }
    root["entrypointPriority"] = std::move(priority);

    llvm::json::Array contexts;
    std::unordered_map<std::string, std::size_t> laneByEntrypoint;
    laneByEntrypoint.reserve(entrypointPriority.size() + runs.size());
    for (std::size_t lane = 0U; lane < entrypointPriority.size(); ++lane)
    {
        laneByEntrypoint.emplace(entrypointPriority[lane], lane);
    }
    for (const ContextRun &run : runs)
    {
        if (laneByEntrypoint.find(run.entrypoint) == laneByEntrypoint.end())
        {
            laneByEntrypoint.emplace(run.entrypoint, laneByEntrypoint.size());
        }
    }
    for (std::size_t lane = 0U; lane < runs.size(); ++lane)
    {
        const auto laneIt = laneByEntrypoint.find(runs[lane].entrypoint);
        const std::size_t stableLane = laneIt != laneByEntrypoint.end() ? laneIt->second : lane;
        contexts.push_back(contextRunToJson(runs[lane], stableLane));
    }
    root["contexts"] = std::move(contexts);

    llvm::json::Array ws;
    for (const std::string &warning : warnings)
    {
        ws.push_back(warning);
    }
    root["warnings"] = std::move(ws);

    return root;
}

// ============================================================================
// Output writers
// ============================================================================

bool writeHtmlFile(const std::string &path, const std::string &contents, std::string &error)
{
    std::ofstream out(path);
    if (!out)
    {
        error = "failed to open HTML output file: " + path;
        return false;
    }

    out << contents;
    return true;
}

bool writeTimelineHtml(
    const std::string &path,
    const std::string &treePageName,
    const llvm::json::Object &vizData,
    std::string &error)
{
    llvm::json::Object payloadObject = vizData;
    const std::string payload = jsonValueToString(llvm::json::Value(std::move(payloadObject)));
    const std::string escapedTreePageName = escapeJsString(treePageName);

    std::ostringstream html;
    html << "<!doctype html>\n"
         << "<html lang=\"en\">\n"
         << "<head>\n"
         << "  <meta charset=\"utf-8\"/>\n"
         << "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>\n"
         << "  <title>Runtime Context Timeline</title>\n"
         << "  <style>\n"
         << "    :root { --bg:#0f131b; --panel:#151b25; --panel-2:#1b2433; --ink:#e6edf8; --muted:#95a3ba; --border:#2a3446; --grid:#263043; --split:#2f3b52; --label:#c7d2e5; }\n"
         << "    body { margin:0; font-family:'IBM Plex Sans','Segoe UI',sans-serif; background: radial-gradient(circle at 0% 0%, #1a2232 0%, #101622 42%, #0d121a 100%); color:var(--ink); }\n"
         << "    .wrap { max-width: 1420px; margin: 22px auto; padding: 0 14px; }\n"
         << "    .card { background: linear-gradient(180deg,var(--panel),#121925); border: 1px solid var(--border); border-radius: 14px; padding: 14px 14px 12px; box-shadow: 0 20px 40px rgba(4,8,14,0.65); }\n"
         << "    h1 { margin: 0 0 4px; font-size: 1.32rem; letter-spacing: 0.01em; display:flex; align-items:center; gap:8px; color:#f2f7ff; }\n"
         << "    .icon { display:inline-flex; align-items:center; justify-content:center; width:22px; height:22px; border-radius:5px; color:#fff; font-size:0.62rem; font-weight:700; box-shadow:0 4px 10px rgba(0,0,0,0.35); }\n"
         << "    .icon-tl { background: linear-gradient(135deg,#0ea5e9,#2563eb); }\n"
         << "    .icon-chip { display:inline-flex; align-items:center; gap:6px; border:1px solid #33425b; background:#172131; border-radius:999px; padding:3px 8px; color:#b8c6de; }\n"
         << "    .meta { color: #c0cde2; margin-bottom: 8px; font-size: 0.84rem; background:#172131; border:1px solid #33425b; border-radius: 999px; padding: 5px 10px; display:inline-block; }\n"
         << "    .axis-note { color: var(--muted); font-size: 0.78rem; margin: 2px 0 8px; text-transform: uppercase; letter-spacing: 0.04em; }\n"
         << "    .timeline-shell { border:1px solid var(--border); border-radius: 10px; overflow-x:auto; overflow-y:hidden; background:linear-gradient(180deg,#151d2a,#121923); }\n"
         << "    .timeline { position: relative; min-height: 276px; }\n"
         << "    .layout { display:grid; grid-template-columns: 220px 1fr; gap:12px; align-items:start; }\n"
         << "    .sidebar { border:1px solid var(--border); border-radius:10px; background:linear-gradient(180deg,#161f2e,#121925); padding:10px; }\n"
         << "    .sidebar-title { color:#d7e2f3; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.06em; margin-bottom:8px; }\n"
         << "    .sidebar-actions { display:flex; gap:6px; margin-bottom:8px; }\n"
         << "    .side-btn { border:1px solid #33425b; background:#172131; color:#c4d3ea; border-radius:7px; font-size:0.74rem; padding:4px 8px; cursor:pointer; }\n"
         << "    .side-btn:hover { background:#1c2a3f; }\n"
         << "    .ctx-row { display:flex; align-items:center; gap:8px; color:#bfcde4; font-size:0.8rem; margin:6px 0; }\n"
         << "    .ctx-row input { accent-color:#22d3ee; }\n"
         << "    .swatch { width:10px; height:10px; border-radius:2px; border:1px solid rgba(10,15,24,0.75); }\n"
         << "    .lane-bg { position:absolute; left:0; right:0; height:36px; background: linear-gradient(90deg,var(--panel-2),#172031); }\n"
         << "    .lane-label { position:absolute; left:10px; width:190px; font-size:0.78rem; color:var(--label); font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }\n"
         << "    .lane-line { position:absolute; left:202px; right:0; height:1px; background:var(--grid); }\n"
         << "    .y-split { position:absolute; top:0; bottom:0; left:200px; width:2px; background:var(--split); }\n"
         << "    .x-grid { position:absolute; top:0; bottom:0; width:1px; background:var(--grid); }\n"
         << "    .x-tick { position:absolute; top:4px; transform: translateX(-50%); font-size:0.7rem; color:#8e9db6; font-family:'IBM Plex Mono',monospace; }\n"
         << "    .bar { position:absolute; height:18px; cursor:pointer; border:1px solid rgba(10,15,24,0.75); box-shadow: 0 0 0 1px rgba(0,0,0,0.25), 0 4px 10px rgba(0,0,0,0.45); transition: transform .08s ease, filter .08s ease; }\n"
         << "    .bar:hover { transform: translateY(-1px); filter:brightness(1.08); }\n"
         << "    .cap-round-left { border-top-left-radius: 11px; border-bottom-left-radius: 11px; }\n"
         << "    .cap-round-right { border-top-right-radius: 11px; border-bottom-right-radius: 11px; }\n"
         << "    .cap-half-right { box-shadow: inset -6px 0 0 0 rgba(245,247,255,0.40); }\n"
         << "    .cap-half-left { box-shadow: inset 6px 0 0 0 rgba(245,247,255,0.40); }\n"
         << "    .legend { margin-top: 10px; color: var(--muted); font-size: 0.78rem; display:flex; gap:10px; align-items:center; flex-wrap:wrap; }\n"
         << "    .dot { display:inline-block; width:10px; height:10px; border-radius:2px; background: linear-gradient(90deg,#22d3ee,#60a5fa); border:1px solid rgba(10,15,24,0.75); margin-right:6px; }\n"
         << "    .warnings { margin-top: 8px; color: #fca5a5; font-size: 0.78rem; }\n"
         << "  </style>\n"
         << "</head>\n"
         << "<body>\n"
         << "  <div class=\"wrap\">\n"
         << "    <div class=\"card\">\n"
         << "      <h1><span class=\"icon icon-tl\">CDA</span>CDA Runtime Context Trace</h1>\n"
         << "      <div class=\"meta\" id=\"meta\"></div>\n"
         << "      <div class=\"axis-note\">CONTEXT LANES (Y) · EVENT INDEX TIMEBASE (X)</div>\n"
         << "      <div class=\"layout\">\n"
         << "        <div class=\"sidebar\"><div class=\"sidebar-title\">Contexts</div><div class=\"sidebar-actions\"><button id=\"ctxAll\" class=\"side-btn\" type=\"button\">Select all</button><button id=\"ctxNone\" class=\"side-btn\" type=\"button\">Clear all</button></div><div id=\"ctxList\"></div></div>\n"
         << "        <div class=\"timeline-shell\" id=\"shell\"><div class=\"timeline\" id=\"timeline\"></div></div>\n"
         << "      </div>\n"
         << "      <div class=\"legend\"><span class=\"icon-chip\"><span class=\"dot\"></span>Execution segment</span><span class=\"icon-chip\">Click segment for call tree</span></div>\n"
         << "      <div class=\"warnings\" id=\"warnings\"></div>\n"
         << "    </div>\n"
         << "  </div>\n"
         << "  <script id=\"runtime-data\" type=\"application/json\">" << payload << "</script>\n"
         << "  <script>\n"
         << "    (function(){\n"
         << "      const data = JSON.parse(document.getElementById('runtime-data').textContent);\n"
         << "      const shell = document.getElementById('shell');\n"
         << "      const timeline = document.getElementById('timeline');\n"
         << "      const meta = document.getElementById('meta');\n"
         << "      const warnings = document.getElementById('warnings');\n"
         << "      const ctxList = document.getElementById('ctxList');\n"
         << "      const ctxAll = document.getElementById('ctxAll');\n"
         << "      const ctxNone = document.getElementById('ctxNone');\n"
         << "      const contexts = Array.isArray(data.contexts) ? data.contexts : [];\n"
         << "      const eventCount = Math.max(1, Number(data.eventCount || 0));\n"
         << "      const entrypointPriority = Array.isArray(data.entrypointPriority) ? data.entrypointPriority.map(String) : [];\n"
         << "      const observedEntrypoints = new Set();\n"
         << "      for (const ctx of contexts) { observedEntrypoints.add(String(ctx.entrypoint || 'unknown')); }\n"
         << "      const entrypointOrder = [];\n"
         << "      const seenEntrypoints = new Set();\n"
         << "      for (const epRaw of entrypointPriority) {\n"
         << "        const ep = String(epRaw);\n"
         << "        if (observedEntrypoints.has(ep) && !seenEntrypoints.has(ep)) {\n"
         << "          seenEntrypoints.add(ep);\n"
         << "          entrypointOrder.push(ep);\n"
         << "        }\n"
         << "      }\n"
         << "      for (const ctx of contexts) {\n"
         << "        const ep = String(ctx.entrypoint || 'unknown');\n"
         << "        if (!seenEntrypoints.has(ep)) {\n"
         << "          seenEntrypoints.add(ep);\n"
         << "          entrypointOrder.push(ep);\n"
         << "        }\n"
         << "      }\n"
         << "      meta.textContent = `Context runs: ${contexts.length} | Entrypoints: ${entrypointOrder.length} | Events: ${eventCount}`;\n"
         << "      const treePageName = '" << escapedTreePageName << "';\n"
         << "      const barGradients = [\n"
         << "        'linear-gradient(90deg,#22d3ee,#60a5fa)',\n"
         << "        'linear-gradient(90deg,#34d399,#10b981)',\n"
         << "        'linear-gradient(90deg,#f59e0b,#f97316)',\n"
         << "        'linear-gradient(90deg,#f472b6,#a78bfa)',\n"
         << "        'linear-gradient(90deg,#84cc16,#14b8a6)'\n"
         << "      ];\n"
         << "      const laneHeight = 36;\n"
         << "      const topOffset = 24;\n"
         << "      const labelWidth = 200;\n"
         << "      const rightPad = 24;\n"
         << "      const enabledByEntrypoint = new Map();\n"
         << "      for (const ep of entrypointOrder) { enabledByEntrypoint.set(ep, true); }\n"
         << "      const colorIndexByEntrypoint = new Map();\n"
         << "      for (let i = 0; i < entrypointOrder.length; i += 1) {\n"
         << "        colorIndexByEntrypoint.set(entrypointOrder[i], i);\n"
         << "      }\n"
         << "      function clearTimeline() { while (timeline.firstChild) { timeline.removeChild(timeline.firstChild); } }\n"
         << "      function renderSidebar() {\n"
         << "        ctxList.innerHTML = '';\n"
         << "        for (let i = 0; i < entrypointOrder.length; i += 1) {\n"
         << "          const ep = entrypointOrder[i];\n"
         << "          const row = document.createElement('label');\n"
         << "          row.className = 'ctx-row';\n"
         << "          const cb = document.createElement('input');\n"
         << "          cb.type = 'checkbox';\n"
         << "          cb.checked = Boolean(enabledByEntrypoint.get(ep));\n"
         << "          cb.addEventListener('change', function(){\n"
         << "            enabledByEntrypoint.set(ep, cb.checked);\n"
         << "            render();\n"
         << "          });\n"
         << "          const swatch = document.createElement('span');\n"
         << "          swatch.className = 'swatch';\n"
         << "          swatch.style.background = barGradients[i % barGradients.length];\n"
         << "          const text = document.createElement('span');\n"
         << "          text.textContent = ep;\n"
         << "          row.appendChild(cb);\n"
         << "          row.appendChild(swatch);\n"
         << "          row.appendChild(text);\n"
         << "          ctxList.appendChild(row);\n"
         << "        }\n"
         << "      }\n"
         << "      function setAllEntrypoints(enabled) {\n"
         << "        for (const ep of entrypointOrder) {\n"
         << "          enabledByEntrypoint.set(ep, enabled);\n"
         << "        }\n"
         << "        renderSidebar();\n"
         << "        render();\n"
         << "      }\n"
         << "      function render() {\n"
         << "        clearTimeline();\n"
         << "        const visibleEntrypoints = entrypointOrder.filter(ep => enabledByEntrypoint.get(ep));\n"
         << "        const visibleLaneByEntrypoint = new Map();\n"
         << "        for (let i = 0; i < visibleEntrypoints.length; i += 1) {\n"
         << "          visibleLaneByEntrypoint.set(visibleEntrypoints[i], i);\n"
         << "        }\n"
         << "        const chartHeight = Math.max(160, topOffset + visibleEntrypoints.length * laneHeight + 20);\n"
         << "        const pxPerEvent = 18;\n"
         << "        const plotWidth = Math.max(760, eventCount * pxPerEvent);\n"
         << "        timeline.style.width = (labelWidth + plotWidth + rightPad) + 'px';\n"
         << "        timeline.style.height = chartHeight + 'px';\n"
         << "        const split = document.createElement('div');\n"
         << "        split.className = 'y-split';\n"
         << "        timeline.appendChild(split);\n"
         << "        for (let i = 0; i <= 10; i += 1) {\n"
         << "          const p = i / 10;\n"
         << "          const x = labelWidth + Math.round(plotWidth * p);\n"
         << "          const grid = document.createElement('div');\n"
         << "          grid.className = 'x-grid';\n"
         << "          grid.style.left = x + 'px';\n"
         << "          timeline.appendChild(grid);\n"
         << "          const tick = document.createElement('div');\n"
         << "          tick.className = 'x-tick';\n"
         << "          tick.style.left = x + 'px';\n"
         << "          tick.textContent = String(Math.round(eventCount * p));\n"
         << "          timeline.appendChild(tick);\n"
         << "        }\n"
         << "        for (let lane = 0; lane < visibleEntrypoints.length; lane += 1) {\n"
         << "          const rowTop = topOffset + lane * laneHeight;\n"
         << "          const laneBg = document.createElement('div');\n"
         << "          laneBg.className = 'lane-bg';\n"
         << "          laneBg.style.top = rowTop + 'px';\n"
         << "          timeline.appendChild(laneBg);\n"
         << "          const line = document.createElement('div');\n"
         << "          line.className = 'lane-line';\n"
         << "          line.style.top = (rowTop + 35) + 'px';\n"
         << "          timeline.appendChild(line);\n"
         << "          const label = document.createElement('div');\n"
         << "          label.className = 'lane-label';\n"
         << "          label.style.top = (rowTop + 9) + 'px';\n"
         << "          label.textContent = visibleEntrypoints[lane];\n"
         << "          timeline.appendChild(label);\n"
         << "        }\n"
         << "        for (const ctx of contexts) {\n"
         << "          const lane = visibleLaneByEntrypoint.get(String(ctx.entrypoint || 'unknown'));\n"
         << "          if (lane === undefined) { continue; }\n"
         << "          const rowTop = topOffset + lane * laneHeight;\n"
         << "          const segments = Array.isArray(ctx.segments) && ctx.segments.length > 0\n"
         << "            ? ctx.segments\n"
         << "            : [{ startEventIndex: ctx.startEventIndex, endEventIndex: ctx.endEventIndex, startsAtContextStart: true, endsAtContextEnd: true }];\n"
         << "          for (const segment of segments) {\n"
         << "            const start = Number(segment.startEventIndex || 0);\n"
         << "            const end = Math.max(start, Number(segment.endEventIndex || start));\n"
         << "            const left = labelWidth + Math.round((start / eventCount) * plotWidth);\n"
         << "            const width = Math.max(Math.round(((end - start + 1) / eventCount) * plotWidth), 3);\n"
         << "            const bar = document.createElement('div');\n"
         << "            bar.className = 'bar';\n"
         << "            if (segment.startsAtContextStart) { bar.classList.add('cap-round-left'); } else { bar.classList.add('cap-half-left'); }\n"
         << "            if (segment.endsAtContextEnd) { bar.classList.add('cap-round-right'); } else { bar.classList.add('cap-half-right'); }\n"
         << "            bar.style.top = (rowTop + 10) + 'px';\n"
         << "            bar.style.left = left + 'px';\n"
         << "            bar.style.width = width + 'px';\n"
         << "            const colorIndex = Number(colorIndexByEntrypoint.get(String(ctx.entrypoint || 'unknown')) || 0);\n"
         << "            bar.style.background = barGradients[colorIndex % barGradients.length];\n"
         << "            bar.title = `${ctx.entrypoint} #${ctx.ordinal} | events ${start}-${end}`;\n"
         << "            bar.addEventListener('click', function(){\n"
         << "              const url = treePageName\n"
         << "                + '?contextId=' + encodeURIComponent(ctx.contextId)\n"
         << "                + '&segmentStart=' + encodeURIComponent(String(start))\n"
         << "                + '&segmentEnd=' + encodeURIComponent(String(end));\n"
         << "              window.location.href = url;\n"
         << "            });\n"
         << "            timeline.appendChild(bar);\n"
         << "          }\n"
         << "        }\n"
         << "      }\n"
         << "      if (ctxAll) {\n"
         << "        ctxAll.addEventListener('click', function(){ setAllEntrypoints(true); });\n"
         << "      }\n"
         << "      if (ctxNone) {\n"
         << "        ctxNone.addEventListener('click', function(){ setAllEntrypoints(false); });\n"
         << "      }\n"
         << "      renderSidebar();\n"
         << "      render();\n"
         << "      shell.scrollLeft = Math.max(0, timeline.clientWidth - shell.clientWidth) > 0 ? 0 : shell.scrollLeft;\n"
         << "      if (Array.isArray(data.warnings) && data.warnings.length > 0) {\n"
         << "        warnings.textContent = 'Warnings: ' + data.warnings.join(' | ');\n"
         << "      }\n"
         << "    })();\n"
         << "  </script>\n"
         << "</body>\n"
         << "</html>\n";

    return writeHtmlFile(path, html.str(), error);
}

bool writeContextTreeHtml(
    const std::string &path,
    const std::string &timelinePageName,
    const llvm::json::Object &vizData,
    std::string &error)
{
    llvm::json::Object payloadObject = vizData;
    const std::string payload = jsonValueToString(llvm::json::Value(std::move(payloadObject)));
    const std::string escapedTimelinePageName = escapeJsString(timelinePageName);

    std::ostringstream html;
    html << "<!doctype html>\n"
         << "<html lang=\"en\">\n"
         << "<head>\n"
         << "  <meta charset=\"utf-8\"/>\n"
         << "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>\n"
         << "  <title>Runtime Context Call Tree</title>\n"
         << "  <style>\n"
         << "    :root { --bg:#0f131b; --panel:#151b25; --border:#2a3446; --node:#182130; --ink:#e6edf8; --muted:#95a3ba; --accent:#4cc9f0; --chip:#1a2536; }\n"
         << "    body { margin:0; font-family:'IBM Plex Sans','Segoe UI',sans-serif; background: radial-gradient(circle at top left,#1a2232,#0f131b 58%,#0c1017 100%); color:var(--ink); }\n"
         << "    .wrap { max-width: 1120px; margin: 24px auto; padding: 0 16px; }\n"
         << "    .card { background: linear-gradient(180deg,var(--panel),#111823); border:1px solid var(--border); border-radius:12px; padding:14px; box-shadow: 0 20px 40px rgba(4,8,14,0.65); }\n"
         << "    h1 { margin:4px 0 8px; font-size:1.34rem; letter-spacing:0.01em; display:flex; align-items:center; gap:8px; color:#f2f7ff; }\n"
         << "    .icon { display:inline-flex; align-items:center; justify-content:center; width:22px; height:22px; border-radius:5px; color:#fff; font-size:0.68rem; font-weight:700; box-shadow:0 4px 10px rgba(0,0,0,0.4); }\n"
         << "    .icon-tree { background: linear-gradient(135deg,#22d3ee,#2563eb); }\n"
         << "    .meta { color:var(--muted); margin-bottom:10px; font-size:0.82rem; background:var(--chip); border:1px solid #314058; border-radius:999px; padding:5px 10px; display:inline-block; }\n"
         << "    a.back { color:var(--accent); text-decoration:none; font-weight:600; font-size:0.84rem; display:inline-flex; align-items:center; gap:6px; }\n"
         << "    .tree { margin-top: 12px; }\n"
         << "    details { background: var(--node); border:1px solid #2f3c54; border-radius:8px; padding:8px 10px; margin:8px 0; }\n"
         << "    details[open] { box-shadow: inset 0 0 0 1px #38506f; }\n"
         << "    summary { cursor:pointer; font-weight:600; color:#d8e4f7; }\n"
         << "    summary:hover { color:#7dd3fc; }\n"
         << "    .leaf { margin: 6px 0 0 18px; color:#9fb0ca; font-size:0.81rem; font-family:'IBM Plex Mono',monospace; }\n"
         << "    .empty { color: var(--muted); padding: 12px 0; }\n"
         << "  </style>\n"
         << "</head>\n"
         << "<body>\n"
         << "  <div class=\"wrap\">\n"
         << "    <div class=\"card\">\n"
         << "      <a class=\"back\" id=\"back\" href=\"#\"><span class=\"icon icon-tree\" style=\"width:18px;height:18px;border-radius:4px;font-size:0.56rem;\">CDA</span>Back to timeline</a>\n"
         << "      <h1 id=\"title\"><span class=\"icon icon-tree\">CDA</span>Context Call Tree</h1>\n"
         << "      <div class=\"meta\" id=\"meta\"></div>\n"
         << "      <div class=\"tree\" id=\"tree\"></div>\n"
         << "    </div>\n"
         << "  </div>\n"
         << "  <script id=\"runtime-data\" type=\"application/json\">" << payload << "</script>\n"
         << "  <script>\n"
         << "    (function(){\n"
         << "      const data = JSON.parse(document.getElementById('runtime-data').textContent);\n"
         << "      const params = new URLSearchParams(window.location.search);\n"
         << "      const contextId = params.get('contextId') || '';\n"
         << "      const segmentStartParam = params.get('segmentStart');\n"
         << "      const segmentEndParam = params.get('segmentEnd');\n"
         << "      const hasSegmentRange = segmentStartParam !== null && segmentEndParam !== null;\n"
         << "      const segmentStart = hasSegmentRange ? Number(segmentStartParam) : 0;\n"
         << "      const segmentEnd = hasSegmentRange ? Number(segmentEndParam) : 0;\n"
         << "      const contexts = Array.isArray(data.contexts) ? data.contexts : [];\n"
         << "      const title = document.getElementById('title');\n"
         << "      const meta = document.getElementById('meta');\n"
         << "      const tree = document.getElementById('tree');\n"
         << "      const back = document.getElementById('back');\n"
         << "      back.setAttribute('href', '" << escapedTimelinePageName << "');\n"
         << "      const selected = contexts.find(c => c.contextId === contextId);\n"
         << "      if (!selected) {\n"
         << "        title.textContent = 'Context not found';\n"
         << "        meta.textContent = 'Provide a valid contextId from the timeline page.';\n"
         << "        tree.innerHTML = '<div class=\"empty\">No call data available for the requested context.</div>';\n"
         << "        return;\n"
         << "      }\n"
         << "      const allCalls = Array.isArray(selected.calls) ? selected.calls : [];\n"
         << "      const calls = hasSegmentRange\n"
         << "        ? allCalls.filter(c => {\n"
         << "            const e = Number(c.eventIndex || 0);\n"
         << "            return e >= segmentStart && e <= segmentEnd;\n"
         << "          })\n"
         << "        : allCalls;\n"
         << "      title.textContent = `${selected.entrypoint} #${selected.ordinal} call tree`;\n"
         << "      if (hasSegmentRange) {\n"
         << "        meta.textContent = `Segment ${segmentStart}-${segmentEnd} | shown calls ${calls.length} of ${allCalls.length}`;\n"
         << "      } else {\n"
         << "        meta.textContent = `Event range ${selected.startEventIndex}-${selected.endEventIndex} | calls ${allCalls.length}`;\n"
         << "      }\n"
         << "      if (!Array.isArray(calls) || calls.length === 0) {\n"
         << "        tree.innerHTML = '<div class=\"empty\">No calls recorded in this context.</div>';\n"
         << "        return;\n"
         << "      }\n"
         << "      const orderedCalls = [...calls].sort((a, b) => Number(a.eventIndex || 0) - Number(b.eventIndex || 0));\n"
         << "      const rootNode = { name: String(selected.entrypoint), children: [], line: null, eventIndex: null };\n"
         << "      const frameStack = [rootNode];\n"
         << "      function findCallerFrameIndex(callerName, callerDepth) {\n"
         << "        if (Number.isFinite(callerDepth) && callerDepth >= 0) {\n"
         << "          const depth = Math.floor(callerDepth);\n"
         << "          const byDepth = (frameStack.length - 1) - depth;\n"
         << "          if (byDepth >= 0 && byDepth < frameStack.length && frameStack[byDepth].name === callerName) {\n"
         << "            return byDepth;\n"
         << "          }\n"
         << "        }\n"
         << "        for (let i = frameStack.length - 1; i >= 0; i -= 1) {\n"
         << "          if (frameStack[i].name === callerName) {\n"
         << "            return i;\n"
         << "          }\n"
         << "        }\n"
         << "        return -1;\n"
         << "      }\n"
         << "      for (const call of orderedCalls) {\n"
         << "        const caller = String(call.caller || selected.entrypoint);\n"
         << "        const callerDepth = Number(call.callerDepth);\n"
         << "        let callerFrameIndex = findCallerFrameIndex(caller, callerDepth);\n"
         << "        if (callerFrameIndex < 0) {\n"
         << "          callerFrameIndex = 0;\n"
         << "          frameStack.length = 1;\n"
         << "        } else {\n"
         << "          frameStack.length = callerFrameIndex + 1;\n"
         << "        }\n"
         << "        const parent = frameStack[frameStack.length - 1];\n"
         << "        const node = {\n"
         << "          name: String(call.callee || '<unknown>'),\n"
         << "          children: [],\n"
         << "          line: Number(call.line || 0),\n"
         << "          eventIndex: Number(call.eventIndex || 0)\n"
         << "        };\n"
         << "        parent.children.push(node);\n"
         << "        frameStack.push(node);\n"
         << "      }\n"
         << "      function renderNode(node, host, depth) {\n"
         << "        const details = document.createElement('details');\n"
         << "        details.open = depth < 2;\n"
         << "        const summary = document.createElement('summary');\n"
         << "        summary.textContent = node.name;\n"
         << "        details.appendChild(summary);\n"
         << "        if (node.line !== null && node.eventIndex !== null) {\n"
         << "          const info = document.createElement('div');\n"
         << "          info.className = 'leaf';\n"
         << "          info.textContent = `line ${node.line}, event ${node.eventIndex}`;\n"
         << "          details.appendChild(info);\n"
         << "        }\n"
         << "        if (!Array.isArray(node.children) || node.children.length === 0) {\n"
         << "          host.appendChild(details);\n"
         << "          return;\n"
         << "        }\n"
         << "        for (const child of node.children) {\n"
         << "          renderNode(child, details, depth + 1);\n"
         << "        }\n"
         << "        host.appendChild(details);\n"
         << "      }\n"
         << "      renderNode(rootNode, tree, 0);\n"
         << "    })();\n"
         << "  </script>\n"
         << "</body>\n"
         << "</html>\n";

    return writeHtmlFile(path, html.str(), error);
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
