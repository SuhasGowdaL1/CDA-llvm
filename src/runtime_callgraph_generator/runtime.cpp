/**
 * @file runtime.cpp
 * @brief Implementation of runtime callgraph analysis and visualization functions.
 */

#include "runtime.h"

#include <algorithm>
#include <cctype>
#include <deque>
#include <fstream>
#include <limits>
#include <queue>
#include <sstream>

#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
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

bool EdgeKey::operator==(const EdgeKey &other) const
{
    return caller == other.caller && callee == other.callee;
}

std::size_t EdgeKeyHash::operator()(const EdgeKey &key) const
{
    const std::size_t h1 = std::hash<std::string>{}(key.caller);
    const std::size_t h2 = std::hash<std::string>{}(key.callee);
    return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6U) + (h1 >> 2U));
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
            line.resize(commentPos);
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
    constexpr std::size_t kProgressEveryLines = 10000U;
    while (std::getline(input, raw))
    {
        ++lineNo;
        if (lineNo % kProgressEveryLines == 0U)
        {
            llvm::errs() << "[runtime] parsed " << lineNo << " log lines, kept " << events.size() << " events\r";
        }

        const std::string token = trimCopy(raw);
        if (token.empty() || token[0] == '#')
        {
            continue;
        }

        Event event;
        event.lineNumber = lineNo;
        event.kind = EventKind::Plain;
        event.baseName = token;

        if (endsWith(token, "_entry"))
        {
            const std::string base = stripSuffix(token, "_entry");
            if (entrypoints.find(base) != entrypoints.end())
            {
                event.kind = EventKind::Entry;
                event.baseName = base;
                event.rawToken = token;
            }
        }
        else if (endsWith(token, "_exit"))
        {
            const std::string base = stripSuffix(token, "_exit");
            if (entrypoints.find(base) != entrypoints.end())
            {
                event.kind = EventKind::Exit;
                event.baseName = base;
                event.rawToken = token;
            }
        }

        events.push_back(std::move(event));
    }

    llvm::errs() << "[runtime] parsed " << lineNo << " log lines, kept " << events.size() << " events\n";

    return true;
}

bool loadStaticEdges(
    const std::string &callgraphPath,
    std::unordered_map<std::string, std::unordered_set<std::string>> &callersByCallee,
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
    const std::set<std::string> &blacklistedFunctions,
    std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction,
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

        struct CallSiteTarget
        {
            std::string callee;
        };

        std::unordered_map<std::string, CallSiteTarget> callSiteTargetById;
        callSiteTargetById.reserve(callSites->size());
        for (const llvm::json::Value &callSiteValue : *callSites)
        {
            const llvm::json::Object *callSiteObj = callSiteValue.getAsObject();
            if (callSiteObj == nullptr)
            {
                continue;
            }

            const std::optional<llvm::StringRef> callSiteId = callSiteObj->getString("callSiteId");
            if (!callSiteId.has_value() || callSiteId->empty())
            {
                continue;
            }

            const std::optional<llvm::StringRef> directCallee = callSiteObj->getString("directCallee");
            const std::optional<bool> isIndirect = callSiteObj->getBoolean("isIndirect");

            CallSiteTarget target;
            if (directCallee.has_value() && !directCallee->empty())
            {
                if (blacklistedFunctions.find(directCallee->str()) != blacklistedFunctions.end())
                {
                    continue;
                }
                target.callee = directCallee->str();
            }
            else if (isIndirect.value_or(false))
            {
                target.callee = "<indirect-call>";
            }
            else
            {
                continue;
            }

            callSiteTargetById[callSiteId->str()] = std::move(target);
        }

        RuntimeFunctionCfg functionCfg;
        const llvm::json::Array *blocks = functionObj->getArray("blocks");
        const std::optional<std::int64_t> entryBlockId = functionObj->getInteger("entryBlockId");
        const std::optional<std::int64_t> exitBlockId = functionObj->getInteger("exitBlockId");
        if (blocks == nullptr || !entryBlockId.has_value() || *entryBlockId < 0 || !exitBlockId.has_value() || *exitBlockId < 0)
        {
            error = "missing full CFG blocks/entryBlockId/exitBlockId for function: " + functionName->str();
            return false;
        }

        functionCfg.entryBlockId = static_cast<std::uint32_t>(*entryBlockId);
        functionCfg.exitBlockId = static_cast<std::uint32_t>(*exitBlockId);

        for (const llvm::json::Value &blockValue : *blocks)
        {
            const llvm::json::Object *blockObj = blockValue.getAsObject();
            if (blockObj == nullptr)
            {
                continue;
            }

            const std::optional<std::int64_t> blockId = blockObj->getInteger("id");
            if (!blockId.has_value() || *blockId < 0)
            {
                continue;
            }

            RuntimeCfgBlock block;
            block.id = static_cast<std::uint32_t>(*blockId);

            if (const llvm::json::Array *lineCallSiteIds = blockObj->getArray("lineCallSiteIds"))
            {
                std::unordered_set<std::string> seenCallSiteIds;
                seenCallSiteIds.reserve(lineCallSiteIds->size() * 2U + 1U);
                for (const llvm::json::Value &lineValue : *lineCallSiteIds)
                {
                    const llvm::json::Array *callSiteIds = lineValue.getAsArray();
                    if (callSiteIds == nullptr)
                    {
                        continue;
                    }

                    for (const llvm::json::Value &callSiteIdValue : *callSiteIds)
                    {
                        const std::optional<llvm::StringRef> callSiteId = callSiteIdValue.getAsString();
                        if (!callSiteId.has_value() || callSiteId->empty())
                        {
                            continue;
                        }

                        const std::string callSiteIdText = callSiteId->str();
                        if (!seenCallSiteIds.insert(callSiteIdText).second)
                        {
                            continue;
                        }

                        const auto targetIt = callSiteTargetById.find(callSiteIdText);
                        if (targetIt != callSiteTargetById.end())
                        {
                            block.callees.push_back(targetIt->second.callee);
                        }
                    }
                }
            }

            if (const llvm::json::Array *successors = blockObj->getArray("successors"))
            {
                for (const llvm::json::Value &successorValue : *successors)
                {
                    if (const std::optional<std::int64_t> successor = successorValue.getAsInteger())
                    {
                        if (*successor >= 0)
                        {
                            block.successors.push_back(static_cast<std::uint32_t>(*successor));
                        }
                    }
                }
                std::sort(block.successors.begin(), block.successors.end());
                block.successors.erase(std::unique(block.successors.begin(), block.successors.end()), block.successors.end());
            }

            functionCfg.blocks[block.id] = std::move(block);
        }

        if (functionCfg.blocks.empty() || functionCfg.blocks.find(functionCfg.entryBlockId) == functionCfg.blocks.end())
        {
            error = "invalid full CFG block graph for function: " + functionName->str();
            return false;
        }

        cfgByFunction[functionName->str()] = std::move(functionCfg);
    }

    return true;
}

// ============================================================================
// Path state management
// ============================================================================

namespace
{
    void computeEpsilonClosure(
        llvm::SmallVectorImpl<InferredFrame::ProgramPoint> &points,
        const RuntimeFunctionCfg &functionCfg);

    std::uint64_t encodeProgramPoint(const InferredFrame::ProgramPoint &point)
    {
        return (static_cast<std::uint64_t>(point.blockId) << 32U) |
               static_cast<std::uint64_t>(point.callIndex);
    }

    InferredFrame::ProgramPoint decodeProgramPoint(std::uint64_t encoded)
    {
        InferredFrame::ProgramPoint point;
        point.blockId = static_cast<std::uint32_t>(encoded >> 32U);
        point.callIndex = static_cast<std::uint32_t>(encoded & 0xFFFFFFFFULL);
        return point;
    }

    bool seedFrameForFunction(
        InferredFrame &frame,
        const std::string &functionName,
        const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction)
    {
        frame.functionName = functionName;
        frame.activePoints.clear();

        const auto cfgIt = cfgByFunction.find(functionName);
        if (cfgIt == cfgByFunction.end())
        {
            return false;
        }

        const RuntimeFunctionCfg &functionCfg = cfgIt->second;
        if (functionCfg.blocks.empty())
        {
            return false;
        }

        if (functionCfg.blocks.find(functionCfg.entryBlockId) == functionCfg.blocks.end())
        {
            return false;
        }

        frame.activePoints.push_back(InferredFrame::ProgramPoint{functionCfg.entryBlockId, 0U});
        frame.closureComputed = false;
        frame.tokenCacheValid = false;
        frame.lastCheckedToken.clear();
        frame.lastCheckedTokenFeasible = false;
        return true;
    }

    void ensureClosureComputed(
        InferredFrame &frame,
        const RuntimeFunctionCfg &functionCfg)
    {
        if (frame.closureComputed)
        {
            return;
        }

        computeEpsilonClosure(frame.activePoints, functionCfg);
        frame.closureComputed = true;
    }

    void normalizePoints(llvm::SmallVectorImpl<InferredFrame::ProgramPoint> &points)
    {
        std::sort(points.begin(), points.end());
        points.erase(std::unique(points.begin(), points.end(), [](const InferredFrame::ProgramPoint &lhs, const InferredFrame::ProgramPoint &rhs)
                                 { return lhs.blockId == rhs.blockId && lhs.callIndex == rhs.callIndex; }),
                     points.end());
    }

    void computeEpsilonClosure(
        llvm::SmallVectorImpl<InferredFrame::ProgramPoint> &points,
        const RuntimeFunctionCfg &functionCfg)
    {
        normalizePoints(points);

        llvm::DenseSet<std::uint64_t> visited;
        llvm::SmallVector<std::uint64_t, 16> queue;
        visited.reserve(points.size() * 2U + 1U);
        queue.reserve(points.size());
        for (const InferredFrame::ProgramPoint &point : points)
        {
            const std::uint64_t encoded = encodeProgramPoint(point);
            if (visited.insert(encoded).second)
            {
                queue.push_back(encoded);
            }
        }

        std::size_t queueIndex = 0U;
        while (queueIndex < queue.size())
        {
            const InferredFrame::ProgramPoint point = decodeProgramPoint(queue[queueIndex++]);

            const auto blockIt = functionCfg.blocks.find(point.blockId);
            if (blockIt == functionCfg.blocks.end())
            {
                continue;
            }

            const RuntimeCfgBlock &block = blockIt->second;
            const std::uint32_t callCount = static_cast<std::uint32_t>(block.callees.size());
            if (point.callIndex < callCount)
            {
                continue;
            }

            for (const std::uint32_t successor : block.successors)
            {
                if (functionCfg.blocks.find(successor) == functionCfg.blocks.end())
                {
                    continue;
                }

                const InferredFrame::ProgramPoint successorPoint{successor, 0U};
                const std::uint64_t encodedSuccessor = encodeProgramPoint(successorPoint);
                if (visited.insert(encodedSuccessor).second)
                {
                    queue.push_back(encodedSuccessor);
                }
            }
        }

        points.clear();
        points.reserve(visited.size());
        std::transform(
            visited.begin(),
            visited.end(),
            std::back_inserter(points),
            [](std::uint64_t encoded)
            { return decodeProgramPoint(encoded); });
        normalizePoints(points);
    }

    bool frameCanCallToken(
        InferredFrame &frame,
        const std::string &token,
        const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction)
    {
        if (frame.tokenCacheValid && frame.lastCheckedToken == token)
        {
            return frame.lastCheckedTokenFeasible;
        }

        const auto cfgIt = cfgByFunction.find(frame.functionName);
        if (cfgIt == cfgByFunction.end())
        {
            frame.tokenCacheValid = true;
            frame.lastCheckedToken = token;
            frame.lastCheckedTokenFeasible = false;
            return false;
        }

        const RuntimeFunctionCfg &functionCfg = cfgIt->second;
        ensureClosureComputed(frame, functionCfg);
        for (const InferredFrame::ProgramPoint &point : frame.activePoints)
        {
            const auto blockIt = functionCfg.blocks.find(point.blockId);
            if (blockIt == functionCfg.blocks.end())
            {
                continue;
            }

            const RuntimeCfgBlock &block = blockIt->second;
            if (point.callIndex >= block.callees.size())
            {
                continue;
            }

            const std::string &expectedCallee = block.callees[point.callIndex];
            if (expectedCallee == token || expectedCallee == "<indirect-call>")
            {
                frame.tokenCacheValid = true;
                frame.lastCheckedToken = token;
                frame.lastCheckedTokenFeasible = true;
                return true;
            }
        }

        frame.tokenCacheValid = true;
        frame.lastCheckedToken = token;
        frame.lastCheckedTokenFeasible = false;
        return false;
    }

    bool consumeTokenInFrame(
        InferredFrame &frame,
        const std::string &token,
        const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction)
    {
        const auto cfgIt = cfgByFunction.find(frame.functionName);
        if (cfgIt == cfgByFunction.end())
        {
            return false;
        }

        const RuntimeFunctionCfg &functionCfg = cfgIt->second;
        ensureClosureComputed(frame, functionCfg);

        llvm::SmallVector<InferredFrame::ProgramPoint, 8> nextPoints;
        for (const InferredFrame::ProgramPoint &point : frame.activePoints)
        {
            const auto blockIt = functionCfg.blocks.find(point.blockId);
            if (blockIt == functionCfg.blocks.end())
            {
                continue;
            }

            const RuntimeCfgBlock &block = blockIt->second;
            if (point.callIndex >= block.callees.size())
            {
                continue;
            }

            const std::string &expectedCallee = block.callees[point.callIndex];
            if (expectedCallee != token && expectedCallee != "<indirect-call>")
            {
                continue;
            }

            nextPoints.push_back(InferredFrame::ProgramPoint{point.blockId, point.callIndex + 1U});
        }

        if (nextPoints.empty())
        {
            return false;
        }

        computeEpsilonClosure(nextPoints, functionCfg);
        frame.activePoints = std::move(nextPoints);
        frame.closureComputed = true;
        frame.tokenCacheValid = false;
        frame.lastCheckedToken.clear();
        frame.lastCheckedTokenFeasible = false;
        return true;
    }
}

void cleanupInferredStack(PathState &path)
{
    while (path.explicitFrames.size() > path.contextStack.size())
    {
        path.explicitFrames.pop_back();
    }

    while (!path.inferredStack.empty() && path.inferredStack.back().explicitDepthAnchor > path.contextStack.size())
    {
        path.inferredStack.pop_back();
    }

    // Drop suspended states for contexts that no longer exist.
    path.suspendedInferredStacks.erase(
        std::remove_if(
            path.suspendedInferredStacks.begin(),
            path.suspendedInferredStacks.end(),
            [&](const SuspendedInferredStack &entry)
            { return entry.resumeDepth > path.contextStack.size(); }),
        path.suspendedInferredStacks.end());
}

void discardInferredFramesAtOrAboveDepth(PathState &path, std::size_t depth)
{
    if (depth < path.explicitFrames.size())
    {
        path.explicitFrames.resize(depth);
    }

    while (!path.inferredStack.empty() && path.inferredStack.back().explicitDepthAnchor >= depth)
    {
        path.inferredStack.pop_back();
    }
}

void suspendInferredFramesAtOrAboveDepth(PathState &path, std::size_t depth)
{
    cleanupInferredStack(path);

    std::size_t begin = path.inferredStack.size();
    while (begin > 0U)
    {
        const InferredFrame &frame = path.inferredStack[begin - 1U];
        if (frame.explicitDepthAnchor < depth)
        {
            break;
        }
        --begin;
    }

    if (begin == path.inferredStack.size())
    {
        return;
    }

    SuspendedInferredStack suspended;
    suspended.resumeDepth = depth;
    suspended.frames.assign(path.inferredStack.begin() + static_cast<std::ptrdiff_t>(begin), path.inferredStack.end());
    path.suspendedInferredStacks.push_back(std::move(suspended));
    path.inferredStack.resize(begin);
}

bool restoreSuspendedInferredFramesForDepth(PathState &path, std::size_t depth)
{
    cleanupInferredStack(path);

    for (std::size_t i = path.suspendedInferredStacks.size(); i > 0U; --i)
    {
        SuspendedInferredStack &candidate = path.suspendedInferredStacks[i - 1U];
        if (candidate.resumeDepth != depth)
        {
            continue;
        }

        path.inferredStack.insert(
            path.inferredStack.end(),
            candidate.frames.begin(),
            candidate.frames.end());
        path.suspendedInferredStacks.erase(path.suspendedInferredStacks.begin() + static_cast<std::ptrdiff_t>(i - 1U));
        return true;
    }

    return false;
}

std::vector<std::string> buildActiveCallerOrder(const PathState &path)
{
    std::vector<std::string> callers;
    callers.reserve(path.inferredStack.size() + path.explicitFrames.size());

    for (std::size_t i = path.inferredStack.size(); i > 0U; --i)
    {
        callers.push_back(path.inferredStack[i - 1U].functionName);
    }

    for (std::size_t i = path.explicitFrames.size(); i > 0U; --i)
    {
        callers.push_back(path.explicitFrames[i - 1U].functionName);
    }

    return callers;
}

std::vector<ActiveCaller> buildFeasibleActiveCallers(
    PathState &path,
    const std::string &token,
    const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction)
{
    cleanupInferredStack(path);

    std::vector<ActiveCaller> callers;
    callers.reserve(path.inferredStack.size() + path.explicitFrames.size());

    std::size_t depth = 0U;
    for (std::size_t i = path.inferredStack.size(); i > 0U; --i)
    {
        InferredFrame &frame = path.inferredStack[i - 1U];
        const bool isTopInferredFrame = (i == path.inferredStack.size());
        const bool mirrorsExplicitTop =
            isTopInferredFrame &&
            !path.explicitFrames.empty() &&
            frame.functionName == path.explicitFrames.back().functionName;

        // Entry-marked calls can create a mirrored inferred top frame for the same function.
        // Do not let that mirrored frame block attribution of sibling calls in the explicit frame.
        if (mirrorsExplicitTop)
        {
            ++depth;
            continue;
        }

        if (frameCanCallToken(frame, token, cfgByFunction))
        {
            callers.push_back(ActiveCaller{frame.functionName, true, i - 1U, depth});
        }

        const std::optional<std::size_t> remainingCalls = minimumRemainingCallsToExit(frame, cfgByFunction);
        if (!remainingCalls.has_value())
        {
            ++depth;
            continue;
        }

        if (*remainingCalls != 0U)
        {
            return callers;
        }
        ++depth;
    }

    if (!path.explicitFrames.empty())
    {
        InferredFrame &frame = path.explicitFrames.back();
        if (frameCanCallToken(frame, token, cfgByFunction))
        {
            callers.push_back(ActiveCaller{frame.functionName, false, path.explicitFrames.size() - 1U, depth});
        }
    }

    return callers;
}

void updateInferredStackAfterAssignment(
    PathState &path,
    const ActiveCaller &chosenCaller,
    const std::string &chosenCallee,
    const std::set<std::string> &entrypoints,
    const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction)
{
    cleanupInferredStack(path);

    if (chosenCaller.isInferred)
    {
        if (chosenCaller.frameIndex < path.inferredStack.size())
        {
            path.inferredStack.resize(chosenCaller.frameIndex + 1U);
        }
    }
    else
    {
        path.inferredStack.clear();
    }

    InferredFrame *callerFrame = nullptr;
    if (chosenCaller.isInferred)
    {
        if (chosenCaller.frameIndex < path.inferredStack.size())
        {
            callerFrame = &path.inferredStack[chosenCaller.frameIndex];
        }
    }
    else if (chosenCaller.frameIndex < path.explicitFrames.size())
    {
        callerFrame = &path.explicitFrames[chosenCaller.frameIndex];
    }

    if (callerFrame != nullptr)
    {
        (void)consumeTokenInFrame(*callerFrame, chosenCallee, cfgByFunction);
    }

    // Keep explicit-frame events authoritative: entrypoints with explicit markers should not be inferred.
    if (entrypoints.find(chosenCallee) != entrypoints.end())
    {
        return;
    }

    InferredFrame frame;
    if (!seedFrameForFunction(frame, chosenCallee, cfgByFunction))
    {
        return;
    }

    frame.functionName = chosenCallee;
    frame.explicitDepthAnchor = path.contextStack.size();
    path.inferredStack.push_back(std::move(frame));
}

std::optional<std::size_t> minimumRemainingCallsToExit(
    InferredFrame &frame,
    const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction)
{
    const auto cfgIt = cfgByFunction.find(frame.functionName);
    if (cfgIt == cfgByFunction.end())
    {
        return std::nullopt;
    }

    const RuntimeFunctionCfg &functionCfg = cfgIt->second;
    ensureClosureComputed(frame, functionCfg);

    using QueueEntry = std::pair<std::size_t, std::uint64_t>;
    std::priority_queue<QueueEntry, std::vector<QueueEntry>, std::greater<QueueEntry>> worklist;
    std::unordered_map<std::uint64_t, std::size_t> bestDistance;
    bestDistance.reserve(frame.activePoints.size() * 4U + 4U);

    for (const InferredFrame::ProgramPoint &point : frame.activePoints)
    {
        const std::uint64_t encoded = encodeProgramPoint(point);
        const auto inserted = bestDistance.emplace(encoded, 0U);
        if (inserted.second)
        {
            worklist.push({0U, encoded});
        }
    }

    while (!worklist.empty())
    {
        const QueueEntry current = worklist.top();
        worklist.pop();

        const auto bestIt = bestDistance.find(current.second);
        if (bestIt == bestDistance.end() || bestIt->second != current.first)
        {
            continue;
        }

        const InferredFrame::ProgramPoint point = decodeProgramPoint(current.second);
        const auto blockIt = functionCfg.blocks.find(point.blockId);
        if (blockIt == functionCfg.blocks.end())
        {
            continue;
        }

        const RuntimeCfgBlock &block = blockIt->second;
        const std::size_t callCount = block.callees.size();
        if (point.blockId == functionCfg.exitBlockId && static_cast<std::size_t>(point.callIndex) >= callCount)
        {
            return current.first;
        }

        if (static_cast<std::size_t>(point.callIndex) < callCount)
        {
            const InferredFrame::ProgramPoint nextPoint{point.blockId, point.callIndex + 1U};
            const std::uint64_t encodedNext = encodeProgramPoint(nextPoint);
            const std::size_t nextDistance = current.first + 1U;
            const auto nextIt = bestDistance.find(encodedNext);
            if (nextIt == bestDistance.end() || nextDistance < nextIt->second)
            {
                bestDistance[encodedNext] = nextDistance;
                worklist.push({nextDistance, encodedNext});
            }
            continue;
        }

        for (const std::uint32_t successor : block.successors)
        {
            if (functionCfg.blocks.find(successor) == functionCfg.blocks.end())
            {
                continue;
            }

            const InferredFrame::ProgramPoint nextPoint{successor, 0U};
            const std::uint64_t encodedNext = encodeProgramPoint(nextPoint);
            const auto nextIt = bestDistance.find(encodedNext);
            if (nextIt == bestDistance.end() || current.first < nextIt->second)
            {
                bestDistance[encodedNext] = current.first;
                worklist.push({current.first, encodedNext});
            }
        }
    }

    return std::nullopt;
}

std::vector<std::string> collectImmediateExpectedCallees(
    InferredFrame &frame,
    const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction)
{
    std::vector<std::string> expected;

    const auto cfgIt = cfgByFunction.find(frame.functionName);
    if (cfgIt == cfgByFunction.end())
    {
        return expected;
    }

    const RuntimeFunctionCfg &functionCfg = cfgIt->second;
    ensureClosureComputed(frame, functionCfg);
    for (const InferredFrame::ProgramPoint &point : frame.activePoints)
    {
        const auto blockIt = functionCfg.blocks.find(point.blockId);
        if (blockIt == functionCfg.blocks.end())
        {
            continue;
        }

        const RuntimeCfgBlock &block = blockIt->second;
        if (point.callIndex >= block.callees.size())
        {
            continue;
        }

        expected.push_back(block.callees[point.callIndex]);
    }

    std::sort(expected.begin(), expected.end());
    expected.erase(std::unique(expected.begin(), expected.end()), expected.end());
    return expected;
}

// ============================================================================
// Path analysis
// ============================================================================

namespace
{
    int compareProgramPoint(const InferredFrame::ProgramPoint &lhs, const InferredFrame::ProgramPoint &rhs)
    {
        if (lhs.blockId != rhs.blockId)
        {
            return lhs.blockId < rhs.blockId ? -1 : 1;
        }
        if (lhs.callIndex != rhs.callIndex)
        {
            return lhs.callIndex < rhs.callIndex ? -1 : 1;
        }
        return 0;
    }

    int compareFrameState(const InferredFrame &lhs, const InferredFrame &rhs)
    {
        if (lhs.functionName != rhs.functionName)
        {
            return lhs.functionName < rhs.functionName ? -1 : 1;
        }
        if (lhs.explicitDepthAnchor != rhs.explicitDepthAnchor)
        {
            return lhs.explicitDepthAnchor < rhs.explicitDepthAnchor ? -1 : 1;
        }

        const std::size_t pointCount = std::min(lhs.activePoints.size(), rhs.activePoints.size());
        for (std::size_t i = 0U; i < pointCount; ++i)
        {
            const int pointCompare = compareProgramPoint(lhs.activePoints[i], rhs.activePoints[i]);
            if (pointCompare != 0)
            {
                return pointCompare;
            }
        }

        if (lhs.activePoints.size() != rhs.activePoints.size())
        {
            return lhs.activePoints.size() < rhs.activePoints.size() ? -1 : 1;
        }

        return 0;
    }

    int compareFrameLists(const std::vector<InferredFrame> &lhs, const std::vector<InferredFrame> &rhs)
    {
        const std::size_t frameCount = std::min(lhs.size(), rhs.size());
        for (std::size_t i = 0U; i < frameCount; ++i)
        {
            const int frameCompare = compareFrameState(lhs[i], rhs[i]);
            if (frameCompare != 0)
            {
                return frameCompare;
            }
        }

        if (lhs.size() != rhs.size())
        {
            return lhs.size() < rhs.size() ? -1 : 1;
        }

        return 0;
    }

    int compareSuspendedStacks(const std::vector<SuspendedInferredStack> &lhs, const std::vector<SuspendedInferredStack> &rhs)
    {
        const std::size_t count = std::min(lhs.size(), rhs.size());
        for (std::size_t i = 0U; i < count; ++i)
        {
            if (lhs[i].resumeDepth != rhs[i].resumeDepth)
            {
                return lhs[i].resumeDepth < rhs[i].resumeDepth ? -1 : 1;
            }

            const int frameCompare = compareFrameLists(lhs[i].frames, rhs[i].frames);
            if (frameCompare != 0)
            {
                return frameCompare;
            }
        }

        if (lhs.size() != rhs.size())
        {
            return lhs.size() < rhs.size() ? -1 : 1;
        }

        return 0;
    }
}

bool pathTieBreakerLess(const PathState &lhs, const PathState &rhs)
{
    const std::size_t assignmentCount = std::min(lhs.assignments.size(), rhs.assignments.size());
    for (std::size_t i = 0U; i < assignmentCount; ++i)
    {
        if (lhs.assignments[i].chosenCaller != rhs.assignments[i].chosenCaller)
        {
            return lhs.assignments[i].chosenCaller < rhs.assignments[i].chosenCaller;
        }
        if (lhs.assignments[i].token != rhs.assignments[i].token)
        {
            return lhs.assignments[i].token < rhs.assignments[i].token;
        }
        if (lhs.assignments[i].chosenCallerDepth != rhs.assignments[i].chosenCallerDepth)
        {
            if (!lhs.assignments[i].chosenCallerDepth.has_value())
            {
                return true;
            }
            if (!rhs.assignments[i].chosenCallerDepth.has_value())
            {
                return false;
            }
            return *lhs.assignments[i].chosenCallerDepth < *rhs.assignments[i].chosenCallerDepth;
        }
    }

    if (lhs.assignments.size() != rhs.assignments.size())
    {
        return lhs.assignments.size() < rhs.assignments.size();
    }

    const std::size_t stackCount = std::min(lhs.contextStack.size(), rhs.contextStack.size());
    for (std::size_t i = 0U; i < stackCount; ++i)
    {
        if (lhs.contextStack[i] != rhs.contextStack[i])
        {
            return lhs.contextStack[i] < rhs.contextStack[i];
        }
    }

    if (lhs.contextStack.size() != rhs.contextStack.size())
    {
        return lhs.contextStack.size() < rhs.contextStack.size();
    }

    const int inferredCompare = compareFrameLists(lhs.inferredStack, rhs.inferredStack);
    if (inferredCompare != 0)
    {
        return inferredCompare < 0;
    }

    const int explicitCompare = compareFrameLists(lhs.explicitFrames, rhs.explicitFrames);
    if (explicitCompare != 0)
    {
        return explicitCompare < 0;
    }

    const int suspendedCompare = compareSuspendedStacks(lhs.suspendedInferredStacks, rhs.suspendedInferredStacks);
    if (suspendedCompare != 0)
    {
        return suspendedCompare < 0;
    }

    return false;
}

void mergeEquivalentPathStates(std::vector<PathState> &paths)
{
    if (paths.size() < 2U)
    {
        return;
    }

    const auto stateLess = [](const PathState &lhs, const PathState &rhs)
    {
        return pathTieBreakerLess(lhs, rhs);
    };

    std::sort(paths.begin(), paths.end(), [&](const PathState &lhs, const PathState &rhs)
              {
        if (stateLess(lhs, rhs))
        {
            return true;
        }
        if (stateLess(rhs, lhs))
        {
            return false;
        }
        if (lhs.score != rhs.score)
        {
            return lhs.score < rhs.score;
        }
        return false; });

    auto isSameState = [&](const PathState &lhs, const PathState &rhs)
    {
        return !stateLess(lhs, rhs) && !stateLess(rhs, lhs);
    };

    std::vector<PathState> merged;
    merged.reserve(paths.size());
    std::size_t i = 0U;
    while (i < paths.size())
    {
        std::size_t bestIndex = i;
        std::size_t j = i + 1U;
        while (j < paths.size() && isSameState(paths[i], paths[j]))
        {
            if (paths[j].score < paths[bestIndex].score)
            {
                bestIndex = j;
            }
            ++j;
        }

        merged.push_back(std::move(paths[bestIndex]));
        i = j;
    }

    paths = std::move(merged);
}

void pruneTopK(std::vector<PathState> &paths, std::size_t topK)
{
    if (paths.size() <= topK)
    {
        std::sort(paths.begin(), paths.end(), [](const PathState &lhs, const PathState &rhs)
                  {
            if (lhs.score != rhs.score)
            {
                return lhs.score < rhs.score;
            }
            return pathTieBreakerLess(lhs, rhs); });
        return;
    }

    const auto cmp = [](const PathState &lhs, const PathState &rhs)
    {
        if (lhs.score != rhs.score)
        {
            return lhs.score < rhs.score;
        }
        return pathTieBreakerLess(lhs, rhs);
    };

    std::nth_element(paths.begin(), paths.begin() + static_cast<std::ptrdiff_t>(topK), paths.end(), cmp);
    paths.resize(topK);
    std::sort(paths.begin(), paths.end(), cmp);
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
    std::copy(
        assignment.candidates.begin(),
        assignment.candidates.end(),
        std::back_inserter(candidates));
    object["candidates"] = std::move(candidates);
    return object;
}

llvm::json::Object pathToJson(const PathState &path, std::size_t rank)
{
    llvm::json::Object object;
    object["rank"] = static_cast<std::int64_t>(rank);
    object["score"] = path.score;

    llvm::json::Array edges;
    std::vector<std::pair<EdgeKey, std::size_t>> sortedEdges;
    sortedEdges.reserve(path.edgeCounts.size());
    std::transform(
        path.edgeCounts.begin(),
        path.edgeCounts.end(),
        std::back_inserter(sortedEdges),
        [](const auto &entry)
        { return std::make_pair(entry.first, entry.second); });
    std::sort(sortedEdges.begin(), sortedEdges.end(), [](const auto &lhs, const auto &rhs)
              {
        if (lhs.first.caller != rhs.first.caller)
        {
            return lhs.first.caller < rhs.first.caller;
        }
        if (lhs.first.callee != rhs.first.callee)
        {
            return lhs.first.callee < rhs.first.callee;
        }
        return lhs.second < rhs.second; });

    for (const std::pair<EdgeKey, std::size_t> &entry : sortedEdges)
    {
        llvm::json::Object edge;
        edge["caller"] = entry.first.caller;
        edge["callee"] = entry.first.callee;
        edge["count"] = static_cast<std::int64_t>(entry.second);
        edges.push_back(std::move(edge));
    }
    object["edges"] = std::move(edges);

    llvm::json::Array assignments;
    std::transform(
        path.assignments.begin(),
        path.assignments.end(),
        std::back_inserter(assignments),
        [](const Assignment &assignment)
        { return assignmentToJson(assignment); });
    object["assignments"] = std::move(assignments);

    llvm::json::Array warnings;
    std::copy(
        path.warnings.begin(),
        path.warnings.end(),
        std::back_inserter(warnings));
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
    std::transform(
        run.calls.begin(),
        run.calls.end(),
        std::back_inserter(calls),
        [](const ContextCall &call)
        { return contextCallToJson(call); });
    object["calls"] = std::move(calls);

    llvm::json::Array warnings;
    std::copy(
        run.warnings.begin(),
        run.warnings.end(),
        std::back_inserter(warnings));
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
    std::copy(
        entrypointPriority.begin(),
        entrypointPriority.end(),
        std::back_inserter(priority));
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
        laneByEntrypoint.try_emplace(run.entrypoint, laneByEntrypoint.size());
    }
    for (std::size_t lane = 0U; lane < runs.size(); ++lane)
    {
        const auto laneIt = laneByEntrypoint.find(runs[lane].entrypoint);
        const std::size_t stableLane = laneIt != laneByEntrypoint.end() ? laneIt->second : lane;
        contexts.push_back(contextRunToJson(runs[lane], stableLane));
    }
    root["contexts"] = std::move(contexts);

    llvm::json::Array ws;
    std::copy(
        warnings.begin(),
        warnings.end(),
        std::back_inserter(ws));
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
         << "    :root { --bg:#0f131b; --panel:#151b25; --panel-2:#1b2433; --ink:#e6edf8; --muted:#95a3ba; --border:#2a3446; --grid:#263043; --split:#2f3b52; --label:#c7d2e5; --label-col:240px; }\n"
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
         << "    .ctx-row { display:flex; align-items:center; gap:8px; color:#bfcde4; font-size:0.8rem; margin:0; height:36px; box-sizing:border-box; border-bottom:1px solid rgba(38,48,67,0.35); white-space:nowrap; overflow:hidden; }\n"
         << "    .ctx-row input { accent-color:#22d3ee; }\n"
         << "    .ctx-label { overflow:hidden; text-overflow:ellipsis; }\n"
         << "    #ctxList { padding-top:0; }\n"
         << "    .swatch { width:10px; height:10px; border-radius:2px; border:1px solid rgba(232,241,255,0.55); box-shadow:0 0 0 1px rgba(10,15,24,0.5); }\n"
         << "    .lane-bg { position:absolute; left:0; right:0; height:36px; background: linear-gradient(90deg,var(--panel-2),#172031); }\n"
         << "    .lane-label { position:absolute; left:12px; width:var(--label-col); font-size:0.78rem; color:var(--label); font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }\n"
         << "    .lane-line { position:absolute; left:calc(var(--label-col) + 24px); right:0; height:1px; background:var(--grid); }\n"
         << "    .y-split { position:absolute; top:0; bottom:0; left:calc(var(--label-col) + 22px); width:2px; background:var(--split); }\n"
         << "    .x-grid { position:absolute; top:0; bottom:0; width:1px; background:var(--grid); }\n"
         << "    .x-tick { position:absolute; top:4px; transform: translateX(-50%); font-size:0.7rem; color:#8e9db6; font-family:'IBM Plex Mono',monospace; }\n"
         << "    .bar { position:absolute; height:18px; cursor:pointer; border:1px solid rgba(232,241,255,0.52); box-shadow: inset 0 0 0 1px rgba(8,12,20,0.35), 0 0 0 1px rgba(0,0,0,0.25), 0 4px 10px rgba(0,0,0,0.45); transition: transform .08s ease, filter .08s ease; }\n"
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
         << "      function colorForEntrypoint(index) {\n"
         << "        let hueA = (index * 137.508) % 360;\n"
         << "        if (hueA >= 200 && hueA <= 245) { hueA = (hueA + 72) % 360; }\n"
         << "        const hueB = (hueA + 28) % 360;\n"
         << "        return {\n"
         << "          bar: `linear-gradient(90deg,hsl(${hueA} 90% 64%),hsl(${hueB} 88% 54%))`,\n"
         << "          label: `hsl(${hueA} 90% 82%)`\n"
         << "        };\n"
         << "      }\n"
         << "      const laneHeight = 36;\n"
         << "      const rightPad = 24;\n"
         << "      const enabledByEntrypoint = new Map();\n"
         << "      for (const ep of entrypointOrder) { enabledByEntrypoint.set(ep, true); }\n"
         << "      const colorsByEntrypoint = new Map();\n"
         << "      for (let i = 0; i < entrypointOrder.length; i += 1) {\n"
         << "        colorsByEntrypoint.set(entrypointOrder[i], colorForEntrypoint(i));\n"
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
         << "          const colors = colorsByEntrypoint.get(ep) || colorForEntrypoint(i);\n"
         << "          swatch.style.background = colors.bar;\n"
         << "          const text = document.createElement('span');\n"
         << "          text.className = 'ctx-label';\n"
         << "          text.textContent = ep;\n"
         << "          text.title = ep;\n"
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
         << "        const listTop = ctxList ? ctxList.getBoundingClientRect().top : 0;\n"
         << "        const timelineTop = timeline.getBoundingClientRect().top;\n"
         << "        const topOffset = Math.max(0, Math.round(listTop - timelineTop));\n"
         << "        const labelWidth = 0;\n"
         << "        const plotOriginX = labelWidth + 24;\n"
         << "        timeline.style.setProperty('--label-col', labelWidth + 'px');\n"
         << "        const visibleEntrypoints = entrypointOrder;\n"
         << "        const visibleLaneByEntrypoint = new Map();\n"
         << "        for (let i = 0; i < visibleEntrypoints.length; i += 1) {\n"
         << "          visibleLaneByEntrypoint.set(visibleEntrypoints[i], i);\n"
         << "        }\n"
         << "        const chartHeight = Math.max(160, topOffset + visibleEntrypoints.length * laneHeight + 20);\n"
         << "        const pxPerEvent = eventCount > 800 ? 3 : (eventCount > 400 ? 5 : (eventCount > 200 ? 7 : 11));\n"
         << "        const plotWidth = Math.max(760, eventCount * pxPerEvent);\n"
         << "        timeline.style.width = (labelWidth + plotWidth + rightPad) + 'px';\n"
         << "        timeline.style.height = chartHeight + 'px';\n"
         << "        const split = document.createElement('div');\n"
         << "        split.className = 'y-split';\n"
         << "        timeline.appendChild(split);\n"
         << "        for (let i = 0; i <= 10; i += 1) {\n"
         << "          const p = i / 10;\n"
         << "          const x = plotOriginX + Math.round(plotWidth * p);\n"
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
         << "        }\n"
         << "        for (const ctx of contexts) {\n"
         << "          if (!enabledByEntrypoint.get(String(ctx.entrypoint || 'unknown'))) { continue; }\n"
         << "          const lane = visibleLaneByEntrypoint.get(String(ctx.entrypoint || 'unknown'));\n"
         << "          if (lane === undefined) { continue; }\n"
         << "          const rowTop = topOffset + lane * laneHeight;\n"
         << "          const segments = Array.isArray(ctx.segments) && ctx.segments.length > 0\n"
         << "            ? ctx.segments\n"
         << "            : [{ startEventIndex: ctx.startEventIndex, endEventIndex: ctx.endEventIndex, startsAtContextStart: true, endsAtContextEnd: true }];\n"
         << "          for (const segment of segments) {\n"
         << "            const start = Number(segment.startEventIndex || 0);\n"
         << "            const end = Math.max(start, Number(segment.endEventIndex || start));\n"
         << "            const left = plotOriginX + Math.round((start / eventCount) * plotWidth);\n"
         << "            const width = Math.max(Math.round(((end - start + 1) / eventCount) * plotWidth), 3);\n"
         << "            const bar = document.createElement('div');\n"
         << "            bar.className = 'bar';\n"
         << "            if (segment.startsAtContextStart) { bar.classList.add('cap-round-left'); } else { bar.classList.add('cap-half-left'); }\n"
         << "            if (segment.endsAtContextEnd) { bar.classList.add('cap-round-right'); } else { bar.classList.add('cap-half-right'); }\n"
         << "            bar.style.top = (rowTop + 10) + 'px';\n"
         << "            bar.style.left = left + 'px';\n"
         << "            bar.style.width = width + 'px';\n"
         << "            const colors = colorsByEntrypoint.get(String(ctx.entrypoint || 'unknown')) || colorForEntrypoint(0);\n"
         << "            bar.style.background = colors.bar;\n"
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
         << "      window.addEventListener('resize', render);\n"
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
    const std::unordered_set<std::string> &nodes,
    const std::unordered_map<EdgeKey, std::size_t, EdgeKeyHash> &edgeCounts,
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

    std::vector<std::string> sortedNodes(nodes.begin(), nodes.end());
    std::sort(sortedNodes.begin(), sortedNodes.end());
    for (const std::string &node : sortedNodes)
    {
        out << "  \"" << escapeDot(node) << "\";\n";
    }

    std::vector<std::pair<EdgeKey, std::size_t>> sortedEdges;
    sortedEdges.reserve(edgeCounts.size());
    std::transform(
        edgeCounts.begin(),
        edgeCounts.end(),
        std::back_inserter(sortedEdges),
        [](const auto &entry)
        { return std::make_pair(entry.first, entry.second); });
    std::sort(sortedEdges.begin(), sortedEdges.end(), [](const auto &lhs, const auto &rhs)
              {
        if (lhs.first.caller != rhs.first.caller)
        {
            return lhs.first.caller < rhs.first.caller;
        }
        if (lhs.first.callee != rhs.first.callee)
        {
            return lhs.first.callee < rhs.first.callee;
        }
        return lhs.second < rhs.second; });

    for (const std::pair<EdgeKey, std::size_t> &entry : sortedEdges)
    {
        out << "  \"" << escapeDot(entry.first.caller) << "\" -> \"" << escapeDot(entry.first.callee)
            << "\" [label=\"" << entry.second << "\"];\n";
    }

    out << "}\n";
    return true;
}
