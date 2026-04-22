/**
 * @file runtime.h
 * @brief Core data structures and analysis functions for runtime callgraph generation.
 */

#ifndef RUNTIME_H
#define RUNTIME_H

#include <memory>
#include <map>
#include <limits>
#include <optional>
#include <set>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/JSON.h"

/**
 * @brief Event kind markers from runtime logs.
 */
enum class EventKind
{
    Entry,
    Exit,
    Plain
};

/**
 * @brief Parsed runtime log event.
 */
struct Event
{
    std::size_t lineNumber = 0U;
    std::string rawToken;
    EventKind kind = EventKind::Plain;
    std::string baseName;
};

/**
 * @brief Hashable call graph edge (caller -> callee).
 */
struct EdgeKey
{
    std::string caller;
    std::string callee;

    bool operator<(const EdgeKey &other) const;
    bool operator==(const EdgeKey &other) const;
};

struct EdgeKeyHash
{
    std::size_t operator()(const EdgeKey &key) const;
};

/**
 * @brief Resolved assignment of a token to a caller.
 */
struct Assignment
{
    std::size_t eventIndex = 0U;
    std::size_t lineNumber = 0U;
    std::string contextId;
    std::string token;
    std::shared_ptr<const std::vector<std::string>> candidates;
    std::string chosenCaller;
    std::optional<std::size_t> chosenCallerDepth;
    bool ambiguous = false;
    bool usedStaticEdge = false;
    double deltaScore = 0.0;
    bool entersContext = false;
    std::string relatedContextId;
};

/**
 * @brief Inferred stack frame for unreported intermediate calls.
 */
struct InferredFrame
{
    std::string functionName;
    std::uint32_t functionId = std::numeric_limits<std::uint32_t>::max();
    struct ProgramPoint
    {
        std::uint32_t blockId = 0U;
        std::uint32_t callIndex = 0U;

        bool operator<(const ProgramPoint &other) const
        {
            if (blockId != other.blockId)
            {
                return blockId < other.blockId;
            }
            return callIndex < other.callIndex;
        }
    };

    llvm::SmallVector<ProgramPoint, 4> activePoints;
    bool closureComputed = false;
    bool tokenCacheValid = false;
    std::uint32_t lastCheckedTokenId = std::numeric_limits<std::uint32_t>::max();
    std::string lastCheckedToken;
    bool lastCheckedTokenFeasible = false;
    bool remainingCallsCacheValid = false;
    std::optional<std::size_t> cachedRemainingCallsToExit;
    std::size_t explicitDepthAnchor = 0U;
};

/**
 * @brief Inferred-frame suffix suspended when an entrypoint interrupts a context.
 */
struct SuspendedInferredStack
{
    std::size_t resumeDepth = 0U;
    std::vector<InferredFrame> frames;
};

/**
 * @brief Basic-block CFG details for one function.
 */
struct RuntimeCfgBlock
{
    std::uint32_t id = 0U;
    std::vector<std::string> callees;
    std::vector<std::uint32_t> successors;
};

/**
 * @brief Runtime-call matching model derived from CFG analysis.
 */
struct RuntimeFunctionCfg
{
    std::uint32_t entryBlockId = 0U;
    std::uint32_t exitBlockId = 0U;
    llvm::DenseMap<std::uint32_t, RuntimeCfgBlock> blocks;
};

/**
 * @brief Active caller frame descriptor used during one token assignment.
 */
struct ActiveCaller
{
    std::uint32_t functionId = std::numeric_limits<std::uint32_t>::max();
    bool isInferred = false;
    std::size_t frameIndex = 0U;
    std::size_t depth = 0U;
};

/**
 * @brief One assignment in a shared packed history chain.
 */
struct PackedAssignmentNode
{
    Assignment assignment;
    std::shared_ptr<const PackedAssignmentNode> previous;
    std::size_t length = 0U;
    std::uint64_t fingerprint = 0U;
};

/**
 * @brief One concrete assignment history packed under a shared future state.
 */
struct PackedPathVariant
{
    std::shared_ptr<const PackedAssignmentNode> tail;
    mutable std::shared_ptr<const std::vector<Assignment>> materializedAssignments;
    double score = 0.0;
};

/**
 * @brief Candidate path state during trace reconstruction.
 */
struct PathState
{
    std::vector<std::string> contextStack;
    std::vector<InferredFrame> explicitFrames;
    std::vector<InferredFrame> inferredStack;
    std::vector<SuspendedInferredStack> suspendedInferredStacks;
    std::unordered_map<EdgeKey, std::size_t, EdgeKeyHash> edgeCounts;
    std::unordered_set<std::string> nodes;
    std::vector<Assignment> assignments;
    std::vector<PackedPathVariant> packedVariants;
    std::vector<std::string> warnings;
    double score = 0.0;
};

/**
 * @brief Call edge within a context segment.
 */
struct ContextCall
{
    std::size_t eventIndex = 0U;
    std::size_t lineNumber = 0U;
    std::string caller;
    std::optional<std::size_t> callerDepth;
    std::string callee;
    bool ambiguous = false;
    bool usedStaticEdge = false;
    double deltaScore = 0.0;
    bool entersContext = false;
    std::string relatedContextId;
};

/**
 * @brief Continuous execution segment for a context.
 */
struct ContextSegment
{
    std::size_t startEventIndex = 0U;
    std::size_t endEventIndex = 0U;
    bool startsAtContextStart = false;
    bool endsAtContextEnd = false;
};

/**
 * @brief Temporal marker for context entry/exit/interruption boundaries.
 */
struct ContextTemporalPoint
{
    std::size_t eventIndex = 0U;
    std::string kind;
    std::string relatedContextId;
};

/**
 * @brief A single invocation of an entrypoint.
 */
struct ContextRun
{
    std::string contextId;
    std::string entrypoint;
    std::string parentContextId;
    std::vector<std::string> childContextIds;
    std::size_t ordinal = 0U;
    std::size_t startEventIndex = 0U;
    std::size_t endEventIndex = 0U;
    std::vector<std::size_t> ownedEventIndices;
    std::vector<ContextSegment> executionSegments;
    std::vector<ContextTemporalPoint> temporalPoints;
    std::vector<ContextCall> calls;
    std::vector<std::string> warnings;
};

std::vector<ContextRun> preprocessContextRuns(
    const std::vector<Event> &events,
    const std::set<std::string> &entrypoints,
    std::vector<std::string> &warnings);

struct RuntimeAnalysisOptions
{
    std::size_t topK = 8U;
    std::size_t lookaheadPlainEvents = 8U;
    std::size_t contextJobs = 0U;
};

struct RuntimeFailureExample
{
    std::string reason;
    double score = 0.0;
    std::string contextSummary;
    std::string activeCallerSummary;
    std::string assignmentSummary;
};

struct ContextAnalysisResult
{
    ContextRun run;
    std::vector<PathState> candidatePaths;
    std::size_t localEventCount = 0U;
    std::size_t processedEventCount = 0U;
    std::size_t pathExpansionCount = 1U;
    std::size_t effectiveLookaheadPlainEvents = 0U;
    std::size_t lookaheadEligibleAmbiguityCount = 0U;
    std::size_t lookaheadResolvedAmbiguityCount = 0U;
    std::size_t failureEventIndex = static_cast<std::size_t>(-1);
    Event failureEvent;
    std::unordered_map<std::string, std::size_t> failureReasons;
    std::vector<RuntimeFailureExample> failureExamples;
};

struct RuntimeAnalysisResult
{
    std::vector<ContextAnalysisResult> contexts;
    std::vector<ContextRun> bestContextRuns;
    std::vector<PathState> candidatePaths;
    std::vector<std::vector<std::size_t>> candidateSelections;
    std::size_t processedEventCount = 0U;
    std::size_t pathExpansionCount = 0U;
};

// String utilities
std::string trimCopy(const std::string &text);
bool endsWith(const std::string &text, const std::string &suffix);
std::string stripSuffix(const std::string &text, const std::string &suffix);
std::string escapeJsString(const std::string &value);
std::string sanitizeForScriptTag(const std::string &jsonText);
std::string jsonValueToString(const llvm::json::Value &value);
std::string fileNameFromPath(const std::string &path);

// File I/O and parsing
bool loadNameList(
    const std::string &path,
    std::set<std::string> &names,
    std::vector<std::string> &orderedNames,
    std::string &error);

bool parseEvents(
    const std::string &logPath,
    const std::set<std::string> &entrypoints,
    std::vector<Event> &events,
    std::string &error);

bool loadStaticEdges(
    const std::string &callgraphPath,
    std::unordered_map<std::string, std::unordered_set<std::string>> &callersByCallee,
    std::string &error);

bool loadCfgDirectCallOrder(
    const std::string &cfgAnalysisPath,
    const std::set<std::string> &blacklistedFunctions,
    std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction,
    std::string &error);

bool analyzeContexts(
    const std::vector<Event> &events,
    const std::vector<ContextRun> &runs,
    const std::set<std::string> &entrypoints,
    const std::unordered_map<std::string, std::unordered_set<std::string>> &callersByCallee,
    const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction,
    const RuntimeAnalysisOptions &options,
    RuntimeAnalysisResult &result,
    std::string &error);

// Path state management
void cleanupInferredStack(PathState &path);
std::vector<std::string> buildActiveCallerOrder(const PathState &path);
llvm::SmallVector<ActiveCaller, 4> buildFeasibleActiveCallers(
    PathState &path,
    const std::string &token,
    const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction);

void updateInferredStackAfterAssignment(
    PathState &path,
    const ActiveCaller &chosenCaller,
    const std::string &chosenCallee,
    const std::set<std::string> &entrypoints,
    const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction);

std::optional<std::size_t> minimumRemainingCallsToExit(
    InferredFrame &frame,
    const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction);

std::vector<std::string> collectImmediateExpectedCallees(
    InferredFrame &frame,
    const std::unordered_map<std::string, RuntimeFunctionCfg> &cfgByFunction);

// Path analysis
void mergeEquivalentPathStates(std::vector<PathState> &paths);
void pruneTopK(std::vector<PathState> &paths, std::size_t topK);
void addEdge(PathState &path, const std::string &caller, const std::string &callee);

// JSON serialization
llvm::json::Object assignmentToJson(const Assignment &assignment);
llvm::json::Object pathToJson(const PathState &path, std::size_t rank);
llvm::json::Object contextCallToJson(const ContextCall &call);
llvm::json::Object contextRunToJson(const ContextRun &run, std::size_t lane);
ContextRun materializeContextRun(const ContextRun &baseRun, const PathState &path);

llvm::json::Object buildVisualizationData(
    const std::vector<Event> &events,
    const std::vector<ContextRun> &runs,
    const std::vector<std::string> &warnings,
    const std::vector<std::string> &entrypointPriority);

// Output writers
bool writeHtmlFile(const std::string &path, const std::string &contents, std::string &error);

bool writeTimelineHtml(
    const std::string &path,
    const std::string &treePageName,
    const llvm::json::Object &vizData,
    std::string &error);

bool writeContextTreeHtml(
    const std::string &path,
    const std::string &timelinePageName,
    const llvm::json::Object &vizData,
    std::string &error);

bool writeDot(
    const std::string &dotPath,
    const std::unordered_set<std::string> &nodes,
    const std::unordered_map<EdgeKey, std::size_t, EdgeKeyHash> &edgeCounts,
    std::string &error);

#endif // RUNTIME_H
