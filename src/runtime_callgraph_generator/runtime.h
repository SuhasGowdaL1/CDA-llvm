/**
 * @file runtime.h
 * @brief Core data structures and analysis functions for runtime callgraph generation.
 */

#ifndef RUNTIME_H
#define RUNTIME_H

#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

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
};

/**
 * @brief Resolved assignment of a token to a caller.
 */
struct Assignment
{
    std::size_t lineNumber = 0U;
    std::string token;
    std::vector<std::string> candidates;
    std::string chosenCaller;
    std::optional<std::size_t> chosenCallerDepth;
    bool ambiguous = false;
    bool usedStaticEdge = false;
    double deltaScore = 0.0;
};

/**
 * @brief Inferred stack frame for unreported intermediate calls.
 */
struct InferredFrame
{
    std::string functionName;
    std::size_t nextExpectedCallIndex = 0U;
    std::size_t explicitDepthAnchor = 0U;
};

/**
 * @brief Candidate path state during trace reconstruction.
 */
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
 * @brief A single invocation of an entrypoint.
 */
struct ContextRun
{
    std::string contextId;
    std::string entrypoint;
    std::size_t ordinal = 0U;
    std::size_t startEventIndex = 0U;
    std::size_t endEventIndex = 0U;
    std::vector<ContextSegment> executionSegments;
    std::vector<ContextCall> calls;
    std::vector<std::string> warnings;
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
    std::unordered_map<std::string, std::set<std::string>> &callersByCallee,
    std::string &error);

bool loadCfgDirectCallOrder(
    const std::string &cfgAnalysisPath,
    std::unordered_map<std::string, std::vector<std::string>> &orderedCalleesByFunction,
    std::string &error);

// Path state management
void cleanupInferredStack(PathState &path);
void discardInferredFramesAtOrAboveDepth(PathState &path, std::size_t depth);
std::vector<std::string> buildActiveCallerOrder(const PathState &path);

void alignInferredFrameForToken(
    PathState &path,
    const std::string &token,
    const std::unordered_map<std::string, std::vector<std::string>> &orderedCalleesByFunction);

void updateInferredStackAfterAssignment(
    PathState &path,
    const std::string &chosenCaller,
    const std::string &chosenCallee,
    const std::set<std::string> &entrypoints,
    const std::unordered_map<std::string, std::vector<std::string>> &orderedCalleesByFunction);

// Path analysis
std::string pathTieBreakerKey(const PathState &path);
void pruneTopK(std::vector<PathState> &paths, std::size_t topK);
void addEdge(PathState &path, const std::string &caller, const std::string &callee);

// JSON serialization
llvm::json::Object assignmentToJson(const Assignment &assignment);
llvm::json::Object pathToJson(const PathState &path, std::size_t rank);
llvm::json::Object contextCallToJson(const ContextCall &call);
llvm::json::Object contextRunToJson(const ContextRun &run, std::size_t lane);

// Context run building and visualization
std::vector<ContextRun> buildContextRunsFromBestPath(
    const std::vector<Event> &events,
    const PathState &best,
    std::vector<std::string> &warnings);

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
    const std::set<std::string> &nodes,
    const std::map<EdgeKey, std::size_t> &edgeCounts,
    std::string &error);

#endif // RUNTIME_H
