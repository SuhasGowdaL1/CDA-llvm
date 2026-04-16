/**
 * @file callgraph_analysis.h
 * @brief Static call graph construction API from CFG analysis JSON.
 */

#ifndef CALLGRAPH_ANALYSIS_H
#define CALLGRAPH_ANALYSIS_H

#include <cstddef>
#include <set>
#include <string>

/**
 * @brief Summary counters produced during call graph generation.
 */
struct CallGraphStats
{
    std::size_t functionCount = 0;
    std::size_t collapsedEdgeCount = 0;
    std::size_t unresolvedIndirectCallCount = 0;
    std::size_t contextNodeCount = 0;
    std::size_t contextEdgeCount = 0;
};

enum class IndirectResolutionMode
{
    ResolveIndirect,
    PrecomputedIndirect
};

/**
 * @brief Builds a call graph with configurable indirect-call resolution mode.
 * @param analysisJsonPath Input CFG analysis JSON.
 * @param outputJsonPath Output call graph JSON.
 * @param outputDotPath Output DOT path (empty disables DOT output).
 * @param contextDepth Bounded context depth used for context stats traversal.
 * @param blacklistedFunctions Exact function names to skip.
 * @param debugLoggingEnabled Enables non-error debug tracing.
 * @param mode Indirect resolution mode.
 * @param indirectMappingPath Mapping file path. Required for precomputed mode; optional output path in resolve mode.
 * @param stats Output summary counters.
 * @param errorMessage Populated on failure.
 * @return true on success, false on error.
 */
bool generateCallGraphFromAnalysisJsonWithMode(
    const std::string &analysisJsonPath,
    const std::string &outputJsonPath,
    const std::string &outputDotPath,
    std::size_t contextDepth,
    const std::set<std::string> &blacklistedFunctions,
    bool debugLoggingEnabled,
    IndirectResolutionMode mode,
    const std::string &indirectMappingPath,
    CallGraphStats &stats,
    std::string &errorMessage);

/**
 * @brief Builds a call graph from analysis JSON using a bounded-context, flow-sensitive pass.
 * @param analysisJsonPath Input CFG analysis JSON.
 * @param outputJsonPath Output call graph JSON.
 * @param outputDotPath Output DOT path (empty disables DOT output).
 * @param contextDepth Bounded context depth used for context stats traversal.
 * @param debugLoggingEnabled Enables non-error debug tracing.
 * @param stats Output summary counters.
 * @param errorMessage Populated on failure.
 * @return true on success, false on error.
 */
bool generateCallGraphFromAnalysisJson(
    const std::string &analysisJsonPath,
    const std::string &outputJsonPath,
    const std::string &outputDotPath,
    std::size_t contextDepth,
    const std::set<std::string> &blacklistedFunctions,
    bool debugLoggingEnabled,
    CallGraphStats &stats,
    std::string &errorMessage);

#endif // CALLGRAPH_ANALYSIS_H
