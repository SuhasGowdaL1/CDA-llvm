#ifndef CALLGRAPH_ANALYSIS_H
#define CALLGRAPH_ANALYSIS_H

#include <cstddef>
#include <string>

struct CallGraphStats
{
    std::size_t functionCount = 0;
    std::size_t collapsedEdgeCount = 0;
    std::size_t unresolvedIndirectCallCount = 0;
    std::size_t contextNodeCount = 0;
    std::size_t contextEdgeCount = 0;
};

/**
 * @brief Builds a call graph from analysis JSON using a bounded-context, flow-sensitive pass.
 */
bool generateCallGraphFromAnalysisJson(
    const std::string &analysisJsonPath,
    const std::string &outputJsonPath,
    const std::string &outputDotPath,
    std::size_t contextDepth,
    CallGraphStats &stats,
    std::string &errorMessage);

#endif // CALLGRAPH_ANALYSIS_H
