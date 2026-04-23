/**
 * @file main.cpp
 * @brief CLI entrypoint for runtime callgraph generation from execution logs.
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include "runtime.h"

namespace
{
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

    llvm::cl::opt<std::string> kBlacklist(
        "blacklist",
        llvm::cl::desc("Path to blacklist file for runtime CFG matching (e.g. printf)"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("blacklist.txt"),
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

    llvm::cl::opt<unsigned> kLookaheadPlainEvents(
        "lookahead-plain-events",
        llvm::cl::desc("Number of future plain events to inspect when scoring candidate callers"),
        llvm::cl::value_desc("N"),
        llvm::cl::init(8),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<unsigned> kContextJobs(
        "context-jobs",
        llvm::cl::desc("Number of contexts to analyze in parallel (0 = auto)"),
        llvm::cl::value_desc("N"),
        llvm::cl::init(0),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kTimelineHtmlOutput(
        "timeline-html",
        llvm::cl::desc("Output HTML timeline path (context lanes vs event index)"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/runtime-timeline.html"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kContextTreeHtmlOutput(
        "context-tree-html",
        llvm::cl::desc("Output HTML context tree path (click-through details page)"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/runtime-context-tree.html"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<bool> kNoHtml(
        "no-html",
        llvm::cl::desc("Disable HTML visualization outputs"),
        llvm::cl::init(false),
        llvm::cl::cat(kCategory));

} // namespace

int main(int argc, const char **argv)
{
    llvm::cl::HideUnrelatedOptions(kCategory);
    llvm::cl::ParseCommandLineOptions(argc, argv, "Generate runtime callgraph with ambiguity scoring\n");

    std::set<std::string> entrypoints;
    std::vector<std::string> orderedEntrypoints;
    std::string error;
    if (!loadNameList(kEntryPoints, entrypoints, orderedEntrypoints, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    std::unordered_map<std::string, std::unordered_set<std::string>> callersByCallee;
    if (!loadStaticEdges(kStaticCallGraph, callersByCallee, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    std::set<std::string> blacklistedFunctions;
    std::vector<std::string> ignoredBlacklistedFunctions;
    if (!loadNameList(kBlacklist, blacklistedFunctions, ignoredBlacklistedFunctions, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    std::unordered_map<std::string, RuntimeFunctionCfg> cfgByFunction;
    if (!loadCfgDirectCallOrder(kCfgAnalysis, blacklistedFunctions, cfgByFunction, error))
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

    std::vector<std::string> preprocessingWarnings;
    std::vector<ContextRun> preprocessedContextRuns = preprocessContextRuns(events, entrypoints, preprocessingWarnings);

    llvm::errs() << "Loaded events: " << events.size() << "\n";
    llvm::errs() << "Preprocessed contexts: " << preprocessedContextRuns.size() << "\n";
    if (!preprocessingWarnings.empty())
    {
        llvm::errs() << "[runtime] preprocessing warnings: " << preprocessingWarnings.size() << "\n";
    }
    if (events.size() >= 50000000U)
    {
        llvm::errs() << "note: processing a very large trace; this can take significant memory and CPU time\n";
    }

    RuntimeAnalysisOptions analysisOptions;
    analysisOptions.topK = static_cast<std::size_t>(kTopK);
    analysisOptions.lookaheadPlainEvents = static_cast<std::size_t>(kLookaheadPlainEvents);
    analysisOptions.contextJobs = static_cast<std::size_t>(kContextJobs);

    llvm::errs() << "[runtime] analyzing " << preprocessedContextRuns.size()
                 << " contexts with context-jobs="
                 << (analysisOptions.contextJobs == 0U ? std::string("auto") : std::to_string(analysisOptions.contextJobs))
                 << "\n";

    RuntimeAnalysisResult analysisResult;
    if (!analyzeContexts(
            events,
            preprocessedContextRuns,
            entrypoints,
            callersByCallee,
            cfgByFunction,
            analysisOptions,
            analysisResult,
            error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    const std::vector<PathState> &activePaths = analysisResult.candidatePaths;
    if (activePaths.empty())
    {
        llvm::errs() << "error: runtime analysis produced no candidate paths\n";
        return 1;
    }

    const PathState &best = activePaths.front();

    std::set<std::string> allFunctions;
    for (const auto &entry : cfgByFunction)
    {
        allFunctions.insert(entry.first);
    }

    std::set<std::string> coveredByAnyPath;
    for (const PathState &path : activePaths)
    {
        coveredByAnyPath.insert(path.nodes.begin(), path.nodes.end());
    }

    std::set<std::string> coveredByAllPaths;
    if (!activePaths.empty())
    {
        coveredByAllPaths.insert(activePaths.front().nodes.begin(), activePaths.front().nodes.end());
        for (std::size_t i = 1U; i < activePaths.size(); ++i)
        {
            std::set<std::string> intersection;
            std::set_intersection(
                coveredByAllPaths.begin(),
                coveredByAllPaths.end(),
                activePaths[i].nodes.begin(),
                activePaths[i].nodes.end(),
                std::inserter(intersection, intersection.begin()));
            coveredByAllPaths = std::move(intersection);
        }
    }

    std::set<std::string> uncoveredFunctions;
    std::set_difference(
        allFunctions.begin(),
        allFunctions.end(),
        coveredByAnyPath.begin(),
        coveredByAnyPath.end(),
        std::inserter(uncoveredFunctions, uncoveredFunctions.begin()));

    const auto namesToJson = [](const std::set<std::string> &names) -> llvm::json::Array
    {
        llvm::json::Array values;
        std::copy(names.begin(), names.end(), std::back_inserter(values));
        return values;
    };

    llvm::json::Object root;

    llvm::json::Object summary;
    summary["events"] = static_cast<std::int64_t>(events.size());
    summary["preprocessedContexts"] = static_cast<std::int64_t>(preprocessedContextRuns.size());
    summary["preprocessingWarnings"] = static_cast<std::int64_t>(preprocessingWarnings.size());
    summary["processedEvents"] = static_cast<std::int64_t>(analysisResult.processedEventCount);
    summary["pathsKept"] = static_cast<std::int64_t>(activePaths.size());
    summary["pathExpansions"] = static_cast<std::int64_t>(analysisResult.pathExpansionCount);
    summary["bestScore"] = best.score;
    summary["bestWarnings"] = static_cast<std::int64_t>(best.warnings.size());
    summary["contextJobs"] = static_cast<std::int64_t>(analysisOptions.contextJobs);
    root["summary"] = std::move(summary);

    llvm::json::Object preprocessing;
    llvm::json::Array preprocessedContextsJson;
    for (std::size_t i = 0U; i < preprocessedContextRuns.size(); ++i)
    {
        preprocessedContextsJson.push_back(contextRunToJson(preprocessedContextRuns[i], i));
    }
    preprocessing["contexts"] = std::move(preprocessedContextsJson);

    llvm::json::Array preprocessingWarningsJson;
    std::copy(
        preprocessingWarnings.begin(),
        preprocessingWarnings.end(),
        std::back_inserter(preprocessingWarningsJson));
    preprocessing["warnings"] = std::move(preprocessingWarningsJson);
    root["preprocessing"] = std::move(preprocessing);

    llvm::json::Object contextProcessing;
    llvm::json::Array contextRunsJson;
    for (std::size_t i = 0U; i < analysisResult.contexts.size(); ++i)
    {
        const ContextAnalysisResult &contextResult = analysisResult.contexts[i];
        llvm::json::Object contextObject = contextRunToJson(contextResult.run, i);
        contextObject["localEvents"] = static_cast<std::int64_t>(contextResult.localEventCount);
        contextObject["processedEvents"] = static_cast<std::int64_t>(contextResult.processedEventCount);
        contextObject["pathExpansions"] = static_cast<std::int64_t>(contextResult.pathExpansionCount);
        contextObject["candidatePaths"] = static_cast<std::int64_t>(contextResult.candidatePaths.size());
        contextObject["effectiveLookaheadPlainEvents"] =
            static_cast<std::int64_t>(contextResult.effectiveLookaheadPlainEvents);
        if (!contextResult.candidatePaths.empty())
        {
            contextObject["bestScore"] = contextResult.candidatePaths.front().score;
        }
        contextRunsJson.push_back(std::move(contextObject));
    }
    contextProcessing["contexts"] = std::move(contextRunsJson);
    root["contextProcessing"] = std::move(contextProcessing);

    llvm::json::Object coverage;
    coverage["totalFunctions"] = static_cast<std::int64_t>(allFunctions.size());
    coverage["coveredFunctions"] = static_cast<std::int64_t>(coveredByAnyPath.size());
    coverage["uncoveredFunctions"] = static_cast<std::int64_t>(uncoveredFunctions.size());
    coverage["coveredByAllCandidatePaths"] = static_cast<std::int64_t>(coveredByAllPaths.size());
    coverage["coveredFunctionNames"] = namesToJson(coveredByAnyPath);
    coverage["uncoveredFunctionNames"] = namesToJson(uncoveredFunctions);
    coverage["coveredByAllCandidatePathNames"] = namesToJson(coveredByAllPaths);
    root["coverage"] = std::move(coverage);

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

    const auto outputPathForRank = [](const std::string &path, std::size_t rank, bool includeRankSuffix) -> std::string
    {
        if (!includeRankSuffix)
        {
            return path;
        }

        const std::string suffix = ".rank" + std::to_string(rank);
        const std::size_t slashPos = path.find_last_of("/\\");
        const std::size_t dotPos = path.find_last_of('.');
        const bool hasExtension = (dotPos != std::string::npos) &&
                                  (slashPos == std::string::npos || dotPos > slashPos);

        if (!hasExtension)
        {
            return path + suffix;
        }

        return path.substr(0U, dotPos) + suffix + path.substr(dotPos);
    };

    const bool multiPathOutputs = activePaths.size() > 1U;
    for (std::size_t i = 0U; i < activePaths.size(); ++i)
    {
        const std::size_t rank = i + 1U;
        const PathState &path = activePaths[i];

        if (!kNoHtml)
        {
            std::vector<ContextRun> visualizationRuns;
            const std::vector<std::size_t> *selection =
                i < analysisResult.candidateSelections.size() ? &analysisResult.candidateSelections[i] : nullptr;
            if (selection != nullptr && selection->size() == analysisResult.contexts.size())
            {
                visualizationRuns.reserve(selection->size());
                for (std::size_t contextIndex = 0U; contextIndex < selection->size(); ++contextIndex)
                {
                    const ContextAnalysisResult &contextResult = analysisResult.contexts[contextIndex];
                    const std::size_t candidateIndex = (*selection)[contextIndex];
                    if (candidateIndex < contextResult.candidatePaths.size())
                    {
                        visualizationRuns.push_back(
                            materializeContextRun(preprocessedContextRuns[contextIndex], contextResult.candidatePaths[candidateIndex]));
                    }
                }
            }
            if (visualizationRuns.empty())
            {
                visualizationRuns = analysisResult.bestContextRuns;
            }
            llvm::json::Object visualizationData =
                buildVisualizationData(events, visualizationRuns, preprocessingWarnings, orderedEntrypoints);
            const std::string timelineOutputPath = outputPathForRank(kTimelineHtmlOutput, rank, multiPathOutputs);
            const std::string contextTreeOutputPath = outputPathForRank(kContextTreeHtmlOutput, rank, multiPathOutputs);
            const std::string timelinePageName = fileNameFromPath(timelineOutputPath);
            const std::string contextTreePageName = fileNameFromPath(contextTreeOutputPath);

            if (!writeTimelineHtml(timelineOutputPath, contextTreePageName, visualizationData, error))
            {
                llvm::errs() << "error: " << error << "\n";
                return 1;
            }

            if (!writeContextTreeHtml(contextTreeOutputPath, timelinePageName, visualizationData, error))
            {
                llvm::errs() << "error: " << error << "\n";
                return 1;
            }
        }

        if (!kNoDot)
        {
            const std::string dotOutputPath = outputPathForRank(kDotOutput, rank, multiPathOutputs);
            if (!writeDot(dotOutputPath, path.nodes, path.edgeCounts, error))
            {
                llvm::errs() << "error: " << error << "\n";
                return 1;
            }
        }
    }

    llvm::outs() << "Wrote runtime callgraph JSON to: " << kOutput << "\n";
    if (!kNoDot)
    {
        if (activePaths.size() == 1U)
        {
            llvm::outs() << "Wrote runtime callgraph DOT to: " << kDotOutput << "\n";
        }
        else
        {
            for (std::size_t i = 0U; i < activePaths.size(); ++i)
            {
                const std::size_t rank = i + 1U;
                llvm::outs() << "Wrote runtime callgraph DOT (rank " << rank << ") to: "
                             << outputPathForRank(kDotOutput, rank, true) << "\n";
            }
        }
    }
    if (!kNoHtml)
    {
        if (activePaths.size() == 1U)
        {
            llvm::outs() << "Wrote runtime timeline HTML to: " << kTimelineHtmlOutput << "\n";
            llvm::outs() << "Wrote runtime context tree HTML to: " << kContextTreeHtmlOutput << "\n";
        }
        else
        {
            for (std::size_t i = 0U; i < activePaths.size(); ++i)
            {
                const std::size_t rank = i + 1U;
                llvm::outs() << "Wrote runtime timeline HTML (rank " << rank << ") to: "
                             << outputPathForRank(kTimelineHtmlOutput, rank, true) << "\n";
                llvm::outs() << "Wrote runtime context tree HTML (rank " << rank << ") to: "
                             << outputPathForRank(kContextTreeHtmlOutput, rank, true) << "\n";
            }
        }
    }
    llvm::outs() << "Events: " << events.size() << "\n";
    llvm::outs() << "Candidate paths kept: " << activePaths.size() << "\n";
    llvm::outs() << "Coverage (functions): "
                 << coveredByAnyPath.size()
                 << "/"
                 << allFunctions.size()
                 << " covered, "
                 << uncoveredFunctions.size()
                 << " uncovered\n";
    llvm::outs() << "Covered in all candidate paths: "
                 << coveredByAllPaths.size()
                 << "\n";

    return 0;
}
