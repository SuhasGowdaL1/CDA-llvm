/**
 * @file main.cpp
 * @brief CLI entrypoint for runtime callgraph generation from execution logs.
 */

#include <cstddef>
#include <set>
#include <string>
#include <unordered_map>
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
                assignment.chosenCallerDepth = std::nullopt;
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
                return lhs < rhs;
            });

            const bool hasStaticCandidate = !staticCandidates.empty();

            for (const std::string &caller : candidates)
            {
                PathState next = prepared;
                addEdge(next, caller, event.baseName);

                const double depthPenalty = static_cast<double>(callerDepthByName[caller]);
                const double fallbackPenalty = hasStaticCandidate ? 0.0 : 3.0;
                const double deltaScore = depthPenalty + fallbackPenalty;
                next.score += deltaScore;

                Assignment assignment;
                assignment.lineNumber = event.lineNumber;
                assignment.token = event.baseName;
                assignment.candidates = candidates;
                assignment.chosenCaller = caller;
                assignment.chosenCallerDepth = callerDepthByName[caller];
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

    if (!kNoHtml)
    {
        std::vector<std::string> visualizationWarnings;
        std::vector<ContextRun> contextRuns = buildContextRunsFromBestPath(events, best, visualizationWarnings);
        llvm::json::Object visualizationData = buildVisualizationData(events, contextRuns, visualizationWarnings, orderedEntrypoints);
        const std::string timelinePageName = fileNameFromPath(kTimelineHtmlOutput);
        const std::string contextTreePageName = fileNameFromPath(kContextTreeHtmlOutput);

        if (!writeTimelineHtml(kTimelineHtmlOutput, contextTreePageName, visualizationData, error))
        {
            llvm::errs() << "error: " << error << "\n";
            return 1;
        }

        if (!writeContextTreeHtml(kContextTreeHtmlOutput, timelinePageName, visualizationData, error))
        {
            llvm::errs() << "error: " << error << "\n";
            return 1;
        }
    }

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
    if (!kNoHtml)
    {
        llvm::outs() << "Wrote runtime timeline HTML to: " << kTimelineHtmlOutput << "\n";
        llvm::outs() << "Wrote runtime context tree HTML to: " << kContextTreeHtmlOutput << "\n";
    }
    llvm::outs() << "Events: " << events.size() << "\n";
    llvm::outs() << "Candidate paths kept: " << activePaths.size() << "\n";
    llvm::outs() << "Single path deduced: " << (uniquelyDeduced ? "yes" : "no") << "\n";

    return 0;
}
