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
    std::vector<std::string> orderedBlacklistedFunctions;
    if (!loadNameList(kBlacklist, blacklistedFunctions, orderedBlacklistedFunctions, error))
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

    llvm::errs() << "Loaded events: " << events.size() << "\n";
    if (events.size() >= 50000000U)
    {
        llvm::errs() << "note: processing a very large trace; this can take significant memory and CPU time\n";
    }

    std::vector<PathState> activePaths(1U);
    std::size_t pathExpansionCount = 1U;
    std::size_t failureEventIndex = static_cast<std::size_t>(-1);
    Event failureEvent;
    std::unordered_map<std::string, std::size_t> failureReasons;
    struct FailureExample
    {
        std::string reason;
        double score = 0.0;
        std::string contextSummary;
        std::string activeCallerSummary;
        std::string assignmentSummary;
    };
    std::vector<FailureExample> failureExamples;

    constexpr std::size_t kProgressEveryEvents = 1000U;
    const std::size_t branchLimit = std::max<std::size_t>(1U, static_cast<std::size_t>(kTopK));
    llvm::errs() << "[runtime] starting event processing\n";
    for (std::size_t eventIndex = 0U; eventIndex < events.size(); ++eventIndex)
    {
        if ((eventIndex + 1U) % kProgressEveryEvents == 0U || (eventIndex + 1U) == events.size())
        {
            llvm::errs() << "[runtime] processed " << (eventIndex + 1U)
                         << "/" << events.size()
                         << " events, active paths=" << activePaths.size()
                         << "\n";
        }

        const Event &event = events[eventIndex];
        std::unordered_map<std::string, std::size_t> invalidationReasonsForEvent;
        std::vector<FailureExample> invalidationExamplesForEvent;
        const auto summarizeFrames = [](const std::vector<std::string> &frames) -> std::string
        {
            if (frames.empty())
            {
                return "<empty>";
            }

            std::ostringstream out;
            for (std::size_t i = 0U; i < frames.size(); ++i)
            {
                if (i != 0U)
                {
                    out << " -> ";
                }
                out << frames[i];
            }
            return out.str();
        };
        const auto summarizeRecentAssignments = [](const PathState &candidate) -> std::string
        {
            if (candidate.assignments.empty())
            {
                return "<none>";
            }

            constexpr std::size_t kRecentAssignments = 3U;
            const std::size_t begin = candidate.assignments.size() > kRecentAssignments
                                          ? candidate.assignments.size() - kRecentAssignments
                                          : 0U;

            std::ostringstream out;
            for (std::size_t i = begin; i < candidate.assignments.size(); ++i)
            {
                if (i != begin)
                {
                    out << " | ";
                }
                const Assignment &assignment = candidate.assignments[i];
                out << "line " << assignment.lineNumber
                    << ": " << assignment.chosenCaller
                    << " -> " << assignment.token;
                if (assignment.chosenCallerDepth.has_value())
                {
                    out << " (depth " << *assignment.chosenCallerDepth << ")";
                }
            }
            return out.str();
        };
        const auto noteInvalidation = [&](const std::string &reason, const PathState &candidate)
        {
            ++invalidationReasonsForEvent[reason];

            constexpr std::size_t kMaxFailureExamples = 6U;
            if (invalidationExamplesForEvent.size() >= kMaxFailureExamples)
            {
                return;
            }

            FailureExample example;
            example.reason = reason;
            example.score = candidate.score;
            example.contextSummary = summarizeFrames(candidate.contextStack);
            example.activeCallerSummary = summarizeFrames(buildActiveCallerOrder(candidate));
            example.assignmentSummary = summarizeRecentAssignments(candidate);
            invalidationExamplesForEvent.push_back(std::move(example));
        };
        const auto joinNames = [](const std::vector<std::string> &names) -> std::string
        {
            if (names.empty())
            {
                return "<none>";
            }

            std::ostringstream out;
            for (std::size_t i = 0U; i < names.size(); ++i)
            {
                if (i != 0U)
                {
                    out << ", ";
                }
                out << names[i];
            }
            return out.str();
        };
        const auto callerMatchesStaticCallee = [&](const std::string &callerName, const std::string &calleeName) -> bool
        {
            const auto staticCallersForCallee = [&](const std::string &candidateCallee) -> const std::unordered_set<std::string> *
            {
                const auto staticIt = callersByCallee.find(candidateCallee);
                if (staticIt == callersByCallee.end())
                {
                    return nullptr;
                }
                return &staticIt->second;
            };

            const std::unordered_set<std::string> *directCallers = staticCallersForCallee(calleeName);
            if (directCallers != nullptr)
            {
                // If we have resolved static targets for this callee token, only accept exact matches.
                return directCallers->find(callerName) != directCallers->end();
            }

            // Only if there is no resolved static target set for this callee token,
            // fall back to callers that have an unresolved indirect edge.
            if (calleeName != "<indirect-call>")
            {
                const std::unordered_set<std::string> *indirectCallers = staticCallersForCallee("<indirect-call>");
                if (indirectCallers != nullptr)
                {
                    return indirectCallers->find(callerName) != indirectCallers->end();
                }
            }

            return false;
        };
        const auto describeNoCfgCaller = [&](PathState &candidate) -> std::string
        {
            cleanupInferredStack(candidate);

            for (std::size_t i = candidate.inferredStack.size(); i > 0U; --i)
            {
                InferredFrame &frame = candidate.inferredStack[i - 1U];
                const std::vector<std::string> expected = collectImmediateExpectedCallees(frame, cfgByFunction);
                const std::optional<std::size_t> remainingCalls = minimumRemainingCallsToExit(frame, cfgByFunction);
                if (remainingCalls.has_value() && *remainingCalls == 0U)
                {
                    continue;
                }

                if (!expected.empty())
                {
                    return llvm::formatv("line {0}: token '{1}' was blocked by active nested callee '{2}', which next expects one of [{3}]",
                                         event.lineNumber,
                                         event.baseName,
                                         frame.functionName,
                                         joinNames(expected))
                        .str();
                }

                if (!remainingCalls.has_value())
                {
                    return llvm::formatv("line {0}: token '{1}' was blocked by active nested callee '{2}', whose CFG completion state could not be proven",
                                         event.lineNumber,
                                         event.baseName,
                                         frame.functionName)
                        .str();
                }

                return llvm::formatv("line {0}: token '{1}' was blocked by active nested callee '{2}'",
                                     event.lineNumber,
                                     event.baseName,
                                     frame.functionName)
                    .str();
            }

            if (!candidate.explicitFrames.empty())
            {
                InferredFrame &frame = candidate.explicitFrames.back();
                const std::vector<std::string> expected = collectImmediateExpectedCallees(frame, cfgByFunction);
                if (!expected.empty())
                {
                    return llvm::formatv("line {0}: top active context '{1}' could not call token '{2}'; next CFG-observable callees are [{3}]",
                                         event.lineNumber,
                                         frame.functionName,
                                         event.baseName,
                                         joinNames(expected))
                        .str();
                }

                const std::optional<std::size_t> remainingCalls = minimumRemainingCallsToExit(frame, cfgByFunction);
                if (remainingCalls.has_value() && *remainingCalls == 0U)
                {
                    return llvm::formatv("line {0}: top active context '{1}' had no remaining CFG calls, so token '{2}' cannot belong to it",
                                         event.lineNumber,
                                         frame.functionName,
                                         event.baseName)
                        .str();
                }
            }

            if (candidate.contextStack.empty())
            {
                return llvm::formatv("line {0}: token '{1}' appeared with no active context",
                                     event.lineNumber,
                                     event.baseName)
                    .str();
            }

            return llvm::formatv("line {0}: token '{1}' had no CFG-feasible active caller",
                                 event.lineNumber,
                                 event.baseName)
                .str();
        };
        const auto describeExitIncompatibility = [&](PathState &candidate) -> std::optional<std::string>
        {
            cleanupInferredStack(candidate);

            for (std::size_t i = candidate.inferredStack.size(); i > 0U; --i)
            {
                InferredFrame &frame = candidate.inferredStack[i - 1U];
                const std::optional<std::size_t> remainingCalls = minimumRemainingCallsToExit(frame, cfgByFunction);
                if (!remainingCalls.has_value())
                {
                    return llvm::formatv("line {0}: could not prove nested callee '{1}' can return before exit marker '{2}'",
                                         event.lineNumber,
                                         frame.functionName,
                                         event.rawToken)
                        .str();
                }

                if (*remainingCalls > 0U)
                {
                    return llvm::formatv("line {0}: nested callee '{1}' still needs {2} CFG call(s) before exit marker '{3}' can close '{4}'",
                                         event.lineNumber,
                                         frame.functionName,
                                         *remainingCalls,
                                         event.rawToken,
                                         event.baseName)
                        .str();
                }
            }

            if (candidate.explicitFrames.empty() || candidate.explicitFrames.back().functionName != event.baseName)
            {
                return llvm::formatv("line {0}: internal frame state for exit marker '{1}' did not match active context '{2}'",
                                     event.lineNumber,
                                     event.rawToken,
                                     event.baseName)
                    .str();
            }

            const std::optional<std::size_t> remainingCalls =
                minimumRemainingCallsToExit(candidate.explicitFrames.back(), cfgByFunction);
            if (!remainingCalls.has_value())
            {
                return llvm::formatv("line {0}: could not prove CFG exit reachability for '{1}' at exit marker '{2}'",
                                     event.lineNumber,
                                     event.baseName,
                                     event.rawToken)
                    .str();
            }

            if (*remainingCalls > 0U)
            {
                return llvm::formatv("line {0}: exit marker '{1}' closed '{2}' before {3} remaining CFG call(s) were observed",
                                     event.lineNumber,
                                     event.rawToken,
                                     event.baseName,
                                     *remainingCalls)
                    .str();
            }

            return std::nullopt;
        };
        std::vector<PathState> nextPaths;
        nextPaths.reserve(activePaths.size() * branchLimit + 1U);
        for (PathState &path : activePaths)
        {
            if (event.kind == EventKind::Entry)
            {
                PathState prepared = std::move(path);
                cleanupInferredStack(prepared);

                // Entry markers always begin a new explicit context. If they interrupt an active
                // context, suspend its inferred stack until an exit unwinds back to this depth.
                suspendInferredFramesAtOrAboveDepth(prepared, prepared.contextStack.size());

                // Only treat entry markers as observed calls when a static caller matches.
                std::vector<ActiveCaller> entryActiveCallers = buildFeasibleActiveCallers(prepared, event.baseName, cfgByFunction);
                std::vector<ActiveCaller> entryStaticCandidates;
                if (!entryActiveCallers.empty())
                {
                    std::copy_if(
                        entryActiveCallers.begin(),
                        entryActiveCallers.end(),
                        std::back_inserter(entryStaticCandidates),
                        [&](const ActiveCaller &candidate)
                        {
                            return callerMatchesStaticCallee(candidate.functionName, event.baseName);
                        });
                }

                if (entryStaticCandidates.size() > 1U)
                {
                    std::sort(entryStaticCandidates.begin(), entryStaticCandidates.end(), [](const ActiveCaller &lhs, const ActiveCaller &rhs)
                              {
                        if (lhs.depth != rhs.depth)
                        {
                            return lhs.depth < rhs.depth;
                        }
                        if (lhs.functionName != rhs.functionName)
                        {
                            return lhs.functionName < rhs.functionName;
                        }
                        if (lhs.isInferred != rhs.isInferred)
                        {
                            return lhs.isInferred;
                        }
                        return lhs.frameIndex < rhs.frameIndex; });
                }

                if (entryStaticCandidates.size() > branchLimit)
                {
                    entryStaticCandidates.resize(branchLimit);
                }

                const auto appendEntryFrame = [&](PathState &next)
                {
                    next.nodes.insert(event.baseName);
                    next.contextStack.push_back(event.baseName);

                    InferredFrame explicitFrame;
                    explicitFrame.functionName = event.baseName;
                    const auto cfgIt = cfgByFunction.find(event.baseName);
                    if (cfgIt != cfgByFunction.end() &&
                        !cfgIt->second.blocks.empty() &&
                        cfgIt->second.blocks.find(cfgIt->second.entryBlockId) != cfgIt->second.blocks.end())
                    {
                        explicitFrame.activePoints.push_back(InferredFrame::ProgramPoint{cfgIt->second.entryBlockId, 0U});
                    }

                    explicitFrame.functionName = event.baseName;
                    explicitFrame.explicitDepthAnchor = next.contextStack.size();

                    next.explicitFrames.push_back(std::move(explicitFrame));
                };

                if (entryStaticCandidates.empty())
                {
                    PathState next = std::move(prepared);
                    appendEntryFrame(next);
                    nextPaths.push_back(std::move(next));
                    continue;
                }

                for (const ActiveCaller &entryCaller : entryStaticCandidates)
                {
                    PathState next = prepared;
                    addEdge(next, entryCaller.functionName, event.baseName);
                    updateInferredStackAfterAssignment(
                        next,
                        entryCaller,
                        event.baseName,
                        entrypoints,
                        cfgByFunction);
                    appendEntryFrame(next);
                    nextPaths.push_back(std::move(next));
                }
                continue;
            }

            if (event.kind == EventKind::Exit)
            {
                PathState next = std::move(path);
                cleanupInferredStack(next);
                if (next.contextStack.empty())
                {
                    noteInvalidation(
                        llvm::formatv("line {0}: exit marker '{1}' had no active context to close",
                                      event.lineNumber,
                                      event.rawToken)
                            .str(),
                        next);
                    continue;
                }

                if (next.contextStack.back() == event.baseName)
                {
                    if (const std::optional<std::string> incompatibility = describeExitIncompatibility(next))
                    {
                        noteInvalidation(*incompatibility, next);
                        continue;
                    }

                    next.contextStack.pop_back();
                    cleanupInferredStack(next);
                    (void)restoreSuspendedInferredFramesForDepth(next, next.contextStack.size());
                    nextPaths.push_back(std::move(next));
                    continue;
                }

                bool found = false;
                while (!next.contextStack.empty())
                {
                    const std::string top = next.contextStack.back();
                    next.contextStack.pop_back();
                    if (top == event.baseName)
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    noteInvalidation(
                        llvm::formatv("line {0}: exit marker '{1}' did not match any active context stack frame",
                                      event.lineNumber,
                                      event.rawToken)
                            .str(),
                        next);
                    continue;
                }

                cleanupInferredStack(next);
                (void)restoreSuspendedInferredFramesForDepth(next, next.contextStack.size());

                nextPaths.push_back(std::move(next));
                continue;
            }

            // Plain function log.
            PathState prepared = std::move(path);
            std::vector<ActiveCaller> activeCallers = buildFeasibleActiveCallers(prepared, event.baseName, cfgByFunction);

            if (activeCallers.empty())
            {
                noteInvalidation(describeNoCfgCaller(prepared), prepared);
                continue;
            }

            std::vector<ActiveCaller> staticCandidates;

            std::copy_if(
                activeCallers.begin(),
                activeCallers.end(),
                std::back_inserter(staticCandidates),
                [&](const ActiveCaller &candidate)
                {
                    return callerMatchesStaticCallee(candidate.functionName, event.baseName);
                });

            if (staticCandidates.empty())
            {
                noteInvalidation(
                    llvm::formatv("line {0}: token '{1}' had CFG-feasible callers, but none matched the static callgraph",
                                  event.lineNumber,
                                  event.baseName)
                        .str(),
                    prepared);
                continue;
            }

            std::vector<ActiveCaller> &candidates = staticCandidates;
            const auto rankActiveCaller = [](const ActiveCaller &lhs, const ActiveCaller &rhs)
            {
                if (lhs.depth != rhs.depth)
                {
                    return lhs.depth < rhs.depth;
                }
                if (lhs.functionName != rhs.functionName)
                {
                    return lhs.functionName < rhs.functionName;
                }
                if (lhs.isInferred != rhs.isInferred)
                {
                    return lhs.isInferred;
                }
                if (lhs.frameIndex != rhs.frameIndex)
                {
                    return lhs.frameIndex < rhs.frameIndex;
                }
                return false;
            };

            if (candidates.size() > 1U)
            {
                std::sort(candidates.begin(), candidates.end(), rankActiveCaller);
            }

            std::vector<std::string> candidateNames;
            candidateNames.reserve(candidates.size());
            std::transform(
                candidates.begin(),
                candidates.end(),
                std::back_inserter(candidateNames),
                [](const ActiveCaller &candidate)
                { return candidate.functionName; });

            if (candidates.size() > 1U && kLookaheadPlainEvents > 0U)
            {
                // Explore a deeper same-context horizon so feasibility branching can
                // disambiguate cases where the first few plain events are symmetric.
                const std::size_t lookaheadPlainLimit =
                    std::max<std::size_t>(static_cast<std::size_t>(kLookaheadPlainEvents), 32U);
                const std::vector<ActiveCaller> originalCandidates = candidates;
                struct LookaheadCandidate
                {
                    ActiveCaller caller;
                    bool feasible = true;
                    std::size_t frontierWidth = static_cast<std::size_t>(-1);
                };

                std::vector<LookaheadCandidate> lookaheadCandidates;
                lookaheadCandidates.reserve(candidates.size());
                std::transform(
                    candidates.begin(),
                    candidates.end(),
                    std::back_inserter(lookaheadCandidates),
                    [](const ActiveCaller &candidate)
                    { return LookaheadCandidate{candidate, true}; });

                for (LookaheadCandidate &entry : lookaheadCandidates)
                {
                    PathState probe = prepared;
                    updateInferredStackAfterAssignment(
                        probe,
                        entry.caller,
                        event.baseName,
                        entrypoints,
                        cfgByFunction);

                    std::vector<PathState> probeStates;
                    probeStates.push_back(std::move(probe));

                    std::size_t inspectedPlainEvents = 0U;
                    std::size_t nestedContextDepth = 0U;
                    for (std::size_t i = eventIndex + 1U;
                         i < events.size() && inspectedPlainEvents < lookaheadPlainLimit;
                         ++i)
                    {
                        const Event &futureEvent = events[i];
                        if (futureEvent.kind == EventKind::Entry)
                        {
                            ++nestedContextDepth;
                            continue;
                        }

                        if (futureEvent.kind == EventKind::Exit)
                        {
                            if (nestedContextDepth == 0U)
                            {
                                // Current context ended; stop lookahead for this candidate.
                                break;
                            }

                            --nestedContextDepth;
                            continue;
                        }

                        if (nestedContextDepth != 0U)
                        {
                            // Ignore plain events that belong to nested/interrupt contexts.
                            continue;
                        }

                        ++inspectedPlainEvents;
                        std::vector<PathState> nextProbeStates;
                        for (PathState &probeState : probeStates)
                        {
                            std::vector<ActiveCaller> futureActiveCallers =
                                buildFeasibleActiveCallers(probeState, futureEvent.baseName, cfgByFunction);
                            if (futureActiveCallers.empty())
                            {
                                continue;
                            }

                            std::vector<ActiveCaller> futureStaticCandidates;
                            std::copy_if(
                                futureActiveCallers.begin(),
                                futureActiveCallers.end(),
                                std::back_inserter(futureStaticCandidates),
                                [&](const ActiveCaller &futureCandidate)
                                {
                                    return callerMatchesStaticCallee(futureCandidate.functionName, futureEvent.baseName);
                                });

                            if (futureStaticCandidates.empty())
                            {
                                continue;
                            }

                            std::sort(futureStaticCandidates.begin(), futureStaticCandidates.end(), rankActiveCaller);
                            if (futureStaticCandidates.size() > branchLimit)
                            {
                                futureStaticCandidates.resize(branchLimit);
                            }

                            for (const ActiveCaller &futureCaller : futureStaticCandidates)
                            {
                                PathState nextProbe = probeState;
                                addEdge(nextProbe, futureCaller.functionName, futureEvent.baseName);
                                updateInferredStackAfterAssignment(
                                    nextProbe,
                                    futureCaller,
                                    futureEvent.baseName,
                                    entrypoints,
                                    cfgByFunction);
                                nextProbeStates.push_back(std::move(nextProbe));
                            }
                        }

                        if (nextProbeStates.empty())
                        {
                            entry.feasible = false;
                            break;
                        }

                        mergeEquivalentPathStates(nextProbeStates);
                        pruneTopK(nextProbeStates, branchLimit);
                        probeStates.swap(nextProbeStates);
                    }

                    if (entry.feasible)
                    {
                        entry.frontierWidth = probeStates.size();
                    }
                }

                candidates.clear();
                std::size_t bestFrontierWidth = static_cast<std::size_t>(-1);
                for (const LookaheadCandidate &entry : lookaheadCandidates)
                {
                    if (entry.feasible)
                    {
                        bestFrontierWidth = std::min(bestFrontierWidth, entry.frontierWidth);
                    }
                }

                if (bestFrontierWidth == static_cast<std::size_t>(-1))
                {
                    candidates = originalCandidates;
                }
                else
                {
                    for (const LookaheadCandidate &entry : lookaheadCandidates)
                    {
                        if (entry.feasible && entry.frontierWidth == bestFrontierWidth)
                        {
                            candidates.push_back(entry.caller);
                        }
                    }
                }

                candidateNames.clear();
                candidateNames.reserve(candidates.size());
                std::transform(
                    candidates.begin(),
                    candidates.end(),
                    std::back_inserter(candidateNames),
                    [](const ActiveCaller &candidate)
                    { return candidate.functionName; });
            }

            const bool tiedBest = candidates.size() > 1U;
            if (candidates.size() > branchLimit)
            {
                candidates.resize(branchLimit);
            }
            for (std::size_t candidateRank = 0U; candidateRank < candidates.size(); ++candidateRank)
            {
                const ActiveCaller &caller = candidates[candidateRank];
                PathState next = prepared;
                addEdge(next, caller.functionName, event.baseName);

                // Keep scoring simple and stable: earlier-ranked callers are preferred.
                const double deltaScore = static_cast<double>(candidateRank) * 0.25;
                next.score += deltaScore;

                Assignment assignment;
                assignment.lineNumber = event.lineNumber;
                assignment.token = event.baseName;
                assignment.candidates = candidateNames;
                assignment.chosenCaller = caller.functionName;
                assignment.chosenCallerDepth = caller.depth;
                assignment.ambiguous = tiedBest;
                assignment.usedStaticEdge = true;
                assignment.deltaScore = deltaScore;
                next.assignments.push_back(std::move(assignment));

                updateInferredStackAfterAssignment(
                    next,
                    caller,
                    event.baseName,
                    entrypoints,
                    cfgByFunction);

                nextPaths.push_back(std::move(next));
            }
        }

        pathExpansionCount += nextPaths.size();
        mergeEquivalentPathStates(nextPaths);
        pruneTopK(nextPaths, std::max<std::size_t>(1U, static_cast<std::size_t>(kTopK)));
        activePaths.swap(nextPaths);
        if (activePaths.empty())
        {
            failureEventIndex = eventIndex;
            failureEvent = event;
            failureReasons = std::move(invalidationReasonsForEvent);
            failureExamples = std::move(invalidationExamplesForEvent);
            break;
        }
    }

    if (activePaths.empty())
    {
        llvm::errs() << "error: no valid runtime paths were produced\n";
        if (failureEventIndex != static_cast<std::size_t>(-1))
        {
            llvm::errs() << "note: all remaining paths were rejected while processing line "
                         << failureEvent.lineNumber
                         << " token '"
                         << (failureEvent.kind == EventKind::Plain ? failureEvent.baseName : failureEvent.rawToken)
                         << "'\n";

            std::vector<std::pair<std::string, std::size_t>> sortedReasons(
                failureReasons.begin(),
                failureReasons.end());
            std::sort(sortedReasons.begin(), sortedReasons.end(), [](const auto &lhs, const auto &rhs)
                      {
                if (lhs.second != rhs.second)
                {
                    return lhs.second > rhs.second;
                }
                return lhs.first < rhs.first; });

            for (const auto &entry : sortedReasons)
            {
                llvm::errs() << "  - rejected " << entry.second << " path(s): " << entry.first << "\n";
            }

            for (std::size_t i = 0U; i < failureExamples.size(); ++i)
            {
                const FailureExample &example = failureExamples[i];
                llvm::errs() << "  example " << (i + 1U) << ":\n";
                llvm::errs() << "    score before rejection: " << example.score << "\n";
                llvm::errs() << "    reason: " << example.reason << "\n";
                llvm::errs() << "    context stack: " << example.contextSummary << "\n";
                llvm::errs() << "    active callers: " << example.activeCallerSummary << "\n";
                llvm::errs() << "    recent assignments: " << example.assignmentSummary << "\n";
            }
        }
        return 1;
    }

    mergeEquivalentPathStates(activePaths);
    pruneTopK(activePaths, std::max<std::size_t>(1U, static_cast<std::size_t>(kTopK)));
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
    summary["pathsKept"] = static_cast<std::int64_t>(activePaths.size());
    summary["pathExpansions"] = static_cast<std::int64_t>(pathExpansionCount);
    summary["bestScore"] = best.score;
    summary["bestWarnings"] = static_cast<std::int64_t>(best.warnings.size());
    root["summary"] = std::move(summary);

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
            std::vector<std::string> visualizationWarnings;
            std::vector<ContextRun> contextRuns = buildContextRunsFromBestPath(events, path, visualizationWarnings);
            llvm::json::Object visualizationData = buildVisualizationData(events, contextRuns, visualizationWarnings, orderedEntrypoints);
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
