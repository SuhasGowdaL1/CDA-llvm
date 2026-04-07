/**
 * @file callgraph_generator_main.cpp
 * @brief CLI entrypoint for callgraph generation from analysis JSON.
 */

#include <cstddef>
#include <string>

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include "callgraph_analysis.h"

namespace
{

    llvm::cl::OptionCategory kCategory("callgraph-generator options");

    llvm::cl::opt<std::string> kInput(
        "i",
        llvm::cl::desc("Path to input analysis JSON"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/cfg-analysis.json"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kOutput(
        "o",
        llvm::cl::desc("Path to output callgraph JSON"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/callgraph.json"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kDotOutput(
        "dot-output",
        llvm::cl::desc("Path to output callgraph DOT file"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/callgraph.dot"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<bool> kNoDot(
        "no-dot",
        llvm::cl::desc("Disable DOT output"),
        llvm::cl::init(false),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<unsigned> kContextDepth(
        "context-depth",
        llvm::cl::desc("Bounded calling context depth"),
        llvm::cl::value_desc("N"),
        llvm::cl::init(2),
        llvm::cl::cat(kCategory));

} // namespace

/**
 * @brief Program entrypoint for callgraph_generator.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit code.
 */
int main(int argc, const char **argv)
{
    llvm::cl::HideUnrelatedOptions(kCategory);
    llvm::cl::ParseCommandLineOptions(argc, argv, "Generate callgraph from CFG analysis JSON\n");

    CallGraphStats stats;
    std::string error;

    const std::string dotOutput = kNoDot ? "" : static_cast<std::string>(kDotOutput);

    if (!generateCallGraphFromAnalysisJson(
            kInput,
            kOutput,
            dotOutput,
            static_cast<std::size_t>(kContextDepth),
            stats,
            error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    llvm::outs() << "Wrote callgraph JSON to: " << kOutput << "\n";
    if (!kNoDot)
    {
        llvm::outs() << "Wrote callgraph DOT to: " << kDotOutput << "\n";
    }
    llvm::outs() << "Functions: " << stats.functionCount << "\n";
    llvm::outs() << "Collapsed edges: " << stats.collapsedEdgeCount << "\n";
    llvm::outs() << "Unresolved indirect calls: " << stats.unresolvedIndirectCallCount << "\n";
    llvm::outs() << "Context nodes: " << stats.contextNodeCount << "\n";
    llvm::outs() << "Context edges: " << stats.contextEdgeCount << "\n";

    return 0;
}
