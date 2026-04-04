#include <string>
#include <vector>

#include "clang/Tooling/CommonOptionsParser.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include "cfg_generation.h"
#include "serialization.h"

namespace
{

    llvm::cl::OptionCategory kCategory("cfg-generator options");

    llvm::cl::opt<std::string> kOutput(
        "o",
        llvm::cl::desc("Path to output CFGB binary"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/cfg.cfgb"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kDotDir(
        "dot-dir",
        llvm::cl::desc("Directory for DOT files"),
        llvm::cl::value_desc("dir"),
        llvm::cl::init("out/dotfiles"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<bool> kEmitDot(
        "emit-dot",
        llvm::cl::desc("Emit per-function DOT files"),
        llvm::cl::init(false),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kFunctionFilter(
        "function",
        llvm::cl::desc("Generate CFG for a specific function name"),
        llvm::cl::value_desc("name"),
        llvm::cl::init(""),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kCfgMode(
        "cfg-mode",
        llvm::cl::desc("CFG mode: call (default) or full"),
        llvm::cl::value_desc("call|full"),
        llvm::cl::init("call"),
        llvm::cl::cat(kCategory));

} // namespace

int main(int argc, const char **argv)
{
    auto parser = clang::tooling::CommonOptionsParser::create(argc, argv, kCategory);
    if (!parser)
    {
        llvm::errs() << parser.takeError();
        return 2;
    }

    CfgMode mode = CfgMode::kCallOnly;
    if (kCfgMode == "full")
    {
        mode = CfgMode::kFull;
    }
    else if (kCfgMode != "call")
    {
        llvm::errs() << "error: unsupported --cfg-mode value: " << kCfgMode << "\n";
        return 2;
    }

    std::vector<std::string> compileArgs;
    compileArgs.push_back("-I.");

    CfgBundle bundle;
    std::string error;
    if (!generateCfgBundle(
            parser.get().getSourcePathList(),
            compileArgs,
            kFunctionFilter,
            mode,
            bundle,
            error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    if (bundle.functions.empty())
    {
        llvm::errs() << "error: no function definitions found\n";
        return 3;
    }

    if (!writeCfgBinary(kOutput, bundle, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    if (kEmitDot)
    {
        if (!emitFunctionDotFiles(bundle, kDotDir, error))
        {
            llvm::errs() << "error: " << error << "\n";
            return 1;
        }
        llvm::outs() << "Wrote DOT files to: " << kDotDir << "\n";
    }

    llvm::outs() << "Wrote CFGB binary to: " << kOutput << "\n";
    llvm::outs() << "Functions: " << bundle.functions.size() << "\n";
    return 0;
}
