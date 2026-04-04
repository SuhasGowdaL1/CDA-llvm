#include <filesystem>
#include <fstream>
#include <string>

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include "cfg_generation.h"
#include "model.h"
#include "serialization.h"

namespace
{

    llvm::cl::OptionCategory kCategory("cfgb-interpreter options");

    llvm::cl::opt<std::string> kInput(
        llvm::cl::Positional,
        llvm::cl::desc("Input CFGB binary"),
        llvm::cl::value_desc("file"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kDotDir(
        "dot-dir",
        llvm::cl::desc("Directory for per-function DOT files"),
        llvm::cl::value_desc("dir"),
        llvm::cl::init("out/dotfiles"),
        llvm::cl::cat(kCategory));

} // namespace

int main(int argc, const char **argv)
{
    llvm::cl::ParseCommandLineOptions(argc, argv, "CFGB interpreter");

    CfgBundle bundle;
    std::string error;
    if (!readCfgBinary(kInput, bundle, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    if (!emitFunctionDotFiles(bundle, kDotDir, error))
    {
        llvm::errs() << "error: " << error << "\n";
        return 1;
    }

    llvm::outs() << "Wrote DOT files to: " << kDotDir << "\n";
    return 0;
}
