/**
 * @file cfg_generator_main.cpp
 * @brief CLI entrypoint for CFG and analysis-fact generation.
 */

#include <string>
#include <fstream>
#include <sstream>
#include <set>
#include <vector>

#include "clang/Tooling/CommonOptionsParser.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include "analysis_output.h"
#include "cfg_generation.h"

namespace
{

    llvm::cl::OptionCategory kCategory("cfg-generator options");

    llvm::cl::opt<std::string> kOutput(
        "o",
        llvm::cl::desc("Path to output analysis JSON"),
        llvm::cl::value_desc("file"),
        llvm::cl::init("out/cfg-analysis.json"),
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

    llvm::cl::list<std::string> kIncludeDirs(
        "include-dir",
        llvm::cl::desc("Additional include directory to forward to Clang; may be repeated"),
        llvm::cl::value_desc("dir"),
        llvm::cl::cat(kCategory));

    llvm::cl::list<std::string> kCompileArgsFiles(
        "compile-args-file",
        llvm::cl::desc("File containing additional compiler arguments; may be repeated"),
        llvm::cl::value_desc("file"),
        llvm::cl::cat(kCategory));

    llvm::cl::opt<std::string> kBlacklistFile(
        "blacklist-file",
        llvm::cl::desc("Text file with exact function names to skip"),
        llvm::cl::value_desc("file"),
        llvm::cl::init(""),
        llvm::cl::cat(kCategory));

    bool loadCompileArgsFile(const std::string &filePath, std::vector<std::string> &compileArgs, std::string &error)
    {
        std::ifstream input(filePath);
        if (!input)
        {
            error = "failed to open compiler args file: " + filePath;
            return false;
        }

        std::string line;
        while (std::getline(input, line))
        {
            const std::size_t commentPos = line.find('#');
            if (commentPos != std::string::npos)
            {
                line = line.substr(0, commentPos);
            }

            std::istringstream stream(line);
            std::string argument;
            while (stream >> argument)
            {
                compileArgs.push_back(argument);
            }
        }

        return true;
    }

    bool loadNameListFile(const std::string &filePath, std::set<std::string> &names, std::string &error)
    {
        if (filePath.empty())
        {
            return true;
        }

        std::ifstream input(filePath);
        if (!input)
        {
            error = "failed to open blacklist file: " + filePath;
            return false;
        }

        std::string line;
        while (std::getline(input, line))
        {
            const std::size_t commentPos = line.find('#');
            if (commentPos != std::string::npos)
            {
                line = line.substr(0, commentPos);
            }

            std::istringstream stream(line);
            std::string name;
            while (stream >> name)
            {
                names.insert(name);
            }
        }

        return true;
    }

} // namespace

/**
 * @brief Program entrypoint for cfg_generator.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Process exit code.
 */
int main(int argc, const char **argv)
{
    auto parser = clang::tooling::CommonOptionsParser::create(argc, argv, kCategory);
    if (!parser)
    {
        llvm::errs() << parser.takeError();
        return 2;
    }

    std::vector<std::string> compileArgs;
    compileArgs.push_back("-I.");
    for (const std::string &includeDir : kIncludeDirs)
    {
        compileArgs.push_back("-I" + includeDir);
    }

    std::string compileArgsError;
    for (const std::string &argsFile : kCompileArgsFiles)
    {
        if (!loadCompileArgsFile(argsFile, compileArgs, compileArgsError))
        {
            llvm::errs() << "error: " << compileArgsError << "\n";
            return 1;
        }
    }

    std::set<std::string> blacklistedFunctions;
    std::string blacklistError;
    if (!loadNameListFile(kBlacklistFile, blacklistedFunctions, blacklistError))
    {
        llvm::errs() << "error: " << blacklistError << "\n";
        return 1;
    }

    CfgBundle bundle;
    std::string error;
    if (!generateCfgBundle(
            parser.get().getSourcePathList(),
            compileArgs,
            kFunctionFilter,
            blacklistedFunctions,
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

    if (!writeCfgAnalysisJson(kOutput, bundle, error))
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

    llvm::outs() << "Wrote analysis JSON to: " << kOutput << "\n";
    llvm::outs() << "Functions: " << bundle.functions.size() << "\n";
    return 0;
}
