#include <filesystem>
#include <iostream>

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include "common.h"

namespace {

llvm::cl::OptionCategory PathFinderCategory("path-finder options");

llvm::cl::opt<std::string> InputBinary(
    llvm::cl::Positional,
    llvm::cl::desc("Input CFG binary file"),
    llvm::cl::value_desc("file"),
    llvm::cl::cat(PathFinderCategory));

llvm::cl::opt<std::string> EntryPoint(
    "entrypoint",
    llvm::cl::desc("Entry point function name (default: main)"),
    llvm::cl::value_desc("name"),
    llvm::cl::init("main"),
    llvm::cl::cat(PathFinderCategory));

llvm::cl::opt<unsigned> MaxPaths(
    "max-paths",
    llvm::cl::desc("Maximum number of paths to enumerate (0 = unlimited)"),
    llvm::cl::value_desc("n"),
    llvm::cl::init(0),
    llvm::cl::cat(PathFinderCategory));

llvm::cl::opt<std::string> OutputFile(
    "o",
    llvm::cl::desc("Output file for enumerated paths (text format)"),
    llvm::cl::value_desc("file"),
    llvm::cl::init("out/paths.txt"),
    llvm::cl::cat(PathFinderCategory));

llvm::cl::opt<std::string> OutputBinary(
    "ob",
    llvm::cl::desc("Output file for enumerated paths (binary format)"),
    llvm::cl::value_desc("file"),
    llvm::cl::init(""),
    llvm::cl::cat(PathFinderCategory));

std::vector<std::vector<std::string>> enumerateFunctionPaths(
    const std::vector<SerializedFunction> &Functions,
    const std::string &EntryPointName,
    unsigned MaxPathsLimit) {
    const bool IsLimited = MaxPathsLimit != 0;

    auto isIdentStart = [](char C) {
        return (C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') || C == '_';
    };
    auto isIdent = [&](char C) {
        return isIdentStart(C) || (C >= '0' && C <= '9');
    };

    std::unordered_map<std::string, const SerializedFunction *> FunctionByName;
    std::set<std::string> Defined;
    for (const SerializedFunction &Fn : Functions) {
        Defined.insert(Fn.Name);
        FunctionByName[Fn.Name] = &Fn;
    }

    auto extractCalledFunctions = [&](const std::string &Line) {
        std::vector<std::string> Calls;
        for (size_t I = 0; I < Line.size(); ++I) {
            if (!isIdentStart(Line[I])) {
                continue;
            }

            size_t J = I + 1;
            while (J < Line.size() && isIdent(Line[J])) {
                ++J;
            }
            if (J >= Line.size() || Line[J] != '(') {
                I = J;
                continue;
            }

            const std::string Candidate = Line.substr(I, J - I);
            if (Defined.find(Candidate) != Defined.end()) {
                Calls.push_back(Candidate);
            }
            I = J;
        }
        return Calls;
    };

    auto enumerateLocalCallSequences = [&](const SerializedFunction &Fn) {
        std::unordered_map<unsigned, const SerializedBlock *> BlockById;
        for (const SerializedBlock &Block : Fn.Blocks) {
            BlockById[Block.Id] = &Block;
        }

        std::vector<std::vector<std::string>> Sequences;
        auto EntryIt = BlockById.find(Fn.EntryBlockId);
        if (EntryIt == BlockById.end()) {
            Sequences.push_back({});
            return Sequences;
        }

        std::function<void(unsigned, std::set<unsigned> &, std::vector<std::string> &)> DfsBlocks;
        DfsBlocks = [&](unsigned BlockId, std::set<unsigned> &Visited, std::vector<std::string> &CurrentCalls) {
            auto It = BlockById.find(BlockId);
            if (It == BlockById.end()) {
                Sequences.push_back(CurrentCalls);
                return;
            }

            const SerializedBlock *Block = It->second;
            const size_t BeforeCalls = CurrentCalls.size();
            for (const std::string &Line : Block->Lines) {
                const std::vector<std::string> CallsInLine = extractCalledFunctions(Line);
                for (const std::string &Call : CallsInLine) {
                    CurrentCalls.push_back(Call);
                }
            }

            bool Extended = false;
            for (unsigned Succ : Block->Successors) {
                if (Visited.find(Succ) != Visited.end()) {
                    continue;
                }
                Extended = true;
                Visited.insert(Succ);
                DfsBlocks(Succ, Visited, CurrentCalls);
                Visited.erase(Succ);
            }

            if (!Extended) {
                Sequences.push_back(CurrentCalls);
            }

            CurrentCalls.resize(BeforeCalls);
        };

        std::set<unsigned> Visited;
        Visited.insert(Fn.EntryBlockId);
        std::vector<std::string> CurrentCalls;
        DfsBlocks(Fn.EntryBlockId, Visited, CurrentCalls);

        std::set<std::string> Seen;
        std::vector<std::vector<std::string>> Unique;
        for (const std::vector<std::string> &Seq : Sequences) {
            std::string Key;
            for (const std::string &Call : Seq) {
                Key += Call;
                Key.push_back('\x1f');
            }
            if (Seen.insert(Key).second) {
                Unique.push_back(Seq);
            }
        }
        if (Unique.empty()) {
            Unique.push_back({});
        }
        return Unique;
    };

    std::string Start = EntryPointName;
    if (Defined.find(Start) == Defined.end()) {
        return {};
    }

    std::function<std::vector<std::vector<std::string>>(const std::string &, std::set<std::string> &)> ExpandFunction;

    ExpandFunction = [&](const std::string &FnName, std::set<std::string> &CallStack) {
        std::vector<std::vector<std::string>> Result;
        if (IsLimited && Result.size() >= MaxPathsLimit) {
            return Result;
        }

        auto FnIt = FunctionByName.find(FnName);
        if (FnIt == FunctionByName.end()) {
            Result.push_back({FnName});
            return Result;
        }

        const std::vector<std::vector<std::string>> LocalSeqs = enumerateLocalCallSequences(*FnIt->second);
        for (const std::vector<std::string> &Seq : LocalSeqs) {
            if (IsLimited && Result.size() >= MaxPathsLimit) {
                break;
            }

            std::vector<std::vector<std::string>> Partials;
            Partials.push_back({FnName});

            for (const std::string &Callee : Seq) {
                std::vector<std::vector<std::string>> NextPartials;
                for (const std::vector<std::string> &Partial : Partials) {
                    if (IsLimited && Result.size() + NextPartials.size() >= MaxPathsLimit) {
                        break;
                    }

                    auto CalleeIt = FunctionByName.find(Callee);
                    if (CalleeIt == FunctionByName.end()) {
                        NextPartials.push_back(Partial);
                        continue;
                    }

                    if (CallStack.find(Callee) != CallStack.end()) {
                        // Skip recursive/cyclic expansion to avoid loop-induced repetition in paths.
                        NextPartials.push_back(Partial);
                        continue;
                    }

                    CallStack.insert(Callee);
                    const std::vector<std::vector<std::string>> ExpandedCallee = ExpandFunction(Callee, CallStack);
                    CallStack.erase(Callee);

                    if (ExpandedCallee.empty()) {
                        NextPartials.push_back(Partial);
                        continue;
                    }

                    for (const std::vector<std::string> &CalleePath : ExpandedCallee) {
                        if (IsLimited && Result.size() + NextPartials.size() >= MaxPathsLimit) {
                            break;
                        }
                        std::vector<std::string> Combined = Partial;
                        Combined.insert(Combined.end(), CalleePath.begin(), CalleePath.end());
                        NextPartials.push_back(std::move(Combined));
                    }
                }

                if (NextPartials.empty()) {
                    break;
                }
                Partials.swap(NextPartials);
            }

            if (Partials.empty()) {
                Result.push_back({FnName});
            } else {
                for (std::vector<std::string> &P : Partials) {
                    if (IsLimited && Result.size() >= MaxPathsLimit) {
                        break;
                    }
                    Result.push_back(std::move(P));
                }
            }
        }

        if (Result.empty()) {
            Result.push_back({FnName});
        }
        if (IsLimited && Result.size() > MaxPathsLimit) {
            Result.resize(MaxPathsLimit);
        }
        return Result;
    };

    std::set<std::string> CallStack;
    CallStack.insert(Start);
    std::vector<std::vector<std::string>> Paths = ExpandFunction(Start, CallStack);
    if (IsLimited && Paths.size() > MaxPathsLimit) {
        Paths.resize(MaxPathsLimit);
    }
    return Paths;
}

void writePaths(const std::string &OutputPath, const std::vector<std::vector<std::string>> &Paths) {
    std::error_code Ec;
    const std::filesystem::path OutPath(OutputPath);
    if (!OutPath.parent_path().empty()) {
        std::filesystem::create_directories(OutPath.parent_path(), Ec);
    }

    std::ofstream File(OutputPath);
    if (!File) {
        llvm::errs() << "error: cannot open output file '" << OutputPath << "'\n";
        return;
    }

    File << "Total paths: " << Paths.size() << "\n";
    File << "==================================================\n";

    for (size_t I = 0; I < Paths.size(); ++I) {
        File << "Path " << (I + 1) << ": ";
        for (size_t J = 0; J < Paths[I].size(); ++J) {
            if (J != 0) {
                File << " -> ";
            }
            File << Paths[I][J];
        }
        File << "\n";
    }

    llvm::outs() << "Wrote " << Paths.size() << " paths to: " << OutputPath << "\n";
}

void writePathsBinary(const std::string &OutputPath, const std::vector<std::vector<std::string>> &Paths) {
    std::error_code Ec;
    const std::filesystem::path OutPath(OutputPath);
    if (!OutPath.parent_path().empty()) {
        std::filesystem::create_directories(OutPath.parent_path(), Ec);
    }

    std::ofstream File(OutputPath, std::ios::binary);
    if (!File) {
        llvm::errs() << "error: cannot open binary output file '" << OutputPath << "'\n";
        return;
    }

    auto writeU32 = [](std::ofstream &F, std::uint32_t V) {
        unsigned char B[4];
        B[0] = static_cast<unsigned char>(V & 0xffu);
        B[1] = static_cast<unsigned char>((V >> 8) & 0xffu);
        B[2] = static_cast<unsigned char>((V >> 16) & 0xffu);
        B[3] = static_cast<unsigned char>((V >> 24) & 0xffu);
        F.write(reinterpret_cast<char *>(B), 4);
    };

    auto writeString = [&writeU32](std::ofstream &F, const std::string &S) {
        writeU32(F, static_cast<std::uint32_t>(S.size()));
        F.write(S.data(), static_cast<std::streamsize>(S.size()));
    };

    // Write magic header and version
    File.write("PTHS", 4);
    unsigned char Version = 1;
    File.write(reinterpret_cast<char *>(&Version), 1);

    // Build function lookup table
    std::vector<std::string> FunctionTable;
    std::unordered_map<std::string, std::uint32_t> FunctionIndex;

    for (const auto &Path : Paths) {
        for (const auto &FuncName : Path) {
            if (FunctionIndex.find(FuncName) == FunctionIndex.end()) {
                FunctionIndex[FuncName] = static_cast<std::uint32_t>(FunctionTable.size());
                FunctionTable.push_back(FuncName);
            }
        }
    }

    // Write function lookup table
    writeU32(File, static_cast<std::uint32_t>(FunctionTable.size()));
    for (const auto &FuncName : FunctionTable) {
        writeString(File, FuncName);
    }

    // Write paths with function indices
    writeU32(File, static_cast<std::uint32_t>(Paths.size()));
    for (const auto &Path : Paths) {
        writeU32(File, static_cast<std::uint32_t>(Path.size()));
        for (const auto &FuncName : Path) {
            writeU32(File, FunctionIndex[FuncName]);
        }
    }

    File.flush();
    llvm::outs() << "Wrote " << Paths.size() << " paths to binary: " << OutputPath << "\n";
}

} // namespace

int main(int argc, const char **argv) {
    llvm::cl::ParseCommandLineOptions(argc, argv, "Path enumerator for CFG");

    if (InputBinary.empty()) {
        llvm::errs() << "error: input binary file required\n";
        return 1;
    }

    llvm::outs() << "Reading CFG binary: " << InputBinary << "\n";
    std::vector<SerializedFunction> Functions = readBinary(InputBinary);
    
    if (Functions.empty()) {
        llvm::errs() << "error: no functions found in binary\n";
        return 1;
    }

    llvm::outs() << "Loaded " << Functions.size() << " functions from binary\n";

    {
        bool FoundEntry = false;
        std::vector<std::string> Names;
        Names.reserve(Functions.size());
        for (const SerializedFunction &Fn : Functions) {
            Names.push_back(Fn.Name);
            if (Fn.Name == EntryPoint) {
                FoundEntry = true;
            }
        }
        if (!FoundEntry) {
            std::sort(Names.begin(), Names.end());
            llvm::errs() << "error: entry point '" << EntryPoint << "' not found in CFG binary\n";
            llvm::errs() << "available functions:";
            for (const std::string &N : Names) {
                llvm::errs() << " " << N;
            }
            llvm::errs() << "\n";
            return 2;
        }
    }

    llvm::outs() << "Enumerating paths from entry point: " << EntryPoint << "\n";
    std::vector<std::vector<std::string>> Paths = 
        enumerateFunctionPaths(Functions, EntryPoint, MaxPaths);

    if (Paths.empty()) {
        llvm::outs() << "warning: no paths found\n";
    }

    writePaths(OutputFile, Paths);

    if (!OutputBinary.empty()) {
        writePathsBinary(OutputBinary, Paths);
    }

    // Also print to stdout
    llvm::outs() << "\n--- Function Call Paths ---\n";
    for (size_t I = 0; I < Paths.size(); ++I) {
        llvm::outs() << "Path " << (I + 1) << ": ";
        for (size_t J = 0; J < Paths[I].size(); ++J) {
            if (J != 0) {
                llvm::outs() << " -> ";
            }
            llvm::outs() << Paths[I][J];
        }
        llvm::outs() << "\n";
    }

    // Print call graph summary
    llvm::outs() << "\n--- Call Graph Summary ---\n";
    std::unordered_map<std::string, std::set<std::string>> CallGraph;
    std::set<std::string> DefinedFunctions;
    
    for (const SerializedFunction &Fn : Functions) {
        DefinedFunctions.insert(Fn.Name);
    }

    for (const SerializedFunction &Fn : Functions) {
        for (const std::string &Callee : Fn.Callees) {
            if (DefinedFunctions.find(Callee) != DefinedFunctions.end()) {
                CallGraph[Fn.Name].insert(Callee);
            }
        }
    }

    for (const auto &[Caller, Callees] : CallGraph) {
        llvm::outs() << Caller << " calls: ";
        for (const auto &Callee : Callees) {
            llvm::outs() << Callee << " ";
        }
        llvm::outs() << "\n";
    }

    return 0;
}
