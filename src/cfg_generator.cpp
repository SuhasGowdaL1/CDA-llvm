#include <filesystem>

#include "clang/Analysis/CFG.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

#include "common.h"

using namespace clang;
using namespace clang::tooling;

namespace {

llvm::cl::OptionCategory CfgCategory("cfg-generator options");

llvm::cl::opt<std::string> OutputPath(
    "o",
    llvm::cl::desc("Path to output binary file"),
    llvm::cl::value_desc("file"),
    llvm::cl::init("out/cfg.cfgb"),
    llvm::cl::cat(CfgCategory));

llvm::cl::opt<std::string> DotOutputDir(
    "dot-dir",
    llvm::cl::desc("Directory for per-function DOT files"),
    llvm::cl::value_desc("dir"),
    llvm::cl::init("out/dotfiles"),
    llvm::cl::cat(CfgCategory));

llvm::cl::opt<std::string> FunctionFilter(
    "function",
    llvm::cl::desc("Only emit CFG for function with this exact name"),
    llvm::cl::value_desc("name"),
    llvm::cl::init(""),
    llvm::cl::cat(CfgCategory));

llvm::cl::opt<std::string> OutputFormat(
    "format",
    llvm::cl::desc("Output format: dot or bin"),
    llvm::cl::value_desc("dot|bin"),
    llvm::cl::init("dot"),
    llvm::cl::cat(CfgCategory));

struct LocatedCall {
    std::string Name;
    unsigned LocKey = 0;
};

std::vector<LocatedCall> extractDirectCallees(const Stmt *S, ASTContext &Context) {
    if (!S) {
        return {};
    }

    class CallExtractor : public RecursiveASTVisitor<CallExtractor> {
    public:
        explicit CallExtractor(ASTContext &Ctx) : Context(Ctx) {}

        ASTContext &Context;
        std::vector<LocatedCall> Calls;
        std::set<std::string> Seen;

        bool VisitCallExpr(CallExpr *Call) {
            if (!Call) {
                return true;
            }
            if (FunctionDecl *Callee = Call->getDirectCallee()) {
                const std::string Name = Callee->getQualifiedNameAsString();
                const SourceManager &SM = Context.getSourceManager();
                const SourceLocation Loc = SM.getSpellingLoc(Call->getExprLoc());
                const unsigned LocKey = Loc.getRawEncoding();
                const std::string Key = Name + "#" + std::to_string(LocKey);
                if (Seen.insert(Key).second) {
                    Calls.push_back(LocatedCall{Name, LocKey});
                }
            }
            return true;
        }
    } Extractor(Context);

    Extractor.TraverseStmt(const_cast<Stmt *>(S));
    return Extractor.Calls;
}

std::vector<std::string> blockLabelLines(const CFGBlock &Block, ASTContext &Context) {
    std::vector<std::string> Lines;
    std::set<const Stmt *> SeenStmts;
    std::set<std::string> SeenCallSites;

    for (const CFGElement &Element : Block) {
        if (auto Statement = Element.getAs<CFGStmt>()) {
            const Stmt *S = Statement->getStmt();
            if (!S) {
                continue;
            }
            if (!SeenStmts.insert(S).second) {
                continue;
            }

            const std::vector<LocatedCall> Calls = extractDirectCallees(S, Context);
            for (const LocatedCall &Call : Calls) {
                const std::string SiteKey = Call.Name + "#" + std::to_string(Call.LocKey);
                if (SeenCallSites.insert(SiteKey).second) {
                    Lines.push_back(Call.Name + "()");
                }
            }
        }
    }

    if (Lines.empty()) {
        Lines.emplace_back("");
    }

    return Lines;
}

class CfgCollectorVisitor : public RecursiveASTVisitor<CfgCollectorVisitor> {
public:
    CfgCollectorVisitor(ASTContext &Context, std::vector<SerializedFunction> &Functions)
        : Context(Context), Functions(Functions) {}

    bool VisitFunctionDecl(FunctionDecl *Func) {
        if (!Func) {
            return true;
        }

        if (!Func->hasBody() || !Func->isThisDeclarationADefinition()) {
            return true;
        }

        const std::string FunctionName = Func->getQualifiedNameAsString();
        if (!FunctionFilter.empty() && FunctionName != FunctionFilter) {
            return true;
        }

        Stmt *Body = Func->getBody();
        if (!Body) {
            return true;
        }

        CFG::BuildOptions Options;
        std::unique_ptr<CFG> Graph = CFG::buildCFG(Func, Body, &Context, Options);
        if (!Graph) {
            llvm::errs() << "warning: unable to build CFG for function: " << FunctionName << "\n";
            return true;
        }

        emitFunctionCfg(*Func, *Graph);
        return true;
    }

private:
    void emitFunctionCfg(const FunctionDecl &Func, const CFG &Graph) {
        const std::string FunctionName = Func.getQualifiedNameAsString();
        const std::string BaseId = sanitizeId(FunctionName);
        SerializedFunction Function;
        Function.Name = FunctionName;
        Function.BaseId = BaseId;
        Function.EntryBlockId = Graph.getEntry().getBlockID();

        // Collect raw blocks first, then reduce to a call-only CFG.
        std::vector<SerializedBlock> RawBlocks;
        std::unordered_map<unsigned, const SerializedBlock *> RawById;
        for (const CFGBlock *Block : Graph) {
            if (!Block) {
                continue;
            }

            SerializedBlock SBlock;
            SBlock.Id = Block->getBlockID();
            SBlock.Lines = blockLabelLines(*Block, Context);
            for (CFGBlock::const_succ_iterator It = Block->succ_begin(); It != Block->succ_end(); ++It) {
                if (*It) {
                    SBlock.Successors.push_back((*It)->getBlockID());
                }
            }
            RawBlocks.push_back(std::move(SBlock));
        }
        for (const SerializedBlock &B : RawBlocks) {
            RawById[B.Id] = &B;
        }

        auto blockHasCalls = [](const SerializedBlock &B) {
            for (const std::string &L : B.Lines) {
                if (!L.empty()) {
                    return true;
                }
            }
            return false;
        };

        std::set<unsigned> CallBlocks;
        unsigned MaxId = 0;
        for (const SerializedBlock &B : RawBlocks) {
            if (blockHasCalls(B)) {
                CallBlocks.insert(B.Id);
            }
            if (B.Id > MaxId) {
                MaxId = B.Id;
            }
        }

        auto nextCallBlocks = [&](unsigned StartId) {
            std::set<unsigned> Result;
            std::set<unsigned> Visited;
            std::vector<unsigned> Work;

            auto StartIt = RawById.find(StartId);
            if (StartIt == RawById.end()) {
                return Result;
            }
            for (unsigned Succ : StartIt->second->Successors) {
                Work.push_back(Succ);
            }

            while (!Work.empty()) {
                const unsigned Cur = Work.back();
                Work.pop_back();
                if (!Visited.insert(Cur).second) {
                    continue;
                }

                auto It = RawById.find(Cur);
                if (It == RawById.end()) {
                    continue;
                }
                if (CallBlocks.find(Cur) != CallBlocks.end()) {
                    Result.insert(Cur);
                    continue;
                }
                for (unsigned Succ : It->second->Successors) {
                    Work.push_back(Succ);
                }
            }

            return Result;
        };

        // Emit only call-bearing blocks with reduced call-to-call successors.
        for (const SerializedBlock &B : RawBlocks) {
            if (CallBlocks.find(B.Id) == CallBlocks.end()) {
                continue;
            }
            SerializedBlock Reduced;
            Reduced.Id = B.Id;
            for (const std::string &L : B.Lines) {
                if (!L.empty()) {
                    Reduced.Lines.push_back(L);
                }
            }
            const std::set<unsigned> Next = nextCallBlocks(B.Id);
            Reduced.Successors.assign(Next.begin(), Next.end());
            Function.Blocks.push_back(std::move(Reduced));
        }

        // Add a synthetic entry block to preserve entry branching without storing non-call blocks.
        const unsigned SyntheticEntryId = MaxId + 1;
        SerializedBlock Entry;
        Entry.Id = SyntheticEntryId;
        const std::set<unsigned> EntryTargets =
            (CallBlocks.find(Function.EntryBlockId) != CallBlocks.end())
                ? std::set<unsigned>{Function.EntryBlockId}
                : nextCallBlocks(Function.EntryBlockId);
        Entry.Successors.assign(EntryTargets.begin(), EntryTargets.end());
        Function.Blocks.push_back(std::move(Entry));
        Function.EntryBlockId = SyntheticEntryId;

        // Extract function calls
        class CallExtractor : public RecursiveASTVisitor<CallExtractor> {
        public:
            std::set<std::string> &Callees;
            CallExtractor(std::set<std::string> &C) : Callees(C) {}

            bool VisitCallExpr(CallExpr *Call) {
                if (FunctionDecl *Callee = Call->getDirectCallee()) {
                    Callees.insert(Callee->getQualifiedNameAsString());
                }
                return RecursiveASTVisitor::VisitCallExpr(Call);
            }
        } Extractor(Function.Callees);

        if (Func.getBody()) {
            Extractor.TraverseStmt(Func.getBody());
        }

        Functions.push_back(Function);
    }

    ASTContext &Context;
    std::vector<SerializedFunction> &Functions;
};

class CfgConsumer : public ASTConsumer {
public:
    CfgConsumer(ASTContext &Context, std::vector<SerializedFunction> &Functions)
        : Visitor(Context, Functions) {}

    void HandleTranslationUnit(ASTContext &Context) override {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }

private:
    CfgCollectorVisitor Visitor;
};

class CfgAction : public ASTFrontendAction {
public:
    CfgAction(std::vector<SerializedFunction> &Functions) : Functions(Functions) {}

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef InFile) override {
        return std::make_unique<CfgConsumer>(CI.getASTContext(), Functions);
    }

private:
    std::vector<SerializedFunction> &Functions;
};

class CfgActionFactory : public FrontendActionFactory {
public:
    CfgActionFactory(std::vector<SerializedFunction> &Functions) : Functions(Functions) {}

    std::unique_ptr<FrontendAction> create() override {
        return std::make_unique<CfgAction>(Functions);
    }

private:
    std::vector<SerializedFunction> &Functions;
};

void emitBinary(const std::vector<SerializedFunction> &Functions, llvm::raw_ostream &Out) {
    static constexpr char Magic[] = {'C', 'F', 'G', 'B', '2'};
    Out.write(Magic, sizeof(Magic));

    std::vector<std::string> LineTable;
    std::unordered_map<std::string, std::uint32_t> LineTableIndex;

    // Build line table
    for (const SerializedFunction &Fn : Functions) {
        for (const SerializedBlock &Block : Fn.Blocks) {
            for (const std::string &Line : Block.Lines) {
                if (LineTableIndex.find(Line) == LineTableIndex.end()) {
                    LineTableIndex[Line] = static_cast<std::uint32_t>(LineTable.size());
                    LineTable.push_back(Line);
                }
            }
        }
    }

    writeU32(Out, static_cast<std::uint32_t>(LineTable.size()));
    for (const std::string &Line : LineTable) {
        writeString(Out, Line);
    }

    writeU32(Out, static_cast<std::uint32_t>(Functions.size()));
    for (const SerializedFunction &Fn : Functions) {
        writeString(Out, Fn.Name);
        writeString(Out, Fn.BaseId);
        writeU32(Out, Fn.EntryBlockId);

        writeU32(Out, static_cast<std::uint32_t>(Fn.Blocks.size()));
        for (const SerializedBlock &Block : Fn.Blocks) {
            writeU32(Out, Block.Id);
            writeU32(Out, static_cast<std::uint32_t>(Block.Lines.size()));
            for (const std::string &Line : Block.Lines) {
                writeString(Out, Line);
            }
            writeU32(Out, static_cast<std::uint32_t>(Block.Successors.size()));
            for (unsigned Succ : Block.Successors) {
                writeU32(Out, Succ);
            }
        }

        writeU32(Out, static_cast<std::uint32_t>(Fn.Callees.size()));
        for (const std::string &Callee : Fn.Callees) {
            writeString(Out, Callee);
        }
    }
}

void emitPerFunctionDotFiles(const std::vector<SerializedFunction> &Functions,
                              const std::string &Dir) {
    std::error_code Ec;
    std::filesystem::create_directories(Dir, Ec);

    for (const SerializedFunction &Fn : Functions) {
        const std::filesystem::path DotPath = std::filesystem::path(Dir) / (Fn.BaseId + ".dot");

        std::error_code FileEc;
        llvm::raw_fd_ostream DotOut(DotPath.string(), FileEc);
        if (FileEc) {
            llvm::errs() << "warning: cannot open DOT file '" << DotPath << "'\n";
            continue;
        }

        DotOut << "digraph " << Fn.BaseId << " {\n";
        DotOut << "  rankdir=TB;\n";

        std::unordered_map<unsigned, const SerializedBlock *> BlockById;
        for (const SerializedBlock &Block : Fn.Blocks) {
            BlockById[Block.Id] = &Block;
        }

        auto hasCalls = [](const SerializedBlock &Block) {
            for (const std::string &Line : Block.Lines) {
                if (!Line.empty()) {
                    return true;
                }
            }
            return false;
        };

        std::set<unsigned> CallBlocks;
        for (const SerializedBlock &Block : Fn.Blocks) {
            if (hasCalls(Block)) {
                CallBlocks.insert(Block.Id);
            }
        }

        // Emit only call-bearing blocks.
        for (const SerializedBlock &Block : Fn.Blocks) {
            if (CallBlocks.find(Block.Id) == CallBlocks.end()) {
                continue;
            }
            const std::string BlockId = Fn.BaseId + "_B" + std::to_string(Block.Id);
            DotOut << "  " << BlockId << " [shape=box,label=\"";
            bool First = true;
            for (const std::string &Line : Block.Lines) {
                if (Line.empty()) {
                    continue;
                }
                if (!First) {
                    DotOut << "\\l";
                }
                DotOut << escapeDot(Line);
                First = false;
            }
            DotOut << "\\l\"];\n";
        }

        // Helper: follow successors through non-call blocks until the next call block(s).
        auto nextCallBlocks = [&](unsigned StartId) {
            std::set<unsigned> Result;
            std::set<unsigned> Visited;
            std::vector<unsigned> Work;

            auto ItStart = BlockById.find(StartId);
            if (ItStart == BlockById.end()) {
                return Result;
            }

            for (unsigned Succ : ItStart->second->Successors) {
                Work.push_back(Succ);
            }

            while (!Work.empty()) {
                const unsigned Cur = Work.back();
                Work.pop_back();
                if (!Visited.insert(Cur).second) {
                    continue;
                }

                auto It = BlockById.find(Cur);
                if (It == BlockById.end()) {
                    continue;
                }

                if (CallBlocks.find(Cur) != CallBlocks.end()) {
                    Result.insert(Cur);
                    continue;
                }

                for (unsigned Succ : It->second->Successors) {
                    Work.push_back(Succ);
                }
            }

            return Result;
        };

        // Connect call blocks with reduced call-only control-flow edges.
        for (unsigned Src : CallBlocks) {
            const std::string SrcId = Fn.BaseId + "_B" + std::to_string(Src);
            const std::set<unsigned> Next = nextCallBlocks(Src);
            for (unsigned Dst : Next) {
                const std::string DstId = Fn.BaseId + "_B" + std::to_string(Dst);
                DotOut << "  " << SrcId << " -> " << DstId << ";\n";
            }
        }

        // Add a synthetic START to show entry-to-first-call fanout for branch divergence.
        DotOut << "  " << Fn.BaseId << "_START [shape=circle,label=\"START\",style=filled,fillcolor=lightgreen];\n";
        std::set<unsigned> EntryTargets;
        if (CallBlocks.find(Fn.EntryBlockId) != CallBlocks.end()) {
            EntryTargets.insert(Fn.EntryBlockId);
        } else {
            EntryTargets = nextCallBlocks(Fn.EntryBlockId);
        }
        for (unsigned Dst : EntryTargets) {
            DotOut << "  " << Fn.BaseId << "_START -> " << Fn.BaseId << "_B" << Dst << ";\n";
        }

        DotOut << "}\n";
    }
}

bool isCSource(const std::filesystem::path &P) {
    const std::string Ext = P.extension().string();
    return Ext == ".c" || Ext == ".h";
}

std::vector<std::string> expandSourceInputs(const std::vector<std::string> &Inputs) {
    std::vector<std::string> Expanded;
    for (const std::string &P : Inputs) {
        std::error_code Ec;
        if (std::filesystem::is_directory(P, Ec)) {
            for (auto It = std::filesystem::recursive_directory_iterator(P);
                 It != std::filesystem::recursive_directory_iterator(); ++It) {
                if (std::filesystem::is_regular_file(It->path(), Ec)) {
                    if (isCSource(It->path())) {
                        Expanded.push_back(It->path().string());
                    }
                }
            }
            continue;
        }

        if (std::filesystem::is_regular_file(P, Ec)) {
            Expanded.push_back(P);
        }
    }

    std::sort(Expanded.begin(), Expanded.end());
    Expanded.erase(std::unique(Expanded.begin(), Expanded.end()), Expanded.end());
    return Expanded;
}

} // namespace

int main(int argc, const char **argv) {
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, CfgCategory);
    if (!ExpectedParser) {
        llvm::errs() << ExpectedParser.takeError();
        return 2;
    }

    CommonOptionsParser &OptionsParser = ExpectedParser.get();
    const std::vector<std::string> ExpandedInputs = expandSourceInputs(OptionsParser.getSourcePathList());
    if (ExpandedInputs.empty()) {
        llvm::errs() << "error: no C source files found from provided input paths\n";
        return 2;
    }

    llvm::outs() << "Processing " << ExpandedInputs.size() << " source files:\n";
    for (const auto &File : ExpandedInputs) {
        llvm::outs() << "  " << File << "\n";
    }

    ClangTool Tool(OptionsParser.getCompilations(), ExpandedInputs);
    Tool.appendArgumentsAdjuster(getInsertArgumentAdjuster("-xc", ArgumentInsertPosition::BEGIN));
    Tool.appendArgumentsAdjuster(getInsertArgumentAdjuster("-std=c11", ArgumentInsertPosition::BEGIN));

    std::vector<SerializedFunction> Functions;
    CfgActionFactory Factory(Functions);
    const int ToolResult = Tool.run(&Factory);

    if (ToolResult != 0) {
        llvm::errs() << "error: clang tooling failed with code " << ToolResult << "\n";
        return ToolResult;
    }

    if (Functions.empty()) {
        llvm::errs() << "warning: no function definitions with bodies were found\n";
        return 3;
    }

    llvm::outs() << "Found " << Functions.size() << " function definitions\n";

    // Always write binary
    {
        const std::filesystem::path BinPath(OutputPath.getValue());
        std::error_code Ec;
        if (!BinPath.parent_path().empty()) {
            std::filesystem::create_directories(BinPath.parent_path(), Ec);
        }

        llvm::raw_fd_ostream BinOut(OutputPath.getValue(), Ec);
        if (Ec) {
            llvm::errs() << "error: cannot open output file '" << OutputPath << "': "
                         << Ec.message() << "\n";
            return 1;
        }
        emitBinary(Functions, BinOut);
        BinOut.flush();
        llvm::outs() << "Wrote CFG binary to: " << OutputPath << "\n";
    }

    if (OutputFormat == "dot") {
        emitPerFunctionDotFiles(Functions, DotOutputDir.getValue());
        llvm::outs() << "Wrote per-function DOT files to: " << DotOutputDir << "\n";
    } else if (OutputFormat != "bin") {
        llvm::errs() << "error: unsupported format '" << OutputFormat << "' (use dot or bin)\n";
        return 2;
    }

    return 0;
}
