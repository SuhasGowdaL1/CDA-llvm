#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "clang/Analysis/CFG.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace clang::tooling;

namespace {

llvm::cl::OptionCategory CfgCategory("cfg-generator options");

llvm::cl::opt<std::string> OutputPath(
    "o",
    llvm::cl::desc("Path to output DOT file (default: stdout)"),
    llvm::cl::value_desc("file"),
    llvm::cl::init(""),
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

struct SerializedBlock {
    unsigned Id = 0;
    std::vector<std::string> Lines;
    std::vector<unsigned> Successors;
};

struct SerializedFunction {
    std::string Name;
    std::string BaseId;
    unsigned EntryBlockId = 0;
    std::vector<SerializedBlock> Blocks;
    std::set<std::string> Callees;
};

void writeU32(llvm::raw_ostream &Out, std::uint32_t V) {
    char B[4];
    B[0] = static_cast<char>(V & 0xffu);
    B[1] = static_cast<char>((V >> 8) & 0xffu);
    B[2] = static_cast<char>((V >> 16) & 0xffu);
    B[3] = static_cast<char>((V >> 24) & 0xffu);
    Out.write(B, 4);
}

void writeString(llvm::raw_ostream &Out, const std::string &S) {
    writeU32(Out, static_cast<std::uint32_t>(S.size()));
    Out.write(S.data(), static_cast<std::streamsize>(S.size()));
}

std::string escapeDot(const std::string &Input) {
    std::string Out;
    Out.reserve(Input.size());
    for (char C : Input) {
        if (C == '"' || C == '\\') {
            Out.push_back('\\');
        }
        Out.push_back(C);
    }
    return Out;
}

std::string normalizeWhitespace(const std::string &Input) {
    std::string Out;
    Out.reserve(Input.size());

    bool InSpace = false;
    for (char C : Input) {
        const unsigned char UC = static_cast<unsigned char>(C);
        if (std::isspace(UC)) {
            if (!InSpace) {
                Out.push_back(' ');
                InSpace = true;
            }
            continue;
        }
        Out.push_back(C);
        InSpace = false;
    }

    while (!Out.empty() && Out.front() == ' ') {
        Out.erase(Out.begin());
    }
    while (!Out.empty() && Out.back() == ' ') {
        Out.pop_back();
    }

    return Out;
}

std::string sanitizeId(const std::string &Input) {
    std::string Out;
    Out.reserve(Input.size());
    for (char C : Input) {
        if ((C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') ||
            (C >= '0' && C <= '9') || C == '_') {
            Out.push_back(C);
        } else {
            Out.push_back('_');
        }
    }
    if (Out.empty()) {
        return "anon";
    }
    return Out;
}

std::vector<std::string> blockLabelLines(const CFGBlock &Block, ASTContext &Context) {
    std::vector<std::string> Lines;
    Lines.emplace_back("B" + std::to_string(Block.getBlockID()));

    if (Block.hasNoReturnElement()) {
        Lines.emplace_back("[noreturn]");
    }
    if (Block.isInevitablySinking()) {
        Lines.emplace_back("[sink]");
    }

    for (const CFGElement &Element : Block) {
        if (auto Statement = Element.getAs<CFGStmt>()) {
            const Stmt *S = Statement->getStmt();
            if (!S) {
                continue;
            }

            std::string Raw;
            llvm::raw_string_ostream Ros(Raw);
            PrintingPolicy Policy(Context.getLangOpts());
            S->printPretty(Ros, nullptr, Policy);
            Ros.flush();

            const std::string Pretty = normalizeWhitespace(Raw);
            if (!Pretty.empty()) {
                Lines.push_back(Pretty);
            }
            continue;
        }

        Lines.emplace_back("[cfg element kind " +
                           std::to_string(static_cast<unsigned>(Element.getKind())) + "]");
    }

    return Lines;
}

class CfgCollectorVisitor : public RecursiveASTVisitor<CfgCollectorVisitor> {
public:
    CfgCollectorVisitor(ASTContext &Context, llvm::raw_ostream &Out, bool &AnyFound)
        : Context(Context), Out(Out), AnyFound(AnyFound) {}

    void emitOutput() {
        if (OutputFormat == "bin") {
            emitBinary();
            return;
        }
        emitDot();
    }

    void emitDot() {
        Out << "digraph cfg {\n";
        Out << "  rankdir=TB;\n";
        Out << "  node [fontname=\"Courier New\", fontsize=10];\n";

        std::unordered_map<std::string, std::string> FunctionEntryNode;
        for (const SerializedFunction &Fn : Functions) {
            FunctionEntryNode[Fn.Name] = Fn.BaseId + "_B" + std::to_string(Fn.EntryBlockId);

            Out << "  subgraph cluster_" << Fn.BaseId << " {\n";
            Out << "    label=\"" << escapeDot(Fn.Name) << "\";\n";
            Out << "    style=rounded;\n";

            for (const SerializedBlock &Block : Fn.Blocks) {
                const std::string NodeId = Fn.BaseId + "_B" + std::to_string(Block.Id);
                Out << "    " << NodeId << " [shape=box,label=\"";
                for (size_t I = 0; I < Block.Lines.size(); ++I) {
                    if (I != 0) {
                        Out << "\\l";
                    }
                    Out << escapeDot(Block.Lines[I]);
                }
                Out << "\\l\"];\n";
            }

            for (const SerializedBlock &Block : Fn.Blocks) {
                const std::string SrcId = Fn.BaseId + "_B" + std::to_string(Block.Id);
                for (unsigned SuccId : Block.Successors) {
                    const std::string DstId = Fn.BaseId + "_B" + std::to_string(SuccId);
                    Out << "    " << SrcId << " -> " << DstId << ";\n";
                }
            }

            Out << "  }\n";
        }

        for (const SerializedFunction &Fn : Functions) {
            auto CallerIt = FunctionEntryNode.find(Fn.Name);
            if (CallerIt == FunctionEntryNode.end()) {
                continue;
            }
            for (const std::string &Callee : Fn.Callees) {
                auto CalleeIt = FunctionEntryNode.find(Callee);
                if (CalleeIt == FunctionEntryNode.end()) {
                    continue;
                }
                Out << "  " << CallerIt->second << " -> " << CalleeIt->second
                    << " [style=dashed,color=blue,label=\"calls\"];\n";
            }
        }

        Out << "}\n";
    }

    void emitBinary() {
        static constexpr char Magic[] = {'C', 'F', 'G', 'B', '2'};
        Out.write(Magic, sizeof(Magic));

        std::vector<std::string> LineTable;
        std::unordered_map<std::string, std::uint32_t> LineIndex;
        for (const SerializedFunction &Fn : Functions) {
            for (const SerializedBlock &Block : Fn.Blocks) {
                for (const std::string &Line : Block.Lines) {
                    auto It = LineIndex.find(Line);
                    if (It != LineIndex.end()) {
                        continue;
                    }
                    const std::uint32_t Idx = static_cast<std::uint32_t>(LineTable.size());
                    LineIndex.emplace(Line, Idx);
                    LineTable.push_back(Line);
                }
            }
        }

        writeU32(Out, static_cast<std::uint32_t>(LineTable.size()));
        for (const std::string &Line : LineTable) {
            writeString(Out, Line);
        }

        writeU32(Out, static_cast<std::uint32_t>(Functions.size()));

        std::unordered_map<std::string, std::uint32_t> FunctionIndex;
        for (std::uint32_t I = 0; I < Functions.size(); ++I) {
            FunctionIndex[Functions[I].Name] = I;
        }

        for (const SerializedFunction &Fn : Functions) {
            writeString(Out, Fn.Name);
            writeU32(Out, static_cast<std::uint32_t>(Fn.EntryBlockId));

            writeU32(Out, static_cast<std::uint32_t>(Fn.Blocks.size()));
            for (const SerializedBlock &Block : Fn.Blocks) {
                writeU32(Out, static_cast<std::uint32_t>(Block.Id));

                writeU32(Out, static_cast<std::uint32_t>(Block.Lines.size()));
                for (const std::string &Line : Block.Lines) {
                    auto It = LineIndex.find(Line);
                    if (It == LineIndex.end()) {
                        writeU32(Out, 0u);
                        continue;
                    }
                    writeU32(Out, It->second);
                }

                writeU32(Out, static_cast<std::uint32_t>(Block.Successors.size()));
                for (unsigned SuccId : Block.Successors) {
                    writeU32(Out, static_cast<std::uint32_t>(SuccId));
                }
            }

            std::vector<std::uint32_t> CalleeIndexes;
            for (const std::string &Callee : Fn.Callees) {
                auto It = FunctionIndex.find(Callee);
                if (It != FunctionIndex.end()) {
                    CalleeIndexes.push_back(It->second);
                }
            }

            writeU32(Out, static_cast<std::uint32_t>(CalleeIndexes.size()));
            for (std::uint32_t Idx : CalleeIndexes) {
                writeU32(Out, Idx);
            }
        }
    }

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
        AnyFound = true;
        return true;
    }

private:
    class DirectCallVisitor : public RecursiveASTVisitor<DirectCallVisitor> {
    public:
        explicit DirectCallVisitor(std::set<std::string> &Callees) : Callees(Callees) {}

        bool VisitCallExpr(CallExpr *Call) {
            if (!Call) {
                return true;
            }

            if (const FunctionDecl *Callee = Call->getDirectCallee()) {
                Callees.insert(Callee->getQualifiedNameAsString());
            }
            return true;
        }

    private:
        std::set<std::string> &Callees;
    };

    void emitFunctionCfg(const FunctionDecl &Func, const CFG &Graph) {
        const std::string FunctionName = Func.getQualifiedNameAsString();
        const std::string BaseId = sanitizeId(FunctionName);
        SerializedFunction Function;
        Function.Name = FunctionName;
        Function.BaseId = BaseId;
        Function.EntryBlockId = Graph.getEntry().getBlockID();

        if (const Stmt *Body = Func.getBody()) {
            std::set<std::string> Callees;
            DirectCallVisitor CallCollector(Callees);
            CallCollector.TraverseStmt(const_cast<Stmt *>(Body));

            for (const std::string &Callee : Callees) {
                if (Callee != FunctionName) {
                    Function.Callees.insert(Callee);
                }
            }
        }

        for (const CFGBlock *Block : Graph) {
            if (!Block) {
                continue;
            }

            SerializedBlock Serialized;
            Serialized.Id = Block->getBlockID();
            Serialized.Lines = blockLabelLines(*Block, Context);

            for (CFGBlock::const_succ_iterator I = Block->succ_begin(); I != Block->succ_end(); ++I) {
                const CFGBlock *Succ = I->getReachableBlock();
                if (!Succ) {
                    continue;
                }
                Serialized.Successors.push_back(Succ->getBlockID());
            }

            Function.Blocks.push_back(std::move(Serialized));
        }

        Functions.push_back(std::move(Function));
    }

    ASTContext &Context;
    llvm::raw_ostream &Out;
    bool &AnyFound;
    std::vector<SerializedFunction> Functions;
};

class CfgCollectorConsumer : public ASTConsumer {
public:
    CfgCollectorConsumer(ASTContext &Context, llvm::raw_ostream &Out, bool &AnyFound)
        : Visitor(Context, Out, AnyFound) {}

    void HandleTranslationUnit(ASTContext &Context) override {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
        Visitor.emitOutput();
    }

private:
    CfgCollectorVisitor Visitor;
};

class CfgCollectorAction : public ASTFrontendAction {
public:
    explicit CfgCollectorAction(llvm::raw_ostream &Out, bool &AnyFound)
        : Out(Out), AnyFound(AnyFound) {}

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &Compiler,
                                                   llvm::StringRef) override {
        return std::make_unique<CfgCollectorConsumer>(Compiler.getASTContext(), Out, AnyFound);
    }

private:
    llvm::raw_ostream &Out;
    bool &AnyFound;
};

class CfgActionFactory : public FrontendActionFactory {
public:
    CfgActionFactory(llvm::raw_ostream &Out, bool &AnyFound)
        : Out(Out), AnyFound(AnyFound) {}

    std::unique_ptr<FrontendAction> create() override {
        return std::make_unique<CfgCollectorAction>(Out, AnyFound);
    }

private:
    llvm::raw_ostream &Out;
    bool &AnyFound;
};

} // namespace

int main(int argc, const char **argv) {
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, CfgCategory);
    if (!ExpectedParser) {
        llvm::errs() << ExpectedParser.takeError();
        return 2;
    }

    CommonOptionsParser &OptionsParser = ExpectedParser.get();
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

    // Default C parsing mode for plain .c processing unless user overrides later arguments.
    Tool.appendArgumentsAdjuster(getInsertArgumentAdjuster("-xc", ArgumentInsertPosition::BEGIN));
    Tool.appendArgumentsAdjuster(getInsertArgumentAdjuster("-std=c11", ArgumentInsertPosition::BEGIN));

    std::error_code Ec;
    std::unique_ptr<llvm::raw_fd_ostream> FileOut;
    llvm::raw_ostream *Out = &llvm::outs();

    if (!OutputPath.empty()) {
        FileOut = std::make_unique<llvm::raw_fd_ostream>(OutputPath, Ec);
        if (Ec) {
            llvm::errs() << "error: cannot open output file '" << OutputPath << "': "
                         << Ec.message() << "\n";
            return 1;
        }
        Out = FileOut.get();
    }

    bool AnyFound = false;
    CfgActionFactory Factory(*Out, AnyFound);
    const int ToolResult = Tool.run(&Factory);
    Out->flush();

    if (ToolResult != 0) {
        llvm::errs() << "error: clang tooling failed with code " << ToolResult << "\n";
        return ToolResult;
    }

    if (!AnyFound) {
        llvm::errs() << "warning: no function definitions with bodies were found\n";
        return 3;
    }

    return 0;
}
