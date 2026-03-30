#include <algorithm>
#include <cctype>
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

    void emitInterFunctionDependencies() {
        for (const auto &Edge : InterFunctionCalls) {
            auto CallerIt = FunctionEntryNode.find(Edge.first);
            auto CalleeIt = FunctionEntryNode.find(Edge.second);
            if (CallerIt == FunctionEntryNode.end() || CalleeIt == FunctionEntryNode.end()) {
                continue;
            }

            Out << "  " << CallerIt->second << " -> " << CalleeIt->second
                << " [style=dashed,color=blue,label=\"calls\"];\n";
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
        const std::string EntryNodeId = BaseId + "_B" + std::to_string(Graph.getEntry().getBlockID());

        FunctionEntryNode[FunctionName] = EntryNodeId;

        if (const Stmt *Body = Func.getBody()) {
            std::set<std::string> Callees;
            DirectCallVisitor CallCollector(Callees);
            CallCollector.TraverseStmt(const_cast<Stmt *>(Body));

            for (const std::string &Callee : Callees) {
                if (Callee != FunctionName) {
                    InterFunctionCalls.insert({FunctionName, Callee});
                }
            }
        }

        Out << "  subgraph cluster_" << BaseId << " {\n";
        Out << "    label=\"" << escapeDot(FunctionName) << "\";\n";
        Out << "    style=rounded;\n";

        for (const CFGBlock *Block : Graph) {
            if (!Block) {
                continue;
            }

            const std::string NodeId = BaseId + "_B" + std::to_string(Block->getBlockID());
            const std::vector<std::string> Lines = blockLabelLines(*Block, Context);

            Out << "    " << NodeId << " [shape=box,label=\"";
            for (size_t I = 0; I < Lines.size(); ++I) {
                if (I != 0) {
                    Out << "\\l";
                }
                Out << escapeDot(Lines[I]);
            }
            Out << "\\l\"];\n";
        }

        for (const CFGBlock *Block : Graph) {
            if (!Block) {
                continue;
            }

            const std::string SrcId = BaseId + "_B" + std::to_string(Block->getBlockID());
            for (CFGBlock::const_succ_iterator I = Block->succ_begin(); I != Block->succ_end(); ++I) {
                const CFGBlock *Succ = I->getReachableBlock();
                if (!Succ) {
                    continue;
                }

                const std::string DstId = BaseId + "_B" + std::to_string(Succ->getBlockID());
                Out << "    " << SrcId << " -> " << DstId << ";\n";
            }
        }

        Out << "  }\n";
    }

    ASTContext &Context;
    llvm::raw_ostream &Out;
    bool &AnyFound;
    std::unordered_map<std::string, std::string> FunctionEntryNode;
    std::set<std::pair<std::string, std::string>> InterFunctionCalls;
};

class CfgCollectorConsumer : public ASTConsumer {
public:
    CfgCollectorConsumer(ASTContext &Context, llvm::raw_ostream &Out, bool &AnyFound)
        : Visitor(Context, Out, AnyFound) {}

    void HandleTranslationUnit(ASTContext &Context) override {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
        Visitor.emitInterFunctionDependencies();
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

    *Out << "digraph cfg {\n";
    *Out << "  rankdir=TB;\n";
    *Out << "  node [fontname=\"Courier New\", fontsize=10];\n";

    bool AnyFound = false;
    CfgActionFactory Factory(*Out, AnyFound);
    const int ToolResult = Tool.run(&Factory);

    *Out << "}\n";
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
