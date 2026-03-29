#include <algorithm>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
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
        if (C == '\n' || C == '\r') {
            Out.push_back(' ');
            continue;
        }
        Out.push_back(C);
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

std::string blockLabel(const CFGBlock &Block) {
    std::ostringstream Ss;
    Ss << "B" << Block.getBlockID();

    if (Block.hasNoReturnElement()) {
        Ss << "\\n[noreturn]";
    }
    if (Block.isInevitablySinking()) {
        Ss << "\\n[sink]";
    }

    return Ss.str();
}

class CfgCollectorVisitor : public RecursiveASTVisitor<CfgCollectorVisitor> {
public:
    CfgCollectorVisitor(ASTContext &Context, llvm::raw_ostream &Out, bool &AnyFound)
        : Context(Context), Out(Out), AnyFound(AnyFound) {}

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
    void emitFunctionCfg(const FunctionDecl &Func, const CFG &Graph) {
        const std::string FunctionName = Func.getQualifiedNameAsString();
        const std::string BaseId = sanitizeId(FunctionName);

        Out << "  subgraph cluster_" << BaseId << " {\n";
        Out << "    label=\"" << escapeDot(FunctionName) << "\";\n";
        Out << "    style=rounded;\n";

        for (const CFGBlock *Block : Graph) {
            if (!Block) {
                continue;
            }

            const std::string NodeId = BaseId + "_B" + std::to_string(Block->getBlockID());
            Out << "    " << NodeId << " [shape=box,label=\""
                << escapeDot(blockLabel(*Block)) << "\"];\n";
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
};

class CfgCollectorConsumer : public ASTConsumer {
public:
    CfgCollectorConsumer(ASTContext &Context, llvm::raw_ostream &Out, bool &AnyFound)
        : Visitor(Context, Out, AnyFound) {}

    void HandleTranslationUnit(ASTContext &Context) override {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
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
