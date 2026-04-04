#include "cfg_generation.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/CFG.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/ArgumentsAdjusters.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/raw_ostream.h"

#include "serialization.h"

namespace
{

    struct LocatedCall
    {
        std::string name;
        unsigned locationKey = 0;
    };

    class CallVisitor : public clang::RecursiveASTVisitor<CallVisitor>
    {
    public:
        explicit CallVisitor(clang::ASTContext &context)
            : context_(context)
        {
        }

        bool VisitCallExpr(clang::CallExpr *call)
        {
            if (call == nullptr)
            {
                return true;
            }

            clang::FunctionDecl *callee = call->getDirectCallee();
            if (callee == nullptr)
            {
                return true;
            }

            const std::string calleeName = callee->getQualifiedNameAsString();
            const clang::SourceManager &sourceManager = context_.getSourceManager();
            const clang::SourceLocation location = sourceManager.getSpellingLoc(call->getExprLoc());
            const unsigned locationKey = location.getRawEncoding();

            const std::string key = calleeName + "#" + std::to_string(locationKey);
            if (seen_.insert(key).second)
            {
                calls_.push_back(LocatedCall{calleeName, locationKey});
            }

            if (calleeName == "State_Change")
            {
                if (stateChangeValues_.empty())
                {
                    stateChangeValues_.assign(3, std::set<std::string>{});
                }
                for (unsigned argIndex = 0; argIndex < 3U; ++argIndex)
                {
                    if (argIndex < call->getNumArgs())
                    {
                        stateChangeValues_[argIndex].insert(extractArgumentText(call->getArg(argIndex)));
                    }
                }
            }

            return true;
        }

        const std::vector<LocatedCall> &calls() const
        {
            return calls_;
        }

        const std::vector<std::set<std::string>> &stateChangeValues() const
        {
            return stateChangeValues_;
        }

    private:
        std::string extractArgumentText(const clang::Expr *expr)
        {
            if (expr == nullptr)
            {
                return "";
            }
            const clang::SourceManager &sourceManager = context_.getSourceManager();
            clang::SourceRange sourceRange = expr->getSourceRange();
            clang::CharSourceRange tokenRange = clang::CharSourceRange::getTokenRange(sourceRange);
            const clang::LangOptions &langOptions = context_.getLangOpts();
            const llvm::StringRef text = clang::Lexer::getSourceText(tokenRange, sourceManager, langOptions);
            return normalizeWhitespace(text.str());
        }

        clang::ASTContext &context_;
        std::vector<LocatedCall> calls_;
        std::unordered_set<std::string> seen_;
        std::vector<std::set<std::string>> stateChangeValues_;
    };

    std::vector<LocatedCall> extractDirectCallees(const clang::Stmt *statement, clang::ASTContext &context)
    {
        if (statement == nullptr)
        {
            return {};
        }
        CallVisitor visitor(context);
        visitor.TraverseStmt(const_cast<clang::Stmt *>(statement));
        return visitor.calls();
    }

    std::string extractStatementText(const clang::Stmt *statement, clang::ASTContext &context)
    {
        if (statement == nullptr)
        {
            return "";
        }
        const clang::SourceManager &sourceManager = context.getSourceManager();
        const clang::LangOptions &langOptions = context.getLangOpts();
        const clang::CharSourceRange tokenRange = clang::CharSourceRange::getTokenRange(statement->getSourceRange());
        const llvm::StringRef text = clang::Lexer::getSourceText(tokenRange, sourceManager, langOptions);
        return normalizeWhitespace(text.str());
    }

    std::vector<std::string> collectBlockLines(const clang::CFGBlock &block, clang::ASTContext &context, CfgMode mode)
    {
        std::vector<std::string> lines;
        std::set<const clang::Stmt *> seenStatements;
        std::set<std::string> seenCallSites;

        for (const clang::CFGElement &element : block)
        {
            auto statement = element.getAs<clang::CFGStmt>();
            if (!statement)
            {
                continue;
            }
            const clang::Stmt *stmt = statement->getStmt();
            if (stmt == nullptr || !seenStatements.insert(stmt).second)
            {
                continue;
            }

            if (mode == CfgMode::kFull)
            {
                const std::string stmtText = extractStatementText(stmt, context);
                if (!stmtText.empty())
                {
                    lines.push_back(stmtText);
                }
            }
            else
            {
                const std::vector<LocatedCall> calls = extractDirectCallees(stmt, context);
                for (const LocatedCall &call : calls)
                {
                    const std::string siteKey = call.name + "#" + std::to_string(call.locationKey);
                    if (seenCallSites.insert(siteKey).second)
                    {
                        lines.push_back(call.name);
                    }
                }
            }
        }

        return lines;
    }

    std::vector<LoopGroup> detectLoopGroups(const std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> &graph)
    {
        std::unordered_map<std::uint32_t, int> indexByNode;
        std::unordered_map<std::uint32_t, int> lowlinkByNode;
        std::unordered_set<std::uint32_t> onStack;
        std::vector<std::uint32_t> stack;
        std::vector<LoopGroup> loopGroups;
        int nextIndex = 0;

        std::function<void(std::uint32_t)> strongConnect = [&](std::uint32_t node)
        {
            indexByNode[node] = nextIndex;
            lowlinkByNode[node] = nextIndex;
            ++nextIndex;
            stack.push_back(node);
            onStack.insert(node);

            const auto it = graph.find(node);
            if (it != graph.end())
            {
                for (std::uint32_t successor : it->second)
                {
                    if (indexByNode.find(successor) == indexByNode.end())
                    {
                        strongConnect(successor);
                        lowlinkByNode[node] = std::min(lowlinkByNode[node], lowlinkByNode[successor]);
                    }
                    else if (onStack.find(successor) != onStack.end())
                    {
                        lowlinkByNode[node] = std::min(lowlinkByNode[node], indexByNode[successor]);
                    }
                }
            }

            if (lowlinkByNode[node] == indexByNode[node])
            {
                std::vector<std::uint32_t> component;
                while (!stack.empty())
                {
                    const std::uint32_t top = stack.back();
                    stack.pop_back();
                    onStack.erase(top);
                    component.push_back(top);
                    if (top == node)
                    {
                        break;
                    }
                }

                bool isLoop = component.size() > 1U;
                if (!isLoop && !component.empty())
                {
                    const auto selfIt = graph.find(component.front());
                    if (selfIt != graph.end())
                    {
                        for (std::uint32_t successor : selfIt->second)
                        {
                            if (successor == component.front())
                            {
                                isLoop = true;
                                break;
                            }
                        }
                    }
                }

                if (isLoop)
                {
                    std::sort(component.begin(), component.end());
                    loopGroups.push_back(LoopGroup{std::move(component)});
                }
            }
        };

        for (const auto &entry : graph)
        {
            if (indexByNode.find(entry.first) == indexByNode.end())
            {
                strongConnect(entry.first);
            }
        }

        std::sort(loopGroups.begin(), loopGroups.end(), [](const LoopGroup &lhs, const LoopGroup &rhs)
                  {
            if (lhs.blockIds.size() != rhs.blockIds.size())
            {
                return lhs.blockIds.size() < rhs.blockIds.size();
            }
            return lhs.blockIds < rhs.blockIds; });

        return loopGroups;
    }

    struct CollectorState
    {
        clang::ASTContext *context = nullptr;
        CfgMode mode = CfgMode::kCallOnly;
        std::string functionFilter;
        std::vector<SerializedFunction> *functions = nullptr;
        std::unordered_map<std::string, std::vector<std::set<std::string>>> stateChangeMap;
        std::unordered_map<std::string, std::set<std::string>> directCallGraph;
    };

    class CfgVisitor : public clang::RecursiveASTVisitor<CfgVisitor>
    {
    public:
        explicit CfgVisitor(CollectorState &state)
            : state_(state)
        {
        }

        bool VisitFunctionDecl(clang::FunctionDecl *functionDecl)
        {
            if (functionDecl == nullptr || !functionDecl->hasBody() || !functionDecl->isThisDeclarationADefinition())
            {
                return true;
            }

            const std::string functionName = functionDecl->getQualifiedNameAsString();
            if (!state_.functionFilter.empty() && functionName != state_.functionFilter)
            {
                return true;
            }

            clang::Stmt *body = functionDecl->getBody();
            if (body == nullptr)
            {
                return true;
            }

            clang::CFG::BuildOptions options;
            std::unique_ptr<clang::CFG> graph = clang::CFG::buildCFG(functionDecl, body, state_.context, options);
            if (graph == nullptr)
            {
                llvm::errs() << "warning: unable to build CFG for function: " << functionName << "\n";
                return true;
            }

            SerializedFunction function;
            function.name = functionName;
            function.entryBlockId = static_cast<std::uint32_t>(graph->getEntry().getBlockID());
            function.exitBlockId = static_cast<std::uint32_t>(graph->getExit().getBlockID());

            std::vector<SerializedBlock> rawBlocks;
            std::unordered_map<std::uint32_t, const SerializedBlock *> rawById;
            std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> adjacency;

            for (const clang::CFGBlock *block : *graph)
            {
                if (block == nullptr)
                {
                    continue;
                }

                SerializedBlock serializedBlock;
                serializedBlock.id = static_cast<std::uint32_t>(block->getBlockID());
                serializedBlock.lines = collectBlockLines(*block, *state_.context, state_.mode);

                for (clang::CFGBlock::const_succ_iterator successorIt = block->succ_begin();
                     successorIt != block->succ_end();
                     ++successorIt)
                {
                    if (*successorIt != nullptr)
                    {
                        serializedBlock.successors.push_back(
                            static_cast<std::uint32_t>((*successorIt)->getBlockID()));
                    }
                }

                adjacency[serializedBlock.id] = serializedBlock.successors;
                rawBlocks.push_back(std::move(serializedBlock));
            }

            const std::vector<LoopGroup> loopGroups = detectLoopGroups(adjacency);
            std::unordered_set<std::uint32_t> loopMembers;
            for (const LoopGroup &group : loopGroups)
            {
                for (std::uint32_t blockId : group.blockIds)
                {
                    loopMembers.insert(blockId);
                }
            }
            for (SerializedBlock &block : rawBlocks)
            {
                block.attributes.hasLoop = loopMembers.find(block.id) != loopMembers.end();
                rawById[block.id] = &block;
            }

            function.attributes.loopGroups = loopGroups;

            auto hasContent = [](const SerializedBlock &block)
            {
                for (const std::string &line : block.lines)
                {
                    if (!line.empty())
                    {
                        return true;
                    }
                }
                return false;
            };

            if (state_.mode == CfgMode::kFull)
            {
                function.blocks = rawBlocks;
            }
            else
            {
                auto isKeptId = [&](std::uint32_t blockId)
                {
                    const auto blockIt = rawById.find(blockId);
                    if (blockIt == rawById.end())
                    {
                        return false;
                    }
                    const SerializedBlock &block = *blockIt->second;
                    return hasContent(block) ||
                           block.id == function.entryBlockId ||
                           block.id == function.exitBlockId ||
                           loopMembers.find(block.id) != loopMembers.end();
                };

                std::set<std::uint32_t> callBlocks;
                for (const SerializedBlock &block : rawBlocks)
                {
                    if (hasContent(block))
                    {
                        callBlocks.insert(block.id);
                    }
                }

                auto nextCallBlocks = [&](std::uint32_t startId)
                {
                    std::set<std::uint32_t> result;
                    std::set<std::uint32_t> visited;
                    std::vector<std::uint32_t> work;

                    const auto startIt = rawById.find(startId);
                    if (startIt == rawById.end())
                    {
                        return result;
                    }

                    for (std::uint32_t successor : startIt->second->successors)
                    {
                        work.push_back(successor);
                    }

                    while (!work.empty())
                    {
                        const std::uint32_t current = work.back();
                        work.pop_back();
                        if (!visited.insert(current).second)
                        {
                            continue;
                        }

                        const auto currentIt = rawById.find(current);
                        if (currentIt == rawById.end())
                        {
                            continue;
                        }

                        if (callBlocks.find(current) != callBlocks.end())
                        {
                            result.insert(current);
                            continue;
                        }

                        if (current == function.exitBlockId)
                        {
                            result.insert(current);
                            continue;
                        }

                        for (std::uint32_t successor : currentIt->second->successors)
                        {
                            work.push_back(successor);
                        }
                    }

                    return result;
                };

                for (const SerializedBlock &block : rawBlocks)
                {
                    const bool keepBlock =
                        hasContent(block) ||
                        block.id == function.entryBlockId ||
                        block.id == function.exitBlockId ||
                        loopMembers.find(block.id) != loopMembers.end();

                    if (!keepBlock)
                    {
                        continue;
                    }

                    SerializedBlock reduced;
                    reduced.id = block.id;
                    reduced.attributes = block.attributes;

                    if (block.id == function.exitBlockId)
                    {
                        reduced.successors.clear();
                    }
                    else if (loopMembers.find(block.id) != loopMembers.end())
                    {
                        for (std::uint32_t successor : block.successors)
                        {
                            if (isKeptId(successor))
                            {
                                reduced.successors.push_back(successor);
                            }
                        }
                    }
                    else
                    {
                        const std::set<std::uint32_t> next = nextCallBlocks(block.id);
                        reduced.successors.assign(next.begin(), next.end());
                    }
                    for (const std::string &line : block.lines)
                    {
                        if (!line.empty())
                        {
                            reduced.lines.push_back(line);
                        }
                    }
                    function.blocks.push_back(std::move(reduced));
                }

                // Final cleanup for call-only binary storage: keep only entry, exit, and call-bearing blocks.
                std::unordered_set<std::uint32_t> keptIds;
                for (const SerializedBlock &block : function.blocks)
                {
                    const bool keep =
                        block.id == function.entryBlockId ||
                        block.id == function.exitBlockId ||
                        hasContent(block) ||
                        loopMembers.find(block.id) != loopMembers.end();
                    if (keep)
                    {
                        keptIds.insert(block.id);
                    }
                }

                std::vector<SerializedBlock> compacted;
                compacted.reserve(function.blocks.size());
                for (const SerializedBlock &block : function.blocks)
                {
                    if (keptIds.find(block.id) == keptIds.end())
                    {
                        continue;
                    }

                    SerializedBlock compact = block;
                    std::vector<std::uint32_t> filteredSucc;
                    for (std::uint32_t successor : compact.successors)
                    {
                        if (keptIds.find(successor) != keptIds.end())
                        {
                            filteredSucc.push_back(successor);
                        }
                    }
                    compact.successors.swap(filteredSucc);
                    compacted.push_back(std::move(compact));
                }
                function.blocks.swap(compacted);

                std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> reducedAdjacency;
                for (const SerializedBlock &block : function.blocks)
                {
                    reducedAdjacency[block.id] = block.successors;
                }
                const std::vector<LoopGroup> reducedLoopGroups = detectLoopGroups(reducedAdjacency);
                std::unordered_set<std::uint32_t> reducedLoopMembers;
                for (const LoopGroup &group : reducedLoopGroups)
                {
                    for (std::uint32_t blockId : group.blockIds)
                    {
                        reducedLoopMembers.insert(blockId);
                    }
                }
                function.attributes.loopGroups = reducedLoopGroups;
                for (SerializedBlock &block : function.blocks)
                {
                    block.attributes.hasLoop = reducedLoopMembers.find(block.id) != reducedLoopMembers.end();
                }
            }

            CallVisitor callVisitor(*state_.context);
            callVisitor.TraverseStmt(body);
            for (const LocatedCall &call : callVisitor.calls())
            {
                state_.directCallGraph[function.name].insert(call.name);
            }

            if (!callVisitor.stateChangeValues().empty())
            {
                function.attributes.callsStateChange = true;
                function.attributes.stateChangeParameterValues = callVisitor.stateChangeValues();
            }

            state_.functions->push_back(std::move(function));
            return true;
        }

    private:
        CollectorState &state_;
    };

    class CfgConsumer : public clang::ASTConsumer
    {
    public:
        explicit CfgConsumer(CollectorState &state)
            : visitor_(state)
        {
        }

        void HandleTranslationUnit(clang::ASTContext &context) override
        {
            (void)context;
            visitor_.TraverseDecl(context.getTranslationUnitDecl());
        }

    private:
        CfgVisitor visitor_;
    };

    class CfgAction : public clang::ASTFrontendAction
    {
    public:
        explicit CfgAction(CollectorState &state)
            : state_(state)
        {
        }

        std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
            clang::CompilerInstance &compilerInstance,
            llvm::StringRef inputFile) override
        {
            (void)inputFile;
            state_.context = &compilerInstance.getASTContext();
            return std::make_unique<CfgConsumer>(state_);
        }

    private:
        CollectorState &state_;
    };

    class CfgActionFactory : public clang::tooling::FrontendActionFactory
    {
    public:
        explicit CfgActionFactory(CollectorState &state)
            : state_(state)
        {
        }

        std::unique_ptr<clang::FrontendAction> create() override
        {
            return std::make_unique<CfgAction>(state_);
        }

    private:
        CollectorState &state_;
    };

    void computeRecursionAttributes(
        std::vector<SerializedFunction> &functions,
        const std::unordered_map<std::string, std::set<std::string>> &directCallGraph)
    {
        std::unordered_map<std::string, std::size_t> indexByName;
        for (std::size_t index = 0; index < functions.size(); ++index)
        {
            indexByName[functions[index].name] = index;
        }

        for (SerializedFunction &function : functions)
        {
            const auto graphIt = directCallGraph.find(function.name);
            function.attributes.hasDirectRecursion =
                graphIt != directCallGraph.end() && graphIt->second.find(function.name) != graphIt->second.end();
        }

        std::vector<int> index(functions.size(), -1);
        std::vector<int> lowlink(functions.size(), -1);
        std::vector<bool> onStack(functions.size(), false);
        std::vector<std::size_t> stack;
        int nextIndex = 0;

        std::function<void(std::size_t)> strongConnect = [&](std::size_t v)
        {
            index[v] = nextIndex;
            lowlink[v] = nextIndex;
            ++nextIndex;
            stack.push_back(v);
            onStack[v] = true;

            const auto graphIt = directCallGraph.find(functions[v].name);
            if (graphIt != directCallGraph.end())
            {
                for (const std::string &callee : graphIt->second)
                {
                    auto it = indexByName.find(callee);
                    if (it == indexByName.end())
                    {
                        continue;
                    }
                    const std::size_t w = it->second;
                    if (index[w] == -1)
                    {
                        strongConnect(w);
                        lowlink[v] = std::min(lowlink[v], lowlink[w]);
                    }
                    else if (onStack[w])
                    {
                        lowlink[v] = std::min(lowlink[v], index[w]);
                    }
                }
            }

            if (lowlink[v] == index[v])
            {
                std::vector<std::size_t> component;
                while (!stack.empty())
                {
                    const std::size_t w = stack.back();
                    stack.pop_back();
                    onStack[w] = false;
                    component.push_back(w);
                    if (w == v)
                    {
                        break;
                    }
                }

                if (component.size() > 1U)
                {
                    for (std::size_t functionIndex : component)
                    {
                        functions[functionIndex].attributes.hasIndirectRecursion = true;
                        for (std::size_t peerIndex : component)
                        {
                            if (peerIndex != functionIndex)
                            {
                                functions[functionIndex].attributes.indirectRecursionPeers.insert(
                                    functions[peerIndex].name);
                            }
                        }
                    }
                }
            }
        };

        for (std::size_t i = 0; i < functions.size(); ++i)
        {
            if (index[i] == -1)
            {
                strongConnect(i);
            }
        }
    }

} // namespace

bool generateCfgBundle(
    const std::vector<std::string> &inputs,
    const std::vector<std::string> &compilationArgs,
    const std::string &functionFilter,
    CfgMode mode,
    CfgBundle &bundle,
    std::string &errorMessage)
{
    if (inputs.empty())
    {
        errorMessage = "no input files provided";
        return false;
    }

    std::vector<std::string> sourceFiles;
    for (const std::string &input : inputs)
    {
        std::error_code ec;
        if (std::filesystem::is_directory(input, ec))
        {
            for (auto it = std::filesystem::recursive_directory_iterator(input);
                 it != std::filesystem::recursive_directory_iterator();
                 ++it)
            {
                if (std::filesystem::is_regular_file(it->path(), ec))
                {
                    const std::string extension = it->path().extension().string();
                    if (extension == ".c" || extension == ".h")
                    {
                        sourceFiles.push_back(it->path().string());
                    }
                }
            }
        }
        else if (std::filesystem::is_regular_file(input, ec))
        {
            sourceFiles.push_back(input);
        }
    }

    std::sort(sourceFiles.begin(), sourceFiles.end());
    sourceFiles.erase(std::unique(sourceFiles.begin(), sourceFiles.end()), sourceFiles.end());

    if (sourceFiles.empty())
    {
        errorMessage = "no C source files discovered";
        return false;
    }

    std::vector<std::string> fixedArgs = compilationArgs;
    if (std::find(fixedArgs.begin(), fixedArgs.end(), "-std=c11") == fixedArgs.end())
    {
        fixedArgs.push_back("-std=c11");
    }

    clang::tooling::FixedCompilationDatabase compilationDatabase(".", fixedArgs);
    clang::tooling::ClangTool tool(compilationDatabase, sourceFiles);
    tool.appendArgumentsAdjuster(clang::tooling::getInsertArgumentAdjuster("-xc", clang::tooling::ArgumentInsertPosition::BEGIN));

    std::vector<SerializedFunction> functions;
    CollectorState state;
    state.mode = mode;
    state.functionFilter = functionFilter;
    state.functions = &functions;

    CfgActionFactory factory(state);
    const int result = tool.run(&factory);
    if (result != 0)
    {
        errorMessage = "clang tooling failed with code " + std::to_string(result);
        return false;
    }

    computeRecursionAttributes(functions, state.directCallGraph);

    if (mode == CfgMode::kCallOnly)
    {
        std::unordered_set<std::string> definedFunctions;
        for (const SerializedFunction &function : functions)
        {
            definedFunctions.insert(function.name);
        }

        auto callNameFromLine = [](const std::string &line)
        {
            const std::size_t open = line.find('(');
            if (open == std::string::npos)
            {
                return line;
            }
            return line.substr(0, open);
        };

        for (SerializedFunction &function : functions)
        {
            for (SerializedBlock &block : function.blocks)
            {
                std::vector<std::string> filtered;
                filtered.reserve(block.lines.size());
                for (const std::string &line : block.lines)
                {
                    const std::string callee = callNameFromLine(line);
                    if (!callee.empty() && definedFunctions.find(callee) != definedFunctions.end())
                    {
                        filtered.push_back(line);
                    }
                }
                block.lines.swap(filtered);
            }

            auto hasContent = [](const SerializedBlock &block)
            {
                for (const std::string &line : block.lines)
                {
                    if (!line.empty())
                    {
                        return true;
                    }
                }
                return false;
            };

            std::unordered_map<std::uint32_t, const SerializedBlock *> byId;
            for (const SerializedBlock &block : function.blocks)
            {
                byId[block.id] = &block;
            }

            std::unordered_set<std::uint32_t> kept;
            for (const SerializedBlock &block : function.blocks)
            {
                if (block.id == function.entryBlockId ||
                    block.id == function.exitBlockId ||
                    hasContent(block))
                {
                    kept.insert(block.id);
                }
            }

            auto nextKept = [&](std::uint32_t startId)
            {
                std::set<std::uint32_t> result;
                std::set<std::uint32_t> visited;
                std::vector<std::uint32_t> work;

                const auto startIt = byId.find(startId);
                if (startIt == byId.end())
                {
                    return result;
                }
                for (std::uint32_t successor : startIt->second->successors)
                {
                    work.push_back(successor);
                }

                while (!work.empty())
                {
                    const std::uint32_t current = work.back();
                    work.pop_back();
                    if (!visited.insert(current).second)
                    {
                        continue;
                    }

                    if (kept.find(current) != kept.end())
                    {
                        result.insert(current);
                        continue;
                    }

                    const auto it = byId.find(current);
                    if (it == byId.end())
                    {
                        continue;
                    }

                    for (std::uint32_t successor : it->second->successors)
                    {
                        work.push_back(successor);
                    }
                }

                return result;
            };

            std::vector<SerializedBlock> compacted;
            compacted.reserve(function.blocks.size());
            for (const SerializedBlock &block : function.blocks)
            {
                if (kept.find(block.id) == kept.end())
                {
                    continue;
                }

                SerializedBlock reduced;
                reduced.id = block.id;
                reduced.lines = block.lines;
                if (block.id == function.exitBlockId)
                {
                    reduced.successors.clear();
                }
                else
                {
                    const std::set<std::uint32_t> next = nextKept(block.id);
                    reduced.successors.assign(next.begin(), next.end());
                }
                compacted.push_back(std::move(reduced));
            }
            function.blocks.swap(compacted);

            std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> reducedAdj;
            for (const SerializedBlock &block : function.blocks)
            {
                reducedAdj[block.id] = block.successors;
            }
            const std::vector<LoopGroup> loops = detectLoopGroups(reducedAdj);
            std::unordered_set<std::uint32_t> loopMembers;
            for (const LoopGroup &group : loops)
            {
                for (std::uint32_t blockId : group.blockIds)
                {
                    loopMembers.insert(blockId);
                }
            }
            function.attributes.loopGroups = loops;
            for (SerializedBlock &block : function.blocks)
            {
                block.attributes.hasLoop = loopMembers.find(block.id) != loopMembers.end();
            }
        }
    }

    bundle.mode = mode;
    bundle.functions = std::move(functions);
    return true;
}

bool emitFunctionDotFiles(const CfgBundle &bundle, const std::string &outputDirectory, std::string &errorMessage)
{
    std::error_code ec;
    std::filesystem::create_directories(outputDirectory, ec);
    if (ec)
    {
        errorMessage = "failed to create dot output directory: " + ec.message();
        return false;
    }

    for (const SerializedFunction &function : bundle.functions)
    {
        const std::string baseId = sanitizeId(function.name);
        const std::filesystem::path dotPath = std::filesystem::path(outputDirectory) / (baseId + ".dot");
        std::ofstream dotFile(dotPath);
        if (!dotFile)
        {
            errorMessage = "failed to open dot output file: " + dotPath.string();
            return false;
        }

        dotFile << "digraph " << baseId << " {\n";
        dotFile << "  rankdir=TB;\n";

        for (const SerializedBlock &block : function.blocks)
        {
            dotFile << "  " << baseId << "_B" << block.id << " [shape=box,label=\"";
            bool first = true;
            for (const std::string &line : block.lines)
            {
                if (!first)
                {
                    dotFile << "\\l";
                }
                dotFile << escapeDot(line);
                first = false;
            }
            if (block.attributes.hasLoop)
            {
                if (!first)
                {
                    dotFile << "\\l";
                }
                dotFile << "[loop]";
            }
            dotFile << "\\l\"];\n";
        }

        for (const SerializedBlock &block : function.blocks)
        {
            for (std::uint32_t successor : block.successors)
            {
                dotFile << "  " << baseId << "_B" << block.id << " -> "
                        << baseId << "_B" << successor << ";\n";
            }
        }

        dotFile << "}\n";
    }

    return true;
}
