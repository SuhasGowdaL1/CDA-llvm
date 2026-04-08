/**
 * @file cfg_generation.cpp
 * @brief Implementation of CFG extraction, callsite fact collection, and DOT emission.
 */

#include "cfg_generation.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
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

    /**
     * @brief Trim leading and trailing whitespace.
     */
    std::string trimCopy(const std::string &text)
    {
        std::size_t begin = 0;
        while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0)
        {
            ++begin;
        }

        std::size_t end = text.size();
        while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1U])) != 0)
        {
            --end;
        }

        return text.substr(begin, end - begin);
    }

    /**
     * @brief Find a character outside nested delimiters/quotes.
     */
    std::size_t findTopLevelChar(const std::string &text, char target, std::size_t startIndex = 0U)
    {
        int depthParen = 0;
        int depthBracket = 0;
        int depthBrace = 0;
        bool inSingleQuote = false;
        bool inDoubleQuote = false;

        for (std::size_t i = startIndex; i < text.size(); ++i)
        {
            const char ch = text[i];
            const char prev = i > 0U ? text[i - 1U] : '\0';

            if (inSingleQuote)
            {
                if (ch == '\'' && prev != '\\')
                {
                    inSingleQuote = false;
                }
                continue;
            }

            if (inDoubleQuote)
            {
                if (ch == '"' && prev != '\\')
                {
                    inDoubleQuote = false;
                }
                continue;
            }

            if (ch == '\'')
            {
                inSingleQuote = true;
                continue;
            }
            if (ch == '"')
            {
                inDoubleQuote = true;
                continue;
            }

            if (ch == '(')
            {
                ++depthParen;
                continue;
            }
            if (ch == ')' && depthParen > 0)
            {
                --depthParen;
                continue;
            }
            if (ch == '[')
            {
                ++depthBracket;
                continue;
            }
            if (ch == ']' && depthBracket > 0)
            {
                --depthBracket;
                continue;
            }
            if (ch == '{')
            {
                ++depthBrace;
                continue;
            }
            if (ch == '}' && depthBrace > 0)
            {
                --depthBrace;
                continue;
            }

            if (depthParen == 0 && depthBracket == 0 && depthBrace == 0 && ch == target)
            {
                return i;
            }
        }

        return std::string::npos;
    }

    struct ConditionalStoreInfo
    {
        std::string left;
        std::string variable;
        std::string trueExpression;
        std::string falseExpression;
        bool isDeclaration = false;
    };

    /**
     * @brief Parse a conditional assignment statement into normalized parts.
     */
    bool parseConditionalStoreLine(const std::string &line, ConditionalStoreInfo &info)
    {
        const std::string trimmed = trimCopy(line);
        if (trimmed.empty() || trimmed.back() != ';')
        {
            return false;
        }

        const std::string withoutSemicolon = trimCopy(trimmed.substr(0, trimmed.size() - 1U));
        const std::size_t equalIndex = findTopLevelChar(withoutSemicolon, '=');
        if (equalIndex == std::string::npos)
        {
            return false;
        }

        const std::string left = trimCopy(withoutSemicolon.substr(0, equalIndex));
        const std::string right = trimCopy(withoutSemicolon.substr(equalIndex + 1U));
        if (left.empty() || right.empty())
        {
            return false;
        }

        const std::size_t questionIndex = findTopLevelChar(right, '?');
        if (questionIndex == std::string::npos)
        {
            return false;
        }

        const std::size_t colonIndex = findTopLevelChar(right, ':', questionIndex + 1U);
        if (colonIndex == std::string::npos)
        {
            return false;
        }

        const std::string trueExpression = trimCopy(right.substr(questionIndex + 1U, colonIndex - (questionIndex + 1U)));
        const std::string falseExpression = trimCopy(right.substr(colonIndex + 1U));
        if (trueExpression.empty() || falseExpression.empty())
        {
            return false;
        }

        std::size_t end = left.size();
        while (end > 0U && std::isspace(static_cast<unsigned char>(left[end - 1U])) != 0)
        {
            --end;
        }
        std::size_t begin = end;
        while (begin > 0U)
        {
            const char ch = left[begin - 1U];
            if (std::isalnum(static_cast<unsigned char>(ch)) == 0 && ch != '_')
            {
                break;
            }
            --begin;
        }
        if (begin == end)
        {
            return false;
        }

        info.left = left;
        info.variable = left.substr(begin, end - begin);
        info.trueExpression = trueExpression;
        info.falseExpression = falseExpression;
        info.isDeclaration =
            left.find(' ') != std::string::npos &&
            left.find("->") == std::string::npos &&
            left.find('.') == std::string::npos &&
            left.find('[') == std::string::npos;
        return true;
    }

    /**
     * @brief Duplicate conditional store effects into predecessor blocks.
     */
    void applyConditionalStoreDuplication(SerializedFunction &function)
    {
        std::unordered_map<std::uint32_t, std::size_t> blockIndexById;
        std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> predecessors;
        std::unordered_map<std::uint32_t, std::vector<std::string>> pendingDeclarationInsertions;

        for (std::size_t index = 0; index < function.blocks.size(); ++index)
        {
            blockIndexById[function.blocks[index].id] = index;
        }

        for (const SerializedBlock &block : function.blocks)
        {
            for (std::uint32_t successor : block.successors)
            {
                predecessors[successor].push_back(block.id);
            }
        }

        auto assignInPredecessor = [&](std::uint32_t predecessorId, const std::string &variable, const std::string &expression)
        {
            const auto blockIt = blockIndexById.find(predecessorId);
            if (blockIt == blockIndexById.end())
            {
                return;
            }

            SerializedBlock &pred = function.blocks[blockIt->second];
            const std::string assignmentLine = variable + " = " + expression + ";";

            for (std::string &line : pred.lines)
            {
                if (trimCopy(line) == expression)
                {
                    line = assignmentLine;
                    return;
                }
            }

            if (std::find(pred.lines.begin(), pred.lines.end(), assignmentLine) == pred.lines.end())
            {
                pred.lines.push_back(assignmentLine);
            }
        };

        for (SerializedBlock &block : function.blocks)
        {
            std::vector<std::string> updatedLines;
            updatedLines.reserve(block.lines.size());

            for (const std::string &line : block.lines)
            {
                ConditionalStoreInfo storeInfo;
                if (!parseConditionalStoreLine(line, storeInfo))
                {
                    updatedLines.push_back(line);
                    continue;
                }

                const auto predsIt = predecessors.find(block.id);
                if (predsIt == predecessors.end() || predsIt->second.size() != 2U)
                {
                    updatedLines.push_back(line);
                    continue;
                }

                std::vector<std::uint32_t> predIds = predsIt->second;
                std::sort(predIds.begin(), predIds.end());

                std::unordered_map<std::uint32_t, std::string> expressionByPred;
                std::unordered_set<std::uint32_t> usedPreds;

                auto matchExpressionToPred = [&](const std::string &expression)
                {
                    for (std::uint32_t predId : predIds)
                    {
                        if (usedPreds.find(predId) != usedPreds.end())
                        {
                            continue;
                        }

                        const auto predBlockIt = blockIndexById.find(predId);
                        if (predBlockIt == blockIndexById.end())
                        {
                            continue;
                        }

                        const SerializedBlock &predBlock = function.blocks[predBlockIt->second];
                        for (const std::string &predLine : predBlock.lines)
                        {
                            const std::string trimmedPredLine = trimCopy(predLine);
                            if (trimmedPredLine == expression)
                            {
                                expressionByPred[predId] = expression;
                                usedPreds.insert(predId);
                                return;
                            }
                        }
                    }
                };

                matchExpressionToPred(storeInfo.trueExpression);
                matchExpressionToPred(storeInfo.falseExpression);

                std::vector<std::string> remainingExpressions;
                if (std::find_if(expressionByPred.begin(), expressionByPred.end(),
                                 [&](const auto &entry)
                                 { return entry.second == storeInfo.trueExpression; }) == expressionByPred.end())
                {
                    remainingExpressions.push_back(storeInfo.trueExpression);
                }
                if (std::find_if(expressionByPred.begin(), expressionByPred.end(),
                                 [&](const auto &entry)
                                 { return entry.second == storeInfo.falseExpression; }) == expressionByPred.end())
                {
                    remainingExpressions.push_back(storeInfo.falseExpression);
                }

                std::size_t fallbackIndex = 0;
                for (std::uint32_t predId : predIds)
                {
                    if (usedPreds.find(predId) != usedPreds.end())
                    {
                        continue;
                    }

                    if (fallbackIndex < remainingExpressions.size())
                    {
                        expressionByPred[predId] = remainingExpressions[fallbackIndex++];
                    }
                }

                for (const auto &entry : expressionByPred)
                {
                    assignInPredecessor(entry.first, storeInfo.variable, entry.second);
                }

                if (storeInfo.isDeclaration)
                {
                    std::uint32_t declarationBlockId = function.entryBlockId;
                    for (const SerializedBlock &candidate : function.blocks)
                    {
                        bool reachesFirst = false;
                        bool reachesSecond = false;
                        for (std::uint32_t successor : candidate.successors)
                        {
                            if (successor == predIds[0])
                            {
                                reachesFirst = true;
                            }
                            if (successor == predIds[1])
                            {
                                reachesSecond = true;
                            }
                        }

                        if (reachesFirst && reachesSecond)
                        {
                            declarationBlockId = candidate.id;
                            break;
                        }
                    }

                    const std::string declarationLine = storeInfo.left + ";";
                    std::vector<std::string> &pending = pendingDeclarationInsertions[declarationBlockId];
                    if (std::find(pending.begin(), pending.end(), declarationLine) == pending.end())
                    {
                        pending.push_back(declarationLine);
                    }
                }
            }

            block.lines.swap(updatedLines);
        }

        for (SerializedBlock &block : function.blocks)
        {
            const auto pendingIt = pendingDeclarationInsertions.find(block.id);
            if (pendingIt == pendingDeclarationInsertions.end())
            {
                continue;
            }

            std::vector<std::string> insertions;
            for (const std::string &declarationLine : pendingIt->second)
            {
                if (std::find(block.lines.begin(), block.lines.end(), declarationLine) == block.lines.end())
                {
                    insertions.push_back(declarationLine);
                }
            }

            if (insertions.empty())
            {
                continue;
            }

            std::vector<std::string> merged;
            merged.reserve(insertions.size() + block.lines.size());
            merged.insert(merged.end(), insertions.begin(), insertions.end());
            merged.insert(merged.end(), block.lines.begin(), block.lines.end());
            block.lines.swap(merged);
        }
    }

    /**
     * @brief Check whether one source range contains another in spelling coordinates.
     */
    bool containsSpellingRange(
        const clang::SourceRange &outer,
        const clang::SourceRange &inner,
        const clang::SourceManager &sourceManager)
    {
        const clang::SourceLocation outerBegin = sourceManager.getSpellingLoc(outer.getBegin());
        const clang::SourceLocation outerEnd = sourceManager.getSpellingLoc(outer.getEnd());
        const clang::SourceLocation innerBegin = sourceManager.getSpellingLoc(inner.getBegin());
        const clang::SourceLocation innerEnd = sourceManager.getSpellingLoc(inner.getEnd());

        if (outerBegin.isInvalid() || outerEnd.isInvalid() || innerBegin.isInvalid() || innerEnd.isInvalid())
        {
            return false;
        }

        if (!sourceManager.isWrittenInSameFile(outerBegin, innerBegin) ||
            !sourceManager.isWrittenInSameFile(outerBegin, innerEnd) ||
            !sourceManager.isWrittenInSameFile(outerBegin, outerEnd))
        {
            return false;
        }

        const bool beginInside =
            outerBegin == innerBegin || sourceManager.isBeforeInTranslationUnit(outerBegin, innerBegin);
        const bool endInside =
            innerEnd == outerEnd || sourceManager.isBeforeInTranslationUnit(innerEnd, outerEnd);
        return beginInside && endInside;
    }

    /**
     * @brief Build a serializable source location record from a Clang location.
     */
    SourceLocationRecord buildSourceLocationRecord(
        clang::SourceLocation location,
        const clang::SourceManager &sourceManager)
    {
        SourceLocationRecord record;
        if (!location.isValid())
        {
            return record;
        }

        const clang::SourceLocation spellingLocation = sourceManager.getSpellingLoc(location);
        if (spellingLocation.isInvalid())
        {
            return record;
        }

        record.file = sourceManager.getFilename(spellingLocation).str();
        record.line = sourceManager.getSpellingLineNumber(spellingLocation);
        record.column = sourceManager.getSpellingColumnNumber(spellingLocation);
        return record;
    }

    /**
     * @brief Convert expression text to normalized spelling source.
     */
    std::string extractExpressionText(clang::ASTContext &context, const clang::Expr *expr)
    {
        if (expr == nullptr)
        {
            return "";
        }

        const clang::SourceManager &sourceManager = context.getSourceManager();
        const clang::LangOptions &langOptions = context.getLangOpts();
        const clang::CharSourceRange tokenRange = clang::CharSourceRange::getTokenRange(expr->getSourceRange());
        const llvm::StringRef text = clang::Lexer::getSourceText(tokenRange, sourceManager, langOptions);
        return normalizeWhitespace(text.str());
    }

    /**
     * @brief Resolve function symbol for an expression denoting a function address.
     */
    std::string extractFunctionSymbol(const clang::Expr *expr)
    {
        if (expr == nullptr)
        {
            return "";
        }

        const clang::Expr *stripped = expr->IgnoreParenImpCasts();

        if (const auto *declRef = llvm::dyn_cast<clang::DeclRefExpr>(stripped))
        {
            if (const auto *functionDecl = llvm::dyn_cast<clang::FunctionDecl>(declRef->getDecl()))
            {
                return functionDecl->getQualifiedNameAsString();
            }
        }

        if (const auto *unaryOperator = llvm::dyn_cast<clang::UnaryOperator>(stripped))
        {
            if (unaryOperator->getOpcode() == clang::UO_AddrOf)
            {
                const clang::Expr *subExpression = unaryOperator->getSubExpr()->IgnoreParenImpCasts();
                if (const auto *subDeclRef = llvm::dyn_cast<clang::DeclRefExpr>(subExpression))
                {
                    if (const auto *functionDecl = llvm::dyn_cast<clang::FunctionDecl>(subDeclRef->getDecl()))
                    {
                        return functionDecl->getQualifiedNameAsString();
                    }
                }
            }
        }

        return "";
    }

    std::uint64_t fnv1a64(const std::string &text)
    {
        std::uint64_t hash = 1469598103934665603ULL;
        for (unsigned char c : text)
        {
            hash ^= static_cast<std::uint64_t>(c);
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    std::string buildStableCallSiteId(const std::string &functionName, const CallSiteRecord &callsite)
    {
        std::ostringstream key;
        key << functionName << "|"
            << callsite.location.file << ":" << callsite.location.line << ":" << callsite.location.column << "|"
            << callsite.directCallee << "|"
            << callsite.throughIdentifier << "|"
            << callsite.calleeExpression << "|";

        for (std::size_t i = 0; i < callsite.argumentExpressions.size(); ++i)
        {
            if (i > 0U)
            {
                key << ",";
            }
            key << callsite.argumentExpressions[i];
        }

        return "cs_" + std::to_string(fnv1a64(key.str()));
    }

    /**
     * @brief AST visitor that captures callsite and pointer-assignment facts.
     */
    class CallVisitor : public clang::RecursiveASTVisitor<CallVisitor>
    {
    public:
        explicit CallVisitor(
            clang::ASTContext &context,
            std::string functionName,
            const std::set<std::string> &blacklistedFunctions)
            : context_(context), functionName_(std::move(functionName)), blacklistedFunctions_(blacklistedFunctions)
        {
        }

        /**
         * @brief Record one call expression.
         */
        bool VisitCallExpr(clang::CallExpr *call)
        {
            if (call == nullptr)
            {
                return true;
            }

            const clang::SourceManager &sourceManager = context_.getSourceManager();
            const clang::SourceLocation location = sourceManager.getSpellingLoc(call->getExprLoc());
            const unsigned locationKey = location.getRawEncoding();

            CallSiteRecord callsite;
            callsite.calleeExpression = extractExpressionText(call->getCallee());
            callsite.location = buildSourceLocationRecord(location, sourceManager);

            clang::FunctionDecl *callee = call->getDirectCallee();
            if (callee != nullptr)
            {
                callsite.directCallee = callee->getQualifiedNameAsString();
                if (blacklistedFunctions_.find(callsite.directCallee) != blacklistedFunctions_.end())
                {
                    return true;
                }

                if (callsite.directCallee == "State_Change")
                {
                    if (stateChangeValues_.empty())
                    {
                        stateChangeValues_.assign(3, std::set<std::string>{});
                    }
                    for (unsigned argIndex = 0; argIndex < 3U; ++argIndex)
                    {
                        if (argIndex < call->getNumArgs())
                        {
                            stateChangeValues_[argIndex].insert(extractExpressionText(call->getArg(argIndex)));
                        }
                    }
                }
            }
            else
            {
                callsite.isIndirect = true;
                callsite.throughIdentifier = extractReferencedIdentifier(call->getCallee());
            }

            for (const clang::Expr *argument : call->arguments())
            {
                callsite.argumentExpressions.push_back(extractExpressionText(argument));
            }

            callsite.callSiteId = buildStableCallSiteId(functionName_, callsite);

            const std::string siteKey =
                callsite.callSiteId +
                "#" +
                std::to_string(locationKey);
            if (seenCallSites_.insert(siteKey).second)
            {
                callSites_.push_back(std::move(callsite));
            }

            for (const clang::Expr *argument : call->arguments())
            {
                const std::string functionSymbol = ::extractFunctionSymbol(argument);
                if (!functionSymbol.empty() && blacklistedFunctions_.find(functionSymbol) == blacklistedFunctions_.end())
                {
                    addressTakenFunctions_.insert(functionSymbol);
                }
            }

            return true;
        }

        /**
         * @brief Record one assignment operation used for pointer flow facts.
         */
        bool VisitBinaryOperator(clang::BinaryOperator *binaryOperator)
        {
            if (binaryOperator == nullptr || !binaryOperator->isAssignmentOp())
            {
                return true;
            }

            PointerAssignmentRecord assignment;
            assignment.lhsExpression = extractExpressionText(binaryOperator->getLHS());
            assignment.rhsExpression = extractExpressionText(binaryOperator->getRHS());
            assignment.assignedFunction = ::extractFunctionSymbol(binaryOperator->getRHS());
            assignment.rhsTakesFunctionAddress = !assignment.assignedFunction.empty();

            if (!assignment.assignedFunction.empty() &&
                blacklistedFunctions_.find(assignment.assignedFunction) != blacklistedFunctions_.end())
            {
                return true;
            }

            const clang::SourceManager &sourceManager = context_.getSourceManager();
            const clang::SourceLocation location = sourceManager.getSpellingLoc(binaryOperator->getExprLoc());
            assignment.location = buildSourceLocationRecord(location, sourceManager);

            if (assignment.rhsTakesFunctionAddress)
            {
                addressTakenFunctions_.insert(assignment.assignedFunction);
            }

            const std::string key =
                assignment.lhsExpression +
                "#" +
                assignment.rhsExpression +
                "#" +
                std::to_string(location.getRawEncoding());
            if (!assignment.lhsExpression.empty() && !assignment.rhsExpression.empty() &&
                seenAssignments_.insert(key).second)
            {
                pointerAssignments_.push_back(std::move(assignment));
            }

            return true;
        }

        /**
         * @brief Record declaration initializers relevant to pointer facts.
         */
        bool VisitVarDecl(clang::VarDecl *varDecl)
        {
            if (varDecl == nullptr || !varDecl->hasInit())
            {
                return true;
            }

            PointerAssignmentRecord assignment;
            assignment.lhsExpression = varDecl->getQualifiedNameAsString();
            assignment.rhsExpression = extractExpressionText(varDecl->getInit());
            assignment.assignedFunction = ::extractFunctionSymbol(varDecl->getInit());
            assignment.rhsTakesFunctionAddress = !assignment.assignedFunction.empty();

            if (!assignment.assignedFunction.empty() &&
                blacklistedFunctions_.find(assignment.assignedFunction) != blacklistedFunctions_.end())
            {
                return true;
            }

            const clang::SourceManager &sourceManager = context_.getSourceManager();
            const clang::SourceLocation location = sourceManager.getSpellingLoc(varDecl->getLocation());
            assignment.location = buildSourceLocationRecord(location, sourceManager);

            if (assignment.rhsTakesFunctionAddress)
            {
                addressTakenFunctions_.insert(assignment.assignedFunction);
            }

            const std::string key =
                assignment.lhsExpression +
                "#" +
                assignment.rhsExpression +
                "#" +
                std::to_string(location.getRawEncoding());
            if (!assignment.lhsExpression.empty() && !assignment.rhsExpression.empty() &&
                seenAssignments_.insert(key).second)
            {
                pointerAssignments_.push_back(std::move(assignment));
            }

            return true;
        }

        const std::vector<CallSiteRecord> &callSites() const
        {
            return callSites_;
        }

        const std::vector<PointerAssignmentRecord> &pointerAssignments() const
        {
            return pointerAssignments_;
        }

        const std::set<std::string> &addressTakenFunctions() const
        {
            return addressTakenFunctions_;
        }

        const std::vector<std::set<std::string>> &stateChangeValues() const
        {
            return stateChangeValues_;
        }

    private:
        /**
         * @brief Convert an expression into normalized source text.
         */
        std::string extractExpressionText(const clang::Expr *expr)
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

        /**
         * @brief Resolve the referenced non-function identifier, if any.
         */
        std::string extractReferencedIdentifier(const clang::Expr *expr)
        {
            if (expr == nullptr)
            {
                return "";
            }
            const clang::Expr *stripped = expr->IgnoreParenImpCasts();
            const auto *declRef = llvm::dyn_cast<clang::DeclRefExpr>(stripped);
            if (declRef == nullptr)
            {
                return "";
            }

            const auto *valueDecl = llvm::dyn_cast<clang::ValueDecl>(declRef->getDecl());
            if (valueDecl == nullptr)
            {
                return "";
            }

            if (llvm::isa<clang::FunctionDecl>(valueDecl))
            {
                return "";
            }

            return valueDecl->getQualifiedNameAsString();
        }

        clang::ASTContext &context_;
        std::string functionName_;
        const std::set<std::string> &blacklistedFunctions_;
        std::vector<CallSiteRecord> callSites_;
        std::vector<PointerAssignmentRecord> pointerAssignments_;
        std::set<std::string> addressTakenFunctions_;
        std::unordered_set<std::string> seenCallSites_;
        std::unordered_set<std::string> seenAssignments_;
        std::vector<std::set<std::string>> stateChangeValues_;
    };

    /**
     * @brief Convert a statement to normalized source text.
     */
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

    /**
     * @brief Collect representative textual lines for one CFG block.
     */
    std::vector<std::string> collectBlockLines(const clang::CFGBlock &block, clang::ASTContext &context)
    {
        std::vector<std::string> lines;
        std::set<const clang::Stmt *> seenStatements;
        std::unordered_map<unsigned, std::string> bestTextByLine;
        std::unordered_map<unsigned, int> bestScoreByLine;
        std::vector<unsigned> lineOrder;
        std::vector<clang::SourceRange> containerRanges;

        for (const clang::CFGElement &element : block)
        {
            auto statement = element.getAs<clang::CFGStmt>();
            if (!statement)
            {
                continue;
            }

            const clang::Stmt *stmt = statement->getStmt();
            if (stmt == nullptr)
            {
                continue;
            }

            if (llvm::isa<clang::ReturnStmt>(stmt) || llvm::isa<clang::DeclStmt>(stmt))
            {
                containerRanges.push_back(stmt->getSourceRange());
            }
        }

        auto scoreStatement = [](const clang::Stmt *stmt, const std::string &text)
        {
            int score = 0;
            if (!llvm::isa<clang::Expr>(stmt))
            {
                score += 100;
            }
            if (llvm::isa<clang::DeclStmt>(stmt) || llvm::isa<clang::ReturnStmt>(stmt))
            {
                score += 25;
            }
            score += static_cast<int>(std::min<std::size_t>(text.size(), 200U));
            return score;
        };

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

            if (llvm::isa<clang::Expr>(stmt))
            {
                bool nestedInContainer = false;
                const clang::SourceManager &sourceManager = context.getSourceManager();
                const clang::SourceRange sourceRange = stmt->getSourceRange();
                for (const clang::SourceRange &containerRange : containerRanges)
                {
                    if (containsSpellingRange(containerRange, sourceRange, sourceManager))
                    {
                        nestedInContainer = true;
                        break;
                    }
                }

                if (nestedInContainer)
                {
                    continue;
                }
            }

            const std::string stmtText = extractStatementText(stmt, context);
            if (stmtText.empty())
            {
                continue;
            }

            const clang::SourceManager &sourceManager = context.getSourceManager();
            const clang::SourceLocation begin = sourceManager.getSpellingLoc(stmt->getBeginLoc());
            const unsigned line = begin.isValid() ? sourceManager.getSpellingLineNumber(begin) : 0U;

            if (line == 0U)
            {
                lines.push_back(stmtText);
                continue;
            }

            const int score = scoreStatement(stmt, stmtText);
            const auto existing = bestTextByLine.find(line);
            if (existing == bestTextByLine.end())
            {
                bestTextByLine[line] = stmtText;
                bestScoreByLine[line] = score;
                lineOrder.push_back(line);
                continue;
            }

            const int currentBest = bestScoreByLine[line];
            if (score > currentBest ||
                (score == currentBest && stmtText.size() > existing->second.size()))
            {
                bestTextByLine[line] = stmtText;
                bestScoreByLine[line] = score;
            }
        }

        for (unsigned line : lineOrder)
        {
            const auto it = bestTextByLine.find(line);
            if (it != bestTextByLine.end())
            {
                lines.push_back(it->second);
            }
        }

        return lines;
    }

    struct CollectorState
    {
        clang::ASTContext *context = nullptr;
        std::string functionFilter;
        std::set<std::string> blacklistedFunctions;
        std::vector<SerializedFunction> *functions = nullptr;
    };

    /**
     * @brief Visitor that serializes each function CFG and associated facts.
     */
    class CfgVisitor : public clang::RecursiveASTVisitor<CfgVisitor>
    {
    public:
        explicit CfgVisitor(CollectorState &state)
            : state_(state)
        {
        }

        /**
         * @brief Visit and serialize a function definition.
         */
        bool VisitFunctionDecl(clang::FunctionDecl *functionDecl)
        {
            if (functionDecl == nullptr || !functionDecl->hasBody() || !functionDecl->isThisDeclarationADefinition())
            {
                return true;
            }

            const std::string functionName = functionDecl->getQualifiedNameAsString();
            if (state_.blacklistedFunctions.find(functionName) != state_.blacklistedFunctions.end())
            {
                return true;
            }
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

            for (const clang::CFGBlock *block : *graph)
            {
                if (block == nullptr)
                {
                    continue;
                }

                SerializedBlock serializedBlock;
                serializedBlock.id = static_cast<std::uint32_t>(block->getBlockID());
                serializedBlock.lines = collectBlockLines(*block, *state_.context);

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

                rawBlocks.push_back(std::move(serializedBlock));
            }

            function.blocks = rawBlocks;
            applyConditionalStoreDuplication(function);

            CallVisitor callVisitor(*state_.context, functionName, state_.blacklistedFunctions);
            callVisitor.TraverseStmt(body);

            ensureGlobalFactsCollected();

            function.attributes.callSites = callVisitor.callSites();
            function.attributes.pointerAssignments = globalPointerAssignments_;
            function.attributes.pointerAssignments.insert(
                function.attributes.pointerAssignments.end(),
                callVisitor.pointerAssignments().begin(),
                callVisitor.pointerAssignments().end());

            function.attributes.addressTakenFunctions = globalAddressTakenFunctions_;
            function.attributes.addressTakenFunctions.insert(
                callVisitor.addressTakenFunctions().begin(),
                callVisitor.addressTakenFunctions().end());

            if (!callVisitor.stateChangeValues().empty())
            {
                function.attributes.callsStateChange = true;
                function.attributes.stateChangeParameterValues = callVisitor.stateChangeValues();
            }

            state_.functions->push_back(std::move(function));
            return true;
        }

    private:
        /**
         * @brief Gather file-scope pointer facts once and reuse for all functions.
         */
        void ensureGlobalFactsCollected()
        {
            if (globalFactsCollected_ || state_.context == nullptr)
            {
                return;
            }

            const clang::SourceManager &sourceManager = state_.context->getSourceManager();
            clang::TranslationUnitDecl *translationUnit = state_.context->getTranslationUnitDecl();
            if (translationUnit == nullptr)
            {
                globalFactsCollected_ = true;
                return;
            }

            std::unordered_set<std::string> seenGlobalAssignments;

            for (const clang::Decl *decl : translationUnit->decls())
            {
                const auto *varDecl = llvm::dyn_cast<clang::VarDecl>(decl);
                if (varDecl == nullptr || !varDecl->isFileVarDecl() || !varDecl->hasInit())
                {
                    continue;
                }

                const clang::Expr *initializer = varDecl->getInit();
                if (initializer == nullptr)
                {
                    continue;
                }

                const clang::Expr *strippedInitializer = initializer->IgnoreParenImpCasts();
                const clang::SourceLocation location = sourceManager.getSpellingLoc(varDecl->getLocation());

                const auto *initList = llvm::dyn_cast<clang::InitListExpr>(strippedInitializer);
                if (initList != nullptr)
                {
                    for (unsigned i = 0; i < initList->getNumInits(); ++i)
                    {
                        const clang::Expr *initExpr = initList->getInit(i);
                        const std::string assignedFunction = ::extractFunctionSymbol(initExpr);
                        if (assignedFunction.empty() ||
                            state_.blacklistedFunctions.find(assignedFunction) != state_.blacklistedFunctions.end())
                        {
                            continue;
                        }

                        PointerAssignmentRecord assignment;
                        assignment.lhsExpression = varDecl->getQualifiedNameAsString();
                        assignment.rhsExpression = extractExpressionText(*state_.context, initExpr);
                        assignment.assignedFunction = assignedFunction;
                        assignment.rhsTakesFunctionAddress = true;
                        assignment.location = buildSourceLocationRecord(location, sourceManager);

                        const std::string key =
                            assignment.lhsExpression +
                            "#" +
                            assignment.assignedFunction +
                            "#" +
                            std::to_string(i) +
                            "#" +
                            std::to_string(location.getRawEncoding());
                        if (seenGlobalAssignments.insert(key).second)
                        {
                            globalPointerAssignments_.push_back(std::move(assignment));
                            globalAddressTakenFunctions_.insert(assignedFunction);
                        }
                    }
                    continue;
                }

                const std::string assignedFunction = ::extractFunctionSymbol(initializer);
                if (assignedFunction.empty() ||
                    state_.blacklistedFunctions.find(assignedFunction) != state_.blacklistedFunctions.end())
                {
                    continue;
                }

                PointerAssignmentRecord assignment;
                assignment.lhsExpression = varDecl->getQualifiedNameAsString();
                assignment.rhsExpression = extractExpressionText(*state_.context, initializer);
                assignment.assignedFunction = assignedFunction;
                assignment.rhsTakesFunctionAddress = true;
                assignment.location = buildSourceLocationRecord(location, sourceManager);

                const std::string key =
                    assignment.lhsExpression +
                    "#" +
                    assignment.assignedFunction +
                    "#" +
                    std::to_string(location.getRawEncoding());
                if (seenGlobalAssignments.insert(key).second)
                {
                    globalPointerAssignments_.push_back(std::move(assignment));
                    globalAddressTakenFunctions_.insert(assignedFunction);
                }
            }

            globalFactsCollected_ = true;
        }

        CollectorState &state_;
        bool globalFactsCollected_ = false;
        std::vector<PointerAssignmentRecord> globalPointerAssignments_;
        std::set<std::string> globalAddressTakenFunctions_;
    };

    /**
     * @brief Translation-unit consumer that runs CFG visitor traversal.
     */
    class CfgConsumer : public clang::ASTConsumer
    {
    public:
        explicit CfgConsumer(CollectorState &state)
            : visitor_(state)
        {
        }

        /**
         * @brief Handle the parsed translation unit.
         */
        void HandleTranslationUnit(clang::ASTContext &context) override
        {
            (void)context;
            visitor_.TraverseDecl(context.getTranslationUnitDecl());
        }

    private:
        CfgVisitor visitor_;
    };

    /**
     * @brief Frontend action creating CFG-oriented AST consumers.
     */
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

    /**
     * @brief Frontend action factory for clang::tooling invocation.
     */
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

} // namespace

/**
 * @brief Generate CFG and call/pointer facts from input sources.
 * @return true on success, false on failure.
 */
bool generateCfgBundle(
    const std::vector<std::string> &inputs,
    const std::vector<std::string> &compilationArgs,
    const std::string &functionFilter,
    const std::set<std::string> &blacklistedFunctions,
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
    state.functionFilter = functionFilter;
    state.blacklistedFunctions = blacklistedFunctions;
    state.functions = &functions;

    CfgActionFactory factory(state);
    const int result = tool.run(&factory);
    if (result != 0)
    {
        errorMessage = "clang tooling failed with code " + std::to_string(result);
        return false;
    }

    bundle.functions = std::move(functions);
    return true;
}

/**
 * @brief Emit per-function DOT CFG files.
 * @return true on success, false on failure.
 */
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
