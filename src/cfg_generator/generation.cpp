/**
 * @file generation.cpp
 * @brief Implementation of CFG extraction, callsite fact collection, and DOT emission.
 */

#include "generation.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
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

    struct ConditionalIndexCallInfo
    {
        std::string trueLine;
        std::string falseLine;
        std::string trueExpression;
        std::string falseExpression;
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
     * @brief Parse a call line that contains a conditional array index.
     */
    bool parseConditionalIndexCallLine(const std::string &line, ConditionalIndexCallInfo &info)
    {
        const std::string trimmed = trimCopy(line);
        if (trimmed.find('(') == std::string::npos)
        {
            return false;
        }

        std::size_t indexStart = std::string::npos;
        std::size_t indexEnd = std::string::npos;
        std::string indexExpression;

        int depth = 0;
        for (std::size_t i = 0; i < trimmed.size(); ++i)
        {
            const char ch = trimmed[i];
            if (ch == '[')
            {
                if (depth == 0)
                {
                    indexStart = i;
                }
                ++depth;
                continue;
            }

            if (ch == ']')
            {
                if (depth > 0)
                {
                    --depth;
                }
                if (depth == 0 && indexStart != std::string::npos)
                {
                    const std::string candidate = trimmed.substr(indexStart + 1U, i - (indexStart + 1U));
                    const std::size_t questionIndex = findTopLevelChar(candidate, '?');
                    if (questionIndex == std::string::npos)
                    {
                        indexStart = std::string::npos;
                        continue;
                    }

                    const std::size_t colonIndex = findTopLevelChar(candidate, ':', questionIndex + 1U);
                    if (colonIndex == std::string::npos)
                    {
                        indexStart = std::string::npos;
                        continue;
                    }

                    indexEnd = i;
                    indexExpression = candidate;
                    break;
                }
            }
        }

        if (indexStart == std::string::npos || indexEnd == std::string::npos || indexExpression.empty())
        {
            const std::size_t questionIndexRaw = trimmed.find('?');
            if (questionIndexRaw == std::string::npos)
            {
                return false;
            }

            const std::size_t colonIndexRaw = trimmed.find(':', questionIndexRaw + 1U);
            if (colonIndexRaw == std::string::npos)
            {
                return false;
            }

            const std::size_t leftBracketRaw = trimmed.rfind('[', questionIndexRaw);
            const std::size_t rightBracketRaw = trimmed.find(']', colonIndexRaw + 1U);
            if (leftBracketRaw == std::string::npos || rightBracketRaw == std::string::npos || leftBracketRaw >= rightBracketRaw)
            {
                return false;
            }

            indexStart = leftBracketRaw;
            indexEnd = rightBracketRaw;
            indexExpression = trimmed.substr(indexStart + 1U, indexEnd - (indexStart + 1U));
        }

        const std::size_t questionIndex = findTopLevelChar(indexExpression, '?');
        const std::size_t colonIndex = findTopLevelChar(indexExpression, ':', questionIndex + 1U);
        if (questionIndex == std::string::npos || colonIndex == std::string::npos)
        {
            return false;
        }

        const std::string trueExpression = trimCopy(indexExpression.substr(questionIndex + 1U, colonIndex - (questionIndex + 1U)));
        const std::string falseExpression = trimCopy(indexExpression.substr(colonIndex + 1U));
        if (trueExpression.empty() || falseExpression.empty())
        {
            return false;
        }

        const std::string prefix = trimmed.substr(0, indexStart + 1U);
        const std::string suffix = trimmed.substr(indexEnd);

        info.trueLine = prefix + trueExpression + suffix;
        info.falseLine = prefix + falseExpression + suffix;
        info.trueExpression = trueExpression;
        info.falseExpression = falseExpression;
        return true;
    }

    /**
     * @brief Duplicate conditional store effects into predecessor blocks.
     */
    void applyConditionalStoreDuplication(SerializedFunction &function)
    {
        std::function<void(SerializedBlock &)> alignBlockCallSiteIds = [](SerializedBlock &block)
        {
            if (block.lineCallSiteIds.size() < block.lines.size())
            {
                block.lineCallSiteIds.resize(block.lines.size());
            }
            else if (block.lineCallSiteIds.size() > block.lines.size())
            {
                block.lineCallSiteIds.resize(block.lines.size());
            }
        };

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

        std::function<void(std::uint32_t, const std::string &, const std::string &)> assignInPredecessor =
            [&](std::uint32_t predecessorId, const std::string &variable, const std::string &expression)
        {
            const std::unordered_map<std::uint32_t, std::size_t>::const_iterator blockIt =
                blockIndexById.find(predecessorId);
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
                pred.lineCallSiteIds.emplace_back();
            }
        };

        std::function<void(std::uint32_t, const std::string &)> addLineInPredecessor =
            [&](std::uint32_t predecessorId, const std::string &line)
        {
            const std::unordered_map<std::uint32_t, std::size_t>::const_iterator blockIt =
                blockIndexById.find(predecessorId);
            if (blockIt == blockIndexById.end())
            {
                return;
            }

            SerializedBlock &pred = function.blocks[blockIt->second];
            if (std::find(pred.lines.begin(), pred.lines.end(), line) == pred.lines.end())
            {
                pred.lines.push_back(line);
                pred.lineCallSiteIds.emplace_back();
            }
        };

        for (SerializedBlock &block : function.blocks)
        {
            std::vector<std::string> updatedLines;
            std::vector<std::vector<std::string>> updatedLineCallSiteIds;
            updatedLines.reserve(block.lines.size());
            updatedLineCallSiteIds.reserve(block.lines.size());

            for (std::size_t lineIndex = 0; lineIndex < block.lines.size(); ++lineIndex)
            {
                const std::string &line = block.lines[lineIndex];
                const std::vector<std::string> &lineCallSiteIds =
                    lineIndex < block.lineCallSiteIds.size() ? block.lineCallSiteIds[lineIndex] : std::vector<std::string>{};
                ConditionalStoreInfo storeInfo;
                if (!parseConditionalStoreLine(line, storeInfo))
                {
                    ConditionalIndexCallInfo indexCallInfo;
                    if (!parseConditionalIndexCallLine(line, indexCallInfo))
                    {
                        updatedLines.push_back(line);
                        updatedLineCallSiteIds.push_back(lineCallSiteIds);
                        continue;
                    }

                    const std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>::const_iterator predsIt =
                        predecessors.find(block.id);
                    if (predsIt == predecessors.end() || predsIt->second.size() != 2U)
                    {
                        updatedLines.push_back(line);
                        updatedLineCallSiteIds.push_back(lineCallSiteIds);
                        continue;
                    }

                    std::vector<std::uint32_t> predIds = predsIt->second;
                    std::sort(predIds.begin(), predIds.end());

                    std::unordered_map<std::uint32_t, std::string> callByPred;
                    std::unordered_set<std::uint32_t> usedPreds;

                    std::function<void(const std::string &, const std::string &)> matchCallToPred =
                        [&](const std::string &indexExpr, const std::string &callLine)
                    {
                        const std::string token = "[" + trimCopy(indexExpr) + "]";
                        for (std::uint32_t predId : predIds)
                        {
                            if (usedPreds.find(predId) != usedPreds.end())
                            {
                                continue;
                            }

                            const std::unordered_map<std::uint32_t, std::size_t>::const_iterator predBlockIt =
                                blockIndexById.find(predId);
                            if (predBlockIt == blockIndexById.end())
                            {
                                continue;
                            }

                            const SerializedBlock &predBlock = function.blocks[predBlockIt->second];
                            for (const std::string &predLine : predBlock.lines)
                            {
                                if (trimCopy(predLine).find(token) != std::string::npos)
                                {
                                    callByPred[predId] = callLine;
                                    usedPreds.insert(predId);
                                    return;
                                }
                            }
                        }
                    };

                    matchCallToPred(indexCallInfo.trueExpression, indexCallInfo.trueLine);
                    matchCallToPred(indexCallInfo.falseExpression, indexCallInfo.falseLine);

                    std::vector<std::string> remainingCalls;
                    if (std::find_if(callByPred.begin(), callByPred.end(),
                                     [&](const std::pair<const std::uint32_t, std::string> &entry)
                                     { return entry.second == indexCallInfo.trueLine; }) == callByPred.end())
                    {
                        remainingCalls.push_back(indexCallInfo.trueLine);
                    }
                    if (std::find_if(callByPred.begin(), callByPred.end(),
                                     [&](const std::pair<const std::uint32_t, std::string> &entry)
                                     { return entry.second == indexCallInfo.falseLine; }) == callByPred.end())
                    {
                        remainingCalls.push_back(indexCallInfo.falseLine);
                    }

                    std::size_t fallbackIndex = 0;
                    for (std::uint32_t predId : predIds)
                    {
                        if (usedPreds.find(predId) != usedPreds.end())
                        {
                            continue;
                        }
                        if (fallbackIndex < remainingCalls.size())
                        {
                            callByPred[predId] = remainingCalls[fallbackIndex++];
                        }
                    }

                    for (const std::pair<const std::uint32_t, std::string> &entry : callByPred)
                    {
                        addLineInPredecessor(entry.first, entry.second);
                    }

                    continue;
                }

                const std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>::const_iterator predsIt =
                    predecessors.find(block.id);
                if (predsIt == predecessors.end() || predsIt->second.size() != 2U)
                {
                    updatedLines.push_back(line);
                    updatedLineCallSiteIds.push_back(lineCallSiteIds);
                    continue;
                }

                std::vector<std::uint32_t> predIds = predsIt->second;
                std::sort(predIds.begin(), predIds.end());

                std::unordered_map<std::uint32_t, std::string> expressionByPred;
                std::unordered_set<std::uint32_t> usedPreds;

                std::function<void(const std::string &)> matchExpressionToPred = [&](const std::string &expression)
                {
                    for (std::uint32_t predId : predIds)
                    {
                        if (usedPreds.find(predId) != usedPreds.end())
                        {
                            continue;
                        }

                        const std::unordered_map<std::uint32_t, std::size_t>::const_iterator predBlockIt =
                            blockIndexById.find(predId);
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
                                 [&](const std::pair<const std::uint32_t, std::string> &entry)
                                 { return entry.second == storeInfo.trueExpression; }) == expressionByPred.end())
                {
                    remainingExpressions.push_back(storeInfo.trueExpression);
                }
                if (std::find_if(expressionByPred.begin(), expressionByPred.end(),
                                 [&](const std::pair<const std::uint32_t, std::string> &entry)
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

                for (const std::pair<const std::uint32_t, std::string> &entry : expressionByPred)
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
            block.lineCallSiteIds.swap(updatedLineCallSiteIds);
            alignBlockCallSiteIds(block);
        }

        for (SerializedBlock &block : function.blocks)
        {
            const std::unordered_map<std::uint32_t, std::vector<std::string>>::const_iterator pendingIt =
                pendingDeclarationInsertions.find(block.id);
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
            std::vector<std::vector<std::string>> mergedIds;
            merged.reserve(insertions.size() + block.lines.size());
            mergedIds.reserve(insertions.size() + block.lines.size());
            for (const std::string &insertedLine : insertions)
            {
                merged.push_back(insertedLine);
                mergedIds.emplace_back();
            }
            merged.insert(merged.end(), block.lines.begin(), block.lines.end());
            mergedIds.insert(mergedIds.end(), block.lineCallSiteIds.begin(), block.lineCallSiteIds.end());
            block.lines.swap(merged);
            block.lineCallSiteIds.swap(mergedIds);
            alignBlockCallSiteIds(block);
        }
    }

    /**
     * @brief Remove presentation-only noise and collapse trivial passthrough blocks.
     */
    void cleanupCfgPresentation(SerializedFunction &function)
    {
        std::function<void(SerializedBlock &)> alignBlockCallSiteIds = [](SerializedBlock &block)
        {
            if (block.lineCallSiteIds.size() < block.lines.size())
            {
                block.lineCallSiteIds.resize(block.lines.size());
            }
            else if (block.lineCallSiteIds.size() > block.lines.size())
            {
                block.lineCallSiteIds.resize(block.lines.size());
            }
        };

        std::function<bool(const std::string &)> isLiteralOnlyLine = [](const std::string &line)
        {
            const std::string trimmed = trimCopy(line);
            if (trimmed.empty())
            {
                return false;
            }

            for (char ch : trimmed)
            {
                if (std::isdigit(static_cast<unsigned char>(ch)) == 0)
                {
                    return false;
                }
            }
            return true;
        };

        for (SerializedBlock &block : function.blocks)
        {
            std::vector<std::string> filtered;
            std::vector<std::vector<std::string>> filteredIds;
            filtered.reserve(block.lines.size());
            filteredIds.reserve(block.lines.size());
            for (std::size_t i = 0; i < block.lines.size(); ++i)
            {
                const std::string &line = block.lines[i];
                if (!isLiteralOnlyLine(line))
                {
                    filtered.push_back(line);
                    filteredIds.push_back(i < block.lineCallSiteIds.size() ? block.lineCallSiteIds[i] : std::vector<std::string>{});
                }
            }
            block.lines.swap(filtered);
            block.lineCallSiteIds.swap(filteredIds);
            alignBlockCallSiteIds(block);
        }

        bool changed = true;
        while (changed)
        {
            changed = false;

            std::unordered_map<std::uint32_t, std::size_t> blockIndexById;
            for (std::size_t i = 0; i < function.blocks.size(); ++i)
            {
                blockIndexById[function.blocks[i].id] = i;
            }

            for (std::size_t i = 0; i < function.blocks.size(); ++i)
            {
                const SerializedBlock &block = function.blocks[i];
                if (block.id == function.exitBlockId)
                {
                    continue;
                }
                if (!block.lines.empty() || block.successors.size() != 1U)
                {
                    continue;
                }

                const std::uint32_t passthroughId = block.id;
                const std::uint32_t targetId = block.successors.front();
                if (passthroughId == targetId)
                {
                    continue;
                }

                if (passthroughId == function.entryBlockId)
                {
                    function.entryBlockId = targetId;
                }

                for (SerializedBlock &pred : function.blocks)
                {
                    for (std::uint32_t &succ : pred.successors)
                    {
                        if (succ == passthroughId)
                        {
                            succ = targetId;
                        }
                    }

                    std::unordered_set<std::uint32_t> seenSucc;
                    std::vector<std::uint32_t> deduped;
                    deduped.reserve(pred.successors.size());
                    for (std::uint32_t succ : pred.successors)
                    {
                        if (seenSucc.insert(succ).second)
                        {
                            deduped.push_back(succ);
                        }
                    }
                    pred.successors.swap(deduped);
                }

                function.blocks.erase(function.blocks.begin() + static_cast<std::ptrdiff_t>(i));
                changed = true;
                break;
            }
        }

        for (SerializedBlock &block : function.blocks)
        {
            alignBlockCallSiteIds(block);
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

        if (const clang::DeclRefExpr *declRef = llvm::dyn_cast<clang::DeclRefExpr>(stripped))
        {
            if (const clang::FunctionDecl *functionDecl = llvm::dyn_cast<clang::FunctionDecl>(declRef->getDecl()))
            {
                return functionDecl->getQualifiedNameAsString();
            }
        }

        if (const clang::UnaryOperator *unaryOperator = llvm::dyn_cast<clang::UnaryOperator>(stripped))
        {
            if (unaryOperator->getOpcode() == clang::UO_AddrOf)
            {
                const clang::Expr *subExpression = unaryOperator->getSubExpr()->IgnoreParenImpCasts();
                if (const clang::DeclRefExpr *subDeclRef = llvm::dyn_cast<clang::DeclRefExpr>(subExpression))
                {
                    if (const clang::FunctionDecl *functionDecl = llvm::dyn_cast<clang::FunctionDecl>(subDeclRef->getDecl()))
                    {
                        return functionDecl->getQualifiedNameAsString();
                    }
                }
            }
        }

        return "";
    }

    /**
     * @brief Collect all function symbols referenced anywhere in an expression.
     */
    void collectFunctionSymbols(const clang::Expr *expr, std::set<std::string> &symbols)
    {
        if (expr == nullptr)
        {
            return;
        }

        const std::string symbol = ::extractFunctionSymbol(expr);
        if (!symbol.empty())
        {
            symbols.insert(symbol);
        }

        for (const clang::Stmt *child : expr->children())
        {
            const clang::Expr *childExpr = llvm::dyn_cast_or_null<clang::Expr>(child);
            if (childExpr != nullptr)
            {
                collectFunctionSymbols(childExpr, symbols);
            }
        }
    }

    /**
     * @brief Parse a struct access expression like "s.f" or "s->f".
     */
    std::pair<std::string, std::string> parseStructAccessText(std::string text)
    {
        for (std::size_t pos = text.find("->"); pos != std::string::npos; pos = text.find("->", pos + 1U))
        {
            text.replace(pos, 2U, ".");
        }

        std::string normalized;
        normalized.reserve(text.size());
        int bracketDepth = 0;
        for (char ch : text)
        {
            if (ch == '[')
            {
                ++bracketDepth;
                continue;
            }
            if (ch == ']')
            {
                if (bracketDepth > 0)
                {
                    --bracketDepth;
                }
                continue;
            }
            if (bracketDepth == 0)
            {
                normalized.push_back(ch);
            }
        }

        normalized = trimCopy(normalized);
        const std::size_t dotIndex = normalized.find('.');
        if (dotIndex == std::string::npos || dotIndex == 0U)
        {
            return {"", ""};
        }

        return {trimCopy(normalized.substr(0, dotIndex)), trimCopy(normalized.substr(dotIndex + 1U))};
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

    std::string extractReferencedIdentifier(const clang::Expr *expr)
    {
        if (expr == nullptr)
        {
            return "";
        }

        const clang::Expr *stripped = expr->IgnoreParenImpCasts();
        const clang::DeclRefExpr *declRef = llvm::dyn_cast<clang::DeclRefExpr>(stripped);
        if (declRef == nullptr)
        {
            return "";
        }

        const clang::ValueDecl *valueDecl = llvm::dyn_cast<clang::ValueDecl>(declRef->getDecl());
        if (valueDecl == nullptr || llvm::isa<clang::FunctionDecl>(valueDecl))
        {
            return "";
        }

        return valueDecl->getQualifiedNameAsString();
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

            const clang::Expr *lhsExpr = binaryOperator->getLHS()->IgnoreParenImpCasts();
            assignment.lhsIsGlobal = isGlobalStorageLhs(lhsExpr);

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

            const std::pair<std::string, std::string> lhsAccess = parseStructAccessText(assignment.lhsExpression);
            if (!lhsAccess.first.empty() && !lhsAccess.second.empty())
            {
                std::set<std::string> functionSymbols;
                collectFunctionSymbols(binaryOperator->getRHS(), functionSymbols);

                if (functionSymbols.empty())
                {
                    const std::pair<std::string, std::string> rhsAccess = parseStructAccessText(assignment.rhsExpression);
                    if (!rhsAccess.first.empty() && !rhsAccess.second.empty())
                    {
                        for (const StructMemberMapping &existing : structMemberMappings_)
                        {
                            if (existing.structVariable == rhsAccess.first && existing.memberName == rhsAccess.second)
                            {
                                functionSymbols.insert(existing.functionName);
                            }
                        }
                    }
                }

                std::vector<std::string> lhsMemberNames;
                lhsMemberNames.push_back(lhsAccess.second);

                const clang::Expr *lhsMemberExpr = binaryOperator->getLHS()->IgnoreParenImpCasts();
                if (const clang::MemberExpr *memberExpr = llvm::dyn_cast<clang::MemberExpr>(lhsMemberExpr))
                {
                    if (const clang::FieldDecl *fieldDecl = llvm::dyn_cast<clang::FieldDecl>(memberExpr->getMemberDecl()))
                    {
                        const clang::RecordDecl *owner = fieldDecl->getParent();
                        if (owner != nullptr && owner->isUnion())
                        {
                            const std::size_t tailPos = lhsAccess.second.rfind('.');
                            const std::string prefix = tailPos == std::string::npos ? "" : lhsAccess.second.substr(0, tailPos + 1U);

                            std::unordered_set<std::string> seenMembers(lhsMemberNames.begin(), lhsMemberNames.end());
                            for (const clang::FieldDecl *sibling : owner->fields())
                            {
                                const std::string siblingName = sibling->getNameAsString();
                                const std::string candidate = prefix + siblingName;
                                if (seenMembers.insert(candidate).second)
                                {
                                    lhsMemberNames.push_back(candidate);
                                }
                            }
                        }
                    }
                }

                for (const std::string &functionSymbol : functionSymbols)
                {
                    if (blacklistedFunctions_.find(functionSymbol) != blacklistedFunctions_.end())
                    {
                        continue;
                    }

                    for (const std::string &lhsMemberName : lhsMemberNames)
                    {
                        StructMemberMapping mapping;
                        mapping.structVariable = lhsAccess.first;
                        mapping.memberName = lhsMemberName;
                        mapping.functionName = functionSymbol;
                        mapping.location = buildSourceLocationRecord(location, sourceManager);

                        structMemberMappings_.push_back(std::move(mapping));
                    }
                    addressTakenFunctions_.insert(functionSymbol);
                }

                // If lhs base aliases a global aggregate, also map the global base member.
                const std::string pointerTarget = resolvePointerTarget(lhsAccess.first);
                const std::string globalBaseName = extractGlobalBaseFromPointerTarget(pointerTarget);
                if (!globalBaseName.empty())
                {
                    for (const std::string &functionSymbol : functionSymbols)
                    {
                        if (blacklistedFunctions_.find(functionSymbol) != blacklistedFunctions_.end())
                        {
                            continue;
                        }

                        for (const std::string &lhsMemberName : lhsMemberNames)
                        {
                            StructMemberMapping globalMapping;
                            globalMapping.structVariable = globalBaseName;
                            globalMapping.memberName = lhsMemberName;
                            globalMapping.functionName = functionSymbol;
                            globalMapping.location = buildSourceLocationRecord(location, sourceManager);

                            structMemberMappings_.push_back(std::move(globalMapping));
                        }
                    }
                }
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
            assignment.lhsIsGlobal = varDecl->hasGlobalStorage();

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

            // Track struct member initializations using the local variable name.
            trackStructMemberMappings(varDecl->getNameAsString(), varDecl->getInit());

            return true;
        }

        /**
         * @brief Track struct member to function mappings from InitListExpr.
         */
        void trackStructMemberMappings(const std::string &varName, const clang::Expr *initExpr)
        {
            if (initExpr == nullptr)
            {
                return;
            }

            std::function<void(const clang::Expr *, const std::string &)> visitInit;
            visitInit = [&](const clang::Expr *expr, const std::string &memberPath)
            {
                if (expr == nullptr)
                {
                    return;
                }

                const clang::Expr *stripped = expr->IgnoreParenImpCasts()->IgnoreImplicit();

                const std::string functionName = ::extractFunctionSymbol(stripped);
                if (!functionName.empty() && !memberPath.empty() &&
                    blacklistedFunctions_.find(functionName) == blacklistedFunctions_.end())
                {
                    StructMemberMapping mapping;
                    mapping.structVariable = varName;
                    mapping.memberName = memberPath;
                    mapping.functionName = functionName;
                    mapping.location = buildSourceLocationRecord(
                        context_.getSourceManager().getSpellingLoc(stripped->getExprLoc()),
                        context_.getSourceManager());

                    structMemberMappings_.push_back(std::move(mapping));
                    addressTakenFunctions_.insert(functionName);
                    return;
                }

                const clang::DesignatedInitExpr *designated = llvm::dyn_cast<clang::DesignatedInitExpr>(stripped);
                if (designated != nullptr)
                {
                    visitInit(designated->getInit(), memberPath);
                    return;
                }

                const clang::InitListExpr *initList = llvm::dyn_cast<clang::InitListExpr>(stripped);
                if (initList == nullptr)
                {
                    return;
                }

                const clang::RecordType *recordType = llvm::dyn_cast<clang::RecordType>(initList->getType().getCanonicalType());
                if (recordType != nullptr)
                {
                    std::vector<std::string> fieldNames;
                    for (const clang::FieldDecl *field : recordType->getDecl()->fields())
                    {
                        fieldNames.push_back(field->getNameAsString());
                    }

                    for (unsigned i = 0; i < initList->getNumInits(); ++i)
                    {
                        const clang::Expr *child = initList->getInit(i);
                        if (child == nullptr)
                        {
                            continue;
                        }

                        std::string childPath = memberPath;
                        if (i < fieldNames.size())
                        {
                            childPath = memberPath.empty() ? fieldNames[i] : (memberPath + "." + fieldNames[i]);
                        }
                        visitInit(child, childPath);
                    }
                    return;
                }

                for (unsigned i = 0; i < initList->getNumInits(); ++i)
                {
                    visitInit(initList->getInit(i), memberPath);
                }
            };

            visitInit(initExpr, "");
        }

        const std::vector<CallSiteRecord> &callSites() const
        {
            return callSites_;
        }

        const std::vector<PointerAssignmentRecord> &pointerAssignments() const
        {
            return pointerAssignments_;
        }

        const std::vector<StructMemberMapping> &structMemberMappings() const
        {
            return structMemberMappings_;
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
            const clang::DeclRefExpr *declRef = llvm::dyn_cast<clang::DeclRefExpr>(stripped);
            if (declRef == nullptr)
            {
                return "";
            }

            const clang::ValueDecl *valueDecl = llvm::dyn_cast<clang::ValueDecl>(declRef->getDecl());
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

        /**
         * @brief Determine whether an LHS expression ultimately targets global storage.
         */
        bool isGlobalStorageLhs(const clang::Expr *expr)
        {
            if (expr == nullptr)
            {
                return false;
            }

            const clang::Expr *current = expr->IgnoreParenImpCasts();
            while (current != nullptr)
            {
                if (const clang::DeclRefExpr *declRef = llvm::dyn_cast<clang::DeclRefExpr>(current))
                {
                    if (const clang::VarDecl *varDecl = llvm::dyn_cast<clang::VarDecl>(declRef->getDecl()))
                    {
                        if (varDecl->hasGlobalStorage())
                        {
                            return true;
                        }

                        if (!varDecl->getType()->isPointerType())
                        {
                            return false;
                        }

                        const std::string directName = varDecl->getNameAsString();
                        const std::string qualifiedName = varDecl->getQualifiedNameAsString();

                        if (!directName.empty())
                        {
                            std::unordered_set<std::string> visited;
                            if (!resolveGlobalBaseFromPointerName(directName, visited).empty())
                            {
                                return true;
                            }
                        }
                        if (!qualifiedName.empty())
                        {
                            std::unordered_set<std::string> visited;
                            if (!resolveGlobalBaseFromPointerName(qualifiedName, visited).empty())
                            {
                                return true;
                            }
                        }

                        if (varDecl->hasInit())
                        {
                            const std::string initText = extractExpressionText(varDecl->getInit());
                            if (!extractGlobalBaseFromPointerTarget(initText).empty())
                            {
                                return true;
                            }
                        }

                        return false;
                    }
                    return false;
                }

                if (const clang::MemberExpr *memberExpr = llvm::dyn_cast<clang::MemberExpr>(current))
                {
                    current = memberExpr->getBase()->IgnoreParenImpCasts();
                    continue;
                }

                if (const clang::ArraySubscriptExpr *arrayExpr = llvm::dyn_cast<clang::ArraySubscriptExpr>(current))
                {
                    current = arrayExpr->getBase()->IgnoreParenImpCasts();
                    continue;
                }

                if (const clang::UnaryOperator *unaryOp = llvm::dyn_cast<clang::UnaryOperator>(current))
                {
                    if (unaryOp->getOpcode() == clang::UO_Deref || unaryOp->getOpcode() == clang::UO_AddrOf)
                    {
                        current = unaryOp->getSubExpr()->IgnoreParenImpCasts();
                        continue;
                    }
                }

                break;
            }

            return false;
        }

        /**
         * @brief Resolve what a local pointer variable points to (e.g., a global).
         * Returns the RHS expression if found in pointer assignments.
         */
        std::string resolvePointerTarget(const std::string &pointerName)
        {
            for (const PointerAssignmentRecord &assignment : pointerAssignments_)
            {
                if (assignment.lhsExpression == pointerName && !assignment.rhsExpression.empty())
                {
                    return assignment.rhsExpression;
                }
            }
            return "";
        }

        /**
         * @brief Check if an expression appears to point to a global.
         */
        bool pointsToGlobal(const std::string &expression)
        {
            return !extractGlobalBaseFromPointerTarget(expression).empty();
        }

        /**
         * @brief Extract first identifier token from expression text.
         */
        std::string extractLeadingIdentifier(const std::string &expression)
        {
            const std::string text = trimCopy(expression);
            std::size_t i = 0;
            while (i < text.size())
            {
                const unsigned char ch = static_cast<unsigned char>(text[i]);
                if (std::isalpha(ch) != 0 || text[i] == '_')
                {
                    break;
                }
                ++i;
            }

            if (i >= text.size())
            {
                return "";
            }

            std::size_t end = i + 1U;
            while (end < text.size())
            {
                const unsigned char ch = static_cast<unsigned char>(text[end]);
                if (std::isalnum(ch) == 0 && text[end] != '_')
                {
                    break;
                }
                ++end;
            }

            return text.substr(i, end - i);
        }

        /**
         * @brief Resolve global base variable referenced by a pointer target expression.
         */
        std::string extractGlobalBaseFromPointerTarget(const std::string &pointerTarget)
        {
            if (pointerTarget.empty())
            {
                return "";
            }

            std::unordered_set<std::string> visited;
            return extractGlobalBaseFromPointerTargetImpl(pointerTarget, visited);
        }

        /**
         * @brief Resolve global base variable recursively from pointer-like expression text.
         */
        std::string extractGlobalBaseFromPointerTargetImpl(
            const std::string &pointerTarget,
            std::unordered_set<std::string> &visited)
        {
            const std::string trimmed = trimCopy(pointerTarget);
            if (trimmed.empty())
            {
                return "";
            }

            if (!visited.insert(trimmed).second)
            {
                return "";
            }

            const std::string base = extractLeadingIdentifier(trimmed);
            if (base.empty())
            {
                return "";
            }

            if (isFileScopeGlobalVariable(base))
            {
                return base;
            }

            const std::string aliasedGlobalBase = resolveGlobalBaseFromPointerName(base, visited);
            if (!aliasedGlobalBase.empty())
            {
                return aliasedGlobalBase;
            }

            for (const PointerAssignmentRecord &assignment : pointerAssignments_)
            {
                if (!assignment.lhsIsGlobal)
                {
                    continue;
                }

                if (assignment.lhsExpression == base)
                {
                    return base;
                }

                const std::pair<std::string, std::string> access = parseStructAccessText(assignment.lhsExpression);
                if (!access.first.empty() && access.first == base)
                {
                    return base;
                }
            }

            return "";
        }

        /**
         * @brief Resolve local pointer name to a global base through recorded assignments.
         */
        std::string resolveGlobalBaseFromPointerName(
            const std::string &pointerName,
            std::unordered_set<std::string> &visited)
        {
            if (pointerName.empty())
            {
                return "";
            }

            if (!visited.insert(pointerName).second)
            {
                return "";
            }

            bool sawDefinition = false;
            std::set<std::string> resolvedGlobalBases;

            for (const PointerAssignmentRecord &assignment : pointerAssignments_)
            {
                if (assignment.lhsExpression != pointerName)
                {
                    continue;
                }

                sawDefinition = true;

                std::unordered_set<std::string> rhsVisited = visited;
                const std::string globalBase = extractGlobalBaseFromPointerTargetImpl(assignment.rhsExpression, rhsVisited);
                if (globalBase.empty())
                {
                    // At least one definition does not resolve to a global base.
                    // Keep lhsIsGlobal false to avoid control-flow-insensitive false positives.
                    return "";
                }

                resolvedGlobalBases.insert(globalBase);
                if (resolvedGlobalBases.size() > 1U)
                {
                    // Conflicting global targets across definitions => not must-global.
                    return "";
                }
            }

            if (!sawDefinition || resolvedGlobalBases.empty())
            {
                return "";
            }

            return *resolvedGlobalBases.begin();
        }

        /**
         * @brief Check whether an identifier refers to a file-scope global variable.
         */
        bool isFileScopeGlobalVariable(const std::string &identifier)
        {
            if (identifier.empty())
            {
                return false;
            }

            ensureGlobalVariableNames();
            return globalVariableNames_.find(identifier) != globalVariableNames_.end();
        }

        /**
         * @brief Populate cache of file-scope global variable names.
         */
        void ensureGlobalVariableNames()
        {
            if (globalVariableNamesInitialized_)
            {
                return;
            }

            globalVariableNamesInitialized_ = true;
            clang::TranslationUnitDecl *translationUnit = context_.getTranslationUnitDecl();
            if (translationUnit == nullptr)
            {
                return;
            }

            for (const clang::Decl *decl : translationUnit->decls())
            {
                const clang::VarDecl *varDecl = llvm::dyn_cast<clang::VarDecl>(decl);
                if (varDecl == nullptr || !varDecl->isFileVarDecl())
                {
                    continue;
                }

                const std::string name = varDecl->getNameAsString();
                if (!name.empty())
                {
                    globalVariableNames_.insert(name);
                }
                const std::string qualifiedName = varDecl->getQualifiedNameAsString();
                if (!qualifiedName.empty())
                {
                    globalVariableNames_.insert(qualifiedName);
                }
            }
        }

        clang::ASTContext &context_;
        std::string functionName_;
        const std::set<std::string> &blacklistedFunctions_;
        std::vector<CallSiteRecord> callSites_;
        std::vector<PointerAssignmentRecord> pointerAssignments_;
        std::vector<StructMemberMapping> structMemberMappings_;
        std::set<std::string> addressTakenFunctions_;
        std::unordered_set<std::string> seenCallSites_;
        std::unordered_set<std::string> seenAssignments_;
        std::vector<std::set<std::string>> stateChangeValues_;
        bool globalVariableNamesInitialized_ = false;
        std::unordered_set<std::string> globalVariableNames_;
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
    struct BlockLineCollection
    {
        std::vector<std::string> lines;
        std::vector<std::vector<std::string>> lineCallSiteIds;
    };

    std::vector<std::string> collectStatementCallSiteIds(
        const clang::Stmt *statement,
        clang::ASTContext &context,
        const std::string &functionName,
        const std::unordered_set<std::string> &knownCallSiteIds)
    {
        std::vector<std::string> callSiteIds;
        if (statement == nullptr)
        {
            return callSiteIds;
        }

        const clang::SourceManager &sourceManager = context.getSourceManager();

        std::function<void(const clang::Stmt *)> visit = [&](const clang::Stmt *node)
        {
            if (node == nullptr)
            {
                return;
            }

            for (const clang::Stmt *child : node->children())
            {
                visit(child);
            }

            if (const clang::CallExpr *call = llvm::dyn_cast<clang::CallExpr>(node))
            {
                CallSiteRecord callSite;
                const clang::SourceLocation location = sourceManager.getSpellingLoc(call->getExprLoc());
                callSite.location = buildSourceLocationRecord(location, sourceManager);
                callSite.calleeExpression = extractStatementText(call->getCallee(), context);

                if (const clang::FunctionDecl *callee = call->getDirectCallee())
                {
                    callSite.directCallee = callee->getQualifiedNameAsString();
                }
                else
                {
                    callSite.isIndirect = true;
                    callSite.throughIdentifier = extractReferencedIdentifier(call->getCallee());
                }

                for (const clang::Expr *argument : call->arguments())
                {
                    callSite.argumentExpressions.push_back(extractStatementText(argument, context));
                }

                const std::string stableId = buildStableCallSiteId(functionName, callSite);
                if (knownCallSiteIds.find(stableId) != knownCallSiteIds.end())
                {
                    callSiteIds.push_back(stableId);
                }
            }
        };

        visit(statement);
        return callSiteIds;
    }

    BlockLineCollection collectBlockLines(
        const clang::CFGBlock &block,
        clang::ASTContext &context,
        const std::string &functionName,
        const std::unordered_set<std::string> &knownCallSiteIds)
    {
        BlockLineCollection result;
        std::set<const clang::Stmt *> seenStatements;
        std::unordered_set<std::string> emittedCallSiteIds;
        std::vector<clang::SourceRange> containerRanges;

        for (const clang::CFGElement &element : block)
        {
            decltype(element.getAs<clang::CFGStmt>()) statement = element.getAs<clang::CFGStmt>();
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

        for (const clang::CFGElement &element : block)
        {
            decltype(element.getAs<clang::CFGStmt>()) statement = element.getAs<clang::CFGStmt>();
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

            std::vector<std::string> stmtCallSiteIds =
                collectStatementCallSiteIds(stmt, context, functionName, knownCallSiteIds);

            // A single semantic call can surface multiple statement views (e.g. ternary
            // lowering), which can repeat the same callsite ID in one block.
            if (!stmtCallSiteIds.empty())
            {
                std::vector<std::string> filteredCallSiteIds;
                filteredCallSiteIds.reserve(stmtCallSiteIds.size());
                for (const std::string &callSiteId : stmtCallSiteIds)
                {
                    if (emittedCallSiteIds.insert(callSiteId).second)
                    {
                        filteredCallSiteIds.push_back(callSiteId);
                    }
                }
                stmtCallSiteIds.swap(filteredCallSiteIds);
            }

            // Preserve all statements in encounter order, including same-line siblings.
            if (result.lines.empty() ||
                result.lines.back() != stmtText ||
                result.lineCallSiteIds.back() != stmtCallSiteIds)
            {
                result.lines.push_back(stmtText);
                result.lineCallSiteIds.push_back(stmtCallSiteIds);
            }
        }

        return result;
    }

    struct CollectorState
    {
        clang::ASTContext *context = nullptr;
        std::string functionFilter;
        std::set<std::string> blacklistedFunctions;
        std::vector<SerializedFunction> *functions = nullptr;
        std::unordered_set<std::string> emittedFunctionDefinitionKeys;
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

            const clang::SourceManager &sourceManager = state_.context->getSourceManager();
            const SourceLocationRecord definitionLocation =
                buildSourceLocationRecord(functionDecl->getLocation(), sourceManager);
            std::string definitionKey = functionName;
            if (!definitionLocation.file.empty() && definitionLocation.line != 0U)
            {
                definitionKey += "#" + definitionLocation.file +
                                 "#" + std::to_string(definitionLocation.line) +
                                 ":" + std::to_string(definitionLocation.column);
            }

            if (!state_.emittedFunctionDefinitionKeys.insert(definitionKey).second)
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

            CallVisitor callVisitor(*state_.context, functionName, state_.blacklistedFunctions);
            callVisitor.TraverseStmt(body);

            std::unordered_set<std::string> knownCallSiteIds;
            for (const CallSiteRecord &callSite : callVisitor.callSites())
            {
                if (!callSite.callSiteId.empty())
                {
                    knownCallSiteIds.insert(callSite.callSiteId);
                }
            }

            std::vector<SerializedBlock> rawBlocks;

            for (const clang::CFGBlock *block : *graph)
            {
                if (block == nullptr)
                {
                    continue;
                }

                SerializedBlock serializedBlock;
                serializedBlock.id = static_cast<std::uint32_t>(block->getBlockID());
                const BlockLineCollection blockLines =
                    collectBlockLines(*block, *state_.context, functionName, knownCallSiteIds);
                serializedBlock.lines = blockLines.lines;
                serializedBlock.lineCallSiteIds = blockLines.lineCallSiteIds;

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
            cleanupCfgPresentation(function);

            bool collapsedEntry = true;
            while (collapsedEntry)
            {
                collapsedEntry = false;
                for (std::size_t i = 0; i < function.blocks.size(); ++i)
                {
                    const SerializedBlock &block = function.blocks[i];
                    if (block.id != function.entryBlockId)
                    {
                        continue;
                    }
                    if (!block.lines.empty() || block.successors.size() != 1U)
                    {
                        break;
                    }

                    const std::uint32_t nextEntry = block.successors.front();
                    if (nextEntry == function.entryBlockId || nextEntry == function.exitBlockId)
                    {
                        break;
                    }

                    function.entryBlockId = nextEntry;
                    function.blocks.erase(function.blocks.begin() + static_cast<std::ptrdiff_t>(i));
                    collapsedEntry = true;
                    break;
                }
            }

            ensureGlobalFactsCollected();

            for (const clang::ParmVarDecl *parameter : functionDecl->parameters())
            {
                if (parameter == nullptr)
                {
                    continue;
                }

                const std::string parameterName = parameter->getNameAsString();
                if (!parameterName.empty())
                {
                    function.attributes.parameterNames.push_back(parameterName);
                }
            }

            const clang::QualType returnType = functionDecl->getReturnType();
            function.attributes.returnsPointerLike =
                returnType->isAnyPointerType() ||
                returnType->isBlockPointerType() ||
                returnType->isReferenceType();

            function.attributes.callSites = callVisitor.callSites();
            function.attributes.pointerAssignments = globalPointerAssignments_;
            function.attributes.pointerAssignments.insert(
                function.attributes.pointerAssignments.end(),
                callVisitor.pointerAssignments().begin(),
                callVisitor.pointerAssignments().end());

            function.attributes.structMemberMappings = globalStructMemberMappings_;
            function.attributes.structMemberMappings.insert(
                function.attributes.structMemberMappings.end(),
                callVisitor.structMemberMappings().begin(),
                callVisitor.structMemberMappings().end());

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
         * @brief Track struct member to function mappings from global InitListExpr.
         */
        void trackGlobalStructMemberMappings(const std::string &varName, const clang::InitListExpr *initListExpr)
        {
            if (initListExpr == nullptr)
            {
                return;
            }

            std::function<void(const clang::Expr *, const std::string &)> visitInit;
            visitInit = [&](const clang::Expr *expr, const std::string &memberPath)
            {
                if (expr == nullptr)
                {
                    return;
                }

                const clang::Expr *stripped = expr->IgnoreParenImpCasts()->IgnoreImplicit();

                const std::string functionName = ::extractFunctionSymbol(stripped);
                if (!functionName.empty() && !memberPath.empty() &&
                    state_.blacklistedFunctions.find(functionName) == state_.blacklistedFunctions.end())
                {
                    StructMemberMapping mapping;
                    mapping.structVariable = varName;
                    mapping.memberName = memberPath;
                    mapping.functionName = functionName;
                    mapping.location = buildSourceLocationRecord(
                        state_.context->getSourceManager().getSpellingLoc(stripped->getExprLoc()),
                        state_.context->getSourceManager());

                    globalStructMemberMappings_.push_back(std::move(mapping));
                    globalAddressTakenFunctions_.insert(functionName);
                    return;
                }

                const clang::DesignatedInitExpr *designated = llvm::dyn_cast<clang::DesignatedInitExpr>(stripped);
                if (designated != nullptr)
                {
                    visitInit(designated->getInit(), memberPath);
                    return;
                }

                const clang::InitListExpr *initList = llvm::dyn_cast<clang::InitListExpr>(stripped);
                if (initList == nullptr)
                {
                    return;
                }

                const clang::RecordType *recordType = llvm::dyn_cast<clang::RecordType>(initList->getType().getCanonicalType());
                if (recordType != nullptr)
                {
                    std::vector<std::string> fieldNames;
                    for (const clang::FieldDecl *field : recordType->getDecl()->fields())
                    {
                        fieldNames.push_back(field->getNameAsString());
                    }

                    for (unsigned i = 0; i < initList->getNumInits(); ++i)
                    {
                        const clang::Expr *child = initList->getInit(i);
                        if (child == nullptr)
                        {
                            continue;
                        }

                        std::string childPath = memberPath;
                        if (i < fieldNames.size())
                        {
                            childPath = memberPath.empty() ? fieldNames[i] : (memberPath + "." + fieldNames[i]);
                        }
                        visitInit(child, childPath);
                    }
                    return;
                }

                for (unsigned i = 0; i < initList->getNumInits(); ++i)
                {
                    visitInit(initList->getInit(i), memberPath);
                }
            };

            visitInit(initListExpr, "");
        }

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
                const clang::VarDecl *varDecl = llvm::dyn_cast<clang::VarDecl>(decl);
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

                const clang::InitListExpr *initList = llvm::dyn_cast<clang::InitListExpr>(strippedInitializer);
                if (initList != nullptr)
                {
                    // Track struct member mappings from global initializers
                    trackGlobalStructMemberMappings(varDecl->getQualifiedNameAsString(), initList);

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
                        assignment.lhsIsGlobal = true;
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
                assignment.lhsIsGlobal = true;
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
        std::vector<StructMemberMapping> globalStructMemberMappings_;
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

    std::function<bool(const std::filesystem::path &)> isCSourceFile = [](const std::filesystem::path &path)
    {
        std::string extension = path.extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char ch)
                       { return static_cast<char>(std::tolower(ch)); });
        return extension == ".c";
    };

    std::function<bool(const std::filesystem::path &)> isCHeaderFile = [](const std::filesystem::path &path)
    {
        std::string extension = path.extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char ch)
                       { return static_cast<char>(std::tolower(ch)); });
        return extension == ".h";
    };

    std::vector<std::string> sourceFiles;
    for (const std::string &input : inputs)
    {
        std::error_code ec;
        if (std::filesystem::is_directory(input, ec))
        {
            for (std::filesystem::recursive_directory_iterator it = std::filesystem::recursive_directory_iterator(input);
                 it != std::filesystem::recursive_directory_iterator();
                 ++it)
            {
                if (std::filesystem::is_regular_file(it->path(), ec))
                {
                    if (isCSourceFile(it->path()) || isCHeaderFile(it->path()))
                    {
                        sourceFiles.push_back(it->path().string());
                    }
                }
            }
        }
        else if (std::filesystem::is_regular_file(input, ec))
        {
            const std::filesystem::path inputPath(input);
            if (isCSourceFile(inputPath) || isCHeaderFile(inputPath))
            {
                sourceFiles.push_back(input);
            }
        }
    }

    std::sort(sourceFiles.begin(), sourceFiles.end());
    sourceFiles.erase(std::unique(sourceFiles.begin(), sourceFiles.end()), sourceFiles.end());

    if (sourceFiles.empty())
    {
        errorMessage = "no C source/header files discovered";
        return false;
    }

    std::vector<std::string> fixedArgs = compilationArgs;
    if (std::find(fixedArgs.begin(), fixedArgs.end(), "-std=c11") == fixedArgs.end())
    {
        fixedArgs.push_back("-std=c11");
    }

    clang::tooling::FixedCompilationDatabase compilationDatabase(".", fixedArgs);
    clang::tooling::ClangTool tool(compilationDatabase, sourceFiles);
    const bool containsHeaderInput = std::any_of(sourceFiles.begin(), sourceFiles.end(), [&](const std::string &file)
                                                 { return isCHeaderFile(std::filesystem::path(file)); });
    if (containsHeaderInput)
    {
        // Explicit header analysis needs an explicit language mode for standalone parsing.
        tool.appendArgumentsAdjuster(clang::tooling::getInsertArgumentAdjuster("-xc", clang::tooling::ArgumentInsertPosition::BEGIN));
    }

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
