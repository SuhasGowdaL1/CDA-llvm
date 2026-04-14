/**
 * @file callgraph_analysis.cpp
 * @brief Flow-sensitive, context-sensitive static call graph resolver.
 */

#include "callgraph_analysis.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <deque>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "llvm/Support/JSON.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"

namespace
{

    bool gDebugLoggingEnabled = false;

    using CallSiteId = std::uint32_t;
    constexpr CallSiteId kInvalidCallSiteId = 0U;

    struct StringInterner
    {
        std::vector<std::string> values;
        std::unordered_map<std::string, CallSiteId> idsByValue;

        CallSiteId intern(const std::string &value)
        {
            if (value.empty())
            {
                return kInvalidCallSiteId;
            }

            const std::unordered_map<std::string, CallSiteId>::const_iterator it = idsByValue.find(value);
            if (it != idsByValue.end())
            {
                return it->second;
            }

            const CallSiteId id = static_cast<CallSiteId>(values.size() + 1U);
            values.push_back(value);
            idsByValue.emplace(values.back(), id);
            return id;
        }

        const std::string &lookup(CallSiteId id) const
        {
            static const std::string kEmpty;
            if (id == kInvalidCallSiteId)
            {
                return kEmpty;
            }

            const std::size_t index = static_cast<std::size_t>(id - 1U);
            if (index >= values.size())
            {
                return kEmpty;
            }

            return values[index];
        }
    };

    using SmallStringList = llvm::SmallVector<std::string, 8>;

    template <typename Container>
    bool appendUnique(Container &container, const typename Container::value_type &value)
    {
        if (std::find(container.begin(), container.end(), value) != container.end())
        {
            return false;
        }

        container.push_back(value);
        return true;
    }

    struct SourceLocation
    {
        std::string file;
        std::uint32_t line = 0;
        std::uint32_t column = 0;
    };

    struct CallSite
    {
        CallSiteId callSiteId = kInvalidCallSiteId;
        std::string calleeExpression;
        std::string directCallee;
        std::string throughIdentifier;
        std::vector<std::string> argumentExpressions;
        bool isIndirect = false;
        SourceLocation location;
    };

    struct PointerAssignment
    {
        std::string lhsExpression;
        std::string rhsExpression;
        std::string assignedFunction;
        bool rhsTakesFunctionAddress = false;
        bool lhsIsGlobal = false;
        SourceLocation location;
    };

    struct StructMemberMapping
    {
        std::string structVariable;
        std::string memberName;
        std::string functionName;
        SourceLocation location;
        bool programWideSeed = false;
    };

    struct FunctionFacts
    {
        std::string name;
        std::uint32_t entryBlockId = 0;
        bool hasReturnPointerMetadata = false;
        bool returnsPointerLike = false;
        std::vector<std::string> parameterNames;
        std::set<std::string> addressTakenFunctions;
        std::vector<CallSite> callSites;
        std::vector<PointerAssignment> pointerAssignments;
        std::vector<StructMemberMapping> structMemberMappings;
        struct BlockFact
        {
            std::uint32_t id = 0;
            std::vector<std::string> lines;
            std::vector<std::vector<CallSiteId>> lineCallSiteIds;
            std::vector<std::uint32_t> successors;
        };
        std::vector<BlockFact> blocks;
    };

    struct CallEdge
    {
        std::string caller;
        std::string callee;
        CallSiteId callSiteId = kInvalidCallSiteId;
        std::string kind;
        SourceLocation location;
        std::string calleeExpression;
        std::string throughIdentifier;
    };

    struct CollapsedEdge
    {
        std::string caller;
        std::string callee;
        std::string kind;

        bool operator<(const CollapsedEdge &other) const
        {
            if (caller != other.caller)
            {
                return caller < other.caller;
            }
            if (callee != other.callee)
            {
                return callee < other.callee;
            }
            return kind < other.kind;
        }
    };

    struct MemoryTransferOp
    {
        std::vector<std::pair<std::string, std::string>> copyPairs;
        std::vector<std::string> clearDestinations;
    };

    using PointsToMap = std::unordered_map<std::string, std::set<std::string>>;

    /**
     * @brief Parse a plain signed integer literal.
     */
    bool isIntegerLiteral(const std::string &text, long long &value)
    {
        if (text.empty())
        {
            return false;
        }

        std::size_t index = 0;
        if (text[0] == '+' || text[0] == '-')
        {
            index = 1;
        }

        if (index >= text.size())
        {
            return false;
        }

        for (; index < text.size(); ++index)
        {
            if (std::isdigit(static_cast<unsigned char>(text[index])) == 0)
            {
                return false;
            }
        }

        try
        {
            value = std::stoll(text);
        }
        catch (...)
        {
            return false;
        }

        return true;
    }

    /**
     * @brief Check whether a binding token encodes a scalar integer value.
     */
    bool isIntegerBinding(const std::string &value)
    {
        return value.rfind("#int:", 0) == 0;
    }

    /**
     * @brief Encode scalar integer value into binding-map token format.
     */
    std::string makeIntegerBinding(long long value)
    {
        return "#int:" + std::to_string(value);
    }

    /**
     * @brief Decode scalar integer binding token.
     */
    std::optional<long long> parseIntegerBinding(const std::string &value)
    {
        if (!isIntegerBinding(value))
        {
            return std::nullopt;
        }

        try
        {
            return std::stoll(value.substr(5U));
        }
        catch (...)
        {
            return std::nullopt;
        }
    }

    /**
     * @brief Trim leading/trailing whitespace.
     */
    std::string trimLine(const std::string &text)
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
     * @brief Parse one serialized block from analysis JSON.
     */
    std::optional<FunctionFacts::BlockFact> parseBlockFact(const llvm::json::Object &blockObject, StringInterner &callSiteInterner)
    {
        FunctionFacts::BlockFact block;

        const std::optional<std::int64_t> id = blockObject.getInteger("id");
        if (!id.has_value() || *id < 0)
        {
            return std::nullopt;
        }
        block.id = static_cast<std::uint32_t>(*id);

        if (const llvm::json::Array *lines = blockObject.getArray("lines"))
        {
            for (const llvm::json::Value &lineValue : *lines)
            {
                if (const std::optional<llvm::StringRef> line = lineValue.getAsString())
                {
                    block.lines.push_back(line->str());
                }
            }
        }

        if (const llvm::json::Array *lineCallSiteIds = blockObject.getArray("lineCallSiteIds"))
        {
            for (const llvm::json::Value &entryValue : *lineCallSiteIds)
            {
                std::vector<CallSiteId> entryIds;
                if (const llvm::json::Array *entryArray = entryValue.getAsArray())
                {
                    for (const llvm::json::Value &idValue : *entryArray)
                    {
                        if (const std::optional<llvm::StringRef> id = idValue.getAsString())
                        {
                            entryIds.push_back(callSiteInterner.intern(id->str()));
                        }
                    }
                }
                block.lineCallSiteIds.push_back(std::move(entryIds));
            }
        }

        if (block.lineCallSiteIds.size() < block.lines.size())
        {
            block.lineCallSiteIds.resize(block.lines.size());
        }

        if (const llvm::json::Array *successors = blockObject.getArray("successors"))
        {
            for (const llvm::json::Value &successorValue : *successors)
            {
                if (const std::optional<std::int64_t> successor = successorValue.getAsInteger())
                {
                    if (*successor >= 0)
                    {
                        block.successors.push_back(static_cast<std::uint32_t>(*successor));
                    }
                }
            }
        }

        return block;
    }

    /**
     * @brief Extract unique identifier-like tokens in appearance order.
     */
    std::vector<std::string> extractIdentifiers(const std::string &text)
    {
        std::vector<std::string> identifiers;
        std::set<std::string> seen;

        std::size_t index = 0;
        while (index < text.size())
        {
            const unsigned char ch = static_cast<unsigned char>(text[index]);
            const bool start = std::isalpha(ch) != 0 || text[index] == '_';
            if (!start)
            {
                ++index;
                continue;
            }

            std::size_t end = index + 1U;
            while (end < text.size())
            {
                const unsigned char next = static_cast<unsigned char>(text[end]);
                if (std::isalnum(next) == 0 && text[end] != '_')
                {
                    break;
                }
                ++end;
            }

            const std::string identifier = text.substr(index, end - index);
            if (seen.insert(identifier).second)
            {
                identifiers.push_back(identifier);
            }
            index = end;
        }

        return identifiers;
    }

    /**
     * @brief Derive a canonical slot name from an expression.
     */
    std::string canonicalSlot(const std::string &expression)
    {
        std::string normalized = trimLine(expression);
        if (normalized.empty())
        {
            return "";
        }

        while (!normalized.empty() && (normalized.front() == '&' || normalized.front() == '*'))
        {
            normalized.erase(normalized.begin());
            normalized = trimLine(normalized);
        }

        for (std::size_t pos = normalized.find("->"); pos != std::string::npos; pos = normalized.find("->", pos + 1U))
        {
            normalized.replace(pos, 2U, ".");
        }

        std::string stripped;
        stripped.reserve(normalized.size());
        int bracketDepth = 0;
        for (char ch : normalized)
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
                stripped.push_back(ch);
            }
        }

        normalized = trimLine(stripped);
        if (normalized.empty())
        {
            return "";
        }

        if (normalized.find('.') != std::string::npos)
        {
            std::string compact;
            compact.reserve(normalized.size());
            for (char ch : normalized)
            {
                if (std::isspace(static_cast<unsigned char>(ch)) == 0)
                {
                    compact.push_back(ch);
                }
            }

            compact.erase(std::remove(compact.begin(), compact.end(), '('), compact.end());
            compact.erase(std::remove(compact.begin(), compact.end(), ')'), compact.end());
            while (!compact.empty() && (compact.front() == '&' || compact.front() == '*'))
            {
                compact.erase(compact.begin());
            }

            return compact;
        }

        if (normalized.find('(') != std::string::npos)
        {
            const std::vector<std::string> identifiers = extractIdentifiers(normalized);
            if (identifiers.empty())
            {
                return "";
            }
            return identifiers.back();
        }

        const std::vector<std::string> identifiers = extractIdentifiers(normalized);
        if (identifiers.empty())
        {
            return "";
        }
        return identifiers.back();
    }

    /**
     * @brief Extract memory slot preserving field and array selectors.
     */
    std::string canonicalMemorySlot(const std::string &expression)
    {
        std::string normalized = trimLine(expression);
        if (normalized.empty())
        {
            return "";
        }

        while (!normalized.empty() && (normalized.front() == '&' || normalized.front() == '*'))
        {
            normalized.erase(normalized.begin());
            normalized = trimLine(normalized);
        }

        for (std::size_t pos = normalized.find("->"); pos != std::string::npos; pos = normalized.find("->", pos + 1U))
        {
            normalized.replace(pos, 2U, ".");
        }

        std::string compact;
        compact.reserve(normalized.size());
        for (char ch : normalized)
        {
            if (std::isspace(static_cast<unsigned char>(ch)) == 0)
            {
                compact.push_back(ch);
            }
        }

        normalized.swap(compact);
        if (normalized.empty())
        {
            return "";
        }

        std::size_t index = 0;
        if (!(std::isalpha(static_cast<unsigned char>(normalized[index])) != 0 || normalized[index] == '_'))
        {
            return "";
        }

        std::string slot;
        while (index < normalized.size())
        {
            const unsigned char ch = static_cast<unsigned char>(normalized[index]);
            if (std::isalnum(ch) == 0 && normalized[index] != '_')
            {
                break;
            }
            slot.push_back(normalized[index]);
            ++index;
        }

        while (index < normalized.size())
        {
            if (normalized[index] == '.')
            {
                ++index;
                const std::size_t memberStart = index;
                while (index < normalized.size())
                {
                    const unsigned char ch = static_cast<unsigned char>(normalized[index]);
                    if (std::isalnum(ch) == 0 && normalized[index] != '_')
                    {
                        break;
                    }
                    ++index;
                }

                if (memberStart == index)
                {
                    break;
                }

                slot.push_back('.');
                slot.append(normalized.substr(memberStart, index - memberStart));
                continue;
            }

            if (normalized[index] == '[')
            {
                std::size_t end = index + 1U;
                int depth = 1;
                while (end < normalized.size() && depth > 0)
                {
                    if (normalized[end] == '[')
                    {
                        ++depth;
                    }
                    else if (normalized[end] == ']')
                    {
                        --depth;
                    }
                    ++end;
                }

                if (depth != 0)
                {
                    break;
                }

                const std::size_t contentBegin = index + 1U;
                const std::size_t contentLength = (end - 1U) - contentBegin;
                std::string indexToken = trimLine(normalized.substr(contentBegin, contentLength));
                bool numericIndex = !indexToken.empty();
                if (numericIndex)
                {
                    for (char tokenCh : indexToken)
                    {
                        if (std::isdigit(static_cast<unsigned char>(tokenCh)) == 0)
                        {
                            numericIndex = false;
                            break;
                        }
                    }
                }

                slot.push_back('[');
                slot.append(numericIndex ? indexToken : "*");
                slot.push_back(']');
                index = end;
                continue;
            }

            break;
        }

        return slot;
    }

    std::string memorySlotRoot(const std::string &slot)
    {
        std::string key = trimLine(slot);
        const std::size_t scopePos = key.rfind("::");
        if (scopePos != std::string::npos)
        {
            key = key.substr(scopePos + 2U);
        }

        const std::size_t dotPos = key.find('.');
        const std::size_t bracketPos = key.find('[');
        std::size_t end = std::string::npos;
        if (dotPos != std::string::npos)
        {
            end = dotPos;
        }
        if (bracketPos != std::string::npos)
        {
            end = (end == std::string::npos) ? bracketPos : std::min(end, bracketPos);
        }

        if (end != std::string::npos)
        {
            key = key.substr(0, end);
        }

        return trimLine(key);
    }

    std::vector<std::string> expandMemorySlotAliases(const std::string &slot)
    {
        std::vector<std::string> aliases;
        std::unordered_set<std::string> seen;

        const std::string trimmed = trimLine(slot);
        if (trimmed.empty())
        {
            return aliases;
        }

        if (seen.insert(trimmed).second)
        {
            aliases.push_back(trimmed);
        }

        std::size_t open = trimmed.find('[');
        if (open != std::string::npos)
        {
            std::size_t close = trimmed.find(']', open + 1U);
            if (close != std::string::npos)
            {
                const std::string token = trimmed.substr(open + 1U, close - open - 1U);
                if (token != "*")
                {
                    std::string wildcard = trimmed;
                    wildcard.replace(open + 1U, close - open - 1U, "*");
                    if (seen.insert(wildcard).second)
                    {
                        aliases.push_back(wildcard);
                    }
                }
            }
        }

        const std::string root = memorySlotRoot(trimmed);
        if (!root.empty() && seen.insert(root).second)
        {
            aliases.push_back(root);
        }

        return aliases;
    }

    std::vector<std::string> collectMemorySlotPrefixes(const std::string &slot)
    {
        std::vector<std::string> prefixes;
        std::unordered_set<std::string> seen;

        const std::string trimmed = trimLine(slot);
        if (trimmed.empty())
        {
            return prefixes;
        }

        std::function<void(std::size_t)> addPrefix = [&](std::size_t length)
        {
            if (length == 0U || length > trimmed.size())
            {
                return;
            }

            const std::string prefix = trimmed.substr(0U, length);
            if (!prefix.empty() && seen.insert(prefix).second)
            {
                prefixes.push_back(prefix);
            }
        };

        for (std::size_t index = 0; index < trimmed.size(); ++index)
        {
            if (trimmed[index] == '.')
            {
                addPrefix(index);
                continue;
            }

            if (trimmed[index] != '[')
            {
                continue;
            }

            addPrefix(index);

            std::size_t end = index + 1U;
            int depth = 1;
            while (end < trimmed.size() && depth > 0)
            {
                if (trimmed[end] == '[')
                {
                    ++depth;
                }
                else if (trimmed[end] == ']')
                {
                    --depth;
                }
                ++end;
            }

            if (depth != 0)
            {
                break;
            }

            addPrefix(end);
            index = end - 1U;
        }

        addPrefix(trimmed.size());
        return prefixes;
    }

    std::string memorySlotFromExpression(const std::string &expression)
    {
        const std::string memorySlot = canonicalMemorySlot(expression);
        if (!memorySlot.empty())
        {
            return memorySlot;
        }
        return canonicalSlot(expression);
    }

    /**
     * @brief Resolve the destination slot(s) written by an assignment LHS.
     */
    std::set<std::string> resolveAssignmentDestinationSlots(
        const std::string &lhsExpression,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &pointsTo)
    {
        std::set<std::string> destinationSlots;
        std::string trimmedLhs = trimLine(lhsExpression);
        if (trimmedLhs.empty())
        {
            return destinationSlots;
        }

        std::size_t derefDepth = 0U;
        while (derefDepth < trimmedLhs.size() && trimmedLhs[derefDepth] == '*')
        {
            ++derefDepth;
        }

        const std::string baseSlot = canonicalSlot(lhsExpression);
        if (baseSlot.empty())
        {
            return destinationSlots;
        }

        std::set<std::string> currentSlots{baseSlot};
        if (derefDepth == 0U)
        {
            destinationSlots.insert(baseSlot);
            return destinationSlots;
        }

        for (std::size_t depth = 0; depth < derefDepth; ++depth)
        {
            std::set<std::string> nextSlots;
            for (const std::string &slot : currentSlots)
            {
                const std::unordered_map<std::string, std::set<std::string>>::const_iterator it = pointsTo.find(slot);
                if (it == pointsTo.end())
                {
                    continue;
                }

                nextSlots.insert(it->second.begin(), it->second.end());
            }

            if (nextSlots.empty())
            {
                break;
            }

            currentSlots = std::move(nextSlots);
        }

        for (const std::string &slot : currentSlots)
        {
            if (!slot.empty() && !isIntegerBinding(slot) && knownFunctions.find(slot) == knownFunctions.end())
            {
                destinationSlots.insert(slot);
            }
        }

        if (destinationSlots.empty())
        {
            destinationSlots.insert(baseSlot);
        }

        return destinationSlots;
    }

    /**
     * @brief Resolve seed tokens through transitive points-to edges.
     */
    std::set<std::string> resolveTransitiveTargets(
        const std::set<std::string> &seedTargets,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &pointsTo,
        bool preserveUnknownTargets)
    {
        std::set<std::string> resolvedTargets;
        std::deque<std::string> pending(seedTargets.begin(), seedTargets.end());
        std::unordered_set<std::string> seen;

        while (!pending.empty())
        {
            const std::string value = pending.front();
            pending.pop_front();

            if (value.empty() || !seen.insert(value).second)
            {
                continue;
            }

            if (knownFunctions.find(value) != knownFunctions.end())
            {
                resolvedTargets.insert(value);
                continue;
            }

            const std::unordered_map<std::string, std::set<std::string>>::const_iterator it = pointsTo.find(value);
            if (it == pointsTo.end() || it->second.empty())
            {
                if (preserveUnknownTargets)
                {
                    resolvedTargets.insert(value);
                }
                continue;
            }

            for (const std::string &next : it->second)
            {
                if (knownFunctions.find(next) != knownFunctions.end())
                {
                    resolvedTargets.insert(next);
                    continue;
                }

                if (!next.empty())
                {
                    pending.push_back(next);
                }
            }
        }

        return resolvedTargets;
    }

    /**
     * @brief Extract callee identifier from a simple call expression text.
     */
    std::string extractCallCalleeIdentifier(const std::string &expression)
    {
        const std::string trimmed = trimLine(expression);
        const std::size_t openParen = trimmed.find('(');
        if (openParen == std::string::npos)
        {
            return "";
        }

        const std::string calleeExpr = trimLine(trimmed.substr(0, openParen));
        if (calleeExpr.empty())
        {
            return "";
        }

        return canonicalSlot(calleeExpr);
    }

    /**
     * @brief Resolve possible direct/indirect callee function targets for a call expression text.
     */
    std::set<std::string> resolveCallCalleeTargets(
        const std::string &expression,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &bindings)
    {
        std::set<std::string> targets;

        const std::string trimmed = trimLine(expression);
        const std::size_t openParen = trimmed.find('(');
        if (openParen == std::string::npos)
        {
            return targets;
        }

        const std::string calleeExpr = trimLine(trimmed.substr(0, openParen));
        if (calleeExpr.empty())
        {
            return targets;
        }

        const std::string slot = canonicalSlot(calleeExpr);
        if (!slot.empty())
        {
            const std::unordered_map<std::string, std::set<std::string>>::const_iterator it = bindings.find(slot);
            if (it != bindings.end())
            {
                targets.insert(it->second.begin(), it->second.end());
            }
        }

        for (const std::string &identifier : extractIdentifiers(calleeExpr))
        {
            const std::unordered_map<std::string, std::set<std::string>>::const_iterator it = bindings.find(identifier);
            if (it != bindings.end())
            {
                targets.insert(it->second.begin(), it->second.end());
            }
            if (knownFunctions.find(identifier) != knownFunctions.end())
            {
                targets.insert(identifier);
            }
        }

        return targets;
    }

    /**
     * @brief Parse optional source location metadata object.
     */
    SourceLocation parseLocation(const llvm::json::Object *locationObject)
    {
        SourceLocation location;
        if (locationObject == nullptr)
        {
            return location;
        }

        if (const llvm::json::Value *file = locationObject->get("file"))
        {
            if (const std::optional<llvm::StringRef> value = file->getAsString())
            {
                location.file = value->str();
            }
        }
        if (const std::optional<std::int64_t> line = locationObject->getInteger("line"))
        {
            if (*line > 0)
            {
                location.line = static_cast<std::uint32_t>(*line);
            }
        }
        if (const std::optional<std::int64_t> column = locationObject->getInteger("column"))
        {
            if (*column > 0)
            {
                location.column = static_cast<std::uint32_t>(*column);
            }
        }

        return location;
    }

    bool isBlacklistedFunction(
        const std::string &functionName,
        const std::set<std::string> &blacklistedFunctions)
    {
        return blacklistedFunctions.find(functionName) != blacklistedFunctions.end();
    }

    bool isDebugLoggingEnabled()
    {
        return gDebugLoggingEnabled;
    }

    void logFunctionProcessed(const std::string &functionName, const PointsToMap &seededPointsTo)
    {
        if (!isDebugLoggingEnabled())
        {
            return;
        }

        llvm::errs() << "[callgraph] processing function=" << functionName
                     << " seed-bindings=" << seededPointsTo.size() << "\n";
    }

    void logPagFunctionPhase(
        const std::string &phase,
        std::size_t index,
        std::size_t total,
        const FunctionFacts &function)
    {
        if (!isDebugLoggingEnabled())
        {
            return;
        }

        llvm::errs() << "[callgraph] phase=" << phase
                     << " function=" << function.name
                     << " index=" << (index + 1U) << "/" << total
                     << " assignments=" << function.pointerAssignments.size()
                     << " calls=" << function.callSites.size()
                     << " blocks=" << function.blocks.size()
                     << "\n";
    }

    void logPagFixedPointSummary(
        std::size_t iterations,
        std::size_t pointsToNodes,
        std::size_t sparseEdges,
        std::size_t relevantNodeCount)
    {
        if (!isDebugLoggingEnabled())
        {
            return;
        }

        llvm::errs() << "[callgraph] phase=fixed-point"
                     << " iterations=" << iterations
                     << " points-to-nodes=" << pointsToNodes
                     << " sparse-edges=" << sparseEdges
                     << " relevant-nodes=" << relevantNodeCount
                     << "\n";
    }

    void logUnresolvedCall(const CallEdge &edge)
    {
        llvm::errs() << "[callgraph] unresolved indirect call"
                     << " caller=" << edge.caller
                     << " calleeExpr=" << edge.calleeExpression
                     << " through=" << edge.throughIdentifier
                     << " at " << edge.location.file << ":" << edge.location.line << ":" << edge.location.column
                     << "\n";
    }

    /**
     * @brief Parse all function facts from cfg-analysis JSON.
     */
    bool parseFunctions(
        const llvm::json::Object &root,
        std::vector<FunctionFacts> &functions,
        std::set<std::string> &knownFunctionNames,
        const std::set<std::string> &blacklistedFunctions,
        StringInterner &callSiteInterner,
        std::string &errorMessage)
    {
        const llvm::json::Array *functionArray = root.getArray("functions");
        if (functionArray == nullptr)
        {
            errorMessage = "analysis JSON missing functions array";
            return false;
        }

        for (const llvm::json::Value &functionValue : *functionArray)
        {
            const llvm::json::Object *functionObject = functionValue.getAsObject();
            if (functionObject == nullptr)
            {
                continue;
            }

            const std::optional<llvm::StringRef> name = functionObject->getString("name");
            if (!name.has_value() || name->empty())
            {
                continue;
            }

            FunctionFacts facts;
            facts.name = name->str();
            if (isBlacklistedFunction(facts.name, blacklistedFunctions))
            {
                continue;
            }
            knownFunctionNames.insert(facts.name);

            if (const std::optional<std::int64_t> entryBlockId = functionObject->getInteger("entryBlockId"))
            {
                if (*entryBlockId >= 0)
                {
                    facts.entryBlockId = static_cast<std::uint32_t>(*entryBlockId);
                }
            }

            const llvm::json::Object *attributes = functionObject->getObject("attributes");
            if (attributes == nullptr)
            {
                if (const llvm::json::Array *blocks = functionObject->getArray("blocks"))
                {
                    for (const llvm::json::Value &blockValue : *blocks)
                    {
                        const llvm::json::Object *blockObject = blockValue.getAsObject();
                        if (blockObject == nullptr)
                        {
                            continue;
                        }

                        const std::optional<FunctionFacts::BlockFact> block = parseBlockFact(*blockObject, callSiteInterner);
                        if (block.has_value())
                        {
                            facts.blocks.push_back(std::move(*block));
                        }
                    }
                }

                functions.push_back(std::move(facts));
                continue;
            }

            if (const std::optional<bool> returnsPointerLike = attributes->getBoolean("returnsPointerLike"))
            {
                facts.hasReturnPointerMetadata = true;
                facts.returnsPointerLike = *returnsPointerLike;
            }

            if (const llvm::json::Array *addressTaken = attributes->getArray("addressTakenFunctions"))
            {
                for (const llvm::json::Value &value : *addressTaken)
                {
                    if (const std::optional<llvm::StringRef> nameValue = value.getAsString())
                    {
                        facts.addressTakenFunctions.insert(nameValue->str());
                    }
                }
            }

            if (const llvm::json::Array *calls = attributes->getArray("callSites"))
            {
                for (const llvm::json::Value &callValue : *calls)
                {
                    const llvm::json::Object *callObject = callValue.getAsObject();
                    if (callObject == nullptr)
                    {
                        continue;
                    }

                    CallSite callSite;
                    if (const std::optional<llvm::StringRef> value = callObject->getString("callSiteId"))
                    {
                        callSite.callSiteId = callSiteInterner.intern(value->str());
                    }
                    if (const std::optional<llvm::StringRef> value = callObject->getString("calleeExpression"))
                    {
                        callSite.calleeExpression = value->str();
                    }
                    if (const std::optional<llvm::StringRef> value = callObject->getString("directCallee"))
                    {
                        callSite.directCallee = value->str();
                    }
                    if (const std::optional<llvm::StringRef> value = callObject->getString("throughIdentifier"))
                    {
                        callSite.throughIdentifier = value->str();
                    }
                    if (const llvm::json::Array *arguments = callObject->getArray("argumentExpressions"))
                    {
                        for (const llvm::json::Value &argumentValue : *arguments)
                        {
                            if (const std::optional<llvm::StringRef> argument = argumentValue.getAsString())
                            {
                                callSite.argumentExpressions.push_back(argument->str());
                            }
                        }
                    }
                    if (const std::optional<bool> value = callObject->getBoolean("isIndirect"))
                    {
                        callSite.isIndirect = *value;
                    }
                    callSite.location = parseLocation(callObject->getObject("location"));

                    facts.callSites.push_back(std::move(callSite));
                }
            }

            if (const llvm::json::Array *parameterNames = attributes->getArray("parameterNames"))
            {
                for (const llvm::json::Value &value : *parameterNames)
                {
                    if (const std::optional<llvm::StringRef> name = value.getAsString())
                    {
                        if (!name->empty())
                        {
                            facts.parameterNames.push_back(name->str());
                        }
                    }
                }
            }

            if (const llvm::json::Array *assignments = attributes->getArray("pointerAssignments"))
            {
                for (const llvm::json::Value &assignmentValue : *assignments)
                {
                    const llvm::json::Object *assignmentObject = assignmentValue.getAsObject();
                    if (assignmentObject == nullptr)
                    {
                        continue;
                    }

                    PointerAssignment assignment;
                    if (const std::optional<llvm::StringRef> value = assignmentObject->getString("lhsExpression"))
                    {
                        assignment.lhsExpression = value->str();
                    }
                    if (const std::optional<llvm::StringRef> value = assignmentObject->getString("rhsExpression"))
                    {
                        assignment.rhsExpression = value->str();
                    }
                    if (const std::optional<llvm::StringRef> value = assignmentObject->getString("assignedFunction"))
                    {
                        assignment.assignedFunction = value->str();
                    }
                    if (const std::optional<bool> value = assignmentObject->getBoolean("rhsTakesFunctionAddress"))
                    {
                        assignment.rhsTakesFunctionAddress = *value;
                    }
                    if (const std::optional<bool> value = assignmentObject->getBoolean("lhsIsGlobal"))
                    {
                        assignment.lhsIsGlobal = *value;
                    }
                    assignment.location = parseLocation(assignmentObject->getObject("location"));

                    facts.pointerAssignments.push_back(std::move(assignment));
                }
            }

            if (const llvm::json::Array *mappings = attributes->getArray("structMemberMappings"))
            {
                for (const llvm::json::Value &mappingValue : *mappings)
                {
                    const llvm::json::Object *mappingObject = mappingValue.getAsObject();
                    if (mappingObject == nullptr)
                    {
                        continue;
                    }

                    StructMemberMapping mapping;
                    if (const std::optional<llvm::StringRef> value = mappingObject->getString("structVariable"))
                    {
                        mapping.structVariable = value->str();
                    }
                    if (const std::optional<llvm::StringRef> value = mappingObject->getString("memberName"))
                    {
                        mapping.memberName = value->str();
                    }
                    if (const std::optional<llvm::StringRef> value = mappingObject->getString("functionName"))
                    {
                        mapping.functionName = value->str();
                    }
                    mapping.location = parseLocation(mappingObject->getObject("location"));

                    facts.structMemberMappings.push_back(std::move(mapping));
                }
            }

            if (const llvm::json::Array *blocks = functionObject->getArray("blocks"))
            {
                for (const llvm::json::Value &blockValue : *blocks)
                {
                    const llvm::json::Object *blockObject = blockValue.getAsObject();
                    if (blockObject == nullptr)
                    {
                        continue;
                    }

                    const std::optional<FunctionFacts::BlockFact> block = parseBlockFact(*blockObject, callSiteInterner);
                    if (block.has_value())
                    {
                        facts.blocks.push_back(std::move(*block));
                    }
                }
            }

            functions.push_back(std::move(facts));
        }

        return true;
    }

    /**
     * @brief Resolve assignment RHS targets under current points-to map.
     */
    std::set<std::string> resolveAssignmentTargets(
        const PointerAssignment &assignment,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &pointsTo)
    {
        std::function<bool(const std::string &)> startsWithAddressOf = [](const std::string &expression)
        {
            const std::string trimmed = trimLine(expression);
            return !trimmed.empty() && trimmed.front() == '&';
        };

        std::function<std::set<std::string>(const std::string &)> collectFunctionDesignators = [&](const std::string &expression)
        {
            std::set<std::string> designators;
            for (const std::string &identifier : extractIdentifiers(expression))
            {
                if (knownFunctions.find(identifier) == knownFunctions.end())
                {
                    continue;
                }

                std::size_t searchPos = 0;
                while (true)
                {
                    searchPos = expression.find(identifier, searchPos);
                    if (searchPos == std::string::npos)
                    {
                        break;
                    }

                    const bool hasLeft = searchPos > 0U;
                    const bool hasRight = searchPos + identifier.size() < expression.size();
                    const bool leftIsIdent =
                        hasLeft &&
                        (std::isalnum(static_cast<unsigned char>(expression[searchPos - 1U])) != 0 || expression[searchPos - 1U] == '_');
                    const bool rightIsIdent =
                        hasRight &&
                        (std::isalnum(static_cast<unsigned char>(expression[searchPos + identifier.size()])) != 0 ||
                         expression[searchPos + identifier.size()] == '_');
                    if (leftIsIdent || rightIsIdent)
                    {
                        searchPos += identifier.size();
                        continue;
                    }

                    std::size_t after = searchPos + identifier.size();
                    while (after < expression.size() && std::isspace(static_cast<unsigned char>(expression[after])) != 0)
                    {
                        ++after;
                    }

                    // Treat as function-pointer designator only when it is not a direct call token.
                    if (after >= expression.size() || expression[after] != '(')
                    {
                        designators.insert(identifier);
                        break;
                    }

                    searchPos += identifier.size();
                }
            }

            return designators;
        };

        std::set<std::string> seeds;

        if (!assignment.assignedFunction.empty())
        {
            if (knownFunctions.find(assignment.assignedFunction) != knownFunctions.end())
            {
                seeds.insert(assignment.assignedFunction);
            }
            return resolveTransitiveTargets(seeds, knownFunctions, pointsTo, false);
        }

        if (assignment.rhsTakesFunctionAddress)
        {
            for (const std::string &identifier : extractIdentifiers(assignment.rhsExpression))
            {
                if (knownFunctions.find(identifier) != knownFunctions.end())
                {
                    seeds.insert(identifier);
                }
            }
            return resolveTransitiveTargets(seeds, knownFunctions, pointsTo, false);
        }

        if (startsWithAddressOf(assignment.rhsExpression))
        {
            const std::vector<std::string> identifiers = extractIdentifiers(assignment.rhsExpression);
            for (const std::string &identifier : identifiers)
            {
                if (knownFunctions.find(identifier) == knownFunctions.end())
                {
                    // Preserve pointer-level aliasing for address-of assignments.
                    // Example: "loc2 = &loc" must bind loc2 -> loc (not transitively to loc's pointee).
                    return std::set<std::string>{identifier};
                }
            }
        }

        const std::string rhsSlot = canonicalSlot(assignment.rhsExpression);
        if (!rhsSlot.empty())
        {
            if (knownFunctions.find(rhsSlot) == knownFunctions.end() && !isIntegerBinding(rhsSlot))
            {
                seeds.insert(rhsSlot);
            }
        }

        for (const std::string &identifier : extractIdentifiers(assignment.rhsExpression))
        {
            const std::unordered_map<std::string, std::set<std::string>>::const_iterator it = pointsTo.find(identifier);
            if (it != pointsTo.end())
            {
                seeds.insert(it->second.begin(), it->second.end());
                continue;
            }

            if (knownFunctions.find(identifier) == knownFunctions.end() && !isIntegerBinding(identifier))
            {
                seeds.insert(identifier);
            }
        }

        const std::set<std::string> functionDesignators = collectFunctionDesignators(assignment.rhsExpression);
        seeds.insert(functionDesignators.begin(), functionDesignators.end());

        return resolveTransitiveTargets(seeds, knownFunctions, pointsTo, true);
    }

    std::set<std::string> resolveExpressionTargets(
        const std::string &expression,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &pointsTo);

    std::set<std::string> resolveMixedExpressionValues(
        const std::string &expression,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &bindings,
        bool includeSlotIdentity = true);

    PointsToMap buildSeedBindings(
        const CallSite &callSite,
        const std::vector<std::string> &parameterSlots,
        const std::set<std::string> &pointerSlots,
        const PointsToMap &callerPointsTo,
        const std::set<std::string> &knownFunctions);

    std::vector<std::string> parseCallArgumentExpressions(const std::string &rawExpression);

    std::optional<std::pair<std::string, std::string>> parseMemcpyArgsFromLine(const std::string &rawLine);

    std::optional<MemoryTransferOp> parseMemoryTransferOpFromLine(const std::string &rawLine);

    /**
     * @brief Resolve callee return tokens through the current caller bindings and call arguments.
     */
    std::set<std::string> resolveCallReturnTargets(
        const std::string &callExpression,
        const std::string &calleeName,
        const PointsToMap &callerBindings,
        const std::unordered_map<std::string, std::set<std::string>> &programWideBindings,
        const std::vector<StructMemberMapping> &callerStructMappings,
        const std::vector<std::string> &calleeParameters,
        const std::set<std::string> &calleePointerSlots,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &returnTargetsByFunction)
    {
        std::set<std::string> resolvedTargets;
        const std::vector<std::string> argumentExpressions = parseCallArgumentExpressions(callExpression);

        CallSite syntheticCallSite;
        syntheticCallSite.argumentExpressions = argumentExpressions;
        PointsToMap callSeeds;
        if (!calleeParameters.empty())
        {
            callSeeds = buildSeedBindings(syntheticCallSite, calleeParameters, calleePointerSlots, callerBindings, knownFunctions);
        }

        std::unordered_map<std::string, std::set<std::string>> parameterArgumentBases;
        const std::size_t argumentLimit = std::min(calleeParameters.size(), argumentExpressions.size());
        for (std::size_t index = 0; index < argumentLimit; ++index)
        {
            const std::string &parameter = calleeParameters[index];
            if (parameter.empty())
            {
                continue;
            }

            std::set<std::string> &bases = parameterArgumentBases[parameter];
            const std::string argumentSlot = canonicalSlot(argumentExpressions[index]);
            if (!argumentSlot.empty())
            {
                bases.insert(argumentSlot);
                const PointsToMap::const_iterator argBindingIt = callerBindings.find(argumentSlot);
                if (argBindingIt != callerBindings.end())
                {
                    bases.insert(argBindingIt->second.begin(), argBindingIt->second.end());
                }
            }

            const std::set<std::string> resolvedArgumentValues =
                resolveMixedExpressionValues(argumentExpressions[index], knownFunctions, callerBindings);
            for (const std::string &value : resolvedArgumentValues)
            {
                if (value.empty() || isIntegerBinding(value) || knownFunctions.find(value) != knownFunctions.end())
                {
                    continue;
                }

                bases.insert(value);
            }
        }

        std::function<PointsToMap(const PointsToMap &, const PointsToMap &)> mergeBindings = [](const PointsToMap &lhs, const PointsToMap &rhs)
        {
            PointsToMap merged = lhs;
            for (const std::pair<const std::string, std::set<std::string>> &entry : rhs)
            {
                std::set<std::string> &values = merged[entry.first];
                values.insert(entry.second.begin(), entry.second.end());
            }
            return merged;
        };

        const PointsToMap combinedBindings = mergeBindings(mergeBindings(callerBindings, callSeeds), programWideBindings);

        std::function<std::string(std::string)> normalizeStructAccess = [](std::string expression)
        {
            expression = trimLine(expression);
            while (!expression.empty() && (expression.front() == '&' || expression.front() == '*'))
            {
                expression.erase(expression.begin());
                expression = trimLine(expression);
            }

            for (std::size_t pos = expression.find("->"); pos != std::string::npos; pos = expression.find("->", pos + 1U))
            {
                expression.replace(pos, 2U, ".");
            }

            std::string stripped;
            stripped.reserve(expression.size());
            int bracketDepth = 0;
            for (char ch : expression)
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
                if (std::isspace(static_cast<unsigned char>(ch)) == 0 && bracketDepth == 0)
                {
                    stripped.push_back(ch);
                }
            }

            return trimLine(stripped);
        };

        std::function<std::pair<std::string, std::string>(const std::string &)> splitStructAccess = [&](const std::string &expression) -> std::pair<std::string, std::string>
        {
            const std::string normalized = normalizeStructAccess(expression);
            const std::size_t dotIndex = normalized.find('.');
            if (dotIndex == std::string::npos || dotIndex == 0U)
            {
                return {"", ""};
            }

            return {normalized.substr(0, dotIndex), normalized.substr(dotIndex + 1U)};
        };

        std::function<bool(const std::string &, const std::string &)> structMemberMatches = [](const std::string &returnedMember, const std::string &mappingMember)
        {
            if (returnedMember.empty() || mappingMember.empty())
            {
                return false;
            }

            if (returnedMember == mappingMember)
            {
                return true;
            }

            const std::size_t returnedLeafDot = returnedMember.rfind('.');
            const std::size_t mappingLeafDot = mappingMember.rfind('.');
            const std::string returnedLeaf = returnedLeafDot == std::string::npos ? returnedMember : returnedMember.substr(returnedLeafDot + 1U);
            const std::string mappingLeaf = mappingLeafDot == std::string::npos ? mappingMember : mappingMember.substr(mappingLeafDot + 1U);
            return returnedLeaf == mappingLeaf;
        };

        const std::unordered_map<std::string, std::set<std::string>>::const_iterator returnIt = returnTargetsByFunction.find(calleeName);
        if (returnIt == returnTargetsByFunction.end())
        {
            return resolvedTargets;
        }

        for (const std::string &returned : returnIt->second)
        {
            if (knownFunctions.find(returned) != knownFunctions.end())
            {
                resolvedTargets.insert(returned);
                continue;
            }

            const PointsToMap::const_iterator seedIt = callSeeds.find(returned);
            if (seedIt != callSeeds.end())
            {
                resolvedTargets.insert(seedIt->second.begin(), seedIt->second.end());
                continue;
            }

            const PointsToMap::const_iterator bindingIt = callerBindings.find(returned);
            if (bindingIt != callerBindings.end())
            {
                resolvedTargets.insert(bindingIt->second.begin(), bindingIt->second.end());
                continue;
            }

            std::set<std::string> translatedSeeds{returned};
            for (const std::string &parameter : calleeParameters)
            {
                if (parameter.empty())
                {
                    continue;
                }

                const bool exactMatch = returned == parameter;
                const bool memberMatch =
                    returned.size() > parameter.size() &&
                    returned.rfind(parameter, 0U) == 0U &&
                    returned[parameter.size()] == '.';
                if (!exactMatch && !memberMatch)
                {
                    continue;
                }

                const std::string suffix = exactMatch ? "" : returned.substr(parameter.size());
                const PointsToMap::const_iterator translatedIt = callSeeds.find(parameter);
                if (translatedIt == callSeeds.end())
                {
                    const std::unordered_map<std::string, std::set<std::string>>::const_iterator argumentBasesIt =
                        parameterArgumentBases.find(parameter);
                    if (argumentBasesIt == parameterArgumentBases.end())
                    {
                        continue;
                    }

                    for (const std::string &base : argumentBasesIt->second)
                    {
                        if (suffix.empty())
                        {
                            translatedSeeds.insert(base);
                            continue;
                        }

                        if (knownFunctions.find(base) == knownFunctions.end())
                        {
                            translatedSeeds.insert(base + suffix);
                        }
                    }
                    continue;
                }

                for (const std::string &base : translatedIt->second)
                {
                    if (suffix.empty())
                    {
                        translatedSeeds.insert(base);
                        continue;
                    }

                    if (knownFunctions.find(base) == knownFunctions.end())
                    {
                        translatedSeeds.insert(base + suffix);
                    }
                }
            }

            const std::set<std::string> translatedTargets =
                resolveTransitiveTargets(translatedSeeds, knownFunctions, combinedBindings, true);
            if (!translatedTargets.empty())
            {
                resolvedTargets.insert(translatedTargets.begin(), translatedTargets.end());
                continue;
            }

            const std::pair<std::string, std::string> returnedAccess = splitStructAccess(returned);
            if (!returnedAccess.first.empty() && !returnedAccess.second.empty())
            {
                std::set<std::string> candidateStructBases;
                candidateStructBases.insert(returnedAccess.first);

                const PointsToMap::const_iterator candidateSeedIt = callSeeds.find(returnedAccess.first);
                if (candidateSeedIt != callSeeds.end())
                {
                    candidateStructBases.insert(candidateSeedIt->second.begin(), candidateSeedIt->second.end());
                }

                const std::unordered_map<std::string, std::set<std::string>>::const_iterator argumentBasesIt =
                    parameterArgumentBases.find(returnedAccess.first);
                if (argumentBasesIt != parameterArgumentBases.end())
                {
                    candidateStructBases.insert(argumentBasesIt->second.begin(), argumentBasesIt->second.end());
                }

                const PointsToMap::const_iterator candidateBindingIt = callerBindings.find(returnedAccess.first);
                if (candidateBindingIt != callerBindings.end())
                {
                    candidateStructBases.insert(candidateBindingIt->second.begin(), candidateBindingIt->second.end());
                }

                for (const std::string &parameter : calleeParameters)
                {
                    if (parameter.empty())
                    {
                        continue;
                    }

                    if (returnedAccess.first != parameter)
                    {
                        continue;
                    }

                    const PointsToMap::const_iterator parameterSeedIt = callSeeds.find(parameter);
                    if (parameterSeedIt != callSeeds.end())
                    {
                        candidateStructBases.insert(parameterSeedIt->second.begin(), parameterSeedIt->second.end());
                    }
                }

                for (const std::string &candidateBase : candidateStructBases)
                {
                    if (candidateBase.empty() || knownFunctions.find(candidateBase) != knownFunctions.end())
                    {
                        continue;
                    }

                    const std::set<std::string> aliases =
                        resolveTransitiveTargets(std::set<std::string>{candidateBase}, knownFunctions, combinedBindings, true);

                    std::set<std::string> allBases = aliases;
                    allBases.insert(candidateBase);

                    for (const std::string &base : allBases)
                    {
                        if (base.empty() || knownFunctions.find(base) != knownFunctions.end())
                        {
                            continue;
                        }

                        for (const StructMemberMapping &mapping : callerStructMappings)
                        {
                            if (mapping.structVariable != base)
                            {
                                continue;
                            }

                            if (!structMemberMatches(returnedAccess.second, mapping.memberName))
                            {
                                continue;
                            }

                            if (knownFunctions.find(mapping.functionName) != knownFunctions.end())
                            {
                                resolvedTargets.insert(mapping.functionName);
                            }
                        }
                    }
                }

                if (!resolvedTargets.empty())
                {
                    continue;
                }
            }

            resolvedTargets.insert(returned);
        }

        return resolvedTargets;
    }

    /**
     * @brief Collect conservative program-wide slot->function targets from assignments.
     */
    std::unordered_map<std::string, std::set<std::string>> collectProgramWidePointerTargets(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions)
    {
        std::unordered_map<std::string, std::set<std::string>> targetsBySlot;
        std::unordered_map<std::string, std::set<std::string>> sourceTargetsBySlot;
        std::set<std::string> globalSlots;

        std::size_t totalAssignments = 0U;
        for (const FunctionFacts &function : functions)
        {
            totalAssignments += function.pointerAssignments.size();
        }

        targetsBySlot.reserve(totalAssignments * 2U + 1U);
        sourceTargetsBySlot.reserve(totalAssignments * 2U + 1U);

        std::vector<const PointerAssignment *> allAssignments;
        std::vector<const PointerAssignment *> globalAssignments;
        allAssignments.reserve(totalAssignments);
        globalAssignments.reserve(totalAssignments);
        for (const FunctionFacts &function : functions)
        {
            for (const PointerAssignment &assignment : function.pointerAssignments)
            {
                const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
                if (!lhsSlot.empty())
                {
                    allAssignments.push_back(&assignment);
                }

                if (!assignment.lhsIsGlobal)
                {
                    continue;
                }

                if (lhsSlot.empty())
                {
                    continue;
                }

                globalSlots.insert(lhsSlot);
                globalAssignments.push_back(&assignment);
            }
        }

        std::function<void(const std::vector<const PointerAssignment *> &,
                           std::unordered_map<std::string, std::set<std::string>> &)>
            applyOrderedAssignments = [&](const std::vector<const PointerAssignment *> &assignments,
                                          std::unordered_map<std::string, std::set<std::string>> &slotTargetsBySlot)
        {
            std::unordered_map<std::string, std::set<std::string>> destinationCache;
            for (const PointerAssignment *assignmentPtr : assignments)
            {
                const PointerAssignment &assignment = *assignmentPtr;
                const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
                if (lhsSlot.empty())
                {
                    continue;
                }

                std::set<std::string> targets = resolveAssignmentTargets(assignment, knownFunctions, slotTargetsBySlot);

                const std::string rhsSlot = canonicalSlot(assignment.rhsExpression);
                if (!rhsSlot.empty())
                {
                    const std::unordered_map<std::string, std::set<std::string>>::const_iterator rhsIt =
                        slotTargetsBySlot.find(rhsSlot);
                    if (rhsIt != slotTargetsBySlot.end())
                    {
                        targets.insert(rhsIt->second.begin(), rhsIt->second.end());
                    }
                }

                if (targets.empty())
                {
                    continue;
                }

                std::unordered_map<std::string, std::set<std::string>>::const_iterator cachedDestinationsIt =
                    destinationCache.find(assignment.lhsExpression);
                if (cachedDestinationsIt == destinationCache.end())
                {
                    cachedDestinationsIt =
                        destinationCache.emplace(
                                            assignment.lhsExpression,
                                            resolveAssignmentDestinationSlots(assignment.lhsExpression, knownFunctions, slotTargetsBySlot))
                            .first;
                }

                bool bindingsChanged = false;
                const std::set<std::string> &destinationSlots = cachedDestinationsIt->second;
                for (const std::string &destinationSlot : destinationSlots)
                {
                    std::set<std::string> &existingTargets = slotTargetsBySlot[destinationSlot];
                    if (existingTargets != targets)
                    {
                        existingTargets = targets;
                        bindingsChanged = true;
                    }
                }

                if (bindingsChanged)
                {
                    destinationCache.clear();
                }
            }
        };

        applyOrderedAssignments(allAssignments, sourceTargetsBySlot);

        PointsToMap mergedGlobalBindings = sourceTargetsBySlot;
        for (const std::pair<const std::string, std::set<std::string>> &entry : targetsBySlot)
        {
            std::set<std::string> &values = mergedGlobalBindings[entry.first];
            values.insert(entry.second.begin(), entry.second.end());
        }

        std::unordered_map<std::string, std::set<std::string>> destinationCache;
        for (const PointerAssignment *assignmentPtr : globalAssignments)
        {
            const PointerAssignment &assignment = *assignmentPtr;
            const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
            if (lhsSlot.empty())
            {
                continue;
            }

            std::set<std::string> targets = resolveAssignmentTargets(assignment, knownFunctions, mergedGlobalBindings);

            const std::string rhsSlot = canonicalSlot(assignment.rhsExpression);
            if (!rhsSlot.empty())
            {
                const std::unordered_map<std::string, std::set<std::string>>::const_iterator rhsIt =
                    mergedGlobalBindings.find(rhsSlot);
                if (rhsIt != mergedGlobalBindings.end())
                {
                    targets.insert(rhsIt->second.begin(), rhsIt->second.end());
                }
            }

            if (targets.empty())
            {
                continue;
            }

            std::unordered_map<std::string, std::set<std::string>>::const_iterator cachedDestinationsIt =
                destinationCache.find(assignment.lhsExpression);
            if (cachedDestinationsIt == destinationCache.end())
            {
                cachedDestinationsIt =
                    destinationCache.emplace(
                                        assignment.lhsExpression,
                                        resolveAssignmentDestinationSlots(assignment.lhsExpression, knownFunctions, mergedGlobalBindings))
                        .first;
            }

            bool bindingsChanged = false;
            const std::set<std::string> &destinationSlots = cachedDestinationsIt->second;
            for (const std::string &destinationSlot : destinationSlots)
            {
                if (targetsBySlot[destinationSlot] != targets)
                {
                    targetsBySlot[destinationSlot] = targets;
                    bindingsChanged = true;
                }
                if (mergedGlobalBindings[destinationSlot] != targets)
                {
                    mergedGlobalBindings[destinationSlot] = targets;
                    bindingsChanged = true;
                }
            }

            if (bindingsChanged)
            {
                destinationCache.clear();
            }
        }

        for (const FunctionFacts &function : functions)
        {
            for (const CallSite &callSite : function.callSites)
            {
                if (callSite.directCallee != "memcpy" &&
                    callSite.directCallee != "memmove" &&
                    callSite.directCallee != "__builtin_memcpy" &&
                    callSite.directCallee != "__builtin_memmove")
                {
                    continue;
                }

                if (callSite.argumentExpressions.size() < 2U)
                {
                    continue;
                }

                const std::string dstSlot = canonicalSlot(callSite.argumentExpressions[0]);
                const std::string srcSlot = canonicalSlot(callSite.argumentExpressions[1]);
                if (dstSlot.empty() || globalSlots.find(dstSlot) == globalSlots.end())
                {
                    continue;
                }

                std::set<std::string> copiedTargets;
                if (!srcSlot.empty())
                {
                    const std::unordered_map<std::string, std::set<std::string>>::const_iterator srcIt =
                        targetsBySlot.find(srcSlot);
                    if (srcIt != targetsBySlot.end())
                    {
                        copiedTargets.insert(srcIt->second.begin(), srcIt->second.end());
                    }

                    const std::unordered_map<std::string, std::set<std::string>>::const_iterator srcSourceIt =
                        sourceTargetsBySlot.find(srcSlot);
                    if (srcSourceIt != sourceTargetsBySlot.end())
                    {
                        copiedTargets.insert(srcSourceIt->second.begin(), srcSourceIt->second.end());
                    }
                }

                if (copiedTargets.empty())
                {
                    for (const std::string &identifier : extractIdentifiers(callSite.argumentExpressions[1]))
                    {
                        if (knownFunctions.find(identifier) != knownFunctions.end())
                        {
                            copiedTargets.insert(identifier);
                        }
                    }
                }

                if (copiedTargets.empty())
                {
                    continue;
                }

                targetsBySlot[dstSlot] = copiedTargets;
            }
        }

        if (gDebugLoggingEnabled)
        {
            std::function<void(const std::string &)> logSlot = [&](const std::string &slotName)
            {
                const std::unordered_map<std::string, std::set<std::string>>::const_iterator it =
                    targetsBySlot.find(slotName);
                if (it == targetsBySlot.end())
                {
                    llvm::errs() << "[callgraph] program-wide slot " << slotName << " = <missing>\n";
                    return;
                }

                llvm::errs() << "[callgraph] program-wide slot " << slotName << " = ";
                bool first = true;
                for (const std::string &value : it->second)
                {
                    if (!first)
                    {
                        llvm::errs() << ",";
                    }
                    llvm::errs() << value;
                    first = false;
                }
                llvm::errs() << "\n";
            };

            logSlot("g_left");
            logSlot("g_right");
        }

        return targetsBySlot;
    }

    /**
     * @brief Collect cross-function memcpy/memmove destination slot summaries.
     */
    std::unordered_map<std::string, std::set<std::string>> collectMemcpyCopySummaryTargets(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions)
    {
        std::unordered_map<std::string, std::set<std::string>> sourceTargetsBySlot;
        std::unordered_map<std::string, std::set<std::string>> destinationCache;

        std::size_t totalAssignments = 0U;
        for (const FunctionFacts &function : functions)
        {
            totalAssignments += function.pointerAssignments.size();
        }

        sourceTargetsBySlot.reserve(totalAssignments * 2U + 1U);
        destinationCache.reserve(totalAssignments + 1U);

        // Single ordered pass keeps overwrite semantics monotonic: later writes replace earlier
        // values on the same resolved destination slot, while alias slots still accumulate.
        for (const FunctionFacts &function : functions)
        {
            for (const PointerAssignment &assignment : function.pointerAssignments)
            {
                const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
                if (lhsSlot.empty())
                {
                    continue;
                }

                std::set<std::string> targets =
                    resolveAssignmentTargets(assignment, knownFunctions, sourceTargetsBySlot);

                const std::string rhsSlot = canonicalSlot(assignment.rhsExpression);
                if (!rhsSlot.empty())
                {
                    const std::unordered_map<std::string, std::set<std::string>>::const_iterator rhsIt =
                        sourceTargetsBySlot.find(rhsSlot);
                    if (rhsIt != sourceTargetsBySlot.end())
                    {
                        targets.insert(rhsIt->second.begin(), rhsIt->second.end());
                    }
                }

                if (targets.empty())
                {
                    continue;
                }

                std::unordered_map<std::string, std::set<std::string>>::const_iterator cachedDestinationsIt =
                    destinationCache.find(assignment.lhsExpression);
                if (cachedDestinationsIt == destinationCache.end())
                {
                    cachedDestinationsIt =
                        destinationCache.emplace(
                                            assignment.lhsExpression,
                                            resolveAssignmentDestinationSlots(assignment.lhsExpression, knownFunctions, sourceTargetsBySlot))
                            .first;
                }

                bool bindingsChanged = false;
                const std::set<std::string> &destinationSlots = cachedDestinationsIt->second;
                for (const std::string &destinationSlot : destinationSlots)
                {
                    std::set<std::string> &existingTargets = sourceTargetsBySlot[destinationSlot];
                    if (existingTargets != targets)
                    {
                        existingTargets = targets;
                        bindingsChanged = true;
                    }
                }

                if (bindingsChanged)
                {
                    destinationCache.clear();
                }
            }
        }

        std::unordered_map<std::string, std::set<std::string>> summaryByDestinationSlot;
        for (const FunctionFacts &function : functions)
        {
            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                for (const std::string &rawLine : block.lines)
                {
                    const std::optional<std::pair<std::string, std::string>> memcpyArgs =
                        parseMemcpyArgsFromLine(rawLine);
                    if (!memcpyArgs.has_value())
                    {
                        continue;
                    }

                    const std::string dstSlot = canonicalSlot(memcpyArgs->first);
                    if (dstSlot.empty())
                    {
                        continue;
                    }

                    std::set<std::string> destinationSlots;
                    destinationSlots.insert(dstSlot);
                    const std::set<std::string> destinationAliases =
                        resolveTransitiveTargets(std::set<std::string>{dstSlot}, knownFunctions, sourceTargetsBySlot, true);
                    for (const std::string &alias : destinationAliases)
                    {
                        if (!alias.empty() &&
                            !isIntegerBinding(alias) &&
                            knownFunctions.find(alias) == knownFunctions.end())
                        {
                            destinationSlots.insert(alias);
                        }
                    }

                    std::set<std::string> copiedTargets;
                    const std::string srcSlot = canonicalSlot(memcpyArgs->second);
                    if (!srcSlot.empty())
                    {
                        const std::unordered_map<std::string, std::set<std::string>>::const_iterator srcIt =
                            sourceTargetsBySlot.find(srcSlot);
                        if (srcIt != sourceTargetsBySlot.end())
                        {
                            copiedTargets.insert(srcIt->second.begin(), srcIt->second.end());
                        }
                    }

                    const std::set<std::string> sourceValues =
                        resolveMixedExpressionValues(memcpyArgs->second, knownFunctions, sourceTargetsBySlot, false);
                    copiedTargets.insert(sourceValues.begin(), sourceValues.end());

                    const std::set<std::string> resolvedTargets =
                        resolveTransitiveTargets(copiedTargets, knownFunctions, sourceTargetsBySlot, true);
                    for (const std::string &target : resolvedTargets)
                    {
                        if (knownFunctions.find(target) != knownFunctions.end())
                        {
                            for (const std::string &destinationSlot : destinationSlots)
                            {
                                summaryByDestinationSlot[destinationSlot].insert(target);
                            }
                        }
                    }
                }
            }
        }

        return summaryByDestinationSlot;
    }

    /**
     * @brief Parse memcpy/memmove destination and source slots from a CFG line.
     */
    std::optional<std::pair<std::string, std::string>> parseMemcpyArgsFromLine(const std::string &rawLine)
    {
        std::string line = trimLine(rawLine);
        if (!line.empty() && line.back() == ';')
        {
            line.pop_back();
            line = trimLine(line);
        }

        std::function<bool(const std::string &)> startsWith = [&](const std::string &prefix)
        {
            return line.rfind(prefix, 0U) == 0U;
        };

        if (!startsWith("memcpy(") &&
            !startsWith("memmove(") &&
            !startsWith("__builtin_memcpy(") &&
            !startsWith("__builtin_memmove("))
        {
            return std::nullopt;
        }

        const std::size_t openParen = line.find('(');
        const std::size_t closeParen = line.rfind(')');
        if (openParen == std::string::npos || closeParen == std::string::npos || closeParen <= openParen + 1U)
        {
            return std::nullopt;
        }

        const std::string argsText = line.substr(openParen + 1U, closeParen - openParen - 1U);
        std::vector<std::string> args;
        std::string current;
        int parenDepth = 0;
        for (char ch : argsText)
        {
            if (ch == '(')
            {
                ++parenDepth;
            }
            else if (ch == ')')
            {
                if (parenDepth > 0)
                {
                    --parenDepth;
                }
            }

            if (ch == ',' && parenDepth == 0)
            {
                args.push_back(trimLine(current));
                current.clear();
                continue;
            }

            current.push_back(ch);
        }
        if (!current.empty())
        {
            args.push_back(trimLine(current));
        }

        if (args.size() < 2U)
        {
            return std::nullopt;
        }

        if (args[0].empty() || args[1].empty())
        {
            return std::nullopt;
        }

        return std::make_pair(args[0], args[1]);
    }

    /**
     * @brief Parse argument expressions from a call-like expression text.
     */
    std::vector<std::string> parseCallArgumentExpressions(const std::string &rawExpression)
    {
        std::string line = trimLine(rawExpression);
        if (!line.empty() && line.back() == ';')
        {
            line.pop_back();
            line = trimLine(line);
        }

        std::function<std::optional<std::pair<std::size_t, std::size_t>>(const std::string &)> findTrailingCallArgumentSpan =
            [](const std::string &text) -> std::optional<std::pair<std::size_t, std::size_t>>
        {
            if (text.empty())
            {
                return std::nullopt;
            }

            std::size_t closeParen = text.size();
            while (closeParen > 0U && std::isspace(static_cast<unsigned char>(text[closeParen - 1U])) != 0)
            {
                --closeParen;
            }
            if (closeParen == 0U || text[closeParen - 1U] != ')')
            {
                return std::nullopt;
            }
            --closeParen;

            std::size_t depth = 0U;
            std::size_t openParen = std::string::npos;
            for (std::size_t i = closeParen + 1U; i-- > 0U;)
            {
                const char ch = text[i];
                if (ch == ')')
                {
                    ++depth;
                    continue;
                }
                if (ch != '(')
                {
                    continue;
                }

                if (depth == 0U)
                {
                    return std::nullopt;
                }

                --depth;
                if (depth == 0U)
                {
                    openParen = i;
                    break;
                }
            }

            if (openParen == std::string::npos)
            {
                return std::nullopt;
            }

            std::size_t calleeEnd = openParen;
            while (calleeEnd > 0U && std::isspace(static_cast<unsigned char>(text[calleeEnd - 1U])) != 0)
            {
                --calleeEnd;
            }
            if (calleeEnd == 0U)
            {
                return std::nullopt;
            }

            return std::make_pair(openParen, closeParen);
        };

        const std::optional<std::pair<std::size_t, std::size_t>> argumentSpan =
            findTrailingCallArgumentSpan(line);
        if (!argumentSpan.has_value())
        {
            return {};
        }

        const std::size_t openParen = argumentSpan->first;
        const std::size_t closeParen = argumentSpan->second;
        if (closeParen <= openParen + 1U)
        {
            return {};
        }

        const std::string argsText = line.substr(openParen + 1U, closeParen - openParen - 1U);
        std::vector<std::string> args;
        std::string current;
        int parenDepth = 0;
        int bracketDepth = 0;
        int braceDepth = 0;
        bool inSingleQuote = false;
        bool inDoubleQuote = false;

        for (char ch : argsText)
        {
            const char prev = current.empty() ? '\0' : current.back();
            if (inSingleQuote)
            {
                if (ch == '\'' && prev != '\\')
                {
                    inSingleQuote = false;
                }
                current.push_back(ch);
                continue;
            }
            if (inDoubleQuote)
            {
                if (ch == '"' && prev != '\\')
                {
                    inDoubleQuote = false;
                }
                current.push_back(ch);
                continue;
            }

            if (ch == '\'')
            {
                inSingleQuote = true;
                current.push_back(ch);
                continue;
            }
            if (ch == '"')
            {
                inDoubleQuote = true;
                current.push_back(ch);
                continue;
            }

            if (ch == '(')
            {
                ++parenDepth;
            }
            else if (ch == ')' && parenDepth > 0)
            {
                --parenDepth;
            }
            else if (ch == '[')
            {
                ++bracketDepth;
            }
            else if (ch == ']' && bracketDepth > 0)
            {
                --bracketDepth;
            }
            else if (ch == '{')
            {
                ++braceDepth;
            }
            else if (ch == '}' && braceDepth > 0)
            {
                --braceDepth;
            }

            if (ch == ',' && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0)
            {
                args.push_back(trimLine(current));
                current.clear();
                continue;
            }

            current.push_back(ch);
        }

        if (!current.empty())
        {
            args.push_back(trimLine(current));
        }

        return args;
    }

    /**
     * @brief Parse returned expression from a CFG line like `return expr;`.
     */
    std::optional<std::string> parseReturnExpressionFromLine(const std::string &rawLine)
    {
        std::string line = trimLine(rawLine);
        if (line.rfind("return", 0U) != 0U)
        {
            return std::nullopt;
        }

        if (line.size() > 6U)
        {
            const unsigned char next = static_cast<unsigned char>(line[6U]);
            if (std::isspace(next) == 0)
            {
                return std::nullopt;
            }
        }

        line = trimLine(line.substr(6U));
        if (!line.empty() && line.back() == ';')
        {
            line.pop_back();
            line = trimLine(line);
        }

        if (line.empty())
        {
            return std::nullopt;
        }

        return line;
    }

    /**
     * @brief Parse known memory transfer/clear operations from one CFG line.
     */
    std::optional<MemoryTransferOp> parseMemoryTransferOpFromLine(const std::string &rawLine)
    {
        const std::string callee = extractCallCalleeIdentifier(rawLine);
        if (callee.empty())
        {
            return std::nullopt;
        }

        const std::vector<std::string> args = parseCallArgumentExpressions(rawLine);
        if (args.empty())
        {
            return std::nullopt;
        }

        MemoryTransferOp op;

        if ((callee == "memcpy" || callee == "memmove" ||
             callee == "__builtin_memcpy" || callee == "__builtin_memmove" ||
             callee == "mempcpy" || callee == "__builtin_mempcpy") &&
            args.size() >= 2U)
        {
            op.copyPairs.push_back({args[1], args[0]});
        }
        else if (callee == "bcopy" && args.size() >= 2U)
        {
            op.copyPairs.push_back({args[0], args[1]});
        }
        else if ((callee == "strcpy" || callee == "stpcpy" || callee == "strncpy" ||
                  callee == "strlcpy" || callee == "wcscpy" || callee == "wmemcpy" ||
                  callee == "wmemmove") &&
                 args.size() >= 2U)
        {
            op.copyPairs.push_back({args[1], args[0]});
        }
        else if ((callee == "strcat" || callee == "strncat") && args.size() >= 2U)
        {
            op.copyPairs.push_back({args[1], args[0]});
        }
        else if ((callee == "memset" || callee == "bzero" || callee == "explicit_bzero" ||
                  callee == "__builtin_memset") &&
                 args.size() >= 1U)
        {
            op.clearDestinations.push_back(args[0]);
        }
        else
        {
            return std::nullopt;
        }

        return op;
    }

    std::vector<std::string> collectParameterSlots(
        const FunctionFacts &function,
        const std::set<std::string> &knownFunctions);

    /**
     * @brief Resolve function targets referenced by an expression.
     */
    std::set<std::string> resolveExpressionTargets(
        const std::string &expression,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &pointsTo)
    {
        std::set<std::string> seeds;

        const std::string slot = canonicalSlot(expression);
        if (!slot.empty())
        {
            seeds.insert(slot);
        }

        for (const std::string &identifier : extractIdentifiers(expression))
        {
            if (knownFunctions.find(identifier) != knownFunctions.end())
            {
                seeds.insert(identifier);
                continue;
            }

            const std::unordered_map<std::string, std::set<std::string>>::const_iterator it = pointsTo.find(identifier);
            if (it != pointsTo.end())
            {
                seeds.insert(it->second.begin(), it->second.end());
            }
        }

        return resolveTransitiveTargets(seeds, knownFunctions, pointsTo, false);
    }

    /**
     * @brief Collect slots that are expected to hold function targets.
     */
    std::set<std::string> collectPointerSlots(const FunctionFacts &function)
    {
        std::set<std::string> slots;

        std::function<std::string(const std::string &)> removeArrayIndices = [](const std::string &text)
        {
            std::string out;
            out.reserve(text.size());
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
                    out.push_back(ch);
                }
            }
            return out;
        };

        for (const PointerAssignment &assignment : function.pointerAssignments)
        {
            const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
            if (lhsSlot.empty())
            {
                continue;
            }

            if (!assignment.assignedFunction.empty() || assignment.rhsTakesFunctionAddress ||
                assignment.rhsExpression.find('&') != std::string::npos)
            {
                slots.insert(lhsSlot);
            }
        }

        for (const CallSite &callSite : function.callSites)
        {
            if (!callSite.throughIdentifier.empty())
            {
                const std::string throughSlot = canonicalSlot(callSite.throughIdentifier);
                if (!throughSlot.empty())
                {
                    slots.insert(throughSlot);
                }
            }

            if (callSite.directCallee.empty())
            {
                const std::string calleeSlot = canonicalSlot(callSite.calleeExpression);
                if (!calleeSlot.empty())
                {
                    slots.insert(calleeSlot);
                }

                std::string normalized = callSite.calleeExpression;
                for (std::size_t pos = normalized.find("->"); pos != std::string::npos; pos = normalized.find("->", pos + 1U))
                {
                    normalized.replace(pos, 2U, ".");
                }
                normalized = removeArrayIndices(normalized);
                const std::size_t dotIndex = normalized.find('.');
                if (dotIndex != std::string::npos && dotIndex > 0)
                {
                    const std::string baseSlot = canonicalSlot(normalized.substr(0, dotIndex));
                    if (!baseSlot.empty())
                    {
                        slots.insert(baseSlot);
                    }
                }
            }
        }

        return slots;
    }

    /**
     * @brief Resolve mixed scalar/function values from an expression.
     */
    std::set<std::string> resolveMixedExpressionValues(
        const std::string &expression,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &bindings,
        bool includeSlotIdentity)
    {
        std::set<std::string> values;

        long long literalValue = 0;
        if (isIntegerLiteral(trimLine(expression), literalValue))
        {
            values.insert(makeIntegerBinding(literalValue));
        }

        if (expression.find('&') != std::string::npos)
        {
            for (const std::string &identifier : extractIdentifiers(expression))
            {
                if (knownFunctions.find(identifier) == knownFunctions.end())
                {
                    values.insert(identifier);
                    break;
                }
            }
        }

        if (includeSlotIdentity)
        {
            const std::string slot = canonicalSlot(expression);
            if (!slot.empty())
            {
                values.insert(slot);
            }
        }

        for (const std::string &identifier : extractIdentifiers(expression))
        {
            if (knownFunctions.find(identifier) != knownFunctions.end())
            {
                values.insert(identifier);
            }

            const std::unordered_map<std::string, std::set<std::string>>::const_iterator bindingIt = bindings.find(identifier);
            if (bindingIt != bindings.end())
            {
                values.insert(bindingIt->second.begin(), bindingIt->second.end());
                continue;
            }

            if (knownFunctions.find(identifier) == knownFunctions.end())
            {
                values.insert(identifier);
            }
        }

        std::set<std::string> resolved = resolveTransitiveTargets(values, knownFunctions, bindings, true);
        for (const std::string &value : values)
        {
            if (isIntegerBinding(value))
            {
                resolved.insert(value);
            }
        }

        if (resolved.empty() && !values.empty())
        {
            return values;
        }

        return resolved;
    }

    /**
     * @brief Collect direct function targets returned by each function.
     */
    std::unordered_map<std::string, std::set<std::string>> collectReturnTargetsByFunction(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions)
    {
        std::unordered_map<std::string, std::set<std::string>> targetsByFunction;
        std::unordered_map<std::string, std::vector<std::string>> parameterSlotsByFunction;
        std::unordered_map<std::string, std::set<std::string>> pointerSlotsByFunction;

        for (const FunctionFacts &function : functions)
        {
            parameterSlotsByFunction[function.name] = collectParameterSlots(function, knownFunctions);
            pointerSlotsByFunction[function.name] = collectPointerSlots(function);
        }

        std::function<PointsToMap(const FunctionFacts &)> seedGlobalPointerBindings = [&](const FunctionFacts &function)
        {
            PointsToMap bindings;
            for (const PointerAssignment &assignment : function.pointerAssignments)
            {
                if (!assignment.lhsIsGlobal)
                {
                    continue;
                }

                const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
                if (lhsSlot.empty())
                {
                    continue;
                }

                const std::set<std::string> targets = resolveAssignmentTargets(assignment, knownFunctions, bindings);
                if (targets.empty())
                {
                    continue;
                }

                std::set<std::string> &slotTargets = bindings[lhsSlot];
                slotTargets.insert(targets.begin(), targets.end());
            }

            return bindings;
        };

        std::function<std::set<std::string>(
            const std::string &,
            const PointsToMap &,
            const std::unordered_map<std::string, std::set<std::string>> &)>
            resolveReturnedCallTargets = [&](const std::string &expression,
                                             const PointsToMap &bindings,
                                             const std::unordered_map<std::string, std::set<std::string>> &currentTargets)
        {
            std::set<std::string> resolved;
            const std::set<std::string> callees = resolveCallCalleeTargets(expression, knownFunctions, bindings);
            const std::vector<std::string> argumentExpressions = parseCallArgumentExpressions(expression);

            for (const std::string &callee : callees)
            {
                const std::unordered_map<std::string, std::set<std::string>>::const_iterator returnIt =
                    currentTargets.find(callee);
                if (returnIt == currentTargets.end())
                {
                    continue;
                }

                const std::unordered_map<std::string, std::vector<std::string>>::const_iterator parametersIt =
                    parameterSlotsByFunction.find(callee);
                const std::unordered_map<std::string, std::set<std::string>>::const_iterator pointerSlotsIt =
                    pointerSlotsByFunction.find(callee);
                const std::vector<std::string> emptyParameters;
                const std::set<std::string> emptyPointerSlots;
                const std::vector<std::string> &calleeParameters =
                    parametersIt != parameterSlotsByFunction.end() ? parametersIt->second : emptyParameters;
                const std::set<std::string> &calleePointerSlots =
                    pointerSlotsIt != pointerSlotsByFunction.end() ? pointerSlotsIt->second : emptyPointerSlots;

                CallSite syntheticCallSite;
                syntheticCallSite.argumentExpressions = argumentExpressions;
                PointsToMap callSeeds;
                if (!calleeParameters.empty())
                {
                    callSeeds = buildSeedBindings(syntheticCallSite, calleeParameters, calleePointerSlots, bindings, knownFunctions);
                }

                for (const std::string &returned : returnIt->second)
                {
                    if (knownFunctions.find(returned) != knownFunctions.end())
                    {
                        resolved.insert(returned);
                        continue;
                    }

                    const PointsToMap::const_iterator seedIt = callSeeds.find(returned);
                    if (seedIt != callSeeds.end())
                    {
                        resolved.insert(seedIt->second.begin(), seedIt->second.end());
                        continue;
                    }

                    const PointsToMap::const_iterator bindingIt = bindings.find(returned);
                    if (bindingIt != bindings.end())
                    {
                        resolved.insert(bindingIt->second.begin(), bindingIt->second.end());
                        continue;
                    }

                    resolved.insert(returned);
                }
            }

            return resolved;
        };

        bool changed = true;
        while (changed)
        {
            changed = false;

            for (const FunctionFacts &function : functions)
            {
                std::unordered_map<std::uint32_t, const FunctionFacts::BlockFact *> blockMap;
                for (const FunctionFacts::BlockFact &block : function.blocks)
                {
                    blockMap[block.id] = &block;
                }

                std::uint32_t entryBlockId = function.entryBlockId;
                if (blockMap.find(entryBlockId) == blockMap.end())
                {
                    if (function.blocks.empty())
                    {
                        continue;
                    }

                    entryBlockId = function.blocks.front().id;
                }

                struct BlockState
                {
                    std::uint32_t blockId = 0;
                    PointsToMap bindings;
                };

                std::function<std::string(std::uint32_t, const PointsToMap &)> makeStateKey = [](std::uint32_t blockId, const PointsToMap &bindings)
                {
                    std::vector<std::pair<std::string, std::vector<std::string>>> entries;
                    entries.reserve(bindings.size());
                    for (const std::pair<const std::string, std::set<std::string>> &entry : bindings)
                    {
                        std::vector<std::string> values(entry.second.begin(), entry.second.end());
                        std::sort(values.begin(), values.end());
                        entries.push_back(std::make_pair(entry.first, std::move(values)));
                    }
                    std::sort(entries.begin(), entries.end(), [](const std::pair<std::string, std::vector<std::string>> &lhs, const std::pair<std::string, std::vector<std::string>> &rhs)
                              { return lhs.first < rhs.first; });

                    std::string key = std::to_string(blockId);
                    key.push_back('|');
                    for (const std::pair<std::string, std::vector<std::string>> &entry : entries)
                    {
                        key += entry.first;
                        key.push_back('=');
                        for (const std::string &value : entry.second)
                        {
                            key += value;
                            key.push_back(',');
                        }
                        key.push_back(';');
                    }
                    return key;
                };

                std::set<std::string> collectedTargets = targetsByFunction[function.name];
                std::deque<BlockState> worklist;
                std::unordered_set<std::string> seenStates;
                worklist.push_back(BlockState{entryBlockId, seedGlobalPointerBindings(function)});

                while (!worklist.empty())
                {
                    BlockState state = std::move(worklist.front());
                    worklist.pop_front();

                    const std::unordered_map<std::uint32_t, const FunctionFacts::BlockFact *>::const_iterator blockIt =
                        blockMap.find(state.blockId);
                    if (blockIt == blockMap.end())
                    {
                        continue;
                    }

                    const FunctionFacts::BlockFact &block = *blockIt->second;
                    const std::string stateKey = makeStateKey(block.id, state.bindings);
                    if (!seenStates.insert(stateKey).second)
                    {
                        continue;
                    }

                    PointsToMap bindings = std::move(state.bindings);

                    for (const std::string &rawLine : block.lines)
                    {
                        const std::string line = trimLine(rawLine);
                        if (line.empty())
                        {
                            continue;
                        }

                        if (line.find('=') != std::string::npos &&
                            line.find("==") == std::string::npos &&
                            line.find("!=") == std::string::npos &&
                            line.find("<=") == std::string::npos &&
                            line.find(">=") == std::string::npos)
                        {
                            const std::size_t equalIndex = line.find('=');
                            if (equalIndex == std::string::npos)
                            {
                                continue;
                            }

                            std::string lhs = trimLine(line.substr(0, equalIndex));
                            std::string rhs = trimLine(line.substr(equalIndex + 1U));
                            if (!rhs.empty() && rhs.back() == ';')
                            {
                                rhs.pop_back();
                                rhs = trimLine(rhs);
                            }

                            const std::string lhsSlot = canonicalSlot(lhs);
                            if (lhsSlot.empty())
                            {
                                continue;
                            }
                            std::set<std::string> values = resolveMixedExpressionValues(rhs, knownFunctions, bindings, false);
                            const std::set<std::string> callReturns =
                                resolveReturnedCallTargets(rhs, bindings, targetsByFunction);
                            if (!callReturns.empty())
                            {
                                values = std::move(callReturns);
                            }

                            if (!values.empty())
                            {
                                std::set<std::string> &slotValues = bindings[lhsSlot];
                                slotValues.clear();
                                slotValues.insert(values.begin(), values.end());
                            }

                            continue;
                        }

                        const bool startsWithReturn = line.rfind("return", 0) == 0;
                        const bool hasReturnTokenBoundary =
                            line.size() == 6U ||
                            line[6] == ';' ||
                            std::isspace(static_cast<unsigned char>(line[6])) != 0;
                        if (!startsWithReturn || !hasReturnTokenBoundary)
                        {
                            continue;
                        }

                        std::string returned = trimLine(line.substr(6U));
                        if (!returned.empty() && returned.front() == ' ')
                        {
                            returned = trimLine(returned);
                        }
                        if (!returned.empty() && returned.back() == ';')
                        {
                            returned.pop_back();
                            returned = trimLine(returned);
                        }

                        std::set<std::string> values = resolveMixedExpressionValues(returned, knownFunctions, bindings);
                        const std::set<std::string> callReturns =
                            resolveReturnedCallTargets(returned, bindings, targetsByFunction);
                        if (!callReturns.empty())
                        {
                            values.insert(callReturns.begin(), callReturns.end());
                        }

                        for (const std::string &value : values)
                        {
                            if (!value.empty() && !isIntegerBinding(value))
                            {
                                collectedTargets.insert(value);
                            }
                        }
                    }

                    for (std::uint32_t successor : block.successors)
                    {
                        worklist.push_back(BlockState{successor, bindings});
                    }
                }

                std::set<std::string> &current = targetsByFunction[function.name];
                const std::size_t before = current.size();
                current.insert(collectedTargets.begin(), collectedTargets.end());
                if (current.size() != before)
                {
                    changed = true;
                }
            }
        }

        return targetsByFunction;
    }

    /**
     * @brief Infer parameter-like slots that should be seeded from call arguments.
     */
    std::vector<std::string> collectParameterSlots(
        const FunctionFacts &function,
        const std::set<std::string> &knownFunctions)
    {
        if (!function.parameterNames.empty())
        {
            std::vector<std::string> parameterSlots;
            std::unordered_set<std::string> seen;
            for (const std::string &name : function.parameterNames)
            {
                if (!name.empty() && seen.insert(name).second)
                {
                    parameterSlots.push_back(name);
                }
            }
            if (!parameterSlots.empty())
            {
                return parameterSlots;
            }
        }

        std::vector<std::string> parameterSlots;
        std::unordered_set<std::string> assignedSlots;
        std::unordered_set<std::string> seenSlots;

        for (const PointerAssignment &assignment : function.pointerAssignments)
        {
            const std::string slot = canonicalSlot(assignment.lhsExpression);
            if (!slot.empty())
            {
                assignedSlots.insert(slot);
            }
        }

        for (const CallSite &callSite : function.callSites)
        {
            if (callSite.directCallee.empty())
            {
                std::string slot;
                if (!callSite.throughIdentifier.empty())
                {
                    slot = canonicalSlot(callSite.throughIdentifier);
                }
                if (slot.empty())
                {
                    slot = canonicalSlot(callSite.calleeExpression);
                }

                if (!slot.empty() && assignedSlots.find(slot) == assignedSlots.end() && seenSlots.insert(slot).second)
                {
                    parameterSlots.push_back(slot);
                }
            }
        }

        for (const PointerAssignment &assignment : function.pointerAssignments)
        {
            for (const std::string &identifier : extractIdentifiers(assignment.rhsExpression))
            {
                if (assignedSlots.find(identifier) != assignedSlots.end())
                {
                    continue;
                }
                if (knownFunctions.find(identifier) != knownFunctions.end())
                {
                    continue;
                }
                if (seenSlots.insert(identifier).second)
                {
                    parameterSlots.push_back(identifier);
                }
            }
        }

        for (const CallSite &callSite : function.callSites)
        {
            for (const std::string &argumentExpression : callSite.argumentExpressions)
            {
                for (const std::string &identifier : extractIdentifiers(argumentExpression))
                {
                    if (assignedSlots.find(identifier) != assignedSlots.end())
                    {
                        continue;
                    }
                    if (knownFunctions.find(identifier) != knownFunctions.end())
                    {
                        continue;
                    }
                    if (seenSlots.insert(identifier).second)
                    {
                        parameterSlots.push_back(identifier);
                    }
                }
            }
        }

        return parameterSlots;
    }

    /**
     * @brief Build callee seed bindings from caller argument expressions.
     */
    PointsToMap buildSeedBindings(
        const CallSite &callSite,
        const std::vector<std::string> &parameterSlots,
        const std::set<std::string> &pointerSlots,
        const PointsToMap &callerPointsTo,
        const std::set<std::string> &knownFunctions)
    {
        PointsToMap seeds;

        const std::size_t limit = std::min(parameterSlots.size(), callSite.argumentExpressions.size());
        for (std::size_t index = 0; index < limit; ++index)
        {
            const std::string &slot = parameterSlots[index];
            const std::string &argumentExpression = callSite.argumentExpressions[index];
            const bool isPointerSlot = pointerSlots.find(slot) != pointerSlots.end();
            const bool argumentLooksPointerLike =
                argumentExpression.find('&') != std::string::npos ||
                argumentExpression.find("->") != std::string::npos ||
                argumentExpression.find('.') != std::string::npos;
            const std::set<std::string> targets =
                resolveMixedExpressionValues(argumentExpression, knownFunctions, callerPointsTo);

            bool hasNonIntegerTarget = false;
            for (const std::string &target : targets)
            {
                if (!isIntegerBinding(target))
                {
                    hasNonIntegerTarget = true;
                    break;
                }
            }

            const bool treatAsPointerLike = isPointerSlot || argumentLooksPointerLike || hasNonIntegerTarget;

            for (const std::string &target : targets)
            {
                if (treatAsPointerLike)
                {
                    if (!isIntegerBinding(target))
                    {
                        seeds[slot].insert(target);
                    }
                }
                else
                {
                    if (isIntegerBinding(target))
                    {
                        seeds[slot].insert(target);
                    }
                }
            }
        }

        return seeds;
    }

    struct DeferredLoadConstraint
    {
        std::string dstNode;
    };

    struct DeferredStoreConstraint
    {
        std::string srcNode;
    };

    struct DeferredStoreSeed
    {
        std::string target;
    };

    struct PagConstraintState
    {
        std::unordered_map<std::string, std::unordered_set<std::string>> pointsTo;
        std::unordered_map<std::string, std::vector<DeferredLoadConstraint>> loadsByPointer;
        std::unordered_map<std::string, std::vector<DeferredStoreConstraint>> storesByPointer;
        std::unordered_map<std::string, std::vector<DeferredStoreSeed>> storeSeedTargetsByPointer;
        std::unordered_map<std::string, std::vector<std::string>> memTransferDstBySrcPtr;
        std::unordered_map<std::string, std::vector<std::string>> memTransferSrcByDstPtr;
        std::unordered_map<std::string, std::vector<std::string>> sparseValueFlowSucc;
        std::unordered_map<std::string, std::vector<std::string>> sparseValueFlowPred;
        std::unordered_set<std::string> sparseValueFlowEdgeKeys;
        std::deque<std::string> worklist;
        std::unordered_set<std::string> inWorklist;
        std::unordered_set<std::string> relevantNodes;
        std::deque<std::string> relevantQueue;

        void reserve(std::size_t estimatedPagNodes, std::size_t trackedSlotCount)
        {
            pointsTo.reserve(estimatedPagNodes);
            loadsByPointer.reserve(estimatedPagNodes / 2U + 1U);
            storesByPointer.reserve(estimatedPagNodes / 2U + 1U);
            storeSeedTargetsByPointer.reserve(estimatedPagNodes / 2U + 1U);
            memTransferDstBySrcPtr.reserve(trackedSlotCount + 1U);
            memTransferSrcByDstPtr.reserve(trackedSlotCount + 1U);
            sparseValueFlowSucc.reserve(estimatedPagNodes);
            sparseValueFlowPred.reserve(estimatedPagNodes);
            sparseValueFlowEdgeKeys.reserve(estimatedPagNodes * 2U + 1U);
            inWorklist.reserve(estimatedPagNodes);
            relevantNodes.reserve(estimatedPagNodes);
        }

        void markRelevant(const std::string &node)
        {
            if (node.empty())
            {
                return;
            }

            if (relevantNodes.insert(node).second)
            {
                relevantQueue.push_back(node);
            }
        }

        void saturateRelevantNodes()
        {
            while (!relevantQueue.empty())
            {
                const std::string node = relevantQueue.front();
                relevantQueue.pop_front();

                const std::unordered_map<std::string, std::vector<std::string>>::const_iterator predIt =
                    sparseValueFlowPred.find(node);
                if (predIt == sparseValueFlowPred.end())
                {
                    continue;
                }

                for (const std::string &pred : predIt->second)
                {
                    if (relevantNodes.insert(pred).second)
                    {
                        const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator ptIt =
                            pointsTo.find(pred);
                        if (ptIt != pointsTo.end() && !ptIt->second.empty() && inWorklist.insert(pred).second)
                        {
                            worklist.push_back(pred);
                        }
                        relevantQueue.push_back(pred);
                    }
                }
            }
        }

        bool addSparseValueFlowEdge(const std::string &src, const std::string &dst)
        {
            if (src.empty() || dst.empty())
            {
                return false;
            }

            const std::string edgeKey = src + "->" + dst;
            if (!sparseValueFlowEdgeKeys.insert(edgeKey).second)
            {
                return false;
            }

            sparseValueFlowSucc[src].push_back(dst);
            sparseValueFlowPred[dst].push_back(src);

            if (relevantNodes.find(dst) != relevantNodes.end() && relevantNodes.insert(src).second)
            {
                relevantQueue.push_back(src);
                saturateRelevantNodes();
            }

            return true;
        }

        bool addCopyEdge(const std::string &src, const std::string &dst)
        {
            if (src.empty() || dst.empty())
            {
                return false;
            }

            return addSparseValueFlowEdge(src, dst);
        }

        void queueNode(const std::string &node)
        {
            if (node.empty())
            {
                return;
            }

            const bool hasDeferredEffects =
                loadsByPointer.find(node) != loadsByPointer.end() ||
                storesByPointer.find(node) != storesByPointer.end() ||
                storeSeedTargetsByPointer.find(node) != storeSeedTargetsByPointer.end() ||
                memTransferDstBySrcPtr.find(node) != memTransferDstBySrcPtr.end() ||
                memTransferSrcByDstPtr.find(node) != memTransferSrcByDstPtr.end();
            if (relevantNodes.find(node) == relevantNodes.end() && !hasDeferredEffects)
            {
                return;
            }

            if (inWorklist.insert(node).second)
            {
                worklist.push_back(node);
            }
        }

        bool addPointsTo(const std::string &node, const std::string &target)
        {
            if (node.empty() || target.empty())
            {
                return false;
            }

            std::pair<std::unordered_map<std::string, std::unordered_set<std::string>>::iterator, bool> entry =
                pointsTo.emplace(node, std::unordered_set<std::string>());
            std::unordered_set<std::string> &targets = entry.first->second;
            if (entry.second)
            {
                targets.reserve(4U);
            }
            if (!targets.insert(target).second)
            {
                return false;
            }

            queueNode(node);
            return true;
        }

        void addAddressSeed(const std::string &lhsNode, const std::string &targetObject)
        {
            addPointsTo(lhsNode, targetObject);
        }

        bool overwritePointsToSingleton(const std::string &node, const std::string &target)
        {
            if (node.empty() || target.empty())
            {
                return false;
            }

            std::pair<std::unordered_map<std::string, std::unordered_set<std::string>>::iterator, bool> entry =
                pointsTo.emplace(node, std::unordered_set<std::string>());
            std::unordered_set<std::string> &targets = entry.first->second;
            if (entry.second)
            {
                targets.reserve(4U);
            }

            if (targets.size() == 1U && targets.find(target) != targets.end())
            {
                return false;
            }

            targets.clear();
            targets.insert(target);
            queueNode(node);
            return true;
        }
    };

    struct CallResolutionContext
    {
        const std::vector<FunctionFacts> &functions;
        const std::unordered_map<std::string, const FunctionFacts *> &functionMap;
        const std::unordered_map<std::string, std::string> &nodeRepresentativeByNode;
        const std::set<std::string> &knownFunctions;
        const std::set<std::string> &blacklistedFunctions;
        const std::unordered_map<std::string, std::unordered_set<std::string>> &pointsTo;
        const std::function<std::vector<std::string>(const std::string &, const std::string &)> &collectCandidateMemoryNodes;
        const std::function<const std::vector<std::string> &(const std::string &)> &getExpandedMemorySlotAliases;
        const std::function<SmallStringList(const std::unordered_set<std::string> &)> &resolveFunctionTargetsTransitively;
        const std::unordered_map<CallSiteId, std::vector<std::string>> *probeNodesByCallSiteId = nullptr;
        const std::unordered_set<std::string> *activeFunctionNames = nullptr;
    };

    /**
     * @brief Reject indirect edges with obviously incompatible argument counts.
     */
    bool hasCompatibleArgumentProfile(const CallSite &callSite, const FunctionFacts &callee)
    {
        if (callee.parameterNames.empty())
        {
            return true;
        }

        return callSite.argumentExpressions.size() >= callee.parameterNames.size();
    }

    std::string canonicalConstraintNode(
        const std::string &node,
        const std::unordered_map<std::string, std::string> &nodeRepresentativeByNode)
    {
        std::string current = node;
        std::unordered_set<std::string> visited;

        while (visited.insert(current).second)
        {
            const std::unordered_map<std::string, std::string>::const_iterator it = nodeRepresentativeByNode.find(current);
            if (it == nodeRepresentativeByNode.end())
            {
                break;
            }

            current = it->second;
        }

        return current;
    }

    void collapseConstraintGraphSccs(
        PagConstraintState &state,
        std::unordered_map<std::string, std::string> &nodeRepresentativeByNode)
    {
        nodeRepresentativeByNode.clear();

        std::unordered_set<std::string> allNodes;
        auto addNode = [&](const std::string &node)
        {
            if (!node.empty())
            {
                allNodes.insert(node);
            }
        };

        for (const std::pair<const std::string, std::unordered_set<std::string>> &entry : state.pointsTo)
        {
            addNode(entry.first);
            for (const std::string &target : entry.second)
            {
                addNode(target);
            }
        }

        for (const std::pair<const std::string, std::vector<DeferredLoadConstraint>> &entry : state.loadsByPointer)
        {
            addNode(entry.first);
            for (const DeferredLoadConstraint &constraint : entry.second)
            {
                addNode(constraint.dstNode);
            }
        }

        for (const std::pair<const std::string, std::vector<DeferredStoreConstraint>> &entry : state.storesByPointer)
        {
            addNode(entry.first);
            for (const DeferredStoreConstraint &constraint : entry.second)
            {
                addNode(constraint.srcNode);
            }
        }

        for (const std::pair<const std::string, std::vector<DeferredStoreSeed>> &entry : state.storeSeedTargetsByPointer)
        {
            addNode(entry.first);
            for (const DeferredStoreSeed &constraint : entry.second)
            {
                addNode(constraint.target);
            }
        }

        for (const std::pair<const std::string, std::vector<std::string>> &entry : state.memTransferDstBySrcPtr)
        {
            addNode(entry.first);
            for (const std::string &dst : entry.second)
            {
                addNode(dst);
            }
        }

        for (const std::pair<const std::string, std::vector<std::string>> &entry : state.memTransferSrcByDstPtr)
        {
            addNode(entry.first);
            for (const std::string &src : entry.second)
            {
                addNode(src);
            }
        }

        for (const std::pair<const std::string, std::vector<std::string>> &entry : state.sparseValueFlowSucc)
        {
            addNode(entry.first);
            for (const std::string &succ : entry.second)
            {
                addNode(succ);
            }
        }

        for (const std::pair<const std::string, std::vector<std::string>> &entry : state.sparseValueFlowPred)
        {
            addNode(entry.first);
            for (const std::string &pred : entry.second)
            {
                addNode(pred);
            }
        }

        for (const std::string &node : state.relevantNodes)
        {
            addNode(node);
        }
        for (const std::string &node : state.worklist)
        {
            addNode(node);
        }

        if (allNodes.empty())
        {
            return;
        }

        std::unordered_map<std::string, std::size_t> indexByNode;
        std::unordered_map<std::string, std::size_t> lowLinkByNode;
        std::unordered_set<std::string> onStack;
        std::vector<std::string> stack;
        std::vector<std::vector<std::string>> components;
        std::size_t nextIndex = 0U;

        std::function<void(const std::string &)> strongConnect = [&](const std::string &node)
        {
            indexByNode[node] = nextIndex;
            lowLinkByNode[node] = nextIndex;
            ++nextIndex;
            stack.push_back(node);
            onStack.insert(node);

            const std::unordered_map<std::string, std::vector<std::string>>::const_iterator succIt =
                state.sparseValueFlowSucc.find(node);
            if (succIt != state.sparseValueFlowSucc.end())
            {
                for (const std::string &next : succIt->second)
                {
                    if (indexByNode.find(next) == indexByNode.end())
                    {
                        strongConnect(next);
                        lowLinkByNode[node] = std::min(lowLinkByNode[node], lowLinkByNode[next]);
                    }
                    else if (onStack.find(next) != onStack.end())
                    {
                        lowLinkByNode[node] = std::min(lowLinkByNode[node], indexByNode[next]);
                    }
                }
            }

            if (lowLinkByNode[node] != indexByNode[node])
            {
                return;
            }

            std::vector<std::string> component;
            while (!stack.empty())
            {
                const std::string current = stack.back();
                stack.pop_back();
                onStack.erase(current);
                component.push_back(current);
                if (current == node)
                {
                    break;
                }
            }

            components.push_back(std::move(component));
        };

        for (const std::string &node : allNodes)
        {
            if (indexByNode.find(node) == indexByNode.end())
            {
                strongConnect(node);
            }
        }

        for (const std::vector<std::string> &component : components)
        {
            if (component.size() <= 1U)
            {
                continue;
            }

            std::string representative = *std::min_element(component.begin(), component.end());
            for (const std::string &node : component)
            {
                if (node != representative)
                {
                    nodeRepresentativeByNode[node] = representative;
                }
            }
        }

        if (nodeRepresentativeByNode.empty())
        {
            return;
        }

        auto remapNode = [&](const std::string &node) -> std::string
        {
            return canonicalConstraintNode(node, nodeRepresentativeByNode);
        };

        auto remapNodeSet = [&](const std::unordered_set<std::string> &values)
        {
            std::unordered_set<std::string> remapped;
            for (const std::string &value : values)
            {
                remapped.insert(remapNode(value));
            }
            return remapped;
        };

        auto remapVector = [&](const std::vector<std::string> &values)
        {
            std::vector<std::string> remapped;
            std::unordered_set<std::string> seen;
            for (const std::string &value : values)
            {
                const std::string node = remapNode(value);
                if (seen.insert(node).second)
                {
                    remapped.push_back(node);
                }
            }
            return remapped;
        };

        std::unordered_map<std::string, std::unordered_set<std::string>> remappedPointsTo;
        for (const std::pair<const std::string, std::unordered_set<std::string>> &entry : state.pointsTo)
        {
            const std::string key = remapNode(entry.first);
            std::unordered_set<std::string> &targets = remappedPointsTo[key];
            const std::unordered_set<std::string> remappedTargets = remapNodeSet(entry.second);
            targets.insert(remappedTargets.begin(), remappedTargets.end());
        }
        state.pointsTo.swap(remappedPointsTo);

        std::unordered_map<std::string, std::vector<DeferredLoadConstraint>> remappedLoadsByPointer;
        for (const std::pair<const std::string, std::vector<DeferredLoadConstraint>> &entry : state.loadsByPointer)
        {
            std::vector<DeferredLoadConstraint> &loads = remappedLoadsByPointer[remapNode(entry.first)];
            for (const DeferredLoadConstraint &constraint : entry.second)
            {
                loads.push_back(DeferredLoadConstraint{remapNode(constraint.dstNode)});
            }
        }
        state.loadsByPointer.swap(remappedLoadsByPointer);

        std::unordered_map<std::string, std::vector<DeferredStoreConstraint>> remappedStoresByPointer;
        for (const std::pair<const std::string, std::vector<DeferredStoreConstraint>> &entry : state.storesByPointer)
        {
            std::vector<DeferredStoreConstraint> &stores = remappedStoresByPointer[remapNode(entry.first)];
            for (const DeferredStoreConstraint &constraint : entry.second)
            {
                stores.push_back(DeferredStoreConstraint{remapNode(constraint.srcNode)});
            }
        }
        state.storesByPointer.swap(remappedStoresByPointer);

        std::unordered_map<std::string, std::vector<DeferredStoreSeed>> remappedStoreSeedTargetsByPointer;
        for (const std::pair<const std::string, std::vector<DeferredStoreSeed>> &entry : state.storeSeedTargetsByPointer)
        {
            std::vector<DeferredStoreSeed> &seeds = remappedStoreSeedTargetsByPointer[remapNode(entry.first)];
            for (const DeferredStoreSeed &constraint : entry.second)
            {
                seeds.push_back(DeferredStoreSeed{remapNode(constraint.target)});
            }
        }
        state.storeSeedTargetsByPointer.swap(remappedStoreSeedTargetsByPointer);

        std::unordered_map<std::string, std::vector<std::string>> remappedMemTransferDstBySrcPtr;
        for (const std::pair<const std::string, std::vector<std::string>> &entry : state.memTransferDstBySrcPtr)
        {
            remappedMemTransferDstBySrcPtr[remapNode(entry.first)] = remapVector(entry.second);
        }
        state.memTransferDstBySrcPtr.swap(remappedMemTransferDstBySrcPtr);

        std::unordered_map<std::string, std::vector<std::string>> remappedMemTransferSrcByDstPtr;
        for (const std::pair<const std::string, std::vector<std::string>> &entry : state.memTransferSrcByDstPtr)
        {
            remappedMemTransferSrcByDstPtr[remapNode(entry.first)] = remapVector(entry.second);
        }
        state.memTransferSrcByDstPtr.swap(remappedMemTransferSrcByDstPtr);

        std::unordered_map<std::string, std::vector<std::string>> remappedSparseValueFlowSucc;
        std::unordered_map<std::string, std::vector<std::string>> remappedSparseValueFlowPred;
        std::unordered_set<std::string> remappedSparseValueFlowEdgeKeys;
        for (const std::pair<const std::string, std::vector<std::string>> &entry : state.sparseValueFlowSucc)
        {
            const std::string src = remapNode(entry.first);
            std::vector<std::string> &succs = remappedSparseValueFlowSucc[src];
            for (const std::string &dstValue : entry.second)
            {
                const std::string dst = remapNode(dstValue);
                if (src == dst)
                {
                    continue;
                }

                const std::string edgeKey = src + "->" + dst;
                if (remappedSparseValueFlowEdgeKeys.insert(edgeKey).second)
                {
                    succs.push_back(dst);
                    remappedSparseValueFlowPred[dst].push_back(src);
                }
            }
        }
        state.sparseValueFlowSucc.swap(remappedSparseValueFlowSucc);
        state.sparseValueFlowPred.swap(remappedSparseValueFlowPred);
        state.sparseValueFlowEdgeKeys.swap(remappedSparseValueFlowEdgeKeys);

        std::unordered_set<std::string> remappedRelevantNodes;
        std::deque<std::string> remappedRelevantQueue;
        for (const std::string &node : state.relevantNodes)
        {
            const std::string remapped = remapNode(node);
            if (remappedRelevantNodes.insert(remapped).second)
            {
                remappedRelevantQueue.push_back(remapped);
            }
        }
        state.relevantNodes.swap(remappedRelevantNodes);
        state.relevantQueue.swap(remappedRelevantQueue);

        std::unordered_set<std::string> remappedInWorklist;
        std::deque<std::string> remappedWorklist;
        for (const std::string &node : state.worklist)
        {
            const std::string remapped = remapNode(node);
            if (remappedInWorklist.insert(remapped).second)
            {
                remappedWorklist.push_back(remapped);
            }
        }
        state.inWorklist.swap(remappedInWorklist);
        state.worklist.swap(remappedWorklist);
    }

    void collectResolvedCallEdges(
        const CallResolutionContext &context,
        std::vector<CallEdge> &resolvedEdges,
        std::vector<CallEdge> &unresolvedIndirect);

    /**
     * @brief Run a PAG/constraint based fixed-point pointer analysis and resolve calls from points-to.
     */
    void runPagConstraintAnalysis(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions,
        const std::set<std::string> &blacklistedFunctions,
        std::vector<CallEdge> &resolvedEdges,
        std::vector<CallEdge> &unresolvedIndirect)
    {
        std::unordered_map<std::string, const FunctionFacts *> functionMap;
        std::unordered_map<std::string, std::string> nodeRepresentativeByNode;
        std::unordered_map<std::string, std::vector<std::string>> parameterSlotsByFunction;
        std::unordered_map<std::string, std::unordered_set<std::string>> parameterSlotSetByFunction;
        std::unordered_set<std::string> linearFunctions;
        std::unordered_set<std::string> globalSlots;
        std::unordered_set<std::string> globalRoots;

        std::size_t totalAssignments = 0U;
        std::size_t totalCallSites = 0U;
        std::size_t totalBlocks = 0U;
        for (const FunctionFacts &function : functions)
        {
            totalAssignments += function.pointerAssignments.size();
            totalCallSites += function.callSites.size();
            totalBlocks += function.blocks.size();
        }

        functionMap.reserve(functions.size() * 2U + 1U);
        parameterSlotsByFunction.reserve(functions.size() * 2U + 1U);
        parameterSlotSetByFunction.reserve(functions.size() * 2U + 1U);
        linearFunctions.reserve(functions.size() * 2U + 1U);
        globalSlots.reserve(totalAssignments + 1U);
        globalRoots.reserve(totalAssignments + 1U);

        for (std::size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
        {
            const FunctionFacts &function = functions[functionIndex];
            logPagFunctionPhase("metadata", functionIndex, functions.size(), function);
            functionMap[function.name] = &function;
            parameterSlotsByFunction[function.name] = collectParameterSlots(function, knownFunctions);
            parameterSlotSetByFunction[function.name] =
                std::unordered_set<std::string>(parameterSlotsByFunction[function.name].begin(), parameterSlotsByFunction[function.name].end());

            std::unordered_map<std::uint32_t, std::size_t> predecessorCount;
            predecessorCount.reserve(function.blocks.size() * 2U + 1U);
            bool isLinearFunction = true;
            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                if (block.successors.size() > 1U)
                {
                    isLinearFunction = false;
                }

                for (std::uint32_t successor : block.successors)
                {
                    const std::size_t count = ++predecessorCount[successor];
                    if (count > 1U)
                    {
                        isLinearFunction = false;
                    }
                }
            }

            if (isLinearFunction)
            {
                linearFunctions.insert(function.name);
            }

            for (const PointerAssignment &assignment : function.pointerAssignments)
            {
                if (!assignment.lhsIsGlobal)
                {
                    continue;
                }

                const std::string lhsSlot = memorySlotFromExpression(assignment.lhsExpression);
                if (!lhsSlot.empty())
                {
                    globalSlots.insert(lhsSlot);
                    globalRoots.insert(memorySlotRoot(lhsSlot));
                }
            }
        }

        std::function<std::string(const std::string &)> normalizeGlobalKey =
            [](const std::string &slot)
        {
            std::string key = slot;
            const std::size_t scopePos = key.rfind("::");
            if (scopePos != std::string::npos)
            {
                key = key.substr(scopePos + 2U);
            }
            return trimLine(key);
        };

        std::function<std::string(const std::string &, const std::string &)> memoryNode =
            [&](const std::string &functionName, const std::string &slot)
        {
            if (slot.empty())
            {
                return std::string();
            }

            const std::string globalKey = normalizeGlobalKey(slot);
            const std::string root = memorySlotRoot(globalKey);
            if (globalRoots.find(root) != globalRoots.end() || globalSlots.find(globalKey) != globalSlots.end())
            {
                return "g::" + globalKey;
            }

            return functionName + "::" + globalKey;
        };

        std::function<std::string(const std::string &)> returnNode =
            [](const std::string &functionName)
        {
            return "ret::" + functionName;
        };

        std::function<bool(const std::string &)> isLikelyPointerIdentifier =
            [&](const std::string &identifier)
        {
            static const std::unordered_set<std::string> kIgnoredTokens = {
                "const", "volatile", "restrict", "signed", "unsigned", "short", "long",
                "int", "char", "float", "double", "void", "struct", "union", "enum", "sizeof",
                "return", "if", "else", "for", "while", "switch", "case", "default", "goto",
                "break", "continue", "static", "extern", "register", "inline", "typedef"};

            if (identifier.empty())
            {
                return false;
            }

            if (kIgnoredTokens.find(identifier) != kIgnoredTokens.end())
            {
                return false;
            }

            if (knownFunctions.find(identifier) != knownFunctions.end())
            {
                return false;
            }

            return true;
        };

        std::function<std::vector<std::string>(const std::string &)> collectExpressionSlots =
            [&](const std::string &expression)
        {
            std::vector<std::string> slots;
            std::unordered_set<std::string> seen;

            const std::string canonical = canonicalMemorySlot(expression);
            if (!canonical.empty() && isLikelyPointerIdentifier(canonical) && seen.insert(canonical).second)
            {
                slots.push_back(canonical);
            }

            const std::string fallbackCanonical = canonicalSlot(expression);
            if (!fallbackCanonical.empty() && isLikelyPointerIdentifier(fallbackCanonical) && seen.insert(fallbackCanonical).second)
            {
                slots.push_back(fallbackCanonical);
            }

            for (const std::string &identifier : extractIdentifiers(expression))
            {
                if (!isLikelyPointerIdentifier(identifier))
                {
                    continue;
                }

                if (seen.insert(identifier).second)
                {
                    slots.push_back(identifier);
                }
            }

            return slots;
        };

        std::unordered_set<std::string> pointerReturningFunctions;
        std::unordered_set<std::string> directPointerReturnFunctions;
        std::unordered_map<std::string, std::unordered_set<std::string>> returnDependenciesByFunction;
        pointerReturningFunctions.reserve(functions.size() * 2U + 1U);
        directPointerReturnFunctions.reserve(functions.size() * 2U + 1U);
        returnDependenciesByFunction.reserve(functions.size() * 2U + 1U);

        for (const FunctionFacts &function : functions)
        {
            if (function.hasReturnPointerMetadata)
            {
                if (function.returnsPointerLike)
                {
                    directPointerReturnFunctions.insert(function.name);
                }
                continue;
            }

            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                for (const std::string &line : block.lines)
                {
                    const std::optional<std::string> returnExpression = parseReturnExpressionFromLine(line);
                    if (!returnExpression.has_value())
                    {
                        continue;
                    }

                    const std::string returnedRaw = trimLine(*returnExpression);
                    if (returnedRaw.empty())
                    {
                        continue;
                    }

                    if (returnedRaw.find('&') != std::string::npos ||
                        !collectExpressionSlots(returnedRaw).empty())
                    {
                        directPointerReturnFunctions.insert(function.name);
                    }

                    const std::string returnedCallee = extractCallCalleeIdentifier(returnedRaw);
                    if (!returnedCallee.empty() && functionMap.find(returnedCallee) != functionMap.end())
                    {
                        returnDependenciesByFunction[function.name].insert(returnedCallee);
                    }

                    for (const std::string &identifier : extractIdentifiers(returnedRaw))
                    {
                        if (knownFunctions.find(identifier) != knownFunctions.end())
                        {
                            directPointerReturnFunctions.insert(function.name);
                            break;
                        }
                    }
                }
            }
        }

        bool changedPointerReturns = true;
        while (changedPointerReturns)
        {
            changedPointerReturns = false;
            for (const FunctionFacts &function : functions)
            {
                if (pointerReturningFunctions.find(function.name) != pointerReturningFunctions.end())
                {
                    continue;
                }

                if (directPointerReturnFunctions.find(function.name) != directPointerReturnFunctions.end())
                {
                    pointerReturningFunctions.insert(function.name);
                    changedPointerReturns = true;
                    continue;
                }

                const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator depsIt =
                    returnDependenciesByFunction.find(function.name);
                if (depsIt == returnDependenciesByFunction.end())
                {
                    continue;
                }

                for (const std::string &callee : depsIt->second)
                {
                    if (pointerReturningFunctions.find(callee) != pointerReturningFunctions.end())
                    {
                        pointerReturningFunctions.insert(function.name);
                        changedPointerReturns = true;
                        break;
                    }
                }
            }
        }

        std::unordered_set<std::string> functionPointerRelevantSlots;
        std::unordered_set<std::string> functionPointerRelevantRoots;
        std::unordered_set<std::string> functionPointerRelevantAncestors;
        functionPointerRelevantSlots.reserve((totalAssignments * 2U) + (totalCallSites * 4U) + 1U);
        functionPointerRelevantRoots.reserve(functions.size() * 4U + 1U);
        functionPointerRelevantAncestors.reserve((totalAssignments * 4U) + (totalCallSites * 6U) + 1U);

        std::function<void(const std::string &)> recordFunctionPointerRelevantSlot =
            [&](const std::string &slot)
        {
            const std::string normalized = normalizeGlobalKey(slot);
            if (normalized.empty() || !isLikelyPointerIdentifier(normalized))
            {
                return;
            }

            functionPointerRelevantSlots.insert(normalized);

            const std::string root = memorySlotRoot(normalized);
            if (!root.empty())
            {
                functionPointerRelevantRoots.insert(root);
            }

            for (const std::string &prefix : collectMemorySlotPrefixes(normalized))
            {
                functionPointerRelevantAncestors.insert(prefix);
            }
        };

        for (const FunctionFacts &function : functions)
        {
            for (const std::string &slot : collectPointerSlots(function))
            {
                recordFunctionPointerRelevantSlot(slot);
            }

            for (const PointerAssignment &assignment : function.pointerAssignments)
            {
                const std::string lhsSlot = memorySlotFromExpression(assignment.lhsExpression);
                if (!assignment.assignedFunction.empty() || assignment.rhsTakesFunctionAddress)
                {
                    recordFunctionPointerRelevantSlot(lhsSlot);
                    for (const std::string &slot : collectExpressionSlots(assignment.rhsExpression))
                    {
                        recordFunctionPointerRelevantSlot(slot);
                    }
                }

                for (const std::string &identifier : extractIdentifiers(assignment.rhsExpression))
                {
                    if (knownFunctions.find(identifier) != knownFunctions.end())
                    {
                        recordFunctionPointerRelevantSlot(lhsSlot);
                        break;
                    }
                }
            }

            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                for (const std::string &line : block.lines)
                {
                    const std::optional<std::string> returnExpression = parseReturnExpressionFromLine(line);
                    if (returnExpression.has_value() &&
                        pointerReturningFunctions.find(function.name) != pointerReturningFunctions.end())
                    {
                        for (const std::string &slot : collectExpressionSlots(*returnExpression))
                        {
                            recordFunctionPointerRelevantSlot(slot);
                        }
                    }

                    const std::optional<MemoryTransferOp> transferOp = parseMemoryTransferOpFromLine(line);
                    if (!transferOp.has_value())
                    {
                        continue;
                    }

                    for (const std::pair<std::string, std::string> &copyPair : transferOp->copyPairs)
                    {
                        for (const std::string &slot : collectExpressionSlots(copyPair.first))
                        {
                            recordFunctionPointerRelevantSlot(slot);
                        }
                        for (const std::string &slot : collectExpressionSlots(copyPair.second))
                        {
                            recordFunctionPointerRelevantSlot(slot);
                        }
                    }
                }
            }
        }

        std::function<bool(const std::string &)> isFunctionPointerRelevantSlot =
            [&](const std::string &slot)
        {
            const std::string normalized = normalizeGlobalKey(slot);
            if (normalized.empty())
            {
                return false;
            }

            if (functionPointerRelevantSlots.find(normalized) != functionPointerRelevantSlots.end() ||
                functionPointerRelevantAncestors.find(normalized) != functionPointerRelevantAncestors.end())
            {
                return true;
            }

            const std::string root = memorySlotRoot(normalized);
            return !root.empty() && functionPointerRelevantRoots.find(root) != functionPointerRelevantRoots.end();
        };

        std::unordered_set<std::string> aliasExpansionDemandSlots;
        aliasExpansionDemandSlots.reserve((totalCallSites * 4U) + totalAssignments + totalBlocks + 1U);
        std::function<void(const std::string &)> recordAliasExpansionDemand =
            [&](const std::string &slot)
        {
            const std::string normalized = normalizeGlobalKey(slot);
            if (normalized.empty() || !isFunctionPointerRelevantSlot(normalized))
            {
                return;
            }

            aliasExpansionDemandSlots.insert(normalized);
            const std::string root = memorySlotRoot(normalized);
            if (!root.empty())
            {
                aliasExpansionDemandSlots.insert(root);
            }
        };

        for (const FunctionFacts &function : functions)
        {
            for (const CallSite &callSite : function.callSites)
            {
                if (callSite.directCallee.empty())
                {
                    recordAliasExpansionDemand(memorySlotFromExpression(callSite.throughIdentifier));
                    recordAliasExpansionDemand(memorySlotFromExpression(callSite.calleeExpression));
                }
            }

            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                for (const std::string &line : block.lines)
                {
                    const std::optional<MemoryTransferOp> transferOp = parseMemoryTransferOpFromLine(line);
                    if (!transferOp.has_value())
                    {
                        continue;
                    }

                    for (const std::string &clearDestination : transferOp->clearDestinations)
                    {
                        for (const std::string &slot : collectExpressionSlots(clearDestination))
                        {
                            recordAliasExpansionDemand(slot);
                        }
                    }

                    for (const std::pair<std::string, std::string> &copyPair : transferOp->copyPairs)
                    {
                        for (const std::string &slot : collectExpressionSlots(copyPair.second))
                        {
                            recordAliasExpansionDemand(slot);
                        }
                    }
                }
            }
        }

        std::unordered_map<std::string, std::vector<std::string>> aliasExpansionCache;
        aliasExpansionCache.reserve(aliasExpansionDemandSlots.size() * 2U + 1U);
        std::function<const std::vector<std::string> &(const std::string &)> getExpandedMemorySlotAliases =
            [&](const std::string &slot) -> const std::vector<std::string> &
        {
            const std::unordered_map<std::string, std::vector<std::string>>::iterator cachedIt =
                aliasExpansionCache.find(slot);
            if (cachedIt != aliasExpansionCache.end())
            {
                return cachedIt->second;
            }

            return aliasExpansionCache.emplace(slot, expandMemorySlotAliases(slot)).first->second;
        };

        std::unordered_set<std::string> trackedMemorySlots;
        std::unordered_set<std::string> addressTakenTrackedSlots;
        std::unordered_map<std::string, std::unordered_set<std::string>> referencedFunctionsBySlot;
        trackedMemorySlots.reserve((totalAssignments * 4U) + (totalCallSites * 4U) + 1U);
        addressTakenTrackedSlots.reserve(totalAssignments + totalCallSites + 1U);
        referencedFunctionsBySlot.reserve((totalAssignments * 4U) + (totalCallSites * 4U) + 1U);
        std::function<void(const std::string &, const std::string &)> recordTrackedSlot =
            [&](const std::string &slot, const std::string &functionName)
        {
            const std::string normalized = normalizeGlobalKey(slot);
            if (normalized.empty() || !isLikelyPointerIdentifier(normalized) ||
                !isFunctionPointerRelevantSlot(normalized))
            {
                return;
            }

            std::vector<std::string> aliasesToRecord;
            aliasesToRecord.push_back(normalized);
            const std::string root = memorySlotRoot(normalized);
            if (!root.empty() && root != normalized)
            {
                aliasesToRecord.push_back(root);
            }

            if (aliasExpansionDemandSlots.find(normalized) != aliasExpansionDemandSlots.end() ||
                (!root.empty() && aliasExpansionDemandSlots.find(root) != aliasExpansionDemandSlots.end()))
            {
                aliasesToRecord = getExpandedMemorySlotAliases(normalized);
            }

            for (const std::string &alias : aliasesToRecord)
            {
                const std::string aliasKey = normalizeGlobalKey(alias);
                if (!aliasKey.empty() && isLikelyPointerIdentifier(aliasKey))
                {
                    trackedMemorySlots.insert(aliasKey);
                    if (!functionName.empty())
                    {
                        referencedFunctionsBySlot[aliasKey].insert(functionName);
                    }
                }
            }
        };

        for (std::size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
        {
            const FunctionFacts &function = functions[functionIndex];
            logPagFunctionPhase("track-slots", functionIndex, functions.size(), function);
            for (const PointerAssignment &assignment : function.pointerAssignments)
            {
                recordTrackedSlot(memorySlotFromExpression(assignment.lhsExpression), function.name);
                for (const std::string &slot : collectExpressionSlots(assignment.rhsExpression))
                {
                    recordTrackedSlot(slot, function.name);
                }
                if (!assignment.rhsExpression.empty() && trimLine(assignment.rhsExpression).front() == '&')
                {
                    const std::string takenSlot = memorySlotFromExpression(assignment.rhsExpression);
                    if (!takenSlot.empty())
                    {
                        addressTakenTrackedSlots.insert(normalizeGlobalKey(takenSlot));
                    }
                }
            }

            for (const StructMemberMapping &mapping : function.structMemberMappings)
            {
                recordTrackedSlot(mapping.structVariable, function.name);
                if (!mapping.memberName.empty())
                {
                    recordTrackedSlot(mapping.structVariable + "." + mapping.memberName, function.name);
                }
            }

            for (const CallSite &callSite : function.callSites)
            {
                recordTrackedSlot(memorySlotFromExpression(callSite.throughIdentifier), function.name);
                recordTrackedSlot(memorySlotFromExpression(callSite.calleeExpression), function.name);
                for (const std::string &argumentExpression : callSite.argumentExpressions)
                {
                    for (const std::string &slot : collectExpressionSlots(argumentExpression))
                    {
                        recordTrackedSlot(slot, function.name);
                    }

                    const std::string trimmedArgument = trimLine(argumentExpression);
                    if (!trimmedArgument.empty() && trimmedArgument.front() == '&')
                    {
                        const std::string takenSlot = memorySlotFromExpression(argumentExpression);
                        if (!takenSlot.empty())
                        {
                            addressTakenTrackedSlots.insert(normalizeGlobalKey(takenSlot));
                        }
                    }
                }
            }

            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                for (const std::string &line : block.lines)
                {
                    const std::optional<std::string> returnExpression = parseReturnExpressionFromLine(line);
                    if (returnExpression.has_value() &&
                        pointerReturningFunctions.find(function.name) != pointerReturningFunctions.end())
                    {
                        for (const std::string &slot : collectExpressionSlots(*returnExpression))
                        {
                            recordTrackedSlot(slot, function.name);
                        }
                    }

                    const std::optional<MemoryTransferOp> transferOp = parseMemoryTransferOpFromLine(line);
                    if (!transferOp.has_value())
                    {
                        continue;
                    }

                    for (const std::string &clearDestination : transferOp->clearDestinations)
                    {
                        for (const std::string &slot : collectExpressionSlots(clearDestination))
                        {
                            recordTrackedSlot(slot, function.name);
                        }
                    }

                    for (const std::pair<std::string, std::string> &copyPair : transferOp->copyPairs)
                    {
                        for (const std::string &slot : collectExpressionSlots(copyPair.first))
                        {
                            recordTrackedSlot(slot, function.name);
                        }
                        for (const std::string &slot : collectExpressionSlots(copyPair.second))
                        {
                            recordTrackedSlot(slot, function.name);
                        }
                    }
                }
            }
        }

        aliasExpansionDemandSlots.clear();
        aliasExpansionDemandSlots.rehash(0);

        std::unordered_map<std::string, std::vector<std::string>> descendantSlotsByAncestor;
        for (const std::string &slot : trackedMemorySlots)
        {
            for (const std::string &prefix : collectMemorySlotPrefixes(slot))
            {
                if (prefix != slot)
                {
                    descendantSlotsByAncestor[prefix].push_back(slot);
                }
            }
        }

        std::function<std::string(const std::string &, const std::string &)> abstractMemoryObject =
            [&](const std::string &functionName, const std::string &slot)
        {
            std::string key = normalizeGlobalKey(slot);

            const std::string root = memorySlotRoot(key);
            const bool isGlobal = globalRoots.find(root) != globalRoots.end() || globalSlots.find(key) != globalSlots.end();
            const bool isParam =
                parameterSlotSetByFunction.find(functionName) != parameterSlotSetByFunction.end() &&
                (parameterSlotSetByFunction[functionName].find(key) != parameterSlotSetByFunction[functionName].end() ||
                 parameterSlotSetByFunction[functionName].find(root) != parameterSlotSetByFunction[functionName].end());

            std::string region;
            if (isGlobal)
            {
                region = "g";
            }
            else if (isParam)
            {
                region = "p:" + functionName;
            }
            else
            {
                region = "l:" + functionName;
            }

            return "obj:" + region + ":" + key;
        };

        std::function<std::string(const std::string &, const std::string &)> addressTakenStorageNode =
            [&](const std::string &functionName, const std::string &slot)
        {
            const std::string normalized = normalizeGlobalKey(slot);
            if (normalized.empty())
            {
                return std::string();
            }

            const std::string root = memorySlotRoot(normalized);
            if (addressTakenTrackedSlots.find(normalized) == addressTakenTrackedSlots.end() &&
                (root.empty() || addressTakenTrackedSlots.find(root) == addressTakenTrackedSlots.end()))
            {
                return std::string();
            }

            return abstractMemoryObject(functionName, normalized);
        };

        std::unordered_map<CallSiteId, std::pair<const FunctionFacts *, const CallSite *>> callSiteById;
        callSiteById.reserve(totalCallSites * 2U + 1U);
        for (const FunctionFacts &function : functions)
        {
            for (const CallSite &callSite : function.callSites)
            {
                if (callSite.callSiteId == kInvalidCallSiteId)
                {
                    continue;
                }
                callSiteById[callSite.callSiteId] = std::make_pair(&function, &callSite);
            }
        }

        std::unordered_map<CallSiteId, std::vector<std::string>> callSiteReturnReceiverSlots;
        callSiteReturnReceiverSlots.reserve(totalCallSites * 2U + 1U);
        std::unordered_map<CallSiteId, std::vector<std::string>> probeNodesByCallSiteId;
        probeNodesByCallSiteId.reserve(totalCallSites * 2U + 1U);
        std::function<std::optional<std::string>(const std::string &)> parseAssignedLhsSlotFromLine =
            [&](const std::string &rawLine) -> std::optional<std::string>
        {
            std::string line = trimLine(rawLine);
            const std::size_t equalIndex = line.find('=');
            if (equalIndex == std::string::npos)
            {
                return std::nullopt;
            }

            if ((equalIndex > 0U && line[equalIndex - 1U] == '=') ||
                (equalIndex + 1U < line.size() && line[equalIndex + 1U] == '='))
            {
                return std::nullopt;
            }

            const std::string lhs = trimLine(line.substr(0U, equalIndex));
            const std::string slot = memorySlotFromExpression(lhs);
            if (slot.empty())
            {
                return std::nullopt;
            }

            return slot;
        };

        for (const FunctionFacts &function : functions)
        {
            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                const std::size_t lineCount = std::min(block.lines.size(), block.lineCallSiteIds.size());
                for (std::size_t lineIndex = 0; lineIndex < lineCount; ++lineIndex)
                {
                    const std::vector<CallSiteId> &lineCallSiteIds = block.lineCallSiteIds[lineIndex];
                    if (lineCallSiteIds.empty())
                    {
                        continue;
                    }

                    const std::optional<std::string> lhsSlot = parseAssignedLhsSlotFromLine(block.lines[lineIndex]);
                    if (!lhsSlot.has_value())
                    {
                        continue;
                    }

                    for (const CallSiteId callSiteId : lineCallSiteIds)
                    {
                        if (callSiteId == kInvalidCallSiteId)
                        {
                            continue;
                        }
                        callSiteReturnReceiverSlots[callSiteId].push_back(*lhsSlot);
                    }
                }
            }
        }

        std::unordered_map<CallSiteId, std::set<std::string>> stitchedIndirectCalleesByCallSite;
        stitchedIndirectCalleesByCallSite.reserve(totalCallSites * 2U + 1U);

        std::unordered_map<std::string, std::vector<std::string>> directCalleesByFunction;
        std::unordered_map<std::string, std::vector<CallSiteId>> indirectCallSiteIdsByFunction;
        std::unordered_map<std::string, std::size_t> directIncomingCountByFunction;
        directCalleesByFunction.reserve(functions.size() * 2U + 1U);
        indirectCallSiteIdsByFunction.reserve(functions.size() * 2U + 1U);
        directIncomingCountByFunction.reserve(functions.size() * 2U + 1U);

        for (const FunctionFacts &function : functions)
        {
            directIncomingCountByFunction.emplace(function.name, 0U);
        }

        for (const FunctionFacts &function : functions)
        {
            std::vector<std::string> directCallees;
            std::vector<CallSiteId> indirectCallSites;

            for (const CallSite &callSite : function.callSites)
            {
                if (!callSite.directCallee.empty())
                {
                    if (functionMap.find(callSite.directCallee) != functionMap.end() &&
                        !isBlacklistedFunction(callSite.directCallee, blacklistedFunctions))
                    {
                        directCallees.push_back(callSite.directCallee);
                        std::unordered_map<std::string, std::size_t>::iterator incomingIt =
                            directIncomingCountByFunction.find(callSite.directCallee);
                        if (incomingIt != directIncomingCountByFunction.end())
                        {
                            ++incomingIt->second;
                        }
                    }
                }
                else if (callSite.callSiteId != kInvalidCallSiteId)
                {
                    indirectCallSites.push_back(callSite.callSiteId);
                }
            }

            if (!directCallees.empty())
            {
                directCalleesByFunction[function.name] = std::move(directCallees);
            }
            if (!indirectCallSites.empty())
            {
                indirectCallSiteIdsByFunction[function.name] = std::move(indirectCallSites);
            }
        }

        std::function<std::unordered_set<std::string>()> computeActiveFunctionNames = [&]()
        {
            std::unordered_set<std::string> active;
            active.reserve(functions.size() * 2U + 1U);

            std::deque<std::string> queue;
            if (functionMap.find("main") != functionMap.end())
            {
                active.insert("main");
                queue.push_back("main");
            }
            else
            {
                for (const FunctionFacts &function : functions)
                {
                    const std::unordered_map<std::string, std::size_t>::const_iterator incomingIt =
                        directIncomingCountByFunction.find(function.name);
                    if (incomingIt != directIncomingCountByFunction.end() && incomingIt->second == 0U)
                    {
                        if (active.insert(function.name).second)
                        {
                            queue.push_back(function.name);
                        }
                    }
                }
            }

            if (queue.empty() && !functions.empty())
            {
                active.insert(functions.front().name);
                queue.push_back(functions.front().name);
            }

            while (!queue.empty())
            {
                const std::string current = queue.front();
                queue.pop_front();

                const std::unordered_map<std::string, std::vector<std::string>>::const_iterator directIt =
                    directCalleesByFunction.find(current);
                if (directIt != directCalleesByFunction.end())
                {
                    for (const std::string &callee : directIt->second)
                    {
                        if (active.insert(callee).second)
                        {
                            queue.push_back(callee);
                        }
                    }
                }

                const std::unordered_map<std::string, std::vector<CallSiteId>>::const_iterator indirectIt =
                    indirectCallSiteIdsByFunction.find(current);
                if (indirectIt != indirectCallSiteIdsByFunction.end())
                {
                    for (const CallSiteId callSiteId : indirectIt->second)
                    {
                        const std::unordered_map<CallSiteId, std::set<std::string>>::const_iterator targetsIt =
                            stitchedIndirectCalleesByCallSite.find(callSiteId);
                        if (targetsIt == stitchedIndirectCalleesByCallSite.end())
                        {
                            continue;
                        }

                        for (const std::string &callee : targetsIt->second)
                        {
                            if (functionMap.find(callee) != functionMap.end() &&
                                active.insert(callee).second)
                            {
                                queue.push_back(callee);
                            }
                        }
                    }
                }
            }

            if (active.empty())
            {
                for (const FunctionFacts &function : functions)
                {
                    active.insert(function.name);
                }
            }

            return active;
        };

        constexpr std::size_t kMaxOnTheFlySolveIterations = 8U;
        std::size_t onTheFlySolveIteration = 0U;
        bool discoveredNewIndirectEdges = false;

        do
        {
            ++onTheFlySolveIteration;
            resolvedEdges.clear();
            unresolvedIndirect.clear();

            const std::unordered_set<std::string> activeFunctionNames = computeActiveFunctionNames();

            PagConstraintState state;
            std::unordered_map<std::string, std::unordered_set<std::string>> &pointsTo = state.pointsTo;
            std::unordered_map<std::string, std::vector<DeferredLoadConstraint>> &loadsByPointer = state.loadsByPointer;
            std::unordered_map<std::string, std::vector<DeferredStoreConstraint>> &storesByPointer = state.storesByPointer;
            std::unordered_map<std::string, std::vector<DeferredStoreSeed>> &storeSeedTargetsByPointer = state.storeSeedTargetsByPointer;
            std::unordered_map<std::string, std::vector<std::string>> &memTransferDstBySrcPtr = state.memTransferDstBySrcPtr;
            std::unordered_map<std::string, std::vector<std::string>> &memTransferSrcByDstPtr = state.memTransferSrcByDstPtr;
            std::unordered_map<std::string, std::vector<std::string>> &sparseValueFlowSucc = state.sparseValueFlowSucc;
            std::unordered_map<std::string, std::vector<std::string>> &sparseValueFlowPred = state.sparseValueFlowPred;
            std::unordered_set<std::string> &sparseValueFlowEdgeKeys = state.sparseValueFlowEdgeKeys;
            std::deque<std::string> &worklist = state.worklist;
            std::unordered_set<std::string> &inWorklist = state.inWorklist;
            std::unordered_set<std::string> &relevantNodes = state.relevantNodes;
            std::deque<std::string> &relevantQueue = state.relevantQueue;

            std::unordered_set<std::string> memTransferSrcDstEdgeKeys;
            std::unordered_set<std::string> memTransferDstSrcEdgeKeys;

            const std::size_t estimatedPagNodes =
                (trackedMemorySlots.size() * 3U) + functions.size() + totalCallSites + totalAssignments + 1U;
            state.reserve(estimatedPagNodes, trackedMemorySlots.size());
            memTransferSrcDstEdgeKeys.reserve(trackedMemorySlots.size() * 4U + 1U);
            memTransferDstSrcEdgeKeys.reserve(trackedMemorySlots.size() * 4U + 1U);

            std::function<std::size_t(const std::string &)> countLeadingDereferences =
                [](const std::string &expression)
            {
                const std::string trimmed = trimLine(expression);
                std::size_t depth = 0U;
                while (depth < trimmed.size() && trimmed[depth] == '*')
                {
                    ++depth;
                }
                return depth;
            };

            std::size_t syntheticPagNodeCounter = 0U;
            std::function<std::string(const std::string &, const std::string &)> makeSyntheticPagNode =
                [&](const std::string &functionName, const std::string &tag)
            {
                return functionName + "::$pag." + tag + "." + std::to_string(++syntheticPagNodeCounter);
            };

            std::function<std::string(const std::string &)> slotFromAbstractObject =
                [&](const std::string &target)
            {
                if (target.rfind("obj:", 0U) != 0U)
                {
                    return std::string();
                }

                const std::size_t split = target.rfind(':');
                if (split == std::string::npos || split + 1U >= target.size())
                {
                    return std::string();
                }

                return normalizeGlobalKey(target.substr(split + 1U));
            };

            std::function<std::vector<std::string>(const std::string &, const std::string &)> collectCandidateMemoryNodes =
                [&](const std::string &functionName, const std::string &slot)
            {
                std::vector<std::string> nodes;
                std::unordered_set<std::string> seen;

                const std::string normalized = normalizeGlobalKey(slot);
                if (normalized.empty() || !isFunctionPointerRelevantSlot(normalized))
                {
                    return nodes;
                }

                std::function<void(const std::string &)> addNode = [&](const std::string &node)
                {
                    if (!node.empty() && seen.insert(node).second)
                    {
                        nodes.push_back(node);
                    }
                };

                addNode(memoryNode(functionName, normalized));
                addNode(addressTakenStorageNode(functionName, normalized));

                const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator refsIt =
                    referencedFunctionsBySlot.find(normalized);
                const std::string root = memorySlotRoot(normalized);
                const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator rootRefsIt =
                    referencedFunctionsBySlot.find(root);
                const bool sharedAcrossFunctions =
                    (refsIt != referencedFunctionsBySlot.end() && refsIt->second.size() > 1U) ||
                    (!root.empty() && rootRefsIt != referencedFunctionsBySlot.end() && rootRefsIt->second.size() > 1U);
                const bool sharedAddressTakenSlot =
                    addressTakenTrackedSlots.find(normalized) != addressTakenTrackedSlots.end() ||
                    (!root.empty() && addressTakenTrackedSlots.find(root) != addressTakenTrackedSlots.end());
                if (sharedAcrossFunctions &&
                    (normalized.find('.') != std::string::npos ||
                     normalized.find('[') != std::string::npos ||
                     sharedAddressTakenSlot))
                {
                    addNode("g::" + normalized);
                }

                return nodes;
            };

            std::function<bool(const std::string &, const std::string &)> canStrongUpdateSlot =
                [&](const std::string &functionName, const std::string &slot)
            {
                const std::string normalized = normalizeGlobalKey(slot);
                if (normalized.empty() ||
                    normalized.find("[*]") != std::string::npos ||
                    linearFunctions.find(functionName) == linearFunctions.end())
                {
                    return false;
                }

                const std::string root = memorySlotRoot(normalized);
                if (globalRoots.find(root) != globalRoots.end() || globalSlots.find(normalized) != globalSlots.end())
                {
                    return false;
                }

                const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator paramsIt =
                    parameterSlotSetByFunction.find(functionName);
                if (paramsIt != parameterSlotSetByFunction.end() &&
                    (paramsIt->second.find(normalized) != paramsIt->second.end() ||
                     paramsIt->second.find(root) != paramsIt->second.end()))
                {
                    return false;
                }

                return true;
            };

            std::function<void(const std::string &, const std::string &, const std::string &)> strongSeedSlotTarget =
                [&](const std::string &functionName, const std::string &slot, const std::string &target)
            {
                if (!canStrongUpdateSlot(functionName, slot))
                {
                    for (const std::string &node : collectCandidateMemoryNodes(functionName, slot))
                    {
                        state.addPointsTo(node, target);
                    }
                    return;
                }

                const std::string expectedValueNode = memoryNode(functionName, normalizeGlobalKey(slot));
                const std::string expectedStorageNode = addressTakenStorageNode(functionName, normalizeGlobalKey(slot));
                for (const std::string &node : collectCandidateMemoryNodes(functionName, slot))
                {
                    if (node == expectedValueNode || (!expectedStorageNode.empty() && node == expectedStorageNode))
                    {
                        state.overwritePointsToSingleton(node, target);
                    }
                    else
                    {
                        state.addPointsTo(node, target);
                    }
                }
            };

            std::function<void(const std::string &, const std::string &, const std::string &)> seedSlotTarget =
                [&](const std::string &functionName, const std::string &slot, const std::string &target)
            {
                if (!isFunctionPointerRelevantSlot(slot))
                {
                    return;
                }

                for (const std::string &node : collectCandidateMemoryNodes(functionName, slot))
                {
                    state.addPointsTo(node, target);
                }
            };

            std::function<void(const std::string &, const std::string &, const std::string &)> copyIntoSlot =
                [&](const std::string &functionName, const std::string &slot, const std::string &srcNode)
            {
                if (!isFunctionPointerRelevantSlot(slot))
                {
                    return;
                }

                for (const std::string &node : collectCandidateMemoryNodes(functionName, slot))
                {
                    state.addCopyEdge(srcNode, node);
                }
            };

            // SVF-style: Add field collapse edges (root <-> member bidirectional).
            std::function<void(const std::string &, const std::string &)> addFieldCollapseEdges =
                [&](const std::string &functionName, const std::string &slot)
            {
                const std::string normalized = normalizeGlobalKey(slot);
                if (normalized.empty())
                {
                    return;
                }

                const std::string root = memorySlotRoot(normalized);
                if (root.empty() || root == normalized)
                {
                    return;
                }

                if (!isFunctionPointerRelevantSlot(normalized) && !isFunctionPointerRelevantSlot(root))
                {
                    return;
                }

                const std::vector<std::string> rootNodes = collectCandidateMemoryNodes(functionName, root);
                const std::vector<std::string> memberNodes = collectCandidateMemoryNodes(functionName, normalized);
                for (const std::string &rootNode : rootNodes)
                {
                    for (const std::string &memberNode : memberNodes)
                    {
                        state.addCopyEdge(rootNode, memberNode);
                        state.addCopyEdge(memberNode, rootNode);
                    }
                }
            };

            for (std::size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
            {
                const FunctionFacts &function = functions[functionIndex];
                if (activeFunctionNames.find(function.name) == activeFunctionNames.end())
                {
                    continue;
                }
                for (const std::string &slot : trackedMemorySlots)
                {
                    addFieldCollapseEdges(function.name, slot);
                }
            }

            // Second pass: add field collapse edges again for comprehensive bidirectional coverage
            for (const FunctionFacts &function : functions)
            {
                if (activeFunctionNames.find(function.name) == activeFunctionNames.end())
                {
                    continue;
                }
                for (const std::string &slot : trackedMemorySlots)
                {
                    addFieldCollapseEdges(function.name, slot);
                }
            }

            std::function<std::vector<std::string>(const std::string &, const std::string &)> collectPointeeAccessSlots =
                [&](const std::string &functionName, const std::string &slot)
            {
                std::vector<std::string> resolvedSlots;
                std::unordered_set<std::string> seen;

                const std::string normalized = normalizeGlobalKey(slot);
                if (normalized.empty())
                {
                    return resolvedSlots;
                }

                const std::string root = memorySlotRoot(normalized);
                if (root.empty() || root == normalized)
                {
                    return resolvedSlots;
                }

                const std::string node = memoryNode(functionName, root);
                if (node.empty())
                {
                    return resolvedSlots;
                }

                const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator ptIt =
                    pointsTo.find(node);
                if (ptIt == pointsTo.end())
                {
                    return resolvedSlots;
                }

                const std::string suffix = normalized.substr(root.size());
                for (const std::string &target : ptIt->second)
                {
                    const std::string pointeeSlot = slotFromAbstractObject(target);
                    if (pointeeSlot.empty())
                    {
                        continue;
                    }

                    const std::string resolvedSlot = pointeeSlot + suffix;
                    if (seen.insert(resolvedSlot).second)
                    {
                        resolvedSlots.push_back(resolvedSlot);
                    }
                }

                return resolvedSlots;
            };

            std::function<SmallStringList(const std::unordered_set<std::string> &)> resolveFunctionTargetsTransitively =
                [&](const std::unordered_set<std::string> &initialTargets)
            {
                SmallStringList resolvedFunctions;
                std::deque<std::string> pending(initialTargets.begin(), initialTargets.end());
                std::unordered_set<std::string> visited(initialTargets.begin(), initialTargets.end());

                while (!pending.empty())
                {
                    const std::string current = pending.front();
                    pending.pop_front();

                    if (current.rfind("fn:", 0U) == 0U)
                    {
                        const std::string callee = current.substr(3U);
                        if (knownFunctions.find(callee) != knownFunctions.end() &&
                            !isBlacklistedFunction(callee, blacklistedFunctions))
                        {
                            appendUnique(resolvedFunctions, callee);
                        }
                        continue;
                    }

                    const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator nextIt =
                        pointsTo.find(current);
                    if (nextIt == pointsTo.end())
                    {
                        continue;
                    }

                    for (const std::string &next : nextIt->second)
                    {
                        if (visited.insert(next).second)
                        {
                            pending.push_back(next);
                        }
                    }
                }

                return resolvedFunctions;
            };

            std::function<void(const std::string &, const std::string &)> addDeferredLoadConstraint =
                [&](const std::string &ptrNode, const std::string &dstNode)
            {
                if (ptrNode.empty() || dstNode.empty())
                {
                    return;
                }

                DeferredLoadConstraint deferredLoad;
                deferredLoad.dstNode = dstNode;
                loadsByPointer[ptrNode].push_back(deferredLoad);
                state.markRelevant(ptrNode);
                state.markRelevant(dstNode);
            };

            std::function<void(const std::string &, const std::string &)> addDeferredStoreConstraint =
                [&](const std::string &ptrNode, const std::string &srcNode)
            {
                if (ptrNode.empty() || srcNode.empty())
                {
                    return;
                }

                DeferredStoreConstraint deferredStore;
                deferredStore.srcNode = srcNode;
                storesByPointer[ptrNode].push_back(deferredStore);
                state.markRelevant(ptrNode);
                state.markRelevant(srcNode);
            };

            std::function<void(const std::string &, const std::string &)> addDeferredStoreSeedConstraint =
                [&](const std::string &ptrNode, const std::string &target)
            {
                if (ptrNode.empty() || target.empty())
                {
                    return;
                }

                DeferredStoreSeed storeSeed;
                storeSeed.target = target;
                storeSeedTargetsByPointer[ptrNode].push_back(storeSeed);
                state.markRelevant(ptrNode);
            };

            std::function<std::string(const std::string &, const std::string &, std::size_t)> materializeDerefPrefixNode =
                [&](const std::string &functionName, const std::string &baseNode, std::size_t dereferenceDepth)
            {
                if (baseNode.empty() || dereferenceDepth == 0U)
                {
                    return std::string();
                }

                std::string currentNode = baseNode;
                for (std::size_t depth = 1; depth < dereferenceDepth; ++depth)
                {
                    const std::string tempNode = makeSyntheticPagNode(functionName, "deref");
                    addDeferredLoadConstraint(currentNode, tempNode);
                    currentNode = tempNode;
                }

                return currentNode;
            };

            std::function<std::set<std::string>(const std::string &, const std::vector<std::string> &)> expandMemcpyDestinationSlots =
                [&](const std::string &functionName, const std::vector<std::string> &initialSlots)
            {
                std::set<std::string> expandedSlots;
                std::deque<std::string> pending;

                std::function<void(const std::string &)> enqueueSlot = [&](const std::string &slot)
                {
                    const std::string normalized = normalizeGlobalKey(slot);
                    if (normalized.empty() ||
                        isIntegerBinding(normalized) ||
                        knownFunctions.find(normalized) != knownFunctions.end() ||
                        !isLikelyPointerIdentifier(normalized))
                    {
                        return;
                    }

                    if (expandedSlots.insert(normalized).second)
                    {
                        pending.push_back(normalized);
                    }
                };

                std::function<void(const std::string &)> enqueuePointeeAliases = [&](const std::string &slot)
                {
                    const std::string node = memoryNode(functionName, slot);
                    if (node.empty())
                    {
                        return;
                    }

                    const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator ptIt =
                        pointsTo.find(node);
                    if (ptIt == pointsTo.end())
                    {
                        return;
                    }

                    for (const std::string &target : ptIt->second)
                    {
                        const std::string pointeeSlot = slotFromAbstractObject(target);
                        if (!pointeeSlot.empty())
                        {
                            enqueueSlot(pointeeSlot);
                        }
                    }
                };

                for (const std::string &slot : initialSlots)
                {
                    enqueueSlot(slot);
                }

                while (!pending.empty())
                {
                    const std::string current = pending.front();
                    pending.pop_front();

                    for (const std::string &alias : getExpandedMemorySlotAliases(current))
                    {
                        enqueueSlot(alias);
                    }

                    const std::unordered_map<std::string, std::vector<std::string>>::const_iterator descendantsIt =
                        descendantSlotsByAncestor.find(current);
                    if (descendantsIt != descendantSlotsByAncestor.end())
                    {
                        for (const std::string &descendant : descendantsIt->second)
                        {
                            enqueueSlot(descendant);
                        }
                    }

                    enqueuePointeeAliases(current);
                }

                return expandedSlots;
            };

            std::function<std::vector<std::string>(const std::vector<std::string> &, const std::set<std::string> &, const std::string &)> collectMemcpySourceSlots =
                [&](const std::vector<std::string> &initialSrcSlots,
                    const std::set<std::string> &expandedDstSlots,
                    const std::string &expandedDstSlot)
            {
                std::vector<std::string> resolvedSrcSlots;
                std::unordered_set<std::string> seen;

                std::function<void(const std::string &)> addSourceSlot = [&](const std::string &slot)
                {
                    const std::string normalized = normalizeGlobalKey(slot);
                    if (normalized.empty())
                    {
                        return;
                    }

                    if (seen.insert(normalized).second)
                    {
                        resolvedSrcSlots.push_back(normalized);
                    }
                };

                for (const std::string &srcSlot : initialSrcSlots)
                {
                    addSourceSlot(srcSlot);
                }

                for (const std::string &dstBaseSlot : expandedDstSlots)
                {
                    const std::string normalizedDstBase = normalizeGlobalKey(dstBaseSlot);
                    if (normalizedDstBase.empty() ||
                        expandedDstSlot == normalizedDstBase ||
                        expandedDstSlot.rfind(normalizedDstBase, 0U) != 0U)
                    {
                        continue;
                    }

                    const std::string suffix = expandedDstSlot.substr(normalizedDstBase.size());
                    if (suffix.empty())
                    {
                        continue;
                    }

                    for (const std::string &srcSlot : initialSrcSlots)
                    {
                        const std::string normalizedSrc = normalizeGlobalKey(srcSlot);
                        const std::string mappedSrcSlot = normalizedSrc + suffix;
                        if (trackedMemorySlots.find(mappedSrcSlot) != trackedMemorySlots.end())
                        {
                            addSourceSlot(mappedSrcSlot);
                        }
                    }
                }

                return resolvedSrcSlots;
            };

            std::function<void(const FunctionFacts &, const CallSite &, const std::string &)> seedCallArgumentsToCallee =
                [&](const FunctionFacts &caller, const CallSite &callSite, const std::string &calleeName)
            {
                if (calleeName.empty())
                {
                    return;
                }

                const std::unordered_map<std::string, const FunctionFacts *>::const_iterator calleeIt =
                    functionMap.find(calleeName);
                if (calleeIt == functionMap.end())
                {
                    return;
                }

                const std::vector<std::string> &calleeParams = parameterSlotsByFunction[calleeName];
                const std::size_t limit = std::min(calleeParams.size(), callSite.argumentExpressions.size());
                for (std::size_t i = 0; i < limit; ++i)
                {
                    const std::vector<std::string> dstNodes =
                        collectCandidateMemoryNodes(calleeName, calleeParams[i]);
                    if (dstNodes.empty())
                    {
                        continue;
                    }

                    const std::string argumentRaw = trimLine(callSite.argumentExpressions[i]);
                    const std::string argSlot = memorySlotFromExpression(callSite.argumentExpressions[i]);
                    const bool passesAddress =
                        !argumentRaw.empty() &&
                        argumentRaw.front() == '&' &&
                        !argSlot.empty() &&
                        knownFunctions.find(argSlot) == knownFunctions.end();
                    if (passesAddress)
                    {
                        seedSlotTarget(calleeName, calleeParams[i], abstractMemoryObject(caller.name, argSlot));
                    }
                    else if (!argSlot.empty())
                    {
                        const std::string srcNode = memoryNode(caller.name, argSlot);
                        copyIntoSlot(calleeName, calleeParams[i], srcNode);
                    }

                    for (const std::string &identifier : extractIdentifiers(callSite.argumentExpressions[i]))
                    {
                        if (knownFunctions.find(identifier) == knownFunctions.end())
                        {
                            continue;
                        }

                        seedSlotTarget(calleeName, calleeParams[i], "fn:" + identifier);
                    }
                }
            };

            for (std::size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
            {
                const FunctionFacts &function = functions[functionIndex];
                if (activeFunctionNames.find(function.name) == activeFunctionNames.end())
                {
                    continue;
                }
                logPagFunctionPhase("seed-args", functionIndex, functions.size(), function);
                for (const CallSite &callSite : function.callSites)
                {
                    if (!callSite.directCallee.empty())
                    {
                        seedCallArgumentsToCallee(function, callSite, callSite.directCallee);
                    }

                    if (callSite.callSiteId == kInvalidCallSiteId)
                    {
                        continue;
                    }

                    const std::unordered_map<CallSiteId, std::set<std::string>>::const_iterator indirectIt =
                        stitchedIndirectCalleesByCallSite.find(callSite.callSiteId);
                    if (indirectIt == stitchedIndirectCalleesByCallSite.end())
                    {
                        continue;
                    }

                    for (const std::string &indirectCallee : indirectIt->second)
                    {
                        seedCallArgumentsToCallee(function, callSite, indirectCallee);

                        if (pointerReturningFunctions.find(indirectCallee) == pointerReturningFunctions.end())
                        {
                            continue;
                        }

                        const std::unordered_map<CallSiteId, std::vector<std::string>>::const_iterator receiverSlotsIt =
                            callSiteReturnReceiverSlots.find(callSite.callSiteId);
                        if (receiverSlotsIt == callSiteReturnReceiverSlots.end())
                        {
                            continue;
                        }

                        for (const std::string &receiverSlot : receiverSlotsIt->second)
                        {
                            copyIntoSlot(function.name, receiverSlot, returnNode(indirectCallee));
                        }
                    }
                }
            }

            for (std::size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
            {
                const FunctionFacts &function = functions[functionIndex];
                if (activeFunctionNames.find(function.name) == activeFunctionNames.end())
                {
                    continue;
                }
                logPagFunctionPhase("seed-struct-members", functionIndex, functions.size(), function);
                for (const StructMemberMapping &mapping : function.structMemberMappings)
                {
                    if (mapping.structVariable.empty() ||
                        mapping.memberName.empty() ||
                        mapping.functionName.empty())
                    {
                        continue;
                    }

                    if (knownFunctions.find(mapping.functionName) == knownFunctions.end() ||
                        isBlacklistedFunction(mapping.functionName, blacklistedFunctions))
                    {
                        continue;
                    }

                    const std::string slot = mapping.structVariable + "." + mapping.memberName;
                    seedSlotTarget(function.name, slot, "fn:" + mapping.functionName);
                }
            }

            for (std::size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
            {
                const FunctionFacts &function = functions[functionIndex];
                if (activeFunctionNames.find(function.name) == activeFunctionNames.end())
                {
                    continue;
                }
                logPagFunctionPhase("build-constraints", functionIndex, functions.size(), function);
                for (const PointerAssignment &assignment : function.pointerAssignments)
                {
                    const std::string lhsSlot = memorySlotFromExpression(assignment.lhsExpression);
                    const std::string lhsNode = memoryNode(function.name, lhsSlot);
                    const std::vector<std::string> rhsSlots = collectExpressionSlots(assignment.rhsExpression);

                    if (lhsNode.empty())
                    {
                        continue;
                    }

                    const std::string lhsRaw = trimLine(assignment.lhsExpression);
                    const std::string rhsRaw = trimLine(assignment.rhsExpression);
                    const bool rhsIsLoad = !rhsRaw.empty() && rhsRaw.front() == '*';
                    const bool lhsIsStore = !lhsRaw.empty() && lhsRaw.front() == '*';
                    const std::size_t rhsDerefDepth = countLeadingDereferences(rhsRaw);
                    const std::size_t lhsDerefDepth = countLeadingDereferences(lhsRaw);
                    const bool hasPointerCast = rhsRaw.find("(") != std::string::npos && rhsRaw.find("*") != std::string::npos;
                    const bool lhsRelevant = isFunctionPointerRelevantSlot(lhsSlot);
                    bool rhsRelevant = false;
                    for (const std::string &rhsSlot : rhsSlots)
                    {
                        if (isFunctionPointerRelevantSlot(rhsSlot))
                        {
                            rhsRelevant = true;
                            break;
                        }
                    }
                    bool mentionsKnownFunction = false;
                    for (const std::string &identifier : extractIdentifiers(rhsRaw))
                    {
                        if (knownFunctions.find(identifier) != knownFunctions.end())
                        {
                            mentionsKnownFunction = true;
                            break;
                        }
                    }
                    if (!lhsRelevant && !rhsRelevant && !mentionsKnownFunction)
                    {
                        continue;
                    }
                    const std::string lhsStoreBaseNode =
                        lhsIsStore ? materializeDerefPrefixNode(function.name, lhsNode, lhsDerefDepth) : std::string();

                    std::vector<std::string> deferredStoreSeedTargets;

                    const std::string rhsDirectCallee = extractCallCalleeIdentifier(rhsRaw);
                    if (!rhsDirectCallee.empty() &&
                        functionMap.find(rhsDirectCallee) != functionMap.end() &&
                        pointerReturningFunctions.find(rhsDirectCallee) != pointerReturningFunctions.end())
                    {
                        if (lhsIsStore)
                        {
                            const std::string rhsValueNode = returnNode(rhsDirectCallee);
                            addDeferredStoreConstraint(lhsStoreBaseNode, rhsValueNode);
                        }
                        else
                        {
                            copyIntoSlot(function.name, lhsSlot, returnNode(rhsDirectCallee));
                        }
                        continue;
                    }

                    if (!assignment.assignedFunction.empty() &&
                        knownFunctions.find(assignment.assignedFunction) != knownFunctions.end())
                    {
                        if (lhsIsStore)
                        {
                            addDeferredStoreSeedConstraint(lhsStoreBaseNode, "fn:" + assignment.assignedFunction);
                            state.addAddressSeed(lhsNode, abstractMemoryObject(function.name, lhsSlot));
                        }
                        else
                        {
                            strongSeedSlotTarget(function.name, lhsSlot, "fn:" + assignment.assignedFunction);
                        }
                        continue;
                    }

                    bool seededFromFunctionAddress = false;
                    if (assignment.rhsTakesFunctionAddress || (!rhsRaw.empty() && rhsRaw.front() == '&'))
                    {
                        for (const std::string &identifier : extractIdentifiers(rhsRaw))
                        {
                            if (knownFunctions.find(identifier) == knownFunctions.end())
                            {
                                continue;
                            }
                            if (lhsIsStore)
                            {
                                deferredStoreSeedTargets.push_back("fn:" + identifier);
                            }
                            else
                            {
                                seedSlotTarget(function.name, lhsSlot, "fn:" + identifier);
                            }
                            seededFromFunctionAddress = true;
                        }

                        if (!seededFromFunctionAddress)
                        {
                            for (const std::string &candidateSlot : rhsSlots)
                            {
                                const std::string targetObject = abstractMemoryObject(function.name, candidateSlot);
                                if (lhsIsStore)
                                {
                                    deferredStoreSeedTargets.push_back(targetObject);
                                }
                                else
                                {
                                    if (rhsSlots.size() == 1U)
                                    {
                                        strongSeedSlotTarget(function.name, lhsSlot, targetObject);
                                    }
                                    else
                                    {
                                        seedSlotTarget(function.name, lhsSlot, targetObject);
                                    }
                                }
                                seededFromFunctionAddress = true;
                            }
                        }
                    }

                    if (seededFromFunctionAddress)
                    {
                        if (lhsIsStore)
                        {
                            for (const std::string &target : deferredStoreSeedTargets)
                            {
                                addDeferredStoreSeedConstraint(lhsStoreBaseNode, target);
                            }
                            state.addAddressSeed(lhsNode, abstractMemoryObject(function.name, lhsSlot));
                        }
                        continue;
                    }

                    if (rhsRaw.find('(') == std::string::npos)
                    {
                        std::size_t directFunctionIdentifierCount = 0U;
                        std::string directFunctionIdentifier;
                        for (const std::string &identifier : extractIdentifiers(rhsRaw))
                        {
                            if (knownFunctions.find(identifier) == knownFunctions.end())
                            {
                                continue;
                            }

                            if (lhsIsStore)
                            {
                                deferredStoreSeedTargets.push_back("fn:" + identifier);
                            }
                            else
                            {
                                ++directFunctionIdentifierCount;
                                directFunctionIdentifier = identifier;
                                seedSlotTarget(function.name, lhsSlot, "fn:" + identifier);
                            }
                            seededFromFunctionAddress = true;
                        }

                        if (!lhsIsStore && directFunctionIdentifierCount == 1U)
                        {
                            strongSeedSlotTarget(function.name, lhsSlot, "fn:" + directFunctionIdentifier);
                        }

                        if (seededFromFunctionAddress)
                        {
                            if (lhsIsStore)
                            {
                                for (const std::string &target : deferredStoreSeedTargets)
                                {
                                    addDeferredStoreSeedConstraint(lhsStoreBaseNode, target);
                                }
                                state.addAddressSeed(lhsNode, abstractMemoryObject(function.name, lhsSlot));
                            }
                            continue;
                        }
                    }

                    // Conservative: if RHS mentions function symbols (including ternary/union-style selectors),
                    // seed them as possible pointees unless RHS is a direct call expression.
                    if (rhsDirectCallee.empty())
                    {
                        for (const std::string &identifier : extractIdentifiers(rhsRaw))
                        {
                            if (knownFunctions.find(identifier) == knownFunctions.end())
                            {
                                continue;
                            }

                            if (lhsIsStore)
                            {
                                deferredStoreSeedTargets.push_back("fn:" + identifier);
                            }
                            else
                            {
                                seedSlotTarget(function.name, lhsSlot, "fn:" + identifier);
                            }
                        }
                    }

                    // Conservative aggregate summary: global field slots may flow through the global base slot.
                    const std::string lhsRoot = memorySlotRoot(lhsSlot);
                    if (!lhsSlot.empty() && lhsRoot != lhsSlot && globalRoots.find(lhsRoot) != globalRoots.end())
                    {
                        const std::string lhsBaseNode = memoryNode(function.name, lhsRoot);
                        state.addCopyEdge(lhsNode, lhsBaseNode);
                        state.addCopyEdge(lhsBaseNode, lhsNode);
                    }

                    if ((rhsIsLoad || lhsIsStore || hasPointerCast) && !lhsSlot.empty())
                    {
                        state.addAddressSeed(lhsNode, abstractMemoryObject(function.name, lhsSlot));
                    }

                    if (rhsIsLoad)
                    {
                        for (const std::string &rhsSlot : rhsSlots)
                        {
                            const std::string rhsNode = memoryNode(function.name, rhsSlot);
                            if (rhsNode.empty())
                            {
                                continue;
                            }

                            const std::string rhsLoadBaseNode =
                                materializeDerefPrefixNode(function.name, rhsNode, rhsDerefDepth);
                            addDeferredLoadConstraint(rhsLoadBaseNode, lhsNode);
                        }
                        continue;
                    }

                    if (lhsIsStore)
                    {
                        for (const std::string &rhsSlot : rhsSlots)
                        {
                            const std::string rhsNode = memoryNode(function.name, rhsSlot);
                            if (rhsNode.empty())
                            {
                                continue;
                            }

                            addDeferredStoreConstraint(lhsStoreBaseNode, rhsNode);
                        }
                        continue;
                    }

                    for (const std::string &rhsSlot : rhsSlots)
                    {
                        const std::string rhsNode = memoryNode(function.name, rhsSlot);
                        if (rhsNode.empty())
                        {
                            continue;
                        }

                        copyIntoSlot(function.name, lhsSlot, rhsNode);
                    }
                }

                if (pointerReturningFunctions.find(function.name) != pointerReturningFunctions.end())
                {
                    const std::string functionReturnNode = returnNode(function.name);
                    for (const FunctionFacts::BlockFact &block : function.blocks)
                    {
                        for (const std::string &line : block.lines)
                        {
                            const std::optional<std::string> returnExpression = parseReturnExpressionFromLine(line);
                            if (!returnExpression.has_value())
                            {
                                continue;
                            }

                            const std::string returnedRaw = trimLine(*returnExpression);
                            if (returnedRaw.empty())
                            {
                                continue;
                            }

                            const std::string returnedCallee = extractCallCalleeIdentifier(returnedRaw);
                            if (!returnedCallee.empty() &&
                                functionMap.find(returnedCallee) != functionMap.end() &&
                                pointerReturningFunctions.find(returnedCallee) != pointerReturningFunctions.end())
                            {
                                state.addCopyEdge(returnNode(returnedCallee), functionReturnNode);
                            }

                            for (const std::string &identifier : extractIdentifiers(returnedRaw))
                            {
                                if (knownFunctions.find(identifier) == knownFunctions.end())
                                {
                                    continue;
                                }

                                if (!returnedCallee.empty() && identifier == returnedCallee)
                                {
                                    continue;
                                }

                                state.addAddressSeed(functionReturnNode, "fn:" + identifier);
                            }

                            for (const std::string &returnedSlot : collectExpressionSlots(returnedRaw))
                            {
                                std::unordered_set<std::string> seenReturnedNodes;
                                for (const std::string &returnedNode : collectCandidateMemoryNodes(function.name, returnedSlot))
                                {
                                    if (returnedNode.empty() || !seenReturnedNodes.insert(returnedNode).second)
                                    {
                                        continue;
                                    }

                                    state.addCopyEdge(returnedNode, functionReturnNode);
                                }

                                for (const std::string &pointeeSlot : collectPointeeAccessSlots(function.name, returnedSlot))
                                {
                                    for (const std::string &returnedNode : collectCandidateMemoryNodes(function.name, pointeeSlot))
                                    {
                                        if (returnedNode.empty() || !seenReturnedNodes.insert(returnedNode).second)
                                        {
                                            continue;
                                        }

                                        state.addCopyEdge(returnedNode, functionReturnNode);
                                    }
                                }
                            }
                        }
                    }
                }

                for (const CallSite &callSite : function.callSites)
                {
                    if (!callSite.directCallee.empty())
                    {
                        seedCallArgumentsToCallee(function, callSite, callSite.directCallee);
                    }

                    if (callSite.callSiteId == kInvalidCallSiteId)
                    {
                        continue;
                    }

                    const std::unordered_map<CallSiteId, std::set<std::string>>::const_iterator indirectIt =
                        stitchedIndirectCalleesByCallSite.find(callSite.callSiteId);
                    if (indirectIt == stitchedIndirectCalleesByCallSite.end())
                    {
                        continue;
                    }

                    for (const std::string &indirectCallee : indirectIt->second)
                    {
                        seedCallArgumentsToCallee(function, callSite, indirectCallee);
                    }
                }

                for (const FunctionFacts::BlockFact &block : function.blocks)
                {
                    for (const std::string &line : block.lines)
                    {
                        const std::optional<MemoryTransferOp> transferOp = parseMemoryTransferOpFromLine(line);
                        if (!transferOp.has_value())
                        {
                            continue;
                        }

                        for (const std::string &clearDestination : transferOp->clearDestinations)
                        {
                            const std::vector<std::string> clearDstSlots = collectExpressionSlots(clearDestination);
                            for (const std::string &dstSlot : clearDstSlots)
                            {
                                const std::string dstNode = memoryNode(function.name, dstSlot);
                                if (dstNode.empty())
                                {
                                    continue;
                                }

                                state.addAddressSeed(dstNode, abstractMemoryObject(function.name, dstSlot));
                                state.markRelevant(dstNode);
                            }
                        }

                        for (const std::pair<std::string, std::string> &copyPair : transferOp->copyPairs)
                        {
                            const std::vector<std::string> srcSlots = collectExpressionSlots(copyPair.first);
                            const std::vector<std::string> dstSlots = collectExpressionSlots(copyPair.second);
                            if (dstSlots.empty() || srcSlots.empty())
                            {
                                continue;
                            }

                            const std::set<std::string> allDstSlots =
                                expandMemcpyDestinationSlots(function.name, dstSlots);

                            for (const std::string &dstSlot : allDstSlots)
                            {
                                const std::vector<std::string> resolvedSrcSlots =
                                    collectMemcpySourceSlots(srcSlots, allDstSlots, dstSlot);
                                const std::vector<std::string> dstNodes =
                                    collectCandidateMemoryNodes(function.name, dstSlot);
                                for (const std::string &dstNode : dstNodes)
                                {
                                    if (dstNode.empty())
                                    {
                                        continue;
                                    }

                                    if (dstNode.rfind("g::", 0U) == 0U)
                                    {
                                        state.addAddressSeed(dstNode, "obj:g:" + normalizeGlobalKey(dstSlot));
                                    }
                                    else
                                    {
                                        state.addAddressSeed(dstNode, abstractMemoryObject(function.name, dstSlot));
                                    }
                                    state.markRelevant(dstNode);
                                    for (const std::string &srcSlot : resolvedSrcSlots)
                                    {
                                        const std::string srcNode = memoryNode(function.name, srcSlot);
                                        if (srcNode.empty())
                                        {
                                            continue;
                                        }
                                        state.addAddressSeed(srcNode, abstractMemoryObject(function.name, srcSlot));
                                        state.markRelevant(srcNode);
                                        state.addCopyEdge(srcNode, dstNode);

                                        const std::string srcDstKey = srcNode + "->" + dstNode;
                                        if (memTransferSrcDstEdgeKeys.insert(srcDstKey).second)
                                        {
                                            memTransferDstBySrcPtr[srcNode].push_back(dstNode);
                                        }

                                        const std::string dstSrcKey = dstNode + "->" + srcNode;
                                        if (memTransferDstSrcEdgeKeys.insert(dstSrcKey).second)
                                        {
                                            memTransferSrcByDstPtr[dstNode].push_back(srcNode);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            for (std::size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
            {
                const FunctionFacts &function = functions[functionIndex];
                if (activeFunctionNames.find(function.name) == activeFunctionNames.end())
                {
                    continue;
                }
                logPagFunctionPhase("mark-indirect-probes", functionIndex, functions.size(), function);
                for (const CallSite &callSite : function.callSites)
                {
                    if (!callSite.directCallee.empty())
                    {
                        continue;
                    }

                    std::vector<std::string> probeNodes;
                    std::unordered_set<std::string> seenProbeNodes;
                    const std::string throughSlot = memorySlotFromExpression(callSite.throughIdentifier);
                    const std::string calleeExprSlot = memorySlotFromExpression(callSite.calleeExpression);
                    if (!throughSlot.empty())
                    {
                        for (const std::string &aliasSlot : getExpandedMemorySlotAliases(throughSlot))
                        {
                            for (const std::string &probeNode : collectCandidateMemoryNodes(function.name, aliasSlot))
                            {
                                state.markRelevant(probeNode);
                                if (!probeNode.empty() && seenProbeNodes.insert(probeNode).second)
                                {
                                    probeNodes.push_back(probeNode);
                                }
                            }
                        }
                    }
                    if (!calleeExprSlot.empty())
                    {
                        for (const std::string &aliasSlot : getExpandedMemorySlotAliases(calleeExprSlot))
                        {
                            for (const std::string &probeNode : collectCandidateMemoryNodes(function.name, aliasSlot))
                            {
                                state.markRelevant(probeNode);
                                if (!probeNode.empty() && seenProbeNodes.insert(probeNode).second)
                                {
                                    probeNodes.push_back(probeNode);
                                }
                            }
                        }
                    }

                    if (callSite.callSiteId != kInvalidCallSiteId && !probeNodes.empty())
                    {
                        probeNodesByCallSiteId[callSite.callSiteId] = std::move(probeNodes);
                    }
                }
            }
            state.saturateRelevantNodes();

            collapseConstraintGraphSccs(state, nodeRepresentativeByNode);

            for (const std::pair<const std::string, std::unordered_set<std::string>> &entry : pointsTo)
            {
                const bool hasDeferredEffects =
                    loadsByPointer.find(entry.first) != loadsByPointer.end() ||
                    storesByPointer.find(entry.first) != storesByPointer.end() ||
                    storeSeedTargetsByPointer.find(entry.first) != storeSeedTargetsByPointer.end() ||
                    memTransferDstBySrcPtr.find(entry.first) != memTransferDstBySrcPtr.end() ||
                    memTransferSrcByDstPtr.find(entry.first) != memTransferSrcByDstPtr.end();
                if (relevantNodes.find(entry.first) == relevantNodes.end() && !hasDeferredEffects)
                {
                    continue;
                }
                if (inWorklist.insert(entry.first).second)
                {
                    worklist.push_back(entry.first);
                }
            }

            std::function<void(const std::string &, const std::string &)> materializeDynamicCopy =
                [&](const std::string &src, const std::string &dst)
            {
                const std::string canonicalSrc = canonicalConstraintNode(src, nodeRepresentativeByNode);
                const std::string canonicalDst = canonicalConstraintNode(dst, nodeRepresentativeByNode);
                if (!state.addSparseValueFlowEdge(canonicalSrc, canonicalDst))
                {
                    return;
                }

                const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator srcIt =
                    pointsTo.find(canonicalConstraintNode(canonicalSrc, nodeRepresentativeByNode));
                if (srcIt == pointsTo.end())
                {
                    return;
                }

                for (const std::string &target : srcIt->second)
                {
                    state.addPointsTo(canonicalConstraintNode(canonicalDst, nodeRepresentativeByNode), target);
                }
            };

            std::size_t fixedPointIterations = 0U;
            std::unordered_map<std::string, std::unordered_set<std::string>> propagatedTargetsByNode;
            propagatedTargetsByNode.reserve(pointsTo.size() * 2U + 1U);
            while (!worklist.empty())
            {
                ++fixedPointIterations;
                const std::string queuedNode = worklist.front();
                worklist.pop_front();
                inWorklist.erase(queuedNode);

                const std::string node = canonicalConstraintNode(queuedNode, nodeRepresentativeByNode);
                if (node.empty())
                {
                    continue;
                }

                if (node != queuedNode)
                {
                    if (inWorklist.insert(node).second)
                    {
                        worklist.push_back(node);
                    }
                    continue;
                }

                std::vector<std::string> newTargets;
                const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator nodeTargetsIt =
                    pointsTo.find(node);
                if (nodeTargetsIt != pointsTo.end())
                {
                    std::unordered_set<std::string> &propagated = propagatedTargetsByNode[node];
                    if (propagated.empty())
                    {
                        propagated.reserve(nodeTargetsIt->second.size() + 1U);
                    }

                    for (const std::string &target : nodeTargetsIt->second)
                    {
                        if (propagated.insert(target).second)
                        {
                            newTargets.push_back(target);
                        }
                    }
                }

                if (newTargets.empty())
                {
                    continue;
                }

                const std::unordered_map<std::string, std::vector<std::string>>::const_iterator svfgSuccIt = sparseValueFlowSucc.find(node);
                if (svfgSuccIt != sparseValueFlowSucc.end())
                {
                    for (const std::string &dst : svfgSuccIt->second)
                    {
                        for (const std::string &target : newTargets)
                        {
                            state.addPointsTo(dst, target);
                        }
                    }
                }

                const std::unordered_map<std::string, std::vector<DeferredLoadConstraint>>::const_iterator loadIt =
                    loadsByPointer.find(node);
                if (loadIt != loadsByPointer.end())
                {
                    for (const DeferredLoadConstraint &loadConstraint : loadIt->second)
                    {
                        for (const std::string &objectNode : newTargets)
                        {
                            materializeDynamicCopy(objectNode, loadConstraint.dstNode);
                        }
                    }
                }

                const std::unordered_map<std::string, std::vector<DeferredStoreConstraint>>::const_iterator storeIt =
                    storesByPointer.find(node);
                if (storeIt != storesByPointer.end())
                {
                    for (const DeferredStoreConstraint &storeConstraint : storeIt->second)
                    {
                        for (const std::string &objectNode : newTargets)
                        {
                            materializeDynamicCopy(storeConstraint.srcNode, objectNode);
                        }
                    }
                }

                const std::unordered_map<std::string, std::vector<DeferredStoreSeed>>::const_iterator storeSeedIt =
                    storeSeedTargetsByPointer.find(node);
                if (storeSeedIt != storeSeedTargetsByPointer.end())
                {
                    for (const DeferredStoreSeed &storeSeed : storeSeedIt->second)
                    {
                        for (const std::string &objectNode : newTargets)
                        {
                            state.addPointsTo(objectNode, storeSeed.target);
                        }
                    }
                }

                const std::unordered_map<std::string, std::vector<std::string>>::const_iterator memDstIt =
                    memTransferDstBySrcPtr.find(node);
                if (memDstIt != memTransferDstBySrcPtr.end())
                {
                    for (const std::string &dstPtrNode : memDstIt->second)
                    {
                        const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator dstTargetsIt =
                            pointsTo.find(dstPtrNode);
                        if (dstTargetsIt == pointsTo.end())
                        {
                            continue;
                        }

                        for (const std::string &srcObj : newTargets)
                        {
                            for (const std::string &dstObj : dstTargetsIt->second)
                            {
                                materializeDynamicCopy(srcObj, dstObj);
                            }
                        }
                    }
                }

                const std::unordered_map<std::string, std::vector<std::string>>::const_iterator memSrcIt =
                    memTransferSrcByDstPtr.find(node);
                if (memSrcIt != memTransferSrcByDstPtr.end())
                {
                    const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator dstTargetsIt =
                        pointsTo.find(node);
                    if (dstTargetsIt != pointsTo.end())
                    {
                        for (const std::string &srcPtrNode : memSrcIt->second)
                        {
                            const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator srcTargetsIt =
                                pointsTo.find(srcPtrNode);
                            if (srcTargetsIt == pointsTo.end())
                            {
                                continue;
                            }

                            for (const std::string &srcObj : srcTargetsIt->second)
                            {
                                for (const std::string &dstObj : newTargets)
                                {
                                    materializeDynamicCopy(srcObj, dstObj);
                                }
                            }
                        }
                    }
                }
            }

            logPagFixedPointSummary(
                fixedPointIterations,
                pointsTo.size(),
                sparseValueFlowEdgeKeys.size(),
                relevantNodes.size());

            CallResolutionContext callResolutionContext{
                functions,
                functionMap,
                nodeRepresentativeByNode,
                knownFunctions,
                blacklistedFunctions,
                pointsTo,
                collectCandidateMemoryNodes,
                getExpandedMemorySlotAliases,
                resolveFunctionTargetsTransitively,
                &probeNodesByCallSiteId,
                &activeFunctionNames};
            collectResolvedCallEdges(callResolutionContext, resolvedEdges, unresolvedIndirect);

            discoveredNewIndirectEdges = false;
            for (const CallEdge &edge : resolvedEdges)
            {
                if (edge.kind != "indirect" || edge.callSiteId == kInvalidCallSiteId || edge.callee.empty())
                {
                    continue;
                }

                if (callSiteById.find(edge.callSiteId) == callSiteById.end())
                {
                    continue;
                }

                if (knownFunctions.find(edge.callee) == knownFunctions.end() ||
                    isBlacklistedFunction(edge.callee, blacklistedFunctions))
                {
                    continue;
                }

                std::set<std::string> &callees = stitchedIndirectCalleesByCallSite[edge.callSiteId];
                if (callees.insert(edge.callee).second)
                {
                    discoveredNewIndirectEdges = true;
                }
            }
        } while (discoveredNewIndirectEdges && onTheFlySolveIteration < kMaxOnTheFlySolveIterations);
    }

    /**
     * @brief Run flow-sensitive and context-sensitive callgraph resolution.
     */
    void runContextSensitiveAnalysis(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions,
        const std::set<std::string> &blacklistedFunctions,
        std::vector<CallEdge> &resolvedEdges,
        std::vector<CallEdge> &unresolvedIndirect)
    {
        runPagConstraintAnalysis(functions, knownFunctions, blacklistedFunctions, resolvedEdges, unresolvedIndirect);
    }

    /**
     * @brief Join context stack entries with a separator.
     */
    std::string joinContext(const std::vector<std::string> &context, const std::string &separator)
    {
        std::string joined;
        for (std::size_t i = 0; i < context.size(); ++i)
        {
            if (i > 0U)
            {
                joined += separator;
            }
            joined += context[i];
        }
        return joined;
    }

    /**
     * @brief Choose root functions for context-statistics traversal.
     */
    std::vector<std::string> chooseRoots(
        const std::set<std::string> &knownFunctions,
        const std::set<CollapsedEdge> &collapsedEdges)
    {
        std::map<std::string, std::size_t> incoming;
        for (const std::string &name : knownFunctions)
        {
            incoming[name] = 0U;
        }

        for (const CollapsedEdge &edge : collapsedEdges)
        {
            std::map<std::string, std::size_t>::iterator it = incoming.find(edge.callee);
            if (it != incoming.end())
            {
                ++it->second;
            }
        }

        std::vector<std::string> roots;
        for (const std::pair<const std::string, std::size_t> &entry : incoming)
        {
            if (entry.second == 0U)
            {
                roots.push_back(entry.first);
            }
        }

        if (!roots.empty())
        {
            return roots;
        }

        if (!knownFunctions.empty())
        {
            return {*knownFunctions.begin()};
        }

        return {};
    }

    /**
     * @brief Serialize source location to JSON object.
     */
    llvm::json::Object locationToJson(const SourceLocation &location)
    {
        llvm::json::Object object;
        object["file"] = location.file;
        object["line"] = static_cast<std::int64_t>(location.line);
        object["column"] = static_cast<std::int64_t>(location.column);
        return object;
    }

    void collectResolvedCallEdges(
        const CallResolutionContext &context,
        std::vector<CallEdge> &resolvedEdges,
        std::vector<CallEdge> &unresolvedIndirect)
    {
        // Pre-index struct member mappings for interprocedural fallback lookups.
        SmallStringList globalStructMappingTargets;
        std::vector<std::pair<std::string, std::string>> structMemberTargetPairs;
        for (const FunctionFacts &func : context.functions)
        {
            for (const StructMemberMapping &mapping : func.structMemberMappings)
            {
                if (mapping.functionName.empty())
                {
                    continue;
                }

                if (mapping.structVariable.find("gSWTimers") != std::string::npos ||
                    mapping.structVariable.find("fps") != std::string::npos)
                {
                    appendUnique(globalStructMappingTargets, mapping.functionName);
                }

                if (!mapping.memberName.empty())
                {
                    structMemberTargetPairs.push_back(std::make_pair(mapping.memberName, mapping.functionName));
                }
            }
        }

        std::unordered_map<std::string, SmallStringList> resolvedTargetsByProbeNode;
        resolvedTargetsByProbeNode.reserve(context.pointsTo.size() * 2U + 1U);

        for (std::size_t functionIndex = 0; functionIndex < context.functions.size(); ++functionIndex)
        {
            const FunctionFacts &function = context.functions[functionIndex];
            if (context.activeFunctionNames != nullptr &&
                context.activeFunctionNames->find(function.name) == context.activeFunctionNames->end())
            {
                continue;
            }
            logPagFunctionPhase("resolve-calls", functionIndex, context.functions.size(), function);

            for (const CallSite &callSite : function.callSites)
            {
                if (!callSite.directCallee.empty())
                {
                    if (isBlacklistedFunction(callSite.directCallee, context.blacklistedFunctions))
                    {
                        continue;
                    }

                    CallEdge edge;
                    edge.caller = function.name;
                    edge.callee = callSite.directCallee;
                    edge.callSiteId = callSite.callSiteId;
                    edge.kind = "direct";
                    edge.location = callSite.location;
                    edge.calleeExpression = callSite.calleeExpression;
                    edge.throughIdentifier = callSite.throughIdentifier;
                    resolvedEdges.push_back(std::move(edge));

                    continue;
                }

                SmallStringList resolvedTargets;
                const std::string throughSlot = memorySlotFromExpression(callSite.throughIdentifier);
                const std::string calleeExprSlot = memorySlotFromExpression(callSite.calleeExpression);

                std::vector<std::string> probeNodes;
                std::unordered_set<std::string> seenProbeNodes;
                bool usedCachedProbeNodes = false;
                if (context.probeNodesByCallSiteId != nullptr && callSite.callSiteId != kInvalidCallSiteId)
                {
                    const std::unordered_map<CallSiteId, std::vector<std::string>>::const_iterator cachedIt =
                        context.probeNodesByCallSiteId->find(callSite.callSiteId);
                    if (cachedIt != context.probeNodesByCallSiteId->end())
                    {
                        probeNodes = cachedIt->second;
                        usedCachedProbeNodes = true;
                    }
                }

                if (!usedCachedProbeNodes && !throughSlot.empty())
                {
                    for (const std::string &aliasSlot : context.getExpandedMemorySlotAliases(throughSlot))
                    {
                        for (const std::string &probe : context.collectCandidateMemoryNodes(function.name, aliasSlot))
                        {
                            if (!probe.empty() && seenProbeNodes.insert(probe).second)
                            {
                                probeNodes.push_back(probe);
                            }
                        }
                    }
                }
                if (!usedCachedProbeNodes && !calleeExprSlot.empty())
                {
                    for (const std::string &aliasSlot : context.getExpandedMemorySlotAliases(calleeExprSlot))
                    {
                        for (const std::string &probe : context.collectCandidateMemoryNodes(function.name, aliasSlot))
                        {
                            if (!probe.empty() && seenProbeNodes.insert(probe).second)
                            {
                                probeNodes.push_back(probe);
                            }
                        }
                    }
                }

                for (const std::string &probeNode : probeNodes)
                {
                    const std::string canonicalProbeNode =
                        canonicalConstraintNode(probeNode, context.nodeRepresentativeByNode);
                    if (canonicalProbeNode.empty())
                    {
                        continue;
                    }

                    const std::unordered_map<std::string, SmallStringList>::const_iterator cachedProbeTargetsIt =
                        resolvedTargetsByProbeNode.find(canonicalProbeNode);
                    if (cachedProbeTargetsIt != resolvedTargetsByProbeNode.end())
                    {
                        for (const std::string &target : cachedProbeTargetsIt->second)
                        {
                            appendUnique(resolvedTargets, target);
                        }
                        continue;
                    }

                    const std::unordered_map<std::string, std::unordered_set<std::string>>::const_iterator ptIt =
                        context.pointsTo.find(canonicalProbeNode);
                    if (ptIt == context.pointsTo.end())
                    {
                        resolvedTargetsByProbeNode.emplace(canonicalProbeNode, SmallStringList());
                        continue;
                    }

                    const SmallStringList probeTargets = context.resolveFunctionTargetsTransitively(ptIt->second);
                    resolvedTargetsByProbeNode.emplace(canonicalProbeNode, probeTargets);
                    for (const std::string &target : probeTargets)
                    {
                        appendUnique(resolvedTargets, target);
                    }
                }

                // Interprocedural struct member resolution: try to resolve via struct member mappings
                // This handles cases like: fps[0].handlerFunc1() where fps is a local array of struct
                // and the function pointer information comes from global struct initialization
                if (resolvedTargets.empty() && !callSite.calleeExpression.empty())
                {
                    // Extract base variable and member name from calleeExpression (e.g., "fps[0].handlerFunc1")
                    std::function<std::string(const std::string &)> extractArrayBase =
                        [](const std::string &expr)
                    {
                        const std::size_t bracketPos = expr.find('[');
                        if (bracketPos != std::string::npos)
                        {
                            return expr.substr(0, bracketPos);
                        }
                        return expr;
                    };

                    std::function<std::string(const std::string &)> extractMemberPath =
                        [](const std::string &expr)
                    {
                        // Extract "handlerFunc1" from "fps[0].handlerFunc1"
                        const std::size_t dotPos = expr.rfind('.');
                        if (dotPos != std::string::npos && dotPos + 1 < expr.size())
                        {
                            return expr.substr(dotPos + 1);
                        }
                        return std::string();
                    };

                    const std::string arrayBase = extractArrayBase(callSite.calleeExpression);
                    const std::string memberName = extractMemberPath(callSite.calleeExpression);

                    // Try to resolve what arrayBase points to through assignments
                    if (!arrayBase.empty() && !memberName.empty())
                    {
                        // Look through assignments to this local variable to find what it aliases to.
                        bool hasAliasAssignment = false;
                        bool hasStructFieldAssignment = false;
                        for (const PointerAssignment &assignment : function.pointerAssignments)
                        {
                            const std::string lhsBase = extractArrayBase(assignment.lhsExpression);
                            if (lhsBase != arrayBase)
                            {
                                continue;
                            }

                            hasAliasAssignment = true;
                            if (assignment.rhsExpression.find("->fp") != std::string::npos ||
                                assignment.rhsExpression.find(".fp") != std::string::npos)
                            {
                                hasStructFieldAssignment = true;
                            }
                        }

                        if (hasAliasAssignment)
                        {
                            // Found assignment to this local variable (for example, fps[0] = current->fp).
                            // Apply global struct mapping fallback once instead of rescanning all mappings
                            // for every matching assignment.
                            for (const std::string &target : globalStructMappingTargets)
                            {
                                appendUnique(resolvedTargets, target);
                            }
                        }

                        if (hasAliasAssignment && hasStructFieldAssignment)
                        {
                            // If assignment RHS looks like struct field access, match by member name.
                            for (const std::pair<std::string, std::string> &memberTargetPair : structMemberTargetPairs)
                            {
                                if (memberTargetPair.first.find(memberName) != std::string::npos ||
                                    memberName.find(memberTargetPair.first) != std::string::npos)
                                {
                                    appendUnique(resolvedTargets, memberTargetPair.second);
                                }
                            }
                        }
                    }
                }

                if (resolvedTargets.empty())
                {
                    CallEdge edge;
                    edge.caller = function.name;
                    edge.callee = "__unknown_indirect_target__";
                    edge.callSiteId = callSite.callSiteId;
                    edge.kind = "indirect-unknown";
                    edge.location = callSite.location;
                    edge.calleeExpression = callSite.calleeExpression;
                    edge.throughIdentifier = callSite.throughIdentifier;
                    resolvedEdges.push_back(edge);

                    CallEdge unresolvedEdge = edge;
                    unresolvedEdge.callee.clear();
                    unresolvedIndirect.push_back(std::move(unresolvedEdge));
                    logUnresolvedCall(unresolvedIndirect.back());
                    continue;
                }

                for (const std::string &callee : resolvedTargets)
                {
                    const std::unordered_map<std::string, const FunctionFacts *>::const_iterator calleeIt =
                        context.functionMap.find(callee);
                    if (calleeIt != context.functionMap.end() &&
                        !hasCompatibleArgumentProfile(callSite, *calleeIt->second))
                    {
                        continue;
                    }

                    CallEdge edge;
                    edge.caller = function.name;
                    edge.callee = callee;
                    edge.callSiteId = callSite.callSiteId;
                    edge.kind = "indirect";
                    edge.location = callSite.location;
                    edge.calleeExpression = callSite.calleeExpression;
                    edge.throughIdentifier = callSite.throughIdentifier;
                    resolvedEdges.push_back(std::move(edge));
                }
            }
        }
    }

    struct CallGraphArtifacts
    {
        std::set<CollapsedEdge> collapsedEdges;
        std::set<std::string> collapsedNodeNames;
        std::vector<std::string> roots;
        std::map<std::string, std::vector<CollapsedEdge>> outgoing;
        std::set<std::string> contextNodeKeys;
        std::set<std::string> contextEdgeKeys;
        std::vector<CallEdge> unresolvedIndirectCalls;
    };

    CallGraphArtifacts buildCallGraphArtifacts(
        const std::vector<CallEdge> &resolvedEdges,
        const std::set<std::string> &knownFunctions,
        std::size_t contextDepth,
        const std::vector<CallEdge> &unresolvedIndirect)
    {
        CallGraphArtifacts artifacts;

        for (const CallEdge &edge : resolvedEdges)
        {
            if (!edge.callee.empty())
            {
                artifacts.collapsedEdges.insert(CollapsedEdge{edge.caller, edge.callee, edge.kind});
            }
        }

        std::function<std::string(const CallEdge &)> makeCallSiteKey = [](const CallEdge &edge)
        {
            return edge.caller + "|" + edge.location.file + "|" + std::to_string(edge.location.line) + ":" +
                   std::to_string(edge.location.column) + "|" + edge.calleeExpression + "|" + edge.throughIdentifier;
        };

        std::unordered_set<std::string> resolvedIndirectCallSites;
        for (const CallEdge &edge : resolvedEdges)
        {
            if (edge.kind != "indirect")
            {
                continue;
            }
            resolvedIndirectCallSites.insert(makeCallSiteKey(edge));
        }

        std::unordered_set<std::string> seenUnresolved;
        for (const CallEdge &edge : unresolvedIndirect)
        {
            const std::string key = makeCallSiteKey(edge);
            if (resolvedIndirectCallSites.find(key) != resolvedIndirectCallSites.end())
            {
                continue;
            }
            if (!seenUnresolved.insert(key).second)
            {
                continue;
            }
            artifacts.unresolvedIndirectCalls.push_back(edge);
        }

        for (const CollapsedEdge &edge : artifacts.collapsedEdges)
        {
            artifacts.outgoing[edge.caller].push_back(edge);
            artifacts.collapsedNodeNames.insert(edge.caller);
            artifacts.collapsedNodeNames.insert(edge.callee);
        }
        for (const std::string &name : knownFunctions)
        {
            artifacts.collapsedNodeNames.insert(name);
        }

        for (std::pair<const std::string, std::vector<CollapsedEdge>> &entry : artifacts.outgoing)
        {
            std::sort(entry.second.begin(), entry.second.end(), [](const CollapsedEdge &lhs, const CollapsedEdge &rhs)
                      {
                if (lhs.callee != rhs.callee)
                {
                    return lhs.callee < rhs.callee;
                }
                return lhs.kind < rhs.kind; });
        }

        artifacts.roots = chooseRoots(knownFunctions, artifacts.collapsedEdges);

        std::function<std::string(const std::string &, const std::vector<std::string> &)> makeNodeKey = [](const std::string &function, const std::vector<std::string> &context)
        {
            if (context.empty())
            {
                return function + "|";
            }
            return function + "|" + joinContext(context, "\x1f");
        };

        std::deque<std::pair<std::string, std::vector<std::string>>> worklist;
        std::function<std::string(const std::string &, const std::vector<std::string> &)> enqueueNode = [&](const std::string &function, const std::vector<std::string> &context)
        {
            const std::string key = makeNodeKey(function, context);
            if (artifacts.contextNodeKeys.insert(key).second)
            {
                worklist.emplace_back(function, context);
            }
            return key;
        };

        for (const std::string &rootFunction : artifacts.roots)
        {
            enqueueNode(rootFunction, {});
        }

        while (!worklist.empty())
        {
            std::pair<std::string, std::vector<std::string>> current = std::move(worklist.front());
            worklist.pop_front();

            const std::string &currentFunction = current.first;
            const std::vector<std::string> &currentContext = current.second;
            const std::string callerKey = makeNodeKey(currentFunction, currentContext);

            const std::map<std::string, std::vector<CollapsedEdge>>::const_iterator outgoingIt = artifacts.outgoing.find(currentFunction);
            if (outgoingIt == artifacts.outgoing.end())
            {
                continue;
            }

            for (const CollapsedEdge &edge : outgoingIt->second)
            {
                std::vector<std::string> nextContext = currentContext;
                nextContext.push_back(currentFunction);
                if (contextDepth > 0U && nextContext.size() > contextDepth)
                {
                    nextContext.erase(nextContext.begin(), nextContext.begin() + (nextContext.size() - contextDepth));
                }

                const std::string calleeKey = enqueueNode(edge.callee, nextContext);
                artifacts.contextEdgeKeys.insert(callerKey + "->" + calleeKey + "|" + edge.kind);
            }
        }

        return artifacts;
    }

    bool writeCallGraphJson(
        const std::string &outputJsonPath,
        const std::string &analysisJsonPath,
        const std::vector<CallEdge> &unresolvedIndirect,
        const CallGraphArtifacts &artifacts,
        std::size_t functionCount,
        std::size_t contextDepth,
        std::string &errorMessage)
    {
        llvm::json::Object rootOut;
        rootOut["kind"] = "callgraph";
        rootOut["input"] = analysisJsonPath;

        llvm::json::Object summary;
        summary["functionCount"] = static_cast<std::int64_t>(functionCount);
        summary["collapsedEdgeCount"] = static_cast<std::int64_t>(artifacts.collapsedEdges.size());
        summary["unresolvedIndirectCallCount"] = static_cast<std::int64_t>(unresolvedIndirect.size());
        summary["contextDepth"] = static_cast<std::int64_t>(contextDepth);
        summary["contextNodeCount"] = static_cast<std::int64_t>(artifacts.contextNodeKeys.size());
        summary["contextEdgeCount"] = static_cast<std::int64_t>(artifacts.contextEdgeKeys.size());
        rootOut["summary"] = std::move(summary);

        llvm::json::Array unresolvedCallsJson;
        for (const CallEdge &edge : unresolvedIndirect)
        {
            llvm::json::Object unresolvedJson;
            unresolvedJson["caller"] = edge.caller;
            unresolvedJson["calleeExpression"] = edge.calleeExpression;
            unresolvedJson["throughIdentifier"] = edge.throughIdentifier;
            unresolvedJson["location"] = locationToJson(edge.location);
            unresolvedCallsJson.push_back(std::move(unresolvedJson));
        }
        rootOut["unresolvedIndirectCalls"] = std::move(unresolvedCallsJson);

        llvm::json::Object collapsed;
        llvm::json::Array collapsedNodes;
        for (const std::string &name : artifacts.collapsedNodeNames)
        {
            collapsedNodes.push_back(name);
        }
        collapsed["nodes"] = std::move(collapsedNodes);

        llvm::json::Array collapsedEdgesJson;
        for (const CollapsedEdge &edge : artifacts.collapsedEdges)
        {
            llvm::json::Object edgeJson;
            edgeJson["caller"] = edge.caller;
            edgeJson["callee"] = edge.callee;
            edgeJson["kind"] = edge.kind;
            collapsedEdgesJson.push_back(std::move(edgeJson));
        }
        collapsed["edges"] = std::move(collapsedEdgesJson);
        rootOut["collapsedCallGraph"] = std::move(collapsed);

        std::error_code outputEc;
        llvm::raw_fd_ostream outputStream(outputJsonPath, outputEc);
        if (outputEc)
        {
            errorMessage = "cannot open output json: " + outputEc.message();
            return false;
        }

        llvm::json::Value outputJson(std::move(rootOut));
        outputStream << llvm::formatv("{0:2}", outputJson);
        outputStream << "\n";
        outputStream.flush();
        return true;
    }

    bool writeCallGraphDot(
        const std::string &outputDotPath,
        const CallGraphArtifacts &artifacts,
        std::string &errorMessage)
    {
        if (outputDotPath.empty())
        {
            return true;
        }

        std::ofstream dotFile(outputDotPath);
        if (!dotFile)
        {
            errorMessage = "cannot open output dot: " + outputDotPath;
            return false;
        }

        dotFile << "digraph callgraph {\n";
        dotFile << "  rankdir=LR;\n";

        for (const std::string &name : artifacts.collapsedNodeNames)
        {
            dotFile << "  \"" << name << "\" [shape=box];\n";
        }

        for (const CollapsedEdge &edge : artifacts.collapsedEdges)
        {
            dotFile << "  \"" << edge.caller << "\" -> \"" << edge.callee
                    << "\" [label=\"" << edge.kind << "\"];\n";
        }

        dotFile << "}\n";
        return true;
    }

} // namespace

/**
 * @brief Generate callgraph outputs from analysis JSON.
 * @return true on success, false on failure.
 */
bool generateCallGraphFromAnalysisJson(
    const std::string &analysisJsonPath,
    const std::string &outputJsonPath,
    const std::string &outputDotPath,
    std::size_t contextDepth,
    const std::set<std::string> &blacklistedFunctions,
    bool debugLoggingEnabled,
    CallGraphStats &stats,
    std::string &errorMessage)
{
    gDebugLoggingEnabled = debugLoggingEnabled;

    std::ifstream input(analysisJsonPath);
    if (!input)
    {
        errorMessage = "cannot open analysis json: " + analysisJsonPath;
        return false;
    }

    std::string jsonText((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    llvm::Expected<llvm::json::Value> parsed = llvm::json::parse(jsonText);
    if (!parsed)
    {
        errorMessage = "failed to parse analysis json";
        return false;
    }

    const llvm::json::Object *root = parsed->getAsObject();
    if (root == nullptr)
    {
        errorMessage = "analysis json root must be an object";
        return false;
    }

    std::vector<FunctionFacts> functions;
    std::set<std::string> knownFunctions;
    StringInterner callSiteInterner;
    if (!parseFunctions(*root, functions, knownFunctions, blacklistedFunctions, callSiteInterner, errorMessage))
    {
        return false;
    }

    std::vector<CallEdge> resolvedEdges;
    std::vector<CallEdge> unresolvedIndirect;

    runContextSensitiveAnalysis(functions, knownFunctions, blacklistedFunctions, resolvedEdges, unresolvedIndirect);
    CallGraphArtifacts artifacts = buildCallGraphArtifacts(resolvedEdges, knownFunctions, contextDepth, unresolvedIndirect);

    if (!writeCallGraphJson(
            outputJsonPath,
            analysisJsonPath,
            artifacts.unresolvedIndirectCalls,
            artifacts,
            knownFunctions.size(),
            contextDepth,
            errorMessage))
    {
        return false;
    }

    if (!writeCallGraphDot(outputDotPath, artifacts, errorMessage))
    {
        return false;
    }

    stats.functionCount = knownFunctions.size();
    stats.collapsedEdgeCount = artifacts.collapsedEdges.size();
    stats.unresolvedIndirectCallCount = artifacts.unresolvedIndirectCalls.size();
    stats.contextNodeCount = artifacts.contextNodeKeys.size();
    stats.contextEdgeCount = artifacts.contextEdgeKeys.size();

    return true;
}
