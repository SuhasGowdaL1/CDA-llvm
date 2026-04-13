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
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "llvm/Support/JSON.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/raw_ostream.h"

namespace
{

    bool gDebugLoggingEnabled = false;

    struct SourceLocation
    {
        std::string file;
        std::uint32_t line = 0;
        std::uint32_t column = 0;
    };

    struct CallSite
    {
        std::string callSiteId;
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
        std::vector<std::string> parameterNames;
        std::set<std::string> addressTakenFunctions;
        std::vector<CallSite> callSites;
        std::vector<PointerAssignment> pointerAssignments;
        std::vector<StructMemberMapping> structMemberMappings;
        struct BlockFact
        {
            std::uint32_t id = 0;
            std::vector<std::string> lines;
            std::vector<std::vector<std::string>> lineCallSiteIds;
            std::vector<std::uint32_t> successors;
        };
        std::vector<BlockFact> blocks;
    };

    enum class EventKind
    {
        kAssignment,
        kCall
    };

    struct Event
    {
        EventKind kind = EventKind::kAssignment;
        std::uint32_t line = 0;
        std::uint32_t column = 0;
        std::size_t index = 0;
        const PointerAssignment *assignment = nullptr;
        const CallSite *callSite = nullptr;
    };

    struct CallEdge
    {
        std::string caller;
        std::string callee;
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

    struct ParameterDispatchInfo
    {
        std::set<std::string> dispatchSlots;
        SourceLocation callLocation;
    };

    using PointsToMap = std::unordered_map<std::string, std::set<std::string>>;

    struct ContextJob
    {
        std::string functionName;
        PointsToMap seededPointsTo;
        std::vector<StructMemberMapping> seededStructMemberMappings;
    };

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
    std::optional<FunctionFacts::BlockFact> parseBlockFact(const llvm::json::Object &blockObject)
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
                std::vector<std::string> entryIds;
                if (const llvm::json::Array *entryArray = entryValue.getAsArray())
                {
                    for (const llvm::json::Value &idValue : *entryArray)
                    {
                        if (const std::optional<llvm::StringRef> id = idValue.getAsString())
                        {
                            entryIds.push_back(id->str());
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

                        const std::optional<FunctionFacts::BlockFact> block = parseBlockFact(*blockObject);
                        if (block.has_value())
                        {
                            facts.blocks.push_back(std::move(*block));
                        }
                    }
                }

                functions.push_back(std::move(facts));
                continue;
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
                        callSite.callSiteId = value->str();
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

                    const std::optional<FunctionFacts::BlockFact> block = parseBlockFact(*blockObject);
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
     * @brief Build deterministic event ordering from source locations.
     */
    std::vector<Event> buildEvents(const FunctionFacts &function)
    {
        std::vector<Event> events;
        events.reserve(function.pointerAssignments.size() + function.callSites.size());

        std::size_t index = 0;
        for (const PointerAssignment &assignment : function.pointerAssignments)
        {
            Event event;
            event.kind = EventKind::kAssignment;
            event.line = assignment.location.line;
            event.column = assignment.location.column;
            event.index = index++;
            event.assignment = &assignment;
            events.push_back(event);
        }

        for (const CallSite &callSite : function.callSites)
        {
            Event event;
            event.kind = EventKind::kCall;
            event.line = callSite.location.line;
            event.column = callSite.location.column;
            event.index = index++;
            event.callSite = &callSite;
            events.push_back(event);
        }

        std::sort(events.begin(), events.end(), [](const Event &lhs, const Event &rhs)
                  {
            if (lhs.line != rhs.line)
            {
                return lhs.line < rhs.line;
            }
            if (lhs.column != rhs.column)
            {
                return lhs.column < rhs.column;
            }
            if (lhs.kind != rhs.kind)
            {
                return lhs.kind == EventKind::kAssignment;
            }
            return lhs.index < rhs.index; });

        return events;
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

        std::vector<const PointerAssignment *> allAssignments;
        std::vector<const PointerAssignment *> globalAssignments;
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

                const std::set<std::string> destinationSlots =
                    resolveAssignmentDestinationSlots(assignment.lhsExpression, knownFunctions, slotTargetsBySlot);
                for (const std::string &destinationSlot : destinationSlots)
                {
                    slotTargetsBySlot[destinationSlot] = targets;
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

            const std::set<std::string> destinationSlots =
                resolveAssignmentDestinationSlots(assignment.lhsExpression, knownFunctions, mergedGlobalBindings);
            for (const std::string &destinationSlot : destinationSlots)
            {
                targetsBySlot[destinationSlot] = targets;
                mergedGlobalBindings[destinationSlot] = targets;
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

                const std::set<std::string> destinationSlots =
                    resolveAssignmentDestinationSlots(assignment.lhsExpression, knownFunctions, sourceTargetsBySlot);
                for (const std::string &destinationSlot : destinationSlots)
                {
                    sourceTargetsBySlot[destinationSlot] = targets;
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

    std::vector<std::string> collectParameterSlots(
        const FunctionFacts &function,
        const std::set<std::string> &knownFunctions);

    /**
     * @brief Collect struct-member targets copied from local structs into global storage.
     */
    std::vector<StructMemberMapping> collectProgramWideStructMemberMappings(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions)
    {
        std::vector<StructMemberMapping> result;
        std::unordered_set<std::string> seen;

        std::function<std::string(std::string)> normalizeAccessExpression = [](std::string expression)
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

            return stripped;
        };

        std::function<std::pair<std::string, std::string>(const std::string &)> splitStructAccess =
            [&](const std::string &expression) -> std::pair<std::string, std::string>
        {
            const std::string normalized = normalizeAccessExpression(expression);
            const std::size_t dot = normalized.find('.');
            if (dot == std::string::npos || dot == 0U)
            {
                return {canonicalSlot(normalized), ""};
            }

            return {normalized.substr(0, dot), normalized.substr(dot + 1U)};
        };

        std::unordered_map<std::string, std::vector<std::string>> parameterSlotsByFunction;
        for (const FunctionFacts &function : functions)
        {
            parameterSlotsByFunction[function.name] = collectParameterSlots(function, knownFunctions);
        }

        std::unordered_map<std::string, std::vector<StructMemberMapping>> incomingParameterMappings;
        std::unordered_map<std::string, const FunctionFacts *> functionMap;
        for (const FunctionFacts &function : functions)
        {
            functionMap[function.name] = &function;
        }

        for (const FunctionFacts &caller : functions)
        {
            for (const CallSite &callSite : caller.callSites)
            {
                if (callSite.directCallee.empty())
                {
                    continue;
                }

                const std::unordered_map<std::string, const FunctionFacts *>::const_iterator calleeIt =
                    functionMap.find(callSite.directCallee);
                if (calleeIt == functionMap.end())
                {
                    continue;
                }

                const std::vector<std::string> &params = parameterSlotsByFunction[callSite.directCallee];
                const std::size_t limit = std::min(params.size(), callSite.argumentExpressions.size());
                if (limit == 0U)
                {
                    continue;
                }

                std::unordered_map<std::string, std::vector<StructMemberMapping>> callerMappingsByVar;
                for (const StructMemberMapping &mapping : caller.structMemberMappings)
                {
                    callerMappingsByVar[mapping.structVariable].push_back(mapping);
                }

                for (std::size_t i = 0; i < limit; ++i)
                {
                    const std::string &param = params[i];
                    const std::string argSlot = canonicalSlot(callSite.argumentExpressions[i]);
                    if (argSlot.empty())
                    {
                        continue;
                    }

                    const std::unordered_map<std::string, std::vector<StructMemberMapping>>::const_iterator argMappingsIt =
                        callerMappingsByVar.find(argSlot);
                    if (argMappingsIt == callerMappingsByVar.end())
                    {
                        continue;
                    }

                    for (const StructMemberMapping &mapping : argMappingsIt->second)
                    {
                        StructMemberMapping propagated = mapping;
                        propagated.structVariable = param;
                        incomingParameterMappings[callSite.directCallee].push_back(std::move(propagated));
                    }
                }
            }
        }

        for (const FunctionFacts &function : functions)
        {
            std::unordered_set<std::string> localStructVars;
            std::unordered_map<std::string, std::vector<StructMemberMapping>> mappingsByVariable;
            for (const StructMemberMapping &mapping : function.structMemberMappings)
            {
                localStructVars.insert(mapping.structVariable);
                mappingsByVariable[mapping.structVariable].push_back(mapping);
            }

            const std::unordered_map<std::string, std::vector<StructMemberMapping>>::const_iterator incomingIt =
                incomingParameterMappings.find(function.name);
            if (incomingIt != incomingParameterMappings.end())
            {
                for (const StructMemberMapping &mapping : incomingIt->second)
                {
                    localStructVars.insert(mapping.structVariable);
                    mappingsByVariable[mapping.structVariable].push_back(mapping);
                }
            }

            if (localStructVars.empty())
            {
                continue;
            }

            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                for (const std::string &line : block.lines)
                {
                    const std::optional<std::pair<std::string, std::string>> copy = parseMemcpyArgsFromLine(line);
                    if (!copy.has_value())
                    {
                        continue;
                    }

                    const std::pair<std::string, std::string> dstAccess = splitStructAccess(copy->first);
                    const std::pair<std::string, std::string> srcAccess = splitStructAccess(copy->second);
                    const std::string &dstSlot = dstAccess.first;
                    const std::string &dstPrefix = dstAccess.second;
                    const std::string &srcSlot = srcAccess.first;
                    if (localStructVars.find(srcSlot) == localStructVars.end())
                    {
                        continue;
                    }
                    if (localStructVars.find(dstSlot) != localStructVars.end())
                    {
                        continue;
                    }

                    const std::unordered_map<std::string, std::vector<StructMemberMapping>>::const_iterator srcIt =
                        mappingsByVariable.find(srcSlot);
                    if (srcIt == mappingsByVariable.end())
                    {
                        continue;
                    }

                    std::unordered_map<std::string, std::uint64_t> latestStampByGroup;
                    for (const StructMemberMapping &mapping : srcIt->second)
                    {
                        const std::size_t groupDot = mapping.memberName.rfind('.');
                        const std::string group =
                            groupDot == std::string::npos ? mapping.memberName : mapping.memberName.substr(0, groupDot + 1U);
                        const std::string localGroupKey = mapping.structVariable + "#" + group;
                        const std::uint64_t stamp = (static_cast<std::uint64_t>(mapping.location.line) << 32U) |
                                                    static_cast<std::uint64_t>(mapping.location.column);
                        const std::unordered_map<std::string, std::uint64_t>::const_iterator latestIt =
                            latestStampByGroup.find(localGroupKey);
                        if (latestIt == latestStampByGroup.end() || stamp >= latestIt->second)
                        {
                            latestStampByGroup[localGroupKey] = stamp;
                        }
                    }

                    for (const StructMemberMapping &mapping : srcIt->second)
                    {
                        const std::size_t groupDot = mapping.memberName.rfind('.');
                        const std::string group =
                            groupDot == std::string::npos ? mapping.memberName : mapping.memberName.substr(0, groupDot + 1U);
                        const std::string localGroupKey = mapping.structVariable + "#" + group;
                        const std::uint64_t stamp = (static_cast<std::uint64_t>(mapping.location.line) << 32U) |
                                                    static_cast<std::uint64_t>(mapping.location.column);
                        const std::unordered_map<std::string, std::uint64_t>::const_iterator latestIt =
                            latestStampByGroup.find(localGroupKey);
                        if (latestIt != latestStampByGroup.end() && stamp != latestIt->second)
                        {
                            continue;
                        }

                        StructMemberMapping propagated = mapping;
                        propagated.structVariable = dstSlot;
                        if (!dstPrefix.empty())
                        {
                            propagated.memberName = dstPrefix + "." + propagated.memberName;
                        }
                        propagated.programWideSeed = true;
                        const std::string key = propagated.structVariable + "#" + propagated.memberName + "#" + propagated.functionName;
                        if (seen.insert(key).second)
                        {
                            result.push_back(std::move(propagated));
                        }
                    }
                }
            }
        }

        return result;
    }

    /**
     * @brief Resolve indirect call targets under current bindings.
     */
    std::set<std::string> resolveIndirectTargets(
        const CallSite &callSite,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &pointsTo,
        const std::vector<StructMemberMapping> &structMappings)
    {
        std::set<std::string> targets;

        if (!callSite.throughIdentifier.empty())
        {
            const std::set<std::string> throughTargets = resolveExpressionTargets(callSite.throughIdentifier, knownFunctions, pointsTo);
            targets.insert(throughTargets.begin(), throughTargets.end());
        }
        if (!callSite.calleeExpression.empty())
        {
            const std::set<std::string> calleeTargets = resolveExpressionTargets(callSite.calleeExpression, knownFunctions, pointsTo);
            targets.insert(calleeTargets.begin(), calleeTargets.end());
        }

        std::function<std::string(const StructMemberMapping &)> memberGroupKey = [&](const StructMemberMapping &mapping)
        {
            std::string groupBase = mapping.structVariable;
            const std::set<std::string> aliasTargets =
                resolveTransitiveTargets(std::set<std::string>{mapping.structVariable}, knownFunctions, pointsTo, true);
            if (aliasTargets.size() == 1U)
            {
                const std::string &candidate = *aliasTargets.begin();
                if (!candidate.empty() &&
                    !isIntegerBinding(candidate) &&
                    knownFunctions.find(candidate) == knownFunctions.end())
                {
                    groupBase = candidate;
                }
            }

            const std::size_t dotIndex = mapping.memberName.rfind('.');
            const std::string group = dotIndex == std::string::npos ? mapping.memberName : mapping.memberName.substr(0, dotIndex + 1U);
            return groupBase + "#" + group;
        };

        std::vector<const StructMemberMapping *> activeMappings;
        activeMappings.reserve(structMappings.size());

        std::unordered_map<std::string, std::uint64_t> latestStampByGroup;
        for (const StructMemberMapping &mapping : structMappings)
        {
            if (mapping.programWideSeed)
            {
                continue;
            }

            const std::string key = memberGroupKey(mapping);
            const std::uint64_t stamp = (static_cast<std::uint64_t>(mapping.location.line) << 32U) |
                                        static_cast<std::uint64_t>(mapping.location.column);
            const std::unordered_map<std::string, std::uint64_t>::const_iterator it = latestStampByGroup.find(key);
            if (it == latestStampByGroup.end() || stamp >= it->second)
            {
                latestStampByGroup[key] = stamp;
            }
        }

        for (const StructMemberMapping &mapping : structMappings)
        {
            if (!mapping.programWideSeed)
            {
                const std::string key = memberGroupKey(mapping);
                const std::uint64_t stamp = (static_cast<std::uint64_t>(mapping.location.line) << 32U) |
                                            static_cast<std::uint64_t>(mapping.location.column);
                const std::unordered_map<std::string, std::uint64_t>::const_iterator it = latestStampByGroup.find(key);
                if (it != latestStampByGroup.end() && stamp != it->second)
                {
                    continue;
                }
            }

            activeMappings.push_back(&mapping);
        }

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

        std::function<std::string(const std::string &)> trimWhitespace = [](const std::string &text)
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
        };

        std::function<std::string(const std::string &)> removeAllWhitespace = [](const std::string &text)
        {
            std::string out;
            out.reserve(text.size());
            for (char ch : text)
            {
                if (std::isspace(static_cast<unsigned char>(ch)) == 0)
                {
                    out.push_back(ch);
                }
            }
            return out;
        };

        // Try to resolve struct member access (e.g., "global_ops.opA")
        std::string normalizedCallee = callSite.calleeExpression;
        for (std::size_t pos = normalizedCallee.find("->"); pos != std::string::npos; pos = normalizedCallee.find("->", pos + 1U))
        {
            normalizedCallee.replace(pos, 2U, ".");
        }
        normalizedCallee = removeArrayIndices(normalizedCallee);
        normalizedCallee = trimWhitespace(normalizedCallee);
        normalizedCallee = removeAllWhitespace(normalizedCallee);

        const std::size_t dotIndex = normalizedCallee.find('.');
        if (dotIndex != std::string::npos && dotIndex > 0)
        {
            const std::string structVar = normalizedCallee.substr(0, dotIndex);
            const std::string memberName = normalizedCallee.substr(dotIndex + 1U);
            const std::size_t nestedDot = memberName.rfind('.');
            const std::string leafMemberName =
                nestedDot == std::string::npos ? memberName : memberName.substr(nestedDot + 1U);

            std::function<bool(const std::string &)> isSimpleIdentifier = [](const std::string &text)
            {
                if (text.empty())
                {
                    return false;
                }

                const unsigned char first = static_cast<unsigned char>(text[0]);
                if (std::isalpha(first) == 0 && text[0] != '_')
                {
                    return false;
                }

                for (std::size_t i = 1; i < text.size(); ++i)
                {
                    const unsigned char ch = static_cast<unsigned char>(text[i]);
                    if (std::isalnum(ch) == 0 && text[i] != '_')
                    {
                        return false;
                    }
                }

                return true;
            };

            std::function<bool(const StructMemberMapping &)> mappingMatchesMember = [&](const StructMemberMapping &mapping)
            {
                const std::size_t mappingNestedDot = mapping.memberName.rfind('.');
                const std::string mappingLeafMemberName =
                    mappingNestedDot == std::string::npos ? mapping.memberName : mapping.memberName.substr(mappingNestedDot + 1U);

                return mapping.memberName == memberName ||
                       mapping.memberName == leafMemberName ||
                       mappingLeafMemberName == memberName;
            };

            for (const StructMemberMapping *mappingPtr : activeMappings)
            {
                const StructMemberMapping &mapping = *mappingPtr;
                if (mapping.structVariable == structVar && mappingMatchesMember(mapping))
                {
                    targets.insert(mapping.functionName);
                }
            }

            const std::set<std::string> aliasSlots =
                resolveTransitiveTargets(std::set<std::string>{structVar}, knownFunctions, pointsTo, true);
            bool aliasChainLooksIndirect = false;
            std::set<std::string> aliasPointeeTargets;
            if (!aliasSlots.empty())
            {
                aliasPointeeTargets.insert(aliasSlots.begin(), aliasSlots.end());
                for (const std::string &aliasBase : aliasSlots)
                {
                    if (knownFunctions.find(aliasBase) == knownFunctions.end())
                    {
                        aliasChainLooksIndirect = true;
                    }

                    for (const StructMemberMapping *mappingPtr : activeMappings)
                    {
                        const StructMemberMapping &mapping = *mappingPtr;
                        if (mapping.structVariable == aliasBase && mappingMatchesMember(mapping))
                        {
                            targets.insert(mapping.functionName);
                        }
                    }
                }

                for (const std::pair<const std::string, std::set<std::string>> &entry : pointsTo)
                {
                    if (entry.first == structVar)
                    {
                        continue;
                    }

                    bool sharesPointee = false;
                    for (const std::string &value : entry.second)
                    {
                        if (aliasPointeeTargets.find(value) != aliasPointeeTargets.end())
                        {
                            sharesPointee = true;
                            break;
                        }
                    }

                    if (!sharesPointee)
                    {
                        continue;
                    }

                    for (const StructMemberMapping &mapping : structMappings)
                    {
                        if (mapping.structVariable == entry.first && mappingMatchesMember(mapping))
                        {
                            targets.insert(mapping.functionName);
                        }
                    }
                }
            }

            if (targets.empty() && aliasChainLooksIndirect && !isSimpleIdentifier(structVar))
            {
                for (const StructMemberMapping *mappingPtr : activeMappings)
                {
                    const StructMemberMapping &mapping = *mappingPtr;
                    if (mappingMatchesMember(mapping))
                    {
                        targets.insert(mapping.functionName);
                    }
                }
            }

            if (targets.empty() &&
                (structVar.find('(') != std::string::npos || structVar.find(')') != std::string::npos ||
                 structVar.find('[') != std::string::npos || structVar.find(']') != std::string::npos))
            {
                for (const StructMemberMapping *mappingPtr : activeMappings)
                {
                    const StructMemberMapping &mapping = *mappingPtr;
                    if (mappingMatchesMember(mapping))
                    {
                        targets.insert(mapping.functionName);
                    }
                }
            }

            if (targets.empty() && !isSimpleIdentifier(structVar))
            {
                // Conservative fallback: if only the member name is known, use any mapping with same member.
                for (const StructMemberMapping *mappingPtr : activeMappings)
                {
                    const StructMemberMapping &mapping = *mappingPtr;
                    if (mappingMatchesMember(mapping))
                    {
                        targets.insert(mapping.functionName);
                    }
                }
            }
        }

        if (!callSite.throughIdentifier.empty())
        {
            const std::unordered_map<std::string, std::set<std::string>>::const_iterator through =
                pointsTo.find(callSite.throughIdentifier);
            if (through != pointsTo.end())
            {
                targets.insert(through->second.begin(), through->second.end());
            }
        }

        if (targets.empty())
        {
            const std::string slot = canonicalSlot(callSite.calleeExpression);
            const std::unordered_map<std::string, std::set<std::string>>::const_iterator slotIt = pointsTo.find(slot);
            if (slotIt != pointsTo.end())
            {
                targets.insert(slotIt->second.begin(), slotIt->second.end());
            }
        }

        if (targets.empty())
        {
            for (const std::string &identifier : extractIdentifiers(callSite.calleeExpression))
            {
                if (knownFunctions.find(identifier) != knownFunctions.end())
                {
                    targets.insert(identifier);
                }
            }
        }

        std::set<std::string> resolvedFunctions;
        std::deque<std::string> pending(targets.begin(), targets.end());
        std::unordered_set<std::string> seenAliases;

        while (!pending.empty())
        {
            const std::string value = pending.front();
            pending.pop_front();

            if (knownFunctions.find(value) != knownFunctions.end())
            {
                resolvedFunctions.insert(value);
                continue;
            }

            if (!seenAliases.insert(value).second)
            {
                continue;
            }

            const std::unordered_map<std::string, std::set<std::string>>::const_iterator it = pointsTo.find(value);
            if (it == pointsTo.end())
            {
                continue;
            }

            for (const std::string &next : it->second)
            {
                pending.push_back(next);
            }
        }

        return resolvedFunctions;
    }

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
     * @brief Detect wrapper-style parameter dispatch functions.
     */
    std::unordered_map<std::string, ParameterDispatchInfo> detectParameterDispatchFunctions(
        const std::vector<FunctionFacts> &functions)
    {
        std::unordered_map<std::string, ParameterDispatchInfo> result;

        for (const FunctionFacts &function : functions)
        {
            std::unordered_set<std::string> assignedSlots;
            for (const PointerAssignment &assignment : function.pointerAssignments)
            {
                const std::string slot = canonicalSlot(assignment.lhsExpression);
                if (!slot.empty())
                {
                    assignedSlots.insert(slot);
                }
            }

            ParameterDispatchInfo info;
            for (const CallSite &callSite : function.callSites)
            {
                if (!callSite.directCallee.empty())
                {
                    continue;
                }

                std::string slot;
                if (!callSite.throughIdentifier.empty())
                {
                    slot = canonicalSlot(callSite.throughIdentifier);
                }
                if (slot.empty())
                {
                    slot = canonicalSlot(callSite.calleeExpression);
                }

                if (!slot.empty() && assignedSlots.find(slot) == assignedSlots.end())
                {
                    info.dispatchSlots.insert(slot);
                    if (info.callLocation.file.empty())
                    {
                        info.callLocation = callSite.location;
                    }
                }
            }

            if (!info.dispatchSlots.empty())
            {
                result[function.name] = std::move(info);
            }
        }

        return result;
    }

    /**
     * @brief Collect wrapper dispatch targets from direct call sites to wrapper-style functions.
     */
    std::unordered_map<std::string, std::set<std::string>> collectWrapperDispatchTargets(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions,
        const std::unordered_map<std::string, ParameterDispatchInfo> &dispatchFunctions)
    {
        std::unordered_map<std::string, std::set<std::string>> wrapperTargets;
        const std::unordered_map<std::string, std::set<std::string>> emptyBindings;

        for (const FunctionFacts &function : functions)
        {
            for (const CallSite &callSite : function.callSites)
            {
                if (callSite.directCallee.empty())
                {
                    continue;
                }

                if (dispatchFunctions.find(callSite.directCallee) == dispatchFunctions.end())
                {
                    continue;
                }

                std::set<std::string> &targets = wrapperTargets[callSite.directCallee];
                for (const std::string &argumentExpression : callSite.argumentExpressions)
                {
                    const std::set<std::string> resolved = resolveExpressionTargets(argumentExpression, knownFunctions, emptyBindings);
                    targets.insert(resolved.begin(), resolved.end());
                }
            }
        }

        return wrapperTargets;
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
     * @brief Collect struct member mappings that flow out of returned local structs.
     */
    std::unordered_map<std::string, std::vector<StructMemberMapping>> collectReturnedStructMemberMappingsByFunction(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions)
    {
        std::unordered_map<std::string, std::vector<StructMemberMapping>> result;

        std::function<std::string(const std::string &)> normalizeStructAccess = [](const std::string &expression)
        {
            std::string normalized = expression;
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

            return trimLine(stripped);
        };

        std::function<std::pair<std::string, std::string>(const std::string &)> parseStructAccess =
            [&](const std::string &expression) -> std::pair<std::string, std::string>
        {
            const std::string normalized = normalizeStructAccess(expression);
            const std::size_t dotIndex = normalized.find('.');
            if (dotIndex == std::string::npos || dotIndex == 0U)
            {
                return {"", ""};
            }

            return {normalized.substr(0, dotIndex), normalized.substr(dotIndex + 1U)};
        };

        for (const FunctionFacts &function : functions)
        {
            std::unordered_map<std::string, std::vector<StructMemberMapping>> mappingsByVariable;
            std::unordered_set<std::string> seen;

            std::function<void(const std::string &, const std::string &, const std::string &)> addMapping =
                [&](const std::string &structVariable, const std::string &memberName, const std::string &functionName)
            {
                const std::string key = structVariable + "#" + memberName + "#" + functionName;
                if (!seen.insert(key).second)
                {
                    return;
                }

                StructMemberMapping mapping;
                mapping.structVariable = structVariable;
                mapping.memberName = memberName;
                mapping.functionName = functionName;
                mappingsByVariable[structVariable].push_back(std::move(mapping));
            };

            for (const StructMemberMapping &mapping : function.structMemberMappings)
            {
                addMapping(mapping.structVariable, mapping.memberName, mapping.functionName);
            }

            bool changed = true;
            const PointsToMap emptyBindings;
            while (changed)
            {
                changed = false;

                for (const PointerAssignment &assignment : function.pointerAssignments)
                {
                    const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
                    if (lhsSlot.empty())
                    {
                        continue;
                    }

                    const std::pair<std::string, std::string> lhsAccess = parseStructAccess(assignment.lhsExpression);
                    if (!lhsAccess.first.empty() && !lhsAccess.second.empty())
                    {
                        const std::set<std::string> targets = resolveAssignmentTargets(assignment, knownFunctions, emptyBindings);
                        for (const std::string &target : targets)
                        {
                            const std::size_t before = seen.size();
                            addMapping(lhsAccess.first, lhsAccess.second, target);
                            if (seen.size() != before)
                            {
                                changed = true;
                            }
                        }
                    }

                    const std::string rhsSlot = canonicalSlot(assignment.rhsExpression);
                    if (rhsSlot.empty() || rhsSlot == lhsSlot)
                    {
                        continue;
                    }

                    const std::unordered_map<std::string, std::vector<StructMemberMapping>>::const_iterator rhsIt =
                        mappingsByVariable.find(rhsSlot);
                    if (rhsIt == mappingsByVariable.end())
                    {
                        continue;
                    }

                    for (const StructMemberMapping &mapping : rhsIt->second)
                    {
                        const std::size_t before = seen.size();
                        addMapping(lhsSlot, mapping.memberName, mapping.functionName);
                        if (seen.size() != before)
                        {
                            changed = true;
                        }
                    }
                }
            }

            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                for (const std::string &rawLine : block.lines)
                {
                    const std::string line = trimLine(rawLine);
                    if (line.rfind("return ", 0) != 0)
                    {
                        continue;
                    }

                    std::string returned = trimLine(line.substr(7U));
                    if (!returned.empty() && returned.back() == ';')
                    {
                        returned.pop_back();
                        returned = trimLine(returned);
                    }

                    const std::string returnedSlot = canonicalSlot(returned);
                    if (returnedSlot.empty())
                    {
                        continue;
                    }

                    const std::unordered_map<std::string, std::vector<StructMemberMapping>>::const_iterator mappingsIt =
                        mappingsByVariable.find(returnedSlot);
                    if (mappingsIt == mappingsByVariable.end())
                    {
                        continue;
                    }

                    for (const StructMemberMapping &mapping : mappingsIt->second)
                    {
                        const std::string key = mapping.structVariable + "#" + mapping.memberName + "#" + mapping.functionName;
                        if (seen.insert(key).second)
                        {
                            result[function.name].push_back(mapping);
                        }
                    }
                }
            }
        }

        return result;
    }

    /**
     * @brief Legacy linear analyzer (retained for debugging/reference).
     */
    void analyzeFunction(
        const FunctionFacts &function,
        const std::set<std::string> &knownFunctions,
        const std::set<std::string> &blacklistedFunctions,
        const std::unordered_map<std::string, ParameterDispatchInfo> &parameterDispatchFunctions,
        std::unordered_map<std::string, std::set<std::string>> &wrapperDispatchTargets,
        std::vector<CallEdge> &resolvedEdges,
        std::vector<CallEdge> &unresolvedIndirect)
    {
        std::unordered_map<std::string, std::set<std::string>> pointsTo;

        for (const Event &event : buildEvents(function))
        {
            if (event.kind == EventKind::kAssignment)
            {
                const PointerAssignment &assignment = *event.assignment;
                const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
                if (lhsSlot.empty())
                {
                    continue;
                }

                const std::set<std::string> targets = resolveAssignmentTargets(assignment, knownFunctions, pointsTo);
                if (targets.empty())
                {
                    continue;
                }

                std::set<std::string> &slotTargets = pointsTo[lhsSlot];
                slotTargets.insert(targets.begin(), targets.end());
                continue;
            }

            const CallSite &callSite = *event.callSite;
            if (!callSite.directCallee.empty())
            {
                if (isBlacklistedFunction(callSite.directCallee, blacklistedFunctions))
                {
                    continue;
                }

                CallEdge edge;
                edge.caller = function.name;
                edge.callee = callSite.directCallee;
                edge.kind = "direct";
                edge.location = callSite.location;
                edge.calleeExpression = callSite.calleeExpression;
                edge.throughIdentifier = callSite.throughIdentifier;
                resolvedEdges.push_back(std::move(edge));

                if (parameterDispatchFunctions.find(callSite.directCallee) != parameterDispatchFunctions.end())
                {
                    std::set<std::string> argumentTargetsUnion;
                    for (const std::string &argumentExpression : callSite.argumentExpressions)
                    {
                        const std::set<std::string> argumentTargets =
                            resolveExpressionTargets(argumentExpression, knownFunctions, pointsTo);
                        argumentTargetsUnion.insert(argumentTargets.begin(), argumentTargets.end());
                    }

                    if (!argumentTargetsUnion.empty())
                    {
                        std::set<std::string> &wrapperTargets = wrapperDispatchTargets[callSite.directCallee];
                        wrapperTargets.insert(argumentTargetsUnion.begin(), argumentTargetsUnion.end());
                    }
                }
                continue;
            }

            const std::set<std::string> targets = resolveIndirectTargets(callSite, knownFunctions, pointsTo, function.structMemberMappings);
            std::set<std::string> filteredTargets;
            for (const std::string &target : targets)
            {
                if (!isBlacklistedFunction(target, blacklistedFunctions))
                {
                    filteredTargets.insert(target);
                }
            }

            if (filteredTargets.empty())
            {
                CallEdge edge;
                edge.caller = function.name;
                edge.kind = "indirect";
                edge.location = callSite.location;
                edge.calleeExpression = callSite.calleeExpression;
                edge.throughIdentifier = callSite.throughIdentifier;
                unresolvedIndirect.push_back(std::move(edge));
                logUnresolvedCall(unresolvedIndirect.back());
                continue;
            }
            for (const std::string &callee : filteredTargets)
            {
                CallEdge edge;
                edge.caller = function.name;
                edge.callee = callee;
                edge.kind = "indirect";
                edge.location = callSite.location;
                edge.calleeExpression = callSite.calleeExpression;
                edge.throughIdentifier = callSite.throughIdentifier;
                resolvedEdges.push_back(std::move(edge));
            }
        }
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
     * @brief Build a deterministic key for one struct-member mapping.
     */
    std::string makeStructMemberMappingKey(const StructMemberMapping &mapping)
    {
        return mapping.structVariable + "#" + mapping.memberName + "#" + mapping.functionName + "@" +
               std::to_string(mapping.location.line) + ":" + std::to_string(mapping.location.column);
    }

    /**
     * @brief Build a deterministic key for a set of struct-member mappings.
     */
    std::string buildStructMemberMappingsKey(const std::vector<StructMemberMapping> &mappings)
    {
        std::vector<std::string> keys;
        keys.reserve(mappings.size());
        for (const StructMemberMapping &mapping : mappings)
        {
            keys.push_back(makeStructMemberMappingKey(mapping));
        }
        std::sort(keys.begin(), keys.end());

        std::string key;
        for (const std::string &mappingKey : keys)
        {
            key += mappingKey;
            key += ";";
        }
        return key;
    }

    /**
     * @brief Build stable context key for worklist deduplication.
     */
    std::string buildContextKey(const std::string &functionName, const PointsToMap &pointsTo)
    {
        std::vector<std::pair<std::string, std::vector<std::string>>> entries;
        entries.reserve(pointsTo.size());

        for (const std::pair<const std::string, std::set<std::string>> &entry : pointsTo)
        {
            std::vector<std::string> targets(entry.second.begin(), entry.second.end());
            std::sort(targets.begin(), targets.end());
            entries.emplace_back(entry.first, std::move(targets));
        }

        std::sort(entries.begin(), entries.end(), [](const std::pair<std::string, std::vector<std::string>> &lhs, const std::pair<std::string, std::vector<std::string>> &rhs)
                  { return lhs.first < rhs.first; });

        std::string key = functionName;
        key += "|";
        for (const std::pair<std::string, std::vector<std::string>> &entry : entries)
        {
            key += entry.first;
            key += "=";
            for (const std::string &target : entry.second)
            {
                key += target;
                key += ",";
            }
            key += ";";
        }
        return key;
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

    /**
     * @brief Run flow-sensitive and context-sensitive callgraph resolution.
     */
    void runContextSensitiveAnalysis(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions,
        const std::set<std::string> &blacklistedFunctions,
        const std::unordered_map<std::string, std::set<std::string>> &wrapperDispatchTargets,
        std::vector<CallEdge> &resolvedEdges,
        std::vector<CallEdge> &unresolvedIndirect)
    {
        std::unordered_map<std::string, const FunctionFacts *> functionMap;
        std::unordered_map<std::string, std::vector<std::string>> parameterSlotsByFunction;
        std::unordered_map<std::string, std::set<std::string>> pointerSlotsByFunction;
        const std::unordered_map<std::string, std::set<std::string>> programWidePointerTargets =
            collectProgramWidePointerTargets(functions, knownFunctions);
        const std::vector<StructMemberMapping> programWideStructMemberMappings =
            collectProgramWideStructMemberMappings(functions, knownFunctions);
        const std::unordered_map<std::string, std::set<std::string>> returnTargetsByFunction =
            collectReturnTargetsByFunction(functions, knownFunctions);
        const std::unordered_map<std::string, std::vector<StructMemberMapping>> returnedStructMemberMappingsByFunction =
            collectReturnedStructMemberMappingsByFunction(functions, knownFunctions);
        const std::unordered_map<std::string, std::set<std::string>> memcpySummaryTargetsByDstSlot =
            collectMemcpyCopySummaryTargets(functions, knownFunctions);
        // Precompute per-function metadata used during traversal.
        for (const FunctionFacts &function : functions)
        {
            functionMap[function.name] = &function;
            parameterSlotsByFunction[function.name] = collectParameterSlots(function, knownFunctions);
            pointerSlotsByFunction[function.name] = collectPointerSlots(function);
        }

        std::deque<ContextJob> worklist;
        std::unordered_set<std::string> seenContexts;

        // Start from every discovered function so snippets without main are covered.
        for (const std::pair<const std::string, const FunctionFacts *> &entry : functionMap)
        {
            worklist.push_back(ContextJob{entry.first, {}, {}});
            seenContexts.insert(buildContextKey(entry.first, {}) + "|sm:");
        }

        while (!worklist.empty())
        {
            ContextJob job = std::move(worklist.front());
            worklist.pop_front();

            logFunctionProcessed(job.functionName, job.seededPointsTo);

            const std::unordered_map<std::string, const FunctionFacts *>::const_iterator functionIt = functionMap.find(job.functionName);
            // Skip stale jobs if the function cannot be found.
            if (functionIt == functionMap.end())
            {
                continue;
            }

            const FunctionFacts &function = *functionIt->second;

            const std::vector<FunctionFacts::BlockFact>::const_iterator blockIt = std::find_if(function.blocks.begin(), function.blocks.end(), [&](const FunctionFacts::BlockFact &block)
                                                                                               { return block.id == function.entryBlockId; });
            // Without a valid entry block we cannot evaluate this function.
            if (blockIt == function.blocks.end())
            {
                continue;
            }

            std::unordered_map<std::uint32_t, const FunctionFacts::BlockFact *> blockMap;
            for (const FunctionFacts::BlockFact &block : function.blocks)
            {
                blockMap[block.id] = &block;
            }

            const std::set<std::string> pointerSlots = pointerSlotsByFunction[function.name];
            const std::vector<std::string> &parameterSlots = parameterSlotsByFunction[function.name];

            std::vector<StructMemberMapping> activeStructMemberMappings = function.structMemberMappings;
            activeStructMemberMappings.insert(
                activeStructMemberMappings.end(),
                job.seededStructMemberMappings.begin(),
                job.seededStructMemberMappings.end());
            activeStructMemberMappings.insert(
                activeStructMemberMappings.end(),
                programWideStructMemberMappings.begin(),
                programWideStructMemberMappings.end());
            std::unordered_set<std::string> seenStructMemberMappings;
            for (const StructMemberMapping &mapping : activeStructMemberMappings)
            {
                seenStructMemberMappings.insert(makeStructMemberMappingKey(mapping));
            }

            std::function<void(std::vector<StructMemberMapping> &,
                               std::unordered_set<std::string> &,
                               const std::string &,
                               const std::vector<StructMemberMapping> &)>
                appendStructMemberMappings = [&](std::vector<StructMemberMapping> &structMemberMappings,
                                                 std::unordered_set<std::string> &seenMappings,
                                                 const std::string &structVariable,
                                                 const std::vector<StructMemberMapping> &sourceMappings)
            {
                for (const StructMemberMapping &mapping : sourceMappings)
                {
                    StructMemberMapping propagated = mapping;
                    propagated.structVariable = structVariable;
                    const std::string key = makeStructMemberMappingKey(propagated);
                    if (seenMappings.insert(key).second)
                    {
                        structMemberMappings.push_back(std::move(propagated));
                    }
                }
            };

            std::function<std::unordered_set<std::string>(const std::string &, const PointsToMap &)> collectOverwriteSlots =
                [&](const std::string &slot, const PointsToMap &currentBindings)
            {
                std::unordered_set<std::string> overwriteSlots;
                overwriteSlots.insert(slot);

                const PointsToMap::const_iterator slotIt = currentBindings.find(slot);
                if (slotIt == currentBindings.end())
                {
                    return overwriteSlots;
                }

                for (const std::pair<const std::string, std::set<std::string>> &entry : currentBindings)
                {
                    if (entry.first == slot)
                    {
                        continue;
                    }

                    bool sharesPointee = false;
                    for (const std::string &value : entry.second)
                    {
                        if (slotIt->second.find(value) != slotIt->second.end())
                        {
                            sharesPointee = true;
                            break;
                        }
                    }

                    if (sharesPointee)
                    {
                        overwriteSlots.insert(entry.first);
                    }
                }

                return overwriteSlots;
            };

            std::function<std::string(std::string)> normalizeStructAccess = [&](std::string text)
            {
                for (std::size_t pos = text.find("->"); pos != std::string::npos; pos = text.find("->", pos + 1U))
                {
                    text.replace(pos, 2U, ".");
                }

                std::string stripped;
                stripped.reserve(text.size());
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
                        stripped.push_back(ch);
                    }
                }

                return stripped;
            };

            std::function<std::pair<std::string, std::string>(const std::string &)> parseStructAccess =
                [&](const std::string &expression) -> std::pair<std::string, std::string>
            {
                const std::string normalized = trimLine(normalizeStructAccess(expression));
                const std::size_t dotIndex = normalized.find('.');
                if (dotIndex == std::string::npos || dotIndex == 0U)
                {
                    return {"", ""};
                }

                return {normalized.substr(0, dotIndex), normalized.substr(dotIndex + 1U)};
            };

            std::function<void(std::vector<StructMemberMapping> &,
                               std::unordered_set<std::string> &,
                               const std::string &,
                               const PointsToMap &)>
                pruneOverwrittenStructMemberMappings = [&](std::vector<StructMemberMapping> &structMemberMappings,
                                                           std::unordered_set<std::string> &seenMappings,
                                                           const std::string &lhsExpression,
                                                           const PointsToMap &currentBindings)
            {
                const std::pair<std::string, std::string> lhsAccess = parseStructAccess(lhsExpression);
                if (lhsAccess.first.empty() || lhsAccess.second.empty())
                {
                    return;
                }

                std::string memberPrefix = lhsAccess.second;
                const std::size_t prefixDot = memberPrefix.rfind('.');
                if (prefixDot != std::string::npos)
                {
                    memberPrefix = memberPrefix.substr(0, prefixDot + 1U);
                }

                const std::unordered_set<std::string> overwriteSlots = collectOverwriteSlots(lhsAccess.first, currentBindings);
                for (std::vector<StructMemberMapping>::iterator it = structMemberMappings.begin(); it != structMemberMappings.end();)
                {
                    const bool slotMatches = overwriteSlots.find(it->structVariable) != overwriteSlots.end();
                    const bool memberMatches =
                        (prefixDot == std::string::npos) ? (it->memberName == lhsAccess.second) : (it->memberName.rfind(memberPrefix, 0U) == 0U);
                    if (slotMatches && memberMatches)
                    {
                        seenMappings.erase(makeStructMemberMappingKey(*it));
                        it = structMemberMappings.erase(it);
                        continue;
                    }

                    ++it;
                }
            };

            std::function<void(std::vector<StructMemberMapping> &,
                               std::unordered_set<std::string> &,
                               const std::string &,
                               const std::string &,
                               const PointsToMap &)>
                pruneOverwrittenStructMemberGroup = [&](std::vector<StructMemberMapping> &structMemberMappings,
                                                        std::unordered_set<std::string> &seenMappings,
                                                        const std::string &structSlot,
                                                        const std::string &memberName,
                                                        const PointsToMap &currentBindings)
            {
                std::string memberPrefix = memberName;
                const std::size_t prefixDot = memberPrefix.rfind('.');
                if (prefixDot != std::string::npos)
                {
                    memberPrefix = memberPrefix.substr(0, prefixDot + 1U);
                }

                const std::unordered_set<std::string> overwriteSlots = collectOverwriteSlots(structSlot, currentBindings);
                for (std::vector<StructMemberMapping>::iterator it = structMemberMappings.begin(); it != structMemberMappings.end();)
                {
                    const bool slotMatches = overwriteSlots.find(it->structVariable) != overwriteSlots.end();
                    const bool memberMatches =
                        (prefixDot == std::string::npos) ? (it->memberName == memberName) : (it->memberName.rfind(memberPrefix, 0U) == 0U);
                    if (slotMatches && memberMatches)
                    {
                        seenMappings.erase(makeStructMemberMappingKey(*it));
                        it = structMemberMappings.erase(it);
                        continue;
                    }
                    ++it;
                }
            };

            std::function<void(const CallSite &,
                               const std::string &,
                               const PointsToMap &,
                               std::vector<StructMemberMapping> &,
                               std::unordered_set<std::string> &)>
                propagateCalleeStructMemberMappings = [&](const CallSite &callSite,
                                                          const std::string &calleeName,
                                                          const PointsToMap &currentBindings,
                                                          std::vector<StructMemberMapping> &structMemberMappings,
                                                          std::unordered_set<std::string> &seenMappings)
            {
                const std::unordered_map<std::string, const FunctionFacts *>::const_iterator calleeIt = functionMap.find(calleeName);
                if (calleeIt == functionMap.end())
                {
                    return;
                }

                const std::vector<std::string> &calleeParameters = parameterSlotsByFunction[calleeName];
                const std::set<std::string> &calleePointerSlots = pointerSlotsByFunction[calleeName];
                const std::size_t limit = std::min(calleeParameters.size(), callSite.argumentExpressions.size());

                std::unordered_map<std::string, std::string> parameterToArgumentSlot;
                for (std::size_t index = 0; index < limit; ++index)
                {
                    const std::string &parameter = calleeParameters[index];
                    const std::string &argumentExpression = callSite.argumentExpressions[index];
                    const std::string argumentSlot = canonicalSlot(argumentExpression);
                    if (argumentSlot.empty())
                    {
                        continue;
                    }

                    if (argumentExpression.find('&') != std::string::npos ||
                        calleePointerSlots.find(parameter) != calleePointerSlots.end())
                    {
                        parameterToArgumentSlot[parameter] = argumentSlot;
                    }
                }

                if (parameterToArgumentSlot.empty())
                {
                    std::vector<std::string> argumentSlots;
                    for (const std::string &argumentExpression : callSite.argumentExpressions)
                    {
                        if (argumentExpression.find('&') == std::string::npos)
                        {
                            continue;
                        }

                        const std::string slot = canonicalSlot(argumentExpression);
                        if (!slot.empty())
                        {
                            argumentSlots.push_back(slot);
                        }
                    }

                    std::vector<std::string> mappingVariables;
                    std::unordered_set<std::string> seenMappingVariables;
                    for (const StructMemberMapping &mapping : calleeIt->second->structMemberMappings)
                    {
                        if (seenMappingVariables.insert(mapping.structVariable).second)
                        {
                            mappingVariables.push_back(mapping.structVariable);
                        }
                    }

                    const std::size_t fallbackLimit = std::min(mappingVariables.size(), argumentSlots.size());
                    for (std::size_t i = 0; i < fallbackLimit; ++i)
                    {
                        parameterToArgumentSlot[mappingVariables[i]] = argumentSlots[i];
                    }
                }

                if (parameterToArgumentSlot.empty())
                {
                    return;
                }

                std::unordered_set<std::string> prunedGroups;

                std::unordered_map<std::string, std::uint64_t> latestStampByLocalGroup;
                for (const StructMemberMapping &mapping : calleeIt->second->structMemberMappings)
                {
                    const std::size_t groupDot = mapping.memberName.rfind('.');
                    const std::string group = groupDot == std::string::npos ? mapping.memberName : mapping.memberName.substr(0, groupDot + 1U);
                    const std::string localGroupKey = mapping.structVariable + "#" + group;
                    const std::uint64_t stamp = (static_cast<std::uint64_t>(mapping.location.line) << 32U) |
                                                static_cast<std::uint64_t>(mapping.location.column);
                    const std::unordered_map<std::string, std::uint64_t>::const_iterator it = latestStampByLocalGroup.find(localGroupKey);
                    if (it == latestStampByLocalGroup.end() || stamp >= it->second)
                    {
                        latestStampByLocalGroup[localGroupKey] = stamp;
                    }
                }

                for (const StructMemberMapping &mapping : calleeIt->second->structMemberMappings)
                {
                    const std::unordered_map<std::string, std::string>::const_iterator targetIt = parameterToArgumentSlot.find(mapping.structVariable);
                    if (targetIt == parameterToArgumentSlot.end())
                    {
                        continue;
                    }

                    const std::size_t localGroupDot = mapping.memberName.rfind('.');
                    const std::string localGroup = localGroupDot == std::string::npos ? mapping.memberName : mapping.memberName.substr(0, localGroupDot + 1U);
                    const std::string localGroupKey = mapping.structVariable + "#" + localGroup;
                    const std::uint64_t stamp = (static_cast<std::uint64_t>(mapping.location.line) << 32U) |
                                                static_cast<std::uint64_t>(mapping.location.column);
                    const std::unordered_map<std::string, std::uint64_t>::const_iterator latestIt = latestStampByLocalGroup.find(localGroupKey);
                    if (latestIt != latestStampByLocalGroup.end() && stamp != latestIt->second)
                    {
                        continue;
                    }

                    const std::size_t groupDot = mapping.memberName.rfind('.');
                    const std::string group = groupDot == std::string::npos ? mapping.memberName : mapping.memberName.substr(0, groupDot + 1U);
                    const std::string pruneKey = targetIt->second + "#" + group;
                    if (prunedGroups.insert(pruneKey).second)
                    {
                        pruneOverwrittenStructMemberGroup(structMemberMappings, seenMappings, targetIt->second, mapping.memberName, currentBindings);
                    }

                    StructMemberMapping propagated = mapping;
                    propagated.structVariable = targetIt->second;
                    propagated.location = callSite.location;

                    const std::string key = makeStructMemberMappingKey(propagated);
                    if (seenMappings.insert(key).second)
                    {
                        structMemberMappings.push_back(std::move(propagated));
                    }
                }
            };

            struct BlockState
            {
                std::uint32_t blockId = 0;
                PointsToMap bindings;
                std::vector<StructMemberMapping> structMemberMappings;
            };

            std::deque<BlockState> blockWorklist;
            std::unordered_set<std::string> seenBlockStates;
            PointsToMap initialBindings = std::move(job.seededPointsTo);
            blockWorklist.push_back(BlockState{function.entryBlockId, std::move(initialBindings), activeStructMemberMappings});

            std::function<std::string(std::uint32_t, const PointsToMap &, const std::vector<StructMemberMapping> &)> makeStateKey =
                [&](std::uint32_t blockId, const PointsToMap &bindings, const std::vector<StructMemberMapping> &structMemberMappings)
            {
                return std::to_string(blockId) + "|" + buildContextKey(function.name, bindings) + "|" + buildStructMemberMappingsKey(structMemberMappings);
            };

            // Enqueue a callee analysis context seeded from this callsite.
            std::function<void(const CallSite &, const PointsToMap &, const std::string &)> enqueueCallee =
                [&](const CallSite &callSite, const PointsToMap &callerBindings, const std::string &calleeName)
            {
                const std::unordered_map<std::string, const FunctionFacts *>::const_iterator calleeIt = functionMap.find(calleeName);
                if (calleeIt == functionMap.end())
                {
                    return;
                }

                const std::vector<std::string> &calleeParameters = parameterSlotsByFunction[calleeName];
                const std::set<std::string> &calleePointerSlots = pointerSlotsByFunction[calleeName];
                PointsToMap seeds;
                if (!calleeParameters.empty())
                {
                    seeds = buildSeedBindings(callSite, calleeParameters, calleePointerSlots, callerBindings, knownFunctions);
                }

                std::vector<StructMemberMapping> seededStructMappings;
                std::unordered_set<std::string> seenSeedMappings;
                const std::size_t limit = std::min(calleeParameters.size(), callSite.argumentExpressions.size());
                for (std::size_t index = 0; index < limit; ++index)
                {
                    const std::string &parameter = calleeParameters[index];
                    if (parameter.empty())
                    {
                        continue;
                    }

                    const std::string argumentSlot = canonicalSlot(callSite.argumentExpressions[index]);
                    if (argumentSlot.empty())
                    {
                        continue;
                    }

                    std::set<std::string> candidateBases{argumentSlot};
                    const PointsToMap::const_iterator bindingIt = callerBindings.find(argumentSlot);
                    if (bindingIt != callerBindings.end())
                    {
                        candidateBases.insert(bindingIt->second.begin(), bindingIt->second.end());
                    }

                    for (const StructMemberMapping &mapping : activeStructMemberMappings)
                    {
                        if (candidateBases.find(mapping.structVariable) == candidateBases.end())
                        {
                            continue;
                        }

                        StructMemberMapping propagated = mapping;
                        propagated.structVariable = parameter;
                        propagated.location = callSite.location;

                        const std::string memberSlot = propagated.structVariable + "." + propagated.memberName;
                        if (!memberSlot.empty() && knownFunctions.find(propagated.functionName) != knownFunctions.end())
                        {
                            seeds[memberSlot].insert(propagated.functionName);
                        }

                        const std::string key = makeStructMemberMappingKey(propagated);
                        if (seenSeedMappings.insert(key).second)
                        {
                            seededStructMappings.push_back(std::move(propagated));
                        }
                    }
                }

                const std::string key = buildContextKey(calleeName, seeds) + "|sm:" + buildStructMemberMappingsKey(seededStructMappings);
                if (seenContexts.insert(key).second)
                {
                    worklist.push_back(ContextJob{calleeName, std::move(seeds), std::move(seededStructMappings)});
                }
            };

            // Match a serialized block line to a parsed callsite record.
            std::function<bool(const std::string &, const CallSite &)> lineMatchesCallSite =
                [&](const std::string &line, const CallSite &callSite)
            {
                const std::string trimmedLine = trimLine(line);
                if (trimmedLine.find('(') == std::string::npos)
                {
                    return false;
                }

                if (!callSite.directCallee.empty())
                {
                    return trimmedLine.find(callSite.directCallee + "(") != std::string::npos;
                }

                if (!callSite.throughIdentifier.empty())
                {
                    return trimmedLine.find(callSite.throughIdentifier + "(") != std::string::npos;
                }

                if (trimmedLine.find(callSite.calleeExpression + "(") != std::string::npos)
                {
                    return true;
                }

                if (callSite.calleeExpression.find('?') != std::string::npos)
                {
                    const std::size_t dotPos = callSite.calleeExpression.rfind('.');
                    const std::size_t arrowPos = callSite.calleeExpression.rfind("->");
                    if (dotPos != std::string::npos)
                    {
                        const std::string member = callSite.calleeExpression.substr(dotPos + 1U);
                        if (!member.empty() &&
                            (trimmedLine.find("." + member + "(") != std::string::npos ||
                             trimmedLine.find("->" + member + "(") != std::string::npos))
                        {
                            return true;
                        }
                    }
                    if (arrowPos != std::string::npos)
                    {
                        const std::string member = callSite.calleeExpression.substr(arrowPos + 2U);
                        if (!member.empty() &&
                            (trimmedLine.find("." + member + "(") != std::string::npos ||
                             trimmedLine.find("->" + member + "(") != std::string::npos))
                        {
                            return true;
                        }
                    }
                }

                return false;
            };

            std::vector<const CallSite *> orderedCallSites;
            orderedCallSites.reserve(function.callSites.size());
            std::unordered_map<std::string, const CallSite *> callSiteById;
            for (const CallSite &callSite : function.callSites)
            {
                orderedCallSites.push_back(&callSite);
                if (!callSite.callSiteId.empty())
                {
                    callSiteById[callSite.callSiteId] = &callSite;
                }
            }
            std::sort(orderedCallSites.begin(), orderedCallSites.end(), [](const CallSite *lhs, const CallSite *rhs)
                      {
                if (lhs->location.line != rhs->location.line)
                {
                    return lhs->location.line < rhs->location.line;
                }
                if (lhs->location.column != rhs->location.column)
                {
                    return lhs->location.column < rhs->location.column;
                }
                return lhs->callSiteId < rhs->callSiteId; });

            std::function<std::string(const CallSite &)> makeCallSiteMatchKey = [](const CallSite &callSite)
            {
                if (!callSite.callSiteId.empty())
                {
                    return callSite.callSiteId;
                }

                return callSite.calleeExpression + "#" + callSite.directCallee + "#" +
                       std::to_string(callSite.location.line) + ":" + std::to_string(callSite.location.column);
            };

            // Lightweight evaluator retained for diagnostics and future branch pruning.
            std::function<std::optional<long long>(const std::string &, const PointsToMap &)> evaluateCondition =
                [&](const std::string &expression, const PointsToMap &bindings) -> std::optional<long long>
            {
                const std::string trimmed = trimLine(expression);
                long long literal = 0;
                if (isIntegerLiteral(trimmed, literal))
                {
                    return literal;
                }

                const std::string slot = canonicalSlot(trimmed);
                if (!slot.empty())
                {
                    const PointsToMap::const_iterator it = bindings.find(slot);
                    if (it != bindings.end())
                    {
                        for (const std::string &value : it->second)
                        {
                            const std::optional<long long> parsed = parseIntegerBinding(value);
                            if (parsed.has_value())
                            {
                                return *parsed;
                            }
                        }
                    }
                }

                const std::size_t eqIndex = trimmed.find("==");
                const std::size_t neIndex = trimmed.find("!=");
                const std::size_t leIndex = trimmed.find("<=");
                const std::size_t geIndex = trimmed.find(">=");
                if (eqIndex != std::string::npos || neIndex != std::string::npos ||
                    leIndex != std::string::npos || geIndex != std::string::npos)
                {
                    const std::size_t opIndex = eqIndex != std::string::npos ? eqIndex : (neIndex != std::string::npos ? neIndex : (leIndex != std::string::npos ? leIndex : geIndex));
                    const std::string lhs = trimLine(trimmed.substr(0, opIndex));
                    const std::string rhs = trimLine(trimmed.substr(opIndex + 2U));
                    const std::optional<long long> lhsValue = evaluateCondition(lhs, bindings);
                    const std::optional<long long> rhsValue = evaluateCondition(rhs, bindings);
                    if (!lhsValue.has_value() || !rhsValue.has_value())
                    {
                        return std::nullopt;
                    }

                    if (eqIndex != std::string::npos)
                    {
                        return *lhsValue == *rhsValue ? 1LL : 0LL;
                    }
                    if (neIndex != std::string::npos)
                    {
                        return *lhsValue != *rhsValue ? 1LL : 0LL;
                    }
                    if (leIndex != std::string::npos)
                    {
                        return *lhsValue <= *rhsValue ? 1LL : 0LL;
                    }
                    return *lhsValue >= *rhsValue ? 1LL : 0LL;
                }

                const std::size_t modIndex = trimmed.find('%');
                if (modIndex != std::string::npos)
                {
                    const std::string lhs = trimLine(trimmed.substr(0, modIndex));
                    const std::string rhs = trimLine(trimmed.substr(modIndex + 1U));
                    const std::optional<long long> lhsValue = evaluateCondition(lhs, bindings);
                    const std::optional<long long> rhsValue = evaluateCondition(rhs, bindings);
                    if (!lhsValue.has_value() || !rhsValue.has_value() || *rhsValue == 0)
                    {
                        return std::nullopt;
                    }
                    return *lhsValue % *rhsValue;
                }

                return std::nullopt;
            };

            while (!blockWorklist.empty())
            {
                BlockState state = std::move(blockWorklist.front());
                blockWorklist.pop_front();

                const std::unordered_map<std::uint32_t, const FunctionFacts::BlockFact *>::const_iterator currentBlockIt = blockMap.find(state.blockId);
                // Ignore invalid CFG successor IDs.
                if (currentBlockIt == blockMap.end())
                {
                    continue;
                }

                const FunctionFacts::BlockFact &block = *currentBlockIt->second;
                const std::string stateKey = makeStateKey(block.id, state.bindings, state.structMemberMappings);
                // Worklist dedup per (block, bindings) state prevents infinite loops.
                if (!seenBlockStates.insert(stateKey).second)
                {
                    continue;
                }

                PointsToMap bindings = std::move(state.bindings);
                std::vector<StructMemberMapping> activeStructMemberMappings = std::move(state.structMemberMappings);
                std::unordered_set<std::string> seenStructMemberMappings;
                for (const StructMemberMapping &mapping : activeStructMemberMappings)
                {
                    seenStructMemberMappings.insert(makeStructMemberMappingKey(mapping));
                }
                std::unordered_set<std::string> consumedCallSites;

                std::function<void(const CallSite &)> processMatchedCallSite = [&](const CallSite &callSite)
                {
                    std::function<void(const std::set<std::string> &, std::set<std::string> &)> appendKnownNonBlacklistedTargets =
                        [&](const std::set<std::string> &candidateTargets,
                            std::set<std::string> &targetsOut)
                    {
                        for (const std::string &target : candidateTargets)
                        {
                            if (knownFunctions.find(target) != knownFunctions.end() &&
                                !isBlacklistedFunction(target, blacklistedFunctions))
                            {
                                targetsOut.insert(target);
                            }
                        }
                    };

                    std::function<void(const std::string &, std::set<std::string> &)> appendTransitiveProgramWideTargetsForSlot =
                        [&](const std::string &slot,
                            std::set<std::string> &targetsOut)
                    {
                        const std::unordered_map<std::string, std::set<std::string>>::const_iterator programWideIt =
                            programWidePointerTargets.find(slot);
                        if (programWideIt == programWidePointerTargets.end())
                        {
                            return;
                        }

                        const std::set<std::string> resolvedFallbackTargets =
                            resolveTransitiveTargets(programWideIt->second, knownFunctions, programWidePointerTargets, false);
                        appendKnownNonBlacklistedTargets(resolvedFallbackTargets, targetsOut);
                    };

                    std::function<void(const std::string &, std::set<std::string> &)> appendMemcpySummaryTargetsForSlot =
                        [&](const std::string &slot,
                            std::set<std::string> &targetsOut)
                    {
                        const std::unordered_map<std::string, std::set<std::string>>::const_iterator summaryIt =
                            memcpySummaryTargetsByDstSlot.find(slot);
                        if (summaryIt == memcpySummaryTargetsByDstSlot.end())
                        {
                            return;
                        }

                        appendKnownNonBlacklistedTargets(summaryIt->second, targetsOut);
                    };

                    std::function<void(const std::string &, std::set<std::string> &)> appendFallbackTargetsForSlot =
                        [&](const std::string &slot,
                            std::set<std::string> &targetsOut)
                    {
                        if (slot.empty())
                        {
                            return;
                        }

                        appendTransitiveProgramWideTargetsForSlot(slot, targetsOut);
                        if (targetsOut.empty())
                        {
                            appendMemcpySummaryTargetsForSlot(slot, targetsOut);
                        }
                    };

                    if (!callSite.directCallee.empty())
                    {
                        if (!isBlacklistedFunction(callSite.directCallee, blacklistedFunctions))
                        {
                            CallEdge edge;
                            edge.caller = function.name;
                            edge.callee = callSite.directCallee;
                            edge.kind = "direct";
                            edge.location = callSite.location;
                            edge.calleeExpression = callSite.calleeExpression;
                            edge.throughIdentifier = callSite.throughIdentifier;
                            resolvedEdges.push_back(std::move(edge));

                            enqueueCallee(callSite, bindings, callSite.directCallee);
                        }
                        propagateCalleeStructMemberMappings(callSite, callSite.directCallee, bindings, activeStructMemberMappings, seenStructMemberMappings);
                        return;
                    }

                    const std::set<std::string> targets = resolveIndirectTargets(callSite, knownFunctions, bindings, activeStructMemberMappings);
                    std::set<std::string> filteredTargets;
                    for (const std::string &target : targets)
                    {
                        if (knownFunctions.find(target) != knownFunctions.end() &&
                            !isBlacklistedFunction(target, blacklistedFunctions))
                        {
                            filteredTargets.insert(target);
                        }
                    }

                    if (filteredTargets.empty())
                    {
                        const std::unordered_map<std::string, std::set<std::string>>::const_iterator wrapperIt =
                            wrapperDispatchTargets.find(function.name);
                        if (wrapperIt != wrapperDispatchTargets.end())
                        {
                            for (const std::string &target : wrapperIt->second)
                            {
                                if (knownFunctions.find(target) != knownFunctions.end() &&
                                    !isBlacklistedFunction(target, blacklistedFunctions))
                                {
                                    filteredTargets.insert(target);
                                }
                            }
                        }
                    }

                    if (filteredTargets.empty())
                    {
                        appendFallbackTargetsForSlot(canonicalSlot(callSite.throughIdentifier), filteredTargets);
                        if (filteredTargets.empty())
                        {
                            appendFallbackTargetsForSlot(canonicalSlot(callSite.calleeExpression), filteredTargets);
                        }
                    }

                    if (filteredTargets.empty())
                    {
                        CallEdge edge;
                        edge.caller = function.name;
                        edge.kind = "indirect";
                        edge.location = callSite.location;
                        edge.calleeExpression = callSite.calleeExpression;
                        edge.throughIdentifier = callSite.throughIdentifier;
                        unresolvedIndirect.push_back(std::move(edge));
                        logUnresolvedCall(unresolvedIndirect.back());
                        return;
                    }

                    for (const std::string &callee : filteredTargets)
                    {
                        CallEdge edge;
                        edge.caller = function.name;
                        edge.callee = callee;
                        edge.kind = "indirect";
                        edge.location = callSite.location;
                        edge.calleeExpression = callSite.calleeExpression;
                        edge.throughIdentifier = callSite.throughIdentifier;
                        resolvedEdges.push_back(std::move(edge));

                        enqueueCallee(callSite, bindings, callee);
                    }
                };

                for (std::size_t lineIndex = 0; lineIndex < block.lines.size(); ++lineIndex)
                {
                    const std::string &rawLine = block.lines[lineIndex];
                    const std::string line = trimLine(rawLine);
                    // Empty lines carry no transfer information.
                    if (line.empty())
                    {
                        continue;
                    }

                    bool handledCallFromIds = false;
                    std::vector<const CallSite *> matchedLineCallSites;
                    if (lineIndex < block.lineCallSiteIds.size())
                    {
                        const std::vector<std::string> &lineCallSiteIds = block.lineCallSiteIds[lineIndex];
                        for (const std::string &callSiteId : lineCallSiteIds)
                        {
                            const std::unordered_map<std::string, const CallSite *>::const_iterator it = callSiteById.find(callSiteId);
                            if (it == callSiteById.end())
                            {
                                continue;
                            }
                            handledCallFromIds = true;
                            consumedCallSites.insert(makeCallSiteMatchKey(*it->second));
                            matchedLineCallSites.push_back(it->second);
                        }
                    }

                    if (handledCallFromIds)
                    {
                        if (matchedLineCallSites.size() > 1U)
                        {
                            bool stabilized = false;
                            while (!stabilized)
                            {
                                const std::size_t before = activeStructMemberMappings.size();
                                for (const CallSite *callSite : matchedLineCallSites)
                                {
                                    if (callSite == nullptr || callSite->directCallee.empty())
                                    {
                                        continue;
                                    }

                                    propagateCalleeStructMemberMappings(
                                        *callSite,
                                        callSite->directCallee,
                                        bindings,
                                        activeStructMemberMappings,
                                        seenStructMemberMappings);
                                }

                                stabilized = activeStructMemberMappings.size() == before;
                            }
                        }

                        for (const CallSite *callSite : matchedLineCallSites)
                        {
                            if (callSite != nullptr)
                            {
                                processMatchedCallSite(*callSite);
                            }
                        }
                    }

                    // Legacy fallback for JSON produced before lineCallSiteIds existed.
                    if (!handledCallFromIds && line.find('(') != std::string::npos)
                    {
                        for (const CallSite *candidate : orderedCallSites)
                        {
                            const std::string callSiteKey = makeCallSiteMatchKey(*candidate);
                            if (consumedCallSites.find(callSiteKey) != consumedCallSites.end())
                            {
                                continue;
                            }

                            if (!lineMatchesCallSite(line, *candidate))
                            {
                                continue;
                            }

                            consumedCallSites.insert(callSiteKey);
                            processMatchedCallSite(*candidate);
                            break;
                        }
                    }

                    const std::optional<std::pair<std::string, std::string>> memcpyArgs =
                        parseMemcpyArgsFromLine(line);
                    if (memcpyArgs.has_value())
                    {
                        const std::string dstSlot = canonicalSlot(memcpyArgs->first);
                        const std::string srcSlot = canonicalSlot(memcpyArgs->second);
                        if (!dstSlot.empty())
                        {
                            std::set<std::string> copiedValues;

                            if (!srcSlot.empty())
                            {
                                const PointsToMap::const_iterator localIt = bindings.find(srcSlot);
                                if (localIt != bindings.end())
                                {
                                    copiedValues.insert(localIt->second.begin(), localIt->second.end());
                                }

                                const std::unordered_map<std::string, std::set<std::string>>::const_iterator globalIt =
                                    programWidePointerTargets.find(srcSlot);
                                if (globalIt != programWidePointerTargets.end())
                                {
                                    copiedValues.insert(globalIt->second.begin(), globalIt->second.end());
                                }
                            }

                            const std::set<std::string> resolvedSourceValues =
                                resolveMixedExpressionValues(memcpyArgs->second, knownFunctions, bindings);
                            copiedValues.insert(resolvedSourceValues.begin(), resolvedSourceValues.end());

                            std::set<std::string> &dstValues = bindings[dstSlot];
                            dstValues.clear();
                            for (const std::string &value : copiedValues)
                            {
                                if (!isIntegerBinding(value))
                                {
                                    dstValues.insert(value);
                                }
                            }
                        }
                        continue;
                    }

                    // Filter out non-assignment lines and comparison operators.
                    if (line.find('=') == std::string::npos || line.find("==") != std::string::npos ||
                        line.find("!=") != std::string::npos || line.find("<=") != std::string::npos ||
                        line.find(">=") != std::string::npos)
                    {
                        continue;
                    }

                    const std::size_t equalIndex = line.find('=');
                    // Defensive guard for malformed assignment text.
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
                    // Cannot update state when no LHS slot can be identified.
                    if (lhsSlot.empty())
                    {
                        continue;
                    }
                    std::set<std::string> values = resolveMixedExpressionValues(rhs, knownFunctions, bindings, false);
                    const std::set<std::string> rhsCallees =
                        resolveCallCalleeTargets(rhs, knownFunctions, bindings);
                    if (!rhsCallees.empty())
                    {
                        std::set<std::string> callReturns;
                        for (const std::string &callee : rhsCallees)
                        {
                            const std::unordered_map<std::string, std::set<std::string>>::const_iterator returnIt =
                                returnTargetsByFunction.find(callee);
                            if (returnIt != returnTargetsByFunction.end())
                            {
                                const std::unordered_map<std::string, std::vector<std::string>>::const_iterator parametersIt =
                                    parameterSlotsByFunction.find(callee);
                                const std::unordered_map<std::string, std::set<std::string>>::const_iterator pointerSlotsIt =
                                    pointerSlotsByFunction.find(callee);
                                const std::vector<std::string> emptyParameterSlots;
                                const std::set<std::string> emptyPointerSlots;
                                const std::vector<std::string> &calleeParameters =
                                    parametersIt != parameterSlotsByFunction.end() ? parametersIt->second : emptyParameterSlots;
                                const std::set<std::string> &calleePointerSlots =
                                    pointerSlotsIt != pointerSlotsByFunction.end() ? pointerSlotsIt->second : emptyPointerSlots;

                                const std::set<std::string> resolvedReturns = resolveCallReturnTargets(
                                    rhs,
                                    callee,
                                    bindings,
                                    programWidePointerTargets,
                                    activeStructMemberMappings,
                                    calleeParameters,
                                    calleePointerSlots,
                                    knownFunctions,
                                    returnTargetsByFunction);
                                callReturns.insert(resolvedReturns.begin(), resolvedReturns.end());
                            }
                        }

                        if (!callReturns.empty())
                        {
                            values = std::move(callReturns);
                        }

                        for (const std::string &callee : rhsCallees)
                        {
                            const std::unordered_map<std::string, std::vector<StructMemberMapping>>::const_iterator structIt =
                                returnedStructMemberMappingsByFunction.find(callee);
                            if (structIt != returnedStructMemberMappingsByFunction.end())
                            {
                                pruneOverwrittenStructMemberMappings(activeStructMemberMappings, seenStructMemberMappings, lhs, bindings);
                                appendStructMemberMappings(activeStructMemberMappings, seenStructMemberMappings, lhsSlot, structIt->second);
                            }
                        }
                    }

                    const std::string rhsSlot = canonicalSlot(rhs);
                    if (!rhsSlot.empty())
                    {
                        const std::unordered_map<std::string, std::set<std::string>>::const_iterator globalTargetsIt =
                            programWidePointerTargets.find(rhsSlot);
                        if (globalTargetsIt != programWidePointerTargets.end())
                        {
                            values.insert(globalTargetsIt->second.begin(), globalTargetsIt->second.end());
                        }
                    }

                    if (!rhsSlot.empty() && rhsSlot != lhsSlot)
                    {
                        std::vector<StructMemberMapping> copiedMappings;
                        for (const StructMemberMapping &mapping : activeStructMemberMappings)
                        {
                            if (mapping.structVariable == rhsSlot)
                            {
                                copiedMappings.push_back(mapping);
                            }
                        }

                        if (!copiedMappings.empty())
                        {
                            pruneOverwrittenStructMemberMappings(activeStructMemberMappings, seenStructMemberMappings, lhs, bindings);
                            appendStructMemberMappings(activeStructMemberMappings, seenStructMemberMappings, lhsSlot, copiedMappings);
                        }
                    }
                    // Ignore assignments that resolve to no usable values.
                    if (values.empty())
                    {
                        continue;
                    }

                    const std::set<std::string> destinationSlots =
                        resolveAssignmentDestinationSlots(lhs, knownFunctions, bindings);

                    for (const std::string &destinationSlot : destinationSlots)
                    {
                        std::set<std::string> &slotValues = bindings[destinationSlot];
                        // Strong update: overwrite the destination slot reached by this assignment.
                        slotValues.clear();
                        bool hasNonIntegerValue = false;
                        for (const std::string &value : values)
                        {
                            if (!isIntegerBinding(value))
                            {
                                hasNonIntegerValue = true;
                                break;
                            }
                        }

                        const bool isPointerSlot =
                            pointerSlots.find(destinationSlot) != pointerSlots.end() || hasNonIntegerValue;
                        for (const std::string &value : values)
                        {
                            if (isPointerSlot)
                            {
                                if (!isIntegerBinding(value))
                                {
                                    slotValues.insert(value);
                                }
                            }
                            else
                            {
                                if (isIntegerBinding(value))
                                {
                                    slotValues.insert(value);
                                }
                            }
                        }
                    }
                }

                // Propagate current state to all CFG successors.
                for (std::uint32_t successor : block.successors)
                {
                    blockWorklist.push_back(BlockState{successor, bindings, activeStructMemberMappings});
                }
            }
        }
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
    if (!parseFunctions(*root, functions, knownFunctions, blacklistedFunctions, errorMessage))
    {
        return false;
    }

    const std::unordered_map<std::string, ParameterDispatchInfo> dispatchFunctions =
        detectParameterDispatchFunctions(functions);
    const std::unordered_map<std::string, std::set<std::string>> wrapperDispatchTargets =
        collectWrapperDispatchTargets(functions, knownFunctions, dispatchFunctions);

    std::vector<CallEdge> resolvedEdges;
    std::vector<CallEdge> unresolvedIndirect;

    runContextSensitiveAnalysis(functions, knownFunctions, blacklistedFunctions, wrapperDispatchTargets, resolvedEdges, unresolvedIndirect);

    std::set<CollapsedEdge> collapsedEdges;
    for (const CallEdge &edge : resolvedEdges)
    {
        if (edge.callee.empty())
        {
            continue;
        }
        collapsedEdges.insert(CollapsedEdge{edge.caller, edge.callee, edge.kind});
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

    std::vector<CallEdge> filteredUnresolved;
    std::unordered_set<std::string> seenUnresolved;
    filteredUnresolved.reserve(unresolvedIndirect.size());
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
        filteredUnresolved.push_back(edge);
    }
    unresolvedIndirect.swap(filteredUnresolved);

    std::map<std::string, std::vector<CollapsedEdge>> outgoing;
    for (const CollapsedEdge &edge : collapsedEdges)
    {
        outgoing[edge.caller].push_back(edge);
    }
    for (std::pair<const std::string, std::vector<CollapsedEdge>> &entry : outgoing)
    {
        std::sort(entry.second.begin(), entry.second.end(), [](const CollapsedEdge &lhs, const CollapsedEdge &rhs)
                  {
            if (lhs.callee != rhs.callee)
            {
                return lhs.callee < rhs.callee;
            }
            return lhs.kind < rhs.kind; });
    }

    const std::vector<std::string> roots = chooseRoots(knownFunctions, collapsedEdges);

    std::set<std::string> contextNodeKeys;
    std::set<std::string> contextEdgeKeys;
    std::deque<std::pair<std::string, std::vector<std::string>>> worklist;

    std::function<std::string(const std::string &, const std::vector<std::string> &)> makeNodeKey = [](const std::string &function, const std::vector<std::string> &context)
    {
        if (context.empty())
        {
            return function + "|";
        }
        return function + "|" + joinContext(context, "\x1f");
    };

    std::function<std::string(const std::string &, const std::vector<std::string> &)> enqueueNode = [&](const std::string &function, const std::vector<std::string> &context)
    {
        const std::string key = makeNodeKey(function, context);
        if (contextNodeKeys.insert(key).second)
        {
            worklist.emplace_back(function, context);
        }
        return key;
    };

    for (const std::string &rootFunction : roots)
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

        std::map<std::string, std::vector<CollapsedEdge>>::iterator outgoingIt = outgoing.find(currentFunction);
        if (outgoingIt == outgoing.end())
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
            const std::string edgeKey = callerKey + "->" + calleeKey + "|" + edge.kind;
            contextEdgeKeys.insert(edgeKey);
        }
    }

    std::set<std::string> collapsedNodeNames = knownFunctions;
    for (const CollapsedEdge &edge : collapsedEdges)
    {
        collapsedNodeNames.insert(edge.caller);
        collapsedNodeNames.insert(edge.callee);
    }

    llvm::json::Object rootOut;
    rootOut["kind"] = "callgraph";
    rootOut["input"] = analysisJsonPath;

    const std::size_t contextNodeCount = contextNodeKeys.size();
    const std::size_t contextEdgeCount = contextEdgeKeys.size();

    llvm::json::Object summary;
    summary["functionCount"] = static_cast<std::int64_t>(knownFunctions.size());
    summary["collapsedEdgeCount"] = static_cast<std::int64_t>(collapsedEdges.size());
    summary["unresolvedIndirectCallCount"] = static_cast<std::int64_t>(unresolvedIndirect.size());
    summary["contextDepth"] = static_cast<std::int64_t>(contextDepth);
    summary["contextNodeCount"] = static_cast<std::int64_t>(contextNodeCount);
    summary["contextEdgeCount"] = static_cast<std::int64_t>(contextEdgeCount);
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
    for (const std::string &name : collapsedNodeNames)
    {
        collapsedNodes.push_back(name);
    }
    collapsed["nodes"] = std::move(collapsedNodes);

    llvm::json::Array collapsedEdgesJson;
    for (const CollapsedEdge &edge : collapsedEdges)
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

    if (!outputDotPath.empty())
    {
        std::ofstream dotFile(outputDotPath);
        if (!dotFile)
        {
            errorMessage = "cannot open output dot: " + outputDotPath;
            return false;
        }

        dotFile << "digraph callgraph {\n";
        dotFile << "  rankdir=LR;\n";

        for (const std::string &name : collapsedNodeNames)
        {
            dotFile << "  \"" << name << "\" [shape=box];\n";
        }

        for (const CollapsedEdge &edge : collapsedEdges)
        {
            dotFile << "  \"" << edge.caller << "\" -> \"" << edge.callee
                    << "\" [label=\"" << edge.kind << "\"];\n";
        }

        dotFile << "}\n";
    }

    stats.functionCount = knownFunctions.size();
    stats.collapsedEdgeCount = collapsedEdges.size();
    stats.unresolvedIndirectCallCount = unresolvedIndirect.size();
    stats.contextNodeCount = contextNodeCount;
    stats.contextEdgeCount = contextEdgeCount;

    return true;
}
