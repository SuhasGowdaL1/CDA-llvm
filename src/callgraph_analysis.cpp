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

    struct SourceLocation
    {
        std::string file;
        std::uint32_t line = 0;
        std::uint32_t column = 0;
    };

    struct CallSite
    {
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
        std::set<std::string> addressTakenFunctions;
        std::vector<CallSite> callSites;
        std::vector<PointerAssignment> pointerAssignments;
        std::vector<StructMemberMapping> structMemberMappings;
        struct BlockFact
        {
            std::uint32_t id = 0;
            std::vector<std::string> lines;
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
        const std::vector<std::string> identifiers = extractIdentifiers(expression);
        if (identifiers.empty())
        {
            return "";
        }
        return identifiers.back();
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
            const auto it = bindings.find(slot);
            if (it != bindings.end())
            {
                targets.insert(it->second.begin(), it->second.end());
            }
        }

        for (const std::string &identifier : extractIdentifiers(calleeExpr))
        {
            const auto it = bindings.find(identifier);
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

    void logFunctionProcessed(const std::string &functionName, const PointsToMap &seededPointsTo)
    {
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
        std::set<std::string> targets;

        if (!assignment.assignedFunction.empty())
        {
            if (knownFunctions.find(assignment.assignedFunction) != knownFunctions.end())
            {
                targets.insert(assignment.assignedFunction);
            }
            return targets;
        }

        if (assignment.rhsTakesFunctionAddress)
        {
            for (const std::string &identifier : extractIdentifiers(assignment.rhsExpression))
            {
                if (knownFunctions.find(identifier) != knownFunctions.end())
                {
                    targets.insert(identifier);
                }
            }
            return targets;
        }

        if (assignment.rhsExpression.find('&') != std::string::npos)
        {
            const std::vector<std::string> identifiers = extractIdentifiers(assignment.rhsExpression);
            for (const std::string &identifier : identifiers)
            {
                if (knownFunctions.find(identifier) == knownFunctions.end())
                {
                    targets.insert(identifier);
                    break;
                }
            }
        }

        const std::string rhsSlot = canonicalSlot(assignment.rhsExpression);
        if (!rhsSlot.empty())
        {
            if (knownFunctions.find(rhsSlot) == knownFunctions.end() && !isIntegerBinding(rhsSlot))
            {
                targets.insert(rhsSlot);
            }

            const auto existing = pointsTo.find(rhsSlot);
            if (existing != pointsTo.end())
            {
                targets.insert(existing->second.begin(), existing->second.end());
            }
        }

        for (const std::string &identifier : extractIdentifiers(assignment.rhsExpression))
        {
            const auto it = pointsTo.find(identifier);
            if (it != pointsTo.end())
            {
                targets.insert(it->second.begin(), it->second.end());
            }
        }

        if (targets.empty())
        {
            for (const std::string &identifier : extractIdentifiers(assignment.rhsExpression))
            {
                if (knownFunctions.find(identifier) != knownFunctions.end())
                {
                    targets.insert(identifier);
                }
            }
        }

        return targets;
    }

    /**
     * @brief Collect conservative program-wide slot->function targets from assignments.
     */
    std::unordered_map<std::string, std::set<std::string>> collectProgramWidePointerTargets(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions)
    {
        std::unordered_map<std::string, std::set<std::string>> targetsBySlot;
        std::set<std::string> globalSlots;

        std::vector<const PointerAssignment *> globalAssignments;
        for (const FunctionFacts &function : functions)
        {
            for (const PointerAssignment &assignment : function.pointerAssignments)
            {
                const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
                if (lhsSlot.empty())
                {
                    continue;
                }

                globalSlots.insert(lhsSlot);
                globalAssignments.push_back(&assignment);
            }
        }

        bool changed = true;
        while (changed)
        {
            changed = false;

            for (const PointerAssignment *assignmentPtr : globalAssignments)
            {
                const PointerAssignment &assignment = *assignmentPtr;
                const std::string lhsSlot = canonicalSlot(assignment.lhsExpression);
                if (lhsSlot.empty())
                {
                    continue;
                }

                std::set<std::string> targets = resolveAssignmentTargets(assignment, knownFunctions, targetsBySlot);

                const std::string rhsSlot = canonicalSlot(assignment.rhsExpression);
                if (!rhsSlot.empty())
                {
                    const auto rhsIt = targetsBySlot.find(rhsSlot);
                    if (rhsIt != targetsBySlot.end())
                    {
                        targets.insert(rhsIt->second.begin(), rhsIt->second.end());
                    }
                }

                if (targets.empty())
                {
                    continue;
                }

                std::set<std::string> &slotTargets = targetsBySlot[lhsSlot];
                const std::size_t before = slotTargets.size();
                slotTargets.insert(targets.begin(), targets.end());
                if (slotTargets.size() != before)
                {
                    changed = true;
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
                        const auto srcIt = targetsBySlot.find(srcSlot);
                        if (srcIt != targetsBySlot.end())
                        {
                            copiedTargets.insert(srcIt->second.begin(), srcIt->second.end());
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

                    std::set<std::string> &dstTargets = targetsBySlot[dstSlot];
                    const std::size_t before = dstTargets.size();
                    dstTargets.insert(copiedTargets.begin(), copiedTargets.end());
                    if (dstTargets.size() != before)
                    {
                        changed = true;
                    }
                }
            }
        }

        return targetsBySlot;
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

        auto startsWith = [&](const std::string &prefix)
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

        auto normalizeAccessExpression = [](std::string expression)
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

        auto splitStructAccess = [&](const std::string &expression) -> std::pair<std::string, std::string>
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

                const auto calleeIt = functionMap.find(callSite.directCallee);
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

                    const auto argMappingsIt = callerMappingsByVar.find(argSlot);
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

            const auto incomingIt = incomingParameterMappings.find(function.name);
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

                    const auto srcIt = mappingsByVariable.find(srcSlot);
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
                        const auto latestIt = latestStampByGroup.find(localGroupKey);
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
                        const auto latestIt = latestStampByGroup.find(localGroupKey);
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

        auto memberGroupKey = [&](const StructMemberMapping &mapping)
        {
            std::string groupBase = mapping.structVariable;
            const auto pointeeIt = pointsTo.find(mapping.structVariable);
            if (pointeeIt != pointsTo.end() && pointeeIt->second.size() == 1U)
            {
                const std::string &candidate = *pointeeIt->second.begin();
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
            const auto it = latestStampByGroup.find(key);
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
                const auto it = latestStampByGroup.find(key);
                if (it != latestStampByGroup.end() && stamp != it->second)
                {
                    continue;
                }
            }

            activeMappings.push_back(&mapping);
        }

        auto resolveAliasSlots = [&](const std::string &slot)
        {
            std::set<std::string> resolved;
            std::deque<std::string> pending;
            std::unordered_set<std::string> seen;
            pending.push_back(slot);

            while (!pending.empty())
            {
                const std::string current = pending.front();
                pending.pop_front();

                if (!seen.insert(current).second)
                {
                    continue;
                }

                const auto it = pointsTo.find(current);
                if (it == pointsTo.end())
                {
                    continue;
                }

                for (const std::string &next : it->second)
                {
                    resolved.insert(next);
                    if (pointsTo.find(next) != pointsTo.end())
                    {
                        pending.push_back(next);
                    }
                }
            }

            return resolved;
        };

        auto removeArrayIndices = [](const std::string &text)
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

        auto trimWhitespace = [](const std::string &text)
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

        auto removeAllWhitespace = [](const std::string &text)
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

            auto isSimpleIdentifier = [](const std::string &text)
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

            auto mappingMatchesMember = [&](const StructMemberMapping &mapping)
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

            const std::set<std::string> aliasSlots = resolveAliasSlots(structVar);
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

                for (const auto &entry : pointsTo)
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
            const auto through = pointsTo.find(callSite.throughIdentifier);
            if (through != pointsTo.end())
            {
                targets.insert(through->second.begin(), through->second.end());
            }
        }

        if (targets.empty())
        {
            const std::string slot = canonicalSlot(callSite.calleeExpression);
            const auto slotIt = pointsTo.find(slot);
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

            const auto it = pointsTo.find(value);
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
        std::set<std::string> targets;

        const std::string slot = canonicalSlot(expression);
        if (!slot.empty())
        {
            const auto slotIt = pointsTo.find(slot);
            if (slotIt != pointsTo.end())
            {
                targets.insert(slotIt->second.begin(), slotIt->second.end());
            }
        }

        for (const std::string &identifier : extractIdentifiers(expression))
        {
            if (knownFunctions.find(identifier) != knownFunctions.end())
            {
                targets.insert(identifier);
            }
        }

        return targets;
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

        auto removeArrayIndices = [](const std::string &text)
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
        const std::unordered_map<std::string, std::set<std::string>> &bindings)
    {
        std::set<std::string> values;

        long long literalValue = 0;
        if (isIntegerLiteral(trimLine(expression), literalValue))
        {
            values.insert(makeIntegerBinding(literalValue));
            return values;
        }

        if (expression.find('&') != std::string::npos)
        {
            for (const std::string &identifier : extractIdentifiers(expression))
            {
                if (knownFunctions.find(identifier) == knownFunctions.end())
                {
                    values.insert(identifier);
                    return values;
                }
            }
        }

        const std::string slot = canonicalSlot(expression);
        if (!slot.empty())
        {
            const auto slotIt = bindings.find(slot);
            if (slotIt != bindings.end())
            {
                values.insert(slotIt->second.begin(), slotIt->second.end());
            }
        }

        for (const std::string &identifier : extractIdentifiers(expression))
        {
            const auto bindingIt = bindings.find(identifier);
            if (bindingIt != bindings.end())
            {
                values.insert(bindingIt->second.begin(), bindingIt->second.end());
            }
            if (knownFunctions.find(identifier) != knownFunctions.end())
            {
                values.insert(identifier);
            }
        }

        if (values.empty())
        {
            for (const std::string &identifier : extractIdentifiers(expression))
            {
                if (knownFunctions.find(identifier) == knownFunctions.end())
                {
                    values.insert(identifier);
                }
            }
        }

        return values;
    }

    void seedBindingsFromAssignments(
        const FunctionFacts &function,
        const std::set<std::string> &knownFunctions,
        PointsToMap &bindings);

    /**
     * @brief Collect direct function targets returned by each function.
     */
    std::unordered_map<std::string, std::set<std::string>> collectReturnTargetsByFunction(
        const std::vector<FunctionFacts> &functions,
        const std::set<std::string> &knownFunctions)
    {
        std::unordered_map<std::string, std::set<std::string>> targetsByFunction;

        for (const FunctionFacts &function : functions)
        {
            std::set<std::string> targets;
            PointsToMap bindings;
            seedBindingsFromAssignments(function, knownFunctions, bindings);

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

                    const std::set<std::string> values =
                        resolveMixedExpressionValues(returned, knownFunctions, bindings);
                    for (const std::string &value : values)
                    {
                        if (knownFunctions.find(value) != knownFunctions.end())
                        {
                            targets.insert(value);
                        }
                    }
                }
            }

            if (!targets.empty())
            {
                targetsByFunction[function.name] = std::move(targets);
            }
        }

        bool changed = true;
        while (changed)
        {
            changed = false;

            for (const FunctionFacts &function : functions)
            {
                PointsToMap bindings;
                seedBindingsFromAssignments(function, knownFunctions, bindings);
                std::set<std::string> expanded = targetsByFunction[function.name];

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

                        const std::set<std::string> callees =
                            resolveCallCalleeTargets(returned, knownFunctions, bindings);
                        for (const std::string &callee : callees)
                        {
                            const auto it = targetsByFunction.find(callee);
                            if (it != targetsByFunction.end())
                            {
                                expanded.insert(it->second.begin(), it->second.end());
                            }
                        }
                    }
                }

                std::set<std::string> &current = targetsByFunction[function.name];
                const std::size_t before = current.size();
                current.insert(expanded.begin(), expanded.end());
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

        auto normalizeStructAccess = [](const std::string &expression)
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

        auto parseStructAccess = [&](const std::string &expression) -> std::pair<std::string, std::string>
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

            auto addMapping = [&](const std::string &structVariable, const std::string &memberName, const std::string &functionName)
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

                    const auto rhsIt = mappingsByVariable.find(rhsSlot);
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

                    const auto mappingsIt = mappingsByVariable.find(returnedSlot);
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
     * @brief Build stable context key for worklist deduplication.
     */
    std::string buildContextKey(const std::string &functionName, const PointsToMap &pointsTo)
    {
        std::vector<std::pair<std::string, std::vector<std::string>>> entries;
        entries.reserve(pointsTo.size());

        for (const auto &entry : pointsTo)
        {
            std::vector<std::string> targets(entry.second.begin(), entry.second.end());
            std::sort(targets.begin(), targets.end());
            entries.emplace_back(entry.first, std::move(targets));
        }

        std::sort(entries.begin(), entries.end(), [](const auto &lhs, const auto &rhs)
                  { return lhs.first < rhs.first; });

        std::string key = functionName;
        key += "|";
        for (const auto &entry : entries)
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
            const bool isPointerSlot = pointerSlots.find(slot) != pointerSlots.end();
            const std::set<std::string> targets =
                resolveMixedExpressionValues(callSite.argumentExpressions[index], knownFunctions, callerPointsTo);

            for (const std::string &target : targets)
            {
                if (isPointerSlot)
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
     * @brief Seed bindings from recorded pointer assignment facts.
     */
    void seedBindingsFromAssignments(
        const FunctionFacts &function,
        const std::set<std::string> &knownFunctions,
        PointsToMap &bindings)
    {
        for (const Event &event : buildEvents(function))
        {
            if (event.kind != EventKind::kAssignment || event.assignment == nullptr)
            {
                continue;
            }

            const PointerAssignment &assignment = *event.assignment;
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
        for (const auto &entry : functionMap)
        {
            worklist.push_back(ContextJob{entry.first, {}});
            seenContexts.insert(buildContextKey(entry.first, {}));
        }

        while (!worklist.empty())
        {
            ContextJob job = std::move(worklist.front());
            worklist.pop_front();

            logFunctionProcessed(job.functionName, job.seededPointsTo);

            const auto functionIt = functionMap.find(job.functionName);
            // Skip stale jobs if the function cannot be found.
            if (functionIt == functionMap.end())
            {
                continue;
            }

            const FunctionFacts &function = *functionIt->second;

            const auto blockIt = std::find_if(function.blocks.begin(), function.blocks.end(), [&](const FunctionFacts::BlockFact &block)
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
            auto makeStructMemberMappingKey = [](const StructMemberMapping &mapping)
            {
                return mapping.structVariable + "#" + mapping.memberName + "#" + mapping.functionName + "@" +
                       std::to_string(mapping.location.line) + ":" + std::to_string(mapping.location.column);
            };

            auto buildStructMappingsKey = [&](const std::vector<StructMemberMapping> &mappings)
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
            };

            std::vector<StructMemberMapping> activeStructMemberMappings = function.structMemberMappings;
            activeStructMemberMappings.insert(
                activeStructMemberMappings.end(),
                programWideStructMemberMappings.begin(),
                programWideStructMemberMappings.end());
            std::unordered_set<std::string> seenStructMemberMappings;
            for (const StructMemberMapping &mapping : activeStructMemberMappings)
            {
                seenStructMemberMappings.insert(makeStructMemberMappingKey(mapping));
            }

            auto appendStructMemberMappings = [&](std::vector<StructMemberMapping> &structMemberMappings,
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

            auto collectOverwriteSlots = [&](const std::string &slot, const PointsToMap &currentBindings)
            {
                std::unordered_set<std::string> overwriteSlots;
                overwriteSlots.insert(slot);

                const auto slotIt = currentBindings.find(slot);
                if (slotIt == currentBindings.end())
                {
                    return overwriteSlots;
                }

                for (const auto &entry : currentBindings)
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

            auto normalizeStructAccess = [&](std::string text)
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

            auto parseStructAccess = [&](const std::string &expression) -> std::pair<std::string, std::string>
            {
                const std::string normalized = trimLine(normalizeStructAccess(expression));
                const std::size_t dotIndex = normalized.find('.');
                if (dotIndex == std::string::npos || dotIndex == 0U)
                {
                    return {"", ""};
                }

                return {normalized.substr(0, dotIndex), normalized.substr(dotIndex + 1U)};
            };

            auto pruneOverwrittenStructMemberMappings = [&](std::vector<StructMemberMapping> &structMemberMappings,
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
                for (auto it = structMemberMappings.begin(); it != structMemberMappings.end();)
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

            auto pruneOverwrittenStructMemberGroup = [&](std::vector<StructMemberMapping> &structMemberMappings,
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
                for (auto it = structMemberMappings.begin(); it != structMemberMappings.end();)
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

            auto propagateCalleeStructMemberMappings = [&](const CallSite &callSite,
                                                           const std::string &calleeName,
                                                           const PointsToMap &currentBindings,
                                                           std::vector<StructMemberMapping> &structMemberMappings,
                                                           std::unordered_set<std::string> &seenMappings)
            {
                const auto calleeIt = functionMap.find(calleeName);
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
                    const auto it = latestStampByLocalGroup.find(localGroupKey);
                    if (it == latestStampByLocalGroup.end() || stamp >= it->second)
                    {
                        latestStampByLocalGroup[localGroupKey] = stamp;
                    }
                }

                for (const StructMemberMapping &mapping : calleeIt->second->structMemberMappings)
                {
                    const auto targetIt = parameterToArgumentSlot.find(mapping.structVariable);
                    if (targetIt == parameterToArgumentSlot.end())
                    {
                        continue;
                    }

                    const std::size_t localGroupDot = mapping.memberName.rfind('.');
                    const std::string localGroup = localGroupDot == std::string::npos ? mapping.memberName : mapping.memberName.substr(0, localGroupDot + 1U);
                    const std::string localGroupKey = mapping.structVariable + "#" + localGroup;
                    const std::uint64_t stamp = (static_cast<std::uint64_t>(mapping.location.line) << 32U) |
                                                static_cast<std::uint64_t>(mapping.location.column);
                    const auto latestIt = latestStampByLocalGroup.find(localGroupKey);
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
            seedBindingsFromAssignments(function, knownFunctions, initialBindings);
            blockWorklist.push_back(BlockState{function.entryBlockId, std::move(initialBindings), activeStructMemberMappings});

            auto makeStateKey = [&](std::uint32_t blockId, const PointsToMap &bindings, const std::vector<StructMemberMapping> &structMemberMappings)
            {
                return std::to_string(blockId) + "|" + buildContextKey(function.name, bindings) + "|" + buildStructMappingsKey(structMemberMappings);
            };

            // Enqueue a callee analysis context seeded from this callsite.
            auto enqueueCallee = [&](const CallSite &callSite, const PointsToMap &callerBindings, const std::string &calleeName)
            {
                const auto calleeIt = functionMap.find(calleeName);
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

                const std::string key = buildContextKey(calleeName, seeds);
                if (seenContexts.insert(key).second)
                {
                    worklist.push_back(ContextJob{calleeName, std::move(seeds)});
                }
            };

            auto emitDirectCall = [&](const CallSite &callSite)
            {
                if (callSite.directCallee.empty())
                {
                    return;
                }

                if (isBlacklistedFunction(callSite.directCallee, blacklistedFunctions))
                {
                    return;
                }

                CallEdge edge;
                edge.caller = function.name;
                edge.callee = callSite.directCallee;
                edge.kind = "direct";
                edge.location = callSite.location;
                edge.calleeExpression = callSite.calleeExpression;
                edge.throughIdentifier = callSite.throughIdentifier;
                resolvedEdges.push_back(std::move(edge));

                enqueueCallee(callSite, initialBindings, callSite.directCallee);
            };

            for (const CallSite &callSite : function.callSites)
            {
                emitDirectCall(callSite);
            }

            // Match a serialized block line to a parsed callsite record.
            auto lineMatchesCallSite = [&](const std::string &line, const CallSite &callSite)
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
                    const auto it = bindings.find(slot);
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

                const auto currentBlockIt = blockMap.find(state.blockId);
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

                for (const std::string &rawLine : block.lines)
                {
                    const std::string line = trimLine(rawLine);
                    // Empty lines carry no transfer information.
                    if (line.empty())
                    {
                        continue;
                    }

                    // Try call transfer before assignment transfer on the same line.
                    if (line.find('(') != std::string::npos)
                    {
                        for (const CallSite &callSite : function.callSites)
                        {
                            // Branch: line does not correspond to this callsite candidate.
                            if (!lineMatchesCallSite(line, callSite))
                            {
                                continue;
                            }

                            // Branch: direct call, emit direct edge and enqueue callee.
                            if (!callSite.directCallee.empty())
                            {
                                propagateCalleeStructMemberMappings(callSite, callSite.directCallee, bindings, activeStructMemberMappings, seenStructMemberMappings);
                                break;
                            }

                            const std::set<std::string> targets = resolveIndirectTargets(callSite, knownFunctions, bindings, activeStructMemberMappings);
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
                                const auto wrapperIt = wrapperDispatchTargets.find(function.name);
                                if (wrapperIt != wrapperDispatchTargets.end())
                                {
                                    for (const std::string &target : wrapperIt->second)
                                    {
                                        if (!isBlacklistedFunction(target, blacklistedFunctions))
                                        {
                                            filteredTargets.insert(target);
                                        }
                                    }
                                }
                            }

                            if (filteredTargets.empty())
                            {
                                if (!callSite.throughIdentifier.empty())
                                {
                                    const std::string throughSlot = canonicalSlot(callSite.throughIdentifier);
                                    const auto it = programWidePointerTargets.find(throughSlot);
                                    if (it != programWidePointerTargets.end())
                                    {
                                        for (const std::string &target : it->second)
                                        {
                                            if (!isBlacklistedFunction(target, blacklistedFunctions))
                                            {
                                                filteredTargets.insert(target);
                                            }
                                        }
                                    }
                                }

                                if (filteredTargets.empty())
                                {
                                    const std::string calleeSlot = canonicalSlot(callSite.calleeExpression);
                                    const auto it = programWidePointerTargets.find(calleeSlot);
                                    if (it != programWidePointerTargets.end())
                                    {
                                        for (const std::string &target : it->second)
                                        {
                                            if (!isBlacklistedFunction(target, blacklistedFunctions))
                                            {
                                                filteredTargets.insert(target);
                                            }
                                        }
                                    }
                                }
                            }

                            // Branch: unresolved indirect call under current bindings.
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
                                break;
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
                            break;
                        }
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

                    const std::vector<std::string> lhsIdentifiers = extractIdentifiers(lhs);
                    // Cannot update state when no LHS slot can be identified.
                    if (lhsIdentifiers.empty())
                    {
                        continue;
                    }
                    const std::string lhsSlot = lhsIdentifiers.back();
                    std::set<std::string> values = resolveMixedExpressionValues(rhs, knownFunctions, bindings);
                    const std::set<std::string> rhsCallees =
                        resolveCallCalleeTargets(rhs, knownFunctions, bindings);
                    if (!rhsCallees.empty())
                    {
                        std::set<std::string> callReturns;
                        for (const std::string &callee : rhsCallees)
                        {
                            const auto returnIt = returnTargetsByFunction.find(callee);
                            if (returnIt != returnTargetsByFunction.end())
                            {
                                callReturns.insert(returnIt->second.begin(), returnIt->second.end());
                            }
                        }

                        if (!callReturns.empty())
                        {
                            values = std::move(callReturns);
                        }

                        for (const std::string &callee : rhsCallees)
                        {
                            const auto structIt = returnedStructMemberMappingsByFunction.find(callee);
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
                        const auto globalTargetsIt = programWidePointerTargets.find(rhsSlot);
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

                    std::set<std::string> &slotValues = bindings[lhsSlot];
                    // Strong update: reassignment overwrites prior slot values on this path.
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
                        pointerSlots.find(lhsSlot) != pointerSlots.end() || hasNonIntegerValue;
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
        if (knownFunctions.find("main") != knownFunctions.end())
        {
            return {"main"};
        }

        std::map<std::string, std::size_t> incoming;
        for (const std::string &name : knownFunctions)
        {
            incoming[name] = 0U;
        }

        for (const CollapsedEdge &edge : collapsedEdges)
        {
            auto it = incoming.find(edge.callee);
            if (it != incoming.end())
            {
                ++it->second;
            }
        }

        std::vector<std::string> roots;
        for (const auto &entry : incoming)
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
    CallGraphStats &stats,
    std::string &errorMessage)
{
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

    std::map<std::string, std::vector<CollapsedEdge>> outgoing;
    for (const CollapsedEdge &edge : collapsedEdges)
    {
        outgoing[edge.caller].push_back(edge);
    }
    for (auto &entry : outgoing)
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

    auto makeNodeKey = [](const std::string &function, const std::vector<std::string> &context)
    {
        if (context.empty())
        {
            return function + "|";
        }
        return function + "|" + joinContext(context, "\x1f");
    };

    auto enqueueNode = [&](const std::string &function, const std::vector<std::string> &context)
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
        const auto current = std::move(worklist.front());
        worklist.pop_front();

        const std::string &currentFunction = current.first;
        const std::vector<std::string> &currentContext = current.second;
        const std::string callerKey = makeNodeKey(currentFunction, currentContext);

        auto outgoingIt = outgoing.find(currentFunction);
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
