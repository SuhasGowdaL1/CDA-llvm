#ifndef CFG_MODEL_H
#define CFG_MODEL_H

#include <cstdint>
#include <set>
#include <string>
#include <vector>

/**
 * @brief Source location information for extracted analysis facts.
 */
struct SourceLocationRecord
{
    std::string file;
    std::uint32_t line = 0;
    std::uint32_t column = 0;
};

/**
 * @brief One callsite with direct/indirect metadata.
 */
struct CallSiteRecord
{
    std::string calleeExpression;
    std::string directCallee;
    std::string throughIdentifier;
    std::vector<std::string> argumentExpressions;
    bool isIndirect = false;
    SourceLocationRecord location;
};

/**
 * @brief One pointer assignment/init fact used by indirect-call analysis.
 */
struct PointerAssignmentRecord
{
    std::string lhsExpression;
    std::string rhsExpression;
    std::string assignedFunction;
    bool rhsTakesFunctionAddress = false;
    SourceLocationRecord location;
};

/**
 * @brief A serialized CFG block.
 */
struct SerializedBlock
{
    std::uint32_t id = 0;
    std::vector<std::string> lines;
    std::vector<std::uint32_t> successors;
};

/**
 * @brief Function-level attributes.
 */
struct FunctionAttributes
{
    bool callsStateChange = false;
    std::vector<CallSiteRecord> callSites;
    std::vector<PointerAssignmentRecord> pointerAssignments;
    std::set<std::string> addressTakenFunctions;
    std::vector<std::set<std::string>> stateChangeParameterValues;
};

/**
 * @brief A serialized function CFG.
 */
struct SerializedFunction
{
    std::string name;
    std::uint32_t entryBlockId = 0;
    std::uint32_t exitBlockId = 0;
    std::vector<SerializedBlock> blocks;
    FunctionAttributes attributes;
};

/**
 * @brief Full CFG bundle emitted to analysis JSON.
 */
struct CfgBundle
{
    std::vector<SerializedFunction> functions;
};

#endif // CFG_MODEL_H
