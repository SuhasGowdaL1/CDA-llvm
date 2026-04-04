#ifndef CFG_MODEL_H
#define CFG_MODEL_H

#include <cstdint>
#include <set>
#include <string>
#include <vector>

/**
 * @brief CFG extraction mode for emitted function graphs.
 */
enum class CfgMode : std::uint8_t
{
    kCallOnly = 0,
    kFull = 1
};

/**
 * @brief A loop group made of CFG block ids.
 */
struct LoopGroup
{
    std::vector<std::uint32_t> blockIds;
};

/**
 * @brief Block-level attributes.
 */
struct BlockAttributes
{
    bool hasLoop = false;
};

/**
 * @brief A serialized CFG block.
 */
struct SerializedBlock
{
    std::uint32_t id = 0;
    std::vector<std::string> lines;
    std::vector<std::uint32_t> successors;
    BlockAttributes attributes;
};

/**
 * @brief Function-level attributes.
 */
struct FunctionAttributes
{
    bool hasDirectRecursion = false;
    bool hasIndirectRecursion = false;
    bool callsStateChange = false;
    std::vector<std::set<std::string>> stateChangeParameterValues;
    std::set<std::string> indirectRecursionPeers;
    std::vector<LoopGroup> loopGroups;
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
 * @brief Full CFG bundle emitted to CFGB binary.
 */
struct CfgBundle
{
    CfgMode mode = CfgMode::kCallOnly;
    std::vector<SerializedFunction> functions;
};

#endif // CFG_MODEL_H
