#include "serialization.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include "varuint.h"

namespace
{

    constexpr std::uint32_t kCfgFlagsDirectRecursion = 1U << 0U;
    constexpr std::uint32_t kCfgFlagsIndirectRecursion = 1U << 1U;
    constexpr std::uint32_t kCfgFlagsCallsStateChange = 1U << 2U;

    std::uint32_t fnv1a32(const std::vector<std::uint8_t> &bytes)
    {
        std::uint32_t hash = 2166136261U;
        for (std::uint8_t byte : bytes)
        {
            hash ^= static_cast<std::uint32_t>(byte);
            hash *= 16777619U;
        }
        return hash;
    }

    void appendBytes(std::vector<std::uint8_t> &destination, const std::vector<std::uint8_t> &source)
    {
        destination.insert(destination.end(), source.begin(), source.end());
    }

    bool writeWholeFile(const std::string &path, const std::vector<std::uint8_t> &bytes, std::string &errorMessage)
    {
        const std::filesystem::path output(path);
        std::error_code ec;
        if (!output.parent_path().empty())
        {
            std::filesystem::create_directories(output.parent_path(), ec);
            if (ec)
            {
                errorMessage = "failed to create output directory: " + ec.message();
                return false;
            }
        }

        std::ofstream file(path, std::ios::binary);
        if (!file)
        {
            errorMessage = "cannot open output file: " + path;
            return false;
        }
        file.write(reinterpret_cast<const char *>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!file.good())
        {
            errorMessage = "failed to write output file: " + path;
            return false;
        }
        return true;
    }

    bool readMagic(std::istream &input, const char *magic, std::size_t size)
    {
        std::string value(size, '\0');
        input.read(value.data(), static_cast<std::streamsize>(size));
        if (input.gcount() != static_cast<std::streamsize>(size))
        {
            return false;
        }
        return value == std::string(magic, size);
    }

    void applyLoopGroupMembership(SerializedFunction &function)
    {
        for (SerializedBlock &block : function.blocks)
        {
            block.attributes.hasLoop = false;
        }

        std::unordered_set<std::uint32_t> members;
        for (const LoopGroup &group : function.attributes.loopGroups)
        {
            for (std::uint32_t blockId : group.blockIds)
            {
                members.insert(blockId);
            }
        }

        if (members.empty())
        {
            return;
        }

        for (SerializedBlock &block : function.blocks)
        {
            block.attributes.hasLoop = members.find(block.id) != members.end();
        }
    }

} // namespace

std::string sanitizeId(const std::string &input)
{
    std::string output;
    output.reserve(input.size());
    for (char character : input)
    {
        const bool isAlphaNum =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') ||
            character == '_';
        output.push_back(isAlphaNum ? character : '_');
    }
    return output.empty() ? "anon" : output;
}

std::string escapeDot(const std::string &input)
{
    std::string output;
    output.reserve(input.size());
    for (char character : input)
    {
        if (character == '"' || character == '\\')
        {
            output.push_back('\\');
        }
        output.push_back(character);
    }
    return output;
}

std::string normalizeWhitespace(const std::string &input)
{
    std::string output;
    output.reserve(input.size());
    bool inSpace = false;
    for (char character : input)
    {
        if (std::isspace(static_cast<unsigned char>(character)) != 0)
        {
            if (!inSpace)
            {
                output.push_back(' ');
                inSpace = true;
            }
            continue;
        }
        inSpace = false;
        output.push_back(character);
    }
    while (!output.empty() && output.front() == ' ')
    {
        output.erase(output.begin());
    }
    while (!output.empty() && output.back() == ' ')
    {
        output.pop_back();
    }
    return output;
}

bool writeCfgBinary(const std::string &path, const CfgBundle &bundle, std::string &errorMessage)
{
    std::vector<std::string> stringTable;
    std::unordered_map<std::string, std::uint64_t> indexByString;

    auto intern = [&](const std::string &value)
    {
        const auto existing = indexByString.find(value);
        if (existing != indexByString.end())
        {
            return existing->second;
        }
        const std::uint64_t index = static_cast<std::uint64_t>(stringTable.size());
        stringTable.push_back(value);
        indexByString.insert({value, index});
        return index;
    };

    for (const SerializedFunction &function : bundle.functions)
    {
        intern(function.name);
        for (const std::string &peer : function.attributes.indirectRecursionPeers)
        {
            intern(peer);
        }
        for (const std::set<std::string> &parameterValues : function.attributes.stateChangeParameterValues)
        {
            for (const std::string &value : parameterValues)
            {
                intern(value);
            }
        }
        for (const SerializedBlock &block : function.blocks)
        {
            for (const std::string &line : block.lines)
            {
                intern(line);
            }
        }
    }

    std::vector<std::uint8_t> payload;
    writeVarUInt(payload, 1U);
    writeVarUInt(payload, static_cast<std::uint64_t>(bundle.mode));

    writeVarUInt(payload, static_cast<std::uint64_t>(stringTable.size()));
    for (const std::string &value : stringTable)
    {
        writeVarString(payload, value);
    }

    std::uint64_t stateChangeFunctionCount = 0;
    for (const SerializedFunction &function : bundle.functions)
    {
        if (function.attributes.callsStateChange)
        {
            ++stateChangeFunctionCount;
        }
    }

    writeVarUInt(payload, static_cast<std::uint64_t>(bundle.functions.size()));
    writeVarUInt(payload, stateChangeFunctionCount);

    for (const SerializedFunction &function : bundle.functions)
    {
        writeVarUInt(payload, intern(function.name));
        writeVarUInt(payload, function.entryBlockId);
        writeVarUInt(payload, function.exitBlockId);

        std::uint32_t flags = 0;
        if (function.attributes.hasDirectRecursion)
        {
            flags |= kCfgFlagsDirectRecursion;
        }
        if (function.attributes.hasIndirectRecursion)
        {
            flags |= kCfgFlagsIndirectRecursion;
        }
        if (function.attributes.callsStateChange)
        {
            flags |= kCfgFlagsCallsStateChange;
        }
        writeVarUInt(payload, flags);

        writeVarUInt(payload, static_cast<std::uint64_t>(function.attributes.indirectRecursionPeers.size()));
        for (const std::string &peer : function.attributes.indirectRecursionPeers)
        {
            writeVarUInt(payload, intern(peer));
        }

        writeVarUInt(payload, static_cast<std::uint64_t>(function.attributes.stateChangeParameterValues.size()));
        for (const std::set<std::string> &parameterValues : function.attributes.stateChangeParameterValues)
        {
            writeVarUInt(payload, static_cast<std::uint64_t>(parameterValues.size()));
            for (const std::string &value : parameterValues)
            {
                writeVarUInt(payload, intern(value));
            }
        }

        writeVarUInt(payload, static_cast<std::uint64_t>(function.blocks.size()));
        for (const SerializedBlock &block : function.blocks)
        {
            writeVarUInt(payload, block.id);

            writeVarUInt(payload, static_cast<std::uint64_t>(block.lines.size()));
            for (const std::string &line : block.lines)
            {
                writeVarUInt(payload, intern(line));
            }

            writeVarUInt(payload, static_cast<std::uint64_t>(block.successors.size()));
            for (std::uint32_t successor : block.successors)
            {
                writeVarUInt(payload, successor);
            }
        }

        writeVarUInt(payload, static_cast<std::uint64_t>(function.attributes.loopGroups.size()));
        for (const LoopGroup &loopGroup : function.attributes.loopGroups)
        {
            writeVarUInt(payload, static_cast<std::uint64_t>(loopGroup.blockIds.size()));
            for (std::uint32_t blockId : loopGroup.blockIds)
            {
                writeVarUInt(payload, blockId);
            }
        }
    }

    std::vector<std::uint8_t> fileBytes;
    fileBytes.push_back('C');
    fileBytes.push_back('F');
    fileBytes.push_back('G');
    fileBytes.push_back('B');
    appendBytes(fileBytes, payload);

    const std::uint32_t checksum = fnv1a32(fileBytes);
    writeVarUInt(fileBytes, checksum);

    return writeWholeFile(path, fileBytes, errorMessage);
}

bool readCfgBinary(const std::string &path, CfgBundle &bundle, std::string &errorMessage)
{
    std::ifstream input(path, std::ios::binary);
    if (!input)
    {
        errorMessage = "cannot open input file: " + path;
        return false;
    }

    if (!readMagic(input, "CFGB", 4))
    {
        errorMessage = "invalid CFGB magic";
        return false;
    }

    std::uint64_t version = 0;
    if (!readVarUInt(input, version) || version != 1U)
    {
        errorMessage = "unsupported CFGB version (expected v1)";
        return false;
    }

    std::uint64_t mode = 0;
    if (!readVarUInt(input, mode))
    {
        errorMessage = "failed to read CFG mode";
        return false;
    }
    bundle.mode = (mode == static_cast<std::uint64_t>(CfgMode::kFull)) ? CfgMode::kFull : CfgMode::kCallOnly;

    std::uint64_t stringCount = 0;
    if (!readVarUInt(input, stringCount))
    {
        errorMessage = "failed to read string table size";
        return false;
    }

    std::vector<std::string> stringTable;
    stringTable.reserve(static_cast<std::size_t>(stringCount));
    for (std::uint64_t i = 0; i < stringCount; ++i)
    {
        std::string value;
        if (!readVarString(input, value))
        {
            errorMessage = "failed to read string table entry";
            return false;
        }
        stringTable.push_back(value);
    }

    auto stringAt = [&](std::uint64_t index, std::string &value)
    {
        if (index >= stringTable.size())
        {
            return false;
        }
        value = stringTable[static_cast<std::size_t>(index)];
        return true;
    };

    std::uint64_t functionCount = 0;
    std::uint64_t logFunctionCount = 0;
    if (!readVarUInt(input, functionCount) || !readVarUInt(input, logFunctionCount))
    {
        errorMessage = "failed to read function counts";
        return false;
    }
    (void)logFunctionCount;

    bundle.functions.clear();
    bundle.functions.reserve(static_cast<std::size_t>(functionCount));

    for (std::uint64_t functionIndex = 0; functionIndex < functionCount; ++functionIndex)
    {
        SerializedFunction function;
        std::uint64_t nameIndex = 0;
        std::uint64_t entryBlockId = 0;
        std::uint64_t exitBlockId = 0;
        std::uint64_t flags = 0;

        if (!readVarUInt(input, nameIndex) || !readVarUInt(input, entryBlockId) ||
            !readVarUInt(input, exitBlockId) ||
            !readVarUInt(input, flags))
        {
            errorMessage = "failed to read function header";
            return false;
        }

        if (!stringAt(nameIndex, function.name))
        {
            errorMessage = "invalid function string index";
            return false;
        }

        function.entryBlockId = static_cast<std::uint32_t>(entryBlockId);
        function.exitBlockId = static_cast<std::uint32_t>(exitBlockId);
        function.attributes.hasDirectRecursion = (flags & kCfgFlagsDirectRecursion) != 0U;
        function.attributes.hasIndirectRecursion = (flags & kCfgFlagsIndirectRecursion) != 0U;
        function.attributes.callsStateChange = (flags & kCfgFlagsCallsStateChange) != 0U;

        std::uint64_t peerCount = 0;
        if (!readVarUInt(input, peerCount))
        {
            errorMessage = "failed to read peer count";
            return false;
        }
        for (std::uint64_t i = 0; i < peerCount; ++i)
        {
            std::uint64_t peerIndex = 0;
            std::string value;
            if (!readVarUInt(input, peerIndex) || !stringAt(peerIndex, value))
            {
                errorMessage = "failed to read peer name";
                return false;
            }
            function.attributes.indirectRecursionPeers.insert(value);
        }

        std::uint64_t parameterCount = 0;
        if (!readVarUInt(input, parameterCount))
        {
            errorMessage = "failed to read state change parameter count";
            return false;
        }

        function.attributes.stateChangeParameterValues.assign(
            static_cast<std::size_t>(parameterCount), std::set<std::string>{});

        for (std::uint64_t parameterIndex = 0; parameterIndex < parameterCount; ++parameterIndex)
        {
            std::uint64_t valueCount = 0;
            if (!readVarUInt(input, valueCount))
            {
                errorMessage = "failed to read state change value count";
                return false;
            }
            for (std::uint64_t valueIndex = 0; valueIndex < valueCount; ++valueIndex)
            {
                std::uint64_t tableIndex = 0;
                std::string value;
                if (!readVarUInt(input, tableIndex) || !stringAt(tableIndex, value))
                {
                    errorMessage = "failed to read state change value";
                    return false;
                }
                function.attributes.stateChangeParameterValues[static_cast<std::size_t>(parameterIndex)].insert(value);
            }
        }

        std::uint64_t blockCount = 0;
        if (!readVarUInt(input, blockCount))
        {
            errorMessage = "failed to read block count";
            return false;
        }

        function.blocks.reserve(static_cast<std::size_t>(blockCount));
        for (std::uint64_t blockIndex = 0; blockIndex < blockCount; ++blockIndex)
        {
            SerializedBlock block;
            std::uint64_t blockId = 0;
            if (!readVarUInt(input, blockId))
            {
                errorMessage = "failed to read block header";
                return false;
            }
            block.id = static_cast<std::uint32_t>(blockId);

            std::uint64_t lineCount = 0;
            if (!readVarUInt(input, lineCount))
            {
                errorMessage = "failed to read block line count";
                return false;
            }
            for (std::uint64_t lineIndex = 0; lineIndex < lineCount; ++lineIndex)
            {
                std::uint64_t tableIndex = 0;
                std::string line;
                if (!readVarUInt(input, tableIndex) || !stringAt(tableIndex, line))
                {
                    errorMessage = "failed to read block line";
                    return false;
                }
                block.lines.push_back(line);
            }

            std::uint64_t successorCount = 0;
            if (!readVarUInt(input, successorCount))
            {
                errorMessage = "failed to read successor count";
                return false;
            }
            for (std::uint64_t successorIndex = 0; successorIndex < successorCount; ++successorIndex)
            {
                std::uint64_t successorId = 0;
                if (!readVarUInt(input, successorId))
                {
                    errorMessage = "failed to read successor id";
                    return false;
                }
                block.successors.push_back(static_cast<std::uint32_t>(successorId));
            }

            function.blocks.push_back(std::move(block));
        }

        std::uint64_t loopGroupCount = 0;
        if (!readVarUInt(input, loopGroupCount))
        {
            errorMessage = "failed to read loop group count";
            return false;
        }

        function.attributes.loopGroups.resize(static_cast<std::size_t>(loopGroupCount));
        for (std::uint64_t groupIndex = 0; groupIndex < loopGroupCount; ++groupIndex)
        {
            std::uint64_t memberCount = 0;
            if (!readVarUInt(input, memberCount))
            {
                errorMessage = "failed to read loop group size";
                return false;
            }

            LoopGroup loopGroup;
            loopGroup.blockIds.reserve(static_cast<std::size_t>(memberCount));
            for (std::uint64_t memberIndex = 0; memberIndex < memberCount; ++memberIndex)
            {
                std::uint64_t blockId = 0;
                if (!readVarUInt(input, blockId))
                {
                    errorMessage = "failed to read loop group block id";
                    return false;
                }
                loopGroup.blockIds.push_back(static_cast<std::uint32_t>(blockId));
            }

            function.attributes.loopGroups[static_cast<std::size_t>(groupIndex)] = std::move(loopGroup);
        }

        applyLoopGroupMembership(function);

        bundle.functions.push_back(std::move(function));
    }

    std::uint64_t checksumValue = 0;
    if (!readVarUInt(input, checksumValue))
    {
        errorMessage = "missing checksum";
        return false;
    }

    return true;
}
