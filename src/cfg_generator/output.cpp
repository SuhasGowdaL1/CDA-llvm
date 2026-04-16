/**
 * @file output.cpp
 * @brief JSON writer for CFG analysis bundles.
 */

#include "output.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace
{

    /**
     * @brief Escape a string for JSON encoding.
     */
    std::string escapeJson(const std::string &input)
    {
        std::string output;
        output.reserve(input.size() + input.size() / 8U);
        for (unsigned char c : input)
        {
            switch (c)
            {
            case '\\':
                output += "\\\\";
                break;
            case '"':
                output += "\\\"";
                break;
            case '\b':
                output += "\\b";
                break;
            case '\f':
                output += "\\f";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default:
                if (c < 0x20U)
                {
                    static const char *hex = "0123456789abcdef";
                    output += "\\u00";
                    output.push_back(hex[(c >> 4U) & 0xFU]);
                    output.push_back(hex[c & 0xFU]);
                }
                else
                {
                    output.push_back(static_cast<char>(c));
                }
                break;
            }
        }
        return output;
    }

    /**
     * @brief Emit indentation spaces.
     */
    void writeIndent(std::ostream &out, int indent)
    {
        for (int i = 0; i < indent; ++i)
        {
            out.put(' ');
        }
    }

    /**
     * @brief Emit a JSON string value.
     */
    void writeString(std::ostream &out, const std::string &value)
    {
        out << '"' << escapeJson(value) << '"';
    }

    /**
     * @brief Emit a source location object.
     */
    void writeLocation(std::ostream &out, const SourceLocationRecord &location, int indent)
    {
        out << "{\n";
        writeIndent(out, indent + 2);
        out << "\"file\": ";
        writeString(out, location.file);
        out << ",\n";
        writeIndent(out, indent + 2);
        out << "\"line\": " << location.line << ",\n";
        writeIndent(out, indent + 2);
        out << "\"column\": " << location.column << "\n";
        writeIndent(out, indent);
        out << "}";
    }

    /**
     * @brief Emit a JSON array of strings.
     */
    void writeStringArray(std::ostream &out, const std::vector<std::string> &values, int indent)
    {
        out << "[";
        if (!values.empty())
        {
            out << "\n";
            for (std::size_t i = 0; i < values.size(); ++i)
            {
                writeIndent(out, indent + 2);
                writeString(out, values[i]);
                if (i + 1U < values.size())
                {
                    out << ",";
                }
                out << "\n";
            }
            writeIndent(out, indent);
        }
        out << "]";
    }

    void writeNestedStringArray(
        std::ostream &out,
        const std::vector<std::vector<std::string>> &values,
        int indent)
    {
        out << "[";
        if (!values.empty())
        {
            out << "\n";
            for (std::size_t i = 0; i < values.size(); ++i)
            {
                writeIndent(out, indent + 2);
                writeStringArray(out, values[i], indent + 2);
                if (i + 1U < values.size())
                {
                    out << ",";
                }
                out << "\n";
            }
            writeIndent(out, indent);
        }
        out << "]";
    }

    /**
     * @brief Emit a deterministic JSON array for a set of strings.
     */
    void writeStringSet(std::ostream &out, const std::set<std::string> &values, int indent)
    {
        out << "[";
        if (!values.empty())
        {
            out << "\n";
            std::size_t index = 0;
            for (const std::string &value : values)
            {
                writeIndent(out, indent + 2);
                writeString(out, value);
                if (index + 1U < values.size())
                {
                    out << ",";
                }
                out << "\n";
                ++index;
            }
            writeIndent(out, indent);
        }
        out << "]";
    }

    /**
     * @brief Emit state-change parameter value sets.
     */
    void writeStateChangeValues(
        std::ostream &out,
        const std::vector<std::set<std::string>> &values,
        int indent)
    {
        out << "[";
        if (!values.empty())
        {
            out << "\n";
            for (std::size_t i = 0; i < values.size(); ++i)
            {
                writeIndent(out, indent + 2);
                writeStringSet(out, values[i], indent + 2);
                if (i + 1U < values.size())
                {
                    out << ",";
                }
                out << "\n";
            }
            writeIndent(out, indent);
        }
        out << "]";
    }

    /**
     * @brief Emit callsite records.
     */
    void writeCallSites(std::ostream &out, const std::vector<CallSiteRecord> &callSites, int indent)
    {
        out << "[";
        if (!callSites.empty())
        {
            out << "\n";
            for (std::size_t i = 0; i < callSites.size(); ++i)
            {
                const CallSiteRecord &callSite = callSites[i];
                writeIndent(out, indent + 2);
                out << "{\n";
                writeIndent(out, indent + 4);
                out << "\"callSiteId\": ";
                writeString(out, callSite.callSiteId);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"calleeExpression\": ";
                writeString(out, callSite.calleeExpression);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"directCallee\": ";
                writeString(out, callSite.directCallee);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"throughIdentifier\": ";
                writeString(out, callSite.throughIdentifier);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"argumentExpressions\": ";
                writeStringArray(out, callSite.argumentExpressions, indent + 4);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"isIndirect\": " << (callSite.isIndirect ? "true" : "false") << ",\n";
                writeIndent(out, indent + 4);
                out << "\"location\": ";
                writeLocation(out, callSite.location, indent + 4);
                out << "\n";
                writeIndent(out, indent + 2);
                out << "}";
                if (i + 1U < callSites.size())
                {
                    out << ",";
                }
                out << "\n";
            }
            writeIndent(out, indent);
        }
        out << "]";
    }

    /**
     * @brief Emit pointer-assignment records.
     */
    void writePointerAssignments(
        std::ostream &out,
        const std::vector<PointerAssignmentRecord> &assignments,
        int indent)
    {
        out << "[";
        if (!assignments.empty())
        {
            out << "\n";
            for (std::size_t i = 0; i < assignments.size(); ++i)
            {
                const PointerAssignmentRecord &assignment = assignments[i];
                writeIndent(out, indent + 2);
                out << "{\n";
                writeIndent(out, indent + 4);
                out << "\"lhsExpression\": ";
                writeString(out, assignment.lhsExpression);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"rhsExpression\": ";
                writeString(out, assignment.rhsExpression);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"assignedFunction\": ";
                writeString(out, assignment.assignedFunction);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"rhsTakesFunctionAddress\": "
                    << (assignment.rhsTakesFunctionAddress ? "true" : "false") << ",\n";
                writeIndent(out, indent + 4);
                out << "\"lhsIsGlobal\": "
                    << (assignment.lhsIsGlobal ? "true" : "false") << ",\n";
                writeIndent(out, indent + 4);
                out << "\"location\": ";
                writeLocation(out, assignment.location, indent + 4);
                out << "\n";
                writeIndent(out, indent + 2);
                out << "}";
                if (i + 1U < assignments.size())
                {
                    out << ",";
                }
                out << "\n";
            }
            writeIndent(out, indent);
        }
        out << "]";
    }

    /**
     * @brief Emit struct member mapping records.
     */
    void writeStructMemberMappings(
        std::ostream &out,
        const std::vector<StructMemberMapping> &mappings,
        int indent)
    {
        out << "[";
        if (!mappings.empty())
        {
            out << "\n";
            for (std::size_t i = 0; i < mappings.size(); ++i)
            {
                const StructMemberMapping &mapping = mappings[i];
                writeIndent(out, indent + 2);
                out << "{\n";
                writeIndent(out, indent + 4);
                out << "\"structVariable\": ";
                writeString(out, mapping.structVariable);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"memberName\": ";
                writeString(out, mapping.memberName);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"functionName\": ";
                writeString(out, mapping.functionName);
                out << ",\n";
                writeIndent(out, indent + 4);
                out << "\"location\": ";
                writeLocation(out, mapping.location, indent + 4);
                out << "\n";
                writeIndent(out, indent + 2);
                out << "}";
                if (i + 1U < mappings.size())
                {
                    out << ",";
                }
                out << "\n";
            }
            writeIndent(out, indent);
        }
        out << "]";
    }

    /**
     * @brief Emit one serialized CFG block.
     */
    void writeBlock(std::ostream &out, const SerializedBlock &block, int indent)
    {
        out << "{\n";
        writeIndent(out, indent + 2);
        out << "\"id\": " << block.id << ",\n";

        writeIndent(out, indent + 2);
        out << "\"lines\": ";
        writeStringArray(out, block.lines, indent + 2);
        out << ",\n";

        writeIndent(out, indent + 2);
        out << "\"lineCallSiteIds\": ";
        writeNestedStringArray(out, block.lineCallSiteIds, indent + 2);
        out << ",\n";

        writeIndent(out, indent + 2);
        out << "\"successors\": [";
        for (std::size_t i = 0; i < block.successors.size(); ++i)
        {
            out << block.successors[i];
            if (i + 1U < block.successors.size())
            {
                out << ", ";
            }
        }
        out << "]\n";

        writeIndent(out, indent);
        out << "}";
    }

    /**
     * @brief Emit one serialized function and its attributes/blocks.
     */
    void writeFunction(std::ostream &out, const SerializedFunction &function, int indent)
    {
        out << "{\n";
        writeIndent(out, indent + 2);
        out << "\"name\": ";
        writeString(out, function.name);
        out << ",\n";
        writeIndent(out, indent + 2);
        out << "\"entryBlockId\": " << function.entryBlockId << ",\n";
        writeIndent(out, indent + 2);
        out << "\"exitBlockId\": " << function.exitBlockId << ",\n";

        writeIndent(out, indent + 2);
        out << "\"attributes\": {\n";
        writeIndent(out, indent + 4);
        out << "\"callsStateChange\": "
            << (function.attributes.callsStateChange ? "true" : "false")
            << ",\n";

        writeIndent(out, indent + 4);
        out << "\"returnsPointerLike\": "
            << (function.attributes.returnsPointerLike ? "true" : "false")
            << ",\n";

        writeIndent(out, indent + 4);
        out << "\"stateChangeParameterValues\": ";
        writeStateChangeValues(out, function.attributes.stateChangeParameterValues, indent + 4);
        out << ",\n";

        writeIndent(out, indent + 4);
        out << "\"addressTakenFunctions\": ";
        writeStringSet(out, function.attributes.addressTakenFunctions, indent + 4);
        out << ",\n";

        writeIndent(out, indent + 4);
        out << "\"callSites\": ";
        writeCallSites(out, function.attributes.callSites, indent + 4);
        out << ",\n";

        writeIndent(out, indent + 4);
        out << "\"parameterNames\": ";
        writeStringArray(out, function.attributes.parameterNames, indent + 4);
        out << ",\n";

        writeIndent(out, indent + 4);
        out << "\"pointerAssignments\": ";
        writePointerAssignments(out, function.attributes.pointerAssignments, indent + 4);
        out << ",\n";

        writeIndent(out, indent + 4);
        out << "\"structMemberMappings\": ";
        writeStructMemberMappings(out, function.attributes.structMemberMappings, indent + 4);
        out << "\n";

        writeIndent(out, indent + 2);
        out << "},\n";

        writeIndent(out, indent + 2);
        out << "\"blocks\": [";
        if (!function.blocks.empty())
        {
            out << "\n";
            for (std::size_t i = 0; i < function.blocks.size(); ++i)
            {
                writeIndent(out, indent + 4);
                writeBlock(out, function.blocks[i], indent + 4);
                if (i + 1U < function.blocks.size())
                {
                    out << ",";
                }
                out << "\n";
            }
            writeIndent(out, indent + 2);
        }
        out << "]\n";

        writeIndent(out, indent);
        out << "}";
    }

} // namespace

/**
 * @brief Write the full CFG analysis bundle to JSON.
 * @return true on success, false on failure.
 */
bool writeCfgAnalysisJson(const std::string &path, const CfgBundle &bundle, std::string &errorMessage)
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

    std::ofstream file(path);
    if (!file)
    {
        errorMessage = "cannot open output file: " + path;
        return false;
    }

    file << "{\n";
    file << "  \"version\": 1,\n";
    file << "  \"functions\": [";

    if (!bundle.functions.empty())
    {
        file << "\n";
        for (std::size_t i = 0; i < bundle.functions.size(); ++i)
        {
            writeIndent(file, 4);
            writeFunction(file, bundle.functions[i], 4);
            if (i + 1U < bundle.functions.size())
            {
                file << ",";
            }
            file << "\n";
        }
        file << "  ";
    }

    file << "]\n";
    file << "}\n";

    if (!file.good())
    {
        errorMessage = "failed to write output file: " + path;
        return false;
    }

    return true;
}
