#include "analysis_output.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace
{

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

    void writeIndent(std::ostream &out, int indent)
    {
        for (int i = 0; i < indent; ++i)
        {
            out.put(' ');
        }
    }

    void writeString(std::ostream &out, const std::string &value)
    {
        out << '"' << escapeJson(value) << '"';
    }

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
        out << "\"pointerAssignments\": ";
        writePointerAssignments(out, function.attributes.pointerAssignments, indent + 4);
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
