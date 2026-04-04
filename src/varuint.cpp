#include "varuint.h"

#include <limits>

void writeVarUInt(std::vector<std::uint8_t> &buffer, std::uint64_t value)
{
    while (value >= 0x80U)
    {
        buffer.push_back(static_cast<std::uint8_t>(value) | 0x80U);
        value >>= 7U;
    }
    buffer.push_back(static_cast<std::uint8_t>(value));
}

bool readVarUInt(std::istream &input, std::uint64_t &value)
{
    value = 0;
    std::uint32_t shift = 0;
    for (std::uint32_t index = 0; index < 10; ++index)
    {
        int raw = input.get();
        if (raw == std::char_traits<char>::eof())
        {
            return false;
        }
        const std::uint8_t byte = static_cast<std::uint8_t>(raw);
        value |= (static_cast<std::uint64_t>(byte & 0x7FU) << shift);
        if ((byte & 0x80U) == 0U)
        {
            return true;
        }
        shift += 7U;
    }
    return false;
}

void writeVarString(std::vector<std::uint8_t> &buffer, const std::string &value)
{
    writeVarUInt(buffer, static_cast<std::uint64_t>(value.size()));
    buffer.insert(buffer.end(), value.begin(), value.end());
}

bool readVarString(std::istream &input, std::string &value)
{
    std::uint64_t size = 0;
    if (!readVarUInt(input, size))
    {
        return false;
    }
    if (size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
    {
        return false;
    }
    value.assign(static_cast<std::size_t>(size), '\0');
    input.read(value.data(), static_cast<std::streamsize>(value.size()));
    return input.good() || input.eof();
}
