#ifndef CFG_VARUINT_H
#define CFG_VARUINT_H

#include <cstdint>
#include <istream>
#include <string>
#include <vector>

/**
 * @brief Writes a varuint-encoded integer to a byte buffer.
 */
void writeVarUInt(std::vector<std::uint8_t> &buffer, std::uint64_t value);

/**
 * @brief Reads a varuint-encoded integer from a byte stream.
 */
bool readVarUInt(std::istream &input, std::uint64_t &value);

/**
 * @brief Writes a varuint-length-prefixed string into a byte buffer.
 */
void writeVarString(std::vector<std::uint8_t> &buffer, const std::string &value);

/**
 * @brief Reads a varuint-length-prefixed string from a byte stream.
 */
bool readVarString(std::istream &input, std::string &value);

#endif // CFG_VARUINT_H
