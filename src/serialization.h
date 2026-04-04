#ifndef CFG_SERIALIZATION_H
#define CFG_SERIALIZATION_H

#include <string>
#include <vector>

#include "model.h"

/**
 * @brief Sanitizes names for DOT-safe identifiers.
 */
std::string sanitizeId(const std::string &input);

/**
 * @brief Escapes a string for DOT label output.
 */
std::string escapeDot(const std::string &input);

/**
 * @brief Normalizes whitespace for stable text encoding.
 */
std::string normalizeWhitespace(const std::string &input);

/**
 * @brief Writes CFG bundle to CFGB v1 binary.
 */
bool writeCfgBinary(const std::string &path, const CfgBundle &bundle, std::string &errorMessage);

/**
 * @brief Reads CFG bundle from CFGB v1 binary.
 */
bool readCfgBinary(const std::string &path, CfgBundle &bundle, std::string &errorMessage);

#endif // CFG_SERIALIZATION_H
