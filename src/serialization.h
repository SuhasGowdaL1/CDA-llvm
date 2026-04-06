#ifndef CFG_SERIALIZATION_H
#define CFG_SERIALIZATION_H

#include <string>

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

#endif // CFG_SERIALIZATION_H
