/**
 * @file serialization.h
 * @brief String normalization and escaping helpers for analysis emitters.
 */

#ifndef CFG_SERIALIZATION_H
#define CFG_SERIALIZATION_H

#include <string>

/**
 * @brief Sanitizes names for DOT-safe identifiers.
 * @param input Raw identifier text.
 * @return DOT-safe identifier.
 */
std::string sanitizeId(const std::string &input);

/**
 * @brief Escapes a string for DOT label output.
 * @param input Raw label text.
 * @return Escaped label text.
 */
std::string escapeDot(const std::string &input);

/**
 * @brief Normalizes whitespace for stable text encoding.
 * @param input Raw text.
 * @return Text with collapsed whitespace.
 */
std::string normalizeWhitespace(const std::string &input);

#endif // CFG_SERIALIZATION_H
