/**
 * @file serialization.cpp
 * @brief Implementations of string normalization and escaping helpers.
 */

#include "serialization.h"

#include <cctype>

/**
 * @brief Convert arbitrary text into a conservative DOT identifier.
 * @return Sanitized identifier or "anon" when empty.
 */
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

/**
 * @brief Escape a string for safe DOT label emission.
 * @return Escaped label.
 */
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

/**
 * @brief Collapse whitespace runs and trim outer whitespace.
 * @return Canonicalized text for stable serialization.
 */
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
