/**
 * @file output.h
 * @brief JSON serialization API for CFG analysis artifacts.
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include <string>

#include "model.h"

/**
 * @brief Writes CFG bundle to analysis-oriented JSON.
 * @param path Output JSON path.
 * @param bundle CFG bundle to serialize.
 * @param errorMessage Populated on failure.
 * @return true on success, false on error.
 */
bool writeCfgAnalysisJson(const std::string &path, const CfgBundle &bundle, std::string &errorMessage);

#endif // OUTPUT_H
