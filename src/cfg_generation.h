/**
 * @file cfg_generation.h
 * @brief CFG extraction and DOT emission interfaces.
 */

#ifndef CFG_GENERATION_H
#define CFG_GENERATION_H

#include <string>
#include <vector>

#include "model.h"

/**
 * @brief Generates CFGs and analysis facts for all discovered functions in the provided sources.
 * @param inputs Source files/directories.
 * @param compilationArgs Compiler arguments forwarded to Clang tooling.
 * @param functionFilter Optional function name filter (empty means all functions).
 * @param bundle Output CFG bundle.
 * @param errorMessage Populated on failure.
 * @return true on success, false on error.
 */
bool generateCfgBundle(
    const std::vector<std::string> &inputs,
    const std::vector<std::string> &compilationArgs,
    const std::string &functionFilter,
    const std::set<std::string> &blacklistedFunctions,
    CfgBundle &bundle,
    std::string &errorMessage);

/**
 * @brief Emits one DOT file per function in the CFG bundle.
 * @param bundle CFG bundle to emit.
 * @param outputDirectory Destination directory for DOT files.
 * @param errorMessage Populated on failure.
 * @return true on success, false on error.
 */
bool emitFunctionDotFiles(const CfgBundle &bundle, const std::string &outputDirectory, std::string &errorMessage);

#endif // CFG_GENERATION_H
