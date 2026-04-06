#ifndef CFG_GENERATION_H
#define CFG_GENERATION_H

#include <string>
#include <vector>

#include "model.h"

/**
 * @brief Generates CFGs and analysis facts for all discovered functions in the provided sources.
 */
bool generateCfgBundle(
    const std::vector<std::string> &inputs,
    const std::vector<std::string> &compilationArgs,
    const std::string &functionFilter,
    CfgBundle &bundle,
    std::string &errorMessage);

/**
 * @brief Emits one DOT file per function in the CFG bundle.
 */
bool emitFunctionDotFiles(const CfgBundle &bundle, const std::string &outputDirectory, std::string &errorMessage);

#endif // CFG_GENERATION_H
