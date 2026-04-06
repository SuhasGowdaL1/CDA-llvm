#ifndef ANALYSIS_OUTPUT_H
#define ANALYSIS_OUTPUT_H

#include <string>

#include "model.h"

/**
 * @brief Writes CFG bundle to analysis-oriented JSON.
 */
bool writeCfgAnalysisJson(const std::string &path, const CfgBundle &bundle, std::string &errorMessage);

#endif // ANALYSIS_OUTPUT_H
