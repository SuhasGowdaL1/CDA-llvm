#ifndef CFG_COMMON_H
#define CFG_COMMON_H

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "llvm/Support/raw_ostream.h"

// Serialize/deserialize utilities
inline void writeU32(llvm::raw_ostream &Out, std::uint32_t V) {
    char B[4];
    B[0] = static_cast<char>(V & 0xffu);
    B[1] = static_cast<char>((V >> 8) & 0xffu);
    B[2] = static_cast<char>((V >> 16) & 0xffu);
    B[3] = static_cast<char>((V >> 24) & 0xffu);
    Out.write(B, 4);
}

inline void writeString(llvm::raw_ostream &Out, const std::string &S) {
    writeU32(Out, static_cast<std::uint32_t>(S.size()));
    Out.write(S.data(), static_cast<std::streamsize>(S.size()));
}

inline std::string escapeDot(const std::string &Input) {
    std::string Out;
    Out.reserve(Input.size());
    for (char C : Input) {
        if (C == '"' || C == '\\') {
            Out.push_back('\\');
        }
        Out.push_back(C);
    }
    return Out;
}

inline std::string normalizeWhitespace(const std::string &Input) {
    std::string Out;
    Out.reserve(Input.size());

    bool InSpace = false;
    for (char C : Input) {
        const unsigned char UC = static_cast<unsigned char>(C);
        if (std::isspace(UC)) {
            if (!InSpace) {
                Out.push_back(' ');
                InSpace = true;
            }
            continue;
        }
        Out.push_back(C);
        InSpace = false;
    }

    while (!Out.empty() && Out.front() == ' ') {
        Out.erase(Out.begin());
    }
    while (!Out.empty() && Out.back() == ' ') {
        Out.pop_back();
    }

    return Out;
}

inline std::string sanitizeId(const std::string &Input) {
    std::string Out;
    Out.reserve(Input.size());
    for (char C : Input) {
        if ((C >= 'a' && C <= 'z') || (C >= 'A' && C <= 'Z') ||
            (C >= '0' && C <= '9') || C == '_') {
            Out.push_back(C);
        } else {
            Out.push_back('_');
        }
    }
    if (Out.empty()) {
        return "anon";
    }
    return Out;
}

// Serialized structures
struct SerializedBlock {
    unsigned Id = 0;
    std::vector<std::string> Lines;
    std::vector<unsigned> Successors;
};

struct SerializedFunction {
    std::string Name;
    std::string BaseId;
    unsigned EntryBlockId = 0;
    std::vector<SerializedBlock> Blocks;
    std::set<std::string> Callees;
};

// Binary I/O functions
inline std::vector<SerializedFunction> readBinary(const std::string &Path) {
    std::vector<SerializedFunction> Functions;
    std::ifstream File(Path, std::ios::binary);
    if (!File) {
        llvm::errs() << "error: cannot open binary file: " << Path << "\n";
        return Functions;
    }

    char Magic[5];
    File.read(Magic, 5);
    if (!File || std::string(Magic, 5) != "CFGB2") {
        llvm::errs() << "error: invalid binary file magic\n";
        return Functions;
    }

    auto readU32 = [](std::ifstream &F) -> std::uint32_t {
        unsigned char B[4];
        F.read(reinterpret_cast<char *>(B), 4);
        return (static_cast<std::uint32_t>(B[0])) |
               (static_cast<std::uint32_t>(B[1]) << 8) |
               (static_cast<std::uint32_t>(B[2]) << 16) |
               (static_cast<std::uint32_t>(B[3]) << 24);
    };

    auto readString = [&readU32](std::ifstream &F) -> std::string {
        std::uint32_t Len = readU32(F);
        std::string S(Len, '\0');
        F.read(S.data(), static_cast<std::streamsize>(Len));
        return S;
    };

    std::uint32_t LineTableSize = readU32(File);
    std::vector<std::string> LineTable(LineTableSize);
    for (std::uint32_t I = 0; I < LineTableSize; ++I) {
        LineTable[I] = readString(File);
    }

    std::uint32_t NumFunctions = readU32(File);
    for (std::uint32_t I = 0; I < NumFunctions; ++I) {
        SerializedFunction Fn;
        Fn.Name = readString(File);
        Fn.BaseId = readString(File);
        Fn.EntryBlockId = readU32(File);

        std::uint32_t NumBlocks = readU32(File);
        for (std::uint32_t J = 0; J < NumBlocks; ++J) {
            SerializedBlock Block;
            Block.Id = readU32(File);
            std::uint32_t NumLines = readU32(File);
            for (std::uint32_t K = 0; K < NumLines; ++K) {
                Block.Lines.push_back(readString(File));
            }
            std::uint32_t NumSucc = readU32(File);
            for (std::uint32_t K = 0; K < NumSucc; ++K) {
                Block.Successors.push_back(readU32(File));
            }
            Fn.Blocks.push_back(Block);
        }

        std::uint32_t NumCallees = readU32(File);
        for (std::uint32_t J = 0; J < NumCallees; ++J) {
            Fn.Callees.insert(readString(File));
        }

        Functions.push_back(Fn);
    }

    return Functions;
}

inline void writeBinary(const std::string &Path, const std::vector<SerializedFunction> &Functions) {
    std::ofstream File(Path, std::ios::binary);
    if (!File) {
        llvm::errs() << "error: cannot open output file: " << Path << "\n";
        return;
    }

    auto writeU32 = [](std::ofstream &F, std::uint32_t V) {
        unsigned char B[4];
        B[0] = static_cast<unsigned char>(V & 0xffu);
        B[1] = static_cast<unsigned char>((V >> 8) & 0xffu);
        B[2] = static_cast<unsigned char>((V >> 16) & 0xffu);
        B[3] = static_cast<unsigned char>((V >> 24) & 0xffu);
        F.write(reinterpret_cast<char *>(B), 4);
    };

    auto writeString = [&writeU32](std::ofstream &F, const std::string &S) {
        writeU32(F, static_cast<std::uint32_t>(S.size()));
        F.write(S.data(), static_cast<std::streamsize>(S.size()));
    };

    // Build line table
    std::vector<std::string> LineTable;
    std::unordered_map<std::string, std::uint32_t> LineTableIndex;
    for (const SerializedFunction &Fn : Functions) {
        for (const SerializedBlock &Block : Fn.Blocks) {
            for (const std::string &Line : Block.Lines) {
                if (LineTableIndex.find(Line) == LineTableIndex.end()) {
                    LineTableIndex[Line] = static_cast<std::uint32_t>(LineTable.size());
                    LineTable.push_back(Line);
                }
            }
        }
    }

    // Write header
    File.write("CFGB2", 5);
    writeU32(File, static_cast<std::uint32_t>(LineTable.size()));
    for (const std::string &Line : LineTable) {
        writeString(File, Line);
    }

    // Write functions
    writeU32(File, static_cast<std::uint32_t>(Functions.size()));
    for (const SerializedFunction &Fn : Functions) {
        writeString(File, Fn.Name);
        writeString(File, Fn.BaseId);
        writeU32(File, Fn.EntryBlockId);

        writeU32(File, static_cast<std::uint32_t>(Fn.Blocks.size()));
        for (const SerializedBlock &Block : Fn.Blocks) {
            writeU32(File, Block.Id);
            writeU32(File, static_cast<std::uint32_t>(Block.Lines.size()));
            for (const std::string &Line : Block.Lines) {
                writeString(File, Line);
            }
            writeU32(File, static_cast<std::uint32_t>(Block.Successors.size()));
            for (unsigned Succ : Block.Successors) {
                writeU32(File, Succ);
            }
        }

        writeU32(File, static_cast<std::uint32_t>(Fn.Callees.size()));
        for (const std::string &Callee : Fn.Callees) {
            writeString(File, Callee);
        }
    }

    File.flush();
}

// Path binary format utilities
inline std::vector<std::vector<std::string>> readPathsBinary(const std::string &Path) {
    std::vector<std::vector<std::string>> Paths;
    std::ifstream File(Path, std::ios::binary);
    if (!File) {
        llvm::errs() << "error: cannot open path binary file: " << Path << "\n";
        return Paths;
    }

    char Magic[4];
    File.read(Magic, 4);
    if (!File || std::string(Magic, 4) != "PTHS") {
        llvm::errs() << "error: invalid path binary file magic\n";
        return Paths;
    }

    unsigned char Version;
    File.read(reinterpret_cast<char *>(&Version), 1);
    if (Version != 1) {
        llvm::errs() << "error: unsupported path binary version: " << (int)Version << "\n";
        return Paths;
    }

    auto readU32 = [](std::ifstream &F) -> std::uint32_t {
        unsigned char B[4];
        F.read(reinterpret_cast<char *>(B), 4);
        return (static_cast<std::uint32_t>(B[0])) |
               (static_cast<std::uint32_t>(B[1]) << 8) |
               (static_cast<std::uint32_t>(B[2]) << 16) |
               (static_cast<std::uint32_t>(B[3]) << 24);
    };

    auto readString = [&readU32](std::ifstream &F) -> std::string {
        std::uint32_t Len = readU32(F);
        std::string S(Len, '\0');
        F.read(S.data(), static_cast<std::streamsize>(Len));
        return S;
    };

    // Read function lookup table
    std::uint32_t NumFunctions = readU32(File);
    std::vector<std::string> FunctionTable(NumFunctions);
    for (std::uint32_t I = 0; I < NumFunctions; ++I) {
        FunctionTable[I] = readString(File);
    }

    // Read paths
    std::uint32_t NumPaths = readU32(File);
    for (std::uint32_t I = 0; I < NumPaths; ++I) {
        std::vector<std::string> Path;
        std::uint32_t PathLength = readU32(File);
        for (std::uint32_t J = 0; J < PathLength; ++J) {
            std::uint32_t FuncIdx = readU32(File);
            if (FuncIdx < FunctionTable.size()) {
                Path.push_back(FunctionTable[FuncIdx]);
            }
        }
        Paths.push_back(Path);
    }

    return Paths;
}

#endif // CFG_COMMON_H
