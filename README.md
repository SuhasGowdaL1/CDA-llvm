# C CFG Generator & Path Finder (LibTooling)

This project provides two complementary tools for analyzing C code:

1. **cfg_generator** - Parses a directory of interdependent C/header files and generates:
   - per-function DOT CFG files
   - one aggregated binary serialization for all discovered functions

2. **path_finder** - Reads the CFG binary and enumerates:
   - all possible function call paths from a specified entry point
   - complete call graph summary

## What It Produces

- `cfg_generator`: CLI tool for CFG generation from C source directories
  - `out/dotfiles/*.dot`: one DOT file per function (when `--format=dot`)
  - `out/cfg.cfgb` (or custom `-o`): single binary for all functions
  
- `path_finder`: CLI tool for path enumeration from CFG binary
  - `out/paths.txt`: all possible function call sequences from entry point
  - Call graph summary printed to stdout

## Features

- **Multi-file Support**: Handles interdependent C and header files in a directory
- **Inter-file Function Calls**: Correctly tracks function calls across different source files
- **Path Enumeration**: Enumerates all possible execution paths from a specified entry point
- **Cycle Detection**: Avoids infinite loops in recursive function calls
- **Compact Binary Format**: Lossless serialization with deduplication (magic: `CFGB2`)

## Requirements

- LLVM/Clang 17 development packages with LibTooling.
- CMake 3.20+.
- A C toolchain.

## Build (Linux)

```sh
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release -DCFGGEN_BUILD_STATIC_LINUX=OFF
cmake --build build-linux -j
```

If full static linking is not available in your distro packages, disable it:

```sh
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release -DCFGGEN_BUILD_STATIC_LINUX=OFF
cmake --build build-linux -j
```

## Run

### Step 1: Generate CFG

Input should be a directory that contains C sources (and headers used by those sources).

```sh
./build-linux/cfg_generator --format=dot --dot-dir out/dotfiles -o out/cfg.cfgb examples -- -I.
```

This produces:
- per-function DOT files in `out/dotfiles/`
- one binary file `out/cfg.cfgb`

Filter a single function name:

```sh
./build-linux/cfg_generator --format=dot --dot-dir out/dotfiles -o out/cfg.cfgb \
	--function classify examples -- -I.
```

### Step 2: Enumerate Function Paths

Use the CFG binary to discover all possible function call paths from an entry point:

```sh
./build-linux/path_finder out/cfg.cfgb --entrypoint classify_series -o out/paths.txt
```

This produces:
- `out/paths.txt`: List of all enumerated paths
- stdout: Function call paths and call graph summary

Options:
- `--entrypoint NAME`: Start path enumeration from function NAME (default: main)
- `--max-paths N`: Limit number of paths to enumerate (default: 256)
@@**Generate both text and binary path formats:**
@@
@@```sh
@@./build-linux/path_finder out/cfg.cfgb --entrypoint classify_series -o out/paths.txt -ob out/paths.bin
@@```
@@
@@- `-o FILE`: Output text format paths (human-readable)
@@- `-ob FILE`: Output binary format paths (compact, ~40% of text size with function deduplication)
@@
@@**Binary Path Format:**
@@The `-ob` option stores paths in a compact binary format:
@@- **Magic header:** `PTHS` (4 bytes)
@@- **Function lookup table:** Unique function names stored once with uint32_t length prefixes
@@- **Paths:** Encoded as sequences of function name indices (uint32_t values)
@@- **Compression:** ~59% size reduction vs text format by eliminating repeated function names

Example output:
```
Path 1: classify_series -> adjust_with_limit -> clamp_range
Path 2: classify_series -> adjust_with_limit -> sign_score
Path 3: classify_series -> choose_bucket -> score_penalty -> clamp_range
...
```

## Docker (Linux)

The Docker setup is dependency-only and Linux-only.

### Exact Steps: Build and Run with Docker

1. Build the Linux dependency image once:

```sh
scripts/build_linux_binary_docker.sh --build-image
```

2. Build both binaries using the stored image:

```sh
scripts/build_linux_binary_docker.sh
```

Verify the output:

```sh
ls -lh build-linux/{cfg_generator,path_finder}
```

3. Create output directory:

```sh
mkdir -p out
```

4. Generate CFG from source directory:

```sh
docker run --rm -v "$PWD:/work" -w /work cfggen:linux-build-deps \
	-lc './build-linux/cfg_generator --format=dot --dot-dir out/dotfiles -o out/cfg.cfgb examples -- -I.'
```

5. Enumerate function paths:

```sh
docker run --rm -v "$PWD:/work" -w /work cfggen:linux-build-deps \
	-lc './build-linux/path_finder out/cfg.cfgb --entrypoint classify_series -o out/paths.txt'
```

6. View results:

```sh
```sh
ls -l out/cfg.cfgb
ls -1 out/dotfiles | head
cat out/paths.txt
```

## Advanced Usage

### Binary Format

The CFG is stored in a compact, lossless binary format (magic header: `CFGB2`):

```sh
# Generate only binary (skip DOT files)
./build-linux/cfg_generator --format=bin -o out/cfg.cfgb examples -- -I.
```

Features:
- Lossless: all graph information preserved
- Compact: line table deduplication
- Self-contained: all function data in single file
- Portable: independent of DOT visualization

### Path Finding Options

Control path enumeration with these flags:

```sh
# Find paths from different entry points
./build-linux/path_finder out/cfg.cfgb --entrypoint classify -o out/classify_paths.txt

# Limit the number of paths (default: 256)
./build-linux/path_finder out/cfg.cfgb --entrypoint main --max-paths 100
```

### Single Function CFG

Generate CFG for a specific function only:

```sh
./build-linux/cfg_generator --function classify_series --format=dot --dot-dir out/dotfiles -o out/cfg.cfgb examples -- -I.
```

## Helper Scripts

Build and run with a single command:

```sh
scripts/build_linux_binary_docker.sh --build-image
scripts/build_linux_binary_docker.sh
```

Store Docker image as tar for transport/reuse:

```sh
scripts/build_and_store_docker_images.sh ./artifacts
docker load -i ./artifacts/linux-deps.tar
```

## Exit Codes

### cfg_generator
- `0`: success; at least one function CFG generated
- `1`: output file errors
- `2`: command-line parsing errors
- `3`: no function definitions found

### path_finder
- `0`: success; paths enumerated (may be 0 if entry point is a leaf)
- `1`: input file errors or I/O failures
- Other codes: execution errors
