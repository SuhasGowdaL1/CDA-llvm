# C CFG Binary Generator (Docker-First)

This repository provides a Docker-first workflow to:

1. Generate function CFGs from C sources.
2. Serialize CFGs into a compact `CFGB` binary.
3. Optionally emit DOT artifacts for inspection.

The recommended entry point is `manage.sh`.

## Tools

- `cfg_generator`: creates `CFGB` from source inputs.
- `cfgb_interpreter`: reads `CFGB` and emits per-function DOT files.

## Prerequisites

- Docker

No host LLVM/Clang installation is required.

## Quick Start (Recommended)

Build image, compile with Ninja in Docker, and generate CFGB:

```sh
./manage.sh --build-image --docker-build --dot
```

This produces:

- `out/cfg.cfgb`
- `out/dotfiles/*.dot` (if `--dot` is set)

## manage.sh Options

```text
--build-image              Build Docker dependency image
--docker-build             Build binaries inside Docker using Ninja
--format-src               Format files in src/ using clang-format
--cfg-input PATH           CFG input path (default: examples)
--cfg-output FILE          CFGB output file (default: out/cfg.cfgb)
--cfg-mode MODE            CFG mode: call|full (default: call)
--dot                      Emit per-function DOT files
--dot-dir DIR              DOT output directory (default: out/dotfiles)
--svg                      Convert DOT files to SVG (requires graphviz `dot`)
```

Notes:

- Docker containers are run as host UID/GID, so generated files are user-owned.
- `--cfg-mode call` is default and emits call-focused CFG data.
- `--cfg-mode full` preserves richer per-block statement content.

## Direct Binary Generation (Without manage.sh)

After Docker build has created `build-linux/*` binaries:

```sh
./build-linux/cfg_generator --cfg-mode call --emit-dot --dot-dir out/dotfiles -o out/cfg.cfgb examples -- -I.
```

## Binary Format Reference

### CFGB (CFG binary)

Magic: `CFGB` (4 bytes)

Encoding:

- Integer fields use unsigned varint encoding (`varuint`).
- String table entries are encoded as `varuint(length)` + raw bytes.
- Most string-bearing fields reference string table indices.

Top-level layout:

| Order | Field | Type | Description |
|---|---|---|---|
| 1 | Magic | bytes[4] | ASCII `CFGB` |
| 2 | Version | varuint | Format version (`2`) |
| 3 | Mode | varuint | `0=call`, `1=full` |
| 4 | String Count | varuint | Number of strings in table |
| 5 | String Table | repeated string | `varuint(len)` + raw bytes |
| 6 | Function Count | varuint | Total functions serialized |
| 7 | Log Function Count | varuint | Number of functions with state-change logs |
| 8 | Function CFGs | repeated record | See function record table below |
| 9 | Checksum | varuint | FNV-1a 32-bit checksum value |

Function record (`Function CFGs`) layout:

| Order | Field | Type | Description |
|---|---|---|---|
| 1 | Function Name Index | varuint | Index into string table |
| 2 | Entry Block ID | varuint | LLVM CFG entry block id |
| 3 | Exit Block ID | varuint | LLVM CFG exit block id |
| 4 | Function Flags | varuint | Bit flags (direct recursion, indirect recursion, state-change calls) |
| 5 | Indirect Recursion Peer Count | varuint | SCC peer count |
| 6 | Indirect Recursion Peers | repeated varuint | String indices of peer names |
| 7 | State Parameter Count | varuint | Number of tracked state-change parameters |
| 8 | State Parameter Value Sets | nested repeated varuint | For each parameter: count + value string indices |
| 9 | Block Count | varuint | Number of blocks in this function |
| 10 | Blocks | repeated record | See block record table below |

Block record (`Blocks`) layout:

| Order | Field | Type | Description |
|---|---|---|---|
| 1 | Block ID | varuint | CFG block id |
| 2 | Block Flags | varuint | Bit flags (loop marker) |
| 3 | Line Count | varuint | Number of label/statement lines |
| 4 | Lines | repeated varuint | String indices for each line |
| 5 | Successor Count | varuint | Number of CFG successors |
| 6 | Successors | repeated varuint | Successor block ids |

## Interpreter Usage

Generate DOT files from an existing `CFGB`:

```sh
./build-linux/cfgb_interpreter out/cfg.cfgb --dot-dir out/dotfiles
```

## Project Structure (src)

- `cfg_generator_main.cpp`: CFG generation CLI entrypoint.
- `cfg_generation.*`: CFG extraction and DOT emission.
- `serialization.*`: CFGB read-write logic.
- `varuint.*`: varuint encoding/decoding helpers.
- `cfgb_interpreter.cpp`: CFGB to DOT interpreter.

## Exit Codes

### cfg_generator

- `0`: success
- `1`: runtime/IO/tooling failure
- `2`: CLI parsing/usage error
- `3`: no function definitions discovered
