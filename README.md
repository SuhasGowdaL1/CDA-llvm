# C CFG Analysis Generator (Docker-First)

This repository provides a Docker-first workflow to:

1. Generate function CFGs from C sources.
2. Emit analysis-oriented JSON for interprocedural call-graph analysis.
3. Generate callgraph artifacts from analysis JSON using a C++ tool.
4. Optionally emit DOT artifacts for inspection.

The recommended entry point is `manage.sh`.

## Tools

- `cfg_generator`: creates analysis JSON from source inputs.
- `callgraph_generator`: builds collapsed/context callgraph JSON (and optional DOT) from analysis JSON.
- `runtime_callgraph_generator`: reconstructs execution-time callgraph from runtime logs using entry/exit markers and static callgraph constraints.

## Prerequisites

- Docker

No host LLVM/Clang installation is required.

## Quick Start (Recommended)

Build image, compile with Ninja in Docker, and generate analysis JSON:

```sh
./manage.sh --build-image --docker-build --dot --callgraph
```

This produces:

- `out/cfg-analysis.json`
- `out/dotfiles/*.dot` (if `--dot` is set)
- `out/callgraph.json` (if `--callgraph` is set)
- `out/callgraph.dot` (if `--callgraph` is set and DOT is enabled)

## manage.sh Options

```text
--build-image              Build Docker dependency image
--docker-build             Build binaries inside Docker using Ninja
--format-src               Format files in src/ using clang-format
--cfg-input PATH           CFG input path (default: examples)
--cfg-include DIR          Additional include directory (may be repeated)
--compile-args-file FILE   Compiler args file forwarded to cfg_generator (may be repeated)
--blacklist-file FILE      Exact function names to skip, forwarded to both generators
--cfg-output FILE          Analysis JSON output file (default: out/cfg-analysis.json)
--dot                      Emit per-function DOT files
--dot-dir DIR              DOT output directory (default: out/dotfiles)
--svg                      Convert DOT files to SVG (requires graphviz `dot`)
--callgraph                Generate callgraph JSON from analysis JSON
--callgraph-output FILE    Callgraph JSON output file (default: out/callgraph.json)
--callgraph-dot-output FILE
						   Callgraph DOT output file (default: out/callgraph.dot)
--callgraph-context-depth N
						   Callgraph bounded context depth (default: 3)
--no-callgraph-dot         Disable callgraph DOT output
```

Notes:

- Docker containers are run as host UID/GID, so generated files are user-owned.
- Generated analysis JSON is always full CFG.

## Direct Generation (Without manage.sh)

After Docker build has created `build-linux/*` binaries:

```sh
./build-linux/cfg_generator --emit-dot --dot-dir out/dotfiles -o out/cfg-analysis.json examples src --include-dir include --include-dir third_party/include -- -I.
./build-linux/callgraph_generator -i out/cfg-analysis.json -o out/callgraph.json --dot-output out/callgraph.dot --context-depth 3
```

You can also pass multiple source roots through `manage.sh` by repeating `--cfg-input`, for example:

```sh
./manage.sh --docker-build --cfg-input examples --cfg-input src --cfg-include include --cfg-include third_party/include --dot --callgraph
```

If you want to keep compiler flags in a file, add one or more `--compile-args-file` options. Each file is read by `cfg_generator` and appended to the Clang arguments list before analysis starts.

To exclude functions completely, pass `--blacklist-file` with a text file containing exact function names. Blank lines and `#` comments are ignored.

Example file contents:

```text
-Iinclude
-isystem /opt/sdk/include
-DPROJECT_FEATURE_X=1
```

Example invocation:

```sh
./manage.sh --docker-build --cfg-input examples --compile-args-file compiler.args
```

## Analysis JSON Schema

Top-level fields:

- `version`: schema version (`1`)
- `functions`: array of function records

Function record fields:

- `name`, `entryBlockId`, `exitBlockId`
- `attributes`
: `callsStateChange`
: `stateChangeParameterValues`
: `addressTakenFunctions`
: `callSites` (includes direct and indirect calls)
: `pointerAssignments` (assignment/init facts for pointer analysis)
- `blocks`
: `id`, `lines`, `successors`

Callsite record fields:

- `calleeExpression`: textual callee expression
- `directCallee`: qualified callee name for direct calls, empty for indirect calls
- `throughIdentifier`: identifier used at callsite when indirect (for example a function pointer variable)
- `argumentExpressions`: argument expressions captured at the callsite
- `isIndirect`: boolean
- `location`: `file`, `line`, `column`

Pointer assignment record fields:

- `lhsExpression`, `rhsExpression`
- `assignedFunction`: function symbol when RHS resolves to a function/address-of-function
- `rhsTakesFunctionAddress`: boolean
- `location`: `file`, `line`, `column`

## Project Structure (src)

- `cfg_generator_main.cpp`: CFG generation CLI entrypoint.
- `cfg_generation.*`: CFG extraction and DOT emission.
- `analysis_output.*`: analysis JSON writer.
- `callgraph_analysis.*`: callgraph extraction from analysis JSON.
- `callgraph_generator_main.cpp`: callgraph generation CLI entrypoint.
- `serialization.*`: shared text and DOT escaping helpers.

## Design Documentation

- Detailed callgraph-analysis rationale (decisions, limitations, alternatives, and challenges):
	- `docs/callgraph-analysis-design.md`

## API Documentation (Doxygen)

Generate HTML docs:

```sh
doxygen Doxyfile
```

Generated site:

- `docs/build/html/index.html`

## Exit Codes

### cfg_generator

- `0`: success
- `1`: runtime/IO/tooling failure
- `2`: CLI parsing/usage error
- `3`: no function definitions discovered

### callgraph_generator

- `0`: success
- `1`: runtime/IO/parsing failure

## Runtime Log Callgraph

Generate execution-time callgraph from logs where entrypoints emit `_entry` / `_exit` markers and other functions emit single-line events.

Inputs:

- `--logs`: runtime log file
- `--entrypoints`: names of functions that use `_entry`/`_exit`
- `--static-callgraph`: static graph JSON (typically `out/callgraph.json`) used to constrain caller candidates

Example:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" -w /work cfggen:linux-build-deps -lc \
	"./build-linux/runtime_callgraph_generator --logs input/logs.txt --entrypoints input/entrypoints.txt --static-callgraph out/callgraph.json -o out/runtime-callgraph.json --dot-output out/runtime-callgraph.dot --top-k 8"
```

Behavior:

- `singlePathDeduced=true`: best path score is strictly better than alternatives.
- If not uniquely deduced, output still contains multiple `candidatePaths` with scores.
- `bestPath` always provides the chosen highest-score reconstruction.
