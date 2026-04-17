#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-build-linux}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
IMAGE_NAME="${CFGGEN_LINUX_IMAGE:-cfggen:linux-build-deps}"
CFG_INPUT="examples"
CFG_INPUTS=()
CFG_INCLUDE_DIRS=(".")
CFG_COMPILE_ARGS_FILES=()
BLACKLIST_FILE=""
CFG_OUTPUT="out/cfg-analysis.json"
DOT_DIR="out/dotfiles"
CALLGRAPH_OUTPUT="out/callgraph.json"
CALLGRAPH_DOT_OUTPUT="out/callgraph.dot"
CALLGRAPH_CONTEXT_DEPTH=3
CALLGRAPH_MODE="resolve-indirect"
CALLGRAPH_INDIRECT_MAPPING="out/indirect-mapping.json"
RUNTIME_LOGS="input/logs.txt"
RUNTIME_ENTRYPOINTS="input/entrypoints.txt"
RUNTIME_OUTPUT="out/runtime-callgraph.json"
RUNTIME_DOT_OUTPUT="out/runtime-callgraph.dot"
RUNTIME_TIMELINE_HTML="out/runtime-timeline.html"
RUNTIME_CONTEXT_TREE_HTML="out/runtime-context-tree.html"
RUNTIME_TOP_K=8
RUNTIME_LOOKAHEAD_PLAIN_EVENTS=8
DO_BUILD_IMAGE=0
DO_FORMAT=0
DO_DOT=0
DO_SVG=0
DO_CALLGRAPH=0
DO_CALLGRAPH_DOT=1
DO_CALLGRAPH_DEBUG=0
DO_RUNTIME_CALLGRAPH=0
DO_RUNTIME_DOT=1
DO_RUNTIME_HTML=1
DO_DOCKER_BUILD=0
ACTIVE_CONTAINER_NAMES=()

cleanup_docker_containers() {
  for name in "${ACTIVE_CONTAINER_NAMES[@]}"; do
    if [[ -n "$name" ]]; then
      docker stop "$name" >/dev/null 2>&1 || true
      docker rm -f "$name" >/dev/null 2>&1 || true
    fi
  done
  ACTIVE_CONTAINER_NAMES=()
}

on_interrupt() {
  echo "Interrupted. Stopping active Docker containers..." >&2
  cleanup_docker_containers
  exit 130
}

on_exit() {
  cleanup_docker_containers
}

trap on_interrupt INT TERM
trap on_exit EXIT

new_container_name() {
  echo "cfggen_${$}_${RANDOM}_${RANDOM}"
}

usage() {
  cat <<'EOF'
Usage: ./manage.sh [options]

Build and run helper for CFG analysis artifacts.

Options:
  --build-image              Build Docker dependency image
  --docker-build             Build binaries inside Docker (Ninja)
  --format-src               Format source files in src/ with clang-format
  --source-dir DIR           Source directory/file for CFG input (may be repeated; default: examples)
  --include-dir DIR          Additional include directory (may be repeated)
  --compile-args-file FILE   Compiler args file forwarded to cfg_generator (may be repeated)
  --blacklist-file FILE      Exact function names to skip, forwarded to both generators
  --cfg-output FILE          Analysis JSON output file (default: out/cfg-analysis.json)
  --dot                      Emit per-function DOT files
  --dot-dir DIR              DOT output directory (default: out/dotfiles)
  --svg                      Convert DOT files to SVG (requires dot command)
  --callgraph                Generate callgraph JSON from analysis JSON
  --callgraph-output FILE    Callgraph JSON output file (default: out/callgraph.json)
  --callgraph-dot-output FILE
                             Callgraph DOT output file (default: out/callgraph.dot)
  --callgraph-context-depth N
                             Callgraph bounded context depth (default: 3)
  --callgraph-mode MODE      Indirect resolution mode: resolve-indirect or precomputed-indirect
  --indirect-mapping FILE    Indirect mapping JSON path (default: out/indirect-mapping.json)
  --callgraph-debug          Enable non-error callgraph debug tracing
  --no-callgraph-dot         Disable callgraph DOT output
  --runtime-callgraph        Generate runtime callgraph from logs
  --runtime-logs FILE        Runtime logs input (default: input/logs.txt)
  --runtime-entrypoints FILE Runtime entrypoints file (default: input/entrypoints.txt)
  --runtime-output FILE      Runtime callgraph JSON output (default: out/runtime-callgraph.json)
  --runtime-dot-output FILE  Runtime callgraph DOT output (default: out/runtime-callgraph.dot)
  --runtime-timeline-html FILE
                             Runtime timeline HTML output (default: out/runtime-timeline.html)
  --runtime-context-tree-html FILE
                             Runtime context tree HTML output (default: out/runtime-context-tree.html)
  --runtime-top-k N          Keep top K runtime candidate paths (default: 8)
  --runtime-lookahead-plain-events N
                             Future plain events used by runtime Viterbi-style lookahead (default: 8)
  --no-runtime-dot           Disable runtime DOT output
  --no-runtime-html          Disable runtime HTML outputs
  -h, --help                 Show help
EOF
}

run_docker_build_image() {
  docker build --target linux-deps -t "$IMAGE_NAME" -f "$ROOT_DIR/Dockerfile" "$ROOT_DIR"
}

run_docker_build() {
  run_in_docker "cmake -S . -B $BUILD_DIR -G Ninja -DCMAKE_BUILD_TYPE=$BUILD_TYPE && cmake --build $BUILD_DIR -j"
}

run_in_docker() {
  local cmd="$1"
  local container_name
  local container_id
  local logger_pid
  local wait_code
  local exit_code

  container_name="$(new_container_name)"
  ACTIVE_CONTAINER_NAMES+=("$container_name")

  container_id="$(docker run -d \
    --name "$container_name" \
    --user "$(id -u):$(id -g)" \
    -v "$ROOT_DIR:/work" \
    -w /work \
    "$IMAGE_NAME" \
    -lc "$cmd")"
  if [[ -z "$container_id" ]]; then
    echo "failed to start docker container" >&2
    return 1
  fi

  docker logs -f "$container_name" &
  logger_pid=$!

  wait_code="$(docker wait "$container_name")"
  exit_code="${wait_code%%[^0-9]*}"
  if [[ -z "$exit_code" ]]; then
    exit_code=1
  fi

  kill "$logger_pid" >/dev/null 2>&1 || true
  wait "$logger_pid" 2>/dev/null || true

  docker rm -f "$container_name" >/dev/null 2>&1 || true

  # Remove from active list once container has exited.
  local remaining=()
  for name in "${ACTIVE_CONTAINER_NAMES[@]}"; do
    if [[ "$name" != "$container_name" ]]; then
      remaining+=("$name")
    fi
  done
  ACTIVE_CONTAINER_NAMES=("${remaining[@]}")

  return "$exit_code"
}

format_sources() {
  if ! command -v clang-format >/dev/null 2>&1; then
    echo "clang-format not found"
    exit 1
  fi
  find "$ROOT_DIR/src" -type f \( -name '*.h' -o -name '*.c' \) -print0 | \
    xargs -0 -r clang-format -i
}

generate_cfg() {
  local cmd="./$BUILD_DIR/cfg_generator -o $CFG_OUTPUT"
  if [[ "$DO_DOT" -eq 1 ]]; then
    cmd="$cmd --emit-dot --dot-dir $DOT_DIR"
  fi

  local inputs=()
  local expanded_inputs=()
  if [[ ${#CFG_INPUTS[@]} -gt 0 ]]; then
    inputs=("${CFG_INPUTS[@]}")
  else
    inputs=("$CFG_INPUT")
  fi

  for input in "${inputs[@]}"; do
    if [[ -d "$input" ]]; then
      while IFS= read -r -d '' file; do
        expanded_inputs+=("$file")
      done < <(find "$input" -type f \( -name '*.c' -o -name '*.h' \) -print0)
      continue
    fi

    expanded_inputs+=("$input")
  done

  if [[ ${#expanded_inputs[@]} -eq 0 ]]; then
    echo "error: no source files found from configured inputs" >&2
    exit 1
  fi

  for include_dir in "${CFG_INCLUDE_DIRS[@]}"; do
    cmd="$cmd --include-dir $(printf '%q' "$include_dir")"
  done

  for args_file in "${CFG_COMPILE_ARGS_FILES[@]}"; do
    cmd="$cmd --compile-args-file $(printf '%q' "$args_file")"
  done

  if [[ -n "$BLACKLIST_FILE" ]]; then
    cmd="$cmd --blacklist-file $(printf '%q' "$BLACKLIST_FILE")"
  fi

  for input in "${expanded_inputs[@]}"; do
    cmd="$cmd $(printf '%q' "$input")"
  done

  if [[ "$DO_DOCKER_BUILD" -eq 1 ]]; then
    run_in_docker "$cmd"
  else
    eval "$cmd"
  fi
}

generate_callgraph() {
  local cmd="./$BUILD_DIR/callgraph_generator -i $CFG_OUTPUT -o $CALLGRAPH_OUTPUT --context-depth $CALLGRAPH_CONTEXT_DEPTH"
  if [[ "$DO_CALLGRAPH_DOT" -eq 1 ]]; then
    cmd="$cmd --dot-output $CALLGRAPH_DOT_OUTPUT"
  else
    cmd="$cmd --no-dot"
  fi

  if [[ -n "$BLACKLIST_FILE" ]]; then
    cmd="$cmd --blacklist-file $(printf '%q' "$BLACKLIST_FILE")"
  fi

  cmd="$cmd --mode $(printf '%q' "$CALLGRAPH_MODE")"
  if [[ "$CALLGRAPH_MODE" == "resolve-indirect" ]]; then
    cmd="$cmd --indirect-mapping $(printf '%q' "$CALLGRAPH_INDIRECT_MAPPING")"
  else
    cmd="$cmd --indirect-mapping $(printf '%q' "$CALLGRAPH_INDIRECT_MAPPING")"
  fi

  if [[ "$DO_CALLGRAPH_DEBUG" -eq 1 ]]; then
    cmd="$cmd --debug"
  fi

  if [[ "$DO_DOCKER_BUILD" -eq 1 ]]; then
    run_in_docker "$cmd"
  else
    eval "$cmd"
  fi
}

generate_runtime_callgraph() {
  local cmd="./$BUILD_DIR/runtime_callgraph_generator --logs $(printf '%q' "$RUNTIME_LOGS") --entrypoints $(printf '%q' "$RUNTIME_ENTRYPOINTS") --static-callgraph $(printf '%q' "$CALLGRAPH_OUTPUT") --cfg-analysis $(printf '%q' "$CFG_OUTPUT") -o $(printf '%q' "$RUNTIME_OUTPUT") --top-k $(printf '%q' "$RUNTIME_TOP_K") --lookahead-plain-events $(printf '%q' "$RUNTIME_LOOKAHEAD_PLAIN_EVENTS")"

  if [[ "$DO_RUNTIME_DOT" -eq 1 ]]; then
    cmd="$cmd --dot-output $(printf '%q' "$RUNTIME_DOT_OUTPUT")"
  else
    cmd="$cmd --no-dot"
  fi

  if [[ "$DO_RUNTIME_HTML" -eq 1 ]]; then
    cmd="$cmd --timeline-html $(printf '%q' "$RUNTIME_TIMELINE_HTML") --context-tree-html $(printf '%q' "$RUNTIME_CONTEXT_TREE_HTML")"
  else
    cmd="$cmd --no-html"
  fi

  if [[ "$DO_DOCKER_BUILD" -eq 1 ]]; then
    run_in_docker "$cmd"
  else
    eval "$cmd"
  fi
}

generate_svgs() {
  if [[ "$DO_DOT" -ne 1 ]]; then
    echo "--svg requires --dot"
    exit 1
  fi
  if ! command -v dot >/dev/null 2>&1; then
    echo "dot command not found. Install graphviz to use --svg."
    exit 1
  fi
  find "$ROOT_DIR/$DOT_DIR" -type f -name '*.dot' -print0 | while IFS= read -r -d '' file; do
    dot -Tsvg "$file" -o "${file%.dot}.svg"
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-image)
      DO_BUILD_IMAGE=1
      shift
      ;;
    --docker-build)
      DO_DOCKER_BUILD=1
      shift
      ;;
    --format-src)
      DO_FORMAT=1
      shift
      ;;
    --source-dir)
      CFG_INPUTS+=("$2")
      shift 2
      ;;
    --include-dir)
      CFG_INCLUDE_DIRS+=("$2")
      shift 2
      ;;
    --compile-args-file)
      CFG_COMPILE_ARGS_FILES+=("$2")
      shift 2
      ;;
    --blacklist-file)
      BLACKLIST_FILE="$2"
      shift 2
      ;;
    --cfg-output)
      CFG_OUTPUT="$2"
      shift 2
      ;;
    --dot)
      DO_DOT=1
      shift
      ;;
    --dot-dir)
      DOT_DIR="$2"
      shift 2
      ;;
    --svg)
      DO_SVG=1
      shift
      ;;
    --callgraph)
      DO_CALLGRAPH=1
      shift
      ;;
    --callgraph-output)
      CALLGRAPH_OUTPUT="$2"
      shift 2
      ;;
    --callgraph-dot-output)
      CALLGRAPH_DOT_OUTPUT="$2"
      shift 2
      ;;
    --callgraph-context-depth)
      CALLGRAPH_CONTEXT_DEPTH="$2"
      shift 2
      ;;
    --callgraph-mode)
      CALLGRAPH_MODE="$2"
      shift 2
      ;;
    --indirect-mapping)
      CALLGRAPH_INDIRECT_MAPPING="$2"
      shift 2
      ;;
    --callgraph-debug)
      DO_CALLGRAPH_DEBUG=1
      shift
      ;;
    --no-callgraph-dot)
      DO_CALLGRAPH_DOT=0
      shift
      ;;
    --runtime-callgraph)
      DO_RUNTIME_CALLGRAPH=1
      shift
      ;;
    --runtime-logs)
      RUNTIME_LOGS="$2"
      shift 2
      ;;
    --runtime-entrypoints)
      RUNTIME_ENTRYPOINTS="$2"
      shift 2
      ;;
    --runtime-output)
      RUNTIME_OUTPUT="$2"
      shift 2
      ;;
    --runtime-dot-output)
      RUNTIME_DOT_OUTPUT="$2"
      shift 2
      ;;
    --runtime-timeline-html)
      RUNTIME_TIMELINE_HTML="$2"
      shift 2
      ;;
    --runtime-context-tree-html)
      RUNTIME_CONTEXT_TREE_HTML="$2"
      shift 2
      ;;
    --runtime-top-k)
      RUNTIME_TOP_K="$2"
      shift 2
      ;;
    --runtime-lookahead-plain-events)
      RUNTIME_LOOKAHEAD_PLAIN_EVENTS="$2"
      shift 2
      ;;
    --no-runtime-dot)
      DO_RUNTIME_DOT=0
      shift
      ;;
    --no-runtime-html)
      DO_RUNTIME_HTML=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ "$DO_BUILD_IMAGE" -eq 1 ]]; then
  run_docker_build_image
fi

if [[ "$DO_DOCKER_BUILD" -eq 1 ]]; then
  run_docker_build
fi

if [[ "$DO_FORMAT" -eq 1 ]]; then
  format_sources
fi

if [[ -f "$ROOT_DIR/$BUILD_DIR/cfg_generator" ]]; then
  generate_cfg

  if [[ "$DO_RUNTIME_CALLGRAPH" -eq 1 && "$DO_CALLGRAPH" -eq 0 && ! -f "$ROOT_DIR/$CALLGRAPH_OUTPUT" ]]; then
    DO_CALLGRAPH=1
  fi

  if [[ "$DO_CALLGRAPH" -eq 1 ]]; then
    if [[ ! -f "$ROOT_DIR/$BUILD_DIR/callgraph_generator" ]]; then
      echo "callgraph_generator not found in $BUILD_DIR"
      exit 1
    fi
    if [[ "$CALLGRAPH_MODE" == "precomputed-indirect" && ! -f "$ROOT_DIR/$CALLGRAPH_INDIRECT_MAPPING" ]]; then
      echo "error: indirect mapping file not found: $CALLGRAPH_INDIRECT_MAPPING"
      exit 1
    fi
    generate_callgraph
  fi

  if [[ "$DO_RUNTIME_CALLGRAPH" -eq 1 ]]; then
    if [[ ! -f "$ROOT_DIR/$BUILD_DIR/runtime_callgraph_generator" ]]; then
      echo "runtime_callgraph_generator not found in $BUILD_DIR"
      exit 1
    fi
    if [[ ! -f "$ROOT_DIR/$CALLGRAPH_OUTPUT" ]]; then
      echo "error: static callgraph JSON not found: $CALLGRAPH_OUTPUT"
      echo "hint: pass --callgraph or provide an existing callgraph file path via --callgraph-output" >&2
      exit 1
    fi
    if [[ ! -f "$ROOT_DIR/$CFG_OUTPUT" ]]; then
      echo "error: cfg analysis JSON not found: $CFG_OUTPUT"
      exit 1
    fi
    generate_runtime_callgraph
  fi

  if [[ "$DO_SVG" -eq 1 ]]; then
    generate_svgs
  fi
fi
