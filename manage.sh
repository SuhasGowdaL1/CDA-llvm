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
DO_BUILD_IMAGE=0
DO_FORMAT=0
DO_DOT=0
DO_SVG=0
DO_CALLGRAPH=0
DO_CALLGRAPH_DOT=1
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
  --no-callgraph-dot         Disable callgraph DOT output
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
  find "$ROOT_DIR/src" -type f \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) -print0 | \
    xargs -0 -r clang-format -i
}

generate_cfg() {
  local cmd="./$BUILD_DIR/cfg_generator -o $CFG_OUTPUT"
  if [[ "$DO_DOT" -eq 1 ]]; then
    cmd="$cmd --emit-dot --dot-dir $DOT_DIR"
  fi

  local inputs=()
  if [[ ${#CFG_INPUTS[@]} -gt 0 ]]; then
    inputs=("${CFG_INPUTS[@]}")
  else
    inputs=("$CFG_INPUT")
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

  for input in "${inputs[@]}"; do
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
    --no-callgraph-dot)
      DO_CALLGRAPH_DOT=0
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
  if [[ "$DO_CALLGRAPH" -eq 1 ]]; then
    if [[ ! -f "$ROOT_DIR/$BUILD_DIR/callgraph_generator" ]]; then
      echo "callgraph_generator not found in $BUILD_DIR"
      exit 1
    fi
    generate_callgraph
  fi
  if [[ "$DO_SVG" -eq 1 ]]; then
    generate_svgs
  fi
fi
