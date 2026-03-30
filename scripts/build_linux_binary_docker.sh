#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
IMAGE_NAME=${CFGGEN_LINUX_IMAGE:-cfggen:linux-build-deps}
BUILD_IMAGE=0
if [ "${1:-}" = "--build-image" ]; then
  BUILD_IMAGE=1
  shift
fi

BUILD_DIR=${1:-build-linux}
BUILD_TYPE=${2:-Release}
STATIC_LINUX=${CFGGEN_BUILD_STATIC_LINUX:-OFF}
AUTO_BUILD=${CFGGEN_AUTO_BUILD:-0}

DOCKERFILE_PATH="$ROOT_DIR/Dockerfile"

if [ "$BUILD_IMAGE" -eq 1 ]; then
  echo "[1/2] Building Linux dependency image: $IMAGE_NAME"
  docker build --target linux-deps -t "$IMAGE_NAME" -f "$DOCKERFILE_PATH" "$ROOT_DIR"
elif docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "[1/2] Using existing Linux dependency image: $IMAGE_NAME"
elif [ "$AUTO_BUILD" = "1" ]; then
  echo "[1/2] Image not found. Building Linux dependency image: $IMAGE_NAME"
  docker buildx build --target linux-deps -t "$IMAGE_NAME" -f "$DOCKERFILE_PATH" "$ROOT_DIR"
else
  echo "Missing Docker image: $IMAGE_NAME"
  echo "Build it once with:"
  echo "  $0 --build-image"
  echo "Or set CFGGEN_AUTO_BUILD=1 to auto-build when missing."
  exit 1
fi

echo "[2/2] Building Linux binary into $BUILD_DIR"
docker run --rm \
  -v "$ROOT_DIR:/work" \
  -w /work \
  "$IMAGE_NAME" \
  -lc "cmake -S . -B $BUILD_DIR -G Ninja -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DCFGGEN_BUILD_STATIC_LINUX=$STATIC_LINUX && cmake --build $BUILD_DIR -j"

echo "Done. Expected outputs:"
echo "  $BUILD_DIR/cfg_generator (CFG generation tool)"
echo "  $BUILD_DIR/path_finder (Path enumeration tool)"
