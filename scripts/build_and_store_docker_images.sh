#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DOCKERFILE_PATH="$ROOT_DIR/Dockerfile"

OUT_DIR=${1:-"$ROOT_DIR/docker-images"}
LINUX_IMAGE=${CFGGEN_LINUX_IMAGE:-cfggen:linux-build-deps}

mkdir -p "$OUT_DIR"

echo "[1/2] Building image for linux-deps target: $LINUX_IMAGE"
docker buildx build --target linux-deps -t "$LINUX_IMAGE" -f "$DOCKERFILE_PATH" "$ROOT_DIR"

echo "[2/2] Saving image tar: $OUT_DIR/linux-deps.tar"
docker save -o "$OUT_DIR/linux-deps.tar" "$LINUX_IMAGE"

echo "Done. Saved image archives in: $OUT_DIR"
echo "To restore later:"
echo "  docker load -i $OUT_DIR/linux-deps.tar"
