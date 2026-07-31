#!/usr/bin/env bash
# =============================================================================
#  build.sh — 构建 libsevent / libsevent_ws (clean + cmake + make)
#
#  用法:
#     ./build.sh                  # 默认 SEVENT_WS_DEFLATE=ON
#     SEVENT_WS_DEFLATE=OFF ./build.sh
#
#  每次全量 clean 重建, 避免残留旧产物导致"改了不生效".
#  =============================================================================
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$PROJECT_DIR/build"
DEFLATE="${SEVENT_WS_DEFLATE:-ON}"

log() { echo "[build] $*"; }

log "clean: $BUILD_DIR"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

log "cmake (SEVENT_WS_DEFLATE=$DEFLATE)"
cmake .. -DCMAKE_BUILD_TYPE=Debug -DSEVENT_WS_DEFLATE="$DEFLATE"

log "make -j$(nproc)"
make -j"$(nproc)"

log "done: $BUILD_DIR"
