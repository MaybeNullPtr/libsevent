#!/bin/bash
# =========================================================================
#  ASan 内存检查: 编译 + 运行所有测试, 检测 use-after-free, OOB, 泄漏
# =========================================================================
# 用法:
#   bash tools/test-asan.sh                   # 默认 POSIX
#   bash tools/test-asan.sh rtos              # RTOS 模式
#   bash tools/test-asan.sh posix             # POSIX 模式 (默认)
# =========================================================================

cd "$(dirname "$0")/.."
MODE="${1:-posix}"

case "$MODE" in
    posix)  EXTRA="" ;;
    rtos)   EXTRA="-DSEVENT_RTOS=ON -DSEVENT_ENABLE_EVENTFD=OFF -DSEVENT_ENABLE_PIPE=OFF" ;;
    *)      echo "usage: $0 [posix|rtos]"; exit 1 ;;
esac

BUILD_DIR="/tmp/sevent-asan-$MODE"
rm -rf "$BUILD_DIR"

echo "== ASan 检查 ($MODE) =="
echo "  cmake -B $BUILD_DIR $EXTRA -DCMAKE_C_FLAGS=-fsanitize=address -g"

cmake -B "$BUILD_DIR" -S . $EXTRA \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" > /dev/null 2>&1

cmake --build "$BUILD_DIR" -j"$(nproc)" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "  [FAIL] 编译失败"
    exit 1
fi

echo ""
echo "  运行时错误 (UAF / OOB / 越界):"
ASAN_OPTIONS=detect_leaks=0 "$BUILD_DIR/test_sevent" 2>&1 \
    | grep -E "heap-use|heap-buf|stack-buf|double-free|ERROR|SUMMARY" \
    | grep -v "^$"

echo ""
echo "  内存泄漏:"
ASAN_OPTIONS=detect_leaks=1 "$BUILD_DIR/test_sevent" 2>&1 \
    | grep -E "Direct|Indirect|SUMMARY" \
    | grep -v "^$"

echo ""
echo "  测试结果:"
ASAN_OPTIONS=detect_leaks=0 "$BUILD_DIR/test_sevent" 2>&1 \
    | grep "result:"
