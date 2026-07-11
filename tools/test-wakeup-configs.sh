#!/bin/bash
# =========================================================================
#  验证所有 wakeup 降级路径:
#   eventfd → pipe → UDP loopback 各配置编译 + 测试全部通过
# =========================================================================

cd "$(dirname "$0")/.."

BUILD_BASE="build-wakeup-test"
rm -rf "$BUILD_BASE"-*

PASS=0 FAIL=0

run_config()
{
    local label="$1" outdir="$2"
    shift 2

    printf "\n===== %s =====\n" "$label"
    cmake -B "$outdir" "$@" > /dev/null 2>&1 || { FAIL=$((FAIL + 1)); return 1; }
    cmake --build "$outdir" -j"$(nproc)" > /dev/null 2>&1 || { FAIL=$((FAIL + 1)); return 1; }
    (cd "$outdir" && ctest --output-on-failure) && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
    rm -rf "$outdir"
}

echo "libsevent wakeup 配置矩阵测试"
echo ""

run_config "1) 默认 (eventfd + pipe)"  "${BUILD_BASE}-1" \
    -DSEVENT_ENABLE_EVENTFD=ON -DSEVENT_ENABLE_PIPE=ON
run_config "2) 仅 pipe"               "${BUILD_BASE}-2" \
    -DSEVENT_ENABLE_EVENTFD=OFF -DSEVENT_ENABLE_PIPE=ON
run_config "3) 仅 eventfd"            "${BUILD_BASE}-3" \
    -DSEVENT_ENABLE_EVENTFD=ON -DSEVENT_ENABLE_PIPE=OFF
run_config "4) UDP loopback (全禁用)" "${BUILD_BASE}-4" \
    -DSEVENT_ENABLE_EVENTFD=OFF -DSEVENT_ENABLE_PIPE=OFF
run_config "5) RTOS (UDP loopback)"   "${BUILD_BASE}-5" \
    -DSEVENT_RTOS=ON -DSEVENT_ENABLE_EVENTFD=OFF

echo "结果: $PASS passed, $FAIL failed"
exit $(( FAIL > 0 ))
