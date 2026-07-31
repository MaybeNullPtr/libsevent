set -euo pipefail

#============================================================================
# Autobahn 合规测试
# 用法:
#   MODE=fuzzingclient  ./tests/run_autobahn_docker.sh   # 测 server (帧层)
#   MODE=fuzzingserver  ./tests/run_autobahn_docker.sh   # 测 client (状态机)
#   CASES='["1.*"]'     ./tests/run_autobahn_docker.sh   # 跑子集
#============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORTS_DIR="$PROJECT_DIR/reports"
CONFIG_DIR="$PROJECT_DIR/config"
BUILD_DIR="$PROJECT_DIR/build"
SHARED_DIR="$HOME/shared"

MODE="${MODE:-fuzzingserver}"
CASES="${CASES:-[\"*\"]}"
PORT=9001
ECHO_PORT=9002
TIMEOUT="${TIMEOUT:-500}"
# SEVENT_WS_DEFLATE=OFF 时: 库与测试程序都不带 deflate 宏 (client 不 offer 压缩)
DEFLATE_FLAG=""
if [ "${SEVENT_WS_DEFLATE:-ON}" = "ON" ]; then
    DEFLATE_FLAG="-DSEVENT_WS_DEFLATE"
fi

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "============================================"
log " Autobahn 合规测试"
log " 模式:    $MODE"
log " 用例:    $CASES"
log " 报告:    $REPORTS_DIR"
log "============================================"

# ---- 1. 编译 ----
log "[1] 编译..."
cd "$PROJECT_DIR"
"$PROJECT_DIR/build.sh" 2>&1 | tail -2
gcc -std=c99 -Wall -Werror $DEFLATE_FLAG -I include -I src -I src/websockets \
    tests/autobahn_echo_server.c \
    -L build -lsevent_ws -lsevent -lz \
    -o "$BUILD_DIR/autobahn_echo_server" -Wl,-rpath,"$BUILD_DIR" 2>&1
g++ -std=c++17 -Wall -Werror $DEFLATE_FLAG -I include -I src -I src/websockets \
    tests/autobahn_client.cpp \
    -L build -lsevent_ws -lsevent -lz \
    -o "$BUILD_DIR/autobahn_client" -Wl,-rpath,"$BUILD_DIR" 2>&1
log "    编译完成"

# ---- 2. 清理遗留 ----
kill "$(lsof -ti:$PORT 2>/dev/null)" 2>/dev/null || true
kill "$(lsof -ti:$ECHO_PORT 2>/dev/null)" 2>/dev/null || true
sg docker -c "docker rm -f autobahn 2>/dev/null" || true
sleep 1

mkdir -p "$CONFIG_DIR" "$REPORTS_DIR"

if [ "$MODE" = "fuzzingclient" ]; then
    # ===== fuzzingclient: 测试 echo server =====
    cat > "$CONFIG_DIR/fuzzingclient.json" << CONF
{
    "outdir": "/reports",
    "servers": [{
        "agent": "libsevent",
        "url": "ws://127.0.0.1:$ECHO_PORT"
    }],
    "cases": $CASES,
    "exclude-cases": [],
    "exclude-agent-cases": {}
}
CONF

    log "[2] 启动 echo server (端口 $ECHO_PORT)..."
    "$BUILD_DIR/autobahn_echo_server" "$ECHO_PORT" &
    sleep 1

    log "[3] 启动 Docker (后台)..."
    sg docker -c "docker rm -f autobahn" 2>/dev/null || true
    sg docker -c "docker run -d \
        -v $CONFIG_DIR:/config \
        -v $REPORTS_DIR:/reports \
        --network host \
        --name autobahn \
        crossbario/autobahn-testsuite:25.10.1 \
        wstest --mode fuzzingclient --spec /config/fuzzingclient.json" 2>&1

    TOTAL_CASES=$(python3 -c "import json; c=$CASES; print('?, 仅按模式匹配')" 2>/dev/null || echo "?")

    log "    测试进行中..."

    END=$((SECONDS + TIMEOUT))
    while [ $SECONDS -lt $END ]; do
        sleep 5

        CID=$(sg docker -c "docker ps -q --filter name=autobahn" 2>/dev/null || true)
        if [ -z "$CID" ]; then
            log "    Docker 容器已停止"
        sg docker -c "docker logs autobahn" 2>/dev/null > "$REPORTS_DIR/wstest.log" || true
            break
        fi

        # 统计所有 JSON 报告（含子目录）
        COUNT=$(find "$REPORTS_DIR" -name '*.json' 2>/dev/null | wc -l)

        # 每轮打印状态
        log "    运行中... ${SECONDS}s | 报告文件: $COUNT"

        if ! kill -0 "$(lsof -ti:$ECHO_PORT 2>/dev/null)" 2>/dev/null; then
            log "    WARNING: echo server 已退出"
        fi

        DLOG=$(sg docker -c "docker logs autobahn 2>&1" | tail -3)
        [ -n "$DLOG" ] && log "    [docker] $DLOG"
    done

    # 超时处理
    CID=$(sg docker -c "docker ps -q --filter name=autobahn" 2>/dev/null || true)
    if [ -n "$CID" ]; then
        log "    超时 ${TIMEOUT}s, 停止容器"
        sg docker -c "docker logs autobahn" 2>/dev/null > "$REPORTS_DIR/wstest.log" || true
        sg docker -c "docker stop autobahn" 2>/dev/null || true
    fi

else
    # ===== fuzzingserver: 测试 C 客户端 =====
    cat > "$CONFIG_DIR/fuzzingserver.json" << CONF
{
    "url": "ws://0.0.0.0:$PORT",
    "outdir": "/reports",
    "cases": $CASES,
    "exclude-cases": []
}
CONF

    log "[2] 启动 Docker fuzzingserver..."
    sg docker -c "docker rm -f autobahn" 2>/dev/null || true
    sg docker -c "docker run -d \
        -v $CONFIG_DIR:/config \
        -v $REPORTS_DIR:/reports \
        --network host \
        --name autobahn \
        crossbario/autobahn-testsuite:25.10.1 \
        wstest --mode fuzzingserver --spec /config/fuzzingserver.json" 2>&1
    sleep 3

    log "[3] 启动 C client..."
    "$BUILD_DIR/autobahn_client" "127.0.0.1" "$PORT" &
    CLIENT_PID=$!
    log "    PID: $CLIENT_PID"

    LAST=0
    END=$((SECONDS + TIMEOUT))
    while [ $SECONDS -lt $END ]; do
        sleep 10

        if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
            log "    client 已退出"
            break
        fi
        DSTATUS=$(sg docker -c "docker ps -a --filter name=autobahn --format '{{.Status}}'" 2>/dev/null)
        if [ -z "$DSTATUS" ]; then
            log "    Docker 已停止"
            break
        fi
        COUNT=$(find "$REPORTS_DIR" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l)
        if [ "$COUNT" -ne "$LAST" ]; then
            log "    已生成 $COUNT 份报告"
            LAST=$COUNT
        fi
        DLOG=$(sg docker -c "docker logs autobahn 2>&1" | tail -3)
        [ -n "$DLOG" ] && log "    [wstest] $DLOG"
    done

    sg docker -c "docker logs autobahn" 2>/dev/null > "$REPORTS_DIR/wstest.log" || true
    kill "$CLIENT_PID" 2>/dev/null || true
    sg docker -c "docker stop autobahn" 2>/dev/null || true
fi

# ---- 4. 报告 ----
log ""
log "[4] 测试结果"
if [ -f "$REPORTS_DIR/index.html" ]; then
    log "  报告: $REPORTS_DIR/index.html"
elif [ -d "$REPORTS_DIR/servers" ]; then
    log "  报告: $REPORTS_DIR/servers/index.html"
    log "  JSON: $(find $REPORTS_DIR/servers -name '*.json' | wc -l) 个文件"
elif [ -d "$REPORTS_DIR/clients" ]; then
    log "  报告: $REPORTS_DIR/clients/index.html"
fi
log "  目录: $REPORTS_DIR"

# 找汇总结果
SUMMARY=$(find "$REPORTS_DIR" -name 'index.json' 2>/dev/null | head -1)
if [ -n "$SUMMARY" ]; then
    python3 -c "
import json
with open('$SUMMARY') as f:
    d = json.load(f)
if isinstance(d, dict):
    total = d.get('total', '?')
    pass_ = d.get('pass', d.get('passed', '?'))
    fail = d.get('fail', d.get('failed', '?'))
    print(f'  汇总: {pass_}/{total} passed ({fail} failed)')
" 2>/dev/null || true
fi

# ---- 5. 拷贝到 ~/shared ----
log ""
log "[5] 拷贝到 $SHARED_DIR ..."
mkdir -p "$SHARED_DIR"
DST="$SHARED_DIR/autobahn_$(date '+%Y%m%d_%H%M%S')"
cp -r "$REPORTS_DIR" "$DST"
ln -snf "$(basename "$DST")" "$SHARED_DIR/autobahn_latest"
log "    done: $DST"
log "    最新: $SHARED_DIR/autobahn_latest"

# ---- 清理 ----
kill "$(lsof -ti:$ECHO_PORT 2>/dev/null)" 2>/dev/null || true
log "=== 完成 ==="
