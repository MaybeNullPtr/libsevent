cmake_minimum_required(VERSION 3.10)
project(libsevent VERSION 1.4.2 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# POSIX 扩展: 启用 clock_gettime / getaddrinfo / pthreads
# _XOPEN_SOURCE=700 = SUSv4 (POSIX.1-2008 + XSI)
add_compile_definitions(
    _XOPEN_SOURCE=700
)

option(SEVENT_RTOS "Build for RTOS (bare-metal / no POSIX threads)" OFF)
option(SEVENT_ENABLE_EVENTFD "Use eventfd for wakeup (Linux)" ON)
option(SEVENT_ENABLE_PIPE     "Use pipe for wakeup (POSIX)" ON)
option(SEVENT_THREAD_SAFE
    "WebSocket client with thread-safe API (adds per-connection mutex locking)" OFF)
option(SEVENT_WS_DEFLATE "WebSocket permessage-deflate compression (requires zlib)" OFF)
option(SEVENT_WS_TLS "WebSocket TLS transport (backend: mbedtls / openssl)" OFF)
set(SEVENT_WS_TLS_BACKEND "MBEDTLS" CACHE STRING "TLS backend: MBEDTLS | OPENSSL (default MBEDTLS)")
set_property(CACHE SEVENT_WS_TLS_BACKEND PROPERTY STRINGS MBEDTLS OPENSSL)

option(SEVENT_ASAN "Build with AddressSanitizer (memory/leak detection)" OFF)
option(SEVENT_TSAN "Build with ThreadSanitizer (data race detection)" OFF)

if(SEVENT_ASAN AND SEVENT_TSAN)
    message(FATAL_ERROR "ASan and TSan are incompatible, enable only one at a time")
endif()
if(SEVENT_ASAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()
if(SEVENT_TSAN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=thread")
endif()

# eventfd 可用性检查 (符号存在 + 可链接)
include(CheckSymbolExists)
if(SEVENT_ENABLE_EVENTFD)
    check_symbol_exists(eventfd sys/eventfd.h SEVENT_HAVE_EVENTFD)
    if(NOT SEVENT_HAVE_EVENTFD)
        set(SEVENT_ENABLE_EVENTFD OFF)
    endif()
endif()
if(SEVENT_ENABLE_EVENTFD)
    add_compile_definitions(SEVENT_ENABLE_EVENTFD)
endif()

# pipe 可用性检查 (RTOS 下通常无 pipe, 连带关闭)
if(SEVENT_ENABLE_PIPE AND NOT SEVENT_RTOS)
    check_symbol_exists(pipe unistd.h SEVENT_HAVE_PIPE)
    if(NOT SEVENT_HAVE_PIPE)
        set(SEVENT_ENABLE_PIPE OFF)
    endif()
endif()
if(SEVENT_ENABLE_PIPE)
    add_compile_definitions(SEVENT_ENABLE_PIPE)
endif()

add_compile_options(-Wall -Werror)
if(SEVENT_RTOS)
    add_compile_definitions(SEVENT_RTOS)
endif()

# ---------- library ----------

set(SEVENT_SOURCES
    src/sevent.c
    src/sevent_dns.c
    src/sevent_platform.c
)

# 示例公用代码 (日志 + Ctrl+C)
set(EXAMPLE_COMMON
    examples/common.c
)

add_library(sevent STATIC ${SEVENT_SOURCES})

target_include_directories(sevent PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(sevent PUBLIC Threads::Threads)

# ---------- WebSocket 库 ----------

# 传输层 (通用, 不依赖 ws 协议; 公开 API 见 include/sevent_stream_conn.h)
set(TRANSPORT_SOURCES
    src/stream_conn.c
    src/tcp_conn.c
    src/tcp_acceptor.c
)

set(WEBSOCKET_SOURCES
    src/websockets/ws_sha1.c
    src/websockets/ws_base64.c
    src/websockets/ws_frame.c
    src/websockets/ws_handshake.c
    src/websockets/ws_conn.c
    src/websockets/ws_deflate.c
)

add_library(sevent_ws STATIC ${WEBSOCKET_SOURCES} ${TRANSPORT_SOURCES})
target_include_directories(sevent_ws PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(sevent_ws PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
)
target_link_libraries(sevent_ws PUBLIC sevent)

if(SEVENT_THREAD_SAFE)
    target_compile_definitions(sevent_ws PRIVATE SEVENT_THREAD_SAFE)
endif()

# permessage-deflate 压缩 (RFC 7692), 需要 zlib
if(SEVENT_WS_DEFLATE)
    find_package(ZLIB REQUIRED)
    target_compile_definitions(sevent_ws PRIVATE SEVENT_WS_DEFLATE)
    target_include_directories(sevent_ws PRIVATE ${ZLIB_INCLUDE_DIRS})
    target_link_libraries(sevent_ws PRIVATE ${ZLIB_LIBRARIES})
endif()

# TLS 传输: ssl 抽象层 (src/ssl/ssl.c + 选中后端) + tls_conn (组合 tcp_conn).
# 只编译选中后端 (D1).
# ssl 层独立单测 (直链 ssl.c + 选中后端, 不经 sevent_ws — 与库互不依赖)
if(SEVENT_WS_TLS)
    add_executable(test-ssl tests/test_ssl.c src/ssl/ssl.c)
    target_include_directories(test-ssl PRIVATE
        include ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/ssl)
    target_compile_definitions(test-ssl PRIVATE
        TEST_CERTS_DIR="${CMAKE_SOURCE_DIR}/tests/certs")
    target_link_libraries(test-ssl PRIVATE sevent) # sevent_ignore_sigpipe (库契约)
    add_custom_command(TARGET test-ssl POST_BUILD
        COMMAND bash ${CMAKE_SOURCE_DIR}/tests/gen_certs.sh)
    add_test(NAME ssl_tests COMMAND test-ssl)
endif()

if(SEVENT_WS_TLS)
    target_sources(sevent_ws PRIVATE src/ssl/ssl.c src/tls_conn.c)
    if(SEVENT_WS_TLS_BACKEND STREQUAL "MBEDTLS")
        # mbedtls 2.x (目标 2.25): 无系统信任库概念 (verify_peer=true 须提供 CA).
        # 自编译安装: -DCMAKE_PREFIX_PATH=$HOME/documents/thirdparty/install
        find_path(MBEDTLS_INCLUDE_DIR mbedtls/ssl.h)
        find_library(MBEDTLS_LIBRARY mbedtls)
        find_library(MBEDX509_LIBRARY mbedx509)
        find_library(MBEDCRYPTO_LIBRARY mbedcrypto)
        if(NOT MBEDTLS_INCLUDE_DIR OR NOT MBEDTLS_LIBRARY OR NOT MBEDX509_LIBRARY
           OR NOT MBEDCRYPTO_LIBRARY)
            message(FATAL_ERROR
                "mbedtls 未找到 (默认后端=MBEDTLS). 解决: "
                "1) 用 -DCMAKE_PREFIX_PATH=<mbedtls 安装前缀> 指向安装位置; "
                "2) 或切换系统自带后端: -DSEVENT_WS_TLS_BACKEND=OPENSSL")
        endif()
        target_compile_definitions(sevent_ws PRIVATE SEVENT_WS_TLS SEVENT_WS_TLS_MBEDTLS)
        target_include_directories(sevent_ws PRIVATE ${MBEDTLS_INCLUDE_DIR})
        target_link_libraries(sevent_ws PRIVATE
            ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})
        target_sources(sevent_ws PRIVATE src/ssl/ssl_mbedtls.c)
        # test-ssl: 后端宏 + 链接
        target_compile_definitions(test-ssl PRIVATE SEVENT_WS_TLS_MBEDTLS)
        target_sources(test-ssl PRIVATE src/ssl/ssl_mbedtls.c)
        target_include_directories(test-ssl PRIVATE ${MBEDTLS_INCLUDE_DIR})
        target_link_libraries(test-ssl PRIVATE
            ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})
    elseif(SEVENT_WS_TLS_BACKEND STREQUAL "OPENSSL")
        find_package(OpenSSL REQUIRED)
        target_compile_definitions(sevent_ws PRIVATE SEVENT_WS_TLS)
        target_include_directories(sevent_ws PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(sevent_ws PRIVATE OpenSSL::SSL OpenSSL::Crypto)
        target_sources(sevent_ws PRIVATE src/ssl/ssl_openssl.c)
        # test-ssl: 后端源 + 链接
        target_sources(test-ssl PRIVATE src/ssl/ssl_openssl.c)
        target_include_directories(test-ssl PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(test-ssl PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    else()
        message(FATAL_ERROR
            "SEVENT_WS_TLS_BACKEND 必须是 MBEDTLS 或 OPENSSL, 当前: ${SEVENT_WS_TLS_BACKEND}")
    endif()
endif()

# ---------- tests ----------

add_executable(test_sevent
    tests/test_sevent.c
)
target_include_directories(test_sevent PRIVATE include)
target_link_libraries(test_sevent PRIVATE sevent)

add_custom_target(check
    COMMAND ctest --output-on-failure
    DEPENDS test_sevent test-ws test-ws-conn test-frag-stream test-redirect test-deflate
)

# ---------- 代码格式化 (需要 clang-format) ----------

find_program(CLANG_FORMAT clang-format-15 clang-format)
if(NOT CLANG_FORMAT)
    message(WARNING "clang-format not found, format targets disabled")
else()
file(GLOB_RECURSE SEVENT_FORMAT_FILES
    ${CMAKE_SOURCE_DIR}/src/*.c ${CMAKE_SOURCE_DIR}/src/*.h
    ${CMAKE_SOURCE_DIR}/include/*.h
    ${CMAKE_SOURCE_DIR}/tests/*.c ${CMAKE_SOURCE_DIR}/tests/*.cpp ${CMAKE_SOURCE_DIR}/tests/*.h
    ${CMAKE_SOURCE_DIR}/examples/*.c ${CMAKE_SOURCE_DIR}/examples/*.cpp
    ${CMAKE_SOURCE_DIR}/examples/*.hpp ${CMAKE_SOURCE_DIR}/examples/*.h
)

add_custom_target(format
    COMMAND ${CLANG_FORMAT} -i -style=file ${SEVENT_FORMAT_FILES}
    COMMENT "Formatting source files with clang-format ..."
)

add_custom_target(check-format
    COMMAND ${CLANG_FORMAT} --dry-run -Werror -style=file ${SEVENT_FORMAT_FILES}
    COMMENT "Checking code format compliance ..."
)
endif()

enable_testing()
add_test(NAME unit_tests COMMAND test_sevent)
add_test(NAME ws_unit_tests COMMAND test-ws)
add_test(NAME ws_conn_tests COMMAND test-ws-conn)
add_test(NAME frag_stream_tests COMMAND test-frag-stream)
add_test(NAME redirect_tests COMMAND test-redirect)
add_test(NAME deflate_tests COMMAND test-deflate)
add_test(NAME stream_conn_tests COMMAND test-stream-conn)

# ---------- examples ----------

add_executable(example-echo-server
    examples/echo_server.c
)
target_include_directories(example-echo-server PRIVATE include)
target_link_libraries(example-echo-server PRIVATE sevent_ws)

add_executable(example-timer-demo
    examples/timer_demo.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-timer-demo PRIVATE include)

# ---------- WebSocket tests ----------

add_executable(test-ws
    tests/test_ws.c
)
target_include_directories(test-ws PRIVATE include)
target_include_directories(test-ws PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test-ws PRIVATE sevent_ws)

add_executable(test-ws-conn
    tests/test_ws_conn.c
)
target_include_directories(test-ws-conn PRIVATE include)
target_include_directories(test-ws-conn PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test-ws-conn PRIVATE sevent_ws)
if(SEVENT_THREAD_SAFE)
    target_compile_definitions(test-ws-conn PRIVATE SEVENT_THREAD_SAFE)
endif()

add_executable(test-frag-stream
    tests/frag_stream_test.c
)
target_include_directories(test-frag-stream PRIVATE include)
target_include_directories(test-frag-stream PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test-frag-stream PRIVATE sevent_ws)

add_executable(test-redirect
    tests/redirect_test.c
)
target_include_directories(test-redirect PRIVATE include)
target_include_directories(test-redirect PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test-redirect PRIVATE sevent_ws)

add_executable(test-stream-conn
    tests/test_stream_conn.c
)
target_include_directories(test-stream-conn PRIVATE include)
target_include_directories(test-stream-conn PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test-stream-conn PRIVATE sevent_ws)
if(SEVENT_THREAD_SAFE)
    target_compile_definitions(test-stream-conn PRIVATE SEVENT_THREAD_SAFE)
endif()

# tcp_conn 公开 API 独立单测 (不经 stream 抽象)
add_executable(test-tcp-conn
    tests/test_tcp_conn.c
)
target_include_directories(test-tcp-conn PRIVATE include)
target_link_libraries(test-tcp-conn PRIVATE sevent_ws)
if(SEVENT_THREAD_SAFE)
    target_compile_definitions(test-tcp-conn PRIVATE SEVENT_THREAD_SAFE)
endif()
add_test(NAME tcp_conn_tests COMMAND test-tcp-conn)

# tls_conn 公开 API 独立单测 (不经 stream 抽象; 证书经 TEST_CERTS_DIR 注入)
if(SEVENT_WS_TLS)
    add_executable(test-tls-conn
        tests/test_tls_conn.c
    )
    target_include_directories(test-tls-conn PRIVATE include)
    target_compile_definitions(test-tls-conn PRIVATE
        SEVENT_WS_TLS TEST_CERTS_DIR="${CMAKE_SOURCE_DIR}/tests/certs")
    target_link_libraries(test-tls-conn PRIVATE sevent_ws)
    add_custom_command(TARGET test-tls-conn POST_BUILD
        COMMAND bash ${CMAKE_SOURCE_DIR}/tests/gen_certs.sh)
    if(SEVENT_WS_TLS_BACKEND STREQUAL "MBEDTLS")
        # 后端符号在 sevent_ws 静态库内, 静态链接不传递 — 测试自身链后端
        target_include_directories(test-tls-conn PRIVATE ${MBEDTLS_INCLUDE_DIR})
        target_link_libraries(test-tls-conn PRIVATE
            ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})
    elseif(SEVENT_WS_TLS_BACKEND STREQUAL "OPENSSL")
        target_include_directories(test-tls-conn PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(test-tls-conn PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    add_test(NAME tls_conn_tests COMMAND test-tls-conn)
endif()

add_executable(test-deflate
    tests/test_deflate.c
    src/websockets/ws_deflate.c
)
target_include_directories(test-deflate PRIVATE include)
target_include_directories(test-deflate PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test-deflate PRIVATE sevent)

find_package(Threads REQUIRED)

if(SEVENT_WS_DEFLATE)
    foreach(t test-ws test-ws-conn test-frag-stream test-redirect test-deflate)
        target_compile_definitions(${t} PRIVATE SEVENT_WS_DEFLATE)
        target_include_directories(${t} PRIVATE ${ZLIB_INCLUDE_DIRS})
        target_link_libraries(${t} PRIVATE ${ZLIB_LIBRARIES})
    endforeach()
endif()

add_executable(example-echo-client
    examples/echo_client.c
)
target_include_directories(example-echo-client PRIVATE include)
target_link_libraries(example-echo-client PRIVATE sevent_ws)

add_executable(example-stdin-echo
    examples/stdin_echo.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-stdin-echo PRIVATE include)

add_executable(example-http-server
    examples/http_server.c
)
target_include_directories(example-http-server PRIVATE include)
target_link_libraries(example-http-server PRIVATE sevent_ws)

add_executable(example-chat-server
    examples/chat_server.c
)
target_include_directories(example-chat-server PRIVATE include)
target_link_libraries(example-chat-server PRIVATE sevent_ws)

add_executable(example-signal-demo
    examples/signal_demo.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-signal-demo PRIVATE include)

add_executable(example-thread-worker
    examples/thread_worker.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-thread-worker PRIVATE include)
target_link_libraries(example-thread-worker PRIVATE Threads::Threads)

# ---------- WebSocket example ----------

add_executable(example-ws-client
    examples/ws_client.c
    ${WEBSOCKET_SOURCES}
    ${SEVENT_SOURCES}
)
target_include_directories(example-ws-client PRIVATE include)
target_include_directories(example-ws-client PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(example-ws-client PRIVATE Threads::Threads)
if(SEVENT_THREAD_SAFE)
    target_compile_definitions(example-ws-client PRIVATE SEVENT_THREAD_SAFE)
endif()
if(SEVENT_WS_DEFLATE)
    target_compile_definitions(example-ws-client PRIVATE SEVENT_WS_DEFLATE)
    target_include_directories(example-ws-client PRIVATE ${ZLIB_INCLUDE_DIRS})
    target_link_libraries(example-ws-client PRIVATE ${ZLIB_LIBRARIES})
endif()

# ---------- DNS example ----------

add_executable(example-dns-demo
    examples/dns_demo.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-dns-demo PRIVATE include)
target_link_libraries(example-dns-demo PRIVATE Threads::Threads)

# ---------- C++ examples ----------

enable_language(CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(example-echo-server-oop
    examples/echo_server_oop.cpp
)
target_include_directories(example-echo-server-oop PRIVATE include)
target_link_libraries(example-echo-server-oop PRIVATE sevent_ws Threads::Threads)
target_link_libraries(example-echo-server-oop PRIVATE Threads::Threads)

add_executable(example-timer-oop
    examples/timer_oop.cpp
    ${SEVENT_SOURCES}
)
target_include_directories(example-timer-oop PRIVATE include)
target_link_libraries(example-timer-oop PRIVATE Threads::Threads)

add_executable(example-post-lambda
    examples/post_lambda.cpp
    ${SEVENT_SOURCES}
)
target_include_directories(example-post-lambda PRIVATE include)
target_link_libraries(example-post-lambda PRIVATE Threads::Threads)

# ---- 示例公用代码 (日志 + Ctrl+C) 注入所有 example ----

set(EXAMPLE_TARGETS
    example-stdin-echo
    example-timer-demo
    example-echo-server
    example-echo-client
    example-http-server
    example-chat-server
    example-signal-demo
    example-thread-worker
    example-echo-server-oop
    example-timer-oop
    example-post-lambda
    example-ws-client
    example-dns-demo
)
foreach(t ${EXAMPLE_TARGETS})
    target_sources(${t} PRIVATE ${EXAMPLE_COMMON})
endforeach()

# ---------- install ----------

install(TARGETS sevent DESTINATION lib)
install(TARGETS sevent_ws DESTINATION lib)
install(FILES include/sevent.h DESTINATION include)
install(FILES include/sevent_ws.h DESTINATION include)
install(FILES include/sevent_stream_conn.h DESTINATION include)
install(FILES include/sevent_tcp_conn.h DESTINATION include)
install(FILES include/sevent_tcp_acceptor.h DESTINATION include)
install(FILES include/sevent_tls_conn.h DESTINATION include)
