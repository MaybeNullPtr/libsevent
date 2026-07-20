cmake_minimum_required(VERSION 3.10)
project(libsevent VERSION 1.0.0 LANGUAGES C)

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
option(SEVENT_WS_THREAD_SAFE
    "WebSocket client with thread-safe API (adds per-connection mutex locking)" OFF)

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

set(WEBSOCKET_SOURCES
    src/websockets/ws_sha1.c
    src/websockets/ws_base64.c
    src/websockets/ws_frame.c
    src/websockets/ws_handshake.c
    src/websockets/ws_conn.c
)

add_library(sevent_ws STATIC ${WEBSOCKET_SOURCES})
target_include_directories(sevent_ws PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(sevent_ws PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
)
target_link_libraries(sevent_ws PUBLIC sevent)

if(SEVENT_WS_THREAD_SAFE)
    target_compile_definitions(sevent_ws PRIVATE SEVENT_WS_THREAD_SAFE)
endif()

# ---------- tests ----------

add_executable(test_sevent
    tests/test_sevent.c
    ${SEVENT_SOURCES}
)

target_include_directories(test_sevent PRIVATE include)
target_link_libraries(test_sevent PRIVATE Threads::Threads)

add_custom_target(check
    COMMAND test_sevent
    DEPENDS test_sevent
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
add_test(NAME frag_terminator_tests COMMAND test-frag-terminator)

# ---------- examples ----------

add_executable(example-echo-server
    examples/echo_server.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-echo-server PRIVATE include)

add_executable(example-timer-demo
    examples/timer_demo.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-timer-demo PRIVATE include)

# ---------- WebSocket tests ----------

add_executable(test-ws
    tests/test_ws.c
    ${WEBSOCKET_SOURCES}
    ${SEVENT_SOURCES}
)
target_include_directories(test-ws PRIVATE include)
target_include_directories(test-ws PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test-ws PRIVATE Threads::Threads)

add_executable(test-ws-conn
    tests/test_ws_conn.c
    ${WEBSOCKET_SOURCES}
    ${SEVENT_SOURCES}
)
target_include_directories(test-ws-conn PRIVATE include)
target_include_directories(test-ws-conn PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test-ws-conn PRIVATE Threads::Threads)
if(SEVENT_WS_THREAD_SAFE)
    target_compile_definitions(test-ws-conn PRIVATE SEVENT_WS_THREAD_SAFE)
endif()

add_executable(test-frag-terminator
    tests/frag_terminator_test.c
    ${WEBSOCKET_SOURCES}
    ${SEVENT_SOURCES}
)
target_include_directories(test-frag-terminator PRIVATE include)
target_include_directories(test-frag-terminator PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test-frag-terminator PRIVATE Threads::Threads)

find_package(Threads REQUIRED)

add_executable(example-echo-client
    examples/echo_client.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-echo-client PRIVATE include)

add_executable(example-stdin-echo
    examples/stdin_echo.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-stdin-echo PRIVATE include)

add_executable(example-http-server
    examples/http_server.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-http-server PRIVATE include)

add_executable(example-chat-server
    examples/chat_server.c
    ${SEVENT_SOURCES}
)
target_include_directories(example-chat-server PRIVATE include)

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
if(SEVENT_WS_THREAD_SAFE)
    target_compile_definitions(example-ws-client PRIVATE SEVENT_WS_THREAD_SAFE)
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
    ${SEVENT_SOURCES}
)
target_include_directories(example-echo-server-oop PRIVATE include)
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
