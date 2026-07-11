cmake_minimum_required(VERSION 3.10)
project(libsevent VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# POSIX 扩展: clock_gettime
add_compile_definitions(
    _XOPEN_SOURCE=500
    _POSIX_C_SOURCE=199309L
)

option(SEVENT_RTOS "Build for RTOS (bare-metal / no POSIX threads)" OFF)
option(SEVENT_ENABLE_EVENTFD "Use eventfd for wakeup (Linux)" ON)
option(SEVENT_ENABLE_PIPE     "Use pipe for wakeup (POSIX)" ON)

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
    src/sevent_platform.c
)

add_library(sevent STATIC ${SEVENT_SOURCES})

target_include_directories(sevent PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(sevent PUBLIC Threads::Threads)

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

enable_testing()
add_test(NAME unit_tests COMMAND test_sevent)

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

# ---------- install ----------

install(TARGETS sevent DESTINATION lib)
install(FILES include/sevent.h DESTINATION include)
