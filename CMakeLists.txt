cmake_minimum_required(VERSION 3.10)
project(libsevent C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# POSIX 扩展: clock_gettime + PTHREAD_MUTEX_RECURSIVE
add_compile_definitions(
    _XOPEN_SOURCE=500
    _POSIX_C_SOURCE=199309L
)

# ---------- library ----------

add_library(sevent STATIC
    src/sevent.c
)

target_include_directories(sevent PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(sevent PUBLIC Threads::Threads)

# ---------- tests ----------

add_executable(test_sevent
    tests/test_sevent.c
    src/sevent.c
)

target_include_directories(test_sevent PRIVATE include)
target_link_libraries(test_sevent PRIVATE Threads::Threads)

add_custom_target(check
    COMMAND test_sevent
    DEPENDS test_sevent
)

# ---------- examples ----------

add_executable(example-echo-server
    examples/echo_server.c
    src/sevent.c
)
target_include_directories(example-echo-server PRIVATE include)

add_executable(example-timer-demo
    examples/timer_demo.c
    src/sevent.c
)
target_include_directories(example-timer-demo PRIVATE include)

find_package(Threads REQUIRED)

add_executable(example-echo-client
    examples/echo_client.c
    src/sevent.c
)
target_include_directories(example-echo-client PRIVATE include)

add_executable(example-stdin-echo
    examples/stdin_echo.c
    src/sevent.c
)
target_include_directories(example-stdin-echo PRIVATE include)

# ---------- install ----------

install(TARGETS sevent DESTINATION lib)
install(FILES include/sevent.h DESTINATION include)
