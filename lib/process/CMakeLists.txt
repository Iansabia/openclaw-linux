# ---------------------------------------------------------------------------
# clawd-linux :: libclawd-process
#
# Process management: fork/exec, PTY, signal bridge, supervisor.
# ---------------------------------------------------------------------------

include(CheckFunctionExists)
include(CheckIncludeFile)

# ---------------------------------------------------------------------------
# Platform feature detection
# ---------------------------------------------------------------------------
check_function_exists(timerfd_create  HAVE_TIMERFD_CREATE)
check_function_exists(signalfd        HAVE_SIGNALFD)
check_function_exists(forkpty         HAVE_FORKPTY)
check_include_file(pty.h              HAVE_PTY_H)
check_include_file(util.h             HAVE_UTIL_H)

# forkpty may live in libutil on Linux
if(NOT HAVE_FORKPTY)
    set(CMAKE_REQUIRED_LIBRARIES util)
    check_function_exists(forkpty HAVE_FORKPTY_IN_UTIL)
    unset(CMAKE_REQUIRED_LIBRARIES)
endif()

# ---------------------------------------------------------------------------
# Library target
# ---------------------------------------------------------------------------
set(PROCESS_SOURCES
    src/process.c
    src/pty.c
    src/signals.c
    src/supervisor.c
)

if(CLAWD_STATIC)
    add_library(clawd-process STATIC ${PROCESS_SOURCES})
else()
    add_library(clawd-process SHARED ${PROCESS_SOURCES})
endif()

add_library(clawd::process ALIAS clawd-process)

target_include_directories(clawd-process
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# ---------------------------------------------------------------------------
# Link dependencies
# ---------------------------------------------------------------------------
target_link_libraries(clawd-process
    PUBLIC
        clawd-core
    PRIVATE
        Threads::Threads
)

# Link libutil for forkpty on Linux
if(HAVE_FORKPTY_IN_UTIL)
    target_link_libraries(clawd-process PRIVATE util)
endif()

# ---------------------------------------------------------------------------
# Compile definitions
# ---------------------------------------------------------------------------
if(HAVE_TIMERFD_CREATE)
    target_compile_definitions(clawd-process PRIVATE HAVE_TIMERFD_CREATE)
endif()
if(HAVE_SIGNALFD)
    target_compile_definitions(clawd-process PRIVATE HAVE_SIGNALFD)
endif()
if(HAVE_FORKPTY OR HAVE_FORKPTY_IN_UTIL)
    target_compile_definitions(clawd-process PRIVATE HAVE_FORKPTY)
endif()
if(HAVE_PTY_H)
    target_compile_definitions(clawd-process PRIVATE HAVE_PTY_H)
endif()
if(HAVE_UTIL_H)
    target_compile_definitions(clawd-process PRIVATE HAVE_UTIL_H)
endif()

# ---------------------------------------------------------------------------
# Compiler settings
# ---------------------------------------------------------------------------
target_compile_options(clawd-process PRIVATE
    -Wall -Wextra -Wpedantic -Werror=implicit-function-declaration
)

set_target_properties(clawd-process PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION 0
    C_STANDARD 17
    C_STANDARD_REQUIRED ON
)

# ---------------------------------------------------------------------------
# Install rules
# ---------------------------------------------------------------------------
install(TARGETS clawd-process
    EXPORT  clawd-targets
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/clawd/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/clawd
    FILES_MATCHING PATTERN "*.h"
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(CLAWD_BUILD_TESTS)
    add_executable(test_process tests/test_process.c)
    target_link_libraries(test_process PRIVATE clawd-process clawd-core)
    add_test(NAME test_process COMMAND test_process)
endif()
