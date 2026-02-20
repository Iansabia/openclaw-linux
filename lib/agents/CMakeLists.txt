# clawd-linux :: libclawd-agents
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)

# ---- sources -------------------------------------------------------------

set(CLAWD_AGENTS_SOURCES
    src/provider.c
    src/tool.c
    src/sandbox.c
    src/agent.c
    src/providers/anthropic.c
    src/providers/openai.c
    src/providers/ollama.c
    src/providers/google.c
    src/providers/bedrock.c
    src/tools/bash_tool.c
    src/tools/file_read.c
    src/tools/file_write.c
    src/tools/web_fetch.c
    src/sandbox/namespace.c
    src/sandbox/seccomp.c
    src/sandbox/cgroup.c
    src/sandbox/mount.c
)

set(CLAWD_AGENTS_HEADERS
    include/clawd/provider.h
    include/clawd/tool.h
    include/clawd/sandbox.h
    include/clawd/agent.h
)

# ---- library target ------------------------------------------------------

if(CLAWD_STATIC)
    add_library(clawd-agents STATIC ${CLAWD_AGENTS_SOURCES})
else()
    add_library(clawd-agents SHARED ${CLAWD_AGENTS_SOURCES})
endif()

target_include_directories(clawd-agents
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# ---- dependencies --------------------------------------------------------

# Core library (str, buf, vec, map, json, log, err, crypto)
target_link_libraries(clawd-agents PUBLIC clawd-core)

# Net library (HTTP client) -- optional but strongly recommended
if(TARGET clawd-net)
    target_link_libraries(clawd-agents PUBLIC clawd-net)
else()
    message(WARNING "clawd-net not found; provider HTTP calls will not link")
endif()

# Process library (process execution for tools)
if(TARGET clawd-process)
    target_link_libraries(clawd-agents PUBLIC clawd-process)
else()
    message(WARNING "clawd-process not found; tool execution will not link")
endif()

# Security library (policy enforcement)
if(TARGET clawd-security)
    target_link_libraries(clawd-agents PUBLIC clawd-security)
else()
    message(WARNING "clawd-security not found; policy checks will not link")
endif()

# Threads
find_package(Threads REQUIRED)
target_link_libraries(clawd-agents PUBLIC Threads::Threads)

# Linux-specific: libseccomp and libcap
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(SECCOMP_FOUND)
        target_link_libraries(clawd-agents PRIVATE PkgConfig::SECCOMP)
        target_compile_definitions(clawd-agents PRIVATE HAVE_SECCOMP=1)
    else()
        message(STATUS "libseccomp not found; seccomp sandbox will be disabled")
    endif()

    if(LIBCAP_FOUND)
        target_link_libraries(clawd-agents PRIVATE PkgConfig::LIBCAP)
        target_compile_definitions(clawd-agents PRIVATE HAVE_LIBCAP=1)
    else()
        message(STATUS "libcap not found; capability management will be disabled")
    endif()
endif()

# ---- compiler options ----------------------------------------------------

target_compile_options(clawd-agents PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-agents PROPERTIES
    C_STANDARD          11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             0.1.0
    SOVERSION           0
    OUTPUT_NAME         clawd-agents
)

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)

install(TARGETS clawd-agents
    EXPORT  clawd-agents-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/clawd
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# ---- tests ---------------------------------------------------------------

if(CLAWD_BUILD_TESTS)
    add_executable(test_agents tests/test_agents.c)
    target_link_libraries(test_agents PRIVATE clawd-agents)
    target_compile_options(test_agents PRIVATE -Wall -Wextra)
    set_target_properties(test_agents PROPERTIES
        C_STANDARD          11
        C_STANDARD_REQUIRED ON
    )
    add_test(NAME test_agents COMMAND test_agents)
endif()
