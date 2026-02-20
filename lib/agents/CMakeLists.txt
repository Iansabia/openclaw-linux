# clawd-linux :: libclawd-agents
# SPDX-License-Identifier: MIT

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

# ---- library target ------------------------------------------------------

if(CLAWD_STATIC)
    add_library(clawd-agents STATIC ${CLAWD_AGENTS_SOURCES})
else()
    add_library(clawd-agents SHARED ${CLAWD_AGENTS_SOURCES})
endif()

add_library(clawd::agents ALIAS clawd-agents)

target_include_directories(clawd-agents
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(clawd-agents
    PUBLIC
        clawd-core
        Threads::Threads
)

# Net library (HTTP client)
if(TARGET clawd-net)
    target_link_libraries(clawd-agents PUBLIC clawd-net)
endif()

# Process library (process execution for tools)
if(TARGET clawd-process)
    target_link_libraries(clawd-agents PUBLIC clawd-process)
endif()

# Security library (policy enforcement)
if(TARGET clawd-security)
    target_link_libraries(clawd-agents PUBLIC clawd-security)
endif()

# Linux-specific: libseccomp and libcap
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(SECCOMP_FOUND)
        target_link_libraries(clawd-agents PRIVATE PkgConfig::SECCOMP)
        target_compile_definitions(clawd-agents PRIVATE HAVE_SECCOMP=1)
    endif()

    if(LIBCAP_FOUND)
        target_link_libraries(clawd-agents PRIVATE PkgConfig::LIBCAP)
        target_compile_definitions(clawd-agents PRIVATE HAVE_LIBCAP=1)
    endif()
endif()

# ---- compiler options ----------------------------------------------------

target_compile_options(clawd-agents PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-agents PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             ${PROJECT_VERSION}
    SOVERSION           ${PROJECT_VERSION_MAJOR}
)

# ---- install -------------------------------------------------------------

install(TARGETS clawd-agents
    EXPORT  clawd-targets
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
    add_test(NAME test_agents COMMAND test_agents)
endif()
