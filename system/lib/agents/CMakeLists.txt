# kelp-linux :: libkelp-agents
# SPDX-License-Identifier: MIT

# ---- sources -------------------------------------------------------------

set(KELP_AGENTS_SOURCES
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

if(KELP_STATIC)
    add_library(kelp-agents STATIC ${KELP_AGENTS_SOURCES})
else()
    add_library(kelp-agents SHARED ${KELP_AGENTS_SOURCES})
endif()

add_library(kelp::agents ALIAS kelp-agents)

target_include_directories(kelp-agents
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(kelp-agents
    PUBLIC
        kelp-core
        Threads::Threads
)

# Net library (HTTP client)
if(TARGET kelp-net)
    target_link_libraries(kelp-agents PUBLIC kelp-net)
endif()

# Process library (process execution for tools)
if(TARGET kelp-process)
    target_link_libraries(kelp-agents PUBLIC kelp-process)
endif()

# Security library (policy enforcement)
if(TARGET kelp-security)
    target_link_libraries(kelp-agents PUBLIC kelp-security)
endif()

# Linux-specific: libseccomp and libcap
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(SECCOMP_FOUND)
        target_link_libraries(kelp-agents PRIVATE PkgConfig::SECCOMP)
        target_compile_definitions(kelp-agents PRIVATE HAVE_SECCOMP=1)
    endif()

    if(LIBCAP_FOUND)
        target_link_libraries(kelp-agents PRIVATE PkgConfig::LIBCAP)
        target_compile_definitions(kelp-agents PRIVATE HAVE_LIBCAP=1)
    endif()
endif()

# ---- compiler options ----------------------------------------------------

target_compile_options(kelp-agents PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(kelp-agents PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             ${PROJECT_VERSION}
    SOVERSION           ${PROJECT_VERSION_MAJOR}
)

# ---- install -------------------------------------------------------------

install(TARGETS kelp-agents
    EXPORT  kelp-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/kelp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# ---- tests ---------------------------------------------------------------

if(KELP_BUILD_TESTS)
    add_executable(test_agents tests/test_agents.c)
    target_link_libraries(test_agents PRIVATE kelp-agents)
    add_test(NAME test_agents COMMAND test_agents)
endif()
