# clawd-linux :: clawd-gateway binary
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)

# ---- sources -------------------------------------------------------------

set(CLAWD_GATEWAY_SOURCES
    main.c
)

# ---- executable -----------------------------------------------------------

add_executable(clawd-gateway ${CLAWD_GATEWAY_SOURCES})

target_compile_options(clawd-gateway PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-gateway PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    OUTPUT_NAME         clawd-gateway
)

# ---- dependencies --------------------------------------------------------

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

target_link_libraries(clawd-gateway PRIVATE
    clawd-core
    clawd-config
    clawd-net
    clawd-security
    clawd-process
    Threads::Threads
)

# libmicrohttpd (via pkg-config)
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
target_link_libraries(clawd-gateway PRIVATE PkgConfig::MICROHTTPD)

# agents library (if available as a target)
if(TARGET clawd-agents)
    target_link_libraries(clawd-gateway PRIVATE clawd-agents)
endif()

# systemd (Linux only, for sd_notify / sd-bus)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    pkg_check_modules(SYSTEMD QUIET IMPORTED_TARGET libsystemd)
    if(SYSTEMD_FOUND)
        target_link_libraries(clawd-gateway PRIVATE PkgConfig::SYSTEMD)
        target_compile_definitions(clawd-gateway PRIVATE HAVE_SYSTEMD=1)
    endif()
endif()

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS clawd-gateway RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
