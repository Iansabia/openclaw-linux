# kelp-linux :: kelp-gateway binary
# SPDX-License-Identifier: MIT



# ---- sources -------------------------------------------------------------

set(KELP_GATEWAY_SOURCES
    main.c
)

# ---- executable -----------------------------------------------------------

add_executable(kelp-gateway ${KELP_GATEWAY_SOURCES})

target_compile_options(kelp-gateway PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(kelp-gateway PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    OUTPUT_NAME         kelp-gateway
)

# ---- dependencies --------------------------------------------------------

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

target_link_libraries(kelp-gateway PRIVATE
    kelp-core
    kelp-config
    kelp-net
    kelp-security
    kelp-process
    Threads::Threads
)

# libmicrohttpd (via pkg-config)
pkg_check_modules(MICROHTTPD REQUIRED IMPORTED_TARGET libmicrohttpd)
target_link_libraries(kelp-gateway PRIVATE PkgConfig::MICROHTTPD)

# agents library (if available as a target)
if(TARGET kelp-agents)
    target_link_libraries(kelp-gateway PRIVATE kelp-agents)
    target_compile_definitions(kelp-gateway PRIVATE HAVE_AGENTS=1)
endif()

# Kernel userspace library (Linux only)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(TARGET kelp-kernel)
        target_link_libraries(kelp-gateway PRIVATE kelp-kernel)
        target_compile_definitions(kelp-gateway PRIVATE HAVE_KERNEL=1)
    endif()
endif()

# systemd (Linux only, for sd_notify / sd-bus)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    pkg_check_modules(SYSTEMD QUIET IMPORTED_TARGET libsystemd)
    if(SYSTEMD_FOUND)
        target_link_libraries(kelp-gateway PRIVATE PkgConfig::SYSTEMD)
        target_compile_definitions(kelp-gateway PRIVATE HAVE_SYSTEMD=1)
    endif()
endif()

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS kelp-gateway RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
