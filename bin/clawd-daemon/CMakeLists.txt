# clawd-linux :: clawd-daemon binary
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)

# ---- sources -------------------------------------------------------------

set(CLAWD_DAEMON_SOURCES
    main.c
)

# ---- executable -----------------------------------------------------------

add_executable(clawd-daemon ${CLAWD_DAEMON_SOURCES})

target_compile_options(clawd-daemon PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-daemon PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    OUTPUT_NAME         clawd-daemon
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(clawd-daemon PRIVATE
    clawd-core
    clawd-config
)

# systemd / dbus (Linux only)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)

    # libsystemd for sd-bus
    pkg_check_modules(SYSTEMD QUIET IMPORTED_TARGET libsystemd)
    if(SYSTEMD_FOUND)
        target_link_libraries(clawd-daemon PRIVATE PkgConfig::SYSTEMD)
        target_compile_definitions(clawd-daemon PRIVATE HAVE_SYSTEMD=1)
    endif()

    # libdbus for D-Bus communication with systemd Manager
    pkg_check_modules(DBUS QUIET IMPORTED_TARGET dbus-1)
    if(DBUS_FOUND)
        target_link_libraries(clawd-daemon PRIVATE PkgConfig::DBUS)
        target_compile_definitions(clawd-daemon PRIVATE HAVE_DBUS=1)
    else()
        message(STATUS "  dbus-1 not found -- clawd-daemon will use systemctl fallback")
    endif()
endif()

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS clawd-daemon RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
