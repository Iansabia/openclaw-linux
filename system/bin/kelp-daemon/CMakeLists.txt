# kelp-linux :: kelp-daemon binary
# SPDX-License-Identifier: MIT



# ---- sources -------------------------------------------------------------

set(KELP_DAEMON_SOURCES
    main.c
)

# ---- executable -----------------------------------------------------------

add_executable(kelp-daemon ${KELP_DAEMON_SOURCES})

target_compile_options(kelp-daemon PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(kelp-daemon PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    OUTPUT_NAME         kelp-daemon
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(kelp-daemon PRIVATE
    kelp-core
    kelp-config
)

# systemd / dbus (Linux only)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)

    # libsystemd for sd-bus
    pkg_check_modules(SYSTEMD QUIET IMPORTED_TARGET libsystemd)
    if(SYSTEMD_FOUND)
        target_link_libraries(kelp-daemon PRIVATE PkgConfig::SYSTEMD)
        target_compile_definitions(kelp-daemon PRIVATE HAVE_SYSTEMD=1)
    endif()

    # libdbus for D-Bus communication with systemd Manager
    pkg_check_modules(DBUS QUIET IMPORTED_TARGET dbus-1)
    if(DBUS_FOUND)
        target_link_libraries(kelp-daemon PRIVATE PkgConfig::DBUS)
        target_compile_definitions(kelp-daemon PRIVATE HAVE_DBUS=1)
    else()
        message(STATUS "  dbus-1 not found -- kelp-daemon will use systemctl fallback")
    endif()
endif()

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS kelp-daemon RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
