# system/CMakeLists.txt — Kelp OS userspace build
#
# All C libraries, binaries, and channel plugins.

# -----------------------------------------------------------------------------
# Required packages (inherited from root, but ensure they're found)
# -----------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_package(CURL   REQUIRED)
find_package(Threads REQUIRED)

find_package(PkgConfig REQUIRED)

pkg_check_modules(CJSON           QUIET IMPORTED_TARGET libcjson)
pkg_check_modules(YAML            QUIET IMPORTED_TARGET yaml-0.1)
pkg_check_modules(MICROHTTPD      QUIET IMPORTED_TARGET libmicrohttpd)
pkg_check_modules(WEBSOCKETS      QUIET IMPORTED_TARGET libwebsockets)
pkg_check_modules(SQLITE3         QUIET IMPORTED_TARGET sqlite3)
pkg_check_modules(AVAHI_CLIENT    QUIET IMPORTED_TARGET avahi-client)
pkg_check_modules(SECCOMP         QUIET IMPORTED_TARGET libseccomp)
pkg_check_modules(SYSTEMD         QUIET IMPORTED_TARGET libsystemd)
pkg_check_modules(LIBCAP          QUIET IMPORTED_TARGET libcap)
pkg_check_modules(NCURSESW        QUIET IMPORTED_TARGET ncursesw)
pkg_check_modules(DBUS            QUIET IMPORTED_TARGET dbus-1)

find_package(SqliteVec QUIET)

# Summarise what was found
message(STATUS "------- dependency status -------")
foreach(_dep CJSON YAML MICROHTTPD WEBSOCKETS SQLITE3
             AVAHI_CLIENT SECCOMP SYSTEMD LIBCAP NCURSESW)
    if(${_dep}_FOUND)
        message(STATUS "  ${_dep} : found")
    else()
        message(STATUS "  ${_dep} : NOT found")
    endif()
endforeach()
if(SQLITEVEC_FOUND)
    message(STATUS "  SqliteVec : found")
else()
    message(STATUS "  SqliteVec : NOT found")
endif()
message(STATUS "---------------------------------")

# -----------------------------------------------------------------------------
# Libraries
# -----------------------------------------------------------------------------
add_subdirectory(lib/core)
add_subdirectory(lib/config)
add_subdirectory(lib/net)
add_subdirectory(lib/security)
add_subdirectory(lib/process)
add_subdirectory(lib/memory)
add_subdirectory(lib/terminal)
add_subdirectory(lib/agents)
add_subdirectory(lib/kernel)

# -----------------------------------------------------------------------------
# Executables
# -----------------------------------------------------------------------------
add_subdirectory(bin/kelp)
add_subdirectory(bin/kelp-gateway)
add_subdirectory(bin/kelp-tui)
add_subdirectory(bin/kelp-daemon)

# -----------------------------------------------------------------------------
# Channel plugins
# -----------------------------------------------------------------------------
add_subdirectory(channels/discord)
add_subdirectory(channels/telegram)
add_subdirectory(channels/slack)
add_subdirectory(channels/signal)

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
if(KELP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../tests
                     ${CMAKE_CURRENT_BINARY_DIR}/tests)
endif()
