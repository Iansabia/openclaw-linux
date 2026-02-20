cmake_minimum_required(VERSION 3.20)
project(clawd-linux VERSION 0.1.0 LANGUAGES C)

# -----------------------------------------------------------------------------
# C standard
# -----------------------------------------------------------------------------
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Expose POSIX and GNU symbols (PATH_MAX, getaddrinfo, struct addrinfo, etc.)
add_compile_definitions(_GNU_SOURCE)

# -----------------------------------------------------------------------------
# Build options
# -----------------------------------------------------------------------------
option(CLAWD_STATIC       "Build static libraries instead of shared" OFF)
option(CLAWD_BUILD_TESTS  "Build unit and integration tests"         ON)

# Default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# -----------------------------------------------------------------------------
# CMake module path & helpers
# -----------------------------------------------------------------------------
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ClawdPackage)

# -----------------------------------------------------------------------------
# Required packages
# -----------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_package(CURL   REQUIRED)
find_package(Threads REQUIRED)

# -----------------------------------------------------------------------------
# pkg-config dependencies
# -----------------------------------------------------------------------------
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

# sqlite-vec extension (optional, custom find module)
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
# Libraries  (lib/)
# -----------------------------------------------------------------------------
add_subdirectory(lib/core)
add_subdirectory(lib/config)
add_subdirectory(lib/net)
add_subdirectory(lib/security)
add_subdirectory(lib/process)
add_subdirectory(lib/memory)
add_subdirectory(lib/terminal)
add_subdirectory(lib/agents)

# -----------------------------------------------------------------------------
# Executables  (bin/)
# -----------------------------------------------------------------------------
add_subdirectory(bin/clawd)
add_subdirectory(bin/clawd-gateway)
add_subdirectory(bin/clawd-tui)
add_subdirectory(bin/clawd-daemon)

# -----------------------------------------------------------------------------
# Channel plugins  (channels/)
# -----------------------------------------------------------------------------
add_subdirectory(channels/discord)
add_subdirectory(channels/telegram)
add_subdirectory(channels/slack)
add_subdirectory(channels/signal)

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------
if(CLAWD_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# -----------------------------------------------------------------------------
# CPack  –  Debian package generation
# -----------------------------------------------------------------------------
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME        "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION     "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "clawd – a Linux-native AI agent system")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "clawd maintainers <maintainers@clawd.dev>")
set(CPACK_DEBIAN_PACKAGE_SECTION    "utils")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS  OFF)

# Per-component .deb generation
set(CPACK_DEB_COMPONENT_INSTALL ON)

include(CPack)
