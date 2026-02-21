cmake_minimum_required(VERSION 3.20)
project(kelp VERSION 0.1.0 LANGUAGES C)

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
option(KELP_STATIC       "Build static libraries instead of shared" OFF)
option(KELP_BUILD_TESTS  "Build unit and integration tests"         ON)

# Default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# -----------------------------------------------------------------------------
# CMake module path & helpers
# -----------------------------------------------------------------------------
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(KelpPackage)

# -----------------------------------------------------------------------------
# Kernel headers (shared between kernel module and userspace)
# -----------------------------------------------------------------------------
install(DIRECTORY kernel/include/kelp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# -----------------------------------------------------------------------------
# Userspace system (libraries, binaries, channels, tests)
# -----------------------------------------------------------------------------
add_subdirectory(system)

# -----------------------------------------------------------------------------
# CPack — Debian package generation
# -----------------------------------------------------------------------------
set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_NAME        "${PROJECT_NAME}")
set(CPACK_PACKAGE_VERSION     "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "Kelp OS — AI-First Operating System")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Kelp OS <maintainers@kelp.dev>")
set(CPACK_DEBIAN_PACKAGE_SECTION    "utils")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS  OFF)

# Per-component .deb generation
set(CPACK_DEB_COMPONENT_INSTALL ON)

include(CPack)
