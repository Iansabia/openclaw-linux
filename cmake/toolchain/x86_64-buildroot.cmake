# CMake toolchain file for Buildroot x86_64 cross-compilation
#
# Usage:
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/x86_64-buildroot.cmake

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Buildroot output host directory (adjust as needed)
set(BUILDROOT_HOST "$ENV{BUILDROOT_HOST}" CACHE PATH "Buildroot host tools")
if(NOT BUILDROOT_HOST)
    set(BUILDROOT_HOST "${CMAKE_CURRENT_LIST_DIR}/../../buildroot-src/output/host")
endif()

set(CMAKE_C_COMPILER   "${BUILDROOT_HOST}/bin/x86_64-buildroot-linux-gnu-gcc")
set(CMAKE_CXX_COMPILER "${BUILDROOT_HOST}/bin/x86_64-buildroot-linux-gnu-g++")

set(CMAKE_SYSROOT "${BUILDROOT_HOST}/x86_64-buildroot-linux-gnu/sysroot")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
