# clawd-linux :: libclawd-core
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)

# ---- sources -------------------------------------------------------------

set(CLAWD_CORE_SOURCES
    src/str.c
    src/buf.c
    src/map.c
    src/json.c
    src/log.c
    src/err.c
    src/crypto.c
)

set(CLAWD_CORE_HEADERS
    include/clawd/clawd.h
    include/clawd/str.h
    include/clawd/buf.h
    include/clawd/vec.h
    include/clawd/map.h
    include/clawd/json.h
    include/clawd/log.h
    include/clawd/err.h
    include/clawd/crypto.h
)

# ---- library target ------------------------------------------------------

if(CLAWD_STATIC)
    add_library(clawd-core STATIC ${CLAWD_CORE_SOURCES})
else()
    add_library(clawd-core SHARED ${CLAWD_CORE_SOURCES})
endif()

target_include_directories(clawd-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# ---- dependencies --------------------------------------------------------

# Threads (pthread)
find_package(Threads REQUIRED)
target_link_libraries(clawd-core PUBLIC Threads::Threads)

# OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(clawd-core PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# cJSON via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(CJSON REQUIRED libcjson)
target_include_directories(clawd-core PUBLIC ${CJSON_INCLUDE_DIRS})
target_link_directories(clawd-core PUBLIC ${CJSON_LIBRARY_DIRS})
target_link_libraries(clawd-core PUBLIC ${CJSON_LIBRARIES})

# ---- compiler options ----------------------------------------------------

target_compile_options(clawd-core PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-core PROPERTIES
    C_STANDARD          11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             0.1.0
    SOVERSION           0
    OUTPUT_NAME         clawd-core
)

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)

install(TARGETS clawd-core
    EXPORT  clawd-core-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/clawd
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# ---- tests ---------------------------------------------------------------

if(CLAWD_BUILD_TESTS)
    add_executable(test_core tests/test_core.c)
    target_link_libraries(test_core PRIVATE clawd-core)
    target_compile_options(test_core PRIVATE -Wall -Wextra)
    set_target_properties(test_core PROPERTIES
        C_STANDARD          11
        C_STANDARD_REQUIRED ON
    )
    add_test(NAME test_core COMMAND test_core)
endif()
