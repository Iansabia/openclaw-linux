# clawd-linux :: libclawd-core
# SPDX-License-Identifier: MIT

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

# ---- library target ------------------------------------------------------

if(CLAWD_STATIC)
    add_library(clawd-core STATIC ${CLAWD_CORE_SOURCES})
else()
    add_library(clawd-core SHARED ${CLAWD_CORE_SOURCES})
endif()

add_library(clawd::core ALIAS clawd-core)

target_include_directories(clawd-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(clawd-core
    PUBLIC
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto
)

if(TARGET PkgConfig::CJSON)
    target_link_libraries(clawd-core PUBLIC PkgConfig::CJSON)
elseif(CJSON_FOUND)
    target_include_directories(clawd-core PUBLIC ${CJSON_INCLUDE_DIRS})
    target_link_directories(clawd-core PUBLIC ${CJSON_LIBRARY_DIRS})
    target_link_libraries(clawd-core PUBLIC ${CJSON_LIBRARIES})
else()
    message(FATAL_ERROR "cJSON (libcjson) is required for libclawd-core")
endif()

# ---- compiler options ----------------------------------------------------

target_compile_options(clawd-core PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-core PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             ${PROJECT_VERSION}
    SOVERSION           ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME         clawd-core
)

# ---- install -------------------------------------------------------------

install(TARGETS clawd-core
    EXPORT  clawd-targets
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
    add_test(NAME test_core COMMAND test_core)
endif()
