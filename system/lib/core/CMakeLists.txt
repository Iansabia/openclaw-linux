# kelp-linux :: libkelp-core
# SPDX-License-Identifier: MIT

# ---- sources -------------------------------------------------------------

set(KELP_CORE_SOURCES
    src/str.c
    src/buf.c
    src/map.c
    src/json.c
    src/log.c
    src/err.c
    src/crypto.c
)

# ---- library target ------------------------------------------------------

if(KELP_STATIC)
    add_library(kelp-core STATIC ${KELP_CORE_SOURCES})
else()
    add_library(kelp-core SHARED ${KELP_CORE_SOURCES})
endif()

add_library(kelp::core ALIAS kelp-core)

target_include_directories(kelp-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(kelp-core
    PUBLIC
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto
)

if(TARGET PkgConfig::CJSON)
    target_link_libraries(kelp-core PUBLIC PkgConfig::CJSON)
elseif(CJSON_FOUND)
    target_include_directories(kelp-core PUBLIC ${CJSON_INCLUDE_DIRS})
    target_link_directories(kelp-core PUBLIC ${CJSON_LIBRARY_DIRS})
    target_link_libraries(kelp-core PUBLIC ${CJSON_LIBRARIES})
else()
    message(FATAL_ERROR "cJSON (libcjson) is required for libkelp-core")
endif()

# ---- compiler options ----------------------------------------------------

target_compile_options(kelp-core PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(kelp-core PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             ${PROJECT_VERSION}
    SOVERSION           ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME         kelp-core
)

# ---- install -------------------------------------------------------------

install(TARGETS kelp-core
    EXPORT  kelp-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/kelp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# ---- tests ---------------------------------------------------------------

if(KELP_BUILD_TESTS)
    add_executable(test_core tests/test_core.c)
    target_link_libraries(test_core PRIVATE kelp-core)
    target_compile_options(test_core PRIVATE -Wall -Wextra)
    add_test(NAME test_core COMMAND test_core)
endif()
