# kelp-linux :: libkelp-memory
# SPDX-License-Identifier: MIT

# ---- sources -------------------------------------------------------------

set(KELP_MEMORY_SOURCES
    src/memory.c
    src/embeddings.c
    src/watcher.c
    src/bm25.c
)

# ---- library target ------------------------------------------------------

if(KELP_STATIC)
    add_library(kelp-memory STATIC ${KELP_MEMORY_SOURCES})
else()
    add_library(kelp-memory SHARED ${KELP_MEMORY_SOURCES})
endif()

add_library(kelp::memory ALIAS kelp-memory)

target_include_directories(kelp-memory
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(kelp-memory
    PUBLIC
        kelp-core
        Threads::Threads
        CURL::libcurl
        ${CMAKE_DL_LIBS}
        m
)

# SQLite3
if(TARGET PkgConfig::SQLITE3)
    target_link_libraries(kelp-memory PUBLIC PkgConfig::SQLITE3)
elseif(SQLITE3_FOUND)
    target_include_directories(kelp-memory PUBLIC ${SQLITE3_INCLUDE_DIRS})
    target_link_directories(kelp-memory PUBLIC ${SQLITE3_LIBRARY_DIRS})
    target_link_libraries(kelp-memory PUBLIC ${SQLITE3_LIBRARIES})
else()
    message(FATAL_ERROR "SQLite3 is required for libkelp-memory")
endif()

# cJSON (already linked through kelp-core, but we need headers for embeddings.c)
if(TARGET PkgConfig::CJSON)
    target_link_libraries(kelp-memory PRIVATE PkgConfig::CJSON)
elseif(CJSON_FOUND)
    target_include_directories(kelp-memory PRIVATE ${CJSON_INCLUDE_DIRS})
endif()

# ---- platform feature checks ---------------------------------------------

include(CheckFunctionExists)

check_function_exists(inotify_init1 HAVE_INOTIFY)
if(HAVE_INOTIFY)
    target_compile_definitions(kelp-memory PRIVATE HAVE_INOTIFY=1)
endif()

check_function_exists(kqueue HAVE_KQUEUE)
if(HAVE_KQUEUE)
    target_compile_definitions(kelp-memory PRIVATE HAVE_KQUEUE=1)
endif()

# ---- compiler options ----------------------------------------------------

target_compile_options(kelp-memory PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(kelp-memory PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             ${PROJECT_VERSION}
    SOVERSION           ${PROJECT_VERSION_MAJOR}
)

# ---- install -------------------------------------------------------------

install(TARGETS kelp-memory
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
    add_executable(test_memory tests/test_memory.c)
    target_link_libraries(test_memory PRIVATE kelp-memory)
    add_test(NAME test_memory COMMAND test_memory)
endif()
