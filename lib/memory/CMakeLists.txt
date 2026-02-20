# clawd-linux :: libclawd-memory
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)

# ---- sources -------------------------------------------------------------

set(CLAWD_MEMORY_SOURCES
    src/memory.c
    src/embeddings.c
    src/watcher.c
    src/bm25.c
)

set(CLAWD_MEMORY_HEADERS
    include/clawd/memory.h
    include/clawd/embeddings.h
    include/clawd/watcher.h
)

# ---- library target ------------------------------------------------------

if(CLAWD_STATIC)
    add_library(clawd-memory STATIC ${CLAWD_MEMORY_SOURCES})
else()
    add_library(clawd-memory SHARED ${CLAWD_MEMORY_SOURCES})
endif()

target_include_directories(clawd-memory
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# ---- dependencies --------------------------------------------------------

# clawd-core (provides logging, error handling, strings, JSON wrappers)
target_link_libraries(clawd-memory PUBLIC clawd-core)

# Threads (pthread)
find_package(Threads REQUIRED)
target_link_libraries(clawd-memory PUBLIC Threads::Threads)

# SQLite3 via pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
target_include_directories(clawd-memory PUBLIC ${SQLITE3_INCLUDE_DIRS})
target_link_directories(clawd-memory PUBLIC ${SQLITE3_LIBRARY_DIRS})
target_link_libraries(clawd-memory PUBLIC ${SQLITE3_LIBRARIES})

# libcurl (for embedding API HTTP requests)
find_package(CURL REQUIRED)
target_link_libraries(clawd-memory PUBLIC CURL::libcurl)

# cJSON (for parsing embedding API responses)
pkg_check_modules(CJSON REQUIRED libcjson)
target_include_directories(clawd-memory PUBLIC ${CJSON_INCLUDE_DIRS})
target_link_directories(clawd-memory PUBLIC ${CJSON_LIBRARY_DIRS})
target_link_libraries(clawd-memory PUBLIC ${CJSON_LIBRARIES})

# dl (for dynamically loading sqlite-vec extension)
target_link_libraries(clawd-memory PUBLIC ${CMAKE_DL_LIBS})

# math library
target_link_libraries(clawd-memory PUBLIC m)

# ---- platform feature checks ---------------------------------------------

include(CheckFunctionExists)

check_function_exists(inotify_init1 HAVE_INOTIFY)
if(HAVE_INOTIFY)
    target_compile_definitions(clawd-memory PRIVATE HAVE_INOTIFY=1)
endif()

check_function_exists(kqueue HAVE_KQUEUE)
if(HAVE_KQUEUE)
    target_compile_definitions(clawd-memory PRIVATE HAVE_KQUEUE=1)
endif()

# ---- compiler options ----------------------------------------------------

target_compile_options(clawd-memory PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-memory PROPERTIES
    C_STANDARD          11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             0.1.0
    SOVERSION           0
    OUTPUT_NAME         clawd-memory
)

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)

install(TARGETS clawd-memory
    EXPORT  clawd-memory-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/clawd
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# ---- tests ---------------------------------------------------------------

if(CLAWD_BUILD_TESTS)
    add_executable(test_memory tests/test_memory.c)
    target_link_libraries(test_memory PRIVATE clawd-memory)
    target_compile_options(test_memory PRIVATE -Wall -Wextra)
    set_target_properties(test_memory PROPERTIES
        C_STANDARD          11
        C_STANDARD_REQUIRED ON
    )
    add_test(NAME test_memory COMMAND test_memory)
endif()
