# clawd-linux :: libclawd-memory
# SPDX-License-Identifier: MIT

# ---- sources -------------------------------------------------------------

set(CLAWD_MEMORY_SOURCES
    src/memory.c
    src/embeddings.c
    src/watcher.c
    src/bm25.c
)

# ---- library target ------------------------------------------------------

if(CLAWD_STATIC)
    add_library(clawd-memory STATIC ${CLAWD_MEMORY_SOURCES})
else()
    add_library(clawd-memory SHARED ${CLAWD_MEMORY_SOURCES})
endif()

add_library(clawd::memory ALIAS clawd-memory)

target_include_directories(clawd-memory
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(clawd-memory
    PUBLIC
        clawd-core
        Threads::Threads
        CURL::libcurl
        ${CMAKE_DL_LIBS}
        m
)

# SQLite3
if(TARGET PkgConfig::SQLITE3)
    target_link_libraries(clawd-memory PUBLIC PkgConfig::SQLITE3)
elseif(SQLITE3_FOUND)
    target_include_directories(clawd-memory PUBLIC ${SQLITE3_INCLUDE_DIRS})
    target_link_directories(clawd-memory PUBLIC ${SQLITE3_LIBRARY_DIRS})
    target_link_libraries(clawd-memory PUBLIC ${SQLITE3_LIBRARIES})
else()
    message(FATAL_ERROR "SQLite3 is required for libclawd-memory")
endif()

# cJSON (already linked through clawd-core, but we need headers for embeddings.c)
if(TARGET PkgConfig::CJSON)
    target_link_libraries(clawd-memory PRIVATE PkgConfig::CJSON)
elseif(CJSON_FOUND)
    target_include_directories(clawd-memory PRIVATE ${CJSON_INCLUDE_DIRS})
endif()

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
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             ${PROJECT_VERSION}
    SOVERSION           ${PROJECT_VERSION_MAJOR}
)

# ---- install -------------------------------------------------------------

install(TARGETS clawd-memory
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
    add_executable(test_memory tests/test_memory.c)
    target_link_libraries(test_memory PRIVATE clawd-memory)
    add_test(NAME test_memory COMMAND test_memory)
endif()
