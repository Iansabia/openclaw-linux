# clawd-linux :: libclawd-terminal
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)

# ---- sources -------------------------------------------------------------

set(CLAWD_TERMINAL_SOURCES
    src/ansi.c
    src/table.c
    src/progress.c
)

set(CLAWD_TERMINAL_HEADERS
    include/clawd/ansi.h
    include/clawd/table.h
    include/clawd/progress.h
)

# ---- library target ------------------------------------------------------

if(CLAWD_STATIC)
    add_library(clawd-terminal STATIC ${CLAWD_TERMINAL_SOURCES})
else()
    add_library(clawd-terminal SHARED ${CLAWD_TERMINAL_SOURCES})
endif()

target_include_directories(clawd-terminal
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(clawd-terminal PUBLIC clawd-core)

find_package(Threads REQUIRED)
target_link_libraries(clawd-terminal PUBLIC Threads::Threads)

# ---- compiler options ----------------------------------------------------

target_compile_options(clawd-terminal PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-terminal PROPERTIES
    C_STANDARD          11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             0.1.0
    SOVERSION           0
    OUTPUT_NAME         clawd-terminal
)

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)

install(TARGETS clawd-terminal
    EXPORT  clawd-terminal-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY include/clawd
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)

# ---- tests ---------------------------------------------------------------

if(CLAWD_BUILD_TESTS)
    add_executable(test_terminal tests/test_terminal.c)
    target_link_libraries(test_terminal PRIVATE clawd-terminal)
    target_compile_options(test_terminal PRIVATE -Wall -Wextra)
    set_target_properties(test_terminal PROPERTIES
        C_STANDARD          11
        C_STANDARD_REQUIRED ON
    )
    add_test(NAME test_terminal COMMAND test_terminal)
endif()
