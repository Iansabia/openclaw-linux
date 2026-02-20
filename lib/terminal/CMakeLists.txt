# clawd-linux :: libclawd-terminal
# SPDX-License-Identifier: MIT

# ---- sources -------------------------------------------------------------

set(CLAWD_TERMINAL_SOURCES
    src/ansi.c
    src/table.c
    src/progress.c
    src/prompt.c
)

set(CLAWD_TERMINAL_HEADERS
    include/clawd/ansi.h
    include/clawd/table.h
    include/clawd/progress.h
    include/clawd/prompt.h
)

# ---- library target ------------------------------------------------------

if(CLAWD_STATIC)
    add_library(clawd-terminal STATIC ${CLAWD_TERMINAL_SOURCES})
else()
    add_library(clawd-terminal SHARED ${CLAWD_TERMINAL_SOURCES})
endif()

add_library(clawd::terminal ALIAS clawd-terminal)

target_include_directories(clawd-terminal
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(clawd-terminal
    PUBLIC
        clawd-core
        Threads::Threads
)

# ---- compiler options ----------------------------------------------------

target_compile_options(clawd-terminal PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-terminal PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             ${PROJECT_VERSION}
    SOVERSION           ${PROJECT_VERSION_MAJOR}
)

# ---- install -------------------------------------------------------------

install(TARGETS clawd-terminal
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
    add_executable(test_terminal tests/test_terminal.c)
    target_link_libraries(test_terminal PRIVATE clawd-terminal)
    add_test(NAME test_terminal COMMAND test_terminal)
endif()
