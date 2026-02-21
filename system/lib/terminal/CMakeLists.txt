# kelp-linux :: libkelp-terminal
# SPDX-License-Identifier: MIT

# ---- sources -------------------------------------------------------------

set(KELP_TERMINAL_SOURCES
    src/ansi.c
    src/table.c
    src/progress.c
    src/prompt.c
)

set(KELP_TERMINAL_HEADERS
    include/kelp/ansi.h
    include/kelp/table.h
    include/kelp/progress.h
    include/kelp/prompt.h
)

# ---- library target ------------------------------------------------------

if(KELP_STATIC)
    add_library(kelp-terminal STATIC ${KELP_TERMINAL_SOURCES})
else()
    add_library(kelp-terminal SHARED ${KELP_TERMINAL_SOURCES})
endif()

add_library(kelp::terminal ALIAS kelp-terminal)

target_include_directories(kelp-terminal
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(kelp-terminal
    PUBLIC
        kelp-core
        Threads::Threads
)

# ---- compiler options ----------------------------------------------------

target_compile_options(kelp-terminal PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(kelp-terminal PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    VERSION             ${PROJECT_VERSION}
    SOVERSION           ${PROJECT_VERSION_MAJOR}
)

# ---- install -------------------------------------------------------------

install(TARGETS kelp-terminal
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
    add_executable(test_terminal tests/test_terminal.c)
    target_link_libraries(test_terminal PRIVATE kelp-terminal)
    add_test(NAME test_terminal COMMAND test_terminal)
endif()
