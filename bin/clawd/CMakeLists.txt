# clawd-linux :: clawd CLI binary
# SPDX-License-Identifier: MIT


# ---- sources -------------------------------------------------------------

set(CLAWD_CLI_SOURCES
    main.c
)

# ---- executable -----------------------------------------------------------

add_executable(clawd ${CLAWD_CLI_SOURCES})

target_compile_options(clawd PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    OUTPUT_NAME         clawd
)

# ---- compile definitions -------------------------------------------------

# Inject build metadata.
string(TIMESTAMP CLAWD_BUILD_DATE "%Y-%m-%d" UTC)
target_compile_definitions(clawd PRIVATE
    CLAWD_BUILD_DATE="${CLAWD_BUILD_DATE}"
)

# Git commit hash (best effort).
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE CLAWD_GIT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(CLAWD_GIT_COMMIT)
    target_compile_definitions(clawd PRIVATE
        CLAWD_BUILD_COMMIT="${CLAWD_GIT_COMMIT}"
    )
endif()

# ---- dependencies --------------------------------------------------------

target_link_libraries(clawd PRIVATE
    clawd-core
    clawd-config
    clawd-terminal
    clawd-kernel
)

# readline
find_path(READLINE_INCLUDE_DIR readline/readline.h)
find_library(READLINE_LIBRARY readline)

if(READLINE_INCLUDE_DIR AND READLINE_LIBRARY)
    target_include_directories(clawd PRIVATE ${READLINE_INCLUDE_DIR})
    target_link_libraries(clawd PRIVATE ${READLINE_LIBRARY})
else()
    message(FATAL_ERROR "readline not found -- required for clawd CLI")
endif()

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS clawd RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
