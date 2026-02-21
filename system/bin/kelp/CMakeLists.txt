# kelp-linux :: kelp CLI binary
# SPDX-License-Identifier: MIT


# ---- sources -------------------------------------------------------------

set(KELP_CLI_SOURCES
    main.c
)

# ---- executable -----------------------------------------------------------

add_executable(kelp ${KELP_CLI_SOURCES})

target_compile_options(kelp PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(kelp PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    OUTPUT_NAME         kelp
)

# ---- compile definitions -------------------------------------------------

# Inject build metadata.
string(TIMESTAMP KELP_BUILD_DATE "%Y-%m-%d" UTC)
target_compile_definitions(kelp PRIVATE
    KELP_BUILD_DATE="${KELP_BUILD_DATE}"
)

# Git commit hash (best effort).
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE KELP_GIT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(KELP_GIT_COMMIT)
    target_compile_definitions(kelp PRIVATE
        KELP_BUILD_COMMIT="${KELP_GIT_COMMIT}"
    )
endif()

# ---- dependencies --------------------------------------------------------

target_link_libraries(kelp PRIVATE
    kelp-core
    kelp-config
    kelp-terminal
    kelp-kernel
)

# readline
find_path(READLINE_INCLUDE_DIR readline/readline.h)
find_library(READLINE_LIBRARY readline)

if(READLINE_INCLUDE_DIR AND READLINE_LIBRARY)
    target_include_directories(kelp PRIVATE ${READLINE_INCLUDE_DIR})
    target_link_libraries(kelp PRIVATE ${READLINE_LIBRARY})
else()
    message(FATAL_ERROR "readline not found -- required for kelp CLI")
endif()

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS kelp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
