# clawd-linux :: clawd-tui binary
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)

# ---- sources -------------------------------------------------------------

set(CLAWD_TUI_SOURCES
    main.c
)

# ---- executable -----------------------------------------------------------

add_executable(clawd-tui ${CLAWD_TUI_SOURCES})

target_compile_options(clawd-tui PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-tui PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    OUTPUT_NAME         clawd-tui
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(clawd-tui PRIVATE
    clawd-core
    clawd-config
    clawd-terminal
)

# ncursesw (wide character ncurses)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NCURSESW QUIET IMPORTED_TARGET ncursesw)
if(NCURSESW_FOUND)
    target_link_libraries(clawd-tui PRIVATE PkgConfig::NCURSESW)
else()
    # Fallback: try to find ncurses directly.
    find_package(Curses REQUIRED)
    target_include_directories(clawd-tui PRIVATE ${CURSES_INCLUDE_DIRS})
    target_link_libraries(clawd-tui PRIVATE ${CURSES_LIBRARIES})
endif()

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS clawd-tui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
