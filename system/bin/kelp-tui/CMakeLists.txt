# kelp-linux :: kelp-tui binary
# SPDX-License-Identifier: MIT



# ---- sources -------------------------------------------------------------

set(KELP_TUI_SOURCES
    main.c
)

# ---- executable -----------------------------------------------------------

add_executable(kelp-tui ${KELP_TUI_SOURCES})

target_compile_options(kelp-tui PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(kelp-tui PROPERTIES
    C_STANDARD          17
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS        OFF
    OUTPUT_NAME         kelp-tui
)

# ---- dependencies --------------------------------------------------------

target_link_libraries(kelp-tui PRIVATE
    kelp-core
    kelp-config
    kelp-terminal
)

# ncursesw (wide character ncurses)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NCURSESW QUIET IMPORTED_TARGET ncursesw)
if(NCURSESW_FOUND)
    target_link_libraries(kelp-tui PRIVATE PkgConfig::NCURSESW)
else()
    # Fallback: try to find ncurses directly.
    find_package(Curses REQUIRED)
    target_include_directories(kelp-tui PRIVATE ${CURSES_INCLUDE_DIRS})
    target_link_libraries(kelp-tui PRIVATE ${CURSES_LIBRARIES})
endif()

# ---- install -------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS kelp-tui RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
