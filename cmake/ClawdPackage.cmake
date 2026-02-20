# ClawdPackage.cmake  –  helper macros for clawd-linux build system
# Included from the top-level CMakeLists.txt

include(GNUInstallDirs)

# ---------------------------------------------------------------------------
# clawd_add_library(<name>)
#
# Creates a library target named clawd-<name> from all *.c files found under
# the calling directory's src/ folder.  Shared or static is chosen by the
# CLAWD_STATIC option.  Public headers are expected in include/clawd/<name>.
#
# After calling this macro the target "clawd-<name>" is available for
# target_link_libraries() in downstream CMakeLists.txt files.
# ---------------------------------------------------------------------------
macro(clawd_add_library name)
    set(_target "clawd-${name}")

    file(GLOB_RECURSE _sources
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
    )

    if(CLAWD_STATIC)
        add_library(${_target} STATIC ${_sources})
    else()
        add_library(${_target} SHARED ${_sources})
    endif()

    # Alias so consumers can use clawd::core, clawd::net, etc.
    add_library(clawd::${name} ALIAS ${_target})

    # Public include directory  –  include/clawd/
    target_include_directories(${_target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    # Default compile options
    target_compile_options(${_target} PRIVATE -Wall -Wextra -Wpedantic)

    # Shared library versioning
    if(NOT CLAWD_STATIC)
        set_target_properties(${_target} PROPERTIES
            VERSION   ${PROJECT_VERSION}
            SOVERSION ${PROJECT_VERSION_MAJOR}
        )
    endif()

    # Install the library binary
    install(TARGETS ${_target}
        EXPORT   clawd-targets
        LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}   COMPONENT ${_target}
        ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}   COMPONENT ${_target}
        RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}   COMPONENT ${_target}
    )

    # Install public headers
    if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/clawd")
        install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/clawd/"
            DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/clawd"
            COMPONENT   ${_target}-dev
            FILES_MATCHING PATTERN "*.h"
        )
    endif()
endmacro()

# ---------------------------------------------------------------------------
# clawd_add_executable(<name>)
#
# Convenience wrapper: creates an executable target from src/*.c in the
# calling directory and sets up a standard install rule.
# ---------------------------------------------------------------------------
macro(clawd_add_executable name)
    file(GLOB_RECURSE _exe_sources
        "${CMAKE_CURRENT_SOURCE_DIR}/*.c"
    )

    add_executable(${name} ${_exe_sources})

    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)

    install(TARGETS ${name}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT ${name}
    )
endmacro()

# ---------------------------------------------------------------------------
# clawd_add_deb(<name> <version> <depends> <description>)
#
# Configures CPack component-level metadata so that `cpack` produces a
# separate .deb for the given component.
#
# Example:
#   clawd_add_deb(clawd-core "0.1.0" "libc6 (>= 2.31), libssl3"
#                 "Core runtime library for the clawd agent system")
# ---------------------------------------------------------------------------
macro(clawd_add_deb name version depends description)
    # CPack uses upper-case component names internally
    string(TOUPPER "${name}" _upper)
    string(REPLACE "-" "_" _upper "${_upper}")

    set(CPACK_DEBIAN_${_upper}_PACKAGE_NAME    "${name}"        CACHE INTERNAL "")
    set(CPACK_DEBIAN_${_upper}_PACKAGE_VERSION "${version}"     CACHE INTERNAL "")
    set(CPACK_DEBIAN_${_upper}_PACKAGE_DEPENDS "${depends}"     CACHE INTERNAL "")
    set(CPACK_DEBIAN_${_upper}_DESCRIPTION     "${description}" CACHE INTERNAL "")

    # Register the component with CPack
    cpack_add_component(${name}
        DISPLAY_NAME "${name}"
        DESCRIPTION  "${description}"
    )
endmacro()

# ---------------------------------------------------------------------------
# clawd_install_config(<files...>)
#
# Installs configuration files into /etc/clawd/.
# ---------------------------------------------------------------------------
macro(clawd_install_config)
    install(FILES ${ARGN}
        DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/clawd"
        COMPONENT   clawd-config-files
    )
endmacro()

# ---------------------------------------------------------------------------
# clawd_install_systemd_unit(<files...>)
#
# Installs systemd unit files.
# ---------------------------------------------------------------------------
macro(clawd_install_systemd_unit)
    install(FILES ${ARGN}
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system"
        COMPONENT   clawd-systemd
    )
endmacro()
