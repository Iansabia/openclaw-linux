# ---------------------------------------------------------------------------
# kelp-linux :: libkelp-security
# ---------------------------------------------------------------------------

set(SECURITY_SOURCES
    src/audit.c
    src/fs_perm.c
    src/policy.c
    src/path_scan.c
    src/timing.c
)

set(SECURITY_HEADERS
    include/kelp/audit.h
    include/kelp/fs_perm.h
    include/kelp/policy.h
    include/kelp/path_scan.h
    include/kelp/timing.h
)

# ---------- library target ------------------------------------------------

if(KELP_STATIC)
    add_library(kelp-security STATIC ${SECURITY_SOURCES})
else()
    add_library(kelp-security SHARED ${SECURITY_SOURCES})
endif()

add_library(kelp::security ALIAS kelp-security)

target_include_directories(kelp-security
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(kelp-security
    PUBLIC
        kelp-core
    PRIVATE
        Threads::Threads
)

set_target_properties(kelp-security PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION 0
    C_STANDARD 17
)

# ---------- install --------------------------------------------------------

install(TARGETS kelp-security
    EXPORT  kelp-targets
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}     COMPONENT security
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}     COMPONENT security
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}     COMPONENT security
)

install(FILES ${SECURITY_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kelp
    COMPONENT   security
)

# ---------- tests ----------------------------------------------------------

if(KELP_BUILD_TESTS)
    add_executable(test_security tests/test_security.c)

    target_link_libraries(test_security
        PRIVATE
            kelp-security
            kelp-core
            Threads::Threads
    )

    add_test(NAME test_security COMMAND test_security)
endif()
