# ---------------------------------------------------------------------------
# clawd-linux :: libclawd-security
# ---------------------------------------------------------------------------

set(SECURITY_SOURCES
    src/audit.c
    src/fs_perm.c
    src/policy.c
    src/path_scan.c
)

set(SECURITY_HEADERS
    include/clawd/audit.h
    include/clawd/fs_perm.h
    include/clawd/policy.h
    include/clawd/path_scan.h
)

# ---------- library target ------------------------------------------------

if(CLAWD_STATIC)
    add_library(clawd-security STATIC ${SECURITY_SOURCES})
else()
    add_library(clawd-security SHARED ${SECURITY_SOURCES})
endif()

add_library(clawd::security ALIAS clawd-security)

target_include_directories(clawd-security
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(clawd-security
    PUBLIC
        clawd-core
    PRIVATE
        Threads::Threads
)

set_target_properties(clawd-security PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION 0
    C_STANDARD 17
)

# ---------- install --------------------------------------------------------

install(TARGETS clawd-security
    EXPORT  clawd-targets
    LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}     COMPONENT security
    ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR}     COMPONENT security
    RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}     COMPONENT security
)

install(FILES ${SECURITY_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/clawd
    COMPONENT   security
)

# ---------- tests ----------------------------------------------------------

if(CLAWD_BUILD_TESTS)
    add_executable(test_security tests/test_security.c)

    target_link_libraries(test_security
        PRIVATE
            clawd-security
            clawd-core
            Threads::Threads
    )

    add_test(NAME test_security COMMAND test_security)
endif()
