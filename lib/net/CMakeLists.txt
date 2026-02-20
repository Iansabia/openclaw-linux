# --------------------------------------------------------------------------
# clawd-linux :: libclawd-net
#
# HTTP client, TLS, SSRF prevention, mDNS discovery, heartbeat.
# --------------------------------------------------------------------------

set(CLAWD_NET_SOURCES
    src/http.c
    src/tls.c
    src/ssrf.c
    src/mdns.c
    src/heartbeat.c
)

set(CLAWD_NET_HEADERS
    include/clawd/http.h
    include/clawd/tls.h
    include/clawd/ssrf.h
    include/clawd/mdns.h
    include/clawd/heartbeat.h
)

# Library target (shared or static based on top-level option)
if(CLAWD_STATIC)
    add_library(clawd-net STATIC ${CLAWD_NET_SOURCES})
else()
    add_library(clawd-net SHARED ${CLAWD_NET_SOURCES})
endif()

add_library(clawd::net ALIAS clawd-net)

# Include directories
target_include_directories(clawd-net
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Required dependencies
target_link_libraries(clawd-net
    PUBLIC
        clawd-core
    PRIVATE
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

# Optional: Avahi mDNS support
if(AVAHI_CLIENT_FOUND)
    target_compile_definitions(clawd-net PRIVATE HAVE_AVAHI)
    target_link_libraries(clawd-net PRIVATE PkgConfig::AVAHI_CLIENT)
    message(STATUS "  clawd-net: Avahi mDNS support enabled")
else()
    message(STATUS "  clawd-net: Avahi not found -- mDNS stubs will be used")
endif()

# Compiler settings
target_compile_options(clawd-net PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(clawd-net PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION 0
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------
include(GNUInstallDirs)

install(TARGETS clawd-net
    EXPORT  clawd-net-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}   COMPONENT clawd-net
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}   COMPONENT clawd-net-dev
)

install(FILES ${CLAWD_NET_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/clawd
    COMPONENT   clawd-net-dev
)

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------
if(CLAWD_BUILD_TESTS)
    add_executable(test_net tests/test_net.c)
    target_link_libraries(test_net PRIVATE clawd-net clawd-core)
    add_test(NAME test_net COMMAND test_net)
endif()
