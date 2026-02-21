# --------------------------------------------------------------------------
# kelp-linux :: libkelp-net
#
# HTTP client, TLS, SSRF prevention, mDNS discovery, heartbeat.
# --------------------------------------------------------------------------

set(KELP_NET_SOURCES
    src/http.c
    src/tls.c
    src/ssrf.c
    src/mdns.c
    src/heartbeat.c
)

set(KELP_NET_HEADERS
    include/kelp/http.h
    include/kelp/tls.h
    include/kelp/ssrf.h
    include/kelp/mdns.h
    include/kelp/heartbeat.h
)

# Library target (shared or static based on top-level option)
if(KELP_STATIC)
    add_library(kelp-net STATIC ${KELP_NET_SOURCES})
else()
    add_library(kelp-net SHARED ${KELP_NET_SOURCES})
endif()

add_library(kelp::net ALIAS kelp-net)

# Include directories
target_include_directories(kelp-net
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Required dependencies
target_link_libraries(kelp-net
    PUBLIC
        kelp-core
    PRIVATE
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

# Optional: Avahi mDNS support
if(AVAHI_CLIENT_FOUND)
    target_compile_definitions(kelp-net PRIVATE HAVE_AVAHI)
    target_link_libraries(kelp-net PRIVATE PkgConfig::AVAHI_CLIENT)
    message(STATUS "  kelp-net: Avahi mDNS support enabled")
else()
    message(STATUS "  kelp-net: Avahi not found -- mDNS stubs will be used")
endif()

# Compiler settings
target_compile_options(kelp-net PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

set_target_properties(kelp-net PROPERTIES
    VERSION   ${PROJECT_VERSION}
    SOVERSION 0
)

# --------------------------------------------------------------------------
# Install
# --------------------------------------------------------------------------
include(GNUInstallDirs)

install(TARGETS kelp-net
    EXPORT  kelp-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}   COMPONENT kelp-net
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}   COMPONENT kelp-net-dev
)

install(FILES ${KELP_NET_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/kelp
    COMPONENT   kelp-net-dev
)

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------
if(KELP_BUILD_TESTS)
    add_executable(test_net tests/test_net.c)
    target_link_libraries(test_net PRIVATE kelp-net kelp-core)
    add_test(NAME test_net COMMAND test_net)
endif()
