# kelp-linux :: kelp-channel-discord
# SPDX-License-Identifier: MIT

add_executable(kelp-channel-discord src/main.c)

target_link_libraries(kelp-channel-discord
    PRIVATE
        kelp-core
        kelp-net
        kelp-config
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

if(CJSON_FOUND)
    target_link_libraries(kelp-channel-discord PRIVATE PkgConfig::CJSON)
endif()

target_compile_options(kelp-channel-discord PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

install(TARGETS kelp-channel-discord RUNTIME DESTINATION bin)
