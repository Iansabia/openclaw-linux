# kelp-linux :: kelp-channel-slack
# SPDX-License-Identifier: MIT

add_executable(kelp-channel-slack src/main.c)

target_link_libraries(kelp-channel-slack
    PRIVATE
        kelp-core
        kelp-net
        kelp-config
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

if(CJSON_FOUND)
    target_link_libraries(kelp-channel-slack PRIVATE PkgConfig::CJSON)
endif()

target_compile_options(kelp-channel-slack PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

install(TARGETS kelp-channel-slack RUNTIME DESTINATION bin)
