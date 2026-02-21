# kelp-linux :: kelp-channel-telegram
# SPDX-License-Identifier: MIT

add_executable(kelp-channel-telegram src/main.c)

target_link_libraries(kelp-channel-telegram
    PRIVATE
        kelp-core
        kelp-net
        kelp-config
        Threads::Threads
)

if(CJSON_FOUND)
    target_link_libraries(kelp-channel-telegram PRIVATE PkgConfig::CJSON)
endif()

target_compile_options(kelp-channel-telegram PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

install(TARGETS kelp-channel-telegram RUNTIME DESTINATION bin)
