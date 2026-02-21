# kelp-linux :: kelp-channel-signal
# SPDX-License-Identifier: MIT

add_executable(kelp-channel-signal src/main.c)

target_link_libraries(kelp-channel-signal
    PRIVATE
        kelp-core
        kelp-config
        Threads::Threads
)

if(CJSON_FOUND)
    target_link_libraries(kelp-channel-signal PRIVATE PkgConfig::CJSON)
endif()

target_compile_options(kelp-channel-signal PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter
)

install(TARGETS kelp-channel-signal RUNTIME DESTINATION bin)
