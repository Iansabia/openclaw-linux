# clawd-linux :: libclawd-config
# SPDX-License-Identifier: MIT

clawd_add_library(config)

# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------

# clawd-core (for str.h / buf.h)
target_link_libraries(clawd-config
    PUBLIC  clawd::core
)

# libyaml (yaml-0.1)
if(YAML_FOUND)
    target_link_libraries(clawd-config PRIVATE PkgConfig::YAML)
else()
    message(FATAL_ERROR "libyaml (yaml-0.1) is required for libclawd-config")
endif()

# cJSON
if(CJSON_FOUND)
    target_link_libraries(clawd-config PRIVATE PkgConfig::CJSON)
else()
    message(FATAL_ERROR "cJSON (libcjson) is required for libclawd-config")
endif()

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------
if(CLAWD_BUILD_TESTS)
    add_executable(test_config tests/test_config.c)
    target_link_libraries(test_config PRIVATE clawd-config)
    add_test(NAME config_tests COMMAND test_config)
endif()
