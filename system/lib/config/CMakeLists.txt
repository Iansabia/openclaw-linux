# kelp-linux :: libkelp-config
# SPDX-License-Identifier: MIT

kelp_add_library(config)

# --------------------------------------------------------------------------
# Dependencies
# --------------------------------------------------------------------------

# kelp-core (for str.h / buf.h)
target_link_libraries(kelp-config
    PUBLIC  kelp::core
)

# libyaml (yaml-0.1)
if(YAML_FOUND)
    target_link_libraries(kelp-config PRIVATE PkgConfig::YAML)
else()
    message(FATAL_ERROR "libyaml (yaml-0.1) is required for libkelp-config")
endif()

# cJSON
if(CJSON_FOUND)
    target_link_libraries(kelp-config PRIVATE PkgConfig::CJSON)
else()
    message(FATAL_ERROR "cJSON (libcjson) is required for libkelp-config")
endif()

# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------
if(KELP_BUILD_TESTS)
    add_executable(test_config tests/test_config.c)
    target_link_libraries(test_config PRIVATE kelp-config)
    add_test(NAME config_tests COMMAND test_config)
endif()
