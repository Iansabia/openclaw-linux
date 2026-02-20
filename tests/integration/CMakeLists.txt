add_executable(test_config_load test_config_load.c)
target_link_libraries(test_config_load PRIVATE clawd-config clawd-core)
add_test(NAME integration_config_load COMMAND test_config_load)
