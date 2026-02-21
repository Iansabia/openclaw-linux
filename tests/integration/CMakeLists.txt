add_executable(test_config_load test_config_load.c)
target_link_libraries(test_config_load PRIVATE kelp-config kelp-core)
add_test(NAME integration_config_load COMMAND test_config_load)
