add_executable(clawd-channel-slack src/main.c)
target_link_libraries(clawd-channel-slack PRIVATE clawd-core clawd-net clawd-config)
install(TARGETS clawd-channel-slack RUNTIME DESTINATION bin)
