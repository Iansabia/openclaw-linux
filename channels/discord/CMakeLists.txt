add_executable(clawd-channel-discord src/main.c)
target_link_libraries(clawd-channel-discord PRIVATE clawd-core clawd-net clawd-config)
install(TARGETS clawd-channel-discord RUNTIME DESTINATION bin)
