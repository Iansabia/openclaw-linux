add_executable(clawd-channel-signal src/main.c)
target_link_libraries(clawd-channel-signal PRIVATE clawd-core clawd-net clawd-config)
install(TARGETS clawd-channel-signal RUNTIME DESTINATION bin)
