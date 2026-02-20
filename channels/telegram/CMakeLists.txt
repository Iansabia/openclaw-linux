add_executable(clawd-channel-telegram src/main.c)
target_link_libraries(clawd-channel-telegram PRIVATE clawd-core clawd-net clawd-config)
install(TARGETS clawd-channel-telegram RUNTIME DESTINATION bin)
