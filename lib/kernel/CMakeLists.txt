# clawd-linux :: libclawd-kernel
# Userspace library for /dev/clawd IPC
# SPDX-License-Identifier: MIT

clawd_add_library(kernel)

target_link_libraries(clawd-kernel PRIVATE
    Threads::Threads
)
