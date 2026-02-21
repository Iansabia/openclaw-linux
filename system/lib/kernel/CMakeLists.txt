# kelp-linux :: libkelp-kernel
# Userspace library for /dev/kelp IPC
# SPDX-License-Identifier: MIT

kelp_add_library(kernel)

target_link_libraries(kelp-kernel PRIVATE
    Threads::Threads
)
