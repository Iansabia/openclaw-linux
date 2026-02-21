# Clawd Kernel Module

## Description
Development skill for building, testing, and debugging the Clawd Linux kernel module (`clawd.ko`). The module provides `/dev/clawd` for userspace IPC, `/proc/clawd/` for runtime stats, and netfilter hooks for network-aware AI.

## Architecture

```
kernel/                        ← Out-of-tree kbuild module
├── clawd_mod.c                ← Module init, chardev, ring buffer
├── clawd_chardev.c            ← /dev/clawd read/write/ioctl
├── clawd_netfilter.c          ← Netfilter LOCAL_OUT hook
├── clawd_procfs.c             ← /proc/clawd/stats, /proc/clawd/netfilter
├── clawd_kernel.h             ← Shared kernel/userspace ioctl defs
├── Kbuild                     ← kbuild module definition
├── Makefile                   ← Convenience wrapper
└── dkms.conf                  ← DKMS config for kernel updates

lib/kernel/                    ← Userspace library (libclawd-kernel)
├── include/clawd/kernel.h     ← Userspace API + ioctl definitions
├── src/kernel.c               ← open/read/write/ioctl wrappers
└── CMakeLists.txt
```

## Key Files
- `kernel/clawd_kernel.h` — ioctl magic `'C'`, struct definitions shared between kernel and userspace
- `lib/kernel/include/clawd/kernel.h` — Userspace API: `clawd_kernel_open()`, `clawd_kernel_send()`, etc.
- `bin/clawd/main.c` — `clawd kernel` CLI subcommand (status/stats/load/unload)

## Build

```bash
# Build kernel module (requires linux-headers)
make -C kernel

# Build userspace library (via CMake, part of normal build)
cmake -B build && cmake --build build

# Install module via DKMS
sudo dkms add kernel/
sudo dkms build clawd-kernel/0.1.0
sudo dkms install clawd-kernel/0.1.0
```

## Test Workflow

```bash
# 1. Build the module
make -C kernel

# 2. Load the module
sudo insmod kernel/clawd.ko log_level=2 enable_netfilter=1

# 3. Verify it's loaded
lsmod | grep clawd
cat /proc/clawd/stats

# 4. Test chardev IPC
echo "hello" > /dev/clawd
cat /dev/clawd

# 5. Test via CLI
clawd kernel status
clawd kernel stats

# 6. Check netfilter events
cat /proc/clawd/netfilter

# 7. Unload
sudo rmmod clawd
```

## ioctl Interface

| Command | Direction | Struct | Description |
|---------|-----------|--------|-------------|
| `CLAWD_IOC_GET_VERSION` | Read | `clawd_kversion` | Module version + build info |
| `CLAWD_IOC_GET_STATS` | Read | `clawd_kstats` | Message counts, bytes, uptime |
| `CLAWD_IOC_SET_LOG_LEVEL` | Write | `int` | Set log verbosity (0-2) |
| `CLAWD_IOC_ENABLE_NF` | Write | `int` | Enable/disable netfilter hook |
| `CLAWD_IOC_QUERY_STATUS` | Read | `clawd_kstatus` | Netfilter state, log level, handles |

## Module Parameters

- `log_level` (int, 0644): 0=quiet, 1=info, 2=debug
- `enable_netfilter` (int, 0644): 0=off, 1=on

## Debugging

```bash
# Watch kernel messages
dmesg -w | grep clawd

# Check module info
modinfo kernel/clawd.ko

# Trace ioctl calls
strace -e ioctl clawd kernel status
```
