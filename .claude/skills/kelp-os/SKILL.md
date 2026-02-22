# Kelp Kernel Module

## Description
Development skill for building, testing, and debugging the Kelp Linux kernel module (`kelp.ko`). The module provides `/dev/kelp` for userspace IPC, `/proc/kelp/` for runtime stats, and netfilter hooks for network-aware AI.

## Architecture

```
kernel/                        ← Out-of-tree kbuild module
├── kelp_mod.c                ← Module init, chardev, ring buffer
├── kelp_chardev.c            ← /dev/kelp read/write/ioctl
├── kelp_netfilter.c          ← Netfilter LOCAL_OUT hook
├── kelp_procfs.c             ← /proc/kelp/stats, /proc/kelp/netfilter
├── kelp_kernel.h             ← Shared kernel/userspace ioctl defs
├── Kbuild                     ← kbuild module definition
├── Makefile                   ← Convenience wrapper
└── dkms.conf                  ← DKMS config for kernel updates

lib/kernel/                    ← Userspace library (libkelp-kernel)
├── include/kelp/kernel.h     ← Userspace API + ioctl definitions
├── src/kernel.c               ← open/read/write/ioctl wrappers
└── CMakeLists.txt
```

## Key Files
- `kernel/kelp_kernel.h` — ioctl magic `'C'`, struct definitions shared between kernel and userspace
- `lib/kernel/include/kelp/kernel.h` — Userspace API: `kelp_kernel_open()`, `kelp_kernel_send()`, etc.
- `bin/kelp/main.c` — `kelp kernel` CLI subcommand (status/stats/load/unload)

## Build

```bash
# Build kernel module (requires linux-headers)
make -C kernel

# Build userspace library (via CMake, part of normal build)
cmake -B build && cmake --build build

# Install module via DKMS
sudo dkms add kernel/
sudo dkms build kelp-kernel/0.1.0
sudo dkms install kelp-kernel/0.1.0
```

## Test Workflow

```bash
# 1. Build the module
make -C kernel

# 2. Load the module
sudo insmod kernel/kelp.ko log_level=2 enable_netfilter=1

# 3. Verify it's loaded
lsmod | grep kelp
cat /proc/kelp/stats

# 4. Test chardev IPC
echo "hello" > /dev/kelp
cat /dev/kelp

# 5. Test via CLI
kelp kernel status
kelp kernel stats

# 6. Check netfilter events
cat /proc/kelp/netfilter

# 7. Unload
sudo rmmod kelp
```

## ioctl Interface

| Command | Direction | Struct | Description |
|---------|-----------|--------|-------------|
| `KELP_IOC_GET_VERSION` | Read | `kelp_kversion` | Module version + build info |
| `KELP_IOC_GET_STATS` | Read | `kelp_kstats` | Message counts, bytes, uptime |
| `KELP_IOC_SET_LOG_LEVEL` | Write | `int` | Set log verbosity (0-2) |
| `KELP_IOC_ENABLE_NF` | Write | `int` | Enable/disable netfilter hook |
| `KELP_IOC_QUERY_STATUS` | Read | `kelp_kstatus` | Netfilter state, log level, handles |

## Module Parameters

- `log_level` (int, 0644): 0=quiet, 1=info, 2=debug
- `enable_netfilter` (int, 0644): 0=off, 1=on

## Debugging

```bash
# Watch kernel messages
dmesg -w | grep kelp

# Check module info
modinfo kernel/kelp.ko

# Trace ioctl calls
strace -e ioctl kelp kernel status
```
