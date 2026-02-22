# Kelp OS — AI-First Operating System

<p align="center">
  <strong>AI-native OS built from the ground up for AI workloads</strong>
</p>

<p align="center">
  <a href="https://github.com/Iansabia/kelp-os/actions/workflows/kelp-os-ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Iansabia/kelp-os/kelp-os-ci.yml?branch=main&style=for-the-badge" alt="CI status"></a>
  <a href="https://github.com/Iansabia/kelp-os/releases"><img src="https://img.shields.io/github/v/release/Iansabia/kelp-os?include_prereleases&style=for-the-badge" alt="GitHub release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge" alt="MIT License"></a>
</p>

---

## Overview

**Kelp OS** is an AI-first operating system. It combines a custom Linux kernel with AI primitives baked in at the lowest level, a system layer for services and IPC, and a full ecosystem of apps, extensions, and skills.

The architecture has three layers:

| Layer | Path | What it does |
|-------|------|-------------|
| **Kernel** | `kernel/` | Linux kernel module with AI IPC, tensor DMA, inference scheduling |
| **System** | `system/` | Daemons, config, networking — the OS glue |
| **Ecosystem** | `ecosystem/` | Gateway, CLI, apps (macOS/iOS/Android), extensions, skills |

## Build

### Kernel module

```bash
make kernel        # build the kelp kernel module
make kernel-test   # run kernel unit tests
```

### System layer

```bash
make system        # build system daemons and libraries
make system-test   # run system tests
```

### Full OS image (Buildroot)

```bash
cd buildroot
make kelp_qemu_x86_64_defconfig
make -j$(nproc)
```

### Boot in QEMU

```bash
qemu-system-x86_64 \
  -kernel buildroot/output/images/bzImage \
  -drive file=buildroot/output/images/rootfs.ext2,format=raw \
  -append "root=/dev/sda console=ttyS0" \
  -nographic -m 512M
```

### Ecosystem (Gateway + CLI + Apps)

Runtime: **Node >= 22**

```bash
cd ecosystem
pnpm install
pnpm build
pnpm kelp onboard --install-daemon
```

## Architecture

### Kernel AI Primitives

The kernel module (`kernel/`) provides:

- **AI IPC** — zero-copy message passing between AI processes
- **Tensor DMA** — direct memory access for tensor data movement
- **Inference scheduler** — CFS-integrated scheduling for inference workloads
- `/dev/kelp` device node for userspace AI runtime access

### System Services

The system layer (`system/`) provides:

- `kelp-gateway` — WebSocket control plane for sessions, channels, tools, events
- Configuration management and state persistence
- Networking and service discovery

### Ecosystem

The ecosystem (`ecosystem/`) includes:

- **Gateway** — local-first control plane with WebSocket API
- **CLI** — `kelp` command for gateway control, agent interaction, onboarding
- **Apps** — macOS menu bar, iOS node, Android node
- **Extensions** — 36+ channel integrations (Telegram, Slack, Discord, WhatsApp, Signal, etc.)
- **Skills** — pluggable agent capabilities via KelpHub

## API Endpoints

The gateway exposes a WebSocket API at `ws://127.0.0.1:18789`:

| Endpoint | Description |
|----------|-------------|
| `sessions.*` | Session lifecycle, history, routing |
| `agent.*` | Agent invocation, tool streaming |
| `channels.*` | Channel status, pairing, config |
| `nodes.*` | Device node control (camera, screen, voice) |
| `canvas.*` | A2UI visual workspace |

## Packaging

Debian/RPM packages for individual components:

```
packaging/
  kelp-agents/       # AI agent runtime
  kelp-daemon/       # System daemon
  kelp-gateway/      # Gateway service
  kelp-kernel/       # Kernel module
  kelp-linux/        # Meta-package
  kelp-terminal/     # Terminal UI
  libkelp-config/    # Configuration library
  libkelp-core/      # Core library
  libkelp-memory/    # Memory management
  libkelp-net/       # Networking
  libkelp-process/   # Process management
  libkelp-security/  # Security primitives
```

## Distro

A live-build configuration is available in `distro/` for creating bootable Kelp OS images.

## Project Structure

```
kelp/
  kernel/          # Linux kernel module (AI IPC, tensor DMA, scheduler)
  system/          # System daemons and libraries (C)
  ecosystem/       # Gateway, CLI, apps, extensions, skills (TypeScript)
  buildroot/       # Buildroot config for full OS image
  packaging/       # Debian/RPM package definitions
  distro/          # Live-build configuration
  docs/            # Documentation (Mintlify)
  scripts/         # Build, deploy, and helper scripts
  patches/         # Kernel and dependency patches
  cmake/           # CMake modules
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and reporting instructions.

## License

MIT — see [LICENSE](LICENSE).
