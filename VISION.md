# Kelp OS Vision

Kelp OS is an AI-first operating system with Apple-level polish.

AI should not be bolted onto an existing OS as an afterthought. It should be a first-class citizen at every layer — from the kernel up through system services to the applications you interact with daily.

## Principles

- **AI at every layer.** Kernel primitives for inference scheduling, tensor DMA, and AI IPC. System services that understand AI workloads natively. Applications that leverage AI seamlessly.
- **Consumer-grade UX.** An OS should be invisible. Setup should be a wizard, not a manual. Updates should be automatic. Everything should just work.
- **Privacy by default.** Your AI runs on your hardware, in your network, under your control. No cloud dependency for core functionality.
- **Hackable by design.** TypeScript ecosystem for rapid iteration. Open kernel module. Extensible at every layer.

## Architecture

### Kernel

The kernel module provides AI primitives that don't exist in mainline Linux:

- Zero-copy IPC optimized for AI message passing
- DMA channels for tensor data movement between devices
- CFS-integrated inference scheduling
- `/dev/kelp` device node for userspace access

### System

System daemons and libraries that make AI a first-class OS concern:

- Gateway service for session and channel management
- Configuration and state persistence
- Networking with service discovery
- Security primitives for AI workload isolation

### Ecosystem

The user-facing layer:

- CLI and gateway for local-first AI interaction
- Companion apps on macOS, iOS, Android
- 36+ channel integrations for messaging platforms
- Skills and extensions via KelpHub

## Current Focus

**Priority:**
- Kernel module stability and test coverage
- Buildroot image that boots and runs AI workloads
- Security and safe defaults

**Next:**
- GPU passthrough for inference acceleration
- Container-native AI workload management
- Expanded hardware support
- Installer and first-run experience

## Contribution Rules

- One PR = one issue/topic. Do not bundle multiple unrelated fixes/features.
- PRs over ~5,000 changed lines are reviewed only in exceptional circumstances.
- Do not open large batches of tiny PRs at once; each PR has review cost.
- For very small related fixes, grouping into one focused PR is encouraged.
