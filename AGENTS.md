# Repository Guidelines

- Repo: https://github.com/Iansabia/kelp-os

## Project Structure

```
kelp/
  kernel/          # Linux kernel module (AI IPC, tensor DMA, scheduler)
  system/          # System daemons and libraries (C)
  buildroot/       # Buildroot config for full OS image
  packaging/       # Debian/RPM package definitions
  distro/          # Live-build configuration
  tests/           # Integration and e2e tests (C)
  cmake/           # CMake modules
  scripts/         # Build and helper scripts
  patches/         # Kernel and dependency patches
  vendor/          # Vendored dependencies
```

## Build Commands

- Build system layer: `make system`
- Build kernel module: `make kernel`
- Run system tests: `make system-test`
- Run kernel tests: `make kernel-test`
- Clean build: `make clean`
- Full OS image: `cd buildroot && make kelp_qemu_x86_64_defconfig && make`

## Coding Style

- Language: C (kernel and system layers)
- Follow Linux kernel coding style for kernel module code
- Use CMake for build system
- Tests live in `tests/` (integration and e2e)

## Commit Guidelines

- Create focused commits (one logical change per commit)
- Follow concise, action-oriented commit messages (e.g., `kernel: add tensor DMA channel`)
- One PR = one issue/topic

## Naming

- Use **Kelp OS** for product/docs headings
- Use `kelp` for binary names, paths, config keys
- Prefix kernel symbols with `kelp_`
- Prefix library names with `libkelp-`
