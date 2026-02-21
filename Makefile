# Kelp OS — Top-level convenience Makefile
#
# Targets:
#   system   — Build all userspace (libraries + binaries)
#   kernel   — Build kelp.ko kernel module
#   os       — Build full OS image via Buildroot
#   qemu     — Boot the x86_64 OS image in QEMU
#   test     — Run all tests
#   clean    — Clean build artifacts

.PHONY: system kernel os qemu test clean help

BUILD_DIR := build

help:
	@echo "Kelp OS Build System"
	@echo "===================="
	@echo ""
	@echo "  make system   — Build userspace (CMake)"
	@echo "  make kernel   — Build kelp.ko kernel module"
	@echo "  make os       — Build full OS image (Buildroot)"
	@echo "  make qemu     — Boot x86_64 image in QEMU"
	@echo "  make test     — Run all tests"
	@echo "  make clean    — Clean build artifacts"

system:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR) -j$$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

kernel:
	$(MAKE) -C kernel/module

os:
	scripts/build-os.sh

qemu:
	scripts/run-qemu.sh

test: system
	cd $(BUILD_DIR) && ctest --output-on-failure

clean:
	rm -rf $(BUILD_DIR)
	$(MAKE) -C kernel/module clean 2>/dev/null || true
