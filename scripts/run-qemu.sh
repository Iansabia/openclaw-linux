#!/bin/bash
# run-qemu.sh — Boot Kelp OS x86_64 image in QEMU
#
# Port forwards:
#   Host 3000 -> Guest 3000 (kelp-gateway API)
#   Host 2222 -> Guest 22   (SSH via dropbear)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KELP_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILDROOT_DIR="${KELP_ROOT}/buildroot-src"
IMAGES="${BUILDROOT_DIR}/output/images"
BZIMAGE="${IMAGES}/bzImage"
ROOTFS="${IMAGES}/rootfs.ext4"

# Check for required files
if [ ! -f "${BZIMAGE}" ]; then
    echo "ERROR: ${BZIMAGE} not found"
    echo "Run 'make os' first to build the OS image."
    exit 1
fi

if [ ! -f "${ROOTFS}" ]; then
    echo "ERROR: ${ROOTFS} not found"
    echo "Run 'make os' first to build the OS image."
    exit 1
fi

# Check for QEMU
QEMU=$(command -v qemu-system-x86_64 2>/dev/null || true)
if [ -z "${QEMU}" ]; then
    echo "ERROR: qemu-system-x86_64 not found"
    echo "Install QEMU: brew install qemu (macOS) or apt install qemu-system-x86 (Linux)"
    exit 1
fi

echo "=========================================="
echo " Kelp OS — QEMU Boot"
echo "=========================================="
echo ""
echo " Kernel:  ${BZIMAGE}"
echo " RootFS:  ${ROOTFS}"
echo ""
echo " Port forwarding:"
echo "   localhost:3000 -> guest:3000 (API)"
echo "   localhost:2222 -> guest:22   (SSH)"
echo ""
echo " Press Ctrl+A then X to exit QEMU"
echo "=========================================="
echo ""

# Create a writable copy of rootfs
ROOTFS_WORK="/tmp/kelp-rootfs.ext4"
cp "${ROOTFS}" "${ROOTFS_WORK}"

# Detect KVM support
ACCEL_OPTS=""
if [ -c /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL_OPTS="-enable-kvm -cpu host"
fi

exec ${QEMU} \
    -M pc \
    ${ACCEL_OPTS} \
    -m 1024 \
    -smp 2 \
    -kernel "${BZIMAGE}" \
    -drive "file=${ROOTFS_WORK},format=raw,if=virtio" \
    -append "root=/dev/vda rw console=ttyS0" \
    -netdev user,id=net0,hostfwd=tcp::3000-:3000,hostfwd=tcp::2222-:22 \
    -device virtio-net-pci,netdev=net0 \
    -nographic
