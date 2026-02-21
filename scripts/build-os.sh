#!/bin/bash
# build-os.sh — Build Kelp OS image using Buildroot
#
# Downloads Buildroot if needed, configures with BR2_EXTERNAL,
# and builds the full OS image.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KELP_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUILDROOT_VERSION="2024.02"
BUILDROOT_URL="https://buildroot.org/downloads/buildroot-${BUILDROOT_VERSION}.tar.gz"
BUILDROOT_DIR="${KELP_ROOT}/buildroot-src"
BR2_EXTERNAL="${KELP_ROOT}/buildroot"

ARCH="${1:-x86_64}"

echo "=========================================="
echo " Kelp OS Image Builder"
echo "=========================================="
echo " Architecture: ${ARCH}"
echo " Buildroot:    ${BUILDROOT_VERSION}"
echo ""

# Download Buildroot if needed
if [ ! -d "${BUILDROOT_DIR}" ]; then
    echo "Downloading Buildroot ${BUILDROOT_VERSION}..."
    TARBALL="/tmp/buildroot-${BUILDROOT_VERSION}.tar.gz"
    if [ ! -f "${TARBALL}" ]; then
        curl -L -o "${TARBALL}" "${BUILDROOT_URL}"
    fi
    echo "Extracting..."
    tar xzf "${TARBALL}" -C "${KELP_ROOT}"
    mv "${KELP_ROOT}/buildroot-${BUILDROOT_VERSION}" "${BUILDROOT_DIR}"
    echo "Buildroot extracted to ${BUILDROOT_DIR}"
fi

cd "${BUILDROOT_DIR}"

# Select defconfig based on architecture
case "${ARCH}" in
    x86_64|x86)
        DEFCONFIG="kelp_x86_64_defconfig"
        ;;
    aarch64|arm64)
        DEFCONFIG="kelp_aarch64_defconfig"
        ;;
    *)
        echo "ERROR: Unsupported architecture: ${ARCH}"
        echo "Supported: x86_64, aarch64"
        exit 1
        ;;
esac

echo "Configuring with ${DEFCONFIG}..."
make BR2_EXTERNAL="${BR2_EXTERNAL}" "${DEFCONFIG}"

echo "Building Kelp OS image (this will take a while)..."
make BR2_EXTERNAL="${BR2_EXTERNAL}" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

echo ""
echo "=========================================="
echo " Build complete!"
echo "=========================================="
echo ""
echo " Images:"
ls -lh output/images/ 2>/dev/null || echo "  (check output/images/)"
echo ""
echo " Boot with: make qemu"
