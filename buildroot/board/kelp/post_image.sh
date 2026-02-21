#!/bin/sh
# post_image.sh — Kelp OS post-image hook for Buildroot
#
# Called after images are generated. Creates bootable disk image.

set -e

BOARD_DIR="$(dirname "$0")"
GENIMAGE_CFG="${BOARD_DIR}/genimage.cfg"
GENIMAGE_TMP="${BUILD_DIR}/genimage.tmp"

rm -rf "${GENIMAGE_TMP}"

genimage \
    --rootpath "${TARGET_DIR}" \
    --tmppath "${GENIMAGE_TMP}" \
    --inputpath "${BINARIES_DIR}" \
    --outputpath "${BINARIES_DIR}" \
    --config "${GENIMAGE_CFG}"

echo "Kelp OS image generation complete."
echo "  bzImage:     ${BINARIES_DIR}/bzImage"
echo "  rootfs.ext4: ${BINARIES_DIR}/rootfs.ext4"
