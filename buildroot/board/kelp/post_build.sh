#!/bin/sh
# post_build.sh — Kelp OS post-build hook for Buildroot
#
# Called after the target filesystem is built but before the image is created.

set -e

TARGET_DIR="$1"

# Ensure kelp log directory exists
mkdir -p "${TARGET_DIR}/var/log/kelp"

# Ensure kelp config directory exists
mkdir -p "${TARGET_DIR}/etc/kelp"

# Set hostname
echo "kelp" > "${TARGET_DIR}/etc/hostname"

echo "Kelp OS post-build complete."
