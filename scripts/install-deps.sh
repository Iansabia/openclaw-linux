#!/bin/bash
set -euo pipefail
# Install build dependencies on Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake pkg-config \
    libssl-dev libcjson-dev libyaml-dev \
    libcurl4-openssl-dev libmicrohttpd-dev libwebsockets-dev \
    libsqlite3-dev libavahi-client-dev \
    libncursesw5-dev libreadline-dev \
    libseccomp-dev libcap-dev libsystemd-dev \
    libvips-dev \
    live-build reprepro
echo "Dependencies installed"
