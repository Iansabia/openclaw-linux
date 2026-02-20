#!/bin/bash
set -euo pipefail
# Generate .deb packages
cd build
cpack -G DEB
echo "Packages generated in build/"
ls -la *.deb
