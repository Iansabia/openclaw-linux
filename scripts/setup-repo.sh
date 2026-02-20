#!/bin/bash
set -euo pipefail
# Set up local APT repository with reprepro
REPO_DIR="$(dirname "$0")/../distro/repo"
cd "$REPO_DIR"

# Generate GPG key if needed
if ! gpg --list-keys "Clawd Linux" &>/dev/null; then
    gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 4096
Name-Real: Clawd Linux
Name-Email: team@clawd.linux
Expire-Date: 0
%no-protection
EOF
fi

# Initialize repo
reprepro -b . export

echo "Repository initialized at $REPO_DIR"
echo "Add packages with: reprepro -b $REPO_DIR includedeb bookworm /path/to/*.deb"
