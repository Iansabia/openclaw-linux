#!/bin/bash
set -euo pipefail
# Run all tests
cd build
ctest --output-on-failure
echo "All tests passed"
