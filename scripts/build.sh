#!/usr/bin/env bash
set -euo pipefail
go build -ldflags "-s -w" -trimpath -o "bin/test" .
echo "  ✓ bin/test"
