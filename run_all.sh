#!/bin/bash
# Resolve the scanner relative to this script; keep targets relative to the caller.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [ "$#" -eq 0 ]; then set -- .; fi
exec python3 "$SCRIPT_DIR/scan_docker.py" "$@"
