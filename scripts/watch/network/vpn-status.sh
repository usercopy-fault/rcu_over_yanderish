#!/usr/bin/env bash
# @32014SRG
# Usage: vpn-status.sh
set -euo pipefail

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  echo "Usage: vpn-status.sh"; exit 0
fi

if ip link show tun0 >/dev/null 2>&1; then
  echo "UP"; exit 0
fi
if ip link show wg0 >/dev/null 2>&1; then
  echo "UP"; exit 0
fi
echo "DOWN"
