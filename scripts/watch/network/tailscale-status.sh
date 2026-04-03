#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  SCRIPT:  tailscale-status.sh
#  GROUP:   32014 Security Research Group
#  PURPOSE: Parse Tailscale status for status bar
#  USAGE:   tailscale-status.sh
#  DEPENDS: tailscale, jq
# ═══════════════════════════════════════════════════════════
# WHAT THIS DOES (plain English):
#   Reads tailscale status in JSON, caches results for 15s, and prints
#   STATUS|IP|PEERS for the status bar segment. Avoids blocking UI.
# ═══════════════════════════════════════════════════════════
set -euo pipefail

TS_BIN=$(command -v tailscale 2>/dev/null || true)
CACHE="/tmp/.ts_status_cache"
CACHE_TTL=15

if [[ -f "$CACHE" ]]; then
  age=$(( $(date +%s) - $(stat -c %Y "$CACHE") ))
  if [[ $age -lt $CACHE_TTL ]]; then
    cat "$CACHE"
    exit 0
  fi
fi

if [[ -z "$TS_BIN" ]]; then
  echo "NONE||0" | tee "$CACHE" >/dev/null
  exit 0
fi

STATUS_JSON=$($TS_BIN status --json 2>/dev/null || true)
if [[ -z "$STATUS_JSON" ]]; then
  echo "DOWN||0" | tee "$CACHE" >/dev/null
  exit 0
fi

BACKEND=$(echo "$STATUS_JSON" | jq -r '.BackendState')
SELF_IP=$(echo "$STATUS_JSON" | jq -r '.Self.TailscaleIPs[0] // ""')
PEERS=$(echo "$STATUS_JSON" | jq '[.Peer[] | select(.Online==true)] | length')

case "$BACKEND" in
  Running)   echo "UP|${SELF_IP}|${PEERS}" ;;
  NeedsLogin) echo "AUTH||0" ;;
  Stopped)   echo "DOWN||0" ;;
  *)         echo "UNKNOWN||0" ;;
esac | tee "$CACHE" >/dev/null
