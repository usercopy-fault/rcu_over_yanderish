#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  SCRIPT:  tailscale-fleet.sh
#  GROUP:   32014 Security Research Group
#  PURPOSE: Interactive Tailscale peer picker
#  USAGE:   tailscale-fleet.sh
#  DEPENDS: tailscale, jq, fzf, ssh, ping, scp
# ═══════════════════════════════════════════════════════════
# WHAT THIS DOES (plain English):
#   Shows all Tailscale peers, lets you pick one, and provides quick
#   actions like SSH, ping, copy IP, set target, or remote command.
# ═══════════════════════════════════════════════════════════
set -euo pipefail

STATUS=$(tailscale status --json 2>/dev/null || true)
if [ -z "$STATUS" ]; then
  echo "tailscale not available"
  exit 1
fi

TMP="/tmp/ts-fleet-$(date +%s).txt"

echo "$STATUS" | jq -r '.Peer | to_entries[] | [.value.HostName, .value.TailscaleIPs[0], .value.OS, (if .value.Online then "✓" else "-" end), (.value.LastSeen // "-")] | @tsv' > "$TMP"

choice=$(column -t -s $'\t' "$TMP" | fzf --prompt="TS> " || true)
if [ -z "$choice" ]; then
  exit 0
fi

name=$(echo "$choice" | awk '{print $1}')
ip=$(echo "$choice" | awk '{print $2}')

read -r -p "Action [S]SH [P]ing [C]opy [T]arget [R]cmd [F]ile: " act
case "$act" in
  S|s) ssh "$ip" ;;
  P|p) ping -c 4 "$ip" ;;
  C|c) printf '%s' "$ip" | xclip -selection clipboard ;;
  T|t) echo "$ip" > "$HOME/.bb_target_current" ;;
  R|r) read -r -p "Command: " cmd; ssh "$ip" "$cmd" ;;
  F|f) read -r -p "Local file: " lf; scp "$lf" "$ip":~/ ;;
  *) exit 0 ;;
esac
