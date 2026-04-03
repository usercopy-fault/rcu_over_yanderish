#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: port-delta.sh <ip_list_file>
Compares port scans over time.
USAGE
}

if [[ ${1:-} == "-h" ]]; then
  usage
  exit 0
fi

ip_file="${1:-$HOME/bounty/${BB_TARGET:-unknown}/recon/ip_list.txt}"

c() { printf "\033[38;2;%s;%s;%sm" "$1" "$2" "$3"; }
reset() { printf "\033[0m"; }

ts() { date '+[%H:%M:%S]'; }
log() { echo "$(ts) $(c 212 200 168)$*$(reset)"; }
warn() { echo "$(ts) $(c 217 95 59)$*$(reset)"; }

if [[ ! -f "$ip_file" ]]; then
  warn "IP list not found: $ip_file"
  exit 2
fi

out_dir="$HOME/bounty/${BB_TARGET:-unknown}/recon"
mkdir -p "$out_dir"

stamp=$(date '+%Y%m%d-%H%M%S')
cur="$out_dir/ports-$stamp.txt"
prev="$out_dir/ports-prev.txt"

log "Running nmap"
nmap -iL "$ip_file" --top-ports 1000 -T4 -oN "$cur" || true

if [[ -f "$prev" ]]; then
  log "Diff"
  diff -u "$prev" "$cur" || true
fi

cp "$cur" "$prev"

if [[ -x "$HOME/.config/wezterm/scripts/kde-connect/kdc-notify.sh" ]]; then
  "$HOME/.config/wezterm/scripts/kde-connect/kdc-notify.sh" "Port delta complete" || true
fi

exit 0
