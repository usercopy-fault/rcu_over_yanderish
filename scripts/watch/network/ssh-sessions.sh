#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  SCRIPT:  ssh-sessions.sh
#  GROUP:   32014 Security Research Group
#  PURPOSE: List active SSH sessions
#  USAGE:   ssh-sessions.sh
#  DEPENDS: wezterm, ps
# ═══════════════════════════════════════════════════════════
# WHAT THIS DOES (plain English):
#   Lists ssh/sshuttle processes and prints a vintage-style receipt so
#   you can see active connections across panes quickly.
# ═══════════════════════════════════════════════════════════
set -euo pipefail

cat <<EOF2
══════════════════════════════════════════════════
 ACTIVE SSH CONNECTIONS :: $(date)
══════════════════════════════════════════════════
EOF2

ps -eo pid,etime,cmd | grep -E 'ssh |sshuttle' | grep -v grep | while read -r line; do
  echo "  $line"
done

if [ -f /tmp/.sshuttle_active ]; then
  echo "══════════════════════════════════════════════════"
  echo "  TUNNEL ACTIVE: $(cat /tmp/.sshuttle_active)"
fi
