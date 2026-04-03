#!/usr/bin/env bash
set -euo pipefail

summary_path="${1:-}"
diff_path="${2:-}"
[[ -n "${summary_path}" && -f "${summary_path}" ]] || exit 0
[[ "${WATCHDOG_NOTIFY:-0}" == "1" ]] || exit 0
command -v notify-send >/dev/null 2>&1 || exit 0

overall="$(
  python3 - "${diff_path}" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
if path.is_file():
    data = json.loads(path.read_text())
    print(data.get("overall_status", "WARN"))
else:
    print("WARN")
PY
)"

case "${overall}" in
  OK) urgency="low" ;;
  WARN) urgency="normal" ;;
  *) urgency="critical" ;;
esac

notify-send -u "${urgency}" "Android Tooling Watchdog: ${overall}" "$(sed -n '1,18p' "${summary_path}")"
