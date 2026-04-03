#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKS_DIR="${ROOT_DIR}/checks"
STATE_DIR="${ROOT_DIR}/state"
LOGS_DIR="${ROOT_DIR}/logs"
BASELINE_PATH="${STATE_DIR}/last-good.json"
LATEST_LINK="${LOGS_DIR}/latest"
VERBOSE=0
ACTION="check"

usage() {
  cat <<'EOF'
Usage: watchdog.sh [--check|--promote|--report] [--verbose]

Commands:
  --check      Run a read-only audit and compare it against the baseline.
  --promote    Run a fresh audit and promote it to last-good.json when healthy.
  --report     Print the latest available summary report.
  --verbose    Print artifact locations after a run.
EOF
}

fail() {
  printf '[watchdog] %s\n' "$*" >&2
  exit 1
}

latest_run_dir() {
  if [[ -L "${LATEST_LINK}" ]]; then
    readlink -f "${LATEST_LINK}"
  elif [[ -d "${LATEST_LINK}" ]]; then
    printf '%s\n' "${LATEST_LINK}"
  fi
}

report_latest() {
  local latest
  latest="$(latest_run_dir || true)"
  [[ -n "${latest:-}" && -f "${latest}/summary.txt" ]] || fail "No report found under ${LOGS_DIR}"
  cat "${latest}/summary.txt"
  if (( VERBOSE )); then
    printf '\nArtifacts:\n'
    printf '  %s\n' "${latest}/summary.txt"
    printf '  %s\n' "${latest}/diff.json"
    printf '  %s\n' "${latest}/detailed.log"
    printf '  %s\n' "${latest}/current.json"
  fi
}

promote_run() {
  local run_dir="$1"
  local overall
  overall="$(python3 - "${run_dir}/diff.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text())
print(data.get("overall_status", "FAIL"))
PY
)"
  [[ "${overall}" != "FAIL" ]] || fail "Refusing to promote an unhealthy audit from ${run_dir}"
  cp "${run_dir}/current.json" "${BASELINE_PATH}"
  printf '[watchdog] promoted %s to %s\n' "${run_dir}/current.json" "${BASELINE_PATH}"
}

ensure_baseline() {
  mkdir -p "${LOGS_DIR}" "${STATE_DIR}"
  [[ -f "${BASELINE_PATH}" ]] && return 0
  cat > "${BASELINE_PATH}" <<'EOF'
{
  "schema_version": 1,
  "created_at": null,
  "baseline_status": "uninitialized",
  "tools": {}
}
EOF
}

run_check() {
  ensure_baseline

  local stamp run_dir current_json summary_txt diff_json detailed_log
  stamp="$(date +%Y%m%d-%H%M%S)"
  run_dir="${LOGS_DIR}/${stamp}"
  mkdir -p "${run_dir}"

  current_json="${run_dir}/current.json"
  summary_txt="${run_dir}/summary.txt"
  diff_json="${run_dir}/diff.json"
  detailed_log="${run_dir}/detailed.log"

  {
    printf '[%s] android-tooling-watchdog start\n' "$(date --iso-8601=seconds)"
    printf 'root_dir=%s\nbaseline=%s\nrun_dir=%s\n' "${ROOT_DIR}" "${BASELINE_PATH}" "${run_dir}"
    python3 "${CHECKS_DIR}/collect_state.py" --output "${current_json}"
    python3 "${CHECKS_DIR}/compare_state.py" \
      --baseline "${BASELINE_PATH}" \
      --current "${current_json}" \
      --summary "${summary_txt}" \
      --diff "${diff_json}"
    printf '[%s] android-tooling-watchdog complete\n' "$(date --iso-8601=seconds)"
  } >> "${detailed_log}" 2>&1

  ln -sfn "${run_dir}" "${LATEST_LINK}"

  if [[ -x "${ROOT_DIR}/notify-hook.sh" ]]; then
    WATCHDOG_VERBOSE="${VERBOSE}" "${ROOT_DIR}/notify-hook.sh" "${summary_txt}" "${diff_json}" >> "${detailed_log}" 2>&1 || true
  fi

  cat "${summary_txt}"
  if (( VERBOSE )); then
    printf '\nArtifacts:\n'
    printf '  %s\n' "${summary_txt}"
    printf '  %s\n' "${diff_json}"
    printf '  %s\n' "${detailed_log}"
    printf '  %s\n' "${current_json}"
  fi
  printf 'RUN_DIR=%s\n' "${run_dir}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)
      ACTION="check"
      ;;
    --promote)
      ACTION="promote"
      ;;
    --report)
      ACTION="report"
      ;;
    --verbose)
      VERBOSE=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "Unknown argument: $1"
      ;;
  esac
  shift
done

case "${ACTION}" in
  check)
    run_check
    ;;
  promote)
    run_output="$(run_check)"
    printf '%s\n' "${run_output}"
    run_dir="$(printf '%s\n' "${run_output}" | sed -n 's/^RUN_DIR=//p' | tail -n 1)"
    [[ -n "${run_dir}" ]] || fail "Could not determine the run directory for promotion"
    promote_run "${run_dir}"
    ;;
  report)
    report_latest
    ;;
esac
