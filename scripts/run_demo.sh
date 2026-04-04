#!/usr/bin/env bash
# run_demo.sh — Full end-to-end container escape detection demo.
#
# Usage:
#   sudo bash scripts/run_demo.sh            # text alerts
#   sudo bash scripts/run_demo.sh --json     # JSON alert output
#
# What it does:
#   1. (Re)builds eBPF probe and C runtime binaries.
#   2. Starts the detector in the background (JSON or text mode).
#   3. Waits 2 s for BPF programs to attach.
#   4. Runs the attack simulator to trigger every detection rule.
#   5. Flushes and prints all captured alerts.
#   6. Sends SIGTERM to the detector and exits.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DETECTOR="${PROJECT_DIR}/bin/detector"
SIMULATOR="${PROJECT_DIR}/bin/simulate_attack"
POLICY="${PROJECT_DIR}/examples/policy.yaml"
BPF_OBJ="${PROJECT_DIR}/internal/bpf/escape_detector.bpf.o"
ALERT_LOG="/tmp/escape_detector_alerts_$$.log"
JSON_MODE=false

if [[ "${1:-}" == "--json" ]]; then
    JSON_MODE=true
fi

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

banner() {
    echo -e "${RED}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║       eBPF Container Escape Detector — DEMO         ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

step() { echo -e "${CYAN}[STEP]${RESET} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }

banner

# ── 1. Ensure running as root ───────────────────────────────────────
if [[ ${EUID} -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must run as root (sudo).${RESET}"
    exit 1
fi

# ── 2. Build ─────────────────────────────────────────────────────────
step "Building eBPF probe and C runtime ..."
cd "${PROJECT_DIR}"
make all 2>&1 | sed 's/^/    /'
ok "Build succeeded."

# ── 3. Build attack simulator ─────────────────────────────────────────
step "Building attack simulator ..."
gcc -O2 -Wall scripts/simulate_attack.c -o "${SIMULATOR}"
ok "Simulator built: ${SIMULATOR}"

# ── 4. Start detector in background ──────────────────────────────────
step "Starting detector (logs → ${ALERT_LOG}) ..."
DETECTOR_ARGS=(-bpf-object "${BPF_OBJ}" -policy "${POLICY}")
if $JSON_MODE; then
    DETECTOR_ARGS+=(-json)
fi

"${DETECTOR}" "${DETECTOR_ARGS[@]}" 2>&1 | tee "${ALERT_LOG}" &
DETECTOR_PID=$!

cleanup() {
    kill "${DETECTOR_PID}" 2>/dev/null || true
    wait "${DETECTOR_PID}" 2>/dev/null || true
}
trap cleanup EXIT

# ── 5. Give BPF programs time to attach ──────────────────────────────
step "Waiting 2 s for BPF tracepoints to attach ..."
sleep 2
ok "Detector running (PID ${DETECTOR_PID})."

# ── 6. Run attack simulator ───────────────────────────────────────────
echo ""
step "Launching attack simulator ..."
echo "──────────────────────────────────────────────────────"
"${SIMULATOR}"
echo "──────────────────────────────────────────────────────"
sleep 1

# ── 7. Print captured alerts ──────────────────────────────────────────
echo ""
step "Captured alerts from detector:"
echo "══════════════════════════════════════════════════════"
grep -v "^detector" "${ALERT_LOG}" || true
echo "══════════════════════════════════════════════════════"

ok "Demo complete. Stopping detector ..."
