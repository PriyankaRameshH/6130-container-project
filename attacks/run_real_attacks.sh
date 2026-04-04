#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# run_real_attacks.sh — Orchestrator for Real Container Escape Demos
#
# This script:
#   1. Builds the detector (if needed)
#   2. Starts the eBPF detector on the HOST
#   3. Launches REAL attack containers (not simulated syscalls)
#   4. Collects and displays detector alerts
#
# Usage:
#   sudo bash attacks/run_real_attacks.sh              # all attacks
#   sudo bash attacks/run_real_attacks.sh --attack 1   # docker socket only
#   sudo bash attacks/run_real_attacks.sh --attack 2   # privileged only
#   sudo bash attacks/run_real_attacks.sh --attack 3   # cgroup only
#   sudo bash attacks/run_real_attacks.sh --json       # JSON output
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DETECTOR="${PROJECT_DIR}/bin/detector"
POLICY="${PROJECT_DIR}/examples/policy.yaml"
BPF_OBJ="${PROJECT_DIR}/internal/bpf/escape_detector.bpf.o"
ALERT_LOG="/tmp/escape_detector_real_$$.log"

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

ATTACK_NUM="all"
JSON_FLAG=""

for arg in "$@"; do
    case "$arg" in
        --attack) shift; ATTACK_NUM="${1:-all}"; shift || true ;;
        --json) JSON_FLAG="-json" ;;
    esac
done

banner() {
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║   eBPF Container Escape Detector — REAL ATTACK DEMO      ║"
    echo "║   Launching actual container escape techniques            ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

step() { echo -e "${CYAN}[STEP]${RESET} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${RESET} $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
fail() { echo -e "${RED}[FAIL]${RESET} $*"; }

banner

# ── Preflight checks ─────────────────────────────────────────────
if [[ ${EUID} -ne 0 ]]; then
    fail "This script must run as root (sudo)."
    exit 1
fi

if ! command -v docker &>/dev/null; then
    fail "Docker is required but not found."
    exit 1
fi

# ── Build ─────────────────────────────────────────────────────────
step "Building detector..."
cd "${PROJECT_DIR}"
make all 2>&1 | sed 's/^/    /'
ok "Build succeeded."
echo ""

# ── Start detector ────────────────────────────────────────────────
step "Starting eBPF detector on host (alerts → ${ALERT_LOG})..."
"${DETECTOR}" -bpf-object "${BPF_OBJ}" -policy "${POLICY}" ${JSON_FLAG} 2>&1 | tee "${ALERT_LOG}" &
DETECTOR_PID=$!

cleanup() {
    echo ""
    step "Stopping detector (PID ${DETECTOR_PID})..."
    kill "${DETECTOR_PID}" 2>/dev/null || true
    wait "${DETECTOR_PID}" 2>/dev/null || true

    # Cleanup any leftover attack containers
    docker rm -f escape_test_container 2>/dev/null || true
    docker rm -f attack1_socket 2>/dev/null || true
    docker rm -f attack2_privileged 2>/dev/null || true
    docker rm -f attack3_cgroup 2>/dev/null || true
}
trap cleanup EXIT

sleep 2
ok "Detector running (PID ${DETECTOR_PID})."
echo ""

# ══════════════════════════════════════════════════════════════════
# ATTACK 1 — Docker Socket Escape
# ══════════════════════════════════════════════════════════════════
run_attack1() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    step "ATTACK 1 — Docker Socket Escape (real container)"
    echo -e "  Container: ubuntu with /var/run/docker.sock mounted"
    echo -e "  Technique: Use Docker API to spawn escape container"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    docker rm -f attack1_socket 2>/dev/null || true
    docker run --rm --name attack1_socket \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "${SCRIPT_DIR}/attack1_docker_socket.sh:/attack.sh:ro" \
        ubuntu:22.04 \
        bash -c "apt-get update -qq && apt-get install -y -qq curl >/dev/null 2>&1 && bash /attack.sh" \
        2>&1 | sed 's/^/    /'

    echo ""
    sleep 2
}

# ══════════════════════════════════════════════════════════════════
# ATTACK 2 — Privileged Container Escape
# ══════════════════════════════════════════════════════════════════
run_attack2() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    step "ATTACK 2 — Privileged Container Escape (real container)"
    echo -e "  Container: ubuntu --privileged --pid=host"
    echo -e "  Technique: Mount host FS, read /proc/1/root, nsenter"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    docker rm -f attack2_privileged 2>/dev/null || true
    docker run --rm --name attack2_privileged \
        --privileged \
        --pid=host \
        -v "${SCRIPT_DIR}/attack2_privileged_escape.sh:/attack.sh:ro" \
        ubuntu:22.04 \
        bash -c "apt-get update -qq && apt-get install -y -qq util-linux >/dev/null 2>&1 && bash /attack.sh" \
        2>&1 | sed 's/^/    /'

    echo ""
    sleep 2
}

# ══════════════════════════════════════════════════════════════════
# ATTACK 3 — Cgroup Release Agent Escape
# ══════════════════════════════════════════════════════════════════
run_attack3() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    step "ATTACK 3 — Cgroup Release Agent Escape (real container)"
    echo -e "  Container: ubuntu --privileged"
    echo -e "  Technique: CVE-2022-0492 cgroup release_agent abuse"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    docker rm -f attack3_cgroup 2>/dev/null || true
    docker run --rm --name attack3_cgroup \
        --privileged \
        -v "${SCRIPT_DIR}/attack3_cgroup_escape.sh:/attack.sh:ro" \
        ubuntu:22.04 \
        bash /attack.sh \
        2>&1 | sed 's/^/    /'

    echo ""
    sleep 2
}

# ══════════════════════════════════════════════════════════════════
# ATTACK 4 — Sensitive Host Filesystem Access
# ══════════════════════════════════════════════════════════════════
run_attack4() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    step "ATTACK 4 — Sensitive Host Filesystem Access (real container)"
    echo -e "  Container: ubuntu with host / mounted read-only at /hostfs"
    echo -e "  Technique: Read credentials, SSH keys, secrets from host FS"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    docker rm -f attack4_sensitive_fs 2>/dev/null || true
    docker run --rm --name attack4_sensitive_fs \
        --pid=host \
        -v /:/hostfs:ro \
        -v "${SCRIPT_DIR}/attack4_sensitive_fs_access.sh:/attack.sh:ro" \
        ubuntu:22.04 \
        bash /attack.sh \
        2>&1 | sed 's/^/    /'

    echo ""
    sleep 2
}

# ══════════════════════════════════════════════════════════════════
# ATTACK 5 — Namespace Escape Attack
# ══════════════════════════════════════════════════════════════════
run_attack5() {
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    step "ATTACK 5 — Namespace Escape Attack (real container)"
    echo -e "  Container: ubuntu --privileged --pid=host"
    echo -e "  Technique: setns() to migrate into host mount/net/pid/uts/ipc NS"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

    docker rm -f attack5_namespace 2>/dev/null || true
    docker run --rm --name attack5_namespace \
        --privileged \
        --pid=host \
        -v "${SCRIPT_DIR}/attack5_namespace_escape.sh:/attack.sh:ro" \
        ubuntu:22.04 \
        bash -c "apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq util-linux iproute2 >/dev/null 2>&1 && bash /attack.sh" \
        2>&1 | sed 's/^/    /'

    echo ""
    sleep 2
}

# ── Run selected attacks ─────────────────────────────────────────
case "$ATTACK_NUM" in
    1) run_attack1 ;;
    2) run_attack2 ;;
    3) run_attack3 ;;
    4) run_attack4 ;;
    5) run_attack5 ;;
    all)
        run_attack1
        run_attack2
        run_attack3
        run_attack4
        run_attack5
        ;;
    *)
        fail "Unknown attack number: $ATTACK_NUM (use 1, 2, 3, or all)"
        exit 1
        ;;
esac

# ── Print collected alerts ────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
step "DETECTOR ALERTS CAPTURED:"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
if [ -f "${ALERT_LOG}" ]; then
    ALERT_COUNT=$(grep -c -E "CRITICAL|HIGH|MEDIUM|LOW" "${ALERT_LOG}" 2>/dev/null || echo 0)
    echo -e "${RED}  Total alerts: ${ALERT_COUNT}${RESET}"
    echo ""
    grep -E "CRITICAL|HIGH|MEDIUM|LOW" "${ALERT_LOG}" 2>/dev/null | head -50 || echo "  (no alerts captured)"
fi
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

ok "Real attack demo complete."
