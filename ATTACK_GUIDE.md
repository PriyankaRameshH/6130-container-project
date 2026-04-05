# Container Escape Attack Guide

This guide documents 5 real Docker container escape attacks and how to run them manually with the eBPF detector monitoring in real time.

> **All 5 attacks are Docker container escape attacks.** They exploit different misconfigurations and privilege escalations to break out of container isolation and access the host system.

---

## Prerequisites

```bash
# Build the project
make all

# Verify Docker is available
docker --version

# Verify the detector binary exists
ls -la bin/detector
```

---

## Start the eBPF Detector

Start the detector **before** running any attacks so it can capture alerts:

```bash
sudo ./bin/detector \
    -bpf-object internal/bpf/escape_detector.bpf.o \
    -policy examples/policy.yaml
```

Keep this running in a separate terminal. All alerts will print in real time.

For JSON output, add `-json`:

```bash
sudo ./bin/detector \
    -bpf-object internal/bpf/escape_detector.bpf.o \
    -policy examples/policy.yaml \
    -json
```

---

## Attack 1 — Docker Socket Escape

**Category:** Docker Socket Escape  
**Risk:** CRITICAL  
**Technique:** Mount the Docker socket into a container, then use the Docker API to spawn a new privileged container that mounts the host root filesystem.

### Docker Command

```bash
docker run --rm -it \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$(pwd)/attacks/attack1_docker_socket.sh:/attack.sh:ro" \
    ubuntu:22.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq curl && bash /attack.sh"
```

### What It Does

1. Verifies the Docker socket (`/var/run/docker.sock`) is accessible inside the container
2. Queries the Docker API to list running containers
3. Creates a new privileged escape container with host root mounted at `/hostfs`
4. Reads host files (e.g., `/etc/hostname`) through the escape container

### Expected Detector Alerts

- `docker-socket-connect` (CRITICAL) — connect() to `/var/run/docker.sock`
- `sensitive-host-path-open` (CRITICAL) — openat() on Docker socket

---

## Attack 2 — Privileged Container Escape

**Category:** Privileged Container Escape  
**Risk:** CRITICAL  
**Technique:** Use `--privileged --pid=host` to gain full capabilities, then access host filesystem via `/proc/1/root` and use `nsenter` to join host namespaces.

### Docker Command

```bash
docker run --rm -it \
    --privileged \
    --pid=host \
    -v "$(pwd)/attacks/attack2_privileged_escape.sh:/attack.sh:ro" \
    ubuntu:22.04 \
    bash /attack.sh
```

### What It Does

1. Confirms `CAP_SYS_ADMIN` is present (container is privileged)
2. Mounts fresh procfs to access host process information
3. Reads host `/etc/shadow` via `/proc/1/root` (PID namespace escape)
4. Attempts to mount the host root block device
5. Uses `nsenter -t 1` to join host PID 1 namespaces
6. Tests write access to `/sys/fs/cgroup`

### Expected Detector Alerts

- `privileged-container-escape` (CRITICAL) — mount() and setns() syscalls
- `sensitive-host-path-open` (HIGH) — openat() on `/proc/1/root`, `/sys`, `/dev`

---

## Attack 3 — Kernel Exploit Simulation (CVE-2022-0492)

**Category:** Cgroup Release Agent Escape  
**Risk:** CRITICAL  
**Technique:** Exploit the cgroup v1 `release_agent` mechanism to execute arbitrary commands on the host as root. This is a simulation of CVE-2022-0492.

### Docker Command

```bash
docker run --rm -it \
    --privileged \
    -v "$(pwd)/attacks/attack3_cgroup_escape.sh:/attack.sh:ro" \
    ubuntu:22.04 \
    bash /attack.sh
```

### What It Does

1. Mounts the cgroup v1 memory controller at `/tmp/cgrp`
2. Creates a child cgroup (`/tmp/cgrp/escape`)
3. Enables `notify_on_release` on the child cgroup
4. Writes a command to `release_agent` (executed by the host kernel on cgroup release)
5. Triggers the release by adding and removing a process from the cgroup

> **Note:** On systems running cgroup v2 (Ubuntu 22.04+), this attack is **blocked** because `release_agent` does not exist. The mount attempt is still detected by the eBPF detector.

### Expected Detector Alerts

- `privileged-container-escape` (CRITICAL) — mount(cgroup) syscalls
- `sensitive-host-path-open` (HIGH) — openat() on `/sys/fs/cgroup`, `/proc/self/cgroup`

---

## Attack 4 — Sensitive Host Filesystem Access

**Category:** Sensitive Host Filesystem Access  
**Risk:** HIGH  
**Technique:** Mount the entire host root filesystem read-only into a container, then read sensitive files including credentials, SSH keys, system configs, and process environment variables.

### Docker Command

```bash
docker run --rm -it \
    --pid=host \
    -v /:/hostfs:ro \
    -v "$(pwd)/attacks/attack4_sensitive_fs_access.sh:/attack.sh:ro" \
    ubuntu:22.04 \
    bash /attack.sh
```

### What It Does

1. **Credential files:** Reads `/hostfs/etc/shadow`, `/hostfs/etc/passwd`, `/hostfs/etc/sudoers`
2. **SSH keys:** Probes `/hostfs/root/.ssh/authorized_keys`, `id_rsa`, `id_ed25519`
3. **System config:** Reads hostname, resolv.conf, fstab, crontab, environment
4. **Container secrets:** Probes Docker daemon config, Docker auth, Docker socket
5. **Kubernetes secrets:** Probes kubelet config, admin.conf, service account tokens
6. **Process environment:** Reads `/proc/1/environ` and enumerates host process command lines
7. **Write test:** Verifies whether the host filesystem is writable

### Expected Detector Alerts

- `sensitive-host-path-open` (HIGH) — openat() on `/etc/shadow`, SSH keys
- `sensitive-host-path-open` (MEDIUM) — openat() on `/etc/passwd`, config files, `/proc/*/environ`
- `docker-socket-open` (CRITICAL) — if Docker socket is also mounted

---

## Attack 5 — Namespace Escape Attack

**Category:** Namespace Escape Attack  
**Risk:** CRITICAL  
**Technique:** Use `nsenter` to join host PID 1's namespaces (mount, network, PID, UTS, IPC), effectively migrating the containerized process into the host's namespace context.

### Docker Command

```bash
docker run --rm -it \
    --privileged \
    --pid=host \
    -v "$(pwd)/attacks/attack5_namespace_escape.sh:/attack.sh:ro" \
    ubuntu:22.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq util-linux iproute2 && bash /attack.sh"
```

### What It Does

1. **Prerequisites:** Verifies `CAP_SYS_ADMIN` and `/proc/1/ns/` accessibility
2. **Enumeration:** Lists container vs host namespace IDs, identifies which differ
3. **Mount NS escape:** `nsenter -t 1 -m` — reads host `/etc/shadow` via host mount namespace
4. **Network NS escape:** `nsenter -t 1 -n` — lists host network interfaces
5. **PID NS escape:** `nsenter -t 1 -p` — enumerates all host processes
6. **Full escape:** `nsenter -t 1 -m -u -i -n -p` — joins ALL host namespaces, runs as root on host
7. **Arbitrary commands:** Reads host `dmesg`, lists `/root/` directory contents

### Expected Detector Alerts

- `privileged-container-escape` (CRITICAL) — setns() syscalls when joining namespaces
- `sensitive-host-path-open` (HIGH) — openat() on `/proc/1/ns/*`

---

## Run All Attacks at Once

The orchestrator script runs all 5 attacks sequentially with the detector:

```bash
sudo bash attacks/run_real_attacks.sh --attack all
```

Or run individual attacks:

```bash
sudo bash attacks/run_real_attacks.sh --attack 1   # Docker Socket Escape
sudo bash attacks/run_real_attacks.sh --attack 2   # Privileged Container Escape
sudo bash attacks/run_real_attacks.sh --attack 3   # Kernel Exploit Simulation
sudo bash attacks/run_real_attacks.sh --attack 4   # Sensitive Host FS Access
sudo bash attacks/run_real_attacks.sh --attack 5   # Namespace Escape
```

Or use Make targets:

```bash
make real-attack     # All 5 attacks
make real-attack1    # Docker Socket Escape only
make real-attack2    # Privileged Container Escape only
make real-attack3    # Kernel Exploit Simulation only
make real-attack4    # Sensitive Host FS Access only
make real-attack5    # Namespace Escape only
```

---

## Attack Summary

| # | Attack | Docker Flags | Escape Result | Detector Alert Level |
|---|--------|-------------|---------------|---------------------|
| 1 | Docker Socket Escape | `-v /var/run/docker.sock:/var/run/docker.sock` | ESCAPED | CRITICAL |
| 2 | Privileged Container Escape | `--privileged --pid=host` | ESCAPED | CRITICAL |
| 3 | Kernel Exploit (CVE-2022-0492) | `--privileged` | BLOCKED (cgroupv2) | CRITICAL |
| 4 | Sensitive Host FS Access | `-v /:/hostfs:ro --pid=host` | EXFILTRATED | HIGH/MEDIUM |
| 5 | Namespace Escape | `--privileged --pid=host` | ESCAPED | CRITICAL |

All attacks are **real Docker container escape techniques** — no simulation or mocking. They exploit actual Docker misconfigurations (excessive privileges, socket exposure, host filesystem mounts) to demonstrate how a compromised container can break out and access the host.
