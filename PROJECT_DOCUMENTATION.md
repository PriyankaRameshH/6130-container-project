# eBPF Container Escape Detector — Project Documentation

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Data Flow](#data-flow)
4. [BPF Kernel Program — `escape_detector.bpf.c`](#bpf-kernel-program)
5. [User-Space Detector — `detector.c`](#user-space-detector)
6. [Attack Scripts](#attack-scripts)
7. [What Triggers an Alert](#what-triggers-an-alert)
8. [Detection Order and Why It Matters](#detection-order-and-why-it-matters)
9. [Build System and Deployment](#build-system-and-deployment)
10. [File Inventory](#file-inventory)

---

## Project Overview

This project is a **real-time container escape detection system** built with **eBPF** (extended Berkeley Packet Filter). It monitors Linux syscalls at the kernel level to detect when a containerized process attempts to break out of its isolation boundary.

The system has two halves:

| Component | Language | Runs In | Purpose |
|-----------|----------|---------|---------|
| `escape_detector.bpf.c` | C (BPF) | Linux kernel | Hooks 4 syscall tracepoints, captures event data, sends to ring buffer |
| `detector.c` | C (user-space) | User-space | Polls ring buffer, enriches events with container metadata, runs 5 attack detectors, prints alerts |

The detector identifies **5 classes of container escape attacks**:

| # | Attack | Severity |
|---|--------|----------|
| 1 | Docker Socket Escape | CRITICAL |
| 2 | Privileged Container Escape | CRITICAL |
| 3 | Cgroup Release Agent Escape (CVE-2022-0492) | CRITICAL |
| 4 | Sensitive Host Filesystem Access | HIGH |
| 5 | Namespace Escape (nsenter) | CRITICAL |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         LINUX KERNEL                                │
│                                                                     │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │           escape_detector.bpf.c  (eBPF programs)            │  │
│   │                                                              │  │
│   │  Tracepoints:                                                │  │
│   │    sys_enter_mount ──┐                                       │  │
│   │    sys_enter_setns ──┤                                       │  │
│   │    sys_enter_openat ─┼──► fill_common() ──► Ring Buffer      │  │
│   │    sys_enter_connect─┘    (CO-RE reads)     (16 MB)          │  │
│   │                                                              │  │
│   │  Maps:                                                       │  │
│   │    events       → BPF_MAP_TYPE_RINGBUF (event transport)     │  │
│   │    detector_pid → BPF_MAP_TYPE_ARRAY   (self-filter)         │  │
│   └──────────────────────────────────────────────────────────────┘  │
│                              │                                      │
└──────────────────────────────┼──────────────────────────────────────┘
                               │ ring_buffer__poll(250ms)
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         USER-SPACE                                   │
│                                                                      │
│   ┌──────────────────────────────────────────────────────────────┐   │
│   │                  detector.c                                  │   │
│   │                                                              │   │
│   │  handle_rb_event()                                           │   │
│   │       │                                                      │   │
│   │       ▼                                                      │   │
│   │  evaluate_event()                                            │   │
│   │       │                                                      │   │
│   │       ├─ enrich_metadata()       ◄── /proc/<pid>/cgroup      │   │
│   │       │   ├─ extract_container_id()                          │   │
│   │       │   ├─ infer_runtime()                                 │   │
│   │       │   └─ is_containerized_by_mntns()                     │   │
│   │       │                                                      │   │
│   │       ├─ Container gate (skip if not containerized)          │   │
│   │       ├─ Noise filter  (skip known host processes)           │   │
│   │       │                                                      │   │
│   │       ├─ detect_docker_socket_escape()   ──► print_alert()   │   │
│   │       ├─ detect_cgroup_escape()          ──► print_alert()   │   │
│   │       ├─ detect_namespace_escape()       ──► print_alert()   │   │
│   │       ├─ detect_privileged_escape()      ──► print_alert()   │   │
│   │       └─ detect_sensitive_fs_access()    ──► print_alert()   │   │
│   └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                    ┌─────────┴─────────┐                             │
│                    │                   │                              │
│              Text Output          JSON Output                        │
│           (human-readable)       (structured)                        │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

This is the end-to-end journey of a single syscall from a container process to a printed alert:

1. **Container process** calls a syscall (e.g., `mount()`, `openat()`, `connect()`, `setns()`)
2. **Kernel tracepoint** fires at syscall entry
3. **BPF handler** (e.g., `trace_enter_mount`) runs:
   - `is_self()` checks if the calling process is the detector itself — if so, skip
   - `bpf_ringbuf_reserve()` allocates a slot in the ring buffer
   - `fill_common()` populates PID, UID, mntns, capabilities, comm, cgroup_id using **CO-RE** reads from `task_struct`
   - Syscall-specific fields are read (path, flags, socket family, etc.)
   - `bpf_ringbuf_submit()` sends the event to user-space
4. **User-space** `ring_buffer__poll()` wakes up and calls `handle_rb_event()`
5. `handle_rb_event()` does a quick self-PID check, then calls `evaluate_event()`
6. `evaluate_event()`:
   - Checks **mntns** from BPF data against host mntns (fast container check)
   - Calls `enrich_metadata()` to read `/proc/<pid>/cgroup` for container ID and runtime
   - **Container gate**: skips if the process is not containerized
   - **Noise filter**: skips known host system processes (systemd, dockerd, runc, etc.)
   - Runs **5 attack detectors** in order — first match wins, returns immediately
7. If a detector matches, `print_alert()` outputs the alert in text or JSON format

---

## BPF Kernel Program

**File:** `internal/bpf/escape_detector.bpf.c` (203 lines)

This program runs inside the Linux kernel. It is compiled with `clang -target bpf` and loaded by the user-space detector via libbpf.

### CO-RE Struct Definitions

```c
struct ns_common   { unsigned int inum; };
struct mnt_namespace { struct ns_common ns; };
struct nsproxy      { struct mnt_namespace *mnt_ns; };
struct kernel_cap_struct { __u64 val; };
struct cred         { kernel_cap_t cap_effective; };
struct task_struct  { struct nsproxy *nsproxy; const struct cred *cred; };
```

These are **CO-RE** (Compile Once – Run Everywhere) stubs with `__attribute__((preserve_access_index))`. They let the BPF program read fields from the kernel's `task_struct` without needing exact kernel headers. The BPF loader rewrites field offsets at load time to match the running kernel.

Two fields are read via CO-RE:
- **`task->nsproxy->mnt_ns->ns.inum`** — The mount namespace ID. If this differs from PID 1's mntns, the process is in a container.
- **`task->cred->cap_effective.val`** — The effective capability bitmask. Bit 21 = `CAP_SYS_ADMIN`, which indicates a `--privileged` container.

### BPF Maps

| Map | Type | Size | Purpose |
|-----|------|------|---------|
| `events` | `BPF_MAP_TYPE_RINGBUF` | 16 MB (`1 << 24`) | Transports `struct event` from kernel to user-space |
| `detector_pid` | `BPF_MAP_TYPE_ARRAY` | 1 entry | Stores the detector's own PID so the kernel skips its syscalls |

### BPF Helper Functions

#### `is_self()`
```c
static __always_inline int is_self(void)
```
Looks up the detector's PID from the `detector_pid` map. If the current process is the detector, returns 1 (skip this event). This prevents an **infinite feedback loop** — the detector reads `/proc` files which trigger `openat` tracepoints, which would generate more events, which the detector reads, and so on.

#### `fill_common()`
```c
static __always_inline void fill_common(struct event *e, __u32 event_type)
```
Populates the shared fields of every event:
- `bpf_ktime_get_ns()` → timestamp
- `bpf_get_current_pid_tgid()` → PID and TGID
- `bpf_get_current_uid_gid()` → UID and GID
- `bpf_get_current_cgroup_id()` → cgroup ID
- `bpf_get_current_comm()` → process name (16 chars)
- `BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum)` → mount namespace ID
- `BPF_CORE_READ(task, cred, cap_effective.val)` → effective capabilities

### Tracepoint Handlers

Each handler follows the same pattern: check `is_self()` → reserve ring buffer slot → `fill_common()` → read syscall-specific args → submit.

#### `trace_enter_mount` — `SEC("tracepoint/syscalls/sys_enter_mount")`
Captures the `mount()` syscall. Reads:
- `args[0]` → source device/filesystem (stored in `path`)
- `args[1]` → mount point (stored in `extra`)
- `args[3]` → mount flags

Triggers for: privileged container mounts, cgroup filesystem mounts.

#### `trace_enter_setns` — `SEC("tracepoint/syscalls/sys_enter_setns")`
Captures the `setns()` syscall used to join a different namespace. Reads:
- `args[0]` → file descriptor
- `args[1]` → namespace type flags (CLONE_NEWNET, CLONE_NEWNS, etc.)

Triggers for: namespace escape via nsenter, privileged container setns.

#### `trace_enter_openat` — `SEC("tracepoint/syscalls/sys_enter_openat")`
Captures file opens. Reads:
- `args[0]` → directory file descriptor
- `args[1]` → file path (stored in `path`)
- `args[2]` → open flags

Triggers for: Docker socket access, host file reads, cgroup release_agent access, namespace probing.

#### `trace_enter_connect` — `SEC("tracepoint/syscalls/sys_enter_connect")`
Captures socket connections. Reads:
- `args[0]` → socket file descriptor
- `args[1]` → sockaddr struct → extracts `sun_family` and `sun_path` for AF_UNIX sockets

Triggers for: Docker socket connection via `connect()`.

---

## User-Space Detector

**File:** `cmd/detector/detector.c` (~690 lines)

### Data Structures

#### `struct event`
Shared between BPF and user-space. Contains all captured syscall data:

| Field | Type | Source |
|-------|------|--------|
| `ts_ns` | `uint64_t` | `bpf_ktime_get_ns()` |
| `pid` | `uint32_t` | Low 32 bits of pid_tgid (thread ID) |
| `tgid` | `uint32_t` | High 32 bits of pid_tgid (process ID) |
| `uid`, `gid` | `uint32_t` | User/group ID |
| `mntns` | `uint32_t` | Mount namespace inode (CO-RE) |
| `event_type` | `uint32_t` | `EVT_MOUNT`, `EVT_OPENAT`, `EVT_CONNECT`, or `EVT_SETNS` |
| `fd` | `int32_t` | File descriptor argument |
| `flags` | `uint32_t` | Syscall flags |
| `family` | `uint32_t` | Socket address family |
| `cgroup_id` | `uint64_t` | Cgroup ID |
| `cap_eff` | `uint64_t` | Effective capabilities bitmask (CO-RE) |
| `comm` | `char[16]` | Process name |
| `path` | `char[128]` | Primary path argument |
| `extra` | `char[128]` | Secondary path (mount target) |

#### `struct metadata`
Enriched container context derived from `/proc`:

| Field | Type | Purpose |
|-------|------|---------|
| `containerized` | `bool` | Whether the process is inside a container |
| `cap_sys_admin` | `bool` | Whether bit 21 of `cap_eff` is set |
| `runtime` | `char[24]` | Container runtime: "docker", "containerd", "cri-o", "podman" |
| `container_id` | `char[65]` | Full 64-char or short 12-char container ID |

### Global State

| Variable | Purpose |
|----------|---------|
| `stop` | Volatile signal flag — set to 1 by SIGINT/SIGTERM handler |
| `json_output` | `-json` CLI flag for structured output |
| `self_tgid` | Detector's own PID — used to skip self-generated events |
| `host_mntns` | PID 1's mount namespace ID — baseline for container detection |

### Utility Functions

#### `is_noise_comm(const char *comm)`
Compares the process name against a hardcoded allowlist of known host-side system processes. Returns `true` if the process should be ignored. The list includes:
- systemd and its child services (journald, resolved, udevd, etc.)
- Docker/container infrastructure (dockerd, containerd, containerd-shim)
- Container setup processes (runc, runc:[*)
- System daemons (snapd, MemoryPoller, FSBroker)

#### `extract_container_id(const char *text, char *out, size_t out_len)`
Scans a cgroup text blob for hex strings. Extracts:
- 64-char hex string → full container ID
- 12+ char hex string → short container ID (fallback)

Docker cgroup paths look like: `0::/system.slice/docker-<64-hex-chars>.scope`

#### `infer_runtime(const char *cg, char *runtime, size_t len)`
Pattern-matches the cgroup text to determine the container runtime:
- Contains "docker" → `docker`
- Contains "containerd" → `containerd`
- Contains "crio" → `cri-o`
- Contains "libpod" → `podman`

#### `get_host_mntns()`
Reads the symlink at `/proc/1/ns/mnt` to get the host's mount namespace inode number. Called once at startup. All container processes have a *different* mntns than PID 1.

#### `is_containerized_by_mntns(uint32_t pid)`
Reads `/proc/<pid>/ns/mnt` and compares it against `host_mntns`. If different, the process is in a container. This is a fallback when cgroup-based detection fails (e.g., short-lived processes).

### Metadata Enrichment

#### `enrich_metadata(uint32_t pid, const struct event *ev)`
The core function that determines if an event came from a container. It performs these steps:

1. **Read `/proc/<pid>/cgroup`** — looks for Docker/containerd/kubepods/crio/libpod markers
2. **Extract container ID** — scans cgroup blob for hex strings (64-char or 12-char)
3. **Infer runtime** — pattern match on cgroup text
4. **mntns fallback** — if cgroup check failed (process already exited), compare mount namespaces
5. **Placeholder ID** — if containerized but no ID found, set "unknown" so the event isn't dropped
6. **CAP_SYS_ADMIN check** — read bit 21 from the BPF-captured `cap_eff` field

### Alert Output

#### `print_alert(ev, meta, severity, attack, rule, message)`
Formats and prints a detection alert. Two output modes:

**Text mode** (default):
```
[2025-01-15T10:30:45Z] CRITICAL [DOCKER-SOCKET-ESCAPE] rule=docker-socket-connect event=connect pid=12345 comm=curl path=/var/run/docker.sock container=a1b2c3d4e5f6 msg=Container process connected to Docker socket
```

**JSON mode** (`-json` flag):
```json
{"timestamp":"2025-01-15T10:30:45Z","severity":"CRITICAL","attack":"DOCKER-SOCKET-ESCAPE","rule":"docker-socket-connect","event":"connect","pid":12345,"comm":"curl","path":"/var/run/docker.sock","container":"a1b2c3d4e5f6","runtime":"docker","cap_sys_admin":false,"message":"Container process connected to Docker socket"}
```

### Detection Functions

Each detector receives the event and enriched metadata. Returns `true` if matched (stops further evaluation), `false` if no match.

---

#### `detect_docker_socket_escape(ev, meta)` — Attack 1

**What it detects:** A container process accessing the Docker daemon socket, which allows full control over the host's Docker engine (create privileged containers, exec into other containers, etc.).

**Trigger conditions:**
| Syscall | Condition | Rule | Severity |
|---------|-----------|------|----------|
| `connect()` | `family == AF_UNIX` AND path is `/var/run/docker.sock` or `/run/docker.sock` | `docker-socket-connect` | CRITICAL |
| `openat()` | Path is `/var/run/docker.sock` or `/run/docker.sock` | `docker-socket-open` | CRITICAL |

---

#### `detect_cgroup_escape(ev, meta)` — Attack 3

**What it detects:** The CVE-2022-0492 cgroup release_agent exploit. An attacker mounts a cgroup filesystem inside a container, creates a child cgroup, enables `notify_on_release`, and writes a payload to `release_agent` — which the host kernel executes when the cgroup empties.

**Trigger conditions:**
| Syscall | Condition | Rule | Severity |
|---------|-----------|------|----------|
| `mount()` | Source is "cgroup" or "cgroup2", or mount target (`extra`) is "cgroup" | `cgroup-mount` | CRITICAL |
| `openat()` | Path contains "release_agent" or "notify_on_release" | `cgroup-release-agent` | CRITICAL |

---

#### `detect_namespace_escape(ev, meta)` — Attack 5

**What it detects:** A container process using `nsenter` or direct `setns()` calls to join the host's namespaces (mount, network, PID, UTS, IPC). Once in the host namespace, the process has full host access.

**Trigger conditions:**
| Syscall | Condition | Rule | Severity |
|---------|-----------|------|----------|
| `setns()` | Caller is NOT runc or containerd-shim (those are legitimate container setup) | `namespace-setns` | CRITICAL |
| `openat()` | Path starts with `/proc/1/ns/` or `/proc/self/ns/` | `namespace-probe` | HIGH |

**Noise exclusion:** `runc`, `runc:[*`, and `containerd-shi` are skipped for `setns()` because they legitimately call `setns()` during container creation.

---

#### `detect_privileged_escape(ev, meta)` — Attack 2

**What it detects:** A `--privileged` container (with `CAP_SYS_ADMIN`) using mount/setns to escape, or reading host files through `/proc/1/root`.

**Prerequisite:** `meta->cap_sys_admin` must be `true` (bit 21 of `cap_eff`). If the container doesn't have `CAP_SYS_ADMIN`, this detector silently returns `false`.

**Trigger conditions:**
| Syscall | Condition | Rule | Severity |
|---------|-----------|------|----------|
| `mount()` | Caller has CAP_SYS_ADMIN, comm is NOT runc/runc:[* | `container-mount` | CRITICAL |
| `setns()` | Caller has CAP_SYS_ADMIN, comm is NOT runc/runc:[* | `container-setns` | CRITICAL |
| `openat()` | Path starts with `/proc/1/root` | `proc-root-access` | CRITICAL |

---

#### `detect_sensitive_fs_access(ev, meta)` — Attack 4

**What it detects:** A container reading sensitive host files that have been bind-mounted into the container (e.g., `-v /:/hostfs:ro`).

**Trigger conditions:**
| Syscall | Path Pattern | Rule | Severity |
|---------|-------------|------|----------|
| `openat()` | `/hostfs/etc/shadow`, `/hostfs/etc/passwd`, `/hostfs/etc/sudoers`, `/hostfs/etc/gshadow` | `hostfs-credential-read` | HIGH |
| `openat()` | `/hostfs/root/.ssh/*` | `hostfs-credential-read` | HIGH |
| `openat()` | `/hostfs/etc/docker/*`, `/hostfs/root/.docker/*` | `hostfs-credential-read` | HIGH |
| `openat()` | `/hostfs/var/lib/kubelet/*`, `/hostfs/etc/kubernetes/*` | `hostfs-credential-read` | HIGH |
| `openat()` | `/proc/1/environ` | `host-environ-read` | HIGH |
| `openat()` | `/proc/1/cmdline` | `host-process-enum` | MEDIUM |

---

### Event Evaluation Pipeline

#### `evaluate_event(const struct event *ev)`
The central dispatcher that ties everything together:

```
evaluate_event(ev)
│
├─ 1. Quick mntns check (BPF data vs host_mntns)
│     → Determines container status without hitting /proc
│
├─ 2. enrich_metadata(ev->tgid, ev)
│     → Reads /proc/<pid>/cgroup for container ID + runtime
│     → Falls back to mntns if /proc read fails
│
├─ 3. Container gate
│     ├─ Not containerized? → RETURN (skip)
│     ├─ No container ID? → RETURN (skip)
│     └─ Noise comm? → RETURN (skip)
│
└─ 4. Run detectors (exclusive, first match wins):
      ├─ detect_docker_socket_escape()  → return if matched
      ├─ detect_cgroup_escape()         → return if matched
      ├─ detect_namespace_escape()      → return if matched
      ├─ detect_privileged_escape()     → return if matched
      └─ detect_sensitive_fs_access()   → last detector
```

### Ring Buffer Callback

#### `handle_rb_event(void *ctx, void *data, size_t len)`
Called by `ring_buffer__poll()` for each event. Does a size check and self-PID filter, then delegates to `evaluate_event()`.

### Main Function

#### `main(int argc, char **argv)`
Startup sequence:

1. Parse CLI args: `-bpf-object <path>`, `-json`
2. Disable stdout buffering (`setvbuf`) — critical for real-time alert visibility
3. Read host mount namespace (`get_host_mntns()`)
4. Store own PID (`self_tgid`)
5. Register SIGINT/SIGTERM handlers
6. Set `RLIMIT_MEMLOCK` to infinity (required for BPF maps)
7. Open and load the BPF object file via libbpf
8. Attach 4 tracepoint programs
9. Write detector PID into `detector_pid` BPF map (kernel-side self-filter)
10. Create ring buffer and register `handle_rb_event` callback
11. Enter poll loop: `ring_buffer__poll(rb, 250)` (250ms timeout)
12. On shutdown: free ring buffer, destroy links, close BPF object

---

## Attack Scripts

Each script runs inside a Docker container and performs a real container escape technique.

### Attack 1 — Docker Socket Escape (`attack1_docker_socket.sh`)

**Docker flags:** `-v /var/run/docker.sock:/var/run/docker.sock`

**What happens:**
1. Container has the Docker socket bind-mounted — this is a common but dangerous pattern
2. Script installs `curl` inside the container
3. Uses `curl --unix-socket /var/run/docker.sock` to query the Docker API
4. Lists containers, images, and Docker version from inside the container
5. This proves full Docker control — an attacker could create a `--privileged` escape container

**Syscalls that trigger alerts:**
- `connect(fd, {AF_UNIX, "/var/run/docker.sock"}, ...)` → **docker-socket-connect** (CRITICAL)
- `openat(AT_FDCWD, "/var/run/docker.sock", ...)` → **docker-socket-open** (CRITICAL)

---

### Attack 2 — Privileged Container Escape (`attack2_privileged_escape.sh`)

**Docker flags:** `--privileged --pid=host`

**What happens:**
1. Verifies `CAP_SYS_ADMIN` by reading `/proc/self/status` CapEff
2. Mounts host procfs: `mount -t proc proc /tmp/hostproc`
3. Reads host files via `/proc/1/root/etc/hostname`, `/etc/os-release`, `/etc/shadow`
4. Proves unrestricted host filesystem access through the process namespace

**Syscalls that trigger alerts:**
- `mount("proc", "/tmp/hostproc", "proc", ...)` → **container-mount** (CRITICAL)
- `openat(AT_FDCWD, "/proc/1/root/etc/hostname", ...)` → **proc-root-access** (CRITICAL)

---

### Attack 3 — Cgroup Escape / CVE-2022-0492 (`attack3_cgroup_escape.sh`)

**Docker flags:** `--privileged`

**What happens:**
1. Mounts cgroup v1 memory controller: `mount -t cgroup -o memory cgroup /tmp/cgroup_escape`
2. Creates child cgroup: `mkdir /tmp/cgroup_escape/escape_test`
3. Enables `notify_on_release`: `echo 1 > .../notify_on_release`
4. Reads `release_agent` — if writable, arbitrary host command execution is possible
5. On modern cgroup v2 systems, `release_agent` doesn't exist (exploit blocked), but the mount is still detected

**Syscalls that trigger alerts:**
- `mount("cgroup", "/tmp/cgroup_escape", "cgroup", ...)` → **cgroup-mount** (CRITICAL)
- `openat(AT_FDCWD, ".../release_agent", ...)` → **cgroup-release-agent** (CRITICAL)

---

### Attack 4 — Sensitive Filesystem Access (`attack4_sensitive_fs_access.sh`)

**Docker flags:** `-v /:/hostfs:ro --pid=host`

**What happens:**
1. Reads credential files: `/hostfs/etc/shadow`, `/hostfs/etc/passwd`, `/hostfs/etc/sudoers`
2. Reads SSH keys: `/hostfs/root/.ssh/authorized_keys`, `id_rsa`, `id_ed25519`
3. Reads host environment: `/proc/1/environ`
4. Enumerates host processes: iterates `/proc/[0-9]*/cmdline`

**Syscalls that trigger alerts:**
- `openat(AT_FDCWD, "/hostfs/etc/shadow", ...)` → **hostfs-credential-read** (HIGH)
- `openat(AT_FDCWD, "/proc/1/environ", ...)` → **host-environ-read** (HIGH)
- `openat(AT_FDCWD, "/proc/1/cmdline", ...)` → **host-process-enum** (MEDIUM)

---

### Attack 5 — Namespace Escape (`attack5_namespace_escape.sh`)

**Docker flags:** `--privileged --pid=host`

**What happens:**
1. Checks prerequisites: verifies `/proc/1/ns/*` files are accessible
2. Enumerates namespace IDs: reads symlinks at `/proc/1/ns/` (mnt, pid, net, uts, ipc)
3. `nsenter -t 1 -m` — joins host mount namespace, runs `hostname`
4. `nsenter -t 1 -n` — joins host network namespace, lists interfaces
5. `nsenter -t 1 -m -u -i -n -p` — joins ALL host namespaces (full escape)

**Syscalls that trigger alerts:**
- `openat(AT_FDCWD, "/proc/1/ns/mnt", ...)` → **namespace-probe** (HIGH)
- `setns(fd, CLONE_NEWNS)` → **namespace-setns** (CRITICAL)

---

### Attack Orchestrator (`run_real_attacks.sh`)

Runs all 5 attacks sequentially in isolated Docker containers:
- Accepts `--attack [1|2|3|4|5|all]` to run specific or all attacks
- Starts the detector in the background
- Launches each attack container with the correct Docker flags and mounted scripts
- Collects alerts from a log file
- Cleans up all containers and the detector on exit (via trap)

---

## What Triggers an Alert

An alert is generated when ALL of these conditions are true:

1. **Syscall is hooked** — One of: `mount()`, `openat()`, `connect()`, `setns()`
2. **Not self** — The caller is not the detector process itself (BPF-side `is_self()` + user-space `self_tgid` check)
3. **Process is containerized** — Determined by:
   - BPF-captured mntns differs from host mntns, OR
   - `/proc/<pid>/cgroup` contains docker/containerd/kubepods markers
4. **Container ID exists** — Either extracted from cgroup or set to "unknown"
5. **Not a noise process** — Process name is not in the `host_noise_comms[]` allowlist
6. **Matches a detection rule** — One of the 5 detector functions identifies the syscall + path combination as an attack pattern

### Complete Alert Rule Reference

| Rule Name | Attack | Event | Condition | Severity |
|-----------|--------|-------|-----------|----------|
| `docker-socket-connect` | DOCKER-SOCKET-ESCAPE | connect | AF_UNIX + docker.sock path | CRITICAL |
| `docker-socket-open` | DOCKER-SOCKET-ESCAPE | openat | docker.sock path | CRITICAL |
| `cgroup-mount` | CGROUP-ESCAPE | mount | source="cgroup" or target="cgroup" | CRITICAL |
| `cgroup-release-agent` | CGROUP-ESCAPE | openat | path contains release_agent or notify_on_release | CRITICAL |
| `namespace-setns` | NAMESPACE-ESCAPE | setns | comm is not runc/containerd-shim | CRITICAL |
| `namespace-probe` | NAMESPACE-ESCAPE | openat | path starts with /proc/1/ns/ or /proc/self/ns/ | HIGH |
| `container-mount` | PRIVILEGED-ESCAPE | mount | CAP_SYS_ADMIN + not runc | CRITICAL |
| `container-setns` | PRIVILEGED-ESCAPE | setns | CAP_SYS_ADMIN + not runc | CRITICAL |
| `proc-root-access` | PRIVILEGED-ESCAPE | openat | path starts with /proc/1/root | CRITICAL |
| `hostfs-credential-read` | SENSITIVE-FS-ACCESS | openat | path in sensitive_host_prefixes[] | HIGH |
| `host-environ-read` | SENSITIVE-FS-ACCESS | openat | path = /proc/1/environ | HIGH |
| `host-process-enum` | SENSITIVE-FS-ACCESS | openat | path = /proc/1/cmdline | MEDIUM |

---

## Detection Order and Why It Matters

The 5 detectors run in a **strict, exclusive order** inside `evaluate_event()`:

```
1. detect_docker_socket_escape()   ← Most specific, unique syscall pattern
2. detect_cgroup_escape()          ← Overlaps with privileged (both use mount)
3. detect_namespace_escape()       ← Overlaps with privileged (both use setns)
4. detect_privileged_escape()      ← Catch-all for remaining mount/setns
5. detect_sensitive_fs_access()    ← openat-only, non-exclusive
```

**Why this order?**

- A cgroup `mount("cgroup")` should trigger **cgroup-escape**, not **privileged-escape**. Since both detectors match on `EVT_MOUNT`, the cgroup detector must run first.
- An `nsenter` calling `setns()` should trigger **namespace-escape**, not **privileged-escape**. Since both match on `EVT_SETNS`, the namespace detector must run first.
- The privileged-escape detector acts as a catch-all for mount/setns events that don't match more specific patterns.
- The first match returns immediately (`if (detect_X()) return;`), preventing duplicate alerts.

---

## Build System and Deployment

### Makefile Targets

| Target | Command | Purpose |
|--------|---------|---------|
| `make all` | `make bpf build` | Build everything |
| `make bpf` | `clang -O2 -g -Wall -Werror -target bpf ...` | Compile BPF program to `.bpf.o` |
| `make build` | `gcc -O2 -g -Wall -Wextra ... -lbpf -lelf -lz` | Compile user-space detector + simulator |
| `make run` | `sudo ./bin/detector -policy examples/policy.yaml` | Run detector standalone |
| `make demo` | `sudo bash scripts/run_demo.sh` | Run simulated attacks |
| `make real-attack` | `sudo bash attacks/run_real_attacks.sh` | Run all 5 real attacks |

### Dependencies

- `clang` / `llvm` / `llvm-strip` — BPF compilation
- `gcc` — User-space compilation
- `libbpf-dev` — BPF loader library
- `libelf-dev` — ELF parsing (required by libbpf)
- `zlib1g-dev` — Compression (required by libbpf)
- `docker` — Running attack containers
- Linux kernel 5.8+ with BTF support (for CO-RE)

### Dockerfile

Multi-stage build:
1. **Build stage** (debian:bookworm): Installs all build tools, compiles BPF + detector
2. **Runtime stage** (debian:bookworm-slim): Only runtime libs (libbpf1, libelf1, zlib1g), copies compiled binaries

---

## File Inventory

```
├── cmd/detector/
│   └── detector.c              # Main user-space detector (690 lines)
│                                #   5 attack detectors, metadata enrichment,
│                                #   ring buffer polling, alert output
│
├── internal/bpf/
│   └── escape_detector.bpf.c   # eBPF kernel program (203 lines)
│                                #   4 tracepoint handlers, CO-RE structs,
│                                #   ring buffer + detector_pid maps
│
├── attacks/
│   ├── attack1_docker_socket.sh      # Docker socket escape (51 lines)
│   ├── attack2_privileged_escape.sh  # Privileged mount + /proc/1/root (54 lines)
│   ├── attack3_cgroup_escape.sh      # CVE-2022-0492 cgroup exploit (53 lines)
│   ├── attack4_sensitive_fs_access.sh # Host credential exfiltration (43 lines)
│   ├── attack5_namespace_escape.sh   # nsenter namespace escape (71 lines)
│   └── run_real_attacks.sh           # Master orchestrator (~180 lines)
│
├── scripts/
│   ├── simulate_attack.c        # Non-destructive syscall simulator (206 lines)
│   └── run_demo.sh              # Demo orchestrator (95 lines)
│
├── examples/
│   └── policy.yaml              # Policy template (11 lines)
│
├── bin/
│   ├── detector                 # Compiled detector binary
│   └── simulate_attack          # Compiled simulator binary
│
├── Makefile                     # Build automation (42 lines)
├── Dockerfile                   # Multi-stage container build (18 lines)
├── README.md                    # Project overview
├── ATTACK_GUIDE.md              # Detailed attack documentation
└── generate_ppt.py              # PowerPoint generation script
```

### How Files Connect

```
Makefile
  ├── compiles: escape_detector.bpf.c  ──►  escape_detector.bpf.o
  ├── compiles: detector.c             ──►  bin/detector
  └── compiles: simulate_attack.c      ──►  bin/simulate_attack

bin/detector
  ├── loads: internal/bpf/escape_detector.bpf.o  (BPF programs)
  └── reads: /proc/<pid>/cgroup                  (container metadata)

escape_detector.bpf.o (kernel)
  └── sends events via: ring buffer  ──►  detector.c (user-space)

run_real_attacks.sh
  ├── starts: bin/detector (background)
  └── launches Docker containers with: attack1-5.sh

run_demo.sh
  ├── starts: bin/detector (background)
  └── runs: bin/simulate_attack

Dockerfile
  └── builds: detector + escape_detector.bpf.o + policy.yaml into container image
```
