# Container Escape Detector (eBPF + C)

Real-time runtime security detector for container escape behaviors using eBPF tracepoints and a C user-space engine (libbpf).

## What It Detects

- Privileged Container Escape
  - `mount` and `setns` syscalls from containerized processes
  - Severity increases when `CAP_SYS_ADMIN` is present
  - Alerts on sensitive host path accesses (`/proc`, `/sys`, `/dev`, etc.) via `openat`
- Docker Socket Escape
  - `openat` access to `/var/run/docker.sock`
  - `connect` attempts to Docker daemon UNIX socket

## Architecture

1. eBPF programs attach to syscall tracepoints:
   - `syscalls:sys_enter_mount`
   - `syscalls:sys_enter_setns`
   - `syscalls:sys_enter_openat`
   - `syscalls:sys_enter_connect`
2. Kernel events are emitted through a `BPF_MAP_TYPE_RINGBUF` map.
3. C user-space reads ring buffer records, enriches process/container metadata from `/proc`, evaluates detection rules, and prints alerts.

## Build

Prerequisites:
- Linux kernel with eBPF enabled
- `clang`, `llvm-strip`, `gcc`, `libbpf`, `libelf`, `zlib`
- Root privileges (or equivalent) to load eBPF programs

```bash
make all
```

## Run (Host)

```bash
sudo ./bin/detector -policy examples/policy.yaml
```

JSON logs:

```bash
sudo ./bin/detector -policy examples/policy.yaml -json
```

## Run in Container

Build image:

```bash
docker build -t escape-detector:latest .
```

Run with capabilities (minimum requested includes `CAP_NET_ADMIN`; many kernels also require `CAP_BPF` and `CAP_PERFMON` to load BPF):

```bash
docker run --rm -it \
  --pid=host \
  --cgroupns=host \
  --cap-add=NET_ADMIN \
  --cap-add=BPF \
  --cap-add=PERFMON \
  --cap-add=SYS_ADMIN \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  -v /proc:/proc:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  escape-detector:latest
```

## Detection Rules

Runtime rules are configurable with `-policy <path>` using a small YAML format.

Example:

```yaml
sensitiveHostPaths:
  - /proc
  - /sys
  - /dev
  - /etc
  - /root
  - /var/lib/kubelet

dockerSocketPaths:
  - /var/run/docker.sock
  - /run/docker.sock
```

If no policy is provided, built-in defaults are used.

## Alert Example

```json
{"timestamp":"2026-03-22T14:51:10.154Z","severity":"CRITICAL","rule":"docker-socket-connect","message":"Container process attempted to connect to Docker daemon socket","eventType":"connect","pid":14122,"tgid":14122,"uid":0,"comm":"python","path":"/var/run/docker.sock","containerId":"9f7a...","runtime":"docker","containerized":true,"cgroupId":2873412,"hasCapSysAdmin":true}
```

## Notes and Limits

- Container context is inferred from `/proc/<pid>/cgroup` patterns.
- This detector targets high-signal escape techniques and is intentionally focused.
- Add more probes/rules for deeper runtime telemetry (e.g., `ptrace`, `bpf`, namespace fd tracking).
