#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

/* ── Constants ─────────────────────────────────────────────────── */
#define TASK_COMM_LEN 16
#define PATH_LEN 128
#define CAP_SYS_ADMIN_BIT 21

enum event_type {
    EVT_MOUNT = 1,
    EVT_OPENAT = 2,
    EVT_CONNECT = 3,
    EVT_SETNS = 4,
};

struct event {
    uint64_t ts_ns;
    uint32_t pid;
    uint32_t tgid;
    uint32_t uid;
    uint32_t gid;
    uint32_t mntns;
    uint32_t event_type;
    int32_t fd;
    uint32_t flags;
    uint32_t family;
    uint64_t cgroup_id;
    char comm[TASK_COMM_LEN];
    char path[PATH_LEN];
    char extra[PATH_LEN];
};

struct metadata {
    bool containerized;
    bool cap_sys_admin;
    char runtime[24];
    char container_id[65];
};

/* ── Globals ───────────────────────────────────────────────────── */
static volatile sig_atomic_t stop = 0;
static bool json_output = false;
static uint32_t self_tgid = 0;
static uint32_t host_mntns = 0;

/* ── Noise filter: known host-side system processes to ignore ── */
static const char *host_noise_comms[] = {
    "systemd-oomd", "systemd-journa", "systemd-timesy",
    "systemd-logind", "systemd-resolv", "systemd-udevd",
    "systemd-networ", "systemd",
    "dockerd", "containerd", "containerd-shi",
    "MemoryPoller", "FSBroker",
    "runc", "runc:[",
    "snapd",
    NULL,
};

static bool is_noise_comm(const char *comm)
{
    for (int i = 0; host_noise_comms[i]; i++) {
        if (strncmp(comm, host_noise_comms[i], strlen(host_noise_comms[i])) == 0)
            return true;
    }
    return false;
}

/* ── Utility functions ─────────────────────────────────────────── */
static void trim_newline(char *s)
{
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

static bool is_hex_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static void extract_container_id(const char *text, char *out, size_t out_len)
{
    size_t run = 0;
    size_t i;

    if (!text || !out || out_len < 13) return;
    out[0] = '\0';

    for (i = 0; text[i] != '\0'; i++) {
        if (is_hex_char(text[i])) { run++; continue; }
        if (run >= 64) {
            size_t start = i - run;
            memcpy(out, text + start, 64);
            out[64] = '\0';
            return;
        }
        if (run >= 12) {
            size_t start = i - run;
            memcpy(out, text + start, 12);
            out[12] = '\0';
            return;
        }
        run = 0;
    }
    if (run >= 64) {
        memcpy(out, text + i - run, 64);
        out[64] = '\0';
    } else if (run >= 12) {
        memcpy(out, text + i - run, 12);
        out[12] = '\0';
    }
}

static void infer_runtime(const char *cg, char *runtime, size_t len)
{
    if (strstr(cg, "docker"))     { snprintf(runtime, len, "docker");     return; }
    if (strstr(cg, "containerd")) { snprintf(runtime, len, "containerd"); return; }
    if (strstr(cg, "crio"))       { snprintf(runtime, len, "cri-o");      return; }
    if (strstr(cg, "libpod"))     { snprintf(runtime, len, "podman");     return; }
    snprintf(runtime, len, "unknown");
}

static const char *event_name(uint32_t t)
{
    switch (t) {
    case EVT_MOUNT:   return "mount";
    case EVT_OPENAT:  return "openat";
    case EVT_CONNECT: return "connect";
    case EVT_SETNS:   return "setns";
    default:          return "unknown";
    }
}

static const char *severity_str(int s)
{
    switch (s) {
    case 1: return "LOW";
    case 2: return "MEDIUM";
    case 3: return "HIGH";
    case 4: return "CRITICAL";
    default: return "INFO";
    }
}

/* ── Metadata enrichment ───────────────────────────────────────── */
static bool has_cap_sys_admin(uint32_t pid)
{
    char path[PATH_MAX];
    FILE *f;
    char line[512];

    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    f = fopen(path, "r");
    if (!f) return false;

    while (fgets(line, sizeof(line), f)) {
        unsigned long long cap;
        if (strncmp(line, "CapEff:", 7) == 0 && sscanf(line + 7, "%llx", &cap) == 1) {
            fclose(f);
            return (cap & (1ULL << CAP_SYS_ADMIN_BIT)) != 0;
        }
    }
    fclose(f);
    return false;
}

static uint32_t get_host_mntns(void)
{
    char link[PATH_MAX];
    ssize_t n;
    unsigned int ino = 0;

    n = readlink("/proc/1/ns/mnt", link, sizeof(link) - 1);
    if (n > 0) {
        link[n] = '\0';
        sscanf(link, "mnt:[%u]", &ino);
    }
    return ino;
}

static bool is_containerized_by_mntns(uint32_t pid)
{
    char ns_path[PATH_MAX], link[PATH_MAX];
    ssize_t n;
    unsigned int ino = 0;

    if (host_mntns == 0) return false;
    snprintf(ns_path, sizeof(ns_path), "/proc/%u/ns/mnt", pid);
    n = readlink(ns_path, link, sizeof(link) - 1);
    if (n > 0) {
        link[n] = '\0';
        sscanf(link, "mnt:[%u]", &ino);
    }
    return ino != 0 && ino != host_mntns;
}

static struct metadata enrich_metadata(uint32_t pid)
{
    struct metadata meta = {0};
    char path[PATH_MAX];
    FILE *f;
    char line[1024];
    char cgroup_blob[8192] = {0};
    size_t used = 0;

    snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);
    f = fopen(path, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            size_t len = strlen(line);
            trim_newline(line);
            if (strstr(line, "docker") || strstr(line, "containerd") ||
                strstr(line, "kubepods") || strstr(line, "crio") ||
                strstr(line, "libpod")) {
                meta.containerized = true;
            }
            if (used + len + 1 < sizeof(cgroup_blob)) {
                memcpy(cgroup_blob + used, line, len);
                used += len;
                cgroup_blob[used++] = '\n';
                cgroup_blob[used] = '\0';
            }
        }
        fclose(f);
        infer_runtime(cgroup_blob, meta.runtime, sizeof(meta.runtime));
        extract_container_id(cgroup_blob, meta.container_id, sizeof(meta.container_id));
    } else {
        snprintf(meta.runtime, sizeof(meta.runtime), "unknown");
    }

    /* mntns fallback — process may be dead before cgroup was read */
    if (!meta.containerized) {
        meta.containerized = is_containerized_by_mntns(pid);
        if (meta.containerized)
            snprintf(meta.runtime, sizeof(meta.runtime), "docker");
    }

    /* If containerized but container_id is empty (short-lived proc),
     * set a placeholder so evaluate_event doesn't skip it. */
    if (meta.containerized && meta.container_id[0] == '\0')
        snprintf(meta.container_id, sizeof(meta.container_id), "unknown");

    meta.cap_sys_admin = has_cap_sys_admin(pid);
    return meta;
}

/* ── Alert output ──────────────────────────────────────────────── */
static void print_alert(const struct event *ev, const struct metadata *meta,
                        int severity, const char *attack, const char *rule,
                        const char *message)
{
    time_t sec = (time_t)(ev->ts_ns / 1000000000ULL);
    struct tm tm_buf;
    char ts[64] = {0};

    gmtime_r(&sec, &tm_buf);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    if (json_output) {
        printf("{\"timestamp\":\"%s\",\"severity\":\"%s\",\"attack\":\"%s\","
               "\"rule\":\"%s\",\"event\":\"%s\",\"pid\":%u,\"comm\":\"%s\","
               "\"path\":\"%s\",\"container\":\"%s\",\"runtime\":\"%s\","
               "\"cap_sys_admin\":%s,\"message\":\"%s\"}\n",
               ts, severity_str(severity), attack, rule,
               event_name(ev->event_type), ev->tgid, ev->comm,
               ev->path, meta->container_id, meta->runtime,
               meta->cap_sys_admin ? "true" : "false", message);
    } else {
        printf("[%s] %s [%s] rule=%s event=%s pid=%u comm=%s path=%s "
               "container=%.12s msg=%s\n",
               ts, severity_str(severity), attack, rule,
               event_name(ev->event_type), ev->tgid, ev->comm,
               ev->path, meta->container_id, message);
    }
    fflush(stdout);
}

/* ══════════════════════════════════════════════════════════════════
 *  ATTACK 1 — Docker Socket Escape
 *
 *  Triggers: connect() or openat() on /var/run/docker.sock
 *  from a process INSIDE a container.
 * ═════════════════════════════════════════════════════════════════ */
static bool detect_docker_socket_escape(const struct event *ev,
                                        const struct metadata *meta)
{
    const char *p = ev->path;

    if (ev->event_type == EVT_CONNECT && ev->family == 1 /* AF_UNIX */) {
        if (strcmp(p, "/var/run/docker.sock") == 0 ||
            strcmp(p, "/run/docker.sock") == 0) {
            print_alert(ev, meta, 4, "DOCKER-SOCKET-ESCAPE",
                        "docker-socket-connect",
                        "Container process connected to Docker socket");
            return true;
        }
    }

    if (ev->event_type == EVT_OPENAT) {
        if (strcmp(p, "/var/run/docker.sock") == 0 ||
            strcmp(p, "/run/docker.sock") == 0) {
            print_alert(ev, meta, 4, "DOCKER-SOCKET-ESCAPE",
                        "docker-socket-open",
                        "Container process opened Docker socket");
            return true;
        }
    }

    return false;
}

/* ══════════════════════════════════════════════════════════════════
 *  ATTACK 2 — Privileged Container Escape
 *
 *  Triggers: mount() or setns() from a container process that has
 *  CAP_SYS_ADMIN, accessing host paths like /proc/1/root
 * ═════════════════════════════════════════════════════════════════ */
static bool detect_privileged_escape(const struct event *ev,
                                     const struct metadata *meta)
{
    const char *p = ev->path;

    if (!meta->cap_sys_admin)
        return false;

    /* mount() from inside a container with CAP_SYS_ADMIN */
    if (ev->event_type == EVT_MOUNT) {
        /* Only alert on interesting mount types, not runc container setup */
        if (strcmp(ev->comm, "runc") == 0 ||
            strncmp(ev->comm, "runc:[", 6) == 0)
            return false;

        print_alert(ev, meta, 4, "PRIVILEGED-ESCAPE",
                    "container-mount",
                    "Privileged container invoked mount()");
        return true;
    }

    /* setns() from inside a container — namespace migration */
    if (ev->event_type == EVT_SETNS) {
        if (strcmp(ev->comm, "runc") == 0 ||
            strncmp(ev->comm, "runc:[", 6) == 0)
            return false;

        print_alert(ev, meta, 4, "PRIVILEGED-ESCAPE",
                    "container-setns",
                    "Privileged container invoked setns()");
        return true;
    }

    /* openat /proc/1/root — reading host filesystem */
    if (ev->event_type == EVT_OPENAT) {
        if (strncmp(p, "/proc/1/root", 12) == 0) {
            print_alert(ev, meta, 4, "PRIVILEGED-ESCAPE",
                        "proc-root-access",
                        "Container accessed host via /proc/1/root");
            return true;
        }
    }

    return false;
}

/* ══════════════════════════════════════════════════════════════════
 *  ATTACK 3 — Kernel Exploit / Cgroup Escape (CVE-2022-0492)
 *
 *  Triggers: mount("cgroup") and access to release_agent,
 *  notify_on_release from inside a container
 * ═════════════════════════════════════════════════════════════════ */
static bool detect_cgroup_escape(const struct event *ev,
                                 const struct metadata *meta)
{
    const char *p = ev->path;

    /* mount() of cgroup filesystem — the first step of CVE-2022-0492 */
    if (ev->event_type == EVT_MOUNT) {
        if (strcmp(p, "cgroup") == 0 || strcmp(p, "cgroup2") == 0 ||
            (ev->extra[0] && strcmp(ev->extra, "cgroup") == 0)) {
            print_alert(ev, meta, 4, "CGROUP-ESCAPE",
                        "cgroup-mount",
                        "Container mounted cgroup filesystem (CVE-2022-0492)");
            return true;
        }
    }

    /* openat on release_agent or notify_on_release files */
    if (ev->event_type == EVT_OPENAT) {
        if (strstr(p, "release_agent") || strstr(p, "notify_on_release")) {
            print_alert(ev, meta, 4, "CGROUP-ESCAPE",
                        "cgroup-release-agent",
                        "Container accessed cgroup release_agent/notify_on_release");
            return true;
        }
    }

    return false;
}

/* ══════════════════════════════════════════════════════════════════
 *  ATTACK 4 — Sensitive Host Filesystem Access
 *
 *  Triggers: openat() on specific high-value host files that have
 *  been bind-mounted into the container (e.g., /etc/shadow)
 * ═════════════════════════════════════════════════════════════════ */
static const char *sensitive_credential_files[] = {
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
    "/root/.ssh/id_rsa", "/root/.ssh/id_ed25519",
    "/root/.ssh/id_ecdsa", "/root/.ssh/authorized_keys",
    "/etc/docker/daemon.json", "/root/.docker/config.json",
    "/var/lib/kubelet/config.yaml", "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/pki",
    NULL,
};

static const char *sensitive_host_prefixes[] = {
    "/hostfs/etc/shadow", "/hostfs/etc/gshadow", "/hostfs/etc/sudoers",
    "/hostfs/etc/passwd",
    "/hostfs/root/.ssh",
    "/hostfs/etc/docker", "/hostfs/root/.docker",
    "/hostfs/var/lib/kubelet", "/hostfs/etc/kubernetes",
    NULL,
};

static bool detect_sensitive_fs_access(const struct event *ev,
                                       const struct metadata *meta)
{
    const char *p = ev->path;

    if (ev->event_type != EVT_OPENAT)
        return false;

    /* Check exact credential file paths */
    for (int i = 0; sensitive_credential_files[i]; i++) {
        if (strcmp(p, sensitive_credential_files[i]) == 0) {
            print_alert(ev, meta, 3, "SENSITIVE-FS-ACCESS",
                        "credential-file-read",
                        "Container read sensitive credential file from host");
            return true;
        }
    }

    /* Check /hostfs/ paths — container reading mounted host filesystem */
    for (int i = 0; sensitive_host_prefixes[i]; i++) {
        if (strncmp(p, sensitive_host_prefixes[i],
                    strlen(sensitive_host_prefixes[i])) == 0) {
            print_alert(ev, meta, 3, "SENSITIVE-FS-ACCESS",
                        "hostfs-credential-read",
                        "Container read host credential via bind mount");
            return true;
        }
    }

    /* /proc/1/environ — reading host init environment */
    if (strcmp(p, "/proc/1/environ") == 0) {
        print_alert(ev, meta, 3, "SENSITIVE-FS-ACCESS",
                    "host-environ-read",
                    "Container read host PID 1 environment variables");
        return true;
    }

    /* /proc/<pid>/cmdline enumeration from container */
    if (strncmp(p, "/proc/", 6) == 0 && strstr(p, "/cmdline")) {
        /* Only alert once per batch — just on PID 1 */
        if (strncmp(p, "/proc/1/cmdline", 15) == 0) {
            print_alert(ev, meta, 2, "SENSITIVE-FS-ACCESS",
                        "host-process-enum",
                        "Container enumerating host process command lines");
            return true;
        }
    }

    return false;
}

/* ══════════════════════════════════════════════════════════════════
 *  ATTACK 5 — Namespace Escape
 *
 *  Triggers: setns() from container + openat on /proc/1/ns/
 *  to join host namespaces
 * ═════════════════════════════════════════════════════════════════ */
static bool detect_namespace_escape(const struct event *ev,
                                    const struct metadata *meta)
{
    const char *p = ev->path;

    /* setns() from nsenter or similar — skip runc (container setup) */
    if (ev->event_type == EVT_SETNS) {
        if (strcmp(ev->comm, "runc") == 0 ||
            strncmp(ev->comm, "runc:[", 6) == 0 ||
            strcmp(ev->comm, "containerd-shi") == 0)
            return false;

        /* nsenter or bash doing setns = real attack */
        print_alert(ev, meta, 4, "NAMESPACE-ESCAPE",
                    "namespace-setns",
                    "Container process called setns() to join host namespace");
        return true;
    }

    /* openat /proc/1/ns/ — probing host namespace files */
    if (ev->event_type == EVT_OPENAT) {
        if (strncmp(p, "/proc/1/ns/", 11) == 0 ||
            strncmp(p, "/proc/self/ns/", 14) == 0) {
            print_alert(ev, meta, 3, "NAMESPACE-ESCAPE",
                        "namespace-probe",
                        "Container opened host namespace file");
            return true;
        }
    }

    return false;
}

/* ══════════════════════════════════════════════════════════════════
 *  Main event evaluator — runs all 5 attack detectors
 * ═════════════════════════════════════════════════════════════════ */
static void evaluate_event(const struct event *ev)
{
    struct metadata meta;
    const char *p = ev->path;

    if (!p) p = "";

    /* ── Step 1: Quick mntns check from BPF data (no /proc needed) ──
     * If the event's mntns differs from the host, it's a container.
     * This avoids the race where short-lived processes exit before
     * we can read /proc/<pid>/cgroup.
     */
    bool is_container_by_mntns = (host_mntns != 0 && ev->mntns != 0 &&
                                   ev->mntns != host_mntns);

    /* ── Step 2: Enrich with container metadata ── */
    meta = enrich_metadata(ev->tgid);

    /* If /proc-based detection failed but BPF mntns says container,
     * trust the BPF data (it was captured at syscall time). */
    if (!meta.containerized && is_container_by_mntns) {
        meta.containerized = true;
        if (meta.container_id[0] == '\0')
            snprintf(meta.container_id, sizeof(meta.container_id), "unknown");
        if (meta.runtime[0] == '\0')
            snprintf(meta.runtime, sizeof(meta.runtime), "docker");
    }

    /* ── Step 3: STRICT container check ── */
    if (!meta.containerized)
        return;

    if (meta.container_id[0] == '\0')
        return;

    if (is_noise_comm(ev->comm))
        return;

    /* ── Step 4: Run attack detectors (exclusive — first match wins) ── */
    if (detect_docker_socket_escape(ev, &meta)) return;
    if (detect_privileged_escape(ev, &meta))     return;
    if (detect_cgroup_escape(ev, &meta))         return;
    if (detect_sensitive_fs_access(ev, &meta))   return;
    detect_namespace_escape(ev, &meta);
}

/* ── Ring buffer callback ──────────────────────────────────────── */
static int handle_rb_event(void *ctx, void *data, size_t len)
{
    const struct event *ev = data;
    (void)ctx;

    if (len < sizeof(*ev))
        return 0;
    if (ev->tgid == self_tgid)
        return 0;

    evaluate_event(ev);
    return 0;
}

/* ── Signal handler ────────────────────────────────────────────── */
static void sig_handler(int signo)
{
    (void)signo;
    stop = 1;
}

/* ── BPF attach helper ─────────────────────────────────────────── */
static struct bpf_link *attach_tp(struct bpf_object *obj,
                                  const char *prog_name,
                                  const char *tp_name)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    struct bpf_link *lnk;

    if (!prog) {
        fprintf(stderr, "program not found: %s\n", prog_name);
        return NULL;
    }
    lnk = bpf_program__attach_tracepoint(prog, "syscalls", tp_name);
    if (!lnk)
        fprintf(stderr, "failed to attach tracepoint %s\n", tp_name);
    return lnk;
}

/* ══════════════════════════════════════════════════════════════════
 *  main
 * ═════════════════════════════════════════════════════════════════ */
int main(int argc, char **argv)
{
    const char *bpf_obj_path = "internal/bpf/escape_detector.bpf.o";
    struct bpf_object *obj = NULL;
    struct bpf_link *links[4] = {0};
    struct ring_buffer *rb = NULL;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_map *events_map;
    int map_fd, err, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-bpf-object") == 0 && i + 1 < argc) {
            bpf_obj_path = argv[++i];
        } else if (strcmp(argv[i], "-json") == 0) {
            json_output = true;
        }
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    host_mntns = get_host_mntns();
    self_tgid = (uint32_t)getpid();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0)
        fprintf(stderr, "setrlimit failed: %s\n", strerror(errno));

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(NULL);

    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "open bpf object failed: %s\n", bpf_obj_path);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "load bpf object failed: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    links[0] = attach_tp(obj, "trace_enter_mount",   "sys_enter_mount");
    links[1] = attach_tp(obj, "trace_enter_setns",   "sys_enter_setns");
    links[2] = attach_tp(obj, "trace_enter_openat",  "sys_enter_openat");
    links[3] = attach_tp(obj, "trace_enter_connect", "sys_enter_connect");

    for (i = 0; i < 4; i++) {
        if (!links[i]) {
            fprintf(stderr, "failed attaching tracepoint %d\n", i);
            for (int j = 0; j < 4; j++)
                if (links[j]) bpf_link__destroy(links[j]);
            bpf_object__close(obj);
            return 1;
        }
    }

    events_map = bpf_object__find_map_by_name(obj, "events");
    if (!events_map) {
        fprintf(stderr, "events ring buffer map not found\n");
        for (i = 0; i < 4; i++) bpf_link__destroy(links[i]);
        bpf_object__close(obj);
        return 1;
    }

    /* Set our PID in BPF map so kernel-side also skips our events */
    {
        struct bpf_map *pid_map = bpf_object__find_map_by_name(obj, "detector_pid");
        if (pid_map) {
            int pid_fd = bpf_map__fd(pid_map);
            __u32 key = 0, pid = (__u32)getpid();
            bpf_map_update_elem(pid_fd, &key, &pid, BPF_ANY);
        }
    }

    map_fd = bpf_map__fd(events_map);
    rb = ring_buffer__new(map_fd, handle_rb_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        for (i = 0; i < 4; i++) bpf_link__destroy(links[i]);
        bpf_object__close(obj);
        return 1;
    }

    fprintf(stderr, "eBPF detector started — monitoring for container escape attacks...\n");
    fprintf(stderr, "  Tracepoints: sys_enter_mount, sys_enter_setns, sys_enter_openat, sys_enter_connect\n");
    fprintf(stderr, "  Attacks: docker-socket | privileged-escape | cgroup-escape | sensitive-fs | namespace-escape\n");
    fprintf(stderr, "  Filtering: container-only (host noise suppressed)\n\n");

    while (!stop) {
        err = ring_buffer__poll(rb, 250);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "ring buffer poll error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    for (i = 0; i < 4; i++) bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    fprintf(stderr, "\ndetector stopped\n");
    return 0;
}
