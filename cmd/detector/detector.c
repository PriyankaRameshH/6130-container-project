#include <bpf/libbpf.h>
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

#define TASK_COMM_LEN 16
#define PATH_LEN 128
#define CAP_SYS_ADMIN_BIT 21
#define MAX_POLICY_PATHS 64

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

static volatile sig_atomic_t stop = 0;
static bool json_output = false;

/* Cache: map cgroup_id → containerized metadata for short-lived processes */
#define CGID_CACHE_SIZE 4096
struct cgid_cache_entry {
    uint64_t cgroup_id;
    struct metadata meta;
};
static struct cgid_cache_entry cgid_cache[CGID_CACHE_SIZE];
static size_t cgid_cache_len = 0;

static void cgid_cache_put(uint64_t cgid, const struct metadata *meta)
{
    size_t i;
    for (i = 0; i < cgid_cache_len; i++) {
        if (cgid_cache[i].cgroup_id == cgid) {
            cgid_cache[i].meta = *meta;
            return;
        }
    }
    if (cgid_cache_len < CGID_CACHE_SIZE) {
        cgid_cache[cgid_cache_len].cgroup_id = cgid;
        cgid_cache[cgid_cache_len].meta = *meta;
        cgid_cache_len++;
    }
}

static const struct metadata *cgid_cache_get(uint64_t cgid)
{
    size_t i;
    for (i = 0; i < cgid_cache_len; i++) {
        if (cgid_cache[i].cgroup_id == cgid) {
            return &cgid_cache[i].meta;
        }
    }
    return NULL;
}

static const char *default_sensitive_paths[] = {"/proc", "/sys", "/dev", "/etc", "/root", "/var/lib/kubelet"};
static const size_t default_sensitive_paths_len = sizeof(default_sensitive_paths) / sizeof(default_sensitive_paths[0]);

static const char *default_docker_sock_paths[] = {"/var/run/docker.sock", "/run/docker.sock"};
static const size_t default_docker_sock_paths_len = sizeof(default_docker_sock_paths) / sizeof(default_docker_sock_paths[0]);

struct policy {
    const char *sensitive_paths[MAX_POLICY_PATHS];
    size_t sensitive_paths_len;
    const char *docker_sock_paths[MAX_POLICY_PATHS];
    size_t docker_sock_paths_len;
    char *owned_paths[MAX_POLICY_PATHS * 2];
    size_t owned_paths_len;
};

static struct policy runtime_policy;

static void trim_newline(char *s);

static char *trim_whitespace(char *s)
{
    char *end;

    if (!s) {
        return s;
    }

    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return s;
}

static char *strip_wrapping_quotes(char *s)
{
    size_t len;

    if (!s) {
        return s;
    }

    len = strlen(s);
    if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') || (s[0] == '\'' && s[len - 1] == '\''))) {
        s[len - 1] = '\0';
        return s + 1;
    }
    return s;
}

static void policy_reset_defaults(struct policy *p)
{
    size_t i;

    memset(p, 0, sizeof(*p));
    for (i = 0; i < default_sensitive_paths_len; i++) {
        p->sensitive_paths[p->sensitive_paths_len++] = default_sensitive_paths[i];
    }
    for (i = 0; i < default_docker_sock_paths_len; i++) {
        p->docker_sock_paths[p->docker_sock_paths_len++] = default_docker_sock_paths[i];
    }
}

static void policy_free_owned(struct policy *p)
{
    size_t i;

    for (i = 0; i < p->owned_paths_len; i++) {
        free(p->owned_paths[i]);
    }
    p->owned_paths_len = 0;
}

static int policy_add_path(struct policy *p, bool sensitive, const char *value)
{
    char *owned;

    if (!value || value[0] == '\0') {
        return 0;
    }

    owned = strdup(value);
    if (!owned) {
        return -1;
    }

    if (p->owned_paths_len >= MAX_POLICY_PATHS * 2) {
        free(owned);
        return -1;
    }
    p->owned_paths[p->owned_paths_len++] = owned;

    if (sensitive) {
        if (p->sensitive_paths_len >= MAX_POLICY_PATHS) {
            return -1;
        }
        p->sensitive_paths[p->sensitive_paths_len++] = owned;
        return 0;
    }

    if (p->docker_sock_paths_len >= MAX_POLICY_PATHS) {
        return -1;
    }
    p->docker_sock_paths[p->docker_sock_paths_len++] = owned;
    return 0;
}

static int load_policy_file(const char *path, struct policy *out)
{
    enum {
        SECTION_NONE = 0,
        SECTION_SENSITIVE = 1,
        SECTION_DOCKER = 2,
    } section = SECTION_NONE;
    FILE *f;
    char line[1024];
    bool custom_sensitive = false;
    bool custom_docker = false;

    if (!path || path[0] == '\0') {
        return 0;
    }

    f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        char *cur;
        char *comment;

        trim_newline(line);
        cur = trim_whitespace(line);
        if (cur[0] == '\0') {
            continue;
        }

        comment = strchr(cur, '#');
        if (comment) {
            *comment = '\0';
            cur = trim_whitespace(cur);
            if (cur[0] == '\0') {
                continue;
            }
        }

        if (strncmp(cur, "sensitiveHostPaths:", 19) == 0) {
            section = SECTION_SENSITIVE;
            continue;
        }
        if (strncmp(cur, "dockerSocketPaths:", 18) == 0) {
            section = SECTION_DOCKER;
            continue;
        }

        if (cur[0] == '-') {
            char *val;

            cur++;
            val = trim_whitespace(cur);
            val = strip_wrapping_quotes(val);
            val = trim_whitespace(val);

            if (section == SECTION_SENSITIVE) {
                if (!custom_sensitive) {
                    out->sensitive_paths_len = 0;
                    custom_sensitive = true;
                }
                if (policy_add_path(out, true, val) != 0) {
                    fclose(f);
                    return -1;
                }
            } else if (section == SECTION_DOCKER) {
                if (!custom_docker) {
                    out->docker_sock_paths_len = 0;
                    custom_docker = true;
                }
                if (policy_add_path(out, false, val) != 0) {
                    fclose(f);
                    return -1;
                }
            }
        }
    }

    fclose(f);
    if (out->sensitive_paths_len == 0) {
        size_t i;
        for (i = 0; i < default_sensitive_paths_len; i++) {
            out->sensitive_paths[out->sensitive_paths_len++] = default_sensitive_paths[i];
        }
    }
    if (out->docker_sock_paths_len == 0) {
        size_t i;
        for (i = 0; i < default_docker_sock_paths_len; i++) {
            out->docker_sock_paths[out->docker_sock_paths_len++] = default_docker_sock_paths[i];
        }
    }
    return 0;
}

static bool str_has_prefix(const char *s, const char *prefix)
{
    size_t n;

    if (!s || !prefix) {
        return false;
    }

    n = strlen(prefix);
    if (strncmp(s, prefix, n) != 0) {
        return false;
    }

    return s[n] == '\0' || s[n] == '/';
}

static const char *event_name(uint32_t t)
{
    switch (t) {
    case EVT_MOUNT:
        return "mount";
    case EVT_OPENAT:
        return "openat";
    case EVT_CONNECT:
        return "connect";
    case EVT_SETNS:
        return "setns";
    default:
        return "unknown";
    }
}

static const char *severity_name(int level)
{
    switch (level) {
    case 1:
        return "LOW";
    case 2:
        return "MEDIUM";
    case 3:
        return "HIGH";
    case 4:
        return "CRITICAL";
    default:
        return "LOW";
    }
}

static void trim_newline(char *s)
{
    size_t n;

    if (!s) {
        return;
    }
    n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static bool is_hex_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

static void extract_container_id(const char *text, char *out, size_t out_len)
{
    size_t i;
    size_t run = 0;

    if (!text || !out || out_len < 13) {
        return;
    }

    for (i = 0; text[i] != '\0'; i++) {
        char ch = text[i];
        if (is_hex_char(ch)) {
            run++;
            continue;
        }

        if (run >= 64) {
            size_t start = i - run;
            size_t copy_len = run >= 64 ? 64 : run;
            memcpy(out, text + start, copy_len);
            out[copy_len] = '\0';
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
        size_t start = i - run;
        size_t copy_len = run >= 64 ? 64 : run;
        memcpy(out, text + start, copy_len);
        out[copy_len] = '\0';
        return;
    }
    if (run >= 12) {
        size_t start = i - run;
        memcpy(out, text + start, 12);
        out[12] = '\0';
    }
}

static void infer_runtime(const char *cg, char *runtime, size_t runtime_len)
{
    if (strstr(cg, "docker") != NULL) {
        snprintf(runtime, runtime_len, "docker");
        return;
    }
    if (strstr(cg, "containerd") != NULL) {
        snprintf(runtime, runtime_len, "containerd");
        return;
    }
    if (strstr(cg, "crio") != NULL) {
        snprintf(runtime, runtime_len, "cri-o");
        return;
    }
    if (strstr(cg, "libpod") != NULL) {
        snprintf(runtime, runtime_len, "podman");
        return;
    }
    snprintf(runtime, runtime_len, "unknown");
}

static bool has_cap_sys_admin(uint32_t pid)
{
    char path[PATH_MAX];
    FILE *f;
    char line[512];

    snprintf(path, sizeof(path), "/proc/%u/status", pid);
    f = fopen(path, "r");
    if (!f) {
        return false;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long long cap_eff;

        if (strncmp(line, "CapEff:", 7) != 0) {
            continue;
        }

        if (sscanf(line + 7, "%llx", &cap_eff) == 1) {
            fclose(f);
            return (cap_eff & (1ULL << CAP_SYS_ADMIN_BIT)) != 0;
        }
    }

    fclose(f);
    return false;
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
        while (fgets(line, sizeof(line), f) != NULL) {
            size_t len = strlen(line);

            trim_newline(line);
            if (strstr(line, "docker") || strstr(line, "containerd") || strstr(line, "kubepods") || strstr(line, "crio") || strstr(line, "libpod")) {
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

    meta.cap_sys_admin = has_cap_sys_admin(pid);
    return meta;
}

static void print_alert(const struct event *ev,
                        const struct metadata *meta,
                        int severity,
                        const char *rule,
                        const char *message,
                        const char *path,
                        const char *extra)
{
    time_t sec = (time_t)(ev->ts_ns / 1000000000ULL);
    struct tm tm_buf;
    char ts[64] = {0};

    gmtime_r(&sec, &tm_buf);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    if (json_output) {
        printf("{\"timestamp\":\"%s\",\"severity\":\"%s\",\"rule\":\"%s\",\"message\":\"%s\",\"eventType\":\"%s\",\"pid\":%u,\"tgid\":%u,\"uid\":%u,\"comm\":\"%s\",\"path\":\"%s\",\"extra\":\"%s\",\"containerId\":\"%s\",\"runtime\":\"%s\",\"containerized\":%s,\"cgroupId\":%llu,\"hasCapSysAdmin\":%s}\n",
               ts,
               severity_name(severity),
               rule,
               message,
               event_name(ev->event_type),
               ev->pid,
               ev->tgid,
               ev->uid,
               ev->comm,
               path,
               extra ? extra : "",
               meta->container_id,
               meta->runtime,
               meta->containerized ? "true" : "false",
               (unsigned long long)ev->cgroup_id,
               meta->cap_sys_admin ? "true" : "false");
        return;
    }

    printf("[%s] %s rule=%s event=%s pid=%u comm=%s path=%s runtime=%s container=%s cap_sys_admin=%s msg=%s\n",
           ts,
           severity_name(severity),
           rule,
           event_name(ev->event_type),
           ev->pid,
           ev->comm,
           path,
           meta->runtime,
           meta->container_id,
           meta->cap_sys_admin ? "true" : "false",
           message);
}

static uint32_t host_mntns = 0;

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
    char ns_path[PATH_MAX];
    char link[PATH_MAX];
    ssize_t n;
    unsigned int ino = 0;

    if (host_mntns == 0) {
        return false;
    }

    snprintf(ns_path, sizeof(ns_path), "/proc/%u/ns/mnt", pid);
    n = readlink(ns_path, link, sizeof(link) - 1);
    if (n > 0) {
        link[n] = '\0';
        sscanf(link, "mnt:[%u]", &ino);
    }
    return ino != 0 && ino != host_mntns;
}

static void evaluate_event(const struct event *ev)
{
    struct metadata meta;
    const char *path = ev->path;
    size_t i;

    if (path == NULL) {
        path = "";
    }

    /* Use tgid (actual PID) for proc lookups */
    meta = enrich_metadata(ev->tgid);

    /* Fallback: if cgroup check failed, try mntns comparison */
    if (!meta.containerized) {
        meta.containerized = is_containerized_by_mntns(ev->tgid);
        if (meta.containerized) {
            snprintf(meta.runtime, sizeof(meta.runtime), "docker");
        }
    }

    /* Cache successful container detection by cgroup_id */
    if (meta.containerized && ev->cgroup_id != 0) {
        cgid_cache_put(ev->cgroup_id, &meta);
    }

    /* Final fallback: lookup cgroup_id cache for short-lived processes */
    if (!meta.containerized && ev->cgroup_id != 0) {
        const struct metadata *cached = cgid_cache_get(ev->cgroup_id);
        if (cached) {
            meta = *cached;
        }
    }

    if (!meta.containerized) {
        return;
    }

    if (ev->event_type == EVT_MOUNT || ev->event_type == EVT_SETNS) {
        int severity = meta.cap_sys_admin ? 4 : 3;
        const char *msg = meta.cap_sys_admin
                              ? "Container process with CAP_SYS_ADMIN invoked mount/setns"
                              : "Container process invoked mount/setns";
        print_alert(ev, &meta, severity, "privileged-container-escape", msg, path, ev->extra);
    }

    if (ev->event_type == EVT_OPENAT) {
        for (i = 0; i < runtime_policy.docker_sock_paths_len; i++) {
            if (str_has_prefix(path, runtime_policy.docker_sock_paths[i])) {
                print_alert(ev,
                            &meta,
                            4,
                            "docker-socket-open",
                            "Container process accessed Docker socket via openat",
                            path,
                            ev->extra);
                break;
            }
        }

        for (i = 0; i < runtime_policy.sensitive_paths_len; i++) {
            if (str_has_prefix(path, runtime_policy.sensitive_paths[i])) {
                print_alert(ev,
                            &meta,
                            meta.cap_sys_admin ? 3 : 2,
                            "sensitive-host-path-open",
                            "Container process opened sensitive host path",
                            path,
                            ev->extra);
                break;
            }
        }
    }

    if (ev->event_type == EVT_CONNECT) {
        for (i = 0; i < runtime_policy.docker_sock_paths_len; i++) {
            if (str_has_prefix(path, runtime_policy.docker_sock_paths[i])) {
                print_alert(ev,
                            &meta,
                            4,
                            "docker-socket-connect",
                            "Container process attempted connect to Docker socket",
                            path,
                            ev->extra);
                break;
            }
        }
    }
}

static int handle_rb_event(void *ctx, void *data, size_t len)
{
    const struct event *ev = data;
    (void)ctx;

    if (len < sizeof(*ev)) {
        return 0;
    }

    evaluate_event(ev);
    return 0;
}

static void sig_handler(int signo)
{
    (void)signo;
    stop = 1;
}

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
    if (!lnk) {
        fprintf(stderr, "failed to attach tracepoint %s\n", tp_name);
    }
    return lnk;
}

int main(int argc, char **argv)
{
    const char *bpf_obj_path = "internal/bpf/escape_detector.bpf.o";
    const char *policy_path = NULL;
    struct bpf_object *obj = NULL;
    struct bpf_link *links[4] = {0};
    struct ring_buffer *rb = NULL;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_map *events_map;
    int map_fd;
    int err;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-bpf-object") == 0 && i + 1 < argc) {
            bpf_obj_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "-json") == 0) {
            json_output = true;
            continue;
        }
        if (strcmp(argv[i], "-policy") == 0 && i + 1 < argc) {
            policy_path = argv[++i];
            continue;
        }
    }

    policy_reset_defaults(&runtime_policy);
    if (load_policy_file(policy_path, &runtime_policy) != 0) {
        fprintf(stderr, "failed to load policy file: %s\n", policy_path ? policy_path : "(null)");
        policy_free_owned(&runtime_policy);
        return 1;
    }

    /* Ensure alerts are flushed immediately even when piped */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Cache host mount namespace for container detection fallback */
    host_mntns = get_host_mntns();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
        fprintf(stderr, "setrlimit failed: %s\n", strerror(errno));
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(NULL);

    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "open bpf object failed: %s\n", bpf_obj_path);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err != 0) {
        fprintf(stderr, "load bpf object failed: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    links[0] = attach_tp(obj, "trace_enter_mount", "sys_enter_mount");
    links[1] = attach_tp(obj, "trace_enter_setns", "sys_enter_setns");
    links[2] = attach_tp(obj, "trace_enter_openat", "sys_enter_openat");
    links[3] = attach_tp(obj, "trace_enter_connect", "sys_enter_connect");

    if (!links[0] || !links[1] || !links[2] || !links[3]) {
        fprintf(stderr, "failed attaching one or more tracepoints\n");
        for (i = 0; i < 4; i++) {
            if (links[i]) {
                bpf_link__destroy(links[i]);
            }
        }
        bpf_object__close(obj);
        return 1;
    }

    events_map = bpf_object__find_map_by_name(obj, "events");
    if (!events_map) {
        fprintf(stderr, "events ring buffer map not found\n");
        for (i = 0; i < 4; i++) {
            bpf_link__destroy(links[i]);
        }
        bpf_object__close(obj);
        return 1;
    }

    map_fd = bpf_map__fd(events_map);
    rb = ring_buffer__new(map_fd, handle_rb_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer reader\n");
        for (i = 0; i < 4; i++) {
            bpf_link__destroy(links[i]);
        }
        bpf_object__close(obj);
        return 1;
    }

    fprintf(stderr, "detector started, waiting for events\n");
    while (!stop) {
        err = ring_buffer__poll(rb, 250);
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring buffer poll error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    for (i = 0; i < 4; i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);
    policy_free_owned(&runtime_policy);
    fprintf(stderr, "detector stopped\n");
    return 0;
}
