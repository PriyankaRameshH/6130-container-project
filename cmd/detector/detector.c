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
    uint64_t cap_eff;
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

static struct metadata enrich_metadata(uint32_t pid, const struct event *ev)
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

    meta.cap_sys_admin = (ev->cap_eff & (1ULL << CAP_SYS_ADMIN_BIT)) != 0;
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
 *  Rule-based detection engine (loaded from policy.yaml)
 * ═════════════════════════════════════════════════════════════════ */

#define MAX_RULES          64
#define MAX_PATHS_PER_RULE 16
#define MAX_EXCLUDES       8

enum match_type {
    MATCH_NONE = 0,
    MATCH_EXACT,
    MATCH_PREFIX,
    MATCH_CONTAINS,
};

struct rule {
    char     name[64];
    char     attack[64];
    uint32_t event_type;
    enum match_type path_match;
    char     paths[MAX_PATHS_PER_RULE][PATH_LEN];
    int      path_count;
    bool     also_match_extra;
    char     exclude_comm[MAX_EXCLUDES][TASK_COMM_LEN];
    int      exclude_count;
    uint32_t family;
    bool     requires_cap;
    int      severity;
    char     message[256];
};

static struct rule policy_rules[MAX_RULES];
static int         policy_rule_count = 0;

/* ── Tiny YAML parser (handles our policy format only) ───────── */

static int parse_severity(const char *s)
{
    if (strcasecmp(s, "CRITICAL") == 0) return 4;
    if (strcasecmp(s, "HIGH") == 0)     return 3;
    if (strcasecmp(s, "MEDIUM") == 0)   return 2;
    if (strcasecmp(s, "LOW") == 0)      return 1;
    return 0;
}

static uint32_t parse_event_type(const char *s)
{
    if (strcmp(s, "mount") == 0)   return EVT_MOUNT;
    if (strcmp(s, "openat") == 0)  return EVT_OPENAT;
    if (strcmp(s, "connect") == 0) return EVT_CONNECT;
    if (strcmp(s, "setns") == 0)   return EVT_SETNS;
    return 0;
}

static enum match_type parse_match(const char *s)
{
    if (strcmp(s, "exact") == 0)    return MATCH_EXACT;
    if (strcmp(s, "prefix") == 0)   return MATCH_PREFIX;
    if (strcmp(s, "contains") == 0) return MATCH_CONTAINS;
    return MATCH_NONE;
}

static char *strip_leading(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

static void strip_quotes(char *s)
{
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len - 1] == '"') {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static int load_policy(const char *path)
{
    FILE *f = fopen(path, "r");
    char line[512];
    struct rule *r = NULL;
    enum { CTX_NONE, CTX_PATHS, CTX_EXCLUDES } list_ctx = CTX_NONE;

    if (!f) {
        fprintf(stderr, "failed to open policy: %s: %s\n", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        trim_newline(line);
        char *s = strip_leading(line);

        if (s[0] == '\0' || s[0] == '#')
            continue;

        /* New rule */
        if (strncmp(s, "- rule:", 7) == 0) {
            if (policy_rule_count >= MAX_RULES) break;
            r = &policy_rules[policy_rule_count++];
            memset(r, 0, sizeof(*r));
            char *val = strip_leading(s + 7);
            strip_quotes(val);
            snprintf(r->name, sizeof(r->name), "%s", val);
            list_ctx = CTX_NONE;
            continue;
        }

        if (!r) continue;

        /* List items */
        if (s[0] == '-' && s[1] == ' ' && list_ctx != CTX_NONE) {
            char *val = strip_leading(s + 2);
            strip_quotes(val);
            if (list_ctx == CTX_PATHS && r->path_count < MAX_PATHS_PER_RULE) {
                snprintf(r->paths[r->path_count++], PATH_LEN, "%s", val);
            } else if (list_ctx == CTX_EXCLUDES && r->exclude_count < MAX_EXCLUDES) {
                snprintf(r->exclude_comm[r->exclude_count++], TASK_COMM_LEN, "%s", val);
            }
            continue;
        }

        list_ctx = CTX_NONE;

        /* Key: value pairs */
        char *colon = strchr(s, ':');
        if (!colon) continue;
        *colon = '\0';
        char *key = s;
        char *val = strip_leading(colon + 1);
        strip_quotes(val);

        if (strcmp(key, "attack") == 0)
            snprintf(r->attack, sizeof(r->attack), "%s", val);
        else if (strcmp(key, "event") == 0)
            r->event_type = parse_event_type(val);
        else if (strcmp(key, "match") == 0)
            r->path_match = parse_match(val);
        else if (strcmp(key, "family") == 0)
            r->family = (uint32_t)atoi(val);
        else if (strcmp(key, "requires_cap_sys_admin") == 0)
            r->requires_cap = (strcmp(val, "true") == 0);
        else if (strcmp(key, "also_match_extra") == 0)
            r->also_match_extra = (strcmp(val, "true") == 0);
        else if (strcmp(key, "severity") == 0)
            r->severity = parse_severity(val);
        else if (strcmp(key, "message") == 0)
            snprintf(r->message, sizeof(r->message), "%s", val);
        else if (strcmp(key, "paths") == 0)
            list_ctx = CTX_PATHS;
        else if (strcmp(key, "exclude_comm") == 0)
            list_ctx = CTX_EXCLUDES;
    }

    fclose(f);
    fprintf(stderr, "  Policy: %d rules from %s\n", policy_rule_count, path);
    return 0;
}

/* ── Rule evaluation ─────────────────────────────────────────── */

static bool match_path_list(const char *value, const struct rule *r)
{
    for (int i = 0; i < r->path_count; i++) {
        switch (r->path_match) {
        case MATCH_EXACT:
            if (strcmp(value, r->paths[i]) == 0) return true;
            break;
        case MATCH_PREFIX:
            if (strncmp(value, r->paths[i], strlen(r->paths[i])) == 0) return true;
            break;
        case MATCH_CONTAINS:
            if (strstr(value, r->paths[i])) return true;
            break;
        case MATCH_NONE:
            break;
        }
    }
    return false;
}

static bool evaluate_rule(const struct rule *r, const struct event *ev,
                          const struct metadata *meta)
{
    if (r->event_type != ev->event_type)
        return false;

    if (r->family != 0 && r->family != ev->family)
        return false;

    if (r->requires_cap && !meta->cap_sys_admin)
        return false;

    for (int i = 0; i < r->exclude_count; i++) {
        if (strncmp(ev->comm, r->exclude_comm[i],
                    strlen(r->exclude_comm[i])) == 0)
            return false;
    }

    if (r->path_count > 0) {
        bool matched = match_path_list(ev->path, r);
        if (!matched && r->also_match_extra && ev->extra[0])
            matched = match_path_list(ev->extra, r);
        if (!matched)
            return false;
    }

    return true;
}

/* ══════════════════════════════════════════════════════════════════
 *  Main event evaluator — runs policy rules in order
 * ═════════════════════════════════════════════════════════════════ */
static void evaluate_event(const struct event *ev)
{
    struct metadata meta;
    const char *p = ev->path;

    if (!p) p = "";

    bool is_container_by_mntns = (host_mntns != 0 && ev->mntns != 0 &&
                                   ev->mntns != host_mntns);

    meta = enrich_metadata(ev->tgid, ev);

    if (!meta.containerized && is_container_by_mntns) {
        meta.containerized = true;
        if (meta.container_id[0] == '\0')
            snprintf(meta.container_id, sizeof(meta.container_id), "unknown");
        if (meta.runtime[0] == '\0')
            snprintf(meta.runtime, sizeof(meta.runtime), "docker");
    }

    if (!meta.containerized)
        return;
    if (meta.container_id[0] == '\0')
        return;
    if (is_noise_comm(ev->comm))
        return;

    /* Evaluate rules in order — first match wins */
    for (int i = 0; i < policy_rule_count; i++) {
        if (evaluate_rule(&policy_rules[i], ev, &meta)) {
            print_alert(ev, &meta, policy_rules[i].severity,
                       policy_rules[i].attack, policy_rules[i].name,
                       policy_rules[i].message);
            return;
        }
    }
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
    const char *policy_path = "examples/policy.yaml";
    struct bpf_object *obj = NULL;
    struct bpf_link *links[4] = {0};
    struct ring_buffer *rb = NULL;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_map *events_map;
    int map_fd, err, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-bpf-object") == 0 && i + 1 < argc) {
            bpf_obj_path = argv[++i];
        } else if (strcmp(argv[i], "-policy") == 0 && i + 1 < argc) {
            policy_path = argv[++i];
        } else if (strcmp(argv[i], "-json") == 0) {
            json_output = true;
        }
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    host_mntns = get_host_mntns();
    self_tgid = (uint32_t)getpid();

    if (load_policy(policy_path) != 0 || policy_rule_count == 0) {
        fprintf(stderr, "no rules loaded — aborting\n");
        return 1;
    }

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
    fprintf(stderr, "  Rules: %d loaded from %s\n", policy_rule_count, policy_path);
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
