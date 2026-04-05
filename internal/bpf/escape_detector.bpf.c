#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/un.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Minimal CO-RE stubs for reading mntns from task_struct */
struct ns_common { unsigned int inum; } __attribute__((preserve_access_index));
struct mnt_namespace { struct ns_common ns; } __attribute__((preserve_access_index));
struct nsproxy { struct mnt_namespace *mnt_ns; } __attribute__((preserve_access_index));
struct task_struct { struct nsproxy *nsproxy; } __attribute__((preserve_access_index));

#define TASK_COMM_LEN 16
#define PATH_LEN 128

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

struct trace_event_raw_sys_enter {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    __s64 id;
    __u64 args[6];
};

enum event_type {
    EVT_MOUNT = 1,
    EVT_OPENAT = 2,
    EVT_CONNECT = 3,
    EVT_SETNS = 4,
};

struct event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 mntns;
    __u32 event_type;
    __s32 fd;
    __u32 flags;
    __u32 family;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    char path[PATH_LEN];
    char extra[PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Map to store the detector's own PID so we can skip our own events */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} detector_pid SEC(".maps");

static __always_inline int is_self(void)
{
    __u32 key = 0;
    __u32 *pid = bpf_map_lookup_elem(&detector_pid, &key);
    if (pid && *pid == (bpf_get_current_pid_tgid() >> 32))
        return 1;
    return 0;
}

static __always_inline void fill_common(struct event *e, __u32 event_type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->ts_ns = bpf_ktime_get_ns();
    e->pid = pid_tgid;
    e->tgid = pid_tgid >> 32;
    e->uid = uid_gid;
    e->gid = uid_gid >> 32;
    e->event_type = event_type;
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Read mntns inum directly from task_struct via CO-RE */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
}

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_enter_mount(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    if (is_self())
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_common(e, EVT_MOUNT);
    bpf_probe_read_user_str(e->path, sizeof(e->path), (const void *)ctx->args[0]);
    bpf_probe_read_user_str(e->extra, sizeof(e->extra), (const void *)ctx->args[1]);
    e->flags = (__u32)ctx->args[3];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_enter_setns(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    if (is_self())
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_common(e, EVT_SETNS);
    e->fd = (__s32)ctx->args[0];
    e->flags = (__u32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    if (is_self())
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_common(e, EVT_OPENAT);
    e->fd = (__s32)ctx->args[0];
    bpf_probe_read_user_str(e->path, sizeof(e->path), (const void *)ctx->args[1]);
    e->flags = (__u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    __u16 family = 0;

    if (is_self())
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_common(e, EVT_CONNECT);
    e->fd = (__s32)ctx->args[0];

    /* Zero path/extra so non-AF_UNIX events don't carry garbage */
    __builtin_memset(e->path, 0, sizeof(e->path));
    __builtin_memset(e->extra, 0, sizeof(e->extra));

    bpf_probe_read_user(&family, sizeof(family), (const void *)ctx->args[1]);
    e->family = family;

    if (family == AF_UNIX) {
        /* Read sun_path directly from userspace sockaddr_un (offset 2 = after sun_family) */
        const void *sun_path_ptr = (const void *)(ctx->args[1] + 2);
        bpf_probe_read_user_str(e->path, sizeof(e->path), sun_path_ptr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
