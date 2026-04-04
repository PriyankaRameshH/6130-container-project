/*
 * simulate_attack.c — Container Escape Attack Simulator
 *
 * Triggers the exact syscalls the eBPF detector monitors:
 *   - openat()  → /var/run/docker.sock  (docker socket escape)
 *   - openat()  → /proc/1/maps          (sensitive host path access)
 *   - connect() → /var/run/docker.sock  (docker socket connect escape)
 *   - mount()                            (privileged container escape)
 *   - setns()                            (namespace escape)
 *
 * All operations are intentionally non-destructive: they will fail with
 * EPERM/EACCES if not privileged, but the kernel tracepoints still fire
 * so the eBPF detector generates real alerts.
 *
 * Run this in a second terminal while the detector is running:
 *   ./bin/simulate_attack
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define RESET   "\033[0m"
#define RED     "\033[1;31m"
#define YELLOW  "\033[1;33m"
#define CYAN    "\033[1;36m"
#define GREEN   "\033[1;32m"

static void banner(void)
{
    printf(RED
           "╔══════════════════════════════════════════════════╗\n"
           "║      CONTAINER ESCAPE ATTACK SIMULATOR          ║\n"
           "║      (non-destructive — for demo/testing)       ║\n"
           "╚══════════════════════════════════════════════════╝\n"
           RESET "\n");
}

static void section(const char *title)
{
    printf(CYAN "\n═══ %s ═══\n" RESET, title);
}

static void attempt(const char *desc)
{
    printf(YELLOW "  [>] %s ... " RESET, desc);
    fflush(stdout);
}

static void result(int err_no)
{
    if (err_no == 0) {
        printf(GREEN "[SUCCESS]\n" RESET);
    } else {
        printf(RED "[BLOCKED: %s]\n" RESET, strerror(err_no));
    }
}

/* ─── Attack 1: Docker socket open (openat) ─────────────────────── */
static void attack_docker_socket_open(void)
{
    section("ATTACK 1 — Docker Socket Open (openat)");
    printf("  Technique: Open /var/run/docker.sock to gain Docker API access.\n");
    printf("  Impact:    Full host control via Docker daemon.\n\n");

    attempt("openat(\"/var/run/docker.sock\", O_RDWR)");
    int fd = open("/var/run/docker.sock", O_RDWR);
    if (fd >= 0) {
        result(0);
        close(fd);
    } else {
        result(errno);
    }
}

/* ─── Attack 2: Docker socket connect ───────────────────────────── */
static void attack_docker_socket_connect(void)
{
    section("ATTACK 2 — Docker Socket Connect (connect)");
    printf("  Technique: Connect via UNIX socket to Docker daemon.\n");
    printf("  Impact:    Spawn privileged containers, mount host filesystem.\n\n");

    attempt("connect() → /var/run/docker.sock");
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        result(errno);
        return;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/var/run/docker.sock", sizeof(addr.sun_path) - 1);

    int r = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    result(r == 0 ? 0 : errno);
    close(sockfd);
}

/* ─── Attack 3: Sensitive host path access ──────────────────────── */
static void attack_sensitive_paths(void)
{
    section("ATTACK 3 — Sensitive Host Path Access (openat)");
    printf("  Technique: Read host /proc and /sys to enumerate processes,\n");
    printf("             network state, and kernel parameters.\n\n");

    const char *paths[] = {
        "/proc/1/maps",
        "/proc/1/environ",
        "/proc/sysrq-trigger",
        "/sys/kernel/security",
        "/etc/shadow",
        NULL,
    };

    for (int i = 0; paths[i] != NULL; i++) {
        char buf[128];
        snprintf(buf, sizeof(buf), "openat(\"%s\")", paths[i]);
        attempt(buf);
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) {
            result(0);
            close(fd);
        } else {
            result(errno);
        }
    }
}

/* ─── Attack 4: Mount syscall (privileged escape) ───────────────── */
static void attack_mount(void)
{
    section("ATTACK 4 — Mount Syscall (privileged container escape)");
    printf("  Technique: Mount host /proc over /mnt to access host namespace.\n");
    printf("  Impact:    Full visibility into host processes and cgroups.\n\n");

    attempt("mount(\"proc\", \"/mnt\", \"proc\", 0, NULL)");
    int r = mount("proc", "/mnt", "proc", 0, NULL);
    result(r == 0 ? 0 : errno);
    if (r == 0) {
        umount("/mnt");
    }
}

/* ─── Attack 5: setns (namespace escape) ────────────────────────── */
static void attack_setns(void)
{
    section("ATTACK 5 — setns (namespace escape)");
    printf("  Technique: Open init process network namespace and setns into it.\n");
    printf("  Impact:    Escape network isolation, access host network stack.\n\n");

    attempt("open(\"/proc/1/ns/net\")");
    int ns_fd = open("/proc/1/ns/net", O_RDONLY);
    if (ns_fd < 0) {
        result(errno);
        return;
    }
    result(0);

    attempt("setns(ns_fd, CLONE_NEWNET)");
    int r = setns(ns_fd, CLONE_NEWNET);
    result(r == 0 ? 0 : errno);
    close(ns_fd);
}

int main(void)
{
    banner();
    printf("PID: %d  UID: %d\n", getpid(), getuid());
    printf("Triggering attack syscalls — check the detector terminal for alerts.\n");

    attack_docker_socket_open();
    sleep(1);
    attack_docker_socket_connect();
    sleep(1);
    attack_sensitive_paths();
    sleep(1);
    attack_mount();
    sleep(1);
    attack_setns();

    printf(GREEN
           "\n╔══════════════════════════════════════════════════╗\n"
           "║  All attack scenarios executed.                  ║\n"
           "║  Check the detector terminal for real alerts.   ║\n"
           "╚══════════════════════════════════════════════════╝\n"
           RESET "\n");
    return 0;
}
