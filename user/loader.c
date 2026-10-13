#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <bpf/libbpf.h>

#define TASK_COMM_LEN  16
#define MAX_STORED     500
#define WINDOW_SECS    30
#define LOG_FILE       "/var/log/ebpf-events.json"

/* Event types - must match bpf/monitor.bpf.c exactly. */
#define EVT_EXEC     0
#define EVT_NET      1
#define EVT_PRIVESC  2
#define EVT_PERSIST  3
#define EVT_LATERAL  4
#define EVT_EXFIL    5
#define EVT_FILE     6
#define EVT_MKDIR    7
#define EVT_UNLINK   8

/* Attack stage bitmask. */
#define STAGE_NONE     0
#define STAGE_ENTRY    (1 << 0)
#define STAGE_RECON    (1 << 1)
#define STAGE_PRIVESC  (1 << 2)
#define STAGE_LATERAL  (1 << 3)
#define STAGE_PERSIST  (1 << 4)
#define STAGE_EXFIL    (1 << 5)

static const char *IGNORE_COMMS[] = {
    "kubelet", "containerd", "containerd-shim",
    "runc", "runc:[2:INIT]", "kubectl", "systemd-journal",
    "systemd", "systemd-resolve",
    "coredns", "kube-proxy", "etcd", "docker-proxy",
    "kube-apiserver", "kindnetd", "firefox", "Socket Thread",
    "xdg-mime", "xdg-settings", NULL
};

static const char *ENTRY_COMMANDS[] = {
    "sh", "bash", "dash", "zsh", "ash", NULL
};

static const char *RECON_COMMANDS[] = {
    "hostname", "whoami", "id", "env", "cat", "ls", "ps",
    "curl", "wget", "nslookup", "dig", "host", "ip", "ifconfig",
    "ss", "netstat", "arp", "nmap", "busybox", NULL
};

static const char *PRIVESC_COMMANDS[] = {
    "sudo", "su", "pkexec", "find", "mount", "capsh", "unshare",
    "setcap", "getcap", NULL
};

static const char *LATERAL_COMMANDS[] = {
    "nc", "ncat", "netcat", "ssh", "scp", "telnet", "socat",
    "psql", "mysql", NULL
};

static const char *PERSIST_COMMANDS[] = {
    "crontab", "systemctl", NULL
};

static const char *EXFIL_COMMANDS[] = {
    "tar", "gzip", "zip", "base64", "scp", "rsync", "openssl", NULL
};

struct bpf_event {
    unsigned long long ktime_ns;
    unsigned int       pid;
    unsigned int       ppid;
    unsigned int       type;
    unsigned int       arg;
    char               comm[TASK_COMM_LEN];
    char               filename[64];
    unsigned char      daddr[4];
    unsigned short     dport;
};

struct stored_event {
    long               ts;
    unsigned int       pid;
    unsigned int       ppid;
    int                type;
    unsigned int       arg;
    char               comm[TASK_COMM_LEN];
    char               filename[64];
    unsigned char      daddr[4];
    unsigned short     dport;
};

static struct stored_event store[MAX_STORED];
static int          store_idx = 0;
static volatile int running = 1;
static FILE        *logfp = NULL;
static int          attack_stages = STAGE_NONE;
static long         stage_first_seen[6] = {0};
static int          last_alert_stage_count = 0;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static int matches(const char *comm, const char **list)
{
    for (int i = 0; list[i]; i++) {
        if (strncmp(comm, list[i], TASK_COMM_LEN) == 0)
            return 1;
    }
    return 0;
}

static const char *base_name(const char *path)
{
    const char *base = path;

    if (!path || !path[0])
        return "";

    for (int i = 0; i < 64 && path[i]; i++) {
        if (path[i] == '/')
            base = &path[i + 1];
    }
    return base;
}

static const char *event_command(const struct bpf_event *e)
{
    const char *exe = base_name(e->filename);

    if (exe[0])
        return exe;
    return e->comm;
}

static int path_starts(const char *path, const char *prefix)
{
    return strncmp(path, prefix, strlen(prefix)) == 0;
}

static int is_recon_path(const char *path)
{
    return strcmp(path, "/etc/passwd") == 0 ||
           strcmp(path, "/etc/os-release") == 0;
}

static int is_privesc_path(const char *path)
{
    return strcmp(path, "/proc/1/status") == 0 ||
           strcmp(path, "/proc/self/status") == 0;
}

static int is_persist_path(const char *path)
{
    return path_starts(path, "/tmp/update") ||
           path_starts(path, "/tmp/.persist") ||
           path_starts(path, "/tmp/cron") ||
           path_starts(path, "/etc/cron") ||
           path_starts(path, "/root/");
}

static int is_exfil_path(const char *path)
{
    return path_starts(path, "/tmp/data") ||
           path_starts(path, "/tmp/demo-data");
}

static void json_escape(char *dst, size_t dst_sz, const char *src)
{
    size_t j = 0;

    if (!dst_sz)
        return;

    if (!src) {
        dst[0] = '\0';
        return;
    }

    for (size_t i = 0; src[i] && j + 1 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];

        if ((c == '"' || c == '\\') && j + 2 < dst_sz) {
            dst[j++] = '\\';
            dst[j++] = (char)c;
        } else if (c == '\n' && j + 2 < dst_sz) {
            dst[j++] = '\\';
            dst[j++] = 'n';
        } else if (c >= 32 && c < 127) {
            dst[j++] = (char)c;
        } else {
            dst[j++] = '?';
        }
    }
    dst[j] = '\0';
}

static void log_json(const char *type, unsigned int pid, unsigned int ppid,
                     const char *comm, const char *detail)
{
    char esc_comm[128];
    char esc_detail[512];

    if (!logfp)
        return;

    json_escape(esc_comm, sizeof(esc_comm), comm);
    json_escape(esc_detail, sizeof(esc_detail), detail);

    fprintf(logfp,
        "{\"ts\":%ld,\"type\":\"%s\",\"pid\":%u,\"ppid\":%u,"
        "\"comm\":\"%s\",\"detail\":\"%s\"}\n",
        time(NULL), type, pid, ppid, esc_comm, esc_detail);
    fflush(logfp);
}

static const char *stage_name(int stage)
{
    switch (stage) {
        case STAGE_ENTRY:   return "ENTRY";
        case STAGE_RECON:   return "RECON";
        case STAGE_PRIVESC: return "PRIVESC";
        case STAGE_LATERAL: return "LATERAL";
        case STAGE_PERSIST: return "PERSIST";
        case STAGE_EXFIL:   return "EXFIL";
        default:            return "UNKNOWN";
    }
}

static void print_stage_line(int stage, const char *label)
{
    if (attack_stages & stage)
        printf("|  [x] %s\n", label);
}

static void mark_stage(int stage, unsigned int pid, unsigned int ppid,
                       const char *comm)
{
    char detail[160];
    int count;

    if (attack_stages & stage)
        return;

    attack_stages |= stage;
    stage_first_seen[__builtin_ctz(stage)] = time(NULL);

    printf("\n[+] STAGE DETECTED: %-8s | comm=%-16s PID=%u\n",
           stage_name(stage), comm, pid);

    snprintf(detail, sizeof(detail), "Stage=%s comm=%s pid=%u",
             stage_name(stage), comm, pid);
    log_json("STAGE", pid, ppid, comm, detail);

    count = __builtin_popcount((unsigned int)attack_stages);
    if (count < 2 || count <= last_alert_stage_count)
        return;

    last_alert_stage_count = count;

    printf("\n");
    printf("+--------------------------------------+\n");
    printf("|     MULTI-STAGE ATTACK DETECTED      |\n");
    printf("+--------------------------------------+\n");
    printf("| Stages completed: %d/6\n", count);
    print_stage_line(STAGE_ENTRY,   "Stage 1: Shell Entry");
    print_stage_line(STAGE_RECON,   "Stage 2: Reconnaissance");
    print_stage_line(STAGE_PRIVESC, "Stage 3: Privilege Escalation");
    print_stage_line(STAGE_LATERAL, "Stage 4: Lateral Movement");
    print_stage_line(STAGE_PERSIST, "Stage 5: Persistence");
    print_stage_line(STAGE_EXFIL,   "Stage 6: Data Exfiltration");
    printf("+--------------------------------------+\n\n");

    snprintf(detail, sizeof(detail),
             "MULTI-STAGE ATTACK: %d/6 stages completed stages_mask=%d",
             count, attack_stages);
    log_json("ALERT", pid, ppid, comm, detail);
}

static void detect_exec_stages(const struct bpf_event *e, const char *cmd)
{
    if (matches(cmd, ENTRY_COMMANDS))
        mark_stage(STAGE_ENTRY, e->pid, e->ppid, cmd);
    if (matches(cmd, RECON_COMMANDS))
        mark_stage(STAGE_RECON, e->pid, e->ppid, cmd);
    if (matches(cmd, PRIVESC_COMMANDS))
        mark_stage(STAGE_PRIVESC, e->pid, e->ppid, cmd);
    if (matches(cmd, LATERAL_COMMANDS))
        mark_stage(STAGE_LATERAL, e->pid, e->ppid, cmd);
    if (matches(cmd, PERSIST_COMMANDS))
        mark_stage(STAGE_PERSIST, e->pid, e->ppid, cmd);
    if (matches(cmd, EXFIL_COMMANDS))
        mark_stage(STAGE_EXFIL, e->pid, e->ppid, cmd);
}

static void detect_file_stages(const struct bpf_event *e, const char *subject)
{
    if (is_recon_path(e->filename))
        mark_stage(STAGE_RECON, e->pid, e->ppid, subject);
    if (is_privesc_path(e->filename))
        mark_stage(STAGE_PRIVESC, e->pid, e->ppid, subject);
    if (is_persist_path(e->filename))
        mark_stage(STAGE_PERSIST, e->pid, e->ppid, subject);
    if (is_exfil_path(e->filename))
        mark_stage(STAGE_EXFIL, e->pid, e->ppid, subject);
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct bpf_event *e = data;
    const char *cmd = event_command(e);
    long now = time(NULL);
    char detail[256];

    (void)ctx;
    (void)len;

    if (matches(e->comm, IGNORE_COMMS) ||
    matches(cmd, IGNORE_COMMS))
    return 0;

    struct stored_event se = {
        .ts    = now,
        .pid   = e->pid,
        .ppid  = e->ppid,
        .type  = (int)e->type,
        .arg   = e->arg,
        .dport = e->dport,
    };
    strncpy(se.comm, e->comm, TASK_COMM_LEN - 1);
    strncpy(se.filename, e->filename, sizeof(se.filename) - 1);
    memcpy(se.daddr, e->daddr, sizeof(se.daddr));
    store[store_idx % MAX_STORED] = se;
    store_idx++;

    switch (e->type) {
    case EVT_EXEC:
        printf("[EXEC   ] PID=%-6u PPID=%-6u comm=%-16s exe=%s\n",
               e->pid, e->ppid, e->comm, e->filename);
        snprintf(detail, sizeof(detail), "exe=%s parent_comm=%s",
                 e->filename, e->comm);
        log_json("EXEC", e->pid, e->ppid, cmd, detail);
        detect_exec_stages(e, cmd);
        break;

    case EVT_NET:
        printf("[NET    ] PID=%-6u comm=%-16s dst=%u.%u.%u.%u:%u\n",
               e->pid, e->comm, e->daddr[0], e->daddr[1],
               e->daddr[2], e->daddr[3], e->dport);
        snprintf(detail, sizeof(detail), "dst=%u.%u.%u.%u port=%u",
                 e->daddr[0], e->daddr[1], e->daddr[2], e->daddr[3],
                 e->dport);
        log_json("NET", e->pid, e->ppid, e->comm, detail);
        break;

    case EVT_LATERAL:
        printf("[LATERAL] PID=%-6u comm=%-16s dst=%u.%u.%u.%u:%u\n",
               e->pid, e->comm, e->daddr[0], e->daddr[1],
               e->daddr[2], e->daddr[3], e->dport);
        snprintf(detail, sizeof(detail), "dst=%u.%u.%u.%u port=%u",
                 e->daddr[0], e->daddr[1], e->daddr[2], e->daddr[3],
                 e->dport);
        log_json("LATERAL", e->pid, e->ppid, e->comm, detail);
        mark_stage(STAGE_LATERAL, e->pid, e->ppid, e->comm);
        break;

    case EVT_PRIVESC:
        printf("[PRIVESC] PID=%-6u comm=%-16s mode=0%o file=%s\n",
               e->pid, e->comm, e->arg, e->filename);
        snprintf(detail, sizeof(detail), "mode=0%o file=%s",
                 e->arg, e->filename);
        log_json("PRIVESC", e->pid, e->ppid, e->comm, detail);
        mark_stage(STAGE_PRIVESC, e->pid, e->ppid, e->comm);
        detect_file_stages(e, e->comm);
        break;

    case EVT_PERSIST:
        printf("[PERSIST] PID=%-6u comm=%-16s file=%s\n",
               e->pid, e->comm, e->filename);
        snprintf(detail, sizeof(detail), "file=%s", e->filename);
        log_json("PERSIST", e->pid, e->ppid, e->comm, detail);
        mark_stage(STAGE_PERSIST, e->pid, e->ppid, e->comm);
        detect_file_stages(e, e->comm);
        break;

    case EVT_EXFIL:
        printf("[EXFIL  ] PID=%-6u comm=%-16s file=%s\n",
               e->pid, e->comm, e->filename);
        snprintf(detail, sizeof(detail), "file=%s", e->filename);
        log_json("EXFIL", e->pid, e->ppid, e->comm, detail);
        mark_stage(STAGE_EXFIL, e->pid, e->ppid, e->comm);
        break;

    case EVT_FILE:
        printf("[FILE   ] PID=%-6u comm=%-16s file=%s\n",
               e->pid, e->comm, e->filename);
        snprintf(detail, sizeof(detail), "file=%s flags=0x%x",
                 e->filename, e->arg);
        log_json("FILE", e->pid, e->ppid, e->comm, detail);
        detect_file_stages(e, e->comm);
        break;

    case EVT_MKDIR:
        printf("[MKDIR  ] PID=%-6u comm=%-16s mode=0%o dir=%s\n",
               e->pid, e->comm, e->arg, e->filename);
        snprintf(detail, sizeof(detail), "dir=%s mode=0%o",
                 e->filename, e->arg);
        log_json("MKDIR", e->pid, e->ppid, e->comm, detail);
        detect_file_stages(e, e->comm);
        break;

    case EVT_UNLINK:
        printf("[UNLINK ] PID=%-6u comm=%-16s file=%s\n",
               e->pid, e->comm, e->filename);
        snprintf(detail, sizeof(detail), "file=%s class=%u",
                 e->filename, e->arg);
        log_json("UNLINK", e->pid, e->ppid, e->comm, detail);
        detect_file_stages(e, e->comm);
        break;

    default:
        break;
    }

    return 0;
}

int main(void)
{
    struct bpf_object  *obj;
    struct bpf_program *prog;
    struct bpf_link    *links[8] = {NULL};
    struct ring_buffer *rb = NULL;
    int err, map_fd;
    int link_count = 0;

    struct hook {
        const char *name;
        int required;
    };

    const struct hook hooks[] = {
        {"handle_execve", 1},
        {"handle_tcp", 1},
        {"handle_chmod", 1},
        {"handle_chmod2", 0},
        {"handle_openat", 1},
        {"handle_mkdirat", 1},
        {"handle_unlinkat", 1},
    };

    signal(SIGINT, sig_handler);

    logfp = fopen(LOG_FILE, "w");
    if (!logfp) {
        fprintf(stderr, "Cannot open %s - run with sudo\n", LOG_FILE);
        return 1;
    }
    printf("Logging to %s\n", LOG_FILE);
    log_json("SESSION", 0, 0, "loader", "session_start");

    FILE *sf = fopen("/var/log/ebpf-session.txt", "w");
    if (sf) {
        fprintf(sf, "%ld\n", time(NULL));
        fclose(sf);
    }

    obj = bpf_object__open_file("build/monitor.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    for (size_t i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
        struct bpf_link *link;

        prog = bpf_object__find_program_by_name(obj, hooks[i].name);
        if (!prog) {
            if (hooks[i].required) {
                fprintf(stderr, "%s not found\n", hooks[i].name);
                return 1;
            }
            printf("Optional hook not found: %s\n", hooks[i].name);
            continue;
        }

        link = bpf_program__attach(prog);
        err = libbpf_get_error(link);
        if (err) {
            if (hooks[i].required) {
                fprintf(stderr, "Failed to attach %s: %d\n", hooks[i].name, err);
                return 1;
            }
            printf("Optional hook not attached: %s (%d)\n", hooks[i].name, err);
            continue;
        }

        links[link_count++] = link;
        printf("Attached: %s\n", hooks[i].name);
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "events map not found\n");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("\n");
    printf("+--------------------------------------+\n");
    printf("|   eBPF Full Attack Chain Detector    |\n");
    printf("|   Monitoring 6 attack stages         |\n");
    printf("|   Stage alerts update up to 6/6      |\n");
    printf("+--------------------------------------+\n\n");
    printf("Hooks: execve | tcp | fchmodat/fchmodat2 | openat | mkdirat | unlinkat\n\n");

    while (running)
        ring_buffer__poll(rb, 100);

    printf("\nShutting down...\n");
    ring_buffer__free(rb);
    for (int i = 0; i < link_count; i++)
        if (links[i])
            bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    if (logfp)
        fclose(logfp);
    return 0;
}
