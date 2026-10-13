#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16

#define EVT_EXEC     0
#define EVT_NET      1
#define EVT_PRIVESC  2
#define EVT_PERSIST  3
#define EVT_LATERAL  4
#define EVT_EXFIL    5
#define EVT_FILE     6
#define EVT_MKDIR    7
#define EVT_UNLINK   8

#define AF_INET          2
#define IPPROTO_TCP      6
#define TCP_ESTABLISHED  1

struct event {
    __u64 ktime_ns;
    __u32 pid;
    __u32 ppid;
    __u32 type;
    __u32 arg;
    char  comm[TASK_COMM_LEN];
    char  filename[64];
    __u8  daddr[4];
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void fill_common(struct event *e, __u32 type)
{
    struct task_struct *task;

    __builtin_memset(e, 0, sizeof(*e));
    e->ktime_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = type;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
}

static __always_inline int is_rfc1918(__u8 *ip)
{
    if (ip[0] == 10)
        return 1;
    if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31)
        return 1;
    if (ip[0] == 192 && ip[1] == 168)
        return 1;
    return 0;
}

static __always_inline int starts_tmp_update(const char *s)
{
    return s[0] == '/' && s[1] == 't' && s[2] == 'm' &&
           s[3] == 'p' && s[4] == '/' && s[5] == 'u' &&
           s[6] == 'p' && s[7] == 'd' && s[8] == 'a' &&
           s[9] == 't' && s[10] == 'e';
}

static __always_inline int starts_tmp_persist(const char *s)
{
    return s[0] == '/' && s[1] == 't' && s[2] == 'm' &&
           s[3] == 'p' && s[4] == '/' && s[5] == '.' &&
           s[6] == 'p' && s[7] == 'e' && s[8] == 'r' &&
           s[9] == 's' && s[10] == 'i' && s[11] == 's' &&
           s[12] == 't';
}

static __always_inline int starts_tmp_cron(const char *s)
{
    return s[0] == '/' && s[1] == 't' && s[2] == 'm' &&
           s[3] == 'p' && s[4] == '/' && s[5] == 'c' &&
           s[6] == 'r' && s[7] == 'o' && s[8] == 'n';
}

static __always_inline int starts_etc_cron(const char *s)
{
    return s[0] == '/' && s[1] == 'e' && s[2] == 't' &&
           s[3] == 'c' && s[4] == '/' && s[5] == 'c' &&
           s[6] == 'r' && s[7] == 'o' && s[8] == 'n';
}

static __always_inline int starts_root(const char *s)
{
    return s[0] == '/' && s[1] == 'r' && s[2] == 'o' &&
           s[3] == 'o' && s[4] == 't' && s[5] == '/';
}

static __always_inline int starts_tmp_data(const char *s)
{
    return s[0] == '/' && s[1] == 't' && s[2] == 'm' &&
           s[3] == 'p' && s[4] == '/' && s[5] == 'd' &&
           s[6] == 'a' && s[7] == 't' && s[8] == 'a';
}

static __always_inline int starts_tmp_demo_data(const char *s)
{
    return s[0] == '/' && s[1] == 't' && s[2] == 'm' &&
           s[3] == 'p' && s[4] == '/' && s[5] == 'd' &&
           s[6] == 'e' && s[7] == 'm' && s[8] == 'o' &&
           s[9] == '-' && s[10] == 'd' && s[11] == 'a' &&
           s[12] == 't' && s[13] == 'a';
}

static __always_inline int is_etc_passwd(const char *s)
{
    return s[0] == '/' && s[1] == 'e' && s[2] == 't' &&
           s[3] == 'c' && s[4] == '/' && s[5] == 'p' &&
           s[6] == 'a' && s[7] == 's' && s[8] == 's' &&
           s[9] == 'w' && s[10] == 'd';
}

static __always_inline int is_etc_os_release(const char *s)
{
    return s[0] == '/' && s[1] == 'e' && s[2] == 't' &&
           s[3] == 'c' && s[4] == '/' && s[5] == 'o' &&
           s[6] == 's' && s[7] == '-' && s[8] == 'r' &&
           s[9] == 'e' && s[10] == 'l' && s[11] == 'e' &&
           s[12] == 'a' && s[13] == 's' && s[14] == 'e';
}

static __always_inline int is_proc_status(const char *s)
{
    if (s[0] == '/' && s[1] == 'p' && s[2] == 'r' &&
        s[3] == 'o' && s[4] == 'c' && s[5] == '/' &&
        s[6] == '1' && s[7] == '/' && s[8] == 's' &&
        s[9] == 't' && s[10] == 'a' && s[11] == 't' &&
        s[12] == 'u' && s[13] == 's')
        return 1;

    if (s[0] == '/' && s[1] == 'p' && s[2] == 'r' &&
        s[3] == 'o' && s[4] == 'c' && s[5] == '/' &&
        s[6] == 's' && s[7] == 'e' && s[8] == 'l' &&
        s[9] == 'f' && s[10] == '/' && s[11] == 's' &&
        s[12] == 't' && s[13] == 'a' && s[14] == 't' &&
        s[15] == 'u' && s[16] == 's')
        return 1;

    return 0;
}

static __always_inline int is_persist_path(const char *s)
{
    return starts_tmp_update(s) || starts_tmp_persist(s) ||
           starts_tmp_cron(s) || starts_etc_cron(s) || starts_root(s);
}

static __always_inline int is_exfil_path(const char *s)
{
    return starts_tmp_data(s) || starts_tmp_demo_data(s);
}

static __always_inline int is_recon_or_privesc_path(const char *s)
{
    return is_etc_passwd(s) || is_etc_os_release(s) || is_proc_status(s);
}

static __always_inline __u32 classify_path(const char *s)
{
    if (is_persist_path(s))
        return EVT_PERSIST;
    if (is_exfil_path(s))
        return EVT_EXFIL;
    if (is_recon_or_privesc_path(s))
        return EVT_FILE;
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename = (const char *)ctx->args[0];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, EVT_EXEC);
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int handle_tcp(struct trace_event_raw_inet_sock_set_state *ctx)
{
    struct event *e;

    if (ctx->newstate != TCP_ESTABLISHED)
        return 0;
    if (ctx->family != AF_INET)
        return 0;
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, EVT_NET);
    e->daddr[0] = ctx->daddr[0];
    e->daddr[1] = ctx->daddr[1];
    e->daddr[2] = ctx->daddr[2];
    e->daddr[3] = ctx->daddr[3];
    e->dport = bpf_ntohs(ctx->dport);

    if (is_rfc1918(e->daddr))
        e->type = EVT_LATERAL;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int emit_chmod(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename = (const char *)ctx->args[1];
    __u32 mode = (__u32)ctx->args[2];
    __u32 type;
    char fname[64];

    __builtin_memset(fname, 0, sizeof(fname));
    bpf_probe_read_user_str(fname, sizeof(fname), filename);

    if (mode & 06000)
        type = EVT_PRIVESC;
    else
        type = classify_path(fname);

    if (!type)
        type = EVT_FILE;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, type);
    e->arg = mode;
    __builtin_memcpy(e->filename, fname, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_chmod(struct trace_event_raw_sys_enter *ctx)
{
    return emit_chmod(ctx);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int handle_chmod2(struct trace_event_raw_sys_enter *ctx)
{
    return emit_chmod(ctx);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename = (const char *)ctx->args[1];
    __u32 type;
    char fname[64];

    __builtin_memset(fname, 0, sizeof(fname));
    bpf_probe_read_user_str(fname, sizeof(fname), filename);
    type = classify_path(fname);
    if (!type)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, type);
    e->arg = (__u32)ctx->args[2];
    __builtin_memcpy(e->filename, fname, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int handle_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename = (const char *)ctx->args[1];
    __u32 type;
    char fname[64];

    __builtin_memset(fname, 0, sizeof(fname));
    bpf_probe_read_user_str(fname, sizeof(fname), filename);
    type = classify_path(fname);
    if (!type)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, type == EVT_FILE ? EVT_MKDIR : type);
    e->arg = (__u32)ctx->args[2];
    __builtin_memcpy(e->filename, fname, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename = (const char *)ctx->args[1];
    __u32 type;
    char fname[64];

    __builtin_memset(fname, 0, sizeof(fname));
    bpf_probe_read_user_str(fname, sizeof(fname), filename);
    type = classify_path(fname);
    if (!type)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, EVT_UNLINK);
    e->arg = type;
    __builtin_memcpy(e->filename, fname, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
