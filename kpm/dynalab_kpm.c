/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/sched.h>
#include <linux/reboot.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <uapi/linux/fs.h>
#include "../include/dl_rpc.h"

/* Minimal KernelPatch KPM ABI declarations, using the target kernel's types. */
#define DL_KPM_INFO(key, value, limit)                                  \
    _Static_assert(sizeof(value) <= limit, "KPM info too long");        \
    static const char dl_kpm_info_##key[] __attribute__((used,           \
        section(".kpm.info"), aligned(1))) = #key "=" value
#define KPM_NAME(x)        DL_KPM_INFO(name, x, 32)
#define KPM_VERSION(x)     DL_KPM_INFO(version, x, 32)
#define KPM_LICENSE(x)     DL_KPM_INFO(license, x, 32)
#define KPM_AUTHOR(x)      DL_KPM_INFO(author, x, 32)
#define KPM_DESCRIPTION(x) DL_KPM_INFO(description, x, 512)

typedef long (*dl_kpm_init_t)(const char *, const char *, void __user *);
typedef long (*dl_kpm_ctl0_t)(const char *, char __user *, int);
typedef long (*dl_kpm_exit_t)(void __user *);
#define KPM_INIT(fn) static dl_kpm_init_t dl_init_##fn __attribute__((used, section(".kpm.init"))) = fn
#define KPM_CTL0(fn) static dl_kpm_ctl0_t dl_ctl_##fn __attribute__((used, section(".kpm.ctl0"))) = fn
#define KPM_EXIT(fn) static dl_kpm_exit_t dl_exit_##fn __attribute__((used, section(".kpm.exit"))) = fn

struct dl_hook_local { u64 data[8]; };
struct dl_hook_fargs4 {
    void *chain;
    int skip_origin;
    struct dl_hook_local local;
    u64 ret;
    union { struct { u64 arg0, arg1, arg2, arg3; }; u64 args[4]; };
} __attribute__((aligned(8)));
typedef struct dl_hook_fargs4 hook_fargs1_t;
typedef struct dl_hook_fargs4 hook_fargs2_t;
typedef struct dl_hook_fargs4 hook_fargs3_t;
typedef struct dl_hook_fargs4 hook_fargs4_t;
struct dl_hook_fargs8 {
    void *chain;
    int skip_origin;
    struct dl_hook_local local;
    u64 ret;
    union {
        struct { u64 arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7; };
        u64 args[8];
    };
} __attribute__((aligned(8)));
typedef struct dl_hook_fargs8 hook_fargs5_t;

extern int hook_wrap(void *func, int argc, void *before, void *after, void *udata);
extern void unhook(void *func);
extern int compat_copy_to_user(void __user *to, const void *from, int n);
extern long compat_strncpy_from_user(char *dest, const char __user *src, long count);
/* KernelPatch exports function-pointer variables with these ELF symbol names. */
extern unsigned long (*kp_lookup_name)(const char *name) __asm__("kallsyms_lookup_name");
extern int (*kp_printk)(const char *fmt, ...) __asm__("printk");
#define dl_log(fmt, ...) kp_printk("[dynalab] " fmt, ##__VA_ARGS__)

KPM_NAME("KPMDynaLab");
KPM_VERSION("0.5.1-test");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("YiJieqwq");
KPM_DESCRIPTION("Android block-device dynamic analysis prototype");

enum dl_profile { DL_TRACE = 1, DL_AUTO = 2, DL_EXPERT = 3 };
enum dl_state { DL_READY = 1, DL_CONFIGURED = 2, DL_SEALED = 3 };

static int profile = DL_AUTO;
static int state = DL_READY;
static void *sym_write_iter, *sym_ioctl, *sym_fallocate, *sym_reboot;
static void *sym_fork, *sym_exec, *sym_exit;
static void (*fn_iov_iter_advance)(struct iov_iter *i, size_t bytes);
static pid_t (*fn_task_pid_nr)(struct task_struct *task, int type,
                               struct pid_namespace *ns);

static struct proc_dir_entry *proc_dir, *proc_control, *proc_events;
static struct proc_dir_entry *(*fn_proc_mkdir)(const char *, struct proc_dir_entry *);
static struct proc_dir_entry *(*fn_proc_create)(const char *, umode_t,
                                                struct proc_dir_entry *,
                                                const struct proc_ops *);
static void (*fn_proc_remove)(struct proc_dir_entry *);

static unsigned long long login_verifier;
static int login_configured;
static int authenticated_tgid = -1;
static char control_reply[96] = "READY";
static struct dl_wire_event event_ring[DL_EVENT_CAPACITY];
static unsigned int event_head;

#define DL_MAX_SUBJECTS 256
struct dl_subject {
    int active;
    int pid;
    int tgid;
    int parent_pid;
    unsigned int session_id;
    unsigned int scope;
};
static struct dl_subject subjects[DL_MAX_SUBJECTS];
static unsigned int session_counter;
static unsigned int active_session;


static int streq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static const char *profile_name(void)
{
    return profile == DL_TRACE ? "TRACE" : profile == DL_AUTO ? "AUTO" : "EXPERT";
}

static int str_len(const char *s)
{
    int n = 0;
    while (s && s[n]) n++;
    return n;
}

static long ctl_reply(char __user *out_msg, int outlen, const char *msg)
{
    int len = str_len(msg) + 1;
    if (!out_msg || outlen <= 0)
        return 0;
    if (len > outlen)
        len = outlen;
    return compat_copy_to_user(out_msg, msg, len) > 0 ? 0 : -14;
}

static void set_reply(const char *msg)
{
    int i = 0;
    while (msg[i] && i < (int)sizeof(control_reply) - 1) {
        control_reply[i] = msg[i];
        i++;
    }
    control_reply[i] = '\0';
}

static int prefix(const char *s, const char *p)
{
    while (*p && *s == *p) { s++; p++; }
    return *p == '\0';
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex64(const char *s, unsigned long long *value)
{
    unsigned long long v = 0;
    int i, x;
    for (i = 0; i < 16; i++) {
        x = hex_value(s[i]);
        if (x < 0) return -1;
        v = (v << 4) | (unsigned int)x;
    }
    if (s[16] != '\0') return -1;
    *value = v;
    return 0;
}

static int parse_decimal(const char *s, int *value)
{
    int v = 0;
    if (!*s) return -1;
    while (*s) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (*s++ - '0');
        if (v < 0) return -1;
    }
    *value = v;
    return 0;
}

static unsigned long long make_verifier(const char *s)
{
    unsigned long long h = 1469598103934665603ULL;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 1099511628211ULL;
    }
    return h;
}

static int current_id(int type)
{
    if (!fn_task_pid_nr) return -1;
    return fn_task_pid_nr(current, type, NULL);
}

static struct dl_subject *find_subject(int pid)
{
    int i;
    for (i = 0; i < DL_MAX_SUBJECTS; i++)
        if (subjects[i].active && subjects[i].pid == pid)
            return &subjects[i];
    return NULL;
}

static struct dl_subject *add_subject(int pid, int tgid, int parent_pid,
                                      unsigned int sid, unsigned int scope)
{
    int i;
    struct dl_subject *s = find_subject(pid);
    if (s) return s;
    for (i = 0; i < DL_MAX_SUBJECTS; i++) {
        if (!subjects[i].active) {
            subjects[i].active = 1;
            subjects[i].pid = pid;
            subjects[i].tgid = tgid;
            subjects[i].parent_pid = parent_pid;
            subjects[i].session_id = sid;
            subjects[i].scope = scope;
            return &subjects[i];
        }
    }
    return NULL;
}

static void clear_subjects(void)
{
    int i;
    for (i = 0; i < DL_MAX_SUBJECTS; i++)
        subjects[i].active = 0;
    active_session = 0;
}

static int active_subject_count(void)
{
    int i, n = 0;
    for (i = 0; i < DL_MAX_SUBJECTS; i++)
        if (subjects[i].active && subjects[i].session_id == active_session)
            n++;
    return n;
}

static void set_active_reply(void)
{
    char tmp[32];
    int n = active_subject_count();
    int pos = 0, start, end;
    const char *p = "ACTIVE ";
    while (*p) tmp[pos++] = *p++;
    if (!n) tmp[pos++] = '0';
    else {
        start = pos;
        while (n) { tmp[pos++] = '0' + n % 10; n /= 10; }
        end = pos - 1;
        while (start < end) {
            char c = tmp[start]; tmp[start++] = tmp[end]; tmp[end--] = c;
        }
    }
    tmp[pos] = '\0';
    set_reply(tmp);
}

static int cli_authenticated(void)
{
    return authenticated_tgid == current_id(1);
}

static void add_event_for(unsigned short type, unsigned short action,
                          int pid, int tgid, int parent_pid,
                          dev_t dev, unsigned long long offset,
                          unsigned long long length, unsigned int command,
                          unsigned int sid, unsigned int scope,
                          const char *name)
{
    unsigned int seq = event_head++;
    int i = 0;
    struct dl_wire_event *e = &event_ring[seq % DL_EVENT_CAPACITY];
    e->magic = DL_EVENT_MAGIC;
    e->version = DL_RPC_VERSION;
    e->type = type;
    e->action = action;
    e->reserved = 0;
    e->pid = pid;
    e->tgid = tgid;
    e->major = MAJOR(dev);
    e->minor = MINOR(dev);
    e->offset = offset;
    e->length = length;
    e->command = command;
    e->sequence = seq + 1;
    e->parent_pid = parent_pid;
    e->session_id = sid;
    e->scope = scope;
    if (name) {
        while (name[i] && i < (int)sizeof(e->name) - 1) {
            e->name[i] = name[i];
            i++;
        }
    }
    e->name[i] = '\0';
}

static void add_event(unsigned short type, unsigned short action,
                      dev_t dev, unsigned long long offset,
                      unsigned long long length, unsigned int command)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    add_event_for(type, action, pid, current_id(1),
                  s ? s->parent_pid : 0, dev, offset, length, command,
                  s ? s->session_id : 0,
                  s ? s->scope : DL_SCOPE_GLOBAL, NULL);
}

static ssize_t control_read(struct file *file, char __user *buf,
                            size_t count, loff_t *ppos)
{
    int len = str_len(control_reply);
    int copied;
    if (*ppos >= len) return 0;
    if (count > (size_t)(len - *ppos)) count = len - *ppos;
    copied = compat_copy_to_user(buf, control_reply + *ppos, count);
    if (copied <= 0) return -14;
    *ppos += copied;
    return copied;
}

static ssize_t control_write(struct file *file, const char __user *buf,
                             size_t count, loff_t *ppos)
{
    char cmd[96];
    long n;
    unsigned long long value;
    if (!count || count >= sizeof(cmd)) return -22;
    n = compat_strncpy_from_user(cmd, buf, count + 1);
    if (n <= 0) return -14;
    cmd[count] = '\0';
    while (count && (cmd[count - 1] == '\n' || cmd[count - 1] == '\r'))
        cmd[--count] = '\0';

    if (streq(cmd, "STATUS")) {
        if (!login_configured) set_reply("UNINITIALIZED");
        else if (state == DL_READY) set_reply("READY AUTO OFF");
        else if (state == DL_CONFIGURED) set_reply("CONFIGURED");
        else if (profile == DL_TRACE) set_reply("SEALED TRACE PASS");
        else if (profile == DL_AUTO) set_reply("SEALED AUTO SIM");
        else set_reply("SEALED EXPERT SIM");
        return n;
    }

    if (prefix(cmd, "LOGIN ")) {
        if (!login_configured) {
            set_reply("ERR UNINITIALIZED");
        } else if (!parse_hex64(cmd + 6, &value) && value == login_verifier) {
            authenticated_tgid = current_id(1);
            set_reply("OK LOGIN");
        } else {
            set_reply("ERR AUTH");
        }
        return n;
    }

    if (!cli_authenticated()) {
        set_reply("ERR LOGIN");
        return -13;
    }

    if (streq(cmd, "ACTIVE")) {
        set_active_reply();
    } else if (prefix(cmd, "TARGET ")) {
        int target_pid;
        if (state == DL_SEALED) { set_reply("ERR SEALED"); return -1; }
        if (parse_decimal(cmd + 7, &target_pid)) {
            set_reply("ERR TARGET");
            return -22;
        }
        clear_subjects();
        active_session = ++session_counter;
        if (!active_session) active_session = ++session_counter;
        if (!add_subject(target_pid, target_pid, current_id(0),
                         active_session, DL_SCOPE_TARGET)) {
            set_reply("ERR SUBJECTS");
            return -12;
        }
        set_reply("OK TARGET");
    } else if (prefix(cmd, "PROFILE ")) {
        if (state == DL_SEALED) { set_reply("ERR SEALED"); return -1; }
        if (streq(cmd + 8, "auto")) profile = DL_AUTO;
        else if (streq(cmd + 8, "trace")) profile = DL_TRACE;
        else if (streq(cmd + 8, "expert")) profile = DL_EXPERT;
        else { set_reply("ERR PROFILE"); return -22; }
        state = DL_CONFIGURED;
        set_reply("OK PROFILE");
    } else if (streq(cmd, "SEAL")) {
        if (state == DL_READY) state = DL_CONFIGURED;
        state = DL_SEALED;
        set_reply("OK SEALED");
    } else if (streq(cmd, "STOP")) {
        state = DL_READY;
        profile = DL_AUTO;
        clear_subjects();
        set_reply("OK STOP");
    } else if (streq(cmd, "CLEAR")) {
        event_head = 0;
        set_reply("OK CLEAR");
    } else if (streq(cmd, "LOGOUT")) {
        authenticated_tgid = -1;
        set_reply("OK LOGOUT");
    } else {
        set_reply("ERR COMMAND");
        return -22;
    }
    return n;
}

static ssize_t events_read(struct file *file, char __user *buf,
                           size_t count, loff_t *ppos)
{
    unsigned int total = event_head;
    unsigned int start = total > DL_EVENT_CAPACITY ? total - DL_EVENT_CAPACITY : 0;
    unsigned int item = (unsigned int)(*ppos / sizeof(struct dl_wire_event));
    unsigned int available = total - start;
    struct dl_wire_event *event;
    int copied;
    if (count < sizeof(struct dl_wire_event) || item >= available)
        return 0;
    event = &event_ring[(start + item) % DL_EVENT_CAPACITY];
    copied = compat_copy_to_user(buf, event, sizeof(*event));
    if (copied <= 0) return -14;
    *ppos += copied;
    return copied;
}

static const struct proc_ops control_ops = {
    .proc_read = control_read,
    .proc_write = control_write,
};

static const struct proc_ops events_ops = {
    .proc_read = events_read,
};

static int simulate_dangerous(void)
{
    /* Analysis policy becomes active only after the manager seals it. */
    return state == DL_SEALED && profile != DL_TRACE;
}

static void before_fork(hook_fargs1_t *args, void *udata)
{
    struct task_struct *child = (struct task_struct *)args->arg0;
    int parent_pid = current_id(0);
    int child_pid, child_tgid;
    struct dl_subject *parent;
    if (!child) return;
    parent = find_subject(parent_pid);
    if (!parent) return;
    child_pid = fn_task_pid_nr(child, 0, NULL);
    child_tgid = fn_task_pid_nr(child, 1, NULL);
    add_subject(child_pid, child_tgid, parent_pid,
                parent->session_id, DL_SCOPE_DESCENDANT);
    add_event_for(DL_WIRE_FORK, DL_WIRE_PASS, child_pid, child_tgid,
                  parent_pid, 0, 0, 0, 0, parent->session_id,
                  DL_SCOPE_DESCENDANT, NULL);
}

static void before_exec(hook_fargs5_t *args, void *udata)
{
    struct filename *filename = (struct filename *)args->arg1;
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    if (!s) return;
    add_event_for(DL_WIRE_EXEC, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, 0, 0, 0, s->session_id, s->scope,
                  filename ? filename->name : NULL);
}

static void before_exit(hook_fargs1_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    if (!s) return;
    add_event_for(DL_WIRE_EXIT, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, 0, (unsigned long long)args->arg0,
                  0, s->session_id, s->scope, NULL);
    s->active = 0;
}

static void before_blkdev_write_iter(hook_fargs2_t *args, void *udata)
{
    struct kiocb *iocb = (struct kiocb *)args->arg0;
    struct iov_iter *from = (struct iov_iter *)args->arg1;
    size_t count;
    loff_t pos;
    dev_t dev = 0;

    if (!iocb || !from) return;
    count = iov_iter_count(from);
    pos = iocb->ki_pos;
    if (iocb->ki_filp && iocb->ki_filp->f_mapping &&
        iocb->ki_filp->f_mapping->host)
        dev = iocb->ki_filp->f_mapping->host->i_rdev;

    dl_log("BLOCK_WRITE pid=%d dev=%u:%u off=%lld len=%zu profile=%s action=%s\n",
            current_id(0), MAJOR(dev), MINOR(dev), pos, count, profile_name(),
            simulate_dangerous() ? "SIMULATE" : "PASS");

    add_event(DL_WIRE_BLOCK_WRITE,
              simulate_dangerous() ? DL_WIRE_SIMULATE : DL_WIRE_PASS,
              dev, pos, count, 0);

    if (!simulate_dangerous()) return;
    fn_iov_iter_advance(from, count);
    iocb->ki_pos += count;
    args->skip_origin = 1;
    args->ret = count;
}

static int dangerous_ioctl(unsigned int cmd)
{
    return cmd == BLKZEROOUT || cmd == BLKDISCARD || cmd == BLKSECDISCARD;
}

static void before_blkdev_ioctl(hook_fargs3_t *args, void *udata)
{
    struct file *file = (struct file *)args->arg0;
    unsigned int cmd = (unsigned int)args->arg1;
    dev_t dev = 0;

    if (!dangerous_ioctl(cmd)) return;
    if (file && file->f_mapping && file->f_mapping->host)
        dev = file->f_mapping->host->i_rdev;

    dl_log("BLOCK_IOCTL pid=%d dev=%u:%u cmd=0x%x profile=%s action=%s\n",
            current_id(0), MAJOR(dev), MINOR(dev), cmd, profile_name(),
            simulate_dangerous() ? "SIMULATE" : "PASS");

    add_event(DL_WIRE_BLOCK_IOCTL,
              simulate_dangerous() ? DL_WIRE_SIMULATE : DL_WIRE_PASS,
              dev, 0, 0, cmd);

    if (simulate_dangerous()) {
        args->skip_origin = 1;
        args->ret = 0;
    }
}

static void before_blkdev_fallocate(hook_fargs4_t *args, void *udata)
{
    struct file *file = (struct file *)args->arg0;
    int mode = (int)args->arg1;
    loff_t start = (loff_t)args->arg2;
    loff_t len = (loff_t)args->arg3;
    dev_t dev = 0;

    if (file && file->f_mapping && file->f_mapping->host)
        dev = file->f_mapping->host->i_rdev;

    dl_log("BLOCK_FALLOCATE pid=%d dev=%u:%u mode=0x%x off=%lld len=%lld profile=%s action=%s\n",
            current_id(0), MAJOR(dev), MINOR(dev), mode, start, len,
            profile_name(), simulate_dangerous() ? "SIMULATE" : "PASS");

    add_event(DL_WIRE_BLOCK_FALLOCATE,
              simulate_dangerous() ? DL_WIRE_SIMULATE : DL_WIRE_PASS,
              dev, start, len, mode);

    if (simulate_dangerous()) {
        args->skip_origin = 1;
        args->ret = 0;
    }
}

/* __arm64_sys_reboot receives pt_regs; for the first test we only suppress it. */
static void before_reboot(hook_fargs1_t *args, void *udata)
{
    dl_log("REBOOT pid=%d profile=%s action=%s\n",
            current_id(0), profile_name(), simulate_dangerous() ? "SUPPRESS" : "PASS");
    add_event(DL_WIRE_REBOOT,
              simulate_dangerous() ? DL_WIRE_SUPPRESS : DL_WIRE_PASS,
              0, 0, 0, 0);
    if (simulate_dangerous()) {
        args->skip_origin = 1;
        args->ret = 0;
    }
}

static int install_one(const char *name, int argc, void *before, void **saved)
{
    void *addr = (void *)kp_lookup_name(name);
    int err;
    if (!addr) {
        dl_log("ERROR: symbol not found: %s\n", name);
        return -2;
    }
    err = hook_wrap(addr, argc, before, NULL, NULL);
    if (err) {
        dl_log("ERROR: hook failed: %s err=%d\n", name, err);
        return -(int)err;
    }
    *saved = addr;
    return 0;
}

static int init_procfs(void)
{
    fn_proc_mkdir = (void *)kp_lookup_name("proc_mkdir");
    fn_proc_create = (void *)kp_lookup_name("proc_create");
    fn_proc_remove = (void *)kp_lookup_name("proc_remove");
    if (!fn_proc_mkdir || !fn_proc_create || !fn_proc_remove) {
        dl_log("ERROR: procfs symbols unavailable\n");
        return -2;
    }
    proc_dir = fn_proc_mkdir("dynalab", NULL);
    if (!proc_dir) return -12;
    proc_control = fn_proc_create("control", 0600, proc_dir, &control_ops);
    proc_events = fn_proc_create("events", 0400, proc_dir, &events_ops);
    if (!proc_control || !proc_events) return -12;
    return 0;
}

static void exit_procfs(void)
{
    if (!fn_proc_remove) return;
    if (proc_events) fn_proc_remove(proc_events);
    if (proc_control) fn_proc_remove(proc_control);
    if (proc_dir) fn_proc_remove(proc_dir);
    proc_events = proc_control = proc_dir = NULL;
}

static long dynalab_init(const char *args, const char *event, void *__user reserved)
{
    int rc;
    profile = DL_AUTO;
    state = DL_READY;
    authenticated_tgid = -1;
    event_head = 0;
    clear_subjects();
    set_reply("UNINITIALIZED");
    dl_log("init event=%s default=AUTO state=READY\n", event ? event : "?");

    fn_iov_iter_advance = (void *)kp_lookup_name("iov_iter_advance");
    fn_task_pid_nr = (void *)kp_lookup_name("__task_pid_nr_ns");
    if (!fn_iov_iter_advance || !fn_task_pid_nr) {
        dl_log("ERROR: helper symbol not found\n");
        return -2;
    }

    rc = install_one("wake_up_new_task", 1, before_fork, &sym_fork);
    if (rc) goto fail;
    rc = install_one("do_execveat_common", 5, before_exec, &sym_exec);
    if (rc) goto fail;
    rc = install_one("do_exit", 1, before_exit, &sym_exit);
    if (rc) goto fail;
    rc = install_one("blkdev_write_iter", 2, before_blkdev_write_iter, &sym_write_iter);
    if (rc) goto fail;
    rc = install_one("blkdev_ioctl", 3, before_blkdev_ioctl, &sym_ioctl);
    if (rc) goto fail;
    rc = install_one("blkdev_fallocate", 4, before_blkdev_fallocate, &sym_fallocate);
    if (rc) goto fail;
    rc = install_one("__arm64_sys_reboot", 1, before_reboot, &sym_reboot);
    if (rc) goto fail;
    rc = init_procfs();
    if (rc) goto fail;

    dl_log("loaded: /proc/dynalab/control + events\n");
    return 0;
fail:
    exit_procfs();
    if (sym_reboot) unhook(sym_reboot);
    if (sym_fallocate) unhook(sym_fallocate);
    if (sym_ioctl) unhook(sym_ioctl);
    if (sym_write_iter) unhook(sym_write_iter);
    if (sym_exit) unhook(sym_exit);
    if (sym_exec) unhook(sym_exec);
    if (sym_fork) unhook(sym_fork);
    sym_reboot = sym_fallocate = sym_ioctl = sym_write_iter = NULL;
    sym_exit = sym_exec = sym_fork = NULL;
    return rc;
}

static long dynalab_ctl0(const char *args, char __user *out_msg, int outlen)
{
    unsigned long long value;
    if (!args) return -22;

    if (streq(args, "STATUS")) {
        if (!login_configured)
            return ctl_reply(out_msg, outlen, "UNINITIALIZED");
        return ctl_reply(out_msg, outlen,
            state == DL_SEALED ? "SEALED" : "READY");
    }

    if (prefix(args, "SETUP ")) {
        if (login_configured) return -1;
        if (!args[6]) return -22;
        login_verifier = make_verifier(args + 6);
        login_configured = 1;
        authenticated_tgid = -1;
        set_reply("READY AUTO OFF");
        dl_log("login verifier configured by manager\n");
        return ctl_reply(out_msg, outlen, "OK SETUP");
    }

    if (prefix(args, "SETVER ")) {
        if (login_configured) return -1;
        if (parse_hex64(args + 7, &value)) return -22;
        login_verifier = value;
        login_configured = 1;
        authenticated_tgid = -1;
        set_reply("READY AUTO OFF");
        dl_log("login verifier configured by manager\n");
        return ctl_reply(out_msg, outlen, "OK SETVER");
    }

    if (streq(args, "RESET")) {
        state = DL_READY;
        profile = DL_AUTO;
        authenticated_tgid = -1;
        event_head = 0;
        clear_subjects();
        set_reply(login_configured ? "READY AUTO OFF" : "UNINITIALIZED");
        dl_log("manager reset session\n");
        return ctl_reply(out_msg, outlen, "OK RESET");
    }

    if (streq(args, "RESET ALL")) {
        state = DL_READY;
        profile = DL_AUTO;
        authenticated_tgid = -1;
        event_head = 0;
        clear_subjects();
        login_verifier = 0;
        login_configured = 0;
        set_reply("UNINITIALIZED");
        dl_log("manager reset all credentials\n");
        return ctl_reply(out_msg, outlen, "OK RESET ALL");
    }

    return -22;
}

static long dynalab_exit(void *__user reserved)
{
    exit_procfs();
    authenticated_tgid = -1;
    if (sym_reboot) unhook(sym_reboot);
    if (sym_fallocate) unhook(sym_fallocate);
    if (sym_ioctl) unhook(sym_ioctl);
    if (sym_write_iter) unhook(sym_write_iter);
    if (sym_exit) unhook(sym_exit);
    if (sym_exec) unhook(sym_exec);
    if (sym_fork) unhook(sym_fork);
    dl_log("unloaded\n");
    return 0;
}

KPM_INIT(dynalab_init);
KPM_CTL0(dynalab_ctl0);
KPM_EXIT(dynalab_exit);
