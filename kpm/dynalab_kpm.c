/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/sched.h>
#include <linux/reboot.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/input.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
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
KPM_VERSION("0.8.14-file-coverage-test");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("YiJieqwq");
KPM_DESCRIPTION("Android block-device dynamic analysis prototype");

enum dl_profile { DL_TRACE = 1, DL_AUTO = 2, DL_EXPERT = 3 };
enum dl_state { DL_READY = 1, DL_CONFIGURED = 2, DL_SEALED = 3 };

static int profile = DL_AUTO;
static int state = DL_READY;
static void *sym_write_iter, *sym_ioctl, *sym_fallocate, *sym_reboot;
static void *sym_fork, *sym_exec, *sym_exit;
static void *sym_vfs_create, *sym_vfs_mkdir, *sym_vfs_write;
static void *sym_f2fs_write_iter, *sym_ext4_write_iter;
static void *sym_do_filp_open;
static void *sym_do_mkdirat;
static void *sym_notify_change, *sym_vfs_unlink, *sym_vfs_truncate;
static void *sym_input_event;
static unsigned long long (*fn_ktime_get_mono_fast_ns)(void);
static unsigned long long (*fn_ktime_get_real_fast_ns)(void);
static char *(*fn_get_task_comm)(char *buf, size_t len,
                                 struct task_struct *task);
static unsigned char gesture_keys[7];
static unsigned long long gesture_times[7];
static unsigned int gesture_len;
static struct delayed_work gesture_work;
static volatile int gesture_pending;
static struct workqueue_struct **fn_system_wq;
static bool (*fn_queue_delayed_work_on)(int cpu, struct workqueue_struct *wq,
                                        struct delayed_work *dwork,
                                        unsigned long delay);
static bool (*fn_cancel_delayed_work)(struct delayed_work *dwork);
static bool (*fn_cancel_delayed_work_sync)(struct delayed_work *dwork);
static void (*fn_init_timer_key)(struct timer_list *timer,
                                 void (*func)(struct timer_list *),
                                 unsigned int flags, const char *name,
                                 struct lock_class_key *key);
static void (*fn_delayed_work_timer_fn)(struct timer_list *timer);
static void (*fn_iov_iter_advance)(struct iov_iter *i, size_t bytes);
static unsigned long (*fn_copy_from_user)(void *to, const void __user *from,
                                          unsigned long n);
static int (*fn_set_memory_ro)(unsigned long addr, int numpages);
static int (*fn_set_memory_rw)(unsigned long addr, int numpages);
static void (*fn_sha256)(const unsigned char *data, unsigned int len,
                         unsigned char *out);
static void *(*fn_vmalloc)(unsigned long size);
static void (*fn_vfree)(const void *addr);
static struct file *(*fn_filp_open)(const char *filename, int flags, umode_t mode);
static int (*fn_filp_close)(struct file *filp, fl_owner_t id);
static ssize_t (*fn_kernel_write)(struct file *file, const void *buf,
                                  size_t count, loff_t *pos);
static ssize_t (*fn_kernel_read)(struct file *file, void *buf,
                                 size_t count, loff_t *pos);
static int (*fn_vfs_fsync)(struct file *file, int datasync);
static int (*fn_kern_path)(const char *name, unsigned int flags, struct path *path);
static void (*fn_path_put)(const struct path *path);
static pid_t (*fn_task_pid_nr)(struct task_struct *task, int type,
                               struct pid_namespace *ns);

static struct proc_dir_entry *proc_dir, *proc_control, *proc_events, *proc_cache;
#define DL_BLG_CACHE_MAX (256UL * 1024UL * 1024UL)
static void *blg_cache;
static unsigned long blg_cache_size;
static unsigned long blg_cache_written;
static int blg_cache_ready;
static int blg_cache_ro;
static unsigned char blg_cache_sha256[32];
static struct dl_blg_map_entry blg_map[DL_BLG_MAP_MAX];
static unsigned int blg_map_count;
static int blg_map_ready;
static unsigned char blg_map_sha256[32];
static struct proc_dir_entry *(*fn_proc_mkdir)(const char *, struct proc_dir_entry *);
static struct proc_dir_entry *(*fn_proc_create)(const char *, umode_t,
                                                struct proc_dir_entry *,
                                                const struct proc_ops *);
static void (*fn_proc_remove)(struct proc_dir_entry *);

static unsigned long long login_verifier;
static int login_configured;
static int authenticated_tgid = -1;
static int hello_tgid = -1;
static int reply_tgid = -1;
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
static dev_t efisp_dev;
static int efisp_guard_armed;


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

static long ctl_error(char __user *out_msg, int outlen, long err,
                      const char *msg)
{
    ctl_reply(out_msg, outlen, msg);
    return err;
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

static int parse_hello(const char *s, int *api, int *event_abi)
{
    int a = 0, e = 0;
    if (!*s) return -1;
    while (*s >= '0' && *s <= '9') a = a * 10 + (*s++ - '0');
    if (*s++ != ' ') return -1;
    if (!*s) return -1;
    while (*s >= '0' && *s <= '9') e = e * 10 + (*s++ - '0');
    if (*s) return -1;
    *api = a;
    *event_abi = e;
    return 0;
}

static int parse_dev_pair(const char *s, unsigned int *major, unsigned int *minor)
{
    unsigned int a = 0, b = 0;
    if (!*s) return -1;
    while (*s >= '0' && *s <= '9') a = a * 10 + (*s++ - '0');
    if (*s++ != ' ') return -1;
    if (!*s) return -1;
    while (*s >= '0' && *s <= '9') b = b * 10 + (*s++ - '0');
    if (*s || a > 0xfff || b > 0xfffff) return -1;
    *major = a;
    *minor = b;
    return 0;
}

static int parse_ulong(const char *s, unsigned long *value)
{
    unsigned long v = 0, next;
    if (!*s) return -1;
    while (*s) {
        if (*s < '0' || *s > '9') return -1;
        next = v * 10 + (*s++ - '0');
        if (next < v) return -1;
        v = next;
    }
    *value = v;
    return 0;
}

static char *next_token(char **cursor)
{
    char *s = *cursor, *start;
    while (*s == ' ') s++;
    if (!*s) { *cursor = s; return NULL; }
    start = s;
    while (*s && *s != ' ') s++;
    if (*s) *s++ = '\0';
    *cursor = s;
    return start;
}

static int parse_map_add(char *s, struct dl_blg_map_entry *e)
{
    char *name, *tok;
    unsigned long v[7];
    int i = 0, n = 0;
    name = next_token(&s);
    if (!name || !*name) return -1;
    while (name[n] && n < DL_BLG_MAP_NAME - 1) {
        e->name[n] = name[n]; n++;
    }
    e->name[n] = '\0';
    while (i < 7 && (tok = next_token(&s)) != NULL) {
        if (parse_ulong(tok, &v[i])) return -1;
        i++;
    }
    if (i != 7 || next_token(&s)) return -1;
    e->cache_offset = v[0];
    e->image_size = v[1];
    e->target_major = v[2];
    e->target_minor = v[3];
    e->target_size = v[4];
    e->flags = v[5];
    e->tier = v[6];
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
    e->version = DL_EVENT_ABI_VERSION;
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
    e->monotonic_ns = fn_ktime_get_mono_fast_ns ?
                      fn_ktime_get_mono_fast_ns() : 0;
    e->realtime_ns = fn_ktime_get_real_fast_ns ?
                     fn_ktime_get_real_fast_ns() : 0;
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
    char comm[TASK_COMM_LEN];
    struct dl_subject *s = find_subject(pid);
    if (fn_get_task_comm)
        fn_get_task_comm(comm, sizeof(comm), current);
    else
        comm[0] = '\0';
    add_event_for(type, action, pid, current_id(1),
                  s ? s->parent_pid : 0, dev, offset, length, command,
                  s ? s->session_id : 0,
                  s ? s->scope : DL_SCOPE_GLOBAL, comm);
}

static int gesture_suffix(const unsigned char *pattern, unsigned int n,
                          unsigned long long window_ns)
{
    unsigned int i, start;
    if (gesture_len < n) return 0;
    start = gesture_len - n;
    for (i = 0; i < n; i++)
        if (gesture_keys[start + i] != pattern[i]) return 0;
    return gesture_times[gesture_len - 1] - gesture_times[start] <= window_ns;
}

static void gesture_event(const char *name, unsigned int command)
{
    add_event_for(DL_WIRE_GESTURE, DL_WIRE_PASS,
                  0, 0, 0, 0, 0, 0, command,
                  0, DL_SCOPE_GLOBAL, name);
}

static int gesture_pending_xchg(int value)
{
    return __atomic_exchange_n(&gesture_pending, value, __ATOMIC_SEQ_CST);
}

static int gesture_pending_cmpxchg(int expected, int value)
{
    __atomic_compare_exchange_n(&gesture_pending, &expected, value, 0,
                                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}

static int gesture_pending_read(void)
{
    return __atomic_load_n(&gesture_pending, __ATOMIC_ACQUIRE);
}

static void gesture_pending_set(int value)
{
    __atomic_store_n(&gesture_pending, value, __ATOMIC_RELEASE);
}

static void gesture_delayed_fn(struct work_struct *work)
{
    int pending = gesture_pending_xchg(0);
    gesture_len = 0;
    if (pending == 1) gesture_event("CONSOLE_FINAL", 1);
    else if (pending == 2) gesture_event("CHECK_FINAL", 3);
}

static void gesture_cancel_pending(int expected)
{
    if (gesture_pending_cmpxchg(expected, 0) == expected)
        fn_cancel_delayed_work(&gesture_work);
}

static void gesture_schedule_pending(int type)
{
    gesture_pending_set(type);
    if (!fn_queue_delayed_work_on(WORK_CPU_UNBOUND, *fn_system_wq,
                                  &gesture_work, (HZ * 300 + 999) / 1000)) {
        if (gesture_pending_cmpxchg(type, 0) == type) {
            gesture_len = 0;
            gesture_event(type == 1 ? "CONSOLE_FINAL" : "CHECK_FINAL",
                          type == 1 ? 1 : 3);
        }
    }
}

static void before_input_event(hook_fargs5_t *args, void *udata)
{
    unsigned int type = (unsigned int)args->arg1;
    unsigned int code = (unsigned int)args->arg2;
    int value = (int)args->arg3;
    unsigned long long now, pending_age = 0;
    unsigned char key;
    static const unsigned char up3[] = { 1, 1, 1 };
    static const unsigned char down3[] = { 2, 2, 2 };
    static const unsigned char check6[] = { 1, 1, 1, 2, 2, 2 };
    unsigned int i;
    int pending;

    if (type != EV_KEY || value != 1) return;
    if (code == KEY_VOLUMEUP) key = 1;
    else if (code == KEY_VOLUMEDOWN) key = 2;
    else return;
    now = fn_ktime_get_mono_fast_ns();

    pending = gesture_pending_read();
    if (pending && gesture_len)
        pending_age = now - gesture_times[gesture_len - 1];
    if (pending == 1) {
        gesture_cancel_pending(1);
        if (pending_age > 300000000ULL) {
            gesture_len = 0;
            gesture_event("CONSOLE_FINAL", 1);
        }
    } else if (pending == 2) {
        if (key == 1 && pending_age <= 300000000ULL &&
            gesture_pending_cmpxchg(2, 0) == 2) {
            fn_cancel_delayed_work(&gesture_work);
            gesture_len = 0;
            gesture_event("FORCE_FINAL", 4);
            return;
        }
        if (gesture_pending_cmpxchg(2, 0) == 2) {
            fn_cancel_delayed_work(&gesture_work);
            gesture_len = 0;
            gesture_event("CHECK_FINAL", 3);
        }
    }

    if (gesture_len && now - gesture_times[gesture_len - 1] > 1000000000ULL)
        gesture_len = 0;
    if (gesture_len == 7) {
        for (i = 1; i < 7; i++) {
            gesture_keys[i - 1] = gesture_keys[i];
            gesture_times[i - 1] = gesture_times[i];
        }
        gesture_len = 6;
    }
    gesture_keys[gesture_len] = key;
    gesture_times[gesture_len] = now;
    gesture_len++;

    if (gesture_suffix(check6, 6, 3000000000ULL)) {
        gesture_schedule_pending(2);
    } else if (gesture_suffix(down3, 3, 900000000ULL)) {
        gesture_len = 0;
        gesture_event("KILL_FINAL", 2);
    } else if (gesture_suffix(up3, 3, 900000000ULL)) {
        gesture_schedule_pending(1);
    }
}

static ssize_t control_read(struct file *file, char __user *buf,
                            size_t count, loff_t *ppos)
{
    int len = str_len(control_reply);
    int copied;
    if (reply_tgid != current_id(1)) return -13;
    if (*ppos >= len) return 0;
    if (count > (size_t)(len - *ppos)) count = len - *ppos;
    copied = compat_copy_to_user(buf, control_reply + *ppos, count);
    if (copied <= 0) return -14;
    *ppos += copied;
    return copied;
}

static int digest_equal(const unsigned char *a, const unsigned char *b)
{
    int i;
    unsigned char diff = 0;
    for (i = 0; i < 32; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static void clear_cache_digest(void)
{
    int i;
    for (i = 0; i < 32; i++) blg_cache_sha256[i] = 0;
}

static void clear_blg_map(void)
{
    unsigned int i, j;
    for (i = 0; i < DL_BLG_MAP_MAX; i++) {
        for (j = 0; j < sizeof(blg_map[i]); j++)
            ((unsigned char *)&blg_map[i])[j] = 0;
    }
    for (i = 0; i < 32; i++) blg_map_sha256[i] = 0;
    blg_map_count = 0;
    blg_map_ready = 0;
}

static int validate_blg_map(void)
{
    unsigned int i, j;
    unsigned long long end;
    if (!blg_cache || !blg_cache_ready || !blg_cache_ro || !blg_map_count)
        return -1;
    for (i = 0; i < blg_map_count; i++) {
        struct dl_blg_map_entry *e = &blg_map[i];
        if (!e->name[0] || !e->image_size || !e->target_major ||
            e->image_size > e->target_size)
            return -1;
        end = e->cache_offset + e->image_size;
        if (end < e->cache_offset || end > blg_cache_size) return -1;
        for (j = 0; j < i; j++)
            if (e->target_major == blg_map[j].target_major &&
                e->target_minor == blg_map[j].target_minor)
                return -1;
    }
    return 0;
}

static int free_blg_cache(void)
{
    int pages, rc;
    if (!blg_cache) return 0;
    pages = (int)((blg_cache_size + PAGE_SIZE - 1) / PAGE_SIZE);
    if (blg_cache_ro) {
        rc = fn_set_memory_rw((unsigned long)blg_cache, pages);
        if (rc) return rc;
        blg_cache_ro = 0;
    }
    fn_vfree(blg_cache);
    blg_cache = NULL;
    blg_cache_size = blg_cache_written = 0;
    blg_cache_ready = 0;
    clear_cache_digest();
    clear_blg_map();
    return 0;
}

static int bytes_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static int blg_loop_selftest(const char *path, int inject)
{
    struct file *file;
    struct inode *inode, *capacity_inode;
    unsigned char *verify = NULL;
    unsigned char zeros[4096];
    unsigned long long total = 0, out_off = 0;
    loff_t pos;
    unsigned int i, j;
    ssize_t io;
    int rc = -5, repaired = 0;
    if (!blg_cache_ready || !blg_cache_ro || !blg_map_ready) return -101;
    if (!path || path[0] != '/') return -22;
    file = fn_filp_open(path, O_RDWR | O_LARGEFILE, 0);
    if (!file || IS_ERR(file)) return -2;
    inode = file_inode(file);
    capacity_inode = file->f_mapping ? file->f_mapping->host : NULL;
    if (!inode || !capacity_inode || !S_ISBLK(inode->i_mode) ||
        MAJOR(inode->i_rdev) != 7) {
        rc = -1; goto out;
    }
    for (i = 0; i < blg_map_count; i++) total += blg_map[i].image_size;
    if (!total || total > (unsigned long long)i_size_read(capacity_inode)) {
        dl_log("SELFTEST stage=capacity total=%llu capacity=%lld\n",
               total, capacity_inode ? (long long)i_size_read(capacity_inode) : -1LL);
        rc = -27; goto out;
    }
    verify = fn_vmalloc(1024 * 1024);
    if (!verify) { rc = -12; goto out; }

    for (i = 0; i < blg_map_count; i++) {
        unsigned long long left = blg_map[i].image_size;
        unsigned long long src = blg_map[i].cache_offset;
        while (left) {
            size_t chunk = left > 1024 * 1024 ? 1024 * 1024 : (size_t)left;
            pos = (loff_t)out_off;
            io = fn_kernel_write(file, (char *)blg_cache + src, chunk, &pos);
            if (io != chunk) {
                dl_log("SELFTEST stage=initial-write rc=%lld off=%llu len=%zu\n",
                       (long long)io, out_off, chunk);
                rc = -110; goto out;
            }
            src += chunk; out_off += chunk; left -= chunk;
        }
    }
    rc = fn_vfs_fsync(file, 0);
    if (rc) { dl_log("SELFTEST stage=initial-fsync rc=%d\n", rc); rc = -111; goto out; }

    if (inject && total >= sizeof(zeros) &&
        blg_map_count && blg_map[0].image_size >= sizeof(zeros)) {
        for (j = 0; j < sizeof(zeros); j++)
            zeros[j] = ((unsigned char *)blg_cache)[blg_map[0].cache_offset + j] ^ 0xff;
        pos = 0;
        io = fn_kernel_write(file, zeros, sizeof(zeros), &pos);
        if (io != sizeof(zeros)) {
            dl_log("SELFTEST stage=inject-write rc=%lld\n", (long long)io);
            rc = -112; goto out;
        }
        rc = fn_vfs_fsync(file, 0);
        if (rc) { dl_log("SELFTEST stage=inject-fsync rc=%d\n", rc); rc = -113; goto out; }
    }

    out_off = 0;
    for (i = 0; i < blg_map_count; i++) {
        unsigned long long left = blg_map[i].image_size;
        unsigned long long src = blg_map[i].cache_offset;
        while (left) {
            size_t chunk = left > 1024 * 1024 ? 1024 * 1024 : (size_t)left;
            pos = (loff_t)out_off;
            io = fn_kernel_read(file, verify, chunk, &pos);
            if (io != chunk) {
                dl_log("SELFTEST stage=detect-read rc=%lld off=%llu len=%zu\n",
                       (long long)io, out_off, chunk);
                rc = -120; goto out;
            }
            if (!bytes_equal(verify, (unsigned char *)blg_cache + src, chunk)) {
                pos = (loff_t)out_off;
                io = fn_kernel_write(file, (char *)blg_cache + src, chunk, &pos);
                if (io != chunk) {
                    dl_log("SELFTEST stage=repair-write rc=%lld off=%llu len=%zu\n",
                           (long long)io, out_off, chunk);
                    rc = -121; goto out;
                }
                repaired++;
            }
            src += chunk; out_off += chunk; left -= chunk;
        }
    }
    if (repaired) {
        rc = fn_vfs_fsync(file, 0);
        if (rc) { dl_log("SELFTEST stage=repair-fsync rc=%d\n", rc); rc = -122; goto out; }
    }

    out_off = 0;
    for (i = 0; i < blg_map_count; i++) {
        unsigned long long left = blg_map[i].image_size;
        unsigned long long src = blg_map[i].cache_offset;
        while (left) {
            size_t chunk = left > 1024 * 1024 ? 1024 * 1024 : (size_t)left;
            pos = (loff_t)out_off;
            io = fn_kernel_read(file, verify, chunk, &pos);
            if (io != chunk ||
                !bytes_equal(verify, (unsigned char *)blg_cache + src, chunk)) {
                dl_log("SELFTEST stage=final-verify rc=%lld off=%llu len=%zu equal=%d\n",
                       (long long)io, out_off, chunk,
                       io == chunk ? bytes_equal(verify, (unsigned char *)blg_cache + src, chunk) : 0);
                rc = -130; goto out;
            }
            src += chunk; out_off += chunk; left -= chunk;
        }
    }
    rc = repaired ? 1 : 0;
out:
    if (verify) fn_vfree(verify);
    fn_filp_close(file, NULL);
    return rc;
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
    reply_tgid = current_id(1);

    if (prefix(cmd, "HELLO ")) {
        int cli_api, event_abi;
        if (state == DL_SEALED && hello_tgid != current_id(1)) {
            set_reply("ERR SEALED");
            return n;
        }
        if (parse_hello(cmd + 6, &cli_api, &event_abi)) {
            set_reply("ERR PROTOCOL");
        } else if (cli_api < DL_RPC_MIN_CLI_API) {
            set_reply("ERR CLI_OLD");
        } else if (cli_api > DL_RPC_API_VERSION) {
            set_reply("ERR KPM_OLD");
        } else if (event_abi != DL_EVENT_ABI_VERSION) {
            set_reply(event_abi > DL_EVENT_ABI_VERSION ?
                      "ERR KPM_OLD" : "ERR CLI_OLD");
        } else {
            hello_tgid = current_id(1);
            set_reply("OK HELLO 15 6 0.8.14-file-coverage-test");
        }
        return n;
    }

    if (hello_tgid != current_id(1)) {
        set_reply("ERR CLI_OLD");
        return n;
    }

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
        if (state == DL_SEALED && authenticated_tgid != current_id(1)) {
            set_reply("ERR SEALED");
            return n;
        }
        if (!login_configured) {
            set_reply("ERR UNINITIALIZED");
        } else if (!parse_hex64(cmd + 6, &value) && value == login_verifier) {
            authenticated_tgid = current_id(1);
            add_event_for(DL_WIRE_CLI_LOGIN, DL_WIRE_PASS,
                          current_id(0), current_id(1), 0, 0, 0, 0, 0,
                          0, DL_SCOPE_GLOBAL, "CLI_LOGIN");
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

    if (prefix(cmd, "BLG SELFTEST ")) {
        char *p = cmd + 13;
        char *space = p;
        int inject = 0, rc;
        if (state == DL_SEALED) { set_reply("ERR SEALED"); return -1; }
        while (*space && *space != ' ') space++;
        if (*space) {
            *space++ = '\0';
            inject = streq(space, "INJECT");
            if (!inject) { set_reply("ERR SELFTEST ARG"); return -22; }
        }
        rc = blg_loop_selftest(p, inject);
        if (rc < 0) { set_reply("ERR SELFTEST"); return rc; }
        set_reply(rc ? "OK SELFTEST REPAIRED" : "OK SELFTEST VERIFIED");
    } else if (streq(cmd, "BLG MAP BEGIN")) {
        if (state == DL_SEALED) { set_reply("ERR SEALED"); return -1; }
        clear_blg_map();
        set_reply("OK MAP BEGIN");
    } else if (prefix(cmd, "BLG MAP ADD ")) {
        if (state == DL_SEALED || blg_map_ready) {
            set_reply("ERR MAP LOCKED"); return -1;
        }
        if (blg_map_count >= DL_BLG_MAP_MAX ||
            parse_map_add(cmd + 12, &blg_map[blg_map_count])) {
            set_reply("ERR MAP ENTRY"); return -22;
        }
        blg_map_count++;
        set_reply("OK MAP ADD");
    } else if (streq(cmd, "BLG MAP COMMIT")) {
        if (validate_blg_map()) {
            set_reply("ERR MAP INVALID"); return -22;
        }
        fn_sha256((unsigned char *)blg_map,
                  blg_map_count * sizeof(blg_map[0]), blg_map_sha256);
        blg_map_ready = 1;
        set_reply("OK PLAN READY NO WRITE");
    } else if (streq(cmd, "BLG MAP VERIFY")) {
        unsigned char digest[32];
        if (!blg_map_ready) { set_reply("ERR MAP NOT READY"); return -22; }
        fn_sha256((unsigned char *)blg_map,
                  blg_map_count * sizeof(blg_map[0]), digest);
        set_reply(digest_equal(digest, blg_map_sha256) ?
                  "OK MAP INTACT" : "ERR MAP CORRUPTED");
    } else if (streq(cmd, "BLG MAP STATUS")) {
        set_reply(blg_map_ready ? "OK PLAN READY NO WRITE" :
                  blg_map_count ? "OK MAP BUILDING" : "OK MAP EMPTY");
    } else if (streq(cmd, "BLG MAP DROP")) {
        if (state == DL_SEALED) { set_reply("ERR SEALED"); return -1; }
        clear_blg_map();
        set_reply("OK MAP EMPTY");
    } else if (prefix(cmd, "BLG CACHE BEGIN ")) {
        unsigned long size;
        if (state == DL_SEALED) { set_reply("ERR SEALED"); return -1; }
        if (parse_ulong(cmd + 16, &size) || !size || size > DL_BLG_CACHE_MAX) {
            set_reply("ERR CACHE SIZE");
            return -22;
        }
        if (!fn_vmalloc || !fn_vfree || !fn_copy_from_user ||
            !fn_set_memory_ro || !fn_set_memory_rw || !fn_sha256) {
            set_reply("ERR CACHE API");
            return -38;
        }
        if (free_blg_cache()) {
            set_reply("ERR CACHE UNLOCK");
            return -5;
        }
        blg_cache = fn_vmalloc(size);
        if (!blg_cache) {
            blg_cache_size = blg_cache_written = 0;
            blg_cache_ready = 0;
            set_reply("ERR CACHE MEMORY");
            return -12;
        }
        blg_cache_size = size;
        blg_cache_written = 0;
        blg_cache_ready = 0;
        blg_cache_ro = 0;
        clear_cache_digest();
        set_reply("OK CACHE BEGIN");
    } else if (streq(cmd, "BLG CACHE COMMIT")) {
        int pages, rc;
        if (!blg_cache || blg_cache_written != blg_cache_size) {
            set_reply("ERR CACHE INCOMPLETE");
            return -22;
        }
        fn_sha256(blg_cache, (unsigned int)blg_cache_size, blg_cache_sha256);
        pages = (int)((blg_cache_size + PAGE_SIZE - 1) / PAGE_SIZE);
        rc = fn_set_memory_ro((unsigned long)blg_cache, pages);
        if (rc) {
            clear_cache_digest();
            set_reply("ERR CACHE RO");
            return rc;
        }
        blg_cache_ro = 1;
        blg_cache_ready = 1;
        set_reply("OK CACHE READY RO");
    } else if (streq(cmd, "BLG CACHE VERIFY")) {
        unsigned char digest[32];
        if (!blg_cache || !blg_cache_ready || !blg_cache_ro) {
            set_reply("ERR CACHE NOT READY");
            return -22;
        }
        fn_sha256(blg_cache, (unsigned int)blg_cache_size, digest);
        set_reply(digest_equal(digest, blg_cache_sha256) ?
                  "OK CACHE INTACT" : "ERR CACHE CORRUPTED");
    } else if (streq(cmd, "BLG CACHE STATUS")) {
        set_reply(blg_cache_ready ?
                  (blg_cache_ro ? "OK CACHE READY RO" : "ERR CACHE RW") :
                  blg_cache ? "OK CACHE LOADING" : "OK CACHE EMPTY");
    } else if (streq(cmd, "BLG CACHE DROP")) {
        if (state == DL_SEALED) { set_reply("ERR SEALED"); return -1; }
        if (free_blg_cache()) {
            set_reply("ERR CACHE UNLOCK");
            return -5;
        }
        set_reply("OK CACHE EMPTY");
    } else if (streq(cmd, "EFISP STATUS")) {
        set_reply(efisp_guard_armed ? "OK EFISP ARMED" : "OK EFISP UNAVAILABLE");
    } else if (prefix(cmd, "EFISP ARM ")) {
        unsigned int maj, min;
        if (state == DL_SEALED) { set_reply("ERR SEALED"); return -1; }
        if (parse_dev_pair(cmd + 10, &maj, &min)) {
            set_reply("ERR EFISP DEVICE");
            return -22;
        }
        efisp_dev = MKDEV(maj, min);
        efisp_guard_armed = 1;
        set_reply("OK EFISP ARMED");
    } else if (streq(cmd, "ACTIVE")) {
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
        if (state == DL_SEALED) {
            set_reply("ERR SEALED");
            return -1;
        }
        event_head = 0;
        set_reply("OK CLEAR");
    } else if (streq(cmd, "LOGOUT")) {
        add_event_for(DL_WIRE_CLI_LOGOUT, DL_WIRE_PASS,
                      current_id(0), current_id(1), 0, 0, 0, 0, 0,
                      0, DL_SCOPE_GLOBAL, "CLI_LOGOUT");
        authenticated_tgid = -1;
        hello_tgid = -1;
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
    unsigned int start;
    unsigned int item;
    unsigned int available;
    struct dl_wire_event *event;
    int copied;
    if (!cli_authenticated()) return -13;
    start = total > DL_EVENT_CAPACITY ? total - DL_EVENT_CAPACITY : 0;
    item = (unsigned int)(*ppos / sizeof(struct dl_wire_event));
    available = total - start;
    if (count < sizeof(struct dl_wire_event) || item >= available)
        return 0;
    event = &event_ring[(start + item) % DL_EVENT_CAPACITY];
    copied = compat_copy_to_user(buf, event, sizeof(*event));
    if (copied <= 0) return -14;
    *ppos += copied;
    return copied;
}

static ssize_t cache_write(struct file *file, const char __user *buf,
                           size_t count, loff_t *ppos)
{
    unsigned long off;
    if (!cli_authenticated()) return -13;
    if (!blg_cache || blg_cache_ready) return -22;
    off = (unsigned long)*ppos;
    if (off > blg_cache_size || count > blg_cache_size - off) return -27;
    if (fn_copy_from_user((char *)blg_cache + off, buf, count)) return -14;
    *ppos += count;
    if ((unsigned long)*ppos > blg_cache_written)
        blg_cache_written = (unsigned long)*ppos;
    return count;
}

static ssize_t cache_read(struct file *file, char __user *buf,
                          size_t count, loff_t *ppos)
{
    unsigned long off, left;
    int copied;
    if (!cli_authenticated()) return -13;
    if (!blg_cache || !blg_cache_ready) return -22;
    off = (unsigned long)*ppos;
    if (off >= blg_cache_size) return 0;
    left = blg_cache_size - off;
    if (count > left) count = left;
    copied = compat_copy_to_user(buf, (char *)blg_cache + off, count);
    if (copied <= 0) return -14;
    *ppos += copied;
    return copied;
}

static const struct proc_ops cache_ops = {
    .proc_read = cache_read,
    .proc_write = cache_write,
};

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

static int simulate_for_current(dev_t dev)
{
    if (efisp_guard_armed && dev == efisp_dev) return 1;
    if (!simulate_dangerous()) return 0;
    return find_subject(current_id(0)) != NULL;
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

static void after_do_filp_open(hook_fargs3_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    struct filename *filename = (struct filename *)args->arg1;
    struct file *file = (struct file *)args->ret;
    if (!s || IS_ERR_OR_NULL(file) || !(file->f_mode & FMODE_CREATED))
        return;
    add_event_for(DL_WIRE_FILE_CREATE, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, 0, 0, file->f_mode,
                  s->session_id, s->scope,
                  filename ? filename->name : NULL);
}

static void after_do_mkdirat(hook_fargs3_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    struct filename *filename = (struct filename *)args->arg1;
    if (!s || (long)args->ret != 0) return;
    add_event_for(DL_WIRE_FILE_MKDIR, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, 0, 0, (unsigned int)args->arg2,
                  s->session_id, s->scope,
                  filename ? filename->name : NULL);
}

static const char *dentry_leaf(struct dentry *dentry)
{
    return dentry && dentry->d_name.name ? dentry->d_name.name : NULL;
}

static void before_vfs_create(hook_fargs5_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    struct dentry *dentry = (struct dentry *)args->arg2;
    if (!s) return;
    add_event_for(DL_WIRE_FILE_CREATE, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, 0, 0, (unsigned int)args->arg3,
                  s->session_id, s->scope, dentry_leaf(dentry));
}

static void before_vfs_mkdir(hook_fargs4_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    struct dentry *dentry = (struct dentry *)args->arg2;
    if (!s) return;
    add_event_for(DL_WIRE_FILE_MKDIR, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, 0, 0, (unsigned int)args->arg3,
                  s->session_id, s->scope, dentry_leaf(dentry));
}

static void before_vfs_write(hook_fargs4_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    struct file *file = (struct file *)args->arg0;
    struct inode *inode;
    loff_t *pos = (loff_t *)args->arg3;
    if (!s || !file) return;
    inode = file_inode(file);
    if (!inode || !S_ISREG(inode->i_mode)) return;
    add_event_for(DL_WIRE_FILE_WRITE, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, pos ? *pos : 0, args->arg2, 0,
                  s->session_id, s->scope,
                  dentry_leaf(file->f_path.dentry));
}

static void before_file_write_iter(hook_fargs2_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    struct kiocb *iocb = (struct kiocb *)args->arg0;
    struct iov_iter *from = (struct iov_iter *)args->arg1;
    struct file *file;
    struct inode *inode;
    if (!s || !iocb || !from) return;
    file = iocb->ki_filp;
    if (!file) return;
    inode = file_inode(file);
    if (!inode || !S_ISREG(inode->i_mode)) return;
    add_event_for(DL_WIRE_FILE_WRITE, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, iocb->ki_pos, iov_iter_count(from), 1,
                  s->session_id, s->scope,
                  dentry_leaf(file->f_path.dentry));
}

static void before_notify_change(hook_fargs4_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    struct dentry *dentry = (struct dentry *)args->arg1;
    struct iattr *attr = (struct iattr *)args->arg2;
    if (!s) return;
    add_event_for(DL_WIRE_FILE_ATTR, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, 0, 0, attr ? attr->ia_valid : 0,
                  s->session_id, s->scope, dentry_leaf(dentry));
}

static void before_vfs_unlink(hook_fargs4_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    struct dentry *dentry = (struct dentry *)args->arg2;
    if (!s) return;
    add_event_for(DL_WIRE_FILE_UNLINK, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, 0, 0, 0,
                  s->session_id, s->scope, dentry_leaf(dentry));
}

static void before_vfs_truncate(hook_fargs2_t *args, void *udata)
{
    int pid = current_id(0);
    struct dl_subject *s = find_subject(pid);
    const struct path *path = (const struct path *)args->arg0;
    if (!s) return;
    add_event_for(DL_WIRE_FILE_TRUNCATE, DL_WIRE_PASS, pid, current_id(1),
                  s->parent_pid, 0, 0, args->arg1, 0,
                  s->session_id, s->scope,
                  path ? dentry_leaf(path->dentry) : NULL);
}

static void before_blkdev_write_iter(hook_fargs2_t *args, void *udata)
{
    struct kiocb *iocb = (struct kiocb *)args->arg0;
    struct iov_iter *from = (struct iov_iter *)args->arg1;
    size_t count;
    loff_t pos;
    dev_t dev = 0;

    int simulate;
    if (!iocb || !from) return;
    count = iov_iter_count(from);
    pos = iocb->ki_pos;
    if (iocb->ki_filp && iocb->ki_filp->f_mapping &&
        iocb->ki_filp->f_mapping->host)
        dev = iocb->ki_filp->f_mapping->host->i_rdev;
    simulate = simulate_for_current(dev);

    dl_log("BLOCK_WRITE pid=%d dev=%u:%u off=%lld len=%zu profile=%s action=%s\n",
            current_id(0), MAJOR(dev), MINOR(dev), pos, count, profile_name(),
            simulate ? "SIMULATE" : "PASS");

    add_event(DL_WIRE_BLOCK_WRITE,
              simulate ? DL_WIRE_SIMULATE : DL_WIRE_PASS,
              dev, pos, count, 0);

    if (!simulate) return;
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
    int simulate;

    if (!dangerous_ioctl(cmd)) return;
    if (file && file->f_mapping && file->f_mapping->host)
        dev = file->f_mapping->host->i_rdev;
    simulate = simulate_for_current(dev);

    dl_log("BLOCK_IOCTL pid=%d dev=%u:%u cmd=0x%x profile=%s action=%s\n",
            current_id(0), MAJOR(dev), MINOR(dev), cmd, profile_name(),
            simulate ? "SIMULATE" : "PASS");

    add_event(DL_WIRE_BLOCK_IOCTL,
              simulate ? DL_WIRE_SIMULATE : DL_WIRE_PASS,
              dev, 0, 0, cmd);

    if (simulate) {
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
    int simulate;

    if (file && file->f_mapping && file->f_mapping->host)
        dev = file->f_mapping->host->i_rdev;
    simulate = simulate_for_current(dev);

    dl_log("BLOCK_FALLOCATE pid=%d dev=%u:%u mode=0x%x off=%lld len=%lld profile=%s action=%s\n",
            current_id(0), MAJOR(dev), MINOR(dev), mode, start, len,
            profile_name(), simulate ? "SIMULATE" : "PASS");

    add_event(DL_WIRE_BLOCK_FALLOCATE,
              simulate ? DL_WIRE_SIMULATE : DL_WIRE_PASS,
              dev, start, len, mode);

    if (simulate) {
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

static int install_optional(const char *name, int argc, void *before,
                            void **saved)
{
    void *addr = (void *)kp_lookup_name(name);
    int err;
    if (!addr) return 0;
    err = hook_wrap(addr, argc, before, NULL, NULL);
    if (err) {
        dl_log("ERROR: optional hook failed: %s err=%d\n", name, err);
        return -(int)err;
    }
    *saved = addr;
    return 0;
}

static int install_one_after(const char *name, int argc, void *after, void **saved)
{
    void *addr = (void *)kp_lookup_name(name);
    int err;
    if (!addr) {
        dl_log("ERROR: symbol not found: %s\n", name);
        return -2;
    }
    err = hook_wrap(addr, argc, NULL, after, NULL);
    if (err) {
        dl_log("ERROR: after-hook failed: %s err=%d\n", name, err);
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
    proc_cache = fn_proc_create("cache", 0600, proc_dir, &cache_ops);
    if (!proc_control || !proc_events || !proc_cache) return -12;
    return 0;
}

static void exit_procfs(void)
{
    if (!fn_proc_remove) return;
    if (proc_cache) fn_proc_remove(proc_cache);
    if (proc_events) fn_proc_remove(proc_events);
    if (proc_control) fn_proc_remove(proc_control);
    if (proc_dir) fn_proc_remove(proc_dir);
    proc_cache = proc_events = proc_control = proc_dir = NULL;
}

static void detect_efisp_device(void)
{
    static const char *names[] = {
        "/dev/block/by-name/efisp",
        "/dev/block/by-name/efisp_a",
        "/dev/block/by-name/efisp_b",
    };
    struct path path;
    struct inode *inode;
    int i;
    if (!fn_kern_path || !fn_path_put) return;
    for (i = 0; i < (int)(sizeof(names) / sizeof(names[0])); i++) {
        if (fn_kern_path(names[i], 0, &path)) continue;
        inode = path.dentry ? d_inode(path.dentry) : NULL;
        if (inode && S_ISBLK(inode->i_mode)) {
            efisp_dev = inode->i_rdev;
            efisp_guard_armed = 1;
            fn_path_put(&path);
            return;
        }
        fn_path_put(&path);
    }
}

static long dynalab_init(const char *args, const char *event, void *__user reserved)
{
    int rc;
    profile = DL_AUTO;
    state = DL_READY;
    authenticated_tgid = -1;
    hello_tgid = -1;
    reply_tgid = -1;
    event_head = 0;
    gesture_len = 0;
    efisp_dev = 0;
    efisp_guard_armed = 0;
    blg_cache = NULL;
    blg_cache_size = blg_cache_written = 0;
    blg_cache_ready = blg_cache_ro = 0;
    clear_cache_digest();
    clear_blg_map();
    clear_subjects();
    set_reply("UNINITIALIZED");
    dl_log("init event=%s default=AUTO state=READY\n", event ? event : "?");

    fn_iov_iter_advance = (void *)kp_lookup_name("iov_iter_advance");
    fn_task_pid_nr = (void *)kp_lookup_name("__task_pid_nr_ns");
    fn_kern_path = (void *)kp_lookup_name("kern_path");
    fn_path_put = (void *)kp_lookup_name("path_put");
    fn_vmalloc = (void *)kp_lookup_name("vmalloc_noprof");
    if (!fn_vmalloc) fn_vmalloc = (void *)kp_lookup_name("vmalloc");
    fn_vfree = (void *)kp_lookup_name("vfree");
    fn_set_memory_ro = (void *)kp_lookup_name("set_memory_ro");
    fn_set_memory_rw = (void *)kp_lookup_name("set_memory_rw");
    fn_sha256 = (void *)kp_lookup_name("sha256");
    fn_filp_open = (void *)kp_lookup_name("filp_open");
    fn_filp_close = (void *)kp_lookup_name("filp_close");
    fn_kernel_write = (void *)kp_lookup_name("kernel_write");
    fn_kernel_read = (void *)kp_lookup_name("kernel_read");
    fn_vfs_fsync = (void *)kp_lookup_name("vfs_fsync");
    fn_ktime_get_mono_fast_ns = (void *)kp_lookup_name("ktime_get_mono_fast_ns");
    fn_ktime_get_real_fast_ns = (void *)kp_lookup_name("ktime_get_real_fast_ns");
    fn_get_task_comm = (void *)kp_lookup_name("__get_task_comm");
    fn_queue_delayed_work_on = (void *)kp_lookup_name("queue_delayed_work_on");
    fn_cancel_delayed_work = (void *)kp_lookup_name("cancel_delayed_work");
    fn_cancel_delayed_work_sync = (void *)kp_lookup_name("cancel_delayed_work_sync");
    fn_init_timer_key = (void *)kp_lookup_name("init_timer_key");
    fn_delayed_work_timer_fn = (void *)kp_lookup_name("delayed_work_timer_fn");
    fn_system_wq = (void *)kp_lookup_name("system_wq");
    fn_copy_from_user = (void *)kp_lookup_name("_copy_from_user");
    if (!fn_copy_from_user)
        fn_copy_from_user = (void *)kp_lookup_name("raw_copy_from_user");
    if (!fn_iov_iter_advance || !fn_task_pid_nr || !fn_vmalloc ||
        !fn_vfree || !fn_copy_from_user || !fn_set_memory_ro ||
        !fn_set_memory_rw || !fn_sha256 || !fn_filp_open || !fn_filp_close ||
        !fn_kernel_write || !fn_kernel_read || !fn_vfs_fsync ||
        !fn_ktime_get_mono_fast_ns || !fn_ktime_get_real_fast_ns ||
        !fn_get_task_comm || !fn_queue_delayed_work_on ||
        !fn_cancel_delayed_work || !fn_cancel_delayed_work_sync ||
        !fn_init_timer_key || !fn_delayed_work_timer_fn || !fn_system_wq) {
        dl_log("ERROR: helper missing iov=%d pid=%d vmalloc=%d vfree=%d copy=%d ro=%d rw=%d sha=%d file=%d io=%d sync=%d time=%d comm=%d work=%d\n",
               !!fn_iov_iter_advance, !!fn_task_pid_nr, !!fn_vmalloc,
               !!fn_vfree, !!fn_copy_from_user, !!fn_set_memory_ro,
               !!fn_set_memory_rw, !!fn_sha256,
               !!fn_filp_open && !!fn_filp_close,
               !!fn_kernel_write && !!fn_kernel_read, !!fn_vfs_fsync,
               !!fn_ktime_get_mono_fast_ns && !!fn_ktime_get_real_fast_ns,
               !!fn_get_task_comm,
               !!fn_queue_delayed_work_on && !!fn_cancel_delayed_work &&
               !!fn_cancel_delayed_work_sync && !!fn_init_timer_key &&
               !!fn_delayed_work_timer_fn && !!fn_system_wq);
        return -2;
    }
    INIT_WORK(&gesture_work.work, gesture_delayed_fn);
    fn_init_timer_key(&gesture_work.timer, fn_delayed_work_timer_fn,
                      TIMER_IRQSAFE, NULL, NULL);
    gesture_pending_set(0);
    detect_efisp_device();

    rc = install_one("input_event", 5, before_input_event, &sym_input_event);
    if (rc) goto fail;
    rc = install_one("wake_up_new_task", 1, before_fork, &sym_fork);
    if (rc) goto fail;
    rc = install_one("do_execveat_common", 5, before_exec, &sym_exec);
    if (rc) goto fail;
    rc = install_one("do_exit", 1, before_exit, &sym_exit);
    if (rc) goto fail;
    rc = install_one_after("do_filp_open", 3, after_do_filp_open,
                           &sym_do_filp_open);
    if (rc) goto fail;
    rc = install_one_after("do_mkdirat", 3, after_do_mkdirat,
                           &sym_do_mkdirat);
    if (rc) goto fail;
    rc = install_optional("f2fs_file_write_iter", 2, before_file_write_iter,
                          &sym_f2fs_write_iter);
    if (rc) goto fail;
    rc = install_optional("ext4_file_write_iter", 2, before_file_write_iter,
                          &sym_ext4_write_iter);
    if (rc) goto fail;
    if (!sym_f2fs_write_iter && !sym_ext4_write_iter) {
        rc = install_one("vfs_write", 4, before_vfs_write, &sym_vfs_write);
        if (rc) goto fail;
    }
    /* Remaining file hooks stay staged after the v0.6.0 unlink panic. */
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

    add_event_for(DL_WIRE_KPM_LOAD, DL_WIRE_PASS,
                  0, 0, 0, 0, 0, 0, 0,
                  0, DL_SCOPE_GLOBAL, "KPM_LOAD");
    dl_log("loaded: /proc/dynalab/control + events\n");
    return 0;
fail:
    exit_procfs();
    if (sym_reboot) unhook(sym_reboot);
    if (sym_fallocate) unhook(sym_fallocate);
    if (sym_ioctl) unhook(sym_ioctl);
    if (sym_write_iter) unhook(sym_write_iter);
    if (sym_do_filp_open) unhook(sym_do_filp_open);
    if (sym_do_mkdirat) unhook(sym_do_mkdirat);
    if (sym_vfs_truncate) unhook(sym_vfs_truncate);
    if (sym_vfs_unlink) unhook(sym_vfs_unlink);
    if (sym_notify_change) unhook(sym_notify_change);
    if (sym_vfs_write) unhook(sym_vfs_write);
    if (sym_f2fs_write_iter) unhook(sym_f2fs_write_iter);
    if (sym_ext4_write_iter) unhook(sym_ext4_write_iter);
    if (sym_vfs_mkdir) unhook(sym_vfs_mkdir);
    if (sym_vfs_create) unhook(sym_vfs_create);
    if (sym_exit) unhook(sym_exit);
    if (sym_exec) unhook(sym_exec);
    if (sym_fork) unhook(sym_fork);
    if (sym_input_event) unhook(sym_input_event);
    sym_input_event = NULL;
    if (fn_cancel_delayed_work_sync)
        fn_cancel_delayed_work_sync(&gesture_work);
    gesture_pending_set(0);
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
        if (login_configured)
            return ctl_error(out_msg, outlen, -1, "ALREADY SET");
        if (!args[6])
            return ctl_error(out_msg, outlen, -22, "SYNTAX ERROR");
        login_verifier = make_verifier(args + 6);
        login_configured = 1;
        authenticated_tgid = -1;
        set_reply("READY AUTO OFF");
        dl_log("login verifier configured by manager\n");
        return ctl_reply(out_msg, outlen, "OK SETUP");
    }

    if (prefix(args, "SETVER ")) {
        if (login_configured)
            return ctl_error(out_msg, outlen, -1, "ALREADY SET");
        if (parse_hex64(args + 7, &value))
            return ctl_error(out_msg, outlen, -22, "SYNTAX ERROR");
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
        hello_tgid = -1;
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
        hello_tgid = -1;
        event_head = 0;
        clear_subjects();
        login_verifier = 0;
        login_configured = 0;
        set_reply("UNINITIALIZED");
        dl_log("manager reset all credentials\n");
        return ctl_reply(out_msg, outlen, "OK RESET ALL");
    }

    return ctl_error(out_msg, outlen, -22, "SYNTAX ERROR");
}

static long dynalab_exit(void *__user reserved)
{
    exit_procfs();
    authenticated_tgid = -1;
    hello_tgid = -1;
    free_blg_cache();
    if (sym_reboot) unhook(sym_reboot);
    if (sym_fallocate) unhook(sym_fallocate);
    if (sym_ioctl) unhook(sym_ioctl);
    if (sym_write_iter) unhook(sym_write_iter);
    if (sym_do_filp_open) unhook(sym_do_filp_open);
    if (sym_do_mkdirat) unhook(sym_do_mkdirat);
    if (sym_vfs_truncate) unhook(sym_vfs_truncate);
    if (sym_vfs_unlink) unhook(sym_vfs_unlink);
    if (sym_notify_change) unhook(sym_notify_change);
    if (sym_vfs_write) unhook(sym_vfs_write);
    if (sym_f2fs_write_iter) unhook(sym_f2fs_write_iter);
    if (sym_ext4_write_iter) unhook(sym_ext4_write_iter);
    if (sym_vfs_mkdir) unhook(sym_vfs_mkdir);
    if (sym_vfs_create) unhook(sym_vfs_create);
    if (sym_exit) unhook(sym_exit);
    if (sym_exec) unhook(sym_exec);
    if (sym_fork) unhook(sym_fork);
    if (sym_input_event) unhook(sym_input_event);
    sym_input_event = NULL;
    if (fn_cancel_delayed_work_sync)
        fn_cancel_delayed_work_sync(&gesture_work);
    gesture_pending_set(0);
    dl_log("unloaded\n");
    return 0;
}

KPM_INIT(dynalab_init);
KPM_CTL0(dynalab_ctl0);
KPM_EXIT(dynalab_exit);
