/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/sched.h>
#include <linux/reboot.h>
#include <linux/kallsyms.h>
#include <uapi/linux/fs.h>

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

extern int hook_wrap(void *func, int argc, void *before, void *after, void *udata);
extern void unhook(void *func);
extern int compat_copy_to_user(void __user *to, const void *from, int n);
/* KernelPatch exports function-pointer variables with these ELF symbol names. */
extern unsigned long (*kp_lookup_name)(const char *name) __asm__("kallsyms_lookup_name");
extern int (*kp_printk)(const char *fmt, ...) __asm__("printk");
#define dl_log(fmt, ...) kp_printk("[dynalab] " fmt, ##__VA_ARGS__)

KPM_NAME("KPMDynaLab");
KPM_VERSION("0.3.3-test");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Linuxnhe Developers");
KPM_DESCRIPTION("Android block-device dynamic analysis prototype");

enum dl_profile { DL_TRACE = 1, DL_AUTO = 2, DL_EXPERT = 3 };
enum dl_state { DL_READY = 1, DL_CONFIGURED = 2, DL_SEALED = 3 };

static int profile = DL_AUTO;
static int state = DL_READY;
static void *sym_write_iter, *sym_ioctl, *sym_fallocate, *sym_reboot;
static void (*fn_iov_iter_advance)(struct iov_iter *i, size_t bytes);

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

static int simulate_dangerous(void)
{
    /* Analysis policy becomes active only after the manager seals it. */
    return state == DL_SEALED && profile != DL_TRACE;
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
            current->pid, MAJOR(dev), MINOR(dev), pos, count, profile_name(),
            simulate_dangerous() ? "SIMULATE" : "PASS");

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
            current->pid, MAJOR(dev), MINOR(dev), cmd, profile_name(),
            simulate_dangerous() ? "SIMULATE" : "PASS");

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
            current->pid, MAJOR(dev), MINOR(dev), mode, start, len,
            profile_name(), simulate_dangerous() ? "SIMULATE" : "PASS");

    if (simulate_dangerous()) {
        args->skip_origin = 1;
        args->ret = 0;
    }
}

/* __arm64_sys_reboot receives pt_regs; for the first test we only suppress it. */
static void before_reboot(hook_fargs1_t *args, void *udata)
{
    dl_log("REBOOT pid=%d profile=%s action=%s\n",
            current->pid, profile_name(), simulate_dangerous() ? "SUPPRESS" : "PASS");
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

static long dynalab_init(const char *args, const char *event, void *__user reserved)
{
    int rc;
    profile = DL_AUTO;
    state = DL_READY;
    dl_log("init event=%s default=AUTO state=READY\n", event ? event : "?");

    fn_iov_iter_advance = (void *)kp_lookup_name("iov_iter_advance");
    if (!fn_iov_iter_advance) {
        dl_log("ERROR: symbol not found: iov_iter_advance\n");
        return -2;
    }

    rc = install_one("blkdev_write_iter", 2, before_blkdev_write_iter, &sym_write_iter);
    if (rc) goto fail;
    rc = install_one("blkdev_ioctl", 3, before_blkdev_ioctl, &sym_ioctl);
    if (rc) goto fail;
    rc = install_one("blkdev_fallocate", 4, before_blkdev_fallocate, &sym_fallocate);
    if (rc) goto fail;
    rc = install_one("__arm64_sys_reboot", 1, before_reboot, &sym_reboot);
    if (rc) goto fail;

    dl_log("loaded: ctl0 TRACE|AUTO|EXPERT, then SEAL\n");
    return 0;
fail:
    if (sym_reboot) unhook(sym_reboot);
    if (sym_fallocate) unhook(sym_fallocate);
    if (sym_ioctl) unhook(sym_ioctl);
    if (sym_write_iter) unhook(sym_write_iter);
    sym_reboot = sym_fallocate = sym_ioctl = sym_write_iter = NULL;
    return rc;
}

static long dynalab_ctl0(const char *args, char __user *out_msg, int outlen)
{
    if (!args)
        return -22;

    if (streq(args, "STATUS")) {
        if (state == DL_READY)
            return ctl_reply(out_msg, outlen, "state=READY profile=AUTO interception=OFF");
        if (state == DL_CONFIGURED)
            return ctl_reply(out_msg, outlen,
                profile == DL_TRACE ? "state=CONFIGURED profile=TRACE interception=OFF" :
                profile == DL_AUTO ? "state=CONFIGURED profile=AUTO interception=OFF" :
                                     "state=CONFIGURED profile=EXPERT interception=OFF");
        return ctl_reply(out_msg, outlen,
            profile == DL_TRACE ? "state=SEALED profile=TRACE interception=PASS" :
            profile == DL_AUTO ? "state=SEALED profile=AUTO interception=SIMULATE" :
                                 "state=SEALED profile=EXPERT interception=SIMULATE");
    }

    if (streq(args, "RESET")) {
        state = DL_READY;
        profile = DL_AUTO;
        dl_log("manager reset -> READY/AUTO interception=OFF\n");
        return ctl_reply(out_msg, outlen, "OK RESET state=READY interception=OFF");
    }

    if (state == DL_SEALED)
        return -1;

    if (streq(args, "TRACE"))
        profile = DL_TRACE;
    else if (streq(args, "AUTO"))
        profile = DL_AUTO;
    else if (streq(args, "EXPERT"))
        profile = DL_EXPERT;
    else if (streq(args, "SEAL")) {
        if (state != DL_CONFIGURED)
            return -22;
        state = DL_SEALED;
        dl_log("SEALED profile=%s\n", profile_name());
        return ctl_reply(out_msg, outlen,
            profile == DL_TRACE ? "OK SEALED TRACE: pass-through enabled" :
            profile == DL_AUTO ? "OK SEALED AUTO: dangerous operations simulated" :
                                 "OK SEALED EXPERT: AUTO-safe fallback");
    } else {
        return -22;
    }

    state = DL_CONFIGURED;
    dl_log("configured profile=%s interception=OFF until SEAL\n", profile_name());
    return ctl_reply(out_msg, outlen,
        profile == DL_TRACE ? "OK CONFIGURED TRACE; send SEAL to activate" :
        profile == DL_AUTO ? "OK CONFIGURED AUTO; send SEAL to activate" :
                             "OK CONFIGURED EXPERT; send SEAL to activate");
}

static long dynalab_exit(void *__user reserved)
{
    if (sym_reboot) unhook(sym_reboot);
    if (sym_fallocate) unhook(sym_fallocate);
    if (sym_ioctl) unhook(sym_ioctl);
    if (sym_write_iter) unhook(sym_write_iter);
    dl_log("unloaded\n");
    return 0;
}

KPM_INIT(dynalab_init);
KPM_CTL0(dynalab_ctl0);
KPM_EXIT(dynalab_exit);
