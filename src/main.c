/*
 * src/main.c — KPMDynaLab 入口
 * =============================
 * KPM 通过 KernelPatch 框架加载, _init → kpm_init() → _ctl0 → kpm_exit()
 */

#include "../include/kpm_dynalab.h"

struct dl_state dl;

/* 日志 — 写入环形缓冲区 + dmesg */
void dl_log(const char *dev, const char *op, loff_t pos, size_t n, int act) {
    unsigned long f;
    spin_lock_irqsave(&dl.lock, f);
    if (dl.entry_count < MAX_ENTRIES) {
        struct dl_entry *e = &dl.entries[dl.entry_count++];
        e->jiffies = jiffies; e->pid = current->pid;
        e->uid = from_kuid(&init_user_ns, current_uid());
        get_task_comm(e->comm, current);
        snprintf(e->devname, DEV_NAME_LEN, "%s", dev ? dev : "?");
        e->lba = (unsigned long)(pos >> 9);
        e->count = n; e->mode = dl.mode; e->action = act;
    }
    spin_unlock_irqrestore(&dl.lock, f);

    pr_info("[dynalab] %s pid=%d(%s) uid=%d dev=%s lba=%lu n=%zu %s\n",
            op, current->pid, current->comm,
            from_kuid(&init_user_ns, current_uid()),
            dev ? dev : "?", (unsigned long)(pos>>9), n,
            act==0?"PASS":act==1?"SIM":"BLOCK");
}

/* KPM 入口 */
int kpm_init(void) {
    int ret;
    spin_lock_init(&dl.lock);
    dl.mode = DL_MODE_LOG;
    dl.entry_count = 0;

    pr_info("[dynalab] %s %s — INIT\n", KPM_NAME, KPM_VERSION);

    /* 安装 block layer hooks */
    ret = hook_blkdev_init();
    if (ret < 0) { pr_err("[dynalab] hook init failed\n"); return ret; }

    /* 创建 /proc/dynalab/ */
    ret = procfs_init();
    if (ret < 0) { pr_err("[dynalab] procfs init failed\n"); return ret; }

    pr_info("[dynalab] loaded — cat /proc/dynalab/log\n");
    return 0;
}

/* KPM 出口 */
void kpm_exit(void) {
    procfs_exit();
    hook_blkdev_exit();
    pr_info("[dynalab] unloaded\n");
}
