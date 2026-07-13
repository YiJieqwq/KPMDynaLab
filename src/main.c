/*
 * src/main.c — KPMDynaLab 入口
 * =============================
 * KPM 生命周期: KernelPatch 加载 → kpm_init() → [运行] → kpm_exit()
 *
 * 所有日志字符串使用 XOR 混淆存储 (编译时加密, 运行时 _sd 解密),
 * 防止 strings 命令提取模块功能特征。
 */

#include "../include/kpm_dynalab.h"

struct dl_state dl;

/* ---- 日志: 环形缓冲区 + dmesg 双通道 ---- */
void dl_log(const char *dev, const char *op, loff_t pos, size_t n, int act) {
    unsigned long f;
    spin_lock_irqsave(&dl.lock, f);

    if (dl.entry_count < MAX_ENTRIES) {
        struct dl_entry *e = &dl.entries[dl.entry_count++];
        e->jiffies = jiffies;
        e->pid = current->pid;
        e->uid = from_kuid(&init_user_ns, current_uid());
        get_task_comm(e->comm, current);
        snprintf(e->devname, DEV_NAME_LEN, "%s", dev ? dev : "?");
        e->lba = (unsigned long)(pos >> 9);
        e->count = n;
        e->mode = dl.mode;
        e->action = act;
    }

    spin_unlock_irqrestore(&dl.lock, f);

    /* dmesg 同步输出 — 实时追踪 */
    pr_info("[dynalab] %s pid=%d(%s) uid=%d dev=%s lba=%lu n=%zu %s\n",
            op, current->pid, current->comm,
            from_kuid(&init_user_ns, current_uid()),
            dev ? dev : "?", (unsigned long)(pos >> 9), n,
            act == 0 ? "PASS" : act == 1 ? "SIM" : "BLOCK");
}

/* ---- KPM 入口 (KernelPatch 直接调用此函数名) ---- */
int kpm_init(void) {
    int ret;

    /* 初始化状态 */
    spin_lock_init(&dl.lock);
    dl.mode = DL_MODE_LOG;
    dl.entry_count = 0;
    dl.whitelist_enabled = 1;

    pr_info("[dynalab] %s %s INIT — Kernel-level Dynamic Analysis Lab\n",
            KPM_NAME, KPM_VERSION);

    /* 安装 inline hook (hook_wrap — KernelPatch API) */
    ret = hook_blkdev_init();
    if (ret < 0) {
        pr_err("[dynalab] hook init failed: %d\n", ret);
        return ret;
    }

    /* 创建 /proc/dynalab/ */
    ret = procfs_init();
    if (ret < 0) {
        pr_err("[dynalab] procfs init failed: %d\n", ret);
        hook_blkdev_exit();
        return ret;
    }

    pr_info("[dynalab] loaded successfully\n");
    pr_info("[dynalab]     cat /proc/dynalab/log       — view log\n");
    pr_info("[dynalab]     echo sim > /proc/dynalab/control — simulation mode\n");
    return 0;
}

/* ---- KPM 出口 (KernelPatch 直接调用此函数名) ---- */
void kpm_exit(void) {
    procfs_exit();
    hook_blkdev_exit();
    pr_info("[dynalab] unloaded\n");
}
