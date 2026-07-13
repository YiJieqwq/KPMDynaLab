/*
 * include/kpm_dynalab.h — KPMDynaLab 全局定义
 * =============================================
 * KPM (Kernel Patch Module) — KernelPatch 框架
 *
 * 目标: 在 block layer 部署不可检测的 inline hook,
 *       记录/模拟/拦截所有块设备写操作,
 *       用于格机程序 (bricker) 行为分析。
 *
 * 格机程序无法检测 — hook 在 block layer (libc 之下 4 层):
 *   app → libc → syscall → VFS → block_layer ← HERE
 */

#ifndef _KPM_DYNALAB_H
#define _KPM_DYNALAB_H

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/spinlock.h>
#include <linux/uio.h>
#include <linux/version.h>

#define KPM_NAME        "KPMDynaLab"
#define KPM_VERSION     "v1.0.0"
#define KPM_LICENSE     "GPL-2.0"
#define KPM_AUTHOR      "Linuxnhe"
#define KPM_DESC        "Kernel-level Dynamic Analysis Lab for brickers"

#define PROC_DIR        "dynalab"
#define MAX_ENTRIES     512
#define DEV_NAME_LEN    32

enum dl_mode { DL_MODE_LOG=0, DL_MODE_SIM=1, DL_MODE_BLOCK=2 };

struct dl_entry {
    unsigned long jiffies; pid_t pid; uid_t uid;
    char comm[TASK_COMM_LEN], devname[DEV_NAME_LEN];
    unsigned long lba; size_t count; int mode, action;
};

struct dl_state {
    int mode, entry_count;
    struct dl_entry entries[MAX_ENTRIES];
    spinlock_t lock;
    struct proc_dir_entry *proc_dir, *proc_log, *proc_ctl;
    int (*real_blkdev_open)(struct block_device *, fmode_t, void *);
    ssize_t (*real_blkdev_write_iter)(struct kiocb *, struct iov_iter *);
    int (*real_blkdev_ioctl)(struct block_device *, fmode_t, unsigned, unsigned long);
};

extern struct dl_state dl;

/* hook 模块 */
int  hook_blkdev_init(void);
void hook_blkdev_exit(void);

/* procfs 模块 */
int  procfs_init(void);
void procfs_exit(void);

/* 工具 */
void dl_log(const char *dev, const char *op, loff_t pos, size_t n, int act);

#endif
