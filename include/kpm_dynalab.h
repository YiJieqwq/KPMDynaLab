/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/kpm_dynalab.h — KPMDynaLab 全局定义
 * =============================================
 * KPM (Kernel Patch Module) — KernelPatch 框架
 *
 * 目标: 在 block layer 部署不可检测的 inline hook,
 *       记录/模拟/拦截所有块设备写操作,
 *       用于格机程序 (bricker) 行为分析。
 *
 * 格机程序无法检测此模块:
 *   - 无 LD_PRELOAD (无 /proc/self/maps 痕迹)
 *   - 无 ptrace 附加 (TracerPid=0)
 *   - 不使用 kprobe (kprobes/list 为空)
 *   - 不使用 ftrace (enabled_functions 无异常)
 *   - 不在 userspace 留任何进程/文件
 *
 * Hook 路径: app → libc → syscall → VFS → blkdev_open ← HERE
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

/* ---- 元数据 (.kpm.info) ---- */
#define KPM_NAME        "KPMDynaLab"
#define KPM_VERSION     "v1.0.0"
#define KPM_LICENSE     "GPL-2.0-only"
#define KPM_AUTHOR      "YiJieqwq"
#define KPM_DESC        "Kernel-level Dynamic Analysis Lab for bricker malware"

/* ---- procfs ---- */
#define PROC_DIR        "dynalab"
#define MAX_ENTRIES     512
#define DEV_NAME_LEN    32
#define COMM_LEN        16

/* ---- 模式 ---- */
enum dl_mode { DL_MODE_LOG = 0, DL_MODE_SIM = 1, DL_MODE_BLOCK = 2 };

/* ---- 日志条目 ---- */
struct dl_entry {
    unsigned long jiffies;
    pid_t pid;
    uid_t uid;
    char comm[TASK_COMM_LEN];
    char devname[DEV_NAME_LEN];
    unsigned long lba;
    size_t count;
    int mode;
    int action;   /* 0=PASS, 1=SIM, 2=BLOCK */
};

/* ---- 全局状态 ---- */
struct dl_state {
    int mode;
    int entry_count;
    struct dl_entry entries[MAX_ENTRIES];
    spinlock_t lock;

    /* procfs 节点 */
    struct proc_dir_entry *proc_dir;
    struct proc_dir_entry *proc_log;
    struct proc_dir_entry *proc_ctl;

    /* 原始函数指针 (hook_wrap 自动填充) */
    int   (*real_blkdev_open)(struct block_device *, fmode_t, void *);
    ssize_t (*real_blkdev_write_iter)(struct kiocb *, struct iov_iter *);
    int   (*real_blkdev_ioctl)(struct block_device *, fmode_t,
                                unsigned, unsigned long);

    /* 内核符号 (kallsyms_lookup_name 解析) */
    void *kallsyms_lookup_name_fn;
    void *printk_fn;
    void *get_task_comm_fn;

    /* 白名单 */
    int whitelist_enabled;
};

extern struct dl_state dl;

/* ---- hook 模块 ---- */
int  hook_blkdev_init(void);
void hook_blkdev_exit(void);
int  is_whitelisted(void);

/* ---- procfs 模块 ---- */
int  procfs_init(void);
void procfs_exit(void);

/* ---- 工具 ---- */
void dl_log(const char *dev, const char *op, loff_t pos, size_t n, int act);

#endif
