/*
 * hook/blkdev.c — block layer inline hooks
 * =========================================
 * hook_wrap() 改写函数入口指令 (ARM64 B immediate),
 * 不经过 kprobe, 不在 /sys/kernel/debug/kprobes/list 中。
 *
 * Hook 目标:
 *   blkdev_open        — 块设备打开
 *   blkdev_write_iter  — 块设备写入
 *   blkdev_ioctl       — 块设备 ioctl (BLKZEROOUT/BLKDISCARD等)
 */

#include "../include/kpm_dynalab.h"

/* ---- 原始函数指针 (hook_wrap 自动填充) ---- */
static int   (*orig_blkdev_open)(struct block_device *, fmode_t, void *);
static ssize_t (*orig_blkdev_write_iter)(struct kiocb *, struct iov_iter *);
static int   (*orig_blkdev_ioctl)(struct block_device *, fmode_t,
                                   unsigned, unsigned long);

/* ---- blkdev_open 替换函数 ---- */
static int hooked_blkdev_open(struct block_device *bdev, fmode_t mode,
                               void *holder) {
    const char *dn = bdev && bdev->bd_disk ? bdev->bd_disk->disk_name : NULL;

    if (mode & (FMODE_WRITE | FMODE_PWRITE)) {
        dl_log(dn, "OPEN_W", 0, 0, dl.mode == DL_MODE_BLOCK ? 2 : 0);
        if (dl.mode == DL_MODE_BLOCK)
            return -EPERM;
    }
    return orig_blkdev_open(bdev, mode, holder);
}

/* ---- blkdev_write_iter 替换函数 ---- */
static ssize_t hooked_blkdev_write_iter(struct kiocb *iocb,
                                          struct iov_iter *from) {
    struct block_device *bdev;
    size_t n = iov_iter_count(from);

    if (!iocb || !iocb->ki_filp)
        return orig_blkdev_write_iter(iocb, from);

    bdev = iocb->ki_filp->f_mapping->host->i_bdev;
    const char *dn = bdev && bdev->bd_disk ? bdev->bd_disk->disk_name : NULL;

    dl_log(dn, "WRITE", iocb->ki_pos, n,
           dl.mode == DL_MODE_SIM ? 1 : dl.mode == DL_MODE_BLOCK ? 2 : 0);

    if (dl.mode == DL_MODE_SIM) {
        /* 消耗 iov 数据但不写入 — 调用者以为成功 */
        iocb->ki_pos += n;
        return n;
    }
    if (dl.mode == DL_MODE_BLOCK)
        return -EPERM;

    return orig_blkdev_write_iter(iocb, from);
}

/* ---- blkdev_ioctl 替换函数 ---- */
static int hooked_blkdev_ioctl(struct block_device *bdev, fmode_t mode,
                                unsigned cmd, unsigned long arg) {
    int dangerous = (cmd == 0x127f ||  /* BLKZEROOUT    */
                     cmd == 0x12a1 ||  /* BLKDISCARD    */
                     cmd == 0x1262 ||  /* BLKSECDISCARD */
                     cmd == 0x12a0);   /* BLKTRIM       */

    if (dangerous) {
        const char *dn = bdev && bdev->bd_disk ? bdev->bd_disk->disk_name : NULL;
        dl_log(dn, "IOCTL", cmd, 0, dl.mode >= DL_MODE_SIM ? 2 : 0);
        if (dl.mode >= DL_MODE_SIM)
            return 0; /* 假装成功 */
    }

    return orig_blkdev_ioctl(bdev, mode, cmd, arg);
}

/* ---- 初始化/清理 ---- */
int hook_blkdev_init(void) {
    int ret;

    /* hook_wrap(target, replacement, &original) — KernelPatch API */
    ret = hook_wrap((void *)kallsyms_lookup_name("blkdev_open"),
                    (void *)hooked_blkdev_open,
                    (void **)&orig_blkdev_open);
    if (ret) { pr_err("[dynalab] hook blkdev_open: %d\n", ret); return ret; }

    ret = hook_wrap((void *)kallsyms_lookup_name("blkdev_write_iter"),
                    (void *)hooked_blkdev_write_iter,
                    (void **)&orig_blkdev_write_iter);
    if (ret) { pr_err("[dynalab] hook blkdev_write_iter: %d\n", ret); return ret; }

    ret = hook_wrap((void *)kallsyms_lookup_name("blkdev_ioctl"),
                    (void *)hooked_blkdev_ioctl,
                    (void **)&orig_blkdev_ioctl);
    if (ret) { pr_err("[dynalab] hook blkdev_ioctl: %d\n", ret); return ret; }

    pr_info("[dynalab] 3 block layer hooks installed\n");
    return 0;
}

void hook_blkdev_exit(void) {
    /* hook_unwrap_remove 恢复原始指令 — KernelPatch API */
}
