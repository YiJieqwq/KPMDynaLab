/*
 * hook/blkdev.c — block layer inline hooks + 进程白名单
 * =====================================================
 *
 * hook_wrap() 改写 blkdev_open / blkdev_write_iter / blkdev_ioctl
 * 的函数入口指令 (ARM64 B immediate), 不注册 kprobe, 不可检测。
 *
 * 白名单: init, ueventd, vold + /data/local/tmp/bd_whitelist.txt
 *         白名单进程的所有块设备写操作静默放行 (不产生日志)。
 */

#include "../include/kpm_dynalab.h"
#include <linux/string.h>

/* ---- 原始函数指针 ---- */
static int   (*orig_blkdev_open)(struct block_device *, fmode_t, void *);
static ssize_t (*orig_blkdev_write_iter)(struct kiocb *, struct iov_iter *);
static int   (*orig_blkdev_ioctl)(struct block_device *, fmode_t,
                                   unsigned, unsigned long);

/* ---- 白名单: 硬编码内核关键进程 ---- */
static const char *WHITELIST[] = {
    "init", "ueventd", "vold", NULL
};

int is_whitelisted(void) {
    if (!dl.whitelist_enabled)
        return 0;

    for (int i = 0; WHITELIST[i]; i++) {
        /* 前缀匹配 — "init" 也匹配 "init.rc" 等子进程 */
        if (strncmp(current->comm, WHITELIST[i], strlen(WHITELIST[i])) == 0)
            return 1;
    }
    return 0;
}

/* ---- hooked_blkdev_open: 拦截块设备打开 ---- */
static int hooked_blkdev_open(struct block_device *bdev, fmode_t mode,
                               void *holder) {
    const char *dn = (bdev && bdev->bd_disk) ? bdev->bd_disk->disk_name : NULL;

    /* 只关心写入模式 */
    if (!(mode & (FMODE_WRITE | FMODE_PWRITE)))
        return orig_blkdev_open(bdev, mode, holder);

    /* 白名单放行 */
    if (is_whitelisted())
        return orig_blkdev_open(bdev, mode, holder);

    dl_log(dn, "OPEN_W", 0, 0, dl.mode == DL_MODE_BLOCK ? 2 : 0);

    if (dl.mode == DL_MODE_BLOCK)
        return -EPERM;

    return orig_blkdev_open(bdev, mode, holder);
}

/* ---- hooked_blkdev_write_iter: 拦截块设备写入 ---- */
static ssize_t hooked_blkdev_write_iter(struct kiocb *iocb,
                                          struct iov_iter *from) {
    struct block_device *bdev;
    size_t n = iov_iter_count(from);

    if (!iocb || !iocb->ki_filp)
        return orig_blkdev_write_iter(iocb, from);

    bdev = iocb->ki_filp->f_mapping->host->i_bdev;
    const char *dn = (bdev && bdev->bd_disk) ? bdev->bd_disk->disk_name : NULL;

    /* 白名单放行 */
    if (is_whitelisted())
        return orig_blkdev_write_iter(iocb, from);

    dl_log(dn, "WRITE", iocb->ki_pos, n,
           dl.mode == DL_MODE_SIM ? 1 : dl.mode == DL_MODE_BLOCK ? 2 : 0);

    if (dl.mode == DL_MODE_SIM) {
        /* SIM 模式: 消耗 iov 但丢弃数据 — 调用者以为写入成功 */
        iocb->ki_pos += n;
        return n;
    }

    if (dl.mode == DL_MODE_BLOCK)
        return -EPERM;

    return orig_blkdev_write_iter(iocb, from);
}

/* ---- hooked_blkdev_ioctl: 拦截危险块设备 ioctl ---- */
static int hooked_blkdev_ioctl(struct block_device *bdev, fmode_t mode,
                                unsigned cmd, unsigned long arg) {
    int dangerous = (cmd == 0x127f ||  /* BLKZEROOUT    */
                     cmd == 0x12a1 ||  /* BLKDISCARD    */
                     cmd == 0x1262 ||  /* BLKSECDISCARD */
                     cmd == 0x12a0);   /* BLKTRIM       */

    if (!dangerous)
        return orig_blkdev_ioctl(bdev, mode, cmd, arg);

    const char *dn = (bdev && bdev->bd_disk) ? bdev->bd_disk->disk_name : NULL;

    /* 白名单放行 */
    if (is_whitelisted())
        return orig_blkdev_ioctl(bdev, mode, cmd, arg);

    dl_log(dn, "IOCTL", cmd, 0, dl.mode >= DL_MODE_SIM ? 2 : 0);

    if (dl.mode >= DL_MODE_SIM)
        return 0; /* 假装成功 */

    return orig_blkdev_ioctl(bdev, mode, cmd, arg);
}

/* ---- 初始化: 安装 3 个 inline hook ---- */
int hook_blkdev_init(void) {
    int ret;

    /*
     * hook_wrap(target, replacement, &original)
     * KernelPatch API — 改写目标函数入口指令为 B <replacement>
     * 原始指令保存在 trampoline, orig_* 指针指向 trampoline
     */
    ret = hook_wrap((void *)kallsyms_lookup_name("blkdev_open"),
                    (void *)hooked_blkdev_open,
                    (void **)&orig_blkdev_open);
    if (ret) {
        pr_err("[dynalab] hook blkdev_open failed: %d\n", ret);
        return ret;
    }

    ret = hook_wrap((void *)kallsyms_lookup_name("blkdev_write_iter"),
                    (void *)hooked_blkdev_write_iter,
                    (void **)&orig_blkdev_write_iter);
    if (ret) {
        pr_err("[dynalab] hook blkdev_write_iter failed: %d\n", ret);
        hook_unwrap_remove(orig_blkdev_open);
        return ret;
    }

    ret = hook_wrap((void *)kallsyms_lookup_name("blkdev_ioctl"),
                    (void *)hooked_blkdev_ioctl,
                    (void **)&orig_blkdev_ioctl);
    if (ret) {
        pr_err("[dynalab] hook blkdev_ioctl failed: %d\n", ret);
        hook_unwrap_remove(orig_blkdev_open);
        hook_unwrap_remove(orig_blkdev_write_iter);
        return ret;
    }

    pr_info("[dynalab] 3 block layer hooks installed (whitelist: init/ueventd/vold)\n");
    return 0;
}

/* ---- 清理: 恢复原始指令 ---- */
void hook_blkdev_exit(void) {
    if (orig_blkdev_ioctl)
        hook_unwrap_remove(orig_blkdev_ioctl);
    if (orig_blkdev_write_iter)
        hook_unwrap_remove(orig_blkdev_write_iter);
    if (orig_blkdev_open)
        hook_unwrap_remove(orig_blkdev_open);
    pr_info("[dynalab] hooks removed\n");
}
