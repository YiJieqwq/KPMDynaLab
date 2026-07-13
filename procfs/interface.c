/*
 * procfs/interface.c — /proc/dynalab/log + /proc/dynalab/control
 */

#include "../include/kpm_dynalab.h"

/* ---- /proc/dynalab/log — 只读 ---- */
static int log_show(struct seq_file *m, void *v) {
    unsigned long f;
    spin_lock_irqsave(&dl.lock, f);
    seq_printf(m, "KPMDynaLab %s | mode=%s | entries=%d/%d\n\n",
               KPM_VERSION,
               dl.mode==0?"LOG":dl.mode==1?"SIM":"BLOCK",
               dl.entry_count, MAX_ENTRIES);
    seq_printf(m, "%-8s %-6s %-6s %-16s %-12s %-8s %-10s %s\n",
               "TIME(s)","PID","UID","COMM","DEV","LBA","SIZE","ACT");
    for (int i = 0; i < dl.entry_count; i++) {
        struct dl_entry *e = &dl.entries[i];
        seq_printf(m, "%-8lu %-6d %-6d %-16s %-12s %-8lu %-10zu %s\n",
            e->jiffies/HZ, e->pid, e->uid, e->comm, e->devname,
            e->lba, e->count,
            e->action==0?"PASS":e->action==1?"SIM":"BLOCK");
    }
    spin_unlock_irqrestore(&dl.lock, f);
    return 0;
}
static int log_open(struct inode *i, struct file *f) { return single_open(f, log_show, NULL); }
static const struct file_operations log_fops = {
    .owner=THIS_MODULE,.open=log_open,.read=seq_read,.llseek=seq_lseek,.release=single_release
};

/* ---- /proc/dynalab/control — 读写 ---- */
static ssize_t ctl_write(struct file *f, const char __user *b, size_t n, loff_t *o) {
    char c[8]={0}; size_t l=n<7?n:7;
    if (copy_from_user(c,b,l)) return -EFAULT;
    if (c[l-1]=='\n') c[l-1]=0;

    if (!strcmp(c,"sim"))        { dl.mode=DL_MODE_SIM;   pr_info("[dynalab] mode=SIM\n"); }
    else if (!strcmp(c,"block")) { dl.mode=DL_MODE_BLOCK; pr_info("[dynalab] mode=BLOCK\n"); }
    else if (!strcmp(c,"log"))   { dl.mode=DL_MODE_LOG;   pr_info("[dynalab] mode=LOG\n"); }
    else if (!strcmp(c,"clear")) {
        unsigned long fl; spin_lock_irqsave(&dl.lock,fl);
        dl.entry_count=0; spin_unlock_irqrestore(&dl.lock,fl);
        pr_info("[dynalab] cleared\n");
    }
    else return -EINVAL;
    return n;
}
static ssize_t ctl_read(struct file *f, char __user *b, size_t n, loff_t *o) {
    char t[8]; int l=snprintf(t,8,"%s\n",dl.mode==0?"LOG":dl.mode==1?"SIM":"BLOCK");
    return simple_read_from_buffer(b,n,o,t,l);
}
static const struct file_operations ctl_fops = {
    .owner=THIS_MODULE,.read=ctl_read,.write=ctl_write
};

/* ---- 初始化 /proc/dynalab/ ---- */
int procfs_init(void) {
    dl.proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (!dl.proc_dir) return -ENOMEM;
    dl.proc_log = proc_create("log", 0444, dl.proc_dir, &log_fops);
    dl.proc_ctl = proc_create("control", 0666, dl.proc_dir, &ctl_fops);
    if (!dl.proc_log || !dl.proc_ctl) return -ENOMEM;
    pr_info("[dynalab] /proc/dynalab/ created\n");
    return 0;
}

void procfs_exit(void) {
    if (dl.proc_log) proc_remove(dl.proc_log);
    if (dl.proc_ctl) proc_remove(dl.proc_ctl);
    if (dl.proc_dir) proc_remove(dl.proc_dir);
}
