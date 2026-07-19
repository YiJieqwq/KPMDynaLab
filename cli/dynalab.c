/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../include/dl_rpc.h"

#define CONTROL_PATH "/proc/dynalab/control"
#define EVENTS_PATH  "/proc/dynalab/events"
#define CACHE_PATH   "/proc/dynalab/cache"
#define BLG_VAULT    "/data/adb/dynalab/blg-recovery-pack"
#define MAX_LINE 512

static int use_color;
static const char *clr(const char *code)
{
    return use_color ? code : "";
}

#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_CYAN   "\033[36m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_RED    "\033[31m"
#define C_DIM    "\033[2m"

static uint64_t password_verifier(const unsigned char *s, size_t n)
{
    /* v0.4 protocol verifier; replaced by challenge/HMAC in the auth milestone. */
    uint64_t h = UINT64_C(1469598103934665603);
    size_t i;
    for (i = 0; i < n; ++i) {
        h ^= s[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

static int read_password(char *buf, size_t size)
{
    struct termios oldt, newt;
    size_t n;
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &oldt) < 0)
        return -1;
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) < 0)
        return -1;
    fputs("Password: ", stdout);
    fflush(stdout);
    if (!fgets(buf, (int)size, stdin)) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
        return -1;
    }
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
    fputc('\n', stdout);
    n = strlen(buf);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    return n ? 0 : -1;
}

static int rpc(const char *command, char *reply, size_t reply_size)
{
    int fd;
    ssize_t n;
    fd = open(CONTROL_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    n = write(fd, command, strlen(command));
    if (n < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    close(fd);
    fd = open(CONTROL_PATH, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    n = read(fd, reply, reply_size - 1);
    if (n < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    reply[n] = '\0';
    close(fd);
    return 0;
}

static int compatibility_check(char *kpm_version, size_t size)
{
    char command[64], reply[256], version[64];
    int kpm_api = 0, event_abi = 0;
    int rc;
    snprintf(command, sizeof(command), "HELLO %d %d",
             DL_RPC_API_VERSION, DL_EVENT_ABI_VERSION);
    rc = rpc(command, reply, sizeof(reply));
    if (rc == -ENOENT || rc == -ENODEV) {
        fprintf(stderr, "KPM component is not loaded. Load KPMDynaLab first.\n");
        return -1;
    }
    if (rc == -EACCES && geteuid() != 0) {
        fprintf(stderr, "Permission denied. Run the CLI as root.\n");
        return -1;
    }
    if (rc < 0) {
        if (rc == -EACCES || rc == -EPERM || rc == -EINVAL) {
            fprintf(stderr, "KPM component is outdated. Update the KPM component.\n");
        } else {
            fprintf(stderr, "KPM communication failed: %s (%d)\n",
                    strerror(-rc), rc);
        }
        return -1;
    }
    if (!strncmp(reply, "ERR KPM_OLD", 11)) {
        fprintf(stderr, "KPM component is outdated. Update the KPM component.\n");
        return -1;
    }
    if (!strncmp(reply, "ERR CLI_OLD", 11)) {
        fprintf(stderr, "CLI component is outdated. Update the CLI.\n");
        return -1;
    }
    if (!strncmp(reply, "ERR SEALED", 10)) {
        fprintf(stderr, "KPM session is SEALED. Use the original CLI or Manager RESET.\n");
        return -1;
    }
    if (sscanf(reply, "OK HELLO %d %d %63s", &kpm_api, &event_abi,
               version) != 3) {
        fprintf(stderr, "Incompatible KPM protocol response: %s\n", reply);
        return -1;
    }
    if (kpm_api < DL_RPC_API_VERSION ||
        event_abi != DL_EVENT_ABI_VERSION) {
        fprintf(stderr, "KPM component is outdated. Update the KPM component.\n");
        return -1;
    }
    snprintf(kpm_version, size, "%s", version);
    return 0;
}

static const char *event_name(unsigned int type)
{
    switch (type) {
    case DL_WIRE_BLOCK_WRITE: return "BLOCK_WRITE";
    case DL_WIRE_BLOCK_IOCTL: return "BLOCK_IOCTL";
    case DL_WIRE_BLOCK_FALLOCATE: return "BLOCK_FALLOCATE";
    case DL_WIRE_REBOOT: return "REBOOT";
    case DL_WIRE_FORK: return "FORK";
    case DL_WIRE_EXEC: return "EXEC";
    case DL_WIRE_EXIT: return "EXIT";
    case DL_WIRE_FILE_CREATE: return "FILE_CREATE";
    case DL_WIRE_FILE_MKDIR: return "FILE_MKDIR";
    case DL_WIRE_FILE_WRITE: return "FILE_WRITE";
    case DL_WIRE_FILE_ATTR: return "FILE_ATTR";
    case DL_WIRE_FILE_RENAME: return "FILE_RENAME";
    case DL_WIRE_FILE_UNLINK: return "FILE_UNLINK";
    case DL_WIRE_FILE_TRUNCATE: return "FILE_TRUNCATE";
    case DL_WIRE_GESTURE: return "GESTURE";
    case DL_WIRE_KPM_LOAD: return "KPM_LOAD";
    case DL_WIRE_CLI_LOGIN: return "CLI_LOGIN";
    case DL_WIRE_CLI_LOGOUT: return "CLI_LOGOUT";
    default: return "UNKNOWN";
    }
}

static const char *action_name(unsigned int action)
{
    switch (action) {
    case DL_WIRE_PASS: return "PASS";
    case DL_WIRE_SIMULATE: return "SIMULATE";
    case DL_WIRE_SUPPRESS: return "SUPPRESS";
    default: return "UNKNOWN";
    }
}

static void format_event_time(const struct dl_wire_event *e,
                              char *buf, size_t size)
{
    time_t sec = (time_t)(e->realtime_ns / 1000000000ULL);
    struct tm tm;
    unsigned long long ms = (e->realtime_ns / 1000000ULL) % 1000ULL;
    if (!e->realtime_ns || !gmtime_r(&sec, &tm)) {
        snprintf(buf, size, "time=?");
        return;
    }
    snprintf(buf, size, "%04d-%02d-%02dT%02d:%02d:%02d.%03lluZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

static const char *scope_name(unsigned int scope)
{
    switch (scope) {
    case DL_SCOPE_TARGET: return "target";
    case DL_SCOPE_DESCENDANT: return "descendant";
    default: return "global";
    }
}

struct dl_dev_label {
    unsigned int major, minor;
    char label[64];
};

static const char *device_label(unsigned int major_no, unsigned int minor_no)
{
    static struct dl_dev_label cache[64];
    static unsigned int used;
    char path[160], buf[4096], *p, *end;
    ssize_t n;
    int fd;
    unsigned int i;

    if (!major_no && !minor_no) return "-";
    for (i = 0; i < used; i++)
        if (cache[i].major == major_no && cache[i].minor == minor_no)
            return cache[i].label;
    if (used >= 64) return "?";
    cache[used].major = major_no;
    cache[used].minor = minor_no;
    snprintf(cache[used].label, sizeof(cache[used].label), "?");

    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/dm/name", major_no, minor_no);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        n = read(fd, cache[used].label, sizeof(cache[used].label) - 1);
        close(fd);
        if (n > 0) {
            cache[used].label[n] = '\0';
            cache[used].label[strcspn(cache[used].label, "\r\n")] = '\0';
            return cache[used++].label;
        }
    }

    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/uevent", major_no, minor_no);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            p = strstr(buf, "PARTNAME=");
            if (!p) p = strstr(buf, "DEVNAME=");
            if (p) {
                p = strchr(p, '=') + 1;
                end = strpbrk(p, "\r\n");
                if (end) *end = '\0';
                snprintf(cache[used].label, sizeof(cache[used].label), "%.63s", p);
            }
        }
    }
    return cache[used++].label;
}

static void print_event_record(FILE *out, const struct dl_wire_event *e, int color)
{
    char timestamp[48];
    const char *dim = color ? C_DIM : "";
    const char *cyan = color ? C_CYAN : "";
    const char *bold = color ? C_BOLD : "";
    const char *reset = color ? C_RESET : "";
    const char *ac = !color ? "" :
        e->action == DL_WIRE_PASS ? C_GREEN :
        e->action == DL_WIRE_SIMULATE ? C_YELLOW : C_RED;

    format_event_time(e, timestamp, sizeof(timestamp));
    fprintf(out, "%s#%u%s  %s%s%s  %smono=+%llu.%03llus%s  ",
            dim, e->sequence, reset, cyan, timestamp, reset, dim,
            e->monotonic_ns / 1000000000ULL,
            (e->monotonic_ns / 1000000ULL) % 1000ULL, reset);

    if (e->type == DL_WIRE_GESTURE) {
        fprintf(out, "%sGESTURE%s  result=%s%s%s  %s%s%s  cmd=0x%x  scope=global\n",
                bold, reset, bold, e->name[0] ? e->name : "UNKNOWN", reset,
                ac, action_name(e->action), reset, e->command);
    } else if (e->type == DL_WIRE_KPM_LOAD) {
        fprintf(out, "%sKPM_LOAD%s  %s%s%s  component=KPMDynaLab\n",
                bold, reset, ac, action_name(e->action), reset);
    } else if (e->type == DL_WIRE_CLI_LOGIN || e->type == DL_WIRE_CLI_LOGOUT) {
        fprintf(out, "%s%s%s  %s%s%s  pid=%u  scope=global\n",
                bold, event_name(e->type), reset,
                ac, action_name(e->action), reset, e->pid);
    } else if (e->type == DL_WIRE_BLOCK_WRITE ||
               e->type == DL_WIRE_BLOCK_IOCTL ||
               e->type == DL_WIRE_BLOCK_FALLOCATE) {
        fprintf(out, "%s%s%s  %s%s%s  dev=%u:%u(%s)  off=%llu  len=%llu  "
                "pid=%u  proc=%s  session=%u  cmd=0x%x\n",
                bold, event_name(e->type), reset, ac, action_name(e->action), reset,
                e->major, e->minor, device_label(e->major, e->minor),
                e->offset, e->length, e->pid,
                e->name[0] ? e->name : "?", e->session_id, e->command);
    } else if (e->type == DL_WIRE_FORK || e->type == DL_WIRE_EXEC ||
               e->type == DL_WIRE_EXIT) {
        fprintf(out, "%s%s%s  %s%s%s  pid=%u  ppid=%u  session=%u  "
                "scope=%s%s%s\n",
                bold, event_name(e->type), reset, ac, action_name(e->action), reset,
                e->pid, e->parent_pid, e->session_id, scope_name(e->scope),
                e->name[0] ? "  name=" : "", e->name[0] ? e->name : "");
    } else if (e->type >= DL_WIRE_FILE_CREATE &&
               e->type <= DL_WIRE_FILE_TRUNCATE) {
        fprintf(out, "%s%s%s  %s%s%s  path=%s  pid=%u  session=%u  "
                "off=%llu  len=%llu\n",
                bold, event_name(e->type), reset, ac, action_name(e->action), reset,
                e->name[0] ? e->name : "?", e->pid, e->session_id,
                e->offset, e->length);
    } else {
        fprintf(out, "%s%s%s  %s%s%s  pid=%u  ppid=%u  session=%u  "
                "dev=%u:%u  off=%llu  len=%llu  cmd=0x%x%s%s\n",
                bold, event_name(e->type), reset, ac, action_name(e->action), reset,
                e->pid, e->parent_pid, e->session_id, e->major, e->minor,
                e->offset, e->length, e->command,
                e->name[0] ? "  name=" : "", e->name[0] ? e->name : "");
    }
}

static int stream_events(FILE *out, int color, unsigned int *exported)
{
    int fd = open(EVENTS_PATH, O_RDONLY | O_CLOEXEC);
    struct dl_wire_event e;
    ssize_t n;
    unsigned int count = 0;
    if (fd < 0) {
        perror(EVENTS_PATH);
        return 1;
    }
    while ((n = read(fd, &e, sizeof(e))) == (ssize_t)sizeof(e)) {
        if (e.magic != DL_EVENT_MAGIC || e.version != DL_EVENT_ABI_VERSION)
            continue;
        print_event_record(out, &e, color);
        count++;
    }
    close(fd);
    if (exported) *exported = count;
    return n < 0 ? 1 : 0;
}

static int show_events(void)
{
    return stream_events(stdout, use_color, NULL);
}

static int run_shell(const char *script)
{
    int status;
    pid_t pid = fork();
    if (pid == 0) {
        execl("/system/bin/sh", "sh", "-c", script, (char *)NULL);
        _exit(127);
    }
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }
    return !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int export_events(void)
{
    const char *dir = "/data/adb/dynalab/logs";
    char path[320];
    time_t now = time(NULL);
    struct tm tm;
    FILE *out;
    int fd;
    unsigned int count = 0;

    if (run_shell("mkdir -p '/data/adb/dynalab/logs' && chmod 700 '/data/adb/dynalab/logs'")) {
        puts("Failed to create log directory.");
        return 1;
    }
    if (!gmtime_r(&now, &tm)) return 1;
    snprintf(path, sizeof(path),
             "%s/dynalab-events-%04d%02d%02dT%02d%02d%02dZ-%d.log",
             dir, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)getpid());
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) { perror(path); return 1; }
    out = fdopen(fd, "w");
    if (!out) { perror("fdopen"); close(fd); unlink(path); return 1; }

    fprintf(out, "# KPMDynaLab Event Export\n");
    fprintf(out, "# format=text-v1 rpc_api=%d event_abi=%d timezone=UTC\n",
            DL_RPC_API_VERSION, DL_EVENT_ABI_VERSION);
    fprintf(out, "# exported_utc=%04d-%02d-%02dT%02d:%02d:%02dZ\n",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (stream_events(out, 0, &count)) {
        fclose(out); unlink(path); puts("Event export failed."); return 1;
    }
    fflush(out);
    fsync(fileno(out));
    fclose(out);
    printf("Exported %u events: %s\n", count, path);
    return 0;
}

static int blg_pack_present(void)
{
    return access(BLG_VAULT "/manifest.sha256", R_OK) == 0;
}

static int blg_efisp_arm(void)
{
    static const char *paths[] = {
        "/dev/block/by-name/efisp",
        "/dev/block/by-name/efisp_a",
        "/dev/block/by-name/efisp_b",
    };
    struct stat st;
    char command[96], reply[256];
    size_t i;
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (stat(paths[i], &st) || !S_ISBLK(st.st_mode))
            continue;
        snprintf(command, sizeof(command), "EFISP ARM %u %u",
                 major(st.st_rdev), minor(st.st_rdev));
        if (rpc(command, reply, sizeof(reply)) < 0) {
            fprintf(stderr, "EFISP Guard registration failed.\n");
            return 1;
        }
        printf("EFISP Guard: %s (%s)\n", reply, paths[i]);
        return strncmp(reply, "OK", 2) != 0;
    }
    puts("EFISP Guard: NOT PRESENT ON THIS DEVICE");
    return 0;
}

static int blg_pack_create(void)
{
    static const char script[] =
        "set -eu\n"
        "V='" BLG_VAULT "'\n"
        "N=\"${V}.new.$$\"\n"
        "O=\"${V}.old\"\n"
        "trap 'rm -rf \"$N\"' EXIT\n"
        "mkdir -p \"$N/images\"\n"
        "COUNT=0\n"
        "for P in xbl_a xbl_b xbl_config_a xbl_config_b abl_a abl_b "
        "devcfg_a devcfg_b tz_a tz_b hyp_a hyp_b rpm_a rpm_b "
        "aop_a aop_b aop_config_a aop_config_b keymaster_a keymaster_b "
        "cmnlib_a cmnlib_b cmnlib64_a cmnlib64_b qupfw_a qupfw_b "
        "uefisecapp_a uefisecapp_b imagefv_a imagefv_b shrm_a shrm_b "
        "multiimgoem_a multiimgoem_b efisp efisp_a efisp_b "
        "ocdt ocdt_a ocdt_b; do\n"
        "  D=\"/dev/block/by-name/$P\"\n"
        "  [ -b \"$D\" ] || continue\n"
        "  S=$(blockdev --getsize64 \"$D\")\n"
        "  [ \"$S\" -gt 0 ] && [ \"$S\" -le 67108864 ] || { "
        "echo \"Skipping unsafe size: $P ($S bytes)\"; continue; }\n"
        "  echo \"  extracting $P ($S bytes)\"\n"
        "  dd if=\"$D\" of=\"$N/images/$P.img\" bs=1048576 status=none\n"
        "  COUNT=$((COUNT + 1))\n"
        "done\n"
        "[ \"$COUNT\" -gt 0 ] || { echo 'No supported boot-chain partitions found.'; exit 4; }\n"
        "for A in \"$N\"/images/*_a.img; do\n"
        "  [ -e \"$A\" ] || continue\n"
        "  B=\"${A%_a.img}_b.img\"\n"
        "  [ -e \"$B\" ] || continue\n"
        "  if cmp -s \"$A\" \"$B\"; then\n"
        "    rm -f \"$B\" && ln \"$A\" \"$B\"\n"
        "    echo \"  deduplicated $(basename \"$A\") / $(basename \"$B\")\"\n"
        "  fi\n"
        "done\n"
        "{\n"
        "  echo 'format=KPMDynaLab-BLG-Pack'\n"
        "  echo 'format_version=2'\n"
        "  echo 'storage=raw-images-with-hardlink-dedup'\n"
        "  echo \"created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)\"\n"
        "  echo \"product=$(getprop ro.product.device)\"\n"
        "  echo \"hardware=$(getprop ro.hardware)\"\n"
        "  echo \"slot=$(getprop ro.boot.slot_suffix)\"\n"
        "  echo \"kernel=$(uname -r)\"\n"
        "  echo \"image_count=$COUNT\"\n"
        "} > \"$N/device.txt\"\n"
        "(cd \"$N\" && sha256sum images/*.img > manifest.sha256)\n"
        "(cd \"$N\" && sha256sum -c manifest.sha256)\n"
        "sync\n"
        "rm -rf \"$O\"\n"
        "[ ! -e \"$V\" ] || mv \"$V\" \"$O\"\n"
        "mv \"$N\" \"$V\"\n"
        "trap - EXIT\n"
        "sync\n"
        "echo \"Recovery Pack created: $V\"\n"
        "du -sh \"$V\" 2>/dev/null || true\n";

    puts("Creating a device-local BLG Recovery Pack...");
    puts("This v0.8.0 milestone only extracts and verifies images; it cannot flash them.");
    return run_shell(script);
}

static int blg_pack_verify_quiet(void)
{
    static const char script[] =
        "set -eu\n"
        "V='" BLG_VAULT "'\n"
        "[ -r \"$V/manifest.sha256\" ]\n"
        "cd \"$V\"\n"
        "sha256sum -c manifest.sha256 >/dev/null\n";
    return run_shell(script);
}

static int blg_pack_verify(void)
{
    static const char script[] =
        "set -eu\n"
        "V='" BLG_VAULT "'\n"
        "[ -r \"$V/manifest.sha256\" ]\n"
        "cd \"$V\"\n"
        "sha256sum -c manifest.sha256\n"
        "echo 'Recovery Pack: VERIFIED'\n";
    return run_shell(script);
}

struct blg_cache_source {
    char path[384];
    off_t size;
    dev_t dev;
    ino_t ino;
};

static char blg_active_slot(void)
{
    const char *files[] = { "/proc/bootconfig", "/proc/cmdline" };
    char buf[8192];
    int i;
    for (i = 0; i < 2; i++) {
        int fd = open(files[i], O_RDONLY | O_CLOEXEC);
        ssize_t n;
        char *p;
        if (fd < 0) continue;
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';
        p = strstr(buf, "androidboot.slot_suffix");
        if (p) {
            p += strlen("androidboot.slot_suffix");
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '=') p++;
            while (*p == ' ' || *p == '\t' || *p == '\"') p++;
            if (*p == '_') p++;
            if (*p == 'a' || *p == 'b') return *p;
        }
    }
    return 0;
}

static int blg_map_build(struct blg_cache_source *src, int used)
{
    char reply[256], command[512], target[DL_BLG_MAP_NAME];
    char active = blg_active_slot();
    unsigned long long offset = 0;
    int i, entries = 0;
    if (active != 'a' && active != 'b') {
        fprintf(stderr, "Cannot determine active slot.\n");
        return 1;
    }
    if (rpc("BLG MAP BEGIN", reply, sizeof(reply)) < 0 || strncmp(reply, "OK", 2))
        return 1;
    for (i = 0; i < used; i++) {
        const char *base = strrchr(src[i].path, '/');
        char name[DL_BLG_MAP_NAME];
        size_t len;
        struct stat st;
        int fd;
        off_t target_size;
        unsigned int flags, tier;
        base = base ? base + 1 : src[i].path;
        len = strlen(base);
        if (len >= sizeof(name)) {
            fprintf(stderr, "Image name too long: %s\n", base);
            return 1;
        }
        memcpy(name, base, len + 1);
        if (len > 4 && !strcmp(name + len - 4, ".img")) name[len - 4] = '\0';

        if (!strcmp(name, "efisp") || !strcmp(name, "efisp_a") ||
            !strcmp(name, "efisp_b")) {
            snprintf(target, sizeof(target), "%s", name);
            flags = DL_BLG_FLAG_SHARED | DL_BLG_FLAG_EFISP;
            tier = 0;
        } else {
            len = strlen(name);
            if (len < 3 || name[len - 2] != '_' ||
                (name[len - 1] != 'a' && name[len - 1] != 'b')) {
                offset += src[i].size;
                continue;
            }
            if (name[len - 1] != active) {
                offset += src[i].size;
                continue;
            }
            snprintf(target, sizeof(target), "%s", name);
            target[len - 1] = active == 'a' ? 'b' : 'a';
            flags = DL_BLG_FLAG_AB;
            tier = (!strncmp(name, "xbl", 3)) ? 0 :
                   (!strncmp(name, "multiimgoem", 11) ? 2 : 1);
        }

        snprintf(command, sizeof(command), "/dev/block/by-name/%s", target);
        if (stat(command, &st) || !S_ISBLK(st.st_mode)) {
            fprintf(stderr, "Missing map target: %s\n", command);
            return 1;
        }
        fd = open(command, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { perror(command); return 1; }
        target_size = lseek(fd, 0, SEEK_END);
        close(fd);
        if (target_size <= 0 || src[i].size > target_size) {
            fprintf(stderr, "Invalid target size: %s\n", command);
            return 1;
        }
        snprintf(command, sizeof(command),
                 "BLG MAP ADD %s %llu %llu %u %u %llu %u %u",
                 target, offset, (unsigned long long)src[i].size,
                 major(st.st_rdev), minor(st.st_rdev),
                 (unsigned long long)target_size, flags, tier);
        if (rpc(command, reply, sizeof(reply)) < 0 || strncmp(reply, "OK", 2)) {
            fprintf(stderr, "Map add failed: %s\n", reply);
            return 1;
        }
        entries++;
        offset += src[i].size;
    }
    if (!entries || rpc("BLG MAP COMMIT", reply, sizeof(reply)) < 0 ||
        strncmp(reply, "OK PLAN READY NO WRITE", 22)) {
        fprintf(stderr, "Map commit failed: %s\n", reply);
        return 1;
    }
    if (rpc("BLG MAP VERIFY", reply, sizeof(reply)) < 0 ||
        strncmp(reply, "OK MAP INTACT", 13)) {
        fprintf(stderr, "Map verification failed: %s\n", reply);
        return 1;
    }
    printf("BLG Image Map: PLAN READY NO WRITE (%d targets, active slot _%c)\n",
           entries, active);
    return 0;
}

static int write_all_fd(int fd, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_full_fd(int fd, void *buf, size_t len)
{
    unsigned char *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int blg_cache_load(int verbose)
{
    struct dirent **entries = NULL;
    struct blg_cache_source src[64];
    struct stat st;
    char directory[320], command[96], reply[256];
    unsigned char *in = NULL, *out = NULL;
    uint64_t total = 0, transferred = 0;
    struct timespec begin, end;
    int count, used = 0, i, j, cache_fd = -1, rc = 1;
    reply[0] = '\0';

    if ((verbose ? blg_pack_verify() : blg_pack_verify_quiet())) return 1;
    snprintf(directory, sizeof(directory), "%s/images", BLG_VAULT);
    count = scandir(directory, &entries, NULL, alphasort);
    if (count < 0) { perror("scandir Recovery Pack"); return 1; }

    for (i = 0; i < count && used < 64; i++) {
        size_t n = strlen(entries[i]->d_name);
        int duplicate = 0;
        if (n < 5 || strcmp(entries[i]->d_name + n - 4, ".img"))
            continue;
        snprintf(src[used].path, sizeof(src[used].path), "%s/%s",
                 directory, entries[i]->d_name);
        if (stat(src[used].path, &st) || !S_ISREG(st.st_mode)) continue;
        for (j = 0; j < used; j++)
            if (src[j].dev == st.st_dev && src[j].ino == st.st_ino)
                duplicate = 1;
        if (duplicate) continue;
        src[used].size = st.st_size;
        src[used].dev = st.st_dev;
        src[used].ino = st.st_ino;
        total += (uint64_t)st.st_size;
        used++;
    }
    for (i = 0; i < count; i++) free(entries[i]);
    free(entries);
    if (!used || !total || total > 256ULL * 1024 * 1024) {
        fprintf(stderr, "Invalid unique Recovery Pack size: %llu bytes\n",
                (unsigned long long)total);
        return 1;
    }

    snprintf(command, sizeof(command), "BLG CACHE BEGIN %llu",
             (unsigned long long)total);
    if (rpc(command, reply, sizeof(reply)) < 0 || strncmp(reply, "OK", 2)) {
        fprintf(stderr, "KPM cache allocation failed: %s\n", reply);
        return 1;
    }
    cache_fd = open(CACHE_PATH, O_WRONLY | O_CLOEXEC);
    if (cache_fd < 0) { perror(CACHE_PATH); goto out; }
    in = malloc(1024 * 1024);
    out = malloc(1024 * 1024);
    if (!in || !out) { perror("cache buffer"); goto out; }

    clock_gettime(CLOCK_MONOTONIC, &begin);
    for (i = 0; i < used; i++) {
        int fd = open(src[i].path, O_RDONLY | O_CLOEXEC);
        off_t left = src[i].size;
        if (fd < 0) { perror(src[i].path); goto out; }
        if (verbose)
            printf("  loading %s (%lld bytes)\n", src[i].path, (long long)left);
        while (left) {
            size_t chunk = left > 1024 * 1024 ? 1024 * 1024 : (size_t)left;
            if (read_full_fd(fd, in, chunk) || write_all_fd(cache_fd, in, chunk)) {
                close(fd); perror("cache upload"); goto out;
            }
            left -= chunk;
            transferred += chunk;
        }
        close(fd);
    }
    close(cache_fd); cache_fd = -1;
    if (rpc("BLG CACHE COMMIT", reply, sizeof(reply)) < 0 ||
        strncmp(reply, "OK CACHE READY", 14)) {
        fprintf(stderr, "KPM cache commit failed: %s\n", reply);
        goto out;
    }

    cache_fd = open(CACHE_PATH, O_RDONLY | O_CLOEXEC);
    if (cache_fd < 0) { perror(CACHE_PATH); goto out; }
    for (i = 0; i < used; i++) {
        int fd = open(src[i].path, O_RDONLY | O_CLOEXEC);
        off_t left = src[i].size;
        if (fd < 0) { perror(src[i].path); goto out; }
        while (left) {
            size_t chunk = left > 1024 * 1024 ? 1024 * 1024 : (size_t)left;
            if (read_full_fd(fd, in, chunk) ||
                read_full_fd(cache_fd, out, chunk) || memcmp(in, out, chunk)) {
                close(fd);
                fprintf(stderr, "RAM cache verification failed: %s\n", src[i].path);
                goto out;
            }
            left -= chunk;
        }
        close(fd);
    }
    if (read(cache_fd, out, 1) != 0) {
        fprintf(stderr, "RAM cache has unexpected trailing data.\n");
        goto out;
    }
    if (rpc("BLG CACHE VERIFY", reply, sizeof(reply)) < 0 ||
        strncmp(reply, "OK CACHE INTACT", 15)) {
        fprintf(stderr, "KPM cache SHA-256 verification failed: %s\n", reply);
        goto out;
    }
    if (blg_map_build(src, used)) goto out;
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("BLG RAM Cache: READY RO / SHA-256 INTACT\nUnique images: %d\nRAM usage: %llu bytes\n",
           used, (unsigned long long)total);
    printf("Upload + full byte verification: %.3f seconds\n",
           (end.tv_sec - begin.tv_sec) +
           (end.tv_nsec - begin.tv_nsec) / 1000000000.0);
    rc = 0;
out:
    if (cache_fd >= 0) close(cache_fd);
    free(in); free(out);
    if (rc) rpc("BLG CACHE DROP", reply, sizeof(reply));
    return rc;
}

static void blg_cache_status(void)
{
    char reply[256];
    if (rpc("BLG CACHE STATUS", reply, sizeof(reply)) < 0)
        puts("BLG RAM Cache: RPC ERROR");
    else
        printf("BLG RAM Cache: %s\n", reply);
}

static int blg_ready(void)
{
    char cache[256], map[256];
    return !rpc("BLG CACHE STATUS", cache, sizeof(cache)) &&
           !rpc("BLG MAP STATUS", map, sizeof(map)) &&
           !strncmp(cache, "OK CACHE READY RO", 17) &&
           !strncmp(map, "OK PLAN READY NO WRITE", 22);
}

static int blg_prepare(void)
{
    if (blg_ready()) {
        puts("Boot Lifeguard: READY");
        return 0;
    }
    if (!blg_pack_present()) {
        puts("Boot Lifeguard: NOT CONFIGURED");
        return 1;
    }
    puts("Preparing Boot Lifeguard...");
    if (blg_cache_load(0)) {
        puts("Boot Lifeguard: PREPARE FAILED");
        return 1;
    }
    puts("Boot Lifeguard: READY");
    return 0;
}

static unsigned long long blg_unique_pack_size(void)
{
    struct dirent **entries = NULL;
    dev_t devs[64]; ino_t inos[64];
    char directory[320], path[384];
    struct stat st;
    unsigned long long total = 0;
    int count, used = 0, i, j;
    snprintf(directory, sizeof(directory), "%s/images", BLG_VAULT);
    count = scandir(directory, &entries, NULL, alphasort);
    if (count < 0) return 0;
    for (i = 0; i < count; i++) {
        size_t n = strlen(entries[i]->d_name);
        int dup = 0;
        if (n < 5 || strcmp(entries[i]->d_name + n - 4, ".img")) continue;
        snprintf(path, sizeof(path), "%s/%s", directory, entries[i]->d_name);
        if (stat(path, &st) || !S_ISREG(st.st_mode)) continue;
        for (j = 0; j < used; j++)
            if (devs[j] == st.st_dev && inos[j] == st.st_ino) dup = 1;
        if (!dup && used < 64) {
            devs[used] = st.st_dev; inos[used] = st.st_ino; used++;
            total += st.st_size;
        }
    }
    for (i = 0; i < count; i++) free(entries[i]);
    free(entries);
    return total;
}

static int blg_selftest(void)
{
    const char *image = "/data/local/tmp/dynalab-blg-selftest.img";
    char loopdev[128] = {0}, command[512], reply[256];
    unsigned long long size;
    struct timespec begin, end;
    FILE *pipe;
    int fd, rc = 1, rpc_rc;
    reply[0] = '\0';

    if (!blg_ready() && blg_prepare()) return 1;
    size = blg_unique_pack_size();
    if (!size) { puts("Cannot determine self-test size."); return 1; }
    fd = open(image, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) { perror(image); return 1; }
    if (ftruncate(fd, (off_t)(size + 1024 * 1024))) {
        perror("ftruncate self-test"); close(fd); unlink(image); return 1;
    }
    close(fd);

    pipe = popen("losetup -f", "r");
    if (!pipe || !fgets(loopdev, sizeof(loopdev), pipe)) {
        if (pipe) pclose(pipe);
        puts("No free loop device."); unlink(image); return 1;
    }
    pclose(pipe);
    loopdev[strcspn(loopdev, "\r\n")] = '\0';
    if (strncmp(loopdev, "/dev/block/loop", 15)) {
        puts("Unexpected loop device path."); unlink(image); return 1;
    }
    snprintf(command, sizeof(command), "losetup '%s' '%s'", loopdev, image);
    if (run_shell(command)) { unlink(image); return 1; }

    printf("BLG loop self-test: %s (%llu bytes, injected corruption enabled)\n",
           loopdev, size);
    snprintf(command, sizeof(command), "BLG SELFTEST %s INJECT", loopdev);
    clock_gettime(CLOCK_MONOTONIC, &begin);
    rpc_rc = rpc(command, reply, sizeof(reply));
    if (rpc_rc < 0) {
        printf("BLG self-test RPC failed: %s (%d)\n", strerror(-rpc_rc), rpc_rc);
        goto out;
    }
    if (strncmp(reply, "OK SELFTEST REPAIRED", 20)) {
        printf("BLG self-test failed: %s\n", reply[0] ? reply : "unknown KPM error");
        goto out;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    printf("%s\n", reply);
    printf("Write + flush + detect + repair + full verify: %.3f seconds\n",
           (end.tv_sec - begin.tv_sec) +
           (end.tv_nsec - begin.tv_nsec) / 1000000000.0);
    rc = 0;
out:
    snprintf(command, sizeof(command), "losetup -d '%s'", loopdev);
    run_shell(command);
    unlink(image);
    return rc;
}

static int blg_verify_all(void)
{
    char reply[256];
    if (blg_pack_verify_quiet()) {
        puts("Recovery Pack: INVALID"); return 1;
    }
    puts("Recovery Pack: VERIFIED");
    if (rpc("BLG CACHE VERIFY", reply, sizeof(reply)) < 0 ||
        strncmp(reply, "OK CACHE INTACT", 15)) {
        printf("RAM Cache: %s\n", reply); return 1;
    }
    puts("RAM Cache: INTACT");
    if (rpc("BLG MAP VERIFY", reply, sizeof(reply)) < 0 ||
        strncmp(reply, "OK MAP INTACT", 13)) {
        printf("Image Map: %s\n", reply); return 1;
    }
    puts("Image Map: INTACT");
    return 0;
}

static void blg_pack_status(void)
{
    if (!blg_pack_present()) {
        puts("Boot Lifeguard: NO RECOVERY PACK");
        return;
    }
    printf("Boot Lifeguard Recovery Pack: %s\n", BLG_VAULT);
    run_shell("cat '" BLG_VAULT "/device.txt' 2>/dev/null || true; "
              "du -sh '" BLG_VAULT "' 2>/dev/null || true");
    blg_cache_status();
    {
        char reply[256];
        if (!rpc("BLG MAP STATUS", reply, sizeof(reply)))
            printf("BLG Image Map: %s\n", reply);
    }
}

static void blg_first_run_prompt(void)
{
    char answer[16];
    if (blg_pack_present()) return;
    puts("\nBoot Lifeguard is not configured.");
    puts("A device-local Recovery Pack is required for future emergency recovery.");
    printf("Create Recovery Pack now? [Y/n] ");
    fflush(stdout);
    if (!fgets(answer, sizeof(answer), stdin) || answer[0] == '\n' ||
        answer[0] == 'y' || answer[0] == 'Y') {
        if (blg_pack_create())
            puts("Recovery Pack creation failed. Use 'blg pack create' to retry.");
    } else {
        puts("Skipped. Use 'blg pack create' later.");
    }
}

static void help(void)
{
    puts("Commands:");
    puts("  status                 show KPM state");
    puts("  active                 show active target/descendant count");
    puts("  profile auto|trace|expert");
    puts("  seal                   activate selected profile");
    puts("  stop                   authenticated stop/reset");
    puts("  events | event         show recorded events");
    puts("  export                 export events to /data/adb/dynalab/logs");
    puts("  blg status             show BLG state");
    puts("  blg setup              rebuild pack and prepare BLG");
    puts("  blg prepare            load/validate BLG if needed");
    puts("  blg verify             verify pack, RAM cache and image map");
    puts("  blg selftest           run loop-backed write/repair verification");
    puts("  blg release            release BLG RAM cache before SEALED");
    puts("  blg advanced           show low-level BLG commands");
    puts("  clear                  clear event ring (not while SEALED)");
    puts("  run <program> [args]   seal and execute target");
    puts("  help");
    puts("  exit");
}

static int send_and_print(const char *cmd)
{
    char reply[256];
    int rc = rpc(cmd, reply, sizeof(reply));
    if (rc < 0) {
        fprintf(stderr, "RPC failed: %s (%d)\n", strerror(-rc), rc);
        return 1;
    }
    puts(reply[0] ? reply : "OK");
    return !strncmp(reply, "ERR", 3);
}

static int login(void)
{
    char password[256];
    char command[64];
    char reply[256];
    uint64_t verifier;
    int rc;

    if (read_password(password, sizeof(password)) < 0)
        return -1;
    verifier = password_verifier((unsigned char *)password, strlen(password));
    memset(password, 0, sizeof(password));
    snprintf(command, sizeof(command), "LOGIN %016llx",
             (unsigned long long)verifier);
    rc = rpc(command, reply, sizeof(reply));
    memset(command, 0, sizeof(command));
    if (rc < 0 || strncmp(reply, "OK", 2)) {
        fprintf(stderr, "%s\n", rc < 0 ? "Login RPC failed" : reply);
        return -1;
    }
    puts("Login successful. Type 'help'.");
    return 0;
}

int main(int argc, char **argv)
{
    char line[MAX_LINE];
    char reply[256];
    char kpm_version[64];

    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (geteuid() != 0)
        fprintf(stderr, "warning: run as root to access %s\n", CONTROL_PATH);

    if (argc == 2 && !strcmp(argv[1], "events"))
        return show_events();
    if (argc == 2 && !strcmp(argv[1], "verifier")) {
        char password[256];
        uint64_t verifier;
        if (read_password(password, sizeof(password)) < 0)
            return 1;
        verifier = password_verifier((unsigned char *)password, strlen(password));
        memset(password, 0, sizeof(password));
        printf("SETVER %016llx\n", (unsigned long long)verifier);
        return 0;
    }

    use_color = isatty(STDOUT_FILENO) && getenv("NO_COLOR") == NULL;
    printf("%s%sKPMDynaLab%s %sv0.8.12-lifecycle-events-test%s\n",
           clr(C_BOLD), clr(C_CYAN), clr(C_RESET), clr(C_DIM), clr(C_RESET));
    printf("%sKernel-assisted dynamic analysis laboratory%s\n\n",
           clr(C_DIM), clr(C_RESET));
    if (compatibility_check(kpm_version, sizeof(kpm_version)) < 0)
        return 2;
    printf("KPM: %s (API %d, Event ABI %d)\n", kpm_version,
           DL_RPC_API_VERSION, DL_EVENT_ABI_VERSION);
    if (rpc("STATUS", reply, sizeof(reply)) < 0) {
        fprintf(stderr, "KPMDynaLab is not available at %s\n", CONTROL_PATH);
        return 1;
    }
    printf("Kernel: %s\n", reply);
    if (!strcmp(reply, "UNINITIALIZED")) {
        fprintf(stderr,
                "No login password is configured. Set it in Manager > KPMDynaLab > Control first.\n");
        fprintf(stderr,
                "Run 'dynalab verifier' to generate a SETVER command.\n");
        return 3;
    }
    if (login() < 0)
        return 1;
    blg_efisp_arm();
    blg_first_run_prompt();
    if (blg_pack_present()) blg_prepare();

    while (1) {
        char *cmd, *arg;
        printf("%sDynaLab%s> ", clr(C_CYAN), clr(C_RESET));
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin))
            break;
        line[strcspn(line, "\r\n")] = '\0';
        cmd = strtok(line, " \t");
        if (!cmd)
            continue;
        arg = strtok(NULL, "");

        if (!strcmp(cmd, "exit") || !strcmp(cmd, "quit")) {
            if (!rpc("STATUS", reply, sizeof(reply)) &&
                !strncmp(reply, "SEALED", 6)) {
                char answer[16];
                printf("Session is SEALED. Stop it before exiting? [Y/n] ");
                fflush(stdout);
                if (!fgets(answer, sizeof(answer), stdin) ||
                    answer[0] == '\n' || answer[0] == 'y' || answer[0] == 'Y') {
                    if (send_and_print("STOP"))
                        continue;
                } else {
                    puts("Leaving protection SEALED; Manager RESET may be required.");
                }
            }
            break;
        }
        if (!strcmp(cmd, "help")) {
            help();
        } else if (!strcmp(cmd, "status")) {
            send_and_print("STATUS");
        } else if (!strcmp(cmd, "active")) {
            send_and_print("ACTIVE");
        } else if (!strcmp(cmd, "profile") && arg) {
            char rpc_cmd[64];
            snprintf(rpc_cmd, sizeof(rpc_cmd), "PROFILE %s", arg);
            send_and_print(rpc_cmd);
        } else if (!strcmp(cmd, "seal")) {
            send_and_print("SEAL");
        } else if (!strcmp(cmd, "stop")) {
            send_and_print("STOP");
        } else if (!strcmp(cmd, "events") || !strcmp(cmd, "event")) {
            show_events();
        } else if (!strcmp(cmd, "export")) {
            export_events();
        } else if (!strcmp(cmd, "blg") && arg) {
            if (!strcmp(arg, "status"))
                blg_pack_status();
            else if (!strcmp(arg, "setup")) {
                if (!send_and_print("BLG CACHE DROP") &&
                    !blg_pack_create()) blg_prepare();
            } else if (!strcmp(arg, "prepare"))
                blg_prepare();
            else if (!strcmp(arg, "verify"))
                blg_verify_all();
            else if (!strcmp(arg, "selftest"))
                blg_selftest();
            else if (!strcmp(arg, "release"))
                send_and_print("BLG CACHE DROP");
            else if (!strcmp(arg, "advanced"))
                puts("Advanced: blg pack create/verify | blg cache load/status/verify/drop | blg map status/verify/drop");
            else if (!strcmp(arg, "pack create"))
                blg_pack_create();
            else if (!strcmp(arg, "pack verify"))
                blg_pack_verify();
            else if (!strcmp(arg, "cache load"))
                blg_cache_load(1);
            else if (!strcmp(arg, "cache status"))
                blg_cache_status();
            else if (!strcmp(arg, "cache verify"))
                send_and_print("BLG CACHE VERIFY");
            else if (!strcmp(arg, "cache drop"))
                send_and_print("BLG CACHE DROP");
            else if (!strcmp(arg, "map status"))
                send_and_print("BLG MAP STATUS");
            else if (!strcmp(arg, "map verify"))
                send_and_print("BLG MAP VERIFY");
            else if (!strcmp(arg, "map drop"))
                send_and_print("BLG MAP DROP");
            else
                puts("Usage: blg status | setup | prepare | verify | release | advanced");
        } else if (!strcmp(cmd, "clear")) {
            send_and_print("CLEAR");
        } else if (!strcmp(cmd, "run") && arg) {
            pid_t pid;
            char *run_argv[64];
            int n = 0, status, gate[2], active = 0;
            char *tok;
            char target_cmd[64], workdir[128], answer[16];

            tok = strtok(arg, " \t");
            while (tok && n < 63) {
                run_argv[n++] = tok;
                tok = strtok(NULL, " \t");
            }
            run_argv[n] = NULL;
            if (!n)
                continue;
            if (pipe(gate) < 0) {
                perror("pipe");
                continue;
            }
            pid = fork();
            if (pid == 0) {
                char go;
                close(gate[1]);
                if (read(gate[0], &go, 1) != 1)
                    _exit(126);
                close(gate[0]);
                snprintf(workdir, sizeof(workdir),
                         "/data/local/tmp/dynalab-run-%d", getpid());
                setenv("DYNALAB_WORKDIR", workdir, 1);
                execvp(run_argv[0], run_argv);
                fprintf(stderr, "exec failed: %s: %s\n",
                        run_argv[0], strerror(errno));
                _exit(127);
            }
            close(gate[0]);
            if (pid < 0) {
                close(gate[1]);
                perror("fork");
                continue;
            }
            snprintf(workdir, sizeof(workdir),
                     "/data/local/tmp/dynalab-run-%d", pid);
            if (mkdir(workdir, 0700) < 0 && errno != EEXIST) {
                perror("mkdir workdir");
                kill(pid, SIGKILL);
                close(gate[1]);
                waitpid(pid, NULL, 0);
                continue;
            }
            snprintf(target_cmd, sizeof(target_cmd), "TARGET %d", pid);
            if (send_and_print(target_cmd) || send_and_print("SEAL")) {
                kill(pid, SIGKILL);
                close(gate[1]);
                waitpid(pid, NULL, 0);
                continue;
            }
            if (write(gate[1], "G", 1) != 1)
                perror("release target");
            close(gate[1]);

            waitpid(pid, &status, 0);
            if (WIFEXITED(status))
                printf("Target exited: code=%d\n", WEXITSTATUS(status));
            else if (WIFSIGNALED(status))
                printf("Target killed: signal=%d\n", WTERMSIG(status));
            else
                printf("Target state: raw_status=%d\n", status);
            show_events();

            if (!rpc("ACTIVE", reply, sizeof(reply)))
                sscanf(reply, "ACTIVE %d", &active);
            if (active > 0) {
                printf("%d descendant(s) still active; session remains SEALED.\n",
                       active);
                printf("Artifacts preserved until descendants exit: %s\n", workdir);
                continue;
            }

            printf("Cleanup session workdir %s? [Y/n] ", workdir);
            fflush(stdout);
            if (!fgets(answer, sizeof(answer), stdin) ||
                answer[0] == '\n' || answer[0] == 'y' || answer[0] == 'Y') {
                pid_t cleaner = fork();
                if (cleaner == 0) {
                    execl("/system/bin/rm", "rm", "-rf", "--", workdir,
                          (char *)NULL);
                    _exit(127);
                }
                if (cleaner > 0) {
                    waitpid(cleaner, &status, 0);
                    printf("Cleanup: %s\n",
                           WIFEXITED(status) && WEXITSTATUS(status) == 0 ?
                           "OK" : "FAILED");
                }
            } else {
                printf("Artifacts preserved: %s\n", workdir);
            }
        } else {
            puts("Unknown command; type 'help'.");
        }
    }
    rpc("LOGOUT", reply, sizeof(reply));
    memset(line, 0, sizeof(line));
    return 0;
}
