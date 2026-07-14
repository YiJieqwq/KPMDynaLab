/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "../include/dl_rpc.h"

#define CONTROL_PATH "/proc/dynalab/control"
#define EVENTS_PATH  "/proc/dynalab/events"
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
    if (rc < 0 || !strncmp(reply, "ERR KPM_OLD", 11)) {
        fprintf(stderr, "KPM component is too old; update required.\n");
        fprintf(stderr, "KPM组件版本过旧，需要更新KPM。\n");
        return -1;
    }
    if (!strncmp(reply, "ERR CLI_OLD", 11)) {
        fprintf(stderr, "CLI component is too old; update required.\n");
        fprintf(stderr, "CLI组件版本过旧，需要更新CLI。\n");
        return -1;
    }
    if (sscanf(reply, "OK HELLO %d %d %63s", &kpm_api, &event_abi,
               version) != 3) {
        fprintf(stderr, "Incompatible KPM protocol response: %s\n", reply);
        return -1;
    }
    if (kpm_api < DL_RPC_API_VERSION ||
        event_abi != DL_EVENT_ABI_VERSION) {
        fprintf(stderr, "KPM component is too old; update required.\n");
        fprintf(stderr, "KPM组件版本过旧，需要更新KPM。\n");
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

static int show_events(void)
{
    int fd = open(EVENTS_PATH, O_RDONLY | O_CLOEXEC);
    struct dl_wire_event e;
    ssize_t n;
    if (fd < 0) {
        perror(EVENTS_PATH);
        return 1;
    }
    while ((n = read(fd, &e, sizeof(e))) == (ssize_t)sizeof(e)) {
        if (e.magic != DL_EVENT_MAGIC || e.version != DL_EVENT_ABI_VERSION)
            continue;
        {
            const char *ac = e.action == DL_WIRE_PASS ? C_GREEN :
                             e.action == DL_WIRE_SIMULATE ? C_YELLOW : C_RED;
            printf("%s#%-5u%s s=%-3u %-16s pid=%-6u ppid=%-6u dev=%u:%u "
                   "off=%llu len=%llu cmd=0x%x %s%-8s%s %s\n",
                   clr(C_DIM), e.sequence, clr(C_RESET), e.session_id,
                   event_name(e.type), e.pid, e.parent_pid, e.major, e.minor,
                   e.offset, e.length, e.command, clr(ac),
                   action_name(e.action), clr(C_RESET), e.name);
        }
    }
    close(fd);
    return n < 0 ? 1 : 0;
}

static void help(void)
{
    puts("Commands:");
    puts("  status                 show KPM state");
    puts("  active                 show active target/descendant count");
    puts("  profile auto|trace|expert");
    puts("  seal                   activate selected profile");
    puts("  stop                   authenticated stop/reset");
    puts("  events                 dump kernel event ring");
    puts("  clear                  clear event ring");
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
    printf("%s%sKPMDynaLab%s %sv0.6.4-test%s\n",
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
    if (login() < 0)
        return 1;

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

        if (!strcmp(cmd, "exit") || !strcmp(cmd, "quit"))
            break;
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
        } else if (!strcmp(cmd, "events")) {
            show_events();
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
