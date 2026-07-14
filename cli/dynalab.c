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
    if (lseek(fd, 0, SEEK_SET) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
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

static const char *event_name(unsigned int type)
{
    switch (type) {
    case DL_WIRE_BLOCK_WRITE: return "BLOCK_WRITE";
    case DL_WIRE_BLOCK_IOCTL: return "BLOCK_IOCTL";
    case DL_WIRE_BLOCK_FALLOCATE: return "BLOCK_FALLOCATE";
    case DL_WIRE_REBOOT: return "REBOOT";
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
        if (e.magic != DL_EVENT_MAGIC || e.version != DL_RPC_VERSION)
            continue;
        printf("#%-5u %-16s pid=%-6u dev=%u:%u off=%llu len=%llu cmd=0x%x %-8s\n",
               e.sequence, event_name(e.type), e.pid, e.major, e.minor,
               e.offset, e.length, e.command, action_name(e.action));
    }
    close(fd);
    return n < 0 ? 1 : 0;
}

static void help(void)
{
    puts("Commands:");
    puts("  status                 show KPM state");
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
    return 0;
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

    puts("KPMDynaLab CLI v0.4.0-test");
    if (rpc("STATUS", reply, sizeof(reply)) < 0) {
        fprintf(stderr, "KPMDynaLab is not available at %s\n", CONTROL_PATH);
        return 1;
    }
    printf("Kernel: %s\n", reply);
    if (login() < 0)
        return 1;

    while (1) {
        char *cmd, *arg;
        fputs("DynaLab> ", stdout);
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
            int n = 0, status;
            char *tok;
            if (send_and_print("SEAL"))
                continue;
            tok = strtok(arg, " \t");
            while (tok && n < 63) {
                run_argv[n++] = tok;
                tok = strtok(NULL, " \t");
            }
            run_argv[n] = NULL;
            if (!n)
                continue;
            pid = fork();
            if (pid == 0) {
                execvp(run_argv[0], run_argv);
                _exit(127);
            }
            if (pid < 0) {
                perror("fork");
                continue;
            }
            waitpid(pid, &status, 0);
            printf("Target exited: status=%d\n", status);
            show_events();
        } else {
            puts("Unknown command; type 'help'.");
        }
    }
    rpc("LOGOUT", reply, sizeof(reply));
    memset(line, 0, sizeof(line));
    return 0;
}
