/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../include/dl_policy.h"

static struct dl_decision emit(struct dl_policy *p, enum dl_event_type type,
                               const char *comm, const char *path,
                               const char *dev, dl_u64 offset, dl_u64 length)
{
    struct dl_event e;
    struct dl_decision d;
    memset(&e, 0, sizeof(e));
    e.type = type;
    e.pid = 4103;
    e.tgid = 4103;
    e.in_target_lineage = 1;
    e.comm = comm;
    e.path = path;
    e.device = dev;
    e.offset = offset;
    e.length = length;
    d = dl_policy_decide(p, &e);
    printf("%-13s pid=%d comm=%-10s path=%-35s dev=%-6s "
           "off=%-8llu len=%-10llu => %-20s (%s)\n",
           dl_event_name(type), e.pid, comm ? comm : "-",
           path ? path : "-", dev ? dev : "-", offset, length,
           dl_action_name(d.action), d.reason);
    return d;
}

static void test_auto_flash_cleanup_chain(void)
{
    struct dl_policy p;
    struct dl_decision d;

    puts("\n=== AUTO: 闪存清理.sh multi-stage chain ===");
    dl_policy_init(&p);
    assert(dl_policy_configure(&p, DL_PROFILE_AUTO) == 0);
    assert(dl_policy_seal(&p) == 0);

    d = emit(&p, DL_EVENT_EXEC, "sh", "/sdcard/闪存清理.sh", 0, 0, 0);
    assert(d.action == DL_ACTION_PASS);
    d = emit(&p, DL_EVENT_FILE_CREATE, "base64", "/data/local/tmp/.stage1", 0, 0, 0);
    assert(d.action == DL_ACTION_PASS);
    d = emit(&p, DL_EVENT_FILE_WRITE, "base64", "/data/local/tmp/.stage1", 0, 0, 32768);
    assert(d.action == DL_ACTION_PASS);
    d = emit(&p, DL_EVENT_FILE_CHMOD_EXEC, "sh", "/data/local/tmp/.stage1", 0, 0, 0);
    assert(d.action == DL_ACTION_PASS);
    d = emit(&p, DL_EVENT_EXEC, ".stage1", "/data/local/tmp/.stage1", 0, 0, 0);
    assert(d.action == DL_ACTION_PASS);
    d = emit(&p, DL_EVENT_ENV_CHECK, "payload", "/proc/self/status", 0, 0, 0);
    assert(d.action == DL_ACTION_PASS);
    d = emit(&p, DL_EVENT_BLOCK_QUERY, "payload", 0, "sde10", 0, 0);
    assert(d.action == DL_ACTION_PASS);
    d = emit(&p, DL_EVENT_BLOCK_DANGEROUS_IOCTL, "payload", 0, "sde10", 0, 12884901888ULL);
    assert(d.action == DL_ACTION_SIMULATE && d.return_value == 0);
    d = emit(&p, DL_EVENT_BLOCK_WRITE, "payload", 0, "sde10", 0, 4096);
    assert(d.action == DL_ACTION_SIMULATE && d.return_value == 4096);
    d = emit(&p, DL_EVENT_REBOOT, "payload", 0, 0, 0, 0);
    assert(d.action == DL_ACTION_SUPPRESS_TERMINATE && d.terminal);

    /* Once sealed, malware cannot alter the profile. */
    assert(dl_policy_configure(&p, DL_PROFILE_TRACE) < 0);
}

static void test_trace(void)
{
    struct dl_policy p;
    struct dl_decision d;
    puts("\n=== TRACE: no interception ===");
    dl_policy_init(&p);
    assert(dl_policy_configure(&p, DL_PROFILE_TRACE) == 0);
    assert(dl_policy_seal(&p) == 0);
    d = emit(&p, DL_EVENT_BLOCK_DANGEROUS_IOCTL, "tester", 0, "sde10", 0, 4096);
    assert(d.action == DL_ACTION_PASS);
    d = emit(&p, DL_EVENT_REBOOT, "tester", 0, 0, 0, 0);
    assert(d.action == DL_ACTION_PASS);
}

static void test_expert_breakpoint(void)
{
    struct dl_policy p;
    struct dl_rule r;
    struct dl_decision d;
    puts("\n=== EXPERT: LBA breakpoint ===");
    dl_policy_init(&p);
    assert(dl_policy_configure(&p, DL_PROFILE_EXPERT) == 0);
    memset(&r, 0, sizeof(r));
    r.enabled = 1;
    r.event_type = DL_EVENT_BLOCK_WRITE;
    r.target_lineage_only = 1;
    strcpy(r.device, "sde10");
    r.offset_begin = 0;
    r.offset_end = 8191;
    r.action = DL_ACTION_BREAK;
    assert(dl_policy_add_rule(&p, &r) == 0);
    assert(dl_policy_seal(&p) == 0);
    d = emit(&p, DL_EVENT_BLOCK_WRITE, "payload", 0, "sde10", 4096, 512);
    assert(d.action == DL_ACTION_BREAK);
    d = emit(&p, DL_EVENT_BLOCK_WRITE, "payload", 0, "sde10", 16384, 512);
    assert(d.action == DL_ACTION_SIMULATE);
}

static void test_fail_closed(void)
{
    struct dl_policy p;
    struct dl_decision d;
    puts("\n=== READY: fail closed ===");
    dl_policy_init(&p);
    d = emit(&p, DL_EVENT_BLOCK_WRITE, "unknown", 0, "sde10", 0, 512);
    assert(d.action == DL_ACTION_DENY);
}

int main(void)
{
    test_auto_flash_cleanup_chain();
    test_trace();
    test_expert_breakpoint();
    test_fail_closed();
    puts("\nAll policy tests passed.");
    return 0;
}
