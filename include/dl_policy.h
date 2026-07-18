/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KPM_DYNALAB_POLICY_H
#define KPM_DYNALAB_POLICY_H

/* Portable policy core: no Linux headers, shared by KPM adapter and tests. */

typedef unsigned long long dl_u64;

enum dl_profile {
    DL_PROFILE_TRACE = 1,
    DL_PROFILE_AUTO = 2,
    DL_PROFILE_EXPERT = 3,
};

enum dl_run_state {
    DL_STATE_UNINITIALIZED = 0,
    DL_STATE_READY,
    DL_STATE_CONFIGURED,
    DL_STATE_SEALED,
    DL_STATE_FINISHED,
};

enum dl_event_type {
    DL_EVENT_NONE = 0,
    DL_EVENT_EXEC,
    DL_EVENT_FILE_CREATE,
    DL_EVENT_FILE_WRITE,
    DL_EVENT_FILE_CHMOD_EXEC,
    DL_EVENT_ENV_CHECK,
    DL_EVENT_BLOCK_OPEN,
    DL_EVENT_BLOCK_QUERY,
    DL_EVENT_BLOCK_READ,
    DL_EVENT_BLOCK_WRITE,
    DL_EVENT_BLOCK_DANGEROUS_IOCTL,
    DL_EVENT_SG_DANGEROUS_CMD,
    DL_EVENT_REBOOT,
};

enum dl_action {
    DL_ACTION_PASS = 0,
    DL_ACTION_SIMULATE,
    DL_ACTION_DENY,
    DL_ACTION_BREAK,
    DL_ACTION_SUPPRESS_TERMINATE,
};

#define DL_RULE_ANY_EVENT 0
#define DL_RULE_ANY_U64 (~(dl_u64)0)
#define DL_MAX_RULES 64

struct dl_event {
    enum dl_event_type type;
    int pid;
    int tgid;
    int in_target_lineage;
    const char *comm;
    const char *path;
    const char *device;
    dl_u64 offset;
    dl_u64 length;
    unsigned int command;
};

struct dl_decision {
    enum dl_action action;
    long return_value;
    unsigned int delay_ms;
    int terminal;
    const char *reason;
};

struct dl_rule {
    int enabled;
    enum dl_event_type event_type;
    int target_lineage_only;
    char device[32];
    dl_u64 offset_begin;
    dl_u64 offset_end;
    enum dl_action action;
    long return_value;
    unsigned int delay_ms;
};

struct dl_policy {
    enum dl_profile profile;
    enum dl_run_state state;
    unsigned int generation;
    unsigned int rule_count;
    struct dl_rule rules[DL_MAX_RULES];
};

void dl_policy_init(struct dl_policy *policy);
int dl_policy_configure(struct dl_policy *policy, enum dl_profile profile);
int dl_policy_seal(struct dl_policy *policy);
int dl_policy_reset(struct dl_policy *policy);
int dl_policy_add_rule(struct dl_policy *policy, const struct dl_rule *rule);
struct dl_decision dl_policy_decide(const struct dl_policy *policy,
                                    const struct dl_event *event);

const char *dl_profile_name(enum dl_profile profile);
const char *dl_event_name(enum dl_event_type event);
const char *dl_action_name(enum dl_action action);

#endif
