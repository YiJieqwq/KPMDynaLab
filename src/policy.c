/* SPDX-License-Identifier: GPL-2.0-only */
#include "../include/dl_policy.h"

static int dl_streq(const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

static void dl_copy_string(char *dst, const char *src, unsigned int size)
{
    unsigned int i = 0;
    if (!size)
        return;
    if (src) {
        for (; i + 1 < size && src[i]; ++i)
            dst[i] = src[i];
    }
    dst[i] = '\0';
}

static int dl_event_is_dangerous(enum dl_event_type type)
{
    return type == DL_EVENT_BLOCK_WRITE ||
           type == DL_EVENT_BLOCK_DANGEROUS_IOCTL ||
           type == DL_EVENT_SG_DANGEROUS_CMD;
}

static int dl_rule_matches(const struct dl_rule *rule,
                           const struct dl_event *event)
{
    if (!rule->enabled)
        return 0;
    if (rule->event_type != DL_RULE_ANY_EVENT &&
        rule->event_type != event->type)
        return 0;
    if (rule->target_lineage_only && !event->in_target_lineage)
        return 0;
    if (rule->device[0] && !dl_streq(rule->device, event->device))
        return 0;
    if (rule->offset_begin != DL_RULE_ANY_U64 &&
        event->offset < rule->offset_begin)
        return 0;
    if (rule->offset_end != DL_RULE_ANY_U64 &&
        event->offset > rule->offset_end)
        return 0;
    return 1;
}

static struct dl_decision dl_make_decision(enum dl_action action,
                                            long return_value,
                                            unsigned int delay_ms,
                                            int terminal,
                                            const char *reason)
{
    struct dl_decision d;
    d.action = action;
    d.return_value = return_value;
    d.delay_ms = delay_ms;
    d.terminal = terminal;
    d.reason = reason;
    return d;
}

void dl_policy_init(struct dl_policy *policy)
{
    unsigned int i;
    policy->profile = DL_PROFILE_AUTO;
    policy->state = DL_STATE_READY;
    policy->generation = 1;
    policy->rule_count = 0;
    for (i = 0; i < DL_MAX_RULES; ++i)
        policy->rules[i].enabled = 0;
}

int dl_policy_configure(struct dl_policy *policy, enum dl_profile profile)
{
    if (policy->state == DL_STATE_SEALED)
        return -1;
    if (profile < DL_PROFILE_TRACE || profile > DL_PROFILE_EXPERT)
        return -2;
    policy->profile = profile;
    policy->state = DL_STATE_CONFIGURED;
    ++policy->generation;
    return 0;
}

int dl_policy_seal(struct dl_policy *policy)
{
    if (policy->state != DL_STATE_CONFIGURED)
        return -1;
    policy->state = DL_STATE_SEALED;
    ++policy->generation;
    return 0;
}

int dl_policy_reset(struct dl_policy *policy)
{
    unsigned int i;
    policy->profile = DL_PROFILE_AUTO;
    policy->state = DL_STATE_READY;
    policy->rule_count = 0;
    for (i = 0; i < DL_MAX_RULES; ++i)
        policy->rules[i].enabled = 0;
    ++policy->generation;
    return 0;
}

int dl_policy_add_rule(struct dl_policy *policy, const struct dl_rule *input)
{
    struct dl_rule *rule;
    if (policy->state == DL_STATE_SEALED)
        return -1;
    if (policy->profile != DL_PROFILE_EXPERT)
        return -2;
    if (policy->rule_count >= DL_MAX_RULES)
        return -3;

    rule = &policy->rules[policy->rule_count++];
    *rule = *input;
    dl_copy_string(rule->device, input->device, sizeof(rule->device));
    rule->enabled = 1;
    ++policy->generation;
    return 0;
}

struct dl_decision dl_policy_decide(const struct dl_policy *policy,
                                    const struct dl_event *event)
{
    unsigned int i;

    /* Fail closed before a run is explicitly configured and sealed. */
    if (policy->state != DL_STATE_SEALED) {
        if (dl_event_is_dangerous(event->type))
            return dl_make_decision(DL_ACTION_DENY, -1, 0, 0,
                                    "policy is not sealed");
        if (event->type == DL_EVENT_REBOOT)
            return dl_make_decision(DL_ACTION_SUPPRESS_TERMINATE, 0, 0, 1,
                                    "reboot suppressed outside session");
        return dl_make_decision(DL_ACTION_PASS, 0, 0, 0,
                                "non-dangerous event outside session");
    }

    if (policy->profile == DL_PROFILE_TRACE)
        return dl_make_decision(DL_ACTION_PASS, 0, 0, 0,
                                "TRACE records without interception");

    if (policy->profile == DL_PROFILE_EXPERT) {
        for (i = 0; i < policy->rule_count; ++i) {
            if (dl_rule_matches(&policy->rules[i], event)) {
                const struct dl_rule *rule = &policy->rules[i];
                return dl_make_decision(rule->action,
                                        rule->return_value,
                                        rule->delay_ms,
                                        rule->action == DL_ACTION_SUPPRESS_TERMINATE,
                                        "EXPERT rule matched");
            }
        }
        /* Expert defaults remain safe when no explicit rule matches. */
    }

    if (event->type == DL_EVENT_REBOOT)
        return dl_make_decision(DL_ACTION_SUPPRESS_TERMINATE, 0, 0, 1,
                                "terminal reboot behavior");

    if (dl_event_is_dangerous(event->type)) {
        long simulated = 0;
        if (event->type == DL_EVENT_BLOCK_WRITE)
            simulated = (long)event->length;
        return dl_make_decision(DL_ACTION_SIMULATE, simulated, 0, 0,
                                "dangerous storage operation");
    }

    return dl_make_decision(DL_ACTION_PASS, 0, 0, 0,
                            "ordinary behavior");
}

const char *dl_profile_name(enum dl_profile profile)
{
    switch (profile) {
    case DL_PROFILE_TRACE: return "TRACE";
    case DL_PROFILE_AUTO: return "AUTO";
    case DL_PROFILE_EXPERT: return "EXPERT";
    default: return "UNKNOWN";
    }
}

const char *dl_event_name(enum dl_event_type event)
{
    switch (event) {
    case DL_EVENT_EXEC: return "EXEC";
    case DL_EVENT_FILE_CREATE: return "FILE_CREATE";
    case DL_EVENT_FILE_WRITE: return "FILE_WRITE";
    case DL_EVENT_FILE_CHMOD_EXEC: return "CHMOD_EXEC";
    case DL_EVENT_ENV_CHECK: return "ENV_CHECK";
    case DL_EVENT_BLOCK_OPEN: return "BLOCK_OPEN";
    case DL_EVENT_BLOCK_QUERY: return "BLOCK_QUERY";
    case DL_EVENT_BLOCK_READ: return "BLOCK_READ";
    case DL_EVENT_BLOCK_WRITE: return "BLOCK_WRITE";
    case DL_EVENT_BLOCK_DANGEROUS_IOCTL: return "BLOCK_IOCTL";
    case DL_EVENT_SG_DANGEROUS_CMD: return "SG_COMMAND";
    case DL_EVENT_REBOOT: return "REBOOT";
    default: return "UNKNOWN";
    }
}

const char *dl_action_name(enum dl_action action)
{
    switch (action) {
    case DL_ACTION_PASS: return "PASS";
    case DL_ACTION_SIMULATE: return "SIMULATE";
    case DL_ACTION_DENY: return "DENY";
    case DL_ACTION_BREAK: return "BREAK";
    case DL_ACTION_SUPPRESS_TERMINATE: return "SUPPRESS+TERMINATE";
    default: return "UNKNOWN";
    }
}
