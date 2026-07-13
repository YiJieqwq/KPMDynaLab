# Analysis Profiles (v0.2 prototype)

KPMDynaLab separates a top-level analysis profile from the action applied to an individual event.

## Profiles

| Profile | Purpose | Default action for dangerous storage | Reboot |
|---|---|---|---|
| TRACE | Confirmed-safe software or sacrificial test device | PASS | PASS |
| AUTO | Malware triage and simple behavior analysis | SIMULATE | SUPPRESS + terminate session |
| EXPERT | Dynamic reverse engineering | First matching rule; otherwise AUTO-safe fallback | Rule or safe fallback |

## Actions

- `PASS`: record and execute the original operation.
- `SIMULATE`: suppress the original operation and return a plausible success result.
- `DENY`: suppress and return an error.
- `BREAK`: pause at a sleepable hook point and ask the controller.
- `SUPPRESS_TERMINATE`: suppress terminal behavior such as reboot and end the target lineage.

## AUTO example

```text
闪存清理.sh                         PASS + log
  ├─ creates /data/local/tmp/.stage1 PASS + log
  ├─ chmod +x .stage1                PASS + log
  └─ exec .stage1                    PASS + log
       ├─ environment checks         PASS real data + log
       ├─ BLKGETSIZE64               PASS real data + log
       ├─ BLKZEROOUT                 SIMULATE success + log
       ├─ block write                SIMULATE byte count + log
       └─ reboot                     SUPPRESS + terminate lineage
```

The parent shell may exit at any point. Monitoring belongs to the analysis session and follows descendants rather than depending only on the original PID/PPID.

## Sealing

A profile is configured before launching the sample and then sealed. Once sealed:

- profile changes are rejected;
- expert rules cannot be added or removed;
- killing the CLI does not disable interception;
- only an authenticated manager `KPM_CTL0` reset may return to READY;
- failures default to deny/simulate, never to real write.

## Current prototype scope

`src/policy.c` is a portable and tested policy engine. It currently models:

- TRACE/AUTO/EXPERT;
- READY/CONFIGURED/SEALED state transitions;
- dangerous block write and ioctl simulation;
- reboot suppression as terminal behavior;
- expert event/device/offset rules;
- fail-closed behavior outside a sealed session.

The target-specific KPM adapter is intentionally build-gated until matching device kernel headers are supplied. The signatures and layouts of `blkdev_open`, `blkdev_write_iter`, `struct block_device`, and related types vary across Android kernels; guessing those layouts in a kernel module is not acceptable.

Run the prototype:

```bash
make test
```
