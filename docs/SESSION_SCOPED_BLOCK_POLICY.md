# v0.8.13 session-scoped block policy

AUTO/EXPERT block simulation is now scoped to tracked analysis subjects instead of every process on the phone.

## Policy

```text
READY, ordinary device                    PASS
READY, EFISP                              SIMULATE
SEALED TRACE, ordinary device             PASS
SEALED AUTO/EXPERT, target/descendant      SIMULATE
SEALED AUTO/EXPERT, unrelated system task  PASS
Any state, EFISP                           SIMULATE
```

Tracked subjects are created by `run <program>` and inherited through the existing fork/exec lineage table. This protects samples and descendants such as shell, dd and extracted stages while allowing unrelated services such as `rmt_storage` and `MI_RIC` to continue required maintenance writes during an analysis session.

Global reboot suppression and EFISP Guard are unchanged.

## Test

1. In READY, an external loop-device dd must be PASS/session 0.
2. Run the smoke sample through `run`; its tracked loop/block write must be SIMULATE with a nonzero session.
3. While SEALED, an unrelated terminal loop-device dd must remain PASS/session 0.
4. EFISP remains SIMULATE regardless of subject/session; do not perform a destructive real-EFISP test.

RPC API is 14; Event ABI remains 6. Matching KPM and CLI are required. License: GPL-2.0-only.
