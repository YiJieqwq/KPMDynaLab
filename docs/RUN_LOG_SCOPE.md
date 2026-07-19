# CLI v0.8.13.1 run-log scope

Before `run <program>` creates and releases the target, CLI snapshots the latest Event Ring sequence number. After the target exits, automatic display includes only records whose sequence is greater than that snapshot.

This removes older KPM_LOAD, CLI_LOGIN, gesture and unrelated system records from the automatic post-run report without deleting them from the kernel ring.

Manual commands remain unchanged:

```text
event / events   show all resident records
export           export all resident records
```

Therefore analysts retain full context when requested, while the default `run` output is focused on the just-completed execution. Filtering uses the monotonic event sequence, not timestamp comparisons, so clock changes do not affect selection.

Compatible with KPM v0.8.13, RPC API 14 and Event ABI 6. License: GPL-2.0-only.
