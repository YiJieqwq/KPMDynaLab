# v0.8.9 BLG gesture arbitration test

This milestone eliminates prefix stacking while remaining observation-only. It performs no kill, flash, reboot or foreground-app action.

## Final events

```text
UUU       → CONSOLE_FINAL
DDD       → KILL_FINAL
UUUDDD    → CHECK_FINAL
UUUDDDU   → FORCE_FINAL
```

Only one final event is emitted for one accepted sequence.

## Arbitration

- `UUU` starts one 300 ms delayed decision. A following Down cancels Console and allows the longer sequence to continue.
- standalone `DDD` finalizes immediately.
- `UUUDDD` starts one 300 ms optional-Up window; it does not emit Kill.
- an Up inside that window atomically claims the pending decision and emits Force only.
- expiration atomically claims the same decision and emits Check only.
- any non-Up continuation finalizes Check, then starts a new sequence.

The pending state uses compare/exchange so the input callback and delayed work cannot both finalize the same decision. The delayed work exists only during a 300 ms arbitration window; there is no periodic worker.

## Test

Clear events before each sequence:

```text
DynaLab> clear
# press one sequence
DynaLab> event
```

`event` is now an alias of `events`.

Expected counts:

```text
UUU:      exactly one CONSOLE_FINAL
DDD:      exactly one KILL_FINAL
UUUDDD:   exactly one CHECK_FINAL
UUUDDDU:  exactly one FORCE_FINAL
```

Waiting more than 300 ms after `UUUDDD` before the final Up must produce CHECK_FINAL and must not produce FORCE_FINAL.

## Protocol

- RPC API: 11
- Event ABI: 4
- License: GPL-2.0-only
