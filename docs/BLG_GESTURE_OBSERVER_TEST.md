# v0.8.8 BLG gesture observer test

This milestone observes volume-key press events through an inline hook on `input_event`. It records matches only; it performs no kill, flash, reboot, foreground-app action, or policy change.

## Recognized observer events

```text
Volume Up x3 within 900 ms       CONSOLE_UUU
Volume Down x3 within 900 ms     KILL_DDD
UUUDDD within 3 seconds          CHECK_UUUDDD
UUUDDDU within 3 seconds         FORCE_UUUDDDU
```

A gap greater than one second resets the rolling sequence. Press events (`EV_KEY`, value 1) are considered; release and autorepeat events are ignored.

Because this is an observer milestone, a long sequence can report its prefixes too. For example `UUUDDDU` may record `CONSOLE_UUU`, `KILL_DDD`, `CHECK_UUUDDD`, then `FORCE_UUUDDDU`. Action arbitration and the optional-U suffix window are deliberately deferred until observation is validated.

## Event ABI

- RPC API: 10
- Event ABI: 3
- New event type: `GESTURE`

Use:

```text
DynaLab> clear
# press a test sequence
DynaLab> events
```

Expected records contain names such as:

```text
GESTURE ... name=CHECK_UUUDDD cmd=3
GESTURE ... name=FORCE_UUUDDDU cmd=4
```

## Safety

The hook never sets `skip_origin`; all volume keys continue to reach Android normally. No delayed worker, timer, periodic scan, or userspace daemon is added.
