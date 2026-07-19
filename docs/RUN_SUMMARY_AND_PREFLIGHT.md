# v0.8.16 run summary and target preflight

## Post-run summary

After printing events newer than the run-start sequence, CLI prints a colored operation summary:

```text
Summary  operations=76  records=61  PASS=75  SIMULATE=1  SUPPRESS=0
```

`records` is the number of Event ABI records printed. `operations` expands `FILE_WRITE_SUM.calls`; every other event has weight one. PASS is green, SIMULATE yellow and SUPPRESS red on a TTY.

## Target preflight

Before creating the gated child, registering TARGET or entering SEALED, CLI verifies the command:

- paths containing `/`: must exist, be a regular file and be executable;
- PATH commands: must resolve to an executable regular file.

A missing target now returns immediately:

```text
Target preflight failed: /path/missing: No such file or directory
```

No target, seal, EXEC or EXIT event is created in this ordinary case. A time-of-check/time-of-use race can still make a previously valid target disappear after preflight; that runtime failure is retained as a target EXIT.

## EXEC semantics

KPM now emits EXEC only after `do_execveat_common` returns success. The before hook stores the requested path in the tracked subject; the after hook emits on return value zero and drops the pending path on error. Failed exec attempts therefore no longer masquerade as successful EXEC events.

RPC API 18 / Event ABI 7. License: GPL-2.0-only.
