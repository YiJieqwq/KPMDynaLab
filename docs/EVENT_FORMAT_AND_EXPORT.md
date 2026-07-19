# CLI v0.8.10.2 event formatting and export

This CLI-only update is compatible with KPM v0.8.10, RPC API 12 and Event ABI 5.

## Type-aware formatting

Every record retains the common prefix:

```text
#sequence  UTC  monotonic  TYPE
```

Fields after TYPE are ordered by relevance:

- GESTURE: result, action, command, scope.
- block I/O: action, device, offset, length, process/session, ioctl command.
- process: action, PID, parent PID, session, scope, name.
- file: action, path, PID/session, offset/length.
- generic/system: action followed by common diagnostic fields.

ANSI colors are emitted only to a TTY. Exported files never contain color escapes.

## Export

```text
DynaLab> export
```

Writes the current authenticated kernel Event Ring to:

```text
/data/adb/dynalab/logs/dynalab-events-<UTC>-<pid>.log
```

Properties:

- directory mode 0700;
- file mode 0600;
- create-exclusive filename;
- UTC export metadata;
- text format version, RPC API and Event ABI header;
- full timestamps and type-aware event rendering;
- `fsync` before success is reported;
- no ANSI color sequences.

The current Event Ring capacity remains 256 records; export is a snapshot of records still resident in that ring, not an unlimited persistent recorder.
