# v0.8.5 BLG Image Map test

This milestone turns the verified flat RO cache into a validated, no-write recovery plan. It does not contain a partition writer.

## Protocol

- RPC API: 8
- Event ABI: 2
- Maximum map entries: 64

Commands:

```text
BLG MAP BEGIN
BLG MAP ADD <name> <cache_offset> <image_size> <major> <minor> <target_size> <flags> <tier>
BLG MAP COMMIT
BLG MAP VERIFY
BLG MAP STATUS
BLG MAP DROP
```

## CLI behavior

After `blg cache load` completes RO and SHA-256 verification, CLI:

1. determines the active slot from bootconfig/cmdline;
2. uses only the active-slot copy as the canonical source when A/B files differ;
3. maps it to the inactive-slot block device;
4. maps shared EFISP back to itself;
5. records cache offsets based on the exact flat-cache upload order;
6. obtains each target `dev_t` and size;
7. submits and commits the map;
8. verifies the KPM map digest.

## KPM validation

KPM rejects a plan if:

- cache is not READY/RO;
- an image range is empty, overflows, or exceeds the cache;
- a target is missing;
- image size exceeds target size;
- two entries resolve to the same target device;
- entry count exceeds 64.

Success state:

```text
OK PLAN READY NO WRITE
```

The wording is intentional: no code in this milestone writes a target partition.

## Test

Deploy matching KPM/CLI, load the existing pack, then run:

```text
DynaLab> blg cache load
DynaLab> blg map status
DynaLab> blg map verify
DynaLab> blg status
```

Expected on the current `_a` device:

```text
BLG Image Map: PLAN READY NO WRITE (15 targets, active slot _a)
OK PLAN READY NO WRITE
OK MAP INTACT
```

`blg cache drop` also clears the map. `blg map drop` clears only the plan before SEALED.
