# v0.8.4 BLG read-only cache test

This milestone hardens the existing KPM RAM cache without adding periodic work, gestures, image maps, partition writes, slot changes, or reboot logic.

## Changes

After an exact-length cache upload, KPM:

1. calculates SHA-256 over the complete cache;
2. stores the baseline digest;
3. calls `set_memory_ro` over every vmalloc page;
4. marks the cache READY/RO.

`BLG CACHE VERIFY` recalculates SHA-256 only on demand. There is no timer, worker or periodic scan.

Before DROP or KPM unload, KPM calls `set_memory_rw` and only then `vfree`.

## Protocol

- RPC API: 7
- Event ABI: 2

New command:

```text
BLG CACHE VERIFY
```

Expected states:

```text
OK CACHE EMPTY
OK CACHE LOADING
OK CACHE READY RO
OK CACHE INTACT
```

## Test

Deploy matching KPM and CLI, load the existing Recovery Pack, then run:

```text
DynaLab> blg cache load
DynaLab> blg cache status
DynaLab> blg cache verify
DynaLab> blg cache drop
DynaLab> blg cache status
```

Expected load completion:

```text
BLG RAM Cache: READY RO / SHA-256 INTACT
```

The most important reliability checks are:

1. no panic when approximately 97 MiB of vmalloc pages become read-only;
2. full CLI readback still succeeds from RO pages;
3. on-demand KPM SHA-256 returns INTACT;
4. DROP restores RW and releases memory safely;
5. KPM unload with a READY/RO cache does not panic.

If KPM load fails, collect the new helper bitmap from dmesg (`ro`, `rw`, `sha`).
