# v0.8.7 BLG loop-backed writer self-test

This milestone adds a recovery-writer rehearsal that is physically restricted to Linux loop block devices (`major == 7`). It cannot open or write UFS boot-chain partitions.

## Command

```text
blg selftest
```

The CLI automatically:

1. ensures Pack, RO Cache and Image Map are ready;
2. creates `/data/local/tmp/dynalab-blg-selftest.img` sized for the unique cache stream;
3. attaches a free loop device;
4. asks KPM to run an injected-corruption self-test;
5. detaches the loop device and removes the backing image.

## KPM pipeline

```text
RO Cache → loop block device
fsync
inject one 4 KiB corruption near the middle
full 1 MiB-chunk readback
rewrite each mismatching chunk from RO Cache
fsync if repaired
second full readback verification
```

Success is:

```text
OK SELFTEST REPAIRED
```

The CLI reports total write + flush + detect + repair + final-verify time.

## Safety gates

KPM refuses the request unless:

- Cache is READY/RO;
- Image Map is ready;
- state is not SEALED;
- path is absolute;
- opened target is a block device;
- target major is exactly 7 (loop);
- target size is at least the concatenated mapped-image size.

No slot metadata, reboot state, EFISP, XBL, ABL or other real partition is changed.

## Protocol

- RPC API: 9
- Event ABI: 2

Matching KPM and versioned CLI are required.
