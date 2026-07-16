# v0.8.2 EFISP Guard test

This milestone adds a narrowly scoped, always-on raw block guard for devices exposing `efisp`, `efisp_a`, or `efisp_b` under `/dev/block/by-name`.

## Behavior

KPM attempts to resolve an EFISP block device during load. If `/dev` is not ready at that point, the authenticated CLI registers it after login using its `dev_t`. The guard is independent of READY/CONFIGURED/SEALED analysis state.

For the registered device:

- `blkdev_write_iter` is simulated successfully;
- BLKZEROOUT, BLKDISCARD and BLKSECDISCARD are simulated successfully;
- block fallocate is simulated successfully;
- events use the existing BLOCK_WRITE/BLOCK_IOCTL/BLOCK_FALLOCATE records.

Other block devices retain the existing profile behavior: PASS outside SEALED and policy behavior while SEALED.

## Pack integration

The CLI v2 pack candidate list now includes:

```text
efisp efisp_a efisp_b
```

Existing packs are not automatically rebuilt. Run `blg pack create` explicitly if EFISP should be added to the disk baseline.

## Test procedure

Load the matching v0.8.2 KPM and CLI. After login, expect one of:

```text
EFISP Guard: OK EFISP ARMED (/dev/block/by-name/efisp)
EFISP Guard: NOT PRESENT ON THIS DEVICE
```

Do not perform destructive writes against a real EFISP partition in this milestone. Verify only:

1. the KPM loads without panic;
2. the CLI detects and arms the expected device;
3. `blg pack create` includes EFISP where present;
4. hashes remain stable during ordinary use.

## Current boundary

This build protects content writes through the existing block-device hook points. It does not yet protect GPT entries, offline Fastboot writes, direct BIO submission, SG/BSG paths, or a KPM-loading-time window where `/dev` is not available and the CLI has not registered the device.
