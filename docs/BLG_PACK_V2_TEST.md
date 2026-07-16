# BLG Recovery Pack v2 test

CLI v0.8.1 expands the extraction-only Recovery Pack candidate set for modern Qualcomm A/B devices. It still contains no partition-write, slot-switch, gesture, or kernel RAM-loader implementation.

## Added candidates

```text
tz_a/b hyp_a/b rpm_a/b
aop_a/b aop_config_a/b
keymaster_a/b
cmnlib_a/b cmnlib64_a/b
qupfw_a/b uefisecapp_a/b
imagefv_a/b shrm_a/b multiimgoem_a/b
```

Existing xbl, xbl_config, abl, devcfg and optional OCDT candidates remain. Only block devices that actually exist are read, and the 64 MiB per-partition cap remains.

## Early storage reduction

After extraction, each `_a`/`_b` pair is compared byte-for-byte. Identical pairs are replaced by hard links inside the pack directory. SHA-256 manifests still contain both logical image names, but identical pairs consume storage once on filesystems that support hard links.

This is not the final compressed container. Pack v3 will use a streaming compressed format with:

- per-image compressed chunks;
- per-chunk hashes;
- A/B content deduplication;
- bounded-memory decompression into the KPM RAM cache;
- no decompression during emergency flash.

Compression is deliberately kept out of the v2 extraction test so that the expanded device-specific image list and sizes can be reviewed first.

## Test

Replace the CLI, log in with KPM v0.7.0, then explicitly rebuild the existing v1 pack:

```text
DynaLab> blg pack create
DynaLab> blg pack verify
DynaLab> blg status
```

The previous pack is retained at:

```text
/data/adb/dynalab/blg-recovery-pack.old
```

Please report the extracted image list, logical size, `du -sh` size, and verification result. Do not upload the image files again unless requested.
