# BLG v0.8.0 Recovery Pack milestone

This milestone implements only device-local Recovery Pack extraction and SHA-256 verification in the CLI. It does **not** load images into kernel RAM, observe hardware gestures, or write any partition.

Use it with KPMDynaLab KPM v0.7.0 (RPC API 4 / Event ABI 2).

## First login

If no pack exists, CLI prompts:

```text
Boot Lifeguard is not configured.
A device-local Recovery Pack is required for future emergency recovery.
Create Recovery Pack now? [Y/n]
```

The fixed development path is:

```text
/data/adb/dynalab/blg-recovery-pack
```

## Included candidates

Only existing block devices from this bounded list are extracted:

```text
xbl_a xbl_b
xbl_config_a xbl_config_b
abl_a abl_b
devcfg_a devcfg_b
ocdt ocdt_a ocdt_b
```

Each candidate must be no larger than 64 MiB. PBL is never included. A later inventory milestone will derive the complete device-specific set from GPT rather than relying on this candidate list.

## Layout

```text
blg-recovery-pack/
  device.txt
  manifest.sha256
  images/*.img
```

The CLI writes a temporary sibling directory, extracts images, calculates SHA-256, verifies every image, syncs storage, then replaces the prior pack while retaining it as `blg-recovery-pack.old`.

## Commands

```text
blg status
blg pack create
blg pack verify
```

## Safety boundary

This release is extraction-only. It contains no raw partition write implementation and cannot perform UUUDDD/UUUDDDU recovery. Review the generated image list, sizes, and hashes before the RAM-loader milestone is enabled.
