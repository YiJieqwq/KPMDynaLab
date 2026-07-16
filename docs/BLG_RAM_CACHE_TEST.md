# v0.8.3 BLG RAM Cache test

This milestone verifies the complete disk-pack → CLI → KPM vmalloc → CLI readback path. It contains no gesture handling, partition writes, slot changes, or reboot logic.

## Protocol

- RPC API: 6
- Event ABI: 2
- Cache limit: 256 MiB
- Binary endpoint: `/proc/dynalab/cache` (0600)

Commands:

```text
BLG CACHE BEGIN <bytes>
BLG CACHE COMMIT
BLG CACHE STATUS
BLG CACHE DROP
```

Only the authenticated CLI TGID can read or write the cache endpoint. Cache mutation is rejected while SEALED.

## Deduplication

The CLI scans Recovery Pack `.img` files in lexical order and deduplicates hard-linked A/B images by `(st_dev, st_ino)`. On the current Redmi K90 Pro Max pack, 28 logical images become 14 unique images and approximately 94 MiB of RAM.

## Verification

`blg cache load` performs:

1. disk SHA-256 verification using `manifest.sha256`;
2. KPM `vmalloc(total_unique_size)`;
3. sequential 1 MiB uploads;
4. cache commit only when exact byte count is present;
5. complete readback from KPM RAM;
6. byte-for-byte comparison with every unique source image.

The CLI reports total upload plus full readback verification time.

## Test

Deploy matching KPM and CLI, reconfigure SETVER, log in, then run:

```text
DynaLab> blg cache status
DynaLab> blg cache load
DynaLab> blg cache status
DynaLab> blg status
```

Expected final state:

```text
BLG RAM Cache: READY
Unique images: 14
RAM usage: approximately 98700000 bytes
OK CACHE READY
```

To release memory before SEALED:

```text
DynaLab> blg cache drop
```

Do not use this milestone as an emergency recovery implementation. The flat cache does not yet contain the future image-to-partition write-plan metadata.
