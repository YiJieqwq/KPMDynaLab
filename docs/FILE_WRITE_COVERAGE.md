# v0.8.14 file-write coverage

This milestone broadens regular-file write observation for tracked sessions while avoiding the previously unstable unlink hook.

## Filesystem write_iter hooks

KPM optionally hooks filesystem-level write_iter entry points when present:

```text
f2fs_file_write_iter
ext4_file_write_iter
```

Both receive `kiocb` and `iov_iter`, allowing KPM to record file, starting offset and requested byte count for buffered, direct and vectored paths entering those filesystems. If neither symbol exists, KPM falls back to the prior `vfs_write` hook.

This replaces, rather than stacks with, `vfs_write` on F2FS/EXT4 systems, preventing duplicate FILE_WRITE records for the same write.

## Ring capacity

Event Ring capacity increases from 256 to 1024 records. At the current ABI record size this remains a small fixed kernel allocation while allowing multi-stage samples substantially more timeline depth before wraparound.

## Expected smoke-test improvement

The prior sample created `loop-backing.img` through dd but often lacked FILE_WRITE records. v0.8.14 should record writes to that regular backing image in addition to stage scripts and payload.note.

RPC API 15 / Event ABI 6. Matching components required. License: GPL-2.0-only.
