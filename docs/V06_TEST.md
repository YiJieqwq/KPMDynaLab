# v0.6 file-event and CLI test

v0.6 keeps the v0.5 process-session flow and adds target-lineage VFS observations.

## New file events

- `FILE_CREATE` from `vfs_create`
- `FILE_MKDIR` from `vfs_mkdir`
- `FILE_WRITE` from `vfs_write`
- `FILE_ATTR` from `notify_change`
- `FILE_UNLINK` from `vfs_unlink`
- `FILE_TRUNCATE` from `vfs_truncate`

Only tagged target/descendant processes generate these file events. Global block protection remains active for all processes while SEALED.

The first implementation records the dentry leaf name rather than reconstructing a full path in hook context. Session workdir cleanup remains path-safe because the CLI created and owns the complete dedicated directory path.

## CLI appearance

Interactive terminals now receive a compact colored banner, colored prompt, dim sequence numbers, and action colors:

- PASS: green
- SIMULATE: yellow
- SUPPRESS: red

Set `NO_COLOR=1` to disable ANSI output.

## Test

Deploy matching v0.6 KPM and CLI, reset the verifier, then run:

```text
DynaLab> profile auto
DynaLab> clear
DynaLab> run /data/local/tmp/device_smoke_sfx.sh
```

Expected additions include events resembling:

```text
FILE_MKDIR  dynalab-run-<pid>
FILE_CREATE .stage1.sh
FILE_WRITE  .stage1.sh
FILE_ATTR   .stage1.sh
FILE_CREATE .stage2.sh
FILE_WRITE  .stage2.sh
FILE_CREATE loop-backing.img
FILE_WRITE  loop-backing.img
FILE_CREATE payload.note
FILE_WRITE  payload.note
FILE_WRITE  loop17
BLOCK_WRITE loop17 SIMULATE
```

Exact event order depends on Android shell/toolbox implementation. Some tools may use open/create paths that converge differently, and buffered writes can be split into multiple FILE_WRITE records.

## Cleanup

When `ACTIVE 0`, CLI offers to remove only:

```text
/data/local/tmp/dynalab-run-<target-pid>
```

Files observed elsewhere are logged but are not automatically deleted yet. Full-path provenance and inode identity are required before external artifact cleanup can be considered safe.
