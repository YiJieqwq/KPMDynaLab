# v0.8.14.1 contiguous file-write summaries

Filesystem write_iter coverage in v0.8.14 exposed the true F2FS call pattern: dd wrote the 64 KiB backing file as sixteen contiguous 4 KiB calls. Logging each call is accurate but noisy and can consume the ring quickly.

v0.8.14.1 aggregates consecutive writes when all are true:

- same tracked PID;
- same open `struct file`;
- next offset equals the prior end offset.

The aggregate is flushed when the process changes file, exits, the session is cleared, or an aggregation slot must be reused.

New event:

```text
FILE_WRITE_SUM  PASS  path=loop-backing.img  off=0  total=65536  calls=16  pid=...  session=1
```

This preserves total bytes, initial offset and syscall count while replacing sixteen repetitive records with one. Non-contiguous writes remain separate summaries. Raw block-write events are not aggregated because offsets and chunk boundaries are safety-critical for recovery and containment diagnostics.

RPC API 16 / Event ABI 7. License: GPL-2.0-only.
