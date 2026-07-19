# v0.8.11 event device/process context

Block and reboot events now capture `current->comm` into the existing Event ABI name field at event time. This preserves the originating task name even if the PID exits before logs are viewed or exported.

CLI resolves block-device labels in userspace, never in the block hook:

1. `/sys/dev/block/<major>:<minor>/dm/name` for Device Mapper devices;
2. `PARTNAME=` from uevent for physical partitions;
3. `DEVNAME=` fallback;
4. `?` when unavailable.

Results are cached by dev_t for the CLI process lifetime.

Example:

```text
BLOCK_WRITE  PASS  dev=8:83(modemst1)  off=0  len=4194304  pid=3583  proc=rmt_storage  session=0  cmd=0x0
```

This adds no path lookup, sysfs access or allocation to the kernel block-write hook. RPC API 12 and Event ABI 5 remain compatible; only the previously optional name field gains context for block/system events.

License: GPL-2.0-only.
