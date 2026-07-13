# Device test — Android 16 / 6.12.23 / 4 KiB pages

Artifact: `build/KPMDynaLab-0.3.1-test.kpm`

## Implemented in this test build

- KernelPatch inline hooks: `blkdev_write_iter`, `blkdev_ioctl`, `blkdev_fallocate`, `__arm64_sys_reboot`.
- AUTO/EXPERT: raw block writes, BLKZEROOUT, BLKDISCARD, BLKSECDISCARD and block fallocate are suppressed with plausible success.
- TRACE: operations pass through after logging.
- READY defaults fail-safe to simulation.
- `SEAL` freezes the selected profile; only authenticated manager CTL0 `RESET` leaves it.
- Logging uses `dmesg` only in this first device build.

Not yet implemented: process lineage, exec/file-drop tracing, procfs UI, password login, SG/BSG/UFS, shadow readback, expert breakpoints, reboot caller termination.

## Load

Runtime load from shell (syntax depends on your KernelPatch frontend):

```sh
kpatch kpm load /data/local/tmp/KPMDynaLab-0.3.1-test.kpm
```

Or select the file in APatch/FolkPatch/KPatch-Next.

Expected log:

```text
[dynalab] init ... default=AUTO state=READY
[dynalab] loaded: ctl0 TRACE|AUTO|EXPERT, then SEAL
```

If any required symbol is absent, init returns an error and removes already-installed hooks.

## Configure through Manager → KPM → Control

Send these as two separate control calls:

```text
AUTO
SEAL
```

Expected:

```text
[dynalab] configured profile=AUTO
[dynalab] SEALED profile=AUTO
```

Commands are uppercase in v0.3.

Other commands:

```text
TRACE       configure dangerous pass-through mode
EXPERT      currently AUTO-safe fallback
RESET       authenticated manager reset to READY/AUTO
```

## Safe smoke test

Do not start with a real partition. Push and run the loop-backed smoke test:

```sh
adb push scripts/device_smoke.sh /data/local/tmp/
adb shell su -c chmod 755 /data/local/tmp/device_smoke.sh
adb shell su -c /data/local/tmp/device_smoke.sh
```

Pass condition:

```text
[PASS] simulated success; backing data unchanged
```

Then inspect:

```sh
dmesg | grep dynalab | tail -30
```

Expected block event:

```text
[dynalab] BLOCK_WRITE ... len=4096 profile=AUTO action=SIMULATE
```

## Unload

```sh
kpatch kpm unload KPMDynaLab
```

Expected:

```text
[dynalab] unloaded
```

## Known risks

This is an ABI-targeted first test build, compiled using AOSP tag `android16-6.12-2025-06_r1` (Linux 6.12.23). Vendor changes may still alter code generation or symbol availability. It intentionally does not hide itself or resist an authenticated KernelPatch manager.
