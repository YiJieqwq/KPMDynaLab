# Async provenance bypass probe

This test-only probe evaluates whether CORDON's current PID/session attribution can be bypassed by asynchronous io_uring execution or by transferring a write to an untracked deputy process.

It never accepts a normal partition. Every write target is opened and verified with `fstat` as a block device whose major number is exactly 7 (loop). The test modifies only a disposable loop backing file under `/data/local/tmp`, which is deleted during cleanup.

## Important scope

The deputy test models the security property of a Binder confused-deputy attack, but uses a local Unix socket to remain deterministic and device-independent. It does not claim to exercise Android Binder itself. A future Binder-specific probe will require a dedicated registered Binder service and transaction instrumentation.

## Build

```text
make async-probe
```

Asset:

```text
build/dynalab-async-probe-arm64
```

## Deploy

```sh
adb push build/dynalab-async-probe-arm64 /data/local/tmp/
adb push scripts/async_probe_device.sh /data/local/tmp/
adb shell su -c 'chmod 755 /data/local/tmp/dynalab-async-probe-arm64 /data/local/tmp/async_probe_device.sh'
```

## Prepare disposable loop

Outside DynaLab:

```sh
su -c '/data/local/tmp/async_probe_device.sh prepare'
```

The helper prints a loop path such as `/dev/block/loop17`. Use only that printed path.

## Probe A: io_uring worker transfer

Inside DynaLab:

```text
run /data/local/tmp/dynalab-async-probe-arm64 io-uring /dev/block/loop17
```

The program reads the first 4 KiB, creates guaranteed-different bytes by XOR with `0xff`, submits one `IORING_OP_WRITE`, waits for completion, and reads back.

Possible outcomes:

### Unavailable

```text
SKIP io_uring_setup: Operation not permitted
```

Android policy or the kernel disabled io_uring. This does not prove CORDON coverage; the path was unavailable.

### Contained

```text
CONTAINED: completion returned, loop backing data unchanged
```

Expected event:

```text
BLOCK_WRITE SIMULATE ... session=<analysis> proc=<target or worker>
```

### Bypass observed

```text
BYPASS OBSERVED: io_uring worker changed disposable loop data
```

A likely event is:

```text
BLOCK_WRITE PASS ... session=0 proc=iou-wrk
```

or the write may be absent if it bypassed the current observation point. The disposable file is removed during cleanup.

## Probe B: untracked deputy

Outside DynaLab, after prepare:

```sh
su -c '/data/local/tmp/async_probe_device.sh start-deputy'
```

The one-shot root deputy is intentionally started outside ANALYZE and therefore remains session 0. It waits for a one-byte request, writes guaranteed-different bytes to the disposable loop, verifies the change, restores the original bytes, and exits.

Inside DynaLab:

```text
run /data/local/tmp/dynalab-async-probe-arm64 deputy-client /data/local/tmp/dynalab-async-probe.sock
```

With the current session-only policy, the expected finding is:

```text
BYPASS OBSERVED: untracked deputy performed the write and restored data
```

Events should show session-0 PASS block writes by the deputy. This demonstrates provenance laundering: the analyzed client caused the operation, but the final writer was outside its process lineage.

Inspect the server log:

```sh
su -c '/data/local/tmp/async_probe_device.sh show-deputy'
```

## Cleanup

Always finish with:

```sh
su -c '/data/local/tmp/async_probe_device.sh cleanup'
```

This detaches only the loop path recorded by the helper and removes the temporary image, socket, and log.

## Security interpretation

- Probe A tests actual io_uring behavior on the target kernel.
- Probe B proves or disproves process-deputy provenance laundering, the same policy weakness used by Binder confused-deputy designs.
- Neither probe writes any real partition.
- A bypass result is expected to be an ERROR exit from the probe so the DynaLab summary highlights it.
- BCG asset guards would still protect registered boot-chain devices even when session provenance is lost; the loop device is intentionally not a BCG asset.
