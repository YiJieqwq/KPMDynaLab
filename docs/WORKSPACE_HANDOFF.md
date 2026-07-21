# KPMDynaLab workspace handoff

## Repository

```text
https://github.com/YiJieqwq/KPMDynaLab.git
branch: main
```

No credentials are stored in this document.

## Latest tested component set

```text
KPM:       0.8.17-error-input-test
CLI:       0.8.17.1-auto-unseal-test
RPC API:   19
Event ABI: 8
License:   GPL-2.0-only
```

KPM SHA-256:

```text
47f6907ee4705a86570945b0095e8132b2f3ecdc47de3a18010e81d33b12cf4a
```

CLI v0.8.17.1 SHA-256:

```text
47984b592fdb65a29e2f7c7d24d8edb8978bac2aea813b8b614c5b420d251455
```

Latest test probe:

```text
dynalab-async-probe-0.1.0-arm64
SHA-256: f3c1253b69c237c74aa21ae0f9c41dfac3eb31fff0da105a8fb62bf926abf2de
```

## Automated bootstrap

On a fresh Ubuntu/Debian-like workspace, use:

```sh
git clone https://github.com/YiJieqwq/KPMDynaLab.git /workspace/KPMDynaLab
bash /workspace/KPMDynaLab/scripts/bootstrap_workspace.sh /workspace
```

The script installs the cross-build dependencies, clones the pinned kernel tag, prepares GKI arm64 headers, and builds policy tests, CLI, async probe and KPM.

Pinned kernel source:

```text
repository: https://android.googlesource.com/kernel/common
tag:        android16-6.12-2025-06_r1
commit:     2d954fcf3d1b73a41d0fa498324da357ec96cbdf
```

After migration, verify with:

```sh
bash /workspace/KPMDynaLab/scripts/verify_dev_environment.sh \
  /workspace/KPMDynaLab /workspace/android16-6.12
```

## Build environment used

```text
Target: Android flagship / OnePlus-derived environment
Kernel headers: Android 16, Linux 6.12.23 GKI
Page size: 4 KiB
Architecture: arm64
Cross compiler: aarch64-linux-gnu-gcc
KPM loader ecosystem: KernelPatch / KPatch-Next; AP/FP target deployment
```

Previous workspace kernel source path:

```text
/workspace/android16-6.12
```

Build commands:

```sh
make test
make cli
make async-probe
make kpm KDIR=/path/to/android16-6.12
```

## Product mission

KPMDynaLab has two product pillars:

1. kernel-assisted dynamic analysis;
2. enough safety for engineers to analyze targeted attacks on expensive, current flagship devices instead of obsolete hardware or emulator environments that may fail environmental checks.

Positioning:

```text
Faithful enough to trigger.
Safe enough to survive.
Observable enough to explain.
```

## Final architecture direction

### BCG — Boot Chain Guard

Always-on, low-overhead, low-interference safety floor. BCG should protect a finite registry of survival-critical assets and provide live-kernel recovery opportunity. It should prioritize daily-use safety and avoid broad white-list complexity.

Planned assets:

- EFISP;
- XBL / XBL config;
- ABL;
- TZ / HYP;
- AOP/RPM-style firmware;
- Keymaster-related firmware;
- Image FV, UEFI-related firmware, SHRM and device-specific boot firmware;
- persist raw-block destruction paths;
- recovery pack, RO RAM cache and image map.

BCG should use explicit authenticated maintenance for OTA rather than trying to infer every legitimate updater.

### CORDON

Short-lived, heavyweight, fail-closed analysis containment. Misblocking and higher overhead are acceptable during a bounded analysis window. Do not attempt to build a complete system-service whitelist with the current team size.

Preferred direction:

- deny writable block-device opens globally while active;
- deny all block-device opens for the target in strict mode;
- deny shared writable block mappings;
- freeze module/KPM loading;
- suppress reboot, SysRq crash and dangerous sync paths;
- later add network/Binder/confidentiality controls;
- enforce TTL and automatic lift after all tracked processes exit.

### ANALYZE

Creates controlled targets and supplies CORDON with target identity, session ID, descendants, attribution, event window, summary and lifecycle. Current user command is `run`; future canonical name should be `analyze`, retaining `run` as a temporary alias.

## Simplified security philosophy

```text
BCG:
  daily-use-safe, always on, narrowly scoped, deterministic.

CORDON:
  short-lived, heavyweight, fail-closed, allowed to misblock.

ANALYZE:
  target identity, lineage, attribution and lifecycle.
```

Do not enumerate an infinite set of attacks. Maintain finite invariants and guard security chokepoints.

## Current implemented capabilities

- authenticated CLI login via verifier;
- API/Event ABI compatibility handshake;
- BCG/BLG recovery-pack creation and verification;
- deduplicated A/B recovery images;
- RO vmalloc recovery cache with SHA-256;
- image map;
- loop-backed writer self-test with corruption injection, detection and repair;
- EFISP direct block write/ioctl/fallocate guard;
- gesture observer and non-stacking arbitration;
- target registration and fork/exec/exit lineage;
- session-scoped block simulation;
- `current->comm` through live-kernel `__get_task_comm`;
- block device labels;
- UTC and monotonic timestamps;
- event export;
- 1024-event ring;
- F2FS/EXT4 write_iter coverage;
- contiguous FILE_WRITE_SUM aggregation;
- lifecycle events: KPM load, CLI login/logout;
- run-scoped automatic event output;
- colored operation summary with PASS/SIMULATE/SUPPRESS/ERROR;
- target path preflight;
- success-only EXEC records;
- EXIT error code/signal classification;
- interactive stdin/stdout/stderr inheritance;
- contextual SEALED errors;
- automatic unseal when ACTIVE reaches zero.

## Confirmed tests

- external loop write in READY: PASS, session 0, proc=dd;
- tracked smoke-sample loop write: SIMULATE, nonzero session, backing hash unchanged;
- process lineage across multi-stage shell extraction;
- FILE_WRITE_SUM for 64 KiB loop backing: total=65536, calls=16;
- failed shell command: EXEC PASS for interpreter, EXIT ERROR code=127;
- interactive target input works;
- event clear denied while SEALED with unseal hint;
- automatic unseal works after all tracked processes exit;
- BLG writer self-test reports OK SELFTEST REPAIRED;
- BLG internal I/O event noise filtered.

## Important known gaps

### Writable block-device mmap / writeback

Linux 6.12 `blkdev_mmap` permits `generic_file_mmap` on writable block devices. A shared writable mapping may dirty pages and later write them through sync/writeback/BIO without entering `blkdev_write_iter` in the original target context.

Current EFISP and block guards do not fully cover this. This is a confirmed architectural gap.

Priority mitigation:

1. global BCG denial of `MAP_SHARED + PROT_WRITE` for guarded devices;
2. CORDON denial of writable block mappings;
3. later, carefully tested BIO-level final guard for BCG devices.

### Binder / deputy provenance laundering

A target may ask a session-0 service to perform work. Current PID-based attribution may PASS the service's operation. BCG asset guards can still protect boot-chain targets, but ordinary file/data operations require Binder transaction provenance or a deliberately fail-closed CORDON policy.

### io_uring worker transfer

An io_uring request may execute in `iou-wrk` or another context and lose target session attribution. A safe major=7-only probe is implemented and released; device results are pending.

### Kernel extension / arbitrary EL1

CORDON should block known module/KPM loading paths before the target gains EL1. It cannot provide absolute containment against arbitrary pre-existing EL1 code execution without EL2/Secure World or another higher trust anchor.

### Confidentiality

Network, Binder, sensitive App Data source tracking and exfiltration sinks remain future work.

### Real recovery gestures

Gesture arbitration is implemented, but final recovery/kill/console actions remain event-only. Image Map remains PLAN READY NO WRITE.

## Threat model

Primary document:

```text
docs/THREAT_MODEL.md
```

Expanded classes:

```text
T1 direct user-space destruction
T2 async/indirect/confused-deputy I/O
T3 controlled kernel-extension entry
T4 arbitrary EL1 execution
T5 EL2/TEE/RPMB/hardware

C1 sensitive source reads
C2 exfiltration sinks
C3 high-privilege confidentiality loss
```

## Recommended next implementation order

1. migrate public CLI vocabulary to `bcg`, `cordon`, `analyze` while keeping aliases;
2. add BCG guard registry and status inventory in monitor-only mode;
3. add major=7 loop test for writable block mmap detection/denial;
4. enforce global writable-mmap denial on BCG assets;
5. add CORDON global writable block-open/mmap restrictions;
6. add CORDON TTL and clearer automatic-lift message;
7. add module/KPM load observation and freeze;
8. add SysRq/emergency_sync/panic/reboot-path coverage;
9. only after extensive loop testing, consider BIO-level BCG guard;
10. later add Binder/io_uring provenance and confidentiality controls.

## AI expert-mode direction

Do not add AI before deterministic v1 foundations stabilize. Future AI should be advisory and bounded:

```text
kernel data plane: deterministic
CLI policy plane: constrained
AI analysis plane: recommendations and correlation
human operator: final authority for critical changes
```

AI must never autonomously disable BCG, enter maintenance, permit boot-chain writes, load unknown KPMs, clear evidence, or override TRUST DEGRADED.

## Recent commits

```text
036ea76 test: add safe async provenance bypass probes
1d3eb0e cli v0.8.17.1: auto-unseal completed run sessions
9b88a19 v0.8.17: classify failed exits and clarify interactive runs
07ee4d6 v0.8.16: add run summaries and target preflight
91243c1 v0.8.15: clarify CLI command semantics
632fad3 v0.8.14.2: suppress BLG selftest internal block noise
012d725 v0.8.14.1: aggregate contiguous file-write events
02fce4b v0.8.14: broaden file-write coverage and event capacity
```
