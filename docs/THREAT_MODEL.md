# KPMDynaLab Threat Model

> Draft for publication.  
> Scope: Android flagship-device dynamic analysis, boot-chain survivability, runtime containment, and evidence preservation.

## 1. Motivation

KPMDynaLab is designed for a difficult but increasingly common analysis scenario:

> Engineers need to analyze targeted Android attacks on real, current flagship devices, because emulators, old spare phones, GSI images, and generic test environments often fail to trigger device-specific payloads.

Modern Android malware and bricker samples may check:

- device model and SoC;
- vendor ROM and build fingerprint;
- security patch level;
- bootloader and root environment;
- TEE / KeyMint / StrongBox behavior;
- baseband and carrier state;
- vendor services;
- UFS layout and by-name partitions;
- hardware-specific properties;
- presence of emulators, old kernels, or analysis artifacts.

Using obsolete or generic devices lowers financial risk but also lowers behavioral fidelity. Using the actual target flagship device increases fidelity but exposes expensive hardware to permanent boot-chain damage, data loss, and targeted anti-analysis behavior.

KPMDynaLab therefore pursues two product goals:

1. kernel-assisted dynamic analysis;  
2. enough safety for engineers to execute high-risk samples on expensive, realistic devices without treating permanent device loss as an acceptable analysis cost.

A concise design statement is:

> Faithful enough to trigger. Safe enough to survive. Observable enough to explain.

## 2. Architecture Terms

KPMDynaLab separates protection into three conceptual layers.

### 2.1 BCG — Boot Chain Guard

BCG is the always-on, low-overhead boot-chain safety floor.

Its role is not to sandbox every process. Its role is to protect a small set of survival-critical assets with very low false-positive risk:

- EFISP;
- XBL / XBL config;
- ABL;
- TZ / HYP;
- AOP / RPM-style firmware;
- Keymaster / KeyMint-related firmware;
- QUP firmware;
- UEFI-related images;
- Image FV;
- SHRM;
- platform-specific boot firmware;
- selected persist-like device identity and calibration assets;
- recovery pack, RAM cache, and recovery image map.

BCG is asset-centered rather than command-centered. It does not simply block every command named `dd` or every deletion tool. Instead, it asks:

> Is this operation attempting to damage a survival-critical asset?

BCG aims to provide:

- global raw block protection for boot-chain assets;
- EFISP permanent guard;
- persist raw-block destruction protection;
- recovery pack extraction and verification;
- read-only RAM recovery cache;
- image map from trusted cache to recovery targets;
- physical emergency gestures;
- live-kernel emergency recovery opportunity.

BCG is intended to be mostly invisible during daily use. OTA and firmware updates may require explicit maintenance mode or module unloading. This is acceptable because advanced users already need to repatch the opposite slot or reconfigure root tooling during OTA.

### 2.2 CORDON

CORDON is the analysis-time containment boundary.

CORDON is not a whole-device lockdown and not a full virtualized sandbox. It is a high-assurance runtime containment boundary around an analysis target and its descendants.

CORDON is responsible for:

- mode selection: trace, auto, expert / strict;
- evidence protection while analysis is active;
- reboot suppression;
- target-session block-write simulation;
- dangerous ioctl and fallocate suppression/simulation;
- file behavior tracking;
- process lineage tracking;
- future network, Binder, mmap, module-loading, and data-exfiltration policies;
- preventing mixed concurrent analysis sessions;
- keeping containment active while tracked descendants remain alive.

CORDON is higher coverage and higher cost than BCG. It reduces freedom for the analyzed target, but it should avoid unnecessarily constraining unrelated system services.

### 2.3 ANALYZE

ANALYZE is the controlled execution workflow.

It provides CORDON with:

- target identity;
- PID and TGID;
- session ID;
- target vs descendant scope;
- fork/exec lineage;
- lifecycle boundaries;
- work directory;
- event filtering window;
- operation summary;
- automatic CORDON lift when all tracked processes exit.

ANALYZE is not merely a process whitelist. It establishes attribution and policy context.

## 3. Assets

The threat model protects multiple asset classes.

### 3.1 Boot Availability Assets

These assets determine whether the device can boot, enter recovery, or remain recoverable:

- boot-chain firmware partitions;
- EFISP;
- bootloader-stage configuration;
- vendor firmware stages;
- selected A/B slot boot-chain assets;
- recovery pack and manifest;
- recovery RAM cache;
- image map;
- physical gesture recovery path.

### 3.2 User Data Integrity Assets

These include:

- application data;
- user files;
- configuration files;
- persist files and calibration data;
- analysis work directories;
- KPMDynaLab logs and exported evidence.

### 3.3 User Data Confidentiality Assets

These include:

- `/data/data/<package>` contents;
- tokens and cookies;
- account databases;
- shared preferences;
- keystore-using workflows;
- media files;
- contacts, SMS, clipboard;
- root-manager configuration;
- other modules' private state.

### 3.4 Evidence Assets

These include:

- event ring;
- exported logs;
- timestamps;
- process lineage;
- block operation records;
- file operation records;
- containment actions;
- lifecycle events;
- operation summaries.

### 3.5 Defender Integrity Assets

These include:

- KPM hooks;
- hook chain integrity;
- KPMDynaLab code and data;
- BCG registry;
- CORDON state;
- event ring integrity;
- authentication state;
- recovery cache and map.

## 4. Trust Assumptions

### 4.1 Trusted or Conditioned-Trusted Components

KPMDynaLab assumes the following are trusted or at least conditionally trusted at startup:

- the kernel environment at KPM load time;
- KernelPatch/KPM loader sufficient to load KPMDynaLab correctly;
- Manager authentication path;
- recovery pack creation on a known-good device state;
- boot-chain partition map at setup time;
- CLI process after successful authentication.

### 4.2 Untrusted Components

The following are untrusted:

- analyzed target;
- descendants of the target;
- scripts extracted by the target;
- data loaded by the target;
- target-controlled files;
- target-controlled network input;
- target-controlled IPC input.

### 4.3 Conditional Trust: System Services

Vendor and system services are conditionally trusted.

Examples:

- `rmt_storage`;
- `MI_RIC`;
- `vold`;
- `system_server`;
- update-related services;
- root tooling and manager processes.

They are not automatically malicious, but they are also not absolute trust anchors. They may become confused deputies if the target can cause them to perform dangerous work.

Therefore, long-term policy should avoid pure process-name whitelists. Better policy combines:

- target device or partition;
- operation type;
- SELinux SID;
- executable identity;
- session taint;
- maintenance state;
- file descriptor or object provenance.

## 5. Threat Classes

The original bricker model can be expressed as three intuitive levels:

1. low-level bricker: `rm -rf`, `dd if=...`;
2. mid-level bricker: ioctl, mmap + fsync;
3. high-level bricker: module loading and race against defender load order.

For a more complete engineering threat model, these are expanded into T1–T5 plus confidentiality classes C1–C3.

## 6. Availability and Integrity Threats

### T1 — Direct User-Space Destruction

Examples:

- `rm -rf`;
- `dd` to block devices;
- `cp` image to block device;
- `cat payload > /dev/block/...`;
- `mkfs`;
- `blkdiscard`;
- `reboot`, `poweroff`;
- file `unlink`, `rename`, `truncate`, `fallocate`;
- toybox/busybox/system shell tooling.

Properties:

- uses ordinary user-space interfaces;
- often script-based;
- usually visible in process lineage;
- generally straightforward to attribute to an ANALYZE session.

BCG responsibility:

- protect survival-critical assets globally;
- simulate direct raw writes/discards/zero-outs to guarded boot-chain partitions;
- protect EFISP and selected persist raw block paths.

CORDON responsibility:

- for tracked targets and descendants, simulate or suppress destructive operations beyond BCG scope;
- record full process and file behavior.

### T2 — Alternative, Asynchronous, or Indirect I/O Paths

Examples:

- dangerous block ioctls;
- `BLKDISCARD`, `BLKSECDISCARD`, `BLKZEROOUT`;
- mmap + MAP_SHARED + write + msync/fsync;
- writeback after target exits;
- direct I/O;
- vectored I/O;
- io_uring;
- splice and copy_file_range;
- SCM_RIGHTS file-descriptor passing;
- Device Mapper manipulation;
- vendor private storage interfaces;
- Binder-based confused deputy writes;
- kworkers performing dirty-page writeback later.

The key complication is that the process performing final I/O may not be the original target:

```text
target mmap-writes a file
→ page becomes dirty
→ later kworker writes it back
```

or:

```text
target sends Binder request
→ system service writes a block device
```

CORDON therefore needs to evolve from PID-based taint toward object and request taint:

- file descriptor taint;
- inode/file taint;
- mmap region taint;
- io_uring request taint;
- Binder transaction taint;
- writeback provenance.

### T3 — Controlled Kernel Extension Entry

Examples:

- `init_module`;
- `finit_module`;
- KernelPatch KPM loading;
- APatch / KPatch module interfaces;
- eBPF program loading;
- vendor debug driver entry;
- root-manager extension systems.

Here the attacker does not yet necessarily have arbitrary EL1 code execution, but attempts to obtain it through a known loading path.

CORDON goals:

- suppress module loading by tracked targets;
- freeze unauthorized module load paths while CORDON is active;
- record module load attempts;
- verify loaded module baseline;
- permit only Manager-authorized maintenance actions.

### T4 — Arbitrary EL1 Code Execution

Examples:

- malicious kernel module already loaded;
- kernel 0-day exploit;
- arbitrary kernel memory write;
- ROP in kernel;
- compromised KPM or hook chain;
- direct `submit_bio` or blk-mq calls;
- direct UFS/SCSI command path;
- hook removal or event-ring tampering.

Important limitation:

> If the attacker already has arbitrary EL1 execution, KPMDynaLab and the attacker are in the same privilege domain. Without an EL2, Secure World, or lower storage-level trust anchor, CORDON cannot provide a formal absolute containment guarantee.

KPMDynaLab can still provide:

- prevention of known module-loading paths;
- hook integrity checks;
- module baseline snapshots;
- anomaly detection;
- recovery attempts if the kernel remains alive;
- higher attack cost;
- evidence of trust degradation.

But it should not claim absolute protection against arbitrary pre-existing EL1 compromise.

### T5 — Higher or External Trust-Domain Attacks

Examples:

- EL2 / hypervisor attacks;
- TEE / Secure World attacks;
- RPMB manipulation;
- bootloader compromise;
- UFS firmware attacks;
- baseband/DSP attacks;
- permanent fuse changes;
- physical or power-fault attacks.

These are outside current KPM-level protection. BCG status should explicitly avoid claiming RPMB or TEE protection unless dedicated coverage exists.

For example:

```text
Boot firmware raw guard: ARMED
EFISP guard: ARMED
Persist raw guard: ARMED
RPMB guard: NOT IMPLEMENTED
TEE guard: NOT IMPLEMENTED
```

## 7. Confidentiality Threats

Information theft is not merely an optional bricker feature. It is an independent confidentiality dimension.

### C1 — Sensitive Source Access

Examples:

- `/data/data/<package>`;
- databases;
- SharedPreferences;
- tokens;
- cookies;
- private app files;
- contacts and SMS;
- clipboard;
- media;
- root-manager configuration;
- keystore-backed operations.

CORDON should record or restrict sensitive reads by tracked targets.

### C2 — Data Exfiltration Sinks

Examples:

- TCP/UDP;
- DNS;
- HTTP/HTTPS;
- Unix sockets;
- Binder;
- shared storage;
- logs;
- clipboard;
- Bluetooth/NFC;
- files later consumed by another process.

Preventing leakage requires source-to-sink reasoning, not only network blocking.

### C3 — High-Privilege Confidentiality Loss

Examples:

- kernel-level memory read;
- TEE compromise;
- keystore/keymint compromise;
- baseband or secure co-processor leakage.

These require stronger trust anchors and are not fully addressed by KPM-level CORDON.

## 8. BCG Security Model

BCG is intended to be always-on and low-friction.

### 8.1 BCG Design Goals

BCG should:

- impose minimal steady-state overhead;
- avoid broad daily-use restrictions;
- protect boot-chain survival assets globally;
- avoid relying on attack signatures;
- provide recovery readiness;
- preserve enough freedom for advanced users;
- require explicit maintenance for OTA or firmware updates.

### 8.2 BCG Guard Targets

Primary targets:

- EFISP;
- boot-chain firmware partitions;
- Recovery Pack and manifest;
- BCG image map;
- BCG RAM cache;
- selected persist raw-block destruction paths.

### 8.3 BCG Actions

BCG may apply:

- PASS;
- SIMULATE;
- SUPPRESS;
- ALERT;
- VERIFY;
- RECOVER, in future recovery-enabled modes.

### 8.4 BCG Maintenance

BCG should not provide a casual global off switch.

Preferred model:

```text
bcg maintenance enter [scope] [timeout]
bcg maintenance exit
```

Suggested scopes:

- firmware;
- persist;
- recovery-pack;
- full, only for authenticated expert use.

Safety rules:

- maintenance is non-persistent across reboot;
- optional timeout auto-rearms;
- CLI warns on exit if maintenance remains active;
- CORDON-active state rejects BCG maintenance entry;
- EFISP may remain protected unless KPM is unloaded.

## 9. CORDON Security Model

CORDON is an analysis-time containment boundary.

### 9.1 CORDON Goals

CORDON should:

- maximize containment over covered attack surfaces;
- preserve analysis evidence;
- allow target behavior to progress far enough to reveal payloads;
- simulate dangerous operations when useful for behavioral fidelity;
- suppress operations that cannot be safely simulated;
- track descendants;
- prevent mixed concurrent sessions;
- remain active while descendants remain alive.

### 9.2 CORDON Modes

Suggested modes:

- TRACE: record, do not interfere except global BCG and critical safety rules;
- AUTO: simulate/suppress known dangerous operations for tracked targets;
- STRICT or EXPERT: broader restrictions, optional network/Binder/file exfiltration controls.

### 9.3 Covered Surfaces

Current or planned CORDON surfaces:

- process lineage;
- exec and exit;
- file create, write, mkdir;
- future unlink, rename, truncate;
- block write;
- block ioctl;
- block fallocate;
- reboot;
- mmap shared-write;
- io_uring;
- module loading;
- Binder;
- network;
- sensitive source reads;
- exfiltration sinks.

## 10. ANALYZE Security Model

ANALYZE creates the context needed by CORDON.

ANALYZE should provide:

- target preflight;
- controlled child release;
- target registration;
- session allocation;
- automatic CORDON engagement;
- process and descendant attribution;
- interactive input support;
- event printing scoped to the run;
- operation summary;
- automatic CORDON lift when safe;
- artifact cleanup;
- exported evidence.

ANALYZE should distinguish:

- invalid target path: no session created;
- exec failure: no false successful EXEC;
- shell runtime failure: EXEC PASS, EXIT ERROR;
- signal termination: EXIT ERROR with signal;
- successful run: EXIT PASS.

## 11. Red-Team / Blue-Team Load-Order Race

Advanced attackers may compete with the defender over initialization order.

### Blue Team First

Ideal case:

```text
BCG/CORDON load early
→ guard registry established
→ module-load paths restricted
→ hook baseline recorded
→ sample analyzed
```

### Red Team First

Dangerous case:

```text
malicious EL1 code already present
→ can hide itself
→ can patch hooks
→ can tamper with KPM state
→ can falsify evidence
```

### Trust Snapshot

CORDON should eventually establish a kernel trust snapshot:

- loaded modules and KPMs;
- key function entry bytes;
- hook-chain state;
- module-loading entry points;
- kallsyms consistency;
- reboot path state;
- block path state;
- BCG registry checksum;
- event-ring integrity metadata.

If suspicious:

```text
CORDON TRUST DEGRADED
ANALYZE REFUSED or WARNED
```

## 12. Evidence and Event-Ring Threats

Attackers may attempt to destroy or bury evidence.

Threats:

- event ring overflow;
- repeated low-value events;
- timestamp manipulation;
- process spam;
- evidence clearing;
- log export denial;
- ring tampering by EL1 attacker.

Mitigations:

- larger ring;
- event aggregation;
- priority events;
- overwrite counters;
- run-scoped output;
- export snapshots;
- CORDON blocks event clearing;
- stable monotonic timestamps;
- future boot-time UTC anchor;
- future high-priority ring for critical events.

## 13. Recovery Threats and Limits

Emergency recovery is a last-resort survival mechanism, not a magic unbrick guarantee.

It depends on:

- Android kernel still running;
- KPMDynaLab still loaded;
- BCG cache intact;
- image map intact;
- UFS still writable;
- key input path working;
- recovery target in protected map.

It may not help if:

- device has already powered off;
- boot chain is damaged and the device rebooted;
- UFS is dead;
- KPM was removed;
- malicious EL1 modified BCG state;
- TEE/RPMB/fuse state is damaged;
- bootloader or hardware-level state is irreversibly changed.

Therefore, product language should say:

> live-kernel emergency recovery opportunity

not:

> guaranteed recovery from any brick.

## 14. Threat Matrix

| Class | Attacker capability | Examples | BCG role | CORDON role |
|---|---|---|---|---|
| T1 | Direct user-space destruction | rm, dd, mkfs, blkdiscard | Protect guarded assets globally | Contain tracked target operations |
| T2 | Alternative/async/indirect I/O | ioctl, mmap, io_uring, Binder, writeback | Asset-level coverage where possible | Requires PID + object/request taint |
| T3 | Controlled kernel extension entry | init_module, KPM load, eBPF | Protect own critical state | Suppress/detect unauthorized loads |
| T4 | Arbitrary EL1 execution | malicious module, kernel exploit | Detection/recovery attempt only | No absolute guarantee without higher trust anchor |
| T5 | EL2/TEE/RPMB/hardware | Secure World, RPMB, baseband, fuse | Out of current KPM scope | Out of current KPM scope |
| C1 | Sensitive source reads | app data, tokens, databases | Not primary BCG scope | Source access monitoring/policy |
| C2 | Exfiltration sinks | network, DNS, Binder, shared files | Not BCG scope | Sink control and taint flow |
| C3 | High-priv confidentiality loss | kernel/TEE/baseband read | Out of current KPM scope | Requires stronger trust anchor |

## 15. Product Security Claims

Recommended safe claims:

- BCG provides always-on, low-overhead protection for critical boot-chain assets.
- BCG reduces permanent boot-chain loss risk and provides live-kernel emergency recovery opportunity.
- CORDON provides high-strength containment for tracked analysis targets over covered attack surfaces.
- ANALYZE supplies target identity, lineage, attribution, and lifecycle management.
- KPMDynaLab enables more realistic analysis on current flagship devices than emulator-only or obsolete-device workflows.

Claims to avoid:

- impossible to brick;
- blocks all attacks;
- defeats arbitrary kernel code execution;
- protects RPMB or TEE without specific implementation;
- guarantees confidentiality against kernel or secure-world compromise;
- completely undetectable analysis environment.

## 16. Roadmap Implications

Near-term priorities:

1. formalize BCG guarded asset registry;
2. implement BCG maintenance mode;
3. protect boot-chain and persist raw-block targets globally;
4. improve unlink/rename/truncate coverage safely;
5. add mmap shared-write detection;
6. add module-load observation and suppression;
7. add event priority and overwrite accounting;
8. add CORDON trust snapshot;
9. add network and Binder attribution;
10. add confidentiality source/sink policies;
11. consider EL2 or other higher-trust anchors for stronger protection against arbitrary EL1 attackers.

## 17. Summary

KPMDynaLab's threat model is not simply "anti-bricker".

It is a layered model for real-device dynamic analysis:

```text
BCG     protects device survivability.
CORDON  contains analyzed behavior.
ANALYZE attributes behavior to targets and descendants.
```

The system is strongest when it loads before the attacker, protects a focused set of survival-critical assets globally, and applies high-strength containment only to tracked analysis sessions.

Its design goal is to let engineers confront targeted, device-specific attacks on real flagship hardware with substantially reduced risk and substantially improved evidence quality, while being transparent about the limits of KPM-level protection against already-established EL1 or higher-privilege compromise.
