# KPMDynaLab — Engineering Specification

## 1. Project Overview

KPMDynaLab is a Kernel Patch Module (KPM) for dynamic analysis of Android bricker malware. It deploys undetectable inline hooks at the Linux block layer to monitor, simulate, or block all block device write operations.

**Target**: Security researchers analyzing bricker malware (格机程序) that destroys Android devices by writing to raw block devices.

**Key Innovation**: Hooks at the block layer (not libc, not syscall) with no userspace footprint, making it impossible for malware to detect via conventional anti-analysis techniques.

## 2. Architecture

```
┌─────────────────────────────────────────┐
│             Userspace                    │
│  app → libc → syscall                    │
│                   ↓                      │
│              VFS layer                   │
│                   ↓                      │
│  ┌─────────────────────────────────────┐│
│  │        Block Layer                   ││
│  │  ┌──────────┐  ┌──────────────────┐ ││
│  │  │blkdev_open│  │blkdev_write_iter │ ││
│  │  │   HOOK    │  │     HOOK         │ ││
│  │  └──────────┘  └──────────────────┘ ││
│  │  ┌──────────┐                       ││
│  │  │blkdev_ioctl│                     ││
│  │  │   HOOK    │                      ││
│  │  └──────────┘                       ││
│  └─────────────────────────────────────┘│
│                   ↓                      │
│  ┌─────────────────────────────────────┐│
│  │         KPMDynaLab Core              ││
│  │  ┌──────┐ ┌────────┐ ┌───────────┐ ││
│  │  │Logger│ │Whitelist│ │ /proc fs  │ ││
│  │  └──────┘ └────────┘ └───────────┘ ││
│  └─────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

## 3. Hook Points

| Function | Layer | Purpose | ARM64 NR |
|:---|:---|:---|:---:|
| `blkdev_open` | block | Intercept block device open with write flag | N/A |
| `blkdev_write_iter` | block | Intercept data writes to block devices | N/A |
| `blkdev_ioctl` | block | Intercept BLKZEROOUT/BLKDISCARD/BLKSECDISCARD/BLKTRIM | N/A |

## 4. Operating Modes

| Mode | Command | Behavior | Use Case |
|:---|:---|:---|:---|
| LOG | `echo log > .../control` | Record all writes, allow them | Initial analysis, unknown samples |
| SIM | `echo sim > .../control` | Record writes, return fake success | Safe analysis without damage |
| BLOCK | `echo block > .../control` | Record writes, return -EPERM | Active protection |

## 5. Process Whitelist

Kernel-critical processes are whitelisted to prevent boot failure:

| Process | Reason |
|:---|:---|
| `init` | System initialization, mount operations |
| `ueventd` | Device node creation |
| `vold` | Volume management, partition mounting |
| (custom) | Added via `/data/local/tmp/bd_whitelist.txt` |

## 6. procfs Interface

### /proc/dynalab/control (RW, 0666)

```
Read:   Returns current mode ("LOG", "SIM", or "BLOCK")
Write:  "sim" → simulation mode
        "block" → block mode
        "log" → log-only mode
        "clear" → clear log buffer
```

### /proc/dynalab/log (RO, 0444)

```
Format:  TIME(s) PID UID COMM DEV LBA SIZE ACT
Example: 1234    5678 0   dd   sde10  0   4096 BLOCK
```

## 7. KPM File Format

Based on KernelPatch specification:

```
.kpm (ELF64 ARM64 relocatable)

Section          Description
───────────────────────────────
.text            Executable code
.rodata.str1.1   Plaintext strings (compile-time encrypted)
.kpm.info        Module metadata (name, version, author, license)
.kpm.start       Entry point
.kpm.init        Init function pointer (→ kpm_init)
.kpm.ctl0        Control callback
.kpm.exit        Exit function pointer (→ kpm_exit)
.bss             Runtime variables
```

## 8. Build

Requires [KernelPatch SDK](https://github.com/bmax121/KernelPatch).

```bash
git clone https://github.com/YiJieqwq/KPMDynaLab.git
cd KPMDynaLab
export KP_SDK=/path/to/KernelPatch
export KDIR=/path/to/kernel/headers
make
# Output: build/kpm_dynalab.kpm
```

## 9. Deployment

```bash
# Method 1: Runtime load (KPatch-Next / SukiSu)
kpatch kpm load /data/local/tmp/kpm_dynalab.kpm

# Method 2: Embed (APatch)
# Use APatch Manager → Embed KPM → select kpm_dynalab.kpm

# Verify
cat /proc/dynalab/control
```

## 10. Anti-Detection Properties

| Detection Method | Visible? | Reason |
|:---|:---:|:---|
| `/proc/self/maps` | ✗ | No userspace library injected |
| `TracerPid` in `/proc/self/status` | ✗ | No ptrace attached |
| `LD_PRELOAD` env var | ✗ | No environment variable used |
| Frida / Xposed / strace | ✗ | No userspace tooling involved |
| `/sys/kernel/debug/kprobes/list` | ✗ | Uses inline hooks, not kprobes |
| `/sys/kernel/tracing/enabled_functions` | ✗ | Uses inline hooks, not ftrace |
| `lsmod` / `/proc/modules` | ✗ | KPM, not traditional LKM |

## 11. Limitations

- Requires KernelPatch-compatible kernel (CONFIG_KALLSYMS=y, ARM64)
- Block-layer hooks only; cannot intercept direct storage controller register writes (requires TEE)
- Whitelist is PID-based, not capability-based; a compromised whitelisted process could bypass

## 12. References

- KernelPatch: https://github.com/bmax121/KernelPatch
- APatch: https://github.com/bmax121/APatch
- KPatch-Next Module: https://github.com/KernelSU-Next/KPatch-Next-Module
