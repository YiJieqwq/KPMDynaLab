# KPMDynaLab

> Kernel-level Dynamic Analysis Lab for Android bricker malware.

KPMDynaLab is a **Kernel Patch Module (KPM)** that deploys undetectable inline hooks at the Linux block layer to monitor, simulate, or block all block device write operations. It is designed for security researchers analyzing bricker malware (格机程序) — programs that destroy Android devices by writing to raw block devices.

## Why KPMDynaLab

Bricker malware detects and evades userspace analysis tools:

| Detection | Userspace (LD_PRELOAD) | KPMDynaLab (inline hook) |
|:---|:---:|:---:|
| `/proc/self/maps` | ✗ exposed | ✓ invisible |
| `ptrace` / `TracerPid` | ✗ detectable | ✓ invisible |
| `LD_PRELOAD` env var | ✗ exposed | ✓ invisible |
| Frida / Xposed | ✗ detectable | ✓ invisible |
| strace | ✗ detectable | ✓ invisible |
| `/sys/kernel/debug/kprobes/list` | N/A | ✓ not using kprobes |

KPMDynaLab hooks at the **block layer** — 4 layers below libc:

```
app → libc → syscall → VFS → block_layer ← KPMDynaLab hooks here
```

## Features

- **3 modes**: LOG (record), SIM (fake success), BLOCK (deny)
- **3 hooks**: `blkdev_open`, `blkdev_write_iter`, `blkdev_ioctl`
- **procfs interface**: `/proc/dynalab/log` + `/proc/dynalab/control`
- **Process whitelist**: init, ueventd, vold (same as production protection modules)
- **Real-time logging**: dmesg + procfs dual channel
- **Zero userspace footprint**: no files, no environment, no process

## Quick Start

```bash
# Load KPM
kpatch kpm load /data/local/tmp/kpm_dynalab.kpm

# Check status
cat /proc/dynalab/control      # → LOG

# Switch to simulation mode (bricker thinks writes succeed but they don't)
echo sim > /proc/dynalab/control

# Run analysis
sh suspicious_script.sh

# View results
cat /proc/dynalab/log
```

## CLI

```bash
dynalab status          # show status
dynalab log -f          # follow log in real-time
dynalab mode sim        # simulation mode
dynalab mode block      # block mode
dynalab mode log        # log-only mode
dynalab clear           # clear log
dynalab run ./bricker   # run program under analysis
```

## Build

Requires [KernelPatch SDK](https://github.com/bmax121/KernelPatch).

```bash
git clone https://github.com/YiJieqwq/KPMDynaLab.git
cd KPMDynaLab
make KDIR=/path/to/kernel
# output: kpm_dynalab.kpm
```

## Project Structure

```
src/main.c               KPM entry point (kpm_init / kpm_exit)
hook/blkdev.c            blkdev_open / write_iter / ioctl hooks
procfs/interface.c       /proc/dynalab/log + control
include/kpm_dynalab.h    Common definitions
scripts/cli.sh           Command-line control tool
```

## Requirements

- Android GKI 2.0 (kernel 5.10+) or kernel 4.14+ with CONFIG_KALLSYMS=y
- ARM64 architecture
- [KernelPatch](https://github.com/bmax121/KernelPatch) or APatch/KPatch-Next

## License

GPL-2.0
