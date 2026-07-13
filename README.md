# KPMDynaLab

> **K**ernel **P**atch **M**odule **Dyna**mic Analysis **Lab**
>
> Undetectable kernel-level dynamic analysis for Android bricker malware.

## What is KPMDynaLab?

KPMDynaLab is a **Kernel Patch Module (KPM)** that deploys inline hooks at the Linux block layer to **monitor, simulate, or block** all block device write operations. It is designed for security researchers and red teams analyzing bricker malware (格机程序) — programs that destroy Android devices by writing to raw block devices.

### Why not LD_PRELOAD / ptrace / Frida?

Bricker malware actively detects and evades conventional userspace analysis:

| Detection Vector | LD_PRELOAD | KPMDynaLab |
|:---|:---:|:---:|
| `/proc/self/maps` | ✗ exposed | ✓ invisible |
| `ptrace` / `TracerPid` | ✗ detectable | ✓ invisible |
| `LD_PRELOAD` env var | ✗ exposed | ✓ invisible |
| Frida / Xposed / strace | ✗ detectable | ✓ invisible |
| `/sys/kernel/debug/kprobes/list` | N/A | ✓ not using kprobes |
| `/sys/kernel/tracing/enabled_functions` | N/A | ✓ not using ftrace |

KPMDynaLab hooks at the **block layer** — 4 layers below libc — where no userspace code can reach:

```
app → libc → syscall → VFS → blkdev_open ← KPMDynaLab inline hook
```

## Device Test Build (v0.3.1-test)

A first hot-loadable KPM adapter is available for **Android 16 / Linux 6.12.23 / 4 KiB pages**. It hooks `blkdev_write_iter`, `blkdev_ioctl`, `blkdev_fallocate`, and `__arm64_sys_reboot`. AUTO simulates dangerous block operations; TRACE passes them through; READY fails safe to simulation.

Build:

```bash
make kpm KDIR=/path/to/prepared/android16-6.12
```

Follow [the device test guide](docs/DEVICE_TEST.md). Start with the loop-backed smoke test, not a real partition.

## Development Status

> **v0.3 device-test build:** the portable TRACE/AUTO/EXPERT policy core is covered by tests, and a minimal Android 16/6.12.23 KPM adapter now provides global block-write/ioctl/fallocate simulation plus reboot suppression. Process lineage, file-drop tracing, password login, shadow readback, and interactive expert breakpoints remain future work.

```bash
make test
```

See [Analysis Profiles](docs/PROFILES.md) for the current behavior and limitations.

## Analysis Profiles

| Profile | Intended use | Dangerous storage behavior |
|:---|:---|:---|
| **TRACE** | Confirmed-safe programs or sacrificial test devices | Record and pass through |
| **AUTO** | Malware verdict and initial behavior analysis | Record and simulate success |
| **EXPERT** | Dynamic reverse engineering | Custom rules and behavior breakpoints |

## Quick Start

```bash
# 1. Load the KPM
kpatch kpm load /data/local/tmp/kpm_dynalab.kpm

# 2. Enter simulation mode (all writes fake success, nothing actually written)
echo sim > /proc/dynalab/control

# 3. Run the suspicious bricker under analysis
sh ./闪存清理.sh

# 4. View what it tried to do
cat /proc/dynalab/log
```

**Example output:**

```
KPMDynaLab v1.0.0 | mode=SIM | entries=3/512

TIME(s)  PID    UID    COMM              DEV          LBA      SIZE      ACT
42       5678   0      sh                sde10        16384    4096      SIM
42       5678   0      sh                sde9         0        512       SIM
43       5680   0      dd                sde10        0        32768     SIM
```

## Features

- **3 Operating Modes**: LOG (record), SIM (fake success), BLOCK (deny)
- **3 Block Layer Hooks**: `blkdev_open`, `blkdev_write_iter`, `blkdev_ioctl`
- **Dangerous IOCTL Detection**: BLKZEROOUT, BLKDISCARD, BLKSECDISCARD, BLKTRIM
- **procfs Interface**: `/proc/dynalab/log` + `/proc/dynalab/control`
- **Process Whitelist**: init, ueventd, vold (prevents boot failure)
- **Dual-channel Logging**: dmesg + procfs
- **Zero Userspace Footprint**: no files, no env vars, no process

## CLI

```bash
dynalab status                    # Show module status
dynalab log -f                    # Follow real-time log
dynalab mode sim                  # Simulation mode
dynalab mode block                # Block mode
dynalab clear                     # Clear log buffer
dynalab run ./bricker             # Run program under analysis
dynalab watch ./bricker           # Run + live log tracking
dynalab whitelist add myapp       # Add to whitelist
```

## Build

Requires [KernelPatch SDK](https://github.com/bmax121/KernelPatch) and kernel headers matching the target device.

```bash
git clone https://github.com/YiJieqwq/KPMDynaLab.git
cd KPMDynaLab

# Set SDK path
export KP_SDK=~/KernelPatch
export KDIR=~/android-kernel

make
# → build/kpm_dynalab.kpm
```

## Project Structure

```
├── src/
│   └── main.c              KPM entry/exit (kpm_init / kpm_exit)
├── hook/
│   └── blkdev.c            Block layer inline hooks + whitelist
├── procfs/
│   └── interface.c         /proc/dynalab/log + /proc/dynalab/control
├── include/
│   └── kpm_dynalab.h       Common definitions
├── scripts/
│   └── cli.sh              Command-line control tool
├── docs/
│   └── SPEC.md             Engineering specification
├── Makefile
└── README.md
```

## How It Works

1. **Load**: KernelPatch framework loads the `.kpm` file into kernel space
2. **Init**: `kpm_init()` resolves kernel symbols via `kallsyms_lookup_name`
3. **Hook**: `hook_wrap()` replaces the first instruction of `blkdev_open` / `blkdev_write_iter` / `blkdev_ioctl` with an ARM64 `B <hook_function>` branch
4. **Monitor**: Every write to any block device passes through our hook handler, which logs the operation and applies the current mode policy
5. **Whitelist**: Critical processes (init, ueventd, vold) bypass all checks to keep the system running
6. **Unload**: `kpm_exit()` calls `hook_unwrap_remove()` to restore original instructions

## Requirements

- Android GKI 2.0 (kernel 5.10+) or kernel 4.14+ with `CONFIG_KALLSYMS=y`
- ARM64 architecture
- [KernelPatch](https://github.com/bmax121/KernelPatch), APatch, KPatch-Next, or SukiSu Ultra

## Authors

- **Linuxnhe Developers** ([@YiJieqwq](https://github.com/YiJieqwq))

## License

GPL-2.0 — See [LICENSE](LICENSE)

## Acknowledgments

- [KernelPatch](https://github.com/bmax121/KernelPatch) — KPM framework
- [APatch](https://github.com/bmax121/APatch) — Root solution with KPM support
- [KernelSU](https://github.com/tiann/KernelSU) — Kernel-based root solution
