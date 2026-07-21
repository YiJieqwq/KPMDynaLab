# Transfer pack instructions

## Source code and built artifacts

The full repository including all built artifacts (`build/` containing `dynalab-arm64`, `dynalab-async-probe-arm64`, `KPMDynaLab-0.8.17-error-input-test.kpm`) is available via git:

```sh
git clone https://github.com/YiJieqwq/KPMDynaLab.git
cd KPMDynaLab
git checkout d63a6bf
```

## What is NOT in the repository

### Kernel source tree

Required for building the KPM (kernel module). Needed at path:

```text
/workspace/android16-6.12
```

Specs: Android 16, Linux 6.12.23 GKI, arm64, 4 KiB pages.

Must be re-imported from the original workspace as a tarball or direct copy.

### Uploaded test files

These files were uploaded by the user during previous conversations and live at `/upload`:

```text
device_smoke_sfx.sh
操作流程.txt
0.8.14测试流程.txt
0.8.17测试流程.txt
```

These are NOT in the repo and must be re-imported by uploading again.

## Build commands after import

```sh
make test
make cli
make async-probe
make kpm KDIR=/path/to/android16-6.12
```
