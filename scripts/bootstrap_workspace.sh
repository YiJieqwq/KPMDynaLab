#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT=${1:-"$PWD"}
REPO_URL=https://github.com/YiJieqwq/KPMDynaLab.git
KERNEL_URL=https://android.googlesource.com/kernel/common
KERNEL_TAG=android16-6.12-2025-06_r1
KERNEL_COMMIT=2d954fcf3d1b73a41d0fa498324da357ec96cbdf
REPO=$ROOT/KPMDynaLab
KDIR=$ROOT/android16-6.12

install_deps() {
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "apt-get unavailable; install git, make, gcc, aarch64 cross-gcc, flex, bison, OpenSSL/ELF headers, file and Python manually." >&2
        return
    fi
    local SUDO=
    if [ "$(id -u)" -ne 0 ]; then
        SUDO=sudo
    fi
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends \
        ca-certificates git make gcc gcc-aarch64-linux-gnu \
        libc6-dev-arm64-cross binutils-aarch64-linux-gnu \
        python3 curl file bc bison flex libssl-dev libelf-dev \
        dwarves rsync xz-utils
}

mkdir -p "$ROOT"
install_deps

if [ ! -d "$REPO/.git" ]; then
    git clone "$REPO_URL" "$REPO"
else
    git -C "$REPO" fetch origin main
    git -C "$REPO" checkout main
    git -C "$REPO" pull --ff-only origin main
fi

if [ ! -d "$KDIR/.git" ]; then
    git clone --depth 1 --branch "$KERNEL_TAG" "$KERNEL_URL" "$KDIR"
else
    git -C "$KDIR" fetch --depth 1 origin "refs/tags/$KERNEL_TAG:refs/tags/$KERNEL_TAG"
    git -C "$KDIR" checkout -f "$KERNEL_TAG"
fi

ACTUAL=$(git -C "$KDIR" rev-parse HEAD)
if [ "$ACTUAL" != "$KERNEL_COMMIT" ]; then
    echo "error: unexpected kernel commit: $ACTUAL" >&2
    echo "expected: $KERNEL_COMMIT" >&2
    exit 1
fi

make -C "$KDIR" ARCH=arm64 gki_defconfig
make -C "$KDIR" ARCH=arm64 prepare

make -C "$REPO" clean
make -C "$REPO" test
make -C "$REPO" cli
make -C "$REPO" async-probe
make -C "$REPO" kpm KDIR="$KDIR"

cat <<EOF

KPMDynaLab workspace ready.
Repository: $REPO
Kernel:     $KDIR
Kernel tag: $KERNEL_TAG
Kernel SHA: $ACTUAL

Build outputs:
EOF
find "$REPO/build" -maxdepth 1 -type f -printf '  %f\n' | sort
