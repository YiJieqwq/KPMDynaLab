#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

REPO=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
KDIR=${2:-"$(cd "$REPO/.." && pwd)/android16-6.12"}
FAIL=0

check_cmd() {
    if command -v "$1" >/dev/null 2>&1; then
        printf 'OK   %-30s %s\n' "$1" "$(command -v "$1")"
    else
        printf 'MISS %-30s\n' "$1"
        FAIL=1
    fi
}

for cmd in git make cc python3 aarch64-linux-gnu-gcc aarch64-linux-gnu-ld file sha256sum; do
    check_cmd "$cmd"
done

for path in \
    "$REPO/Makefile" \
    "$REPO/kpm/dynalab_kpm.c" \
    "$REPO/cli/dynalab.c" \
    "$KDIR/include/generated/autoconf.h" \
    "$KDIR/include/linux/kconfig.h" \
    "$KDIR/arch/arm64/include"; do
    if [ -e "$path" ]; then
        printf 'OK   %s\n' "$path"
    else
        printf 'MISS %s\n' "$path"
        FAIL=1
    fi
done

if [ "$FAIL" -ne 0 ]; then
    echo "Environment verification failed." >&2
    exit 1
fi

make -C "$REPO" test
make -C "$REPO" cli
make -C "$REPO" async-probe
make -C "$REPO" kpm KDIR="$KDIR"

printf '\nEnvironment verified.\n'
printf 'Repository HEAD: %s\n' "$(git -C "$REPO" rev-parse HEAD)"
printf 'Cross compiler:  %s\n' "$(aarch64-linux-gnu-gcc --version | head -1)"
printf 'Artifacts:\n'
sha256sum "$REPO"/build/dynalab-arm64 \
          "$REPO"/build/dynalab-async-probe-arm64 \
          "$REPO"/build/KPMDynaLab-*.kpm
