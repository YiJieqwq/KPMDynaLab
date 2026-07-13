#!/system/bin/sh
# KPMDynaLab v0.3 safe smoke test using a loop-backed disposable image.
# Run as root after loading KPMDynaLab and selecting AUTO + SEAL.
set -u

IMG=/data/local/tmp/dynalab-loop.img
MNT_DEV=""

cleanup() {
    [ -n "$MNT_DEV" ] && losetup -d "$MNT_DEV" 2>/dev/null
    rm -f "$IMG"
}
trap cleanup EXIT INT TERM

command -v losetup >/dev/null 2>&1 || {
    echo "[SKIP] losetup unavailable; do NOT substitute a real partition yet."
    exit 2
}

rm -f "$IMG"
dd if=/dev/urandom of="$IMG" bs=4096 count=16 status=none || exit 1
BEFORE=$(sha256sum "$IMG" | cut -d' ' -f1)

MNT_DEV=$(losetup -f 2>/dev/null) || {
    echo "[SKIP] no free loop device"
    exit 2
}
losetup "$MNT_DEV" "$IMG" || exit 1

echo "[*] loop device: $MNT_DEV"
echo "[*] hash before: $BEFORE"

# Expected: dd reports success, KPM logs SIMULATE, backing image stays unchanged.
dd if=/dev/zero of="$MNT_DEV" bs=4096 count=1 conv=fsync
RC=$?
AFTER=$(sha256sum "$IMG" | cut -d' ' -f1)

echo "[*] dd rc: $RC"
echo "[*] hash after:  $AFTER"

if [ "$RC" -eq 0 ] && [ "$BEFORE" = "$AFTER" ]; then
    echo "[PASS] simulated success; backing data unchanged"
    echo "[*] inspect: dmesg | grep dynalab | tail -30"
    exit 0
fi

if [ "$BEFORE" != "$AFTER" ]; then
    echo "[FAIL] hook did not simulate; disposable loop image changed"
else
    echo "[FAIL] write was blocked/error rather than simulated success"
fi
exit 1
