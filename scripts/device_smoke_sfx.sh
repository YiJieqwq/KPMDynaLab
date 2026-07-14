#!/system/bin/sh
# KPMDynaLab self-extracting multi-stage smoke sample.
# The CLI provides DYNALAB_WORKDIR and may remove it after execution.
set -u

WORK="${DYNALAB_WORKDIR:-/data/local/tmp/dynalab-sfx-$$}"
STAGE1="$WORK/.stage1.sh"
mkdir -p "$WORK" || exit 1

echo "[*] SFX launcher pid=$$ workdir=$WORK"
awk 'emit { print } /^__DYNALAB_PAYLOAD__$/ { emit=1; next }' "$0" > "$STAGE1" || exit 1
chmod 700 "$STAGE1" || exit 1
echo "[*] extracted stage1: $STAGE1"
exec /system/bin/sh "$STAGE1"
exit 127

__DYNALAB_PAYLOAD__
#!/system/bin/sh
set -u
WORK="${DYNALAB_WORKDIR:?missing DYNALAB_WORKDIR}"
STAGE2="$WORK/.stage2.sh"

echo "[*] stage1 pid=$$"
cat > "$STAGE2" <<'__DYNALAB_STAGE2__'
#!/system/bin/sh
set -u
WORK="${DYNALAB_WORKDIR:?missing DYNALAB_WORKDIR}"
IMG="$WORK/loop-backing.img"
DEV=""

cleanup_loop() {
    [ -n "$DEV" ] && losetup -d "$DEV" 2>/dev/null
}
trap cleanup_loop EXIT INT TERM

echo "[*] stage2 pid=$$"
echo "payload artifact from stage2" > "$WORK/payload.note"

command -v losetup >/dev/null 2>&1 || {
    echo "[SKIP] losetup unavailable"
    exit 2
}

dd if=/dev/urandom of="$IMG" bs=4096 count=16 status=none || exit 1
BEFORE=$(sha256sum "$IMG" | cut -d' ' -f1)
DEV=$(losetup -f 2>/dev/null) || {
    echo "[SKIP] no free loop device"
    exit 2
}
losetup "$DEV" "$IMG" || exit 1

echo "[*] loop device: $DEV"
echo "[*] hash before: $BEFORE"
dd if=/dev/zero of="$DEV" bs=4096 count=1 conv=fsync
RC=$?
AFTER=$(sha256sum "$IMG" | cut -d' ' -f1)

echo "[*] dd rc: $RC"
echo "[*] hash after:  $AFTER"
if [ "$RC" -eq 0 ] && [ "$BEFORE" = "$AFTER" ]; then
    echo "[PASS] SFX payload saw success; backing data unchanged"
    echo "[*] intentionally leaving extracted artifacts for CLI cleanup"
    exit 0
fi
if [ "$BEFORE" != "$AFTER" ]; then
    echo "[FAIL] backing image changed"
else
    echo "[FAIL] write did not report simulated success"
fi
exit 1
__DYNALAB_STAGE2__
chmod 700 "$STAGE2" || exit 1
echo "[*] extracted stage2: $STAGE2"
exec /system/bin/sh "$STAGE2"
exit 127
