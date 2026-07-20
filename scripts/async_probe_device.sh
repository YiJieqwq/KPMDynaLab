#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
BASE=/data/local/tmp/dynalab-async-probe
IMG=$BASE.img
LOOPFILE=$BASE.loop
SOCK=$BASE.sock
LOG=$BASE-deputy.log

case "${1:-}" in
  prepare)
    rm -f "$IMG" "$LOOPFILE" "$SOCK" "$LOG"
    dd if=/dev/urandom of="$IMG" bs=1M count=1 status=none
    LOOP=$(losetup -f)
    losetup "$LOOP" "$IMG"
    echo "$LOOP" > "$LOOPFILE"
    chmod 600 "$IMG" "$LOOPFILE"
    echo "LOOP=$LOOP"
    echo "Only this major=7 disposable loop device may be passed to the probe."
    ;;
  start-deputy)
    test -f "$LOOPFILE"
    LOOP=$(cat "$LOOPFILE")
    rm -f "$SOCK" "$LOG"
    nohup /data/local/tmp/dynalab-async-probe-arm64 \
      deputy-server "$SOCK" "$LOOP" >"$LOG" 2>&1 &
    PID=$!
    i=0
    while [ ! -S "$SOCK" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i+1)); done
    test -S "$SOCK"
    echo "DEPUTY_PID=$PID"
    echo "SOCKET=$SOCK"
    cat "$LOG"
    ;;
  show-deputy)
    cat "$LOG"
    ;;
  cleanup)
    if [ -f "$LOOPFILE" ]; then
      LOOP=$(cat "$LOOPFILE")
      losetup -d "$LOOP" 2>/dev/null || true
    fi
    rm -f "$IMG" "$LOOPFILE" "$SOCK" "$LOG"
    echo "Cleaned disposable async-provenance test assets."
    ;;
  *)
    echo "Usage: $0 prepare | start-deputy | show-deputy | cleanup" >&2
    exit 2
    ;;
esac
