#!/system/bin/sh
# dynalab — KPMDynaLab 命令行控制工具
# =====================================
# 用法: dynalab <command> [args]
#
# Commands:
#   status           查看状态
#   log [-f]         查看/跟踪日志
#   mode [sim|block|log] 切换模式
#   clear            清空日志
#   run <prog> [args] 启动程序并监控

CTL=/proc/dynalab/control
LOG=/proc/dynalab/log

usage() {
    echo "dynalab — KPMDynaLab CLI"
    echo "  status          show status"
    echo "  log [-f]        view/follow log"
    echo "  mode [MODE]     get/set mode (sim|block|log)"
    echo "  clear           clear log"
    echo "  run <prog> ...  run program under analysis"
}

status() {
    if [ -e "$CTL" ]; then
        echo "KPMDynaLab: active"
        echo "mode: $(cat $CTL 2>/dev/null)"
        head -1 $LOG 2>/dev/null
    else
        echo "KPMDynaLab: not loaded"
    fi
}

do_log() {
    [ ! -e "$LOG" ] && { echo "not loaded"; return 1; }
    if [ "$1" = "-f" ]; then
        echo "streaming $LOG (Ctrl+C to stop)..."
        tail -f $LOG
    else
        cat $LOG
    fi
}

do_mode() {
    [ ! -e "$CTL" ] && { echo "not loaded"; return 1; }
    if [ -z "$1" ]; then
        echo "mode: $(cat $CTL)"
    else
        echo "$1" > $CTL 2>/dev/null && echo "mode → $1" || echo "failed"
    fi
}

do_clear() {
    [ ! -e "$CTL" ] && { echo "not loaded"; return 1; }
    echo "clear" > $CTL && echo "cleared"
}

do_run() {
    [ -z "$1" ] && { echo "usage: $0 run <prog> [args]"; return 1; }
    [ ! -e "$CTL" ] && echo "[!] KPMDynaLab not active — KPM mode"

    echo "[*] running: $@"
    echo "---"
    "$@"
    echo "---"
    echo "[*] done — cat $LOG"
}

CMD="${1:-}"
shift 2>/dev/null
case "$CMD" in
    status)  status ;;
    log)     do_log "$@" ;;
    mode)    do_mode "$@" ;;
    clear)   do_clear ;;
    run)     do_run "$@" ;;
    *)       usage ;;
esac
