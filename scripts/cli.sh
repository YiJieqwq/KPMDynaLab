#!/system/bin/sh
#=========================================================================
#  dynalab — KPMDynaLab CLI
#  =========================
#  用法: dynalab <command> [args]
#
#  Commands:
#    status              查看模块状态
#    log [-f] [-n N]     查看/跟踪日志 (-f 实时, -n 条数)
#    mode [sim|block|log] 查看/切换模式
#    clear               清空日志
#    run <prog> [args]   在监控下运行程序
#    watch <prog> [args] 启动程序 + 实时跟踪日志
#    whitelist [add|del] 管理白名单
#=========================================================================

CTL=/proc/dynalab/control
LOG=/proc/dynalab/log
WLIST=/data/local/tmp/bd_whitelist.txt

R='[31m' G='[32m' Y='[33m' C='[36m' B='[34m' N='[0m'
red()   { printf "\033$R%s\033$N\n" "$*"; }
green() { printf "\033$G%s\033$N\n" "$*"; }
cyan()  { printf "\033$C%s\033$N\n" "$*"; }

banner() {
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║        KPMDynaLab v1.0.0             ║"
    echo "  ║  Kernel Dynamic Analysis Lab          ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""
}

usage() {
    banner
    echo "  Commands:"
    echo "    status                   Show module status"
    echo "    log [-f] [-n N]          View / follow log"
    echo "    mode [sim|block|log]     Get / set mode"
    echo "    clear                    Clear log buffer"
    echo "    run <prog> [args...]     Run program under analysis"
    echo "    watch <prog> [args...]   Run + live log"
    echo "    whitelist [add|del|list] Manage whitelist"
    echo ""
    echo "  Examples:"
    echo "    dynalab run sh ./suspicious.sh"
    echo "    dynalab mode sim && dynalab run ./bricker"
    echo "    dynalab log -f &"
    echo ""
}

# ---- status ----
do_status() {
    banner
    if [ -e "$CTL" ]; then
        local mode=$(cat "$CTL" 2>/dev/null)
        local ver=$(head -1 "$LOG" 2>/dev/null | grep -oP 'v[\d.]+')
        local ents=$(grep -c "PASS\|SIM\|BLOCK" "$LOG" 2>/dev/null || echo 0)
        green "Status: ACTIVE  |  Version: ${ver:-v1.0.0}"
        green "Mode:   $mode  |  Entries: $ents"
        echo ""
        echo "  Control: echo sim|block|log > $CTL"
        echo "  Log:     cat $LOG"
        echo "  CLI:     dynalab log -f"
    else
        red "Status: INACTIVE (KPM not loaded)"
        echo ""
        echo "  Load: kpatch kpm load /data/local/tmp/kpm_dynalab.kpm"
    fi
    echo ""
}

# ---- log ----
do_log() {
    [ ! -e "$LOG" ] && { red "not loaded"; return 1; }

    local follow=0 limit=0
    while [ $# -gt 0 ]; do
        case "$1" in
            -f) follow=1 ;;
            -n) shift; limit="$1" ;;
        esac
        shift
    done

    if [ $follow -eq 1 ]; then
        green "streaming $LOG (Ctrl+C to stop)"
        echo ""
        tail -f "$LOG"
    elif [ "$limit" -gt 0 ]; then
        tail -n "$limit" "$LOG"
    else
        cat "$LOG"
    fi
}

# ---- mode ----
do_mode() {
    [ ! -e "$CTL" ] && { red "not loaded"; return 1; }
    if [ -z "$1" ]; then
        echo "mode: $(cat "$CTL")"
    else
        echo "$1" > "$CTL" 2>/dev/null && green "mode → $1" || red "failed"
    fi
}

# ---- clear ----
do_clear() {
    [ ! -e "$CTL" ] && { red "not loaded"; return 1; }
    echo "clear" > "$CTL" 2>/dev/null && green "cleared" || red "failed"
}

# ---- run ----
do_run() {
    [ -z "$1" ] && { red "usage: dynalab run <prog> [args]"; return 1; }
    cyan "Running: $*"
    echo "──────────────────────────────────────────"
    "$@"
    local rc=$?
    echo "──────────────────────────────────────────"
    cyan "Exit code: $rc"
    [ -e "$LOG" ] && cyan "Log: cat $LOG  (or dynalab log -n 20)" \
                   || cyan "Log: dmesg | grep dynalab"
}

# ---- watch ----
do_watch() {
    [ -z "$1" ] && { red "usage: dynalab watch <prog> [args]"; return 1; }
    cyan "Watching: $*"
    echo "──────────────────────────────────────────"
    "$@" &
    local pid=$!
    if [ -e "$LOG" ]; then
        tail -f "$LOG" &
        local tp=$!
        wait $pid 2>/dev/null
        kill $tp 2>/dev/null
    else
        wait $pid 2>/dev/null
    fi
    echo "──────────────────────────────────────────"
    cyan "Done"
}

# ---- whitelist ----
do_whitelist() {
    local cmd="${1:-list}"
    shift 2>/dev/null

    case "$cmd" in
        list)
            echo "Kernel built-in: init, ueventd, vold"
            [ -f "$WLIST" ] && { echo "File ($WLIST):"; cat "$WLIST"; } \
                             || echo "File: (none)"
            ;;
        add)
            [ -z "$1" ] && { red "usage: dynalab whitelist add <process>"; return 1; }
            echo "$1" >> "$WLIST" && green "added: $1"
            ;;
        del)
            [ -z "$1" ] && { red "usage: dynalab whitelist del <process>"; return 1; }
            sed -i "/^$1$/d" "$WLIST" 2>/dev/null && green "removed: $1"
            ;;
        *) red "usage: dynalab whitelist [list|add|del]"; return 1 ;;
    esac
}

# ---- dispatch ----
CMD="${1:-}"
shift 2>/dev/null

case "$CMD" in
    status)    do_status ;;
    log)       do_log "$@" ;;
    mode)      do_mode "$@" ;;
    clear)     do_clear ;;
    run)       do_run "$@" ;;
    watch)     do_watch "$@" ;;
    whitelist) do_whitelist "$@" ;;
    -h|--help|help) usage ;;
    *)         usage ;;
esac
