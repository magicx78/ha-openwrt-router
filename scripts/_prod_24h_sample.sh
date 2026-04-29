#!/bin/bash
# _prod_24h_sample.sh — 24h read-only Production-Diagnose der Home-Assistant
# Python-Prozess-Resourcen. Schreibt eine JSONL-Datei (eine Zeile = ein Sample
# alle 60s) für `openwrt_router` v1.18.0 FD-Leak / RSS-Trend-Analyse.
#
# Usage:
#   nohup ./scripts/_prod_24h_sample.sh /var/log/ha-24h.jsonl >/dev/null 2>&1 &
#   (oder mit eigenem Output-Pfad als $1)
#
# Beendet sich nach ~24h (86400 s) selbst. Read-only — schreibt nur ins Logfile.
#
# Schemas (eine Zeile pro Sample, JSON):
#   {
#     "t":           unix_seconds,
#     "rss_kb":      VmRSS,                       # resident memory
#     "vms_kb":      VmSize,                      # virtual memory
#     "threads":     thread count,
#     "fd_total":    open file descriptors,
#     "fd_sock":     FDs of type socket:* (TCP/UDP/UNIX),
#     "fd_pipe":     FDs of type pipe:*    (subprocess pipes),
#     "fd_file":     FDs pointing at regular files (/...),
#     "subproc":     direct children of HA pid,
#     "zombie":      direct children in state Z (defunct)
#   }
#
# Auswertung (nach 24h, lokal):
#   jq -s 'sort_by(.t) | .[].fd_total' /var/log/ha-24h.jsonl
#   # oder pandas: pd.read_json("ha-24h.jsonl", lines=True)
#
# Decision rules (siehe v1.18.0 Plan):
#   - fd_total wächst monoton + Pearson(fd_total, kumuliert subproc) > 0.9 → F5 zwingend
#   - rss_kb wächst monoton, fd_total flat → Ursache nicht im subprocess-Pfad
#   - zombie > 0 persistiert → opkg-detach defekt (api.py:3168)

set -u

# ---- locate HA python pid ----------------------------------------------------
PID=$(pgrep -f '/opt/ha-venv/bin/python3.*hass' | head -1)
if [ -z "${PID:-}" ]; then
    # fallback for non-venv installs (HASS-OS, hass via systemd, docker)
    PID=$(pgrep -fx 'python3 .*hass' | head -1)
fi
if [ -z "${PID:-}" ]; then
    echo "ERROR: no Home Assistant python pid found" >&2
    echo "       tried: pgrep -f '/opt/ha-venv/bin/python3.*hass'" >&2
    echo "              pgrep -fx 'python3 .*hass'" >&2
    exit 1
fi

# ---- output path -------------------------------------------------------------
OUT=${1:-/tmp/ha-24h.jsonl}
INTERVAL=${INTERVAL:-60}
DURATION=${DURATION:-86400}
END=$(($(date +%s) + DURATION))

# header into stderr — does not pollute the JSONL stream
echo "ha-24h-sampler: pid=$PID interval=${INTERVAL}s duration=${DURATION}s out=$OUT" >&2

while [ "$(date +%s)" -lt "$END" ]; do
    # process may have died (HA crashed) — record nothing further and exit
    if [ ! -d "/proc/$PID" ]; then
        echo "ha-24h-sampler: pid $PID gone at $(date -Iseconds), exiting" >&2
        exit 0
    fi

    NOW=$(date +%s)
    RSS=$(awk '/^VmRSS:/{print $2}'    "/proc/$PID/status" 2>/dev/null)
    VMS=$(awk '/^VmSize:/{print $2}'   "/proc/$PID/status" 2>/dev/null)
    THR=$(awk '/^Threads:/{print $2}'  "/proc/$PID/status" 2>/dev/null)

    # FD count + breakdown by symlink-target prefix.
    # `find -lname` reads each symlink in /proc/$PID/fd and matches its target;
    # this avoids invoking lsof (often missing on appliance/Docker installs).
    FD_TOTAL=$(ls "/proc/$PID/fd" 2>/dev/null | wc -l)
    FD_SOCK=$(find  "/proc/$PID/fd" -maxdepth 1 -lname 'socket:*' 2>/dev/null | wc -l)
    FD_PIPE=$(find  "/proc/$PID/fd" -maxdepth 1 -lname 'pipe:*'   2>/dev/null | wc -l)
    FD_FILE=$(find  "/proc/$PID/fd" -maxdepth 1 -lname '/*'       2>/dev/null | wc -l)

    # Direct children: ps --ppid filters by parent pid; --no-headers + wc counts.
    SUBPROC=$(ps --ppid "$PID" --no-headers 2>/dev/null | wc -l)
    # Zombies: stat starts with Z (e.g. "Z" or "Z+").
    ZOMBIE=$(ps --ppid "$PID" --no-headers -o stat 2>/dev/null | awk '/^Z/{n++} END{print n+0}')

    # Default missing values to 0 so jq/pandas don't choke on null arithmetic.
    : "${RSS:=0}" "${VMS:=0}" "${THR:=0}"
    : "${FD_TOTAL:=0}" "${FD_SOCK:=0}" "${FD_PIPE:=0}" "${FD_FILE:=0}"
    : "${SUBPROC:=0}" "${ZOMBIE:=0}"

    printf '{"t":%d,"rss_kb":%s,"vms_kb":%s,"threads":%s,"fd_total":%s,"fd_sock":%s,"fd_pipe":%s,"fd_file":%s,"subproc":%s,"zombie":%s}\n' \
        "$NOW" "$RSS" "$VMS" "$THR" "$FD_TOTAL" "$FD_SOCK" "$FD_PIPE" "$FD_FILE" "$SUBPROC" "$ZOMBIE" \
        >> "$OUT"

    sleep "$INTERVAL"
done

echo "ha-24h-sampler: finished after ${DURATION}s" >&2
