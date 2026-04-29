#!/bin/bash
# Sample HA RSS over time — for memory-leak diagnosis.
# Picks the python3 child of the bash wrapper.
set -u
PID=$(ps -ef | grep '/opt/ha-venv/bin/python3' | grep hass | grep -v grep | awk '{print $2}' | head -1)
if [ -z "$PID" ]; then
    echo "ERROR: no HA python PID found"
    ps -ef | grep -i hass | grep -v grep
    exit 1
fi
echo "HA python PID: $PID"
echo "---"
SAMPLES=${1:-8}
INTERVAL=${2:-8}
for i in $(seq 1 $SAMPLES); do
    RSS=$(grep VmRSS /proc/$PID/status 2>/dev/null | awk '{print $2}')
    VMS=$(grep VmSize /proc/$PID/status 2>/dev/null | awk '{print $2}')
    OPEN_FDS=$(ls /proc/$PID/fd 2>/dev/null | wc -l)
    THREADS=$(grep Threads /proc/$PID/status 2>/dev/null | awk '{print $2}')
    NOW=$(date +%s)
    echo "t=${NOW} | rss=${RSS} KB | vms=${VMS} KB | fds=${OPEN_FDS} | threads=${THREADS}"
    if [ "$i" -lt "$SAMPLES" ]; then sleep $INTERVAL; fi
done
