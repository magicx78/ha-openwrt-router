"""Module constants of Traffic Analytics (Phase 5; plan 2026-11-20).

Limits, rasters and reason codes live here so ``const.py`` only carries the
store keys, signals and unique-id prefixes (plan §2.1, §11). No Home
Assistant import: the pure modules (``traffic_counters``, ``traffic_model``)
and ``api.py`` read these limits without pulling in HA.
"""

from __future__ import annotations

import logging
import re
from typing import Final

_LOGGER = logging.getLogger(__name__)

# --- identity in the enterprise core (plan §10) -------------------------------

MODULE_NAME: Final = "traffic_analytics"
EVENT_PREFIX: Final = "traffic_analytics."
CAPABILITY_PREFIX: Final = "traffic."
# Purpose of the module key for client_ref / evidence_ref (plan §10).
IDENTITY_KEY_PURPOSE: Final = "identity"

CAP_NETDEV_COUNTERS: Final = "traffic.netdev_counters"
CAP_STATION_COUNTERS: Final = "traffic.station_counters"
CAP_STATION_DETAIL: Final = "traffic.station_detail"
CAP_OFFLOAD_STATE: Final = "traffic.offload_state"
CAP_FLOW_COLLECTOR: Final = "traffic.flow_collector"
CAPABILITIES: Final = (
    CAP_NETDEV_COUNTERS,
    CAP_STATION_COUNTERS,
    CAP_STATION_DETAIL,
    CAP_OFFLOAD_STATE,
    CAP_FLOW_COLLECTOR,
)

# --- counter processing (plan §3.4) -------------------------------------------

# Same window as the WAN rate of the coordinator (_WAN_RATE_MIN/MAX_INTERVAL_S).
MIN_INTERVAL_S: Final = 5.0
MAX_INTERVAL_S: Final = 900.0
# Rule 8 (HA restart): |delta uptime - delta wall| must stay below this.
UPTIME_MISMATCH_S: Final = 10.0
COUNTER_32_RANGE: Final = 2**32
# Entscheidung: a 32-bit wrap is only taken when the wrapped delta is at most
# half the counter range. A reconnect (counter back near 0) would otherwise
# pass the rate limit at 60 s polls (2.4 Gbit/s x 60 s > 4 GiB) and add a
# fake 4 GiB; this way it counts as counter_reset and no bytes are invented.
WRAP_32_MAX_DELTA: Final = 2**31
# Plausibility: link speed in Mbit/s x 125 000 B/s x 1.05.
BYTES_PER_S_PER_MBPS: Final = 125_000
PLAUSIBILITY_MARGIN: Final = 1.05
# Start values without link speed (not calibrated), bytes per second.
DEFAULT_LIMIT_WIRED_BPS: Final = 10_000_000_000 // 8  # WAN / interface 10 Gbit/s
DEFAULT_LIMIT_STATION_BPS: Final = 2_400_000_000 // 8  # station 2.4 Gbit/s

# --- bounded memory (plan §5 quotas used from Phase B on) ----------------------

# Coordinator block: at most this many netdevs are copied per poll.
MAX_DEVICES_PER_ROUTER: Final = 64
# Counter baselines (one per measuring point).
MAX_POINTS_INFRA_PER_ROUTER: Final = 32
MAX_POINTS_INFRA_TOTAL: Final = 160
MAX_POINTS_CLIENT: Final = 200
# A client point idle this long may be replaced by a new one (never an active).
CLIENT_POINT_IDLE_S: Final = 24 * 3600
# Baselines not updated for this long are dropped (they can only give a gap).
BASELINE_TTL_S: Final = 24 * 3600
# Stations copied per router and poll (more are dropped and counted).
MAX_STATIONS_PER_ROUTER: Final = 256
# Queue coordinator -> engine: one snapshot per router, at most this many routers.
MAX_QUEUE_ROUTERS: Final = 64

# --- switchable extra calls (plan §6.2) ----------------------------------------

OPT_STATION_DETAIL: Final = "station_detail"
OPT_SYSFS_FALLBACK: Final = "sysfs_fallback"
OPT_OFFLOAD_PROBE: Final = "offload_probe"
EXTRA_OPTIONS: Final = (OPT_STATION_DETAIL, OPT_SYSFS_FALLBACK, OPT_OFFLOAD_PROBE)

STATION_DETAIL_INTERVAL_S: Final = 300.0
SYSFS_INTERVAL_S: Final = 300.0
OFFLOAD_INTERVAL_S: Final = 6 * 3600.0
INTERVAL_OF_OPTION: Final = {
    OPT_STATION_DETAIL: STATION_DETAIL_INTERVAL_S,
    OPT_SYSFS_FALLBACK: SYSFS_INTERVAL_S,
    OPT_OFFLOAD_PROBE: OFFLOAD_INTERVAL_S,
}
EXTRA_CALL_TIMEOUT_S: Final = 10.0
# A call starts only if the next scheduled poll is at least this far away
# (timeout + margin), so it never runs next to the poll of its router.
EXTRA_CALL_POLL_MARGIN_S: Final = EXTRA_CALL_TIMEOUT_S + 5.0
MAX_EXTRA_CALLS_TOTAL: Final = 2
EXTRA_FAILURES_BEFORE_PAUSE: Final = 3
EXTRA_PAUSE_S: Final = 3600.0
MAX_AP_INTERFACES: Final = 4
MAX_STATIONS_PER_REPLY: Final = 256
MAX_SYSFS_DEVICES: Final = 4
SYSFS_COUNTER_FILES: Final = (
    "rx_bytes",
    "tx_bytes",
    "rx_packets",
    "tx_packets",
    "rx_errors",
    "tx_errors",
    "rx_dropped",
    "tx_dropped",
)
# Reply caps (JSON size after decoding; larger replies are dropped).
OFFLOAD_REPLY_MAX_BYTES: Final = 16 * 1024
STATION_REPLY_MAX_BYTES: Final = 256 * 1024
SYSFS_REPLY_MAX_BYTES: Final = 256
# netdev names (IFNAMSIZ - 1); "/" and ".." are refused separately as well.
DEVICE_NAME_RE: Final = re.compile(r"^[A-Za-z0-9._@-]{1,15}$")
# VLAN netdev: <parent>.<vid> (br-lan.10, lan1.20).
VLAN_NETDEV_RE: Final = re.compile(r"^[A-Za-z0-9_@-][A-Za-z0-9._@-]*\.([0-9]{1,4})$")

# --- conntrack (plan §6.1, §14.1 F2) -------------------------------------------

CONNTRACK_SOURCE_COUNT_FILE: Final = "count_file"
CONNTRACK_SOURCE_TABLE_SCAN: Final = "table_scan"

# --- settings (plan §7 /settings, E1) ------------------------------------------

SETTINGS_VERSION: Final = 1
MAX_SETTINGS_ROUTERS: Final = 64

# --- reason codes (capabilities, readiness) ------------------------------------

REASON_OK: Final = "ok"
REASON_DISABLED: Final = "disabled"
REASON_NO_DATA_YET: Final = "no_data_yet"
REASON_NOT_PROBED: Final = "not_probed"
REASON_SOURCE_MISSING: Final = "source_missing"
REASON_NO_STATIONS: Final = "no_stations"
REASON_MODULE_KEY_MISSING: Final = "module_key_missing"
REASON_ROUTER_ID_MISSING: Final = "router_id_missing"
REASON_CORE_MISSING: Final = "core_missing"
REASON_PAUSED: Final = "paused_after_failures"
REASON_PERMISSION_DENIED: Final = "permission_denied"
REASON_NOT_CONFIGURED: Final = "not_configured"
REASON_COVERED_ELSEWHERE: Final = "covered_by_other_module"
# Why a due extra call did not run (planner).
BLOCK_DISABLED: Final = "disabled"
BLOCK_NOT_DUE: Final = "not_due"
BLOCK_PAUSED: Final = "paused"
BLOCK_POLL_RUNNING: Final = "poll_running"
BLOCK_POLL_SOON: Final = "poll_soon"
BLOCK_THROTTLED: Final = "throttled"
BLOCK_SSH_FALLBACK: Final = "ssh_fallback"
BLOCK_BUSY: Final = "router_busy"
BLOCK_COVERED: Final = "covered_elsewhere"
BLOCK_NOTHING_TO_DO: Final = "nothing_to_do"
