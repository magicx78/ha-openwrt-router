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

# --- accounting (plan §3.5, Phase C) -------------------------------------------

# Two station sightings of one client at different associations count as
# "the same poll" when they lie at most this far apart.
# Entscheidung: like client_history.roam_grace (max(2 x interval, 150 s)) at
# the default 60 s poll; the polls of different routers are not aligned.
SIGHTING_WINDOW_S: Final = 150.0
# Associations remembered per client for the duplicate decision.
MAX_ASSOC_PER_CLIENT: Final = 4
# Clients with live sightings (bounded like the client points, x2 margin).
MAX_SIGHTING_CLIENTS: Final = 2 * MAX_POINTS_CLIENT
# Ports a router may name as uplinks of other routers (trunk ports).
MAX_UPLINK_PORTS: Final = 16

# Named refusals of the sum function (never a silent addition).
SUM_NO_POINTS: Final = "no_points"
SUM_DUPLICATE_POINT: Final = "duplicate_point"
SUM_MIXED_SCOPES: Final = "mixed_scopes"
SUM_STATION_PLUS_PORT: Final = "station_plus_port"
SUM_INTERFACE_PLUS_VLAN: Final = "interface_plus_vlan"
SUM_CLIENT_PLUS_WAN: Final = "client_plus_wan"
SUM_BRIDGE_PLUS_PORTS: Final = "bridge_plus_ports"
SUM_INTERFACES_OVERLAP: Final = "interfaces_overlap"
SUM_VLAN_NETDEVS_OVERLAP: Final = "vlan_netdevs_overlap"
SUM_WAN_SAME_ROUTER: Final = "wan_same_router"
SUM_PORTS_OF_SEVERAL_ROUTERS: Final = "ports_of_several_routers"
SUM_PORT_IS_UPLINK: Final = "port_is_uplink_of_counted_router"
SUM_UPLINKS_UNKNOWN: Final = "uplinks_unknown"
SUM_DUPLICATE_CLIENT: Final = "duplicate_client"
SUM_NEEDS_FLOW_SOURCE: Final = "needs_flow_source"
SUM_NO_FLEET_VLAN_TOTAL: Final = "no_fleet_vlan_total"
# Notes a valid sum carries (limits of what it means).
NOTE_RX_TX_SEPARATE: Final = "rx_tx_never_combined"
NOTE_PORT_COUNTERS_UNVERIFIED: Final = "dsa_port_counters_unverified"
NOTE_POINTS_OMITTED: Final = "points_omitted"
NOTE_DIRECTION_MISSING: Final = "direction_missing"

# Why a download/upload mapping is not given.
DIR_AMBIGUOUS_BRIDGE: Final = "bridged_traffic_not_counted"
DIR_PORT_ROLE_UNKNOWN: Final = "port_role_unknown"
DIR_FLOW_DIRECTION: Final = "flow_direction_is_initiator"

# Port roles (download/upload only with a known role).
PORT_ROLE_UPLINK: Final = "uplink"
PORT_ROLE_DOWNLINK: Final = "downlink"

# --- client and VLAN attribution (plan §4, Phase D) ----------------------------

# Hard caps of tracked clients, separate from the infrastructure points and
# from each other (a big bridge FDB never crowds out Wi-Fi clients).
MAX_TRACKED_WIFI_CLIENTS: Final = MAX_POINTS_CLIENT
MAX_TRACKED_WIRED_CLIENTS: Final = 100
# Wired sightings (bridge FDB) copied per router and poll.
MAX_WIRED_PER_ROUTER: Final = 256
# Configured VLANs copied per port.
MAX_VLANS_PER_PORT: Final = 64
# Time windows of the client view; filled by the history store (Phase I).
CLIENT_WINDOWS: Final = {
    "1h": 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
}

LINK_WIFI: Final = "wifi"
LINK_WIRED: Final = "wired"
# What a client value is: Wi-Fi traffic as the AP counted it.
CLIENT_VALUE_KIND: Final = "wlan_traffic_at_ap"
IDENTITY_REGISTRY: Final = "registry"
IDENTITY_MAC_ONLY: Final = "mac_only"
IDENTITY_UNCONFIRMED: Final = "unconfirmed"
IDENTITY_REGISTRY_MISSING: Final = "registry_missing"
LOCATION_REGISTRY: Final = "registry"
LOCATION_STATION: Final = "station_counters"
LOCATION_FDB: Final = "bridge_fdb"

REASON_HISTORY_NOT_BUILT: Final = "history_not_built"
REASON_NO_WIFI_VLAN_MAPPING: Final = "no_wifi_vlan_mapping"
REASON_PORT_VLAN_AMBIGUOUS: Final = "port_vlan_ambiguous"
REASON_PORT_VLAN_UNKNOWN: Final = "port_vlan_unknown"
REASON_NO_VLAN_NETDEV: Final = "no_vlan_netdev"
REASON_VLAN_NOT_CONFIGURED: Final = "vlan_not_configured"
REASON_NO_CLIENT_VLAN_SOURCE: Final = "no_client_vlan_source"
REASON_NO_RATE_YET: Final = "no_rate_yet"
REASON_NO_COVERED_TIME: Final = "no_covered_time"
REASON_NO_LOCATION: Final = "no_location"
BASIS_FDB_SINGLE_VLAN_PORT: Final = "bridge_fdb_single_vlan_port"

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

# --- history read interface and memory ring (Phase E; store in Phase I) ----------

# Resolution of the in-memory ring (the "fine" tier of plan §5).
SERIES_RESOLUTION_S: Final = 300
# Buckets kept per point: infrastructure 24 h, clients 6 h (plan §5 "fein").
SERIES_MAX_BUCKETS_INFRA: Final = 288
SERIES_MAX_BUCKETS_CLIENT: Final = 72
# A window counts as fully covered in time from this share on.
FULL_TIME_COVERAGE: Final = 0.95
# A bucket below this coverage is "lückenhaft" (plan §3.3).
GAPPY_BELOW: Final = 0.5

REASON_BEYOND_RETENTION: Final = "window_beyond_retention"
REASON_HISTORY_SHORT: Final = "history_shorter_than_window"
REASON_TIME_PARTIAL: Final = "time_coverage_incomplete"
REASON_UNKNOWN_POINT: Final = "unknown_point"
REASON_INSUFFICIENT_DATA: Final = "insufficient_data"

# --- top talkers (Phase E, task §6) ------------------------------------------------

TALKER_WINDOWS: Final = {
    "5m": 300,
    "1h": 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
}
DEFAULT_TALKERS: Final = 10
MAX_TALKERS: Final = 50
# Ranked results kept in the cache of the talker board.
TALKER_CACHE_SIZE: Final = 32
# Recurring peaks: a bucket is a peak when its peak rate is at least this
# multiple of the median average rate of the window and above the floor.
PEAK_FACTOR: Final = 3.0
PEAK_MIN_BPS: Final = 1_000_000.0
PEAK_MIN_BUCKETS: Final = 12

TALKER_DIRECTIONS: Final = ("download", "upload", "rx", "tx")
REASON_SCOPE_NOT_RANKED: Final = "scope_not_ranked"
REASON_USE_CLIENT_SCOPE: Final = "station_counts_per_association_use_client"
REASON_NO_DATA_FOR_WINDOW: Final = "no_data_for_window"
REASON_UNKNOWN_WINDOW: Final = "unknown_window"
REASON_UNKNOWN_DIRECTION: Final = "unknown_direction"
REASON_SHARE_REFERENCE_NOT_FULL: Final = "share_reference_not_fully_covered"
REASON_SHARE_REFERENCE_ZERO: Final = "share_reference_zero"
REASON_POINTS_DROPPED: Final = "points_dropped_by_quota"
REASON_POINTS_OMITTED: Final = "points_omitted"

# --- flows and conntrack snapshots (Phase E, task §8; plan §5, §8) -------------------

# Flow records in RAM: in total, per feed (router x origin), and how long.
MAX_FLOWS_TOTAL: Final = 2000
MAX_FLOWS_PER_FEED: Final = 500
FLOW_TTL_S: Final = 3600.0
FLOW_TTL_MIN_S: Final = 60.0
FLOW_TTL_MAX_S: Final = 24 * 3600.0
MAX_FLOW_QUERY: Final = 200
# Collector record rules (plan §8).
FLOW_MAX_STRING: Final = 64
FLOW_MAX_FUTURE_S: Final = 300.0
FLOW_MAX_AGE_S: Final = 24 * 3600.0
FLOW_MAX_SPAN_S: Final = 3600.0
FLOW_PROTOCOLS: Final = ("tcp", "udp", "icmp", "other")
# Bounded conntrack snapshot (delivered by a collector; never read here).
MAX_SNAPSHOT_ENTRIES: Final = 2000
MAX_SNAPSHOT_LINE: Final = 512
# Aggregates kept for later storage (anonymised: client_ref x proto x class).
MAX_FLOW_AGGREGATES: Final = 1000

FEED_COLLECTOR: Final = "collector_flow"
FEED_CONNTRACK: Final = "conntrack_snapshot"

FLOW_STATE_NO_SOURCE: Final = "no_flow_source"
FLOW_STATE_READY: Final = "ready"
FLOW_STATE_NOT_READY: Final = "not_ready"
FLOW_STATE_SILENT: Final = "source_silent"

REJECT_NOT_OBJECT: Final = "not_an_object"
REJECT_UNKNOWN_FIELD: Final = "unknown_field"
REJECT_NOT_FLOW: Final = "not_a_flow_record"
REJECT_BAD_FIELD: Final = "invalid_field"
REJECT_FUTURE: Final = "timestamp_in_future"
REJECT_TOO_OLD: Final = "timestamp_too_old"
REJECT_SPAN: Final = "window_too_long"
REJECT_KEY_MISSING: Final = "module_key_missing"
REASON_SNAPSHOT_NOT_HISTORY: Final = "snapshot_is_not_flow_history"
REASON_SNAPSHOT_TRUNCATED: Final = "snapshot_truncated"
REASON_NAT_SEEN: Final = "nat_rewrites_addresses"
REASON_ACCT_OFF: Final = "conntrack_accounting_off"
REASON_INVISIBLE_IS_UNKNOWN: Final = "not_seen_is_unknown_not_absent"
REASON_EMPTY_IS_NOT_NO_TRAFFIC: Final = "empty_list_is_not_no_traffic"
REASON_FLOW_SOURCE_SILENT: Final = "flow_source_silent"

# --- protocol visibility (task §9) -------------------------------------------------

PROTO_BASIS_PORT: Final = "port_heuristic"
PROTO_BASIS_IP: Final = "ip_protocol"
PROTO_BASIS_NONE: Final = "none"
ACCURACY_LOW: Final = "low"
ACCURACY_MEDIUM: Final = "medium"
ACCURACY_NONE: Final = "none"
PROTO_UNKNOWN: Final = "unknown"
NOTE_PORT_IS_NO_PROOF: Final = "port_does_not_prove_application"
NOTE_TLS_NOT_ATTRIBUTED: Final = "tls_not_attributed_to_an_application"

# --- anomaly candidates (Phase F, task §10; plan §5, §10) -----------------------------

# Baselines: robust median / MAD per weekday class and hour.
BASELINE_LOOKBACK_S: Final = 28 * 86400
BASELINE_MIN_DAYS: Final = 3
BASELINE_MIN_VALUES: Final = 6
MAD_SCALE: Final = 1.4826
# Spread floor: never narrower than this (bit/s) or this share of the median.
SPREAD_MIN_BPS: Final = 100_000.0
SPREAD_REL_FLOOR: Final = 0.1
# Thresholds in spreads above the median: raise, clear (hysteresis).
K_RAISE: Final = 6.0
K_CLEAR: Final = 3.0
K_SUSTAINED: Final = 3.0
K_SUSTAINED_CLEAR: Final = 2.0
# Minimum duration in complete buckets.
SPIKE_MIN_BUCKETS: Final = 2
SUSTAINED_MIN_BUCKETS: Final = 6
DROP_MIN_BUCKETS: Final = 3
# Sudden drop: at most this share of a median of at least DROP_MIN_MEDIAN_BPS.
DROP_RATIO: Final = 0.2
DROP_MIN_MEDIAN_BPS: Final = 1_000_000.0
# Repeated short bursts within the recent hour.
BURST_MIN_COUNT: Final = 4
RECENT_WINDOW_S: Final = 3600
# Local hours (0-23) counted as night.
NIGHT_HOURS: Final = frozenset(range(6))
# Unusual daily volume of one client.
VOLUME_MIN_DAYS: Final = 5
VOLUME_MIN_BYTES: Final = 50_000_000
VOLUME_RATIO: Final = 2.0
# Brakes against alarm floods.
CANDIDATE_DEBOUNCE_S: Final = 1800.0
BUDGET_PER_HOUR: Final = 30
BUDGET_POINT_PER_HOUR: Final = 2
BUDGET_POINT_KIND_S: Final = 6 * 3600.0
# Candidate memory: 100 entries, separate quotas (open/ended vs suppressed).
MAX_CANDIDATES: Final = 100
MAX_CANDIDATES_SUPPRESSED: Final = 20
MAX_SUPPRESSION_RULES: Final = 32
ANOMALY_EVAL_EVERY_S: Final = 300.0
# Confidence of a candidate never reaches certainty.
MAX_CONFIDENCE: Final = 0.9

ANOMALY_STATE_LEARNING: Final = "learning"
ANOMALY_STATE_ACTIVE: Final = "active"
ANOMALY_STATE_UNAVAILABLE: Final = "unavailable"
ANOMALY_STATE_COVERED_BY_NI: Final = "covered_by_network_intelligence"

SUPPRESSED_RULE: Final = "suppression_rule"
SUPPRESSED_BUDGET_HOUR: Final = "budget_per_hour"
SUPPRESSED_BUDGET_POINT: Final = "budget_per_point_hour"
SUPPRESSED_BUDGET_POINT_KIND: Final = "budget_per_point_and_kind"
SUPPRESSED_STORE_FULL: Final = "candidate_store_full"

REASON_CONNTRACK_NOT_COUNT_FILE: Final = "conntrack_source_not_count_file"
REASON_FLOW_HISTORY_NOT_BUILT: Final = "flow_history_not_built"
REASON_NI_RULE: Final = "network_intelligence_rule"
REASON_NO_CANDIDATE_API: Final = "net_engine_has_no_candidate_api"
REASON_NOT_PUBLISHED: Final = "core_events_not_bound"

EVENT_ANOMALY_STARTED: Final = "traffic_analytics.anomaly_started"
EVENT_ANOMALY_ENDED: Final = "traffic_analytics.anomaly_ended"

# --- capacity planning (Phase G, task §11; plan §5 P95) --------------------------------

CAPACITY_WINDOW_S: Final = 7 * 86400
TREND_LOOKBACK_S: Final = 90 * 86400
# P95 needs at least this many usable buckets (nearest rank, no interpolation).
P95_MIN_POINTS: Final = 20
P95_QUANTILE: Final = 0.95
# Finest resolution with an exact P95 (coarser buckets: marked estimated).
P95_EXACT_RESOLUTION_S: Final = 300
# Utilisation levels in percent of the link.
APPROACHING_PCT: Final = 70.0
NEAR_CAPACITY_PCT: Final = 80.0
HIGH_P95_PCT: Final = 90.0
# A recurring bottleneck: near capacity for this many consecutive buckets on
# at least this many distinct days.
NEAR_MIN_BUCKETS: Final = 2
RECURRING_MIN_DAYS: Final = 2
# Trend: daily means over at least this many days and this share of the span.
TREND_MIN_DAYS: Final = 14
TREND_MIN_COVERAGE: Final = 0.7
TREND_MAX_CONFIDENCE: Final = 0.8
TREND_HORIZON_DAYS: Final = 365.0
MAX_CAPACITY_ROWS: Final = 160

CAP_STATE_INSUFFICIENT: Final = "insufficient_data"
CAP_STATE_NO_LINK: Final = "no_link_speed"
CAP_STATE_HEADROOM: Final = "headroom"
CAP_STATE_APPROACHING: Final = "approaching_capacity"
CAP_STATE_POSSIBLE_BOTTLENECK: Final = "possible_bottleneck"
CAP_STATE_POSSIBLE_UPLINK_BOTTLENECK: Final = "possible_uplink_bottleneck"
REASON_NO_LINK_SPEED: Final = "link_speed_unknown"
REASON_HALF_DUPLEX_SHARED: Final = "half_duplex_rx_tx_share_the_link"
REASON_TREND_TOO_SHORT: Final = "trend_series_too_short"
REASON_TREND_LOW_COVERAGE: Final = "trend_series_low_coverage"
REASON_BEYOND_HORIZON: Final = "beyond_forecast_horizon"
REASON_NOT_RISING: Final = "trend_not_rising"
REASON_P95_FROM_COARSE: Final = "p95_from_coarse_buckets"
TREND_METHOD: Final = "theil_sen_daily_mean"

# --- correlation (Phase H, task §12, §13; plan §10) ------------------------------------

# hass.data keys of the optional modules (not on main; looked up at run time).
# Fundstelle: const.DATA_NET_DIAGNOSTICS on origin/claude/net-diagnostics-f989ed
# (b226259, const.py L858) and const.DATA_WIFI_RF_CENTER on
# origin/claude/wifi-rf-48d270 (fddb6cf, const.py L854).
DIAG_DATA_KEY: Final = "openwrt_router_net_diagnostics"
WIFI_RF_DATA_KEY: Final = "openwrt_router_wifi_rf_center"

# Observation window of the bottleneck narrowing (recent hour, 5-min buckets).
CORR_WINDOW_S: Final = 3600
# Utilisation is judged only with this many usable buckets in the window.
CORR_MIN_BUCKETS: Final = 6
# "Dauerhaft hoch": at least this share of usable buckets at >= HIGH_UTIL_PCT.
HIGH_UTIL_PCT: Final = NEAR_CAPACITY_PCT
HIGH_UTIL_SHARE: Final = 0.5
# Interface counters in the window (Startwerte, nicht kalibriert).
DROP_MIN_COUNT: Final = 10
DROP_MIN_RATIO: Final = 0.001
ERROR_MIN_COUNT: Final = 10
# Path quality from Network Diagnostics (Startwerte, nicht kalibriert):
# elevated latency = 1 h mean >= 2 x the 7 d mean and >= 20 ms above it.
LATENCY_ELEVATED_FACTOR: Final = 2.0
LATENCY_ELEVATED_MIN_MS: Final = 20.0
LOSS_ELEVATED_PCT: Final = 2.0
DIAG_MIN_SAMPLES: Final = 6
DIAG_MIN_COVERAGE: Final = 0.5
DIAG_LATENCY_KINDS: Final = frozenset({"icmp", "tcp", "http"})
# WiFi RF: same raise level as rf_correlate.high_pct / NI wifi_channel_busy,
# retry level as rf_clients.ClientThresholds.retry_high (branch fddb6cf).
AIRTIME_HIGH_PCT: Final = 70.0
RF_MIN_VALID: Final = 6
RETRY_HIGH_RATE: Final = 0.25
RETRY_HIGH_SHARE: Final = 0.25
# Recommendations need this data base (else none, with the reason).
RECOMMEND_MIN_BUCKETS: Final = 9
RECOMMEND_MIN_COVERAGE: Final = 0.7
RECOMMEND_MIN_FAMILIES: Final = 1
CORR_BASE_CONFIDENCE: Final = 0.3
CORR_FAMILY_CONFIDENCE: Final = 0.2
CORR_MAX_CONFIDENCE: Final = 0.8
# Bounded memory of the correlator.
MAX_CORR_POINTS: Final = MAX_POINTS_INFRA_TOTAL
MAX_QUALITY_SAMPLES: Final = 64
MAX_LINK_DEVICES: Final = MAX_POINTS_INFRA_TOTAL
MAX_LINK_SAMPLES: Final = 64
MAX_NI_NOTES: Final = 100
# NI incident types that mean a connection failure (net_rules.py names).
CONNECTIVITY_INCIDENT_TYPES: Final = frozenset(
    {
        "router_unreachable",
        "lan_unreachable",
        "lan_uplink_down",
        "uplink_down",
        "uplink_lost",
        "wan_down",
        "wan_unstable",
    }
)

SRC_TRAFFIC: Final = "traffic_analytics"
SRC_DIAG: Final = "net_diagnostics"
SRC_WIFI_RF: Final = "wifi_rf"
SRC_NI: Final = "network_intelligence"
SRC_SECURITY: Final = "security_center"
SOURCE_READY: Final = "ready"
SOURCE_MODULE_MISSING: Final = "module_missing"
SOURCE_NOT_READY: Final = "not_ready"
SOURCE_NO_DATA: Final = "no_data"
SOURCE_NOT_CONNECTED: Final = "not_connected"

REASON_MODULE_NOT_LOADED: Final = "module_not_loaded"
REASON_LOOKUP_FAILED: Final = "lookup_failed"
REASON_INTERFACE_MISMATCH: Final = "interface_mismatch"
REASON_READ_FAILED: Final = "read_failed"
REASON_MODULE_DISABLED: Final = "module_disabled"
REASON_UNKNOWN_STATE: Final = "unknown_module_state"
REASON_NO_ROUTER_SERIES: Final = "no_series_for_router"
REASON_TOO_FEW_SAMPLES: Final = "too_few_samples"
REASON_NO_REFERENCE: Final = "no_reference_window"
REASON_NO_COUNTER_DATA: Final = "no_counter_data"
REASON_NO_LINK_DATA: Final = "no_link_state_data"
REASON_NOT_LISTENING: Final = "incident_events_not_bound"
REASON_NO_INDICATOR_INTAKE: Final = "security_center_has_no_traffic_indicator_intake"
REASON_SINGLE_INDICATOR: Final = "single_indicator_only"
REASON_NOT_A_BOTTLENECK_ALONE: Final = "high_bandwidth_alone_proves_no_bottleneck"

ASSESS_HIGH_UTIL: Final = "high_utilization_observed"
ASSESS_BOTTLENECK: Final = "possible_bottleneck"
ASSESS_UPLINK_BOTTLENECK: Final = "possible_uplink_bottleneck"
ASSESS_LINK_QUALITY: Final = "possible_link_quality_issue"
ASSESS_WIFI_CONGESTION: Final = "possible_wifi_congestion"
ASSESS_WIFI_SINGLE: Final = "wifi_rf_indicator_observed"

VERDICT_FINDINGS: Final = "findings_present"
VERDICT_NOTHING_IN_COVERED: Final = "nothing_detected_in_covered_data"
VERDICT_INSUFFICIENT: Final = "insufficient_data"

# Security indicators (task §13): events with a stable evidence_ref.
EVENT_INDICATOR: Final = "traffic_analytics.indicator"
IND_UNUSUAL_VOLUME: Final = "unusual_traffic_volume"
IND_OUTBOUND: Final = "unusual_outbound_connections"
IND_NEW_DESTINATIONS: Final = "new_communication_destinations"
IND_PROTOCOL_MIX: Final = "changed_protocol_distribution"
IND_INTER_VLAN: Final = "unusual_inter_vlan_traffic"
IND_CONNECTION_RATE: Final = "suspicious_connection_rate"
INDICATORS: Final = (
    IND_OUTBOUND,
    IND_UNUSUAL_VOLUME,
    IND_NEW_DESTINATIONS,
    IND_PROTOCOL_MIX,
    IND_INTER_VLAN,
    IND_CONNECTION_RATE,
)
# Anomaly kinds (suffix) that become an "unusual volume" indicator.
VOLUME_INDICATOR_KINDS: Final = (
    "_volume",
    "_spike",
    "_sustained_high",
    "_night_activity",
)
INDICATOR_CLASSIFICATION: Final = "traffic_indicator"
INDICATOR_WORDING: Final = "traffic_deviation_not_an_attack"
INDICATOR_BUDGET_PER_HOUR: Final = 10
INDICATOR_POINT_KIND_S: Final = 6 * 3600.0
EVIDENCE_PREFIX: Final = "evr_"
EVIDENCE_HEX: Final = 16
MAX_EVIDENCE: Final = 100
# Evidence excerpt: the hour before the candidate opened (finest buckets).
EVIDENCE_EXCERPT_S: Final = 3600
MAX_EVIDENCE_ROWS: Final = 30

# Read API for other modules (acceptance criterion 11).
READ_API_VERSION: Final = 1
READ_WINDOWS: Final = {
    "5m": 300,
    "1h": 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "90d": 90 * 86400,
}
