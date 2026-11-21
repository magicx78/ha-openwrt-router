// Example answers of the Traffic Analytics routes, shaped like
// traffic_output.py (v 1). Invented values only: no real router, no real
// MAC or host name. The PLANTED_* strings are put where a careless view
// could leak them; the tests check that none reaches the rendered DOM.

export const RID1 = 'rtr_' + 'a1'.repeat(16);
export const RID2 = 'rtr_' + 'b2'.repeat(16);
export const WAN1 = 'tpt_' + '1'.repeat(16);
export const LAN1 = 'tpt_' + '2'.repeat(16);
export const CLI1 = 'cli_' + 'c0ffee'.padEnd(16, '0');
export const PLANTED_MAC = '02:00:00:00:02:01';
export const PLANTED_IFNAME = 'phy1-ap0';
export const PLANTED = [PLANTED_MAC, PLANTED_MAC.toUpperCase(), PLANTED_IFNAME];

export const TS = 1800001010;

const base = (status = 'ready', reasons = []) => ({ v: 1, status, reasons, generated_at: TS });
const dirWan = { perspective: 'router', rx_means: 'received_from_the_line', tx_means: 'sent_to_the_line', download: 'rx', upload: 'tx', reason: null };
const dirBridge = { perspective: 'router', rx_means: 'received_by_the_router', tx_means: 'sent_by_the_router', download: null, upload: null, reason: 'bridged_traffic_not_counted' };

const rate = (over = {}) => ({
  point_id: WAN1, router_id: RID1, scope: 'wan', device: 'wan', vlan_id: null, client_ref: null,
  rx_bps: 80_000_000, tx_bps: 9_000_000, down_bps: 80_000_000, up_bps: 9_000_000, direction: dirWan,
  quality: 'ok', coverage: 'partial', coverage_reason: 'hw_offload_unknown', interval_s: 60, wall_s: TS, ...over,
});

export function off() {
  return { ...base('off', ['disabled']) };
}

export function overviewReady() {
  return {
    ...base(),
    coverage: { points: 3, full: 1, partial: 2, estimated: 0, unavailable: 0, unknown: 0, full_share: 0.33, reasons: { hw_offload_unknown: 2 } },
    wan: [rate()],
    wan_total: { scope: 'wan', refused: null, rx_bps: 80_000_000, tx_bps: 9_000_000, rx_bytes: 1, tx_bytes: 1, coverage: 'partial', coverage_reasons: ['hw_offload_unknown'], notes: ['rx_tx_never_combined'], contributing: 1, omitted: 0, omitted_by_quality: {}, routers: 1 },
    wan_24h: [{
      v: 1, point_id: WAN1, router_id: RID1, scope: 'wan', device: 'wan', state: 'available', reason: null,
      window_s: 86400, resolution_s: 3600, rx_bytes: 52_000_000_000, tx_bytes: 4_000_000_000,
      avg_rx_bps: 4_800_000, avg_tx_bps: 370_000, peak_rx_bps: 95_000_000, peak_tx_bps: 20_000_000,
      download: 'rx', upload: 'tx', time_coverage: 0.98, coverage: 'partial', reasons: ['hw_offload_unknown'],
    }],
    talkers_top: {
      scope: 'client', window: '1h', window_s: 3600, direction: 'download', metric: 'bytes', state: 'available', reason: null,
      partial: true, partial_reasons: ['station_counters_only'],
      rows: [talkerRow()], considered: 4, omitted: {}, total: null, limit: 5,
    },
    anomalies: {
      open: 1, ended: 2, suppressed: 0,
      families: {
        spikes: { state: 'active', reason: null },
        inter_vlan: { state: 'unavailable', reason: 'needs_flow_source' },
        port_errors: { state: 'covered_by_network_intelligence', reason: 'network_intelligence_rule:lan_port_errors' },
      },
    },
    interfaces: [
      { ...rate(), link_mbps: 1000, duplex: 'full', utilization_pct: 8, utilization_reason: null },
      { ...rate({ point_id: LAN1, scope: 'port', device: 'lan1', direction: dirBridge, down_bps: null, up_bps: null, rx_bps: 1000, tx_bps: 2000 }), link_mbps: null, duplex: null, utilization_pct: null, utilization_reason: 'link_speed_unknown' },
    ],
    vlans: [],
    flow_sources: [
      { source: 'collector', state: 'unavailable', reason: 'collector_interface_not_built' },
      { source: 'conntrack_count', state: 'unavailable', reason: 'count_file_not_seen', routers: 0, note: 'count_only_no_flows' },
    ],
    correlation_sources: [
      { module: 'net_diagnostics', state: 'ready', reason: null },
      { module: 'wifi_rf', state: 'not_ready', reason: 'interface_mismatch' },
      { module: 'security_center', state: 'not_connected', reason: 'security_center_has_no_traffic_indicator_intake' },
    ],
    routers: [{ router_id: RID1, devices: 5, stations: null, conntrack_count: null }],
    drops: { dropped_points_infra: 0, late_rates: 3 },
    history: { profile: 'standard', fine_bytes: 1_200_000, coarse_bytes: null, day_boundary: 'utc' },
  };
}

export function talkerRow(over = {}) {
  return {
    rank: 1, point_id: 'tpt_' + '3'.repeat(16), scope: 'client', router_id: RID2, client_ref: CLI1,
    device: PLANTED_IFNAME, vlan_id: 20, counter: 'tx', value: 3_500_000_000, observed_bytes: 3_500_000_000,
    peak_bps: 40_000_000, measuring_area: 'station_counters', coverage: 'partial', coverage_reasons: ['station_counters_only'],
    time_coverage: 0.9, share_pct: null, share_reason: 'share_reference_not_fully_covered', last_active: TS - 30, ...over,
  };
}

export function talkers(kind = 'window') {
  return {
    ...base(), kind, scope: 'client', window: kind === 'current' ? null : '24h', window_s: 86400, direction: 'download',
    metric: kind === 'current' ? 'bps' : kind === 'peaks' ? 'episodes' : 'bytes', state: 'available', reason: null,
    partial: true, partial_reasons: ['station_counters_only'],
    rows: [talkerRow(), talkerRow({ rank: 2, point_id: LAN1, scope: 'port', client_ref: null, device: 'lan1', vlan_id: null, value: 1_000_000, router_id: RID1 })],
    considered: 7, omitted: { scope_not_ranked: 2 }, total: null, limit: 20,
  };
}

export function points() {
  return {
    ...base(), total: 2, truncated: false,
    points: [
      { point_id: LAN1, router_id: RID1, scope: 'port', device: 'lan1', vlan_id: null, client_ref: null, coverage: 'partial', quality: 'ok', last_seen: TS },
      { point_id: WAN1, router_id: RID1, scope: 'wan', device: 'wan', vlan_id: null, client_ref: null, coverage: 'partial', quality: 'ok', last_seen: TS },
      { point_id: 'bogus', router_id: RID1, scope: 'wan', device: PLANTED_MAC },
    ],
  };
}

const DAY = 86400;
export function seriesDays() {
  const end = Math.floor(TS / DAY) * DAY;
  const buckets = [];
  for (let i = 4; i >= 0; i -= 1) {
    buckets.push({ ts: end - i * DAY, rx_bytes: i === 2 ? null : 10_000_000_000 + i, tx_bytes: i === 2 ? null : 1_000_000_000, rx_peak_bps: 90_000_000, tx_peak_bps: 9_000_000, coverage: i === 2 ? 0 : 1 });
  }
  return {
    ...base('not_ready', ['core_missing']), point_id: WAN1, window: '30d', router_id: RID1, scope: 'wan', device: 'wan',
    vlan_id: null, client_ref: null, state: 'available', reason: null, window_s: 30 * DAY, end: end + DAY, resolution_s: DAY,
    rx_bytes: 40_000_000_000, tx_bytes: 4_000_000_000, avg_rx_bps: 3_700_000, avg_tx_bps: 370_000, peak_rx_bps: 90_000_000,
    peak_tx_bps: 9_000_000, download: 'rx', upload: 'tx', perspective: 'router', time_coverage: 0.13, coverage: 'partial',
    window_reasons: ['history_shorter_than_window'], point: { point_id: WAN1, router_id: RID1, scope: 'wan' },
    direction: dirWan, utc_days: true, buckets,
  };
}

export function seriesHours() {
  const s = seriesDays();
  return { ...s, window: '24h', resolution_s: 3600, utc_days: false, buckets: s.buckets.map((b, i) => ({ ...b, ts: TS - (5 - i) * 3600 })) };
}

export function seriesUnknown() {
  return { ...base(), point_id: WAN1, window: '1h', state: 'unavailable', reason: 'unknown_point', buckets: [] };
}

export function clients() {
  return {
    ...base(), total: 1, truncated: false,
    clients: [{
      client_ref: CLI1, link: 'wifi', identity: 'registry', value_kind: 'station', perspective: 'client', router_id: RID2,
      radio_id: PLANTED_IFNAME, location_source: 'station_counters', port: null, down_bps: 12_000_000, up_bps: null,
      down_bytes: 900_000_000, up_bytes: 80_000_000, covered_s: 7200, avg_down_bps: null, avg_up_bps: null,
      max_down_bps: null, max_up_bps: null, vlan_id: null, coverage: 'partial', coverage_reasons: ['station_counters_only'],
      windows: {}, wan_attribution: { coverage: 'unavailable', reason: 'needs_flow_source' }, roaming_gaps: 1,
      interruptions: 0, stale_sightings: 0, last_seen_wall: TS - 10,
      unavailable: { up_bps: 'no_rate_yet', vlan_id: 'no_wifi_vlan_mapping' },
    }],
  };
}

export function vlans() {
  return {
    ...base(),
    vlans: [{
      router_id: RID1, vlan_id: 20, measured: [{ point_id: LAN1 }], rx_bps: 1_000_000, tx_bps: null, rx_bytes: null, tx_bytes: null,
      coverage: 'partial', coverage_reasons: ['hw_offload_unknown'], direction: dirBridge, configured_ports: ['lan2', 'lan3'],
      inter_vlan: { coverage: 'unavailable', reason: 'needs_flow_source' }, wan_related: { coverage: 'unavailable', reason: 'wan_same_router' },
      active_clients: null, active_clients_coverage: 'unknown', active_clients_basis: null,
      unavailable: { tx_bps: 'no_rate_yet', active_clients: 'no_client_vlan_source' },
    }],
  };
}

export function capacity() {
  return {
    ...base(),
    rows: [{
      point_id: WAN1, scope: 'wan', router_id: RID1, device: 'wan', vlan_id: null, link_mbps: 100, duplex: 'full', uplink: true,
      window_s: 7 * DAY, usable_buckets: 160, gappy_buckets: 8, time_coverage: 0.95, p95_estimated: true,
      directions: [
        { counter: 'rx', meaning: 'download', avg_bps: 30_000_000, peak_bps: 98_000_000, p95_bps: 85_000_000, avg_pct: 30, peak_pct: 98, p95_pct: 85, unavailable: {} },
        { counter: 'tx', meaning: 'upload', avg_bps: null, peak_bps: null, p95_bps: null, avg_pct: null, peak_pct: null, p95_pct: null, unavailable: { avg_bps: 'insufficient_data', p95_pct: 'insufficient_data' } },
      ],
      shared_p95_pct: null, near_capacity_days: 3, state: 'approaching_capacity', reasons: ['p95_from_coarse_buckets'],
      trend: { state: 'estimated', reason: null, method: 'theil_sen_daily_mean', estimate: true, basis_days: 20, span_days: 21, slope_bps_per_day: 1, slope_pct_per_week: 1.5, level_bps: 1, days_to_near_capacity: 40, days_to_near_capacity_reason: null, confidence: 0.6 },
    }],
  };
}

export function recommendations() {
  return {
    ...base(), verdict: 'findings_present', points_evaluated: 3, points_insufficient: 1,
    findings: [{
      finding_id: 'tcf_' + '9'.repeat(16), router_id: RID1, point_id: WAN1, scope: 'wan', assessment: 'possible_uplink_bottleneck',
      wording: 'possible', observations: [
        { indicator: 'utilization_high', family: 'utilization', elevated: true, value: 92.5, unit: 'pct', threshold: 80, window_s: 3600, start: TS - 3600, end: TS, source: 'traffic', detail: {} },
        { indicator: 'latency_elevated', family: 'path_quality', elevated: true, value: 85, unit: 'ms', threshold: 50, window_s: 3600, start: TS - 3600, end: TS, source: 'net_diagnostics', detail: {} },
      ],
      independent_families: ['utilization', 'path_quality'], possible_causes: ['upstream_congestion'],
      recommendations: ['check_wan_capacity', 'check_sqm_configuration'], recommendation_withheld: null, confidence: 0.6,
      coverage: {}, unmeasured: { wifi_rf: 'module_disabled' }, incident_refs: [], window_s: 3600, start: TS - 3600, end: TS,
    }],
    sources: [
      { module: 'traffic_analytics', state: 'ready', reason: null },
      { module: 'wifi_rf', state: 'module_disabled', reason: 'module_disabled' },
    ],
  };
}

export function anomalies() {
  return {
    ...base(), total: 1,
    rows: [{
      candidate_id: 'tac_' + '7'.repeat(16), point_id: WAN1, router_id: RID1, client_ref: null, kind: 'download_spike',
      observed: 90_000_000, baseline_median: 10_000_000, threshold: 40_000_000, window_s: 300, confidence: 0.5,
      coverage: 'partial', started: TS - 600, last_seen: TS - 300, state: 'open', suppressed_reason: null, incident_ref: null,
    }],
    families: { spikes: { state: 'active', reason: null }, connection_rate: { state: 'unavailable', reason: 'conntrack_source_not_count_file' } },
    incident_engine: { state: 'not_connected', reason: 'net_engine_has_no_candidate_api' },
  };
}

export function flows() {
  return {
    ...base(), source: { state: 'unavailable', reason: 'needs_flow_source', feeds: 0, records: 0 }, rows: [], complete: false,
    notes: ['empty_is_not_no_traffic', 'invisible_is_unknown'],
    sources: [{ source: 'collector', state: 'unavailable', reason: 'collector_interface_not_built' }],
  };
}
