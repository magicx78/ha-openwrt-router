// Example answers of the WiFi RF routes, shaped like rf_output.py (schema 1).
// Invented values only: no real router, no real MAC, SSID or BSSID. The
// PLANTED_* strings are put where a careless view could leak them; the tests
// check that none of them reaches the rendered DOM.

export const RID1 = 'rtr_' + '1'.repeat(32);
export const RID2 = 'rtr_' + '2'.repeat(32);
export const PLANTED_MAC = '02:00:00:00:02:01';
export const PLANTED_BSSID = '02:00:00:00:aa:01';
export const PLANTED_SSID = 'example-ssid';
export const PLANTED_IFNAME = 'phy1-ap0';
export const PLANTED = [PLANTED_MAC, PLANTED_MAC.toUpperCase(), PLANTED_BSSID, PLANTED_SSID, PLANTED_IFNAME];

const TS = 1795000000;

const base = (status = 'ready', reasons = []) => ({ schema: 1, status, reasons, generated_at: TS });

const metric = (value, state, source = 'iwinfo.info') => ({
  value, state, source, measured_at: state === 'measured' || state === 'stale' ? TS - 30 : null,
});

const health = (score, grade, coverage, withheld = []) => ({ score, grade, coverage, capped: false, withheld });

export function overviewReady() {
  return {
    ...base(),
    routers: [
      { router_id: RID1, enabled: true, status: 'ok', reason: null, radios: 2, reads: ['assoclist', 'get_status'],
        every_n_polls: 5, last_poll_at: TS - 20, health: health(72, 'good', 0.8), ssid: PLANTED_SSID },
      { router_id: RID2, enabled: true, status: 'source_unreachable', reason: 'capability_unavailable', radios: 1,
        reads: ['survey'], every_n_polls: 5, last_poll_at: null, health: health(null, 'unknown', 0.1) },
    ],
    monitoring_coverage: 0.4567,
    network_health: health(72, 'good', 0.8),
    counts: { radios: 3, clients: 12, conflicts: 1, conflicts_measured: 0, recommendations: 2 },
  };
}

export function overviewNotReady() {
  return {
    ...base('not_ready', ['module_key_missing', 'no_poll_data']),
    routers: [],
    monitoring_coverage: null,
    network_health: health(null, 'unknown', null, ['module_key_missing', 'no_poll_data']),
    counts: { radios: 0, clients: 0, conflicts: 0, conflicts_measured: 0, recommendations: 0 },
  };
}

export function overviewOff() {
  return {
    ...base('off'),
    routers: [],
    monitoring_coverage: null,
    network_health: health(null, 'unknown', null, ['no_evaluation']),
    counts: { radios: 0, clients: 0, conflicts: 0, conflicts_measured: 0, recommendations: 0 },
  };
}

function radio(routerId, radioId, band, channel, width, metrics, caps, extra = {}) {
  return {
    router_id: routerId, radio_id: radioId, radio_id_source: 'uci', band, channel, width_mhz: width,
    center_channel: channel, htmode: width > 20 ? `HE${width}` : 'HE20', backhaul: false, country: 'DE',
    interfaces: 1, measured_at: TS - 30, metrics,
    utilization: { reason: null, summary: { current: 41.5, mean: 38.25, peak: 77, valid_count: 9, invalid_count: 0, coverage: 0.9, phases: [], sustained_overload: false } },
    clients: { count: 5, problem_clients: 1, flagged_clients: 2, weak_persistent_clients: 0, signal_coverage: 1, retry_coverage: 0.8 },
    capabilities: { router_id: routerId, radio_id: radioId, states: caps, excluded: [], coverage: 0.6 },
    health: { ...health(64, 'fair', 0.7), components: [], evidence: [`client:${PLANTED_MAC}`] },
    load: { ref: { router_id: routerId, radio_id: radioId }, status: 'elevated', evidence: [], confidence: 0.5 },
    sources: { assoclist: { state: 'measured', reason: null }, get_status: { state: 'measured', reason: null } },
    roams_1h: 3,
    // fields a careless view could print (the backend never sends them)
    ssid: PLANTED_SSID, bssid: PLANTED_BSSID, ifname: PLANTED_IFNAME,
    ...extra,
  };
}

const CAPS_FULL = {
  channel: 'measured', width: 'measured', txpower: 'measured', txpower_max: null, noise: 'measured',
  busy_time: 'measured', active_time: 'measured', rx_time: null, tx_time: null, utilization: 'measured',
  client_airtime: 'measured', clients: 'measured', rssi: 'measured', rate: 'measured', retries: 'measured',
  failed: 'measured', connected_time: 'measured', freqlist: 'no_data', country: 'measured', scan: 'unsupported',
};

export function radiosReady() {
  return {
    ...base(),
    radios: [
      radio(RID1, 'radio0', '2.4g', 6, 20, {
        utilization: metric(41.5, 'measured', 'hostapd.get_status'),
        noise: metric(-95, 'measured'),
        txpower: metric(20, 'measured'),
        retry_rate: metric(0.153, 'measured', 'iwinfo.assoclist'),
        signal_quality: metric(53, 'measured', 'hostapd.get_clients'),
        rssi_mean: metric(-70.5, 'measured', 'hostapd.get_clients'),
        airtime_top_client: metric(1234.5, 'measured', 'hostapd.get_clients'),
      }, CAPS_FULL),
      radio(RID1, 'radio1', '5g', 36, 80, {
        utilization: metric(null, 'unsupported', 'hostapd.get_status'),
        noise: metric(-92, 'stale'),
        txpower: metric(null, 'no_data'),
        retry_rate: metric(null, 'unreachable', 'iwinfo.assoclist'),
        signal_quality: null,
        rssi_mean: null,
        airtime_top_client: metric(null, 'no_data', 'hostapd.get_clients'),
      }, { ...CAPS_FULL, utilization: 'unsupported', retries: 'unreachable', noise: 'stale' }, {
        clients: { count: 0, problem_clients: null, flagged_clients: 0, weak_persistent_clients: 0, signal_coverage: null, retry_coverage: null },
        health: health(null, 'unknown', 0.1, []),
        roams_1h: null,
        width_mhz: null,
      }),
    ],
  };
}

export function channelMapReady() {
  return {
    ...base(),
    bands: {
      '2.4g': [
        { router_id: RID1, radio_id: 'radio0', channel: 6, width_mhz: 20, center_channel: 6, backhaul: false, client_count: 5,
          utilization: metric(41.5, 'measured', 'hostapd.get_status'), ssid: PLANTED_SSID, bssid: PLANTED_BSSID },
        { router_id: RID2, radio_id: 'radio0', channel: 6, width_mhz: 20, center_channel: 6, backhaul: true, client_count: 1,
          utilization: null },
      ],
      '5g': [
        { router_id: RID1, radio_id: 'radio1', channel: 36, width_mhz: 80, center_channel: 42, backhaul: false, client_count: 0,
          utilization: metric(null, 'unsupported', 'hostapd.get_status') },
      ],
    },
    conflicts: [
      { kind: 'co_channel', band: '2.4g', members: [{ router_id: RID1, radio_id: 'radio0' }, { router_id: RID2, radio_id: 'radio0' }],
        status: 'potential', severity: 'info', evidence: [`same_channel:6`, `heard:${PLANTED_BSSID}`] },
    ],
  };
}

export function recommendationsReady() {
  return {
    ...base(),
    recommendations: [
      { kind: 'channel', target: { router_id: RID1, radio_id: 'radio0' }, scope: 'radio', problem: 'sustained_high_utilization',
        evidence: ['utilization:ch6:78.4%', `client:${PLANTED_MAC}`], action: 'change_channel',
        action_params: { channel: 11, width_mhz: 20, basis: 'lower_observed_utilization' },
        expected_effect: 'lower_channel_utilization', confidence: 0.7, risk: ['clients_reconnect_on_change'], requires: [],
        basis: 'lower_observed_utilization', priority: 'normal' },
      { kind: 'load', target: null, scope: 'network', problem: 'band_imbalance', evidence: ['per_band:2.4g=10,5g=2'],
        action: 'review_band_settings', action_params: {}, expected_effect: 'none_without_admin_review', confidence: 0.3,
        risk: [], requires: ['utilization'], basis: null, priority: 'low' },
    ],
    load: { aps: [
      { router_id: RID1, status: 'elevated', radios: [], evidence: [], confidence: 0.5 },
      { router_id: RID2, status: 'unknown', radios: [], evidence: [], confidence: 0 },
    ] },
    distribution: { per_ap: { [RID1]: 10, [RID2]: 2 }, per_band: { '2.4g': 10, '5g': 2 }, total: 12, coverage: 1,
      largest_ap: RID1, largest_share: 0.8333, max_over_median: 1.5, findings: [], evidence: [] },
  };
}

function points(values) {
  return values.map((mean, i) => ({ ts: TS - (values.length - i) * 60, mean, min: mean, max: mean, count: mean === null ? 0 : 1, invalid: 0 }));
}

export function timelineReady() {
  return {
    ...base(),
    window: '1h',
    radios: [
      { router_id: RID1, radio_id: 'radio0', series: {
        utilization: { window_s: 3600, resolution_s: 60, source: 'raw', coverage: 0.8, points: points([10.5, 20, null, 35.25, 40]) },
      } },
      { router_id: RID1, radio_id: 'radio1', series: {
        utilization: { window_s: 3600, resolution_s: 60, source: 'raw', coverage: 0, points: points([null, null, null]) },
      } },
    ],
  };
}

export function roamingCounts() {
  return {
    ...base(),
    window_s: 3600,
    per_radio: [{ router_id: RID1, radio_id: 'radio0', roams: 3 }, { router_id: RID1, radio_id: 'radio1', roams: 0 }],
    events: null,
    events_restricted: 'admin_only',
  };
}

export function roamingApproved() {
  return {
    ...roamingCounts(),
    events: [
      { client_ref: 'cli_' + 'a'.repeat(16), from: { router_id: RID1, radio_id: 'radio0' }, to: { router_id: RID2, radio_id: 'radio0' },
        at: TS - 120, gap_s: 3.2, mac: PLANTED_MAC },
      { client_ref: PLANTED_MAC, from: null, to: { router_id: RID1, radio_id: 'radio1' }, at: TS - 60, gap_s: null },
    ],
    events_restricted: null,
  };
}

export const SAMPLE_TS = TS;
