/**
 * securityMock.ts — DEV ONLY mock backend of the security routes (?securitymock).
 *
 * A fake fetch answers the routes from in-memory sample data, and the REAL
 * client (createSecurityApi) runs on top of it, so paths, parsers and error
 * mapping are exercised as in production. main.tsx loads this file only
 * behind `import.meta.env.DEV`, so it is not part of the built bundle.
 *
 * Scenarios (?securitymock=<name>): default, nonadmin, off, empty,
 * notready (no module key: nothing recorded, device actions 409),
 * forbidden, gone, unavailable. All data is invented: MACs 02:00:00:…,
 * RFC 5737 addresses, example.org host names, no real routers or users.
 */

import { createSecurityApi } from './securityApi.ts';
import type { SecurityApi, SecurityHass } from './securityTypes';

export const MOCK_SCENARIOS = ['default', 'nonadmin', 'off', 'empty', 'notready', 'forbidden', 'gone', 'unavailable'] as const;

/** The keys the settings route accepts; anything else is a 400 like the backend. */
const SETTINGS_KEYS: ReadonlySet<string> = new Set(['enabled', 'log_path', 'syslog_port', 'thresholds', 'subnet_zones']);
export type MockScenario = (typeof MOCK_SCENARIOS)[number];

type Json = Record<string, unknown>;

const RID_A = `rtr_${'a1'.repeat(16)}`;
const RID_B = `rtr_${'b2'.repeat(16)}`;
const SEC = (n: number) => Math.floor(Date.now() / 1000) - n;
const MIN = 60;
const HOUR = 3600;

export function mockHass(scenario: string): SecurityHass {
  return {
    callApi: () => Promise.reject(new Error('mock: callApi not used')),
    user: { is_admin: scenario !== 'nonadmin' },
    auth: { data: { access_token: 'mock-token' } },
  };
}

interface DeviceRow extends Json { mac: string; state: string }

function build(scenario: string) {
  const admin = scenario !== 'nonadmin';
  const settings: Json = {
    enabled: scenario !== 'off', log_path: 'off', syslog_port: 5514,
    thresholds: {}, subnet_zones: scenario === 'default' ? { '192.0.2.0/24': 'lan', '198.51.100.0/24': 'iot' } : {},
  };
  // not ready: the center runs but records nothing (no module key of the core)
  const notReady = scenario === 'notready';
  const empty = scenario === 'empty';
  const noHints = empty || notReady;

  const incidents: Json[] = noHints ? [] : [
    {
      id: 'sec_0001aa', type: 'sec_wifi_auth_repeat', detector: 'wifi_auth_repeat', event_id: 'evt_1',
      category: 'wifi', severity: 'warning', assessment: 'noticeable', status: 'open', router_id: RID_A,
      client_ref: 'cli_demo_phone', has_client: true, first_seen: SEC(3 * HOUR), last_seen: SEC(12 * MIN), count: 14,
      evidence: ['window_s=300', 'login_failures=9', 'connected_after=False'],
      linked_incident_ids: ['inc_demo_roaming_1'], drift_refs: [],
      title: 'Wiederholte WLAN-Anmeldefehler eines Geräts',
      hint: 'Hinweis zur Prüfung; kein Beleg für eine Ursache.', resolved_at: null, from_logs: false,
    },
    {
      id: 'sec_0002bb', type: 'sec_vlan_segmentation_drift', detector: 'vlan_segmentation_drift', event_id: 'evt_2',
      category: 'vlan', severity: 'critical', assessment: 'suspicious', status: 'confirmed', router_id: RID_B,
      client_ref: null, has_client: false, first_seen: SEC(26 * HOUR), last_seen: SEC(25 * HOUR), count: 1,
      evidence: ['drift_id=drift_demo_1', 'areas=firewall+vlan'],
      linked_incident_ids: [], drift_refs: ['drift_demo_1'],
      title: 'Segmentierungsrelevante Konfigurationsänderung',
      hint: 'Konfigurationsänderung in einem segmentierungsrelevanten Bereich (firewall, vlan). Bitte prüfen, ob die Änderung geplant war.',
      resolved_at: null, from_logs: false,
    },
    {
      id: 'sec_0003cc', type: 'sec_wifi_assoc_burst', detector: 'wifi_assoc_burst', event_id: 'evt_3',
      category: 'wifi', severity: 'info', assessment: 'normal', status: 'resolved', router_id: RID_A,
      client_ref: 'cli_demo_tablet', has_client: true, first_seen: SEC(50 * HOUR), last_seen: SEC(49 * HOUR), count: 3,
      evidence: ['attempts=12'], linked_incident_ids: [], drift_refs: [],
      title: 'Auffällig viele WLAN-Verbindungsversuche', hint: 'Hinweis zur Prüfung; kein Beleg für eine Ursache.',
      resolved_at: SEC(48 * HOUR), from_logs: false,
    },
    {
      id: 'sec_0004dd', type: 'sec_fw_mgmt_access', detector: 'fw_mgmt_access', event_id: 'evt_4',
      category: 'firewall', severity: 'warning', assessment: 'noticeable', status: 'resolved', router_id: RID_B,
      client_ref: null, has_client: false, first_seen: SEC(80 * HOUR), last_seen: SEC(79 * HOUR), count: 4,
      evidence: ['dst_port=22', 'attempts=31'], linked_incident_ids: [], drift_refs: [],
      title: 'Zugriffsversuche auf die Router-Verwaltung', hint: 'Hinweis aus Logzeilen; Logzeilen können gefälscht sein.',
      resolved_at: SEC(70 * HOUR), from_logs: true,
    },
  ];
  const timeline: Json[] = noHints ? [] : [
    { ts: SEC(12 * MIN), kind: 'incident_reopened', category: 'wifi', severity: 'warning', router_id: RID_A, client_ref: 'cli_demo_phone', has_client: true, incident_id: 'sec_0001aa', type: null, drift_id: null, linked: [], text: 'Wiederholte WLAN-Anmeldefehler eines Geräts' },
    { ts: SEC(40 * MIN), kind: 'notice', category: 'device', severity: 'info', router_id: RID_A, client_ref: 'cli_demo_guest', has_client: true, incident_id: null, type: 'trust_new_device', drift_id: null, linked: [], text: 'Neues Gerät' },
    { ts: SEC(3 * HOUR), kind: 'incident_opened', category: 'wifi', severity: 'warning', router_id: RID_A, client_ref: 'cli_demo_phone', has_client: true, incident_id: 'sec_0001aa', type: null, drift_id: null, linked: ['inc_demo_roaming_1'], text: 'Wiederholte WLAN-Anmeldefehler eines Geräts' },
    { ts: SEC(25 * HOUR), kind: 'drift', category: 'config', severity: 'warning', router_id: RID_B, client_ref: null, has_client: false, incident_id: null, type: null, drift_id: 'drift_demo_1', linked: [], text: 'Konfigurationsänderung erkannt' },
    { ts: SEC(78 * HOUR), kind: 'log_quota_reached', category: 'system', severity: 'warning', router_id: null, client_ref: null, has_client: false, incident_id: null, type: null, drift_id: null, linked: [], text: 'Quote für Hinweise aus Logzeilen erreicht: weitere werden nur gezählt' },
  ];
  const devices: DeviceRow[] = empty ? [] : [
    { mac: '02:00:00:00:00:01', ip: '192.0.2.21', hostname: 'phone.example.org', name: 'Telefon Demo', state: 'known', first_seen: SEC(90 * 24 * HOUR), last_seen: SEC(5 * MIN), private_mac: true, confirmed: true, observed: true, indicators: [] },
    { mac: '02:00:00:00:00:02', ip: '192.0.2.22', hostname: null, name: null, state: 'suspicious', first_seen: SEC(2 * 24 * HOUR), last_seen: SEC(12 * MIN), private_mac: false, confirmed: false, observed: true, indicators: ['login_failures', 'ip_churn'] },
    { mac: '02:00:00:00:00:03', ip: '192.0.2.23', hostname: 'tablet.example.org', name: null, state: 'new', first_seen: SEC(40 * MIN), last_seen: SEC(10 * MIN), private_mac: true, confirmed: false, observed: true, indicators: [] },
    { mac: '02:00:00:00:00:04', ip: null, hostname: null, name: null, state: 'unrecognized', first_seen: SEC(30 * 24 * HOUR), last_seen: SEC(6 * 24 * HOUR), private_mac: false, confirmed: false, observed: false, indicators: [] },
  ];

  const refOf = (mac: string) => `cli_${mac.replace(/:/g, '').slice(-6)}`;
  const view = (d: DeviceRow): Json => admin ? { ...d } : {
    ...d, mac: refOf(d.mac), ip: d.ip ? 'ipa_demo01' : null, hostname: d.hostname ? 'hst_demo01' : null, name: null, name_set: d.name !== null,
  };

  const counts = () => {
    const c: Record<string, number> = { known: 0, new: 0, unrecognized: 0, suspicious: 0, quarantined: 0 };
    for (const d of devices) c[d.state] += 1;
    return c;
  };

  const detections: Json[] = [
    ...(['wifi_auth_repeat', 'wifi_auth_many_clients', 'wifi_assoc_burst', 'wifi_deauth_cluster', 'wifi_multi_ap_auth'] as const).map(id => ({
      id, description: id, availability: empty ? 'not_available' : id === 'wifi_deauth_cluster' ? 'limited' : 'available',
      reason: empty ? 'no_router' : '', missing: [], limitations: id === 'wifi_deauth_cluster' ? [] : [], learning: id === 'wifi_assoc_burst', format_unconfirmed: false,
    })),
    ...(['fw_blocked', 'fw_port_scan_hint', 'fw_mgmt_access', 'fw_inter_vlan'] as const).map(id => ({
      // fw4 confirmed live in 1.46.2: no "Format unbestätigt" mark any more
      id, description: id, availability: 'not_available', reason: 'disabled', missing: ['security.center.firewall_log'],
      limitations: [], learning: false, format_unconfirmed: false,
    })),
    { id: 'vlan_segmentation_drift', description: 'drift', availability: empty ? 'not_available' : 'available', reason: empty ? 'no_router' : '', missing: [], limitations: [], learning: false, format_unconfirmed: false },
    ...(['dns_rate', 'dns_nxdomain_cluster', 'dns_many_domains', 'dns_tunnel_hint'] as const).map(id => ({
      id, description: id, availability: 'not_available', reason: 'disabled', missing: ['security.center.dns_query_log'],
      limitations: [], learning: false, format_unconfirmed: true,
    })),
  ];
  if (!empty) {
    const d = detections.find(x => x.id === 'wifi_deauth_cluster')!;
    d.limitations = ['capacity'];
    d.reason = 'capacity';
  }

  const src = (source: string, availability: string, reason: string, lastOk: number | null): Json => ({ source, availability, reason, last_ok: lastOk });
  const sourcesFor = (): Json => empty ? {} : {
    [RID_A]: {
      'security.center.wifi_events': src('security.center.wifi_events', 'available', 'ok', SEC(MIN)),
      'data.hostapd_clients': src('data.hostapd_clients', 'available', 'ok', SEC(MIN)),
      'security.center.client_history': src('security.center.client_history', 'stale', 'stale', SEC(HOUR)),
      'security.center.firewall_log': src('security.center.firewall_log', 'not_available', 'disabled', null),
      'security.center.dns_query_log': src('security.center.dns_query_log', 'not_available', 'disabled', null),
    },
    [RID_B]: {
      'config.drift': src('config.drift', 'available', 'ok', SEC(5 * MIN)),
      'security.center.wifi_events': src('security.center.wifi_events', 'not_available', 'no_data_yet', null),
    },
  };

  // Fleet sources (1.46.2): N of M routers, the same numbers in the log path and the coverage list.
  const fleet = (): Json => ({
    'security.center.dns_query_log': { routers_delivering: 0, routers: empty ? 0 : 2, rate_limited: 0 },
    'security.center.firewall_log': { routers_delivering: 0, routers: empty ? 0 : 2, rate_limited: 0 },
  });
  const logPath = (): Json => ({
    setting: settings.log_path,
    status: [
      { ...src('security.center.firewall_log', 'not_available', settings.log_path === 'syslog' ? 'no_data_yet' : 'disabled', null),
        ...(fleet()['security.center.firewall_log'] as Json) },
      { ...src('security.center.dns_query_log', 'not_available', settings.log_path === 'syslog' ? 'no_data_yet' : 'disabled', null),
        ...(fleet()['security.center.dns_query_log'] as Json) },
    ],
    receiver: settings.log_path === 'syslog' ? { listening: true, reason: null, port: settings.syslog_port, senders: 1 } : null,
    rate_limited_routers: 0,
  });

  const overview = (): Json => ({
    enabled: settings.enabled, active: settings.enabled === true, admin_view: admin,
    ready: !notReady, not_ready_reason: notReady ? 'module_key_missing' : null,
    score: notReady
      ? { score: null, coverage: 57, cap: 79, reason: 'not ready: module_key_missing', factors: [], routers: 2 }
      : empty
      ? { score: null, coverage: 0, cap: 0, reason: 'unknown: no usable data source', factors: [], routers: 0 }
      : {
        score: 78, coverage: 57, cap: 79, reason: 'capped at 79: partial coverage', routers: 2,
        factors: [
          { id: 'active_incidents', weight: 40, deduction: 9, assessable: true, reason: '', value: 2, missing: [], partial: false, limitations: [] },
          { id: 'critical_config_changes', weight: 15, deduction: 0, assessable: true, reason: '', value: 0, missing: [], partial: false, limitations: [] },
          { id: 'login_failures', weight: 10, deduction: 3.5, assessable: true, reason: '', value: 1, missing: [], partial: true, limitations: ['capacity'] },
          { id: 'network_activity', weight: 15, deduction: null, assessable: false, reason: '', value: null, missing: ['security.center.firewall_log', 'security.center.dns_query_log'], partial: false, limitations: [] },
          { id: 'unknown_devices', weight: 10, deduction: 4, assessable: true, reason: '', value: 2, missing: [], partial: false, limitations: [] },
        ],
      },
    coverage: empty
      ? { value: 0, available: [], stale: [], missing: ['security.center.wifi_events', 'data.hostapd_clients', 'config.drift', 'security.center.firewall_log', 'security.center.dns_query_log'], fleet: fleet() }
      : { value: 57, available: ['security.center.wifi_events', 'data.hostapd_clients', 'config.drift'], stale: ['security.center.client_history'], missing: ['security.center.firewall_log', 'security.center.dns_query_log'], fleet: fleet() },
    incidents: incidents.map(i => admin ? { ...i, client: i.client_ref ? '02:00:00:00:00:02' : null, client_name: null } : { ...i }),
    timeline,
    devices: devices.map(view),
    device_counts: counts(),
    detections,
    log_path: logPath(),
    subnet_map: { state: 'configured', subnets: Object.keys(settings.subnet_zones as Json).length },
    module_key: !notReady,
    limits: {
      incident_cap: 100, incidents_cap_dropped: 0, log_incident_quota: 50,
      log_incidents: incidents.filter(i => i.from_logs === true).length,
      incidents_log_quota_dropped: noHints ? 0 : 12, other_incident_quota: 50,
      other_incidents: incidents.filter(i => i.from_logs !== true).length,
      incidents_other_quota_dropped: 0, events_throttled: 0,
    },
  });

  const settingsView = (): Json => ({
    settings: { ...settings, subnet_zones: admin ? settings.subnet_zones : {} },
    subnet_zone_count: Object.keys(settings.subnet_zones as Json).length,
    active: settings.enabled === true, can_edit: admin,
    receiver: settings.log_path === 'syslog' ? { listening: true, reason: null, port: settings.syslog_port, senders: 1 } : null,
  });

  return { admin, notReady, settings, incidents, timeline, devices, detections, overview, settingsView, sourcesFor, logPath };
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const err = (status: number, code: string, message = 'masked') => json(status, { message, code, details: {} });

export function createMockSecurityApi(scenario: string): SecurityApi {
  const m = build(scenario);
  const hass = mockHass(scenario);

  const fetchLike = async (url: string, init: RequestInit): Promise<Response> => {
    await new Promise(r => setTimeout(r, 150));
    if (scenario === 'forbidden') return err(403, 'authorization_denied');
    if (scenario === 'gone') return err(410, 'integration_not_loaded');
    if (scenario === 'unavailable') return err(503, 'not_running');
    const u = new URL(url, 'http://mock.invalid');
    const path = u.pathname.replace('/api/openwrt_topology/security/', '');
    const method = init.method ?? 'GET';
    const body = typeof init.body === 'string' ? (JSON.parse(init.body) as Json) : {};

    if (method === 'GET' && path === 'overview') {
      const o = m.overview();
      const q = u.searchParams;
      const since = q.has('since') ? Number(q.get('since')) : null;
      const sevRank: Record<string, number> = { info: 0, warning: 1, critical: 2 };
      const keep = (e: Json, key: string) => {
        const ts = e[key] as number;
        if (since !== null && ts < since) return false;
        if (q.get('router_id') && e.router_id !== q.get('router_id')) return false;
        if (q.get('category') && e.category !== q.get('category')) return false;
        if (q.get('client') && e.client_ref !== q.get('client') && e.client !== q.get('client')) return false;
        const sev = q.get('severity');
        return !sev || sevRank[e.severity as string] >= sevRank[sev];
      };
      o.timeline = (o.timeline as Json[]).filter(e => keep(e, 'ts'));
      o.incidents = (o.incidents as Json[]).filter(e => keep(e, 'last_seen'));
      return json(200, o);
    }
    if (method === 'GET' && path === 'detections') {
      return json(200, { enabled: m.settings.enabled, active: m.settings.enabled, detections: m.detections, sources: m.sourcesFor(), log_path: m.logPath() });
    }
    if (path === 'settings') {
      if (method === 'POST') {
        if (!m.admin) return err(403, 'authorization_denied');
        if (Object.keys(body).some(k => !SETTINGS_KEYS.has(k))) {
          return json(400, { message: 'masked', code: 'invalid_request', details: { field: 'body', reason: 'unknown_key' } });
        }
        if ('log_path' in body && body.log_path === 'collector') return err(400, 'invalid_request');
        Object.assign(m.settings, body);
      }
      return json(200, m.settingsView());
    }
    const inc = /^incidents\/(sec_[A-Za-z0-9_-]+)(\/status)?$/.exec(path);
    if (inc) {
      const found = m.incidents.find(i => i.id === inc[1]);
      if (!found) return err(404, 'unknown_incident');
      if (inc[2]) {
        if (!m.admin) return err(403, 'authorization_denied');
        found.status = body.status;
        return json(200, { incident: found });
      }
      return json(200, {
        admin_view: m.admin,
        incident: m.admin ? { ...found, client: found.client_ref ? '02:00:00:00:00:02' : null, client_name: null } : found,
        timeline: m.timeline.filter(t => t.incident_id === found.id), now: SEC(0),
      });
    }
    // the MAC comes in the body, like the backend (never in a path)
    const dev = /^devices\/(confirm|name)$/.exec(path);
    if (dev && method === 'POST') {
      if (!m.admin) return err(403, 'authorization_denied');
      if (typeof body.mac !== 'string') return err(400, 'invalid_request');
      if (m.notReady) return err(409, 'not_ready');
      const mac = body.mac;
      const row = m.devices.find(d => d.mac === mac);
      if (!row) return err(404, 'unknown_device');
      if (dev[1] === 'confirm') {
        row.state = 'known';
        row.confirmed = true;
        if (typeof body.name === 'string') row.name = body.name;
        return json(200, { confirmed: true });
      }
      row.name = (body.name as string | null) ?? null;
      return json(200, { named: row.name !== null });
    }
    return err(404, 'refused');
  };

  return createSecurityApi(() => hass, { fetch: fetchLike as never });
}
