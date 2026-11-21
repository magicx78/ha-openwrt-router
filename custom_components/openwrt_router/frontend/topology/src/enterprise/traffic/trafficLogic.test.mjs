// Tests of the pure Traffic Analytics logic (node:test, no dependencies).
// Node strips the TypeScript types of the imported .ts files itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DASH, POLL_MIN_MS, SECTIONS, SERIES_WINDOWS, TAB_ID, TAB_ORDER, TAB_TITLE, TrafficApiError,
  anomalyKindText, bucketLabel, clientLabel, coverageView, errorInfo, fmtBytes, fmtPct, fmtRate, historyPoints,
  overviewTiles, parseAnomalies, parseCapacity, parseClients, parseFlows, parseOverview, parsePoints,
  parseRecommendations, parseSeries, parseTalkers, parseVlans, pointLabel, rateParts, reasonText, safeText,
  sectionsFor, seriesCharts, seriesQuery, shouldFetch, sourceStateView, statusView, talkerQuery, talkerValue,
  trendText, utcDayNote, windowFacts,
} from './trafficLogic.ts';
import * as S from './trafficSamples.mjs';

test('tab identity: order 50 under Enterprise, after WiFi (40)', () => {
  assert.equal(TAB_ID, 'traffic');
  assert.equal(TAB_TITLE, 'Traffic Analytics');
  assert.equal(TAB_ORDER, 50);
});

test('the sections are the Phase J views; Flows only for administrators', () => {
  assert.deepEqual(SECTIONS.map(s => s.title),
    ['Übersicht', 'Verlauf', 'Top Talkers', 'Clients & VLANs', 'Anomalien', 'Kapazität', 'Flows']);
  assert.ok(!sectionsFor(false).some(s => s.id === 'flows'));
  assert.ok(sectionsFor(true).some(s => s.id === 'flows'));
});

test('polling: never faster than 60 s and only while visible', () => {
  assert.equal(POLL_MIN_MS, 60_000);
  assert.equal(shouldFetch({ visible: false, lastMs: null, nowMs: 0, intervalMs: 1 }), false);
  assert.equal(shouldFetch({ visible: true, lastMs: 0, nowMs: 59_999, intervalMs: 1000 }), false);
  assert.equal(shouldFetch({ visible: true, lastMs: 0, nowMs: 60_000, intervalMs: 1000 }), true);
});

test('unknown is a dash, never 0', () => {
  for (const f of [fmtRate, fmtBytes, fmtPct]) {
    assert.equal(f(null), DASH);
    assert.equal(f(undefined), DASH);
    assert.equal(f(Number.NaN), DASH);
  }
  assert.equal(talkerValue('bytes', null), DASH);
  assert.notEqual(fmtRate(0), DASH); // a measured 0 is a value
});

test('overview parses; a missing part makes the WAN sum unknown, not smaller', () => {
  const o = parseOverview(S.overviewReady());
  assert.equal(o.status, 'ready');
  assert.equal(o.wan[0].downBps, 80_000_000);
  assert.equal(o.interfaces[1].utilizationPct, null);
  assert.equal(o.interfaces[1].utilizationReason, 'link_speed_unknown');
  assert.equal(o.history.dayBoundary, 'utc');
  assert.equal(o.history.coarseBytes, null);
  assert.deepEqual(o.drops, [{ code: 'late_rates', count: 3 }]);
  const tiles = overviewTiles(o);
  assert.equal(tiles[0].known, true);
  assert.match(tiles[0].text, /Mbit\/s/);
  const raw = S.overviewReady();
  raw.wan.push({ ...raw.wan[0], point_id: 'tpt_' + '4'.repeat(16), down_bps: null });
  assert.equal(overviewTiles(parseOverview(raw))[0].text, DASH);
  const refused = S.overviewReady();
  refused.wan_total.refused = 'mixed_scopes';
  assert.equal(overviewTiles(parseOverview(refused))[0].known, false);
});

test('bridged traffic shows rx / tx, never a guessed download', () => {
  const o = parseOverview(S.overviewReady());
  const parts = rateParts(o.interfaces[1]);
  assert.deepEqual(parts.map(p => p.name), ['Empfangen (rx)', 'Gesendet (tx)']);
  assert.deepEqual(rateParts(o.wan[0]).map(p => p.name), ['Download', 'Upload']);
});

test('sources: not-available reasons are visible (WiFi RF, Security Center)', () => {
  const o = parseOverview(S.overviewReady());
  const wifi = o.correlationSources.find(s => s.name === 'wifi_rf');
  assert.equal(wifi.reason, 'interface_mismatch');
  assert.equal(sourceStateView(wifi.state).tone, 'warn');
  const sec = o.correlationSources.find(s => s.name === 'security_center');
  assert.equal(sec.state, 'not_connected');
  assert.equal(sourceStateView('module_disabled').label, 'ausgeschaltet');
  assert.notEqual(sourceStateView('not_connected').tone, 'ok');
  assert.notEqual(coverageView('unknown').tone, 'ok');
  assert.notEqual(coverageView(null).tone, 'ok');
});

test('status view: off is muted, not_ready shows its reasons', () => {
  assert.equal(statusView('off', ['disabled']).tone, 'muted');
  assert.match(statusView('not_ready', ['core_missing']).hint, /Enterprise Core/);
  assert.equal(parseOverview(S.off()).status, 'off');
});

test('series: UTC days are labelled in local time and say so; gaps stay gaps', () => {
  const s = parseSeries(S.seriesDays());
  assert.equal(s.utcDays, true);
  assert.equal(s.buckets.length, 5);
  assert.deepEqual(s.windowReasons, ['history_shorter_than_window']);
  const label = bucketLabel(s.buckets[0].ts, true);
  assert.match(label, /UTC-Tag/);
  assert.match(label, /Ortszeit/);
  assert.match(utcDayNote(s.buckets[0].ts), /UTC-Tage/);
  const [down, up] = seriesCharts(s);
  assert.equal(down.label, 'Download');
  assert.equal(up.label, 'Upload');
  assert.equal(down.points[2].mean, null); // never 0
  assert.equal(down.known, 4);
  const hours = parseSeries(S.seriesHours());
  assert.equal(hours.utcDays, false);
  assert.doesNotMatch(bucketLabel(hours.buckets[0].ts, false), /UTC/);
  assert.equal(parseSeries(S.seriesUnknown()).summary, null);
});

test('series: at most 500 buckets are kept', () => {
  const raw = S.seriesDays();
  raw.buckets = Array.from({ length: 800 }, (_, i) => ({ ts: 1_800_000_000 + i * 300, rx_bytes: i, tx_bytes: i, coverage: 1 }));
  assert.equal(parseSeries(raw).buckets.length, 500);
});

test('window facts name download/upload only when the direction is known', () => {
  const s = parseSeries(S.seriesDays());
  assert.ok(windowFacts(s.summary).some(f => f.name === 'Download gesamt'));
  const raw = S.seriesDays();
  raw.download = null; raw.upload = null;
  const facts = windowFacts(parseSeries(raw).summary);
  assert.ok(facts.every(f => !/Download|Upload/.test(f.name)));
});

test('points: invalid ids are dropped; WAN first', () => {
  const p = parsePoints(S.points());
  assert.equal(p.points.length, 2);
  assert.equal(historyPoints(p)[0].scope, 'wan');
});

test('talkers, clients, vlans, capacity, anomalies, recommendations, flows parse', () => {
  const t = parseTalkers(S.talkers());
  assert.equal(t.rows.length, 2);
  assert.equal(t.rows[0].sharePct, null);
  assert.equal(t.rows[0].shareReason, 'share_reference_not_fully_covered');
  assert.deepEqual(t.omitted, [{ code: 'scope_not_ranked', count: 2 }]);
  assert.equal(talkerValue('bps', 1_000_000), fmtRate(1_000_000));
  const c = parseClients(S.clients());
  assert.equal(c.clients[0].upBps, null);
  assert.ok(c.clients[0].unavailable.some(u => u.field === 'up_bps'));
  assert.ok(!('radioId' in c.clients[0]));
  const v = parseVlans(S.vlans());
  assert.equal(v.vlans[0].configuredPorts, 2);
  assert.equal(v.vlans[0].interVlan.reason, 'needs_flow_source');
  const cap = parseCapacity(S.capacity());
  assert.equal(cap.rows[0].directions[1].p95Pct, null);
  assert.match(trendText(cap.rows[0].trend), /Schätzung/);
  assert.match(trendText({ state: 'insufficient_data', reason: 'trend_series_too_short' }), /^—/);
  const a = parseAnomalies(S.anomalies());
  assert.equal(a.rows[0].state, 'open');
  assert.equal(a.incidentEngine.state, 'not_connected');
  assert.equal(anomalyKindText('download_spike'), 'Download: Spitze');
  assert.equal(anomalyKindText('rx_night_activity'), 'Empfangen (rx): Nachtaktivität');
  const r = parseRecommendations(S.recommendations());
  assert.equal(r.findings[0].assessment, 'possible_uplink_bottleneck');
  assert.equal(r.findings[0].unmeasured[0].reason, 'module_disabled');
  const f = parseFlows(S.flows());
  assert.equal(f.source.state, 'unavailable');
  assert.ok(f.notes.includes('empty_is_not_no_traffic'));
});

test('parsers survive junk without throwing', () => {
  for (const p of [parseOverview, parsePoints, parseSeries, parseTalkers, parseClients, parseVlans, parseCapacity,
    parseAnomalies, parseRecommendations, parseFlows]) {
    for (const junk of [null, undefined, 1, 'x', [], { rows: 'x', points: {}, buckets: [null, 1] }]) p(junk);
  }
});

test('labels: pseudonyms only, MACs masked, WLAN netdev names hidden', () => {
  assert.equal(clientLabel(S.CLI1), 'Client c0ffee');
  assert.equal(clientLabel('aa:bb'), 'Client');
  assert.equal(safeText(S.PLANTED_IFNAME), 'WLAN-Schnittstelle');
  assert.equal(safeText(`x ${S.PLANTED_MAC}`), 'x [MAC]');
  assert.equal(pointLabel({ scope: 'port', device: 'lan1', vlanId: 20 }), 'Port lan1 · VLAN 20');
  assert.equal(pointLabel({ scope: 'client', device: S.PLANTED_IFNAME, vlanId: null, clientRef: S.CLI1 }), 'Client c0ffee');
  assert.doesNotMatch(reasonText(`weird_${S.PLANTED_MAC}`), /02:00/);
  assert.equal(reasonText('network_intelligence_rule:lan_port_errors'), 'durch Network Intelligence abgedeckt');
});

test('queries: only the fixed lists; a bad query never builds', () => {
  assert.deepEqual(SERIES_WINDOWS, ['1h', '24h', '7d', '30d', '90d']);
  assert.equal(seriesQuery({ pointId: S.WAN1, window: '7d' }), `point_id=${S.WAN1}&window=7d`);
  assert.throws(() => seriesQuery({ pointId: 'tpt_x', window: '7d' }), TrafficApiError);
  assert.throws(() => seriesQuery({ pointId: S.WAN1, window: '5m' }), TrafficApiError);
  assert.equal(talkerQuery({ kind: 'window', scope: 'client', window: '24h', direction: 'download', limit: 20 }),
    'kind=window&scope=client&direction=download&limit=20&window=24h');
  assert.equal(talkerQuery({ kind: 'current', scope: 'wan', window: '24h', direction: 'upload', limit: 5 }),
    'kind=current&scope=wan&direction=upload&limit=5');
  for (const bad of [{ kind: 'x' }, { scope: 'flow' }, { window: '90d' }, { direction: 'both' }, { limit: 51 }, { limit: 0 }]) {
    assert.throws(() => talkerQuery({ kind: 'window', scope: 'client', window: '1h', direction: 'download', limit: 10, ...bad }), TrafficApiError, JSON.stringify(bad));
  }
});

test('errors map from status and code, never from server text', () => {
  assert.equal(errorInfo(new TrafficApiError(403, 'forbidden')).kind, 'forbidden');
  assert.equal(errorInfo(new TrafficApiError(503, 'not_running')).kind, 'unavailable');
  assert.equal(errorInfo(new TrafficApiError(410, 'gone')).kind, 'unavailable');
  assert.equal(errorInfo(new TrafficApiError(null, 'not_connected')).kind, 'network');
  assert.equal(errorInfo(new TypeError('x')).kind, 'network');
  const e = errorInfo(new TrafficApiError(500, 'internal'));
  assert.equal(e.retry, true);
  assert.doesNotMatch(e.message, /internal/);
});
