// Tests of the pure WiFi Intelligence logic (node:test, no dependencies).
// Node 24 strips the TypeScript types of the imported .ts files itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DASH,
  NOT_A_SPECTRUM_ANALYZER,
  OFF_HINT,
  POLL_MIN_MS,
  SCAN_WARNING,
  SERIES_IDS,
  TAB_ID,
  TAB_ORDER,
  TAB_TITLE,
  WINDOWS,
  WifiApiError,
  channelRows,
  errorInfo,
  fmtNum,
  healthView,
  linePath,
  metricView,
  parseChannelMap,
  parseOverview,
  parseRadios,
  parseRecommendations,
  parseRoaming,
  parseTimeline,
  pollDelay,
  recommendationView,
  roamingSummary,
  scrub,
  shouldFetch,
  stateText,
  statusView,
  timelineQuery,
} from './wifiLogic.ts';
import * as S from './wifiSamples.mjs';

const here = dirname(fileURLToPath(import.meta.url));

// ── Tab identity ─────────────────────────────────────────────────────────

test('the tab is "WiFi Intelligence", after Netzwerkdiagnose (order 30)', () => {
  assert.equal(TAB_ID, 'wifi');
  assert.equal(TAB_TITLE, 'WiFi Intelligence');
  assert.ok(TAB_ORDER > 30);
});

// ── Parsers: unknown stays unknown ───────────────────────────────────────

test('an empty or wrong answer parses to unknown, never to 0, ready or healthy', () => {
  for (const bad of [null, undefined, 'x', 7, [], {}]) {
    const o = parseOverview(bad);
    assert.equal(o.status, null);
    assert.equal(o.networkHealth.score, null);
    assert.equal(o.monitoringCoverage, null);
    assert.equal(o.counts.radios, null);
    assert.equal(o.counts.clients, null);
    assert.deepEqual(o.routers, []);
    assert.deepEqual(parseRadios(bad).radios, []);
    assert.deepEqual(parseChannelMap(bad).bands, []);
    assert.deepEqual(parseTimeline(bad).radios, []);
    assert.equal(parseRoaming(bad).events, null);
    assert.deepEqual(parseRecommendations(bad).recommendations, []);
  }
  assert.equal(parseOverview({ status: 'READY' }).status, null);
  assert.equal(parseOverview({ status: 'ready' }).status, 'ready');
});

test('radios: metrics keep value and state; a bool or a value without its state is not a measurement', () => {
  const r = parseRadios(S.radiosReady()).radios;
  assert.equal(r.length, 2);
  assert.equal(r[0].metrics.utilization.value, 41.5);
  assert.equal(r[0].metrics.utilization.state, 'measured');
  assert.equal(r[1].metrics.utilization.value, null);
  assert.equal(r[1].metrics.utilization.state, 'unsupported');
  assert.equal(r[1].metrics.signal_quality, null);
  assert.equal(r[1].widthMhz, null);
  assert.equal(r[1].roams1h, null);
  assert.equal(r[1].clients.problem, null);
  assert.equal(r[0].capabilities.states.scan, 'unsupported');
  assert.equal(r[0].capabilities.states.txpower_max, null);
  const odd = parseRadios({ radios: [{ router_id: S.RID1, radio_id: 'r', metrics: {
    a: { value: true, state: 'measured' }, b: { value: 3 }, c: { value: 4, state: 'weird' }, d: { value: 0, state: 'no_data' } } }] });
  const m = odd.radios[0].metrics;
  assert.equal(m.a.value, null);
  assert.equal(m.b.state, null);
  assert.equal(m.c.state, null);
  assert.equal(m.d.value, null); // a value next to a missing state is dropped
});

test('fields the views never need (ssid, bssid, mac, ifname) are not kept by the parsers', () => {
  const all = JSON.stringify([
    parseOverview(S.overviewReady()), parseRadios(S.radiosReady()), parseChannelMap(S.channelMapReady()),
    parseRecommendations(S.recommendationsReady()), parseRoaming(S.roamingApproved()), parseTimeline(S.timelineReady()),
  ]);
  for (const secret of [S.PLANTED_SSID, S.PLANTED_IFNAME]) assert.ok(!all.includes(secret), secret);
  assert.doesNotMatch(all, /"(ssid|bssid|mac|ifname)"/);
});

test('channel map bands sort 2.4 / 5 / 6 GHz; conflicts keep their members', () => {
  const m = parseChannelMap({ ...S.channelMapReady(), bands: { '6g': [], '5g': [], '2.4g': [] } });
  assert.deepEqual(m.bands.map(b => b.band), ['2.4g', '5g', '6g']);
  const c = parseChannelMap(S.channelMapReady()).conflicts[0];
  assert.equal(c.kind, 'co_channel');
  assert.equal(c.members.length, 2);
});

test('timeline points keep gaps as null', () => {
  const t = parseTimeline(S.timelineReady());
  assert.equal(t.window, '1h');
  const pts = t.radios[0].series.utilization.points;
  assert.deepEqual(pts.map(p => p.mean), [10.5, 20, null, 35.25, 40]);
});

test('roaming: counts per radio; events null while restricted', () => {
  const r = parseRoaming(S.roamingCounts());
  assert.equal(r.events, null);
  assert.equal(r.eventsRestricted, 'admin_only');
  assert.deepEqual(r.perRadio.map(p => p.roams), [3, 0]);
  const a = parseRoaming(S.roamingApproved());
  assert.equal(a.events.length, 2);
  assert.equal(a.events[0].gapS, 3.2);
  assert.equal(a.events[1].from, null);
});

// ── Numbers: German format, unknown is a dash with its reason ────────────

test('numbers use the German format', () => {
  assert.equal(fmtNum(1234.5, 1), '1.234,5');
  assert.equal(fmtNum(41.5, 1), '41,5');
  assert.equal(fmtNum(-0.01, 1), '0,0');
  assert.equal(fmtNum(null, 1), DASH);
  assert.equal(fmtNum(Number.NaN), DASH);
  const u = metricView({ value: 41.5, state: 'measured', source: 's', measuredAt: 1 }, 'pct');
  assert.equal(u.text, '41,5 %');
  assert.equal(metricView({ value: -95, state: 'measured', source: 's', measuredAt: 1 }, 'dbm').text, '-95 dBm');
  assert.equal(metricView({ value: 0.153, state: 'measured', source: 's', measuredAt: 1 }, 'per_packet').text, '0,15 je Paket');
});

test('unknown or not measured is "—" with its reason, never 0 and never green', () => {
  for (const state of ['no_data', 'unsupported', 'unreachable']) {
    const v = metricView({ value: null, state, source: 's', measuredAt: null }, 'pct');
    assert.equal(v.known, false);
    assert.ok(v.text.startsWith(DASH), v.text);
    assert.doesNotMatch(v.text, /\b0\b/);
    assert.notEqual(v.tone, 'ok');
    assert.equal(v.reason, state);
    assert.ok(v.reasonText && v.reasonText.length > 0);
  }
  // stale: a dash with the reason; the old value only as "zuletzt"
  const stale = metricView({ value: -92, state: 'stale', source: 's', measuredAt: 1 }, 'dbm');
  assert.equal(stale.known, false);
  assert.ok(stale.text.startsWith(DASH));
  assert.match(stale.text, /veraltet/);
  assert.notEqual(stale.tone, 'ok');
  // a metric that is not assessed at all (its read is off)
  const none = metricView(null, 'pct');
  assert.equal(none.known, false);
  assert.ok(none.text.startsWith(DASH));
  assert.equal(none.reason, 'not_assessed');
  // a measured state without a number is still unknown
  assert.equal(metricView({ value: null, state: 'measured', source: 's', measuredAt: 1 }, 'pct').known, false);
  assert.equal(stateText('unsupported'), 'nicht unterstützt');
  assert.equal(stateText('unreachable'), 'nicht erreichbar');
  assert.equal(stateText('no_data'), 'keine Daten');
  assert.equal(stateText('stale'), 'veraltet');
  assert.equal(stateText(null), 'nicht bewertet');
});

test('health: a score is shown only when known; unknown says why, is muted, never green', () => {
  const known = healthView({ score: 72, grade: 'good', coverage: 0.8, capped: false, withheld: [] }, 'ready');
  assert.equal(known.value, '72');
  assert.equal(known.tone, 'ok');
  const low = healthView({ score: 90, grade: 'excellent', coverage: 0.2, capped: false, withheld: [] }, 'ready');
  assert.notEqual(low.tone, 'ok'); // low coverage is no all-clear
  assert.match(low.note, /Abdeckung/);
  const capped = healthView({ score: 90, grade: 'excellent', coverage: 0.9, capped: true, withheld: [] }, 'ready');
  assert.notEqual(capped.tone, 'ok');
  for (const status of ['not_ready', 'off', null]) {
    const v = healthView({ score: 88, grade: 'good', coverage: 1, capped: false, withheld: ['module_key_missing'] }, status);
    assert.equal(v.value, null, String(status)); // never a score outside "ready"
    assert.equal(v.tone, 'muted');
    assert.ok(v.text.startsWith(DASH));
  }
  const none = healthView({ score: null, grade: 'unknown', coverage: 0, capped: false, withheld: [] }, 'ready');
  assert.equal(none.value, null);
  assert.equal(none.tone, 'muted');
  assert.match(none.text, /keine Bewertung/);
  assert.equal(healthView({ score: 30, grade: 'poor', coverage: 0.9, capped: false, withheld: [] }, 'ready').tone, 'critical');
});

test('status: off shows how to switch RF on; not_ready is "nicht bereit" with the reason and no all-clear', () => {
  const off = statusView('off', []);
  assert.equal(off.label, 'aus');
  assert.notEqual(off.tone, 'ok');
  assert.match(OFF_HINT, /Integrationsoptionen|Optionen/);
  assert.match(OFF_HINT, /wifi_rf_enabled/);
  const nr = statusView('not_ready', ['module_key_missing', 'something_new']);
  assert.equal(nr.label, 'nicht bereit');
  assert.equal(nr.tone, 'warn');
  assert.equal(nr.reasons.length, 2);
  assert.match(nr.reasons[0], /Schlüssel/);
  assert.equal(nr.reasons[1], 'something_new');
  for (const r of nr.reasons) assert.doesNotMatch(r, /alles in Ordnung|keine Probleme|gesund/i);
  assert.equal(statusView('ready', []).label, 'bereit');
  assert.equal(statusView(null, []).label, 'unbekannt');
  assert.equal(statusView(null, []).tone, 'muted');
});

test('the scan warning and the fixed driver-counter note exist', () => {
  assert.match(SCAN_WARNING, /Scan/);
  assert.match(SCAN_WARNING, /stören/);
  assert.equal(NOT_A_SPECTRUM_ANALYZER, 'kein Spektrumanalysator: Werte stammen aus Treiberzählern');
});

// ── Errors ───────────────────────────────────────────────────────────────

test('403 is "Admin nötig", 503/410 "nicht verfügbar", a network error "nicht erreichbar"', () => {
  assert.match(errorInfo(new WifiApiError(403, 'authorization_denied')).message, /Admin nötig/);
  assert.equal(errorInfo(new WifiApiError(403, 'authorization_denied')).kind, 'forbidden');
  assert.match(errorInfo(new WifiApiError(503, 'not_running')).message, /nicht verfügbar/);
  assert.match(errorInfo(new WifiApiError(503, 'no_core')).message, /nicht verfügbar/);
  assert.match(errorInfo(new WifiApiError(410, 'integration_not_loaded')).message, /nicht verfügbar/);
  assert.match(errorInfo(new TypeError('Failed to fetch')).message, /nicht erreichbar/);
  assert.match(errorInfo(new WifiApiError(null, 'not_connected')).message, /nicht erreichbar/);
  assert.equal(errorInfo(new WifiApiError(500, 'internal')).kind, 'other');
  // the server text never reaches the user
  const e = new WifiApiError(500, 'internal');
  assert.doesNotMatch(errorInfo(e).message, /internal/);
});

// ── Polling: never faster than 60 s, only while visible ──────────────────

test('polling is never faster than 60 s and only while the tab is visible', () => {
  assert.equal(POLL_MIN_MS, 60_000);
  assert.equal(pollDelay(5_000), 60_000);
  assert.equal(pollDelay(120_000), 120_000);
  assert.equal(pollDelay(Number.NaN), 60_000);
  assert.equal(shouldFetch({ visible: false, lastMs: 0, nowMs: 10_000_000, intervalMs: 60_000 }), false);
  assert.equal(shouldFetch({ visible: true, lastMs: null, nowMs: 0, intervalMs: 60_000 }), true);
  assert.equal(shouldFetch({ visible: true, lastMs: 1_000, nowMs: 30_000, intervalMs: 60_000 }), false);
  assert.equal(shouldFetch({ visible: true, lastMs: 1_000, nowMs: 61_000, intervalMs: 60_000 }), true);
  assert.equal(shouldFetch({ visible: true, lastMs: 1_000, nowMs: 30_000, intervalMs: 1_000 }), false); // clamped
});

// ── Timeline query and chart ─────────────────────────────────────────────

test('the timeline query takes the fixed windows and valid ids only', () => {
  assert.deepEqual(WINDOWS, ['1h', '24h', '7d', '30d']);
  assert.ok(SERIES_IDS.includes('utilization'));
  assert.equal(timelineQuery({ window: '24h' }), 'window=24h');
  assert.equal(timelineQuery({ window: '1h', series: 'noise', radioId: 'radio0', routerId: S.RID1 }),
    `window=1h&radio_id=radio0&router_id=${S.RID1}&series=noise`);
  for (const bad of [{ window: '2h' }, { window: '1h', series: 'all' }, { window: '1h', radioId: '../x' },
    { window: '1h', radioId: 'a b' }, { window: '1h', routerId: 'rtr_x' }, { window: '1h', radioId: 'r'.repeat(129) }]) {
    assert.throws(() => timelineQuery(bad), WifiApiError, JSON.stringify(bad));
  }
});

test('the SVG line breaks at gaps and has no point for an unknown value', () => {
  const p = linePath([{ ts: 0, mean: 10 }, { ts: 60, mean: 20 }, { ts: 120, mean: null }, { ts: 180, mean: 30 }, { ts: 240, mean: 40 }], 200, 100);
  assert.equal(p.known, true);
  assert.equal(p.segments.length, 2);
  assert.equal(p.min, 10);
  assert.equal(p.max, 40);
  for (const seg of p.segments) assert.doesNotMatch(seg, /NaN/);
  const none = linePath([{ ts: 0, mean: null }, { ts: 60, mean: null }], 200, 100);
  assert.equal(none.known, false);
  assert.deepEqual(none.segments, []);
  assert.equal(none.min, null);
  const flat = linePath([{ ts: 0, mean: 5 }, { ts: 60, mean: 5 }], 200, 100);
  assert.equal(flat.segments.length, 1);
  assert.doesNotMatch(flat.segments[0], /NaN|Infinity/);
});

// ── Channel map ──────────────────────────────────────────────────────────

test('channel rows: own radios per channel; foreign networks are a count or a dash with reason, never an SSID', () => {
  const map = parseChannelMap(S.channelMapReady());
  const radios = parseRadios(S.radiosReady());
  const rows = channelRows(map, radios);
  const b24 = rows.find(b => b.band === '2.4g');
  assert.equal(b24.channels.length, 1);
  assert.equal(b24.channels[0].channel, 6);
  assert.equal(b24.channels[0].own.length, 2);
  assert.equal(b24.channels[0].foreign.known, false);
  assert.ok(b24.channels[0].foreign.text.startsWith(DASH));
  assert.match(b24.channels[0].foreign.text, /nicht unterstützt/);
  assert.ok(!JSON.stringify(rows).includes(S.PLANTED_SSID));
});

// ── Recommendations ──────────────────────────────────────────────────────

test('recommendations: text, reason, evidence and level in German; no apply action', () => {
  const recs = parseRecommendations(S.recommendationsReady()).recommendations;
  const v = recommendationView(recs[0]);
  assert.match(v.title, /Kanal/);
  assert.match(v.title, /11/);
  assert.match(v.reason, /Auslastung/);
  assert.ok(v.evidence.length >= 1);
  assert.equal(v.level, 'normal');
  assert.match(v.confidence, /70 %/);
  for (const e of v.evidence) assert.ok(!e.includes(S.PLANTED_MAC), e);
  const low = recommendationView(recs[1]);
  assert.equal(low.level, 'niedrig');
  assert.match(low.target, /ganzes Netz/);
  // an unknown code is shown as itself, never dropped
  const odd = recommendationView({ ...recs[1], action: 'brand_new', problem: 'new_problem' });
  assert.match(odd.title, /brand_new/);
});

// ── Roaming ──────────────────────────────────────────────────────────────

test('roaming summary: unknown counts stay unknown', () => {
  const s = roamingSummary(parseRadios(S.radiosReady()));
  assert.equal(s.roams.text, '3');
  assert.equal(s.roams.partial, true); // one radio without a count
  assert.equal(s.problemClients.text, '1');
  assert.equal(s.problemClients.partial, true);
  const empty = roamingSummary(parseRadios({ radios: [] }));
  assert.ok(empty.roams.text.startsWith(DASH));
});

// ── Privacy ──────────────────────────────────────────────────────────────

test('scrub removes MAC-like text in every common spelling', () => {
  for (const mac of ['02:00:00:00:02:01', '02-00-00-00-02-01', '02:00:00:00:AA:01', '0200.0000.0201']) {
    assert.doesNotMatch(scrub(`client:${mac}:x`), /02[:.-]?00/, mac);
  }
  assert.equal(scrub('utilization:ch6:78.4%'), 'utilization:ch6:78.4%');
  assert.equal(scrub(S.RID1), S.RID1);
});

// ── Source guards ────────────────────────────────────────────────────────

const SRC = readdirSync(here).filter(f => /\.(ts|tsx)$/.test(f)).map(f => [f, readFileSync(join(here, f), 'utf8')]);

test('no file of the tab renders HTML, logs, stores in the browser, or writes to the router', () => {
  assert.ok(SRC.length >= 10);
  for (const [name, text] of SRC) {
    assert.doesNotMatch(text, /dangerouslySetInnerHTML|\binnerHTML\b/, name);
    assert.doesNotMatch(text, /console\.(log|info|warn|error|debug)/, name);
    assert.doesNotMatch(text, /(localStorage|sessionStorage|indexedDB|document\.cookie)/, name);
    assert.doesNotMatch(text, /'(POST|PUT|PATCH|DELETE)'/, `${name}: write method`);
  }
});

test('no switch or apply buttons: the module only observes and recommends', () => {
  for (const [name, text] of SRC) {
    const ui = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(ui, /\b(Anwenden|Übernehmen|Umschalten|Ausführen|Kanal wechseln jetzt|Scan starten)\b/, name);
  }
});

test('no new chart library: the timeline is plain SVG', () => {
  const pkg = JSON.parse(readFileSync(join(here, '../../../package.json'), 'utf8'));
  assert.deepEqual(Object.keys(pkg.dependencies).sort(), ['react', 'react-dom']);
  const chart = SRC.find(([n]) => n === 'WifiTimeline.tsx')[1];
  assert.match(chart, /<svg/);
  assert.match(chart, /<polyline/);
});
