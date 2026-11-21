// Render tests of the Traffic Analytics views (node:test).
//
// Node cannot load .tsx itself, so the views are bundled once with esbuild
// (already in node_modules as Vite's own bundler; no new dependency) into
// node_modules/.cache and rendered with react-dom/server. Invented sample
// answers only; no real router, no real Home Assistant.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import * as S from './trafficSamples.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '../../..');
const outFile = join(root, 'node_modules/.cache/traffic-render-test/bundle.mjs');

const inlineCss = {
  name: 'inline-css',
  setup(b) {
    b.onResolve({ filter: /\.css\?inline$/ }, a => ({ path: join(a.resolveDir, a.path.replace(/\?inline$/, '')), namespace: 'css-inline' }));
    b.onLoad({ filter: /.*/, namespace: 'css-inline' }, a => ({ contents: readFileSync(a.path, 'utf8'), loader: 'text' }));
  },
};

let M;
before(async () => {
  mkdirSync(dirname(outFile), { recursive: true });
  await build({
    stdin: {
      contents: [
        "export * from './trafficLogic.ts';",
        "export { TrafficOverview, OffNotice } from './TrafficOverview';",
        "export { SeriesView, HistoryPicker } from './TrafficHistory';",
        "export { TalkerCards } from './TrafficTalkers';",
        "export { ClientCards, VlanCards } from './TrafficClients';",
        "export { AnomalyView } from './TrafficAnomalies';",
        "export { CapacityCards, RecommendationsView } from './TrafficCapacity';",
        "export { FlowsBody } from './TrafficFlows';",
        "export { SettingsForm, RouterSettingsFacts, TrafficSettings } from './TrafficSettings';",
        "export { TrafficAnalyticsView } from './TrafficAnalyticsView';",
        "export { getEnterpriseTabs } from '../registry';",
        "export { bindConfigHass } from '../config/register';",
        "export { bindSecurityHass } from '../security/register';",
        "export { bindDiagnosticsHass } from '../diagnostics/register';",
        "export { bindWifiHass } from '../wifi/register';",
        "export { bindTrafficHass } from './register';",
      ].join('\n'),
      resolveDir: here,
      loader: 'ts',
    },
    bundle: true,
    format: 'esm',
    platform: 'node',
    jsx: 'automatic',
    outfile: outFile,
    external: ['react', 'react-dom', 'react/jsx-runtime', 'react-dom/client', 'react-dom/server'],
    define: { 'import.meta.env.DEV': 'false' },
    plugins: [inlineCss],
    logLevel: 'silent',
  });
  M = await import(pathToFileURL(outFile).href);
});

const html = el => renderToStaticMarkup(el);
const h = React.createElement;
const neverApi = new Proxy({}, { get: () => () => new Promise(() => {}) });

function allViews() {
  return [
    html(h(M.TrafficOverview, { overview: M.parseOverview(S.overviewReady()) })),
    html(h(M.SeriesView, { series: M.parseSeries(S.seriesDays()) })),
    html(h(M.SeriesView, { series: M.parseSeries(S.seriesHours()) })),
    html(h(M.HistoryPicker, { list: M.parsePoints(S.points()), api: neverApi, rev: 0 })),
    html(h(M.TalkerCards, { list: M.parseTalkers(S.talkers()) })),
    html(h(M.ClientCards, { list: M.parseClients(S.clients()) })),
    html(h(M.VlanCards, { list: M.parseVlans(S.vlans()) })),
    html(h(M.AnomalyView, { list: M.parseAnomalies(S.anomalies()) })),
    html(h(M.CapacityCards, { list: M.parseCapacity(S.capacity()) })),
    html(h(M.RecommendationsView, { data: M.parseRecommendations(S.recommendations()) })),
    html(h(M.FlowsBody, { data: M.parseFlows(S.flows()) })),
  ];
}

// ── Registration ─────────────────────────────────────────────────────────

test('the tab hangs under "Enterprise" after the other four modules', () => {
  const fake = { callApi: async () => ({}), user: { is_admin: true } };
  for (const bind of [M.bindConfigHass, M.bindSecurityHass, M.bindDiagnosticsHass, M.bindWifiHass, M.bindTrafficHass]) bind(() => fake);
  const tabs = M.getEnterpriseTabs();
  assert.deepEqual(tabs.map(t => t.id), ['config', 'security', 'diagnostics', 'wifi', 'traffic']);
  assert.equal(tabs.at(-1).title, 'Traffic Analytics');
  M.bindTrafficHass(() => null);
  assert.ok(!M.getEnterpriseTabs().some(t => t.id === 'traffic'));
  M.bindTrafficHass(() => fake);
});

test('the panel binds the tab once; no bottom-bar entry', () => {
  const main = readFileSync(join(root, 'src/main.tsx'), 'utf8');
  assert.match(main, /import \{ bindTrafficHass \} from '\.\/enterprise\/traffic\/register';/);
  assert.equal((main.match(/bindTrafficHass\(\(\) => this\._hass\)/g) || []).length, 1);
  const sidebar = readFileSync(join(root, 'src/components/Sidebar.tsx'), 'utf8');
  assert.doesNotMatch(sidebar, /Traffic Analytics|enterprise\/traffic/);
});

// ── Views ────────────────────────────────────────────────────────────────

test('no MAC or WLAN interface name in the rendered DOM of any view', () => {
  const out = allViews().join('\n');
  for (const secret of S.PLANTED) assert.ok(!out.includes(secret), secret);
  assert.doesNotMatch(out, /([0-9a-f]{2}[:-]){5}[0-9a-f]{2}/i);
  assert.match(out, /Client c0ffee/); // the pseudonym label is fine
});

test('unknown is "—" with its reason, never 0, and never in the ok tone', () => {
  const out = allViews().join('\n');
  assert.match(out, /— Link-Geschwindigkeit unbekannt/);
  assert.match(out, /— noch keine Rate/); // client upload
  assert.match(out, /— keine Zuordnung WLAN → VLAN/);
  assert.match(out, /— keine Quelle für VLAN der Clients/);
  assert.match(out, /— zu wenige Daten/); // capacity upload P95
  assert.match(out, /— Bezugsgröße nicht vollständig erfasst/); // talker share
  assert.doesNotMatch(out, /cfg-badge--ok[^>]*>[^<]*(unbekannt|nicht verfügbar|nicht angebunden|—)/);
  const ov = html(h(M.TrafficOverview, { overview: M.parseOverview(S.overviewReady()) }));
  assert.match(ov, /80,0 Mbit\/s/);
  assert.match(ov, /52,0 GB/);
  assert.match(ov, /— noch nicht gespeichert/); // coarse store not written yet
});

test('data quality and "not available" reasons are visible', () => {
  const ov = html(h(M.TrafficOverview, { overview: M.parseOverview(S.overviewReady()) }));
  assert.match(ov, /Schnittstellen passen nicht/); // WiFi RF interface_mismatch
  assert.match(ov, /Security Center/);
  assert.match(ov, /nicht angebunden/); // Security Center not_connected
  assert.match(ov, /Collector ausgeschaltet/);
  assert.match(ov, /Hardware-Offload unbekannt/);
  assert.match(ov, /Abdeckung teilweise/);
  const rec = html(h(M.RecommendationsView, { data: M.parseRecommendations(S.recommendations()) }));
  assert.match(rec, /Modul ausgeschaltet/); // wifi_rf module_disabled
  assert.match(rec, /Möglicher Engpass am Uplink/);
  assert.match(rec, /WAN-Bandbreite prüfen/);
  assert.doesNotMatch(rec, /<button/); // nothing applies a change
});

test('daily values are UTC days, labelled in local time, and say so', () => {
  const days = html(h(M.SeriesView, { series: M.parseSeries(S.seriesDays()) }));
  assert.match(days, /Tageswerte sind UTC-Tage/);
  assert.match(days, /UTC-Tag, ab \d\d:\d\d Ortszeit/);
  assert.match(days, /<svg/);
  assert.equal((days.match(/<polyline/g) || []).length, 4); // the null day splits each line
  const hours = html(h(M.SeriesView, { series: M.parseSeries(S.seriesHours()) }));
  assert.doesNotMatch(hours, /UTC-Tag/);
  const unknown = html(h(M.SeriesView, { series: M.parseSeries(S.seriesUnknown()) }));
  assert.match(unknown, /— Messpunkt unbekannt/);
});

test('history picker offers the valid points (WAN first) and the five windows', () => {
  const out = html(h(M.HistoryPicker, { list: M.parsePoints(S.points()), api: neverApi, rev: 0 }));
  assert.equal((out.match(/<option/g) || []).length, 2 + 5);
  assert.ok(out.indexOf('WAN wan') < out.indexOf('Port lan1'));
  assert.match(out, /90 Tage/);
});

test('off shows a notice and loads nothing; the nav hides Flows for users', () => {
  const off = html(h(M.OffNotice));
  assert.match(off, /Traffic Analytics ist aus/);
  const frame = html(h(M.TrafficAnalyticsView, { api: neverApi, isAdmin: () => false }));
  assert.match(frame, /Traffic Analytics/);
  assert.match(frame, /aria-busy="true"/); // the overview is loading; nothing else is mounted
});

test('collector flows render as pseudonyms, never as addresses', () => {
  const raw = S.flowsWithRows();
  raw.rows.push({ ...raw.rows[0], src: '192.0.2.10', dst: S.PLANTED_MAC, client_ref: null });
  const out = html(h(M.FlowsBody, { data: M.parseFlows(raw) }));
  assert.match(out, /Flows vom Collector \(2\)/);
  assert.match(out, /Adresse 11111111:50000/);
  assert.match(out, /Client unbekannt/);
  assert.doesNotMatch(out, /192\.0\.2\.10/);
  assert.ok(!out.includes(S.PLANTED_MAC));
  const empty = html(h(M.FlowsBody, { data: M.parseFlows(S.flows()) }));
  assert.doesNotMatch(empty, /Flows vom Collector/);
});

test('a view never throws on junk answers', () => {
  for (const bad of [null, 'x', 7, [], { rows: 'x' }, { rows: [null, 3, { kind: 5 }] }]) {
    assert.doesNotThrow(() => html(h(M.TrafficOverview, { overview: M.parseOverview(bad) })));
    assert.doesNotThrow(() => html(h(M.SeriesView, { series: M.parseSeries(bad) })));
    assert.doesNotThrow(() => html(h(M.TalkerCards, { list: M.parseTalkers(bad) })));
    assert.doesNotThrow(() => html(h(M.ClientCards, { list: M.parseClients(bad) })));
    assert.doesNotThrow(() => html(h(M.AnomalyView, { list: M.parseAnomalies(bad) })));
    assert.doesNotThrow(() => html(h(M.CapacityCards, { list: M.parseCapacity(bad) })));
    assert.doesNotThrow(() => html(h(M.RecommendationsView, { data: M.parseRecommendations(bad) })));
    assert.doesNotThrow(() => html(h(M.FlowsBody, { data: M.parseFlows(bad) })));
  }
});

test('narrow layout: the stylesheet keeps 360 px without sideways scrolling', () => {
  const css = readFileSync(join(here, 'traffic.css'), 'utf8');
  assert.match(css, /@media \(max-width: 600px\)/);
  assert.match(css, /\.trf \{[^}]*min-width: 0/);
  assert.match(css, /overflow-wrap: anywhere/);
  assert.doesNotMatch(css, /min-width: (3[7-9]\d|[4-9]\d\d|\d{4,})px/);
  // the grid column floor fits a 360 px screen minus the panel padding
  const floor = Number(/minmax\((\d+)px/.exec(css)[1]);
  assert.ok(floor <= 300, floor);
});

// ── Settings form (Phase L, administrators only) ─────────────────────────

const settingsForm = (over = {}, sel = null, props = {}) => html(h(M.SettingsForm, {
  view: M.parseSettings(S.settings(over)),
  users: M.parseCollectorUsers(S.collectorUsers(sel)),
  clients: M.parseClients(S.clients()),
  onSave: async () => {},
  ...props,
}));

test('the settings form offers the collector user by name and the clients by pseudonym only', () => {
  const out = settingsForm({ client_sensors: [S.CLI2] }, S.USR1);
  assert.match(out, /Externer Collector/);
  assert.match(out, /<option value="usr_5{16}" selected="">Collector<\/option>/);
  assert.match(out, /Client c0ffee/);
  assert.match(out, /Client beef00 <span class="wifi-muted">· derzeit nicht erfasst/); // chosen, not seen now
  assert.match(out, /Client-Sensoren \(1 von 20\)/);
  for (const secret of S.PLANTED) assert.ok(!out.includes(secret), secret);
  assert.doesNotMatch(out, /[0-9a-f]{32}/); // no HA user id, no raw id of any kind
  assert.doesNotMatch(out, /Gespeichert/); // nothing is shown as saved before the route confirms
  assert.match(out, /<button type="submit"[^>]*disabled=""[^>]*>Speichern/); // no change, nothing to send
});

test('while the module cannot store, the form is locked and says why', () => {
  const out = settingsForm({ writable: false });
  assert.match(out, /Speichern geht erst, wenn Traffic Analytics an mindestens einem Router läuft/);
  assert.match(out, /<input type="checkbox" disabled=""/);
});

test('no choosable user and a stored user that vanished are both explained', () => {
  const none = html(h(M.SettingsForm, {
    view: M.parseSettings(S.settings({ collector: { ...S.settings().collector, user_configured: true } })),
    users: M.parseCollectorUsers({ ...S.collectorUsers(), users: [], user_configured: true, selected_listed: false }),
    clients: M.parseClients({ ...S.clients(), clients: [] }),
    onSave: async () => {},
  }));
  assert.match(none, /keinen wählbaren Benutzer/);
  assert.match(none, /nicht mehr wählbar/);
  assert.match(none, /eingetragener Benutzer bleibt/);
  assert.match(none, /noch kein Client erfasst/);
});

test('router switches are shown read only with the way to the options flow', () => {
  const out = html(h(M.RouterSettingsFacts, { view: M.parseSettings(S.settings()) }));
  assert.match(out, /1 von 2 Routern/);
  assert.match(out, /compact \(Standard\)/);
  assert.match(out, /Integrationsoptionen/);
  assert.doesNotMatch(out, /<input/);
});

test('non-administrators get no settings section; the tab never loads it for them', () => {
  const seen = [];
  const spy = new Proxy({}, { get: (_t, key) => () => { seen.push(key); return new Promise(() => {}); } });
  html(h(M.TrafficAnalyticsView, { api: spy, isAdmin: () => false }));
  assert.ok(!seen.includes('settings') && !seen.includes('collectorUsers') && !seen.includes('updateSettings'));
  assert.ok(!M.sectionsFor(false).some(s => s.id === 'settings'));
});

// ── Browser check 1.49.3 ─────────────────────────────────────────────────

test('anomaly values carry their unit: rates for spikes, bytes for volumes, bare for unknown kinds', () => {
  const out = html(h(M.AnomalyView, { list: M.parseAnomalies(S.anomalies()) }));
  assert.match(out, /90,0 Mbit\/s \/ 10,0 Mbit\/s \/ 40,0 Mbit\/s/);
  assert.doesNotMatch(out, /90\.000\.000/);
  assert.equal(M.anomalyValueText('download_volume', 2_000_000_000), M.fmtBytes(2_000_000_000));
  for (const k of ['upload_spike', 'rx_night_activity', 'tx_sustained_high', 'download_drop', 'upload_bursts']) {
    assert.equal(M.anomalyValueText(k, 1_000_000), M.fmtRate(1_000_000), k);
  }
  assert.equal(M.anomalyValueText('connection_rate', 1234), M.fmtNum(1234, 0));
  assert.equal(M.anomalyValueText('download_spike', null), M.DASH);
});

test('a finding threshold has the same unit as its value', () => {
  const out = html(h(M.RecommendationsView, { data: M.parseRecommendations(S.recommendations()) }));
  assert.match(out, /Schwelle 80,0 %/);
  assert.match(out, /Schwelle 50,0 ms/);
});

test('the history chart names its lowest value too (the scale is not zero based)', () => {
  const out = html(h(M.SeriesView, { series: M.parseSeries(S.seriesHours()) }));
  assert.match(out, /höchster Wert/);
  assert.match(out, /class="wifi-chart__axis wifi-chart__axis--min"><span>niedrigster Wert /);
});

test('grid facts keep values whole; the collector select is styled like the others', () => {
  const css = readFileSync(join(here, 'traffic.css'), 'utf8');
  assert.match(css, /\.trf-grid \.wifi-fact__name \{ min-width: 0; \}/);
  assert.match(css, /\.trf-grid \.wifi-fact__value \{ flex: 1 1 auto; \}/);
  assert.match(css, /\.trf-field select \{[^}]*background: var\(--surface-raised\)[^}]*color: var\(--text-primary\)|\.trf-field select \{[^}]*color: var\(--text-primary\)[^}]*background: var\(--surface-raised\)/);
});
