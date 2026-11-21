// Render tests of the WiFi Intelligence views (node:test).
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
import * as S from './wifiSamples.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '../../..');
const outFile = join(root, 'node_modules/.cache/wifi-render-test/bundle.mjs');

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
        "export * from './wifiLogic.ts';",
        "export { WifiOverview } from './WifiOverview';",
        "export { WifiRadios } from './WifiRadios';",
        "export { WifiChannelMap } from './WifiChannelMap';",
        "export { WifiTimelineChart } from './WifiTimeline';",
        "export { WifiRoamingView } from './WifiRoaming';",
        "export { WifiRecommendations } from './WifiRecommendations';",
        "export { SectionBoundary } from './wifiUi';",
        "export { getEnterpriseTabs } from '../registry';",
        "export { bindConfigHass } from '../config/register';",
        "export { bindSecurityHass } from '../security/register';",
        "export { bindDiagnosticsHass } from '../diagnostics/register';",
        "export { bindWifiHass } from './register';",
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

function parsedAll() {
  return {
    overview: M.parseOverview(S.overviewReady()),
    radios: M.parseRadios(S.radiosReady()),
    map: M.parseChannelMap(S.channelMapReady()),
    recs: M.parseRecommendations(S.recommendationsReady()),
    timeline: M.parseTimeline(S.timelineReady()),
    roaming: M.parseRoaming(S.roamingApproved()),
  };
}

// ── Registration ─────────────────────────────────────────────────────────

test('the tab hangs under "Enterprise" next to the other three modules', () => {
  const fake = { callApi: async () => ({}), user: { is_admin: true } };
  for (const bind of [M.bindConfigHass, M.bindSecurityHass, M.bindDiagnosticsHass, M.bindWifiHass]) bind(() => fake);
  const tabs = M.getEnterpriseTabs();
  assert.deepEqual(tabs.map(t => t.id), ['config', 'security', 'diagnostics', 'wifi']);
  const wifi = tabs.find(t => t.id === 'wifi');
  assert.equal(wifi.title, 'WiFi Intelligence');
  assert.equal(typeof wifi.component, 'function');
  // without hass the tab is hidden like the others
  M.bindWifiHass(() => null);
  assert.ok(!M.getEnterpriseTabs().some(t => t.id === 'wifi'));
  M.bindWifiHass(() => fake);
});

test('there is no new entry in the bottom bar; the panel binds the tab once', () => {
  const sidebar = readFileSync(join(root, 'src/components/Sidebar.tsx'), 'utf8');
  assert.doesNotMatch(sidebar, /wifi|WiFi Intelligence/i);
  const typeLine = /export type SidebarTab = ([^;]+);/.exec(sidebar)[1];
  assert.equal(typeLine.split('|').length, 10); // unchanged count of bottom bar ids
  const topo = readFileSync(join(root, 'src/TopologyView.tsx'), 'utf8');
  assert.doesNotMatch(topo, /WifiIntelligence|enterprise\/wifi/);
  const main = readFileSync(join(root, 'src/main.tsx'), 'utf8');
  assert.match(main, /import \{ bindWifiHass \} from '\.\/enterprise\/wifi\/register';/);
  assert.match(main, /bindWifiHass\(\(\) => this\._hass\)/);
});

// ── Views with the sample answers ────────────────────────────────────────

test('no MAC, SSID, BSSID or interface name in the rendered DOM of any view', () => {
  const p = parsedAll();
  const out = [
    html(h(M.WifiOverview, { overview: p.overview })),
    html(h(M.WifiRadios, { view: p.radios })),
    html(h(M.WifiChannelMap, { map: p.map, radios: p.radios })),
    html(h(M.WifiRecommendations, { data: p.recs })),
    html(h(M.WifiTimelineChart, { timeline: p.timeline, series: 'utilization' })),
    html(h(M.WifiRoamingView, { radios: p.radios, admin: true, approval: { step: 'approved', ack: true, error: null }, roaming: p.roaming, onOpen() {}, onAck() {}, onCancel() {}, onSubmit() {} })),
    html(h(M.WifiRoamingView, { radios: p.radios, admin: true, approval: { step: 'confirm', ack: false, error: null }, roaming: null, onOpen() {}, onAck() {}, onCancel() {}, onSubmit() {} })),
  ].join('\n');
  for (const secret of S.PLANTED) assert.ok(!out.includes(secret), secret);
  assert.doesNotMatch(out, /\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/i);
  // the pseudonym of the client is fine
  assert.match(out, /cli_aaaaaaaaaaaaaaaa/);
});

test('numbers are German; unknown is "—" with its reason, never 0 and never green', () => {
  const p = parsedAll();
  const radios = html(h(M.WifiRadios, { view: p.radios }));
  assert.match(radios, /41,5 %/);
  assert.match(radios, /-95 dBm/);
  assert.match(radios, /0,15 je Paket/);
  assert.match(radios, /1\.234,5 %/);
  assert.match(radios, /— nicht unterstützt/);
  assert.match(radios, /— nicht erreichbar/);
  assert.match(radios, /— keine Daten/);
  assert.match(radios, /— veraltet/);
  // an unknown value never carries the ok tone
  assert.doesNotMatch(radios, /wifi-tone-ok[^>]*>—/);
  assert.doesNotMatch(radios, /wifi-tone-ok[^>]*>[^<]*nicht/);
  const ov = html(h(M.WifiOverview, { overview: p.overview }));
  assert.match(ov, /46 %/); // monitoring coverage 0.4567
  assert.match(ov, /72/);
  assert.doesNotMatch(ov, /wifi-tone-ok[^>]*>—/);
  const map = html(h(M.WifiChannelMap, { map: p.map, radios: p.radios }));
  assert.match(map, /2,4 GHz/);
  assert.match(map, /Fremde Netze/);
  assert.match(map, /— nicht unterstützt/);
});

test('off explains how to switch RF on; not_ready says "nicht bereit" with the reason, no score', () => {
  const off = html(h(M.WifiOverview, { overview: M.parseOverview(S.overviewOff()) }));
  assert.match(off, /wifi_rf_enabled/);
  assert.match(off, /Integrationsoptionen/);
  assert.doesNotMatch(off, /wifi-tone-ok/);
  const nr = html(h(M.WifiOverview, { overview: M.parseOverview(S.overviewNotReady()) }));
  assert.match(nr, /nicht bereit/i);
  assert.match(nr, /Schlüssel des Moduls fehlt/);
  assert.doesNotMatch(nr, /\/ 100/);
  assert.doesNotMatch(nr, /wifi-tone-ok/);
  assert.doesNotMatch(nr, /in Ordnung|keine Probleme/);
});

test('survey / scan: a visible warning and the fixed driver-counter note', () => {
  const p = parsedAll();
  for (const out of [html(h(M.WifiRadios, { view: p.radios })), html(h(M.WifiChannelMap, { map: p.map, radios: p.radios }))]) {
    assert.match(out, /role="note"[^>]*>[^]*?Scan[^]*?stören/);
    assert.match(out, /kein Spektrumanalysator: Werte stammen aus Treiberzählern/);
  }
});

test('roaming: counts for everyone; details only after the admin approval; 403 shows "Admin nötig"', () => {
  const p = parsedAll();
  const cb = { onOpen() {}, onAck() {}, onCancel() {}, onSubmit() {} };
  const user = html(h(M.WifiRoamingView, { radios: p.radios, admin: false, approval: M.APPROVAL_INIT, roaming: null, ...cb }));
  assert.match(user, /Roaming-Wechsel/);
  assert.match(user, /nur für Administratoren/i);
  assert.doesNotMatch(user, /cli_/);
  assert.doesNotMatch(user, /<button[^>]*>[^<]*freigeben/i);
  const admin = html(h(M.WifiRoamingView, { radios: p.radios, admin: true, approval: M.APPROVAL_INIT, roaming: null, ...cb }));
  assert.match(admin, /<button[^>]*>Roaming-Details freigeben/);
  assert.doesNotMatch(admin, /cli_/);
  const confirm = html(h(M.WifiRoamingView, { radios: p.radios, admin: true, approval: { step: 'confirm', ack: false, error: null }, roaming: null, ...cb }));
  assert.match(confirm, /type="checkbox"/);
  assert.match(confirm, /<button[^>]*disabled=""[^>]*>Freigeben und anzeigen/);
  const refused = M.approvalReduce({ step: 'loading', ack: true, error: null },
    { type: 'failed', error: new M.WifiApiError(403, 'authorization_denied') });
  const denied = html(h(M.WifiRoamingView, { radios: p.radios, admin: true, approval: refused, roaming: null, ...cb }));
  assert.match(denied, /Admin nötig/);
  assert.doesNotMatch(denied, /cli_/);
});

test('recommendations show text, reason, evidence and level, and no apply button', () => {
  const out = html(h(M.WifiRecommendations, { data: M.parseRecommendations(S.recommendationsReady()) }));
  assert.match(out, /Kanal 11/);
  assert.match(out, /Begründung/);
  assert.match(out, /Nachweis/);
  assert.match(out, /Stufe/);
  assert.match(out, /Sicherheit 70 %/);
  assert.doesNotMatch(out, /<button/);
});

test('the timeline is an SVG line with gaps; an empty series is "—" with a reason', () => {
  const out = html(h(M.WifiTimelineChart, { timeline: M.parseTimeline(S.timelineReady()), series: 'utilization' }));
  assert.match(out, /<svg/);
  assert.equal((out.match(/<polyline/g) || []).length, 2); // gap splits radio0's line
  assert.match(out, /— keine Daten in diesem Fenster/);
  assert.match(out, /10,5 %/);
});

test('a view that throws shows a fallback instead of taking the panel down', () => {
  const boundary = new M.SectionBoundary({ title: 'Radios', children: null });
  assert.deepEqual(M.SectionBoundary.getDerivedStateFromError(new Error('x')), { failed: true });
  boundary.state = { failed: true };
  const out = html(boundary.render());
  assert.match(out, /konnte nicht angezeigt werden/);
  // the parsers never throw on garbage, so a view always gets safe data
  for (const bad of [null, 'x', 7, [], { radios: 'x' }, { radios: [null, 3, { router_id: 5 }] }]) {
    assert.doesNotThrow(() => html(h(M.WifiRadios, { view: M.parseRadios(bad) })));
    assert.doesNotThrow(() => html(h(M.WifiOverview, { overview: M.parseOverview(bad) })));
    assert.doesNotThrow(() => html(h(M.WifiChannelMap, { map: M.parseChannelMap(bad), radios: null })));
    assert.doesNotThrow(() => html(h(M.WifiRecommendations, { data: M.parseRecommendations(bad) })));
    assert.doesNotThrow(() => html(h(M.WifiTimelineChart, { timeline: M.parseTimeline(bad), series: 'noise' })));
  }
});

test('narrow layout: the stylesheet keeps 360 px without sideways scrolling', () => {
  const css = readFileSync(join(here, 'wifi.css'), 'utf8');
  assert.match(css, /@media \(max-width: 600px\)/);
  assert.match(css, /overflow-wrap: anywhere/);
  assert.match(css, /\.wifi \{[^}]*min-width: 0/);
  assert.doesNotMatch(css, /min-width: (3[7-9]\d|[4-9]\d\d|\d{4,})px/); // nothing wider than 360 px is forced
});
