// Render tests of the "Zeitreise" tab (node:test). The views are bundled
// once with esbuild (Vite's own bundler, already in node_modules; no new
// dependency) and rendered with react-dom/server. The answers are real route
// answers from tmFixture.json (tests/test_tm_panel_fixture_v1500.py,
// invented values only).
process.env.TZ = 'Europe/Berlin';

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '../../..');
const outFile = join(root, 'node_modules/.cache/tm-render-test/bundle.mjs');
const F = JSON.parse(readFileSync(join(here, 'tmFixture.json'), 'utf8'));

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
        "export * from './tmLogic.ts';",
        "export { TimeMachineScreen, FilterBar, TimeMachineView } from './TimeMachineView';",
        "export { getEnterpriseTabs } from '../registry';",
        "export { bindConfigHass } from '../config/register';",
        "export { bindSecurityHass } from '../security/register';",
        "export { bindDiagnosticsHass } from '../diagnostics/register';",
        "export { bindWifiHass } from '../wifi/register';",
        "export { bindTrafficHass } from '../traffic/register';",
        "export { bindTimeMachineHass } from './register';",
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

const h = React.createElement;
// generated_at of the fixture is two hours after its world start: "now" sits there
const NOW_MS = F.admin.body.generated_at * 1000;
const noop = () => {};

function loaded(name, { pages = [], loading = false, error = null } = {}) {
  let s = M.listReducer(M.LIST_INIT, { type: 'start', seq: 1, more: false });
  s = M.listReducer(s, { type: 'first', gen: 0, seq: 1, answer: M.parseTimeline(F[name].body) });
  pages.forEach((p, i) => {
    s = M.listReducer(s, { type: 'start', seq: i + 2, more: true });
    s = M.listReducer(s, { type: 'older', gen: 0, seq: i + 2, answer: M.parseTimeline(F[p].body) });
  });
  if (loading || error) s = M.listReducer(s, { type: 'start', seq: 99, more: false });
  if (error) s = M.listReducer(s, { type: 'fail', gen: 0, seq: 99, more: false, error });
  return s;
}

function screen(state, extra = {}) {
  return withStyles(state, extra).replace(/<style>[\s\S]*?<\/style>/g, '');
}
function withStyles(state, extra = {}) {
  return renderToStaticMarkup(h(M.TimeMachineScreen, {
    state, filters: M.DEFAULT_FILTERS, hidden: [], routers: M.rememberRouters({}, state.marks), nowMs: NOW_MS,
    onFilters: noop, onToggleGroup: noop, onRefresh: noop, onMore: noop, ...extra,
  }));
}
const text = html => html.replace(/<style>[\s\S]*?<\/style>/g, '').replace(/<[^>]+>/g, ' ').replace(/&#x27;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ').replace(/ ([:.,])/g, '$1');
const count = (html, needle) => html.split(needle).length - 1;

// Values that must never be printed (none of them is in the fixture either).
const PRIVATE = /(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:wlan|phy|eth|br-|lan\d)\S*/i;

test('the tab hangs under Enterprise at order 60, after Traffic Analytics', () => {
  M.bindTimeMachineHass(() => ({ callApi: async () => ({}) }));
  M.bindTrafficHass(() => ({ callApi: async () => ({}) }));
  const tabs = M.getEnterpriseTabs();
  const ids = tabs.map(t => t.id);
  const tm = tabs.find(t => t.id === 'timemachine');
  assert.equal(tm.title, 'Zeitreise');
  assert.equal(tm.order, 60);
  assert.ok(ids.indexOf('traffic') < ids.indexOf('timemachine'));
});

test('first load: a quiet hint, header, intro, no filters yet', () => {
  const html = screen(M.listReducer(M.LIST_INIT, { type: 'start', seq: 1, more: false }));
  const t = text(html);
  assert.match(t, /Zeitreise Aktualisieren/);
  assert.ok(t.includes(M.INTRO));
  assert.ok(t.includes(M.LOADING_TEXT));
  assert.ok(!html.includes('tm-filters'));
  assert.ok(!t.includes('Stand'));
});

test('a full answer: header with "Stand", filters, sources, days and marks', () => {
  const state = loaded('admin');
  const html = screen(state);
  const t = text(html);
  assert.ok(t.includes(M.standText(F.admin.body.generated_at)));
  for (const w of ['1 Stunde', '24 Stunden', '7 Tage', '14 Tage', 'Audit', 'Konfiguration', 'Netzwerk-Ereignisse', 'Vorfälle', 'Security Center',
    'Alle', 'ab Warnung', 'nur kritisch', 'Alle Router', 'Router e1']) assert.ok(t.includes(w), w);
  assert.ok(t.includes(`${state.marks.length} von ${state.marks.length} Marken`));
  assert.equal(count(html, 'class="tm-mark"'), state.marks.length);
  assert.ok(t.includes('Heute'));
  // every mark: time with the UTC ISO title, severity word, group, router, source
  for (const m of state.marks) assert.ok(html.includes(`title="${M.isoUtc(m.ts)}"`), m.id);
  assert.ok(t.includes('Vorfall eröffnet: WAN-Verbindung ausgefallen'));
  assert.ok(t.includes('3 Vorkommen · 2-mal wieder geöffnet'));
  assert.ok(t.includes('1 client-bezogenes Ereignis ist ausgeblendet.'));
  assert.ok(!html.includes('cfg-notice--warn'));
  assert.ok(!html.includes('cfg-badge--ok'));
  assert.ok(!html.includes('dangerouslySetInnerHTML'));
  assert.doesNotMatch(text(html), PRIVATE);
  // the default window is pressed
  assert.match(html, /aria-pressed="true"[^>]*>24 Stunden/);
});

test('info is never shown in a warning colour', () => {
  const html = screen(loaded('admin'));
  for (const m of html.matchAll(/tm-sev--(\w+)"><span class="tm-sev__dot" aria-hidden="true"><\/span>(\w+)/g)) {
    const [, tone, word] = m;
    assert.equal({ Info: 'info', Warnung: 'warn', Kritisch: 'critical' }[word], tone, word);
  }
  assert.ok(html.includes('tm-sev--info'));
});

test('derived marks carry "abgeleitet" (Phase A sends none: one is set here)', () => {
  const state = loaded('admin');
  assert.equal(count(screen(state), '>abgeleitet<'), 0);
  const one = { ...state, marks: state.marks.map((m, i) => (i === 0 ? { ...m, derived: true } : m)) };
  assert.equal(count(screen(one), '>abgeleitet<'), 1);
});

test('the tab brings its styles (config, wifi and its own)', () => {
  const html = withStyles(loaded('admin'));
  assert.equal(count(html, '<style>'), 3);
  assert.ok(html.includes('container: tmlist / inline-size'));
});

test('group chips hide marks client-side and count them', () => {
  const state = loaded('admin');
  const html = screen(state, { hidden: ['configuration'] });
  const shown = M.visibleMarks(state.marks, ['configuration']).length;
  assert.equal(count(html, 'class="tm-mark"'), shown);
  assert.ok(text(html).includes(`${shown} von ${state.marks.length} Marken`));
  const all = screen(state, { hidden: [...M.groupsOf(state.marks)] });
  assert.ok(text(all).includes('Keine Marken der gewählten Arten.'));
});

test('empty: neutral text, never a green tick', () => {
  const html = screen(loaded('empty'));
  const t = text(html);
  assert.ok(t.includes(M.EMPTY_TEXT));
  assert.ok(!/[✓✔]/.test(t));
  assert.ok(!html.includes('cfg-notice--ok') && !html.includes('cfg-badge--ok'));
  assert.ok(t.includes('Audit: leer'));
  assert.ok(!t.includes('Ältere laden'));
});

test('partial: banner above the list, the unreadable source says why', () => {
  for (const name of ['partial', 'partial_empty']) {
    const html = screen(loaded(name));
    const t = text(html);
    assert.ok(t.includes(M.PARTIAL_TEXT), name);
    assert.ok(t.includes('Security Center: Quelle nicht lesbar · Fehler'), name);
    assert.ok(html.indexOf(M.PARTIAL_TEXT) < html.indexOf('tm-sources'), name);
  }
});

test('a user without admin: audit and configuration are greyed out and locked, no client hint', () => {
  const html = screen(loaded('user'));
  const t = text(html);
  for (const name of ['Audit', 'Konfiguration']) {
    assert.match(html, new RegExp(`disabled=""[^>]*>${name}<span class="tm-chip__note"> · nur für Administratoren`), name);
    assert.ok(t.includes(`${name}: aus · nur für Administratoren`), name);
  }
  assert.match(html, /<button[^>]*aria-pressed="true"(?![^>]*disabled)[^>]*>Netzwerk-Ereignisse/);
  assert.ok(!html.includes('tm-omitted'));
});

test('off: the box with the settings path, no filters, no list', () => {
  const html = screen(loaded('off'));
  const t = text(html);
  assert.ok(t.includes(M.OFF_TITLE));
  assert.ok(t.includes(M.OFF_HOW));
  assert.ok(t.includes('Aktualisieren'));
  assert.ok(!html.includes('tm-filters') && !html.includes('tm-list') && !html.includes('tm-sources'));
  assert.ok(!t.includes(M.EMPTY_TEXT));
});

test('older pages: "Ältere laden" while there is a next_until, then the cut hint', () => {
  const page1 = screen(loaded('admin_page1'));
  assert.ok(text(page1).includes('Ältere laden'));
  assert.ok(!text(page1).includes(M.CUT_TEXT));
  const both = loaded('admin_page1', { pages: ['admin_page2'] });
  assert.equal(count(screen(both), 'class="tm-mark"'), both.marks.length);
  // a cut answer without next_until names what to do
  const cut = { ...both, nextUntil: null, truncated: true };
  const html = screen(cut);
  assert.ok(text(html).includes(M.CUT_TEXT));
  assert.ok(!text(html).includes('Ältere laden'));
});

test('a page with only left-out entries is not "empty": the hint and "Ältere laden" (review S1)', () => {
  // the shape of a real first page (admin_page1); its part of the window holds client entries only
  const b = structuredClone(F.admin_page1.body);
  b.marks = [];
  b.omitted_client_marks = 3;
  b.sources = b.sources.map(src => src.id === 'ni_events'
    ? { ...src, state: 'ok', count: 0, oldest: null, truncated: true, cut: 'next_page' }
    : { ...src, count: 0, oldest: null });
  let s = M.listReducer(M.LIST_INIT, { type: 'start', seq: 1, more: false });
  s = M.listReducer(s, { type: 'first', gen: 0, seq: 1, answer: M.parseTimeline(b) });
  const html = screen(s);
  const t = text(html);
  assert.ok(t.includes(M.HIDDEN_ONLY_TEXT));
  assert.equal(M.HIDDEN_ONLY_TEXT, 'In diesem Abschnitt gibt es nur ausgeblendete Einträge. Ältere laden, um weiter zurückzugehen.');
  assert.ok(!t.includes(M.EMPTY_TEXT));
  assert.match(html, /<button[^>]*>Ältere laden<\/button>/);
  assert.ok(t.includes('Netzwerk-Ereignisse: 0 Marken · gekürzt'));
  assert.ok(!t.includes('Netzwerk-Ereignisse: leer'));
  assert.ok(t.includes('3 client-bezogene Ereignisse sind ausgeblendet.'));
  // an unreachable rest says so in its pill
  const u = M.sourcePill({ id: 'config_versions', state: 'ok', reason: null, count: 0, oldest: null, truncated: true, cut: 'unreachable' });
  assert.equal(u.text, '0 Marken · gekürzt, Älteres nicht abrufbar');
});

test('loading again keeps the old list on screen', () => {
  const state = loaded('admin', { loading: true });
  const html = screen(state);
  assert.equal(count(html, 'class="tm-mark"'), state.marks.length);
  assert.ok(text(html).includes(M.LOADING_TEXT));
  assert.match(html, /disabled=""[^>]*>Aktualisieren/);
});

test('errors: rights, unloaded, failed with retry, invalid filters with the field only', () => {
  const first = M.listReducer(M.LIST_INIT, { type: 'start', seq: 1, more: false });
  const fail = err => screen(M.listReducer(first, { type: 'fail', gen: 0, seq: 1, more: false, error: err }));
  for (const s of [401, 403]) {
    const t = text(fail(new M.TmApiError(s, 'forbidden')));
    assert.ok(t.includes('Keine Berechtigung für die Zeitreise.'));
    assert.ok(!t.includes('Erneut versuchen'));
  }
  assert.ok(text(fail(new M.TmApiError(410, 'integration_not_loaded'))).includes('Die Integration wurde entladen.'));
  for (const err of [new M.TmApiError(500, 'internal'), new TypeError('Failed to fetch')]) {
    const t = text(fail(err));
    assert.ok(t.includes('Die Zeitleiste konnte nicht geladen werden.'));
    assert.ok(t.includes('Erneut versuchen'));
  }
  const bad = F.bad_request.body;
  const t = text(fail(new M.TmApiError(400, bad.code, bad.details)));
  assert.ok(t.includes('Ungültige Filterkombination. Feld: Art.'));
  assert.ok(!t.includes('nope'));
  // an error on top of a loaded list keeps the list
  const kept = loaded('admin', { error: new M.TmApiError(503, '') });
  const html = screen(kept);
  assert.ok(text(html).includes('Erneut versuchen'));
  assert.equal(count(html, 'class="tm-mark"'), kept.marks.length);
});

test('no selectable source: a hint instead of a list', () => {
  const html = screen(loaded('admin'), { filters: { ...M.DEFAULT_FILTERS, sourcesOff: [...M.SOURCE_IDS] } });
  const t = text(html);
  assert.ok(t.includes(M.NO_SOURCE_TEXT));
  assert.ok(!html.includes('class="tm-mark"'));
  assert.ok(!t.includes('Ältere laden'));
});

test('an unknown title_key falls back to "Code <title_key>"', () => {
  const state = loaded('admin');
  const odd = { ...state, marks: [{ ...state.marks[0], id: 'tmm_ffffffffffffffff', titleKey: 'core_audit.future.thing', text: null }] };
  assert.ok(text(screen(odd)).includes('Code core_audit.future.thing'));
});

test('the container renders its first-load state without touching the network', () => {
  const never = { timeline: () => new Promise(() => {}) };
  const html = renderToStaticMarkup(h(M.TimeMachineView, { api: never }));
  assert.ok(text(html).includes(M.LOADING_TEXT));
});
