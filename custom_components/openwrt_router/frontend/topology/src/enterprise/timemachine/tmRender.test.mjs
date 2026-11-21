// Render tests of the "Zeitreise" tab (node:test). The views are bundled
// once with esbuild (Vite's own bundler, already in node_modules; no new
// dependency) and rendered with react-dom/server. The answers are real route
// answers from tmFixture.json (tests/test_tm_panel_fixture_v1500.py) and
// tmFixtureClients.json (tests/test_tm_panel_fixture_v1510.py), invented
// values only.
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
// Phases B/C from one world of three routers (tests/test_tm_panel_fixture_v1510.py)
const FC = JSON.parse(readFileSync(join(here, 'tmFixtureClients.json'), 'utf8'));

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
        "export { TimeMachineScreen, FilterBar, TimeMachineView, SessionsScreen, ViewSwitch } from './TimeMachineView';",
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

// ── 1.51.0: own history, intervals, clients, sessions ───────────────────

const FC_NOW = FC.timeline.body.generated_at * 1000;

function loadedC(name, { pages = [] } = {}) {
  let s = M.listReducer(M.LIST_INIT, { type: 'start', seq: 1, more: false });
  s = M.listReducer(s, { type: 'first', gen: 0, seq: 1, answer: M.parseTimeline(FC[name].body) });
  pages.forEach((p, i) => {
    s = M.listReducer(s, { type: 'start', seq: i + 2, more: true });
    s = M.listReducer(s, { type: 'older', gen: 0, seq: i + 2, answer: M.parseTimeline(FC[p].body) });
  });
  return s;
}
function screenC(state, extra = {}) {
  return renderToStaticMarkup(h(M.TimeMachineScreen, {
    state, filters: M.DEFAULT_FILTERS, hidden: [], routers: M.rememberRouters({}, state.marks), nowMs: FC_NOW,
    onFilters: noop, onToggleGroup: noop, onRefresh: noop, onMore: noop, onDismiss: noop, ...extra,
  })).replace(/<style>[\s\S]*?<\/style>/g, '');
}

function apiError(name) {
  const { status, body } = FC[name];
  return new M.TmApiError(status, body.code, body.details ?? {});
}
function sessionsState(name, { pages = [], error = null } = {}) {
  let s = M.sessionReducer(M.SESSION_LIST_INIT, { type: 'start', seq: 1, more: false });
  if (error) return M.sessionReducer(s, { type: 'fail', gen: 0, seq: 1, more: false, error });
  s = M.sessionReducer(s, { type: 'first', gen: 0, seq: 1, answer: M.parseSessions(FC[name].body) });
  pages.forEach((p, i) => {
    s = M.sessionReducer(s, { type: 'start', seq: i + 2, more: true });
    s = M.sessionReducer(s, { type: 'older', gen: 0, seq: i + 2, answer: M.parseSessions(FC[p].body) });
  });
  return s;
}
function sessions(state, extra = {}) {
  return renderToStaticMarkup(h(M.SessionsScreen, {
    state, filters: M.DEFAULT_SESSION_FILTERS, routers: M.rememberSessionRouters({}, state.sessions),
    clients: M.rememberClients({}, state.sessions), nowMs: FC_NOW,
    onFilters: noop, onRefresh: noop, onMore: noop, onDismiss: noop, ...extra,
  })).replace(/<style>[\s\S]*?<\/style>/g, '');
}

test('own history: titles, durations, client labels and the roaming text', () => {
  const html = screenC(loadedC('timeline'));
  const t = text(html);
  for (const w of ['Eigener Verlauf: 3', 'Verweise: leer', 'Client-Verläufe: 5', 'Router wieder erreichbar', 'Router nicht erreichbar',
    'Dauer 5 min', 'Gewechselt', 'von Router 1 nach Router 2', 'Client ·a1ce4d', 'Client tablet-kueche', 'Verbunden', 'Getrennt',
    'per Zeitablauf erkannt', '1 Wechsel', 'seit 09:01, noch offen', 'Eigener Verlauf', 'Clients']) assert.ok(t.includes(w), w);
  // a pseudonym is never shown whole, and nothing private is generated
  assert.ok(!t.includes('tmc_f3e24c9bafa1ce4d'));
  assert.doesNotMatch(t, PRIVATE);
  assert.ok(!html.includes('dangerouslySetInnerHTML'));
  // no fallback title for any mark of the own index or the client histories
  for (const m of M.parseTimeline(FC.timeline.body).marks) assert.ok(!M.titleOf(m).startsWith('Ereignis'), m.code);
});

test('marks that began before the window stand in their own block on top, with date and time', () => {
  const state = loadedC('timeline');
  const html = screenC(state);
  const t = text(html);
  const at = t.indexOf(M.SPANS_TITLE);
  assert.ok(at > 0);
  assert.ok(at < t.indexOf('Heute'), 'block above the days');
  const block = /<section class="tm-day tm-spans"[\s\S]*?<\/section>/.exec(html)[0];
  assert.equal(count(block, 'class="tm-mark"'), 2);
  const spans = state.marks.filter(m => m.spansIn);
  assert.equal(spans.length, 2);
  for (const m of spans) assert.ok(text(block).includes(M.startText(m.ts)), m.id);
  assert.match(text(block), /seit \d\d\.\d\d\., \d\d:\d\d, noch offen|seit \d\d:\d\d, noch offen/);
  // every mark once: 9 in the answer, 2 in the block, 6 below
  assert.equal(count(html, 'class="tm-mark"'), state.marks.length);
});

test('a non-admin answer: references and client histories locked, no block of clients', () => {
  const html = screenC(loadedC('timeline_user'));
  for (const name of ['Verweise', 'Client-Verläufe']) {
    assert.match(html, new RegExp(`disabled=""[^>]*>${name}<span class="tm-chip__note"> · nur für Administratoren`), name);
  }
  assert.ok(!text(html).includes('Client ·'));
});

test('client histories off: the pill says how to switch them on', () => {
  const t = text(screenC(loadedC('timeline_clients_off')));
  assert.ok(t.includes('Client-Verläufe: aus · in den Optionen einschalten'));
  assert.ok(!t.includes('späteren Version'));
});

test('doubles: the pill says "n doppelt" and its title says what happened', () => {
  const body = structuredClone(FC.timeline.body);
  body.sources.find(s => s.id === 'tm_index').duplicates = 2;
  const state = M.listReducer(M.listReducer(M.LIST_INIT, { type: 'start', seq: 1, more: false }),
    { type: 'first', gen: 0, seq: 1, answer: M.parseTimeline(body) });
  const html = screenC(state);
  assert.match(html, /title="2 doppelt ausgeblendet"[^>]*><span class="tm-pill__name">Eigener Verlauf<\/span>: 3 Marken · 2 doppelt/);
});

test('after "Ältere laden" the sources heading says "(neueste Seite)"', () => {
  assert.ok(!text(screenC(loadedC('timeline_page1'))).includes(M.SOURCES_NEWEST));
  const t = text(screenC(loadedC('timeline_page1', { pages: ['timeline'] })));
  assert.ok(t.includes(`${M.SOURCES_TITLE} ${M.SOURCES_NEWEST}`));
});

test('a restarted list shows the notice with a button to dismiss it', () => {
  const state = { ...loadedC('timeline'), restarted: true };
  const html = screenC(state);
  assert.ok(text(html).includes(M.RESTART_TEXT));
  assert.match(html, /tm-restart[\s\S]*?>Ausblenden<\/button>/);
  assert.ok(!text(screenC(M.listReducer(state, { type: 'dismiss' }))).includes(M.RESTART_TEXT));
});

test('the view switch: administrators see both chips, everyone else none', () => {
  const api = { timeline: () => new Promise(noop), sessions: () => new Promise(noop) };
  const admin = renderToStaticMarkup(h(M.TimeMachineView, { api, isAdmin: true }));
  assert.match(admin, /aria-pressed="true"[^>]*>Zeitleiste<\/button>/);
  assert.match(admin, /aria-pressed="false"[^>]*>Client-Sitzungen<\/button>/);
  const bare = props => renderToStaticMarkup(h(M.TimeMachineView, props)).replace(/<style>[\s\S]*?<\/style>/g, '');
  assert.ok(bare({ api, isAdmin: true }).includes('tm-views'));
  for (const html of [bare({ api, isAdmin: false }), bare({ api })]) {
    assert.ok(!html.includes('Client-Sitzungen'));
    assert.ok(!html.includes('tm-views'));
  }
});

test('sessions: days, start, duration, client, router, band and changes', () => {
  const state = sessionsState('sessions');
  const html = sessions(state, { viewSwitch: h(M.ViewSwitch, { view: 'sessions', onView: noop }) });
  const t = text(html);
  assert.equal(count(html, 'class="tm-session"'), 3);
  for (const w of ['Zeitleiste', 'Client-Sitzungen', 'Zeitfenster', 'Alle Router', 'Alle Clients', 'Client ·a1ce4d', 'Client tablet-kueche',
    'Router 1', 'Router 2', '5 GHz', 'Dauer 1 min', 'Dauer 3 min', 'noch verbunden', '1 Wechsel', M.RECORDING_ON, 'Heute']) assert.ok(t.includes(w), w);
  assert.match(html, /aria-pressed="true"[^>]*>Client-Sitzungen<\/button>/);
  // newest start first
  const starts = [...html.matchAll(/class="tm-session__time" dateTime="([^"]+)"/g)].map(m => m[1]);
  assert.deepEqual(starts, [...starts].sort().reverse());
  assert.ok(!t.includes('tmc_'));
  assert.doesNotMatch(t, PRIVATE);
  assert.ok(!t.includes('Ältere laden'));
  // the client select names each client by its label only
  assert.match(html, /<option value="tmc_11154ea545af3e29">Client tablet-kueche<\/option>/);
});

test('sessions: "Ältere laden" while next_until is set; a cut without it says so', () => {
  const first = sessionsState('sessions_page1');
  assert.ok(text(sessions(first)).includes('Ältere laden'));
  const both = sessionsState('sessions_page1', { pages: ['sessions_page2'] });
  assert.equal(count(sessions(both), 'class="tm-session"'), 3);
  assert.ok(!text(sessions(both)).includes('Ältere laden'));
  const cut = { ...both, truncated: true };
  assert.ok(text(sessions(cut)).includes(M.SESSIONS_CUT_TEXT));
});

test('sessions: off, client histories off, unavailable and empty', () => {
  const off = text(sessions(sessionsState('sessions_off')));
  assert.ok(off.includes(M.OFF_TITLE) && off.includes(M.OFF_HOW));
  const coff = sessions(sessionsState('sessions_clients_off'));
  for (const w of [M.CLIENTS_OFF_TITLE, M.CLIENTS_OFF_HOW, M.CLIENTS_PRIVACY]) assert.ok(text(coff).includes(w), w);
  assert.ok(!coff.includes('tm-filters'));
  const un = text(sessions(sessionsState('sessions_unavailable')));
  assert.ok(un.includes(M.UNAVAILABLE_TITLE));
  assert.ok(un.includes('Grund:'));
  assert.ok(!un.includes('not_running'));
  const empty = text(sessions(sessionsState('sessions_empty')));
  assert.ok(empty.includes(M.SESSIONS_EMPTY_TEXT));
  assert.ok(!/[✓✔]/.test(empty));
});

test('sessions: 403, 410, 5xx and 400 in plain words, never the server text', () => {
  const forbidden = text(sessions(sessionsState(null, { error: apiError('sessions_user') })));
  assert.ok(forbidden.includes('Keine Berechtigung für die Client-Sitzungen'));
  assert.ok(!forbidden.includes('administrators only'));
  const bad = text(sessions(sessionsState(null, { error: apiError('sessions_bad_request') })));
  assert.ok(bad.includes('Ungültige Filterkombination. Feld: Client.'));
  const gone = text(sessions(sessionsState(null, { error: new M.TmApiError(410, 'gone') })));
  assert.ok(gone.includes('Die Integration wurde entladen.'));
  const failed = sessions(sessionsState(null, { error: new M.TmApiError(503, 'x') }));
  assert.ok(text(failed).includes(M.SESSIONS_FAILED_TEXT));
  assert.ok(failed.includes('Erneut versuchen'));
});

test('sessions: the first load is a spinner, a running reload keeps the list', () => {
  const start = M.sessionReducer(M.SESSION_LIST_INIT, { type: 'start', seq: 1, more: false });
  assert.ok(text(sessions(start)).includes(M.SESSIONS_LOADING_TEXT));
  const again = M.sessionReducer(sessionsState('sessions'), { type: 'start', seq: 5, more: false });
  const html = sessions(again);
  assert.equal(count(html, 'class="tm-session"'), 3);
  assert.ok(text(html).includes(M.SESSIONS_LOADING_TEXT));
});
