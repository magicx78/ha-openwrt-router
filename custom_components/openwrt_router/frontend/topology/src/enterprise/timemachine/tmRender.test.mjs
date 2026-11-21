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
// the query a first page was asked with (the cursor of its answer belongs to it)
const qOf = a => ({ from: a.from, until: a.until, sources: null, minSeverity: null, routerId: null, spans: true, cursor: null, client: null });

function loaded(name, { pages = [], loading = false, error = null } = {}) {
  let s = M.listReducer(M.LIST_INIT, { type: 'start', seq: 1, more: false });
  s = M.listReducer(s, { type: 'first', gen: 0, seq: 1, answer: M.parseTimeline(F[name].body), query: qOf(M.parseTimeline(F[name].body)) });
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

test('older pages: "Ältere laden" while there is a next_cursor, then the cut hint', () => {
  const page1 = screen(loaded('admin_page1'));
  assert.ok(text(page1).includes('Ältere laden'));
  assert.ok(!text(page1).includes(M.CUT_TEXT));
  const both = loaded('admin_page1', { pages: ['admin_page2'] });
  assert.equal(count(screen(both), 'class="tm-mark"'), both.marks.length);
  assert.equal(both.nextCursor, F.admin_page2.body.next_cursor);
  // a cut answer without next_cursor names what to do
  const cut = { ...both, nextCursor: null, truncated: true };
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
  s = M.listReducer(s, { type: 'first', gen: 0, seq: 1, answer: M.parseTimeline(b), query: qOf(M.parseTimeline(b)) });
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
  s = M.listReducer(s, { type: 'first', gen: 0, seq: 1, answer: M.parseTimeline(FC[name].body), query: qOf(M.parseTimeline(FC[name].body)) });
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
  s = M.sessionReducer(s, { type: 'first', gen: 0, seq: 1, answer: M.parseSessions(FC[name].body), query: qOf(M.parseSessions(FC[name].body)) });
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
  // the pills count the marks of the answer; the block before the window (spanning) is not in them
  for (const w of ['Eigener Verlauf: 2', 'Verweise: leer', 'Client-Verläufe: 4', 'Router wieder erreichbar', 'Router nicht erreichbar',
    'Dauer 5 min', 'Gewechselt', 'von Router 1 nach Router 2', 'Client ·a1ce4d', 'Client tablet-kueche', 'Verbunden', 'Getrennt',
    'per Zeitablauf erkannt', '1 Wechsel', 'noch offen, bisher 34 min', 'Eigener Verlauf', 'Clients']) assert.ok(t.includes(w), w);
  // a pseudonym is never shown whole, and nothing private is generated
  assert.ok(!t.includes('tmc_f3e24c9bafa1ce4d'));
  // ... but the short label carries it whole in its title, for the forget service (client: tmc_…)
  const titles = [...html.matchAll(/title="([^"]*)"/g)].map(x => x[1]).filter(x => x.includes('tmc_'));
  assert.ok(titles.length > 0);
  for (const x of titles) assert.match(x, /^tmc_[0-9a-f]{16}$/);
  for (const [, label] of html.matchAll(/<span class="tm-client" title="(tmc_[0-9a-f]{16})">/g)) assert.ok(label);
  assert.equal(count(html, 'class="tm-client" title="tmc_'), count(html, 'class="tm-client"'));
  assert.doesNotMatch(t, PRIVATE);
  assert.ok(!html.includes('dangerouslySetInnerHTML'));
  // no fallback title for any mark of the own index or the client histories
  for (const m of M.parseTimeline(FC.timeline.body).marks) assert.ok(!M.titleOf(m).startsWith('Ereignis'), m.code);
});

test('marks that began before the window: the first page’s spanning as a block on top', () => {
  const state = loadedC('timeline');
  const html = screenC(state);
  const t = text(html);
  const at = t.indexOf(M.SPANS_TITLE);
  assert.ok(at > 0);
  assert.ok(at < t.indexOf('Heute'), 'block above the days');
  const block = /<section class="tm-day tm-spans"[\s\S]*?<\/section>/.exec(html)[0];
  const spans = state.head.spanning;
  assert.equal(spans.length, 2);
  assert.equal(count(block, 'class="tm-mark"'), 2);
  // the first line is the start with date and time, the second how long it has run so far
  for (const m of spans) assert.ok(text(block).includes(M.startText(m.ts)), m.id);
  assert.ok(text(block).includes('noch offen, bisher 34 min'));
  assert.ok(text(block).includes('noch offen, bisher 35 min'));
  assert.doesNotMatch(text(block), /seit \d/);
  assert.ok(!html.includes('tm-spans-cut'));
  // every mark once: the block plus the answer's marks
  assert.equal(count(html, 'class="tm-mark"'), spans.length + state.marks.length);
  assert.ok(state.marks.every(m => !m.spansIn));
});

test('the block stays while older pages load, and only a new first page replaces it', () => {
  let s = loadedC('timeline_page1');
  const block = h => /<section class="tm-day tm-spans"[\s\S]*?<\/section>/.exec(h)?.[0] ?? null;
  const before = block(screenC(s));
  assert.ok(before);
  s = M.listReducer(s, { type: 'start', seq: 2, more: true });
  assert.equal(block(screenC(s)), before, 'while loading');
  s = M.listReducer(s, { type: 'older', gen: 0, seq: 2, answer: M.parseTimeline(FC.timeline_page2.body) });
  assert.equal(block(screenC(s)), before, 'after the older page');
  assert.equal(s.nextCursor, null);
  assert.ok(!text(screenC(s)).includes('Ältere laden'));
  // a new first page (refresh, also a restart) brings its own block
  s = M.listReducer(M.listReducer(s, { type: 'start', seq: 3, more: false }),
    { type: 'first', gen: 0, seq: 3, answer: M.parseTimeline(FC.timeline_spans_cut.body), query: qOf(M.parseTimeline(FC.timeline_spans_cut.body)) });
  assert.equal(count(block(screenC(s)), 'class="tm-mark"'), 1);
});

test('a cut block says that more run since before the window', () => {
  const html = screenC(loadedC('timeline_spans_cut'));
  const block = /<section class="tm-day tm-spans"[\s\S]*?<\/section>/.exec(html)[0];
  assert.equal(count(block, 'class="tm-mark"'), 1);
  assert.match(block, /class="cfg-hint tm-spans-cut" role="note">Weitere laufen seit vor dem Zeitfenster; Zeitfenster oder Filter enger wählen\.</);
});

test('a cursor the server refuses: plain words and "Aktualisieren", no retry button', () => {
  let s = loadedC('timeline_page1');
  s = M.listReducer(s, { type: 'start', seq: 2, more: true });
  s = M.listReducer(s, { type: 'fail', gen: 0, seq: 2, more: true, error: apiError('timeline_bad_cursor') });
  const html = screenC(s);
  assert.ok(text(html).includes('Die Stelle zum Weiterblättern liegt nicht mehr im Zeitfenster. Bitte „Aktualisieren“.'));
  assert.ok(!text(html).includes('out_of_range'));
  assert.ok(!html.includes('Erneut versuchen'));
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
    { type: 'first', gen: 0, seq: 1, answer: M.parseTimeline(body), query: qOf(M.parseTimeline(body)) });
  const html = screenC(state);
  assert.match(html, /title="2 doppelt ausgeblendet"[^>]*><span class="tm-pill__name">Eigener Verlauf<\/span>: 2 Marken · 2 doppelt/);
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

test('sessions: "Ältere laden" while next_cursor is set; a cut without it says so', () => {
  const first = sessionsState('sessions_page1');
  assert.ok(first.nextCursor);
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
  assert.ok(un.includes('Die Aufzeichnung läuft gerade nicht.'));
  assert.ok(!un.includes('not_running'));
  const nl = text(sessions(sessionsState('sessions_not_loaded')));
  assert.ok(nl.includes('Der gespeicherte Verlauf wird noch geladen.'));
  assert.ok(!nl.includes('not_loaded'));
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

test('sessions: the router name keeps its full text in the title, the client its pseudonym', () => {
  const html = sessions(sessionsState('sessions'));
  for (const [, title, name] of html.matchAll(/<span class="tm-session__router" title="([^"]*)">([^<]*)<\/span>/g)) assert.equal(title, name);
  assert.equal(count(html, 'class="tm-session__router" title="Router'), 3);
  assert.equal(count(html, 'class="tm-client" title="tmc_'), 3);
});

// ── 1.51.0 browser review: the effective flex of every item in a column ──
// A tiny cascade over the stylesheets the tab really loads (the panel's
// topology.css, then the tab's own <style> elements in their order:
// config.css, wifi.css, timemachine.css), applied to the rendered markup.
// In a column flex box (.cfg is one) a flex-basis is a height: the view
// switch, a .tm-chips row with `flex: 1 1 260px`, stood 260 px tall in
// Firefox. The check below finds, for every element whose parent is a
// column flex box, the winning flex-basis by specificity and source order
// and fails on a fixed length. With the rule `.tm-chips.tm-views` taken out
// it reports exactly that 260 px (asserted below), so this bug is red.

const CSS_FILES = ['../../topology.css', '../config/config.css', '../wifi/wifi.css', 'timemachine.css'];

function parseCss(src, media = null, out = []) {
  src = src.replace(/\/\*[\s\S]*?\*\//g, '');
  let i = 0;
  while (i < src.length) {
    const open = src.indexOf('{', i);
    if (open < 0) break;
    const head = src.slice(i, open).trim();
    let depth = 1, j = open + 1;
    while (j < src.length && depth) { if (src[j] === '{') depth++; else if (src[j] === '}') depth--; j++; }
    const body = src.slice(open + 1, j - 1);
    if (head.startsWith('@media')) {
      const w = /max-width:\s*(\d+)px/.exec(head);
      parseCss(body, w ? Number(w[1]) : Infinity, out);
    } else if (!head.startsWith('@')) {
      const decls = body.split(';').map(d => d.trim()).filter(Boolean).map(d => {
        const k = d.indexOf(':');
        return [d.slice(0, k).trim(), d.slice(k + 1).trim()];
      });
      for (const sel of head.split(',').map(x => x.trim()).filter(Boolean)) out.push({ sel, decls, media, order: out.length });
    }
    i = j;
  }
  return out;
}

// compound selectors with ' ' and '>' combinators; pseudo-classes and attributes never match a resting element
function parseSel(sel) {
  const parts = sel.replace(/\s*>\s*/g, ' > ').split(/\s+/);
  const chain = [];
  let comb = ' ';
  for (const p of parts) {
    if (p === '>') { comb = '>'; continue; }
    const m = /^(\*|[a-z][a-z0-9]*)?((?:\.[\w-]+)*)(.*)$/i.exec(p);
    chain.push({ comb, tag: m[1] && m[1] !== '*' ? m[1].toLowerCase() : null, classes: m[2].split('.').filter(Boolean), rest: m[3] });
    comb = ' ';
  }
  const spec = chain.reduce((s, c) => s + c.classes.length * 100 + (c.tag ? 1 : 0) + (c.rest ? 100 : 0), 0);
  return { chain, spec };
}
const matchesOne = (c, el) => !c.rest && (!c.tag || c.tag === el.tag) && c.classes.every(x => el.classes.includes(x));
function matches(chain, el, k = chain.length - 1) {
  if (!el || !matchesOne(chain[k], el)) return false;
  if (k === 0) return true;
  if (chain[k].comb === '>') return matches(chain, el.parent, k - 1);
  for (let a = el.parent; a; a = a.parent) if (matches(chain, a, k - 1)) return true;
  return false;
}

function parseHtml(html) {
  html = html.replace(/<style>[\s\S]*?<\/style>/g, '');
  const VOID = new Set(['input', 'br', 'hr', 'img', 'meta', 'link']);
  const root = { tag: '#root', classes: [], children: [], parent: null };
  let cur = root;
  for (const m of html.matchAll(/<(\/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*?)(\/?)>/g)) {
    if (m[1]) { cur = cur.parent; continue; }
    const cls = /class="([^"]*)"/.exec(m[3]);
    const el = { tag: m[2].toLowerCase(), classes: cls ? cls[1].split(/\s+/) : [], children: [], parent: cur };
    cur.children.push(el);
    if (!m[4] && !VOID.has(el.tag)) cur = el;
  }
  return root;
}

function flexOf(value) {
  const t = value.split(/\s+/);
  if (value === 'none') return { grow: '0', basis: 'auto' };
  if (value === 'auto') return { grow: '1', basis: 'auto' };
  if (t.length === 1) return /^[\d.]+$/.test(t[0]) ? { grow: t[0], basis: '0%' } : { grow: '1', basis: t[0] };
  if (t.length === 2) return /^[\d.]+$/.test(t[1]) ? { grow: t[0], basis: '0%' } : { grow: t[0], basis: t[1] };
  return { grow: t[0], basis: t[2] };
}

/** The winning value of each property for one element at a viewport width. */
function computed(rules, el, width) {
  const win = {};
  for (const r of rules) {
    if (r.media !== null && width > r.media) continue;
    const { chain, spec } = r.parsed;
    if (!matches(chain, el)) continue;
    for (const [k, v] of r.decls) {
      const set = (prop, val) => {
        const w = win[prop];
        if (!w || spec > w.spec || (spec === w.spec && r.order >= w.order)) win[prop] = { val, spec, order: r.order, sel: r.sel };
      };
      if (k === 'flex') { const f = flexOf(v); set('flex-grow', f.grow); set('flex-basis', f.basis); }
      else set(k, v);
    }
  }
  return win;
}

function loadRules(override = {}) {
  const rules = [];
  for (const f of CSS_FILES) parseCss(override[f] ?? readFileSync(join(here, f), 'utf8'), null, rules);
  rules.forEach((r, i) => { r.order = i; r.parsed = parseSel(r.sel); });
  return rules;
}

/** Items of a column flex box whose winning flex-basis is a fixed length (a height there). */
function columnTraps(rules, html, width) {
  const bad = [];
  const walk = el => {
    for (const c of el.children) {
      if (el.tag !== '#root') {
        const p = computed(rules, el, width);
        const col = /flex/.test(p.display?.val ?? '') && p['flex-direction']?.val?.startsWith('column');
        if (col) {
          const b = computed(rules, c, width)['flex-basis'];
          if (b && /^[1-9][\d.]*(px|em|rem|vh|ch)$/.test(b.val)) bad.push(`${c.classes.join('.')} @${width}px: flex-basis ${b.val} from "${b.sel}"`);
        }
      }
      walk(c);
    }
  };
  walk(parseHtml(html));
  return bad;
}

function everyScreen() {
  const api = { timeline: () => new Promise(noop), sessions: () => new Promise(noop) };
  const sw = view => h(M.ViewSwitch, { view, onView: noop });
  const restarted = { ...loadedC('timeline'), restarted: true };
  let failed = M.listReducer(loadedC('timeline_page1'), { type: 'start', seq: 2, more: true });
  failed = M.listReducer(failed, { type: 'fail', gen: 0, seq: 2, more: true, error: apiError('timeline_bad_cursor') });
  return {
    loading: renderToStaticMarkup(h(M.TimeMachineView, { api, isAdmin: true })),
    timeline: screenC(loadedC('timeline_spans_cut'), { viewSwitch: sw('timeline') }),
    restarted: screenC(restarted, { viewSwitch: sw('timeline') }),
    failed: screenC(failed, { viewSwitch: sw('timeline') }),
    page1: screen(loaded('admin_page1')),
    off: screen(loaded('off')),
    sessions: sessions(sessionsState('sessions_page1'), { viewSwitch: sw('sessions') }),
    clientsOff: sessions(sessionsState('sessions_clients_off'), { viewSwitch: sw('sessions') }),
    unavailable: sessions(sessionsState('sessions_unavailable'), { viewSwitch: sw('sessions') }),
  };
}

test('no item of a column flex box gets a fixed flex-basis (the 260 px view switch)', () => {
  const rules = loadRules();
  const screens = everyScreen();
  assert.ok(screens.loading.includes('tm-chips tm-views'));
  for (const [name, html] of Object.entries(screens)) {
    for (const width of [1280, 768, 360]) assert.deepEqual(columnTraps(rules, html, width), [], `${name} @${width}px`);
  }
  // the view switch itself: .cfg is a column, and the winning rule is the tab's own
  const tree = parseHtml(screens.loading);
  const find = (el, cls) => el.classes.includes(cls) ? el : el.children.map(c => find(c, cls)).find(Boolean);
  const views = find(tree, 'tm-views');
  assert.ok(views.parent.classes.includes('cfg'));
  assert.equal(computed(rules, views.parent, 1280)['flex-direction'].val, 'column');
  for (const width of [1280, 360]) {
    const c = computed(rules, views, width);
    assert.equal(c['flex-basis'].val, 'auto');
    assert.equal(c['flex-grow'].val, '0');
    assert.equal(c['flex-basis'].sel, '.tm-chips.tm-views');
  }
  // without that rule the check reports exactly the bug of the browser review
  const tm = readFileSync(join(here, 'timemachine.css'), 'utf8');
  const without = tm.replace('.tm-chips.tm-views { flex: 0 0 auto; }', '');
  assert.notEqual(without, tm);
  const traps = columnTraps(loadRules({ 'timemachine.css': without }), screens.loading, 1280);
  assert.deepEqual(traps, ['tm-chips.tm-views @1280px: flex-basis 260px from ".tm-chips"']);
});
