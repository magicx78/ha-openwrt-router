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
// Phases D-F: state, compare, export (tests/test_tm_panel_fixture_v1520.py)
const FS = JSON.parse(readFileSync(join(here, 'tmFixtureState.json'), 'utf8'));
// 1.52.2: after the update from 1.51.0, a disabled router (tests/test_tm_compare_display_v1522.py)
const FX = JSON.parse(readFileSync(join(here, 'tmFixtureCompare.json'), 'utf8'));

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
        "export { TimeMachineScreen, FilterBar, TimeMachineView, SessionsScreen, ViewSwitch, ExportBox, EXPORT_INIT, exportStep } from './TimeMachineView';",
        "export { StateScreen, CompareScreen, StateContainer, CompareContainer } from './TimeMachineState';",
        "export { JumpContext, MarkRow } from './tmUi';",
        "export * as TS from './tmState.ts';",
        "export { isEnterpriseTabAvailable, openEnterpriseTab, peekEnterpriseEntry, clearEnterpriseEntry, onEnterpriseOpen } from '../registry';",
        "export { SecurityCenterView, entryIncident } from '../security/SecurityCenterView';",
        "export { ConfigManagerView, entryRouter } from '../config/ConfigManagerView';",
        "export { EnterpriseView } from '../../components/EnterpriseView';",
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
  assert.equal(count(html, '<li class="tm-mark'), state.marks.length);
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
  assert.equal(count(html, '<li class="tm-mark'), shown);
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
  assert.equal(count(screen(both), '<li class="tm-mark'), both.marks.length);
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
  assert.equal(count(html, '<li class="tm-mark'), state.marks.length);
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
  assert.equal(count(html, '<li class="tm-mark'), kept.marks.length);
});

test('no selectable source: a hint instead of a list', () => {
  const html = screen(loaded('admin'), { filters: { ...M.DEFAULT_FILTERS, sourcesOff: [...M.SOURCE_IDS] } });
  const t = text(html);
  assert.ok(t.includes(M.NO_SOURCE_TEXT));
  assert.ok(!html.includes('<li class="tm-mark'));
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
  // with a name the title is "<name> · tmc_…" (the name is clamped in a row), else the pseudonym alone
  for (const x of titles) assert.match(x, /^(?:[^·]+ · )?tmc_[0-9a-f]{16}$/);
  assert.ok(titles.includes('tablet-kueche · tmc_11154ea545af3e29'), titles.join(', '));
  for (const [, title, label] of html.matchAll(/<span class="tm-client" title="([^"]*)">([^<]*)<\/span>/g)) {
    if (label.startsWith('Client ·')) assert.match(title, /^tmc_[0-9a-f]{16}$/);
    else assert.equal(title, `${label.replace(/^Client /, '')} · ${title.split(' · ').pop()}`);
  }
  assert.equal(count(html, 'class="tm-client" title="'), count(html, 'class="tm-client"'));
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
  assert.equal(count(block, '<li class="tm-mark'), 2);
  // the first line is the start with date and time, the second how long it has run so far
  for (const m of spans) assert.ok(text(block).includes(M.startText(m.ts)), m.id);
  assert.ok(text(block).includes('noch offen, bisher 34 min'));
  assert.ok(text(block).includes('noch offen, bisher 35 min'));
  assert.doesNotMatch(text(block), /seit \d/);
  assert.ok(!html.includes('tm-spans-cut'));
  // every mark once: the block plus the answer's marks
  assert.equal(count(html, '<li class="tm-mark'), spans.length + state.marks.length);
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
  assert.equal(count(block(screenC(s)), '<li class="tm-mark'), 1);
});

test('a cut block says that more run since before the window', () => {
  const html = screenC(loadedC('timeline_spans_cut'));
  const block = /<section class="tm-day tm-spans"[\s\S]*?<\/section>/.exec(html)[0];
  assert.equal(count(block, '<li class="tm-mark'), 1);
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

test('the view switch: administrators see four chips, everyone else three (no sessions)', () => {
  const api = { timeline: () => new Promise(noop), sessions: () => new Promise(noop) };
  const admin = renderToStaticMarkup(h(M.TimeMachineView, { api, isAdmin: true }));
  assert.match(admin, /aria-pressed="true"[^>]*>Zeitleiste<\/button>/);
  for (const name of ['Zustand', 'Vergleich', 'Client-Sitzungen']) assert.match(admin, new RegExp(`aria-pressed="false"[^>]*>${name}</button>`));
  const bare = props => renderToStaticMarkup(h(M.TimeMachineView, props)).replace(/<style>[\s\S]*?<\/style>/g, '');
  assert.ok(bare({ api, isAdmin: true }).includes('tm-views'));
  for (const html of [bare({ api, isAdmin: false }), bare({ api })]) {
    assert.ok(!html.includes('Client-Sitzungen'));
    assert.ok(html.includes('tm-views'));
    assert.match(html, />Zustand<\/button>/);
    assert.match(html, />Vergleich<\/button>/);
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
  // the client: its pseudonym, after its full name when it has one
  const titles = [...html.matchAll(/class="tm-client" title="([^"]*)"/g)].map(x => x[1]);
  assert.equal(titles.length, 3);
  for (const t of titles) assert.match(t, /^(?:[^·]+ · )?tmc_[0-9a-f]{16}$/);
  assert.ok(titles.some(t => t.includes(' · tmc_')));
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

function parseCss(src, media = null, out = [], container = null, cwidth = null) {
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
      parseCss(body, w ? Number(w[1]) : Infinity, out, container, cwidth);
    } else if (head.startsWith('@container')) {
      // an unnamed query (@container (max-width: …)) asks the nearest size container: '*'
      parseCss(body, media, out, /^@container\s+([a-z][\w-]*)\s*\(/i.exec(head)?.[1] ?? '*',
        Number(/max-width:\s*(\d+)px/.exec(head)?.[1] ?? NaN));
    } else if (!head.startsWith('@')) {
      const decls = body.split(';').map(d => d.trim()).filter(Boolean).map(d => {
        const k = d.indexOf(':');
        return [d.slice(0, k).trim(), d.slice(k + 1).trim()];
      });
      for (const sel of head.split(',').map(x => x.trim()).filter(Boolean)) out.push({ sel, decls, media, container, cwidth, order: out.length });
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
  const root = { tag: '#root', classes: [], children: [], parent: null, text: '' };
  let cur = root;
  let last = 0;
  for (const m of html.matchAll(/<(\/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*?)(\/?)>/g)) {
    // the text right inside an element (no markup): its own text
    cur.text += html.slice(last, m.index);
    last = m.index + m[0].length;
    if (m[1]) { cur = cur.parent; continue; }
    const cls = /class="([^"]*)"/.exec(m[3]);
    const el = { tag: m[2].toLowerCase(), classes: cls ? cls[1].split(/\s+/) : [], children: [], parent: cur, text: '' };
    cur.children.push(el);
    if (!m[4] && !VOID.has(el.tag)) cur = el;
  }
  return root;
}

function flexOf(value) {
  // tokens, a calc(…) with its spaces as one
  const t = value.match(/(?:[^\s(]+|\([^)]*\))+/g) ?? [];
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
    if (r.container !== null) continue; // container queries: see containerTraps
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

/**
 * Elements a rule inside `@container <name>` is written for, but which have
 * no ancestor that is a container of that name: the query never applies to
 * them (second browser review: the block before the window sat beside the
 * tmlist container and kept its six columns at 360 px).
 */
function containerTraps(rules, html) {
  const bad = new Set();
  const names = el => {
    const c = computed(rules, el, 1280);
    const v = c['container-name']?.val ?? c.container?.val?.split('/')[0];
    return v ? v.trim().split(/\s+/) : [];
  };
  const isContainer = el => {
    const c = computed(rules, el, 1280);
    return /inline-size|size/.test(c['container-type']?.val ?? c.container?.val ?? '');
  };
  const walk = el => {
    for (const r of rules) {
      if (r.container === null || el.tag === '#root' || !matches(r.parsed.chain, el)) continue;
      let a = el.parent;
      while (a && a.tag !== '#root' && !(r.container === '*' ? isContainer(a) : names(a).includes(r.container))) a = a.parent;
      if (!a || a.tag === '#root') bad.add(`${el.classes.join('.')} outside @container ${r.container} ("${r.sel}")`);
    }
    el.children.forEach(walk);
  };
  walk(parseHtml(html));
  return [...bad].sort();
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
    user: screenC(loadedC('timeline_user')),
    timelineFull: screenC(loadedC('timeline'), { viewSwitch: sw('timeline') }),
    timelineOlder: screenC(loadedC('timeline_page1', { pages: ['timeline_page2'] })),
    clientsOffTimeline: screenC(loadedC('timeline_clients_off')),
    partial: screen(loaded('partial')),
    empty: screen(loaded('empty')),
    admin: screen(loaded('admin')),
    sessionsAll: sessions(sessionsState('sessions'), { viewSwitch: sw('sessions') }),
    sessionsOlder: sessions(sessionsState('sessions_page1', { pages: ['sessions_page2'] })),
    sessionsEmpty: sessions(sessionsState('sessions_empty')),
    sessionsNotLoaded: sessions(sessionsState('sessions_not_loaded')),
    sessionsOff: sessions(sessionsState('sessions_off')),
    sessionsError: sessions(sessionsState(null, { error: apiError('sessions_bad_request') })),
    ...stateScreens(sw),
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

test('every rule inside @container reaches its elements: they sit in a container of that name', () => {
  const rules = loadRules();
  assert.ok(rules.some(r => r.container === 'tmlist') && rules.some(r => r.container === 'tmsessions'));
  const screens = everyScreen();
  for (const [name, html] of Object.entries(screens)) assert.deepEqual(containerTraps(rules, html), [], name);
  // the rows really are under the queries: marks of the block, of the list, and sessions
  const tree = parseHtml(screens.timelineFull);
  const all = (el, cls, out = []) => { if (el.classes.includes(cls)) out.push(el); el.children.forEach(c => all(c, cls, out)); return out; };
  const marks = all(tree, 'tm-mark');
  assert.ok(marks.length >= 8);
  const up = (el, cls) => { for (let a = el.parent; a; a = a.parent) if (a.classes.includes(cls)) return a; return null; };
  for (const m of marks) assert.ok(up(m, 'tm-timeline'), 'every mark inside .tm-timeline');
  assert.equal(marks.filter(m => up(m, 'tm-spans')).length, 2);
  // the state before the fix (container on .tm-list, the block beside it) is red, for exactly the block
  const tm = readFileSync(join(here, 'timemachine.css'), 'utf8');
  const old = tm
    .replace('.tm-timeline { display: flex; flex-direction: column; gap: 10px; min-width: 0; container: tmlist / inline-size; }', '.tm-timeline { display: flex; }')
    .replace('.tm-list { display: flex; flex-direction: column; gap: 10px; min-width: 0; }', '.tm-list { display: flex; flex-direction: column; gap: 10px; min-width: 0; container: tmlist / inline-size; }');
  assert.notEqual(old, tm);
  const traps = containerTraps(loadRules({ 'timemachine.css': old }), screens.timelineFull);
  assert.ok(traps.length > 0);
  for (const t of traps) assert.match(t, /^tm-mark(__\w+|\.tm-mark--start)? outside @container tmlist/, t);
  assert.ok(traps.includes('tm-mark.tm-mark--start outside @container tmlist (".tm-mark")'));
  assert.ok(traps.includes('tm-mark.tm-mark--start outside @container tmlist (".tm-mark.tm-mark--start")'));
  assert.ok(traps.includes('tm-mark__main outside @container tmlist (".tm-mark__main")'));
  // ... and so are the marks of the list fine in that old state: only the block is hit
  assert.equal(marks.filter(m => !up(m, 'tm-spans')).length, marks.length - 2);
});

test('after a refused cursor "Ältere laden" is gone until a new first page (both views)', () => {
  const refused = apiError('timeline_bad_cursor');
  let t = loadedC('timeline_page1');
  t = M.listReducer(t, { type: 'start', seq: 2, more: true });
  t = M.listReducer(t, { type: 'fail', gen: 0, seq: 2, more: true, error: refused });
  assert.equal(t.cursorRefused, true);
  const html = screenC(t);
  assert.ok(text(html).includes('Die Stelle zum Weiterblättern liegt nicht mehr im Zeitfenster.'));
  assert.ok(!text(html).includes('Ältere laden'));
  // "Aktualisieren": a new first page brings a fresh cursor and the button again
  t = M.listReducer(M.listReducer(t, { type: 'start', seq: 3, more: false }),
    { type: 'first', gen: 0, seq: 3, answer: M.parseTimeline(FC.timeline_page1.body), query: qOf(M.parseTimeline(FC.timeline_page1.body)) });
  assert.equal(t.cursorRefused, false);
  assert.ok(text(screenC(t)).includes('Ältere laden'));
  assert.ok(!text(screenC(t)).includes('Weiterblättern'));
  // sessions
  let s = sessionsState('sessions_page1');
  s = M.sessionReducer(s, { type: 'start', seq: 2, more: true });
  s = M.sessionReducer(s, { type: 'fail', gen: 0, seq: 2, more: true, error: new M.TmApiError(400, 'invalid_request', { field: 'cursor', reason: 'invalid' }) });
  assert.ok(!text(sessions(s)).includes('Ältere laden'));
  assert.ok(text(sessions(s)).includes('Ungültige Stelle zum Weiterblättern.'));
  s = M.sessionReducer(M.sessionReducer(s, { type: 'start', seq: 3, more: false }),
    { type: 'first', gen: 0, seq: 3, answer: M.parseSessions(FC.sessions_page1.body), query: qOf(M.parseSessions(FC.sessions_page1.body)) });
  assert.ok(text(sessions(s)).includes('Ältere laden'));
  // another failure of an older page (503) keeps the button: it can be tried again
  let o = M.listReducer(loadedC('timeline_page1'), { type: 'start', seq: 2, more: true });
  o = M.listReducer(o, { type: 'fail', gen: 0, seq: 2, more: true, error: new M.TmApiError(503, 'x') });
  assert.equal(o.cursorRefused, false);
  assert.ok(text(screenC(o)).includes('Ältere laden'));
});

// ── 1.52.0: "Zustand", "Vergleich", export, jumps, own window, client filter ─

const FS_NOW = FS.state.body.generated_at * 1000;
const RS1 = 'rtr_11111111111111111111111111111111';
const RS2 = 'rtr_22222222222222222222222222222222';
const RNAMES = { [RS1]: 'Router 1', [RS2]: 'Router 2' };
const RS3 = 'rtr_33333333333333333333333333333333';
const RNAMES3 = { ...RNAMES, [RS3]: 'Router 3' };
const BKP = 'bkp_' + 'a'.repeat(32);
const errS = name => new M.TmApiError(FS[name].status, FS[name].body.code, FS[name].body.details ?? {});

function stView(name, { error = null, more = [], loading = false } = {}) {
  let s = M.TS.stateReducer(M.TS.STATE_INIT, { type: 'start', seq: 1 });
  if (name === null) return error ? M.TS.stateReducer(s, { type: 'fail', seq: 1, error }) : s;
  const body = typeof name === 'string' ? FS[name].body : name;
  s = M.TS.stateReducer(s, { type: 'done', seq: 1, answer: M.TS.parseState(body), query: { at: body.at, routerId: null, clientsCursor: null } });
  more.forEach((p, i) => {
    s = M.TS.stateReducer(s, { type: 'moreStart', seq: i + 2 });
    s = M.TS.stateReducer(s, { type: 'moreDone', seq: i + 2, answer: M.TS.parseState(FS[p].body) });
  });
  if (loading || error) s = M.TS.stateReducer(s, { type: 'start', seq: 50 });
  if (error) s = M.TS.stateReducer(s, { type: 'fail', seq: 50, error });
  return s;
}
function stateHtml(view, extra = {}, jump = null) {
  const el = h(M.StateScreen, {
    state: view, input: M.TS.toLocalInput(FS.state.body.at), live: false, routerId: null, routers: RNAMES, nowMs: FS_NOW,
    isAdmin: true, onInput: noop, onNow: noop, onStep: noop, onRouter: noop, onRefresh: noop, onMore: noop, onShowWindow: noop, ...extra,
  });
  return renderToStaticMarkup(jump ? h(M.JumpContext.Provider, { value: jump }, el) : el).replace(/<style>[\s\S]*?<\/style>/g, '');
}
function cmpView(name, { error = null } = {}) {
  let s = M.TS.compareReducer(M.TS.COMPARE_INIT, { type: 'start', seq: 1 });
  if (name !== null) s = M.TS.compareReducer(s, { type: 'done', seq: 1, answer: M.TS.parseCompare(typeof name === 'string' ? FS[name].body : name) });
  if (error) s = M.TS.compareReducer(M.TS.compareReducer(s, { type: 'start', seq: 2 }), { type: 'fail', seq: 2, error });
  return s;
}
function compareHtml(view, extra = {}, jump = null) {
  const el = h(M.CompareScreen, {
    state: view, from: M.TS.toLocalInput(FS.compare.body.t1 ?? 1800000090), until: M.TS.toLocalInput(FS.state.body.at), routerId: null,
    routers: RNAMES, nowMs: FS_NOW, isAdmin: true, showSame: {}, onFrom: noop, onUntil: noop, onPick: noop, onRouter: noop,
    onRefresh: noop, onToggleSame: noop, onShowWindow: noop, ...extra,
  });
  return renderToStaticMarkup(jump ? h(M.JumpContext.Provider, { value: jump }, el) : el).replace(/<style>[\s\S]*?<\/style>/g, '');
}
const JUMP_ALL = { canOpen: () => true, open: noop };
const JUMP_USER = { canOpen: tab => tab !== 'config', open: noop };

/** A state answer with an open incident and a configuration version, each with its target (as the server sends them). */
function stateWithTargets() {
  const b = structuredClone(FS.state.body);
  b.incidents = {
    state: 'ok', reason: null, total: 1, truncated: false,
    items: [{ id: 'inc_7', type: 'router_offline', severity: 'warning', router_id: RS2, router_name: 'Router 2', since: b.at - 600, state: 'open',
      target: { tab: 'security', object_type: 'incident', object_id: 'inc_7', version_id: null } }],
  };
  b.config = {
    state: 'ok', reason: null,
    items: [{ router_id: RS1, router_name: 'Router 1', version_id: BKP, created_at: b.at - 3600, code: null,
      target: { tab: 'config', object_type: 'version', object_id: BKP, version_id: BKP } }],
  };
  return b;
}

/** The down router of the browser review: radios partial with no item, the reason the same (and a radio off across a restart). */
function radiosDownState() {
  const b = structuredClone(FS.state.body);
  b.routers[1].radios = { state: 'partial', reason: 'router_down', derived: false, items: [] };
  b.routers[0].radios = { ...b.routers[0].radios, state: 'partial', reason: 'not_observed' };
  b.routers[0].traffic = { ...b.routers[0].traffic, state: 'unreadable', reason: 'unreadable' };
  return b;
}

/** The screens of the new views for the structural style checks (everyScreen). */
function stateScreens(sw) {
  const clients = { ...stView('state_clients_page1') };
  return {
    stateKnown: stateHtml(stView('state'), { viewSwitch: sw('state') }),
    stateTargets: stateHtml(stView(stateWithTargets()), { viewSwitch: sw('state') }, JUMP_ALL),
    stateClientsPage: stateHtml(clients),
    stateClientsAll: stateHtml(stView('state_clients_page1', { more: ['state_clients_page2'] })),
    stateUser: stateHtml(stView('state_user'), { isAdmin: false, viewSwitch: h(M.ViewSwitch, { view: 'state', onView: noop, isAdmin: false }) }),
    stateNotRecorded: stateHtml(stView('state_not_recorded')),
    stateBeyond: stateHtml(stView('state_beyond_retention')),
    stateClientsOff: stateHtml(stView('state_clients_off')),
    stateOff: stateHtml(stView('state_off')),
    stateUnavailable: stateHtml(stView('state_unavailable')),
    stateBadAt: stateHtml(stView(null, { error: errS('state_bad_at') })),
    stateLoading: stateHtml(stView(null)),
    stateFailed: stateHtml(stView('state', { error: new M.TmApiError(500, 'x') })),
    compare: compareHtml(cmpView('compare'), { viewSwitch: sw('compare') }),
    compareSame: compareHtml(cmpView('compare'), { showSame: { [RS1]: true, [RS2]: true } }),
    compareQuiet: compareHtml(cmpView('compare_quiet')),
    compareOther: compareHtml(cmpView('compare_other')),
    compareUnreadable: compareHtml(cmpView('compare_unreadable')),
    compareUnavailable: compareHtml(cmpView({ ...FS.compare_off.body, status: 'unavailable', reason: 'not_loaded' })),
    stateRadiosDown: stateHtml(stView(radiosDownState())),
    stateGapField: stateHtml(stView('state'), { input: '2027-03-28T02:30' }),
    compareTwiceField: compareHtml(cmpView('compare'), { from: '2027-10-31T02:30' }),
    compareOne: compareHtml(cmpView('compare_one_unknown')),
    compareUser: compareHtml(cmpView('compare_user'), { isAdmin: false }),
    compareEmpty: compareHtml(cmpView(null, { error: errS('compare_empty') })),
    compareTooLarge: compareHtml(cmpView(null, { error: errS('compare_too_large') })),
    compareOff: compareHtml(cmpView('compare_off')),
    compareLoading: compareHtml(cmpView(null)),
    // 1.52.2: each side's own value, a disabled router, an emptied field
    compareAfterUpdate: compareHtml(cmpView(FX.compare_after_update), { routers: RNAMES3 }),
    compareRouterDown: compareHtml(cmpView(FX.compare_router_down), { routers: RNAMES3, showSame: { [RS1]: true, [RS2]: true } }),
    compareDisabled: compareHtml(cmpView(FX.compare_disabled), { routers: RNAMES3 }),
    compareDisabledBoth: compareHtml(cmpView(FX.compare_disabled_both), { routers: RNAMES3 }),
    compareFromEmptied: compareHtml(cmpView('compare'), { from: '' }),
    stateDisabled: stateHtml(stView(FX.state_disabled), { routers: RNAMES3 }),
    stateDisabledEarlier: stateHtml(stView(FX.compare_disabled.before), { routers: RNAMES3 }),
    timelineCustom: screenC(loadedC('timeline'), {
      viewSwitch: sw('timeline'), isAdmin: true,
      filters: { ...M.DEFAULT_FILTERS, window: M.CUSTOM_WINDOW, custom: { from: 1800000000, until: 1800003600 }, client: 'tmc_f3e24c9bafa1ce4d' },
      exportState: { ...M.EXPORT_INIT, confirm: true }, onExport: { ask: noop, confirm: noop, cancel: noop, next: noop },
    }),
    timelineExportCut: screenC(loadedC('timeline'), {
      isAdmin: true, exportState: { ...M.EXPORT_INIT, saved: 1, next: { query: qOf({ from: 1, until: 2 }), cursor: FS.export_cut.body.next_cursor } },
      onExport: { ask: noop, confirm: noop, cancel: noop, next: noop },
    }),
    timelineExportDone: screenC(loadedC('timeline'), {
      isAdmin: true, exportState: { ...M.EXPORT_INIT, saved: 1, omitted: FS.export_cut.body.omitted_client_marks },
      onExport: { ask: noop, confirm: noop, cancel: noop, next: noop },
    }),
    timelineExportRefused: screenC(loadedC('timeline'), {
      isAdmin: true, exportState: { ...M.EXPORT_INIT, error: errS('export_refused') },
      onExport: { ask: noop, confirm: noop, cancel: noop, next: noop },
    }),
  };
}

test('state: router cards in words, unknown muted with its reason, never green or red', () => {
  const html = stateHtml(stView('state'));
  const t = text(html);
  assert.match(t, /Zustand am 15\.01\.2027,? 09:09:59/);
  assert.equal(count(html, 'class="tm-card"'), 2);
  for (const k of ['Erreichbar', 'Rolle', 'Uplink', 'Funk']) assert.equal(count(html, `<dt>${k}</dt>`), 2, k);
  assert.ok(t.includes('erreichbar abgeleitet'));
  // "nicht erreichbar": the warning colour and the word
  assert.match(html, /<span class="tm-value tm-value--warn">nicht erreichbar/);
  // unknown: "unbekannt" muted plus the reason, no tone class
  assert.ok(t.includes('unbekannt · noch kein Wert beobachtet'));
  assert.ok(t.includes('unbekannt · Router nicht erreichbar'));
  for (const m of html.matchAll(/<span class="([^"]*tm-value--unknown[^"]*)"/g)) assert.doesNotMatch(m[1], /warn|ok|good|bad|error|crit/);
  assert.doesNotMatch(html, /tm-value--(ok|good|bad|error)/);
  // the derived badge says what it means in its title
  assert.match(html, /<span class="cfg-badge cfg-badge--info tm-derived" title="[^"]+">abgeleitet<\/span>/);
  assert.ok(t.includes('5 GHz Kanal 44 · 80 MHz · an'));
  // sections: intervals, incidents, traffic, config, clients (administrator)
  for (const s of [M.TS.SECTION_INTERVALS, M.TS.SECTION_INCIDENTS, M.TS.SECTION_TRAFFIC, M.TS.SECTION_CONFIG, M.TS.SECTION_CLIENTS]) assert.ok(html.includes(`>${s}</h3>`), s);
  assert.equal(count(html, '<li class="tm-mark'), 1);
  assert.ok(t.includes('2 Clients: Router 1 1 · Router 2 1') || t.includes('2 Clients: Router 2 1 · Router 1 1'), t);
  assert.equal(count(html, 'class="tm-item tm-client-row"'), 2);
  assert.match(t, /seit \d/);
  assert.ok(!PRIVATE.test(t), t.match(PRIVATE)?.[0]);
  // "In der Zeitleiste zeigen" is a real button
  assert.match(html, /<button type="button" class="diag-btn cfg-btn tm-show">In der Zeitleiste zeigen<\/button>/);
  assert.ok(!t.includes('Weitere laden'));
});

test('state: one box and no router cards when the moment is not known (every global reason)', () => {
  for (const name of ['not_recorded', 'beyond_retention', 'ha_gap', 'observation_gap', 'evicted']) {
    const html = stateHtml(stView(`state_${name}`));
    const t = text(html);
    assert.ok(t.includes(M.TS.UNKNOWN_TITLE), name);
    assert.ok(t.includes(M.TS.globalReasonText(name)), name);
    assert.equal(count(html, 'tm-card'), 0, name);
    assert.equal(count(html, 'tm-unknown'), 1, name);
    assert.ok(!html.includes(`>${M.TS.SECTION_INTERVALS}</h3>`), name);
  }
});

test('state: clients for administrators with "Weitere laden", nothing of them for a user', () => {
  const page1 = stateHtml(stView('state_clients_page1'));
  assert.equal(count(page1, 'class="tm-item tm-client-row"'), 1);
  assert.ok(text(page1).includes('Weitere laden'));
  const both = stateHtml(stView('state_clients_page1', { more: ['state_clients_page2'] }));
  assert.equal(count(both, 'class="tm-item tm-client-row"'), 2);
  assert.ok(!text(both).includes('Weitere laden'));
  // a user: no client section, no configuration section, no client names or pseudonyms
  const user = stateHtml(stView('state_user'), { isAdmin: false });
  const t = text(user);
  assert.ok(!user.includes(`>${M.TS.SECTION_CLIENTS}</h3>`) && !user.includes(`>${M.TS.SECTION_CONFIG}</h3>`));
  assert.ok(user.includes(`>${M.TS.SECTION_INTERVALS}</h3>`));
  assert.ok(!user.includes('tm-client'));
  assert.ok(!/tmc_[0-9a-f]{16}/.test(user));
  assert.equal(count(user, 'class="tm-card"'), 2);
  // an administrator with the switch off: how to switch it on
  const off = text(stateHtml(stView('state_clients_off')));
  assert.ok(off.includes(M.CLIENTS_OFF_TITLE));
});

test('state: off, unavailable, the future moment at the field, a failure keeps the answer', () => {
  assert.ok(text(stateHtml(stView('state_off'))).includes(M.OFF_TITLE));
  assert.ok(stateHtml(stView('state_unavailable')).includes('tm-unavailable'));
  const bad = stateHtml(stView(null, { error: errS('state_bad_at') }));
  assert.match(bad, /aria-invalid="true"/);
  assert.match(bad, /<span class="tm-field__error" role="alert">Der Zeitpunkt liegt in der Zukunft\. Bitte einen früheren wählen\.<\/span>/);
  assert.ok(!bad.includes('Erneut versuchen'));
  assert.ok(!text(bad).includes(FS.state_bad_at.body.message));
  const failed = stateHtml(stView('state', { error: new M.TmApiError(500, 'x') }));
  assert.ok(text(failed).includes('Der Zustand konnte nicht geladen werden.'));
  assert.equal(count(failed, 'class="tm-card"'), 2);
  assert.ok(text(stateHtml(stView(null))).includes(M.TS.STATE_LOADING_TEXT));
  // controls: the field (local time), "Jetzt", −1 h, −24 h, the router select
  const html = stateHtml(stView('state'), { live: true });
  assert.match(html, /<input type="datetime-local" step="1" value="2027-01-15T09:09:59"/);
  assert.match(text(html), /Jetzt −1 h −24 h/);
  assert.match(html, /aria-pressed="true"[^>]*>Jetzt</);
  assert.match(html, /<option value=""( selected="")?>Alle Router<\/option>/);
});

test('jumps: incidents to the Security Center and versions to the configuration, only for tabs the user has', () => {
  const view = stView(stateWithTargets());
  const html = stateHtml(view, {}, JUMP_ALL);
  assert.match(html, /<button type="button" class="diag-btn cfg-btn tm-jump">Im Tab Security Center öffnen <span aria-hidden="true">→<\/span><\/button>/);
  assert.equal(count(html, 'Im Tab Konfiguration öffnen'), 1);
  // the intervals are the Time Machine's own marks: no link to itself
  assert.ok(!html.includes('Im Tab Zeitreise'));
  // a user without the configuration tab: only the Security Center
  const user = stateHtml(view, {}, JUMP_USER);
  assert.equal(count(user, 'tm-jump'), 1);
  assert.ok(!user.includes('Konfiguration öffnen'));
  // without a jump api (tests, other hosts): no button at all
  assert.equal(count(stateHtml(view), 'tm-jump'), 0);
  // a mark of the timeline with a ref of another module gets its button inside the main column
  const raw = { ...FS.state.body.intervals[0], ref: { module: 'security_center', type: 'incident', id: 'inc_7' } };
  const row = renderToStaticMarkup(h(M.JumpContext.Provider, { value: JUMP_ALL }, h(M.MarkRow, { m: M.parseMark(raw), nowMs: FS_NOW })));
  assert.match(row, /<span class="tm-mark__main">.*<button type="button" class="diag-btn cfg-btn tm-jump">Im Tab Security Center öffnen/);
  const none = renderToStaticMarkup(h(M.JumpContext.Provider, { value: JUMP_ALL }, h(M.MarkRow, { m: M.parseMark(FS.state.body.intervals[0]), nowMs: FS_NOW })));
  assert.ok(!none.includes('tm-jump'));
});

test('compare: a table per router, "geändert" badges, the same rows behind a button, unknown uncoloured', () => {
  const html = compareHtml(cmpView('compare'));
  const t = text(html);
  assert.equal(count(html, 'role="table"'), 2);
  assert.match(t, /Merkmal Vorher Nachher/);
  assert.equal(count(html, '>geändert</span>'), 4);
  assert.ok(t.includes('Kanal 36 · 80 MHz · an') && t.includes('Kanal 44 · 80 MHz · an'));
  assert.ok(t.includes('von 2 auf 1 (−1)'));
  assert.ok(t.includes(M.TS.compareSummary(M.TS.parseCompare(FS.compare.body), true)));
  // the same rows: collapsed, a button with aria-expanded
  assert.match(html, /<button type="button" class="diag-btn cfg-btn tm-same" aria-expanded="false">Unverändertes zeigen \(1\)<\/button>/);
  assert.equal(count(html, 'tm-crow--same'), 0);
  const open = compareHtml(cmpView('compare'), { showSame: { [RS1]: true } });
  assert.equal(count(open, 'tm-crow--same'), 1);
  assert.ok(open.includes('aria-expanded="true">Unverändertes ausblenden'));
  // unknown cells are muted and never carry the warning of a change
  for (const m of html.matchAll(/<div class="tm-crow tm-crow--unknown"[\s\S]*?<\/div>/g)) {
    assert.ok(!m[0].includes('geändert'));
    assert.ok(m[0].includes('tm-value--unknown'));
  }
  // events in between with the jump into the timeline
  assert.ok(t.includes('4 Ereignisse'));
  assert.match(html, /tm-show">In der Zeitleiste zeigen/);
  assert.ok(html.includes(`>${M.TS.SECTION_COMPARE_INCIDENTS}</h3>`) && html.includes(`>${M.TS.SECTION_COMPARE_CONFIG}</h3>`));
  assert.ok(!t.includes(M.TS.NOTHING_CHANGED));
  assert.ok(!PRIVATE.test(t));
});

test('compare: quiet, one side unknown, a user, refused pairs at their field, off', () => {
  const quiet = text(compareHtml(cmpView('compare_quiet')));
  assert.ok(!quiet.includes(M.TS.NOTHING_CHANGED));
  assert.ok(quiet.includes('Keine bekannte Änderung'));
  const one = compareHtml(cmpView('compare_one_unknown'));
  assert.match(one, /class="cfg-notice cfg-notice--warn tm-sides" role="note"/);
  assert.ok(text(one).includes(`„Von“: ${M.TS.globalReasonText('not_recorded')}`));
  assert.equal(count(one, '>geändert</span>'), 0);
  const user = compareHtml(cmpView('compare_user'), { isAdmin: false });
  assert.ok(!user.includes('role="rowheader">Clients<') && !user.includes(`>${M.TS.SECTION_COMPARE_CONFIG}</h3>`));
  assert.ok(!/tmc_[0-9a-f]{16}/.test(user));
  const empty = compareHtml(cmpView(null, { error: errS('compare_empty') }));
  assert.match(empty, /<span class="tm-field__error" role="alert">„Bis“ muss nach „Von“ liegen\.<\/span>/);
  assert.ok(!empty.includes('role="table"'));
  const big = compareHtml(cmpView(null, { error: errS('compare_too_large') }));
  assert.match(big, /Von<\/span><input[^>]*\/?><span class="tm-field__error" role="alert">Zwischen „Von“ und „Bis“ liegen höchstens 14 Tage\.</);
  assert.ok(text(compareHtml(cmpView('compare_off'))).includes(M.OFF_TITLE));
  assert.match(text(compareHtml(cmpView(null))), /Von Bis Schnellwahl/);
  // the honest sentence: both known, nothing differs, nothing happened
  const b = structuredClone(FS.compare_quiet.body);
  for (const r of b.changes.routers) {
    r.role.state = 'same'; r.uplink.state = 'same'; r.radios = [];
    for (const k of ['reachable', 'role', 'uplink']) { r[k].reason = null; r[k].before ??= r[k].after; }
  }
  // 1.52.2: the cells come from the two blocks; there too every value known and the same
  for (const side of [b.before, b.after]) {
    for (const r of side.routers) {
      r.role = { value: 'gateway', derived: true, reason: null };
      r.uplink = { value: null, derived: true, reason: null };
      r.radios = { state: 'ok', reason: null, derived: true, items: [{ key: '5g0', band: '5g', channel: 44, width: 80, state: 'up', reason: null }] };
    }
  }
  b.changes.marks = { count: 0, by_group: {} };
  const honest = text(compareHtml(cmpView(b)));
  assert.ok(honest.includes(M.TS.NOTHING_CHANGED), honest);
});

test('timeline: the own window as "Fenster: …" with × back to 24 Stunden; the client filter for administrators only', () => {
  const filters = { ...M.DEFAULT_FILTERS, window: M.CUSTOM_WINDOW, custom: { from: 1800000000, until: 1800003600 }, client: 'tmc_f3e24c9bafa1ce4d' };
  let changed = null;
  const html = screenC(loadedC('timeline'), { filters, isAdmin: true, onFilters: f => { changed = f; } });
  assert.ok(text(html).includes(M.customWindowText(filters.custom)));
  assert.match(html, /class="tm-own"/);
  assert.match(html, /aria-label="Eigenes Fenster schließen, zurück zu 24 Stunden"/);
  // the client select and the filter buttons on client labels
  assert.match(html, /<select[^>]*>[\s\S]*?<option value="">Alle Clients<\/option>/);
  assert.ok(html.includes('tm-client--filter'));
  assert.match(html, /aria-label="Zeitleiste nach [^"]+ filtern"/);
  assert.equal(changed, null);
  // a user: neither the select nor a filter button
  const user = screenC(loadedC('timeline_user'), { filters: M.DEFAULT_FILTERS });
  assert.ok(!user.includes('Alle Clients'));
  assert.ok(!user.includes('tm-client--filter'));
  // an administrator without the custom window: the four windows as before, no "Fenster:"
  const plain = screenC(loadedC('timeline'), { isAdmin: true });
  assert.ok(!plain.includes('tm-own'));
  assert.ok(plain.includes('tm-client--filter'));
});

test('export: the button, the confirmation in the tab with the exact text, the cut and the refusal', () => {
  const on = { ask: noop, confirm: noop, cancel: noop, next: noop };
  const idle = screenC(loadedC('timeline'), { isAdmin: true, exportState: M.EXPORT_INIT, onExport: on });
  assert.match(idle, /<div class="tm-export"><button type="button" class="diag-btn cfg-btn">Exportieren<\/button><\/div>/);
  const ask = screenC(loadedC('timeline'), { isAdmin: true, exportState: { ...M.EXPORT_INIT, confirm: true }, onExport: on });
  assert.match(ask, /role="alertdialog" aria-label="Export bestätigen"/);
  assert.ok(text(ask).includes(text(M.TS.EXPORT_CONFIRM_TEXT)));
  assert.match(text(ask), /Exportieren Abbrechen/);
  const cut = screenC(loadedC('timeline'), {
    isAdmin: true, exportState: { ...M.EXPORT_INIT, saved: 1, next: { query: qOf({ from: 1, until: 2 }), cursor: FS.export_cut.body.next_cursor } }, onExport: on,
  });
  assert.ok(text(cut).includes('Weitere Seite exportieren'));
  assert.ok(text(cut).includes('Seite 1 gespeichert.'));
  const refused = screenC(loadedC('timeline'), { isAdmin: true, exportState: { ...M.EXPORT_INIT, error: errS('export_refused') }, onExport: on });
  assert.ok(text(refused).includes('Export nicht möglich: Das Audit-Protokoll ist nicht verfügbar.'));
  // a user never sees the export
  assert.ok(!screenC(loadedC('timeline_user'), { exportState: M.EXPORT_INIT, onExport: on }).includes('tm-export'));
});

test('the containers of the new views render their first state without touching the network', () => {
  let asked = 0;
  const api = { timeline: () => new Promise(noop), state: () => { asked++; return new Promise(noop); }, compare: () => { asked++; return new Promise(noop); } };
  const st = renderToStaticMarkup(h(M.StateContainer, { api, active: true, isAdmin: true, onShowWindow: noop }));
  assert.ok(st.includes('type="datetime-local"'));
  assert.equal(renderToStaticMarkup(h(M.StateContainer, { api, active: false, onShowWindow: noop })), '');
  const cmp = renderToStaticMarkup(h(M.CompareContainer, { api, active: true, onShowWindow: noop }));
  assert.equal(count(cmp, 'type="datetime-local"'), 2);
  assert.equal(asked, 0);
  // the tab mounts only the timeline at first: the other views are not even rendered
  const tab = renderToStaticMarkup(h(M.TimeMachineView, { api, isAdmin: true }));
  assert.ok(!tab.includes('datetime-local'));
  // 1.52.1: the first state of an opened view with its prefilled fields says "lädt", not "wählen"
  assert.ok(text(st).includes(M.TS.STATE_LOADING_TEXT));
  assert.ok(!text(st).includes(M.TS.STATE_PICK_TEXT));
  assert.ok(text(cmp).includes(M.TS.COMPARE_LOADING_TEXT));
  assert.ok(!text(cmp).includes(M.TS.COMPARE_PICK_TEXT));
});

test('1.52.1: before the first answer the hint shows only for an empty field (browser review 1.52.0)', () => {
  const idle = M.TS.STATE_INIT;
  const filled = text(stateHtml(idle));
  assert.ok(filled.includes(M.TS.STATE_LOADING_TEXT));
  assert.ok(!filled.includes(M.TS.STATE_PICK_TEXT));
  const empty = text(stateHtml(idle, { input: '' }));
  assert.ok(empty.includes(M.TS.STATE_PICK_TEXT));
  assert.ok(!empty.includes(M.TS.STATE_LOADING_TEXT));
  // a skipped time: only the field's own error, no hint, no spinner
  const gap = stateHtml(idle, { input: '2027-03-28T02:30' });
  assert.ok(text(gap).includes(M.TS.LOCAL_GAP_TEXT));
  assert.ok(!text(gap).includes(M.TS.STATE_PICK_TEXT));
  assert.ok(!text(gap).includes(M.TS.STATE_LOADING_TEXT));

  const cIdle = M.TS.COMPARE_INIT;
  const both = text(compareHtml(cIdle));
  assert.ok(both.includes(M.TS.COMPARE_LOADING_TEXT));
  assert.ok(!both.includes(M.TS.COMPARE_PICK_TEXT));
  for (const extra of [{ from: '' }, { until: '' }, { from: '', until: '' }]) {
    const t = text(compareHtml(cIdle, extra));
    assert.ok(t.includes(M.TS.COMPARE_PICK_TEXT), JSON.stringify(extra));
    assert.ok(!t.includes(M.TS.COMPARE_LOADING_TEXT), JSON.stringify(extra));
  }
  const cGap = text(compareHtml(cIdle, { until: '2027-03-28T02:30' }));
  assert.ok(cGap.includes(M.TS.LOCAL_GAP_TEXT));
  assert.ok(!cGap.includes(M.TS.COMPARE_PICK_TEXT));
  assert.ok(!cGap.includes(M.TS.COMPARE_LOADING_TEXT));
  // 1.52.2 (owner's decision): a field cleared after an answer shows the hint, not the old result
  const cleared = text(stateHtml(stView('state'), { input: '' }));
  assert.ok(cleared.includes(M.TS.STATE_PICK_TEXT));
  assert.ok(!cleared.includes('Zustand am'));
});

// ── foreign tabs: an entry selects, without one they start as before ────

test('registry entries: only for an available tab, read by that tab only, cleared after reading', () => {
  M.bindSecurityHass(() => ({ callApi: async () => ({}), user: { is_admin: true } }));
  assert.equal(M.isEnterpriseTabAvailable('nope'), false);
  assert.equal(M.openEnterpriseTab({ tab: 'nope', objectType: null, objectId: null, versionId: null, routerId: null }), false);
  assert.equal(M.peekEnterpriseEntry('nope'), null);
  const seen = [];
  const off = M.onEnterpriseOpen(e => seen.push(e.tab));
  assert.equal(M.openEnterpriseTab({ tab: 'security', objectType: 'incident', objectId: 'inc_7', versionId: null, routerId: null }), true);
  assert.deepEqual(seen, ['security']);
  assert.equal(M.peekEnterpriseEntry('config'), null);
  assert.equal(M.entryIncident(M.peekEnterpriseEntry('security')), 'inc_7');
  M.clearEnterpriseEntry('config');
  assert.ok(M.peekEnterpriseEntry('security'));
  M.clearEnterpriseEntry('security');
  assert.equal(M.peekEnterpriseEntry('security'), null);
  off();
  M.openEnterpriseTab({ tab: 'security', objectType: null, objectId: null, versionId: null, routerId: null });
  assert.deepEqual(seen, ['security']);
  M.clearEnterpriseEntry('security');
  // the readers: nothing without an entry or with another object
  assert.equal(M.entryIncident(null), null);
  assert.equal(M.entryIncident({ tab: 'security', objectType: 'timeline', objectId: 'x', versionId: null, routerId: null }), null);
  assert.equal(M.entryRouter(null), null);
  assert.equal(M.entryRouter({ tab: 'config', objectType: 'version', objectId: BKP, versionId: BKP, routerId: RS1 }), RS1);
});

test('Security Center and configuration start exactly as before without an entry or with one for another tab', () => {
  const pending = () => new Promise(noop);
  const secApi = new Proxy({}, { get: () => pending });
  const cfgApi = new Proxy({}, { get: () => pending });
  const sec = () => renderToStaticMarkup(h(M.SecurityCenterView, { api: secApi, isAdmin: () => true }));
  const cfg = () => renderToStaticMarkup(h(M.ConfigManagerView, { api: cfgApi }));
  const secBase = sec();
  const cfgBase = cfg();
  assert.ok(secBase.length > 0 && cfgBase.length > 0);
  // an entry for another tab changes nothing here
  M.bindConfigHass(() => ({ callApi: async () => ({}), user: { is_admin: true } }));
  assert.ok(M.openEnterpriseTab({ tab: 'config', objectType: 'version', objectId: BKP, versionId: BKP, routerId: RS1 }));
  assert.equal(sec(), secBase);
  const cfgEntry = cfg();
  M.clearEnterpriseEntry('config');
  assert.equal(cfg(), cfgBase);
  // before its overview has loaded the configuration tab looks the same with or without an entry:
  // the router is selected in its first state (entryRouter, above), shown once the overview is there
  assert.equal(cfgEntry, cfgBase);
  assert.ok(M.openEnterpriseTab({ tab: 'security', objectType: 'incident', objectId: 'inc_7', versionId: null, routerId: null }));
  assert.equal(cfg(), cfgBase);
  const secEntry = sec();
  M.clearEnterpriseEntry('security');
  assert.equal(sec(), secBase);
  // the same before the overview has loaded (a skeleton); the incident is in the first state (entryIncident)
  assert.equal(secEntry, secBase);
  // the Enterprise container: without an entry the first tab, as before
  const ent = renderToStaticMarkup(h(M.EnterpriseView));
  const first = M.getEnterpriseTabs()[0];
  assert.match(ent, new RegExp(`aria-selected="true"[^>]*>${first.title}<`));
});

test('the four-chip view switch: two rows of two at 360 px (40 px), one row at 768 and 1280 px (32 px)', () => {
  const rules = loadRules();
  const html = renderToStaticMarkup(h(M.ViewSwitch, { view: 'state', onView: noop, isAdmin: true }));
  const tree = parseHtml(html);
  const views = tree.children[0];
  assert.ok(views.classes.includes('tm-views'));
  const chips = views.children;
  assert.equal(chips.length, 4);
  assert.deepEqual(chips.map(c => c.tag), ['button', 'button', 'button', 'button']);
  // the row wraps, with a gap of 6 px: 2 × (50 % − 3 px) + 6 px = 100 %, so exactly two per row
  for (const width of [360, 768, 1280]) {
    const row = computed(rules, views, width);
    assert.equal(row['flex-wrap'].val, 'wrap', `${width}`);
    assert.equal(row.gap.val, '6px', `${width}`);
  }
  for (const c of chips) {
    const narrow = computed(rules, c, 360);
    assert.equal(narrow['flex-basis'].val, 'calc(50% - 3px)');
    assert.equal(narrow['flex-grow'].val, '1');
    assert.equal(narrow['min-height'].val, '40px');
    assert.equal(narrow['box-sizing'].val, 'border-box');
    for (const width of [768, 1280]) {
      const wide = computed(rules, c, width);
      // no forced share of the row: the chips sit side by side at their own width
      assert.ok(!wide['flex-basis'] || wide['flex-basis'].val === 'auto', `${width}: ${wide['flex-basis']?.val}`);
      assert.equal(wide['min-height'].val, '32px', `${width}`);
    }
  }
  // a user: three chips, the same rules (the last one alone in its row at 360 px, full width)
  const user = parseHtml(renderToStaticMarkup(h(M.ViewSwitch, { view: 'state', onView: noop, isAdmin: false })));
  assert.equal(user.children[0].children.length, 3);
});

test('the new views sit in their size containers: cards, client rows and compare tables', () => {
  const rules = loadRules();
  for (const name of ['tmstate', 'tmclients', 'tmcompare']) assert.ok(rules.some(r => r.container === name), name);
  const screens = everyScreen();
  const all = (el, cls, out = []) => { if (el.classes.includes(cls)) out.push(el); el.children.forEach(c => all(c, cls, out)); return out; };
  const up = (el, cls) => { for (let a = el.parent; a; a = a.parent) if (a.classes.includes(cls)) return a; return null; };
  const st = parseHtml(screens.stateKnown);
  const cards = all(st, 'tm-card');
  assert.equal(cards.length, 2);
  for (const c of cards) assert.ok(up(c, 'tm-state'));
  const rows = all(st, 'tm-client-row');
  assert.equal(rows.length, 2);
  for (const r of rows) assert.ok(up(r, 'tm-clients'));
  const cmp = parseHtml(screens.compare);
  const tables = all(cmp, 'tm-ctable');
  assert.equal(tables.length, 2);
  for (const t of tables) assert.ok(up(t, 'tm-compare'));
  // the intervals of "Zustand" are marks: inside .tm-timeline (tmlist)
  for (const m of all(st, 'tm-mark')) assert.ok(up(m, 'tm-timeline'));
  // the screens of the new views are part of the structural checks above
  for (const k of ['stateKnown', 'stateUser', 'stateNotRecorded', 'compare', 'compareOne', 'timelineCustom', 'timelineExportCut']) assert.ok(k in screens, k);
});

/**
 * Marks whose time column shows a date ("22.11.2026, 01:46") but whose
 * winning grid gives it less than the dated 9.5em column, or whose card
 * layout does not start at 920 px of the tmlist container (1.52.0 browser
 * review: the intervals of "Zustand" broke the year in two).
 */
function datedMarkTraps(rules, html) {
  const bad = [];
  const walk = el => {
    if (el.classes.includes('tm-mark__time') && /\d{2}\.\d{2}\.\d{4}/.test(el.text)) {
      const row = el.parent;
      const cols = computed(rules, row, 1280)['grid-template-columns']?.val ?? '';
      const first = /^([\d.]+)em\b/.exec(cols);
      if (!first || Number(first[1]) < 9.5) bad.push(`"${el.text}" in a ${cols.split(' ')[0] || 'missing'} column`);
      const cards = rules.some(r => r.container === 'tmlist' && r.cwidth >= 920 && matches(r.parsed.chain, row)
        && r.decls.some(([k, v]) => k === 'display' && v === 'flex'));
      if (!cards) bad.push(`"${el.text}" without cards from 920 px`);
    }
    el.children.forEach(walk);
  };
  walk(parseHtml(html));
  return bad;
}

test('every mark that shows its date has the wide time column and turns into a card at 920 px', () => {
  const rules = loadRules();
  const screens = everyScreen();
  let dated = 0;
  for (const [name, html] of Object.entries(screens)) {
    assert.deepEqual(datedMarkTraps(rules, html), [], name);
    dated += count(html, 'tm-mark--start');
  }
  assert.ok(dated >= 3, 'the block and the intervals of "Zustand" were checked');
  assert.ok(screens.stateKnown.includes('tm-mark--start'));
  // the state of the browser review (the dated columns bound to .tm-spans) is red, for the intervals only
  const tm = readFileSync(join(here, 'timemachine.css'), 'utf8');
  const old = tm.replaceAll('.tm-mark.tm-mark--start {', '.tm-spans .tm-mark {').replaceAll('.tm-mark--start .tm-mark__', '.tm-spans .tm-mark__');
  assert.notEqual(old, tm);
  const oldRules = loadRules({ 'timemachine.css': old });
  const traps = datedMarkTraps(oldRules, screens.stateKnown);
  assert.ok(traps.some(t => /in a 5em column$/.test(t)), traps.join('; '));
  assert.ok(traps.some(t => /without cards from 920 px$/.test(t)));
  assert.deepEqual(datedMarkTraps(oldRules, screens.timeline), []);
});

// ── 1.52.0 review before the merge: what the screens say ─────────────────

test('compare: the other modules in "Ereignisse dazwischen", unknown when one was not read', () => {
  const sc = stateScreens(() => null);
  const quiet = text(sc.compareQuiet);
  assert.ok(!quiet.includes('aus anderen Modulen') && !quiet.includes('ist unbekannt:'));
  const other = text(sc.compareOther);
  assert.ok(other.includes('Dazu 1 Eintrag aus anderen Modulen.'), other);
  assert.ok(!other.includes(M.TS.NOTHING_CHANGED));
  const bad = text(sc.compareUnreadable);
  assert.ok(bad.includes('Ob dazwischen etwas geschah, ist unbekannt: Eine Quelle ließ sich nicht lesen. Nicht gelesen: Audit.'), bad);
  assert.ok(!bad.includes(M.TS.NOTHING_CHANGED));
  assert.match(sc.compareUnreadable, /<div class="cfg-hint tm-others" role="note">Ob dazwischen/);
});

test('compare unavailable: the reason in words, as in "Zustand"', () => {
  const t = text(stateScreens(() => null).compareUnavailable);
  assert.ok(t.includes(`${M.TS.STATE_UNAVAILABLE_TEXT} Der gespeicherte Verlauf wird noch geladen.`), t);
  assert.equal(text(stateScreens(() => null).stateUnavailable).includes(M.TS.STATE_UNAVAILABLE_TEXT), true);
});

test('router cards: the reason of a down router once, not_observed and an unreadable part in sentences', () => {
  const html = stateScreens(() => null).stateRadiosDown;
  const t = text(html);
  assert.ok(t.includes('Funk unbekannt · Router nicht erreichbar · unvollständig'), t);
  assert.ok(!t.includes('unvollständig · Router nicht erreichbar'));
  assert.ok(t.includes('Nicht alle Funkmodule sind bekannt: Eines blieb über einen Neustart aus.'));
  assert.ok(t.includes('Verkehr: Konnte nicht gelesen werden.'), t);
  assert.ok(!t.includes('nicht lesbar · nicht lesbar'));
});

test('the fields on a clock change: an error for the skipped hour, a note for the doubled one', () => {
  const sc = stateScreens(() => null);
  assert.match(sc.stateGapField, /aria-invalid="true"/);
  assert.match(sc.stateGapField, /<span class="tm-field__error" role="alert">Diese Uhrzeit gibt es wegen der Zeitumstellung nicht\.<\/span>/);
  assert.match(sc.compareTwiceField, /<span class="tm-field__note cfg-hint">Diese Uhrzeit gibt es wegen der Zeitumstellung zweimal; gezeigt wird die erste\.<\/span>/);
  assert.ok(!sc.stateKnown.includes('Zeitumstellung'));
});

test('export: the confirmation is a modal alertdialog described by its text; the left-out client marks after it', () => {
  const sc = stateScreens(() => null);
  const ask = sc.timelineCustom;
  // tabindex -1 (browser check): a tap on the text keeps the focus in the dialog; not in the Tab order
  const m = /<div class="[^"]*tm-export__ask" role="alertdialog" aria-label="Export bestätigen" aria-modal="true" aria-describedby="([^"]+)" tabindex="-1">/.exec(ask);
  assert.ok(m, 'aria-modal, aria-describedby and tabindex -1');
  assert.ok(!ask.includes('tabindex="0"'));
  assert.ok(ask.includes(`<span id="${m[1]}">${M.TS.EXPORT_CONFIRM_TEXT}</span>`));
  // the last button is "Abbrechen" (focused on open, see dialogFocus); no trigger next to the dialog
  assert.match(ask, /Exportieren<\/button><button type="button" class="diag-btn cfg-btn">Abbrechen<\/button>/);
  const done = text(sc.timelineExportDone);
  assert.ok(done.includes('Export gespeichert. 4 Client-Einträge sind nicht enthalten.'), done);
  assert.ok(!text(sc.timelineExportCut).includes('Client-Einträge'));
  // busy: the trigger stays focusable (aria-disabled), so the focus can come back to it
  const busy = screenC(loadedC('timeline'), { isAdmin: true, exportState: { ...M.EXPORT_INIT, busy: true }, onExport: { ask: noop, confirm: noop, cancel: noop, next: noop } });
  assert.match(busy, /<button type="button" class="diag-btn cfg-btn" aria-disabled="true">Exportieren<\/button>/);
});

// ── browser check before the merge: an export without a mark ─────────────

const fileOf = name => {
  const b = FS[name].body;
  return {
    blob: null, status: b.status, reason: b.reason, marks: b.marks.length, spanning: b.spanning.length, truncated: b.truncated,
    nextCursor: b.next_cursor, omittedClientMarks: b.omitted_client_marks,
  };
};

test('export without a mark: no file is saved, the message says why, never "Export gespeichert"', () => {
  const q = qOf({ from: 1, until: 2 });
  const on = { ask: noop, confirm: noop, cancel: noop, next: noop };
  for (const name of ['export_unavailable', 'export_empty', 'export_empty_partial', 'export_off']) {
    const step = M.exportStep(fileOf(name), 1, q, M.EXPORT_INIT);
    assert.equal(step.save, null, name);
    assert.equal(step.state.empty, M.TS.exportEmptyText(fileOf(name)), name);
    assert.deepEqual([step.state.saved, step.state.next, step.state.busy, step.state.confirm], [null, null, false, false], name);
    const html = screenC(loadedC('timeline'), { isAdmin: true, exportState: step.state, onExport: on });
    assert.ok(html.includes(`<span class="cfg-hint tm-export__empty" role="status">${step.state.empty}</span>`), name);
    assert.ok(!text(html).includes('gespeichert.') || text(html).includes('keine Datei gespeichert.'), name);
    assert.ok(!text(html).includes('Export gespeichert'), name);
  }
  assert.ok(text(screenC(loadedC('timeline'), { isAdmin: true, exportState: M.exportStep(fileOf('export_unavailable'), 1, q, M.EXPORT_INIT).state, onExport: on }))
    .includes('Nichts zu exportieren, es wurde keine Datei gespeichert. Die Zeitreise läuft gerade nicht.'));
  // with marks exactly as before: the file is saved and "Export gespeichert."
  const data = M.exportStep(fileOf('export'), 1, q, M.EXPORT_INIT);
  assert.equal(data.save, M.TS.EXPORT_FILENAME);
  assert.deepEqual([data.state.saved, data.state.next, data.state.empty], [1, null, null]);
  assert.equal(data.state.omitted, FS.export.body.omitted_client_marks);
  const done = text(screenC(loadedC('timeline'), { isAdmin: true, exportState: data.state, onExport: on }));
  assert.ok(done.includes('Export gespeichert.'), done);
  assert.ok(!done.includes('Nichts zu exportieren'));
  // a cut export goes on; its second page is a file of its own
  const cut = M.exportStep(fileOf('export_cut'), 1, q, M.EXPORT_INIT);
  assert.deepEqual([cut.save, cut.state.saved, cut.state.next?.cursor], [M.TS.EXPORT_FILENAME, 1, FS.export_cut.body.next_cursor]);
  const second = M.exportStep(fileOf('export'), 2, q, cut.state);
  assert.equal(second.save, 'openwrt-router-time-machine-2.json');
  assert.equal(second.state.saved, 2);
  // a later page without a mark: no further file, the pages saved so far stay counted
  const none = M.exportStep(fileOf('export_empty'), 2, q, cut.state);
  assert.equal(none.save, null);
  assert.deepEqual([none.state.saved, none.state.next, none.state.empty], [1, null, M.TS.EXPORT_EMPTY_MORE]);
  const noneHtml = text(screenC(loadedC('timeline'), { isAdmin: true, exportState: none.state, onExport: on }));
  assert.ok(noneHtml.includes(M.TS.EXPORT_EMPTY_MORE));
  assert.ok(!noneHtml.includes('Weitere Seite exportieren'));
  // busy or failed: the message waits
  const busy = screenC(loadedC('timeline'), { isAdmin: true, exportState: { ...none.state, busy: true }, onExport: on });
  assert.ok(!busy.includes('tm-export__empty'));
});

// ── 1.52.2: each cell of "Vergleich" its own side, an emptied field, a disabled router ──

const tx = html => text(html).trim();

/** The rows of the compare table of one router: [label, Vorher cell, Nachher cell, row class]. */
function tableRows(html, name) {
  const table = html.split(`aria-label="Vergleich ${name}"`)[1]?.split('</section>')[0] ?? '';
  return [...table.matchAll(/<div class="tm-crow tm-crow--(\w+)" role="row">([\s\S]*?)<\/span><\/div>/g)]
    .filter(m => m[1] !== 'head')
    .map(m => {
      const cells = m[2].split('<span role="cell">').slice(1);
      return { state: m[1], label: text(m[2].split('</span>')[0]).trim(), before: cells[0] ?? '', after: cells[1] ?? '' };
    });
}

test('1.52.2 compare: "Vorher" unknown, "Nachher" known: the known values in Nachher, the reason only in Vorher', () => {
  const sc = stateScreens(() => null);
  const html = sc.compareAfterUpdate;
  for (const [name, uplink, role] of [['Router 1', 'kein vorgeschalteter Router', 'Gateway'], ['Router 2', 'über Router 1', 'Mesh-Knoten']]) {
    const rows = tableRows(html, name);
    assert.deepEqual(rows.map(r => r.label), ['Erreichbar', 'Rolle', 'Uplink', 'Funk 5 GHz'], name);
    const after = Object.fromEntries(rows.map(r => [r.label, tx(r.after)]));
    assert.deepEqual(after, {
      'Erreichbar': 'Nachher: erreichbar', 'Rolle': `Nachher: ${role}`, 'Uplink': `Nachher: ${uplink}`,
      'Funk 5 GHz': 'Nachher: Kanal 36 · 80 MHz · an',
    }, name);
    for (const r of rows) {
      assert.equal(r.state, 'unknown');
      assert.equal(tx(r.before), 'Vorher: unbekannt · noch kein Wert beobachtet', `${name} ${r.label}`);
      assert.ok(!r.after.includes('tm-reason') && !r.after.includes('tm-value--unknown'), `${name} ${r.label}`);
      assert.ok(!r.after.includes('geändert') && !r.before.includes('geändert'));
    }
  }
  const t = text(html);
  assert.ok(t.includes('Keine bekannte Änderung; 8 Merkmale sind zu einem der Zeitpunkte unbekannt.'), t);
  // the disabled Router 3 (unknown at both moments): no table, one line
  assert.ok(!html.includes('aria-label="Vergleich Router 3"'));
  assert.ok(t.includes('1 Router ist deaktiviert und nicht aufgeführt; zu beiden Zeitpunkten ist von ihm nichts bekannt.'), t);
  assert.ok(!PRIVATE.test(t));
});

test('1.52.2 compare: the mirror: "Vorher" known, "Nachher" unknown with its own reason', () => {
  const html = stateScreens(() => null).compareRouterDown;
  const rows = Object.fromEntries(tableRows(html, 'Router 2').map(r => [r.label, r]));
  assert.equal(tx(rows.Uplink.before), 'Vorher: über Router 1');
  assert.equal(tx(rows.Uplink.after), 'Nachher: unbekannt · Router nicht erreichbar');
  assert.equal(tx(rows['Funk 5 GHz'].before), 'Vorher: Kanal 36 · 80 MHz · an');
  assert.equal(tx(rows['Funk 5 GHz'].after), 'Nachher: unbekannt · Router nicht erreichbar');
  assert.equal(rows.Erreichbar.state, 'changed');
  assert.ok(!rows.Uplink.before.includes('tm-reason'));
  // "Von" unknown as a whole: the known "Bis" values of the fixture of 1.52.0
  const one = compareHtml(cmpView('compare_one_unknown'));
  const r1 = Object.fromEntries(tableRows(one, 'Router 1').map(r => [r.label, r]));
  assert.equal(tx(r1['Funk 5 GHz'].after), 'Nachher: Kanal 44 · 80 MHz · an');
  assert.equal(tx(r1['Funk 5 GHz'].before), 'Vorher: unbekannt · nicht aufgezeichnet');
  assert.equal(tx(r1.Erreichbar.after), 'Nachher: erreichbar');
});

test('1.52.2: "Von" or "Bis" emptied after an answer: the hint, no table; the reducer drops the result', () => {
  const sc = stateScreens(() => null);
  for (const html of [sc.compareFromEmptied, compareHtml(cmpView('compare'), { until: '' })]) {
    const t = text(html);
    assert.ok(t.includes(M.TS.COMPARE_PICK_TEXT), t);
    assert.ok(!html.includes('tm-ctable') && !t.includes('Merkmale haben sich geändert'));
  }
  // the container's step: the cleared state shows the hint too, a late answer does not bring the table back
  let s = M.TS.compareReducer(cmpView('compare'), { type: 'start', seq: 2 });
  s = M.TS.compareReducer(s, { type: 'clear', seq: 3 });
  s = M.TS.compareReducer(s, { type: 'done', seq: 2, answer: M.TS.parseCompare(FS.compare.body) });
  const cleared = compareHtml(s, { from: '' });
  assert.ok(text(cleared).includes(M.TS.COMPARE_PICK_TEXT) && !cleared.includes('tm-ctable'));
  // a skipped hour: its field error, no old table, no hint
  const gap = compareHtml(M.TS.compareReducer(cmpView('compare'), { type: 'clear', seq: 3 }), { from: '2027-03-28T02:30' });
  assert.ok(text(gap).includes(M.TS.LOCAL_GAP_TEXT) && !gap.includes('tm-ctable') && !text(gap).includes(M.TS.COMPARE_PICK_TEXT));
  // "Zustand" the same
  let z = M.TS.stateReducer(stView('state'), { type: 'clear', seq: 9 });
  const zt = text(stateHtml(z, { input: '' }));
  assert.ok(zt.includes(M.TS.STATE_PICK_TEXT) && !zt.includes('Zustand am'));
  z = M.TS.stateReducer(z, { type: 'done', seq: 1, answer: M.TS.parseState(FS.state.body), query: { at: 1, routerId: null, clientsCursor: null } });
  assert.equal(z.answer, null);
});

test('1.52.2: a disabled router is "deaktiviert" in "Zustand" and no difference in "Vergleich"', () => {
  const sc = stateScreens(() => null);
  const html = sc.stateDisabled;
  const card = name => html.split(`<section class="tm-card" aria-label="${name}">`)[1]?.split('</section>')[0] ?? '';
  for (const name of ['Router 2', 'Router 3']) {
    const c = card(name);
    assert.ok(c, name);
    // one line instead of four unknown rows
    assert.equal(count(c, '<dt>'), 0, name);
    assert.equal(count(c, 'deaktiviert'), 1, name);
    assert.ok(!c.includes('noch kein Wert beobachtet'), name);
    assert.match(text(c), /deaktiviert · in Home Assistant ausgeschaltet, zu diesem Zeitpunkt nichts bekannt/);
  }
  assert.equal(count(card('Router 1'), '<dt>'), 4);
  assert.ok(!card('Router 1').includes('deaktiviert'));
  // known values of a moment before the disable: shown, the router marked as disabled now
  const earlier = sc.stateDisabledEarlier;
  const r2 = earlier.split('<section class="tm-card" aria-label="Router 2">')[1].split('</section>')[0];
  assert.equal(count(r2, '<dt>'), 4);
  assert.ok(text(r2).includes('derzeit deaktiviert') && text(r2).includes('über Router 1'));
  // "Vergleich": both disabled and unknown at both moments: no table, not counted, one line
  const both = sc.compareDisabledBoth;
  assert.equal(count(both, 'role="table"'), 0);
  assert.ok(text(both).includes('2 Router sind deaktiviert und nicht aufgeführt'), text(both));
  assert.ok(!/Merkmale? (sind|ist) zu einem der Zeitpunkte unbekannt/.test(text(both)));
  // with known history at "Von": listed as usual and marked
  const once = sc.compareDisabled;
  assert.equal(count(once, 'role="table"'), 1);
  const head = once.split('aria-label="Router 2">')[1].split('role="table"')[0];
  assert.ok(text(head).includes('derzeit deaktiviert'), head);
  assert.ok(text(once).includes('1 Router ist deaktiviert und nicht aufgeführt'));
  // an answer of 1.52.1 (no field): nobody is disabled
  assert.ok(!stateHtml(stView('state')).includes('deaktiviert'));
  assert.ok(!compareHtml(cmpView('compare_quiet')).includes('deaktiviert'));
});

// ── 1.52.2 review: hidden routers in the summary, "deaktiviert" only for not_observed ──

const cloneJ = v => JSON.parse(JSON.stringify(v));
const rawR = (side, name) => side.routers.find(r => r.router_name === name);

test('1.52.2 review: with hidden disabled routers the summary qualifies "nothing changed"', () => {
  const a = cloneJ(FX.compare_disabled_both);
  a.changes.other_sources = { state: 'ok', reason: null, count: 0, truncated: false, unreadable: [] };
  const t = text(compareHtml(cmpView(a), { routers: RNAMES3 }));
  assert.ok(t.includes('Über 2 deaktivierte Router ist nichts bekannt; sonst hat sich zwischen diesen Zeitpunkten nichts geändert.'), t);
  assert.ok(!t.includes(M.TS.NOTHING_CHANGED), t);
  assert.ok(t.includes('2 Router sind deaktiviert und nicht aufgeführt'), t);
  assert.equal(count(compareHtml(cmpView(a), { routers: RNAMES3 }), 'role="table"'), 0);
});

test('1.52.2 review: a disabled router with another reason keeps its card and its table, with the real reasons', () => {
  const st = cloneJ(FX.state_disabled);
  rawR(st, 'Router 2').reachable.reason = 'evicted';
  const html = stateHtml(stView(st), { routers: RNAMES3 });
  const card = html.split('<section class="tm-card" aria-label="Router 2">')[1]?.split('</section>')[0] ?? '';
  assert.equal(count(card, '<dt>'), 4);
  assert.ok(text(card).includes('derzeit deaktiviert'), text(card));
  assert.ok(text(card).includes('Aufzeichnung verdrängt'), text(card));
  assert.ok(!text(card).includes('in Home Assistant ausgeschaltet'), text(card));
  // Router 3 (not_observed only) stays one line
  const r3 = html.split('<section class="tm-card" aria-label="Router 3">')[1]?.split('</section>')[0] ?? '';
  assert.equal(count(r3, '<dt>'), 0);
  // "Vergleich": listed with its reasons and the badge; the summary counts its rows
  const a = cloneJ(FX.compare_disabled_both);
  rawR(a.after, 'Router 2').uplink.reason = 'observation_gap';
  const c = compareHtml(cmpView(a), { routers: RNAMES3 });
  const rows = Object.fromEntries(tableRows(c, 'Router 2').map(r => [r.label, r]));
  assert.equal(tx(rows.Uplink.after), 'Nachher: unbekannt · nicht beobachtet');
  assert.equal(tx(rows.Uplink.before), 'Vorher: unbekannt · noch kein Wert beobachtet');
  const head = c.split('aria-label="Router 2">')[1].split('role="table"')[0];
  assert.ok(text(head).includes('derzeit deaktiviert'), head);
  assert.ok(text(c).includes('1 Router ist deaktiviert und nicht aufgeführt'), text(c));
});
