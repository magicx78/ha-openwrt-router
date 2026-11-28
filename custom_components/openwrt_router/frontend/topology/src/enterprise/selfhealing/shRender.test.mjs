// Render tests of the "Self-Healing" tab (node:test). The view is bundled
// once with esbuild (Vite's own bundler, already in node_modules; no new
// dependency) and rendered with react-dom/server, the Time Machine way. The
// answers are real route answers from shFixture.json (made and checked by
// tests/test_sh_panel_fixture_v1530.py; invented ids, no address or name).
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
const outFile = join(root, 'node_modules/.cache/sh-render-test/bundle.mjs');
const F = JSON.parse(readFileSync(join(here, 'shFixture.json'), 'utf8'));

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
        "export * from './shLogic.ts';",
        "export { PLAN_LOADING_TEXT, PLAN_MISSING_TEXT, SelfHealingScreen, SelfHealingView, SH_INIT, applyLoad, isOff } from './SelfHealingView';",
        "export { createMockShApi, mockHass } from './shMock.ts';",
        "export { getEnterpriseTabs } from '../registry';",
        "export { bindDiagnosticsHass } from '../diagnostics/register';",
        "export { bindWifiHass } from '../wifi/register';",
        "export { bindSelfHealingHass } from './register';",
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
const noop = () => {};
const R1 = 'rtr_11111111111111111111111111111111';
const ID_OPEN = F.detail_open.body.action.action_id;
const ID_CLOSED = F.detail_closed.body.action.action_id;

/** State from fixture keys (parsed with the tab's own parsers). */
function state(keys = {}) {
  const s = { ...M.SH_INIT };
  const take = (k, parse) => {
    const a = F[k];
    if (a.status === 200) return [parse(a.body), null];
    return [null, new M.ShApiError(a.status, a.body?.code ?? '')];
  };
  if (keys.overview) [s.overview, s.overviewError] = take(keys.overview, M.parseOverview);
  if (keys.list) [s.list, s.listError] = take(keys.list, M.parseActions);
  if (keys.settings) [s.settings, s.settingsError] = take(keys.settings, M.parseSettings);
  if (keys.detail) [s.detail, s.detailError] = take(keys.detail, M.parseDetail);
  if (keys.plan) {
    const [plans, err] = take(keys.plan, M.parsePlans);
    s.plan = plans ? plans.find(p => p.actionId === keys.selected) ?? null : null;
    s.planFor = plans ? keys.selected : null;
    s.planError = err;
  }
  return { ...s, ...(keys.extra ?? {}) };
}

function screen(s, { isAdmin = true, selected = null, filters = M.DEFAULT_LIST_FILTERS } = {}) {
  return renderToStaticMarkup(h(M.SelfHealingScreen, {
    state: s, isAdmin, filters, selected, onRefresh: noop, onFilters: noop, onSelect: noop,
  }));
}

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', '#x27': "'", '#39': "'", nbsp: ' ' };
/** The visible text of a markup (styles dropped, tags as spaces). */
function text(html) {
  return html.replace(/<style>[\s\S]*?<\/style>/g, '').replace(/<[^>]+>/g, ' ')
    .replace(/&(amp|lt|gt|quot|#x27|#39|nbsp);/g, (_, e) => ENT[e]).replace(/\s+/g, ' ').trim();
}
/** The markup without the inlined stylesheets. */
const body = html => html.replace(/<style>[\s\S]*?<\/style>/g, '');
const buttons = html => [...html.matchAll(/<button[^>]*>([\s\S]*?)<\/button>/g)].map(m => text(m[1]));

const FULL = { overview: 'overview', list: 'actions', settings: 'settings' };
const HELD = { overview: 'held_overview', list: 'actions', settings: 'settings' };
const ALL_STATES = () => [
  ['loading', screen(M.SH_INIT)],
  ['full', screen(state(FULL))],
  ['held', screen(state(HELD))],
  ['detail', screen(state({ ...FULL, detail: 'detail_open', plan: 'plan_candidate', selected: ID_OPEN }), { selected: ID_OPEN })],
  ['detail-closed', screen(state({ ...FULL, detail: 'detail_closed', plan: 'plan_closed', selected: ID_CLOSED }), { selected: ID_CLOSED })],
  ['empty', screen(state({ overview: 'empty_overview', list: 'empty_actions', settings: 'settings' }))],
  ['masked', screen(state({ overview: 'user_overview' }), { isAdmin: false })],
  ['forbidden', screen(state({ overview: 'user_overview_closed_panel' }), { isAdmin: false })],
  ['off', screen(state({ overview: 'disabled_overview' }))],
  ['notrunning', screen(state({ overview: 'not_running' }))],
  ['error', screen({ ...M.SH_INIT, overviewError: new TypeError('Failed to fetch') })],
];

// ── States of the review round (PR #84): broken, partial and outdated answers ──

const ok = v => ({ ok: true, value: v });
const bad = e => ({ ok: false, error: e });
const broken = field => new M.ShApiError(200, 'invalid_body', { field });
const ID_X = `rem_${'f'.repeat(32)}`;

/** A good first load, then a refresh where every request fails (the old answers stay). */
function staleState(selected = null) {
  const first = M.applyLoad(M.SH_INIT, {
    overview: ok(M.parseOverview(F.overview.body)), list: ok(M.parseActions(F.actions.body)),
    settings: ok(M.parseSettings(F.settings.body)),
    detail: selected ? ok(M.parseDetail(F.detail_open.body)) : undefined,
    plan: selected ? ok(M.parsePlans(F.plan_open.body).find(p => p.actionId === selected) ?? null) : undefined,
    selected,
  });
  const e = new TypeError('Failed to fetch');
  return M.applyLoad(first, {
    overview: bad(e), list: bad(e), settings: bad(e),
    detail: selected ? bad(e) : undefined, plan: selected ? bad(e) : undefined, selected,
  });
}
function listState(raw) {
  return { ...state(FULL), list: M.parseActions(raw) };
}
const PARTIAL = (() => {
  const raw = structuredClone(F.actions.body);
  raw.actions.push({ action_id: 'kaputt', state: 'proposed' });
  raw.total = 4;
  return raw;
})();
const NO_ROUTERS = (() => {
  const b = structuredClone(F.overview.body);
  delete b.routers;
  return b;
})();
const REVIEW_STATES = () => [
  ['stale', screen(staleState())],
  ['stale-detail', screen(staleState(ID_OPEN), { selected: ID_OPEN })],
  ['invalid-overview', screen({ ...M.SH_INIT, overviewError: broken('json') })],
  ['invalid-list', screen({ ...state(FULL), list: null, listError: broken('actions') })],
  ['partial-list', screen(listState(PARTIAL))],
  ['unreadable-only', screen(listState({ ...F.actions.body, total: 1, actions: [{ action_id: 'x' }] }))],
  ['invalid-detail', screen({ ...state(FULL), detailError: broken('action') }, { selected: ID_OPEN })],
  ['no-plan', screen({ ...state({ ...FULL, detail: 'detail_open' }), plan: null, planFor: ID_OPEN }, { selected: ID_OPEN })],
  ['plan-loading', screen(state({ ...FULL, detail: 'detail_open' }), { selected: ID_OPEN })],
  ['admin-no-routers', screen({ ...state(FULL), overview: M.parseOverview(NO_ROUTERS) })],
  ['odd-status', screen({ ...state(FULL), overview: M.parseOverview({ ...F.overview.body, status: 'maintenance' }) })],
  ['timeout', screen({ ...M.SH_INIT, overviewError: new M.ShApiError(null, 'timeout') })],
];

const PRIVATE = /(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:wlan|phy|eth|br-|lan\d)\S*/i;

test('the tab hangs under Enterprise at order 35, between Network Diagnostics and WiFi Intelligence', () => {
  const hass = () => ({ callApi: async () => ({}) });
  M.bindDiagnosticsHass(hass);
  M.bindWifiHass(hass);
  M.bindSelfHealingHass(hass);
  const tabs = M.getEnterpriseTabs();
  const ids = tabs.map(t => t.id);
  const sh = tabs.find(t => t.id === 'selfhealing');
  assert.equal(sh.title, 'Self-Healing');
  assert.equal(sh.order, 35);
  assert.ok(ids.indexOf('diagnostics') < ids.indexOf('selfhealing'));
  assert.ok(ids.indexOf('selfhealing') < ids.indexOf('wifi'));
});

test('the "observe only" notice stands at the top in every state', () => {
  for (const [name, html] of ALL_STATES()) {
    const t = text(html);
    assert.ok(t.startsWith(`Self-Healing Aktualisieren ${M.OBSERVE_TITLE} ${M.OBSERVE_TEXT}`), name);
  }
});

test('no state has a control that changes anything, and nothing reads as OK', () => {
  const allowed = new Set(['Aktualisieren', 'Erneut versuchen', 'Details anzeigen', 'Details schließen', 'Alle', 'Offen', 'Abgeschlossen']);
  const seen = new Set();
  for (const [name, html] of ALL_STATES()) {
    for (const b of buttons(html)) { assert.ok(allowed.has(b), `${name}: button "${b}"`); seen.add(b); }
    assert.doesNotMatch(body(html), /<(form|input|textarea)\b/, name);
    // no record is resolved in these answers: no green badge or notice anywhere
    assert.doesNotMatch(body(html), /cfg-badge--ok|cfg-notice--ok/, name);
    assert.doesNotMatch(text(html), PRIVATE, name);
  }
  for (const b of ['Aktualisieren', 'Details anzeigen', 'Details schließen', 'Erneut versuchen', 'Alle']) assert.ok(seen.has(b), b);
});

test('overview: tiles, unknown tile with its reason, rollback line', () => {
  const t = text(screen(state(FULL)));
  assert.match(t, /Übersicht 1 Offene Datensätze noch nicht abgeschlossen 0 Laufende Reparaturen/);
  assert.ok(t.includes(`unbekannt Blockierte riskante Aktionen ${M.BLOCKED_RISKY_UNKNOWN}`));
  assert.ok(t.includes(M.ROLLBACK_LINE));
  assert.match(t, /Wartende Vorfälle 1 \(warten, bis ihr Router frei ist\)/);
  assert.ok(t.indexOf('Übersicht') < t.indexOf('Router und Modus'));
  assert.ok(t.indexOf('Router und Modus') < t.indexOf('Datensätze Ein Datensatz je Wurzelvorfall'));
  assert.ok(t.indexOf('Datensätze Ein Datensatz je Wurzelvorfall') < t.indexOf('Einstellungen (nur Anzeige)'));
});

test('routers: configured and effective mode, hold and fleet pause with their reasons', () => {
  const t = text(screen(state(HELD)));
  assert.match(t, new RegExp(`Flotte pausiert ja – ${M.reasonText('store_lost').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} – endet in 1 h`));
  assert.ok(t.includes(`Router 111111 Eingestellt Nur beobachten`) || t.includes('Router 111111 Eingestellt'));
  assert.ok(t.includes(`Gesperrt ${M.reasonText('outcome_unknown')} – ohne Ende – nur ein Administrator hebt sie auf`));
  assert.match(t, /Router 222222 Eingestellt [^·]+ Gilt jetzt [^(]+\(Flotte pausiert\)/);
  assert.ok(t.includes(M.modeText('auto_heal')));
});

test('records: state, incident, router, time, risk and decision per row', () => {
  const html = screen(state(FULL));
  const t = text(html);
  assert.ok(t.includes(M.incidentText('system_service_restart')));
  assert.ok(t.includes(M.stateText('proposed')) && t.includes(M.stateText('cancelled')));
  assert.ok(t.includes(M.outcomeText('recommended')));
  assert.ok(t.includes('Risiko 0 – nur lesend'));
  assert.match(t, /\d{2}\.\d{2}\.\d{4}, \d{2}:\d{2}:\d{2}/);
  assert.match(html, /<time dateTime="2026-/);
  assert.equal((html.match(/class="sh-record"/g) ?? []).length, 2);
  assert.doesNotMatch(body(html), /sh-detail/);
});

test('a selected record: history, explanation, candidate "nicht ausgeführt", what would block, counters', () => {
  const t = text(screen(state({ ...FULL, detail: 'detail_open', plan: 'plan_candidate', selected: ID_OPEN }), { selected: ID_OPEN }));
  for (const part of ['Vorfall und Ursache', 'Entscheidung des Datensatzes', 'Erklärung der Richtlinie', 'Was würde blockieren', 'Zähler', 'Verlauf', 'Weitere Angaben']) {
    assert.ok(t.includes(part), part);
  }
  assert.ok(t.includes(M.CANDIDATE_LABEL));
  assert.ok(t.includes(M.CANDIDATE_NOTE));
  assert.ok(t.includes('Geplante Änderung (nicht ausgeführt)'));
  for (const b of ['no_write_path', 'mode_observe', 'nothing_executable']) assert.ok(t.includes(M.reasonText(b)), b);
  assert.ok(t.includes(M.reasonText('incident_opened')) && t.includes(M.reasonText('decision_recommended')));
  assert.match(t, /Ausführbar: nein/);
  assert.match(t, /Keine Vorabprüfung gespeichert/);
  assert.match(t, /Versuche je Router in 24 h unbekannt – keine lesende Route liefert diese Zahl/);
  assert.match(t, /Ausführung nie ausgeführt/);
});

test('without a candidate the box says so (the live engine names none in 1.53.0)', () => {
  const t = text(screen(state({ ...FULL, detail: 'detail_open', plan: 'plan_open', selected: ID_OPEN }), { selected: ID_OPEN }));
  assert.ok(t.includes(`${M.CANDIDATE_LABEL} ${M.NO_CANDIDATE_TEXT}`));
  assert.ok(!t.includes(M.CANDIDATE_NOTE));
});

test('a failed plan request shows an error, not an empty explanation', () => {
  const s = state({ ...FULL, detail: 'detail_open', selected: ID_OPEN, extra: { planError: new TypeError('x') } });
  const t = text(screen(s, { selected: ID_OPEN }));
  assert.match(t, /Der Datensatz konnte nicht geladen werden/);
  assert.match(t, /Was würde blockieren unbekannt – Plan nicht geladen/);
});

test('empty: a friendly state of its own, never an error', () => {
  const t = text(screen(state({ overview: 'empty_overview', list: 'empty_actions', settings: 'settings' })));
  assert.ok(t.includes(`${M.EMPTY_TITLE} ${M.EMPTY_TEXT}`));
  assert.ok(!t.includes('nicht geladen'));
  assert.match(t, /Letzte Aktivität unbekannt – noch kein Datensatz/);
});

test('a failed overview is an error state with retry, never tiles or "all fine"', () => {
  const html = screen({ ...M.SH_INIT, overviewError: new TypeError('Failed to fetch') });
  const t = text(html);
  assert.match(t, /Self-Healing konnte nicht geladen werden/);
  assert.ok(buttons(html).includes('Erneut versuchen'));
  assert.ok(!t.includes('Übersicht'));
  // a failed refresh keeps the last answer and says so above it
  const stale = text(screen({ ...state(FULL), overviewError: new TypeError('x') }));
  assert.ok(stale.indexOf('konnte nicht geladen werden') < stale.indexOf('Übersicht'));
});

test('410 (integration unloaded): an error without retry, no off box, no tiles', () => {
  const s = { ...M.SH_INIT, overviewError: new M.ShApiError(410, 'integration_not_loaded') };
  const html = screen(s);
  const t = text(html);
  assert.ok(t.startsWith(`Self-Healing Aktualisieren ${M.OBSERVE_TITLE}`));
  assert.match(t, /Die Integration wurde entladen\./);
  assert.match(body(html), /cfg-notice--error/);
  assert.deepEqual(buttons(html), ['Aktualisieren']);
  assert.ok(!t.includes(M.OFF_TITLE));
  assert.ok(!M.isOff(s));
  assert.doesNotMatch(body(html), /id="sh-(overview|routers|records|settings)"/);
  // a 410 after a good answer drops it: nothing from before is shown as current
  const first = M.applyLoad(M.SH_INIT, { overview: { ok: true, value: M.parseOverview(F.overview.body) }, selected: null });
  const gone = M.applyLoad(first, { overview: { ok: false, error: new M.ShApiError(410, 'integration_not_loaded') }, selected: null });
  assert.equal(gone.overview, null);
  assert.ok(!text(screen(gone)).includes('Übersicht'));
});

test('the detail reads plainly: labelled scores, no doubled recovery, "nie"', () => {
  const open = text(screen(state({ ...FULL, detail: 'detail_open', plan: 'plan_open', selected: ID_OPEN }), { selected: ID_OPEN }));
  assert.match(open, /Konfidenz bei der Entscheidung 17 von 100/);
  assert.ok(open.includes('Erklärung der Richtlinie (mit den Fakten von jetzt)'));
  assert.match(open, /Vorfall wieder geöffnet nie/);
  assert.ok(!open.includes('×'));
  // read_only_nothing_changes already says read_only: said once
  const rec = M.reasonText('read_only_nothing_changes');
  assert.ok(open.includes(`Wiederherstellung ${rec} `), open);
  assert.ok(!open.includes(`${rec} (${M.reasonText('read_only')})`));
  // a candidate keeps its rollback kind, and its score lines have a heading
  const cand = text(screen(state({ ...FULL, detail: 'detail_open', plan: 'plan_candidate', selected: ID_OPEN }), { selected: ID_OPEN }));
  assert.match(cand, /Beiträge zur Konfidenz Ursachenstufe/);
  assert.ok(!/Nicht bekannt (?!e)/.test(cand));
});

test('module off, not running, or no route: the "ausgeschaltet" box', () => {
  for (const s of [state({ overview: 'disabled_overview' }), state({ overview: 'not_running' }),
    { ...M.SH_INIT, overviewError: new M.ShApiError(404, '') }]) {
    const t = text(screen(s));
    assert.ok(t.includes(M.OFF_TITLE), t);
    assert.ok(t.includes(M.OFF_HOW));
    assert.doesNotMatch(body(screen(s)), /id="sh-(overview|routers|records|settings)"/);
    assert.ok(M.isOff(s));
  }
});

test('non-admins: counts only, no routers, records or ids', () => {
  const html = screen(state({ overview: 'user_overview' }), { isAdmin: false });
  const t = text(html);
  assert.ok(t.includes(M.MASKED_TEXT));
  assert.ok(t.includes('Übersicht'));
  for (const no of ['Router und Modus', 'Einstellungen', 'Router 111111', 'Wartende Vorfälle']) assert.ok(!t.includes(no), no);
  assert.doesNotMatch(body(html), /id="sh-(routers|records|settings)"/);
  assert.doesNotMatch(body(html), /rtr_|rem_/);
  const forbidden = text(screen(state({ overview: 'user_overview_closed_panel' }), { isAdmin: false }));
  assert.match(forbidden, /Nur für Administratoren/);
  assert.ok(!forbidden.includes('Übersicht'));
});

test('an unknown code is shown raw, never hidden', () => {
  const raw = structuredClone(F.actions.body);
  raw.actions[0].incident_type = 'brand_new_incident';
  raw.actions[0].state = 'brand_new_state';
  const s = { ...state(FULL), list: M.parseActions(raw) };
  const t = text(screen(s));
  assert.ok(t.includes('brand_new_incident') && t.includes('brand_new_state'));
});

test('server text is rendered as text, never as markup', () => {
  const raw = structuredClone(F.actions.body);
  raw.actions[0].incident_type = '<img_src=x>';
  const html = screen({ ...state(FULL), list: M.parseActions(raw) });
  assert.doesNotMatch(body(html), /<img/);
});

test('applyLoad: a failed refresh keeps the last answer; off and forbidden clear it', () => {
  const ok = v => ({ ok: true, value: v });
  const bad = e => ({ ok: false, error: e });
  const ov = M.parseOverview(F.overview.body);
  const first = M.applyLoad(M.SH_INIT, { overview: ok(ov), selected: null });
  assert.equal(first.overview, ov);
  const kept = M.applyLoad(first, { overview: bad(new TypeError('x')), selected: null });
  assert.equal(kept.overview, ov);
  assert.ok(kept.overviewError instanceof TypeError);
  assert.equal(M.applyLoad(first, { overview: bad(new M.ShApiError(503, 'not_running')), selected: null }).overview, null);
  assert.equal(M.applyLoad(first, { overview: bad(new M.ShApiError(403, 'authorization_denied')), selected: null }).overview, null);
  // a deselected record drops its detail
  const withDetail = { ...first, detail: M.parseDetail(F.detail_open.body) };
  assert.equal(M.applyLoad(withDetail, { overview: ok(ov), selected: null }).detail, null);
});

test('the container renders the loading state first (no request during render)', () => {
  let calls = 0;
  const api = { overview: () => { calls++; return new Promise(noop); }, actions: noop, action: noop, plan: noop, settings: noop };
  const t = text(renderToStaticMarkup(h(M.SelfHealingView, { api, isAdmin: true })));
  assert.ok(t.includes(M.OBSERVE_TITLE));
  assert.ok(t.includes(M.LOADING_TEXT));
  assert.equal(calls, 0);
});

test('the dev mock serves every scenario from the recorded answers', async () => {
  for (const sc of ['default', 'empty', 'held', 'candidate', 'user']) {
    const api = M.createMockShApi(sc);
    const ov = await api.overview();
    assert.ok(ov.status === 'on', sc);
  }
  const plan = await M.createMockShApi('candidate').plan(ID_OPEN);
  assert.ok(plan.explanation.candidate);
  await assert.rejects(M.createMockShApi('notrunning').overview(), e => e.status === 503);
  assert.equal(M.mockHass('user').user.is_admin, false);
  // the review scenarios: a 200 without JSON, a partial list, answers that go stale
  await assert.rejects(M.createMockShApi('invalid').overview(), e => e.status === 200 && e.code === 'invalid_body');
  const partial = await M.createMockShApi('partial').actions();
  assert.equal(partial.unreadable, 1);
  assert.equal(M.listNotes(partial).length, 2);
  const stale = M.createMockShApi('stale');
  assert.equal((await stale.overview()).status, 'on');
  await new Promise(r => setTimeout(r, 600));
  await assert.rejects(stale.overview());
});

// ── Review round of PR #84 ───────────────────────────────────────────────

test('P2-1: a broken list answer is an error, never "Noch nichts beobachtet"', () => {
  const t = text(screen({ ...state(FULL), list: null, listError: broken('actions') }));
  assert.match(t, /Die Antwort der Liste war nicht lesbar \(Status 200, Teil actions\)/);
  assert.ok(!t.includes(M.EMPTY_TITLE) && !t.includes('das ist kein Fehler'));
  assert.ok(buttons(screen({ ...state(FULL), list: null, listError: broken('actions') })).includes('Erneut versuchen'));
});

test('P2-1: a broken overview is an error for an admin, never "only administrators" or a page of "unbekannt"', () => {
  const html = screen({ ...M.SH_INIT, overviewError: broken('json') });
  const t = text(html);
  assert.match(t, /Die Antwort von Self-Healing war nicht lesbar \(Status 200, Teil json\)/);
  assert.match(body(html), /cfg-notice--error/);
  assert.ok(!t.includes(M.MASKED_TEXT) && !t.includes('Übersicht'));
  assert.ok(buttons(html).includes('Erneut versuchen'));
});

test('P2-1: dropped rows and a total that does not match are said; empty only for 0 and []', () => {
  const t = text(screen(listState(PARTIAL)));
  assert.match(t, /1 Datensatz nicht lesbar/);
  assert.match(t, /Die Antwort passt nicht zusammen: Der Server meldet 4 Datensätze, geliefert wurden 3\./);
  assert.equal((screen(listState(PARTIAL)).match(/class="sh-record"/g) ?? []).length, 2);
  const only = text(screen(listState({ ...F.actions.body, total: 1, actions: [{ action_id: 'x' }] })));
  assert.match(only, /Keine lesbaren Datensätze in der Antwort\. 1 Datensatz nicht lesbar/);
  assert.ok(!only.includes(M.EMPTY_TITLE));
  const lost = text(screen(listState({ ...F.actions.body, total: 3, actions: [] })));
  assert.ok(!lost.includes(M.EMPTY_TITLE));
  assert.match(lost, /Der Server meldet 3 Datensätze, geliefert wurden 0\./);
  const noTotal = text(screen(listState({ actions: [] })));
  assert.ok(!noTotal.includes(M.EMPTY_TITLE));
  assert.match(noTotal, /nennt keine Gesamtzahl/);
  assert.ok(text(screen(listState(F.empty_actions.body))).includes(M.EMPTY_TITLE));
});

test('P3-1: unknown by_state keys are listed with raw code and count', () => {
  const b = structuredClone(F.overview.body);
  b.counts.by_state.brand_new_state = 3;
  const t = text(screen({ ...state(FULL), overview: M.parseOverview(b) }));
  assert.match(t, /Zustände, die dieser Tab nicht kennt \(roh vom Server\): brand_new_state: 3/);
  // only unknown states counted: not "in keinem Zustand ein Datensatz"
  const z = structuredClone(F.empty_overview.body);
  z.counts.by_state.brand_new_state = 1;
  const tz = text(screen({ ...state({ overview: 'empty_overview', list: 'empty_actions', settings: 'settings' }), overview: M.parseOverview(z) }));
  assert.ok(!tz.includes('in keinem Zustand ein Datensatz'));
  assert.match(tz, /brand_new_state: 1/);
});

test('P3-2: after a failed refresh the old values are marked outdated with their time', () => {
  const html = screen(staleState());
  const t = text(html);
  assert.ok(t.includes('Aktualisieren fehlgeschlagen (keine Antwort vom Server). Die Werte unten sind vom 21.09.2026, 16:45:20 und können veraltet sein.'));
  assert.ok(!t.includes('Es wird nichts als „in Ordnung“ angezeigt'));
  // overview + routers, the list and the settings: each its own outdated block, with the word "Veraltet"
  assert.equal((body(html).match(/class="sh-stale" data-stale="true"/g) ?? []).length, 3);
  assert.equal((t.match(/Veraltet Aktualisieren fehlgeschlagen/g) ?? []).length, 3);
  const at = body(html).indexOf('data-stale');
  assert.ok(at < body(html).indexOf('id="sh-overview"') && at < body(html).indexOf('id="sh-routers"'));
  // the open record too
  const d = screen(staleState(ID_OPEN), { selected: ID_OPEN });
  assert.equal((body(d).match(/data-stale="true"/g) ?? []).length, 4);
  assert.match(text(d), /Veraltet Aktualisieren fehlgeschlagen \(keine Antwort vom Server\)\. Die Werte unten sind vom 21\.09\.2026, 16:45:20 und können veraltet sein\. Erneut versuchen Vorfall und Ursache/);
});

test('P3-3: a missing field reads "unbekannt", only an explicit null "keine"', () => {
  const raw = structuredClone(F.detail_open.body);
  delete raw.router_hold;
  for (const k of ['playbook_id', 'backup_ref', 'verification', 'planned_changes', 'components']) delete raw.action[k];
  const s = { ...state({ ...FULL, plan: 'plan_open', selected: ID_OPEN }), detail: M.parseDetail(raw) };
  const t = text(screen(s, { selected: ID_OPEN }));
  for (const name of ['Sperre des Routers', 'Geplante Änderung', 'Playbook', 'Sicherung', 'Nachprüfung', 'Bauteile']) {
    assert.ok(t.includes(`${name} unbekannt – nicht in der Antwort`), name);
  }
  const full = text(screen(state({ ...FULL, detail: 'detail_open', plan: 'plan_open', selected: ID_OPEN }), { selected: ID_OPEN }));
  for (const line of ['Sperre des Routers keine', 'Geplante Änderung keine', 'Playbook keines', 'Sicherung keine Sicherung verknüpft',
    'Nachprüfung keine Nachprüfung', 'Bauteile keine (der Router selbst)']) {
    assert.ok(full.includes(line), line);
  }
});

test('P3-4: a detail answer without a valid action shows an error, not "loading" forever', () => {
  const t = text(screen({ ...state(FULL), detailError: broken('action') }, { selected: ID_OPEN }));
  assert.match(t, /Die Antwort zum Datensatz war nicht lesbar \(Status 200, Teil action\)/);
  assert.ok(!t.includes('Datensatz wird geladen'));
});

test('P3-5: no plan in the answer is not "no candidate"; "no candidate" needs a plan that names none', () => {
  const none = text(screen({ ...state({ ...FULL, detail: 'detail_open' }), plan: null, planFor: ID_OPEN }, { selected: ID_OPEN }));
  assert.ok(!none.includes(M.NO_CANDIDATE_TEXT));
  assert.ok(none.includes(`${M.CANDIDATE_LABEL} unbekannt – ${M.PLAN_MISSING_TEXT}`));
  assert.ok(none.includes(`Was würde blockieren unbekannt – ${M.PLAN_MISSING_TEXT}`));
  // not loaded yet: loading, never "no candidate"
  const wait = text(screen(state({ ...FULL, detail: 'detail_open' }), { selected: ID_OPEN }));
  assert.ok(!wait.includes(M.NO_CANDIDATE_TEXT));
  assert.ok(wait.includes(`${M.CANDIDATE_LABEL} ${M.PLAN_LOADING_TEXT}`));
  // a plan without an explanation: the candidate is unknown
  const plan = { ...M.parsePlans(F.plan_open.body)[0], explanation: null };
  const noExp = text(screen({ ...state({ ...FULL, detail: 'detail_open' }), plan, planFor: ID_OPEN }, { selected: ID_OPEN }));
  assert.ok(noExp.includes(`${M.CANDIDATE_LABEL} unbekannt – der Plan enthält keine Erklärung`));
  // a plan whose explanation names none: now it says so
  const named = text(screen(state({ ...FULL, detail: 'detail_open', plan: 'plan_open', selected: ID_OPEN }), { selected: ID_OPEN }));
  assert.ok(named.includes(`${M.CANDIDATE_LABEL} ${M.NO_CANDIDATE_TEXT}`));
});

test('P3-6: an unknown overview status is shown raw', () => {
  const html = screen({ ...state(FULL), overview: M.parseOverview({ ...F.overview.body, status: 'maintenance' }) });
  assert.match(text(html), /Der Server meldet den Zustand „maintenance“, den dieser Tab nicht kennt\./);
  assert.match(body(html), /data-status="maintenance"/);
  assert.doesNotMatch(text(screen(state(FULL))), /meldet den Zustand/);
});

test('P3-7: an admin whose overview has no routers is told the list is missing, not "only administrators"', () => {
  const html = screen({ ...state(FULL), overview: M.parseOverview(NO_ROUTERS) });
  const t = text(html);
  assert.ok(t.includes(M.ROUTERS_MISSING_TEXT));
  assert.ok(!t.includes(M.MASKED_TEXT));
  assert.match(body(html), /id="sh-routers"/);
  assert.match(body(html), /id="sh-records"/);
  // a non-admin still sees the counts only
  assert.ok(text(screen(state({ overview: 'user_overview' }), { isAdmin: false })).includes(M.MASKED_TEXT));
});

test('P3-8: the container loads through the loader, aborts on unmount and polls with "poll"', () => {
  const tsx = readFileSync(join(here, 'SelfHealingView.tsx'), 'utf8');
  assert.match(tsx, /const l = createShLoader\(\{/);
  assert.match(tsx, /return \(\) => \{\n\s+l\.dispose\(\);/);
  assert.match(tsx, /\) load\('poll'\);/);
  assert.match(tsx, /if \(pageVisible\(\)\) load\('now'\);/);
  assert.doesNotMatch(tsx, /api\.(overview|actions|action|plan|settings)\(/, 'requests only through the loader');
});

test('P3-9: every clickable element of every state is on a pinned list', () => {
  const BUTTONS = ['Abgeschlossen', 'Aktualisieren', 'Alle', 'Details anzeigen', 'Details schließen', 'Erneut versuchen', 'Offen'];
  const OPTIONS = ['Alle Router', 'Router 111111', 'Router 222222'];
  const seenButtons = new Set();
  const seenOptions = new Set();
  for (const [name, html] of [...ALL_STATES(), ...REVIEW_STATES()]) {
    const b = body(html);
    for (const x of buttons(b)) seenButtons.add(x);
    for (const m of b.matchAll(/<option[^>]*>([\s\S]*?)<\/option>/g)) seenOptions.add(text(m[1]));
    assert.equal((b.match(/<select\b/g) ?? []).length <= 1, true, `${name}: one select at most`);
    // nothing else is clickable: no link, no role=button, no tabindex, no summary, no input, no form
    assert.doesNotMatch(b, /<(a|input|textarea|form|summary|details)\b|role="(button|link|menuitem|switch|checkbox)"|tabindex=|contenteditable/i, name);
  }
  assert.deepEqual([...seenButtons].sort(), BUTTONS);
  assert.deepEqual([...seenOptions].sort(), OPTIONS);
});

test('P3-10: holds and modes read plainly: nothing ran, nothing runs', () => {
  const t = text(screen(state(HELD)));
  assert.ok(t.includes(`Gesperrt ${M.reasonText('outcome_unknown')} – ohne Ende – nur ein Administrator hebt sie auf ${M.HOLD_OUTCOME_NOTE}`));
  assert.match(t, new RegExp(`Router 222222 Eingestellt ${M.modeText('auto_heal')} – ${M.MODE_NOTE}`));
  assert.doesNotMatch(t, new RegExp(`${M.modeText('observe')} – ${M.MODE_NOTE}`));
  // the record's hold in the detail too
  const d = text(screen(state({ ...HELD, detail: 'held_detail', plan: 'held_plan', selected: ID_OPEN }), { selected: ID_OPEN }));
  assert.ok(d.includes(`Sperre des Routers ${M.reasonText('outcome_unknown')} – ohne Ende – nur ein Administrator hebt sie auf ${M.HOLD_OUTCOME_NOTE}`));
});
