// Tests of the logic of "Zustand", "Vergleich", the export and the jumps of
// the "Zeitreise" tab (1.52.0; node:test, no dependencies). The answers are
// real route answers from tmFixtureState.json, written by
// tests/test_tm_panel_fixture_v1520.py (invented values only).
process.env.TZ = 'Europe/Berlin';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AROUND_S, CUSTOM_WINDOW, DEFAULT_FILTERS, TmApiError, aroundWindow, askedFilters, customWindow, customWindowText,
  errorInfo, exportQueryString, filterKey, firstQuery, parseMark, queryString, rememberMarkClients,
} from './tmLogic.ts';
import {
  COMPARE_INIT, NOTHING_CHANGED, SAME_BUT_EVENTS, STATE_INIT, UNKNOWN, compareQueryString, compareReducer, compareRows,
  compareSummary, deltaText, fromLocalInput, globalReasonText, jumpLabel, markTarget, moreClientsQuery, parseCompare,
  parseState, reachableView, roleView, radioView, shownTarget, stateQueryString, stateReasonText, stateReducer, targetOf,
  toLocalInput, uplinkView, utilizationText, wanText,
} from './tmState.ts';
import {
  GLOBAL_REASON_TEXT, JUMP_KIND_TAB, JUMP_REF_TAB, JUMP_TAB_TEXT, STATE_REASON_TEXT,
} from './tmTexts.ts';
import {
  LOCAL_GAP_TEXT, LOCAL_TWICE_TEXT, OTHER_UNKNOWN_MANY, OTHER_UNKNOWN_NONE, OTHER_UNKNOWN_ONE, PART_UNREADABLE_TEXT,
  RADIOS_NOT_OBSERVED_TEXT, dialogFocus, dialogKey, exportOmittedText, otherSourcesText, otherUnknownText, parseLocalInput,
  partStateText, radiosView, stateLoadAt,
} from './tmState.ts';
import { clientTitle, paramsText, timeText } from './tmLogic.ts';

const here = dirname(fileURLToPath(import.meta.url));
const F = JSON.parse(readFileSync(join(here, 'tmFixtureState.json'), 'utf8'));
const S = name => parseState(F[name].body);
const C = name => parseCompare(F[name].body);
const err = name => new TmApiError(F[name].status, F[name].body.code, F[name].body.details ?? {});
const NOW_MS = F.state.body.generated_at * 1000;
const R1 = 'rtr_11111111111111111111111111111111';
const R2 = 'rtr_22222222222222222222222222222222';

// ── state ────────────────────────────────────────────────────────────────

test('state: a known answer per router, values with reason are never shown', () => {
  const s = S('state');
  assert.equal(s.status, 'ok');
  assert.equal(s.known, true);
  const [r1, r2] = s.routers;
  assert.deepEqual([r1.routerId, r2.routerId], [R1, R2]);
  assert.deepEqual(reachableView(r1.reachable), { text: 'erreichbar', unknown: false, reason: null, derived: true, tone: null });
  assert.deepEqual(reachableView(r2.reachable), { text: 'nicht erreichbar', unknown: false, reason: null, derived: false, tone: 'warn' });
  // role unknown (not observed): "unbekannt" and the reason, never a value
  const role = roleView(r1.role);
  assert.equal(role.text, UNKNOWN);
  assert.equal(role.unknown, true);
  assert.equal(role.tone, null);
  assert.equal(role.reason, 'noch kein Wert beobachtet');
  assert.equal(roleView(r2.role).reason, 'Router nicht erreichbar');
  // radios: channel 44 after the change, derived
  assert.equal(r1.radios.derived, true);
  assert.equal(radioView(r1.radios.items[0], true).text, 'Kanal 44 · 80 MHz · an');
  assert.equal(r2.radios.state, 'unknown');
  assert.equal(r2.radios.reason, 'router_down');
  // the open outage of Router 2 is an interval in the timeline format
  assert.equal(s.intervals.length, 1);
  assert.equal(s.intervals[0].kind, 'router_down');
  assert.equal(s.intervals[0].endState, 'open');
  // clients for an administrator: two sessions, one per router
  assert.equal(s.clients.state, 'ok');
  assert.equal(s.clients.total, 2);
  assert.deepEqual(s.clients.perRouter.map(p => p.clients), [1, 1]);
  assert.ok(s.clients.items.every(c => /^tmc_[0-9a-f]{16}$/.test(c.client)));
});

test('state: a value whose reason is set drops a value the server might still send', () => {
  const s = parseState({
    status: 'ok', known: true, routers: [{
      router_id: R1, reachable: { value: true, derived: false, reason: 'observation_gap' },
      role: { value: 'gateway', derived: false, reason: 'settling' }, uplink: { value: null, derived: false, reason: null },
      radios: { state: 'ok', items: [{ key: '5g0', band: '5g', channel: 36, width: 80, state: 'up', reason: 'ambiguous_radio' }] },
    }],
  });
  const r = s.routers[0];
  assert.equal(r.reachable.value, null);
  assert.equal(reachableView(r.reachable).text, UNKNOWN);
  assert.equal(r.role.value, null);
  assert.equal(r.radios.items[0].channel, null);
  assert.equal(radioView(r.radios.items[0], false).reason, 'Funk nicht eindeutig zuzuordnen');
  // a known null uplink: directly at the gateway
  assert.equal(uplinkView(r.uplink).text, 'kein vorgeschalteter Router');
  assert.equal(uplinkView({ value: { routerId: R2, routerName: 'Router 2' }, derived: true, reason: null, cause: null }).text, 'über Router 2');
  // LAN down: "nicht erreichbar (LAN)", still a warning in words
  assert.equal(reachableView({ value: false, derived: true, reason: null, cause: 'lan_down' }).text, 'nicht erreichbar (LAN)');
  assert.equal(roleView({ value: 'gateway', derived: true, reason: null, cause: null }).text, 'Gateway');
  assert.equal(roleView({ value: 'node', derived: true, reason: null, cause: null }).text, 'Mesh-Knoten');
});

test('state: every global reason of the fixture is unknown with its sentence, no routers counted as known', () => {
  for (const reason of ['not_recorded', 'beyond_retention', 'ha_gap', 'observation_gap', 'evicted']) {
    const s = S(`state_${reason}`);
    assert.equal(s.known, false, reason);
    assert.equal(s.unknownReason, reason);
    assert.equal(globalReasonText(reason), GLOBAL_REASON_TEXT[reason]);
    for (const r of s.routers) assert.equal(reachableView(r.reachable).unknown, true, reason);
  }
  assert.equal(globalReasonText('something_new'), 'Der Grund ist unbekannt.');
  assert.equal(stateReasonText('something_new'), 'Grund unbekannt');
  for (const [k, v] of Object.entries(STATE_REASON_TEXT)) assert.equal(stateReasonText(k), v);
});

test('state: off, unavailable, a user and the client switch off', () => {
  assert.equal(S('state_off').status, 'off');
  assert.equal(S('state_unavailable').status, 'unavailable');
  assert.equal(S('state_unavailable').reason, 'not_running');
  const user = S('state_user');
  assert.equal(user.clients.reason, 'admin_only');
  assert.equal(user.config.reason, 'admin_only');
  assert.equal(S('state_clients_off').clients.reason, 'clients_off');
});

test('state: the client list in two pages; "Weitere laden" only for administrators', () => {
  const p1 = S('state_clients_page1');
  const q = { at: p1.at, routerId: null, clientsCursor: null };
  let s = stateReducer(STATE_INIT, { type: 'start', seq: 1 });
  s = stateReducer(s, { type: 'done', seq: 1, answer: p1, query: q });
  assert.equal(s.clients.length, 1);
  assert.equal(s.clientsCursor, F.state_clients_page1.body.clients.next_cursor);
  // a non-admin never asks for a client page, an administrator with the answer's moment
  assert.equal(moreClientsQuery(s, false), null);
  const more = moreClientsQuery(s, true);
  assert.deepEqual(more, { ...q, clientsCursor: s.clientsCursor });
  assert.match(stateQueryString(more), /^at=1800000599&clients_cursor=1800000180000%3Atmm_[0-9a-f]{16}$/);
  s = stateReducer(s, { type: 'moreStart', seq: 2 });
  s = stateReducer(s, { type: 'moreDone', seq: 2, answer: S('state_clients_page2') });
  assert.equal(s.clients.length, 2);
  assert.equal(s.clientsCursor, null);
  assert.equal(moreClientsQuery(s, true), null);
});

test('state: an older answer never overwrites a newer one; a new moment drops a pending page', () => {
  let s = stateReducer(STATE_INIT, { type: 'start', seq: 1 });
  s = stateReducer(s, { type: 'start', seq: 2 });
  const newer = S('state');
  s = stateReducer(s, { type: 'done', seq: 2, answer: newer, query: { at: 1, routerId: null, clientsCursor: null } });
  const after = stateReducer(s, { type: 'done', seq: 1, answer: S('state_off'), query: { at: 0, routerId: null, clientsCursor: null } });
  assert.equal(after, s);
  assert.equal(stateReducer(s, { type: 'fail', seq: 1, error: new Error('x') }), s);
  let m = stateReducer(s, { type: 'moreStart', seq: 3 });
  m = stateReducer(m, { type: 'start', seq: 4 });
  assert.equal(m.loadingMore, false);
  assert.equal(stateReducer(m, { type: 'moreDone', seq: 3, answer: S('state_clients_page2') }), m);
});

test('state and compare: query strings from checked values only', () => {
  assert.equal(stateQueryString({ at: 1800000599.5, routerId: R1, clientsCursor: null }), `at=1800000599.5&router_id=${R1}`);
  assert.equal(stateQueryString({ at: 1, routerId: 'eth0', clientsCursor: '<x>' }), 'at=1');
  assert.equal(compareQueryString({ t1: 10, t2: 20, routerId: null }), 't1=10&t2=20');
  assert.equal(compareQueryString({ t1: 10, t2: 20, routerId: R2 }), `t1=10&t2=20&router_id=${R2}`);
});

test('state: server errors in plain words at the field', () => {
  const at = errorInfo(err('state_bad_at'), 'state');
  assert.deepEqual(at, { kind: 'invalid', message: 'Der Zeitpunkt liegt in der Zukunft. Bitte einen früheren wählen.', retry: false, field: 'at' });
  assert.equal(errorInfo(err('compare_empty'), 'compare').message, '„Bis“ muss nach „Von“ liegen.');
  assert.equal(errorInfo(err('compare_too_large'), 'compare').message, 'Zwischen „Von“ und „Bis“ liegen höchstens 14 Tage.');
  assert.equal(errorInfo(new TmApiError(400, 'invalid_request', { field: 't1', reason: 'missing' }), 'compare').message, 'Bitte „Von“ angeben.');
  assert.equal(errorInfo(new TmApiError(400, 'invalid_request', { field: 't2', reason: 'missing' }), 'compare').message, 'Bitte „Bis“ angeben.');
  assert.equal(errorInfo(new TmApiError(403, 'x'), 'state').kind, 'forbidden');
  assert.equal(errorInfo(new TmApiError(500, 'x'), 'compare').message, 'Der Vergleich konnte nicht geladen werden.');
  // the server's message never reaches the screen
  for (const name of ['state_bad_at', 'compare_empty', 'compare_too_large', 'export_refused', 'export_user']) {
    assert.ok(!errorInfo(err(name), 'compare').message.includes(F[name].body.message));
  }
});

test('local time of the fields: round trip, seconds optional, nonsense refused', () => {
  const ts = F.state.body.at;
  const v = toLocalInput(ts);
  assert.equal(v, '2027-01-15T09:09:59');
  assert.equal(fromLocalInput(v), Math.floor(ts));
  assert.equal(fromLocalInput('2027-01-15T09:09'), Math.floor(ts) - 59);
  assert.equal(fromLocalInput('2027-01-15T09:09:59.250'), Math.floor(ts));
  for (const bad of ['', 'heute', '2027-02-30T10:00', '2027-01-15 09:09', '2027-13-01T00:00']) assert.equal(fromLocalInput(bad), null, bad);
  // summer time: the local clock, not UTC
  assert.equal(toLocalInput(Date.UTC(2026, 6, 1, 10, 0, 0) / 1000), '2026-07-01T12:00:00');
});

test('traffic and utilization in words, "—" for what is unknown', () => {
  assert.equal(wanText({ state: 'available', avgRxBps: 1.2e6, avgTxBps: 3e5, timeCoverage: 1 }), 'Empfangen Ø 1,2 Mbit/s · Gesendet Ø 300 kbit/s');
  assert.equal(wanText({ state: 'available', avgRxBps: null, avgTxBps: 3e5, timeCoverage: 1 }), 'Empfangen Ø — · Gesendet Ø 300 kbit/s');
  assert.equal(wanText({ state: 'unavailable', avgRxBps: null, avgTxBps: null, timeCoverage: null }), 'keine Messwerte in dieser Stunde');
  assert.equal(utilizationText({ band: '5g', state: 'measured', mean: 41.3, maximum: 80 }), '5 GHz: Ø 41 % · höchstens 80 %');
  assert.equal(utilizationText({ band: '2.4g', state: 'unknown', mean: null, maximum: null }), '2,4 GHz: —');
  const r = S('state').routers[0];
  assert.deepEqual([r.traffic.state, r.traffic.reason, r.utilization.reason], ['off', 'not_running', 'not_running']);
});

// ── compare ──────────────────────────────────────────────────────────────

test('compare: rows per router; changed, same and unknown kept apart', () => {
  const a = C('compare');
  const [r1, r2] = a.routers;
  const rows1 = compareRows(r1, a, true);
  const by = rows => Object.fromEntries(rows.map(r => [r.key, r]));
  const x1 = by(rows1);
  assert.deepEqual([x1.reachable.state, x1.reachable.before, x1.reachable.after], ['same', 'erreichbar', 'erreichbar']);
  assert.deepEqual([x1.role.state, x1.role.before, x1.role.after], ['unknown', UNKNOWN, UNKNOWN]);
  assert.deepEqual([x1['radio-5g0'].state, x1['radio-5g0'].before, x1['radio-5g0'].after],
    ['changed', 'Kanal 36 · 80 MHz · an', 'Kanal 44 · 80 MHz · an']);
  assert.equal(x1['radio-5g0'].label, 'Funk 5 GHz');
  assert.deepEqual([x1.clients.before, x1.clients.after, x1.clients.state], ['2', '1', 'changed']);
  assert.equal(deltaText(r1.clients), 'von 2 auf 1 (−1)');
  assert.equal(deltaText(r2.clients), 'von 0 auf 1 (+1)');
  const x2 = by(compareRows(r2, a, true));
  assert.deepEqual([x2.reachable.state, x2.reachable.after], ['changed', 'nicht erreichbar']);
  assert.deepEqual([x2.radios.state, x2.radios.reason], ['unknown', 'Router nicht erreichbar']);
  // a user never gets the client row
  assert.ok(!compareRows(r1, a, false).some(r => r.key === 'clients'));
  assert.ok(C('compare_user').routers.every(r => r.clients === null));
  assert.deepEqual(a.marks, { count: 4, byGroup: { clients: 2, infrastructure: 1, radio: 1 } });
  assert.equal(compareSummary(a, true), '4 Merkmale haben sich geändert.');
});

test('compare: "nothing changed" only when both are known and nothing differs or happened', () => {
  const quiet = C('compare_quiet');
  // the real quiet pair: Router 2 is down, its radios unknown, roles not observed
  assert.equal(compareSummary(quiet, true), 'Keine bekannte Änderung; 5 Merkmale sind zu einem der Zeitpunkte unbekannt.');
  const known = { ...quiet, routers: quiet.routers.map(r => ({
    ...r, role: { ...r.role, state: 'same' }, uplink: { ...r.uplink, state: 'same' }, radios: [],
  })) };
  assert.equal(compareSummary(known, true), NOTHING_CHANGED);
  assert.equal(compareSummary({ ...known, marks: { count: 2, byGroup: {} } }, true), SAME_BUT_EVENTS);
  // one side unknown: never "nothing changed", the dependent rows unknown with the side's reason
  const one = C('compare_one_unknown');
  assert.equal(one.before.known, false);
  assert.equal(compareSummary(one, true), 'Für „Von“ ist kein Zustand bekannt; Änderungen, die davon abhängen, sind unbekannt.');
  const rows = compareRows(one.routers[0], one, true);
  assert.equal(rows[0].state, 'unknown');
  assert.equal(rows[0].before, UNKNOWN);
  assert.equal(rows[0].after, 'erreichbar');
  assert.equal(rows[0].reason, 'nicht aufgezeichnet');
  assert.ok(rows.every(r => r.state !== 'changed'));
});

test('compare: an older answer never overwrites a newer one', () => {
  let s = compareReducer(COMPARE_INIT, { type: 'start', seq: 1 });
  s = compareReducer(s, { type: 'start', seq: 2 });
  s = compareReducer(s, { type: 'done', seq: 2, answer: C('compare') });
  assert.equal(compareReducer(s, { type: 'done', seq: 1, answer: C('compare_quiet') }), s);
  assert.equal(compareReducer(s, { type: 'fail', seq: 1, error: new Error('x') }), s);
  assert.equal(C('compare_off').status, 'off');
});

// ── timeline: custom window, client filter, export ───────────────────────

test('custom window: ±30 min around a moment, capped at now and at 14 days, shown as text', () => {
  const at = F.state.body.at;
  assert.equal(AROUND_S, 1800);
  assert.deepEqual(aroundWindow(at, (at + 3600) * 1000), { from: Math.floor(at - 1800), until: Math.ceil(at + 1800) });
  // the upper end never lies after now (+1 s, like a first page)
  assert.deepEqual(aroundWindow(at, at * 1000), { from: Math.floor(at - 1800), until: Math.floor(at) + 1 });
  assert.equal(customWindow(100, 100, 1e12), null);
  const big = customWindow(0, 30 * 86_400, 1e15);
  assert.equal(big.until - big.from, 14 * 86_400);
  assert.equal(customWindowText({ from: Date.UTC(2026, 10, 21, 12, 30) / 1000, until: Date.UTC(2026, 10, 21, 13, 30) / 1000 }),
    'Fenster: 21.11. 13:30 – 14:30');
  assert.equal(customWindowText({ from: Date.UTC(2026, 10, 21, 22, 30) / 1000, until: Date.UTC(2026, 10, 22, 0, 30) / 1000 }),
    'Fenster: 21.11. 23:30 – 22.11. 01:30');
});

test('custom window and client filter reach the query; a user never sends a client', () => {
  const f = { ...DEFAULT_FILTERS, window: CUSTOM_WINDOW, custom: { from: 1000, until: 5000 }, client: 'tmc_0123456789abcdef' };
  const q = firstQuery(f, 1e13);
  assert.deepEqual([q.from, q.until, q.client], [1000, 5000, 'tmc_0123456789abcdef']);
  assert.equal(queryString(q), 'from=1000&until=5000&spans=1&client=tmc_0123456789abcdef');
  assert.equal(firstQuery(askedFilters(f, false), 1e13).client, null);
  assert.equal(askedFilters(f, true), f);
  assert.equal(firstQuery({ ...f, client: 'aa:bb' }, 1e13).client, null);
  // a change of window, custom window or client is a new list
  const keys = new Set([filterKey(DEFAULT_FILTERS), filterKey(f), filterKey({ ...f, client: null }), filterKey({ ...f, custom: { from: 1, until: 2 } })]);
  assert.equal(keys.size, 4);
  // the export: the same window and filters, never spans or client, a cursor only when valid
  assert.equal(exportQueryString(q), 'from=1000&until=5000');
  assert.equal(exportQueryString({ ...q, routerId: R1 }, '1800000360000:tmm_e388f728c5caaf9a'),
    `from=1000&until=5000&router_id=${R1}&cursor=1800000360000%3Atmm_e388f728c5caaf9a`);
  assert.equal(exportQueryString(q, 'nope'), 'from=1000&until=5000');
});

test('client filter options come from the loaded marks of the real client filter answer', () => {
  const marks = F.timeline_client.body.marks.map(parseMark);
  const names = rememberMarkClients({}, marks);
  assert.deepEqual(Object.keys(names), [F.timeline_client.body.marks[0].client]);
});

test('export: 503 of the audit log and 403 in plain words', () => {
  assert.deepEqual(errorInfo(err('export_refused'), 'export'),
    { kind: 'refused', message: 'Export nicht möglich: Das Audit-Protokoll ist nicht verfügbar.', retry: true });
  assert.equal(errorInfo(err('export_user'), 'export').message, 'Keine Berechtigung für den Export (nur Administratoren).');
  assert.equal(errorInfo(new TmApiError(503, 'x'), 'export').message, 'Der Export ist fehlgeschlagen.');
  assert.equal(F.export_cut.body.truncated, true);
  assert.match(F.export_cut.body.next_cursor, /^\d+:tmm_[0-9a-f]{16}$/);
});

// ── jumps (§23) ──────────────────────────────────────────────────────────

const mark = (module, type, kind, id = 'abc', versionId = null) =>
  ({ ref: { module, type, id, versionId }, kind, routerId: R1 });

test('jumps: every ref of the table leads to its tab, by kind for audit entries, none for NI', () => {
  const can = () => true;
  for (const [key, tab] of Object.entries(JUMP_REF_TAB)) {
    const [module, type] = key.split('.');
    if (tab === 'by_kind') {
      for (const [kind, ktab] of Object.entries(JUMP_KIND_TAB)) {
        const t = markTarget(mark(module, type, kind));
        assert.equal(t?.tab ?? 'none', ktab, `${key} ${kind}`);
      }
      assert.equal(markTarget(mark(module, type, 'brand_new_kind')), null);
      continue;
    }
    const t = markTarget(mark(module, type, 'x'));
    assert.equal(t?.tab ?? 'none', tab, key);
  }
  // the object: an incident is selected, a version by its version id, the audit entry by its id
  assert.deepEqual(markTarget(mark('security_center', 'incident', 'x', 'inc_1')),
    { tab: 'security', objectType: 'incident', objectId: 'inc_1', versionId: null, routerId: R1 });
  const v = 'bkp_' + '0'.repeat(32);
  assert.deepEqual(markTarget(mark('config_manager', 'version', 'config_version', v, v)),
    { tab: 'config', objectType: 'version', objectId: v, versionId: v, routerId: R1 });
  assert.equal(markTarget(mark('security_center', 'timeline', 'x', null)).objectType, null);
  assert.equal(markTarget({ ref: null, kind: 'x', routerId: null }), null);
  assert.equal(markTarget(mark('unknown_module', 'thing', 'x')), null);
  // shown: never the Time Machine itself, never a tab this user does not have
  assert.equal(shownTarget(markTarget(mark('time_machine', 'mark', 'x')), can), null);
  assert.equal(shownTarget(markTarget(mark('core_audit', 'drift', 'config_drift')), tab => tab !== 'config'), null);
  assert.equal(shownTarget(markTarget(mark('core_audit', 'drift', 'config_drift')), can).tab, 'config');
  for (const tab of Object.keys(JUMP_TAB_TEXT)) assert.equal(jumpLabel(tab), `Im Tab ${JUMP_TAB_TEXT[tab]} öffnen`);
  assert.equal(jumpLabel('security'), 'Im Tab Security Center öffnen');
});

test('jumps: a target the server sends is checked (known tab, ids by their form)', () => {
  const v = 'bkp_' + 'a'.repeat(32);
  assert.deepEqual(targetOf({ tab: 'config', object_type: 'version', object_id: v, version_id: v }, R1),
    { tab: 'config', objectType: 'version', objectId: v, versionId: v, routerId: R1 });
  assert.equal(targetOf({ tab: 'evil', object_type: null }), null);
  assert.equal(targetOf(null), null);
  assert.equal(targetOf({ tab: 'config', object_type: 'version', object_id: '<script>', version_id: 'x' }).objectId, null);
  // the marks of the real answers carry their ref
  const m = parseMark(F.state.body.intervals[0]);
  assert.deepEqual(m.ref, { module: 'time_machine', type: 'mark', id: 'm7', versionId: null });
  assert.equal(shownTarget(markTarget(m), () => true), null);
});

// ── tmApi: state, compare, export (fake fetch) ───────────────────────────

import { TM_BASE, createTmApi } from './tmApi.ts';

function fakeHass(calls, answers) {
  const hass = { auth: { data: { access_token: 'tok-secret' } }, callApi: async () => { throw new Error('no callApi'); } };
  const fetch = async (url, init) => {
    calls.push({ url, init });
    const { status, body } = answers.shift();
    const text = JSON.stringify(body);
    return { status, ok: status >= 200 && status < 300, json: async () => JSON.parse(text), text: async () => text };
  };
  return createTmApi(() => hass, { fetch });
}

test('api: state and compare ask their route with the checked query and parse the answer', async () => {
  const calls = [];
  const api = fakeHass(calls, [F.state, F.compare]);
  const s = await api.state({ at: F.state.body.at, routerId: R1, clientsCursor: null });
  assert.equal(calls[0].url, `${TM_BASE}/state?at=1800000599&router_id=${R1}`);
  assert.equal(calls[0].init.headers.Authorization, 'Bearer tok-secret');
  assert.equal(s.routers.length, 2);
  const c = await api.compare({ t1: 1, t2: 2, routerId: null });
  assert.equal(calls[1].url, `${TM_BASE}/compare?t1=1&t2=2`);
  assert.equal(c.routers.length, 2);
  // the token never goes into a URL
  assert.ok(calls.every(x => !x.url.includes('tok-secret')));
});

test('api: the export is a Blob of the server bytes; the cut and its cursor are read; refusals throw', async () => {
  const calls = [];
  const api = fakeHass(calls, [F.export_cut, F.export_refused, F.export_user]);
  const q = { from: 100, until: 200, sources: null, minSeverity: null, routerId: null, spans: true, cursor: null, client: 'tmc_0123456789abcdef' };
  const file = await api.exportFile(q);
  assert.equal(calls[0].url, `${TM_BASE}/export?from=100&until=200`);
  assert.equal(file.truncated, true);
  assert.equal(file.nextCursor, F.export_cut.body.next_cursor);
  assert.equal(file.marks, F.export_cut.body.marks.length);
  assert.equal(file.omittedClientMarks, F.export_cut.body.omitted_client_marks);
  assert.equal(file.blob.type, 'application/json');
  assert.deepEqual(JSON.parse(await file.blob.text()), F.export_cut.body);
  await assert.rejects(api.exportFile({ ...q, cursor: file.nextCursor }), e => {
    assert.equal(errorInfo(e, 'export').message, 'Export nicht möglich: Das Audit-Protokoll ist nicht verfügbar.');
    return true;
  });
  assert.ok(calls[1].url.endsWith(`&cursor=${encodeURIComponent(F.export_cut.body.next_cursor)}`));
  await assert.rejects(api.exportFile(q), e => e.status === 403);
});

// ── 1.52.0 review before the merge ───────────────────────────────────────

test('compare: other modules between the moments (other_sources) decide "nothing changed" too', () => {
  const quiet = C('compare_quiet');
  const known = { ...quiet, routers: quiet.routers.map(r => ({
    ...r, role: { ...r.role, state: 'same' }, uplink: { ...r.uplink, state: 'same' }, radios: [],
  })) };
  // the fixture's three real answers: read and empty, one audit entry, the audit log unreadable
  assert.deepEqual(C('compare').otherSources, { state: 'ok', reason: null, count: 0, truncated: false, unreadable: [] });
  const other = C('compare_other').otherSources;
  assert.deepEqual(other, { state: 'ok', reason: null, count: 1, truncated: false, unreadable: [] });
  const unreadable = C('compare_unreadable').otherSources;
  assert.deepEqual(unreadable, { state: 'unreadable', reason: 'unreadable', count: 0, truncated: false, unreadable: ['core_audit'] });
  assert.equal(compareSummary(known, true), NOTHING_CHANGED);
  assert.equal(otherSourcesText(known.otherSources), null);
  // an entry of another module: the states are the same, but something happened
  assert.equal(compareSummary({ ...known, otherSources: other }, true), SAME_BUT_EVENTS);
  assert.equal(otherSourcesText(other), 'Dazu 1 Eintrag aus anderen Modulen.');
  assert.equal(otherSourcesText({ ...other, count: 500, truncated: true }), 'Dazu mindestens 500 Einträge aus anderen Modulen.');
  assert.equal(otherSourcesText({ ...other, count: 3 }), 'Dazu 3 Einträge aus anderen Modulen.');
  // a source not read: unknown, never "nothing changed", with the source's name
  const why = `${OTHER_UNKNOWN_ONE} Nicht gelesen: Audit.`;
  assert.equal(compareSummary({ ...known, otherSources: unreadable }, true), why);
  assert.equal(otherSourcesText(unreadable), why);
  assert.equal(OTHER_UNKNOWN_ONE, 'Ob dazwischen etwas geschah, ist unbekannt: Eine Quelle ließ sich nicht lesen.');
  assert.equal(otherUnknownText({ ...unreadable, unreadable: ['core_audit', 'ni_incidents'] }), `${OTHER_UNKNOWN_MANY} Nicht gelesen: Audit, Vorfälle.`);
  // no other_sources at all (an older server) or "off": unknown as well
  assert.equal(parseCompare({ ...F.compare_quiet.body, changes: { ...F.compare_quiet.body.changes, other_sources: undefined } }).otherSources, null);
  assert.equal(compareSummary({ ...known, otherSources: null }, true), OTHER_UNKNOWN_NONE);
  assert.equal(compareSummary({ ...known, otherSources: { state: 'off', reason: null, count: 0, truncated: false, unreadable: [] } }, true), OTHER_UNKNOWN_NONE);
  // cut at 0 entries is not "nothing" either
  assert.notEqual(compareSummary({ ...known, otherSources: { ...known.otherSources, truncated: true } }, true), NOTHING_CHANGED);
  // a change stays a change, whatever the other modules say
  assert.match(compareSummary({ ...C('compare'), otherSources: unreadable }, true), /geändert\.$/);
});

test('radios of a router card: one reason, said once; not_observed in a sentence', () => {
  // the down router of the browser review: a partial block without items, the same reason twice
  const down = { state: 'partial', reason: 'router_down', derived: false, items: [] };
  assert.deepEqual(radiosView(down), { whole: true, reason: 'Router nicht erreichbar', note: 'unvollständig' });
  // items that already say it
  const items = [{ key: '5g0', band: '5g', channel: null, width: null, state: 'unknown', reason: 'router_down' }];
  assert.deepEqual(radiosView({ ...down, items }), { whole: false, reason: null, note: 'unvollständig' });
  // a different reason of the block is said
  assert.deepEqual(radiosView({ ...down, reason: 'inconsistent', items }), { whole: false, reason: null, note: 'unvollständig · Aufzeichnung widersprüchlich' });
  // the real unknown block of the fixture: one reason, no note
  assert.deepEqual(radiosView(S('state').routers[1].radios), { whole: true, reason: 'Router nicht erreichbar', note: null });
  // one radio stayed off across a restart
  const absent = { state: 'partial', reason: 'not_observed', derived: true, items: [{ key: '5g0', band: '5g', channel: 44, width: 80, state: 'up', reason: null }] };
  assert.deepEqual(radiosView(absent), { whole: false, reason: null, note: RADIOS_NOT_OBSERVED_TEXT });
  assert.equal(RADIOS_NOT_OBSERVED_TEXT, 'Nicht alle Funkmodule sind bekannt: Eines blieb über einen Neustart aus.');
});

test('a part the server could not read says so in a sentence', () => {
  assert.equal(PART_UNREADABLE_TEXT, 'Konnte nicht gelesen werden.');
  assert.equal(partStateText({ state: 'unreadable', reason: 'unreadable' }), PART_UNREADABLE_TEXT);
  assert.equal(partStateText({ state: 'unreadable', reason: null }), PART_UNREADABLE_TEXT);
  assert.equal(partStateText({ state: 'unreadable', reason: 'timeout' }), 'Konnte nicht gelesen werden: Zeitüberschreitung.');
  assert.equal(partStateText({ state: 'off', reason: 'module_off' }), 'aus · Modul aus');
});

test('clock_shift has its sentence and its short reason', () => {
  assert.equal(GLOBAL_REASON_TEXT.clock_shift, 'Die Uhr von Home Assistant ist zurückgesprungen; diese Zeit kommt im Verlauf doppelt vor.');
  assert.equal(globalReasonText('clock_shift'), GLOBAL_REASON_TEXT.clock_shift);
  assert.equal(stateReasonText('clock_shift'), 'Uhr zurückgesprungen, Zeit doppelt');
});

test('the first sighting of a new uplink or role: "zuerst gesehen HH:MM:SS"', () => {
  const since = Date.UTC(2027, 0, 15, 8, 4, 5) / 1000;
  assert.equal(paramsText({ since }), `zuerst gesehen ${timeText(since)}`);
  assert.equal(paramsText({ since }), 'zuerst gesehen 09:04:05');
  assert.equal(paramsText({ since, count: 2 }), '2-mal · zuerst gesehen 09:04:05');
});

test('local time on the clock changes of Europe/Berlin: the skipped hour is an error, the doubled one the first', () => {
  // spring 2027: 28 March, 02:00 → 03:00
  for (const v of ['2027-03-28T02:00', '2027-03-28T02:30:15', '2027-03-28T02:59:59']) {
    assert.deepEqual(parseLocalInput(v), { ts: null, error: LOCAL_GAP_TEXT, note: null }, v);
    assert.equal(fromLocalInput(v), null, v);
  }
  assert.equal(LOCAL_GAP_TEXT, 'Diese Uhrzeit gibt es wegen der Zeitumstellung nicht.');
  assert.equal(fromLocalInput('2027-03-28T01:59:59'), Date.UTC(2027, 2, 28, 0, 59, 59) / 1000);
  assert.equal(fromLocalInput('2027-03-28T03:00'), Date.UTC(2027, 2, 28, 1, 0, 0) / 1000);
  // autumn 2027: 31 October, 03:00 → 02:00; 02:30 comes twice, the first (summer time) is taken
  const twice = parseLocalInput('2027-10-31T02:30');
  assert.deepEqual(twice, { ts: Date.UTC(2027, 9, 31, 0, 30, 0) / 1000, error: null, note: LOCAL_TWICE_TEXT });
  assert.equal(LOCAL_TWICE_TEXT, 'Diese Uhrzeit gibt es wegen der Zeitumstellung zweimal; gezeigt wird die erste.');
  assert.equal(parseLocalInput('2027-10-31T02:00').ts, Date.UTC(2027, 9, 31, 0, 0, 0) / 1000);
  assert.equal(parseLocalInput('2027-10-31T02:59:59').note, LOCAL_TWICE_TEXT);
  // the hours around it are plain
  for (const v of ['2027-10-31T01:59:59', '2027-10-31T03:00', '2027-01-15T09:09:59']) assert.deepEqual(parseLocalInput(v).note, null, v);
  assert.equal(parseLocalInput('2027-10-31T03:00').ts, Date.UTC(2027, 9, 31, 2, 0, 0) / 1000);
  // nonsense stays nonsense, without a clock text
  for (const bad of ['2027-02-30T10:00', '2027-03-28T24:00', '2027-03-28T02:60', 'heute']) {
    assert.deepEqual(parseLocalInput(bad), { ts: null, error: null, note: null }, bad);
  }
});

test('"Jetzt": the moment loaded and the field always agree', () => {
  const now = F.state.body.at + 0.4;
  const live = stateLoadAt(true, '2027-01-14T08:00:00', now);
  assert.equal(live.at, Math.floor(now) - 1);
  assert.equal(live.input, toLocalInput(live.at));
  assert.notEqual(live.input, '2027-01-14T08:00:00');
  // a chosen time is kept as typed
  assert.deepEqual(stateLoadAt(false, '2027-01-14T08:00:00', now), { at: fromLocalInput('2027-01-14T08:00:00'), input: '2027-01-14T08:00:00' });
  assert.deepEqual(stateLoadAt(false, '2027-03-28T02:30', now), { at: null, input: '2027-03-28T02:30' });
});

test('export confirmation: Escape cancels, Tab goes round its buttons, focus on Abbrechen and back to the trigger', () => {
  assert.deepEqual(dialogKey('Escape', false, 0, 2), { action: 'cancel' });
  assert.deepEqual(dialogKey('Esc', true, -1, 2), { action: 'cancel' });
  assert.deepEqual(dialogKey('Tab', false, 0, 2), { action: 'focus', index: 1 });
  assert.deepEqual(dialogKey('Tab', false, 1, 2), { action: 'focus', index: 0 });
  assert.deepEqual(dialogKey('Tab', true, 0, 2), { action: 'focus', index: 1 });
  assert.deepEqual(dialogKey('Tab', true, 1, 2), { action: 'focus', index: 0 });
  // the focus somewhere else: Tab comes back in, at the first or (Shift) the last button
  assert.deepEqual(dialogKey('Tab', false, -1, 2), { action: 'focus', index: 0 });
  assert.deepEqual(dialogKey('Tab', true, -1, 2), { action: 'focus', index: 1 });
  // one button left (the other disabled): it stays
  assert.deepEqual(dialogKey('Tab', false, 0, 1), { action: 'focus', index: 0 });
  for (const k of ['Enter', ' ', 'a', 'ArrowDown']) assert.equal(dialogKey(k, false, 0, 2), null, k);
  assert.equal(dialogKey('Tab', false, -1, 0), null);
  assert.equal(dialogFocus(false, true), 'cancel');
  assert.equal(dialogFocus(true, false), 'trigger');
  assert.equal(dialogFocus(false, false), null);
  assert.equal(dialogFocus(true, true), null);
});

test('export: the client marks left out, counted over the whole window', () => {
  assert.equal(F.export_cut.body.omitted_client_marks, 4);
  assert.equal(exportOmittedText(4), '4 Client-Einträge sind nicht enthalten.');
  assert.equal(exportOmittedText(1), '1 Client-Eintrag ist nicht enthalten.');
  for (const n of [0, null, NaN, -1]) assert.equal(exportOmittedText(n), null);
});

test('client title: the full name and the pseudonym, else the pseudonym alone', () => {
  const id = 'tmc_0123456789abcdef';
  assert.equal(clientTitle(id, 'tablet-kueche'), 'tablet-kueche · tmc_0123456789abcdef');
  assert.equal(clientTitle(id, null), id);
  assert.equal(clientTitle(id), id);
  assert.equal(clientTitle(null, 'tablet-kueche'), 'tablet-kueche');
  assert.equal(clientTitle('aa:bb:cc:dd:ee:ff', null), null);
});
