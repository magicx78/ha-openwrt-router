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
  RADIOS_NOT_OBSERVED_TEXT, activeIn, dialogFocus, dialogKey, exportOmittedText, otherSourcesText, otherUnknownText, parseLocalInput,
  partStateText, radiosView, stateLoadAt,
} from './tmState.ts';
import { clientTitle, paramsText, timeText } from './tmLogic.ts';
// 1.52.1: a namespace import, so a missing export fails its own test only
import * as TS from './tmState.ts';

const here = dirname(fileURLToPath(import.meta.url));
const F = JSON.parse(readFileSync(join(here, 'tmFixtureState.json'), 'utf8'));
const S = name => parseState(F[name].body);
const C = name => parseCompare(F[name].body);
const err = name => new TmApiError(F[name].status, F[name].body.code, F[name].body.details ?? {});
const NOW_MS = F.state.body.generated_at * 1000;
const R1 = 'rtr_11111111111111111111111111111111';
const R2 = 'rtr_22222222222222222222222222222222';

/**
 * The quiet pair with every value known and the same at both moments: in
 * `changes` (state same) and, since 1.52.2 (the cells come from the
 * blocks), in the `before` and `after` blocks too.
 */
function knownQuiet() {
  const quiet = C('compare_quiet');
  const known = side => ({ ...side, routers: side.routers.map(r => ({
    ...r,
    role: { value: 'gateway', derived: true, reason: null, cause: null },
    uplink: { value: null, derived: true, reason: null, cause: null },
    radios: { state: 'ok', reason: null, derived: true, items: [{ key: '5g0', band: '5g', channel: 44, width: 80, state: 'up', reason: null }] },
  })) });
  return {
    ...quiet, before: known(quiet.before), after: known(quiet.after),
    routers: quiet.routers.map(r => ({ ...r, role: { ...r.role, state: 'same' }, uplink: { ...r.uplink, state: 'same' }, radios: [] })),
  };
}

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
  // 1.52.2: Router 2 is down at "Bis": its radio of "Von" stays known, "Bis" unknown with its own reason
  assert.deepEqual([x2['radio-5g0'].state, x2['radio-5g0'].before, x2['radio-5g0'].after, x2['radio-5g0'].afterReason, x2['radio-5g0'].beforeReason],
    ['unknown', 'Kanal 36 · 80 MHz · an', UNKNOWN, 'Router nicht erreichbar', null]);
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
  const known = knownQuiet();
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
  assert.equal(rows[0].beforeReason, 'nicht aufgezeichnet');
  assert.equal(rows[0].afterReason, null);
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
  const known = knownQuiet();
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

test('export confirmation in a Shadow DOM: the focused button is found in the shadow root, not the document', () => {
  const a = { name: 'Abbrechen' };
  const b = { name: 'Exportieren' };
  const host = { name: 'shadow host' };
  const shadow = { activeElement: b };
  const doc = { activeElement: host };
  const inShadow = { getRootNode: () => shadow };
  // document.activeElement is the shadow host: the old way found no button
  assert.equal([a, b].indexOf(doc.activeElement), -1);
  assert.equal(activeIn(inShadow, doc), b);
  assert.deepEqual(dialogKey('Tab', false, [a, b].indexOf(activeIn(inShadow, doc)), 2), { action: 'focus', index: 0 });
  assert.deepEqual(dialogKey('Tab', true, [a, b].indexOf(activeIn(inShadow, doc)), 2), { action: 'focus', index: 0 });
  shadow.activeElement = a;
  assert.deepEqual(dialogKey('Tab', false, [a, b].indexOf(activeIn(inShadow, doc)), 2), { action: 'focus', index: 1 });
  // nothing focused inside the shadow root
  shadow.activeElement = null;
  assert.equal(activeIn(inShadow, doc), null);
  // outside a Shadow DOM the root is the document itself
  const inDoc = { getRootNode: () => doc };
  assert.equal(activeIn(inDoc, doc), host);
  // no dialog yet, or a root without activeElement: the document's
  assert.equal(activeIn(null, doc), host);
  assert.equal(activeIn({ getRootNode: () => ({}) }, doc), host);
  assert.equal(activeIn(undefined, null), null);
});

// ── browser check before the merge: an export without a mark, focus after a click ──

import { EXPORT_EMPTY_MORE, EXPORT_EMPTY_TITLE, exportEmptyText, focusLost } from './tmState.ts';
import { EXPORT_UNAVAILABLE_TEXT } from './tmTexts.ts';

test('export without a mark: nothing to save, and why in words (real route answers)', async () => {
  const calls = [];
  const api = fakeHass(calls, [F.export_unavailable, F.export_empty, F.export_empty_partial, F.export_off, F.export, F.export_cut]);
  const q = { from: 100, until: 200, sources: null, minSeverity: null, routerId: null, spans: true, cursor: null, client: null };
  const unavailable = await api.exportFile(q);
  assert.deepEqual([unavailable.status, unavailable.reason, unavailable.marks, unavailable.spanning], ['unavailable', 'not_running', 0, 0]);
  assert.equal(EXPORT_EMPTY_TITLE, 'Nichts zu exportieren, es wurde keine Datei gespeichert.');
  assert.equal(exportEmptyText(unavailable), 'Nichts zu exportieren, es wurde keine Datei gespeichert. Die Zeitreise läuft gerade nicht.');
  const empty = await api.exportFile(q);
  assert.deepEqual([empty.status, empty.reason, empty.marks, empty.spanning], ['ok', null, 0, 0]);
  assert.equal(exportEmptyText(empty),
    'Nichts zu exportieren, es wurde keine Datei gespeichert. Im gewählten Zeitfenster gibt es mit den gewählten Filtern keine exportierbaren Marken.');
  const partial = await api.exportFile(q);
  assert.equal(partial.status, 'partial');
  assert.equal(exportEmptyText(partial),
    'Nichts zu exportieren, es wurde keine Datei gespeichert. Im gewählten Zeitfenster gibt es mit den gewählten Filtern keine exportierbaren Marken. '
    + 'Mindestens eine Quelle ließ sich nicht lesen.');
  const off = await api.exportFile(q);
  assert.equal(exportEmptyText(off), 'Nichts zu exportieren, es wurde keine Datei gespeichert. Die Zeitreise ist ausgeschaltet.');
  // an answer with marks is saved as before
  const data = await api.exportFile(q);
  assert.ok(data.marks > 0);
  assert.equal(exportEmptyText(data), null);
  assert.equal(exportEmptyText(await api.exportFile(q)), null);
  const file = (o = {}) => ({ status: 'ok', reason: null, marks: 0, spanning: 0, omittedClientMarks: 0, ...o });
  // only running intervals in the window: the file holds them, it is saved
  assert.equal(exportEmptyText(file({ spanning: 2 })), null);
  // only client marks: they are never exported, so nothing is saved, and the count says why
  assert.equal(exportEmptyText(file({ omittedClientMarks: 4 })),
    'Nichts zu exportieren, es wurde keine Datei gespeichert. Im gewählten Zeitfenster gibt es mit den gewählten Filtern keine exportierbaren Marken. '
    + '4 Client-Einträge werden nie exportiert.');
  assert.ok(exportEmptyText(file({ omittedClientMarks: 1 })).endsWith(' 1 Client-Eintrag wird nie exportiert.'));
  // the other reason of the route, and one it may send later
  assert.equal(exportEmptyText(file({ status: 'unavailable', reason: 'not_loaded' })),
    'Nichts zu exportieren, es wurde keine Datei gespeichert. Der gespeicherte Verlauf wird noch geladen; bitte gleich noch einmal versuchen.');
  assert.equal(exportEmptyText(file({ status: 'unavailable', reason: 'something_new' })),
    'Nichts zu exportieren, es wurde keine Datei gespeichert. Die Zeitreise ist gerade nicht verfügbar.');
  assert.equal(exportEmptyText(file({ status: 'unknown_status' })), EXPORT_EMPTY_TITLE);
  // a later page without a mark: no further file
  assert.equal(EXPORT_EMPTY_MORE, 'Keine weiteren Marken, es wurde keine weitere Datei gespeichert.');
  assert.equal(exportEmptyText(file(), 2), EXPORT_EMPTY_MORE);
  assert.equal(exportEmptyText(file({ status: 'unavailable', reason: 'not_running' }), 3), `${EXPORT_EMPTY_MORE} Die Zeitreise läuft gerade nicht.`);
  assert.deepEqual(Object.keys(EXPORT_UNAVAILABLE_TEXT).sort(), ['not_loaded', 'not_running']);
  assert.ok(calls.every(x => x.url.startsWith(`${TM_BASE}/export?`)));
});

test('export confirmation: a focus fallen to <body> (a tap on the text) is lost; a real focus elsewhere is not', () => {
  const body = { n: 'body' };
  const host = { n: 'shadow host' };
  const button = { n: 'Abbrechen' };
  const other = { n: 'a chip of the filters' };
  // in the panel's shadow root nothing is focused and the document's focus is on <body>
  assert.equal(focusLost(null, body, body), true);
  // without a Shadow DOM the dialog's root is the document: activeIn gives <body>
  assert.equal(focusLost(body, body, body), true);
  assert.equal(focusLost(null, null, body), true);
  // a button, the focus in another tree (the HA sidebar: the document's is its host) or another control: not lost
  assert.equal(focusLost(button, host, body), false);
  assert.equal(focusLost(null, host, body), false);
  assert.equal(focusLost(other, other, body), false);
  // a lost focus goes by the dialog's rule: Tab to the first button, Shift+Tab to the last, Escape cancels
  assert.deepEqual(dialogKey('Tab', false, -1, 2), { action: 'focus', index: 0 });
  assert.deepEqual(dialogKey('Tab', true, -1, 2), { action: 'focus', index: 1 });
  assert.deepEqual(dialogKey('Escape', false, -1, 2), { action: 'cancel' });
});

// ── 1.52.1: the views load when they open, the hint only for an empty field ──

test('opening a view loads at once; typing waits a short pause; a hidden page loads when it is shown', () => {
  // the first load of an opened view does not wait for a typing pause (browser review 1.52.0:
  // until then the view showed "Einen Zeitpunkt wählen." under prefilled fields)
  assert.equal(TS.loadDelay(true, true), 0);
  assert.equal(TS.loadDelay(false, true), TS.TM_DEBOUNCE_MS);
  assert.equal(TS.TM_DEBOUNCE_MS, 400);
  // a hidden page loads nothing now; the load is due and runs when the page is shown
  assert.equal(TS.loadDelay(true, false), null);
  assert.equal(TS.loadDelay(false, false), null);
});

test('before the first answer: the hint only for a really empty field, else "lädt" or the field error', () => {
  const now = toLocalInput(F.state.body.at);
  // prefilled fields (now; the last 24 hours): a load is due, never the hint
  assert.equal(TS.waitingBody([now], false), 'loading');
  assert.equal(TS.waitingBody([toLocalInput(F.state.body.at - 86_400), now], false), 'loading');
  assert.equal(TS.waitingBody([now], true), 'loading');
  // a field the browser reports empty (cleared, or not a complete date): the hint
  assert.equal(TS.waitingBody([''], false), 'pick');
  assert.equal(TS.waitingBody(['  '], false), 'pick');
  assert.equal(TS.waitingBody(['', now], false), 'pick');
  assert.equal(TS.waitingBody([now, ''], false), 'pick');
  assert.equal(TS.waitingBody(['2027-02-30T10:00'], false), 'pick');
  // a time the clock skips: the field shows its own error, the body nothing more
  assert.equal(TS.waitingBody(['2027-03-28T02:30'], false), 'none');
  assert.equal(TS.waitingBody([now, '2027-03-28T02:30'], false), 'none');
  // an empty field wins over a skipped time in the other one: something is still to be chosen
  assert.equal(TS.waitingBody(['', '2027-03-28T02:30'], false), 'pick');
  // a load already running shows "lädt" even with a field just cleared (its answer still comes)
  assert.equal(TS.waitingBody([''], true), 'loading');
});

// ── 1.52.2: each cell of "Vergleich" is its side's value, a disabled router, an emptied field ──

// answers of one world after the update from 1.51.0 (tests/test_tm_compare_display_v1522.py):
// three routers, Router 3 disabled (never set up), Router 2 behind Router 1
const FX = JSON.parse(readFileSync(join(here, 'tmFixtureCompare.json'), 'utf8'));
const R3 = 'rtr_33333333333333333333333333333333';
const NOT_OBSERVED = 'noch kein Wert beobachtet';
const rowsBy = (a, id) => Object.fromEntries(compareRows(a.routers.find(r => r.routerId === id), a, true).map(r => [r.key, r]));
const routerOf = (s, id) => s.routers.find(r => r.routerId === id);

test('1.52.2 compare: before unknown, after known: "Nachher" is the value of "Zustand", the reason only in "Vorher"', () => {
  const a = parseCompare(FX.compare_after_update);
  const st = parseState(FX.state_after_update);
  assert.ok(a.before.known && a.after.known);
  for (const [id, uplinkText, role] of [[R1, 'kein vorgeschalteter Router', 'Gateway'], [R2, 'über Router 1', 'Mesh-Knoten']]) {
    const x = rowsBy(a, id);
    const s = routerOf(st, id);
    // the same moment: "Nachher" says what "Zustand" says
    assert.equal(x.uplink.after, uplinkView(s.uplink).text);
    assert.equal(x.uplink.after, uplinkText);
    assert.equal(x.reachable.after, reachableView(s.reachable).text);
    assert.equal(x.role.after, role);
    assert.equal(x['radio-5g0'].after, 'Kanal 36 · 80 MHz · an');
    assert.equal(x['radio-5g0'].label, 'Funk 5 GHz');
    assert.ok(!('radios' in x), 'no "Funk unbekannt" row when one side is known');
    for (const row of Object.values(x)) {
      // "Vorher" unknown with its own reason; "Nachher" known, without a reason
      assert.deepEqual([row.before, row.beforeReason], [UNKNOWN, NOT_OBSERVED], `${id} ${row.key}`);
      assert.equal(row.afterReason, null, `${id} ${row.key}`);
      assert.notEqual(row.after, UNKNOWN, `${id} ${row.key}`);
      // a row with an unknown side is unknown, never a change
      assert.equal(row.state, 'unknown', `${id} ${row.key}`);
    }
  }
  // the summary counts the rows the tables show: 4 per router, the disabled one not listed
  assert.deepEqual(TS.compareRouters(a).shown.map(r => r.routerId), [R1, R2]);
  assert.equal(compareSummary(a, true), 'Keine bekannte Änderung; 8 Merkmale sind zu einem der Zeitpunkte unbekannt.');
  const unknownRows = TS.compareRouters(a).shown.flatMap(r => compareRows(r, a, true)).filter(r => r.state === 'unknown').length;
  assert.equal(unknownRows, 8);
});

test('1.52.2 compare: the mirror (before known, after unknown) and a side unknown as a whole', () => {
  const a = parseCompare(FX.compare_router_down);
  const x = rowsBy(a, R2);
  assert.deepEqual([x.reachable.before, x.reachable.after, x.reachable.state], ['erreichbar', 'nicht erreichbar', 'changed']);
  assert.deepEqual([x.uplink.before, x.uplink.beforeReason, x.uplink.after, x.uplink.afterReason, x.uplink.state],
    ['über Router 1', null, UNKNOWN, 'Router nicht erreichbar', 'unknown']);
  assert.deepEqual([x.role.before, x.role.afterReason], ['Mesh-Knoten', 'Router nicht erreichbar']);
  assert.deepEqual([x['radio-5g0'].before, x['radio-5g0'].after, x['radio-5g0'].afterReason, x['radio-5g0'].beforeReason],
    ['Kanal 36 · 80 MHz · an', UNKNOWN, 'Router nicht erreichbar', null]);
  assert.equal(compareSummary(a, true), '1 Merkmal hat sich geändert.');
  // "Von" unknown as a whole (known: false): the known "Bis" values stay, the reason only in "Vorher"
  const one = C('compare_one_unknown');
  const y = Object.fromEntries(compareRows(one.routers[0], one, true).map(r => [r.key, r]));
  assert.deepEqual([y.reachable.before, y.reachable.beforeReason, y.reachable.after, y.reachable.afterReason],
    [UNKNOWN, 'nicht aufgezeichnet', 'erreichbar', null]);
  assert.deepEqual([y['radio-5g0'].before, y['radio-5g0'].beforeReason, y['radio-5g0'].after],
    [UNKNOWN, 'nicht aufgezeichnet', 'Kanal 44 · 80 MHz · an']);
  // both sides unknown: one "Funk" row, each side with its own reason
  assert.deepEqual([y.role.beforeReason, y.role.afterReason], ['nicht aufgezeichnet', NOT_OBSERVED]);
  const z = Object.fromEntries(compareRows(one.routers[1], one, true).map(r => [r.key, r]));
  assert.deepEqual([z.radios.before, z.radios.beforeReason, z.radios.after, z.radios.afterReason],
    [UNKNOWN, 'nicht aufgezeichnet', UNKNOWN, 'Router nicht erreichbar']);
});

test('1.52.2: a disabled router says so; unknown on both sides it is no difference and not counted', () => {
  // "Zustand": disabled and nothing known: one line; known values of the moment stay
  const st = parseState(FX.state_disabled);
  assert.deepEqual(st.routers.map(r => [r.routerId, r.entry]), [[R1, 'enabled'], [R2, 'disabled'], [R3, 'disabled']]);
  assert.deepEqual(st.routers.map(TS.disabledView), [null, 'only', 'only']);
  const earlier = parseCompare(FX.compare_disabled);
  assert.equal(TS.disabledView(routerOf(earlier.before, R2)), 'now');
  // "Vergleich", both sides after the disable: nothing listed, nothing counted, one line
  const both = parseCompare(FX.compare_disabled_both);
  assert.deepEqual(TS.compareRouters(both), { shown: [], disabled: 2 });
  assert.doesNotMatch(compareSummary(both, true), /Merkmal/);
  assert.equal(TS.disabledText(2), '2 Router sind deaktiviert und nicht aufgeführt; zu beiden Zeitpunkten ist von ihnen nichts bekannt.');
  assert.equal(TS.disabledText(1), '1 Router ist deaktiviert und nicht aufgeführt; zu beiden Zeitpunkten ist von ihm nichts bekannt.');
  assert.equal(TS.disabledText(0), null);
  // known history at one moment: listed as usual (marked as disabled now), Router 3 not
  const c = TS.compareRouters(earlier);
  assert.deepEqual([c.shown.map(r => r.routerId), c.disabled], [[R2], 1]);
  const x = rowsBy(earlier, R2);
  assert.deepEqual([x.uplink.before, x.uplink.after, x.uplink.afterReason], ['über Router 1', UNKNOWN, NOT_OBSERVED]);
  assert.equal(compareSummary(earlier, true), 'Keine bekannte Änderung; 4 Merkmale sind zu einem der Zeitpunkte unbekannt.');
  // an answer without the field (1.52.1 and older): nobody is disabled, nothing hidden
  const older = JSON.parse(JSON.stringify(F.state.body));
  for (const r of older.routers) delete r.entry;
  const olderState = parseState(older);
  assert.ok(olderState.routers.length > 0);
  assert.ok(olderState.routers.every(r => r.entry === null && TS.disabledView(r) === null));
  // the regenerated fixture of 1.52.2 names the entry of every router
  assert.ok(S('state').routers.every(r => r.entry === 'enabled' && TS.disabledView(r) === null));
  assert.equal(TS.compareRouters(C('compare_quiet')).shown.length, C('compare_quiet').routers.length);
  assert.equal(TS.compareRouters(C('compare_quiet')).disabled, 0);
  // and an older panel's fields of the new answer are the old ones (the field is additive)
  const old = parseState(FX.state_after_update);
  assert.deepEqual(Object.keys(old.routers[0]).filter(k => k !== 'entry').sort(),
    ['radios', 'reachable', 'role', 'routerId', 'routerName', 'traffic', 'uplink', 'utilization']);
});

test('1.52.2: an emptied field clears the result; a late answer after it is dropped', () => {
  let c = compareReducer(COMPARE_INIT, { type: 'start', seq: 1 });
  c = compareReducer(c, { type: 'done', seq: 1, answer: C('compare') });
  assert.ok(c.answer);
  c = compareReducer(c, { type: 'start', seq: 2 });
  c = compareReducer(c, { type: 'clear', seq: 3 });
  assert.deepEqual(c, { ...COMPARE_INIT, seq: 3 });
  // the answer of the load before the field was emptied comes late: dropped
  assert.equal(compareReducer(c, { type: 'done', seq: 2, answer: C('compare_quiet') }), c);
  assert.equal(compareReducer(c, { type: 'fail', seq: 2, error: new Error('x') }), c);
  let s = stateReducer(STATE_INIT, { type: 'start', seq: 1 });
  s = stateReducer(s, { type: 'done', seq: 1, answer: S('state_clients_page1'), query: { at: 1, routerId: null, clientsCursor: null } });
  s = stateReducer(s, { type: 'moreStart', seq: 2 });
  s = stateReducer(s, { type: 'clear', seq: 3 });
  assert.equal(s.answer, null);
  assert.deepEqual([s.clients, s.clientsCursor, s.loading, s.loadingMore, s.error, s.seq], [[], null, false, false, null, 3]);
  assert.equal(stateReducer(s, { type: 'done', seq: 1, answer: S('state'), query: { at: 1, routerId: null, clientsCursor: null } }), s);
  assert.equal(stateReducer(s, { type: 'moreDone', seq: 2, answer: S('state_clients_page2') }), s);
  assert.equal(moreClientsQuery(s, true), null);
});

// ── 1.52.2 review: hidden routers in the summary, "deaktiviert" only for not_observed,
//    the reachability row, radio reasons, the load step ──

import * as TT from './tmTexts.ts';

const clone = v => JSON.parse(JSON.stringify(v));
const OTHER_OK = { state: 'ok', reason: null, count: 0, truncated: false, unreadable: [] };
/** compare_disabled_both with the other modules read and empty: only the two disabled routers differ. */
function quietDisabledBoth() {
  const a = clone(FX.compare_disabled_both);
  a.changes.other_sources = { ...OTHER_OK };
  return a;
}
const rawRouter = (side, id) => side.routers.find(r => r.router_id === id);

test('1.52.2 review: hidden disabled routers: the summary never says "nothing changed" about them', () => {
  const a = parseCompare(quietDisabledBoth());
  assert.deepEqual(TS.compareRouters(a), { shown: [], disabled: 2 });
  const s = compareSummary(a, true);
  assert.notEqual(s, NOTHING_CHANGED);
  assert.equal(s, 'Über 2 deaktivierte Router ist nichts bekannt; sonst hat sich zwischen diesen Zeitpunkten nichts geändert.');
  // with events in between: never "Die Zustände zu beiden Zeitpunkten sind gleich" alone
  const ev = quietDisabledBoth();
  ev.changes.marks = { count: 1, by_group: { infrastructure: 1 } };
  const e = compareSummary(parseCompare(ev), true);
  assert.notEqual(e, SAME_BUT_EVENTS);
  assert.equal(e, 'Über 2 deaktivierte Router ist nichts bekannt; sonst sind die Zustände zu beiden Zeitpunkten gleich, und dazwischen gab es Ereignisse.');
  assert.equal(TS.disabledSummaryText(1, false),
    'Über 1 deaktivierten Router ist nichts bekannt; sonst hat sich zwischen diesen Zeitpunkten nichts geändert.');
  assert.equal(TS.disabledSummaryText(0, false), null);
  // the routers stay unlisted and uncounted; a summary with something unknown or changed is unchanged
  assert.doesNotMatch(s, /Merkmal/);
  assert.equal(compareSummary(parseCompare(FX.compare_after_update), true), 'Keine bekannte Änderung; 8 Merkmale sind zu einem der Zeitpunkte unbekannt.');
  // without hidden routers the sentences of 1.52.1 stay
  const known = knownQuiet();
  assert.equal(compareSummary({ ...known, otherSources: { state: 'ok', reason: null, count: 0, truncated: false, unreadable: [] } }, true), NOTHING_CHANGED);
});

test('1.52.2 review: "deaktiviert" only when every unknown reason is not_observed; else the real reasons', () => {
  for (const [part, reason, words] of [['reachable', 'evicted', 'Aufzeichnung verdrängt'], ['uplink', 'observation_gap', 'nicht beobachtet'], ['radios', 'clock_shift', null]]) {
    const raw = clone(FX.state_disabled);
    rawRouter(raw, R2)[part].reason = reason;
    const st = parseState(raw);
    assert.equal(TS.disabledView(routerOf(st, R2)), 'now', `${part} ${reason}`);
    assert.equal(TS.disabledView(routerOf(st, R3)), 'only');
    if (words) assert.equal((part === 'reachable' ? reachableView : uplinkView)(routerOf(st, R2)[part]).reason, words);
  }
  // a radio of the list with another reason
  const raw = clone(FX.state_disabled);
  Object.assign(rawRouter(raw, R2).radios, { state: 'partial', reason: 'not_observed', items: [{ key: '5g0', band: '5g', channel: null, width: null, state: 'unknown', reason: 'evicted' }] });
  assert.equal(TS.disabledView(routerOf(parseState(raw), R2)), 'now');
  // "Vergleich": another reason at either moment: listed as usual, with its reasons
  for (const side of ['before', 'after']) {
    const a = quietDisabledBoth();
    rawRouter(a[side], R2).reachable.reason = 'observation_gap';
    const p = parseCompare(a);
    const c = TS.compareRouters(p);
    assert.deepEqual([c.shown.map(r => r.routerId), c.disabled], [[R2], 1], side);
    assert.ok(TS.disabledNow(c.shown[0], p));
    const x = rowsBy(p, R2);
    assert.equal(x.reachable[side === 'before' ? 'beforeReason' : 'afterReason'], 'nicht beobachtet', side);
    assert.equal(compareSummary(p, true), 'Keine bekannte Änderung; 4 Merkmale sind zu einem der Zeitpunkte unbekannt.');
  }
});

test('1.52.2 review: a reachability row whose cells say different things is a change', () => {
  const k = knownQuiet();
  const id = k.routers[0].routerId;
  const reach = (side, cause) => ({ ...side, routers: side.routers.map(r => (r.routerId === id
    ? { ...r, reachable: { value: false, derived: false, reason: null, cause } } : r)) });
  const a = { ...k, before: reach(k.before, 'lan_down'), after: reach(k.after, null),
    routers: k.routers.map(r => ({ ...r, reachable: { from: false, to: false, state: 'same', fromReason: null, toReason: null } })) };
  const x = Object.fromEntries(compareRows(a.routers[0], a, true).map(r => [r.key, r]));
  assert.deepEqual([x.reachable.before, x.reachable.after, x.reachable.state], ['nicht erreichbar (LAN)', 'nicht erreichbar', 'changed']);
  assert.equal(compareSummary({ ...a, otherSources: { ...OTHER_OK } }, true), '1 Merkmal hat sich geändert.');
  // the same words on both sides: the server's "same" stays
  const b = { ...a, after: reach(k.after, 'lan_down') };
  const y = Object.fromEntries(compareRows(b.routers[0], b, true).map(r => [r.key, r]));
  assert.deepEqual([y.reachable.before, y.reachable.after, y.reachable.state], ['nicht erreichbar (LAN)', 'nicht erreichbar (LAN)', 'same']);
});

test('1.52.2 review: every unknown radio cell has its reason (a partial list without items, a radio not seen)', () => {
  const k = knownQuiet();
  const radios = (side, value) => ({ ...side, routers: side.routers.map(r => ({ ...r, radios: value })) });
  const NOT_OBS = { state: 'partial', reason: 'not_observed', derived: false, items: [] };
  // one side partial / not_observed without items: "unbekannt" with the sentence, never without a reason
  const a = { ...k, after: radios(k.after, NOT_OBS) };
  const x = Object.fromEntries(compareRows(a.routers[0], a, true).map(r => [r.key, r]));
  assert.deepEqual([x['radio-5g0'].after, x['radio-5g0'].afterReason], [UNKNOWN, RADIOS_NOT_OBSERVED_TEXT]);
  const both = { ...k, before: radios(k.before, NOT_OBS), after: radios(k.after, NOT_OBS) };
  const y = Object.fromEntries(compareRows(both.routers[0], both, true).map(r => [r.key, r]));
  assert.deepEqual([y.radios.beforeReason, y.radios.afterReason], [RADIOS_NOT_OBSERVED_TEXT, RADIOS_NOT_OBSERVED_TEXT]);
  // a radio the other side's complete list does not have: "zu diesem Zeitpunkt nicht gesehen"
  const two = { state: 'ok', reason: null, derived: true, items: [{ key: '2g0', band: '2g', channel: 1, width: 20, state: 'up', reason: null }] };
  const c = { ...k, after: radios(k.after, two) };
  const z = Object.fromEntries(compareRows(c.routers[0], c, true).map(r => [r.key, r]));
  assert.equal(TT.RADIO_NOT_SEEN, 'zu diesem Zeitpunkt nicht gesehen');
  assert.deepEqual([z['radio-5g0'].before, z['radio-5g0'].after, z['radio-5g0'].afterReason], ['Kanal 44 · 80 MHz · an', UNKNOWN, TT.RADIO_NOT_SEEN]);
  assert.deepEqual([z['radio-2g0'].before, z['radio-2g0'].beforeReason, z['radio-2g0'].after], [UNKNOWN, TT.RADIO_NOT_SEEN, 'Kanal 1 · 20 MHz · an']);
  // an incomplete list says its own reason instead
  const cut = { ...two, state: 'partial', reason: 'evicted' };
  const d = { ...k, after: radios(k.after, cut) };
  const w = Object.fromEntries(compareRows(d.routers[0], d, true).map(r => [r.key, r]));
  assert.equal(w['radio-5g0'].afterReason, 'Aufzeichnung verdrängt');
});

test('1.52.2 review: the load step: a field without a moment clears; else it starts with the query', () => {
  const t = '2027-01-14T08:00';
  const u = '2027-01-14T09:00';
  for (const [from, until] of [['', u], [t, ''], ['2027-03-28T02:30', u], [t, '2027-03-28T02:30']]) {
    assert.deepEqual(TS.compareLoadStep(from, until, R1, 4), { action: { type: 'clear', seq: 4 }, query: null }, `${from} ${until}`);
  }
  assert.deepEqual(TS.compareLoadStep(t, u, R1, 5),
    { action: { type: 'start', seq: 5 }, query: { t1: fromLocalInput(t), t2: fromLocalInput(u), routerId: R1 } });
  const now = 1800000000.7;
  for (const input of ['', '2027-03-28T02:30']) {
    assert.deepEqual(TS.stateLoadStep(false, input, R1, now, 7), { action: { type: 'clear', seq: 7 }, query: null, input });
  }
  assert.deepEqual(TS.stateLoadStep(false, t, R1, now, 8),
    { action: { type: 'start', seq: 8 }, query: { at: fromLocalInput(t), routerId: R1, clientsCursor: null }, input: t });
  const live = TS.stateLoadStep(true, '', null, now, 9);
  assert.deepEqual(live, { action: { type: 'start', seq: 9 }, query: { at: 1799999999, routerId: null, clientsCursor: null }, input: toLocalInput(1799999999) });
  // each container dispatches the step's action, the clear one included (no DOM here: pinned in the source)
  // right after the step, unconditionally, before anything returns
  const src = readFileSync(join(here, 'TimeMachineState.tsx'), 'utf8');
  assert.equal(src.split('dispatch(step.action)').length - 1, 2);
  for (const fn of ['stateLoadStep', 'compareLoadStep']) {
    assert.match(src, new RegExp(`\\n( +)const step = ${fn}\\([^\\n]*\\);\\n\\1dispatch\\(step\\.action\\);\\n`), fn);
  }
  // and the cleared state is the reducer's clear
  assert.deepEqual(compareReducer({ ...COMPARE_INIT, answer: C('compare'), seq: 3 }, TS.compareLoadStep('', u, null, 4).action), { ...COMPARE_INIT, seq: 4 });
});

test('1.52.2 review: an answer without a router\'s block: the fallback cell says the server\'s reason of its side', () => {
  const raw = clone(FX.compare_after_update);
  raw.before.routers = [];
  const a = parseCompare(raw);
  assert.equal(a.routers[0].reachable.fromReason, 'not_observed');
  const x = rowsBy(a, R2);
  assert.deepEqual([x.reachable.before, x.reachable.beforeReason], [UNKNOWN, NOT_OBSERVED]);
  assert.deepEqual([x.uplink.before, x.uplink.beforeReason, x.uplink.after], [UNKNOWN, NOT_OBSERVED, 'über Router 1']);
  // an answer without the fields (1.52.1): the side's reason as before
  const old = clone(raw);
  for (const r of old.changes.routers) for (const k of ['reachable', 'role', 'uplink']) { delete r[k].from_reason; delete r[k].to_reason; }
  const o = parseCompare(old);
  assert.equal(o.routers[0].reachable.fromReason, null);
  assert.equal(rowsBy(o, R2).reachable.beforeReason, null);
});
