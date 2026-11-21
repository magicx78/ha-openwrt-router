// Tests of the 1.51.0 logic of the "Zeitreise" tab (node:test, no
// dependencies): intervals and the block of marks that began before the
// window, client labels, roaming text, the restart notice, and the client
// sessions (parser, queries, reducer, polling). The sample answers come from
// tmFixtureClients.json, written from the real routes by
// tests/test_tm_panel_fixture_v1510.py (invented values only).
process.env.TZ = 'Europe/Berlin';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_SESSION_FILTERS, LIST_INIT, SESSION_LIST_INIT, bandText, clientLabel, clientOptions, detailText, exactDuration,
  firstSessionQuery, intervalText, listReducer, olderSessionQuery, parseSessions, parseTimeline, peersText, reachesInto,
  rememberClients, roamText, sessionDays, sessionDurationText, sessionFilterKey, sessionQueryString, sessionReducer,
  shouldPollSessions, splitSpans, startText, titleOf, unavailableText,
} from './tmLogic.ts';

const here = dirname(fileURLToPath(import.meta.url));
const FC = JSON.parse(readFileSync(join(here, 'tmFixtureClients.json'), 'utf8'));
const T = name => parseTimeline(FC[name].body);
const S = name => parseSessions(FC[name].body);
const NOW_MS = FC.timeline.body.generated_at * 1000;
const M1 = 'tmc_f3e24c9bafa1ce4d';
const M2 = 'tmc_11154ea545af3e29';

test('exact durations: seconds, minutes, hours, days', () => {
  assert.equal(exactDuration(12), '12 s');
  assert.equal(exactDuration(252), '4 min 12 s');
  assert.equal(exactDuration(300), '5 min');
  assert.equal(exactDuration(7500), '2 Std. 5 min');
  assert.equal(exactDuration(3 * 86_400 + 4 * 3600 + 59), '3 Tage 4 Std.');
  assert.equal(exactDuration(86_400), '1 Tag');
  assert.equal(exactDuration(-1), '—');
});

test('intervals: closed with its duration, open since its start, unknown end', () => {
  const at = Date.UTC(2026, 10, 21, 13, 3, 0) / 1000; // 14:03 in Berlin
  const now = Date.UTC(2026, 10, 21, 15, 0, 0);
  assert.equal(intervalText({ ts: at, end: at + 252, endState: 'closed' }, now), 'Dauer 4 min 12 s');
  assert.equal(intervalText({ ts: at, end: null, endState: 'open' }, now), 'seit 14:03, noch offen');
  assert.equal(intervalText({ ts: at - 86_400, end: null, endState: 'open' }, now), 'seit 20.11., 14:03, noch offen');
  assert.equal(intervalText({ ts: at, end: null, endState: 'unknown' }, now), 'Ende unbekannt');
  assert.equal(intervalText({ ts: at, end: null, endState: null }, now), null);
  assert.equal(startText(at), '21.11.2026, 14:03');
});

test('reaching into the window: open, or ended at or after its start', () => {
  assert.ok(reachesInto({ ts: 5, end: null, endState: 'open' }, 10));
  assert.ok(reachesInto({ ts: 5, end: 10, endState: 'closed' }, 10));
  assert.ok(!reachesInto({ ts: 5, end: 9, endState: 'closed' }, 10));
  assert.ok(!reachesInto({ ts: 5, end: null, endState: 'unknown' }, 10));
  assert.ok(!reachesInto({ ts: 10, end: null, endState: 'open' }, 10));
  assert.ok(!reachesInto({ ts: 5, end: null, endState: null }, 10));
});

test('the block of marks before the window: spans_in from the server, each mark once', () => {
  const t = T('timeline');
  const { spans, rest } = splitSpans(t.marks, t.from);
  assert.deepEqual(spans.map(m => m.kind), ['router_down', 'client_session']);
  assert.ok(spans.every(m => m.spansIn && m.endState === 'open' && m.ts < t.from));
  assert.equal(spans.length + rest.length, t.marks.length);
  assert.ok(rest.every(m => m.ts >= t.from));
  // the first page of a paged answer has none yet (they come on the last page)
  const p1 = T('timeline_page1');
  assert.equal(splitSpans(p1.marks, p1.from).spans.length, 0);
});

test('client label: the server name, else the pseudonym\'s last six characters, never more', () => {
  assert.equal(clientLabel(M1, null), 'Client ·a1ce4d');
  assert.equal(clientLabel(M2, 'tablet-kueche'), 'Client tablet-kueche');
  assert.equal(clientLabel(null, null), 'Client unbekannt');
  assert.equal(clientLabel('aa:bb:cc:dd:ee:ff', null), 'Client unbekannt');
  // a name that looks like a MAC is scrubbed, not shown
  assert.ok(!/(?:[0-9a-f]{2}:){5}/i.test(clientLabel(M1, 'aa:bb:cc:dd:ee:ff')));
});

test('roaming: "von Router 1 nach Router 2" from the peers, and the detail line', () => {
  const roam = T('timeline').marks.find(m => m.kind === 'client_roam');
  assert.equal(titleOf(roam), 'Gewechselt');
  assert.equal(peersText(roam), 'von Router 1 nach Router 2');
  assert.equal(detailText(roam, NOW_MS), 'Client ·a1ce4d · von Router 1 nach Router 2');
  assert.equal(peersText({ peers: { before: null, after: { routerId: null, routerName: 'Router 9' } } }), 'nach Router 9');
  assert.equal(peersText({ peers: null }), null);
  const session = T('timeline').marks.find(m => m.kind === 'client_session' && m.params.roam);
  assert.equal(detailText(session, NOW_MS), 'Client ·a1ce4d · Dauer 1 min · 5 GHz · 1 Wechsel');
});

test('a refresh that does not reach the loaded older pages restarts the list and says so until dismissed', () => {
  const page = (ids, ts0, nextUntil, until) => ({
    ...T('timeline'), until, nextUntil, truncated: nextUntil !== null,
    marks: ids.map((id, i) => ({ ...T('timeline').marks[0], id, ts: ts0 - i, spansIn: false, endState: null })),
  });
  let s = listReducer(LIST_INIT, { type: 'start', seq: 1, more: false });
  s = listReducer(s, { type: 'first', gen: 0, seq: 1, answer: page(['a', 'b'], 1800001000, 1800000999, 1800001001) });
  assert.equal(s.restarted, false);
  s = listReducer(listReducer(s, { type: 'start', seq: 2, more: true }), { type: 'older', gen: 0, seq: 2, answer: page(['c'], 1800000999, null, 1800001001) });
  s = listReducer(s, { type: 'start', seq: 3, more: false });
  s = listReducer(s, { type: 'first', gen: 0, seq: 3, answer: page(['x', 'y'], 1800002000, 1800001999, 1800002001) });
  assert.deepEqual(s.marks.map(m => m.id), ['x', 'y']);
  assert.equal(s.restarted, true);
  // a later refresh that joins keeps the notice; dismiss takes it away
  s = listReducer(listReducer(s, { type: 'start', seq: 4, more: false }), { type: 'first', gen: 0, seq: 4, answer: page(['x', 'y'], 1800002000, 1800001999, 1800002001) });
  assert.equal(s.restarted, true);
  s = listReducer(s, { type: 'dismiss' });
  assert.equal(s.restarted, false);
  assert.equal(listReducer(s, { type: 'dismiss' }), s);
  // a single page that is replaced is no restart (nothing older was loaded)
  let one = listReducer(LIST_INIT, { type: 'start', seq: 1, more: false });
  one = listReducer(one, { type: 'first', gen: 0, seq: 1, answer: page(['a'], 1800001000, 1800000999, 1800001001) });
  one = listReducer(listReducer(one, { type: 'start', seq: 2, more: false }), { type: 'first', gen: 0, seq: 2, answer: page(['x'], 1800002000, 1800001999, 1800002001) });
  assert.equal(one.restarted, false);
});

test('sessions parser: newest start first, pseudonyms only, band and changes', () => {
  const a = S('sessions');
  assert.equal(a.status, 'ok');
  assert.equal(a.recording, true);
  assert.deepEqual(a.sessions.map(x => x.ts), [...a.sessions.map(x => x.ts)].sort((p, q) => q - p));
  assert.deepEqual(a.sessions.map(sessionDurationText), ['Dauer 1 min', 'Dauer 3 min', 'noch verbunden']);
  assert.deepEqual(a.sessions.map(x => bandText(x.band)), ['5 GHz', '5 GHz', '5 GHz']);
  assert.deepEqual(a.sessions.map(x => roamText(x.params)), ['1 Wechsel', null, null]);
  assert.equal(sessionDurationText({ ts: 1, end: null, endState: 'unknown' }), 'Ende unbekannt');
  assert.equal(bandText(2.4), '2,4 GHz');
  assert.equal(bandText(6), '6 GHz');
  assert.equal(bandText(null), null);
  assert.equal(roamText({ roam: 3 }), '3 Wechsel');
  assert.equal(sessionDays(a.sessions, NOW_MS).length, 1);
  assert.equal(unavailableText(S('sessions_unavailable').reason).includes('not_running'), false);
  for (const name of ['sessions_off', 'sessions_clients_off', 'sessions_unavailable', 'sessions_empty']) {
    assert.deepEqual(S(name).sessions, [], name);
  }
});

test('the client select: remembered clients by label, the pseudonym only as value', () => {
  const names = rememberClients({}, S('sessions').sessions);
  assert.deepEqual(clientOptions(names), [
    { value: M1, label: 'Client ·a1ce4d' },
    { value: M2, label: 'Client tablet-kueche' },
  ]);
  // narrowing to one client keeps the others in the select
  assert.equal(rememberClients(names, S('sessions_client').sessions), names);
});

test('session queries: checked values only, in a fixed order', () => {
  const q = firstSessionQuery({ ...DEFAULT_SESSION_FILTERS, client: M1, routerId: 'rtr_11111111111111111111111111111111' }, NOW_MS);
  assert.equal(q.until - q.from, 86_400);
  assert.equal(sessionQueryString(q), `from=${q.from}&until=${q.until}&client=${M1}&router_id=rtr_11111111111111111111111111111111`);
  const bad = firstSessionQuery({ ...DEFAULT_SESSION_FILTERS, client: 'aa:bb:cc:dd:ee:ff', routerId: 'eth0' }, NOW_MS);
  assert.equal(bad.client, null);
  assert.equal(bad.routerId, null);
  assert.equal(sessionQueryString(olderSessionQuery(q, 1800000600, 1800000780)).startsWith('from=1800000600&until=1800000780'), true);
  assert.notEqual(sessionFilterKey(DEFAULT_SESSION_FILTERS), sessionFilterKey({ ...DEFAULT_SESSION_FILTERS, client: M1 }));
});

const start = (s, seq, more = false) => sessionReducer(s, { type: 'start', seq, more });

test('sessions reducer: pages join, stale answers lose, a filter change starts anew', () => {
  let s = start(SESSION_LIST_INIT, 1);
  s = sessionReducer(s, { type: 'first', gen: 0, seq: 1, answer: S('sessions_page1') });
  assert.equal(s.nextUntil, FC.sessions_page1.body.next_until);
  s = sessionReducer(start(s, 2, true), { type: 'older', gen: 0, seq: 2, answer: S('sessions_page2') });
  assert.deepEqual(s.sessions.map(x => x.id), S('sessions').sessions.map(x => x.id));
  assert.equal(s.older, true);
  // a late first answer of an older request is dropped
  const s2 = start(s, 3);
  assert.equal(sessionReducer(s2, { type: 'first', gen: 0, seq: 1, answer: S('sessions_empty') }), s2);
  // a filter change: new generation, answers of the old one are dropped
  const f = sessionReducer(s2, { type: 'filters' });
  assert.equal(f.sessions.length, 0);
  assert.equal(f.loading, true);
  assert.equal(sessionReducer(f, { type: 'first', gen: 0, seq: 3, answer: S('sessions') }), f);
});

test('sessions reducer: a refresh during "Ältere laden" joins without a gap, or starts anew', () => {
  let s = start(SESSION_LIST_INIT, 1);
  s = sessionReducer(s, { type: 'first', gen: 0, seq: 1, answer: S('sessions_page1') });
  s = start(s, 2, true);
  s = start(s, 3);
  // the refresh reaches the loaded list (same page): joined, the older page still counts
  s = sessionReducer(s, { type: 'first', gen: 0, seq: 3, answer: S('sessions_page1') });
  s = sessionReducer(s, { type: 'older', gen: 0, seq: 2, answer: S('sessions_page2') });
  assert.equal(s.sessions.length, 3);
  assert.equal(s.restarted, false);
  // a refresh far ahead that does not reach: the list starts anew and says so
  const far = { ...S('sessions_page1'), until: 1900000000, nextUntil: 1899999000,
    sessions: [{ ...S('sessions').sessions[0], id: 'tmm_far', ts: 1899999500 }] };
  s = sessionReducer(start(s, 4), { type: 'first', gen: 0, seq: 4, answer: far });
  assert.deepEqual(s.sessions.map(x => x.id), ['tmm_far']);
  assert.equal(s.restarted, true);
  assert.equal(sessionReducer(s, { type: 'dismiss' }).restarted, false);
});

test('sessions reducer: off, clients_off and unavailable clear the list', () => {
  let s = sessionReducer(start(SESSION_LIST_INIT, 1), { type: 'first', gen: 0, seq: 1, answer: S('sessions') });
  for (const name of ['sessions_clients_off', 'sessions_off', 'sessions_unavailable']) {
    const n = sessionReducer(start(s, 9), { type: 'first', gen: 0, seq: 9, answer: S(name) });
    assert.deepEqual(n.sessions, [], name);
    assert.equal(n.head.status, FC[name].body.status, name);
    assert.equal(n.nextUntil, null, name);
  }
});

test('sessions poll: visible, at most every 60 s, never while off or clients_off', () => {
  const base = { visible: true, lastMs: 0, nowMs: 60_000, status: 'ok' };
  assert.equal(shouldPollSessions(base), true);
  assert.equal(shouldPollSessions({ ...base, nowMs: 59_999 }), false);
  assert.equal(shouldPollSessions({ ...base, visible: false }), false);
  assert.equal(shouldPollSessions({ ...base, status: 'off' }), false);
  assert.equal(shouldPollSessions({ ...base, status: 'clients_off' }), false);
  assert.equal(shouldPollSessions({ ...base, status: 'unavailable' }), true);
});
