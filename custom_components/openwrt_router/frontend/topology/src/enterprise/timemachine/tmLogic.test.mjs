// Tests of the pure "Zeitreise" logic (node:test, no dependencies). Node
// strips the TypeScript types of the imported .ts files itself. The sample
// answers come from tmFixture.json, written from the real route by
// tests/test_tm_panel_fixture_v1500.py (invented values only).
process.env.TZ = 'Europe/Berlin';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CUT_TEXT, DEFAULT_FILTERS, LIST_INIT, SOURCE_IDS, TAB_ID, TAB_ORDER, TAB_TITLE, TmApiError,
  adminOnlySources, countText, dayGroups, dayLabel, dedupe, errorInfo, filterKey, firstQuery, groupsOf, isFallbackTitle,
  isoUtc, listReducer, mergeMarks, olderQuery, omittedText, paramsText, parseTimeline, queryString, rememberRouters,
  routerOptions, routerText, severityView, shouldPoll, sourcePill, standText, timeText, titleOf, visibleMarks,
} from './tmLogic.ts';
import { TITLE_TEXT } from './tmTexts.ts';

const here = dirname(fileURLToPath(import.meta.url));
const F = JSON.parse(readFileSync(join(here, 'tmFixture.json'), 'utf8'));
const body = name => F[name].body;
const T = name => parseTimeline(body(name));

const NOW_MS = Date.UTC(2026, 10, 21, 12, 0, 0);

test('tab identity: "Zeitreise", order 60 under Enterprise, after Traffic (50)', () => {
  assert.equal(TAB_ID, 'timemachine');
  assert.equal(TAB_TITLE, 'Zeitreise');
  assert.equal(TAB_ORDER, 60);
});

test('the fixture is a real answer: every title_key in it has a German text', () => {
  for (const name of Object.keys(F)) {
    for (const m of body(name).marks ?? []) assert.ok(TITLE_TEXT[m.title_key], m.title_key);
  }
});

test('parser keeps the answer, newest first, ties by id', () => {
  const t = T('admin');
  assert.equal(t.status, 'ok');
  assert.equal(t.marks.length, body('admin').marks.length);
  assert.deepEqual(t.marks.map(m => m.id), body('admin').marks.map(m => m.id));
  assert.equal(t.omittedClientMarks, 1);
  assert.equal(t.sources.length, 5);
  for (let i = 1; i < t.marks.length; i++) {
    const [a, b] = [t.marks[i - 1], t.marks[i]];
    assert.ok(a.ts > b.ts || (a.ts === b.ts && a.id < b.id));
  }
  const off = T('off');
  assert.equal(off.status, 'off');
  assert.equal(off.from, null);
});

test('parser drops broken marks, unknown severities count as info, params keep numbers only', () => {
  const t = parseTimeline({
    status: 'ok', marks: [
      { id: 'tmm_0000000000000001', ts: 10, title_key: 'ni_events.wan.down', severity: 'loud', params: { a: 1, b: 'x', c: null } },
      { id: 'tmm_0000000000000002', title_key: 'x' },
      'nonsense',
    ], sources: [],
  });
  assert.equal(t.marks.length, 1);
  assert.equal(t.marks[0].severity, 'info');
  assert.deepEqual(t.marks[0].params, { a: 1 });
});

test('marks are deduplicated by id (the first wins)', () => {
  const [a, b] = T('admin').marks;
  const merged = mergeMarks([a, b], [b, a, { ...a, ts: 1 }]);
  assert.deepEqual(merged.map(m => m.id), [a.id, b.id]);
  assert.equal(merged.find(m => m.id === a.id).ts, a.ts);
  assert.equal(dedupe([a, a, a]).length, 1);
});

// ── Query ────────────────────────────────────────────────────────────────

test('first query: both ends of the window, all sources as default', () => {
  const q = firstQuery(DEFAULT_FILTERS, NOW_MS);
  assert.equal(q.until - q.from, 86_400);
  assert.equal(q.until, Math.floor(NOW_MS / 1000) + 1);
  assert.equal(q.sources, null);
  assert.equal(queryString(q), `from=${q.from}&until=${q.until}`);
  const week = firstQuery({ ...DEFAULT_FILTERS, window: '14d' }, NOW_MS);
  assert.equal(week.until - week.from, 14 * 86_400);
});

test('source, severity and router reach the query; sources hidden for the user are kept', () => {
  const rid = 'rtr_' + 'a'.repeat(32);
  const q = firstQuery({ window: '1h', sourcesOff: ['ni_events', 'core_audit'], severity: 'warning', routerId: rid }, NOW_MS, ['core_audit']);
  assert.deepEqual(q.sources, ['core_audit', 'config_versions', 'ni_incidents', 'security_timeline']);
  assert.equal(q.minSeverity, 'warning');
  assert.equal(
    queryString(q),
    `from=${q.from}&until=${q.until}&source=core_audit%2Cconfig_versions%2Cni_incidents%2Csecurity_timeline&router_id=${rid}&min_severity=warning`,
  );
  // an invalid router id is never sent
  assert.equal(firstQuery({ ...DEFAULT_FILTERS, routerId: '192.0.2.1' }, NOW_MS).routerId, null);
});

test('no selectable source left: no request', () => {
  assert.equal(firstQuery({ ...DEFAULT_FILTERS, sourcesOff: [...SOURCE_IDS] }, NOW_MS), null);
  const userOff = ['core_audit', 'config_versions'];
  assert.equal(firstQuery({ ...DEFAULT_FILTERS, sourcesOff: ['ni_events', 'ni_incidents', 'security_timeline'] }, NOW_MS, userOff), null);
});

test('older page: same filters and from, until = next_until', () => {
  const first = firstQuery({ ...DEFAULT_FILTERS, severity: 'critical' }, NOW_MS);
  const page1 = T('admin_page1');
  const q = olderQuery(first, page1.from, page1.nextUntil);
  assert.equal(q.from, page1.from);
  assert.equal(q.until, page1.nextUntil);
  assert.equal(q.minSeverity, 'critical');
  assert.match(queryString(q), new RegExp(`until=${page1.nextUntil}&min_severity=critical$`));
});

test('the filter key changes with what the server is asked, not with the order of sources', () => {
  const a = filterKey({ ...DEFAULT_FILTERS, sourcesOff: ['ni_events', 'core_audit'] });
  const b = filterKey({ ...DEFAULT_FILTERS, sourcesOff: ['core_audit', 'ni_events'] });
  assert.equal(a, b);
  assert.notEqual(filterKey(DEFAULT_FILTERS), filterKey({ ...DEFAULT_FILTERS, window: '7d' }));
});

// ── List state ───────────────────────────────────────────────────────────

function start(s, seq, more = false) {
  return listReducer(s, { type: 'start', seq, more });
}

test('loading older pages with next_until appends them, deduplicated', () => {
  let s = start(LIST_INIT, 1);
  s = listReducer(s, { type: 'first', gen: 0, seq: 1, answer: T('admin_page1') });
  assert.equal(s.nextUntil, T('admin_page1').nextUntil);
  assert.equal(s.older, false);
  s = start(s, 2, true);
  const page2 = T('admin_page2');
  s = listReducer(s, { type: 'older', gen: 0, seq: 2, answer: page2 });
  const ids = s.marks.map(m => m.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(ids.length, T('admin_page1').marks.length + page2.marks.length);
  assert.equal(s.nextUntil, page2.nextUntil);
  assert.equal(s.older, true);
  // the whole answer holds every mark of both pages
  const all = new Set(T('admin').marks.map(m => m.id));
  assert.ok(ids.every(id => all.has(id)));
});

test('a new first page with older pages loaded goes in front and keeps their next_until', () => {
  let s = start(LIST_INIT, 1);
  s = listReducer(s, { type: 'first', gen: 0, seq: 1, answer: T('admin_page1') });
  s = listReducer(start(s, 2, true), { type: 'older', gen: 0, seq: 2, answer: T('admin_page2') });
  const before = s.marks.length;
  const keep = s.nextUntil;
  s = listReducer(start(s, 3), { type: 'first', gen: 0, seq: 3, answer: T('admin_page1') });
  assert.equal(s.marks.length, before); // the same marks again: nothing doubled
  assert.equal(s.nextUntil, keep);
  // without older pages a new first page replaces the list
  let p = listReducer(start(LIST_INIT, 1), { type: 'first', gen: 0, seq: 1, answer: T('admin') });
  p = listReducer(start(p, 2), { type: 'first', gen: 0, seq: 2, answer: T('empty') });
  assert.deepEqual(p.marks, []);
});

// K3 (review 1.50.0): a 60-s refresh that answers while "Ältere laden" runs.
const rm = (id, ts) => ({ ...T('admin').marks[0], id, ts });
const page = (marks, nextUntil, until = 1000) => ({
  status: 'ok', generatedAt: until, from: 0, until, marks, sources: [], omittedClientMarks: 0,
  truncated: nextUntil !== null, nextUntil,
});

test('a refresh during "Ältere laden" never drops the marks in between', () => {
  let s = start(LIST_INIT, 1);
  s = listReducer(s, { type: 'first', gen: 0, seq: 1, answer: page([rm('a', 100), rm('b', 99), rm('c', 98)], 98) });
  s = start(s, 2, true); // "Ältere laden" (until = 98)
  s = start(s, 3); // the poll starts meanwhile; three new marks came in
  s = listReducer(s, { type: 'first', gen: 0, seq: 3, answer: page([rm('x', 103), rm('y', 102), rm('z', 101)], 101) });
  assert.equal(s.nextUntil, 98); // still where the pending older page continues
  s = listReducer(s, { type: 'older', gen: 0, seq: 2, answer: page([rm('d', 97), rm('e', 96), rm('f', 95)], 95) });
  assert.deepEqual(s.marks.map(m => m.id), ['x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f']);
  assert.equal(s.nextUntil, 95);
});

test('a refresh that does not reach the loaded list starts it anew, never with a gap', () => {
  // loaded: 100..95 (head until 101); the refresh covers only 300..198
  let s = start(LIST_INIT, 1);
  s = listReducer(s, { type: 'first', gen: 0, seq: 1, answer: page([rm('a', 100), rm('b', 99), rm('c', 98)], 98, 101) });
  s = listReducer(start(s, 2, true), { type: 'older', gen: 0, seq: 2, answer: page([rm('d', 97)], 95, 101) });
  s = start(s, 3, true); // another older page in flight
  s = start(s, 4);
  s = listReducer(s, { type: 'first', gen: 0, seq: 4, answer: page([rm('x', 200), rm('y', 199), rm('z', 198)], 198, 300) });
  assert.deepEqual(s.marks.map(m => m.id), ['x', 'y', 'z']);
  assert.equal(s.nextUntil, 198);
  assert.equal(s.older, false);
  assert.equal(s.loadingMore, false);
  // the older page of the old list is dropped, it would leave a gap
  assert.equal(listReducer(s, { type: 'older', gen: 0, seq: 3, answer: page([rm('e', 94)], null, 101) }), s);
});

test('a stale answer never overwrites a newer one', () => {
  let s = start(start(LIST_INIT, 1), 2);
  s = listReducer(s, { type: 'first', gen: 0, seq: 2, answer: T('empty') });
  const late = listReducer(s, { type: 'first', gen: 0, seq: 1, answer: T('admin') });
  assert.equal(late, s);
  const lateError = listReducer(s, { type: 'fail', gen: 0, seq: 1, more: false, error: new Error('x') });
  assert.equal(lateError.error, null);
});

test('a filter change drops answers of the old filters and starts loading', () => {
  let s = start(LIST_INIT, 1);
  s = listReducer(s, { type: 'first', gen: 0, seq: 1, answer: T('admin') });
  s = start(s, 2, true);
  s = listReducer(s, { type: 'filters' });
  assert.equal(s.gen, 1);
  assert.deepEqual(s.marks, []);
  assert.equal(s.loading, true);
  assert.equal(listReducer(s, { type: 'older', gen: 0, seq: 2, answer: T('admin_page2') }), s);
  s = start(s, 3);
  assert.equal(listReducer(s, { type: 'first', gen: 0, seq: 3, answer: T('admin') }), s);
  s = listReducer(s, { type: 'first', gen: 1, seq: 3, answer: T('user') });
  assert.equal(s.marks.length, T('user').marks.length);
});

test('an error keeps the last list on screen', () => {
  let s = listReducer(start(LIST_INIT, 1), { type: 'first', gen: 0, seq: 1, answer: T('admin') });
  s = listReducer(start(s, 2), { type: 'fail', gen: 0, seq: 2, more: false, error: new TmApiError(500, 'internal') });
  assert.equal(s.marks.length, T('admin').marks.length);
  assert.ok(s.error instanceof TmApiError);
});

test('off empties the list', () => {
  let s = listReducer(start(LIST_INIT, 1), { type: 'first', gen: 0, seq: 1, answer: T('admin') });
  s = listReducer(start(s, 2), { type: 'first', gen: 0, seq: 2, answer: T('off') });
  assert.deepEqual(s.marks, []);
  assert.equal(s.head.status, 'off');
});

test('polling: at most every 60 s, only while visible, never while off', () => {
  assert.equal(shouldPoll({ visible: true, lastMs: null, nowMs: 0, off: false }), true);
  assert.equal(shouldPoll({ visible: true, lastMs: 0, nowMs: 59_999, off: false }), false);
  assert.equal(shouldPoll({ visible: true, lastMs: 0, nowMs: 60_000, off: false }), true);
  assert.equal(shouldPoll({ visible: false, lastMs: null, nowMs: 0, off: false }), false);
  assert.equal(shouldPoll({ visible: true, lastMs: null, nowMs: 0, off: true }), false);
});

// ── Groups and routers ───────────────────────────────────────────────────

test('the group chips filter the loaded marks only, with a counter', () => {
  const marks = T('admin').marks;
  const groups = groupsOf(marks);
  assert.deepEqual(groups, ['infrastructure', 'configuration', 'disruption', 'security', 'administration']);
  const shown = visibleMarks(marks, ['configuration']);
  assert.ok(shown.length < marks.length && shown.every(m => m.group !== 'configuration'));
  assert.equal(countText(shown.length, marks.length), `${shown.length} von ${marks.length} Marken`);
  assert.equal(countText(1, 1), '1 von 1 Marke');
});

test('routers of the select come from the loaded marks and are kept', () => {
  const r = rememberRouters({}, T('admin').marks);
  const opts = routerOptions(r);
  assert.equal(opts.length, 1);
  assert.equal(opts[0].label, 'Router e1');
  assert.equal(rememberRouters(r, []), r);
  assert.equal(routerOptions({ ['rtr_' + 'b'.repeat(32)]: null })[0].label, 'Router bbbbbb');
});

test('router text: name, short label, all routers or none', () => {
  const m = T('admin').marks.find(x => x.routerId);
  assert.equal(routerText(m), 'Router e1');
  assert.equal(routerText({ fleet: true, routerId: null, routerName: null }), 'alle Router');
  assert.equal(routerText({ fleet: false, routerId: null, routerName: null }), 'ohne Router');
  assert.equal(routerText({ fleet: false, routerId: 'rtr_' + 'c'.repeat(32), routerName: null }), 'Router cccccc');
});

// ── Titles and parameters ────────────────────────────────────────────────

test('title: German text, else the server text (masked), else "Code <title_key>"', () => {
  const sec = T('admin').marks.find(m => m.source === 'security_timeline');
  assert.equal(titleOf(sec), TITLE_TEXT[sec.titleKey]);
  assert.equal(titleOf({ titleKey: 'security_timeline.brand_new', text: 'Gerät 02:00:5e:00:00:01 neu', source: 'security_timeline', kind: 'security_event' }),
    'Gerät [MAC] neu');
  assert.equal(titleOf({ titleKey: 'core_audit.future_module.thing', text: null, source: 'core_audit', kind: 'audit_event' }),
    'Code core_audit.future_module.thing');
  assert.equal(titleOf({ titleKey: '<b>x</b>', text: null, source: 'core_audit', kind: 'audit_event' }), 'Code unbekannt');
  assert.equal(isFallbackTitle('core_audit.future_module.thing'), true);
  assert.equal(isFallbackTitle('ni_events.wan.down'), false);
});

test('incidents say whether they were opened or resolved', () => {
  const inc = T('admin').marks.find(m => m.source === 'ni_incidents');
  assert.equal(titleOf(inc), 'Vorfall eröffnet: WAN-Verbindung ausgefallen');
  assert.equal(titleOf({ ...inc, kind: 'incident_resolved' }), 'Vorfall behoben: WAN-Verbindung ausgefallen');
});

test('parameters in plain words, known keys only, zeros left out', () => {
  const inc = T('admin').marks.find(m => m.source === 'ni_incidents');
  assert.deepEqual(inc.params, { affected: 0, occurrences: 3, reopen_count: 2, children: 0 });
  assert.equal(paramsText(inc.params), '3 Vorkommen · 2-mal wieder geöffnet');
  assert.equal(paramsText({ critical_count: 2, changes: 5, mac_count: 7 }), '5 Änderungen · 2 kritische Änderungen');
  assert.equal(paramsText({ changes: 1, critical_count: 1 }), '1 Änderung · 1 kritische Änderung');
  assert.equal(paramsText({ gap_s: 3600, channel: 36, frequency: 5180 }), 'Kanal 36 · 5.180 MHz · Lücke von 1 Std.');
  assert.equal(paramsText({ unknown: 1 }), null);
  assert.equal(paramsText({}), null);
});

test('severity: dot and word; info never in a warning colour', () => {
  assert.deepEqual(severityView('info'), { label: 'Info', tone: 'info' });
  assert.deepEqual(severityView('warning'), { label: 'Warnung', tone: 'warn' });
  assert.deepEqual(severityView('critical'), { label: 'Kritisch', tone: 'critical' });
});

// ── Sources ──────────────────────────────────────────────────────────────

test('source pills say their state in words and are never green', () => {
  const pills = name => T(name).sources.map(sourcePill);
  for (const p of pills('admin')) assert.match(p.text, /^\d+ Marken?$/);
  assert.ok(pills('empty').every(p => p.text === 'leer' && p.tone === 'muted'));
  const sec = pills('partial').find(p => p.name === 'Security Center');
  assert.deepEqual(sec, { name: 'Security Center', text: 'Quelle nicht lesbar · Fehler', tone: 'warn' });
  const audit = pills('user').find(p => p.name === 'Audit');
  assert.equal(audit.text, 'aus · nur für Administratoren');
  assert.equal(sourcePill({ id: 'ni_events', state: 'ok', reason: null, count: 1, oldest: 1, truncated: true }).text, '1 Marke · gekürzt');
  assert.equal(sourcePill({ id: 'config_versions', state: 'off', reason: 'module_off', count: 0, oldest: null, truncated: false }).text, 'aus · Modul aus');
  for (const [reason, text] of [['timeout', 'Zeitüberschreitung'], ['bad_format', 'unerwartetes Format'], ['not_loaded', 'Daten noch nicht geladen']]) {
    assert.equal(sourcePill({ id: 'ni_events', state: 'unreadable', reason, count: 0, oldest: null, truncated: false }).text, `Quelle nicht lesbar · ${text}`);
  }
  for (const name of Object.keys(F)) for (const p of pills(name)) assert.notEqual(p.tone, 'ok');
});

test('sources the server reports as admin_only are not selectable', () => {
  assert.deepEqual(adminOnlySources(T('user')), ['core_audit', 'config_versions']);
  assert.deepEqual(adminOnlySources(T('admin')), []);
});

test('hint about left-out client events only when there are some', () => {
  assert.equal(omittedText(T('admin').omittedClientMarks),
    '1 client-bezogenes Ereignis ist ausgeblendet. Client-Verläufe kommen mit einem eigenen Schalter in einer späteren Version.');
  assert.match(omittedText(3), /^3 client-bezogene Ereignisse sind ausgeblendet\./);
  assert.equal(omittedText(T('user').omittedClientMarks), null);
  assert.equal(omittedText(0), null);
});

test('the cut hint names what to do', () => {
  assert.equal(CUT_TEXT, 'Weitere Marken im Zeitfenster wurden gekürzt; Zeitfenster oder Filter enger wählen.');
});

// ── Time in local time ───────────────────────────────────────────────────

const sec = iso => Date.parse(iso) / 1000;
const mk = (id, iso) => ({ ...T('admin').marks[0], id, ts: sec(iso) });

test('days in local time across midnight and the end of summer time', () => {
  // Europe/Berlin: summer time ends 2026-10-25 01:00 UTC (03:00 CEST -> 02:00 CET)
  const marks = [
    mk('tmm_a', '2026-10-24T21:59:59Z'), // Sat 23:59:59 CEST
    mk('tmm_b', '2026-10-24T22:00:00Z'), // Sun 00:00:00 CEST
    mk('tmm_c', '2026-10-25T22:59:59Z'), // Sun 23:59:59 CET (a 25-hour day)
    mk('tmm_d', '2026-10-25T23:00:00Z'), // Mon 00:00:00 CET
  ];
  const groups = dayGroups(marks, Date.parse('2026-10-26T11:00:00Z'));
  assert.deepEqual(groups.map(g => [g.label, g.marks.map(m => m.id)]), [
    ['Heute', ['tmm_d']],
    ['Gestern', ['tmm_c', 'tmm_b']],
    ['Samstag, 24.10.2026', ['tmm_a']],
  ]);
  // the doubled hour: two instants, the same local clock time
  assert.equal(timeText(sec('2026-10-25T00:30:00Z')), '02:30:00');
  assert.equal(timeText(sec('2026-10-25T01:30:00Z')), '02:30:00');
  assert.equal(isoUtc(sec('2026-10-25T01:30:00Z')), '2026-10-25T01:30:00.000Z');
});

test('days in local time at the start of summer time', () => {
  // 2026-03-29 01:00 UTC: 02:00 CET -> 03:00 CEST (a 23-hour day)
  const marks = [mk('tmm_e', '2026-03-28T22:59:59Z'), mk('tmm_f', '2026-03-28T23:00:00Z'), mk('tmm_g', '2026-03-29T21:59:59Z')];
  const groups = dayGroups(marks, Date.parse('2026-03-29T21:59:59Z'));
  assert.deepEqual(groups.map(g => [g.label, g.marks.length]), [['Heute', 2], ['Gestern', 1]]);
  assert.equal(timeText(sec('2026-03-29T01:00:00Z')), '03:00:00');
  assert.equal(dayLabel(sec('2026-03-20T12:00:00Z'), Date.parse('2026-03-29T12:00:00Z')), 'Freitag, 20.03.2026');
});

test('"Stand" of generated_at in local time', () => {
  assert.equal(standText(sec('2026-11-21T13:05:59Z')), 'Stand 21.11.26, 14:05');
  assert.equal(standText(null), 'Stand —');
});

// ── Errors ───────────────────────────────────────────────────────────────

test('errors map from status and field only', () => {
  const bad = F.bad_request.body;
  const e400 = new TmApiError(400, bad.code, bad.details);
  assert.deepEqual(errorInfo(e400), { kind: 'invalid', message: 'Ungültige Filterkombination. Feld: Art.', retry: false });
  assert.equal(errorInfo(new TmApiError(400, 'invalid_request', { field: '<script>' })).message, 'Ungültige Filterkombination. Feld: unbekannt.');
  for (const status of [401, 403]) assert.equal(errorInfo(new TmApiError(status, '')).message, 'Keine Berechtigung für die Zeitreise.');
  assert.equal(errorInfo(new TmApiError(410, 'integration_not_loaded')).message, 'Die Integration wurde entladen.');
  for (const err of [new TmApiError(500, 'internal'), new TmApiError(503, ''), new TmApiError(null, 'not_connected'), new TypeError('Failed to fetch')]) {
    assert.deepEqual(errorInfo(err), { kind: 'failed', message: 'Die Zeitleiste konnte nicht geladen werden.', retry: true });
  }
});
