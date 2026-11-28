// Logic of the "Self-Healing" tab (node:test, no dependencies): parsers on
// real route answers (shFixture.json, made and checked by
// tests/test_sh_panel_fixture_v1530.py from heal_views.py; invented ids), the error mapping, "truth or unknown", and the
// ONE reason table compared with the backend's own sources.
process.env.TZ = 'Europe/Berlin';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as L from './shLogic.ts';
import * as T from './shTexts.ts';

const here = dirname(fileURLToPath(import.meta.url));
const F = JSON.parse(readFileSync(join(here, 'shFixture.json'), 'utf8'));
const PY = join(here, '../../../../..');
const py = name => readFileSync(join(PY, name), 'utf8');
const R1 = 'rtr_11111111111111111111111111111111';
const R2 = 'rtr_22222222222222222222222222222222';

// ── The reason table and the backend ────────────────────────────────────

function pythonDict(src, name) {
  const start = src.indexOf(`\n${name}: Final[Mapping[str, str]] = MappingProxyType(`);
  assert.ok(start >= 0, `${name} found`);
  const end = src.indexOf('\n)\n', start);
  const out = {};
  for (const m of src.slice(start, end).matchAll(/^\s+"([a-z0-9_]+)": "((?:[^"\\]|\\.)*)",$/gm)) out[m[1]] = m[2];
  return out;
}

test('REASON_TEXT holds every heal_policy.REASON_TEXT_DE text unchanged', () => {
  const de = pythonDict(py('heal_policy.py'), 'REASON_TEXT_DE');
  assert.ok(Object.keys(de).length >= 100, `${Object.keys(de).length} codes read`);
  for (const [k, v] of Object.entries(de)) assert.equal(T.REASON_TEXT[k], v, k);
});

/** Every code the engine, the model and the store put into a plan, a history entry or a hold. */
function backendCodes() {
  const engine = py('heal_engine.py');
  const model = py('heal_model.py');
  const store = py('heal_store.py');
  const policy = py('heal_policy.py');
  const out = new Set();
  for (const m of engine.matchAll(/^BLOCK_[A-Z_]+: Final = "([a-z_]+)"/gm)) out.add(m[1]);
  for (const m of engine.matchAll(/reason="([a-z_]+)"(?: if \w+ else "([a-z_]+)")?/g)) { out.add(m[1]); if (m[2]) out.add(m[2]); }
  for (const m of engine.matchAll(/self\._close\(action, "([a-z_]+)"\)/g)) out.add(m[1]);
  const closed = /_CLOSED_STATUS: Final\[Mapping\[str, str\]\] = \{([\s\S]*?)\}/.exec(engine);
  assert.ok(closed, '_CLOSED_STATUS');
  for (const m of closed[1].matchAll(/: "([a-z_]+)"/g)) out.add(m[1]);
  const hold = /class HoldReason\(StrEnum\):([\s\S]*?)\n\n\n/.exec(model);
  assert.ok(hold, 'HoldReason');
  for (const m of hold[1].matchAll(/= "([a-z_]+)"/g)) out.add(m[1]);
  for (const m of model.matchAll(/"([a-z_]+_restart)"/g)) out.add(m[1]);
  const outcomes = /class DecisionOutcome\(StrEnum\):([\s\S]*?)\n\n\n/.exec(model);
  assert.ok(outcomes, 'DecisionOutcome');
  for (const m of outcomes[1].matchAll(/= "([a-z_]+)"/g)) out.add(`decision_${m[1]}`);
  for (const m of store.matchAll(/^REASON_[A-Z_]+: Final = "([a-z_]+)"/gm)) out.add(m[1]);
  for (const m of store.matchAll(/reason="([a-z_]+)"/g)) out.add(m[1]);
  for (const m of policy.matchAll(/reason="(fleet_[a-z_]+)"/g)) out.add(m[1]);
  return out;
}

test('every blocker, history, hold and pause code of the backend has a German text', () => {
  const codes = backendCodes();
  assert.ok(codes.size >= 35, `${codes.size} codes read`);
  for (const c of ['no_write_path', 'mode_observe', 'incident_opened', 'incident_cleared', 'decision_recommended',
    'outcome_unknown', 'store_lost', 'fleet_failures', 'interrupted_by_restart', 'released_by_admin']) {
    assert.ok(codes.has(c), `${c} read from the backend`);
  }
  const missing = [...codes].filter(c => !(c in T.REASON_TEXT));
  assert.deepEqual(missing, []);
});

test('every code in the recorded route answers is shown in German (no raw code on screen)', () => {
  const seen = new Map();
  const add = (table, c) => { if (typeof c === 'string') seen.set(`${table}:${c}`, [table, c]); };
  const walk = (v, key) => {
    if (Array.isArray(v)) { v.forEach(x => walk(x, key)); return; }
    // texts_de: the server's own German texts; the tab uses its one table instead
    if (v && typeof v === 'object') { for (const [k, x] of Object.entries(v)) if (k !== 'texts_de') walk(x, k); return; }
    if (['reason', 'why', 'why_not', 'refusal', 'pause_reason', 'statement'].includes(key)) add('reason', v);
    if (key === 'blockers' || key === 'reasons' || key === 'factor') add('reason', v);
    if (key === 'state' || key === 'to_state' || key === 'from_state') add('state', v);
    if (key === 'actor') add('actor', v);
    if (key === 'permission') add('permission', v);
    if (key === 'configured_mode' || key === 'effective_mode') add('mode', v);
    if (key === 'incident_type') add('incident', v);
    if (key === 'source_families') add('family', v);
    if (key === 'unknown' || key === 'missing') add('fact', v);
  };
  for (const [k, a] of Object.entries(F)) if (a.status === 200) walk(a.body, k);
  const TABLES = { reason: T.REASON_TEXT, state: T.STATE_TEXT, actor: T.ACTOR_TEXT, permission: T.PERMISSION_TEXT,
    mode: T.MODE_TEXT, incident: T.INCIDENT_TEXT, family: T.FAMILY_TEXT, fact: T.FACT_TEXT };
  const missing = [...seen.values()].filter(([t, c]) => !(c in TABLES[t])).map(([t, c]) => `${t}:${c}`);
  assert.deepEqual(missing, []);
  assert.ok(seen.size > 30, `${seen.size} codes looked at`);
});

test('incident and cause texts are the panel\'s own (utils/intel.ts), so both say the same', () => {
  const intel = readFileSync(join(here, '../../utils/intel.ts'), 'utf8');
  const table = name => {
    const m = new RegExp(`const ${name}: Record<string, string> = \\{([\\s\\S]*?)\\n\\};`).exec(intel);
    assert.ok(m, name);
    const out = {};
    for (const x of m[1].matchAll(/^\s+([a-z0-9_]+): '((?:[^'\\]|\\.)*)',/gm)) out[x[1]] = x[2];
    return out;
  };
  const types = table('TYPE_LABEL');
  const causes = table('CAUSE_LABEL');
  assert.ok(Object.keys(types).length > 20 && Object.keys(causes).length > 10);
  for (const [k, v] of Object.entries(types)) assert.equal(T.INCIDENT_TEXT[k], v, k);
  for (const [k, v] of Object.entries(causes)) assert.equal(T.CAUSE_TEXT[k], v, k);
});

test('an unknown code is shown raw, a missing one as "unbekannt"', () => {
  assert.equal(L.reasonText('something_new_42'), 'something_new_42');
  assert.equal(L.reasonText(null), 'unbekannt');
  assert.equal(L.stateText('brand_new_state'), 'brand_new_state');
  assert.equal(L.incidentText(undefined), 'unbekannt');
  assert.equal(L.causeText(null), 'keine Ursache gemeldet');
  assert.equal(L.reasonText('no_write_path'), T.REASON_TEXT.no_write_path);
});

// ── Parsers ──────────────────────────────────────────────────────────────

test('overview: modes, hold, fleet pause and counts as the route sends them', () => {
  const ov = L.parseOverview(F.held_overview.body);
  assert.equal(ov.status, 'on');
  assert.equal(ov.releaseMode, 'observe_only');
  assert.equal(ov.writePath, false);
  assert.equal(ov.automaticRollback, 'not_available');
  assert.equal(ov.fleet.paused, true);
  assert.equal(ov.fleet.pauseReason, 'store_lost');
  assert.equal(ov.fleet.pauseRemainingS, 3600);
  assert.deepEqual(ov.routers.map(r => [r.routerId, r.configuredMode, r.effectiveMode, r.held]), [
    [R1, 'observe', 'observe', true], [R2, 'auto_heal', 'observe', false],
  ]);
  assert.deepEqual(ov.routers[0].hold, { reason: 'outcome_unknown', fleet: false, noEnd: true, remainingS: null, actionId: null });
  assert.equal(L.holdText(ov.routers[0].hold), `${T.REASON_TEXT.outcome_unknown} – ohne Ende – nur ein Administrator hebt sie auf`);
  assert.equal(L.modeWhy(ov.routers[1], ov), 'Flotte pausiert');
  assert.equal(L.modeWhy(ov.routers[0], ov), null);
  assert.equal(ov.pendingIncidents, 1);
});

test('a non-admin answer has no router list: masked, never "no routers"', () => {
  const ov = L.parseOverview(F.user_overview.body);
  assert.equal(ov.routers, null);
  assert.equal(ov.pendingIncidents, null);
  assert.ok(ov.counts.total !== null);
});

test('list and detail: one row per record, the decision and the history', () => {
  const list = L.parseActions(F.actions.body);
  assert.equal(list.actions.length, 2);
  const open = list.actions.find(r => r.state === 'proposed');
  assert.equal(open.incidentType, 'system_service_restart');
  assert.equal(open.decision, 'recommended');
  assert.equal(open.riskClass, 0);
  assert.equal(L.isOpen(open), true);
  const d = L.parseDetail(F.detail_closed.body);
  assert.equal(d.action.state, 'cancelled');
  assert.deepEqual(d.action.history.map(h => h.reason), ['incident_opened', 'cause_from_incident', 'decision_recommended', 'incident_cleared']);
  assert.deepEqual(d.action.preflight, []);
  assert.equal(d.action.executionAttempt, 0);
  // dependants (router ids) arrive as their number only
  assert.equal(L.parseDetail(F.detail_open.body).action.expectedImpact.dependants, 0);
});

test('plans: blockers and the explanation; a candidate only when the server labels one', () => {
  const [p] = L.parsePlans(F.plan_open.body);
  assert.equal(p.executable, false);
  assert.ok(p.blockers.includes('no_write_path') && p.blockers.includes('mode_observe'));
  assert.equal(p.explanation.candidate, null);
  const [c] = L.parsePlans(F.plan_candidate.body);
  const cand = c.explanation.candidate;
  assert.equal(cand.actionType, 'service.restart');
  assert.equal(cand.policy.recovery.statement !== undefined, true);
  assert.deepEqual(cand.plannedChanges, [{ kind: 'service', target: 'dnsmasq', effect: 'service.restart' }]);
  // something that is not labelled "candidate" is never shown as one
  const fake = structuredClone(F.plan_candidate.body);
  fake.plans[0].explanation.candidate.label = 'decision';
  assert.equal(L.parsePlans(fake)[0].explanation.candidate, null);
  assert.deepEqual(L.parsePlans(F.empty_plans.body), []);
});

test('a missing or malformed value stays unknown (null), never 0 or false', () => {
  const ov = L.parseOverview({ status: 'on', counts: { by_state: { proposed: 'x' } }, fleet: { paused: 'yes' } });
  assert.equal(ov.fleet.paused, null);
  assert.equal(ov.counts.open, null);
  assert.deepEqual(ov.counts.byState, {});
  const tiles = L.tiles(ov);
  assert.ok(tiles.every(t => t.value === null), 'every tile unknown');
  assert.ok(tiles.every(t => t.note.length > 0));
  // the status is never dropped: an odd one stays raw (rendered as text), cut to 64 characters
  assert.equal(L.parseOverview({ status: '<b>on</b> now', counts: {} }).status, '<b>on</b> now');
  assert.equal(L.parseOverview({ status: 'x'.repeat(100), counts: {} }).status.length, 64);
  assert.equal(L.yesNo(null), 'unbekannt');
  assert.equal(L.countText(undefined), 'unbekannt');
  assert.equal(L.durationText(null), 'unbekannt');
  assert.equal(L.timeText(null), 'unbekannt');
  assert.deepEqual(L.riskView(null), { label: 'Risiko unbekannt', tone: 'muted' });
});

test('the "blocked risky actions" tile is unknown with its reason (no route counts it)', () => {
  const t = L.tiles(L.parseOverview(F.overview.body)).find(x => x.id === 'blocked');
  assert.equal(t.value, null);
  assert.equal(t.note, L.BLOCKED_RISKY_UNKNOWN);
});

test('settings: switch, stored limits and retention', () => {
  const s = L.parseSettings(F.settings.body);
  assert.equal(s.moduleSwitch, true);
  assert.equal(s.enabled, true);
  assert.equal(s.limits.cooldown_s, 1800);
  assert.equal(s.retentionS, 7776000);
  assert.equal(s.maxActions, 500);
});

// ── Errors ───────────────────────────────────────────────────────────────

test('errors: 403, 404, 410, 503 and a network failure', () => {
  const e = (s, c) => L.errorInfo(new L.ShApiError(s, c));
  assert.equal(e(403, 'authorization_denied').kind, 'forbidden');
  assert.equal(L.errorInfo(new L.ShApiError(404, 'unknown_action'), 'record').kind, 'missing');
  assert.equal(e(404, '').kind, 'off');
  assert.equal(e(410, 'integration_not_loaded').kind, 'gone');
  assert.equal(e(503, 'not_running').kind, 'off');
  assert.equal(e(503, 'other').kind, 'failed');
  const net = L.errorInfo(new TypeError('Failed to fetch'));
  assert.equal(net.kind, 'failed');
  assert.equal(net.retry, true);
  assert.match(net.message, /nicht geladen/);
  // the server's message never reaches the screen; a field name only when it is a code
  assert.equal(L.errorInfo(new L.ShApiError(400, 'invalid_request', { field: 'limit' })).message, 'Ungültige Anfrage (Feld limit).');
  assert.equal(L.errorInfo(new L.ShApiError(400, 'invalid_request', { field: '<x y>' })).message, 'Ungültige Anfrage.');
});

// ── List helpers and polling ─────────────────────────────────────────────

test('filters: open, closed and per router', () => {
  const rows = L.parseActions(F.actions.body).actions;
  assert.equal(L.filterRows(rows, { show: 'open', routerId: null }).length, 1);
  assert.equal(L.filterRows(rows, { show: 'closed', routerId: null }).length, 1);
  assert.equal(L.filterRows(rows, { show: 'all', routerId: R2 }).every(r => r.routerId === R2), true);
  const cut = { total: 340, limit: 200, offset: 0, actions: new Array(200), received: 200, unreadable: 0 };
  assert.equal(L.cutText(cut), 'Angezeigt werden die neuesten 200 von 340 Datensätzen.');
  assert.equal(L.cutText({ ...cut, total: 2, actions: rows, received: 2 }), null);
});

test('router names are the panel standard (the routes send ids only)', () => {
  assert.equal(L.routerText(R1), 'Router 111111');
  assert.equal(L.routerText(null), 'Router unbekannt');
});

test('polling: at most every 60 s, only while visible, never while stopped', () => {
  assert.equal(L.POLL_MIN_MS, 60_000);
  assert.equal(L.shouldPoll({ visible: true, lastMs: null, nowMs: 0, stopped: false }), true);
  assert.equal(L.shouldPoll({ visible: true, lastMs: 0, nowMs: 59_000, stopped: false }), false);
  assert.equal(L.shouldPoll({ visible: true, lastMs: 0, nowMs: 60_000, stopped: false }), true);
  assert.equal(L.shouldPoll({ visible: false, lastMs: 0, nowMs: 600_000, stopped: false }), false);
  assert.equal(L.shouldPoll({ visible: true, lastMs: 0, nowMs: 600_000, stopped: true }), false);
});

test('times are local with the date; durations in words', () => {
  assert.equal(L.timeText(1_790_000_000), '21.09.2026, 16:13:20');
  assert.equal(L.isoUtc(1_790_000_000), '2026-09-21T14:13:20.000Z');
  assert.equal(L.durationText(3600), '1 h');
  assert.equal(L.durationText(86400 * 3), '3 Tage');
  assert.equal(L.scoreText(0.67), '67 von 100');
  assert.equal(L.pointsText(-10), '-10');
});

// ── Review round of PR #84: truth, unknown or an error; never a calm state ──

const isBroken = field => e => e instanceof L.ShApiError && e.code === 'invalid_body' && e.details.field === field;

test('P2-1: an answer of the wrong shape is an error, never an empty answer', () => {
  for (const bad of [null, 'x', [], 7]) {
    assert.throws(() => L.parseOverview(bad), isBroken('body'));
    assert.throws(() => L.parseActions(bad), isBroken('body'));
    assert.throws(() => L.parseDetail(bad), isBroken('body'));
    assert.throws(() => L.parsePlans(bad), isBroken('body'));
    assert.throws(() => L.parseSettings(bad), isBroken('body'));
  }
  assert.throws(() => L.parseOverview({ counts: {} }), isBroken('status'));
  assert.throws(() => L.parseOverview({ status: 'on' }), isBroken('counts'));
  for (const actions of [undefined, null, 'x', {}]) assert.throws(() => L.parseActions({ total: 0, actions }), isBroken('actions'));
  assert.throws(() => L.parsePlans({ plans: {} }), isBroken('plans'));
  assert.throws(() => L.parseSettings({ limits: {} }), isBroken('settings'));
  // every recorded 200 answer still parses
  for (const [k, a] of Object.entries(F)) {
    if (a.status !== 200) continue;
    const parse = /overview|not_running/.test(k) ? L.parseOverview : /actions/.test(k) ? L.parseActions
      : /detail/.test(k) ? L.parseDetail : /plan/.test(k) ? L.parsePlans : L.parseSettings;
    assert.doesNotThrow(() => parse(a.body), k);
  }
  const info = L.errorInfo(L.invalidBody('actions', 200), 'list');
  assert.equal(info.kind, 'broken');
  assert.equal(info.retry, true);
  assert.equal(info.message, 'Die Antwort der Liste war nicht lesbar (Status 200, Teil actions). Es wird nichts daraus angezeigt – auch nicht als leer oder „in Ordnung“.');
});

test('P2-1: dropped rows are counted, a total that does not fit is said, empty only for 0 and []', () => {
  const raw = structuredClone(F.actions.body);
  raw.actions.push({ action_id: 'kaputt' }, 'x');
  const list = L.parseActions(raw);
  assert.equal(list.actions.length, 2);
  assert.equal(list.received, 4);
  assert.equal(list.unreadable, 2);
  assert.deepEqual(L.listNotes(list), [
    '2 Datensätze nicht lesbar (in der Antwort, aber ohne gültige Kennung oder Form; sie werden nicht angezeigt).',
    'Die Antwort passt nicht zusammen: Der Server meldet 2 Datensätze, geliefert wurden 4.',
  ]);
  assert.equal(L.isEmptyList(list), false);
  const one = L.parseActions({ ...F.actions.body, total: 3, actions: [...F.actions.body.actions, { action_id: 'x' }] });
  assert.deepEqual(L.listNotes(one), ['1 Datensatz nicht lesbar (in der Antwort, aber ohne gültige Kennung oder Form; er wird nicht angezeigt).']);
  // an empty list with a total above 0, or without a total, is not "nothing observed"
  const lost = L.parseActions({ total: 3, limit: 200, offset: 0, actions: [] });
  assert.equal(L.isEmptyList(lost), false);
  assert.deepEqual(L.listNotes(lost), ['Die Antwort passt nicht zusammen: Der Server meldet 3 Datensätze, geliefert wurden 0.']);
  const noTotal = L.parseActions({ actions: [] });
  assert.equal(L.isEmptyList(noTotal), false);
  assert.deepEqual(L.listNotes(noTotal), ['Die Antwort nennt keine Gesamtzahl der Datensätze – ob es weitere gibt, ist unbekannt.']);
  assert.equal(L.isEmptyList(L.parseActions(F.empty_actions.body)), true);
  assert.deepEqual(L.listNotes(L.parseActions(F.actions.body)), []);
  // a cut by the limit is no mismatch
  const cut = L.parseActions({ total: 340, limit: 2, offset: 0, actions: F.actions.body.actions });
  assert.deepEqual(L.listNotes(cut), []);
  assert.equal(L.cutText(cut), 'Angezeigt werden die neuesten 2 von 340 Datensätzen.');
});

test('P3-1: a state the tab does not know is listed raw with its count, also a 0', () => {
  const body = structuredClone(F.overview.body);
  body.counts.by_state.brand_new_state = 2;
  body.counts.by_state.other_new = 0;
  const ov = L.parseOverview(body);
  assert.deepEqual(L.unknownStates(ov), [{ state: 'brand_new_state', n: 2 }, { state: 'other_new', n: 0 }]);
  assert.deepEqual(L.unknownStates(L.parseOverview(F.overview.body)), []);
});

test('P3-2: the note above an answer from before says it is old and from when', () => {
  assert.equal(L.staleText(1_790_001_920, new TypeError('x')),
    'Aktualisieren fehlgeschlagen (keine Antwort vom Server). Die Werte unten sind vom 21.09.2026, 16:45:20 und können veraltet sein.');
  assert.equal(L.staleText(null, L.invalidBody('json', 200)),
    'Aktualisieren fehlgeschlagen (Antwort nicht lesbar). Die Werte unten stammen aus einer früheren Antwort (Stand unbekannt) und können veraltet sein.');
  assert.match(L.staleText(1, new L.ShApiError(null, 'timeout')), /\(keine Antwort in 30 s\)/);
  assert.doesNotMatch(L.staleText(1_790_001_920, new TypeError('x')), /nichts als „in Ordnung“/);
});

test('P3-3: a missing key is unknown (undefined), only an explicit null is "none" (null)', () => {
  const full = L.parseDetail(F.detail_open.body);
  assert.equal(full.routerHold, null);
  assert.equal(full.action.playbookId, null);
  assert.equal(full.action.backupVersionId, null);
  assert.equal(full.action.backupReason, null);
  assert.equal(full.action.verificationResult, null);
  assert.deepEqual(full.action.plannedChanges, []);
  assert.deepEqual(full.action.components, []);
  const body = structuredClone(F.detail_open.body);
  delete body.router_hold;
  for (const k of ['playbook_id', 'backup_ref', 'verification', 'planned_changes', 'components']) delete body.action[k];
  const gone = L.parseDetail(body);
  assert.equal(gone.routerHold, undefined);
  assert.equal(gone.action.playbookId, undefined);
  assert.equal(gone.action.backupVersionId, undefined);
  assert.equal(gone.action.backupReason, undefined);
  assert.equal(gone.action.verificationResult, undefined);
  assert.equal(gone.action.plannedChanges, undefined);
  assert.equal(gone.action.components, undefined);
  // inside a present object a missing key is unknown too; a malformed value is unknown, not "none"
  const half = structuredClone(F.detail_open.body);
  half.action.backup_ref = { version_id: null };
  half.action.verification = {};
  half.action.playbook_id = 42;
  half.action.planned_changes = 'x';
  const h = L.parseDetail(half);
  assert.equal(h.action.backupVersionId, null);
  assert.equal(h.action.backupReason, undefined);
  assert.equal(h.action.verificationResult, undefined);
  assert.equal(h.action.playbookId, undefined);
  assert.equal(h.action.plannedChanges, undefined);
});

test('P3-4: a detail without a valid action is an error, never an empty record', () => {
  assert.throws(() => L.parseDetail({ generated_at: 1 }), isBroken('action'));
  assert.throws(() => L.parseDetail({ action: { state: 'proposed' } }), isBroken('action'));
  assert.throws(() => L.parseDetail({ action: { action_id: 'rem_123' } }), isBroken('action'));
});

test('P3-6 / P3-10: an unknown overview status and any mode other than observe are flagged', () => {
  assert.equal(L.unknownStatus(L.parseOverview(F.overview.body)), null);
  assert.equal(L.unknownStatus(L.parseOverview(F.disabled_overview.body)), null);
  assert.equal(L.unknownStatus(L.parseOverview({ ...F.overview.body, status: 'maintenance' })), 'maintenance');
  assert.equal(L.needsModeNote('observe'), false);
  assert.equal(L.needsModeNote(null), false);
  for (const m of ['approval', 'auto_heal', 'brand_new_mode']) assert.equal(L.needsModeNote(m), true, m);
  assert.equal(L.MODE_NOTE, 'In dieser Version wird trotzdem nichts ausgeführt.');
  assert.deepEqual(L.OUTCOME_HOLDS, ['outcome_unknown', 'outcome_escalated']);
  assert.equal(L.REQUEST_TIMEOUT_MS, 30_000);
});
