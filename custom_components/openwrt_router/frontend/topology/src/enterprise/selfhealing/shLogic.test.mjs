// Logic of the "Self-Healing" tab (node:test, no dependencies): parsers on
// real route answers (shFixture.json, recorded from heal_views.py against a
// test engine; invented ids), the error mapping, "truth or unknown", and the
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
  const ov = L.parseOverview({ counts: { by_state: { proposed: 'x' } }, fleet: { paused: 'yes' } });
  assert.equal(ov.fleet.paused, null);
  assert.equal(ov.counts.open, null);
  assert.equal(ov.status, null);
  assert.deepEqual(ov.counts.byState, {});
  const tiles = L.tiles(ov);
  assert.ok(tiles.every(t => t.value === null), 'every tile unknown');
  assert.ok(tiles.every(t => t.note.length > 0));
  // a free text where a code belongs is dropped
  assert.equal(L.parseOverview({ status: '<b>on</b> now' }).status, null);
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
  assert.equal(L.cutText({ total: 340, actions: new Array(200) }), 'Angezeigt werden die neuesten 200 von 340 Datensätzen.');
  assert.equal(L.cutText({ total: 2, actions: rows }), null);
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
