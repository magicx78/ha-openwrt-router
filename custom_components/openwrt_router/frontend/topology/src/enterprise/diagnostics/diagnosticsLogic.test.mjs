// Tests of the pure Network Diagnostics logic (node:test, no dependencies).
// Node 24 strips the TypeScript types of the imported .ts files itself.
// All values are invented; addresses (if any) are from documentation ranges.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DiagApiError,
  MAX_RUN_TARGETS,
  TAB_TITLE,
  TAB_TITLE_EN,
  buildRunBody,
  buildSettingsUpdate,
  chainChips,
  controlsFor,
  draftFromSettings,
  errorInfo,
  findingView,
  formatCoverage,
  formatMs,
  formatPct,
  formatWait,
  historyRows,
  moduleView,
  outcomeView,
  parseHistory,
  parseOverview,
  parseRetryAfter,
  parseRunResult,
  parseSettingsView,
  pointStateView,
  scoreView,
  stageTone,
  stageView,
  usableTargets,
} from './diagnosticsLogic.ts';

const STAGES = ['router', 'gateway', 'wan', 'internet', 'dns'];
const FORBIDDEN_FOR_UNKNOWN = /gesund|\bok\b|in ordnung|erreichbar|fehlerfrei|0 ?%/i;

function chain(states, basis = 'direct') {
  return STAGES.map((stage, i) => ({ stage, family: 'ipv4', state: states[i], basis }));
}

// ── Labels ───────────────────────────────────────────────────────────────

test('the tab is called Netzwerkdiagnose (English: Network Diagnostics)', () => {
  assert.equal(TAB_TITLE, 'Netzwerkdiagnose');
  assert.equal(TAB_TITLE_EN, 'Network Diagnostics');
});

// ── Unknown is never healthy ─────────────────────────────────────────────

test('unknown, missing and garbage stage states never get the healthy tone or text', () => {
  for (const bad of ['unknown', null, undefined, '', 'bogus', 'HEALTHY ', 42, {}, 'ok']) {
    assert.notEqual(stageTone(bad), 'ok', `tone of ${String(bad)}`);
    const v = stageView(bad);
    assert.equal(v.tone, 'muted');
    assert.doesNotMatch(v.text, FORBIDDEN_FOR_UNKNOWN);
  }
  assert.equal(stageView('healthy').tone, 'ok');
  assert.equal(stageView('degraded').tone, 'warn');
  assert.equal(stageView('failed').tone, 'critical');
  // not applicable is neutral, but a different text from unknown
  assert.equal(stageView('not_applicable').tone, 'muted');
  assert.notEqual(stageView('not_applicable').text, stageView('unknown').text);
});

test('a missing chain shows five unknown chips in order, none healthy', () => {
  for (const c of [null, undefined, [], 'x']) {
    const chips = chainChips(c);
    assert.deepEqual(chips.map(x => x.stage), STAGES);
    for (const chip of chips) {
      assert.equal(chip.state, 'unknown');
      assert.equal(chip.tone, 'muted');
      assert.doesNotMatch(chip.text, FORBIDDEN_FOR_UNKNOWN);
    }
  }
});

test('chain chips: states, missing stages and the unknown-beats-healthy rule', () => {
  const chips = chainChips(chain(['healthy', 'healthy', 'failed', 'unknown', 'not_applicable']));
  assert.deepEqual(chips.map(c => c.state), ['healthy', 'healthy', 'failed', 'unknown', 'not_applicable']);
  assert.deepEqual(chips.map(c => c.tone), ['ok', 'ok', 'critical', 'muted', 'muted']);

  // a stage the server did not deliver is unknown, not healthy
  const partial = chainChips([{ stage: 'router', family: 'ipv4', state: 'healthy', basis: 'direct' }]);
  assert.equal(partial[0].state, 'healthy');
  for (const c of partial.slice(1)) assert.equal(c.state, 'unknown');

  // two families: healthy + unknown is NOT healthy; failed beats degraded beats unknown beats healthy
  const two = chainChips([
    { stage: 'wan', family: 'ipv4', state: 'healthy', basis: 'direct' },
    { stage: 'wan', family: 'ipv6', state: 'unknown', basis: 'none' },
    { stage: 'dns', family: 'ipv4', state: 'degraded', basis: 'direct' },
    { stage: 'dns', family: 'ipv6', state: 'failed', basis: 'direct' },
    { stage: 'internet', family: 'ipv4', state: 'healthy', basis: 'direct' },
    { stage: 'internet', family: 'ipv6', state: 'healthy', basis: 'indirect' },
  ]);
  const by = Object.fromEntries(two.map(c => [c.stage, c]));
  assert.equal(by.wan.state, 'unknown');
  assert.equal(by.dns.state, 'failed');
  assert.equal(by.internet.state, 'healthy');
  assert.match(by.wan.detail, /IPv4/);
  assert.match(by.wan.detail, /IPv6/);
  // only not_applicable entries stay not applicable
  const na = chainChips([
    { stage: 'wan', family: 'ipv4', state: 'not_applicable', basis: 'none' },
    { stage: 'wan', family: 'ipv6', state: 'not_applicable', basis: 'none' },
  ]);
  assert.equal(na.find(c => c.stage === 'wan').state, 'not_applicable');
});

test('"healthy" without any basis is shown as unknown', () => {
  const chips = chainChips(chain(['healthy', 'healthy', 'healthy', 'healthy', 'healthy'], 'none'));
  for (const c of chips) assert.equal(c.state, 'unknown');
});

test('indirect evidence is marked, direct is not', () => {
  const chips = chainChips([
    { stage: 'router', family: 'ipv4', state: 'healthy', basis: 'indirect' },
    { stage: 'gateway', family: 'ipv4', state: 'healthy', basis: 'direct' },
  ]);
  assert.match(chips[0].detail ?? '', /indirekt/);
  assert.doesNotMatch(chips[1].detail ?? '', /indirekt/);
});

test('a point without a state is unknown, not healthy', () => {
  for (const p of [null, { state: null }, { state: 'bogus' }, { state: 'unknown', reason: 'no_data_yet' }]) {
    const v = pointStateView(p);
    assert.equal(v.tone, 'muted');
    assert.doesNotMatch(v.label, FORBIDDEN_FOR_UNKNOWN);
  }
  assert.equal(pointStateView({ state: 'problem' }).tone, 'critical');
  assert.equal(pointStateView({ state: 'ok' }).tone, 'ok');
  assert.match(pointStateView({ state: 'unknown', reason: 'no_data_yet' }).reasonText, /noch keine Daten/);
});

test('missing numbers are text, never 0 or a percent', () => {
  for (const bad of [null, undefined, Number.NaN, 'x', Infinity]) {
    assert.equal(formatMs(bad), 'k. A.');
    assert.equal(formatPct(bad), 'k. A.');
    assert.equal(formatCoverage(bad), 'k. A.');
  }
  assert.equal(formatMs(0), '0 ms'); // a real zero stays a zero
  assert.equal(formatMs(12.34), '12,3 ms');
  assert.equal(formatPct(0), '0 %');
  assert.equal(formatCoverage(0.5), '50 %');
});

// ── Score / coverage / module state ──────────────────────────────────────

test('the score is shown with its coverage; low coverage is never green', () => {
  const good = scoreView({ score: 93.4, coveragePct: 88, lowConfidence: false });
  assert.equal(good.value, '93');
  assert.equal(good.tone, 'ok');
  assert.match(good.coverageText, /88 %/);
  assert.equal(good.low, false);

  const low = scoreView({ score: 97, coveragePct: 30, lowConfidence: true });
  assert.equal(low.value, '97');
  assert.notEqual(low.tone, 'ok');
  assert.equal(low.low, true);
  assert.match(low.coverageText, /30 %/);
  assert.match(low.note, /Aussagekraft/);

  // low coverage even when the server forgot the flag
  assert.equal(scoreView({ score: 99, coveragePct: 20, lowConfidence: false }).low, true);
  // unknown flag counts as low
  assert.equal(scoreView({ score: 99, coveragePct: 90, lowConfidence: null }).low, true);

  for (const none of [null, { score: null, coveragePct: null, lowConfidence: true }]) {
    const v = scoreView(none);
    assert.equal(v.value, null);
    assert.equal(v.tone, 'muted');
    assert.match(v.text, /keine Bewertung/i);
    assert.match(v.coverageText, /unbekannt/);
  }
});

test('module state: off is "Aus", not_ready lists reasons, unknown is not ready', () => {
  assert.equal(moduleView('off', ['disabled']).label, 'Aus');
  assert.equal(moduleView('off', ['disabled']).tone, 'muted');
  const nr = moduleView('not_ready', ['core_unavailable', 'scheduler_not_running']);
  assert.equal(nr.tone, 'warn');
  assert.equal(nr.reasons.length, 2);
  assert.match(nr.reasons[0], /Core/);
  assert.equal(moduleView('ready', []).tone, 'ok');
  assert.equal(moduleView(null, []).tone, 'muted');
  assert.notEqual(moduleView(null, []).label, moduleView('ready', []).label);
});

// ── Parsing ──────────────────────────────────────────────────────────────

const OVERVIEW = {
  state: 'ready',
  reasons: [],
  enabled: true,
  fleet: {
    score: 91.2, score_coverage: 0.75, low_confidence: false, routers: 2, routers_scored: 2,
    routers_unknown: 0, coverage: 75, ha_state: 'ok', findings_active: 1,
    findings_by_classification: { wan_problem: 1 }, ha_latency_ms: 18.5, ha_loss_pct: 0.0,
    dns_ms: 22, ha_measured_at: 1_800_000_000,
  },
  routers: {
    rtr_aaaa11112222: {
      state: 'problem', reason: 'wan_problem', settling: false, score: { score: 60, coverage: 0.4, low_confidence: true, observation_seconds: 5000 },
      restarts_24h: 0,
      finding: {
        point_kind: 'router', router_id: 'rtr_aaaa11112222', classification: 'wan_problem', severity: 'critical',
        cause_class: 'probable', stage: 'wan', family: 'ipv4', underlying: null,
        summary: 'wan_problem', recommendation: 'check_wan_connection_and_provider', unmeasured_count: 1, is_change: false,
      },
      chain: chain(['healthy', 'healthy', 'failed', 'unknown', 'unknown']),
      down_interfaces: 1,
      gateway: { state: true, reason: 'healthy', family: 'ipv4' },
    },
    rtr_bbbb33334444: {
      state: 'unknown', reason: 'no_data_yet', settling: false, score: null, restarts_24h: 0,
      finding: null, chain: null, down_interfaces: 0, gateway: { state: null, reason: 'no_data_yet' },
    },
  },
  ha: { state: 'unknown', reason: 'no_measurement_yet', finding: null, chain: null },
  last_run: { ts: 1_800_000_100, probes: 3 },
};

test('overview is parsed from the real field names', () => {
  const o = parseOverview(OVERVIEW);
  assert.equal(o.state, 'ready');
  assert.equal(o.fleet.score, 91.2);
  assert.equal(o.fleet.coveragePct, 75);
  assert.equal(o.fleet.findingsActive, 1);
  assert.equal(o.routers.length, 2);
  const [a, b] = o.routers;
  assert.equal(a.id, 'rtr_aaaa11112222');
  assert.equal(a.finding.classification, 'wan_problem');
  assert.equal(a.finding.causeClass, 'probable');
  assert.equal(a.finding.unmeasuredCount, 1);
  assert.equal(a.score.lowConfidence, true);
  assert.equal(a.gateway.reachable, true);
  assert.equal(b.chain, null);
  assert.equal(b.gateway.reachable, null);
  assert.equal(o.ha.id, 'ha');
  assert.equal(o.ha.kind, 'ha');
  assert.equal(o.lastRun.ts, 1_800_000_100);
});

test('module off: state off, no fleet, no points', () => {
  const o = parseOverview({ state: 'off', reasons: ['disabled'], enabled: false, fleet: null, routers: null, ha: null, last_run: null });
  assert.equal(o.state, 'off');
  assert.equal(o.enabled, false);
  assert.equal(o.fleet, null);
  assert.deepEqual(o.routers, []);
  assert.equal(o.ha, null);
  assert.equal(o.lastRun, null);
});

test('garbage never becomes a number or a healthy state', () => {
  for (const junk of [null, undefined, 'x', 7, [], { state: 'weird', fleet: { score: '90', coverage: 'a', low_confidence: 'no' }, routers: [1, 2], ha: 'x', last_run: { ts: '5' } }]) {
    const o = parseOverview(junk);
    assert.equal(o.state, null);
    assert.deepEqual(o.routers, []);
    assert.equal(o.ha, null);
    assert.equal(o.lastRun === null || o.lastRun.ts === null, true);
    if (o.fleet) {
      assert.equal(o.fleet.score, null);
      assert.equal(o.fleet.coveragePct, null);
      assert.equal(o.fleet.lowConfidence, null);
    }
  }
});

test('the finding text maps the classification; unknown tokens stay unknown-styled', () => {
  const f = parseOverview(OVERVIEW).routers[0].finding;
  const v = findingView(f);
  assert.match(v.text, /WAN/);
  assert.equal(v.tone, 'critical');
  assert.equal(v.causeText, 'wahrscheinlich');
  assert.ok(v.recommendation);
  // no fault: no cause line
  const none = findingView({ classification: 'no_fault_detected', severity: 'ok', causeClass: 'unknown', summary: 'no_fault_detected' });
  assert.equal(none.tone, 'ok');
  assert.equal(none.causeText, null);
  // insufficient data is never green
  assert.notEqual(findingView({ classification: 'insufficient_data', severity: 'ok', causeClass: 'unknown' }).tone, 'ok');
  assert.notEqual(findingView({ classification: 'partially_measured', severity: 'info', causeClass: 'unknown' }).tone, 'ok');
  // an unknown token is shown as it came, muted
  const odd = findingView({ classification: 'brand_new_thing', severity: null, causeClass: 'strange' });
  assert.equal(odd.tone, 'muted');
  assert.equal(odd.text, 'brand_new_thing');
  assert.equal(findingView(null), null);
  // cause class unknown is shown as unknown
  assert.equal(findingView({ classification: 'dns_problem', severity: 'warning', causeClass: 'unknown' }).causeText, 'unbekannt');
  // dns_problem's delivered summary token is mapped too
  assert.match(findingView({ classification: 'dns_problem', summary: 'internet_access_restricted', severity: 'warning', causeClass: 'possible' }).text, /Internet/);
});

const HISTORY = {
  state: 'ready', reasons: [], windows: ['1h', '24h', '7d', '30d'], gaps: 2,
  series: [
    {
      point: 'ha', target_id: 'ref-web', kind: 'http', family: 'ipv4',
      windows: {
        '1h': { answered: 10, lost: 0, gaps: 0, expected: 12, coverage: 0.83, current_ms: 20, mean_ms: 21.5, min_ms: 18, max_ms: 40, jitter_ms: 2.2, loss_pct: 0.0, outliers: 0 },
        '24h': null,
        '7d': { answered: 0, lost: 0, gaps: 5, expected: 100, coverage: 0, current_ms: null, mean_ms: null, min_ms: null, max_ms: null, jitter_ms: null, loss_pct: null, outliers: 0 },
      },
    },
  ],
};

test('history rows: all four windows, missing values are k. A., a real 0 stays 0', () => {
  const h = parseHistory(HISTORY);
  assert.equal(h.series.length, 1);
  const rows = historyRows(h.series[0], h.windows);
  assert.deepEqual(rows.map(r => r.window), ['1h', '24h', '7d', '30d']);
  assert.equal(rows[0].latency, '21,5 ms');
  assert.equal(rows[0].loss, '0 %');
  assert.equal(rows[0].hasData, true);
  // null window and missing window: no data, no zeros
  for (const r of [rows[1], rows[3]]) {
    assert.equal(r.hasData, false);
    assert.equal(r.latency, 'k. A.');
    assert.equal(r.loss, 'k. A.');
    assert.equal(r.jitter, 'k. A.');
    assert.equal(r.gaps, 'k. A.');
  }
  // present window without answers: loss is unknown, not 0 %
  assert.equal(rows[2].loss, 'k. A.');
  assert.equal(rows[2].latency, 'k. A.');
});

test('history with the module off has no series (null), not an empty healthy list', () => {
  const h = parseHistory({ state: 'off', reasons: ['disabled'], series: null });
  assert.equal(h.state, 'off');
  assert.equal(h.series, null);
});

// ── Errors ───────────────────────────────────────────────────────────────

test('Retry-After is parsed strictly and shown as a wait time', () => {
  assert.equal(parseRetryAfter('30'), 30);
  assert.equal(parseRetryAfter(' 7 '), 7);
  for (const bad of [null, undefined, '', '-5', '1.5', 'soon', 'Wed, 21 Oct 2026 07:28:00 GMT', '999999']) {
    assert.equal(parseRetryAfter(bad), null, String(bad));
  }
  assert.equal(formatWait(1), '1 Sekunde');
  assert.equal(formatWait(45), '45 Sekunden');
  assert.equal(formatWait(60), '1 Minute');
  assert.equal(formatWait(61), '2 Minuten');
  assert.equal(formatWait(3600), '1 Stunde');
});

test('429 shows the wait time; without the header it says "später"', () => {
  const e = errorInfo(new DiagApiError(429, 'rate_limited', { reason: 'rate_limited', retryAfter: 90 }));
  assert.equal(e.kind, 'rate_limited');
  assert.equal(e.waitSeconds, 90);
  assert.match(e.message, /2 Minuten/);
  const none = errorInfo(new DiagApiError(429, 'rate_limited', {}));
  assert.equal(none.waitSeconds, null);
  assert.match(none.message, /später/);
});

test('409 / 422 / 503 / 403 map to plain texts, the server message is dropped', () => {
  const off = errorInfo(new DiagApiError(409, 'disabled', { state: 'off', reason: 'disabled' }));
  assert.equal(off.kind, 'disabled');
  assert.match(off.message, /ausgeschaltet/);
  assert.equal(errorInfo(new DiagApiError(409, 'busy', {})).kind, 'busy');
  assert.equal(errorInfo(new DiagApiError(409, 'conflict', {})).kind, 'conflict');

  const refused = errorInfo(new DiagApiError(422, 'refused', { reason: 'target.not_confirmed' }));
  assert.equal(refused.kind, 'refused');
  assert.match(refused.message, /abgelehnt/);
  assert.match(refused.message, /bestätigt/);
  // an unknown reason is not echoed
  const odd = errorInfo(new DiagApiError(422, 'refused', { reason: 'target.Evil<script>' }));
  assert.doesNotMatch(odd.message, /script/);

  assert.equal(errorInfo(new DiagApiError(503, 'not_running', {})).kind, 'unavailable');
  assert.equal(errorInfo(new DiagApiError(503, 'no_core', {})).kind, 'unavailable');
  assert.equal(errorInfo(new DiagApiError(403, 'authorization_denied', {})).kind, 'forbidden');
  assert.equal(errorInfo(new DiagApiError(401, '', {})).kind, 'session');
  assert.equal(errorInfo(new TypeError('Failed to fetch')).kind, 'network');
  assert.equal(errorInfo(new DiagApiError(500, 'internal', {})).kind, 'other');
});

// ── Admin gating ─────────────────────────────────────────────────────────

test('non-admins get no run and no settings controls', () => {
  const user = controlsFor(false);
  assert.equal(user.run, false);
  assert.equal(user.settings, false);
  assert.deepEqual(user.sections.map(s => s.id), ['overview', 'history']);
  const admin = controlsFor(true);
  assert.equal(admin.run, true);
  assert.equal(admin.settings, true);
  assert.deepEqual(admin.sections.map(s => s.id), ['overview', 'history', 'run', 'settings']);
  // only a strict true counts
  for (const v of [undefined, null, 1, 'true', {}]) {
    assert.equal(controlsFor(v).run, false);
    assert.equal(controlsFor(v).settings, false);
  }
});

// ── Manual run: IDs only ─────────────────────────────────────────────────

const SETTINGS_VIEW = {
  state: 'ready', reasons: [],
  settings: {
    enabled: true, periodic: false, interval_s: 300, targets: [
      { id: 'ref-web', kind: 'http', scope: 'external', confirmed: true, stage: null, port: 443 },
      { id: 'ref-dns', kind: 'dns', scope: 'external', confirmed: false, stage: null, port: null },
    ],
    internal_networks: ['192.0.2.0/24'], local_domains: [], dns_query_name: null, http_path: '/', ha_resolver_internal: false,
  },
  targets: [
    { id: 'ref-web', kind: 'http', scope: 'external', confirmed: true, usable: true, reason: 'ok' },
    { id: 'ref-dns', kind: 'dns', scope: 'external', confirmed: false, usable: false, reason: 'target.not_confirmed' },
    { id: 'ref-ping', kind: 'icmp', scope: 'external', confirmed: true, usable: false, reason: 'icmp_not_available_on_ha' },
  ],
  load: { ha: { periodic: false, probes_per_round: 0, packets_per_round: 0, rounds_per_day: 0.0, packets_per_day: 0.0, run_limit: { max_runs: 3, window_s: 600 } }, router: {} },
};

test('settings view parses without hosts and with target status', () => {
  const v = parseSettingsView(SETTINGS_VIEW);
  assert.equal(v.settings.enabled, true);
  assert.equal(v.settings.intervalS, 300);
  assert.equal(v.settings.internalNetworkCount, 1);
  assert.equal(v.settings.targets.length, 2);
  assert.equal('host' in v.settings.targets[0], false);
  assert.equal(v.targets.length, 3);
  assert.equal(v.load.runLimitMax, 3);
  assert.deepEqual(usableTargets(v.targets).map(t => t.id), ['ref-web']);
});

test('a run body contains configured, usable target IDs only', () => {
  const targets = parseSettingsView(SETTINGS_VIEW).targets;
  assert.deepEqual(buildRunBody(['ref-web'], targets), { ids: ['ref-web'], error: null });
  // empty selection
  assert.equal(buildRunBody([], targets).ids.length, 0);
  assert.ok(buildRunBody([], targets).error);
  // hosts / addresses / unknown ids / unusable ids are refused, never passed on
  for (const bad of ['192.0.2.10', 'example.org', 'https://example.org', 'ref-web x', 'unknown-id', 'ref-dns', 'ref-ping', '../x', '']) {
    const r = buildRunBody(['ref-web', bad], targets);
    assert.deepEqual(r.ids, [], `bad: ${bad}`);
    assert.ok(r.error, `bad: ${bad}`);
  }
  // duplicates collapse
  assert.deepEqual(buildRunBody(['ref-web', 'ref-web'], targets).ids, ['ref-web']);
  // limit
  const many = Array.from({ length: MAX_RUN_TARGETS + 1 }, (_, i) => ({ id: `t${i}`, kind: 'tcp', scope: 'external', confirmed: true, usable: true, reason: 'ok' }));
  assert.ok(buildRunBody(many.map(t => t.id), many).error);
});

test('run results parse; unknown outcomes and missing rtt are not green and not 0', () => {
  const r = parseRunResult({
    status: 'success', correlation_id: 'abc', error: null, probes: 2,
    refused: [{ id: 'ref-dns', reason: 'target.not_confirmed' }],
    results: [
      { target_id: 'ref-web', kind: 'http', family: 'ipv4', outcome: 'ok', rtt_ms: 21.4 },
      { target_id: 'ref-x', kind: 'tcp', family: null, outcome: 'timeout', rtt_ms: null },
    ],
    finding: { classification: 'no_fault_detected', severity: 'ok', cause_class: 'unknown', stage: null, family: null, unmeasured: ['dns'] },
  });
  assert.equal(r.status, 'success');
  assert.equal(r.probes, 2);
  assert.equal(r.refused[0].id, 'ref-dns');
  assert.equal(r.results[0].rttMs, 21.4);
  assert.equal(r.results[1].rttMs, null);
  assert.equal(r.finding.unmeasuredCount, 1);
  assert.equal(outcomeView('ok').tone, 'ok');
  assert.equal(outcomeView('timeout').tone, 'critical');
  for (const bad of [null, undefined, 'skipped', 'wat']) assert.notEqual(outcomeView(bad).tone, 'ok');
  assert.equal(parseRunResult(null).status, null);
});

// ── Settings form ────────────────────────────────────────────────────────

test('settings update carries only changed, valid fields the backend accepts', () => {
  const s = parseSettingsView(SETTINGS_VIEW).settings;
  const d = draftFromSettings(s);
  assert.deepEqual(d, { enabled: true, periodic: false, intervalS: '300', haResolverInternal: false });
  assert.deepEqual(buildSettingsUpdate(s, d), { update: {}, error: null });
  assert.deepEqual(buildSettingsUpdate(s, { ...d, enabled: false }).update, { enabled: false });
  assert.deepEqual(buildSettingsUpdate(s, { ...d, periodic: true, intervalS: '120' }).update, { periodic: true, interval_s: 120 });
  assert.deepEqual(buildSettingsUpdate(s, { ...d, haResolverInternal: true }).update, { ha_resolver_internal: true });
  for (const bad of ['59', '86401', 'abc', '1.5', '', '-1', '1e3']) {
    const r = buildSettingsUpdate(s, { ...d, intervalS: bad });
    assert.ok(r.error, bad);
    assert.deepEqual(r.update, {});
  }
  // no host-bearing key can be produced
  const keys = Object.keys(buildSettingsUpdate(s, { ...d, enabled: false, periodic: true, intervalS: '90', haResolverInternal: true }).update);
  assert.deepEqual(keys.sort(), ['enabled', 'ha_resolver_internal', 'interval_s', 'periodic']);
});
