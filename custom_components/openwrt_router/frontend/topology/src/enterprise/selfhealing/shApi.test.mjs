// Client of the "Self-Healing" tab (node:test): it only reads. Every request
// is a GET without a body to one of the five read routes of heal_views.py,
// and no file of the tab names another HTTP method, another route or a
// network call outside shApi.ts (source scan).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LIST_LIMIT, SH_BASE, createShApi } from './shApi.ts';
import { ShApiError } from './shLogic.ts';

const here = dirname(fileURLToPath(import.meta.url));
const F = JSON.parse(readFileSync(join(here, 'shFixture.json'), 'utf8'));
const ID_OPEN = F.detail_open.body.action.action_id;

function response(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

function world({ answers = {}, token = 'tok', refresh = true } = {}) {
  const calls = [];
  let refreshed = 0;
  const hass = {
    callApi: async (method, path) => { calls.push({ via: 'callApi', method, path }); return answers[path]?.body ?? {}; },
    auth: token === null ? undefined : {
      data: { access_token: token },
      refreshAccessToken: refresh ? async () => { refreshed += 1; } : undefined,
    },
  };
  const fetch = async (url, init) => {
    calls.push({ via: 'fetch', url, ...init });
    const path = url.slice(SH_BASE.length + 1);
    const queue = answers[path];
    const a = Array.isArray(queue) ? queue.shift() : queue;
    return response(a?.status ?? 200, a?.body ?? {});
  };
  return { api: createShApi(() => hass, { fetch }), calls, refreshed: () => refreshed };
}

test('the five calls are GET requests to the read routes, without a body', async () => {
  const w = world({
    answers: {
      overview: F.overview, [`actions?limit=${LIST_LIMIT}`]: F.actions, [`actions/${ID_OPEN}`]: F.detail_open,
      [`plans?action_id=${ID_OPEN}`]: F.plan_open, settings: F.settings,
    },
  });
  await w.api.overview();
  await w.api.actions();
  await w.api.action(ID_OPEN);
  const plan = await w.api.plan(ID_OPEN);
  await w.api.settings();
  assert.equal(plan.actionId, ID_OPEN);
  assert.deepEqual(w.calls.map(c => c.url), [
    `${SH_BASE}/overview`, `${SH_BASE}/actions?limit=200`, `${SH_BASE}/actions/${ID_OPEN}`,
    `${SH_BASE}/plans?action_id=${ID_OPEN}`, `${SH_BASE}/settings`,
  ]);
  for (const c of w.calls) {
    assert.equal(c.method, 'GET');
    assert.equal(c.body, undefined);
    assert.equal(c.credentials, 'same-origin');
    assert.equal(c.headers.Authorization, 'Bearer tok');
  }
  assert.equal(SH_BASE, '/api/openwrt_router/enterprise/selfhealing/v1');
});

test('a 401 is retried once after a token refresh, still as GET', async () => {
  const w = world({ answers: { overview: [{ status: 401, body: {} }, F.overview] } });
  const ov = await w.api.overview();
  assert.equal(ov.status, 'on');
  assert.equal(w.refreshed(), 1);
  assert.deepEqual(w.calls.map(c => c.method), ['GET', 'GET']);
});

test('without a token the request goes through hass.callApi, as GET', async () => {
  const w = world({ token: null, answers: { 'openwrt_router/enterprise/selfhealing/v1/overview': F.overview } });
  await w.api.overview();
  assert.deepEqual(w.calls, [{ via: 'callApi', method: 'GET', path: 'openwrt_router/enterprise/selfhealing/v1/overview' }]);
});

test('errors carry status and code only (the server message is dropped)', async () => {
  const w = world({ answers: { overview: F.user_overview_closed_panel, [`actions/${ID_OPEN}`]: F.unknown_action } });
  await assert.rejects(w.api.overview(), e => e instanceof ShApiError && e.status === 403 && e.code === 'authorization_denied');
  await assert.rejects(w.api.action(ID_OPEN), e => e instanceof ShApiError && e.status === 404 && e.code === 'unknown_action');
});

test('an id that is not a record id never reaches a URL', async () => {
  const w = world();
  for (const bad of ['../settings', 'rem_123', `${ID_OPEN}?x=1`, `${ID_OPEN}/approve`]) {
    await assert.rejects(w.api.action(bad), e => e instanceof ShApiError && e.code === 'invalid_action_id');
    await assert.rejects(w.api.plan(bad), e => e instanceof ShApiError && e.code === 'invalid_action_id');
  }
  assert.equal(w.calls.length, 0);
});

test('P2-1: a 200 without JSON or with the wrong shape is ShApiError(200, invalid_body)', async () => {
  const hass = { callApi: async () => ({}), auth: { data: { access_token: 'tok' } } };
  const answers = {
    overview: { ok: true, status: 200, json: async () => { throw new SyntaxError('Unexpected token <'); } },
    [`actions?limit=${LIST_LIMIT}`]: response(200, { total: 2, actions: 'x' }),
    [`actions/${ID_OPEN}`]: response(200, { action: { ...F.detail_open.body.action, action_id: `rem_${'f'.repeat(32)}` } }),
    [`plans?action_id=${ID_OPEN}`]: response(200, { plans: null }),
    settings: response(200, 'not an object'),
  };
  const api = createShApi(() => hass, { fetch: async url => answers[url.slice(SH_BASE.length + 1)] });
  const broken = field => e => e instanceof ShApiError && e.status === 200 && e.code === 'invalid_body' && e.details.field === field;
  await assert.rejects(api.overview(), broken('json'));
  await assert.rejects(api.actions(), broken('actions'));
  // an answer about another record is no answer about this one
  await assert.rejects(api.action(ID_OPEN), broken('action_id'));
  await assert.rejects(api.plan(ID_OPEN), broken('plans'));
  await assert.rejects(api.settings(), broken('body'));
  // through hass.callApi (no token) the status is unknown, the error the same
  const viaCall = createShApi(() => ({ callApi: async () => ({ actions: {} }) }));
  await assert.rejects(viaCall.actions(), e => e instanceof ShApiError && e.status === null && e.code === 'invalid_body');
});

test('P3-8: every request carries an AbortSignal, stops on abort and ends after the deadline', async () => {
  const hass = { callApi: async () => ({}), auth: { data: { access_token: 'tok' } } };
  const seen = [];
  const hang = (url, init) => { seen.push(init.signal); return new Promise(() => {}); };
  const slow = createShApi(() => hass, { fetch: hang, timeoutMs: 20 });
  await assert.rejects(slow.overview(), e => e instanceof ShApiError && e.status === null && e.code === 'timeout');
  assert.ok(seen[0] instanceof AbortSignal && seen[0].aborted, 'the request itself is aborted at the deadline');
  const api = createShApi(() => hass, { fetch: hang });
  const ctrl = new AbortController();
  const p = api.actions(ctrl.signal);
  ctrl.abort();
  await assert.rejects(p, e => e instanceof ShApiError && e.code === 'aborted');
  assert.ok(seen[1].aborted);
  // an already aborted signal sends nothing
  await assert.rejects(api.settings(ctrl.signal), e => e.code === 'aborted');
  assert.equal(seen.length, 2);
  // hass.callApi cannot be stopped: its late answer is dropped, the caller gets the timeout
  const viaCall = createShApi(() => ({ callApi: () => new Promise(() => {}) }), { timeoutMs: 20 });
  await assert.rejects(viaCall.overview(), e => e.code === 'timeout');
});

test('P3-8: the default deadline is 30 s (no other tab has one: DECIDED)', async () => {
  const src = readFileSync(join(here, 'shApi.ts'), 'utf8');
  assert.match(src, /const timeoutMs = deps\.timeoutMs \?\? REQUEST_TIMEOUT_MS;/);
  const { REQUEST_TIMEOUT_MS } = await import('./shLogic.ts');
  assert.equal(REQUEST_TIMEOUT_MS, 30_000);
});

// ── Source scan: the whole tab only reads ────────────────────────────────

const SOURCES = readdirSync(here).filter(f => /\.(ts|tsx)$/.test(f));
const src = Object.fromEntries(SOURCES.map(f => [f, readFileSync(join(here, f), 'utf8')]));
// comments may explain what the tab does NOT do; the scan looks at the code
const code = text => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');

test('no file of the tab names a writing HTTP method', () => {
  assert.ok(SOURCES.includes('shApi.ts') && SOURCES.includes('SelfHealingView.tsx') && SOURCES.length >= 7, SOURCES.join(','));
  for (const [f, text] of Object.entries(src)) {
    assert.doesNotMatch(code(text), /\b(POST|PUT|DELETE|PATCH)\b/, f);
    assert.doesNotMatch(code(text), /method:\s*['"](?!GET['"])/i, f);
    assert.doesNotMatch(code(text), /callApi(<[^>]*>)?\(\s*['"](?!GET['"])/, f);
    // a request body (JSON or a literal) is never built
    assert.doesNotMatch(code(text), /\bbody:\s*(JSON|[`'"{[])|JSON\.stringify/, f);
  }
});

test('only shApi.ts talks to the network, and only to the read routes', () => {
  for (const [f, text] of Object.entries(src)) {
    if (f === 'shApi.ts') continue;
    assert.doesNotMatch(code(text), /\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket|callApi\(|callService|callWS/, f);
  }
  const api = code(src['shApi.ts']);
  const paths = [...api.matchAll(/get\(\s*[`'"]([^`'"]+)[`'"]/g)].map(m => m[1]);
  assert.deepEqual(paths, ['overview', 'actions?limit=${LIST_LIMIT}', 'actions/${checkedId(id)}', 'plans?action_id=${checkedId(id)}', 'settings']);
  assert.doesNotMatch(api, /approve|execute|release|pause|resume|\/mode|reject|acknowledge/i);
});

// P3-9: the shared modules the tab imports (transitively, outside its folder) only read too
function importsOf(file) {
  const text = readFileSync(file, 'utf8');
  return [...code(text).matchAll(/^\s*import\s+(?!type\b)[^'"]*['"](\.{1,2}\/[^'"]+)['"]/gm)]
    .map(m => m[1]).filter(p => !/\.(css|json)(\?inline)?$/.test(p))
    .map(p => {
      const base = join(dirname(file), p);
      for (const cand of [base, `${base}.ts`, `${base}.tsx`]) { try { readFileSync(cand); return cand; } catch { /* next */ } }
      throw new Error(`unresolved ${p} in ${file}`);
    });
}

test('P3-9: the shared modules the tab imports name no writing method and no network call', () => {
  const seen = new Set();
  const queue = SOURCES.filter(f => !/\.test\./.test(f)).map(f => join(here, f));
  while (queue.length) {
    const f = queue.shift();
    if (seen.has(f)) continue;
    seen.add(f);
    queue.push(...importsOf(f));
  }
  const shared = [...seen].filter(f => !f.startsWith(here)).map(f => f.slice(join(here, '../..').length + 1)).sort();
  // pinned: if the tab starts to import another module, it has to be looked at (and added here)
  assert.deepEqual(shared, ['enterprise/registry.ts', 'enterprise/wifi/wifiLogic.ts', 'utils/format.ts']);
  for (const rel of shared) {
    const text = code(readFileSync(join(here, '../..', rel), 'utf8'));
    assert.doesNotMatch(text, /\b(POST|PUT|DELETE|PATCH)\b/, rel);
    assert.doesNotMatch(text, /\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket|callApi|callService|callWS|sendMessage/, rel);
  }
});

test('the markup has no control that changes anything', () => {
  const tsx = code(src['SelfHealingView.tsx']);
  // every button label in the source: refresh, details, retry and the list filters only
  const labels = [...tsx.matchAll(/<button[^>]*>\s*([^<{]*?)\s*(?:<|\{)/g)].map(m => m[1]).filter(Boolean);
  for (const l of labels) assert.ok(['Aktualisieren', 'Erneut versuchen'].includes(l), `button "${l}"`);
  assert.doesNotMatch(tsx, /<(form|input)\b/);
  assert.doesNotMatch(tsx, /onSubmit|type="submit"/);
  assert.doesNotMatch(tsx, /(Freigeben|Ausführen|Genehmigen|Ablehnen|Pausieren|Fortsetzen|Sperre aufheben|Modus ändern|Rollback starten)<\/button>/);
});
