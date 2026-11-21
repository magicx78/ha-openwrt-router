// Tests of the Network Diagnostics HTTP client with a fake fetch (node:test).
// Invented values only; no real device, no real Home Assistant.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DIAG_BASE, createDiagApi, diagPaths } from './diagnosticsApi.ts';
import { DiagApiError, errorInfo } from './diagnosticsLogic.ts';

function hass(token = 'tok-1', refresh) {
  return {
    callApi: async () => { throw new Error('callApi not expected'); },
    user: { is_admin: true },
    auth: { data: { access_token: token }, refreshAccessToken: refresh },
  };
}

function jsonResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

test('paths stay under the diagnostics prefix and carry no query or identity', () => {
  assert.equal(DIAG_BASE, '/api/openwrt_topology/diagnostics');
  assert.deepEqual(Object.values(diagPaths).sort(), ['history', 'overview', 'run', 'settings']);
  for (const p of Object.values(diagPaths)) assert.doesNotMatch(p, /[?&=]/);
});

test('requests carry the bearer token and only go to the diagnostics prefix', async () => {
  const calls = [];
  const api = createDiagApi(() => hass(), {
    fetch: async (url, init) => { calls.push({ url, init }); return jsonResponse(200, { state: 'off', reasons: ['disabled'], enabled: false, fleet: null, routers: null, ha: null, last_run: null }); },
  });
  const o = await api.overview();
  assert.equal(o.state, 'off');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/openwrt_topology/diagnostics/overview');
  assert.equal(calls[0].init.method, 'GET');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer tok-1');
  assert.equal(calls[0].init.headers['Content-Type'], undefined);
  assert.equal(calls[0].init.body, undefined);
  assert.equal(calls[0].init.credentials, 'same-origin');
  assert.equal(calls[0].init.cache, 'no-store');
});

test('a run posts configured target IDs only', async () => {
  const calls = [];
  const api = createDiagApi(() => hass(), {
    fetch: async (url, init) => { calls.push({ url, init }); return jsonResponse(200, { status: 'success', probes: 1, refused: [], results: [], finding: null }); },
  });
  const r = await api.run(['ref-web', 'ref-web', 'ref-dns']);
  assert.equal(r.status, 'success');
  assert.equal(calls[0].url, '/api/openwrt_topology/diagnostics/run');
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].init.body), { target_ids: ['ref-web', 'ref-dns'] });
  assert.equal(calls[0].init.headers['Content-Type'], 'application/json');
});

test('hosts, addresses and odd text never reach the network as a run target', async () => {
  let called = 0;
  const api = createDiagApi(() => hass(), { fetch: async () => { called += 1; return jsonResponse(200, {}); } });
  for (const bad of ['192.0.2.7', 'example.org', 'http://example.org', 'A_B', 'x y', '', '../a', 'a'.repeat(65)]) {
    await assert.rejects(() => api.run(['ref-web', bad]), e => e instanceof DiagApiError && e.status === 400, bad);
  }
  await assert.rejects(() => api.run([]), DiagApiError);
  await assert.rejects(() => api.run(Array.from({ length: 17 }, (_, i) => `t${i}`)), DiagApiError);
  assert.equal(called, 0);
});

test('settings update is a POST with the given body', async () => {
  const calls = [];
  const api = createDiagApi(() => hass(), {
    fetch: async (url, init) => { calls.push({ url, init }); return jsonResponse(200, { state: 'ready', reasons: [], settings: { enabled: true, interval_s: 120 }, targets: [], load: null }); },
  });
  const v = await api.updateSettings({ enabled: true, interval_s: 120 });
  assert.equal(v.settings.intervalS, 120);
  assert.equal(calls[0].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[0].init.body), { enabled: true, interval_s: 120 });
});

test('a 429 carries the Retry-After wait; the server message is dropped', async () => {
  const api = createDiagApi(() => hass(), {
    fetch: async () => jsonResponse(429, { message: 'Too many diagnoses; 192.0.2.55', code: 'rate_limited', details: { reason: 'rate_limited' } }, { 'Retry-After': '42' }),
  });
  await assert.rejects(() => api.run(['ref-web']), e => {
    assert.ok(e instanceof DiagApiError);
    assert.equal(e.status, 429);
    assert.equal(e.details.retryAfter, 42);
    assert.doesNotMatch(e.message, /192/);
    const info = errorInfo(e);
    assert.equal(info.waitSeconds, 42);
    assert.match(info.message, /42 Sekunden/);
    return true;
  });
  // a broken header: no wait time
  const api2 = createDiagApi(() => hass(), {
    fetch: async () => jsonResponse(429, { code: 'rate_limited' }, { 'Retry-After': 'soon' }),
  });
  await assert.rejects(() => api2.run(['ref-web']), e => e.details.retryAfter === null);
});

test('409 off, 422 refused and 503 map through status, code and state', async () => {
  const make = (status, body) => createDiagApi(() => hass(), { fetch: async () => jsonResponse(status, body) });
  await assert.rejects(() => make(409, { code: 'disabled', state: 'off', details: { reason: 'disabled' } }).run(['a']), e => {
    assert.equal(e.details.state, 'off');
    assert.equal(errorInfo(e).kind, 'disabled');
    return true;
  });
  await assert.rejects(() => make(422, { code: 'refused', details: { reason: 'target.not_confirmed' } }).run(['a']), e => errorInfo(e).kind === 'refused');
  await assert.rejects(() => make(503, { code: 'not_running' }).overview(), e => errorInfo(e).kind === 'unavailable');
  await assert.rejects(() => make(403, { code: 'authorization_denied' }).settings(), e => errorInfo(e).kind === 'forbidden');
  // a body that is not JSON still gives a status-only error
  const broken = createDiagApi(() => hass(), { fetch: async () => new Response('<html>', { status: 502 }) });
  await assert.rejects(() => broken.overview(), e => e.status === 502 && e.code === '');
});

test('a 401 is retried once after a token refresh', async () => {
  let token = 'old';
  const h = hass('old', async () => { token = 'new'; h.auth.data.access_token = 'new'; });
  const seen = [];
  const api = createDiagApi(() => h, {
    fetch: async (url, init) => {
      seen.push(init.headers.Authorization);
      return init.headers.Authorization === 'Bearer old' ? jsonResponse(401, {}) : jsonResponse(200, { state: 'ready', reasons: [] });
    },
  });
  const o = await api.history();
  assert.equal(o.state, 'ready');
  assert.deepEqual(seen, ['Bearer old', 'Bearer new']);
  assert.equal(token, 'new');
});

test('without a token the JSON routes fall back to hass.callApi, and its errors are mapped', async () => {
  const calls = [];
  const h = {
    callApi: async (method, path, body) => {
      calls.push({ method, path, body });
      throw { status_code: 409, body: { code: 'disabled', state: 'off' } };
    },
    user: { is_admin: true },
  };
  const api = createDiagApi(() => h);
  await assert.rejects(() => api.run(['ref-web']), e => e instanceof DiagApiError && e.status === 409 && e.details.state === 'off');
  assert.deepEqual(calls[0], { method: 'POST', path: 'openwrt_topology/diagnostics/run', body: { target_ids: ['ref-web'] } });
});

test('without hass the client says not connected, no request is made', async () => {
  let called = 0;
  const api = createDiagApi(() => null, { fetch: async () => { called += 1; return jsonResponse(200, {}); } });
  await assert.rejects(() => api.overview(), e => e instanceof DiagApiError && e.code === 'not_connected');
  assert.equal(called, 0);
});
