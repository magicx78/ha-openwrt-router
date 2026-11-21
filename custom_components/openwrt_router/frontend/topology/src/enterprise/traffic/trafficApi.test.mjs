// Tests of the Traffic Analytics HTTP client with a fake fetch (node:test).
// Invented values only; no real router, no real Home Assistant.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TRAFFIC_BASE, createTrafficApi, trafficPaths } from './trafficApi.ts';
import { TrafficApiError, errorInfo } from './trafficLogic.ts';
import * as S from './trafficSamples.mjs';

function hass(token = 'tok-1', refresh) {
  return {
    callApi: async () => { throw new Error('callApi not expected'); },
    user: { is_admin: true },
    auth: { data: { access_token: token }, refreshAccessToken: refresh },
  };
}

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

test('the routes are the read routes of the backend plus the settings and the collector users', () => {
  assert.equal(TRAFFIC_BASE, '/api/openwrt_topology/traffic');
  assert.deepEqual(Object.values(trafficPaths).sort(), [
    'anomalies', 'capacity', 'clients', 'collector/users', 'flows', 'overview', 'points', 'recommendations', 'series',
    'settings', 'talkers', 'vlans',
  ]);
});

test('every request is a GET with the bearer token and no body', async () => {
  const calls = [];
  const api = createTrafficApi(() => hass(), {
    fetch: async (url, init) => { calls.push({ url, init }); return jsonResponse(200, S.overviewReady()); },
  });
  for (const fn of ['overview', 'points', 'clients', 'vlans', 'capacity', 'anomalies', 'recommendations', 'flows']) await api[fn]();
  await api.series({ pointId: S.WAN1, window: '90d' });
  await api.talkers({ kind: 'peaks', scope: 'port', window: '7d', direction: 'upload', limit: 10 });
  assert.deepEqual(calls.map(c => c.url.replace(TRAFFIC_BASE, '')), [
    '/overview', '/points', '/clients', '/vlans', '/capacity', '/anomalies', '/recommendations', '/flows',
    `/series?point_id=${S.WAN1}&window=90d`,
    '/talkers?kind=peaks&scope=port&direction=upload&limit=10&window=7d',
  ]);
  for (const c of calls) {
    assert.equal(c.init.method, 'GET');
    assert.equal(c.init.body, undefined);
    assert.equal(c.init.headers.Authorization, 'Bearer tok-1');
    assert.equal(c.init.cache, 'no-store');
    assert.equal(c.init.credentials, 'same-origin');
  }
});

test('a bad query never reaches the network', async () => {
  let called = 0;
  const api = createTrafficApi(() => hass(), { fetch: async () => { called += 1; return jsonResponse(200, {}); } });
  await assert.rejects(() => api.series({ pointId: '../x', window: '1h' }), e => e instanceof TrafficApiError && e.status === 400);
  await assert.rejects(() => api.series({ pointId: S.WAN1, window: '5m' }), e => e instanceof TrafficApiError);
  await assert.rejects(() => api.talkers({ kind: 'window', scope: 'client', window: '1h', direction: 'x', limit: 5 }), TrafficApiError);
  assert.equal(called, 0);
});

test('403 / 503 / 410 map through status and code; the server message is dropped', async () => {
  const make = (status, body) => createTrafficApi(() => hass(), { fetch: async () => jsonResponse(status, body) });
  await assert.rejects(() => make(403, { code: 'forbidden', message: `no ${S.PLANTED_MAC}` }).flows(), e => {
    assert.ok(e instanceof TrafficApiError);
    assert.equal(e.status, 403);
    assert.doesNotMatch(e.message, /02:00/);
    assert.match(errorInfo(e).message, /Admin nötig/);
    return true;
  });
  await assert.rejects(() => make(503, { code: 'not_running' }).overview(), e => errorInfo(e).kind === 'unavailable');
  await assert.rejects(() => make(410, { code: 'integration_not_loaded' }).overview(), e => errorInfo(e).kind === 'unavailable');
  const broken = createTrafficApi(() => hass(), { fetch: async () => new Response('<html>', { status: 502 }) });
  await assert.rejects(() => broken.overview(), e => e.status === 502 && e.code === '');
});

test('a 401 is retried once after a token refresh', async () => {
  const h = hass('old', async () => { h.auth.data.access_token = 'new'; });
  const seen = [];
  const api = createTrafficApi(() => h, {
    fetch: async (url, init) => {
      seen.push(init.headers.Authorization);
      return init.headers.Authorization === 'Bearer old' ? jsonResponse(401, {}) : jsonResponse(200, S.clients());
    },
  });
  const r = await api.clients();
  assert.equal(r.clients.length, 1);
  assert.deepEqual(seen, ['Bearer old', 'Bearer new']);
});

test('without a token the routes fall back to hass.callApi (GET), errors mapped', async () => {
  const calls = [];
  const h = {
    callApi: async (method, path, body) => {
      calls.push({ method, path, body });
      throw { status_code: 403, body: { code: 'forbidden' } };
    },
    user: { is_admin: false },
  };
  const api = createTrafficApi(() => h);
  await assert.rejects(() => api.series({ pointId: S.WAN1, window: '7d' }), e => e instanceof TrafficApiError && e.status === 403);
  assert.deepEqual(calls[0], { method: 'GET', path: `openwrt_topology/traffic/series?point_id=${S.WAN1}&window=7d`, body: undefined });
});

test('without hass the client says not connected, no request is made', async () => {
  let called = 0;
  const api = createTrafficApi(() => null, { fetch: async () => { called += 1; return jsonResponse(200, {}); } });
  await assert.rejects(() => api.overview(), e => e instanceof TrafficApiError && e.code === 'not_connected');
  assert.equal(called, 0);
});
