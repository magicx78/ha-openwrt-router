// Tests of the WiFi Intelligence HTTP client with a fake fetch (node:test).
// Invented values only; no real router, no real Home Assistant.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WIFI_BASE, createWifiApi, wifiPaths } from './wifiApi.ts';
import { WifiApiError, errorInfo } from './wifiLogic.ts';
import * as S from './wifiSamples.mjs';

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

test('the routes are the six GET routes of the backend, nothing else', () => {
  assert.equal(WIFI_BASE, '/api/openwrt_router/enterprise/wifi');
  assert.deepEqual(Object.values(wifiPaths).sort(),
    ['channel_map', 'overview', 'radios', 'recommendations', 'roaming', 'timeline']);
  assert.ok(!Object.values(wifiPaths).some(p => /scan/.test(p)));
});

test('every request is a GET with the bearer token and no body', async () => {
  const calls = [];
  const api = createWifiApi(() => hass(), {
    fetch: async (url, init) => { calls.push({ url, init }); return jsonResponse(200, S.overviewReady()); },
  });
  for (const fn of ['overview', 'radios', 'channelMap', 'recommendations', 'roaming']) await api[fn]();
  await api.timeline({ window: '24h', series: 'noise' });
  assert.deepEqual(calls.map(c => c.url), [
    '/api/openwrt_router/enterprise/wifi/overview',
    '/api/openwrt_router/enterprise/wifi/radios',
    '/api/openwrt_router/enterprise/wifi/channel_map',
    '/api/openwrt_router/enterprise/wifi/recommendations',
    '/api/openwrt_router/enterprise/wifi/roaming',
    '/api/openwrt_router/enterprise/wifi/timeline?window=24h&series=noise',
  ]);
  for (const c of calls) {
    assert.equal(c.init.method, 'GET');
    assert.equal(c.init.body, undefined);
    assert.equal(c.init.headers.Authorization, 'Bearer tok-1');
    assert.equal(c.init.cache, 'no-store');
    assert.equal(c.init.credentials, 'same-origin');
  }
});

test('a bad timeline query never reaches the network', async () => {
  let called = 0;
  const api = createWifiApi(() => hass(), { fetch: async () => { called += 1; return jsonResponse(200, {}); } });
  for (const q of [{ window: '2h' }, { window: '1h', series: 'x' }, { window: '1h', radioId: '../a' }, { window: '1h', routerId: 'x' }]) {
    await assert.rejects(() => api.timeline(q), e => e instanceof WifiApiError && e.status === 400, JSON.stringify(q));
  }
  assert.equal(called, 0);
});

test('403 / 503 / 410 map through status and code; the server message is dropped', async () => {
  const make = (status, body) => createWifiApi(() => hass(), { fetch: async () => jsonResponse(status, body) });
  await assert.rejects(() => make(403, { code: 'authorization_denied', message: `no ${S.PLANTED_MAC}`, details: { reason: 'refused' } }).roaming(), e => {
    assert.ok(e instanceof WifiApiError);
    assert.equal(e.status, 403);
    assert.equal(e.details.reason, 'refused');
    assert.doesNotMatch(e.message, /02:00/);
    assert.match(errorInfo(e).message, /Admin nötig/);
    return true;
  });
  await assert.rejects(() => make(503, { code: 'no_core' }).roaming(), e => errorInfo(e).kind === 'unavailable');
  await assert.rejects(() => make(410, { code: 'integration_not_loaded' }).overview(), e => errorInfo(e).kind === 'unavailable');
  const broken = createWifiApi(() => hass(), { fetch: async () => new Response('<html>', { status: 502 }) });
  await assert.rejects(() => broken.overview(), e => e.status === 502 && e.code === '');
});

test('a network failure is "nicht erreichbar"', async () => {
  const api = createWifiApi(() => hass(), { fetch: async () => { throw new TypeError('Failed to fetch'); } });
  await assert.rejects(() => api.overview(), e => /nicht erreichbar/.test(errorInfo(e).message));
});

test('a 401 is retried once after a token refresh', async () => {
  const h = hass('old', async () => { h.auth.data.access_token = 'new'; });
  const seen = [];
  const api = createWifiApi(() => h, {
    fetch: async (url, init) => {
      seen.push(init.headers.Authorization);
      return init.headers.Authorization === 'Bearer old' ? jsonResponse(401, {}) : jsonResponse(200, S.radiosReady());
    },
  });
  const r = await api.radios();
  assert.equal(r.radios.length, 2);
  assert.deepEqual(seen, ['Bearer old', 'Bearer new']);
});

test('without a token the routes fall back to hass.callApi (GET), errors mapped', async () => {
  const calls = [];
  const h = {
    callApi: async (method, path, body) => {
      calls.push({ method, path, body });
      throw { status_code: 403, body: { code: 'authorization_denied' } };
    },
    user: { is_admin: false },
  };
  const api = createWifiApi(() => h);
  await assert.rejects(() => api.timeline({ window: '7d' }), e => e instanceof WifiApiError && e.status === 403);
  assert.deepEqual(calls[0], { method: 'GET', path: 'openwrt_router/enterprise/wifi/timeline?window=7d', body: undefined });
});

test('without hass the client says not connected, no request is made', async () => {
  let called = 0;
  const api = createWifiApi(() => null, { fetch: async () => { called += 1; return jsonResponse(200, {}); } });
  await assert.rejects(() => api.overview(), e => e instanceof WifiApiError && e.code === 'not_connected');
  assert.equal(called, 0);
});
