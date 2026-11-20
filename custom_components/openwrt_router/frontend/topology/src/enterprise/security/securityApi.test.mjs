// Tests of the Security Center HTTP client with a fake fetch (node:test).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SECURITY_BASE, createSecurityApi, overviewQuery, securityPaths } from './securityApi.ts';
import { SecurityApiError, errorInfo } from './securityLogic.ts';
import { MOCK_SCENARIOS, createMockSecurityApi } from './securityMock.ts';

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

const MAC = '02:00:00:00:00:01';

test('paths stay under the security prefix and encode the ids', () => {
  assert.equal(SECURITY_BASE, '/api/openwrt_topology/security');
  assert.equal(securityPaths.overview(), 'overview');
  assert.equal(securityPaths.detections(), 'detections');
  assert.equal(securityPaths.settings(), 'settings');
  assert.equal(securityPaths.incident('sec_ab-1_x'), 'incidents/sec_ab-1_x');
  assert.equal(securityPaths.incidentStatus('sec_ab'), 'incidents/sec_ab/status');
  assert.equal(securityPaths.deviceConfirm(MAC), 'devices/02%3A00%3A00%3A00%3A00%3A01/confirm');
  assert.equal(securityPaths.deviceName(MAC), 'devices/02%3A00%3A00%3A00%3A00%3A01/name');
});

test('the overview query carries only the backend filters and drops unusable values', () => {
  assert.equal(overviewQuery({}), '');
  assert.equal(
    overviewQuery({ since: 1700000000.9, until: 1700003600, routerId: 'rtr_ab12', client: 'cli_x_1', category: 'wifi', severity: 'warning', limit: 50 }),
    '?since=1700000000&until=1700003600&router_id=rtr_ab12&client=cli_x_1&category=wifi&severity=warning&limit=50',
  );
  assert.equal(overviewQuery({ client: MAC }), '?client=02%3A00%3A00%3A00%3A00%3A01');
  // unusable: not sent at all
  assert.equal(overviewQuery({ since: -1, until: Number.NaN, routerId: 'rtr 1&x=1', client: 'host.example.org', category: 'bogus', severity: 'high', limit: 9999 }), '');
  assert.equal(overviewQuery({ limit: 0 }), '');
  assert.equal(overviewQuery({ category: 'wifi&x=1' }), '');
});

test('requests carry the bearer token and only go to the security prefix', async () => {
  const calls = [];
  const api = createSecurityApi(() => hass(), {
    fetch: async (url, init) => { calls.push({ url, init }); return jsonResponse(200, { enabled: true, active: true, admin_view: true }); },
  });
  const o = await api.overview({ category: 'dns' });
  assert.equal(o.enabled, true);
  assert.equal(o.adminView, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/openwrt_topology/security/overview?category=dns');
  assert.equal(calls[0].init.method, 'GET');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer tok-1');
  assert.equal(calls[0].init.headers['Content-Type'], undefined);
  assert.equal(calls[0].init.body, undefined);
  assert.equal(calls[0].init.credentials, 'same-origin');
  assert.equal(calls[0].init.cache, 'no-store');
});

test('write routes send the documented JSON bodies', async () => {
  const calls = [];
  const api = createSecurityApi(() => hass(), {
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (url.endsWith('/status')) return jsonResponse(200, { incident: { id: 'sec_1', status: 'resolved' } });
      if (url.endsWith('/settings')) return jsonResponse(200, { settings: { enabled: true, log_path: 'syslog', syslog_port: 5514 }, can_edit: true, active: true });
      return jsonResponse(200, { ok: true });
    },
  });
  const inc = await api.setIncidentStatus('sec_1', 'resolved');
  assert.equal(inc.status, 'resolved');
  const s = await api.updateSettings({ enabled: true, log_path: 'syslog', syslog_port: 5514 });
  assert.equal(s.settings.logPath, 'syslog');
  await api.confirmDevice(MAC);
  await api.confirmDevice(MAC, 'Telefon');
  await api.setDeviceName(MAC, 'Drucker');
  await api.setDeviceName(MAC, null);
  assert.deepEqual(calls.map(c => [c.init.method, c.url.replace(SECURITY_BASE, ''), c.init.body]), [
    ['POST', '/incidents/sec_1/status', '{"status":"resolved"}'],
    ['POST', '/settings', '{"enabled":true,"log_path":"syslog","syslog_port":5514}'],
    ['POST', '/devices/02%3A00%3A00%3A00%3A00%3A01/confirm', '{}'],
    ['POST', '/devices/02%3A00%3A00%3A00%3A00%3A01/confirm', '{"name":"Telefon"}'],
    ['POST', '/devices/02%3A00%3A00%3A00%3A00%3A01/name', '{"name":"Drucker"}'],
    ['POST', '/devices/02%3A00%3A00%3A00%3A00%3A01/name', '{"name":null}'],
  ]);
  assert.equal(calls[0].init.headers['Content-Type'], 'application/json');
});

test('a pseudonym or a bad incident id is refused before any request is made', async () => {
  let calls = 0;
  const api = createSecurityApi(() => hass(), { fetch: async () => { calls += 1; return jsonResponse(200, {}); } });
  for (const run of [
    () => api.confirmDevice('cli_abc123'),
    () => api.setDeviceName('***', 'x'),
    () => api.setDeviceName('02:00:00:00:00:0G', 'x'),
    () => api.incident('inc_1'),
    () => api.incident('sec_../x'),
    () => api.setIncidentStatus('nope', 'open'),
  ]) {
    await assert.rejects(run, e => e instanceof SecurityApiError && e.status === 400 && e.code === 'invalid_request');
  }
  assert.equal(calls, 0);
});

test('a 401 refreshes the token once and retries', async () => {
  let token = 'old';
  const h = hass(undefined, async () => { token = 'new'; });
  Object.defineProperty(h.auth, 'data', { get: () => ({ access_token: token }) });
  const seen = [];
  const api = createSecurityApi(() => h, {
    fetch: async (_url, init) => {
      seen.push(init.headers.Authorization);
      return init.headers.Authorization === 'Bearer new' ? jsonResponse(200, { enabled: true }) : jsonResponse(401, { message: 'expired' });
    },
  });
  const o = await api.overview();
  assert.deepEqual(seen, ['Bearer old', 'Bearer new']);
  assert.equal(o.enabled, true);
});

test('a 401 that cannot be refreshed becomes a session error', async () => {
  const api = createSecurityApi(() => hass(), { fetch: async () => jsonResponse(401, {}) });
  await assert.rejects(api.overview(), e => errorInfo(e).kind === 'session');
});

test('errors keep status, code and field/reason tokens; never the server message', async () => {
  const api = createSecurityApi(() => hass(), {
    fetch: async () => jsonResponse(400, { message: '<script>x</script>', code: 'invalid_request', details: { field: 'syslog_port', reason: 'out_of_range', secret: 'x' } }),
  });
  await assert.rejects(api.updateSettings({ syslog_port: 80 }), e => {
    assert.ok(e instanceof SecurityApiError);
    assert.equal(e.status, 400);
    assert.equal(e.code, 'invalid_request');
    assert.deepEqual(e.details, { field: 'syslog_port', reason: 'out_of_range' });
    assert.doesNotMatch(e.message, /script/);
    assert.doesNotMatch(errorInfo(e).message, /script/);
    return true;
  });
});

test('the documented status codes map to the matching error kinds', async () => {
  const cases = [[403, 'authorization_denied', 'forbidden'], [404, 'unknown_incident', 'not_found'], [409, 'disabled', 'disabled'],
    [410, 'integration_not_loaded', 'gone'], [413, 'body_too_large', 'too_large'], [503, 'not_running', 'unavailable']];
  for (const [status, code, kind] of cases) {
    const api = createSecurityApi(() => hass(), { fetch: async () => jsonResponse(status, { message: 'm', code, details: {} }) });
    await assert.rejects(api.settings(), e => e.status === status && e.code === code && errorInfo(e).kind === kind, `${status}`);
  }
});

test('without a token the JSON routes fall back to hass.callApi (and map its errors)', async () => {
  const calls = [];
  const h = {
    callApi: async (method, path, body) => {
      calls.push([method, path, body]);
      if (path.endsWith('/detections')) throw { status_code: 503, body: { code: 'no_core', message: 'x', details: {} } };
      return { enabled: false };
    },
    user: { is_admin: false },
  };
  const api = createSecurityApi(() => h, { fetch: async () => { throw new Error('fetch not expected'); } });
  const o = await api.overview({ severity: 'critical' });
  assert.equal(o.enabled, false);
  assert.deepEqual(calls[0], ['GET', 'openwrt_topology/security/overview?severity=critical', undefined]);
  await assert.rejects(api.detections(), e => e instanceof SecurityApiError && e.status === 503 && e.code === 'no_core');
});

test('no hass yet is a retryable "not connected" error', async () => {
  const api = createSecurityApi(() => null, { fetch: async () => { throw new Error('no'); } });
  await assert.rejects(api.overview(), e => e instanceof SecurityApiError && e.code === 'not_connected');
});

// ── Dev mock: the real client on invented data ───────────────────────────

test('mock scenario default: score, coverage, findings, devices and detections parse', async () => {
  const api = createMockSecurityApi('default');
  const o = await api.overview();
  assert.equal(o.enabled, true);
  assert.equal(o.adminView, true);
  assert.equal(o.score.score, 78);
  assert.equal(o.score.factors.find(f => f.id === 'network_activity').deduction, null);
  assert.equal(o.incidents.length, 3);
  assert.equal(o.devices.find(d => d.state === 'suspicious').indicators.length, 2);
  assert.ok(o.detections.some(d => d.formatUnconfirmed));
  const d = await api.detections();
  assert.ok(Object.keys(d.sources).length === 2);
  const detail = await api.incident('sec_0001aa');
  assert.equal(detail.incident.linkedIncidentIds[0], 'inc_demo_roaming_1');
  assert.equal(detail.timeline.length, 2);
});

test('mock scenario empty: no rating possible and nothing counted as healthy', async () => {
  const o = await createMockSecurityApi('empty').overview();
  assert.equal(o.score.score, null);
  assert.equal(o.coverage.value, 0);
  assert.deepEqual(o.incidents, []);
});

test('mock scenario nonadmin: pseudonyms as sent, writes refused with 403', async () => {
  const api = createMockSecurityApi('nonadmin');
  const o = await api.overview();
  assert.equal(o.adminView, false);
  assert.ok(o.devices.every(d => d.mac.startsWith('cli_')));
  assert.ok(o.devices.every(d => d.name === null));
  await assert.rejects(api.setIncidentStatus('sec_0001aa', 'resolved'), e => e.status === 403);
  await assert.rejects(api.confirmDevice(MAC), e => e.status === 403);
  const s = await api.settings();
  assert.equal(s.canEdit, false);
});

test('mock scenario off: enabled false, then switched on by the settings route', async () => {
  const api = createMockSecurityApi('off');
  assert.equal((await api.overview()).enabled, false);
  const s = await api.updateSettings({ enabled: true });
  assert.equal(s.settings.enabled, true);
  assert.equal((await api.overview()).enabled, true);
});

test('mock filters work through the real query and admin actions change the data', async () => {
  const api = createMockSecurityApi('default');
  const crit = await api.overview({ severity: 'critical' });
  assert.deepEqual(crit.incidents.map(i => i.id), ['sec_0002bb']);
  assert.ok(crit.timeline.every(t => t.severity === 'critical'));
  await api.confirmDevice(MAC.replace('01', '02'), 'Demo Gerät');
  const o = await api.overview();
  const dev = o.devices.find(x => x.mac === '02:00:00:00:00:02');
  assert.equal(dev.state, 'known');
  assert.equal(dev.name, 'Demo Gerät');
});

test('every mock scenario name is accepted and the error scenarios map to their kinds', async () => {
  const kinds = { forbidden: 'forbidden', gone: 'gone', unavailable: 'unavailable' };
  for (const name of MOCK_SCENARIOS) {
    const api = createMockSecurityApi(name);
    if (kinds[name]) await assert.rejects(api.overview(), e => errorInfo(e).kind === kinds[name], name);
    else assert.equal(typeof (await api.overview()).enabled, 'boolean', name);
  }
});
