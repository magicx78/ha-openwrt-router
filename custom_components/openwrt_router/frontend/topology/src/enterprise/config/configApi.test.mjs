// Tests of the Configuration Manager HTTP client with a fake fetch (node:test).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CONFIG_BASE, configPaths, createConfigApi } from './configApi.ts';
import { ConfigApiError } from './configLogic.ts';
import { MOCK_SCENARIOS, createMockConfigApi } from './configMock.ts';
import { routerViewState } from './configLogic.ts';

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

test('paths encode every id and stay under the config prefix', () => {
  assert.equal(CONFIG_BASE, '/api/openwrt_topology/config');
  assert.equal(configPaths.router('rtr_a/../b'), 'routers/rtr_a%2F..%2Fb');
  assert.equal(configPaths.versions('rtr_1', { limit: 20, since: 'bkp_?&' }), 'routers/rtr_1/versions?limit=20&since=bkp_%3F%26');
  assert.equal(configPaths.versions('rtr_1'), 'routers/rtr_1/versions');
  assert.equal(configPaths.diff('r#1', 'bkp_1', 'live'), 'routers/r%231/diff?from=bkp_1&to=live');
  assert.equal(configPaths.driftAck('rtr_1', 'd/1'), 'routers/rtr_1/drift/d%2F1/ack');
  assert.equal(configPaths.sshPin('rtr_1', 'confirm'), 'routers/rtr_1/ssh-pin/confirm');
  assert.equal(configPaths.approvals('rtr 1'), 'approvals?router_id=rtr%201');
  assert.equal(configPaths.approvals(), 'approvals');
  assert.equal(configPaths.download('apr_1'), 'approvals/apr_1/download');
});

test('requests carry the bearer token, a JSON body and only go to the config prefix', async () => {
  const calls = [];
  const api = createConfigApi(() => hass(), {
    fetch: async (url, init) => { calls.push({ url, init }); return jsonResponse(200, { backup_id: 'bkp_1', created: true, status: 'ok' }); },
  });
  const r = await api.backup('rtr_1', '  Notiz\u0001 ');
  assert.deepEqual(r, { backupId: 'bkp_1', created: true, status: 'ok' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/openwrt_topology/config/routers/rtr_1/backup');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer tok-1');
  assert.equal(calls[0].init.body, JSON.stringify({ note: 'Notiz' }));
  assert.equal(calls[0].init.credentials, 'same-origin');
});

test('a 401 refreshes the token once and retries', async () => {
  let token = 'old';
  const h = hass(undefined, async () => { token = 'new'; });
  Object.defineProperty(h.auth, 'data', { get: () => ({ access_token: token }) });
  const seen = [];
  const api = createConfigApi(() => h, {
    fetch: async (_url, init) => {
      seen.push(init.headers.Authorization);
      return init.headers.Authorization === 'Bearer new'
        ? jsonResponse(200, { provider: 'config_manager', routers: [] })
        : jsonResponse(401, { message: 'expired' });
    },
  });
  const o = await api.overview();
  assert.deepEqual(seen, ['Bearer old', 'Bearer new']);
  assert.equal(o.provider, 'config_manager');
});

test('errors become ConfigApiError with code, retryable and Retry-After; never the server text', async () => {
  const api = createConfigApi(() => hass(), {
    fetch: async () => jsonResponse(409, { message: '<script>x</script>', code: 'operation_in_progress',
      error_class: 'busy', retryable: true }, { 'Retry-After': '30' }),
  });
  await assert.rejects(api.backup('rtr_1'), err => {
    assert.ok(err instanceof ConfigApiError);
    assert.equal(err.status, 409);
    assert.equal(err.code, 'operation_in_progress');
    assert.equal(err.retryable, true);
    assert.equal(err.retryAfter, 30);
    assert.ok(!err.message.includes('<script>'));
    return true;
  });
  const html = createConfigApi(() => hass(), { fetch: async () => new Response('<html>oops</html>', { status: 502 }) });
  await assert.rejects(html.overview(), err => err instanceof ConfigApiError && err.code === '' && err.status === 502);
});

test('download saves the blob under a safe name only after a 2xx answer', async () => {
  const saved = [];
  const api = createConfigApi(() => hass(), {
    fetch: async (url, init) => {
      assert.equal(url, '/api/openwrt_topology/config/approvals/apr_1/download');
      assert.equal(init.method, 'POST');
      return new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: {
        'Content-Type': 'application/gzip', 'Content-Disposition': 'attachment; filename="../ap 1.tar.gz"' } });
    },
    saveBlob: (blob, name) => saved.push({ size: blob.size, name }),
  });
  const r = await api.download('apr_1');
  assert.deepEqual(saved, [{ size: 3, name: 'ap_1.tar.gz' }]);
  assert.deepEqual(r, { filename: 'ap_1.tar.gz', sizeBytes: 3 });

  const failing = createConfigApi(() => hass(), {
    fetch: async () => jsonResponse(422, { code: 'backup_integrity_failed', retryable: false }),
    saveBlob: () => assert.fail('must not save on an error'),
  });
  await assert.rejects(failing.download('apr_1'), err => err.code === 'backup_integrity_failed');
});

test('download without an access token refuses instead of using callApi', async () => {
  const h = hass(undefined);
  h.auth = undefined;
  const api = createConfigApi(() => h, { fetch: async () => assert.fail('no fetch'), saveBlob: () => assert.fail('no save') });
  await assert.rejects(api.download('apr_1'), err => err instanceof ConfigApiError && err.code === 'no_token');
});

test('without hass every call fails with a ConfigApiError', async () => {
  const api = createConfigApi(() => null, { fetch: async () => assert.fail('no fetch') });
  await assert.rejects(api.overview(), err => err instanceof ConfigApiError && err.code === 'not_connected');
});

// ── Mock client (dev only) ────────────────────────────────────────────────

test('the mock overview shows every router state', async () => {
  const api = createMockConfigApi('default', { delayMs: 0 });
  const o = await api.overview();
  const states = new Set(o.routers.map(routerViewState));
  for (const s of ['ok', 'drift', 'disabled', 'never', 'failed', 'running', 'blocked']) assert.ok(states.has(s), s);
  // Every scenario answers or fails with a ConfigApiError.
  for (const name of MOCK_SCENARIOS) {
    const m = createMockConfigApi(name, { delayMs: 0 });
    try {
      assert.ok(Array.isArray((await m.overview()).routers), name);
    } catch (err) {
      assert.ok(err instanceof ConfigApiError, name);
    }
  }
});

test('mock export follows request → approve → download and refuses a second download', async () => {
  const saved = [];
  const api = createMockConfigApi('default', { delayMs: 0, saveBlob: (b, n) => saved.push(n) });
  const o = await api.overview();
  const rid = o.routers[0].routerId;
  const versions = await api.versions(rid);
  const a = await api.requestExport(versions[0].backupId, 'archive');
  assert.equal(a.status, 'pending');
  await assert.rejects(api.download(a.approvalId), err => err.code === 'approval_required');
  await api.approve(a.approvalId);
  await api.download(a.approvalId);
  assert.equal(saved.length, 1);
  await assert.rejects(api.download(a.approvalId), err => err.code === 'approval_invalid');
});
