// Tests of the Traffic Analytics settings form: logic and the HTTP client
// (node:test, fake fetch). Invented values only; no real router, no real
// Home Assistant.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TRAFFIC_BASE, createTrafficApi } from './trafficApi.ts';
import {
  CLIENT_SENSORS_MAX, TrafficApiError, buildSettingsUpdate, parseCollectorUsers, parseSettings, settingsDraft,
  settingsErrorText, toggleClientSensor, userLabel,
} from './trafficLogic.ts';
import * as S from './trafficSamples.mjs';

const view = (over) => parseSettings(S.settings(over));
const users = (sel) => parseCollectorUsers(S.collectorUsers(sel));

function hass(token = 'tok-1') {
  return {
    callApi: async () => { throw new Error('callApi not expected'); },
    user: { is_admin: true },
    auth: { data: { access_token: token } },
  };
}
const ok = body => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
const fail = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

// ── Parsing ──────────────────────────────────────────────────────────────

test('settings: router options read only, collector without any user id', () => {
  const v = view();
  assert.equal(v.routersEnabled, 1);
  assert.deepEqual(v.routers.map(r => [r.routerId, r.enabled, r.historyProfile]),
    [[S.RID1, true, 'compact'], [S.RID2, false, 'standard']]);
  assert.equal(v.clientSensorsMax, 20);
  assert.equal(v.writable, true);
  assert.deepEqual(v.collector, {
    enabled: false, userConfigured: false, state: 'off', schema: 'traffic.collector.v1',
    path: '/api/openwrt_topology/traffic/collector/ingest',
  });
  assert.equal(CLIENT_SENSORS_MAX, 20);
  // bad client refs and an out-of-range maximum are dropped
  const odd = view({ client_sensors: [S.CLI1, 'aa:bb:cc:dd:ee:ff', 5], client_sensors_max: 999 });
  assert.deepEqual(odd.clientSensors, [S.CLI1]);
  assert.equal(odd.clientSensorsMax, 20);
});

test('collector users: only usr_ references, names scrubbed and short', () => {
  const raw = S.collectorUsers(S.USR1);
  raw.users.push({ user_ref: 'a'.repeat(32), name: 'raw id', selected: false }, { user_ref: S.USR1.slice(0, -1), name: 'x' });
  raw.users[0].name = 'y'.repeat(200);
  const u = parseCollectorUsers(raw);
  assert.deepEqual(u.users.map(x => x.userRef), [S.USR1, S.USR2]);
  assert.equal(u.users[0].name.length, 64);
  assert.ok(!u.users[1].name.includes(S.PLANTED_MAC));
  assert.equal(u.selectedListed, true);
  assert.equal(userLabel({ userRef: S.USR1, name: '', selected: false }), 'Benutzer 555555');
});

// ── Draft and update ─────────────────────────────────────────────────────

test('the draft starts from what the server stored; no change sends nothing', () => {
  const v = view({ client_sensors: [S.CLI2, S.CLI1] });
  const u = users(S.USR1);
  const d = settingsDraft(v, u);
  assert.deepEqual(d, { collectorEnabled: false, userRef: S.USR1, clientSensors: [S.CLI1, S.CLI2].sort() });
  assert.deepEqual(buildSettingsUpdate(v, u, d), { update: {}, error: null });
});

test('switching the collector on needs a user; the reference is sent, never an id', () => {
  const v = view();
  const u = users(null);
  const d = { ...settingsDraft(v, u), collectorEnabled: true };
  assert.match(buildSettingsUpdate(v, u, d).error, /Benutzer/);
  assert.deepEqual(buildSettingsUpdate(v, u, { ...d, userRef: S.USR2 }),
    { update: { collector: { enabled: true, user_ref: S.USR2 } }, error: null });
  // a stored user (not in the list) may be switched on without choosing again
  const stored = view({ collector: { ...S.settings().collector, user_configured: true } });
  assert.deepEqual(buildSettingsUpdate(stored, u, d), { update: { collector: { enabled: true } }, error: null });
  // only a changed user is sent
  const sel = users(S.USR1);
  assert.deepEqual(buildSettingsUpdate(stored, sel, { ...settingsDraft(stored, sel), userRef: S.USR2 }).update,
    { collector: { user_ref: S.USR2 } });
});

test('client sensors: toggled, sorted, at most 20, the full list is sent', () => {
  const v = view();
  let d = settingsDraft(v, null);
  d = toggleClientSensor(d, S.CLI2, true);
  d = toggleClientSensor(d, S.CLI1, true);
  d = toggleClientSensor(d, 'aa:bb:cc:dd:ee:ff', true); // ignored
  assert.deepEqual(d.clientSensors, [S.CLI1, S.CLI2].sort());
  assert.deepEqual(buildSettingsUpdate(v, null, d).update, { client_sensors: [S.CLI1, S.CLI2].sort() });
  const many = Array.from({ length: 20 }, (_, i) => 'cli_' + i.toString(16).padStart(16, '0'));
  let full = { ...d, clientSensors: many };
  assert.equal(toggleClientSensor(full, S.CLI1, true), full); // the 21st is refused
  full = { ...full, clientSensors: [...many, S.CLI1] };
  assert.match(buildSettingsUpdate(v, null, full).error, /Höchstens 20/);
  // deselecting everything sends an empty list
  const stored = view({ client_sensors: [S.CLI1] });
  assert.deepEqual(buildSettingsUpdate(stored, null, { ...settingsDraft(stored, null), clientSensors: [] }).update,
    { client_sensors: [] });
});

test('route errors are explained and never read as saved', () => {
  const e = (status, reason, field = 'collector') => new TrafficApiError(status, 'x', { field, reason });
  assert.match(settingsErrorText(new TrafficApiError(409, 'disabled')), /^Nicht gespeichert: Traffic Analytics ist aus/);
  assert.match(settingsErrorText(e(400, 'user_is_admin')), /Administrator kann nicht/);
  assert.match(settingsErrorText(e(400, 'user_unknown')), /nicht \(mehr\) wählbar/);
  assert.match(settingsErrorText(e(400, 'collector_user_missing', 'settings')), /Benutzer/);
  assert.match(settingsErrorText(e(400, 'client_sensors_too_many', 'settings')), /Höchstens 20/);
  assert.match(settingsErrorText(e(400, 'something_new')), /nicht angenommen/);
  assert.match(settingsErrorText(new TrafficApiError(403, 'authorization_denied')), /Administrator/);
  assert.match(settingsErrorText(new TrafficApiError(413, 'body_too_large')), /zu groß/);
  assert.match(settingsErrorText(new TrafficApiError(503, 'not_running')), /^Nicht gespeichert: .*läuft gerade nicht/);
  assert.match(settingsErrorText(new TypeError('fetch failed')), /^Nicht gespeichert: .*keine Verbindung/);
});

// ── HTTP client ──────────────────────────────────────────────────────────

test('settings and collector users are GETs; the save is one POST with a JSON body', async () => {
  const calls = [];
  const api = createTrafficApi(() => hass(), {
    fetch: async (url, init) => {
      calls.push({ url: url.replace(TRAFFIC_BASE, ''), method: init.method, body: init.body, headers: init.headers });
      if (url.endsWith('/collector/users')) return ok(S.collectorUsers());
      return ok(S.settings({ client_sensors: [S.CLI1] }));
    },
  });
  await api.settings();
  await api.collectorUsers();
  const stored = await api.updateSettings({ collector: { enabled: true, user_ref: S.USR1 }, client_sensors: [S.CLI1] });
  assert.deepEqual(stored.clientSensors, [S.CLI1]); // the server's answer, not the request
  assert.deepEqual(calls.map(c => [c.method, c.url]), [['GET', '/settings'], ['GET', '/collector/users'], ['POST', '/settings']]);
  assert.equal(calls[0].body, undefined);
  assert.equal(calls[2].headers['Content-Type'], 'application/json');
  assert.equal(calls[2].headers.Authorization, 'Bearer tok-1');
  assert.deepEqual(JSON.parse(calls[2].body), { collector: { enabled: true, user_ref: S.USR1 }, client_sensors: [S.CLI1] });
});

test('a bad update is refused before any request; a route error is thrown with its reason', async () => {
  let called = 0;
  const api = createTrafficApi(() => hass(), {
    fetch: async () => { called += 1; return fail(400, { code: 'invalid_request', message: 'secret text', details: { field: 'collector', reason: 'user_is_admin' } }); },
  });
  for (const bad of [{}, { collector: { user_ref: 'a'.repeat(32) } }, { collector: { enabled: 'yes' } },
    { client_sensors: ['aa:bb:cc:dd:ee:ff'] }, { client_sensors: Array(21).fill(S.CLI1) }]) {
    await assert.rejects(() => api.updateSettings(bad), e => e instanceof TrafficApiError && e.status === 400);
  }
  assert.equal(called, 0);
  await assert.rejects(() => api.updateSettings({ collector: { enabled: false } }),
    e => e.status === 400 && e.details.reason === 'user_is_admin' && !e.message.includes('secret'));
  assert.equal(called, 1);
});

test('without a token the save falls back to hass.callApi POST with the body', async () => {
  const calls = [];
  const h = {
    callApi: async (method, path, body) => { calls.push({ method, path, body }); return S.settings(); },
    user: { is_admin: true },
  };
  await createTrafficApi(() => h).updateSettings({ client_sensors: [] });
  assert.deepEqual(calls, [{ method: 'POST', path: 'openwrt_topology/traffic/settings', body: { client_sensors: [] } }]);
});
