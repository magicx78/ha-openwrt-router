/**
 * configMock.ts — DEV ONLY mock backend of the config routes (?configmock).
 *
 * A fake fetch answers the routes R1–R20 from in-memory sample data, and the
 * REAL client (createConfigApi) runs on top of it, so paths, parsers and
 * error mapping are exercised as in production. main.tsx loads this file
 * only behind `import.meta.env.DEV`, so it is not part of the built bundle.
 *
 * Scenarios (?configmock=<name>): default, empty, forbidden, gone,
 * unavailable, conflict, slow. All data is invented: no real hosts, keys or
 * addresses.
 */

import { createConfigApi } from './configApi.ts';
import type { ConfigApi, ConfigHass } from './configTypes';

export const MOCK_SCENARIOS = ['default', 'empty', 'forbidden', 'gone', 'unavailable', 'conflict', 'slow'] as const;
export type MockScenario = (typeof MOCK_SCENARIOS)[number];

export const MOCK_HASS: ConfigHass = {
  callApi: () => Promise.reject(new Error('mock: callApi not used')),
  user: { is_admin: true },
  auth: { data: { access_token: 'mock-token' } },
};

type Json = Record<string, unknown>;

const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;
const iso = (t: number) => new Date(t).toISOString();
const hex = (seed: string, len: number) => seed.repeat(Math.ceil(len / seed.length)).slice(0, len);
const rid = (seed: string) => `rtr_${hex(seed, 32)}`;

interface MockRouter {
  summary: Json;
  detail: Json;
  versions: Json[];
  drift: Json;
  /** Polls left until a running backup finishes. */
  runningPolls: number;
}

function version(routerId: string, n: number, at: number, over: Json = {}): Json {
  const type = (over.backup_type as string | undefined) ?? 'full_archive';
  const artifacts = type === 'uci_snapshot'
    ? [{ kind: 'uci', size_bytes: 18_400 + n * 37, sha256: hex(`${n}c`, 64) }]
    : [
        { kind: 'archive', size_bytes: 41_234 + n * 211, sha256: hex(`${n}a`, 64) },
        { kind: 'uci', size_bytes: 18_400 + n * 37, sha256: hex(`${n}b`, 64) },
        { kind: 'inventory', size_bytes: 6_100, sha256: hex(`${n}d`, 64) },
      ];
  return {
    backup_id: `bkp_${hex(`${routerId.slice(4, 6)}${n.toString(16)}`, 32)}`,
    router_id: routerId,
    created_at: iso(at),
    last_seen_at: iso(at),
    reason: 'scheduled',
    backup_type: type,
    status: 'ok',
    protected: false,
    created_by: { kind: 'module', mine: false },
    openwrt_version: '24.10.0',
    validation: { state: 'unverified', checked_at: null },
    warnings: [],
    note: null,
    artifacts,
    ...over,
  };
}

function buildRouters(now: number): MockRouter[] {
  const cap = (state: string, reason: string | null) => ({ state, reason });
  const caps = (archive: boolean, cgi = archive) => ({
    'config.backup': cap('available', 'ok'),
    'config.cgi_backup': cgi ? cap('available', 'ok') : cap('unavailable', 'permission_denied'),
    'config.ssh_root': archive && !cgi ? cap('available', 'ok') : cap('unavailable', 'transport_unsupported'),
    'config.uci_read': cap('available', 'ok'),
    'config.packagelist': cap('available', 'ok'),
    'config.restore': cap('unavailable', 'provider_declined'),
  });
  const clean = (at: number) => ({ state: 'clean', drift_id: null, critical_count: 0, unknown_count: 0, checked_at: iso(at) });
  const schedule = (next: number) => ({ mode: 'daily', time: '03:30', next_run_at: iso(next) });
  const tomorrow = now + 15 * HOUR;

  const gw = rid('a1');
  const gwVersions = Array.from({ length: 12 }, (_, i) => version(gw, 12 - i, now - (i * 2.5 + 0.4) * DAY));
  gwVersions[0] = { ...gwVersions[0], validation: { state: 'valid', checked_at: iso(now - 3 * HOUR) } };
  gwVersions[1] = { ...gwVersions[1], reason: 'manual', note: 'Vor dem Firmware-Update', protected: true,
    created_by: { kind: 'user', mine: true } };
  gwVersions[2] = { ...gwVersions[2], reason: 'drift', backup_type: 'uci_snapshot',
    artifacts: [{ kind: 'uci', size_bytes: 18_900, sha256: hex('9e', 64) }] };
  gwVersions[4] = { ...gwVersions[4], status: 'partial', warnings: ['uci_missing'] };
  gwVersions[6] = { ...gwVersions[6], validation: { state: 'corrupt', checked_at: iso(now - 9 * DAY) } };
  gwVersions[11] = { ...gwVersions[11], openwrt_version: '23.05.3', reason: 'release_change' };

  const ap = (seed: string, name: string, over: Partial<MockRouter> & { summary?: Json } = {}): MockRouter => {
    const id = rid(seed);
    const versions = over.versions ?? Array.from({ length: 5 }, (_, i) => version(id, 5 - i, now - (i + 0.4) * DAY));
    return {
      summary: {
        router_id: id, name, enabled: true, status: 'ok', error_class: null, running: false,
        last_backup_at: versions[0]?.created_at ?? null, versions: versions.length,
        capability: cap('available', null), schedule: schedule(tomorrow + 600_000), drift: clean(now - 2 * HOUR),
        openwrt_version: '24.10.0', ...over.summary,
      },
      detail: {
        router_id: id, enabled: true, capabilities: caps(true),
        ssh_pin: { state: 'confirmed', fingerprint: `SHA256:${hex('Mock', 43)}` },
        acl: { offerable: [], deployed_version: 9 }, ...over.detail,
      },
      versions,
      drift: over.drift ?? { state: 'clean', report: null, acks: [] },
      runningPolls: over.runningPolls ?? 0,
    };
  };

  const garten = rid('f6');
  return [
    {
      summary: {
        router_id: gw, name: 'Gateway', enabled: true, status: 'ok', error_class: null, running: false,
        last_backup_at: gwVersions[0].created_at, versions: gwVersions.length,
        capability: cap('available', null), schedule: schedule(tomorrow),
        drift: { state: 'open', drift_id: 'drf_mock_0001', critical_count: 1, unknown_count: 1, checked_at: iso(now - 50 * 60_000) },
        openwrt_version: '24.10.0',
      },
      detail: {
        router_id: gw, enabled: true, capabilities: caps(true),
        ssh_pin: { state: 'confirmed', fingerprint: `SHA256:${hex('GwKey', 43)}` },
        acl: { offerable: [], deployed_version: 9 },
      },
      versions: gwVersions,
      drift: {
        state: 'open',
        report: { drift_id: 'drf_mock_0001', checked_at: iso(now - 50 * 60_000), baseline_backup_id: gwVersions[0].backup_id,
          critical_count: 1, unknown_count: 1, comparison: 'complete' },
        acks: [],
      },
      runningPolls: 0,
    },
    ap('b2', 'AP Flur'),
    ap('c3', 'AP Keller', { summary: { enabled: false, status: 'disabled', capability: cap('unavailable', 'disabled'),
      schedule: { mode: 'off', time: null, next_run_at: null }, drift: null }, detail: { enabled: false } }),
    ap('d4', 'AP Garage', {
      versions: [],
      summary: { status: 'never', last_backup_at: null, capability: cap('unknown', 'not_probed'), drift: null },
      detail: { ssh_pin: { state: 'pending', fingerprint: `SHA256:${hex('NewKey', 43)}` },
        capabilities: { 'config.backup': cap('unknown', 'not_probed'), 'config.cgi_backup': cap('unknown', 'not_probed'),
          'config.ssh_root': cap('unknown', 'ssh_pin_pending'), 'config.uci_read': cap('unknown', 'not_probed') } },
    }),
    ap('e5', 'AP Büro', { summary: { status: 'failed', error_class: 'network', openwrt_version: '23.05.5' },
      detail: { ssh_pin: { state: 'mismatch', fingerprint: `SHA256:${hex('Other', 43)}` } } }),
    ap('a7', 'AP Dach', { summary: { running: true, status: 'running' }, runningPolls: 2 }),
    ap('f6', 'AP Garten', {
      versions: [version(garten, 2, now - 0.5 * DAY, { backup_type: 'uci_snapshot' }),
        version(garten, 1, now - 1.5 * DAY, { backup_type: 'uci_snapshot' })],
      summary: { capability: cap('unavailable', 'permission_denied'), openwrt_version: '24.10.1' },
      detail: { capabilities: { ...caps(false), 'config.backup': cap('unavailable', 'permission_denied') },
        acl: { offerable: ['config_backup_read'], deployed_version: 8 } },
    }),
  ];
}

const DIFF_CHANGES: Json[] = [
  { area: 'wlan', risk: 'high', config: 'wireless', section: 'default_radio0', option: 'key', op: 'changed', old: '***', new: '***', secret: true },
  { area: 'mgmt_ip', risk: 'critical', config: 'network', section: 'lan', option: 'ipaddr', op: 'changed', old: '192.0.2.1', new: '192.0.2.2' },
  { area: 'firewall', risk: 'high', config: 'firewall', section: 'cfg0e92bd', option: null, op: 'added', old: null, new: { name: 'Allow-Mock', target: 'ACCEPT' } },
  { area: 'vlan', risk: 'high', config: 'network', section: 'vlan_iot', option: null, op: 'removed', old: { vid: '30' }, new: null },
  { area: 'ssh', risk: 'high', config: 'dropbear', section: 'main', option: 'Port', op: 'changed', old: '22', new: '2222' },
  { area: 'dhcp', risk: 'low', config: 'dhcp', section: 'lan', option: 'leasetime', op: 'changed', old: '12h', new: '24h' },
  { area: 'system', risk: 'low', config: 'system', section: 'cfg01e48a', option: 'zonename', op: 'changed', old: 'UTC', new: 'Europe/Berlin' },
  { area: 'other', risk: null, config: 'luci', section: 'main', option: 'mediaurlbase', op: 'changed', old: '/a', new: '/b' },
  { area: 'wlan', risk: 'medium', config: 'wireless', section: 'radio1', option: 'channel', op: 'changed', old: '36', new: '44' },
];

function respond(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers },
  });
}

const fail = (status: number, code: string, retryable = false, details?: Json, headers?: Record<string, string>) =>
  respond(status, { message: `mock ${code}`, code, error_class: 'mock', retryable, ...(details ? { details } : {}) }, headers);

function createMockFetch(scenario: MockScenario, delayMs: number) {
  const now = () => Date.now();
  const routers = scenario === 'empty' ? [] : buildRouters(now());
  const approvals = new Map<string, Json>();
  let seq = 0;
  const byId = (id: string) => routers.find(r => r.summary.router_id === id);
  const findVersion = (bid: string) => {
    for (const r of routers) {
      const v = r.versions.find(x => x.backup_id === bid);
      if (v) return { r, v };
    }
    return null;
  };
  const newApproval = (action: string, routerId: string, subject: string | null): Json => {
    seq += 1;
    const a = { approval_id: `apr_${hex(seq.toString(16).padStart(2, '0'), 32)}`, action, router_id: routerId,
      subject_id: subject, status: 'pending', requested_by: { kind: 'user', mine: true }, expires_at: iso(now() + 15 * 60_000) };
    approvals.set(a.approval_id, a);
    return a;
  };
  const readOnly = scenario === 'conflict';

  function route(method: string, path: string, body: Json): Response {
    if (scenario === 'forbidden') return fail(403, 'authorization_denied');
    if (scenario === 'gone') return fail(410, 'not_loaded');
    if (scenario === 'unavailable') return fail(503, 'core_not_running', true);
    if (readOnly && method === 'POST') return fail(409, 'provider_conflict');
    const [p, qs] = path.split('?');
    const q = new URLSearchParams(qs ?? '');
    const seg = p.split('/').map(decodeURIComponent);

    if (method === 'GET' && p === 'overview') {
      for (const r of routers) {
        if (r.runningPolls > 0 && --r.runningPolls === 0) {
          r.summary = { ...r.summary, running: false, status: 'ok', last_backup_at: iso(now()) };
        }
      }
      return respond(200, {
        provider: readOnly ? 'fremdes_modul' : 'config_manager',
        pending_approvals: [...approvals.values()].filter(a => a.status === 'pending').length,
        routers: routers.map(r => r.summary),
      });
    }
    if (seg[0] === 'routers') {
      const r = byId(seg[1]);
      if (!r) return fail(404, 'router_not_found');
      const enabled = r.summary.enabled === true;
      const sub = seg.slice(2).join('/');
      if (method === 'GET' && sub === '') return respond(200, r.detail);
      if (method === 'GET' && sub === 'versions') {
        const limit = Number(q.get('limit') ?? 50);
        return respond(200, { versions: r.versions.slice(0, limit) });
      }
      if (method === 'GET' && sub === 'drift') return respond(200, r.drift);
      if (method === 'GET' && sub === 'diff') {
        if (!q.get('from') || !q.get('to')) return fail(400, 'invalid_request');
        const changes = q.get('to') === 'live' || q.get('from') === r.versions[r.versions.length - 1]?.backup_id ? DIFF_CHANGES : DIFF_CHANGES.slice(5);
        return respond(200, { from: q.get('from'), to: q.get('to'), complete: true, changes });
      }
      if (!enabled) return fail(409, 'capability_unavailable', false, { state: 'unavailable', reason: 'disabled' });
      if (method === 'POST' && sub === 'backup') {
        if (r.summary.running) return fail(409, 'operation_in_progress', true, undefined, { 'Retry-After': '30' });
        if (r.summary.capability && (r.summary.capability as Json).state === 'unavailable') {
          return fail(409, 'capability_unavailable', false, { state: 'unavailable', reason: 'permission_denied' });
        }
        const v = version(r.summary.router_id as string, 100 + seq++, now(), {
          reason: 'manual', note: typeof body.note === 'string' ? body.note : null, created_by: { kind: 'user', mine: true } });
        r.versions = [v, ...r.versions];
        r.summary = { ...r.summary, versions: r.versions.length, last_backup_at: v.created_at, status: 'ok' };
        return respond(200, { backup_id: v.backup_id, created: true, status: 'ok' });
      }
      if (method === 'POST' && sub === 'drift/check') {
        const report = { drift_id: 'drf_mock_0002', checked_at: iso(now()), baseline_backup_id: r.versions[0]?.backup_id ?? null,
          critical_count: 1, unknown_count: 0, comparison: 'complete' };
        r.drift = { state: 'open', report, acks: [] };
        r.summary = { ...r.summary, drift: { state: 'open', drift_id: report.drift_id, critical_count: 1, unknown_count: 0, checked_at: report.checked_at } };
        return respond(200, r.drift);
      }
      if (method === 'POST' && seg[2] === 'drift' && seg[4] === 'ack') {
        const state = body.state === 'known' ? 'known' : 'acknowledged';
        r.drift = { ...r.drift, state, acks: [{ drift_id: seg[3], state, at: iso(now()), by: { kind: 'user', mine: true } }] };
        r.summary = { ...r.summary, drift: { ...(r.summary.drift as Json), state } };
        return respond(200, r.drift);
      }
      if (method === 'POST' && sub === 'acl-offer') {
        const a = newApproval('acl_deploy', r.summary.router_id as string, 'config_backup_read');
        return respond(200, { ...a, offer: {
          added: ['cgi-io: backup', 'rpc-sys: packagelist', 'uci: read (14 Konfigurationen)'],
          removed: [],
          risks: ['Das Archiv enthält alle Router-Geheimnisse.', 'rpcd wird einmal neu gestartet.'],
          target_file: '/usr/share/rpcd/acl.d/ha-openwrt-router.json',
          rights_added: ['cgi-io: backup', 'rpc-sys: packagelist'],
          rights_removed: [],
          rights_unlisted: 1,
          risk_text: 'MOCK RISK: the backup archive contains all router secrets in plain text.',
          rollback_text: 'MOCK ROLLBACK: copy the saved file back and restart rpcd.',
          rollback_template: 'cp /usr/share/rpcd/acl.d/ha-openwrt-router.json.bak-<timestamp> /usr/share/rpcd/acl.d/ha-openwrt-router.json && /etc/init.d/rpcd restart',
          rollback_template_no_previous: 'rm /usr/share/rpcd/acl.d/ha-openwrt-router.json && /etc/init.d/rpcd restart',
        } });
      }
      if (method === 'POST' && seg[2] === 'ssh-pin' && (seg[3] === 'confirm' || seg[3] === 'reset')) {
        return respond(200, newApproval(`ssh_pin_${seg[3]}`, r.summary.router_id as string, null));
      }
      return fail(404, 'not_found');
    }
    if (seg[0] === 'versions') {
      const found = findVersion(seg[1]);
      if (!found) return fail(404, 'backup_not_found');
      const { r, v } = found;
      const replace = (nv: Json) => { r.versions = r.versions.map(x => (x.backup_id === v.backup_id ? nv : x)); return nv; };
      if (method === 'GET' && seg.length === 2) return respond(200, v);
      if (method === 'POST' && seg[2] === 'validate') {
        const state = (v.validation as Json).state === 'corrupt' ? 'corrupt' : 'valid';
        return respond(200, replace({ ...v, validation: { state, checked_at: iso(now()) } }));
      }
      if (method === 'POST' && seg[2] === 'protect') return respond(200, replace({ ...v, protected: body.protected === true }));
      if (method === 'POST' && seg[2] === 'restore-check') {
        if (v.backup_type === 'uci_snapshot') return fail(409, 'capability_unavailable', false, { state: 'unavailable', reason: 'no_archive' });
        if (v.openwrt_version === '23.05.3') {
          return respond(200, { backup_id: v.backup_id, compatible: false,
            findings: [{ code: 'board_mismatch', level: 'block' }, { code: 'release_downgrade', level: 'warning' }],
            steps: [], instructions: ['restore_blocked'], expires_at: iso(now() + 15 * 60_000) });
        }
        return respond(200, {
          backup_id: v.backup_id, compatible: true,
          findings: [{ code: 'lockout_risk', level: 'warning' }, { code: 'checksum_unverified', level: 'warning' }],
          steps: [{ order: 1, action: 'archive_restore', instructions: 'config.restore.manual_upload' }, { order: 2, action: 'reboot', instructions: null }],
          warnings: ['access_files_overwritten', 'restore_not_reversible'],
          instructions: ['restore_prepare_console_failsafe', 'restore_luci_upload', 'restore_cli_sysupgrade',
            'restore_secrets_and_identity', 'restore_verify_after_reboot'],
          requires_reboot: true,
          diff: { changes: DIFF_CHANGES.slice(0, 6) },
          expires_at: iso(now() + 15 * 60_000),
        });
      }
      if (method === 'POST' && seg[2] === 'export') {
        return respond(200, newApproval('export', r.summary.router_id as string, v.backup_id as string));
      }
      return fail(404, 'not_found');
    }
    if (seg[0] === 'approvals') {
      if (method === 'GET' && seg.length === 1) {
        const want = q.get('router_id');
        return respond(200, { approvals: [...approvals.values()].filter(a => !want || a.router_id === want) });
      }
      const a = approvals.get(seg[1]);
      if (!a) return fail(409, 'approval_invalid');
      const set = (over: Json) => { const na = { ...a, ...over }; approvals.set(seg[1], na); return na; };
      if (Date.parse(a.expires_at as string) <= now() && a.status !== 'used') set({ status: 'expired' });
      const cur = approvals.get(seg[1]) as Json;
      if (method === 'POST' && seg[2] === 'approve') {
        if (cur.action === 'export' && body.acknowledge_plaintext !== true) {
          return fail(400, 'plaintext_not_acknowledged', false, { field: 'acknowledge_plaintext', reason: 'required' });
        }
        return cur.status === 'pending' ? respond(200, set({ status: 'approved' })) : fail(409, 'approval_invalid');
      }
      if (method === 'POST' && seg[2] === 'reject') return respond(200, set({ status: 'rejected' }));
      if (method === 'POST' && seg[2] === 'download') {
        if (cur.action !== 'export') return fail(409, 'approval_invalid');
        if (cur.status === 'pending') return fail(409, 'approval_required');
        if (cur.status !== 'approved') return fail(409, 'approval_invalid');
        set({ status: 'used' });
        const name = `backup-${String(cur.router_id).slice(4, 12)}-mock.tar.gz`;
        return new Response(new TextEncoder().encode('MOCK ARCHIVE – keine echten Daten\n'), { status: 200, headers: {
          'Content-Type': 'application/gzip', 'Content-Disposition': `attachment; filename="${name}"`,
          'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
      }
      if (method === 'POST' && seg[2] === 'execute') {
        if (cur.action === 'export') return fail(409, 'approval_invalid');
        if (cur.status !== 'approved') return fail(409, 'approval_required');
        set({ status: 'used' });
        const r = byId(String(cur.router_id));
        if (r && cur.action === 'ssh_pin_confirm') r.detail = { ...r.detail, ssh_pin: { ...(r.detail.ssh_pin as Json), state: 'confirmed' } };
        if (r && cur.action === 'ssh_pin_reset') r.detail = { ...r.detail, ssh_pin: { state: 'none', fingerprint: null } };
        if (r && cur.action === 'acl_deploy') {
          r.detail = { ...r.detail, acl: { offerable: [], deployed_version: 9 } };
          r.summary = { ...r.summary, capability: { state: 'available', reason: null } };
        }
        return respond(200, { done: true, result: {} });
      }
    }
    return fail(404, 'not_found');
  }

  return async (url: string, init: RequestInit): Promise<Response> => {
    const wait = scenario === 'slow' ? 4_000 : delayMs;
    if (wait > 0) await new Promise(res => setTimeout(res, wait));
    const prefix = '/api/openwrt_topology/config/';
    if (!url.startsWith(prefix)) return fail(404, 'not_found');
    let body: Json = {};
    if (typeof init.body === 'string') {
      try { body = JSON.parse(init.body) as Json; } catch { return fail(400, 'invalid_request'); }
    }
    return route(init.method ?? 'GET', url.slice(prefix.length), body);
  };
}

export function createMockConfigApi(
  scenario: string,
  opts: { delayMs?: number; saveBlob?: (blob: Blob, filename: string) => void } = {},
): ConfigApi {
  const name = (MOCK_SCENARIOS as readonly string[]).includes(scenario) ? (scenario as MockScenario) : 'default';
  return createConfigApi(() => MOCK_HASS, {
    fetch: createMockFetch(name, opts.delayMs ?? 350),
    saveBlob: opts.saveBlob,
  });
}
