// 1.46.1: partial versions in the panel — reasons, checksum, rights note,
// last attempt (node:test, no dependencies). Invented values only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  backupRightsMissing,
  formatTime,
  lastBackupText,
  latestVersion,
  parseOverview,
  parseRouterDetail,
  parseVersion,
  partialInfo,
  shortHash,
  versionWarningText,
} from './configLogic.ts';

const NOW = Date.parse('2026-11-18T12:00:00Z');
const HEX = c => c.repeat(64);

function summary(over = {}) {
  return parseOverview({
    routers: [{
      router_id: 'rtr_' + 'b'.repeat(32), name: 'AP', enabled: true, status: 'ok',
      running: false, last_backup_at: null, versions: 1,
      capability: { state: 'available', reason: null }, ...over,
    }],
  }).routers[0];
}

function detail(caps) {
  return parseRouterDetail({ router_id: 'rtr_x', enabled: true,
    capabilities: Object.fromEntries(Object.entries(caps).map(([k, v]) => [k,
      typeof v === 'string' ? { state: v, reason: v === 'available' ? 'ok' : null } : v])),
    acl: { offerable: ['config_backup_read'], deployed_version: null } });
}

const DENIED = { state: 'unavailable', reason: 'permission_denied', required_permissions: ['cgi-io:backup'] };

// ── Point 5: checksum column ──────────────────────────────────────────────

test('a version without archive shows the checksum of its UCI content, never the inventory', () => {
  // Core form: artifacts as a list sorted by kind (inventory before uci), sha256 null.
  const v = parseVersion({ backup_id: 'bkp_1', status: 'partial', sha256: null,
    artifacts: [{ kind: 'inventory', sha256: HEX('d'), size_bytes: 10 },
      { kind: 'uci', sha256: HEX('c'), size_bytes: 20 }] });
  assert.equal(v.sha256, HEX('c'));
  const other = parseVersion({ backup_id: 'bkp_2', status: 'partial', sha256: null,
    artifacts: [{ kind: 'inventory', sha256: HEX('d'), size_bytes: 10 },
      { kind: 'uci', sha256: HEX('e'), size_bytes: 20 }] });
  assert.notEqual(shortHash(v.sha256), shortHash(other.sha256));
});

test('a version holding only an inventory shows "–" as checksum', () => {
  const v = parseVersion({ backup_id: 'bkp_3', status: 'partial', sha256: null,
    artifacts: [{ kind: 'inventory', sha256: HEX('d'), size_bytes: 10 }] });
  assert.equal(v.sha256, null);
  assert.equal(shortHash(v.sha256), '–');
});

test('a version with archive keeps the archive checksum', () => {
  const v = parseVersion({ backup_id: 'bkp_4', status: 'ok', sha256: HEX('a'),
    artifacts: [{ kind: 'archive', sha256: HEX('a'), size_bytes: 30 },
      { kind: 'inventory', sha256: HEX('d'), size_bytes: 10 }, { kind: 'uci', sha256: HEX('c'), size_bytes: 20 }] });
  assert.equal(v.sha256, HEX('a'));
});

// ── Point 6: "Leserechte fehlen" only when they do ────────────────────────

test('no missing rights when the archive works as root', () => {
  const d = detail({ 'config.cgi_backup': 'available', 'config.ssh_root': 'available', 'config.uci_read': 'available' });
  assert.equal(backupRightsMissing(d, null, null), false);
  const sshOnly = detail({ 'config.cgi_backup': DENIED, 'config.ssh_root': 'available', 'config.uci_read': 'available' });
  assert.equal(backupRightsMissing(sshOnly, null, null), false);
});

test('missing rights when no archive path is left for lack of rights', () => {
  const d = detail({ 'config.cgi_backup': DENIED,
    'config.ssh_root': { state: 'unavailable', reason: 'permission_denied' }, 'config.uci_read': 'available' });
  assert.equal(backupRightsMissing(d, null, null), true);
  const uci = detail({ 'config.cgi_backup': 'available', 'config.uci_read': { state: 'unavailable', reason: 'permission_denied' } });
  assert.equal(backupRightsMissing(uci, null, null), true);
});

test('a backup that failed for lack of rights counts, a plain-HTTP failure does not', () => {
  const d = detail({ 'config.cgi_backup': 'available', 'config.uci_read': 'available' });
  assert.equal(backupRightsMissing(d, 'permission', null), true);
  assert.equal(backupRightsMissing(d, 'not_available', 'insecure_transport'), false);
});

// ── Point 7: last attempt instead of "noch keins" ─────────────────────────

test('a partial run without any usable backup shows the last attempt', () => {
  const at = '2026-11-18T03:41:12+00:00';
  const r = summary({ status: 'partial', last_attempt_at: at });
  assert.equal(r.lastAttemptAt, at);
  assert.equal(lastBackupText(r, NOW), `letzter Versuch: unvollständig, ${formatTime(at)}`);
});

test('without attempt, or with a usable backup, the text stays as before', () => {
  assert.equal(lastBackupText(summary({ status: 'never' }), NOW), 'noch keins');
  assert.equal(lastBackupText(summary({ status: 'partial' }), NOW), 'noch keins');
  const at = '2026-11-18T03:41:12+00:00';
  const ok = lastBackupText(summary({ status: 'partial', last_backup_at: at, last_attempt_at: at }), NOW);
  assert.ok(ok.startsWith(formatTime(at)), ok);
});

// ── Point 2: reasons of an incomplete run in plain text ───────────────────

const CAUSES = {
  cgi: ['insecure_transport', 'permission', 'not_available', 'not_probed', 'unreachable', 'timeout'],
  ssh: ['permission', 'pin_unavailable', 'pin_pending', 'pin_refused', 'mismatch', 'algorithm_unavailable',
    'pin_invalid', 'pin_save_failed', 'pin_store_unavailable', 'no_host_key', 'refused', 'not_probed'],
};

test('every archive_not_attempted item has a German text, no raw code', () => {
  const codes = ['archive_not_attempted:requested',
    ...CAUSES.cgi.map(c => `archive_not_attempted:cgi.${c}`),
    ...CAUSES.ssh.map(c => `archive_not_attempted:ssh.${c}`)];
  for (const code of codes) {
    const text = versionWarningText(code);
    assert.ok(!text.includes('archive_not_attempted') && !text.includes('_'), `${code} → ${text}`);
  }
  assert.match(versionWarningText('archive_not_attempted:ssh.pin_pending'), /SSH/);
  assert.match(versionWarningText('archive_not_attempted:cgi.not_probed'), /cgi-io/);
});

test('host-key reasons read as text; a masked reason never shows the mask', () => {
  assert.match(versionWarningText('ssh_host_key:pin_pending'), /nicht bestätigt/);
  const masked = versionWarningText('ssh_host_key:**REDACTED**');
  assert.ok(!masked.includes('REDACTED') && !masked.includes('*'), masked);
  assert.equal(versionWarningText('uci_missing'), 'Einzelne UCI-Dateien fehlen');
});

test('an incomplete run names error class, reasons and the next step once', () => {
  const info = partialInfo('incomplete', [
    'archive_not_attempted:cgi.not_probed', 'archive_not_attempted:ssh.pin_pending', 'ssh_host_key:pin_pending',
  ]);
  assert.match(info.classText, /unvollständig/);
  assert.equal(info.reasons.length, 3);
  assert.ok(info.reasons.every(r => !r.includes('_')), info.reasons.join(' | '));
  assert.deepEqual(info.nextSteps.filter(s => s.includes('SSH-Host-Key bestätigen')).length, 1);
});

// ── PR 59 review R3: "not probed" means the next backup finds out ────────

test('an unprobed path names the next backup as the step that finds out', () => {
  for (const path of ['cgi', 'ssh']) {
    const { nextSteps } = partialInfo('incomplete', [`archive_not_attempted:${path}.not_probed`]);
    assert.equal(nextSteps.length, 1, path);
    assert.match(nextSteps[0], /Jetzt sichern/);
    assert.match(nextSteps[0], /Archiv/);
  }
  assert.match(partialInfo(null, ['archive_not_attempted:ssh.not_probed']).nextSteps[0], /SSH/);
  assert.match(partialInfo(null, ['archive_not_attempted:cgi.not_probed']).nextSteps[0], /cgi-io/);
});

test('the newest version is picked by time', () => {
  const vs = [
    parseVersion({ backup_id: 'bkp_old', created_at: '2026-11-17T03:00:00+00:00', status: 'ok' }),
    parseVersion({ backup_id: 'bkp_new', created_at: '2026-11-18T03:00:00+00:00', status: 'partial' }),
  ];
  assert.equal(latestVersion(vs)?.backupId, 'bkp_new');
  assert.equal(latestVersion([]), null);
});
