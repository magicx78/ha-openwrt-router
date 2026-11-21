// Tests of the pure Configuration Manager logic (node:test, no dependencies).
// Node 24 strips the TypeScript types of the imported .ts files itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ConfigApiError,
  ERROR_TEXT,
  FINDING_TEXT,
  RESTORE_KEY_TEXT,
  WARNING_TEXT,
  approveBody,
  archivePath,
  canApprove,
  canDownload,
  changeValueText,
  errorInfo,
  exportApproveOptions,
  exportInit,
  failureText,
  isAccessFailure,
  isTransportFailure,
  versionActionLocks,
  CAP_REASON_TEXT,
  exportReduce,
  groupChangesByArea,
  isCriticalChange,
  parseApproval,
  parseContentDisposition,
  parseDiff,
  parseDriftState,
  parseOverview,
  parseRestorePlan,
  parseRouterDetail,
  parseVersion,
  restoreCanProceed,
  restoreImpact,
  restoreInit,
  restoreKeyText,
  restoreReduce,
  routerRisk,
  routerViewState,
  safeFilename,
  sanitizeNote,
  shortHash,
  sortChanges,
  stepText,
} from './configLogic.ts';

const NOW = Date.parse('2026-11-18T12:00:00Z');

function router(over = {}) {
  return parseOverview({
    routers: [{
      router_id: 'rtr_' + 'a'.repeat(32), name: 'AP', enabled: true, status: 'ok',
      running: false, last_backup_at: '2026-11-18T03:41:12+00:00', versions: 3,
      capability: { state: 'available', reason: null },
      drift: { state: 'clean', drift_id: null, critical_count: 0, unknown_count: 0 },
      ...over,
    }],
  }).routers[0];
}

// ── Parsing ───────────────────────────────────────────────────────────────

test('parseOverview tolerates garbage and fills defaults', () => {
  assert.deepEqual(parseOverview(null), { provider: null, pendingApprovals: 0, routers: [] });
  const o = parseOverview({ provider: 'config_manager', pending_approvals: 2,
    routers: [{ router_id: 'rtr_x' }, 'junk', null] });
  assert.equal(o.routers.length, 1);
  assert.equal(o.pendingApprovals, 2);
  const r = o.routers[0];
  assert.equal(r.name, 'rtr_x');
  assert.equal(r.enabled, false);
  assert.equal(r.versions, 0);
  assert.equal(r.capability.state, 'unknown');
  assert.equal(r.drift, null);
});

test('parseRouterDetail reads capabilities, ssh pin and acl', () => {
  const d = parseRouterDetail({ router_id: 'rtr_x', enabled: true,
    capabilities: { 'config.cgi_backup': { state: 'unavailable', reason: 'permission_denied',
      required_permissions: ['cgi-io:backup'] } },
    ssh_pin: { state: 'pending', fingerprint: 'SHA256:abc' },
    acl: { offerable: ['config_backup_read'], deployed_version: 8 } });
  assert.deepEqual(d.capabilities['config.cgi_backup'].missing, ['cgi-io:backup']);
  assert.equal(d.sshPin.state, 'pending');
  assert.equal(d.acl.deployedVersion, 8);
});

test('parseVersion accepts the plan form and the core to_dict form', () => {
  const plan = parseVersion({ backup_id: 'bkp_1', status: 'ok', validation: { state: 'ok' },
    artifacts: [{ kind: 'archive', size_bytes: 41234, sha256: 'f'.repeat(64) }] });
  assert.equal(plan.validation.state, 'ok');
  assert.equal(plan.sizeBytes, 41234);
  assert.equal(plan.sha256, 'f'.repeat(64));
  const core = parseVersion({ backup_id: 'bkp_2', validation: { status: 'valid' },
    artifacts: { uci: { sha256: 'a'.repeat(64), size_bytes: 10 }, archive: { sha256: 'b'.repeat(64), size_bytes: 20 } },
    size_bytes: 30, sha256: 'b'.repeat(64) });
  assert.equal(core.validation.state, 'valid');
  assert.deepEqual(core.artifacts.map(a => a.kind).sort(), ['archive', 'uci']);
  assert.equal(core.sizeBytes, 30);
});

test('parseDiff maps core kinds and hides every secret value', () => {
  const d = parseDiff({ base: { kind: 'backup', backup_id: 'bkp_1' }, other: { kind: 'live' },
    changes: [
      { kind: 'modified', config: 'wireless', section: 'r0', option: 'key', before: '***', after: '***', secret: true, area: 'wlan', risk: 'high' },
      { kind: 'added', config: 'network', section: 'lan', option: 'ipaddr', after: '10.0.0.1', area: 'mgmt_ip', risk: 'critical' },
      { op: 'changed', config: 'system', section: 's', option: 'hostname', old: 'a', new: 'b', area: 'system', risk: 'low' },
      { op: 'changed', config: 'dropbear', section: 'd', option: 'pw', old: '***', new: 'sha256:abcd' },
    ] });
  assert.equal(d.from, 'bkp_1');
  assert.equal(d.to, 'live');
  assert.equal(d.changes[0].op, 'changed');
  assert.equal(d.changes[0].oldText, null);
  assert.equal(changeValueText(d.changes[0], 'new'), 'geändert');
  assert.equal(d.changes[1].newText, '10.0.0.1');
  assert.equal(d.changes[2].oldText, 'a');
  // A masked marker on either side makes the whole change a secret.
  assert.equal(d.changes[3].secret, true);
  assert.equal(changeValueText(d.changes[3], 'new'), 'geändert');
  assert.equal(d.changes[3].area, 'other');
});

test('parseDriftState and parseRestorePlan accept both forms', () => {
  const s = parseDriftState({ state: 'open', report: { drift_id: 'd1', critical_count: 1, comparison: 'complete' }, acks: [] });
  assert.equal(s.report.criticalCount, 1);
  const plan = parseRestorePlan({ backup_id: 'bkp_1', compatible: true,
    findings: [{ code: 'release_downgrade', level: 'warning' }],
    steps: [{ order: 1, action: 'archive_restore', instructions: 'config.restore.manual_upload' }] });
  assert.equal(plan.compatible, true);
  assert.equal(plan.findings[0].blocking, false);
  const core = parseRestorePlan({ backup_id: 'bkp_1',
    compatibility: { compatible: false, issues: [{ code: 'board_mismatch', blocking: true, message: '<b>x</b>' }] },
    steps: [], requires_reboot: true, warnings: ['restore_not_reversible'], instructions: ['restore_blocked'] });
  assert.equal(core.compatible, false);
  assert.equal(core.findings[0].blocking, true);
  assert.equal(core.requiresReboot, true);
  assert.ok(!JSON.stringify(core).includes('<b>'), 'free-text messages are dropped');
});

// ── Overview state and risk ──────────────────────────────────────────────

test('routerViewState covers every overview state', () => {
  assert.equal(routerViewState(router({ enabled: false })), 'disabled');
  assert.equal(routerViewState(router({ running: true })), 'running');
  assert.equal(routerViewState(router({ status: 'failed', error_class: 'network' })), 'failed');
  assert.equal(routerViewState(router({ status: 'never', versions: 0 })), 'never');
  assert.equal(routerViewState(router({ capability: { state: 'unavailable', reason: 'permission_denied' } })), 'blocked');
  assert.equal(routerViewState(router({ drift: { state: 'open', critical_count: 0 } })), 'drift');
  assert.equal(routerViewState(router({ status: 'partial' })), 'partial');
  assert.equal(routerViewState(router()), 'ok');
});

test('routerRisk ranks drift, failures and stale backups', () => {
  assert.equal(routerRisk(router({ enabled: false }), NOW), 'none');
  assert.equal(routerRisk(router({ drift: { state: 'open', critical_count: 2 } }), NOW), 'critical');
  assert.equal(routerRisk(router({ status: 'failed' }), NOW), 'high');
  assert.equal(routerRisk(router({ drift: { state: 'open', critical_count: 0, unknown_count: 1 } }), NOW), 'high');
  assert.equal(routerRisk(router({ last_backup_at: '2026-11-01T00:00:00Z' }), NOW), 'medium');
  assert.equal(routerRisk(router({ versions: 0, last_backup_at: null, status: 'never' }), NOW), 'medium');
  assert.equal(routerRisk(router(), NOW), 'low');
  // An acknowledged drift is no longer a risk.
  assert.equal(routerRisk(router({ drift: { state: 'acknowledged', critical_count: 2 } }), NOW), 'low');
});

test('archivePath tells UCI-only routers apart', () => {
  const caps = (cgi, ssh, uci) => parseRouterDetail({ capabilities: {
    'config.cgi_backup': { state: cgi }, 'config.ssh_root': { state: ssh }, 'config.uci_read': { state: uci } } });
  assert.equal(archivePath(caps('available', 'unavailable', 'available')), 'archive');
  assert.equal(archivePath(caps('unavailable', 'available', 'available')), 'archive');
  assert.equal(archivePath(caps('unavailable', 'unavailable', 'available')), 'uci_only');
  assert.equal(archivePath(caps('unavailable', 'unavailable', 'unavailable')), 'none');
  assert.equal(archivePath(caps('unknown', 'unavailable', 'available')), 'unknown');
});

// ── Diff ordering ─────────────────────────────────────────────────────────

test('sortChanges puts the highest risk first and groups mark critical areas', () => {
  const d = parseDiff({ changes: [
    { op: 'changed', area: 'system', risk: 'low', config: 'system', section: 'a' },
    { op: 'added', area: 'firewall', risk: 'medium', config: 'firewall', section: 'b' },
    { op: 'removed', area: 'wlan', risk: 'critical', config: 'wireless', section: 'c' },
    { op: 'changed', area: 'dns', risk: null, config: 'dhcp', section: 'd' },
  ] });
  assert.deepEqual(sortChanges(d.changes).map(c => c.risk), ['critical', 'medium', 'low', null]);
  const groups = groupChangesByArea(d.changes);
  assert.deepEqual(groups.map(g => g.area), ['wlan', 'firewall', 'system', 'dns']);
  assert.equal(groups.find(g => g.area === 'firewall').critical, true);
  assert.equal(groups.find(g => g.area === 'system').critical, false);
  assert.deepEqual(groups.find(g => g.area === 'firewall').counts, { added: 1, removed: 0, changed: 0, other: 0 });
  assert.equal(isCriticalChange(d.changes[2]), true);
  for (const area of ['mgmt_ip', 'vlan', 'firewall', 'ssh', 'interface']) {
    assert.equal(isCriticalChange({ ...d.changes[0], area }), true, area);
  }
});

// ── Errors ────────────────────────────────────────────────────────────────

test('every documented error code has a German text', () => {
  const codes = ['router_not_found', 'backup_not_found', 'authorization_denied', 'approval_required',
    'approval_invalid', 'operation_in_progress', 'version_protected', 'provider_conflict',
    'capability_unavailable', 'backup_integrity_failed', 'backup_incomplete', 'restore_incompatible',
    'storage_ref_invalid', 'router_unavailable', 'provider_unavailable', 'core_not_running',
    'operation_timeout', 'router_auth_failed', 'router_permission_denied', 'provider_error',
    'artifact_too_large', 'storage_full', 'storage_error', 'internal'];
  for (const code of codes) assert.ok(ERROR_TEXT[code], code);
});

test('errorInfo never shows the server message and classifies the state', () => {
  const evil = new ConfigApiError(500, 'something_new', false, {}, null);
  evil.serverMessage = '<img src=x onerror=alert(1)>';
  const info = errorInfo(evil);
  assert.ok(!info.message.includes('<img'));
  assert.equal(info.kind, 'other');
  assert.equal(errorInfo(new ConfigApiError(403, 'authorization_denied', false, {}, null)).kind, 'forbidden');
  assert.equal(errorInfo(new ConfigApiError(410, '', false, {}, null)).kind, 'gone');
  assert.equal(errorInfo(new ConfigApiError(503, 'core_not_running', true, {}, null)).kind, 'unavailable');
  assert.equal(errorInfo(new ConfigApiError(409, 'provider_conflict', false, {}, null)).kind, 'conflict');
  assert.equal(errorInfo(new ConfigApiError(409, 'operation_in_progress', true, {}, 30)).kind, 'busy');
  assert.equal(errorInfo(new ConfigApiError(409, 'approval_invalid', false, {}, null)).kind, 'expired');
  const off = errorInfo(new ConfigApiError(409, 'capability_unavailable', false, { state: 'unavailable', reason: 'disabled' }, null));
  assert.equal(off.kind, 'disabled');
  assert.match(off.message, /Optionen/);
  assert.equal(errorInfo(new TypeError('Failed to fetch')).kind, 'network');
  assert.equal(errorInfo(new ConfigApiError(502, 'router_auth_failed', true, {}, null)).retry, true);
});

test('busy names any operation on the router; rate_limited names the seconds', () => {
  const busy = errorInfo(new ConfigApiError(409, 'operation_in_progress', true, { reason: 'router_busy' }, 30));
  assert.equal(busy.kind, 'busy');
  assert.match(busy.message, /anderer Vorgang \(Backup, Drift- oder Live-Prüfung\)/);
  assert.equal(busy.retryAfter, 30);

  for (const reason of ['min_gap_backup', 'min_gap_live_check']) {
    const info = errorInfo(new ConfigApiError(429, 'rate_limited', true, { reason }, 42));
    assert.equal(info.kind, 'rate_limited');
    assert.equal(info.message, 'Zu früh nach dem letzten manuellen Lauf, bitte in 42 Sekunden erneut versuchen.');
    assert.equal(info.retryAfter, 42);
    // No retry button that would only hit the limit again.
    assert.equal(info.retry, false);
  }
  const noHeader = errorInfo(new ConfigApiError(429, 'rate_limited', true, {}, null));
  assert.equal(noHeader.retryAfter, null);
  assert.match(noHeader.message, /später erneut/);
  assert.match(errorInfo(new ConfigApiError(400, 'plaintext_not_acknowledged', false,
    { field: 'acknowledge_plaintext', reason: 'required' }, null)).message, /Klartext/);
});

test('insecure_transport explains HTTPS / SSH and never points to the ACL', () => {
  for (const key of ['insecure_transport', 'provider:insecure_transport']) {
    assert.match(CAP_REASON_TEXT[key] ?? '', /Kein Archiv über HTTP/);
    assert.match(CAP_REASON_TEXT[key], /HTTPS/);
    // HTTP without root SSH fails the backup; no silent UCI-only fallback.
    assert.match(CAP_REASON_TEXT[key], /root/);
    assert.match(CAP_REASON_TEXT[key], /schlägt das Backup fehl/);
    assert.doesNotMatch(CAP_REASON_TEXT[key], /nur der UCI-Snapshot/);
  }
  const r = router({ status: 'failed', error_class: 'not_available', error_reason: 'insecure_transport' });
  assert.equal(r.errorReason, 'insecure_transport');
  assert.equal(router({ status: 'failed', error_class: 'not_available' }).errorReason, null);
  assert.equal(isAccessFailure('not_available', 'insecure_transport'), false);
  assert.equal(isTransportFailure('insecure_transport'), true);
  assert.equal(isTransportFailure(null), false);
  const text = failureText('not_available', 'insecure_transport');
  assert.match(text, /Kein Archiv über HTTP/);
  assert.match(text, /SSH/);
  assert.doesNotMatch(text, /rpcd-ACL|ACL-Angebot/);
  // Older answers without error_reason keep the ACL hint.
  assert.match(failureText('not_available', null), /ACL-Angebot/);
});

test('invalid_request has a German text', () => {
  assert.equal(ERROR_TEXT.invalid_request, 'Die Anfrage war ungültig.');
  assert.equal(errorInfo(new ConfigApiError(400, 'invalid_request', false, {}, null)).message, 'Die Anfrage war ungültig.');
});

test('version actions that change something are locked while the option is off', () => {
  assert.deepEqual(versionActionLocks({ enabled: false }), { validate: true, protect: true, export: true });
  assert.deepEqual(versionActionLocks({ enabled: true }), { validate: false, protect: false, export: false });
});

test('a failed backup for lack of rights points to the access section', () => {
  for (const cls of ['permission', 'not_available']) {
    assert.equal(isAccessFailure(cls), true);
    assert.match(failureText(cls), /rpcd-ACL/);
    assert.match(failureText(cls), /„Zugang“/);
  }
  assert.equal(isAccessFailure('unreachable'), false);
  assert.doesNotMatch(failureText('unreachable'), /Zugang/);
  assert.match(failureText('something_new'), /Fehlerart: something_new/);
  assert.equal(failureText(null), 'Das letzte Backup ist fehlgeschlagen.');
});

// ── Restore texts and impact ──────────────────────────────────────────────

test('every restore key, finding and warning has a text', () => {
  const keys = ['restore_blocked', 'restore_not_reversible', 'restore_prepare_console_failsafe',
    'restore_review_warnings', 'restore_install_missing_packages', 'restore_apk_package_names',
    'restore_release_eol', 'restore_luci_upload', 'restore_cli_sysupgrade',
    'restore_verify_after_reboot', 'restore_secrets_and_identity', 'config.restore.manual_upload'];
  for (const k of keys) {
    assert.ok(RESTORE_KEY_TEXT[k], k);
    assert.equal(restoreKeyText(k), RESTORE_KEY_TEXT[k]);
  }
  const findings = ['archive_invalid', 'checksum_mismatch', 'checksum_unverified', 'board_mismatch',
    'board_unknown', 'switch_model_mismatch', 'release_unknown', 'release_downgrade',
    'release_major_change', 'firewall_fw3_to_fw4', 'package_manager_change', 'missing_package',
    'packages_unknown', 'inventory_partial', 'insufficient_space', 'lockout_risk'];
  for (const f of findings) assert.ok(FINDING_TEXT[f], f);
  for (const w of ['snapshot_stale', 'snapshot_age_unknown', 'config_not_comparable',
    'access_files_overwritten', 'restore_not_reversible']) assert.ok(WARNING_TEXT[w], w);
  assert.match(restoreKeyText('unheard_of'), /unheard_of/);
  assert.match(stepText({ order: 1, action: 'reboot', instructions: null }), /neu/);
});

test('restoreImpact flags reboot, connection loss and blocking findings', () => {
  const plan = parseRestorePlan({ backup_id: 'bkp_1',
    compatibility: { compatible: true, issues: [{ code: 'lockout_risk', blocking: false }] },
    steps: [{ order: 1, action: 'archive_restore' }, { order: 2, action: 'reboot' }],
    requires_reboot: true, warnings: [],
    diff: { changes: [
      { kind: 'modified', area: 'mgmt_ip', risk: 'critical', config: 'network', section: 'lan', option: 'ipaddr', before: 'a', after: 'b' },
      { kind: 'added', area: 'wlan', risk: 'low', config: 'wireless', section: 'x' },
    ] } });
  const impact = restoreImpact(plan);
  assert.equal(impact.reboot, true);
  assert.equal(impact.connectionRisk, true);
  assert.equal(impact.critical.length, 1);
  assert.deepEqual(impact.areas.map(a => a.area), ['mgmt_ip', 'wlan']);
  assert.equal(impact.blocking.length, 0);
  const calm = restoreImpact(parseRestorePlan({ backup_id: 'b', compatible: true, steps: [] }));
  assert.equal(calm.connectionRisk, false);
  assert.equal(calm.reboot, false);
});

// ── Export flow: no download without explicit confirmation ────────────────

const APPROVAL = parseApproval({ approval_id: 'apr_1', action: 'export', status: 'pending',
  requested_by: { kind: 'user', mine: true }, expires_at: '2026-11-18T12:15:00Z' });
const APPROVED = { ...APPROVAL, status: 'approved' };

test('export: approve and download stay locked until the plaintext warning is confirmed', () => {
  let s = exportInit();
  assert.equal(canDownload(s, NOW), false);
  s = exportReduce(s, { type: 'request' });
  assert.equal(s.step, 'requesting');
  s = exportReduce(s, { type: 'requested', approval: APPROVAL });
  assert.equal(s.step, 'requested');
  assert.equal(canApprove(s, NOW), false);
  // Approve without the tick is ignored.
  assert.equal(exportReduce(s, { type: 'approve' }).step, 'requested');
  // Download before approval is ignored.
  assert.equal(exportReduce(s, { type: 'download' }).step, 'requested');
  s = exportReduce(s, { type: 'acknowledge', value: true });
  assert.equal(canApprove(s, NOW), true);
  s = exportReduce(s, { type: 'approve' });
  assert.equal(s.step, 'approving');
  s = exportReduce(s, { type: 'approved', approval: APPROVED });
  assert.equal(canDownload(s, NOW), true);
  // Unticking again locks the download.
  assert.equal(canDownload(exportReduce(s, { type: 'acknowledge', value: false }), NOW), false);
  s = exportReduce(s, { type: 'download' });
  assert.equal(s.step, 'downloading');
  s = exportReduce(s, { type: 'downloaded', filename: 'x.tar.gz' });
  assert.equal(s.step, 'done');
  // A used approval cannot be downloaded twice.
  assert.equal(canDownload(s, NOW), false);
});

test('export: acknowledge_plaintext is sent only after the tick', () => {
  let s = exportReduce(exportInit(), { type: 'requested', approval: APPROVAL });
  // No tick: nothing to send at all, and the body would carry no field.
  assert.equal(exportApproveOptions(s, NOW), null);
  assert.deepEqual(approveBody(undefined), {});
  assert.deepEqual(approveBody({ acknowledgePlaintext: false }), {});
  s = exportReduce(s, { type: 'acknowledge', value: true });
  const options = exportApproveOptions(s, NOW);
  assert.deepEqual(options, { acknowledgePlaintext: true });
  assert.deepEqual(approveBody(options), { acknowledge_plaintext: true });
  // Unticked again or expired: no approval is sent.
  assert.equal(exportApproveOptions(exportReduce(s, { type: 'acknowledge', value: false }), NOW), null);
  assert.equal(exportApproveOptions(s, Date.parse('2026-11-18T13:00:00Z')), null);
});

test('export: an expired or invalid approval must be requested again', () => {
  let s = exportReduce(exportInit(), { type: 'requested', approval: APPROVAL });
  s = exportReduce(s, { type: 'acknowledge', value: true });
  s = exportReduce(s, { type: 'approved', approval: APPROVED });
  const later = Date.parse('2026-11-18T12:16:00Z');
  assert.equal(canDownload(s, later), false);
  const failed = exportReduce(s, { type: 'failed', error: new ConfigApiError(409, 'approval_invalid', false, {}, null) });
  assert.equal(failed.step, 'failed');
  assert.equal(failed.renew, true);
  assert.equal(canDownload(failed, NOW), false);
  assert.equal(exportReduce(failed, { type: 'reset' }).step, 'idle');
  // A not-approved answer never unlocks the download.
  const odd = exportReduce(exportReduce(exportInit(), { type: 'requested', approval: APPROVAL }), { type: 'acknowledge', value: true });
  assert.equal(canDownload(exportReduce(odd, { type: 'approved', approval: APPROVAL }), NOW), false);
});

// ── Restore wizard ────────────────────────────────────────────────────────

test('restore wizard: blocked plans stop, confirmation gates the export, nothing executes', () => {
  const ok = parseRestorePlan({ backup_id: 'bkp_1', compatible: true, steps: [{ order: 1, action: 'archive_restore' }] });
  const bad = parseRestorePlan({ backup_id: 'bkp_1', compatible: false, findings: [{ code: 'board_mismatch', level: 'block' }] });
  let s = restoreInit('bkp_1');
  assert.equal(s.step, 'compat');
  s = restoreReduce(s, { type: 'checked', plan: bad });
  assert.equal(restoreCanProceed(s), false);
  assert.equal(restoreReduce(s, { type: 'next' }).step, 'compat');
  s = restoreReduce(restoreInit('bkp_1'), { type: 'checked', plan: ok });
  assert.equal(restoreCanProceed(s), true);
  s = restoreReduce(s, { type: 'next' });
  assert.equal(s.step, 'preview');
  s = restoreReduce(s, { type: 'next' });
  assert.equal(s.step, 'confirm');
  assert.equal(restoreCanProceed(s), false);
  assert.equal(restoreReduce(s, { type: 'next' }).step, 'confirm');
  s = restoreReduce(s, { type: 'understood', value: true });
  s = restoreReduce(s, { type: 'next' });
  assert.equal(s.step, 'guide');
  assert.equal(restoreReduce(s, { type: 'next' }).step, 'guide');
  assert.equal(restoreReduce(s, { type: 'back' }).step, 'confirm');
  const steps = new Set(['compat', 'preview', 'confirm', 'guide']);
  assert.ok(steps.has(s.step));
});

// ── Small helpers ─────────────────────────────────────────────────────────

test('file names are reduced to safe characters', () => {
  assert.equal(safeFilename('../../etc/passwd', 'application/gzip'), 'etc_passwd');
  assert.equal(safeFilename('backup-ap1_2026.tar.gz', 'application/gzip'), 'backup-ap1_2026.tar.gz');
  assert.equal(safeFilename('', 'application/gzip'), 'openwrt-config.tar.gz');
  assert.equal(safeFilename(null, 'application/json'), 'openwrt-config.json');
  assert.equal(safeFilename('...', 'application/octet-stream'), 'openwrt-config.bin');
  assert.equal(parseContentDisposition('attachment; filename="a b.tar.gz"'), 'a b.tar.gz');
  assert.equal(parseContentDisposition("attachment; filename*=UTF-8''x%2Fy.json"), 'x/y.json');
  assert.equal(parseContentDisposition(null), null);
});

test('notes are trimmed, cut and lose control characters', () => {
  assert.equal(sanitizeNote('  vor Update\u0007\n '), 'vor Update');
  assert.equal(sanitizeNote('x'.repeat(300)).length, 200);
  assert.equal(sanitizeNote('   '), '');
  assert.equal(shortHash('abcdef0123456789abcdef'), 'abcdef012345');
  assert.equal(shortHash(null), '–');
});
