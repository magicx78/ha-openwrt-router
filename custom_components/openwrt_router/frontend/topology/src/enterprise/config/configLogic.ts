/**
 * configLogic.ts — pure logic of the Configuration Manager tab (plan 8).
 *
 * Parsers (server JSON → view types), view states, risk ordering, German
 * texts per error code / restore key, and the two wizard state machines
 * (export, restore). No React, no DOM, no network: node --test imports it.
 *
 * Server text is never shown: errors are mapped from their `code`, restore
 * findings from their `code`; free-text fields (`message`, `description`)
 * are dropped while parsing.
 */

import type {
  AclOffer,
  Approval,
  Artifact,
  Capability,
  Change,
  ChangeOp,
  Diff,
  DriftAck,
  DriftReport,
  DriftState,
  DriftSummary,
  Overview,
  RestoreFinding,
  RestorePlan,
  RestoreStep,
  RiskLevel,
  RouterDetail,
  RouterRisk,
  RouterSummary,
  Version,
} from './configTypes';

// ── Small parse helpers ──────────────────────────────────────────────────

type Obj = Record<string, unknown>;

function obj(v: unknown): Obj | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Obj) : null;
}
function str(v: unknown): string | null {
  return typeof v === 'string' && v !== '' ? v : null;
}
function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x !== '') : [];
}
function objList(v: unknown): Obj[] {
  return Array.isArray(v) ? v.map(obj).filter((x): x is Obj => x !== null) : [];
}

/** Look a server code up in a label map; unknown codes are shown as the code. */
export function label(map: Record<string, string>, key: string | null | undefined): string {
  if (!key) return '–';
  return map[key] ?? key;
}

// ── Error ────────────────────────────────────────────────────────────────

/** A failed config request. Carries the code only, never the server message. */
export class ConfigApiError extends Error {
  readonly status: number | null;
  readonly code: string;
  readonly retryable: boolean;
  readonly details: { state?: string; reason?: string };
  readonly retryAfter: number | null;

  constructor(
    status: number | null,
    code: string,
    retryable: boolean,
    details: { state?: string; reason?: string },
    retryAfter: number | null,
  ) {
    super(`config api ${status ?? '-'} ${code || 'unknown'}`);
    this.name = 'ConfigApiError';
    this.status = status;
    this.code = code;
    this.retryable = retryable;
    this.details = details;
    this.retryAfter = retryAfter;
  }
}

// ── Labels ───────────────────────────────────────────────────────────────

export const AREA_LABEL: Record<string, string> = {
  mgmt_ip: 'Management-IP',
  vlan: 'VLAN',
  interface: 'Schnittstellen / Uplink',
  firewall: 'Firewall',
  ssh: 'SSH-Zugang',
  routing: 'Routing',
  wlan: 'WLAN',
  dhcp: 'DHCP',
  dns: 'DNS',
  services: 'Dienste',
  system: 'System',
  other: 'Sonstiges',
};

/** Areas whose changes can cut HA off the router; always marked (Management-IP, VLAN, Firewall, SSH, Uplink). */
export const CRITICAL_AREAS: ReadonlySet<string> = new Set(['mgmt_ip', 'vlan', 'firewall', 'ssh', 'interface']);

export const RISK_LABEL: Record<string, string> = {
  critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig', none: 'Aus',
};

export const OP_LABEL: Record<ChangeOp, string> = {
  added: 'hinzugefügt', removed: 'entfernt', changed: 'geändert',
  reordered: 'umsortiert', not_comparable: 'nicht vergleichbar',
};

export const REASON_LABEL: Record<string, string> = {
  manual: 'Manuell', scheduled: 'Geplant', pre_firmware_update: 'Vor Firmware-Update',
  release_change: 'Release-Wechsel', pre_restore: 'Vor Wiederherstellung', pre_change: 'Vor Änderung',
  drift: 'Drift', incident: 'Vorfall', migration: 'Migration', import: 'Import',
};

export const TYPE_LABEL: Record<string, string> = {
  full_archive: 'Vollarchiv', uci_snapshot: 'UCI-Snapshot', partial: 'Teilweise',
};

export const VERSION_STATUS_LABEL: Record<string, string> = {
  ok: 'OK', partial: 'Unvollständig', failed: 'Fehlgeschlagen',
};

export const VALIDATION_LABEL: Record<string, string> = {
  ok: 'Geprüft', valid: 'Geprüft', unverified: 'Nicht geprüft', invalid: 'Ungültig',
  corrupt: 'Beschädigt', missing: 'Datei fehlt', failed: 'Fehlgeschlagen',
};

export const ROUTER_STATE_LABEL: Record<RouterViewState, string> = {
  disabled: 'Ausgeschaltet', running: 'Backup läuft', blocked: 'Zugriff fehlt', failed: 'Fehlgeschlagen',
  never: 'Noch kein Backup', drift: 'Drift offen', partial: 'Unvollständig', ok: 'OK',
};

export const DRIFT_STATE_LABEL: Record<string, string> = {
  open: 'Offen', drifted: 'Offen', acknowledged: 'Bestätigt', known: 'Als bekannt markiert',
  clean: 'Keine Abweichung', none: 'Keine Abweichung', unknown: 'Unbekannt',
};

export const COMPARISON_LABEL: Record<string, string> = {
  complete: 'vollständig', partial: 'teilweise', unknown: 'nicht vertrauenswürdig',
};

export const APPROVAL_ACTION_LABEL: Record<string, string> = {
  export: 'Export', acl_deploy: 'ACL verteilen', ssh_pin_confirm: 'SSH-Host-Key bestätigen',
  ssh_pin_reset: 'SSH-Host-Key vergessen',
};

export const APPROVAL_STATUS_LABEL: Record<string, string> = {
  pending: 'Wartet auf Freigabe', approved: 'Freigegeben', rejected: 'Abgelehnt',
  expired: 'Abgelaufen', used: 'Eingelöst',
};

export const SSH_PIN_LABEL: Record<string, string> = {
  pending: 'Ausstehend', confirmed: 'Bestätigt', pinned: 'Bestätigt', ok: 'Bestätigt',
  mismatch: 'Abweichend', none: 'Kein Key gespeichert', unknown: 'Unbekannt',
};

export const ACTOR_LABEL: Record<string, string> = {
  user: 'Benutzer', automation: 'Automation', module: 'Modul', system: 'System',
};

export const SCHEDULE_LABEL: Record<string, string> = { daily: 'Täglich', off: 'Aus' };

export const INSECURE_TRANSPORT_TEXT =
  'Kein Archiv über HTTP: Der Router ist ohne TLS eingebunden. Archiv-Backups laufen dann nur über SSH mit '
  + 'bestätigtem Hostkey; sonst wird nur der UCI-Snapshot gesichert. Empfohlen: Router-Eintrag auf HTTPS umstellen.';

export const CAP_REASON_TEXT: Record<string, string> = {
  insecure_transport: INSECURE_TRANSPORT_TEXT,
  'provider:insecure_transport': INSECURE_TRANSPORT_TEXT,
  ok: 'verfügbar',
  no_data_yet: 'noch keine Daten',
  not_checked: 'noch nicht geprüft',
  not_probed: 'noch nicht geprüft',
  not_detected: 'auf dem Router nicht gefunden',
  permission_denied: 'dem Router fehlen Rechte (rpcd-ACL)',
  transport_unsupported: 'über diese Verbindung nicht möglich',
  unsupported_firmware: 'Firmware nicht unterstützt',
  router_offline: 'Router nicht erreichbar',
  entry_not_loaded: 'Integrationseintrag nicht geladen',
  disabled: 'in den Optionen ausgeschaltet',
  no_provider: 'kein Backup-Modul angemeldet',
  provider_declined: 'vom Backup-Modul abgelehnt',
  determined_on_first_use: 'wird beim ersten Backup geklärt',
  no_archive: 'Version enthält kein Archiv',
  ssh_pin_pending: 'SSH-Host-Key noch nicht bestätigt',
  ssh_pin_mismatch: 'SSH-Host-Key weicht ab',
};

export const CAP_LABEL: Record<string, string> = {
  'config.capture': 'Erfassen', 'config.backup': 'Backup', 'config.validate': 'Prüfen',
  'config.diff': 'Vergleich', 'config.drift': 'Drift', 'config.restore_dry_run': 'Restore-Prüfung',
  'config.restore': 'Restore (automatisch)', 'config.export': 'Export',
  'config.cgi_backup': 'Archiv über cgi-io', 'config.ssh_root': 'Archiv über SSH',
  'config.uci_read': 'UCI lesen', 'config.packagelist': 'Paketliste',
};

export const VERSION_WARNING_TEXT: Record<string, string> = {
  archive_unavailable: 'Kein Archiv möglich, nur UCI-Snapshot',
  archive_warning: 'Archiv mit Auffälligkeiten',
  uci_missing: 'Einzelne UCI-Dateien fehlen',
  uci_failed: 'UCI-Lesen fehlgeschlagen',
  uci_unavailable: 'UCI nicht lesbar',
  uci_source: 'UCI aus Ersatzquelle',
  uci_too_large: 'UCI-Daten zu groß',
  uci_archive_mismatch: 'UCI und Archiv weichen ab',
  config_missing_in_archive: 'Konfiguration fehlt im Archiv',
};

// ── Parsers ──────────────────────────────────────────────────────────────

export function parseCapability(v: unknown): Capability {
  const c = obj(v) ?? {};
  return {
    state: str(c.state) ?? 'unknown',
    reason: str(c.reason),
    missing: strList(c.required_permissions ?? c.missing),
  };
}

function parseDriftSummary(v: unknown): DriftSummary | null {
  const d = obj(v);
  if (!d) return null;
  return {
    state: str(d.state) ?? 'unknown',
    driftId: str(d.drift_id),
    criticalCount: num(d.critical_count) ?? 0,
    unknownCount: num(d.unknown_count) ?? 0,
    checkedAt: str(d.checked_at),
    comparison: str(d.comparison),
  };
}

function parseRouterSummary(r: Obj): RouterSummary | null {
  const routerId = str(r.router_id);
  if (!routerId) return null;
  const sched = obj(r.schedule);
  return {
    routerId,
    name: str(r.name) ?? routerId,
    enabled: r.enabled === true,
    status: str(r.status) ?? 'never',
    errorClass: str(r.error_class),
    errorReason: str(r.error_reason),
    running: r.running === true,
    lastBackupAt: str(r.last_backup_at),
    versions: num(r.versions) ?? 0,
    capability: parseCapability(r.capability),
    schedule: sched
      ? { mode: str(sched.mode) ?? 'off', time: str(sched.time), nextRunAt: str(sched.next_run_at) }
      : null,
    drift: parseDriftSummary(r.drift),
    openwrtVersion: str(r.openwrt_version),
  };
}

export function parseOverview(raw: unknown): Overview {
  const o = obj(raw) ?? {};
  return {
    provider: str(o.provider),
    pendingApprovals: num(o.pending_approvals) ?? 0,
    routers: objList(o.routers).map(parseRouterSummary).filter((r): r is RouterSummary => r !== null),
  };
}

export function parseRouterDetail(raw: unknown): RouterDetail {
  const d = obj(raw) ?? {};
  const caps = obj(d.capabilities) ?? {};
  const pin = obj(d.ssh_pin);
  const acl = obj(d.acl);
  return {
    routerId: str(d.router_id) ?? '',
    enabled: d.enabled === true,
    capabilities: Object.fromEntries(Object.entries(caps).map(([k, v]) => [k, parseCapability(v)])),
    sshPin: pin ? { state: str(pin.state) ?? 'unknown', fingerprint: str(pin.fingerprint) } : null,
    acl: acl ? { offerable: strList(acl.offerable), deployedVersion: num(acl.deployed_version) } : null,
  };
}

function parseArtifacts(v: unknown): Artifact[] {
  const one = (kind: string | null, a: Obj): Artifact | null =>
    kind ? { kind, sizeBytes: num(a.size_bytes), sha256: str(a.sha256) } : null;
  if (Array.isArray(v)) {
    return objList(v).map(a => one(str(a.kind), a)).filter((a): a is Artifact => a !== null);
  }
  const map = obj(v) ?? {};
  return Object.entries(map)
    .map(([kind, a]) => one(kind, obj(a) ?? {}))
    .filter((a): a is Artifact => a !== null);
}

export function parseVersion(raw: unknown): Version {
  const v = obj(raw) ?? {};
  const artifacts = parseArtifacts(v.artifacts);
  const val = obj(v.validation) ?? {};
  const by = obj(v.created_by);
  const sizes = artifacts.map(a => a.sizeBytes).filter((n): n is number => n !== null);
  const main = artifacts.find(a => a.kind === 'archive') ?? artifacts[0];
  return {
    backupId: str(v.backup_id) ?? '',
    routerId: str(v.router_id) ?? '',
    createdAt: str(v.created_at),
    lastSeenAt: str(v.last_seen_at),
    reason: str(v.reason) ?? 'manual',
    backupType: str(v.backup_type) ?? 'partial',
    status: str(v.status) ?? 'ok',
    errorClass: str(v.error_class),
    protected: v.protected === true,
    createdBy: by ? { kind: str(by.kind) ?? 'system', mine: by.mine === true } : null,
    openwrtVersion: str(v.openwrt_version),
    validation: { state: str(val.state ?? val.status) ?? 'unverified', checkedAt: str(val.checked_at) },
    warnings: strList(v.warnings),
    note: str(v.note),
    artifacts,
    sizeBytes: num(v.size_bytes) ?? (sizes.length ? sizes.reduce((a, b) => a + b, 0) : null),
    sha256: str(v.sha256) ?? main?.sha256 ?? null,
  };
}

export function parseVersions(raw: unknown): Version[] {
  return objList(obj(raw)?.versions).map(parseVersion).filter(v => v.backupId !== '');
}

const OPS: ReadonlySet<string> = new Set(['added', 'removed', 'changed', 'reordered', 'not_comparable']);
const RISKS: ReadonlySet<string> = new Set(['critical', 'high', 'medium', 'low']);

/** True for a value the server masked (`***`, `**REDACTED**`, `{"secret": …}`). */
function isMasked(v: unknown): boolean {
  if (typeof v === 'string') return v.includes('***') || v.includes('REDACTED');
  const o = obj(v);
  return o !== null && Object.keys(o).length === 1 && 'secret' in o;
}

/** Plain display text of a UCI value (string, list, number); capped. */
function valueText(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  let text: string;
  if (typeof v === 'string') text = v;
  else if (typeof v === 'number' || typeof v === 'boolean') text = String(v);
  else if (Array.isArray(v)) text = v.map(x => (typeof x === 'string' ? x : JSON.stringify(x))).join(', ');
  else text = JSON.stringify(v);
  return text.length > 500 ? `${text.slice(0, 500)}…` : text;
}

function parseChange(c: Obj): Change {
  const rawOp = str(c.op) ?? str(c.kind) ?? 'changed';
  const op = (rawOp === 'modified' ? 'changed' : OPS.has(rawOp) ? rawOp : 'changed') as ChangeOp;
  const before = 'old' in c ? c.old : c.before;
  const after = 'new' in c ? c.new : c.after;
  const secret = c.secret === true || isMasked(before) || isMasked(after);
  const risk = str(c.risk);
  return {
    area: str(c.area) ?? 'other',
    risk: risk && RISKS.has(risk) ? (risk as RiskLevel) : null,
    config: str(c.config) ?? '',
    section: str(c.section) ?? '',
    option: str(c.option),
    op,
    oldText: secret ? null : valueText(before),
    newText: secret ? null : valueText(after),
    secret,
  };
}

function refId(v: unknown): string | null {
  if (typeof v === 'string') return v;
  const r = obj(v);
  if (!r) return null;
  if (r.kind === 'live') return 'live';
  return str(r.backup_id) ?? str(r.id);
}

export function parseDiff(raw: unknown): Diff {
  const d = obj(raw) ?? {};
  const truncated = d.truncated === true;
  return {
    from: refId(d.from) ?? refId(d.base),
    to: refId(d.to) ?? refId(d.other),
    complete: d.complete !== false && !truncated,
    truncated,
    changes: objList(d.changes).map(parseChange),
  };
}

function parseDriftReport(v: unknown): DriftReport | null {
  const r = obj(v);
  if (!r) return null;
  return {
    driftId: str(r.drift_id),
    checkedAt: str(r.checked_at),
    baselineBackupId: str(r.baseline_backup_id),
    criticalCount: num(r.critical_count) ?? 0,
    unknownCount: num(r.unknown_count) ?? 0,
    comparison: str(r.comparison) ?? 'unknown',
  };
}

export function parseDriftState(raw: unknown): DriftState {
  const d = obj(raw) ?? {};
  const acks: DriftAck[] = objList(d.acks).map(a => ({
    driftId: str(a.drift_id),
    state: str(a.state) ?? 'acknowledged',
    at: str(a.at) ?? str(a.acknowledged_at) ?? str(a.created_at),
    mine: obj(a.by ?? a.actor ?? a.created_by)?.mine === true,
  }));
  return { state: str(d.state) ?? 'unknown', report: parseDriftReport(d.report), acks };
}

export function parseRestorePlan(raw: unknown): RestorePlan {
  const p = obj(raw) ?? {};
  const compat = obj(p.compatibility);
  const findings: RestoreFinding[] = objList(p.findings ?? compat?.issues)
    .map(f => ({
      code: str(f.code) ?? 'unknown',
      blocking: f.blocking === true || f.level === 'block' || f.level === 'blocking',
    }));
  const steps: RestoreStep[] = objList(p.steps).map((s, i) => ({
    order: num(s.order) ?? i + 1,
    action: str(s.action) ?? 'unknown',
    instructions: str(s.instructions),
  }));
  const compatible = typeof p.compatible === 'boolean' ? p.compatible : compat?.compatible === true;
  return {
    backupId: str(p.backup_id) ?? '',
    compatible,
    findings,
    steps,
    warnings: strList(p.warnings),
    instructions: strList(p.instructions),
    requiresReboot: p.requires_reboot === true || steps.some(s => s.action === 'reboot'),
    expiresAt: str(p.expires_at),
    changes: p.diff ? parseDiff(p.diff).changes : [],
  };
}

export function parseApproval(raw: unknown): Approval {
  const a = obj(raw) ?? {};
  return {
    approvalId: str(a.approval_id) ?? '',
    action: str(a.action) ?? 'unknown',
    routerId: str(a.router_id),
    subjectId: str(a.subject_id),
    status: str(a.status) ?? 'pending',
    requestedByMine: obj(a.requested_by)?.mine === true,
    expiresAt: str(a.expires_at),
  };
}

export function parseApprovals(raw: unknown): Approval[] {
  return objList(obj(raw)?.approvals).map(parseApproval).filter(a => a.approvalId !== '');
}

export function parseAclOffer(raw: unknown): { approval: Approval; offer: AclOffer } {
  const r = obj(raw) ?? {};
  const offer = obj(r.offer) ?? {};
  const text = (v: unknown): string | null => {
    const s = str(v);
    return s !== null && !isMasked(s) ? s : null;
  };
  const targetFile = text(offer.target_file);
  const riskText = text(offer.risk_text);
  const rollbackText = text(offer.rollback_text);
  const rollbackTemplate = text(offer.rollback_template);
  const rollbackTemplateNoPrevious = text(offer.rollback_template_no_previous);
  const lists = Array.isArray(offer.rights_added) && Array.isArray(offer.rights_removed);
  return {
    approval: parseApproval(obj(r.approval) ?? r),
    offer: {
      added: strList(offer.added ?? offer.add),
      removed: strList(offer.removed ?? offer.remove),
      risks: strList(offer.risks),
      targetFile,
      rightsAdded: strList(offer.rights_added),
      rightsRemoved: strList(offer.rights_removed),
      rightsUnlisted: Math.max(0, Math.floor(num(offer.rights_unlisted) ?? 0)),
      riskText,
      rollbackText,
      rollbackTemplate,
      rollbackTemplateNoPrevious,
      complete: lists && targetFile !== null && riskText !== null && rollbackText !== null
        && rollbackTemplate !== null && rollbackTemplateNoPrevious !== null,
    },
  };
}

/** Body of R15: the plaintext acknowledgement only when it was given. */
export function approveBody(options?: { acknowledgePlaintext?: boolean }): Record<string, true> {
  return options?.acknowledgePlaintext === true ? { acknowledge_plaintext: true } : {};
}

// ── Router state and risk ────────────────────────────────────────────────

export type RouterViewState = 'disabled' | 'running' | 'blocked' | 'failed' | 'never' | 'drift' | 'partial' | 'ok';

export function isDriftOpen(d: { state: string } | null | undefined): boolean {
  return d?.state === 'open' || d?.state === 'drifted';
}

export function routerViewState(r: RouterSummary): RouterViewState {
  if (!r.enabled || r.status === 'disabled') return 'disabled';
  if (r.running || r.status === 'running') return 'running';
  if (r.capability.state === 'unavailable') return 'blocked';
  if (r.status === 'failed') return 'failed';
  if (r.versions === 0 || r.status === 'never') return 'never';
  if (isDriftOpen(r.drift)) return 'drift';
  if (r.status === 'partial') return 'partial';
  return 'ok';
}

/** No backup for this long counts as a risk (daily schedule = 3 missed runs). */
export const STALE_BACKUP_MS = 3 * 24 * 3600 * 1000;

export function routerRisk(r: RouterSummary, now: number): RouterRisk {
  if (!r.enabled || r.status === 'disabled') return 'none';
  const open = isDriftOpen(r.drift);
  if (open && (r.drift?.criticalCount ?? 0) > 0) return 'critical';
  if (r.status === 'failed' || open) return 'high';
  const last = r.lastBackupAt ? Date.parse(r.lastBackupAt) : NaN;
  const stale = !Number.isFinite(last) || now - last > STALE_BACKUP_MS;
  if (stale || r.status === 'partial' || r.capability.state === 'unavailable') return 'medium';
  return 'low';
}

export type ArchivePath = 'archive' | 'uci_only' | 'none' | 'unknown';

/** Can this router deliver a full archive, or only a UCI snapshot? */
export function archivePath(d: RouterDetail): ArchivePath {
  const st = (name: string) => d.capabilities[name]?.state ?? 'unknown';
  const ways = [st('config.cgi_backup'), st('config.ssh_root')];
  if (ways.includes('available')) return 'archive';
  if (ways.some(s => s !== 'unavailable')) return 'unknown';
  const uci = st('config.uci_read');
  if (uci === 'available') return 'uci_only';
  return uci === 'unavailable' ? 'none' : 'unknown';
}

// ── Diff ordering ────────────────────────────────────────────────────────

const RISK_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function riskRank(r: string | null): number {
  return r ? RISK_RANK[r] ?? 0 : 0;
}

export function isCriticalChange(c: Change): boolean {
  return c.risk === 'critical' || CRITICAL_AREAS.has(c.area);
}

/** Highest risk first; then config / section / option for a stable order. */
export function sortChanges(changes: readonly Change[]): Change[] {
  return [...changes].sort((a, b) =>
    riskRank(b.risk) - riskRank(a.risk)
    || a.config.localeCompare(b.config)
    || a.section.localeCompare(b.section)
    || (a.option ?? '').localeCompare(b.option ?? ''));
}

export interface ChangeGroup {
  area: string;
  label: string;
  critical: boolean;
  maxRisk: RiskLevel | null;
  counts: { added: number; removed: number; changed: number; other: number };
  changes: Change[];
}

export function groupChangesByArea(changes: readonly Change[]): ChangeGroup[] {
  const groups = new Map<string, Change[]>();
  for (const c of changes) groups.set(c.area, [...(groups.get(c.area) ?? []), c]);
  return [...groups.entries()]
    .map(([area, list]): ChangeGroup => {
      const sorted = sortChanges(list);
      const count = (op: ChangeOp) => list.filter(c => c.op === op).length;
      return {
        area,
        label: label(AREA_LABEL, area),
        critical: CRITICAL_AREAS.has(area) || list.some(c => c.risk === 'critical'),
        maxRisk: sorted[0]?.risk ?? null,
        counts: {
          added: count('added'), removed: count('removed'), changed: count('changed'),
          other: list.length - count('added') - count('removed') - count('changed'),
        },
        changes: sorted,
      };
    })
    .sort((a, b) =>
      riskRank(b.maxRisk) - riskRank(a.maxRisk)
      || Number(b.critical) - Number(a.critical)
      || a.label.localeCompare(b.label, 'de'));
}

/** Text of one side of a change; secrets never show a value. */
export function changeValueText(c: Change, side: 'old' | 'new'): string {
  if (c.secret) return 'geändert';
  const v = side === 'old' ? c.oldText : c.newText;
  return v ?? '–';
}

// ── Error texts ──────────────────────────────────────────────────────────

export const OPTION_HINT =
  'Das Konfigurations-Backup ist für diesen Router ausgeschaltet. Einschalten in den Optionen des Routers: '
  + 'Einstellungen → Geräte & Dienste → OpenWrt Router → Konfigurieren → „Konfigurations-Backup“.';

export const ERROR_TEXT: Record<string, string> = {
  router_not_found: 'Router nicht gefunden. Bitte die Liste aktualisieren.',
  backup_not_found: 'Version nicht gefunden – vielleicht von der Aufbewahrung entfernt.',
  authorization_denied: 'Nur für Administratoren.',
  approval_required: 'Für diese Aktion fehlt noch die Freigabe.',
  approval_invalid: 'Die Freigabe ist abgelaufen oder schon eingelöst. Bitte neu beantragen.',
  operation_in_progress:
    'Auf diesem Router läuft gerade ein anderer Vorgang (Backup, Drift- oder Live-Prüfung). Bitte gleich erneut versuchen.',
  rate_limited: 'Zu früh nach dem letzten manuellen Lauf, bitte später erneut versuchen.',
  plaintext_not_acknowledged:
    'Die Freigabe des Exports braucht die ausdrückliche Bestätigung, dass das Archiv Geheimnisse im Klartext enthält.',
  version_protected: 'Die Version ist geschützt.',
  provider_conflict: 'Ein anderes Backup-Modul ist angemeldet. Diese Ansicht ist nur lesbar.',
  capability_unavailable: 'Die Funktion ist für diesen Router nicht verfügbar.',
  backup_integrity_failed: 'Die Prüfsumme der gespeicherten Datei stimmt nicht. Es wurde nichts ausgeliefert.',
  backup_incomplete: 'Die Version ist unvollständig.',
  restore_incompatible: 'Die Version passt nicht zu diesem Router.',
  storage_ref_invalid: 'Der Speicherverweis der Version ist ungültig.',
  router_unavailable: 'Der Router ist nicht erreichbar.',
  provider_unavailable: 'Das Backup-Modul ist gerade nicht verfügbar.',
  core_not_running: 'Der Enterprise Core läuft nicht. Bitte die Integration neu laden.',
  operation_timeout: 'Zeitüberschreitung beim Router.',
  router_auth_failed: 'Die Anmeldung am Router ist fehlgeschlagen.',
  router_permission_denied: 'Dem Router fehlen Rechte (rpcd-ACL).',
  provider_error: 'Das Backup-Modul meldet einen Fehler.',
  artifact_too_large: 'Die Datei ist zu groß.',
  storage_full: 'Der Speicher für Versionen ist voll.',
  storage_error: 'Fehler beim Speichern der Version.',
  internal: 'Interner Fehler im Backend.',
  invalid_request: 'Die Anfrage war ungültig.',
  no_token: 'Für den Download fehlt das Zugangstoken. Bitte die Seite neu laden.',
  not_connected: 'Keine Verbindung zu Home Assistant.',
};

const STATUS_TEXT: Record<number, string> = {
  400: 'Ungültige Anfrage.',
  401: 'Sitzung abgelaufen. Bitte die Seite neu laden.',
  403: 'Nur für Administratoren.',
  404: 'Nicht gefunden.',
  409: 'Die Aktion ist gerade nicht möglich.',
  410: 'Die Integration ist nicht geladen.',
  413: 'Die Anfrage ist zu groß.',
  422: 'Die Version ist nicht verwendbar.',
  429: 'Zu früh nach dem letzten manuellen Lauf, bitte später erneut versuchen.',
  500: 'Interner Fehler im Backend.',
  502: 'Fehler beim Router.',
  503: 'Der Configuration Manager ist noch nicht bereit.',
  504: 'Zeitüberschreitung.',
  507: 'Der Speicher für Versionen ist voll.',
};

export type ErrorKind =
  | 'forbidden' | 'gone' | 'unavailable' | 'conflict' | 'disabled' | 'capability'
  | 'busy' | 'rate_limited' | 'expired' | 'auth' | 'network' | 'other';

export interface ErrorInfo {
  kind: ErrorKind;
  message: string;
  retry: boolean;
  /** Seconds from Retry-After (busy, rate_limited); the caller may lock its button that long. */
  retryAfter: number | null;
}

function errorKind(e: ConfigApiError): ErrorKind {
  if (e.code === 'not_connected') return 'network';
  if (e.status === 401) return 'auth';
  if (e.status === 403 || e.code === 'authorization_denied') return 'forbidden';
  if (e.status === 410) return 'gone';
  if (e.code === 'provider_conflict') return 'conflict';
  if (e.code === 'operation_in_progress') return 'busy';
  if (e.code === 'rate_limited' || e.status === 429) return 'rate_limited';
  if (e.code === 'approval_invalid') return 'expired';
  if (e.code === 'capability_unavailable') return e.details.reason === 'disabled' ? 'disabled' : 'capability';
  if (e.status === 503 || e.code === 'core_not_running' || e.code === 'provider_unavailable') return 'unavailable';
  return 'other';
}

/** Kind, German text and retry hint of a failed request; never the server text. */
export function errorInfo(err: unknown): ErrorInfo {
  if (!(err instanceof ConfigApiError)) {
    const name = (err as { name?: unknown } | null)?.name;
    if (err instanceof TypeError || name === 'AbortError' || name === 'NetworkError') {
      return { kind: 'network', message: 'Keine Verbindung zu Home Assistant. Bitte erneut versuchen.', retry: true, retryAfter: null };
    }
    return { kind: 'other', message: 'Unerwarteter Fehler im Panel.', retry: true, retryAfter: null };
  }
  const kind = errorKind(err);
  const retryAfter = err.retryAfter !== null && err.retryAfter > 0 ? Math.ceil(err.retryAfter) : null;
  let message = ERROR_TEXT[err.code] ?? (err.status !== null ? STATUS_TEXT[err.status] : undefined)
    ?? 'Die Anfrage ist fehlgeschlagen.';
  if (kind === 'disabled') message = OPTION_HINT;
  else if (kind === 'rate_limited' && retryAfter !== null) {
    message = `Zu früh nach dem letzten manuellen Lauf, bitte in ${retryAfter} Sekunden erneut versuchen.`;
  } else if (kind === 'capability' && err.details.reason) {
    message = `${message} Grund: ${label(CAP_REASON_TEXT, err.details.reason)}.`;
  }
  // rate_limited: no retry button; the caller locks its own button for retryAfter.
  const retry = kind !== 'rate_limited' && (err.retryable || ['unavailable', 'network', 'gone', 'busy'].includes(kind));
  return { kind, message, retry, retryAfter };
}

/** Error classes of a failed backup that mean "the router lacks the right". */
const ACCESS_ERROR_CLASSES = new Set(['permission', 'not_available']);

/** The entry talks plain HTTP: no archive over it (not a missing right). */
export function isTransportFailure(reason: string | null | undefined): boolean {
  return reason === 'insecure_transport';
}

/** Validate, protect and export answer 409 (disabled) while the option is off: lock them up front. */
export function versionActionLocks(s: { enabled: boolean }): { validate: boolean; protect: boolean; export: boolean } {
  const locked = !s.enabled;
  return { validate: locked, protect: locked, export: locked };
}

export function isAccessFailure(errorClass: string | null, reason: string | null = null): boolean {
  return errorClass !== null && ACCESS_ERROR_CLASSES.has(errorClass) && !isTransportFailure(reason);
}

export const ERROR_CLASS_TEXT: Record<string, string> = {
  permission: 'Dem Router fehlt das Recht für das Backup (rpcd-ACL).',
  not_available: 'Die Backup-Funktion ist auf dem Router nicht verfügbar – meist fehlt das Recht dafür (rpcd-ACL).',
  unreachable: 'Der Router war nicht erreichbar.',
  timeout: 'Zeitüberschreitung beim Router.',
  auth: 'Die Anmeldung am Router ist fehlgeschlagen.',
  too_large: 'Die Datei war zu groß.',
  incomplete: 'Die Sicherung war unvollständig.',
  invalid: 'Die Antwort des Routers war ungültig.',
  checksum_mismatch: 'Die Prüfsumme stimmte nicht.',
  storage_full: 'Der Speicher für Versionen ist voll.',
  storage_error: 'Die Version konnte nicht gespeichert werden.',
  busy: 'Auf dem Router lief gerade ein anderer Vorgang.',
  internal: 'Interner Fehler im Backend.',
};

/** German text for a failed backup's error class; access problems point to "Zugang". */
export function failureText(errorClass: string | null, errorReason: string | null = null): string {
  const base = 'Das letzte Backup ist fehlgeschlagen.';
  if (isTransportFailure(errorReason)) {
    return `${base} ${INSECURE_TRANSPORT_TEXT} Den SSH-Host-Key bestätigt man im Bereich „Zugang“ unten.`;
  }
  if (!errorClass) return base;
  const reason = ERROR_CLASS_TEXT[errorClass] ?? `Fehlerart: ${errorClass}.`;
  const hint = isAccessFailure(errorClass, errorReason)
    ? ' Im Bereich „Zugang“ unten kann das ACL-Angebot angefordert und nach Freigabe auf den Router geschrieben werden.'
    : '';
  return `${base} ${reason}${hint}`;
}

// ── Restore texts ────────────────────────────────────────────────────────

export const RESTORE_KEY_TEXT: Record<string, string> = {
  restore_blocked: 'Die Wiederherstellung ist blockiert. Erst die blockierenden Befunde klären.',
  restore_not_reversible: 'Eine Wiederherstellung ist nicht automatisch reversibel. Vorher eine aktuelle Sicherung anlegen.',
  restore_prepare_console_failsafe:
    'Konsole oder Failsafe-Modus bereithalten: Die Änderung kann Zugang, Management-IP oder Firewall-Eingang betreffen.',
  restore_review_warnings: 'Die Warnungen oben prüfen, bevor das Archiv eingespielt wird.',
  restore_install_missing_packages: 'Fehlende Pakete vorher auf dem Router installieren.',
  restore_apk_package_names: 'OpenWrt mit apk: Paketnamen können sich gegenüber opkg unterscheiden.',
  restore_release_eol: 'Das Release der Version bekommt keine Updates mehr; ein Wechsel auf ein aktuelles Release wird empfohlen.',
  restore_luci_upload: 'In LuCI unter „System → Sichern/Aktualisieren → Sicherung wiederherstellen“ das Archiv hochladen.',
  restore_cli_sysupgrade: 'Alternativ per SSH auf dem Router: sysupgrade -r <datei>.',
  restore_verify_after_reboot: 'Nach dem Neustart Erreichbarkeit, WAN, WLAN und Clients prüfen und in Home Assistant die Drift-Prüfung auslösen.',
  restore_secrets_and_identity:
    'Das Archiv setzt Passwörter, SSH-Schlüssel und Zertifikate zurück; Logins und Host-Key können sich ändern.',
  'config.restore.manual_upload':
    'Das Archiv von Hand einspielen: LuCI „System → Sichern/Aktualisieren → Sicherung wiederherstellen“ oder sysupgrade -r <datei>.',
};

export const FINDING_TEXT: Record<string, string> = {
  archive_invalid: 'Das Archiv ist ungültig.',
  checksum_mismatch: 'Die Prüfsumme des Archivs stimmt nicht.',
  checksum_unverified: 'Die Prüfsumme wurde noch nicht geprüft.',
  board_mismatch: 'Die Version stammt von anderer Hardware (Board).',
  board_unknown: 'Das Board ist unbekannt.',
  switch_model_mismatch: 'Anderes Switch-Modell (swconfig/DSA).',
  release_unknown: 'Das OpenWrt-Release ist unbekannt.',
  release_downgrade: 'Die Version stammt von einem älteren OpenWrt-Release (Downgrade).',
  release_major_change: 'Wechsel zwischen OpenWrt-Hauptversionen.',
  firewall_fw3_to_fw4: 'Firewall-Wechsel fw3 → fw4 (iptables → nftables).',
  package_manager_change: 'Anderer Paketmanager (opkg/apk).',
  missing_package: 'Ein benötigtes Paket fehlt auf dem Router.',
  packages_unknown: 'Die Paketliste ist unbekannt.',
  inventory_partial: 'Die Bestandsaufnahme des Routers ist unvollständig.',
  insufficient_space: 'Auf dem Router ist zu wenig Platz.',
  lockout_risk: 'Gefahr, sich auszusperren (Zugang, Management-IP oder Firewall-Eingang ändern sich).',
};

export const WARNING_TEXT: Record<string, string> = {
  snapshot_stale: 'Der Vergleich mit dem aktuellen Stand ist nicht mehr frisch.',
  snapshot_age_unknown: 'Das Alter des Vergleichsstands ist unbekannt.',
  config_not_comparable: 'Einzelne Konfigurationen ließen sich nicht vergleichen.',
  access_files_overwritten: 'Passwörter, SSH-Schlüssel oder TLS-Schlüssel werden überschrieben – der Login kann sich ändern.',
  restore_not_reversible: 'Nicht automatisch reversibel.',
};

const STEP_ACTION_TEXT: Record<string, string> = {
  archive_restore: 'Archiv von Hand einspielen (LuCI oder sysupgrade -r)',
  reboot: 'Der Router startet neu',
  uci_set: 'UCI-Wert setzen',
  uci_delete: 'UCI-Wert löschen',
};

export function restoreKeyText(key: string): string {
  return RESTORE_KEY_TEXT[key] ?? `Weiterer Hinweis (${key}).`;
}

export function stepText(s: RestoreStep): string {
  const base = STEP_ACTION_TEXT[s.action] ?? `Schritt ${s.action}`;
  return s.instructions ? `${base}: ${restoreKeyText(s.instructions)}` : base;
}

const CONNECTION_FINDINGS: ReadonlySet<string> = new Set(['lockout_risk']);
const CONNECTION_WARNINGS: ReadonlySet<string> = new Set(['access_files_overwritten']);

export interface RestoreImpact {
  areas: Array<{ area: string; label: string; count: number; maxRisk: RiskLevel | null; critical: boolean }>;
  critical: Change[];
  blocking: RestoreFinding[];
  warnings: RestoreFinding[];
  reboot: boolean;
  connectionRisk: boolean;
}

export function restoreImpact(plan: RestorePlan): RestoreImpact {
  const groups = groupChangesByArea(plan.changes);
  const critical = sortChanges(plan.changes.filter(isCriticalChange));
  const connectionRisk = plan.requiresReboot
    || plan.findings.some(f => CONNECTION_FINDINGS.has(f.code))
    || plan.warnings.some(w => CONNECTION_WARNINGS.has(w))
    || critical.length > 0;
  return {
    areas: groups.map(g => ({
      area: g.area, label: g.label, count: g.changes.length, maxRisk: g.maxRisk, critical: g.critical,
    })),
    critical,
    blocking: plan.findings.filter(f => f.blocking),
    warnings: plan.findings.filter(f => !f.blocking),
    reboot: plan.requiresReboot,
    connectionRisk,
  };
}

/** Checklist after a manual restore (plan 7.7 step 5). */
export const VERIFY_CHECKLIST: readonly string[] = [
  'Router antwortet wieder (Ping oder LuCI-Anmeldung).',
  'Management-IP und Zugang (SSH/LuCI) sind wie erwartet.',
  'WAN bzw. Uplink ist verbunden, Internet erreichbar.',
  'WLANs senden, Clients verbinden sich wieder.',
  'VLANs und Firewall-Zonen verhalten sich wie vorher.',
  'Die Integration in Home Assistant ist wieder verbunden.',
  'In dieser Ansicht „Drift jetzt prüfen“ auslösen und das Ergebnis ansehen.',
];

// ── Export flow (R13 → R15 → R17) ────────────────────────────────────────

export type ExportStep = 'idle' | 'requesting' | 'requested' | 'approving' | 'approved' | 'downloading' | 'done' | 'failed';

export interface ExportState {
  step: ExportStep;
  approval: Approval | null;
  /** The admin ticked "contains all secrets in plain text". */
  acknowledged: boolean;
  error: unknown;
  /** The approval is gone (expired / used / restart): only a new request helps. */
  renew: boolean;
  filename: string | null;
}

export type ExportEvent =
  | { type: 'request' }
  | { type: 'requested'; approval: Approval }
  | { type: 'resume'; approval: Approval }
  | { type: 'acknowledge'; value: boolean }
  | { type: 'approve' }
  | { type: 'approved'; approval: Approval }
  | { type: 'download' }
  | { type: 'downloaded'; filename: string }
  | { type: 'failed'; error: unknown }
  | { type: 'reset' };

export function exportInit(): ExportState {
  return { step: 'idle', approval: null, acknowledged: false, error: null, renew: false, filename: null };
}

export function isExpired(a: Approval | null, now: number): boolean {
  if (!a?.expiresAt) return false;
  const t = Date.parse(a.expiresAt);
  return Number.isFinite(t) && now >= t;
}

export function canApprove(s: ExportState, now: number): boolean {
  return s.step === 'requested' && s.acknowledged && s.approval?.status === 'pending' && !isExpired(s.approval, now);
}

/**
 * R15 options of an export approval: the plaintext acknowledgement, and
 * only once the admin ticked it. Null means "do not send the approval".
 */
export function exportApproveOptions(s: ExportState, now: number): { acknowledgePlaintext: true } | null {
  return canApprove(s, now) && s.acknowledged ? { acknowledgePlaintext: true } : null;
}

export function canDownload(s: ExportState, now: number): boolean {
  return s.step === 'approved' && s.acknowledged && s.approval?.status === 'approved' && !isExpired(s.approval, now);
}

function afterApproval(s: ExportState, approval: Approval): ExportState {
  const step: ExportStep = approval.status === 'approved' ? 'approved'
    : approval.status === 'pending' ? 'requested' : 'failed';
  return { ...s, step, approval, renew: step === 'failed', error: null };
}

export function exportReduce(s: ExportState, e: ExportEvent): ExportState {
  switch (e.type) {
    case 'request':
      return s.step === 'idle' || s.step === 'failed' || s.step === 'done'
        ? { ...exportInit(), step: 'requesting' } : s;
    case 'requested':
      return afterApproval({ ...s, acknowledged: false }, e.approval);
    case 'resume':
      return afterApproval({ ...exportInit() }, e.approval);
    case 'acknowledge':
      return s.step === 'requested' || s.step === 'approved' ? { ...s, acknowledged: e.value } : s;
    case 'approve':
      return s.step === 'requested' && s.acknowledged ? { ...s, step: 'approving' } : s;
    case 'approved':
      return s.step === 'approving' || s.step === 'requested' ? afterApproval(s, e.approval) : s;
    case 'download':
      return s.step === 'approved' && s.acknowledged && s.approval?.status === 'approved'
        ? { ...s, step: 'downloading' } : s;
    case 'downloaded':
      return s.step === 'downloading'
        ? { ...s, step: 'done', filename: e.filename, approval: s.approval && { ...s.approval, status: 'used' } }
        : s;
    case 'failed': {
      const code = e.error instanceof ConfigApiError ? e.error.code : '';
      const renew = code === 'approval_invalid' || code === 'approval_required' || code === 'backup_not_found';
      // A failed download of a still valid approval may be retried without a new request.
      const keep = !renew && s.step === 'downloading';
      return { ...s, step: keep ? 'approved' : 'failed', error: e.error, renew };
    }
    case 'reset':
      return exportInit();
  }
}

// ── Restore wizard (R12, then export + manual steps; never executes) ─────

export type RestoreWizardStep = 'compat' | 'preview' | 'confirm' | 'guide';
const WIZARD_ORDER: readonly RestoreWizardStep[] = ['compat', 'preview', 'confirm', 'guide'];

export interface RestoreWizardState {
  step: RestoreWizardStep;
  backupId: string;
  plan: RestorePlan | null;
  loading: boolean;
  error: unknown;
  /** "Ich habe verstanden: nicht automatisch reversibel …" */
  understood: boolean;
}

export type RestoreEvent =
  | { type: 'checked'; plan: RestorePlan }
  | { type: 'failed'; error: unknown }
  | { type: 'select'; backupId: string }
  | { type: 'understood'; value: boolean }
  | { type: 'next' }
  | { type: 'back' };

export function restoreInit(backupId: string): RestoreWizardState {
  return { step: 'compat', backupId, plan: null, loading: true, error: null, understood: false };
}

export function restoreCanProceed(s: RestoreWizardState): boolean {
  switch (s.step) {
    case 'compat': return !s.loading && s.plan !== null && s.plan.compatible;
    case 'preview': return true;
    case 'confirm': return s.understood;
    case 'guide': return false;
  }
}

export function restoreReduce(s: RestoreWizardState, e: RestoreEvent): RestoreWizardState {
  const at = WIZARD_ORDER.indexOf(s.step);
  switch (e.type) {
    case 'checked': return { ...s, plan: e.plan, loading: false, error: null };
    case 'failed': return { ...s, loading: false, error: e.error };
    case 'select': return restoreInit(e.backupId);
    case 'understood': return s.step === 'confirm' ? { ...s, understood: e.value } : s;
    case 'next': return restoreCanProceed(s) ? { ...s, step: WIZARD_ORDER[at + 1] } : s;
    case 'back': return at > 0 ? { ...s, step: WIZARD_ORDER[at - 1] } : s;
  }
}

// ── Formatting ───────────────────────────────────────────────────────────

export function formatTime(iso: string | null): string {
  if (!iso) return '–';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '–';
  return d.toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

export function formatRelative(iso: string | null, now: number): string {
  if (!iso) return '–';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '–';
  const diff = Math.round((now - t) / 60000);
  const abs = Math.abs(diff);
  const text = abs < 1 ? 'jetzt'
    : abs < 60 ? `${abs} min`
    : abs < 48 * 60 ? `${Math.round(abs / 60)} h`
    : `${Math.round(abs / 1440)} Tagen`;
  if (text === 'jetzt') return text;
  return diff >= 0 ? `vor ${text}` : `in ${text}`;
}

export function formatBytes(n: number | null): string {
  if (n === null) return '–';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toLocaleString('de-DE', { maximumFractionDigits: 1 })} KB`;
  return `${(n / 1024 / 1024).toLocaleString('de-DE', { maximumFractionDigits: 1 })} MB`;
}

export function shortHash(h: string | null): string {
  return h ? h.slice(0, 12) : '–';
}

/** Note text the routes accept: no control characters, at most 200 characters. */
export function sanitizeNote(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f-\u009f]/g, '').replace(/\s+/g, ' ').trim().slice(0, 200);
}

/** File name from Content-Disposition (filename* preferred); null if absent. */
export function parseContentDisposition(header: string | null): string | null {
  if (!header) return null;
  const star = /filename\*\s*=\s*[A-Za-z0-9-]*''([^;]+)/i.exec(header);
  if (star) {
    try {
      return decodeURIComponent(star[1].trim());
    } catch {
      return null;
    }
  }
  const quoted = /filename\s*=\s*"([^"]*)"/i.exec(header);
  if (quoted) return quoted[1];
  const plain = /filename\s*=\s*([^;]+)/i.exec(header);
  return plain ? plain[1].trim() : null;
}

/** Download name reduced to [A-Za-z0-9._-]; fallback by content type. */
export function safeFilename(name: string | null, contentType: string | null): string {
  const cleaned = (name ?? '')
    .replace(/[^A-Za-z0-9._-]/g, '_')
    .replace(/\.{2,}/g, '.')
    .replace(/_+/g, '_')
    .replace(/^[._-]+/, '')
    .slice(0, 100);
  if (cleaned && /[A-Za-z0-9]/.test(cleaned)) return cleaned;
  const type = contentType ?? '';
  const ext = type.includes('gzip') ? 'tar.gz' : type.includes('json') ? 'json' : 'bin';
  return `openwrt-config.${ext}`;
}

/** Versions that can be restored at all: not failed and holding an archive. */
export function restorableVersions(versions: readonly Version[]): Version[] {
  return versions.filter(v => v.status !== 'failed' && v.artifacts.some(a => a.kind === 'archive'));
}

/** Positions (0 = oldest edge, 1 = now) of versions inside the last `days`. */
export function timelinePoints(versions: readonly Version[], now: number, days = 30):
  Array<{ backupId: string; pos: number; status: string; reason: string; createdAt: string | null }> {
  const span = days * 24 * 3600 * 1000;
  return versions.flatMap(v => {
    const t = v.createdAt ? Date.parse(v.createdAt) : NaN;
    if (!Number.isFinite(t) || now - t > span || t > now) return [];
    return [{ backupId: v.backupId, pos: 1 - (now - t) / span, status: v.status, reason: v.reason, createdAt: v.createdAt }];
  });
}

/** While a backup runs the view re-reads every 5 s, for at most 5 min (plan 8). */
export const POLL_INTERVAL_MS = 5_000;
export const POLL_LIMIT_MS = 300_000;
