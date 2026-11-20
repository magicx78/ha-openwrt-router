/**
 * configTypes.ts — shapes of the Configuration Manager panel (plan 7.5).
 *
 * The server sends snake_case JSON; configLogic.ts parses it defensively into
 * these camelCase view types (unknown fields ignored, missing ones defaulted),
 * so a renamed backend field breaks one parser, not the views.
 * Type-only module: no runtime code (node --test strips it).
 */

/** Minimal hass the config client needs (structurally the panel's HassLike). */
export interface ConfigHass {
  callApi<T>(method: 'GET' | 'POST', path: string, parameters?: Record<string, unknown>): Promise<T>;
  user?: { is_admin?: boolean };
  auth?: {
    data?: { access_token?: string };
    expired?: boolean;
    refreshAccessToken?: () => Promise<void>;
  };
}

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';
/** Overview risk indicator; 'none' = module off for this router. */
export type RouterRisk = RiskLevel | 'none';

export interface Capability {
  state: string; // available | unavailable | unknown | disabled
  reason: string | null;
  missing: string[]; // required_permissions
}

export interface DriftSummary {
  state: string; // open | acknowledged | known | clean | unknown
  driftId: string | null;
  criticalCount: number;
  unknownCount: number;
  checkedAt: string | null;
  comparison: string | null;
}

export interface RouterSummary {
  routerId: string;
  name: string;
  enabled: boolean;
  status: string; // ok | partial | failed | running | disabled | never
  errorClass: string | null;
  running: boolean;
  lastBackupAt: string | null;
  versions: number;
  capability: Capability;
  schedule: { mode: string; time: string | null; nextRunAt: string | null } | null;
  drift: DriftSummary | null;
  openwrtVersion: string | null;
}

export interface Overview {
  provider: string | null;
  pendingApprovals: number;
  routers: RouterSummary[];
}

export interface RouterDetail {
  routerId: string;
  enabled: boolean;
  capabilities: Record<string, Capability>;
  sshPin: { state: string; fingerprint: string | null } | null;
  acl: { offerable: string[]; deployedVersion: number | null } | null;
}

export interface Artifact {
  kind: string; // archive | uci | inventory
  sizeBytes: number | null;
  sha256: string | null;
}

export interface Version {
  backupId: string;
  routerId: string;
  createdAt: string | null;
  lastSeenAt: string | null;
  reason: string;
  backupType: string;
  status: string; // ok | partial | failed
  errorClass: string | null;
  protected: boolean;
  createdBy: { kind: string; mine: boolean } | null;
  openwrtVersion: string | null;
  validation: { state: string; checkedAt: string | null };
  warnings: string[];
  note: string | null;
  artifacts: Artifact[];
  sizeBytes: number | null;
  sha256: string | null;
}

export type ChangeOp = 'added' | 'removed' | 'changed' | 'reordered' | 'not_comparable';

export interface Change {
  area: string;
  risk: RiskLevel | null;
  config: string;
  section: string;
  option: string | null;
  op: ChangeOp;
  /** Display text of the old / new value; null for secrets (shown as "geändert"). */
  oldText: string | null;
  newText: string | null;
  secret: boolean;
}

export interface Diff {
  from: string | null;
  to: string | null;
  complete: boolean;
  truncated: boolean;
  changes: Change[];
}

export interface DriftAck {
  driftId: string | null;
  state: string;
  at: string | null;
  mine: boolean;
}

export interface DriftReport {
  driftId: string | null;
  checkedAt: string | null;
  baselineBackupId: string | null;
  criticalCount: number;
  unknownCount: number;
  comparison: string;
}

export interface DriftState {
  state: string;
  report: DriftReport | null;
  acks: DriftAck[];
}

export interface RestoreFinding {
  code: string;
  blocking: boolean;
}

export interface RestoreStep {
  order: number;
  action: string;
  instructions: string | null;
}

export interface RestorePlan {
  backupId: string;
  compatible: boolean;
  findings: RestoreFinding[];
  steps: RestoreStep[];
  warnings: string[];
  instructions: string[];
  requiresReboot: boolean;
  expiresAt: string | null;
  changes: Change[];
}

export interface Approval {
  approvalId: string;
  action: string; // export | acl_deploy | ssh_pin_confirm | ssh_pin_reset
  routerId: string | null;
  subjectId: string | null;
  status: string; // pending | approved | rejected | expired | used
  requestedByMine: boolean;
  expiresAt: string | null;
}

export interface AclOffer {
  added: string[];
  removed: string[];
  risks: string[];
  /** Fixed core texts of R18 (null in the older response form). */
  targetFile: string | null;
  rightsAdded: string[];
  rightsRemoved: string[];
  rightsUnlisted: number;
  riskText: string | null;
  rollbackText: string | null;
  rollbackTemplate: string | null;
  rollbackTemplateNoPrevious: string | null;
  /** All texts above are present and unmasked; only then may it be approved. */
  complete: boolean;
}

/** Options of R15; only an export approval carries the plaintext acknowledgement. */
export interface ApproveOptions {
  acknowledgePlaintext?: boolean;
}

export type ExportArtifact = 'archive' | 'uci' | 'inventory';
export type DriftAckChoice = 'acknowledged' | 'known';
export type SshPinOp = 'confirm' | 'reset';

/** Result of R17 after the file was handed to the browser. */
export interface DownloadResult {
  filename: string;
  sizeBytes: number;
}

/** Client of /api/openwrt_topology/config/* (routes R1–R20). */
export interface ConfigApi {
  overview(): Promise<Overview>;
  router(routerId: string): Promise<RouterDetail>;
  versions(routerId: string, query?: { limit?: number; since?: string }): Promise<Version[]>;
  version(backupId: string): Promise<Version>;
  backup(routerId: string, note?: string): Promise<{ backupId: string | null; created: boolean; status: string }>;
  validate(backupId: string): Promise<Version>;
  protect(backupId: string, value: boolean): Promise<Version>;
  diff(routerId: string, from: string, to: string): Promise<Diff>;
  drift(routerId: string): Promise<DriftState>;
  driftCheck(routerId: string): Promise<DriftState>;
  driftAck(routerId: string, driftId: string, state: DriftAckChoice, note?: string): Promise<DriftState>;
  restoreCheck(backupId: string): Promise<RestorePlan>;
  requestExport(backupId: string, artifact?: ExportArtifact): Promise<Approval>;
  approvals(routerId?: string): Promise<Approval[]>;
  approve(approvalId: string, options?: ApproveOptions): Promise<Approval>;
  reject(approvalId: string, reason?: string): Promise<Approval>;
  download(approvalId: string): Promise<DownloadResult>;
  aclOffer(routerId: string): Promise<{ approval: Approval; offer: AclOffer }>;
  sshPin(routerId: string, op: SshPinOp): Promise<Approval>;
  execute(approvalId: string): Promise<{ done: boolean }>;
}
