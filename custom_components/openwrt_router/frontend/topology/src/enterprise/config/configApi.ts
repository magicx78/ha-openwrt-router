/**
 * configApi.ts — client of /api/openwrt_topology/config/* (plan 7.5, R1–R20).
 *
 * Bearer fetch on the same origin (HA's token from hass.auth); a 401 is
 * retried once after a token refresh (own copy of the panel's refresh,
 * LÜCKE L9 — api.ts stays unchanged). Without a token the JSON routes fall
 * back to hass.callApi; the download (R17) needs the token and refuses.
 *
 * Errors become ConfigApiError(status, code, retryable, details): the
 * server's `message` is never kept. Nothing is logged or stored.
 */

import {
  ConfigApiError,
  parseAclOffer,
  parseApproval,
  parseApprovals,
  parseDiff,
  parseDriftState,
  parseOverview,
  parseRestorePlan,
  parseRouterDetail,
  parseVersion,
  parseVersions,
  parseContentDisposition,
  safeFilename,
  sanitizeNote,
} from './configLogic.ts';
import type { ConfigApi, ConfigHass, ExportArtifact } from './configTypes';

export const CONFIG_BASE = '/api/openwrt_topology/config';

const enc = encodeURIComponent;

function query(q: Record<string, string | number | undefined>): string {
  const parts = Object.entries(q)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${enc(k)}=${enc(String(v))}`);
  return parts.length ? `?${parts.join('&')}` : '';
}

/** Route paths below CONFIG_BASE; every id is URI-encoded. */
export const configPaths = {
  overview: () => 'overview',
  router: (rid: string) => `routers/${enc(rid)}`,
  versions: (rid: string, q: { limit?: number; since?: string } = {}) =>
    `routers/${enc(rid)}/versions${query({ limit: q.limit, since: q.since })}`,
  version: (bid: string) => `versions/${enc(bid)}`,
  backup: (rid: string) => `routers/${enc(rid)}/backup`,
  validate: (bid: string) => `versions/${enc(bid)}/validate`,
  protect: (bid: string) => `versions/${enc(bid)}/protect`,
  diff: (rid: string, from: string, to: string) => `routers/${enc(rid)}/diff${query({ from, to })}`,
  drift: (rid: string) => `routers/${enc(rid)}/drift`,
  driftCheck: (rid: string) => `routers/${enc(rid)}/drift/check`,
  driftAck: (rid: string, driftId: string) => `routers/${enc(rid)}/drift/${enc(driftId)}/ack`,
  restoreCheck: (bid: string) => `versions/${enc(bid)}/restore-check`,
  exportRequest: (bid: string) => `versions/${enc(bid)}/export`,
  approvals: (rid?: string) => `approvals${query({ router_id: rid })}`,
  approve: (aid: string) => `approvals/${enc(aid)}/approve`,
  reject: (aid: string) => `approvals/${enc(aid)}/reject`,
  download: (aid: string) => `approvals/${enc(aid)}/download`,
  aclOffer: (rid: string) => `routers/${enc(rid)}/acl-offer`,
  sshPin: (rid: string, op: 'confirm' | 'reset') => `routers/${enc(rid)}/ssh-pin/${enc(op)}`,
  execute: (aid: string) => `approvals/${enc(aid)}/execute`,
};

type Method = 'GET' | 'POST';
type FetchLike = (url: string, init: RequestInit & { headers: Record<string, string> }) => Promise<Response>;

export interface ConfigApiDeps {
  fetch?: FetchLike;
  /** Hands the file to the browser; default: short-lived object URL + <a download>. */
  saveBlob?: (blob: Blob, filename: string) => void;
}

/** Default save: object URL lives only until the click has been handled. */
export function saveBlobInBrowser(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  try {
    a.click();
  } finally {
    a.remove();
    // Revoke after the browser has started the download (immediate revoke
    // cancels it in some browsers).
    setTimeout(() => URL.revokeObjectURL(url), 1_000);
  }
}

function token(hass: ConfigHass): string | undefined {
  return hass.auth?.data?.access_token;
}

async function refreshToken(hass: ConfigHass): Promise<boolean> {
  const refresh = hass.auth?.refreshAccessToken;
  if (typeof refresh !== 'function') return false;
  try {
    await refresh.call(hass.auth);
    return true;
  } catch {
    return false;
  }
}

/** Build the error from status + JSON body; the body's `message` is dropped. */
function errorFrom(status: number | null, body: unknown, retryAfter: string | null): ConfigApiError {
  const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const details = b.details && typeof b.details === 'object' ? (b.details as Record<string, unknown>) : {};
  const ra = retryAfter !== null ? Number(retryAfter) : NaN;
  return new ConfigApiError(
    status,
    typeof b.code === 'string' ? b.code : '',
    b.retryable === true,
    {
      state: typeof details.state === 'string' ? details.state : undefined,
      reason: typeof details.reason === 'string' ? details.reason : undefined,
    },
    Number.isFinite(ra) ? ra : null,
  );
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/** hass.callApi rejects with { status_code, body }; map it like a fetch error. */
function callApiError(err: unknown): unknown {
  if (err && typeof err === 'object' && !(err instanceof Error)) {
    const e = err as { status_code?: unknown; body?: unknown };
    if (typeof e.status_code === 'number') return errorFrom(e.status_code, e.body, null);
  }
  return err;
}

export function createConfigApi(getHass: () => ConfigHass | null, deps: ConfigApiDeps = {}): ConfigApi {
  const doFetch: FetchLike = deps.fetch ?? ((url, init) => window.fetch(url, init));
  const save = deps.saveBlob ?? saveBlobInBrowser;

  function hassOrThrow(): ConfigHass {
    const hass = getHass();
    if (!hass) throw new ConfigApiError(null, 'not_connected', true, {}, null);
    return hass;
  }

  async function send(hass: ConfigHass, method: Method, path: string, body: unknown): Promise<Response> {
    const t = token(hass);
    const headers: Record<string, string> = { Authorization: `Bearer ${t ?? ''}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    return doFetch(`${CONFIG_BASE}/${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
      cache: 'no-store',
    });
  }

  /** One authorised request; a 401 is retried once after a token refresh. */
  async function authorised(method: Method, path: string, body: unknown): Promise<Response> {
    const hass = hassOrThrow();
    if (hass.auth?.expired) await refreshToken(hass);
    let response = await send(hass, method, path, body);
    if (response.status === 401 && (await refreshToken(hass))) {
      response = await send(hass, method, path, body);
    }
    if (!response.ok) {
      throw errorFrom(response.status, await readJson(response), response.headers.get('Retry-After'));
    }
    return response;
  }

  async function json(method: Method, path: string, body?: unknown): Promise<unknown> {
    const hass = hassOrThrow();
    if (token(hass) === undefined) {
      try {
        return await hass.callApi<unknown>(method, `openwrt_topology/config/${path}`,
          body as Record<string, unknown> | undefined);
      } catch (err) {
        throw callApiError(err);
      }
    }
    return readJson(await authorised(method, path, body));
  }

  const post = (path: string, body: Record<string, unknown> = {}) => json('POST', path, body);

  return {
    overview: async () => parseOverview(await json('GET', configPaths.overview())),
    router: async rid => parseRouterDetail(await json('GET', configPaths.router(rid))),
    versions: async (rid, q) => parseVersions(await json('GET', configPaths.versions(rid, q))),
    version: async bid => parseVersion(await json('GET', configPaths.version(bid))),
    backup: async (rid, note) => {
      const clean = note !== undefined ? sanitizeNote(note) : '';
      const r = (await post(configPaths.backup(rid), clean ? { note: clean } : {})) as Record<string, unknown> | null;
      return {
        backupId: typeof r?.backup_id === 'string' ? r.backup_id : null,
        created: r?.created === true,
        status: typeof r?.status === 'string' ? r.status : 'ok',
      };
    },
    validate: async bid => parseVersion(await post(configPaths.validate(bid))),
    protect: async (bid, value) => parseVersion(await post(configPaths.protect(bid), { protected: value })),
    diff: async (rid, from, to) => parseDiff(await json('GET', configPaths.diff(rid, from, to))),
    drift: async rid => parseDriftState(await json('GET', configPaths.drift(rid))),
    driftCheck: async rid => parseDriftState(await post(configPaths.driftCheck(rid))),
    driftAck: async (rid, driftId, state, note) => {
      const clean = note !== undefined ? sanitizeNote(note) : '';
      return parseDriftState(await post(configPaths.driftAck(rid, driftId), clean ? { state, note: clean } : { state }));
    },
    restoreCheck: async bid => parseRestorePlan(await post(configPaths.restoreCheck(bid))),
    requestExport: async (bid, artifact?: ExportArtifact) =>
      parseApproval(await post(configPaths.exportRequest(bid), artifact ? { artifact } : {})),
    approvals: async rid => parseApprovals(await json('GET', configPaths.approvals(rid))),
    approve: async aid => parseApproval(await post(configPaths.approve(aid))),
    reject: async (aid, reason) => {
      const clean = reason !== undefined ? sanitizeNote(reason) : '';
      return parseApproval(await post(configPaths.reject(aid), clean ? { reason: clean } : {}));
    },
    download: async aid => {
      const hass = hassOrThrow();
      if (token(hass) === undefined) throw new ConfigApiError(null, 'no_token', false, {}, null);
      const response = await authorised('POST', configPaths.download(aid), {});
      const type = response.headers.get('Content-Type');
      const filename = safeFilename(parseContentDisposition(response.headers.get('Content-Disposition')), type);
      const blob = await response.blob();
      save(blob, filename);
      return { filename, sizeBytes: blob.size };
    },
    aclOffer: async rid => parseAclOffer(await post(configPaths.aclOffer(rid))),
    sshPin: async (rid, op) => parseApproval(await post(configPaths.sshPin(rid, op))),
    execute: async aid => {
      const r = (await post(configPaths.execute(aid))) as Record<string, unknown> | null;
      return { done: r?.done === true };
    },
  };
}
