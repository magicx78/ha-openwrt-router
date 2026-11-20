/**
 * securityApi.ts — client of /api/openwrt_topology/security/*.
 *
 * Bearer fetch on the same origin (HA's token from hass.auth); a 401 is
 * retried once after a token refresh (own copy of the panel's refresh, like
 * configApi.ts; api.ts stays unchanged). Without a token the JSON routes
 * fall back to hass.callApi.
 *
 * Errors become SecurityApiError(status, code, details): the server's
 * `message` is never kept. Nothing is logged or stored. Query strings carry
 * only the backend's own overview filters (including `client`); the only
 * identity in a path is the MAC of the admin device routes.
 */

import {
  CATEGORIES,
  SecurityApiError,
  isRealMac,
  parseIncident,
  parseIncidentDetail,
  parseDetectionsView,
  parseOverview,
  parseSettingsView,
} from './securityLogic.ts';
import type {
  IncidentStatus,
  OverviewFilters,
  SecurityApi,
  SecurityHass,
  SettingsUpdate,
} from './securityTypes';

export const SECURITY_BASE = '/api/openwrt_topology/security';

const enc = encodeURIComponent;

const EPOCH_MAX = 4_102_444_800;
const TOKEN_RE = /^[A-Za-z0-9_.:-]{1,64}$/;
const CLIENT_REF_RE = /^cli_[A-Za-z0-9_-]{1,60}$/;
const INCIDENT_RE = /^sec_[A-Za-z0-9_-]{1,60}$/;
const SEVERITIES: ReadonlySet<string> = new Set(['info', 'warning', 'critical']);

function epoch(v: unknown): string | null {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= EPOCH_MAX ? String(Math.floor(v)) : null;
}

/**
 * Query string of the overview. Only the backend's keys are sent and every
 * value is checked first; an unusable value is dropped, not sent.
 */
export function overviewQuery(f: OverviewFilters = {}): string {
  const q: Array<[string, string]> = [];
  const since = epoch(f.since);
  const until = epoch(f.until);
  if (since !== null) q.push(['since', since]);
  if (until !== null) q.push(['until', until]);
  if (f.routerId && TOKEN_RE.test(f.routerId)) q.push(['router_id', f.routerId]);
  if (f.client && (CLIENT_REF_RE.test(f.client) || isRealMac(f.client))) q.push(['client', f.client]);
  if (f.category && CATEGORIES.includes(f.category)) q.push(['category', f.category]);
  if (f.severity && SEVERITIES.has(f.severity)) q.push(['severity', f.severity]);
  if (typeof f.limit === 'number' && Number.isInteger(f.limit) && f.limit >= 1 && f.limit <= 500) {
    q.push(['limit', String(f.limit)]);
  }
  return q.length ? `?${q.map(([k, v]) => `${enc(k)}=${enc(v)}`).join('&')}` : '';
}

function badInput(field: string): SecurityApiError {
  return new SecurityApiError(400, 'invalid_request', { field });
}

function checkedIncident(id: string): string {
  if (!INCIDENT_RE.test(id)) throw badInput('incident_id');
  return enc(id);
}

function checkedMac(mac: string): string {
  if (!isRealMac(mac)) throw badInput('mac');
  return enc(mac);
}

/** Route paths below SECURITY_BASE. */
export const securityPaths = {
  overview: (f: OverviewFilters = {}) => `overview${overviewQuery(f)}`,
  incident: (id: string) => `incidents/${checkedIncident(id)}`,
  incidentStatus: (id: string) => `incidents/${checkedIncident(id)}/status`,
  detections: () => 'detections',
  settings: () => 'settings',
  deviceConfirm: (mac: string) => `devices/${checkedMac(mac)}/confirm`,
  deviceName: (mac: string) => `devices/${checkedMac(mac)}/name`,
};

type Method = 'GET' | 'POST';
type FetchLike = (url: string, init: RequestInit & { headers: Record<string, string> }) => Promise<Response>;

export interface SecurityApiDeps {
  fetch?: FetchLike;
}

function token(hass: SecurityHass): string | undefined {
  return hass.auth?.data?.access_token;
}

async function refreshToken(hass: SecurityHass): Promise<boolean> {
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
function errorFrom(status: number | null, body: unknown): SecurityApiError {
  const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const d = b.details && typeof b.details === 'object' ? (b.details as Record<string, unknown>) : {};
  return new SecurityApiError(status, typeof b.code === 'string' ? b.code : '', {
    field: typeof d.field === 'string' ? d.field : undefined,
    reason: typeof d.reason === 'string' ? d.reason : undefined,
  });
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
    if (typeof e.status_code === 'number') return errorFrom(e.status_code, e.body);
  }
  return err;
}

export function createSecurityApi(getHass: () => SecurityHass | null, deps: SecurityApiDeps = {}): SecurityApi {
  const doFetch: FetchLike = deps.fetch ?? ((url, init) => window.fetch(url, init));

  function hassOrThrow(): SecurityHass {
    const hass = getHass();
    if (!hass) throw new SecurityApiError(null, 'not_connected');
    return hass;
  }

  async function send(hass: SecurityHass, method: Method, path: string, body: unknown): Promise<Response> {
    const headers: Record<string, string> = { Authorization: `Bearer ${token(hass) ?? ''}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    return doFetch(`${SECURITY_BASE}/${path}`, {
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
    if (!response.ok) throw errorFrom(response.status, await readJson(response));
    return response;
  }

  async function json(method: Method, path: string, body?: unknown): Promise<unknown> {
    const hass = hassOrThrow();
    if (token(hass) === undefined) {
      try {
        return await hass.callApi<unknown>(method, `openwrt_topology/security/${path}`,
          body as Record<string, unknown> | undefined);
      } catch (err) {
        throw callApiError(err);
      }
    }
    return readJson(await authorised(method, path, body));
  }

  return {
    overview: async filters => parseOverview(await json('GET', securityPaths.overview(filters))),
    incident: async id => {
      const d = parseIncidentDetail(await json('GET', securityPaths.incident(id)));
      if (!d) throw new SecurityApiError(200, 'invalid_response');
      return d;
    },
    detections: async () => parseDetectionsView(await json('GET', securityPaths.detections())),
    settings: async () => parseSettingsView(await json('GET', securityPaths.settings())),
    updateSettings: async (update: SettingsUpdate) =>
      parseSettingsView(await json('POST', securityPaths.settings(), update)),
    setIncidentStatus: async (id: string, status: IncidentStatus) => {
      const r = (await json('POST', securityPaths.incidentStatus(id), { status })) as Record<string, unknown> | null;
      const inc = parseIncident(r?.incident);
      if (!inc) throw new SecurityApiError(200, 'invalid_response');
      return inc;
    },
    confirmDevice: async (mac, name) => {
      await json('POST', securityPaths.deviceConfirm(mac), name !== undefined ? { name } : {});
    },
    setDeviceName: async (mac, name) => {
      await json('POST', securityPaths.deviceName(mac), { name });
    },
  };
}
