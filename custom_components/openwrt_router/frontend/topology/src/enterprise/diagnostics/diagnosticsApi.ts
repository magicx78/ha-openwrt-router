/**
 * diagnosticsApi.ts — client of /api/openwrt_topology/diagnostics/*.
 *
 * Same pattern as securityApi.ts: Bearer fetch on the same origin (HA's
 * token from hass.auth); a 401 is retried once after a token refresh;
 * without a token the JSON routes fall back to hass.callApi. This is the
 * only place of the tab that talks to the network.
 *
 * Errors become DiagApiError(status, code, details): the server's `message`
 * is never kept. A 429's Retry-After header is read into details.retryAfter
 * (the callApi fallback cannot see headers, so there it stays null). Nothing
 * is logged or stored. Query strings are never built: the routes used here
 * take none. The run body carries configured target IDs only; anything that
 * does not look like an ID is refused before a request is made.
 */

import {
  DiagApiError,
  MAX_RUN_TARGETS,
  isTargetId,
  parseHistory,
  parseOverview,
  parseRetryAfter,
  parseRunResult,
  parseSettingsView,
} from './diagnosticsLogic.ts';
import type { DiagApi, DiagHass, SettingsUpdate } from './diagnosticsTypes';

export const DIAG_BASE = '/api/openwrt_topology/diagnostics';

/** Route paths below DIAG_BASE. */
export const diagPaths = {
  overview: 'overview',
  history: 'history',
  settings: 'settings',
  run: 'run',
};

type Method = 'GET' | 'POST';
type FetchLike = (url: string, init: RequestInit & { headers: Record<string, string> }) => Promise<Response>;

export interface DiagApiDeps {
  fetch?: FetchLike;
}

function token(hass: DiagHass): string | undefined {
  return hass.auth?.data?.access_token;
}

async function refreshToken(hass: DiagHass): Promise<boolean> {
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
function errorFrom(status: number | null, body: unknown, retryAfter: number | null = null): DiagApiError {
  const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const d = b.details && typeof b.details === 'object' ? (b.details as Record<string, unknown>) : {};
  return new DiagApiError(status, typeof b.code === 'string' ? b.code : '', {
    field: typeof d.field === 'string' ? d.field : undefined,
    reason: typeof d.reason === 'string' ? d.reason : undefined,
    state: typeof b.state === 'string' ? b.state : undefined,
    retryAfter,
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

export function createDiagApi(getHass: () => DiagHass | null, deps: DiagApiDeps = {}): DiagApi {
  const doFetch: FetchLike = deps.fetch ?? ((url, init) => window.fetch(url, init));

  function hassOrThrow(): DiagHass {
    const hass = getHass();
    if (!hass) throw new DiagApiError(null, 'not_connected');
    return hass;
  }

  async function send(hass: DiagHass, method: Method, path: string, body: unknown): Promise<Response> {
    const headers: Record<string, string> = { Authorization: `Bearer ${token(hass) ?? ''}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    return doFetch(`${DIAG_BASE}/${path}`, {
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
      const wait = response.status === 429 ? parseRetryAfter(response.headers.get('Retry-After')) : null;
      throw errorFrom(response.status, await readJson(response), wait);
    }
    return response;
  }

  async function json(method: Method, path: string, body?: unknown): Promise<unknown> {
    const hass = hassOrThrow();
    if (token(hass) === undefined) {
      try {
        return await hass.callApi<unknown>(method, `openwrt_topology/diagnostics/${path}`,
          body as Record<string, unknown> | undefined);
      } catch (err) {
        throw callApiError(err);
      }
    }
    return readJson(await authorised(method, path, body));
  }

  return {
    overview: async () => parseOverview(await json('GET', diagPaths.overview)),
    history: async () => parseHistory(await json('GET', diagPaths.history)),
    settings: async () => parseSettingsView(await json('GET', diagPaths.settings)),
    updateSettings: async (update: SettingsUpdate) =>
      parseSettingsView(await json('POST', diagPaths.settings, update)),
    run: async (targetIds: string[]) => {
      const ids = [...new Set(targetIds)];
      if (ids.length === 0 || ids.length > MAX_RUN_TARGETS || !ids.every(isTargetId)) {
        throw new DiagApiError(400, 'invalid_request', { field: 'target_ids' });
      }
      return parseRunResult(await json('POST', diagPaths.run, { target_ids: ids }));
    },
  };
}
