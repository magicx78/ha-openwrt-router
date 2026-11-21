/**
 * tmApi.ts — client of GET /api/openwrt_router/enterprise/timemachine/timeline.
 *
 * Same pattern as trafficApi.ts: Bearer fetch on the same origin (HA's token
 * from hass.auth); a 401 is retried once after a token refresh; without a
 * token the route falls back to hass.callApi. This is the only place of the
 * tab that talks to the network, and it only reads (GET, no body).
 *
 * Errors become TmApiError(status, code, details): the server's `message`
 * is never kept. The query string is built only from checked values
 * (tmLogic.queryString).
 */

import { TmApiError, parseTimeline, queryString } from './tmLogic.ts';
import type { TimelineQuery, TmApi, TmHass } from './tmTypes';

export const TM_BASE = '/api/openwrt_router/enterprise/timemachine';
const CALL_API_BASE = 'openwrt_router/enterprise/timemachine';

type FetchLike = (url: string, init: RequestInit & { headers: Record<string, string> }) => Promise<Response>;

export interface TmApiDeps {
  fetch?: FetchLike;
}

function token(hass: TmHass): string | undefined {
  return hass.auth?.data?.access_token;
}

async function refreshToken(hass: TmHass): Promise<boolean> {
  const refresh = hass.auth?.refreshAccessToken;
  if (typeof refresh !== 'function') return false;
  try {
    await refresh.call(hass.auth);
    return true;
  } catch {
    return false;
  }
}

function errorFrom(status: number | null, body: unknown): TmApiError {
  const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const d = b.details && typeof b.details === 'object' ? (b.details as Record<string, unknown>) : {};
  return new TmApiError(status, typeof b.code === 'string' ? b.code : '', {
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

export function createTmApi(getHass: () => TmHass | null, deps: TmApiDeps = {}): TmApi {
  const doFetch: FetchLike = deps.fetch ?? ((url, init) => window.fetch(url, init));

  function send(hass: TmHass, path: string): Promise<Response> {
    return doFetch(`${TM_BASE}/${path}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token(hass) ?? ''}` },
      credentials: 'same-origin',
      cache: 'no-store',
    });
  }

  async function get(path: string): Promise<unknown> {
    const hass = getHass();
    if (!hass) throw new TmApiError(null, 'not_connected');
    if (token(hass) === undefined) {
      try {
        return await hass.callApi<unknown>('GET', `${CALL_API_BASE}/${path}`);
      } catch (err) {
        throw callApiError(err);
      }
    }
    if (hass.auth?.expired) await refreshToken(hass);
    let response = await send(hass, path);
    if (response.status === 401 && (await refreshToken(hass))) response = await send(hass, path);
    if (!response.ok) throw errorFrom(response.status, await readJson(response));
    return readJson(response);
  }

  return {
    timeline: async (q: TimelineQuery) => parseTimeline(await get(`timeline?${queryString(q)}`)),
  };
}
