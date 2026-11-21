/**
 * wifiApi.ts — client of /api/openwrt_router/enterprise/wifi/*.
 *
 * Same pattern as diagnosticsApi.ts: Bearer fetch on the same origin (HA's
 * token from hass.auth); a 401 is retried once after a token refresh;
 * without a token the routes fall back to hass.callApi. This is the only
 * place of the tab that talks to the network, and it only sends GETs: the
 * backend has no write route and no scan route.
 *
 * Errors become WifiApiError(status, code, details): the server's `message`
 * is never kept. The only query string is the timeline's, built from the
 * fixed window / series lists and validated ids (timelineQuery).
 */

import {
  WifiApiError,
  parseChannelMap,
  parseOverview,
  parseRadios,
  parseRecommendations,
  parseRoaming,
  parseTimeline,
  timelineQuery,
} from './wifiLogic.ts';
import type { TimelineQuery, WifiApi, WifiHass } from './wifiTypes';

export const WIFI_BASE = '/api/openwrt_router/enterprise/wifi';
const CALL_API_BASE = 'openwrt_router/enterprise/wifi';

/** Route paths below WIFI_BASE. */
export const wifiPaths = {
  overview: 'overview',
  radios: 'radios',
  channelMap: 'channel_map',
  recommendations: 'recommendations',
  timeline: 'timeline',
  roaming: 'roaming',
};

type FetchLike = (url: string, init: RequestInit & { headers: Record<string, string> }) => Promise<Response>;

export interface WifiApiDeps {
  fetch?: FetchLike;
}

function token(hass: WifiHass): string | undefined {
  return hass.auth?.data?.access_token;
}

async function refreshToken(hass: WifiHass): Promise<boolean> {
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
function errorFrom(status: number | null, body: unknown): WifiApiError {
  const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const d = b.details && typeof b.details === 'object' ? (b.details as Record<string, unknown>) : {};
  return new WifiApiError(status, typeof b.code === 'string' ? b.code : '', {
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

export function createWifiApi(getHass: () => WifiHass | null, deps: WifiApiDeps = {}): WifiApi {
  const doFetch: FetchLike = deps.fetch ?? ((url, init) => window.fetch(url, init));

  function hassOrThrow(): WifiHass {
    const hass = getHass();
    if (!hass) throw new WifiApiError(null, 'not_connected');
    return hass;
  }

  function send(hass: WifiHass, path: string): Promise<Response> {
    return doFetch(`${WIFI_BASE}/${path}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token(hass) ?? ''}` },
      credentials: 'same-origin',
      cache: 'no-store',
    });
  }

  /** One authorised GET; a 401 is retried once after a token refresh. */
  async function get(path: string): Promise<unknown> {
    const hass = hassOrThrow();
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
    overview: async () => parseOverview(await get(wifiPaths.overview)),
    radios: async () => parseRadios(await get(wifiPaths.radios)),
    channelMap: async () => parseChannelMap(await get(wifiPaths.channelMap)),
    recommendations: async () => parseRecommendations(await get(wifiPaths.recommendations)),
    roaming: async () => parseRoaming(await get(wifiPaths.roaming)),
    timeline: async (query: TimelineQuery) => {
      const qs = timelineQuery(query); // throws before any request
      return parseTimeline(await get(`${wifiPaths.timeline}?${qs}`));
    },
  };
}
