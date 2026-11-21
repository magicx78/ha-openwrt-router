/**
 * trafficApi.ts — client of /api/openwrt_topology/traffic/*.
 *
 * Same pattern as wifiApi.ts: Bearer fetch on the same origin (HA's token
 * from hass.auth); a 401 is retried once after a token refresh; without a
 * token the routes fall back to hass.callApi. This is the only place of the
 * tab that talks to the network, and it only sends GETs: Phase J has no
 * write route.
 *
 * Errors become TrafficApiError(status, code, details): the server's
 * `message` is never kept. Query strings are built only from the fixed
 * lists and validated ids (seriesQuery, talkerQuery).
 */

import {
  TrafficApiError,
  parseAnomalies,
  parseCapacity,
  parseClients,
  parseFlows,
  parseOverview,
  parsePoints,
  parseRecommendations,
  parseSeries,
  parseTalkers,
  parseVlans,
  seriesQuery,
  talkerQuery,
} from './trafficLogic.ts';
import type { SeriesQuery, TalkerQuery, TrafficApi, TrafficHass } from './trafficTypes';

export const TRAFFIC_BASE = '/api/openwrt_topology/traffic';
const CALL_API_BASE = 'openwrt_topology/traffic';

/** Route paths below TRAFFIC_BASE (all GET). */
export const trafficPaths = {
  overview: 'overview',
  points: 'points',
  series: 'series',
  talkers: 'talkers',
  clients: 'clients',
  vlans: 'vlans',
  capacity: 'capacity',
  anomalies: 'anomalies',
  recommendations: 'recommendations',
  flows: 'flows',
};

type FetchLike = (url: string, init: RequestInit & { headers: Record<string, string> }) => Promise<Response>;

export interface TrafficApiDeps {
  fetch?: FetchLike;
}

function token(hass: TrafficHass): string | undefined {
  return hass.auth?.data?.access_token;
}

async function refreshToken(hass: TrafficHass): Promise<boolean> {
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
function errorFrom(status: number | null, body: unknown): TrafficApiError {
  const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const d = b.details && typeof b.details === 'object' ? (b.details as Record<string, unknown>) : {};
  return new TrafficApiError(status, typeof b.code === 'string' ? b.code : '', {
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

export function createTrafficApi(getHass: () => TrafficHass | null, deps: TrafficApiDeps = {}): TrafficApi {
  const doFetch: FetchLike = deps.fetch ?? ((url, init) => window.fetch(url, init));

  function hassOrThrow(): TrafficHass {
    const hass = getHass();
    if (!hass) throw new TrafficApiError(null, 'not_connected');
    return hass;
  }

  function send(hass: TrafficHass, path: string): Promise<Response> {
    return doFetch(`${TRAFFIC_BASE}/${path}`, {
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
    overview: async () => parseOverview(await get(trafficPaths.overview)),
    points: async () => parsePoints(await get(trafficPaths.points)),
    series: async (q: SeriesQuery) => {
      const qs = seriesQuery(q); // throws before any request
      return parseSeries(await get(`${trafficPaths.series}?${qs}`));
    },
    talkers: async (q: TalkerQuery) => {
      const qs = talkerQuery(q);
      return parseTalkers(await get(`${trafficPaths.talkers}?${qs}`));
    },
    clients: async () => parseClients(await get(trafficPaths.clients)),
    vlans: async () => parseVlans(await get(trafficPaths.vlans)),
    capacity: async () => parseCapacity(await get(trafficPaths.capacity)),
    anomalies: async () => parseAnomalies(await get(trafficPaths.anomalies)),
    recommendations: async () => parseRecommendations(await get(trafficPaths.recommendations)),
    flows: async () => parseFlows(await get(trafficPaths.flows)),
  };
}
