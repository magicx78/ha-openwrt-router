/**
 * trafficApi.ts — client of /api/openwrt_topology/traffic/*.
 *
 * Same pattern as wifiApi.ts: Bearer fetch on the same origin (HA's token
 * from hass.auth); a 401 is retried once after a token refresh; without a
 * token the routes fall back to hass.callApi. This is the only place of the
 * tab that talks to the network. Every view only GETs; the one write is the
 * settings form of administrators (POST /settings, a JSON body built from
 * the checked draft; the answer is the stored settings, so nothing counts as
 * saved before the server confirms it).
 *
 * Errors become TrafficApiError(status, code, details): the server's
 * `message` is never kept. Query strings are built only from the fixed
 * lists and validated ids (seriesQuery, talkerQuery).
 */

import {
  CLIENT_SENSORS_MAX,
  TrafficApiError,
  isClientRef,
  isUserRef,
  parseAnomalies,
  parseCapacity,
  parseClients,
  parseCollectorUsers,
  parseFlows,
  parseOverview,
  parsePoints,
  parseRecommendations,
  parseSeries,
  parseSettings,
  parseTalkers,
  parseVlans,
  seriesQuery,
  talkerQuery,
} from './trafficLogic.ts';
import type { SeriesQuery, SettingsUpdate, TalkerQuery, TrafficApi, TrafficHass } from './trafficTypes';

export const TRAFFIC_BASE = '/api/openwrt_topology/traffic';
const CALL_API_BASE = 'openwrt_topology/traffic';

/** Route paths below TRAFFIC_BASE (GET; settings also POST). */
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
  settings: 'settings',
  collectorUsers: 'collector/users',
};

type Method = 'GET' | 'POST';

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

/** Only the keys and shapes the route takes; anything else is refused before a request. */
function checkedUpdate(update: SettingsUpdate): SettingsUpdate {
  const out: SettingsUpdate = {};
  if (update.collector !== undefined) {
    const c: { enabled?: boolean; user_ref?: string } = {};
    if (update.collector.enabled !== undefined) {
      if (typeof update.collector.enabled !== 'boolean') throw new TrafficApiError(400, 'invalid_request', { field: 'collector', reason: 'enabled' });
      c.enabled = update.collector.enabled;
    }
    if (update.collector.user_ref !== undefined) {
      if (!isUserRef(update.collector.user_ref)) throw new TrafficApiError(400, 'invalid_request', { field: 'collector', reason: 'user_ref' });
      c.user_ref = update.collector.user_ref;
    }
    out.collector = c;
  }
  if (update.client_sensors !== undefined) {
    const list = update.client_sensors;
    if (!Array.isArray(list) || list.length > CLIENT_SENSORS_MAX || !list.every(isClientRef)) {
      throw new TrafficApiError(400, 'invalid_request', { field: 'client_sensors', reason: 'client_ref' });
    }
    out.client_sensors = [...list];
  }
  if (!Object.keys(out).length) throw new TrafficApiError(400, 'invalid_request', { field: 'body', reason: 'empty' });
  return out;
}

export function createTrafficApi(getHass: () => TrafficHass | null, deps: TrafficApiDeps = {}): TrafficApi {
  const doFetch: FetchLike = deps.fetch ?? ((url, init) => window.fetch(url, init));

  function hassOrThrow(): TrafficHass {
    const hass = getHass();
    if (!hass) throw new TrafficApiError(null, 'not_connected');
    return hass;
  }

  function send(hass: TrafficHass, method: Method, path: string, body: unknown): Promise<Response> {
    const headers: Record<string, string> = { Authorization: `Bearer ${token(hass) ?? ''}` };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    return doFetch(`${TRAFFIC_BASE}/${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
      cache: 'no-store',
    });
  }

  /** One authorised request; a 401 is retried once after a token refresh. */
  async function json(method: Method, path: string, body?: unknown): Promise<unknown> {
    const hass = hassOrThrow();
    if (token(hass) === undefined) {
      try {
        return await hass.callApi<unknown>(method, `${CALL_API_BASE}/${path}`, body as Record<string, unknown> | undefined);
      } catch (err) {
        throw callApiError(err);
      }
    }
    if (hass.auth?.expired) await refreshToken(hass);
    let response = await send(hass, method, path, body);
    if (response.status === 401 && (await refreshToken(hass))) response = await send(hass, method, path, body);
    if (!response.ok) throw errorFrom(response.status, await readJson(response));
    return readJson(response);
  }

  const get = (path: string): Promise<unknown> => json('GET', path);

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
    settings: async () => parseSettings(await get(trafficPaths.settings)),
    collectorUsers: async () => parseCollectorUsers(await get(trafficPaths.collectorUsers)),
    updateSettings: async (update: SettingsUpdate) => parseSettings(await json('POST', trafficPaths.settings, checkedUpdate(update))),
  };
}
