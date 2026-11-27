/**
 * shApi.ts — client of the five read routes of heal_views.py under
 * /api/openwrt_router/enterprise/selfhealing/v1: overview, actions,
 * actions/{id}, plans (?action_id=) and settings.
 *
 * The ONLY place of the tab that talks to the network, and it only reads:
 * every request is a GET without a body (shApi.test.mjs checks the method,
 * and that no file of the tab names another method). Same pattern as
 * tmApi.ts: Bearer fetch on the same origin (HA's token from hass.auth); a
 * 401 is retried once after a token refresh; without a token the request
 * goes through hass.callApi('GET', …).
 *
 * Errors become ShApiError(status, code, details): the server's `message`
 * is never kept. Ids in a path or query are checked against their exact
 * pattern first (rem_ + 32 hex), so nothing else ever reaches a URL.
 */

import { ACTION_ID_RE, ShApiError, parseActions, parseDetail, parseOverview, parsePlans, parseSettings } from './shLogic.ts';
import type { ShApi, ShHass } from './shTypes';

export const SH_BASE = '/api/openwrt_router/enterprise/selfhealing/v1';
const CALL_API_BASE = 'openwrt_router/enterprise/selfhealing/v1';
/** The list asks for the most the route gives (heal_views.LIMIT_MAX). */
export const LIST_LIMIT = 200;

type FetchLike = (url: string, init: RequestInit & { headers: Record<string, string> }) => Promise<Response>;

export interface ShApiDeps {
  fetch?: FetchLike;
}

function token(hass: ShHass): string | undefined {
  return hass.auth?.data?.access_token;
}

async function refreshToken(hass: ShHass): Promise<boolean> {
  const refresh = hass.auth?.refreshAccessToken;
  if (typeof refresh !== 'function') return false;
  try {
    await refresh.call(hass.auth);
    return true;
  } catch {
    return false;
  }
}

function errorFrom(status: number | null, body: unknown): ShApiError {
  const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
  const d = b.details && typeof b.details === 'object' ? (b.details as Record<string, unknown>) : {};
  return new ShApiError(status, typeof b.code === 'string' ? b.code : '', {
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

function checkedId(id: string): string {
  if (!ACTION_ID_RE.test(id)) throw new ShApiError(null, 'invalid_action_id');
  return id;
}

export function createShApi(getHass: () => ShHass | null, deps: ShApiDeps = {}): ShApi {
  const doFetch: FetchLike = deps.fetch ?? ((url, init) => window.fetch(url, init));

  function send(hass: ShHass, path: string): Promise<Response> {
    return doFetch(`${SH_BASE}/${path}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token(hass) ?? ''}` },
      credentials: 'same-origin',
      cache: 'no-store',
    });
  }

  async function get(path: string): Promise<unknown> {
    const hass = getHass();
    if (!hass) throw new ShApiError(null, 'not_connected');
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
    overview: async () => parseOverview(await get('overview')),
    actions: async () => parseActions(await get(`actions?limit=${LIST_LIMIT}`)),
    action: async (id: string) => parseDetail(await get(`actions/${checkedId(id)}`)),
    plan: async (id: string) => {
      const plans = parsePlans(await get(`plans?action_id=${checkedId(id)}`));
      return plans.find(p => p.actionId === id) ?? null;
    },
    settings: async () => parseSettings(await get('settings')),
  };
}
