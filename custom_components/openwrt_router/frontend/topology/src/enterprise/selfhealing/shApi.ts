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
 *
 * A 2xx answer that is no JSON or has the wrong shape is an error too
 * (ShApiError(status, 'invalid_body')), never an empty answer. Every request
 * ends after REQUEST_TIMEOUT_MS (ShApiError(null, 'timeout')) and stops when
 * the caller's AbortSignal fires (ShApiError(null, 'aborted')).
 */

import {
  ACTION_ID_RE, REQUEST_TIMEOUT_MS, ShApiError, invalidBody, parseActions, parseDetail, parseOverview, parsePlans,
  parseSettings,
} from './shLogic.ts';
import type { ShApi, ShHass } from './shTypes';

export const SH_BASE = '/api/openwrt_router/enterprise/selfhealing/v1';
const CALL_API_BASE = 'openwrt_router/enterprise/selfhealing/v1';
/** The list asks for the most the route gives (heal_views.LIMIT_MAX). */
export const LIST_LIMIT = 200;

type FetchLike = (url: string, init: RequestInit & { headers: Record<string, string> }) => Promise<Response>;

export interface ShApiDeps {
  fetch?: FetchLike;
  /** Tests only: a shorter deadline than REQUEST_TIMEOUT_MS. */
  timeoutMs?: number;
}

/** What a request gave: the status (null through hass.callApi, which only resolves 2xx) and the parsed JSON. */
interface Answer {
  status: number | null;
  data: unknown;
}

const NO_JSON = Symbol('no-json');

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
    return NO_JSON;
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

/** Parse a 2xx answer; a wrong shape keeps the answer's status. */
function parsed<T>(a: Answer, parse: (data: unknown) => T): T {
  if (a.data === NO_JSON) throw invalidBody('json', a.status);
  try {
    return parse(a.data);
  } catch (err) {
    if (err instanceof ShApiError && err.code === 'invalid_body') throw invalidBody(err.details.field ?? 'body', a.status);
    throw err;
  }
}

export function createShApi(getHass: () => ShHass | null, deps: ShApiDeps = {}): ShApi {
  const doFetch: FetchLike = deps.fetch ?? ((url, init) => window.fetch(url, init));
  const timeoutMs = deps.timeoutMs ?? REQUEST_TIMEOUT_MS;

  function send(hass: ShHass, path: string, signal: AbortSignal): Promise<Response> {
    return doFetch(`${SH_BASE}/${path}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token(hass) ?? ''}` },
      credentials: 'same-origin',
      cache: 'no-store',
      signal,
    });
  }

  async function attempt(hass: ShHass, path: string, signal: AbortSignal): Promise<Answer> {
    if (token(hass) === undefined) {
      try {
        return { status: null, data: await hass.callApi<unknown>('GET', `${CALL_API_BASE}/${path}`) };
      } catch (err) {
        throw callApiError(err);
      }
    }
    if (hass.auth?.expired) await refreshToken(hass);
    let response = await send(hass, path, signal);
    if (response.status === 401 && (await refreshToken(hass))) response = await send(hass, path, signal);
    if (!response.ok) {
      const data = await readJson(response);
      throw errorFrom(response.status, data === NO_JSON ? null : data);
    }
    return { status: response.status, data: await readJson(response) };
  }

  /** One GET with a deadline; the caller's signal stops it (hass.callApi cannot be stopped: its answer is dropped). */
  async function get(path: string, signal?: AbortSignal): Promise<Answer> {
    const hass = getHass();
    if (!hass) throw new ShApiError(null, 'not_connected');
    if (signal?.aborted) throw new ShApiError(null, 'aborted');
    const ctrl = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, timeoutMs);
    const onAbort = () => ctrl.abort();
    signal?.addEventListener('abort', onAbort, { once: true });
    const stopped = new Promise<never>((_, fail) => {
      ctrl.signal.addEventListener('abort', () => fail(new ShApiError(null, timedOut ? 'timeout' : 'aborted')), { once: true });
    });
    try {
      return await Promise.race([attempt(hass, path, ctrl.signal), stopped]);
    } catch (err) {
      if (ctrl.signal.aborted) throw new ShApiError(null, timedOut ? 'timeout' : 'aborted');
      throw err;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
  }

  return {
    overview: async (signal?: AbortSignal) => parsed(await get('overview', signal), parseOverview),
    actions: async (signal?: AbortSignal) => parsed(await get(`actions?limit=${LIST_LIMIT}`, signal), parseActions),
    action: async (id: string, signal?: AbortSignal) => parsed(await get(`actions/${checkedId(id)}`, signal), data => {
      const detail = parseDetail(data);
      // an answer about another record is no answer about this one
      if (detail.action.actionId !== id) throw invalidBody('action_id');
      return detail;
    }),
    plan: async (id: string, signal?: AbortSignal) => {
      const plans = parsed(await get(`plans?action_id=${checkedId(id)}`, signal), parsePlans);
      return plans.find(p => p.actionId === id) ?? null;
    },
    settings: async (signal?: AbortSignal) => parsed(await get('settings', signal), parseSettings),
  };
}
