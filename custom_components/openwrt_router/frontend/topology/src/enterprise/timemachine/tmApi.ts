/**
 * tmApi.ts — client of GET /api/openwrt_router/enterprise/timemachine/timeline,
 * …/sessions (client sessions, administrators only; 403 for others), and
 * since 1.52.0 …/state, …/compare and …/export (administrators only; the
 * answer is kept as a Blob and saved as a file, the token never goes into a
 * URL).
 *
 * Same pattern as trafficApi.ts: Bearer fetch on the same origin (HA's token
 * from hass.auth); a 401 is retried once after a token refresh; without a
 * token the route falls back to hass.callApi. This is the only place of the
 * tab that talks to the network, and it only reads (GET, no body).
 *
 * Errors become TmApiError(status, code, details): the server's `message`
 * is never kept. The query string is built only from checked values
 * (tmLogic.queryString, tmLogic.sessionQueryString).
 */

import {
  TmApiError, cursorOf, exportQueryString, parseSessions, parseTimeline, queryString, sessionQueryString,
} from './tmLogic.ts';
import { compareQueryString, parseCompare, parseState, stateQueryString } from './tmState.ts';
import type { CompareQuery, ExportFile, SessionQuery, StateQuery, TimelineQuery, TmApi, TmHass } from './tmTypes';

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

  /** The answer as text (fetch), or the parsed body of hass.callApi (no token). */
  async function raw(path: string): Promise<{ text: string | null; body: unknown }> {
    const hass = getHass();
    if (!hass) throw new TmApiError(null, 'not_connected');
    if (token(hass) === undefined) {
      try {
        return { text: null, body: await hass.callApi<unknown>('GET', `${CALL_API_BASE}/${path}`) };
      } catch (err) {
        throw callApiError(err);
      }
    }
    if (hass.auth?.expired) await refreshToken(hass);
    let response = await send(hass, path);
    if (response.status === 401 && (await refreshToken(hass))) response = await send(hass, path);
    if (!response.ok) throw errorFrom(response.status, await readJson(response));
    const text = await response.text();
    let body: unknown = null;
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
    return { text, body };
  }

  async function get(path: string): Promise<unknown> {
    return (await raw(path)).body;
  }

  /** One export page: the server's bytes as a Blob (never shown, never put in a URL with a token). */
  async function exportFile(q: TimelineQuery, cursor: string | null = null): Promise<ExportFile> {
    const { text, body } = await raw(`export?${exportQueryString(q, cursor)}`);
    const b = body && typeof body === 'object' ? (body as Record<string, unknown>) : {};
    const content = text ?? JSON.stringify(body);
    return {
      blob: new Blob([content], { type: 'application/json' }),
      status: typeof b.status === 'string' ? b.status : '',
      reason: typeof b.reason === 'string' ? b.reason : null,
      marks: Array.isArray(b.marks) ? b.marks.length : 0,
      spanning: Array.isArray(b.spanning) ? b.spanning.length : 0,
      truncated: b.truncated === true,
      nextCursor: cursorOf(b.next_cursor),
      omittedClientMarks: typeof b.omitted_client_marks === 'number' && Number.isFinite(b.omitted_client_marks)
        ? Math.max(0, Math.floor(b.omitted_client_marks)) : 0,
    };
  }

  return {
    timeline: async (q: TimelineQuery) => parseTimeline(await get(`timeline?${queryString(q)}`)),
    sessions: async (q: SessionQuery) => parseSessions(await get(`sessions?${sessionQueryString(q)}`)),
    state: async (q: StateQuery) => parseState(await get(`state?${stateQueryString(q)}`)),
    compare: async (q: CompareQuery) => parseCompare(await get(`compare?${compareQueryString(q)}`)),
    exportFile: (q: TimelineQuery) => exportFile(q, q.cursor),
  };
}
