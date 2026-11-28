/**
 * shMock.ts — DEV ONLY: the Self-Healing tab on recorded route answers
 * (shFixture.json, made by the real heal_views.py routes and checked by
 * tests/test_sh_panel_fixture_v1530.py; ids are invented, no address or name). main.tsx imports
 * this behind import.meta.env.DEV for ?selfhealingmock[=scenario], so the
 * production build drops it and the fixture.
 *
 * Scenarios: default (records, one open), empty (nothing observed yet),
 * held (router hold and fleet pause), candidate (a plan with a candidate),
 * user (a non-administrator: counts only), forbidden (panel not open to all),
 * off (module switched off), notrunning (503), error (the requests fail),
 * invalid (the overview answers 200 without JSON), partial (the list has an
 * unreadable row and a total that does not match), stale (the answers of the
 * first half second arrive, every later request fails: press "Aktualisieren").
 */

import fixture from './shFixture.json';
import { ShApiError, invalidBody, parseActions, parseDetail, parseOverview, parsePlans, parseSettings } from './shLogic.ts';
import type { ShApi, ShHass } from './shTypes';

type Answer = { status: number; body: unknown };
const F = fixture as unknown as Record<string, Answer>;

export function mockHass(scenario: string): ShHass {
  const admin = scenario !== 'user' && scenario !== 'forbidden';
  return {
    callApi: () => Promise.reject(new Error('mock')),
    user: { is_admin: admin },
  };
}

/** A 200 whose body is no JSON (an HTML error page of a proxy, say). */
const NOT_JSON: Answer = { status: 200, body: Symbol('not-json') };

/** The partial list: the recorded rows, one unreadable row, and a total that does not match. */
function partialList(): Answer {
  const b = structuredClone(F.actions.body) as { actions: unknown[]; total: number };
  b.actions.push({ action_id: 'kaputt', state: 'proposed' });
  b.total = 4;
  return { status: 200, body: b };
}

function answer<T>(key: string | Answer, parse: (b: unknown) => T): Promise<T> {
  const a = typeof key === 'string' ? F[key] : key;
  const delay = 150;
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      if (!a) return reject(new Error(`no fixture ${String(key)}`));
      if (a.status !== 200) {
        const b = (a.body ?? {}) as { code?: string };
        return reject(new ShApiError(a.status, typeof b.code === 'string' ? b.code : ''));
      }
      if (typeof a.body === 'symbol') return reject(invalidBody('json', a.status));
      try {
        resolve(parse(a.body));
      } catch (err) {
        // the real client keeps the answer's status on a wrong shape
        reject(err instanceof ShApiError && err.code === 'invalid_body' ? invalidBody(err.details.field ?? 'body', a.status) : err);
      }
    }, delay);
  });
}

/**
 * stale: the routes answer during the first half second (React's dev mode
 * mounts the tab twice at once), every later request fails.
 */
function answersThenFail(api: ShApi, windowMs = 500): ShApi {
  let t0: number | null = null;
  const gate = <T>(run: () => Promise<T>): Promise<T> => {
    const now = Date.now();
    if (t0 === null) t0 = now;
    return now - t0 <= windowMs ? run() : Promise.reject(new Error('mock: request failed'));
  };
  return {
    overview: () => gate(() => api.overview()),
    actions: () => gate(() => api.actions()),
    action: (id: string) => gate(() => api.action(id)),
    plan: (id: string) => gate(() => api.plan(id)),
    settings: () => gate(() => api.settings()),
  };
}

export function createMockShApi(scenario: string): ShApi {
  const fail = () => Promise.reject(new Error('mock: request failed'));
  if (scenario === 'error') {
    return { overview: fail, actions: fail, action: fail, plan: fail, settings: fail };
  }
  const ov = {
    empty: 'empty_overview', held: 'held_overview', user: 'user_overview', forbidden: 'user_overview_closed_panel',
    off: 'disabled_overview', notrunning: 'not_running',
  }[scenario] ?? 'overview';
  const list = scenario === 'empty' ? 'empty_actions' : scenario === 'partial' ? partialList() : 'actions';
  if (scenario === 'stale') return answersThenFail(createMockShApi('default'));
  return {
    overview: () => answer(scenario === 'invalid' ? NOT_JSON : ov, parseOverview),
    actions: () => answer(list, parseActions),
    action: (id: string) => {
      const keys = scenario === 'held' ? ['held_detail', 'detail_open', 'detail_closed'] : ['detail_open', 'detail_closed', 'held_detail'];
      const key = keys.find(k => (F[k]?.body as { action?: { action_id?: string } } | undefined)?.action?.action_id === id);
      return key ? answer(key, parseDetail) : answer('unknown_action', parseDetail);
    },
    plan: (id: string) => {
      const keys = scenario === 'candidate' ? ['plan_candidate', 'plan_open', 'plan_closed']
        : scenario === 'held' ? ['held_plan', 'plan_open', 'plan_closed'] : ['plan_open', 'plan_closed'];
      return Promise.all(keys.map(k => answer(k, parsePlans).catch(() => [])))
        .then(all => all.flat().find(p => p.actionId === id) ?? null);
    },
    settings: () => answer('settings', parseSettings),
  };
}
