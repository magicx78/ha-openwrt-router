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
 * off (module switched off), notrunning (503), error (the requests fail).
 */

import fixture from './shFixture.json';
import { ShApiError, parseActions, parseDetail, parseOverview, parsePlans, parseSettings } from './shLogic.ts';
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

function answer<T>(key: string, parse: (b: unknown) => T): Promise<T> {
  const a = F[key];
  const delay = 150;
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      if (!a) return reject(new Error(`no fixture ${key}`));
      if (a.status !== 200) {
        const b = (a.body ?? {}) as { code?: string };
        return reject(new ShApiError(a.status, typeof b.code === 'string' ? b.code : ''));
      }
      resolve(parse(a.body));
    }, delay);
  });
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
  const list = scenario === 'empty' ? 'empty_actions' : 'actions';
  return {
    overview: () => answer(ov, parseOverview),
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
