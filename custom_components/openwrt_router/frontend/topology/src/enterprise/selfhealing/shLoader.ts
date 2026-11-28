/**
 * shLoader.ts — one load of the "Self-Healing" tab at a time (no React).
 *
 * A load asks the read routes through ShApi (GET only) with one
 * AbortController for all its requests:
 * - a poll is skipped while a load is still running (never two at once);
 * - a load asked for by hand (refresh, a new selection) aborts the running
 *   one first, and the aborted load's answers are dropped;
 * - dispose() (the tab is unmounted) aborts the running load and ends the
 *   loader: nothing is reported after it.
 * Every request also ends on its own after 30 s (shApi.ts).
 */

import type { ActionList, Detail, Overview, Plan, Settings, ShApi } from './shTypes';

export type Settled<T> = { ok: true; value: T } | { ok: false; error: unknown };

export function settle<T>(p: Promise<T>): Promise<Settled<T>> {
  return p.then(value => ({ ok: true as const, value }), error => ({ ok: false as const, error }));
}

export interface LoadResult {
  overview: Settled<Overview>;
  list?: Settled<ActionList>;
  settings?: Settled<Settings>;
  detail?: Settled<Detail>;
  plan?: Settled<Plan | null>;
  /** The record the load asked for (null: none). */
  selected: string | null;
}

export type LoadHow = 'poll' | 'now';

export interface ShLoader {
  /** Start a load; returns false when none started (a poll while one runs, or after dispose). */
  load(selected: string | null, how: LoadHow): boolean;
  /** True while a load runs. */
  readonly running: boolean;
  /** Abort the running load and report nothing more. */
  dispose(): void;
}

export function createShLoader(o: {
  api: ShApi;
  isAdmin: boolean;
  onStart: () => void;
  onResult: (r: LoadResult) => void;
}): ShLoader {
  let current: AbortController | null = null;
  let disposed = false;
  return {
    get running() {
      return current !== null;
    },
    load(sel, how) {
      if (disposed) return false;
      if (current !== null) {
        if (how === 'poll') return false;
        current.abort();
      }
      const ctrl = new AbortController();
      current = ctrl;
      const signal = ctrl.signal;
      o.onStart();
      // non-admins ask for the overview only (the other routes answer them 403)
      const overview = settle(o.api.overview(signal));
      const list = o.isAdmin ? settle(o.api.actions(signal)) : undefined;
      const settings = o.isAdmin ? settle(o.api.settings(signal)) : undefined;
      const detail = o.isAdmin && sel ? settle(o.api.action(sel, signal)) : undefined;
      const plan = o.isAdmin && sel ? settle(o.api.plan(sel, signal)) : undefined;
      void Promise.all([overview, list, settings, detail, plan]).then(([ov, l, st, d, p]) => {
        if (current !== ctrl) return; // aborted, replaced or disposed: its answers are dropped
        current = null;
        o.onResult({ overview: ov, list: l, settings: st, detail: d, plan: p, selected: sel });
      });
      return true;
    },
    dispose() {
      disposed = true;
      current?.abort();
      current = null;
    },
  };
}
