/**
 * register.ts — hangs the Network Time Machine ("Zeitreise") under
 * "Enterprise", after Traffic Analytics (50); this tab is order 60. It adds
 * no bottom-bar entry.
 *
 * Tab components get no props and no hass, so the panel binds its hass getter
 * once (main.tsx, constructor) via bindTimeMachineHass; the tab reads it from
 * here. The tab is offered to every logged-in user: the backend decides what
 * a reader may see (administrators everything; everyone else while the
 * panel is open to all users, without audit, configuration, the Time
 * Machine's references and the client histories; else 403). The switch to
 * the client sessions is shown to administrators only (hass.user.is_admin);
 * the sessions route itself answers 403 to everyone else.
 */

import React from 'react';
import { registerEnterpriseTab } from '../registry';
import { createTmApi } from './tmApi.ts';
import { TAB_ID, TAB_ORDER, TAB_TITLE } from './tmLogic.ts';
import type { TmApi, TmHass } from './tmTypes';
import { TimeMachineView } from './TimeMachineView';

let getHass: () => TmHass | null = () => null;
let client: TmApi | null = null;

/** Called once by the panel with a getter of its current hass object. */
export function bindTimeMachineHass(getter: () => TmHass | null): void {
  getHass = getter;
  client = createTmApi(getter);
}

function TimeMachineTab() {
  if (!client) client = createTmApi(getHass);
  return React.createElement(TimeMachineView, { api: client, isAdmin: getHass()?.user?.is_admin === true });
}

registerEnterpriseTab({
  id: TAB_ID,
  title: TAB_TITLE,
  order: TAB_ORDER,
  component: TimeMachineTab,
  isAvailable: () => getHass() !== null,
});
