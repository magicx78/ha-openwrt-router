/**
 * register.ts — hangs the Self-Healing Center ("Self-Healing") under
 * "Enterprise", after Network Diagnostics (30) and before WiFi Intelligence
 * (40); this tab is order 35. It adds no bottom-bar entry.
 *
 * Tab components get no props and no hass, so the panel binds its hass
 * getter once (main.tsx, constructor) via bindSelfHealingHass. The tab is
 * offered to every logged-in user: the backend decides what a reader may see
 * (administrators everything; everyone else the counts only while the panel
 * is open to all users, else 403). Non-administrators request the overview
 * only (the other routes answer them 403).
 *
 * The tab only reads (GET): there is no write path in 1.53.0.
 *
 * installSelfHealingMock is the dev-mode hook for ?selfhealingmock; main.tsx
 * calls it only behind import.meta.env.DEV, so a production build never takes
 * that path.
 */

import React from 'react';
import { registerEnterpriseTab } from '../registry';
import { createShApi } from './shApi.ts';
import { TAB_ID, TAB_ORDER, TAB_TITLE } from './shLogic.ts';
import type { ShApi, ShHass } from './shTypes';
import { SelfHealingView } from './SelfHealingView';

let getHass: () => ShHass | null = () => null;
let client: ShApi | null = null;

/** Called once by the panel with a getter of its current hass object. */
export function bindSelfHealingHass(getter: () => ShHass | null): void {
  getHass = getter;
  client = createShApi(getter);
}

/** Dev only: replace hass and client by the mock (see shMock.ts). */
export function installSelfHealingMock(getter: () => ShHass | null, api: ShApi): void {
  getHass = getter;
  client = api;
}

function SelfHealingTab() {
  if (!client) client = createShApi(getHass);
  return React.createElement(SelfHealingView, { api: client, isAdmin: getHass()?.user?.is_admin === true });
}

registerEnterpriseTab({
  id: TAB_ID,
  title: TAB_TITLE,
  order: TAB_ORDER,
  component: SelfHealingTab,
  isAvailable: () => getHass() !== null,
});
