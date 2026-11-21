/**
 * register.ts — hangs WiFi Intelligence under "Enterprise", next to the
 * Configuration Manager (order 10), the Security Center (20) and the Network
 * Diagnostics (30); this tab is order 40. It adds no bottom-bar entry.
 *
 * Tab components get no props and no hass, so the panel binds its hass getter
 * once (main.tsx, constructor) via bindWifiHass; the tab reads it from here.
 * The tab is offered to every logged-in user: the backend decides what a
 * reader may see (administrators, and everyone else while the panel is open
 * to all users; else 403). The client roaming history is for administrators
 * only, after an approval per session.
 */

import React from 'react';
import { registerEnterpriseTab } from '../registry';
import { createWifiApi } from './wifiApi.ts';
import { TAB_ID, TAB_ORDER, TAB_TITLE } from './wifiLogic.ts';
import type { WifiApi, WifiHass } from './wifiTypes';
import { WifiIntelligenceView } from './WifiIntelligenceView';

let getHass: () => WifiHass | null = () => null;
let client: WifiApi | null = null;

/** Called once by the panel with a getter of its current hass object. */
export function bindWifiHass(getter: () => WifiHass | null): void {
  getHass = getter;
  client = createWifiApi(getter);
}

const isAdmin = (): boolean => getHass()?.user?.is_admin === true;

function WifiTab() {
  if (!client) client = createWifiApi(getHass);
  return React.createElement(WifiIntelligenceView, { api: client, isAdmin });
}

registerEnterpriseTab({
  id: TAB_ID,
  title: TAB_TITLE,
  order: TAB_ORDER,
  component: WifiTab,
  isAvailable: () => getHass() !== null,
});
