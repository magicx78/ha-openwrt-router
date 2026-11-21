/**
 * register.ts — hangs Traffic Analytics under "Enterprise", after the
 * Configuration Manager (10), the Security Center (20), the Network
 * Diagnostics (30) and WiFi Intelligence (40); this tab is order 50. It adds
 * no bottom-bar entry.
 *
 * Tab components get no props and no hass, so the panel binds its hass getter
 * once (main.tsx, constructor) via bindTrafficHass; the tab reads it from
 * here. The tab is offered to every logged-in user: the backend decides what
 * a reader may see (administrators, and everyone else while the panel is open
 * to all users; else 403). Flows are for administrators only.
 */

import React from 'react';
import { registerEnterpriseTab } from '../registry';
import { createTrafficApi } from './trafficApi.ts';
import { TAB_ID, TAB_ORDER, TAB_TITLE } from './trafficLogic.ts';
import type { TrafficApi, TrafficHass } from './trafficTypes';
import { TrafficAnalyticsView } from './TrafficAnalyticsView';

let getHass: () => TrafficHass | null = () => null;
let client: TrafficApi | null = null;

/** Called once by the panel with a getter of its current hass object. */
export function bindTrafficHass(getter: () => TrafficHass | null): void {
  getHass = getter;
  client = createTrafficApi(getter);
}

const isAdmin = (): boolean => getHass()?.user?.is_admin === true;

function TrafficTab() {
  if (!client) client = createTrafficApi(getHass);
  return React.createElement(TrafficAnalyticsView, { api: client, isAdmin });
}

registerEnterpriseTab({
  id: TAB_ID,
  title: TAB_TITLE,
  order: TAB_ORDER,
  component: TrafficTab,
  isAvailable: () => getHass() !== null,
});
