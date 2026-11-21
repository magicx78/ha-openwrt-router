/**
 * register.ts — hangs the Security Center under "Enterprise", next to the
 * Configuration Manager ("Konfiguration", order 10; this tab is order 20).
 *
 * Tab components get no props and no hass, so the panel binds its hass getter
 * once (main.tsx, constructor) via bindSecurityHass; the tab reads it from
 * here. The tab is offered to every logged-in user: the backend decides what
 * a reader may see (administrators plain data, everyone else pseudonyms, or
 * 403 while the panel is not opened to all users), and only administrators
 * get write buttons.
 *
 * installSecurityMock is the dev-mode hook for ?securitymock; main.tsx calls
 * it only behind import.meta.env.DEV, so a production build never takes that
 * path.
 */

import React from 'react';
import { registerEnterpriseTab } from '../registry';
import { createSecurityApi } from './securityApi.ts';
import type { SecurityApi, SecurityHass } from './securityTypes';
import { SecurityCenterView } from './SecurityCenterView';

let getHass: () => SecurityHass | null = () => null;
let client: SecurityApi | null = null;

/** Called once by the panel with a getter of its current hass object. */
export function bindSecurityHass(getter: () => SecurityHass | null): void {
  getHass = getter;
  client = createSecurityApi(getter);
}

/** Dev only: replace hass and client by the mock (see securityMock.ts). */
export function installSecurityMock(getter: () => SecurityHass | null, api: SecurityApi): void {
  getHass = getter;
  client = api;
}

const isAdmin = (): boolean => getHass()?.user?.is_admin === true;

function SecurityTab() {
  if (!client) client = createSecurityApi(getHass);
  return React.createElement(SecurityCenterView, { api: client, isAdmin });
}

registerEnterpriseTab({
  id: 'security',
  title: 'Security Center',
  order: 20,
  component: SecurityTab,
  isAvailable: () => getHass() !== null,
});
