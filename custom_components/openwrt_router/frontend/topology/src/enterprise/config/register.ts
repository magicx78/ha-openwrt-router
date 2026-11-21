/**
 * register.ts — hangs the Configuration Manager under "Enterprise".
 *
 * Tab components get no props and no hass (LÜCKE L8), so the panel binds
 * its hass getter once (main.tsx, constructor) via bindConfigHass; the tab
 * reads it from here. The tab is offered to administrators only.
 *
 * installConfigMock is the dev-mode hook for ?configmock; main.tsx calls it only
 * behind import.meta.env.DEV, so a production build never takes that path.
 */

import React from 'react';
import { registerEnterpriseTab } from '../registry';
import { createConfigApi } from './configApi.ts';
import type { ConfigApi, ConfigHass } from './configTypes';
import { ConfigManagerView } from './ConfigManagerView';

let getHass: () => ConfigHass | null = () => null;
let client: ConfigApi | null = null;

/** Called once by the panel with a getter of its current hass object. */
export function bindConfigHass(getter: () => ConfigHass | null): void {
  getHass = getter;
  client = createConfigApi(getter);
}

/** Dev only: replace hass and client by the mock (see configMock.ts). */
export function installConfigMock(getter: () => ConfigHass | null, api: ConfigApi): void {
  getHass = getter;
  client = api;
}

function ConfigTab() {
  if (!client) client = createConfigApi(getHass);
  return React.createElement(ConfigManagerView, { api: client });
}

registerEnterpriseTab({
  id: 'config',
  title: 'Konfiguration',
  order: 10,
  component: ConfigTab,
  isAvailable: () => getHass()?.user?.is_admin === true,
});
