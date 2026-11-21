/**
 * register.ts — hangs the Network Diagnostics under "Enterprise", next to the
 * Configuration Manager ("Konfiguration", order 10) and the Security Center
 * (order 20); this tab is order 30.
 *
 * Tab components get no props and no hass, so the panel binds its hass getter
 * once (main.tsx, constructor) via bindDiagnosticsHass; the tab reads it from
 * here. The tab is offered to every logged-in user: the backend decides what a
 * reader may see (administrators and, while the panel is open to all users,
 * everyone else get the brief, masked view; else 403), and only administrators
 * get the run and settings controls.
 */

import React from 'react';
import { registerEnterpriseTab } from '../registry';
import { createDiagApi } from './diagnosticsApi.ts';
import { TAB_ID, TAB_TITLE } from './diagnosticsLogic.ts';
import type { DiagApi, DiagHass } from './diagnosticsTypes';
import { DiagnosticsView } from './DiagnosticsView';

let getHass: () => DiagHass | null = () => null;
let client: DiagApi | null = null;

/** Called once by the panel with a getter of its current hass object. */
export function bindDiagnosticsHass(getter: () => DiagHass | null): void {
  getHass = getter;
  client = createDiagApi(getter);
}

const isAdmin = (): boolean => getHass()?.user?.is_admin === true;

function DiagnosticsTab() {
  if (!client) client = createDiagApi(getHass);
  return React.createElement(DiagnosticsView, { api: client, isAdmin });
}

registerEnterpriseTab({
  id: TAB_ID,
  title: TAB_TITLE,
  order: 30,
  component: DiagnosticsTab,
  isAvailable: () => getHass() !== null,
});
