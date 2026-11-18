/**
 * Enterprise sub-tab registry.
 *
 * Every Enterprise module (Configuration Manager, Security Center, Network
 * Diagnostics, WiFi Intelligence, ...) hangs exactly ONE sub-tab under the
 * "Enterprise" navigation entry by registering it here. EnterpriseView renders
 * whatever is registered; with nothing registered it shows a placeholder.
 *
 * Usage (in the module's own file, imported once for its side effect from
 * main.tsx / TopologyView.tsx):
 *
 *   import { registerEnterpriseTab } from './enterprise/registry';
 *   import { ConfigManagerView } from './components/ConfigManagerView';
 *
 *   registerEnterpriseTab({
 *     id: 'config',                 // unique, stable
 *     title: 'Konfiguration',       // tab label
 *     icon: IconSettings,           // optional, 14 px
 *     order: 10,                    // ascending; ties sorted by title
 *     component: ConfigManagerView, // rendered while the tab is active
 *     isAvailable: () => backendHasConfigApi(), // optional; false hides the tab
 *   });
 *
 * Rules: a duplicate id throws in dev builds and is ignored with a console
 * warning in production (the first registration wins). `isAvailable` is
 * evaluated on every render of EnterpriseView, so it must be cheap.
 */

import type React from 'react';

export interface EnterpriseTab {
  id: string;
  title: string;
  icon?: React.FC<{ size?: number; className?: string }>;
  /** Ascending sort key; equal orders fall back to the title. */
  order: number;
  component: React.ComponentType;
  /** Return false to hide the tab (e.g. backend capability missing). */
  isAvailable?: () => boolean;
}

const tabs = new Map<string, EnterpriseTab>();

export function registerEnterpriseTab(tab: EnterpriseTab): void {
  if (tabs.has(tab.id)) {
    const msg = `Enterprise tab "${tab.id}" is already registered`;
    if (import.meta.env.DEV) throw new Error(msg);
    console.warn(`${msg}; ignoring the duplicate.`);
    return;
  }
  tabs.set(tab.id, tab);
}

/** Registered tabs that are currently available, sorted by order then title. */
export function getEnterpriseTabs(): EnterpriseTab[] {
  return [...tabs.values()]
    .filter(t => (t.isAvailable ? t.isAvailable() : true))
    .sort((a, b) => a.order - b.order || a.title.localeCompare(b.title, 'de'));
}
