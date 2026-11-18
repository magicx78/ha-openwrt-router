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
 * warning in production (the first registration wins). In dev, re-registering
 * an id from the SAME file (hot reload) replaces the old entry. The Enterprise
 * nav entry is shown only while hasEnterpriseTabs() is true. `isAvailable` is
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
/** Dev only: id -> file that registered it, so a hot reload may replace it. */
const sources = new Map<string, string | null>();

/** Dev only: URL of the file that called registerEnterpriseTab, without ?t=/line info. */
function callerFile(): string | null {
  const line = new Error().stack?.split('\n')[3] ?? '';
  const m = /((?:https?|file):\/\/[^\s)?]+|[A-Za-z]:[^\s)?]+?)(?:\?[^\s):]*)?:\d+:\d+/.exec(line);
  return m ? m[1] : null;
}

export function registerEnterpriseTab(tab: EnterpriseTab): void {
  if (tabs.has(tab.id)) {
    const src = import.meta.env.DEV ? callerFile() : null;
    if (src !== null && src === sources.get(tab.id)) {
      tabs.set(tab.id, tab); // hot reload of the same module: replace
      return;
    }
    const msg = `Enterprise tab "${tab.id}" is already registered`;
    if (import.meta.env.DEV) throw new Error(msg);
    console.warn(`${msg}; ignoring the duplicate.`);
    return;
  }
  tabs.set(tab.id, tab);
  if (import.meta.env.DEV) sources.set(tab.id, callerFile());
}

/** True when at least one tab is registered and available (drives the nav entry). */
export function hasEnterpriseTabs(): boolean {
  return getEnterpriseTabs().length > 0;
}

/** Registered tabs that are currently available, sorted by order then title. */
export function getEnterpriseTabs(): EnterpriseTab[] {
  return [...tabs.values()]
    .filter(t => (t.isAvailable ? t.isAvailable() : true))
    .sort((a, b) => a.order - b.order || a.title.localeCompare(b.title, 'de'));
}
