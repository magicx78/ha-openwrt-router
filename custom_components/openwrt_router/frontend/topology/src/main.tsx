/**
 * main.tsx — Entry point for both dev mode and HA panel (webcomponent).
 *
 * Dev mode:  if <div id="root"> exists, mounts TopologyView with MOCK_DATA.
 * HA mode:   defines <openwrt-topology-panel> custom element that receives
 *            the `hass` object, fetches live data, and renders TopologyView.
 */

import React from 'react';
import { createRoot } from 'react-dom/client';
import type { Root } from 'react-dom/client';
import './topology.css';
import { TopologyView } from './TopologyView';
import { fetchTopologyData } from './api';
import { MOCK_DATA } from './mockData';

// ── HA Webcomponent ──────────────────────────────────────────────────────

class OpenWrtTopologyPanel extends HTMLElement {
  private _root: Root | null = null;
  private _hass: Record<string, unknown> | null = null;
  private _hasLoaded = false;
  private _refreshTimer: ReturnType<typeof setInterval> | null = null;

  connectedCallback() {
    this.style.display = 'block';
    this.style.height = '100%';
    this._root = createRoot(this);
    this._renderPlaceholder('Loading topology…');

    // Periodic refresh every 30 s
    this._refreshTimer = setInterval(() => {
      const token = this._getToken();
      if (token) void this._fetchAndRender(token);
    }, 30_000);
  }

  disconnectedCallback() {
    if (this._refreshTimer) clearInterval(this._refreshTimer);
    this._root?.unmount();
    this._root = null;
    this._hasLoaded = false;
  }

  // HA calls this setter on every state update; only fetch on first call.
  set hass(hass: Record<string, unknown>) {
    this._hass = hass;
    if (!this._hasLoaded) {
      const token = this._getToken();
      if (token) {
        this._hasLoaded = true;
        void this._fetchAndRender(token);
      }
    }
  }

  private _getToken(): string | null {
    // HA exposes the token at hass.auth.data.access_token
    const auth = this._hass?.auth as Record<string, unknown> | undefined;
    const data = auth?.data as Record<string, unknown> | undefined;
    return (data?.access_token as string) ?? null;
  }

  private async _fetchAndRender(token: string) {
    try {
      const topologyData = await fetchTopologyData(token);
      this._root?.render(
        <React.StrictMode>
          <TopologyView data={topologyData} />
        </React.StrictMode>,
      );
    } catch (err) {
      this._root?.render(
        <div
          style={{
            color: 'var(--error-color, #db4437)',
            padding: '24px',
            fontFamily: 'var(--paper-font-body1_-_font-family, sans-serif)',
          }}
        >
          Failed to load topology: {String(err)}
        </div>,
      );
    }
  }

  private _renderPlaceholder(message: string) {
    this._root?.render(
      <div
        style={{
          color: 'var(--secondary-text-color, #888)',
          padding: '24px',
          fontFamily: 'var(--paper-font-body1_-_font-family, sans-serif)',
        }}
      >
        {message}
      </div>,
    );
  }
}

if (!customElements.get('openwrt-topology-panel')) {
  customElements.define('openwrt-topology-panel', OpenWrtTopologyPanel);
}

// ── Dev mode mount ────────────────────────────────────────────────────────

const rootEl = document.getElementById('root');
if (rootEl) {
  createRoot(rootEl).render(
    <React.StrictMode>
      <TopologyView data={MOCK_DATA} />
    </React.StrictMode>,
  );
}
