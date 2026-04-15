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
import { fetchTopologyData, type HassLike } from './api';
import { MOCK_DATA } from './mockData';

// ── HA Webcomponent ──────────────────────────────────────────────────────

class OpenWrtTopologyPanel extends HTMLElement {
  private _root: Root | null = null;
  private _hass: HassLike | null = null;
  private _hasLoaded = false;
  private _refreshTimer: ReturnType<typeof setInterval> | null = null;

  connectedCallback() {
    this.style.display = 'block';
    this.style.height = '100%';
    this._root = createRoot(this);
    this._renderPlaceholder('Loading topology…');

    // Periodic refresh every 30 s
    this._refreshTimer = setInterval(() => {
      if (this._hass) void this._fetchAndRender();
    }, 30_000);
  }

  disconnectedCallback() {
    if (this._refreshTimer) clearInterval(this._refreshTimer);
    this._root?.unmount();
    this._root = null;
    this._hasLoaded = false;
  }

  // HA calls this setter on every state update; only fetch on first call.
  set hass(hass: HassLike) {
    this._hass = hass;
    if (!this._hasLoaded) {
      this._hasLoaded = true;
      void this._fetchAndRender();
    }
  }

  private async _fetchAndRender() {
    if (!this._hass || !this._root) return;
    try {
      const topologyData = await fetchTopologyData(this._hass);
      if (!this._root) return; // unmounted while fetching
      this._root.render(
        <React.StrictMode>
          <TopologyView data={topologyData} />
        </React.StrictMode>,
      );
    } catch (err) {
      // AbortError = HA navigation cancelled mid-fetch — reset so next hass update retries
      if ((err as Error)?.name === 'AbortError') {
        this._hasLoaded = false;
        return;
      }
      if (!this._root) return;
      this._root.render(
        <div
          style={{
            color: 'var(--error-color, #db4437)',
            padding: '24px',
            fontFamily: 'var(--paper-font-body1_-_font-family, sans-serif)',
          }}
        >
          Topology load failed: {String(err)}
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
