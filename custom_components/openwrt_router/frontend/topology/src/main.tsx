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
import topologyCSS from './topology.css?inline';
import { TopologyView } from './TopologyView';
import { fetchTopologyData, type HassLike } from './api';
import { MOCK_DATA } from './mockData';

// ── HA Webcomponent ──────────────────────────────────────────────────────

class OpenWrtTopologyPanel extends HTMLElement {
  private _root: Root | null = null;
  private _hass: HassLike | null = null;
  private _refreshTimer: ReturnType<typeof setInterval> | null = null;
  private _retryTimer: ReturnType<typeof setTimeout> | null = null;
  private _fetching = false;
  private _sessionExpired = false;

  connectedCallback() {
    this.style.display = 'block';
    this.style.height = '100%';

    // Inject CSS as a sibling <style> element — NOT inside the React container.
    // React's createRoot().render() would otherwise remove it when it replaces
    // the container's children on first render.
    const styleEl = document.createElement('style');
    styleEl.textContent = topologyCSS;
    this.appendChild(styleEl);

    // Mount React into a separate <div> so React DOM updates never touch the
    // <style> element injected above.
    const reactContainer = document.createElement('div');
    reactContainer.style.cssText = 'height:100%;display:contents';
    this.appendChild(reactContainer);

    this._root = createRoot(reactContainer);
    this._renderPlaceholder('Loading topology…');

    // Wait 500 ms for HA navigation transition to complete before first fetch.
    // HA's callApi uses the navigation AbortSignal — fetching immediately
    // causes an AbortError while the panel transition is still in progress.
    this._retryTimer = setTimeout(() => void this._fetchAndRender(), 500);

    // Periodic refresh every 30 s
    this._refreshTimer = setInterval(() => void this._fetchAndRender(), 30_000);
  }

  disconnectedCallback() {
    if (this._refreshTimer) clearInterval(this._refreshTimer);
    if (this._retryTimer) clearTimeout(this._retryTimer);
    this._root?.unmount();
    this._root = null;
  }

  // HA calls this setter on every state update — just store the reference.
  // If a new hass object arrives after session expiry, reset and resume polling.
  set hass(hass: HassLike) {
    const wasExpired = this._sessionExpired;
    this._hass = hass;
    if (wasExpired && hass) {
      this._sessionExpired = false;
      this._refreshTimer = setInterval(() => void this._fetchAndRender(), 30_000);
      void this._fetchAndRender();
    }
  }

  private async _fetchAndRender() {
    if (!this._hass || !this._root || this._fetching || this._sessionExpired) return;
    this._fetching = true;
    try {
      const topologyData = await fetchTopologyData(this._hass);
      if (!this._root) return;
      this._root.render(
        <React.StrictMode>
          <TopologyView data={topologyData} />
        </React.StrictMode>,
      );
    } catch (err) {
      // AbortError = HA navigation still in progress — retry after 1 s
      if ((err as Error)?.name === 'AbortError') {
        this._retryTimer = setTimeout(() => void this._fetchAndRender(), 1_000);
        return;
      }
      if (!this._root) return;

      // 401 = session expired — stop polling, show reload prompt
      const is401 = String(err).includes('401');
      if (is401) {
        this._sessionExpired = true;
        if (this._refreshTimer) {
          clearInterval(this._refreshTimer);
          this._refreshTimer = null;
        }
        this._root.render(
          <div style={{ color: 'var(--warning-color, #f59e0b)', padding: '24px', fontFamily: 'var(--paper-font-body1_-_font-family, sans-serif)' }}>
            <strong>Sitzung abgelaufen.</strong>{' '}
            <a href="#" onClick={e => { e.preventDefault(); window.location.reload(); }} style={{ color: 'var(--primary-color, #03a9f4)' }}>
              Seite neu laden
            </a>
          </div>,
        );
        return;
      }

      this._root.render(
        <div style={{ color: 'var(--error-color, #db4437)', padding: '24px', fontFamily: 'var(--paper-font-body1_-_font-family, sans-serif)' }}>
          Topology load failed: {String(err)}
        </div>,
      );
    } finally {
      this._fetching = false;
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
