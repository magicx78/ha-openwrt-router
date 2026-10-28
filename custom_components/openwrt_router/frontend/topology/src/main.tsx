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
import { fetchTopologyData, hassAccessToken, TopologyFetchError, type HassLike } from './api';
import type { TopologyData } from './types';
import { MOCK_DATA } from './mockData';

// ── HA Webcomponent ──────────────────────────────────────────────────────

const REFRESH_MS = 30_000;
const FONT = 'var(--paper-font-body1_-_font-family, sans-serif)';

/** Why requests are paused / refused: 401 waits for a new token, 403 for rights. */
type AuthBlock = 'expired' | 'forbidden' | null;

function httpStatus(err: unknown): number | null {
  if (err instanceof TopologyFetchError) return err.status;
  // Last resort for errors that only carry the status in their text.
  const m = /\bHTTP (\d{3})\b/.exec(String(err));
  return m ? Number(m[1]) : null;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

class OpenWrtTopologyPanel extends HTMLElement {
  private _root: Root | null = null;
  private _hass: HassLike | null = null;
  private _refreshTimer: ReturnType<typeof setInterval> | null = null;
  private _retryTimer: ReturnType<typeof setTimeout> | null = null;
  private _fetching = false;
  // Last successfully loaded topology — kept on screen across transient errors.
  private _lastData: TopologyData | null = null;
  private _authBlock: AuthBlock = null;
  // Token that got the 401: requests resume only once HA hands us another one.
  private _blockedToken: string | undefined = undefined;
  private readonly _onVisibility = () => {
    // callApi path (no token to compare): one attempt each time the tab
    // becomes visible again — event-driven, so no request loop.
    if (document.visibilityState === 'visible' && this._authBlock === 'expired') {
      this._resume();
    }
  };

  connectedCallback() {
    this.style.display = 'block';
    this.style.height = '100%';
    // Anchor for the non-blocking error badge.
    this.style.position = 'relative';

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
    document.addEventListener('visibilitychange', this._onVisibility);

    // Re-attached while the session is expired: show that, request nothing
    // until the token changes or the tab becomes visible again.
    if (this._authBlock === 'expired') {
      this._renderExpired();
      return;
    }
    this._renderMessage('Loading topology…', 'var(--secondary-text-color, #888)');

    // Wait 500 ms for HA navigation transition to complete before first fetch.
    // HA's callApi uses the navigation AbortSignal — fetching immediately
    // causes an AbortError while the panel transition is still in progress.
    this._retryTimer = setTimeout(() => void this._fetchAndRender(), 500);
    this._startPolling();
  }

  disconnectedCallback() {
    document.removeEventListener('visibilitychange', this._onVisibility);
    this._stopPolling();
    if (this._retryTimer) clearTimeout(this._retryTimer);
    this._retryTimer = null;
    this._root?.unmount();
    this._root = null;
  }

  // HA calls this setter on every state update — just store the reference.
  // After a 401, requests resume only when the access token actually changed
  // (HA refreshed it); retrying with the same token would loop on 401.
  set hass(hass: HassLike) {
    this._hass = hass;
    if (this._authBlock !== 'expired' || !hass) return;
    const token = hassAccessToken(hass);
    if (token === undefined || token === this._blockedToken) return;
    this._resume();
  }

  /** Leave the 401 block with ONE request; polling restarts only on success. */
  private _resume() {
    if (!this._root) return;
    this._authBlock = null;
    this._blockedToken = undefined;
    void this._fetchAndRender();
  }

  private _startPolling() {
    if (this._refreshTimer) return;
    this._refreshTimer = setInterval(() => void this._fetchAndRender(), REFRESH_MS);
  }

  private _stopPolling() {
    if (this._refreshTimer) clearInterval(this._refreshTimer);
    this._refreshTimer = null;
  }

  private async _fetchAndRender() {
    if (!this._hass || !this._root || this._fetching || this._authBlock === 'expired') return;
    this._fetching = true;
    const hass = this._hass;
    try {
      const topologyData = await fetchTopologyData(hass);
      if (!this._root) return;
      this._authBlock = null;
      this._lastData = topologyData;
      this._renderTopology(topologyData, null);
      this._startPolling();
    } catch (err) {
      // AbortError = HA navigation still in progress — retry after 1 s
      if ((err as Error)?.name === 'AbortError') {
        this._retryTimer = setTimeout(() => void this._fetchAndRender(), 1_000);
        return;
      }
      if (!this._root) return;

      const status = httpStatus(err);

      // 401 even after fetchTopologyData's one refresh-and-retry: stop
      // requesting until the token changes (or the tab becomes visible).
      if (status === 401) {
        this._authBlock = 'expired';
        this._blockedToken = hassAccessToken(hass);
        this._stopPolling();
        this._renderExpired();
        return;
      }

      // 403 = not an admin and the panel is not opened to all users. Drop
      // the cached view (no longer allowed). Polling continues at the normal
      // interval (one request per 30 s), so the view comes back by itself
      // once an admin enables the option.
      if (status === 403) {
        this._authBlock = 'forbidden';
        this._lastData = null;
        this._startPolling();
        this._root.render(
          <div style={{ color: 'var(--warning-color, #f59e0b)', padding: '24px', fontFamily: FONT }}>
            <strong>Nur für Administratoren.</strong>{' '}
            Die Netzwerk-Topologie ist auf Administratoren beschränkt. Ein Administrator
            kann sie in den Optionen der OpenWrt-Router-Integration
            („Topologie-Panel allen Benutzern anzeigen“) für alle Benutzer freigeben.
          </div>,
        );
        return;
      }

      // Not an auth problem: keep the normal 30 s polling (also after a
      // resume from the 401 block) so the view recovers by itself.
      this._startPolling();

      // Transient error (500, network, 410 during a reload …): keep the last
      // good topology and flag the problem instead of blanking the view.
      if (this._lastData) {
        this._renderTopology(this._lastData, errorText(err));
        return;
      }

      this._renderMessage(`Topology load failed: ${errorText(err)}`, 'var(--error-color, #db4437)');
    } finally {
      this._fetching = false;
    }
  }

  private _renderTopology(data: TopologyData, staleError: string | null) {
    this._root?.render(
      <React.StrictMode>
        <TopologyView data={data} />
        {staleError && (
          <div
            role="status"
            title={staleError}
            style={{
              position: 'absolute',
              top: '8px',
              right: '8px',
              zIndex: 1000,
              maxWidth: '360px',
              padding: '6px 10px',
              borderRadius: '6px',
              background: 'var(--card-background-color, #1f2937)',
              border: '1px solid var(--error-color, #db4437)',
              color: 'var(--error-color, #db4437)',
              fontSize: '12px',
              fontFamily: FONT,
              pointerEvents: 'none',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            Aktualisierung fehlgeschlagen — letzter Stand wird angezeigt ({staleError})
          </div>
        )}
      </React.StrictMode>,
    );
  }

  private _renderExpired() {
    this._root?.render(
      <div style={{ color: 'var(--warning-color, #f59e0b)', padding: '24px', fontFamily: FONT }}>
        <strong>Sitzung abgelaufen.</strong>{' '}
        <a href="#" onClick={e => { e.preventDefault(); window.location.reload(); }} style={{ color: 'var(--primary-color, #03a9f4)' }}>
          Seite neu laden
        </a>
      </div>,
    );
  }

  private _renderMessage(message: string, color: string) {
    this._root?.render(
      <div style={{ color, padding: '24px', fontFamily: FONT }}>
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
  // Mount inside a shadow root like HA does, so CSS that only works in a
  // plain document (e.g. variables on :root) fails here too instead of
  // only in Home Assistant. The stylesheet is bundled as an inline string.
  const shadow = rootEl.attachShadow({ mode: 'open' });
  const devStyle = document.createElement('style');
  devStyle.textContent = topologyCSS;
  shadow.appendChild(devStyle);
  const devContainer = document.createElement('div');
  devContainer.style.cssText = 'height:100%;display:contents';
  shadow.appendChild(devContainer);
  createRoot(devContainer).render(
    <React.StrictMode>
      <TopologyView data={MOCK_DATA} />
    </React.StrictMode>,
  );
}
