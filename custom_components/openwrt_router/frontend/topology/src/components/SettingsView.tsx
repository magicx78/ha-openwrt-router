/**
 * SettingsView — Integration info, links to HA config, and about section.
 */

import React from 'react';

export function SettingsView() {
  return (
    <div className="topo-view">
      <div className="view-header">
        <span className="view-title">Einstellungen</span>
      </div>

      {/* Integration */}
      <div className="settings-card">
        <div className="settings-card__heading">Integration</div>
        <a
          className="settings-link"
          href="/config/integrations"
          title="HA Integrationen öffnen"
        >
          Integrationseinstellungen öffnen →
        </a>
        <a
          className="settings-link"
          href="/config/entities?domain=sensor&search=openwrt"
          title="OpenWrt Entities in HA"
        >
          OpenWrt Entities in HA →
        </a>
        <a
          className="settings-link"
          href="/config/devices"
          title="Geräte in HA"
        >
          Geräteverwaltung →
        </a>
      </div>

      {/* Data */}
      <div className="settings-card">
        <div className="settings-card__heading">Datenpflege</div>
        <div className="settings-row">
          <span className="settings-row__label">Polling-Intervall</span>
          <span className="settings-row__value">30 s</span>
        </div>
        <div className="settings-row">
          <span className="settings-row__label">API-Endpunkt</span>
          <span className="settings-row__value settings-row__value--mono">/api/openwrt_topology/snapshot</span>
        </div>
        <div className="settings-info">
          Die Topology-Daten werden automatisch alle 30 Sekunden vom HA-Backend abgerufen.
          Gerätedaten (Uptime, WAN-Status, Clients) werden durch den HA-Coordinator aktualisiert.
        </div>
      </div>

      {/* About */}
      <div className="settings-card">
        <div className="settings-card__heading">Über</div>
        <div className="settings-row">
          <span className="settings-row__label">Integration</span>
          <span className="settings-row__value">ha-openwrt-router</span>
        </div>
        <div className="settings-row">
          <span className="settings-row__label">Domain</span>
          <span className="settings-row__value settings-row__value--mono">openwrt_router</span>
        </div>
        <div className="settings-row">
          <span className="settings-row__label">GitHub</span>
          <span className="settings-row__value">
            <a
              className="settings-link settings-link--inline"
              href="https://github.com/magicx78/ha-openwrt-router"
              target="_blank"
              rel="noopener noreferrer"
            >
              magicx78/ha-openwrt-router ↗
            </a>
          </span>
        </div>
        <div className="settings-row">
          <span className="settings-row__label">Schema</span>
          <span className="settings-row__value settings-row__value--mono">v1.0</span>
        </div>
      </div>
    </div>
  );
}
