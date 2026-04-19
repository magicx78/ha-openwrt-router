import { useMemo } from 'react';
import { TopologyData, Gateway, AccessPoint, Client } from './types';

export type AlertSeverity = 'critical' | 'warning';

export interface Alert {
  id: string;
  severity: AlertSeverity;
  message: string;
  nodeId: string;
  nodeName: string;
  nodeType: 'gateway' | 'ap' | 'client';
}

const CPU_CRITICAL = 85;
const RAM_CRITICAL = 90;
const PING_HIGH_MS = 100;
const AP_CLIENT_MAX = 30;
const BACKHAUL_POOR_DBM = -80;
const CLIENT_POOR_DBM = -80;
const WAN_TRAFFIC_HIGH_BPS = 900_000_000; // 900 Mbps

export function useAlerts(data: TopologyData): Alert[] {
  return useMemo(() => {
    const alerts: Alert[] = [];
    const gw = data.gateway;

    // Rule 9: WAN offline
    if (gw.status === 'offline') {
      alerts.push({
        id: 'gw-wan-offline',
        severity: 'critical',
        message: 'WAN offline — kein Internet',
        nodeId: gw.id,
        nodeName: gw.name,
        nodeType: 'gateway',
      });
    }

    // Rule 1: CPU überlastet
    if (gw.cpuLoad != null && gw.cpuLoad > CPU_CRITICAL) {
      alerts.push({
        id: 'gw-cpu-high',
        severity: 'warning',
        message: `CPU überlastet: ${gw.cpuLoad.toFixed(0)}%`,
        nodeId: gw.id,
        nodeName: gw.name,
        nodeType: 'gateway',
      });
    }

    // Rule 2: RAM kritisch
    if (gw.memUsage != null && gw.memUsage > RAM_CRITICAL) {
      alerts.push({
        id: 'gw-ram-high',
        severity: 'warning',
        message: `RAM kritisch: ${gw.memUsage.toFixed(0)}%`,
        nodeId: gw.id,
        nodeName: gw.name,
        nodeType: 'gateway',
      });
    }

    // Rule 4: Internet nicht erreichbar (ping null bei WAN online)
    if (gw.status !== 'offline' && gw.pingMs == null) {
      alerts.push({
        id: 'gw-ping-null',
        severity: 'warning',
        message: 'Internet nicht erreichbar (kein Ping)',
        nodeId: gw.id,
        nodeName: gw.name,
        nodeType: 'gateway',
      });
    }
    // Rule 3: Ping zu hoch
    else if (gw.pingMs != null && gw.pingMs > PING_HIGH_MS) {
      alerts.push({
        id: 'gw-ping-high',
        severity: 'warning',
        message: `Hohe Latenz: ${gw.pingMs} ms`,
        nodeId: gw.id,
        nodeName: gw.name,
        nodeType: 'gateway',
      });
    }

    // Rule 10: Hoher WAN-Traffic
    const wanBps = Math.max(
      gw.wanTraffic?.downstream_bps ?? 0,
      gw.wanTraffic?.upstream_bps ?? 0,
    );
    if (wanBps > WAN_TRAFFIC_HIGH_BPS) {
      alerts.push({
        id: 'gw-wan-traffic-high',
        severity: 'warning',
        message: `Hoher WAN-Traffic: ${(wanBps / 1_000_000).toFixed(0)} Mbit/s`,
        nodeId: gw.id,
        nodeName: gw.name,
        nodeType: 'gateway',
      });
    }

    for (const ap of data.accessPoints) {
      // Rule 5: AP offline
      if (ap.status === 'offline') {
        alerts.push({
          id: `ap-offline-${ap.id}`,
          severity: 'critical',
          message: 'AP offline',
          nodeId: ap.id,
          nodeName: ap.name,
          nodeType: 'ap',
        });
        continue; // skip further checks for offline APs
      }

      // Rule 6: AP überlastet (zu viele Clients)
      if (ap.clientCount > AP_CLIENT_MAX) {
        alerts.push({
          id: `ap-overloaded-${ap.id}`,
          severity: 'warning',
          message: `AP überlastet: ${ap.clientCount} Clients`,
          nodeId: ap.id,
          nodeName: ap.name,
          nodeType: 'ap',
        });
      }

      // Rule 7: Schlechter Backhaul
      if (ap.uplinkType === 'mesh' && ap.backhaulSignal < BACKHAUL_POOR_DBM) {
        alerts.push({
          id: `ap-backhaul-poor-${ap.id}`,
          severity: 'warning',
          message: `Schwaches Backhaul-Signal: ${ap.backhaulSignal} dBm`,
          nodeId: ap.id,
          nodeName: ap.name,
          nodeType: 'ap',
        });
      }
    }

    // Rule 8: Clients mit schlechtem Signal
    for (const client of data.clients) {
      if (client.signal < CLIENT_POOR_DBM) {
        alerts.push({
          id: `client-signal-poor-${client.id}`,
          severity: 'warning',
          message: `Schwaches Signal: ${client.signal} dBm`,
          nodeId: client.id,
          nodeName: client.name,
          nodeType: 'client',
        });
      }
    }

    // Sort: critical first
    return alerts.sort((a, b) => {
      if (a.severity === b.severity) return 0;
      return a.severity === 'critical' ? -1 : 1;
    });
  }, [data]);
}
