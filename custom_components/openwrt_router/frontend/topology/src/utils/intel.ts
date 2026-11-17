/**
 * intel.ts — German wording for the network intelligence (Diagnose tab, P7).
 *
 * The engine sends stable keys (incident type, cause, event kind, status);
 * this file turns them into labels. The recommendations are static advice
 * per incident type — the engine itself never acts on a router.
 */

import { TopologyFetchError } from '../api';
import type { CauseLevel, IncidentCounts, IncidentStatus, Severity } from '../types';

/** Short German text for a failed intelligence request. */
export function errorMessage(err: unknown): string {
  if (err instanceof TopologyFetchError) {
    if (err.status === 403) return 'Nur für Administratoren.';
    if (err.status === 503) return 'Die Netzwerk-Analyse startet noch – gleich erneut versuchen.';
    if (err.status === 410) return 'Die Integration ist nicht geladen.';
  }
  return err instanceof Error ? err.message : String(err);
}

const TYPE_LABEL: Record<string, string> = {
  wifi_reconnect_storm: 'Client verbindet sich ständig neu',
  wifi_auth_failures: 'Wiederholte Anmeldefehler (Client)',
  wifi_auth_wave: 'Anmeldefehler bei vielen Clients',
  wifi_mass_disconnect: 'Viele Clients gleichzeitig getrennt',
  wifi_no_ip: 'WLAN-Client ohne IP-Adresse',
  wifi_dhcp_after_connect: 'DHCP-Fehler nach WLAN-Verbindung',
  wifi_band_flapping: 'Client wechselt ständig das Band',
  wifi_roam_flapping: 'Client springt zwischen APs',
  wifi_weak_clients: 'Mehrere Clients mit schwachem Signal',
  wifi_channel_busy: 'Funkkanal stark ausgelastet',
  wifi_radio_change: 'Funkmodul hat den Kanal gewechselt',
  system_cpu_high: 'CPU-Last hoch',
  system_ram_high: 'Arbeitsspeicher knapp',
  system_reboot: 'Router neu gestartet',
  system_service_restart: 'Dienst neu gestartet',
  system_clock_skew: 'Uhrzeit des Routers weicht ab',
  system_conntrack_jump: 'Sprung bei offenen Verbindungen',
  router_unreachable: 'Router nicht erreichbar',
  lan_unreachable: 'Alle Router nicht erreichbar',
  lan_port_flap: 'LAN-Port geht ständig auf und ab',
  lan_port_speed_drop: 'LAN-Port mit geringerer Geschwindigkeit',
  lan_port_errors: 'Fehlerhafte Pakete am LAN-Port',
  lan_port_load: 'LAN-Port stark ausgelastet',
  lan_uplink_down: 'Uplink-Port getrennt',
  lan_lldp_change: 'LLDP-Nachbar geändert',
  wan_down: 'WAN getrennt',
  wan_unstable: 'WAN instabil',
  wan_ip_changed: 'WAN-IP geändert',
  dhcp_pool_full: 'DHCP-Pool fast voll',
  dhcp_conflict: 'IP-Adresskonflikt (DHCP)',
};

const RECOMMENDATION: Record<string, string> = {
  wifi_reconnect_storm:
    'Signal und Energiesparmodus des Clients prüfen; bei mehreren Clients am selben AP dessen Kanal und Platzierung prüfen.',
  wifi_auth_failures:
    'WLAN-Passwort auf dem Client neu eingeben; bei WPA3 prüfen, ob der Client SAE unterstützt.',
  wifi_auth_wave:
    'Wurde das WLAN-Passwort oder die Verschlüsselung geändert? Sonst auf unbekannte Geräte (Angriff) achten.',
  wifi_mass_disconnect:
    'Systemprotokoll des APs auf Funkneustart, DFS-Radar oder Stromausfall prüfen.',
  wifi_no_ip:
    'DHCP-Server und VLAN-Zuordnung des WLANs prüfen; feste IP auf dem Client ausschließen.',
  wifi_dhcp_after_connect:
    'DHCP-Server, Pool-Größe und VLAN des WLANs prüfen.',
  wifi_band_flapping:
    'Band-Steering-Einstellungen prüfen; ggf. den Client fest auf ein Band legen.',
  wifi_roam_flapping:
    'Überlappung der APs verringern (Sendeleistung) oder Roaming-Schwellen anpassen.',
  wifi_weak_clients:
    'AP-Platzierung oder Sendeleistung prüfen; ggf. einen weiteren AP ergänzen.',
  wifi_channel_busy:
    'Einen weniger belegten Kanal wählen oder die Kanalbreite verringern.',
  wifi_radio_change:
    'DFS-Radar oder automatische Kanalwahl; tritt es oft auf, einen Nicht-DFS-Kanal wählen.',
  system_cpu_high: 'Prozesse auf dem Router prüfen (top); Last durch Dienste wie SQM oder Adblock?',
  system_ram_high: 'Speicherverbrauch prüfen; nicht benötigte Pakete oder Dienste entfernen.',
  system_reboot: 'Ursache im Systemprotokoll prüfen (Stromversorgung, Watchdog, Update).',
  system_service_restart: 'Protokoll des Dienstes prüfen; wiederholte Neustarts deuten auf eine Fehlkonfiguration hin.',
  system_clock_skew: 'NTP auf dem Router prüfen (Zeitserver erreichbar?).',
  system_conntrack_jump: 'Auf ungewöhnlich viele Verbindungen eines Geräts achten (Scan, Fehlverhalten).',
  router_unreachable: 'Strom und Kabel des Routers prüfen; ist sein Uplink-Port aktiv?',
  lan_unreachable: 'Verbindung zwischen Home Assistant und dem Netz prüfen (Switch, Kabel, HA-Host).',
  lan_port_flap: 'Kabel und Stecker am Port tauschen; Gegenstelle prüfen.',
  lan_port_speed_drop: 'Kabel prüfen (Adernpaare); Gegenstelle auf Auto-Negotiation prüfen.',
  lan_port_errors: 'Kabel tauschen; Duplex-Einstellungen beider Seiten vergleichen.',
  lan_port_load: 'Großen Verbraucher an diesem Port suchen (Traffic-Ansicht).',
  lan_uplink_down: 'Uplink-Kabel und den Switch-Port davor prüfen.',
  lan_lldp_change: 'Wurde umgesteckt? Sonst Verkabelung prüfen.',
  wan_down: 'Modem und Provider-Status prüfen; WAN-Kabel kontrollieren.',
  wan_unstable: 'Modem-Protokoll und Leitung prüfen; ggf. Störung beim Provider melden.',
  wan_ip_changed: 'Normal bei dynamischer IP; DynDNS-Aktualisierung prüfen.',
  dhcp_pool_full: 'DHCP-Pool vergrößern oder Lease-Zeit verkürzen.',
  dhcp_conflict: 'Gerät mit fester IP im DHCP-Bereich suchen und Adresse ändern.',
};

const CAUSE_LABEL: Record<string, string> = {
  router_unreachable: 'Router nicht erreichbar',
  lan_unreachable: 'Netz nicht erreichbar',
  router_reboot: 'Router-Neustart',
  wan_down: 'WAN-Ausfall',
  radio_change: 'Kanalwechsel des Funkmoduls',
  uplink_down: 'Uplink getrennt',
  mass_disconnect: 'Massen-Trennung am AP',
  weak_signal: 'schwaches Signal',
  ap_full: 'AP voll belegt',
  attack: 'möglicher Angriff',
  band_steering: 'Band-Steering',
  client_driver: 'Treiber des Clients',
  client_power_save: 'Energiesparmodus des Clients',
  coverage: 'Funkabdeckung',
  dhcp_server: 'DHCP-Server',
  interference: 'Funkstörung',
  overlapping_coverage: 'überlappende Funkzellen',
  pool_exhausted: 'DHCP-Pool erschöpft',
  power_supply: 'Stromversorgung',
  psk_changed: 'WLAN-Passwort geändert',
  psk_wrong: 'falsches WLAN-Passwort',
  radio_restart: 'Neustart des Funkmoduls',
  sae_mismatch: 'WPA3/SAE inkompatibel',
  static_ip: 'feste IP am Client',
  steering: 'Steering',
  uplink_config: 'Uplink-Konfiguration',
  vlan: 'VLAN-Zuordnung',
  wrong_network: 'falsches Netz',
  port_flap: 'Port geht ständig auf und ab',
  client_side: 'Problem auf Client-Seite',
  dns_resolution: 'DNS-Auflösung',
  ip_conflict: 'IP-Adresskonflikt',
  mac_filter: 'MAC-Filter',
  roaming: 'Roaming',
  auth: 'Anmeldung',
};

/**
 * Advice per cause (RT7), by the engine's recommendation_key (rec_<cause>).
 * English versions: docs/realtime-rca.md. tests/test_net_recommendations.py
 * checks that every key the engine sends has a text here.
 */
const CAUSE_RECOMMENDATION: Record<string, string> = {
  rec_ap_full: 'Clients auf weitere APs verteilen oder das Client-Limit des APs erhöhen.',
  rec_attack: 'Auf unbekannte Geräte achten; ggf. WLAN-Passwort ändern.',
  rec_auth: 'WLAN-Passwort und Verschlüsselung auf dem Client prüfen.',
  rec_band_steering: 'Band-Steering-Einstellungen prüfen; ggf. den Client fest auf ein Band legen.',
  rec_client_driver: 'Treiber oder Firmware des Clients aktualisieren.',
  rec_client_power_save: 'Energiesparmodus des WLANs am Client abschalten (z. B. ESP: power_save_mode none).',
  rec_client_side:
    'Andere Clients am selben Funkmodul sind stabil: Gerät, Stromversorgung und Standort des Clients prüfen.',
  rec_coverage: 'AP-Platzierung oder Sendeleistung prüfen; ggf. einen weiteren AP ergänzen.',
  rec_dhcp_server: 'DHCP-Server (dnsmasq/odhcpd) auf dem Gateway prüfen.',
  rec_dns_resolution: 'Upstream-DNS-Server und WAN-Verbindung des Gateways prüfen.',
  rec_interference: 'Kanal und Störquellen prüfen; einen weniger belegten Kanal wählen.',
  rec_ip_conflict: 'Gerät mit fester IP im DHCP-Bereich suchen und Adresse ändern.',
  rec_lan_unreachable: 'Verbindung zwischen Home Assistant und dem Netz prüfen (Switch, Kabel, HA-Host).',
  rec_mac_filter: 'MAC-Filter des WLANs prüfen.',
  rec_mass_disconnect: 'Systemprotokoll des APs auf Funkneustart, DFS-Radar oder Stromausfall prüfen.',
  rec_overlapping_coverage: 'Überlappung der APs verringern (Sendeleistung) oder Roaming-Schwellen anpassen.',
  rec_pool_exhausted: 'DHCP-Pool vergrößern oder Lease-Zeit verkürzen.',
  rec_port_flap: 'Kabel und Stecker am Port tauschen; Gegenstelle und deren Stromversorgung prüfen.',
  rec_power_supply: 'Stromversorgung des Geräts prüfen (Netzteil, PoE-Budget).',
  rec_psk_changed: 'Wurde das WLAN-Passwort geändert? Dann auf den Clients neu eingeben.',
  rec_psk_wrong: 'WLAN-Passwort auf dem Client neu eingeben.',
  rec_radio_change: 'DFS-Radar oder automatische Kanalwahl; tritt es oft auf, einen Nicht-DFS-Kanal wählen.',
  rec_radio_restart: 'Systemprotokoll des APs auf Neustarts des Funkmoduls prüfen.',
  rec_roaming: 'Roaming-Schwellen und Sendeleistung der APs prüfen.',
  rec_router_reboot: 'Ursache des Neustarts im Systemprotokoll prüfen (Stromversorgung, Watchdog, Update).',
  rec_router_unreachable: 'Strom und Kabel des Routers prüfen; ist sein Uplink-Port aktiv?',
  rec_sae_mismatch: 'Prüfen, ob der Client WPA3/SAE unterstützt; sonst WPA2/WPA3-Mischmodus nutzen.',
  rec_static_ip: 'Feste IP-Einstellung am Client entfernen oder an das Netz anpassen.',
  rec_steering: 'Steering-Einstellungen (usteer) prüfen.',
  rec_uplink_config: 'Konfiguration des Uplinks (VLAN, Bridge) prüfen.',
  rec_uplink_down: 'Uplink-Kabel und den Switch-Port davor prüfen.',
  rec_vlan: 'VLAN-Zuordnung des WLANs oder Ports prüfen.',
  rec_wan_down: 'Modem und Provider-Status prüfen; WAN-Kabel kontrollieren.',
  rec_weak_signal: 'Signal prüfen: AP näher, Antenne ausrichten, ggf. 2,4 GHz nutzen.',
  rec_wrong_network: 'Prüfen, ob der Client mit dem richtigen WLAN verbunden ist.',
};

export const CATEGORY_LABEL: Record<string, string> = {
  wifi: 'WLAN',
  dhcp: 'DHCP',
  system: 'System',
  lan: 'LAN',
  wan: 'WAN',
  dns: 'DNS',
  mesh: 'Mesh',
};

export const AREA_LABEL: Record<string, string> = {
  wifi: 'WLAN',
  system: 'System',
  lan: 'LAN',
  wan: 'WAN',
  dhcp_dns: 'DHCP/DNS',
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'kritisch',
  warning: 'Warnung',
  info: 'Info',
};

export const STATUS_LABEL: Record<IncidentStatus, string> = {
  active: 'aktiv',
  acknowledged: 'bestätigt (gesehen)',
  ignored: 'ignoriert',
  resolved: 'behoben',
};

/** cause_level → German (planned field for RT-1; today derived in net_query.py). */
export const CAUSE_LEVEL_LABEL: Record<CauseLevel, string> = {
  confirmed: 'bestätigt',
  likely: 'wahrscheinlich',
  possible: 'möglich',
  unknown: 'unbekannt',
};

export const SCOPE_LABEL: Record<string, string> = {
  client: 'Client',
  radio: 'Funkmodul',
  port: 'Port',
  router: 'Router',
  segment: 'Segment',
  fleet: 'Flotte',
};

function humanize(key: string): string {
  return key.replace(/[._]/g, ' ');
}

export function typeLabel(type: string): string {
  return TYPE_LABEL[type] ?? humanize(type);
}

/** Advice for an incident: by its cause if there is one, else by its type. */
export function recommendation(type: string, key?: string | null): string | undefined {
  return (key ? CAUSE_RECOMMENDATION[key] : undefined) ?? RECOMMENDATION[type];
}

export function causeLabel(cause: string | null): string {
  if (!cause) return 'keine Ursache ermittelt';
  return CAUSE_LABEL[cause] ?? humanize(cause);
}

export function kindLabel(kind: string): string {
  return humanize(kind);
}

/** Area of an incident for the WLAN / infrastructure split. */
export function isWifiIncident(type: string, area: string | null): boolean {
  return area === 'wifi' || type.startsWith('wifi_');
}

export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ${m % 60} min`;
  return `${Math.floor(h / 24)} d ${h % 24} h`;
}

export function formatTs(ts: number | null | undefined): string {
  if (ts == null || !Number.isFinite(ts)) return '–';
  return new Date(ts * 1000).toLocaleString('de-DE', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/** Highest severity with a count > 0, or null. */
export function topSeverity(counts?: IncidentCounts): Severity | null {
  if (!counts) return null;
  if (counts.critical > 0) return 'critical';
  if (counts.warning > 0) return 'warning';
  if (counts.info > 0) return 'info';
  return null;
}

export function countsTotal(counts?: IncidentCounts): number {
  return counts ? counts.critical + counts.warning + counts.info : 0;
}
