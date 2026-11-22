/**
 * tmTexts.ts — German texts of the "Zeitreise" tab (Network Time Machine).
 *
 * TITLE_TEXT holds a text for every `title_key` the backend can produce
 * (tm_sources.py; the own index of 1.51.0 in tm_engine.py, tm_clients.py and
 * tm_marks.py). tests/test_tm_panel_texts_v1500.py and …_v1510.py collect
 * the keys from the backend itself and fail when one has no text here. A
 * key of the own index may carry a code variant (`<key>.<code>`).
 *
 * Fallback rule (titleOf in tmLogic.ts): a key without an entry shows the
 * server's `text` (only the Security Center sends one, already masked), else
 * "Code <title_key>". That covers what cannot be listed in advance: module
 * event types of a module added later or of a newer stored version, log kinds
 * of a newer parser, incident types of an older stored version, Security
 * Center kinds added later.
 *
 * Texts are short, plain German without trailing period. Keep the format
 * `  'key': 'text',` (one per line, single quotes): the Python test reads it.
 */

export const TITLE_TEXT: Record<string, string> = {
  // Audit-Protokoll des Enterprise Core: Kerntypen und Modultypen
  'core_audit.config_manager.backup_blocked': 'Sicherung der Konfiguration blockiert',
  'core_audit.configuration.backup_created': 'Konfiguration gesichert',
  'core_audit.configuration.backup_deleted': 'Konfigurationsversion gelöscht',
  'core_audit.configuration.backup_exported': 'Konfigurationsversion exportiert',
  'core_audit.configuration.backup_failed': 'Sicherung der Konfiguration fehlgeschlagen',
  'core_audit.configuration.backup_protection_changed': 'Schutz einer Konfigurationsversion geändert',
  'core_audit.configuration.backup_recovered': 'Konfigurationsversion wiederhergestellt',
  'core_audit.configuration.backup_validated': 'Konfigurationsversion geprüft',
  'core_audit.configuration.change_critical': 'Kritische Konfigurationsänderung erkannt',
  'core_audit.configuration.change_unknown': 'Unbekannte Konfigurationsänderung erkannt',
  'core_audit.configuration.drift_acknowledged': 'Abweichung der Konfiguration quittiert',
  'core_audit.configuration.drift_detected': 'Abweichung der Konfiguration erkannt',
  'core_audit.configuration.drift_incomplete': 'Abweichungsprüfung unvollständig',
  'core_audit.configuration.integrity_failed': 'Prüfung einer gesicherten Konfiguration fehlgeschlagen',
  'core_audit.configuration.restore_approved': 'Wiederherstellung freigegeben',
  'core_audit.configuration.restore_checked': 'Wiederherstellung probeweise geprüft',
  'core_audit.configuration.restore_completed': 'Konfiguration wiederhergestellt',
  'core_audit.configuration.restore_failed': 'Wiederherstellung fehlgeschlagen',
  'core_audit.configuration.restore_rejected': 'Wiederherstellung abgelehnt',
  'core_audit.configuration.restore_requested': 'Wiederherstellung angefragt',
  'core_audit.configuration.retention_applied': 'Alte Konfigurationsversionen aufgeräumt',
  'core_audit.configuration.router_archived': 'Versionen eines entfernten Routers archiviert',
  'core_audit.configuration.storage_limit_exceeded': 'Speichergrenze für Konfigurationsversionen überschritten',
  'core_audit.configuration.storage_swept': 'Speicher der Konfigurationsversionen bereinigt',
  'core_audit.core.action_rate_limited': 'Aktion wegen zu vieler Aufrufe gebremst',
  'core_audit.core.active_action_granted': 'Aktive Aktion freigegeben',
  'core_audit.core.installation_key_lost': 'Installationsschlüssel verloren',
  'core_audit.core.installation_key_replaced': 'Installationsschlüssel ersetzt',
  'core_audit.core.installation_key_reset': 'Installationsschlüssel zurückgesetzt',
  'core_audit.core.store_recovered': 'Gespeicherte Daten des Kerns neu aufgebaut',
  'core_audit.net_diagnostics.cause': 'Netzwerkdiagnose hat eine Ursache ermittelt',
  'core_audit.net_diagnostics.dns_server_changed': 'DNS-Server gewechselt',
  'core_audit.net_diagnostics.finding': 'Netzwerkdiagnose hat einen Befund gemeldet',
  'core_audit.net_diagnostics.gateway_changed': 'Standard-Gateway gewechselt',
  'core_audit.net_diagnostics.manual_run': 'Netzwerkdiagnose von Hand gestartet',
  'core_audit.net_diagnostics.router_probes_changed': 'Messziele der Netzwerkdiagnose geändert',
  'core_audit.router.adopted': 'Router wieder zugeordnet',
  'core_audit.router.capabilities_changed': 'Fähigkeiten des Routers geändert',
  'core_audit.router.duplicate_suspected': 'Router möglicherweise doppelt eingetragen',
  'core_audit.router.forgotten': 'Verwaister Router entfernt',
  'core_audit.router.identity_changed': 'Identität des Routers geändert',
  'core_audit.router.orphaned': 'Router ohne Eintrag in Home Assistant',
  'core_audit.router.registered': 'Router registriert',
  'core_audit.security.acl_deploy_failed': 'Zugriffsrechte am Router nicht eingerichtet',
  'core_audit.security.acl_deployed': 'Zugriffsrechte am Router eingerichtet',
  'core_audit.security.approval_approved': 'Freigabe erteilt',
  'core_audit.security.approval_expired': 'Freigabe abgelaufen',
  'core_audit.security.approval_rejected': 'Freigabe abgelehnt',
  'core_audit.security.approval_requested': 'Freigabe angefragt',
  'core_audit.security.authorization_consumed': 'Berechtigung verwendet',
  'core_audit.security.authorization_denied': 'Berechtigung verweigert',
  'core_audit.security.authorization_granted': 'Berechtigung erteilt',
  'core_audit.security.config_option_changed': 'Schalter der Konfigurationssicherung geändert',
  'core_audit.security.ssh_pin_confirmed': 'Zugangsschlüssel des Routers bestätigt',
  'core_audit.security.ssh_pin_mismatch': 'Zugangsschlüssel des Routers stimmt nicht überein',
  'core_audit.security.ssh_pin_pending': 'Zugangsschlüssel des Routers wartet auf Bestätigung',
  'core_audit.security.ssh_pin_reset': 'Zugangsschlüssel des Routers zurückgesetzt',
  'core_audit.security_center.dns_many_domains': 'Viele verschiedene DNS-Namen abgefragt',
  'core_audit.security_center.dns_nxdomain_cluster': 'Häufung von DNS-Abfragen nach nicht vorhandenen Namen',
  'core_audit.security_center.dns_rate': 'Ungewöhnlich viele DNS-Abfragen',
  'core_audit.security_center.dns_tunnel_hint': 'Hinweis auf Datenübertragung über DNS',
  'core_audit.security_center.fw_blocked': 'Firewall hat Verbindungen blockiert',
  'core_audit.security_center.fw_inter_vlan': 'Verbindungen zwischen VLANs',
  'core_audit.security_center.fw_mgmt_access': 'Zugriff auf die Verwaltung des Routers',
  'core_audit.security_center.fw_port_scan_hint': 'Hinweis auf einen Portscan',
  'core_audit.security_center.incident_status_changed': 'Status eines Sicherheitsvorfalls geändert',
  'core_audit.security_center.settings_changed': 'Einstellungen des Security Center geändert',
  'core_audit.security_center.trust_confirmed': 'Gerät als vertrauenswürdig bestätigt',
  'core_audit.security_center.trust_quarantined': 'Gerät in Quarantäne gesetzt',
  'core_audit.security_center.trust_released': 'Gerät aus der Quarantäne entlassen',
  'core_audit.security_center.trust_renamed': 'Gerät umbenannt',
  'core_audit.security_center.vlan_segmentation_drift': 'Trennung der VLANs geändert',
  'core_audit.security_center.wifi_assoc_burst': 'Viele WLAN-Anmeldungen in kurzer Zeit',
  'core_audit.security_center.wifi_auth_many_clients': 'Anmeldefehler bei vielen WLAN-Geräten',
  'core_audit.security_center.wifi_auth_repeat': 'Wiederholte WLAN-Anmeldefehler',
  'core_audit.security_center.wifi_deauth_cluster': 'Häufung von WLAN-Abmeldungen',
  'core_audit.security_center.wifi_multi_ap_auth': 'Anmeldefehler an mehreren Zugangspunkten',
  'core_audit.traffic_analytics.anomaly_ended': 'Auffälligkeit im Verkehr beendet',
  'core_audit.traffic_analytics.anomaly_started': 'Auffälligkeit im Verkehr begonnen',
  'core_audit.traffic_analytics.collector_rejected': 'Verkehrsdaten des Sammlers abgelehnt',
  'core_audit.traffic_analytics.indicator': 'Auffälligkeit im Verkehr gemeldet',
  'core_audit.unknown': 'Eintrag im Audit-Protokoll',
  'core_audit.wifi_rf.channel_conflict_measured': 'Kanalkonflikt gemessen',
  'core_audit.wifi_rf.channel_utilization_high': 'Funkkanal stark ausgelastet',
  'core_audit.wifi_rf.recommendation_new': 'Neue Funkempfehlung',
  'core_audit.wifi_rf.recommendation_resolved': 'Funkempfehlung erledigt',
  'core_audit.wifi_rf.scan_executed': 'Funkscan ausgeführt',
  'core_audit.wifi_rf.scan_refused': 'Funkscan abgelehnt',
  'core_audit.wifi_rf.scan_requested': 'Funkscan angefragt',
  // Konfigurationsversionen: Anlass x Ergebnis
  'config_versions.drift.failed': 'Sicherung der Konfiguration fehlgeschlagen (nach Abweichung)',
  'config_versions.drift.ok': 'Konfiguration gesichert (nach Abweichung)',
  'config_versions.drift.partial': 'Konfiguration teilweise gesichert (nach Abweichung)',
  'config_versions.import.failed': 'Sicherung der Konfiguration fehlgeschlagen (Import)',
  'config_versions.import.ok': 'Konfiguration gesichert (Import)',
  'config_versions.import.partial': 'Konfiguration teilweise gesichert (Import)',
  'config_versions.incident.failed': 'Sicherung der Konfiguration fehlgeschlagen (nach Vorfall)',
  'config_versions.incident.ok': 'Konfiguration gesichert (nach Vorfall)',
  'config_versions.incident.partial': 'Konfiguration teilweise gesichert (nach Vorfall)',
  'config_versions.manual.failed': 'Sicherung der Konfiguration fehlgeschlagen (von Hand)',
  'config_versions.manual.ok': 'Konfiguration gesichert (von Hand)',
  'config_versions.manual.partial': 'Konfiguration teilweise gesichert (von Hand)',
  'config_versions.migration.failed': 'Sicherung der Konfiguration fehlgeschlagen (bei Übernahme)',
  'config_versions.migration.ok': 'Konfiguration gesichert (bei Übernahme)',
  'config_versions.migration.partial': 'Konfiguration teilweise gesichert (bei Übernahme)',
  'config_versions.pre_change.failed': 'Sicherung der Konfiguration fehlgeschlagen (vor Änderung)',
  'config_versions.pre_change.ok': 'Konfiguration gesichert (vor Änderung)',
  'config_versions.pre_change.partial': 'Konfiguration teilweise gesichert (vor Änderung)',
  'config_versions.pre_firmware_update.failed': 'Sicherung der Konfiguration fehlgeschlagen (vor Firmware-Update)',
  'config_versions.pre_firmware_update.ok': 'Konfiguration gesichert (vor Firmware-Update)',
  'config_versions.pre_firmware_update.partial': 'Konfiguration teilweise gesichert (vor Firmware-Update)',
  'config_versions.pre_restore.failed': 'Sicherung der Konfiguration fehlgeschlagen (vor Wiederherstellung)',
  'config_versions.pre_restore.ok': 'Konfiguration gesichert (vor Wiederherstellung)',
  'config_versions.pre_restore.partial': 'Konfiguration teilweise gesichert (vor Wiederherstellung)',
  'config_versions.release_change.failed': 'Sicherung der Konfiguration fehlgeschlagen (nach Firmware-Wechsel)',
  'config_versions.release_change.ok': 'Konfiguration gesichert (nach Firmware-Wechsel)',
  'config_versions.release_change.partial': 'Konfiguration teilweise gesichert (nach Firmware-Wechsel)',
  'config_versions.scheduled.failed': 'Sicherung der Konfiguration fehlgeschlagen (geplant)',
  'config_versions.scheduled.ok': 'Konfiguration gesichert (geplant)',
  'config_versions.scheduled.partial': 'Konfiguration teilweise gesichert (geplant)',
  'config_versions.unknown': 'Konfigurationsversion',
  // Ereignisse von Network Intelligence
  'ni_events.dfs.cac_completed': 'Radarprüfung des Kanals abgeschlossen',
  'ni_events.dfs.cac_failed': 'Radarprüfung des Kanals fehlgeschlagen',
  'ni_events.dfs.cac_start': 'Radarprüfung des Kanals gestartet',
  'ni_events.dfs.channel_change': 'Kanal gewechselt',
  'ni_events.dfs.new_channel': 'Kanal wegen Radar gewechselt',
  'ni_events.dfs.nop_finished': 'Sperrzeit eines Radarkanals beendet',
  'ni_events.dfs.pre_cac_expired': 'Vorab-Radarprüfung abgelaufen',
  'ni_events.dfs.radar_detected': 'Radar erkannt',
  'ni_events.dhcp.decline': 'DHCP-Adresse wegen Konflikt abgelehnt',
  'ni_events.dhcp.nak': 'DHCP-Anfrage abgewiesen',
  'ni_events.dhcp.no_address': 'Keine freie DHCP-Adresse',
  'ni_events.dhcp.pool_usage': 'DHCP-Adressbereich stark belegt',
  'ni_events.dns.no_servers': 'Kein DNS-Server erreichbar',
  'ni_events.dns.query_limit': 'Grenze gleichzeitiger DNS-Anfragen erreicht',
  'ni_events.dns.send_failed': 'DNS-Anfrage konnte nicht gesendet werden',
  'ni_events.dns.server_changed': 'DNS-Server gewechselt',
  'ni_events.lan.lldp_change': 'Nachbargerät an einem Port geändert',
  'ni_events.lan.port_down': 'LAN-Port getrennt',
  'ni_events.lan.port_errors': 'Fehlerhafte Pakete an einem LAN-Port',
  'ni_events.lan.port_flap': 'LAN-Port geht ständig auf und ab',
  'ni_events.lan.port_load': 'LAN-Port stark ausgelastet',
  'ni_events.lan.port_speed': 'Geschwindigkeit eines LAN-Ports geändert',
  'ni_events.lan.port_up': 'LAN-Port verbunden',
  'ni_events.lan.uplink': 'Uplink gewechselt',
  'ni_events.rf.channel_busy': 'Funkkanal stark ausgelastet',
  'ni_events.rf.channel_conflict': 'Kanalkonflikt gemessen',
  'ni_events.rf.retry_high': 'Viele Wiederholungen auf dem Funkkanal',
  'ni_events.system.clock_skew': 'Uhrzeit des Routers weicht ab',
  'ni_events.system.conntrack': 'Sprung bei offenen Verbindungen',
  'ni_events.system.cpu_load': 'Hohe Prozessorlast',
  'ni_events.system.lan_reachable': 'Netz wieder erreichbar',
  'ni_events.system.lan_unreachable': 'Netz nicht erreichbar',
  'ni_events.system.log_gap': 'Lücke im Protokoll des Routers',
  'ni_events.system.memory_pressure': 'Arbeitsspeicher knapp',
  'ni_events.system.oom_kill': 'Prozess wegen Speichermangel beendet',
  'ni_events.system.reboot': 'Router neu gestartet',
  'ni_events.system.router_reachable': 'Router wieder erreichbar',
  'ni_events.system.router_unreachable': 'Router nicht erreichbar',
  'ni_events.system.service_crash_loop': 'Dienst stürzt wiederholt ab',
  'ni_events.system.service_restart': 'Dienst neu gestartet',
  'ni_events.system.service_stopped': 'Dienst angehalten',
  'ni_events.unknown': 'Netzwerk-Ereignis',
  'ni_events.wan.down': 'WAN-Verbindung ausgefallen',
  'ni_events.wan.failover': 'Auf Ersatz-WAN umgeschaltet',
  'ni_events.wan.gateway_changed': 'Standard-Gateway gewechselt',
  'ni_events.wan.ip_changed': 'WAN-Adresse geändert',
  'ni_events.wan.reconnect': 'WAN-Verbindung neu aufgebaut',
  'ni_events.wan.status': 'WAN-Zustand geändert',
  'ni_events.wan.up': 'WAN-Verbindung hergestellt',
  'ni_events.wifi.assoc_rejected': 'WLAN-Anmeldung abgewiesen',
  'ni_events.wifi.auth_wave': 'Anmeldefehler bei vielen WLAN-Geräten',
  'ni_events.wifi.backhaul_auth_failed': 'Funkverbindung zum vorgelagerten Router nicht angemeldet',
  'ni_events.wifi.band_change': 'WLAN-Gerät hat das Band gewechselt',
  'ni_events.wifi.dhcp_after_connect': 'DHCP-Fehler nach WLAN-Verbindung',
  'ni_events.wifi.handshake_failed': 'WLAN-Schlüsselaustausch fehlgeschlagen',
  'ni_events.wifi.inactivity_timeout': 'WLAN-Gerät wegen Inaktivität getrennt',
  'ni_events.wifi.mass_disconnect': 'Viele WLAN-Geräte gleichzeitig getrennt',
  'ni_events.wifi.no_ip': 'WLAN-Gerät ohne Adresse',
  'ni_events.wifi.psk_mismatch': 'Falsches WLAN-Passwort',
  'ni_events.wifi.reconnect': 'WLAN-Gerät verbindet sich neu',
  'ni_events.wifi.roam': 'WLAN-Gerät hat den Zugangspunkt gewechselt',
  'ni_events.wifi.sae_failed': 'Sichere WLAN-Anmeldung fehlgeschlagen',
  'ni_events.wifi.weak_clients': 'Mehrere WLAN-Geräte mit schwachem Signal',
  // Vorfälle von Network Intelligence (Typ; der Zustand steht davor)
  'ni_incidents.dhcp_conflict': 'Adresskonflikt im Netz',
  'ni_incidents.dhcp_pool_full': 'DHCP-Adressbereich fast voll',
  'ni_incidents.lan_lldp_change': 'Nachbargerät an einem Port geändert',
  'ni_incidents.lan_port_errors': 'Fehlerhafte Pakete an einem LAN-Port',
  'ni_incidents.lan_port_flap': 'LAN-Port geht ständig auf und ab',
  'ni_incidents.lan_port_load': 'LAN-Port stark ausgelastet',
  'ni_incidents.lan_port_speed_drop': 'LAN-Port mit geringerer Geschwindigkeit',
  'ni_incidents.lan_unreachable': 'Alle Router nicht erreichbar',
  'ni_incidents.lan_uplink_down': 'Uplink-Port getrennt',
  'ni_incidents.router_unreachable': 'Router nicht erreichbar',
  'ni_incidents.system_clock_skew': 'Uhrzeit des Routers weicht ab',
  'ni_incidents.system_conntrack_jump': 'Sprung bei offenen Verbindungen',
  'ni_incidents.system_cpu_high': 'Prozessorlast hoch',
  'ni_incidents.system_ram_high': 'Arbeitsspeicher knapp',
  'ni_incidents.system_reboot': 'Router neu gestartet',
  'ni_incidents.system_service_restart': 'Dienst neu gestartet',
  'ni_incidents.unknown': 'Unbekannter Vorfall',
  'ni_incidents.wan_down': 'WAN-Verbindung ausgefallen',
  'ni_incidents.wan_ip_changed': 'WAN-Adresse geändert',
  'ni_incidents.wan_unstable': 'WAN-Verbindung instabil',
  'ni_incidents.wifi_auth_failures': 'Wiederholte WLAN-Anmeldefehler',
  'ni_incidents.wifi_auth_wave': 'Anmeldefehler bei vielen WLAN-Geräten',
  'ni_incidents.wifi_band_flapping': 'WLAN-Gerät wechselt ständig das Band',
  'ni_incidents.wifi_channel_busy': 'Funkkanal stark ausgelastet',
  'ni_incidents.wifi_dhcp_after_connect': 'DHCP-Fehler nach WLAN-Verbindung',
  'ni_incidents.wifi_mass_disconnect': 'Viele WLAN-Geräte gleichzeitig getrennt',
  'ni_incidents.wifi_no_ip': 'WLAN-Gerät ohne Adresse',
  'ni_incidents.wifi_radio_change': 'Funkmodul hat den Kanal gewechselt',
  'ni_incidents.wifi_reconnect_storm': 'WLAN-Gerät verbindet sich ständig neu',
  'ni_incidents.wifi_roam_flapping': 'WLAN-Gerät springt zwischen Zugangspunkten',
  'ni_incidents.wifi_weak_clients': 'Mehrere WLAN-Geräte mit schwachem Signal',
  // Zeitleiste des Security Center: Art[.Typ]
  'security_timeline.action': 'Aktion an einem Gerät',
  'security_timeline.action.trust_confirmed': 'Gerät als vertrauenswürdig bestätigt',
  'security_timeline.action.trust_quarantined': 'Gerät in Quarantäne gesetzt',
  'security_timeline.action.trust_released': 'Gerät aus der Quarantäne entlassen',
  'security_timeline.action.trust_renamed': 'Gerät umbenannt',
  'security_timeline.cap_reached': 'Höchstzahl an Sicherheitshinweisen erreicht',
  'security_timeline.drift': 'Abweichung der Konfiguration erkannt',
  'security_timeline.incident_opened': 'Sicherheitsvorfall eröffnet',
  'security_timeline.incident_reopened': 'Sicherheitsvorfall wieder eröffnet',
  'security_timeline.incident_resolved': 'Sicherheitsvorfall behoben',
  'security_timeline.incident_seen_again': 'Sicherheitsvorfall erneut beobachtet',
  'security_timeline.log_quota_reached': 'Anteil für Hinweise aus Protokollen ausgeschöpft',
  'security_timeline.notice': 'Hinweis zu einem Gerät',
  'security_timeline.notice.trust_capacity': 'Geräteliste voll',
  'security_timeline.notice.trust_incomplete': 'Angaben zu einem Gerät unvollständig',
  'security_timeline.notice.trust_ip_churn': 'Gerät wechselt häufig die Adresse',
  'security_timeline.notice.trust_new_device': 'Neues Gerät im Netz',
  'security_timeline.notice.trust_private_mac': 'Gerät mit privater Hardware-Adresse',
  'security_timeline.notice.trust_suspicious': 'Auffälliges Gerät',
  'security_timeline.other_quota_reached': 'Anteil für sonstige Sicherheitshinweise ausgeschöpft',
  'security_timeline.reused': 'Bekannter Hinweis erneut gesehen',
  'security_timeline.reused.dns_many_domains': 'Erneut gesehen: Viele verschiedene DNS-Namen abgefragt',
  'security_timeline.reused.dns_nxdomain_cluster': 'Erneut gesehen: Häufung von DNS-Abfragen nach nicht vorhandenen Namen',
  'security_timeline.reused.dns_rate': 'Erneut gesehen: Ungewöhnlich viele DNS-Abfragen',
  'security_timeline.reused.dns_tunnel_hint': 'Erneut gesehen: Hinweis auf Datenübertragung über DNS',
  'security_timeline.reused.fw_blocked': 'Erneut gesehen: Firewall hat Verbindungen blockiert',
  'security_timeline.reused.fw_inter_vlan': 'Erneut gesehen: Verbindungen zwischen VLANs',
  'security_timeline.reused.fw_mgmt_access': 'Erneut gesehen: Zugriff auf die Verwaltung des Routers',
  'security_timeline.reused.fw_port_scan_hint': 'Erneut gesehen: Hinweis auf einen Portscan',
  'security_timeline.reused.vlan_segmentation_drift': 'Erneut gesehen: Trennung der VLANs geändert',
  'security_timeline.reused.wifi_assoc_burst': 'Erneut gesehen: Viele WLAN-Anmeldungen in kurzer Zeit',
  'security_timeline.reused.wifi_auth_many_clients': 'Erneut gesehen: Anmeldefehler bei vielen WLAN-Geräten',
  'security_timeline.reused.wifi_auth_repeat': 'Erneut gesehen: Wiederholte WLAN-Anmeldefehler',
  'security_timeline.reused.wifi_deauth_cluster': 'Erneut gesehen: Häufung von WLAN-Abmeldungen',
  'security_timeline.reused.wifi_multi_ap_auth': 'Erneut gesehen: Anmeldefehler an mehreren Zugangspunkten',
  'security_timeline.status': 'Status eines Sicherheitsvorfalls geändert',
  'security_timeline.traffic_indicator': 'Auffälligkeit im Verkehr',
  'security_timeline.traffic_indicator.changed_protocol_distribution': 'Veränderte Verteilung der Protokolle',
  'security_timeline.traffic_indicator.new_communication_destinations': 'Neue Kommunikationsziele',
  'security_timeline.traffic_indicator.suspicious_connection_rate': 'Auffällige Verbindungsrate',
  'security_timeline.traffic_indicator.unusual_inter_vlan_traffic': 'Ungewöhnlicher Verkehr zwischen VLANs',
  'security_timeline.traffic_indicator.unusual_outbound_connections': 'Ungewöhnliche ausgehende Verbindungen',
  'security_timeline.traffic_indicator.unusual_traffic_volume': 'Ungewöhnliche Verkehrsmenge',
  'security_timeline.unknown': 'Eintrag des Security Center',
  'security_timeline.wifi_quota_reached': 'Anteil für WLAN-Hinweise ausgeschöpft',
  // Eigener Verlauf (1.51.0): Schlüssel <Quelle>.<Art>, mit Code-Varianten
  // <Quelle>.<Art>.<Code> (titleOf nimmt die Variante zuerst)
  'tm_clients.client_disconnect': 'Getrennt',
  'tm_clients.client_flapping': 'Sehr viele Wechsel (zusammengefasst)',
  'tm_clients.client_roam': 'Gewechselt',
  'tm_clients.client_session': 'Verbunden',
  'tm_index.channel_changed': 'Kanal gewechselt',
  'tm_index.channel_changed.dfs': 'Kanal gewechselt (Radar)',
  'tm_index.clock_shift': 'Uhr verstellt',
  'tm_index.clock_shift.backwards': 'Uhr zurückgestellt',
  'tm_index.clock_shift.forwards': 'Uhr vorgestellt',
  'tm_index.config_fingerprint_changed': 'Konfiguration verändert',
  'tm_index.ha_gap': 'Home Assistant war aus',
  'tm_index.ha_gap.unclean': 'Home Assistant war aus, nicht sauber beendet',
  'tm_index.lan_down': 'Kein Router erreichbar',
  'tm_index.lan_up': 'Router wieder erreichbar (ganzes Netz)',
  'tm_index.observation_gap': 'Keine Daten',
  'tm_index.observation_gap.unloaded': 'Keine Daten (Integration entladen)',
  'tm_index.radio_down': 'Funkmodul fehlt',
  'tm_index.radio_up': 'Funkmodul wieder da',
  'tm_index.router_down': 'Router nicht erreichbar',
  'tm_index.router_role_changed': 'Rolle gewechselt',
  'tm_index.router_role_changed.gateway': 'Rolle gewechselt: Gateway',
  'tm_index.router_role_changed.node': 'Rolle gewechselt: Knoten',
  'tm_index.router_up': 'Router wieder erreichbar',
  'tm_index.tm_cleared': 'Verlauf gelöscht',
  'tm_index.tm_cleared.clients': 'Client-Verläufe gelöscht',
  'tm_index.tm_disabled': 'Zeitreise ausgeschaltet',
  'tm_index.tm_forgot_client': 'Client vergessen',
  'tm_index.tm_started': 'Zeitreise gestartet',
  'tm_index.tm_started.switched_on': 'Zeitreise eingeschaltet',
  'tm_index.tm_store_recovered': 'Verlauf neu begonnen (Datei beschädigt)',
  'tm_index.uplink_changed': 'Uplink gewechselt',
  'tm_index.uplink_changed.uplink_lost': 'Uplink verloren',
};

/** Display names of the sources (tm_sources.ALL_SOURCE_IDS). */
export const SOURCE_TEXT: Record<string, string> = {
  'core_audit': 'Audit',
  'config_versions': 'Konfiguration',
  'ni_events': 'Netzwerk-Ereignisse',
  'ni_incidents': 'Vorfälle',
  'security_timeline': 'Security Center',
  'tm_index': 'Eigener Verlauf',
  'tm_refs': 'Verweise',
  'tm_clients': 'Client-Verläufe',
};

/** State of a source (shown as text, never as colour alone). */
export const STATE_TEXT: Record<string, string> = {
  'ok': 'gelesen',
  'empty': 'leer',
  'off': 'aus',
  'unreadable': 'Quelle nicht lesbar',
};

/** Why a source is off or unreadable (tm_sources.REASONS). */
export const REASON_TEXT: Record<string, string> = {
  'admin_only': 'nur für Administratoren',
  'module_off': 'Modul aus',
  'not_running': 'Modul nicht eingerichtet',
  'not_loaded': 'Daten noch nicht geladen',
  'timeout': 'Zeitüberschreitung',
  'error': 'Fehler',
  'bad_format': 'unerwartetes Format',
  'clients_off': 'in den Optionen einschalten',
};

/**
 * Why the client sessions are not available (status "unavailable" of
 * GET …/sessions; the reasons tm_query.sessions_page sends, checked by
 * tests/test_tm_panel_texts_v1510.py). Whole sentences after "Client-Sitzungen
 * sind noch nicht verfügbar.".
 */
export const UNAVAILABLE_TEXT: Record<string, string> = {
  'not_running': 'Die Aufzeichnung läuft gerade nicht.',
  'not_loaded': 'Der gespeicherte Verlauf wird noch geladen.',
};

/** Groups of the kinds (tm_sources.KIND_GROUP values). */
export const GROUP_TEXT: Record<string, string> = {
  'infrastructure': 'Infrastruktur',
  'radio': 'Funk',
  'topology': 'Topologie',
  'configuration': 'Konfiguration',
  'disruption': 'Störung',
  'security': 'Sicherheit',
  'administration': 'Verwaltung',
  'clients': 'Clients',
  'time_machine': 'Zeitreise',
};

export const SEVERITY_TEXT: Record<string, string> = {
  'info': 'Info',
  'warning': 'Warnung',
  'critical': 'Kritisch',
};

/**
 * Numbers of `params` in plain words: `{n}` is the German number. Only these
 * keys are shown, in this order; unknown keys are left out. PARAM_ONE holds
 * the singular where it differs.
 */
export const PARAM_TEXT: Record<string, string> = {
  'occurrences': '{n} Vorkommen',
  'reopen_count': '{n}-mal wieder geöffnet',
  'repeat_count': '{n}-mal wiederholt',
  'count': '{n}-mal',
  'changes': '{n} Änderungen',
  'critical_count': '{n} kritische Änderungen',
  'unknown_count': '{n} unbekannte Änderungen',
  'not_compared_count': '{n} Bereiche nicht verglichen',
  'affected': '{n} Geräte betroffen',
  'children': '{n} Folgeereignisse',
  'routers': '{n} Router',
  'channel': 'Kanal {n}',
  'frequency': '{n} MHz',
  'gap_s': 'Lücke von {d}',
  'missed': '{n} Protokollzeilen verpasst',
  // eigener Verlauf (1.51.0); {D} genaue Dauer, {g} Band, {to} Wert von *_to
  'band': '{g}',
  'channel_from': 'Kanal {n} → {to}',
  'channel_to': 'Kanal {n}',
  'width_from': 'Breite {n} → {to} MHz',
  'width_to': 'Breite {n} MHz',
  'dfs': 'wegen Radar',
  'duration_s': 'Dauer {D}',
  'off_s': 'vorher {D} aus',
  'shift_s': 'um {D}',
  'clean': 'sauber beendet',
  'deleted': '{n} gelöscht',
  'timed': 'per Zeitablauf erkannt',
  'resumed': 'nach Neustart fortgesetzt',
  'roam': '{n} Wechsel',
  'gaps': '{n} Lücken',
  'blips': '{n} kurze Aussetzer',
  'suppressed': '{n} zusammengefasst',
  'cap': 'Grenze {n} je Tag',
  // 1.52.0: epoch of the first sighting of a new uplink or role ({t} its time)
  'since': 'zuerst gesehen {t}',
};

export const PARAM_ONE: Record<string, string> = {
  'changes': '1 Änderung',
  'critical_count': '1 kritische Änderung',
  'unknown_count': '1 unbekannte Änderung',
  'not_compared_count': '1 Bereich nicht verglichen',
  'affected': '1 Gerät betroffen',
  'children': '1 Folgeereignis',
  'missed': '1 Protokollzeile verpasst',
  'roam': '1 Wechsel',
  'gaps': '1 Lücke',
  'blips': '1 kurzer Aussetzer',
  'deleted': '1 gelöscht',
};

// ── 1.52.0: state at a moment, comparison, jumps ─────────────────────────

/**
 * Why nothing at a moment is known (`unknown_reason` of a `known: false`
 * answer, tm_state.Snapshot.global_reason). Whole sentences after
 * "Für diesen Zeitpunkt ist kein Zustand bekannt.". Checked against the
 * backend by tests/test_tm_panel_texts_v1520.py.
 */
export const GLOBAL_REASON_TEXT: Record<string, string> = {
  'ha_gap': 'Home Assistant lief zu dieser Zeit nicht.',
  'observation_gap': 'Die Router wurden zu dieser Zeit nicht beobachtet.',
  'not_recorded': 'Zu dieser Zeit wurde noch nicht aufgezeichnet.',
  'beyond_retention': 'Der Zeitpunkt liegt außerhalb der Aufbewahrung von 14 Tagen.',
  'evicted': 'Die Aufzeichnung zu dieser Zeit wurde verdrängt.',
  'clock_shift': 'Die Uhr von Home Assistant ist zurückgesprungen; diese Zeit kommt im Verlauf doppelt vor.',
};

/**
 * Why one value or part is unknown or incomplete (`reason` next to a value,
 * a radio, a part or an incident; tm_state.UNKNOWN_REASONS and the part
 * reasons). Shown muted after "unbekannt" (or "aus", "unvollständig").
 */
export const STATE_REASON_TEXT: Record<string, string> = {
  'beyond_retention': 'außerhalb der Aufbewahrung',
  'not_recorded': 'nicht aufgezeichnet',
  'ha_gap': 'Home Assistant lief nicht',
  'observation_gap': 'nicht beobachtet',
  'evicted': 'Aufzeichnung verdrängt',
  'clock_shift': 'Uhr zurückgesprungen, Zeit doppelt',
  'not_observed': 'noch kein Wert beobachtet',
  'router_down': 'Router nicht erreichbar',
  'lan_down': 'LAN nicht erreichbar',
  'ambiguous_radio': 'Funk nicht eindeutig zuzuordnen',
  'inconsistent': 'Aufzeichnung widersprüchlich',
  'settling': 'Wechsel noch nicht gefestigt',
  'flapping': 'ein Client wechselte sehr oft, Sitzungen zusammengefasst',
  'reopened_since': 'seitdem wieder geöffnet, früherer Zustand verloren',
  'source_pruned': 'ältere Vorfälle nicht mehr gespeichert',
  'cut': 'gekürzt',
  'unreadable': 'nicht lesbar',
  'module_off': 'Modul aus',
  'not_running': 'Modul nicht eingerichtet',
  'not_loaded': 'Daten noch nicht geladen',
  'admin_only': 'nur für Administratoren',
  'clients_off': 'Client-Verläufe ausgeschaltet',
  'timeout': 'Zeitüberschreitung',
  'error': 'Fehler',
  'bad_format': 'unerwartetes Format',
};

/** State of a part of the state (shown as a word, never as colour alone). */
export const PART_STATE_TEXT: Record<string, string> = {
  'ok': 'gelesen',
  'partial': 'unvollständig',
  'unknown': 'unbekannt',
  'off': 'aus',
  'unreadable': 'nicht lesbar',
};

/** Role of a router in the mesh (`role.value`). */
export const ROLE_TEXT: Record<string, string> = {
  'gateway': 'Gateway',
  'node': 'Mesh-Knoten',
};

/** Radio state at a moment (`radios.items[].state`). */
export const RADIO_STATE_TEXT: Record<string, string> = {
  'up': 'an',
  'down': 'aus',
  'unknown': 'unbekannt',
};

/** Band names of the radios (`band` of a radio item and of the utilization, channel_plan.BAND_*). */
export const RADIO_BAND_TEXT: Record<string, string> = {
  '2.4g': '2,4 GHz',
  '5g': '5 GHz',
  '6g': '6 GHz',
};

/** Names of the Enterprise tabs a jump opens (the panel's tab ids, tm_sources.TAB_*). */
export const JUMP_TAB_TEXT: Record<string, string> = {
  'config': 'Konfiguration',
  'security': 'Security Center',
  'diagnostics': 'Netzwerkdiagnose',
  'wifi': 'WiFi Intelligence',
  'traffic': 'Traffic Analytics',
  'timemachine': 'Zeitreise',
};

/**
 * `<ref.module>.<ref.type>` of a mark -> tab id, `by_kind` (JUMP_KIND_TAB)
 * or `none` (no Enterprise tab). The panel's copy of tm_sources.JUMP_TARGETS;
 * tests/test_tm_panel_texts_v1520.py compares both ways.
 */
export const JUMP_REF_TAB: Record<string, string> = {
  'core_audit.event': 'by_kind',
  'core_audit.drift': 'config',
  'config_manager.version': 'config',
  'network_intelligence.event': 'none',
  'network_intelligence.incident': 'none',
  'security_center.incident': 'security',
  'security_center.drift': 'security',
  'security_center.timeline': 'security',
  'time_machine.mark': 'timemachine',
};

/** `kind` of a `core_audit.event` mark -> tab id or `none` (tm_sources.KIND_TABS, KIND_NO_TAB). */
export const JUMP_KIND_TAB: Record<string, string> = {
  'config_event': 'config',
  'config_drift': 'config',
  'security_incident': 'security',
  'rf_event': 'wifi',
  'diag_finding': 'diagnostics',
  'traffic_anomaly': 'traffic',
  'registry_event': 'none',
  'security_event': 'none',
  'core_event': 'none',
  'audit_event': 'none',
};

/** What the object of a target is (tm_sources._OBJECT): only these are selected in their tab. */
export const JUMP_OBJECT: Record<string, string> = {
  'core_audit.event': 'audit_event',
  'core_audit.drift': 'audit_event',
  'config_manager.version': 'version',
  'security_center.incident': 'incident',
  'security_center.drift': 'drift',
};

