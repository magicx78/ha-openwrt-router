/**
 * shTexts.ts — the German texts of the "Self-Healing" tab (read only).
 *
 * REASON_TEXT is the ONE table for every reason code the routes of
 * heal_views.py can return (decision rules, risk reasons, score lines, gate
 * reasons, blockers of the plan, history reasons, hold and pause reasons,
 * recovery statements). The policy part is a copy of
 * heal_policy.REASON_TEXT_DE (shLogic.test.mjs compares both, key by key).
 * A code that is not in the table is shown as the raw code, never hidden
 * (shLogic.reasonText).
 *
 * The other tables are labels of fixed values (states, modes, outcomes,
 * actors, permissions, catalog actions, playbooks, fact names).
 */

export const REASON_TEXT: Readonly<Record<string, string>> = {
  // ── heal_policy.REASON_TEXT_DE (copy; compared in shLogic.test.mjs) ──
  action_type_invalid: 'Die Aktionskennung hat keine gültige Form.',
  unknown_action: 'Diese Aktion steht nicht im Katalog.',
  params_invalid: 'Die Parameter haben keine gültige Form.',
  param_unknown: 'Ein Parameter ist für diese Aktion unbekannt.',
  param_missing: 'Ein nötiger Parameter fehlt.',
  param_value_invalid: 'Ein Parameterwert liegt außerhalb der erlaubten Werte.',
  never_client_action: 'Aktionen an Clients (trennen, sperren, umlenken) gibt es nie.',
  never_firewall: 'Firewall-Änderungen stehen nie im Katalog.',
  never_vlan: 'VLAN-Änderungen stehen nie im Katalog.',
  never_management_ip: 'Änderungen der Management-Adresse stehen nie im Katalog.',
  never_routing: 'Routing-Änderungen stehen nie im Katalog.',
  never_firmware: 'Firmware-Eingriffe stehen nie im Katalog.',
  never_network_reload: 'Ein Neuladen des ganzen Netzwerks steht nicht im Katalog.',
  never_wpad_restart: 'Ein Neustart von wpad (WLAN aller Clients) steht nicht im Katalog.',
  never_config_write: 'Konfiguration schreiben steht nicht im Katalog.',
  never_shell: 'Befehle auf dem Router gibt es nicht.',
  never_dhcp_lease_delete: 'DHCP-Leases werden nie gelöscht.',
  entry_not_in_catalog: 'Der Katalogeintrag ist nicht der des Katalogs.',
  components_invalid: 'Die Bauteile passen nicht zu den Parametern.',
  first_write_release_approval_only: 'Erste schreibende Aktion: nur mit Freigabe, ab 1.54.0.',
  call_unverified_on_fleet: 'Der Router-Aufruf ist auf dieser Flotte nicht geprüft.',
  modelled_blocked_no_out_of_band: 'Modelliert und gesperrt: kein zweiter Zugangsweg zum Router.',
  restore_dry_run_only: 'Wiederherstellen ist nur ein Probelauf.',
  recommendation_only_no_acl: 'Nur Empfehlung: keine Rechte für Schnittstellen.',
  role_unknown: 'Die Rolle des Routers ist unbekannt.',
  identity_not_confirmed: 'Die Identität des Routers ist nicht bestätigt.',
  open_security_finding: 'Am Router gibt es eine offene Sicherheitserkennung.',
  in_maintenance_window: 'Für Router oder Ziel läuft ein Wartungsfenster.',
  service_disabled_on_purpose: 'Der Dienst ist auf diesem Router absichtlich aus; ein Neustart wäre keine Reparatur.',
  target_on_management_path: 'Die Aktion trifft den Management-Weg von Home Assistant.',
  wireless_uplink_radio: 'Das Funkmodul trägt einen drahtlosen Uplink.',
  uplink_for_other_routers: 'Hinter diesem Ziel hängen weitere Router.',
  clients_affected: 'Verbundene Clients wären betroffen.',
  service_serves_other_routers: 'Andere Router und ihre Clients nutzen DNS/DHCP dieses Routers.',
  service_config_unapplied: 'Die gespeicherte Konfiguration des Dienstes ist nicht angewendet; ein Neustart würde sie in Kraft setzen (Drift-Playbook statt Neustart).',
  context_missing: 'Nötige Angaben zum Router fehlen; das Risiko gilt als hoch.',
  not_in_catalog: 'Nicht im Katalog: das Risiko gilt als hoch.',
  action_disabled: 'Die Aktion ist modelliert, aber gesperrt.',
  not_root_incident: 'Repariert wird nur der Wurzelvorfall, nicht ein Folgevorfall.',
  diagnostics_off: 'Die Netzwerkdiagnose ist aus.',
  router_unreachable: 'Der Router ist nicht erreichbar.',
  breaker_open: 'Der Schutzschalter dieser Aktion ist offen.',
  concurrent_repair: 'Auf dem Router läuft schon eine Reparatur.',
  risk_high_no_recovery: 'Hohes Risiko ohne Wiederherstellungsweg.',
  no_incident: 'Kein Vorfall belegt diese Aktion.',
  history_unknown: 'Die Versuche der letzten 24 h sind unbekannt.',
  cause_outside_router: 'Die Ursache liegt außerhalb des Routers; ein Neustart hilft nicht.',
  cause_location_unknown: 'Unklar, ob die Ursache außerhalb des Routers liegt.',
  root_unknown: 'Unklar, ob es der Wurzelvorfall ist.',
  temporal_correlation_only: 'Nur zeitlicher Zusammenhang: zuerst diagnostizieren.',
  evidence_stale: 'Die Hinweise sind veraltet.',
  hypothesis_single_source: 'Vermutung aus nur einer Quellenfamilie.',
  no_direct_target_fact: 'Kein direkter Befund am Ziel.',
  score_below_threshold: 'Die Konfidenz liegt unter der Schwelle.',
  temporal_link_diagnose_only: 'Nur zeitlicher Zusammenhang: Diagnose ist der richtige Schritt.',
  impact_summary: 'Auswirkung: Clients, abhängige Router, geschätzte Unterbrechung.',
  recovery_statement: 'Aussage zur Wiederherstellung dieser Aktion.',
  risk_needs_approval: 'Risiko 2 oder höher: nur mit ausdrücklicher Freigabe.',
  all_rules_passed: 'Alle Regeln erfüllt.',
  outcome_unsupported: 'Nicht unterstützt.',
  outcome_not_safe: 'Nicht sicher.',
  outcome_insufficient_evidence: 'Zu wenig Belege.',
  cause_level: 'Ursachenstufe',
  cause_status: 'Ursachenstatus',
  incident_confidence: 'Konfidenz des Vorfalls',
  source_families: 'Quellenfamilien',
  target_fact: 'Befund am Ziel',
  prior_attempts: 'Frühere Versuche',
  config_change: 'Konfigurationsänderung',
  severity: 'Schweregrad',
  clamp: 'Begrenzung auf 0 bis 100',
  cause_level_confirmed: 'Ursache bestätigt.',
  cause_level_likely: 'Ursache wahrscheinlich.',
  cause_level_possible: 'Ursache möglich.',
  cause_level_unknown: 'Ursache unbekannt.',
  cause_status_confirmed: 'Ursache gemessen bestätigt.',
  cause_status_hypothesis: 'Ursache ist eine Vermutung.',
  confidence_missing: 'Keine Konfidenz angegeben.',
  incident_confidence_scaled: 'Konfidenz von Network Intelligence, auf 10 Punkte skaliert.',
  no_source_family: 'Keine Quellenfamilie.',
  one_source_family: 'Eine Quellenfamilie.',
  two_or_more_source_families: 'Zwei oder mehr unabhängige Quellenfamilien.',
  target_fact_direct: 'Direkter Befund am Ziel.',
  target_fact_log_only: 'Nur Log-Hinweise am Ziel.',
  target_fact_none: 'Kein Befund am Ziel.',
  prior_failed_attempts: 'Fehlgeschlagene oder unklare Versuche in 24 h.',
  no_prior_attempts: 'Keine früheren Versuche in 24 h.',
  prior_attempts_unknown: 'Unbekannt, ob es frühere Versuche gab.',
  no_config_change_24h: 'Keine Konfigurationsänderung in 24 h.',
  config_change_24h: 'Konfigurationsänderung im selben Bereich in 24 h.',
  config_change_unknown: 'Unbekannt, ob sich die Konfiguration geändert hat.',
  severity_info: 'Nur ein Hinweis (info).',
  severity_warning: 'Warnung.',
  severity_critical: 'Kritisch.',
  severity_unknown: 'Schweregrad unbekannt (zählt wie ein Hinweis).',
  within_range: 'Summe liegt zwischen 0 und 100.',
  clamped_to_range: 'Summe auf 0 bis 100 begrenzt.',
  gate_input_invalid: 'Sperre, Pause oder Modulschalter sind unklar: nichts erlaubt.',
  module_disabled: 'Self-Healing ist ausgeschaltet.',
  risk_below_catalog: 'Risiko unter dem Katalogwert: abgelehnt.',
  risk_high_never_authorised: 'Risiko 3 wird nie freigegeben.',
  decision_blocked: 'Die Entscheidung erlaubt keine Aktion.',
  router_held: 'Der Router ist gesperrt (nur beobachten).',
  fleet_paused: 'Self-Healing ist für die Flotte pausiert.',
  observe_mode: 'Modus Beobachten: nur Empfehlung.',
  risk_above_auto_limit: 'Risiko über 1: nie automatisch.',
  not_allowlisted: 'Nicht auf der Allowlist dieses Routers.',
  in_maintenance: 'Wartung aktiv oder unklar: keine automatische Aktion.',
  guards_not_green: 'Nicht alle Prüfungen bestanden.',
  not_in_release: 'In dieser Version wird nichts ausgeführt.',
  allowlist_invalid: 'Die Allowlist hat keine gültige Form.',
  too_many_entries: 'Zu viele Einträge in der Allowlist.',
  entry_invalid: 'Ein Eintrag der Allowlist ist ungültig.',
  duplicate_entry: 'Doppelter Eintrag in der Allowlist.',
  max_risk_below_action_risk: 'Das erlaubte Risiko liegt unter dem Risiko der Aktion.',
  cooling_down: 'Abklingzeit läuft.',
  max_attempts: 'Versuche in 24 h aufgebraucht.',
  min_interval: 'Mindestabstand zwischen zwei Läufen noch nicht erreicht.',
  interval_unknown: 'Unbekannt, wann die Aktion zuletzt lief: keine schreibende Aktion.',
  // ── blockers of a plan (heal_engine BLOCK_*) not in the policy table ──
  no_write_path: 'Diese Version hat keinen Schreibweg: nichts wird ausgeführt.',
  mode_observe: 'Geltender Modus ist Beobachten: nur Empfehlung.',
  router_not_loaded: 'Der Router ist in Self-Healing nicht geladen.',
  insufficient_evidence_sources: 'Zu wenig unabhängige Belege für eine schreibende Aktion.',
  nothing_executable: 'Es gibt keine ausführbare Aktion.',
  not_in_planning: 'Der Datensatz ist nicht mehr in der Planung.',
  // ── history reasons (heal_engine, heal_store, heal_model) ──
  incident_opened: 'Network Intelligence hat den Vorfall gemeldet.',
  incident_reopened: 'Network Intelligence hat den Vorfall wieder geöffnet.',
  incident_deferred: 'Der Vorfall hat gewartet, bis der Router frei war.',
  incident_reconciled: 'Beim Abgleich nachgeholt (offener Vorfall ohne Datensatz).',
  cause_from_incident: 'Ursache so übernommen, wie Network Intelligence sie meldet.',
  no_cause_reported: 'Network Intelligence meldet keine Ursache.',
  decision_recommended: 'Vorschlag: Empfohlen.',
  decision_requires_approval: 'Vorschlag: nur mit Freigabe.',
  decision_not_safe: 'Vorschlag: nicht sicher.',
  decision_insufficient_evidence: 'Vorschlag: zu wenig Belege.',
  decision_unsupported: 'Vorschlag: nicht unterstützt.',
  incident_cleared: 'Network Intelligence meldet den Vorfall als behoben.',
  incident_ignored: 'Der Vorfall wurde in Network Intelligence ignoriert.',
  incident_gone: 'Network Intelligence kennt den Vorfall nicht mehr.',
  incident_now_child: 'Der Vorfall ist inzwischen ein Folgevorfall.',
  no_decision_policy: 'Keine Entscheidungsrichtlinie: vorsichtige Vorgabe.',
  released_by_admin: 'Sperre von einem Administrator aufgehoben.',
  interrupted_by_restart: 'Durch einen Neustart von Home Assistant unterbrochen; Zustand muss geprüft werden.',
  rollback_lost_on_restart: 'Ein ausstehender Rollback ging bei einem Neustart verloren.',
  approval_lost_on_restart: 'Die Freigabe ging bei einem Neustart verloren.',
  preflight_lost_on_restart: 'Die Vorabprüfung ging bei einem Neustart verloren.',
  failed_before_restart: 'Vor dem Neustart fehlgeschlagen: eskaliert.',
  // ── hold reasons (heal_model.HoldReason) ──
  outcome_unknown: 'Ausgang einer Aktion unbekannt.',
  outcome_escalated: 'Eine Aktion wurde eskaliert.',
  record_unreadable: 'Ein gespeicherter Datensatz war nicht lesbar.',
  store_lost: 'Der Speicher von Self-Healing ging verloren.',
  stuck_released: 'Eine hängende Sperre wurde aufgehoben.',
  lock_forced: 'Eine Sperre wurde erzwungen gelöst.',
  interface: 'Sperre einer Schnittstelle.',
  service: 'Sperre eines Dienstes.',
  // ── fleet pause reasons (heal_store, heal_policy) ──
  store_damaged: 'Der Speicher von Self-Healing war beschädigt.',
  fleet_failures: 'Zu viele Fehlschläge in der Flotte.',
  // ── recovery statements of the catalog (heal_catalog) ──
  read_only_nothing_changes: 'Nur lesend: am Router ändert sich nichts.',
  applies_saved_config_no_undo_manual_if_not_back: 'Lädt die gespeicherte Konfiguration; nicht rückgängig zu machen, kommt der Dienst nicht zurück, hilft nur Handarbeit.',
  up_undoes_down_only_while_path_holds: 'Ein zweiter Aufruf macht es rückgängig, aber nur solange der Zugang zum Router hält.',
  no_rollback_no_out_of_band_path: 'Kein Rollback: es gibt keinen zweiten Zugangsweg zum Router.',
  no_rollback_restore_is_manual: 'Kein Rollback: Wiederherstellen ist Handarbeit.',
  read_only: 'Nur lesend.',
  second_call: 'Ein zweiter Aufruf macht es rückgängig (solange der Zugang hält).',
  manual_recovery: 'Kein Rollback: Wiederherstellung von Hand.',
  // ── risk without an assessment (heal_engine ObserveOnlyDecider) ──
  not_assessed: 'Nicht bewertet: das Risiko gilt als das höchste.',
};

/** The 17 states of a record (heal_model.ActionState). */
export const STATE_TEXT: Readonly<Record<string, string>> = {
  detected: 'Erkannt',
  analyzed: 'Analysiert',
  proposed: 'Vorgeschlagen',
  preflight: 'Vorabprüfung',
  waiting_approval: 'Wartet auf Freigabe',
  approved: 'Freigegeben',
  executing: 'Wird ausgeführt',
  verifying: 'Wird nachgeprüft',
  resolved: 'Behoben',
  rejected: 'Abgelehnt',
  cancelled: 'Abgeschlossen ohne Aktion',
  failed: 'Fehlgeschlagen',
  rollback_pending: 'Rollback ausstehend',
  rolling_back: 'Rollback läuft',
  rolled_back: 'Zurückgerollt',
  escalated: 'Eskaliert',
  manual_recovery_required: 'Wiederherstellung von Hand nötig',
};

export const MODE_TEXT: Readonly<Record<string, string>> = {
  observe: 'Beobachten',
  approval: 'Freigabe',
  auto_heal: 'Auto-Heal',
};

/** Decision outcomes (heal_model.DecisionOutcome, the five of the policy). */
export const OUTCOME_TEXT: Readonly<Record<string, string>> = {
  recommended: 'Empfohlen',
  requires_approval: 'Nur mit Freigabe',
  not_safe: 'Nicht sicher',
  insufficient_evidence: 'Zu wenig Belege',
  unsupported: 'Nicht unterstützt',
};

export const ACTOR_TEXT: Readonly<Record<string, string>> = {
  engine: 'Engine',
  admin: 'Administrator',
  recovery: 'Wiederherstellung nach Neustart',
};

/** What the gate would allow (heal_policy.Permission). */
export const PERMISSION_TEXT: Readonly<Record<string, string>> = {
  none: 'Nichts erlaubt',
  recommend: 'Nur als Empfehlung',
  run_read_only: 'Nur lesender Schritt',
  needs_approval: 'Nur nach ausdrücklicher Freigabe',
  auto_run: 'Automatisch (Auto-Heal)',
};

/** The closed catalog (heal_catalog). */
export const ACTION_TEXT: Readonly<Record<string, string>> = {
  'observe.evaluate': 'Bewerten (nur lesend)',
  'diag.refresh': 'Diagnose erneut erfassen',
  'diag.ha_probes': 'Prüfungen von Home Assistant aus',
  'service.restart': 'Dienst neu starten',
  'wifi.radio_restart': 'Funkmodul neu starten',
  'router.reboot': 'Router neu starten',
  'config.restore': 'Konfiguration wiederherstellen',
  'interface.cycle': 'Schnittstelle ab- und anschalten',
};

export const PLAYBOOK_TEXT: Readonly<Record<string, string>> = {
  dns_recovery: 'A – DNS',
  dhcp_recovery: 'B – DHCP',
  radio_recovery: 'C – WLAN-Funkmodul',
  interface_recovery: 'D – Schnittstelle',
  wan_recovery: 'E – WAN',
  drift_recovery: 'F – Konfigurationsabweichung',
  client_recovery: 'G – Client-Verbindung',
};

export const COMPONENT_TEXT: Readonly<Record<string, string>> = {
  router: 'Router',
  service: 'Dienst',
  radio: 'Funkmodul',
  interface: 'Schnittstelle',
  config: 'Konfiguration',
  client: 'Client',
};

export const CHECK_TEXT: Readonly<Record<string, string>> = {
  pass: 'bestanden',
  fail: 'nicht bestanden',
  unknown: 'unbekannt',
};

export const CAUSE_STATUS_TEXT: Readonly<Record<string, string>> = {
  confirmed: 'gemessen bestätigt',
  hypothesis: 'Vermutung',
};

export const CAUSE_LEVEL_TEXT: Readonly<Record<string, string>> = {
  confirmed: 'bestätigt',
  likely: 'wahrscheinlich',
  possible: 'möglich',
  unknown: 'unbekannt',
};

export const APPROVAL_TEXT: Readonly<Record<string, string>> = {
  not_required: 'nicht nötig',
  not_requested: 'nicht angefordert',
  pending: 'angefordert, offen',
  approved: 'freigegeben',
  rejected: 'abgelehnt',
  expired: 'abgelaufen',
  invalidated: 'ungültig geworden',
};

export const VERIFICATION_TEXT: Readonly<Record<string, string>> = {
  resolved: 'behoben',
  partial: 'teilweise behoben',
  not_resolved: 'nicht behoben',
  unknown: 'Zustand unbekannt',
  new_fault: 'neue Störung verursacht',
};

export const ROLLBACK_STATUS_TEXT: Readonly<Record<string, string>> = {
  not_available: 'nicht verfügbar',
  pending: 'ausstehend',
  running: 'läuft',
  done: 'erledigt',
  failed: 'fehlgeschlagen',
  unknown: 'unbekannt (unterbrochen)',
};

export const ROLLBACK_MECHANISM_TEXT: Readonly<Record<string, string>> = {
  none: 'keiner',
};

/** Names of the facts a decision knew or did not know (heal_policy RiskContext, IncidentFacts). */
export const FACT_TEXT: Readonly<Record<string, string>> = {
  role: 'Rolle des Routers',
  identity_confirmed: 'Identität bestätigt',
  reachable: 'Router erreichbar',
  dependants: 'abhängige Router',
  target_on_mgmt_path: 'Ziel auf dem Management-Weg',
  target_is_wireless_uplink: 'Ziel ist drahtloser Uplink',
  target_carries_dependants: 'hinter dem Ziel hängen Router',
  service_enabled: 'Dienst eingeschaltet',
  service_dependant_routers: 'Router, die den Dienst nutzen',
  service_dependant_clients: 'Clients, die den Dienst nutzen',
  service_config_unapplied: 'gespeicherte Dienst-Konfiguration nicht angewendet',
  clients_on_router: 'Clients am Router',
  clients_on_target: 'Clients am Ziel',
  open_security_findings: 'offene Sicherheitserkennungen',
  in_maintenance: 'Wartung',
  concurrent_repair: 'laufende Reparatur',
  breaker_open: 'Schutzschalter offen',
  diag_enabled: 'Netzwerkdiagnose an',
  incident_type: 'Vorfallart',
  severity: 'Schweregrad',
  cause_level: 'Ursachenstufe',
  cause_status: 'Ursachenstatus',
  confidence: 'Konfidenz',
  source_families: 'Quellenfamilien',
  is_root: 'Wurzelvorfall',
  temporal_only: 'nur zeitlicher Zusammenhang',
  evidence_fresh: 'Belege aktuell',
  target_fact: 'Befund am Ziel',
  cause_outside_router: 'Ursache außerhalb des Routers',
  prior_failed_attempts: 'frühere Fehlversuche (24 h)',
  config_change_24h: 'Konfigurationsänderung (24 h)',
};

/** Source families of a cause (net_rules.cause_families). */
export const FAMILY_TEXT: Readonly<Record<string, string>> = {
  log: 'Systemprotokoll',
  poll: 'Abfrage des Routers',
  usteer: 'usteer',
  topology: 'Topologie',
  fleet: 'Flotte',
  correlation: 'Zusammenhang mehrerer Ereignisse',
  peers: 'andere Router',
};

/** Keys of an impact (heal_policy explanation, heal_model expected_impact). */
export const IMPACT_TEXT: Readonly<Record<string, string>> = {
  clients_on_router: 'Clients am Router',
  clients_on_target: 'Clients am Ziel',
  clients_on_component: 'Clients am Bauteil',
  dependants: 'abhängige Router',
  est_outage_s: 'geschätzte Unterbrechung',
  service_dependant_clients: 'Clients, die den Dienst nutzen',
  service_dependant_routers: 'Router, die den Dienst nutzen',
  disruption: 'Unterbrechung',
};

export const DISRUPTION_TEXT: Readonly<Record<string, string>> = {
  none: 'keine',
  service: 'ein Dienst',
  radio: 'ein Funkmodul',
  interface: 'eine Schnittstelle',
  router: 'der ganze Router',
};

/** Incident types, in the words of the Diagnose tab (utils/intel.ts TYPE_LABEL; compared in shLogic.test.mjs). */
export const INCIDENT_TEXT: Readonly<Record<string, string>> = {
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
  // not in the Diagnose tab's table (network diagnostics change types)
  wan_gateway_changed: 'WAN-Gateway geändert',
  dns_server_changed: 'DNS-Server geändert',
};

/** Cause codes of Network Intelligence (utils/intel.ts CAUSE_LABEL; compared in shLogic.test.mjs). */
export const CAUSE_TEXT: Readonly<Record<string, string>> = {
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
