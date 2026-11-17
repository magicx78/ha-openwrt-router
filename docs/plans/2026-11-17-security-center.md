# Plan: Security Center (Enterprise Security Intelligence, Phase 2) – Phase A

<!-- Ablage: docs/plans/2026-11-17-security-center.md · Branch claude/security-center-6fdcdd
     (Basis main @ 0dc20cd, Version 1.42.0). Keine IPs, MACs, Hostnamen echter Geräte,
     Passwörter oder Tokens. Rollen statt Namen. Beispielwerte nur aus RFC-5737/RFC-3849-
     Bereichen und lokal verwalteten Platzhalter-MACs. -->

Kennzeichnung wie in den NI- und CS-Plänen:

- **verifiziert**: selbst gelesen, mit `datei:zeile` (Stand `0dc20cd`) oder mit Quell-URL;
- **Annahme**: mit Prüfweg;
- **Schätzung**: Kostenangabe ohne Messung;
- **nicht belegt**: wörtlich so, wenn weder Repo, Fixtures noch offizielle Quellen es zeigen;
- **Vorschlag**: Planentscheidung, Freigabe durch den Master;
- **DECIDED** / **QUESTION**: Abschnitt 9.

Begriffe, damit nichts verwechselt wird:

- **Gruppe a/b/c** (klein): Herkunft einer Datenquelle (Abschnitt 2.1).
- **Empfangsweg A/B** (groß): wie ausgelagerte Logs ankommen. A ist der Syslog-Empfänger in HA, B der separate Collector (Abschnitt 4).

## Status

- **Stand:** 2026-11-17 · **Phase:** A (Bestandsanalyse und Fähigkeitsmatrix). Es ist **nichts gebaut**.
- **Branch:** `claude/security-center-6fdcdd` · Basis `main@0dc20cd` (1.42.0).
- **Regeln dieser Phase:**
  - kein Kontakt zu Routern, HA, Host, VM oder Drucker;
  - keine Router-Aufrufe;
  - nur Repo, Fixtures und öffentliche Quellen gelesen.
- **Leitplanken des Nutzers:**
  - Das Security Center **beobachtet nur**.
  - Keine Erkennung ohne Datenquelle.
  - Minimale Routerlast. Ziel ist der Cudy WR3000 (MT7981, 256 MB RAM, wenig Flash); ein Gerät ist ein FRITZ!Repeater 3000 mit OpenWrt.
  - **Keine zweite Client-Datenbank**, **keine zweite Incident-Engine**.
- **Entscheidung des Nutzers (Korrektur 2):**
  - Beide Empfangswege werden gebaut und sind in den Einstellungen wählbar.
  - Standard ist **„aus“**.
  - Es ist immer genau ein Weg aktiv.

---

## 1. Bestandsanalyse

### 1.1 API-Aufrufe je Poll

**Verifiziert** in `coordinator.py:682-1211` (`_async_poll`). Die Reihenfolge ist die des Codes.

Takt: `SCAN_INTERVAL_SECONDS = 60` (`const.py:61`). Bei CPU-Last gelten 120 s (`const.py:63`), im SSH-Fallback 300 s (`SSH_FALLBACK_INTERVAL_SECONDS`, `const.py:66`).

| # | Aufruf (api.py) | ubus / Quelle | Rhythmus |
|---|---|---|---|
| 1 | `get_router_info` (`api.py:1681`) | `system board` u. a. | Poll 1, dann alle 10 Polls (`BOARD_REFRESH_CYCLES = 10`, `const.py:71`) |
| 2 | `get_wan_status` (`:1948`) | `network.interface.wan status` | jeder Poll |
| 3 | `get_wifi_status` (`:2168`) | `network.wireless status` / iwinfo / UCI | jeder Poll |
| 4 | `get_dhcp_leases` (`:3825`) | `luci-rpc getDHCPLeases` | jeder Poll |
| 5 | `get_connected_clients` (`:2553`) | `hostapd.<if> get_clients` (je AP-Interface) | jeder Poll |
| 6 | `get_ap_interface_details` (`:2270`) | iwinfo/hostapd | jeder Poll |
| 7 | `get_sta_interface_details` (`:2440`) | iwinfo | jeder Poll |
| 8 | TCP-Ping 8.8.8.8:53 **von HA aus** | kein Router-Aufruf | ab Poll 2 |
| 9 | `get_ddns_status` (`:5731`) | `uci get ddns`, file read `/var/run/ddns` | wenn WAN verbunden |
| 10 | `get_router_status` (`:1732`) | `system info` (Uptime, Speicher, Last, Lokalzeit) | jeder Poll |
| 11 | `get_disk_space` (`:4104`) | – | jeder Poll |
| 12 | `get_tmpfs_stats` (`:4134`) | – | jeder Poll |
| 13 | `get_device_status` (`:4211`) | `network.device status {}` | jeder Poll |
| 14 | `get_network_interfaces` (`:4230`) | `network.interface dump` | jeder Poll |
| 15 | `get_port_stats` (`:4307`) | Fehlerzähler je Port | jeder Poll |
| 16 | `get_port_vlan_map` (`:4392`) | `uci get network` (bridge-vlan, switch_vlan) | jeder Poll |
| 17 | `get_bridge_fdb` (`:4651`) | file read `/sys/class/net/br-lan/brforward` (base64) | jeder Poll |
| 18 | `get_arp_table` (`:4745`) | file read `/proc/net/arp`, bei Abschneiden `luci-rpc getHostHints` | jeder Poll |
| 19 | `get_trunk_port_map` (`:4814`) | – | jeder Poll |
| 20 | `get_lldp_neighbors` (`:4474`) | ubus-Probe `lldpd`, sonst SSH `lldpcli`, gecacht | gecacht (laut `tests/test_poll_no_ssh.py:14-15` alle 600 s, nur mit lldpd) |
| 21 | `_ingest_log` → `get_log_entries` (`coordinator.py:1407`, `api.py:1912`) | `log read {"lines":N,"stream":false}` | jeder Poll ab Poll 2 (`LOG_READ_INTERVAL_CYCLES = 1`), N = 250 (100–700 adaptiv, ca. 165 B/Zeile; `const.py:514-522`) |
| 22 | `_fetch_dhcp_config` → `get_dhcp_config` (`api.py:3944`) | `uci get dhcp` | Poll 2, dann alle 10 Polls (`DHCP_CONFIG_REFRESH_CYCLES`, `const.py:537`) |
| 23 | `_fetch_usteer` → `get_usteer_clients` (`api.py:1936`) | `usteer get_clients` (ca. 40 KB) | alle 2 Polls ab Poll 3 (`const.py:549`) |
| 24 | `get_active_connections` (`api.py:4843`) | file read `/proc/sys/net/netfilter/nf_conntrack_count` | jeder Poll |
| 25 | `get_services(DEFAULT_SERVICES)` (`api.py:4987`) | `service list`; Dienste `dnsmasq, dropbear, firewall, network, uhttpd, wpad` (`const.py:561`) | jeder Poll |

Weitere Aufrufe:

- Paket-Updates (`check_package_updates`, `api.py:4894`, SSH apk/opkg) laufen **nur auf Knopfdruck**.
- Fallback in `get_active_connections`: Wenn `nf_conntrack_count` nicht lesbar ist, liest die Methode die ganze `/proc/net/nf_conntrack` und zählt die Zeilen.
- Laut Kommentar `api.py:1889-1891` liest rpcd `file read` von proc-Dateien mit Größe 0 nur 4 KiB. **Folge:** Die volle Conntrack-Tabelle ist über ubus nicht lesbar.
- `api.py:4651` (Kommentar `get_bridge_fdb`): file/exec wird bewusst nicht benutzt, weil rpcd bei großer Ausgabe je exec-Aufruf Speicher verliert. Das betrifft jede Idee, `nft` oder `conntrack` per ubus-exec zu lesen.

### 1.2 `coordinator.data`

**Verifiziert**: `OpenWrtCoordinatorData` (`coordinator.py:298-430`). `as_dict` ab `:432` lässt `client_stability.clients` weg.

| Bereich | Schlüssel |
|---|---|
| System | `router_info`, `uptime`, `cpu_load`, `cpu_load_5`, `cpu_load_15`, `cpu_cores`, `load_average`, `memory`, `memory_pressure`, `disk_space`, `tmpfs`, `localtime`, `localtime_at`, `cpu_history` |
| WAN | `wan_status`, `wan_connected`, `wan_status_at`, `wan_traffic`, `ping_ms`, `ping_checked`, `ddns_status` |
| WLAN | `wifi_radios`, `clients`, `client_count`, `ap_interfaces`, `sta_interfaces`, `dfs`, `usteer_connected` |
| DHCP / Identität | `dhcp_leases`, `dhcp_pools`, `dhcp_static_macs`, `arp_table` |
| LAN / Topologie | `network_interfaces`, `port_stats`, `port_vlan_map`, `port_fdb_map`, `trunk_port_map`, `lldp_neighbors`, `lldp_status`, `topology_snapshots`, `vlans_stale` |
| Dienste | `services`, `service_instances`, `service_actions`, `wifi_actions`, `updates_available`, `features` |
| Conntrack | `active_connections` (nur Anzahl) |
| Log | `log_status`, `log_stats`, `new_log_events` (geparste `LogEvent`s), `new_log_batch` (Cursor-Fakten) – `coordinator.py:411-412`, gesetzt in `_process_log` `:1439-1452` |
| Sonstiges | `events`, `client_stability`, `error_type`, `consecutive_failures`, `last_seen` |

Wichtig für das Security Center: Die **Rohzeilen** des Logs werden **nicht** aufbewahrt.

- `_process_log` (`coordinator.py:1439-1452`) übergibt nur geparste Ereignisse und Cursor-Fakten.
- `parse_entry` verwirft unbekannte Prozesse, darunter `dropbear` (`tests/test_log_parser.py:105`, `tests/test_net_infra.py:255`).

### 1.3 RuntimeData

**Verifiziert**:

- `OpenWrtRuntimeData` (`__init__.py:78-90`) hat die Felder `api: OpenWrtAPI` und `coordinator: OpenWrtCoordinator`.
- Typ-Alias `type OpenWrtConfigEntry = ConfigEntry[OpenWrtRuntimeData]` (`__init__.py:94`).
- NI- und CS-Engine liegen **nicht** in `runtime_data`. Es sind Singletons je HA-Instanz: `async_get_engine` (`net_engine.py:322`) und `async_get_client_engine` (`client_engine.py:453`).
- Setup: `__init__.py:395-420`. Der Listener `engine.async_ingest_coordinator` ist der einzige Engine-Eingang.
- Unload: `__init__.py:483-553`, in dieser Reihenfolge:
  1. Flotte abgeben;
  2. Plattformen entladen;
  3. Panel abbauen;
  4. NI entladen;
  5. CS entladen.

### 1.4 NI: Ereignisarten mit Feldern

**Verifiziert**: `net_events.py:200` (`NetEvent`), `:341` (`Incident`). Enums stehen in `:46-111`.

**`NetEvent`-Felder:** `id` (`f"{entry_id}:{seq}"`, `net_engine.py:1619`), `ts`, `router`, `category`, `kind`, `origin`, `source`, `subject` (z. B. `mac`, `iface`, `ip`, `name`, `pool`), `signal`, `count`, `severity`, `cause`, `cause_status`, `confidence`, `msg_key`, `params`, `maintenance`, `src_ts`, `clock_skew`, `parent_id`.

Enums:

| Enum | Werte |
|---|---|
| `Category` | `wifi, dhcp, system, lan, wan, dns, mesh` |
| `Origin` | `observed, inferred` |
| `Source` | `log, hostapd, poll, procd, netifd, fleet, usteer, lldp, topology` |
| `CauseStatus` | `confirmed, hypothesis` |
| `IncidentStatus` | `active, resolved, acknowledged, ignored` |
| `Scope` | `client, radio, port, router, segment, fleet` |

**Ereignisarten (`category.kind`)**, gesammelt aus `net_rules.py`. Dazu kommen die Log-Arten unten.

| Kategorie | Arten |
|---|---|
| `wifi.` | `assoc_rejected, auth_wave, backhaul_auth_failed, band_change, dhcp_after_connect, handshake_failed, mass_disconnect, no_ip, psk_mismatch, reconnect, roam, sae_failed, weak_clients` |
| `system.` | `clock_skew, conntrack, cpu_load, lan_reachable, lan_unreachable, log_gap` (`net_engine.py:198`), `memory_pressure, oom_kill, reboot, router_reachable, router_unreachable, service_crash_loop, service_restart, service_stopped` |
| `lan.` | `lldp_change, port_down, port_errors, port_flap, port_load, port_speed, port_up, uplink` |
| `wan.` | `down, failover, ip_changed, reconnect, status, up` |
| `dhcp.` | `decline, pool_usage` |
| `dns.` | `no_servers, query_limit, send_failed` |
| `dfs.` | `cac_failed, new_channel, radar_detected` |

**Log-Arten** (`log_parser.py`, `LogEvent`, Schlüssel `category.kind`):

- **`LogEvent`-Felder:** `category, kind, log_id, time_ms, mac, interface, ip, message (≤ 200 Zeichen), frequency, channel, process, name, reason, reason_category, reason_code`.
- **wifi:** `connected, disconnected, psk_mismatch, inactivity_timeout, handshake_failed, deauth, disassoc, handshake_completed, usteer_connected, usteer_disconnected, ap_disabled, assoc_rejected, sae_failed, backhaul_auth_failed`.
- **dhcp:** `ack, nak, decline, no_address, odhcpd_error`.
- **link:** `up, down`. **iface:** `up, down, link_lost`. **system:** `service_crash_loop, oom_kill`. **dns:** `query_limit, no_servers, send_failed`.
- **dfs:** `radar_detected, cac_start, cac_completed, cac_failed, nop_finished, new_channel, pre_cac_expired, channel_change`.
- **Gründe (`reason`):** `inactivity, local_request, prune, other, timeout, invalid_mic, failed, psk, max_sta, blocked, missing_acks`.
- **Ausgewertete Prozesse:** hostapd, dnsmasq*, netifd, procd, odhcpd, usteer, wpa_supplicant, kernel (Quelle 0, nur Link und OOM). **Nicht ausgewertet:** dropbear, uhttpd, rpcd, Firewall-Kernelzeilen.
- **Nur gezählt:** `COUNT_ONLY_KINDS` (`log_parser.py:114-136`), `ENGINE_ONLY_KINDS` (`:140-146`).
- Laut Docstring wurden die Formate von kernel, netifd, procd, odhcpd und dem dnsmasq-Resolver nicht live gesehen. Außerdem gilt: *„hostapd at the default log level writes no reason= codes“*.

**Bus-Event** `openwrt_router_incident_event` (`docs/network-intelligence.md`, `net_engine.py:1885-1890`) mit den Feldern `state, incident_id, type, severity, confidence, cause, cause_status, scope, routers, entry_ids, device_id, mac, reason, cause_level`.

### 1.5 Incident Engine

**Verifiziert**: `net_rules.py`, `net_engine.py`, `net_events.py`.

**Entstehung:**

1. Ablauf eines Polls in `NetIntelligence.ingest` (`net_engine.py:756-877`):
   1. Log-Ingest;
   2. Evidenz;
   3. Infrastruktur-Findings (z. B. `detect_reboot` `net_rules.py:2024`, `detect_conntrack` `:2209`, `detect_dhcp` `:2988`);
   4. WLAN-Findings;
   5. `_run_machine` (`:968`);
   6. Pruning und Speichern;
   7. Beobachter benachrichtigen (`_notify`, Fehler isoliert).
2. Findings werden über `finding_evidence` (`net_rules.py:3035`) zu `Evidence` (Felder `net_rules.py:419-474`: `type, scope_key, scope, kind, event_id, value, count, router, affected, severity, confidence, origin, cause, cause_status, maintenance, hold, since`).
3. `_run_machine` filtert über `_filter_evidence` (Ausschlüsse, Wartung; `net_engine.py:1465`) und ruft `AlarmMachine.update(now, evidence)` (`net_rules.py:989`). Danach folgen `correlate` und `_refresh`.

**Schlüssel und Dedup:**

- Ein Incident ist eindeutig über `(type, scope_key)` (`AlarmMachine`, ab `net_rules.py:678`).
- Fenster-Einträge werden je `event_id` dedupliziert.
- Regeln liest `_rule(type_)` (`:1204`) nur aus `settings["thresholds"]`, im Modus `window`, `level` oder `event`. **Typen ohne Regel werden ignoriert.**

**Bestehende Incident-Typen** (`DEFAULT_SETTINGS["thresholds"]`, `net_rules.py:141-228`):

- **WLAN:** `wifi_reconnect_storm, wifi_auth_failures, wifi_auth_wave, wifi_mass_disconnect, wifi_no_ip, wifi_dhcp_after_connect, wifi_band_flapping, wifi_roam_flapping, wifi_weak_clients, wifi_channel_busy` (inaktiv), `wifi_radio_change`.
- **System:** `system_cpu_high, system_ram_high, system_reboot, router_unreachable, lan_unreachable, system_service_restart, system_clock_skew, system_conntrack_jump`.
- **LAN:** `lan_port_flap, lan_port_speed_drop, lan_port_errors, lan_port_load, lan_uplink_down, lan_lldp_change`.
- **WAN:** `wan_down, wan_unstable, wan_ip_changed`.
- **DHCP:** `dhcp_pool_full, dhcp_conflict`.

**Persistenz:**

- Store `openwrt_router.intelligence` (`INTEL_STORE_KEY`, `const.py:586-618`), Speicherverzögerung 300 s, Kappe 1,5 MB, `.bak` bei Schaden.
- Grenzen: `MAX_INCIDENTS = 500`, `MAX_EVENTS = 3000`, `RETENTION_DAYS = 30`, `STORE_EVIDENCE = 5` (`net_events.py:27-34`).
- `prune_incidents` (`:523`) verwirft nie aktive oder quittierte Incidents.
- `merge_settings` (`net_rules.py:250`) verwirft unbekannte Schlüssel.

**Wie eine neue Regel andockt**, ohne bestehende Incidents zu ändern oder zu unterdrücken (Analyse, **Vorschlag** in 6.3):

1. **Schwellwert-Eintrag nötig.** Ohne Eintrag in `DEFAULT_SETTINGS["thresholds"]` ignoriert `_rule` den Typ, und `merge_settings` verwirft gespeicherte Overlays. Ein neuer Typ braucht also einen Eintrag, oder eine Registrierfunktion, die ihn vor dem Laden der Settings ergänzt.
2. **Evidenz-Zufuhr nötig.** Ein Beobachter (`add_poll_observer`, `net_engine.py:881`; Protokoll `PollObserver` `:308`) läuft **nach** `_run_machine`. Ein Beobachter allein kann also keine Evidenz in denselben Maschinenschritt geben. Nötig ist ein kleiner Hook vor `_run_machine` (z. B. `add_evidence_source`).
3. **Dedup trennt die Typen.** Neue Typen haben eigene Schlüssel `(type, scope_key)` und verändern bestehende Incidents nicht.
4. **Keine Wurzeln.** `ROOT_TIERS` (`net_rules.py:4727`) nennt nur `lan_unreachable, router_unreachable, system_reboot, wan_down, wifi_radio_change, lan_uplink_down, lan_port_flap, wifi_mass_disconnect`. Ein `sec_*`-Typ wird nie Wurzel und kann daher nichts Bestehendes unterdrücken.
5. **Nebenwirkungen, die einen Hook brauchen:**
   - `_incident_link` (`:5164`): Unter `lan_unreachable` wird jedes Kind verlinkt. `_router_link` (`:5258`) verlinkt alles, was den Router betrifft. `sec_*`-Incidents würden während Ausfällen oder Neustarts zu stillen Kindern. Das ist für Sicherheitshinweise falsch, etwa bei Anmeldefehlern direkt nach einem Neustart.
   - `incident_area` (`:5453`) gibt für das Präfix `sec_` `None` zurück. **Gut:** kein Einfluss auf den Health-Score.
   - `counted_incidents` (`:5660`) und `counts_for_router` (`:5675`) zählen **alle** aktiven Typen. Neue Typen würden also `incidents_active` und `incident_critical` sowie die Flottenwerte verändern. **Das ist eine Änderung an Bestehendem** und muss ausgeschlossen werden.
   - `_announce` (`net_engine.py:1817`) feuert für jeden Typ ab `notify_min_severity`. Bestehende Automationen auf `openwrt_router_incident_event` würden neue Sicherheitsereignisse bekommen.
   - Speicher: Die 500er-Kappe und die 1,5 MB werden geteilt. Gelöste `sec_*`-Incidents könnten ältere gelöste NI-Incidents früher verdrängen.

### 1.6 Client Stability (CS)

**Verifiziert**: `client_history.py`, `client_engine.py`, `const.py:624-638`.

**Datenmodell:**

- **`ClientObs`** (`client_history.py:473`): `mac, band, rssi, rate_rx_kbit, rate_tx_kbit, ip_visible, hostname, ip`.
- **`ClientEvent`** (`:487`): `mac, kind, ts, router, reason, peer, count, infra, incident_id`. Arten `connect, disconnect, reconnect, roam, band_change, auth_fail, assoc_fail, dhcp_fail` (`:81-89`).
- **`PollInput`** (`:509`): `router, now, interval, fresh, clients, events, down_routers, infra, loc`.
- **`ClientLive`** (`:565`): `mac, private_mac, state, since, ap, band, rssi, session_start, session_start_known, first_seen, last_seen, last_disconnect, hostname, hostname_changed, ip, ip_changed`.
  - Zustände: `online, grace, offline, unknown`.
  - Disconnect-Klassen: `error, inactivity, leave, unknown, infra`.
  - Übergänge: `start, end, move, gap, resume, blip`.
- **`Bucket`** (`:311`, je Stunde und Tag): `observed_s, online_s, gap_s, sessions, associations, longest_stable_s, dc_error, dc_inactivity, dc_leave, dc_unknown, dc_infra, reconnects, roams_in, roams_out, roam_flaps, band_changes, auth_fail, assoc_fail, dhcp_fail, rssi_n, rssi_sum, rssi_min, rssi_max, weak_s, ip_visible_n, rate_rx_sum, rate_tx_sum, rate_n, online_2g_s, online_5g_s, online_6g_s, session_s_sum`, dazu 10 Sitzungsdauer-Klassen `sess_lt5m … sess_ge24h`.
- **Intern** (`_Client`, `:697`): Hostname und IP mit Zeit der letzten Änderung (`host/host_t`, `ip/ip_t`). **Für das Security Center nutzbar** bei neuem Gerät, IP-Wechsel und Hostname-Wechsel.
- `is_private_mac` (`:648`) erkennt zufällige MACs.

**Grenzen** (`client_history.py:135-147`): `RAW_RING_S = 3600` / `RAW_RING_MAX = 120`, `TRANSITIONS_KEEP_S = 86400` / `TRANSITIONS_MAX = 64`, `HOURS_KEEP = 168`, `RETENTION_DAYS` 30 (max. 90), `MAX_CLIENTS_DEFAULT = 1000`, `GAP_TRACK_S` 1 Tag, `OFFLINE_TRACK_S` 7 Tage.

**Store:**

- Schlüssel `openwrt_router.client_history` (`CLIENT_STORE_KEY`). Standard 3 MB (1–8 MB einstellbar), `.bak` bei Schaden.
- `_data_to_save` kürzt auf `max_store_mb`.
- Format je Client mit kurzen Schlüsseln, z. B. `m{p,fs,ls,la,hn,ht,ip,it}`, `l{…}`, `aps`, `h`, `ho`, `d`, `dm`, `tr` (`client_history.py:1757-1806`, `to_dict` `:1576`).

**Flush und Unload:**

- `ClientStability` (`client_engine.py:493`) nutzt `schedule_save` und `async_flush`.
- `async_unload_client_stability` (`:472`) flusht nur, wenn sich etwas geändert hat, und erst nach dem letzten Router.
- `on_poll` (`:661`) kehrt sofort zurück, wenn CS aus ist.

**Entities nur für gewählte Clients:**

- Einstellung `entity_macs`, höchstens `CLIENT_ENTITY_MAX = 25` (`const.py:624-638`).
- Die Sensoren hängen am Flotten-Anker (`client_entities.py:8`, `:87`).

**Andockung:** CS ist ein `PollObserver` am NI-Engine und bekommt `PollFacts` (`net_engine.py:268-305`): `router, now, interval, fresh_clients, context, wifi_lines, log_ok, findings, stored_events, auth_attempts, loc, lease_macs, arp_macs, down_routers, auth_failed, exclude, log_coverage`. Es gibt **keinen** zweiten Coordinator-Listener.

### 1.7 Panel-Routen, Auth und Admin

**Verifiziert**: `topology_panel.py`, `client_views.py`.

| Route | Klasse / Zeile | Methoden | Prüfung |
|---|---|---|---|
| `/api/openwrt_topology/snapshot` | `OpenWrtMeshSnapshotView` `topology_panel.py:141-145` | GET | `requires_auth = True`, Admin oder Panel für alle offen (`_panel_open_to_all` `:118`) |
| `/api/openwrt_topology/intelligence/summary` | `:299` | GET | `_IntelView._check` |
| `…/events` | `:312` | GET | dito |
| `…/incidents` | `:330` | GET | dito |
| `…/incidents/{incident_id}` | `:348` | GET, POST (`:360`, `write=True`) | dito, Schreiben nur Admin |
| `…/settings` | `:387` | GET (`:422`), POST (`:432`, `write=True`) | dito |
| `…/clients`, `…/clients/aps`, `…/clients/{mac}` | `client_views.py:780, 796, 848` | GET | dito |
| `…/clients/settings` | `client_views.py:812` | GET, POST (`:824-826`, `write=True`) | dito |

`_IntelView._check` (`topology_panel.py:202-230`):

- Schreiben ohne Admin gibt 403.
- Lesen ohne Admin, wenn das Panel nicht für alle offen ist, gibt 403.
- Nach dem letzten Unload (`_PANEL_VIEW_DISABLED_KEY`) gibt es 410.
- Laut Docstring gibt es 503, solange die Engine nicht läuft.

### 1.8 Flottensensor-Muster

**Verifiziert**:

- `NetIntelligence.claim_fleet(platform, entry_id, create)` (`net_engine.py:2071-2089`): Der erste Router wird Anker.
- `withdraw_fleet` (`:2097-2113`): Beim Unload wählt es die kleinste verbleibende Entry-ID.
- `async_withdraw_fleet` (`net_entities.py:73-99`) verschiebt die Registry-Einträge. Das gilt auch für CS-Sensoren mit `CLIENT_UID_PREFIX`.
- Unique-IDs: `openwrt_router_fleet_*` (`FLEET_UID_PREFIX`, `const.py:615`), ohne Gerät.
- Pro Router gilt `f"{entry_id}_{suffix}"` (`net_entities.py:8-16`).
- Die Entities lesen nur die Engine-View und aktualisieren über `SIGNAL_NET_INTEL`.

### 1.9 Diagnose-Redaktion

**Verifiziert**: `diagnostics.py:36-139`, `:192-235`; `const.py:252-286`.

- **Erster Durchgang:** `async_redact_data` über exakte Schlüssel `DIAGNOSTICS_TO_REDACT`: `address, bssid, chassis_id, domain, host, hostname, ip, ipv4, ipv4_addr, ipv4_address, mac, management_ip, router, ssid, ssids, username, web_url`.
- **Zweiter Durchgang:** jeder Schlüssel, dessen Name `password, token, ubus_rpc_session, secret, key, auth` enthält.
- **Zusätzlich ersetzt durch Anzahl oder Zusammenfassung:**
  - `dhcp_leases` und `arp_table` werden durch eine Anzahl ersetzt;
  - bei `lldp_neighbors` werden Name, Chassis-ID, Management-IP und eine MAC-Port-ID ersetzt;
  - `clients` wird zu Anzahl und Signal-Aggregaten;
  - die CS-Listen `sticky`, `weak`, `unstable` werden durch eine Anzahl ersetzt;
  - die NI- und CS-Summaries enthalten keine Identitäten.
- **Folge für das Security Center:**
  - Eigene Diagnose nur als Zähler.
  - Ein Collector-Token muss einen Schlüssel mit `token` im Namen tragen.
  - Absender-IPs und Rohzeilen dürfen nie in die Diagnose.

### 1.10 Die genaue rpcd-ACL

**Verifiziert**:

- `acl_provisioning.py`: `ACL_VERSION = 8`, Datei `/usr/share/rpcd/acl.d/ha-openwrt-router.json`, Inhalt `RPCD_ACL_CONTENT` (`:61-145`).
- `ensure_acl` vergleicht den Inhalt und spielt über ubus `file write` (oder SSH) neu ein. Danach startet es rpcd neu. Aufruf in `__init__.py:315`.

**read.file:**

| Pfad | Recht |
|---|---|
| `/etc/openwrt_release`, `/etc/config/ddns` | read |
| `/var/run/ddns` und `/tmp/run/ddns` | list |
| `/var/run/ddns/*` und `/tmp/run/ddns/*` | read |
| `/sys/class/net` | list |
| `/sys/class/net/*`, `/sys/devices/*/net/*` | read |
| `/proc/cpuinfo`, `/proc/net/arp`, `/proc/net/nf_conntrack`, `/proc/*/net/arp`, `/proc/*/net/nf_conntrack`, `/proc/sys/net/netfilter/nf_conntrack_count` | read |
| `/tmp/opkg_list`, die ACL-Datei selbst | read |

**read.ubus:**

| Objekt | Methoden |
|---|---|
| `file` | `read, stat, list, exec` |
| `hostapd.*` | `get_clients, get_status` |
| `network.wireless` | `status, up, down` |
| `network.device` | `status` |
| `network.interface` | `dump` |
| `network.interface.*`, `network.interface.wan` | `status, statistics` |
| `luci-rpc` | `getDHCPLeases, getHostHints, getWirelessDevices` |
| `iwinfo` | `info, assoclist, devices, scan, freqlist` |
| `system` | `board, info` |
| `uci` | `get` |
| `rc` | `list` |
| `service` | `list, get_data` |
| `log` | `read` |
| `usteer` | `get_clients` |

**write:** file `/etc/init.d/rpcd` (exec); ubus `network.wireless` (`up, down`), `network` (`reload`).

**Was die ACL nicht enthält:**

- Kein `uci`-Abschnitt je Config.
  - **Annahme**, gestützt auf den Docstring `api.py:3947-3949`: `uci get dhcp` ist für den root-Login über die LuCI-ACLs erlaubt (`read '*'`). Für `uci get firewall` gilt dasselbe, **nicht belegt**.
- Kein `:subscribe`-Recht. Es fehlen außerdem `dnsmasq`, `nf_conntrack_max`, `/proc/net/snmp` und jedes nft-Objekt.
- `iwinfo scan` ist **schon erlaubt**.

### 1.11 Vorhandene Log-Tests und Fixtures

**Verifiziert:**

| Datei | Inhalt |
|---|---|
| `tests/test_log_parser.py:3-4` | Laut Docstring *„exact format seen on OpenWrt 25.12.1 routers (hostapd, dnsmasq-dhcp, usteer, dropbear)“*. Eintragsform `{"msg","id","priority":30,"source":1,"time"}` (`:46-47`). Zeilen hostapd/dnsmasq-dhcp `:59-75`, ignorierte Zeilen inkl. `dropbear[2565]: Password auth succeeded for 'root' from 192.0.2.5:64008` (`:105`) |
| `tests/test_net_infra.py:250-264` | Unbekannte Zeilen (kein Ergebnis): Kernel `[ 1.0] random: …` (Quelle 0), `crond`, `dropbear[3000]: Child connection from 192.0.2.10:50000`, netifd, procd, odhcpd, `dnsmasq[2345]: using nameserver 192.0.2.1#53`, usteer. Ob diese Zeilen live gesehen wurden, steht dort nicht: **nicht belegt** |
| `tests/test_net_wifi.py:254` | `dropbear[2565]: Pubkey auth succeeded for 'root' with key from 192.0.2.5:64008` |
| `tests/test_poll_no_ssh.py:1-16` | Ein gesunder Poll öffnet keine SSH-Verbindung, weil dropbear-Zeilen das Router-Log füllten. LLDP ist der einzige SSH-Leser (alle 600 s) |
| `tests/test_net_rt_log.py`, `test_net_rt_scenarios.py` | RT-Szenarien (`docs/realtime-rca.md:124-139`); im Detail nicht gelesen |
| `scripts/mock_router.py` | Enthält **kein** `log`, dnsmasq, conntrack oder firewall (Grep ohne Treffer) |

Es gibt **keine** Fixtures für die folgenden Formate:

- logd-Remote-Syslog;
- fw4/nft-Logzeilen;
- dnsmasq-Abfragezeilen (`log-queries`);
- dropbear-Fehlversuche;
- uhttpd/rpcd-Anmeldefehler.

### 1.12 Was fürs Security Center fehlt

1. Ein Hook für Evidenz vor `_run_machine`. Dazu gehören:
   - der Ausschluss der `sec_*`-Typen aus Zählern, Bus-Event und Wurzel-Verlinkung;
   - eine eigene Kappe im geteilten Speicher (1.5).
2. Zugriff auf **Rohzeilen** des vorhandenen `log read` für dropbear (1.2). Heute verwirft der Parser sie.
3. Kein Parser für dropbear, uhttpd/rpcd, Firewall-Kernelzeilen und dnsmasq-Abfragen.
4. Kein Empfang ausgelagerter Logs: weder Listener noch Collector-Client, keine gemeinsame Log-Quelle, kein Dedup über Wege.
5. Kein Abruf für folgende Daten:
   - Firewall-Konfiguration (`uci get firewall`);
   - `nf_conntrack_max`;
   - dnsmasq-Metriken;
   - `/proc/net/snmp`;
   - IPv6-Nachbarn;
   - nft-Zähler.
6. Keine Router-ID, keine Registry, keine Capability-Erkennung und kein Event-/Audit-Schema auf diesem Branch (Abschnitt 6.1).
7. Kein Panel-Tab, keine Routen und keine Entities fürs Security Center.
8. Keine Fixtures für die Formate aus 1.11.

---

## 2. Fähigkeitsmatrix

### 2.1 Gruppen

- **Gruppe a**: Die Daten liegen schon in der Integration (`coordinator.data`, NI, CS). **0 neue Router-Aufrufe.** Es fehlt höchstens ein Parser oder eine Auswertung.
- **Gruppe b**: Ein neuer, sparsamer Abruf über ubus oder file read, oder auf Anforderung über SSH. **Keine** Änderung der Routerkonfiguration, eventuell eine ACL-Erweiterung (QUESTION Q-ACL).
- **Gruppe c**: Braucht eine Änderung der Routerkonfiguration (Logging an, Remote-Syslog, Paket) oder ist auf dem WR3000 zu teuer. Die Daten werden **nur ausgelagert** genutzt und sind **standardmäßig aus**.

Weitere Kürzel:

- **Weg**: Welcher Empfangsweg die Quelle nutzen kann. **A** = Syslog-Empfänger in HA, **B** = Collector, **P** = vorhandener Poll (kein Log-Weg nötig).
- **Stock**: Auf Standard-OpenWrt ohne Zusatzpaket und ohne Konfigänderung vorhanden.
- **(S)**: Schätzung.

### 2.2 Matrix (eine Zeile je Quelle)

| # | Quelle | Schon in den Daten? (wo) | Sonst nötiger Abruf | ACL nötig / heute gedeckt? | Kosten WR3000 | Stock? | Gruppe | Weg | Auslagerung | Beleg |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | nftables/fw4-Regelsatz (laufend) | nein | `nft -j list ruleset` per SSH, nur auf Anforderung | keine rpcd-ACL (SSH); ubus-exec gemieden (rpcd-Leck) | einige 10 KB Ausgabe, kurzer CPU-Stoß (S); SSH erzeugt dropbear-Logzeilen | ja (fw4) | b | P | – | Leck-Kommentar `api.py:4651`; Größe **nicht belegt** |
| 2 | nftables-Zähler | nein | derselbe Abruf wie #1, Zähler je Regel/Zone | wie #1 | wie #1 (S) | ja: `counter` ist für Zonen und Regeln standardmäßig an | b | P | – | fw4 `fw4.uc` (parse_zone/parse_rule `counter: ["bool","1"]`), `zone-verdict.uc`, `rule.uc` |
| 3 | Conntrack-Statistik aggregiert (Anzahl/Max, `conntrack -S`) | Anzahl ja: `active_connections` (`api.py:4843`), NI `system.conntrack` (`net_rules.py:2209`, relativ zum Median, **ohne** Max) | file read `/proc/sys/net/netfilter/nf_conntrack_max` (selten); `conntrack -S` nicht vorgesehen (Paket/exec) | Max: **nicht** in ACL v8 → Erweiterung | < 100 B je Abruf (S) | Max-Datei ja (Kernel); `conntrack`-Tool **nicht belegt** | b | P | – | Docstring `net_rules.py:2219` „nf_conntrack_max is not readable, F3“ |
| 4 | Volle Conntrack-Tabelle | nein | über ubus nicht lesbar (4-KiB-Grenze, `api.py:1889-1891`); per SSH zu teuer | – | hoch: Tabelle mit Tausenden Zeilen (S) | ja (Kernel) | c | B | nur ausgelagert: Flow-Export (NetFlow/IPFIX, Paket) zum Collector; **nicht empfohlen** auf dem WR3000 | Kosten und Paketverfügbarkeit **nicht belegt** |
| 5 | Firewall-Logs (fw4 `option log`) | nein | Router-Konfig: `log` und `log_limit` an Zone oder Regel | keine (kommt als Kernel-Logzeile) | je geloggtes Paket eine Zeile; ohne `log_limit` Flutgefahr für den logd-Ring (S) | **standardmäßig aus** | c | A, B | Kernel → logd → Remote-Syslog (Abschnitte 2.3 und 4.10) | Standard-Config ohne `log`: firewall4 `root/etc/config/firewall`; Präfix: `zone-verdict.uc`, `ruleset.uc`, `rule.uc` |
| 6 | Kernel-Logs | ja: `log read` liefert Kernelzeilen (Quelle 0), Parser nutzt nur Link und OOM (`log_parser.py`) | – | `log read` (v6+) gedeckt | 0 | ja | a | P (auch A/B) | – | `tests/test_net_infra.py:253` |
| 7 | Interface-Zähler | ja: `network_interfaces`, `port_stats`, `wan_traffic` (`api.py:4230`, `:4307`) | – | gedeckt | 0 | ja | a | P | – | `coordinator.py:298-430` |
| 8 | Netzwerk-Verbindungsstatistik (`/proc/net/snmp`, TCP/UDP-Zähler) | nein | file read `/proc/net/snmp`, alle 5 min | **nicht** in ACL v8 | ca. 1–2 KB (S); passt in die 4 KiB **(nicht belegt)** | ja (Kernel) | b | P | – | **nicht belegt** (Inhalt live nicht gesehen) |
| 9 | dnsmasq-Dienst und Metriken | Dienststatus ja: `services` (`DEFAULT_SERVICES`, `const.py:561`) | `ubus call <dnsmasq-Objekt> metrics` | **nicht** in ACL v8 | < 1 KB (S) | ubus-Anbindung standardmäßig an (`--enable-ubus`); Objektname und Felder von `metrics` **nicht belegt** | b | P | – | OpenWrt `dnsmasq.init`: `config_get_bool ubus "$cfg" "ubus" 1` → `--enable-ubus=$instance_name` |
| 10 | DHCP-Leases | ja: `dhcp_leases` (`api.py:3825`), DHCP-Logzeilen `dhcp.*` | – | gedeckt | 0 | ja | a | P | – | `tests/test_log_parser.py:71-75` |
| 11 | DNS-Fehlerstatistik | ja, eingeschränkt: dnsmasq-Logzeilen `dns.query_limit/no_servers/send_failed` | – | gedeckt | 0 | ja (Format laut Parser-Docstring nicht live gesehen) | a | P (auch A/B) | – | `log_parser.py` (Arten), Docstring |
| 12 | DNS-Abfragelogs (`logqueries`) | nein | Router-Konfig: `dhcp.@dnsmasq[0].logqueries=1` | keine | **hoch**: je Abfrage eine Logzeile; verdrängt NI-Zeilen im logd-Ring (Abschnitt 4.10) | **standardmäßig aus** | c | A, B | dnsmasq → logd → Remote-Syslog; besser Alternative AdGuard/Unbound auf eigenem Host (Abschnitt 5) | `dhcp.conf` ohne `logqueries`; `dnsmasq.init`: `append_bool "$cfg" logqueries "--log-queries=extra"`; Zeilenformat **nicht belegt** |
| 13 | odhcpd | ja: Logart `dhcp.odhcpd_error` | – | gedeckt | 0 | ja | a | P (auch A/B) | – | `log_parser.py`; Format **nicht belegt** (Docstring) |
| 14 | IPv6-Nachbarn | nein (ARP nur IPv4) | `luci-rpc getHostHints` (schon erlaubt; heute nur bei ARP-Abschneiden), alle 10 Polls | gedeckt | ca. 100 B je Gerät (S) | ja (LuCI-rpc) | b | P | – | Ob `getHostHints` IPv6-Adressen liefert: **nicht belegt** |
| 15 | hostapd `get_clients` | ja: `clients` (`api.py:2553`) | – | gedeckt | 0 | ja | a | P | – | `docs/plans/2026-11-16-client-stability.md` 1.1 |
| 16 | ubus-WLAN-Ereignisstrom (subscribe) | nein | `ubus subscribe hostapd.*` über SSE (`api.async_subscribe` `api.py:5855`, `ubus_stream.py`) | `:subscribe` fehlt in ACL v8 | uhttpd stürzte auf zwei APs ab | ja, aber instabil | c | – | keine (Push-Strom, kein Log); **nicht empfohlen** | `docs/realtime-rca.md:15-17`; `STREAM_FORBIDDEN_OBJECTS = {"hostapd-auth"}` (`const.py:645-673`) |
| 17 | Assoziations- und Authentifizierungsfehler | ja: `wifi.psk_mismatch, handshake_failed, assoc_rejected, sae_failed, backhaul_auth_failed`; CS `auth_fail`, `assoc_fail` | – | gedeckt | 0 | ja | a | P (auch A/B) | – | `tests/test_log_parser.py:61-70` |
| 18 | Deauthentifizierungs-Ereignisse | ja: `wifi.deauth`, `wifi.disassoc`, `inactivity_timeout` | – | gedeckt | 0 | ja; Reason-Codes bei Standard-Loglevel nicht vorhanden | a | P (auch A/B) | – | Parser-Docstring; `tests/test_log_parser.py:63` |
| 19 | Wiederholte Verbindungsversuche | ja: `wifi.connected`-Zeilen (nur gezählt), CS `associations`, `reconnects` je Stunde | – | gedeckt | 0 | ja | a | P | – | `client_history.py:311` |
| 20 | WLAN-Scan (`iwinfo scan`) für Rogue-AP-Indikatoren | nein | `iwinfo scan` je Radio, **nur manuell** | schon in ACL v8 | Funk verlässt kurz den Kanal; Wirkung auf Clients **nicht belegt** | ja | b | P | – | ACL `acl_provisioning.py:61-145`; Dauer und Wirkung **nicht belegt** |
| 21 | logread (Router-Log) | ja: `log read` jeden Poll, 100–700 Zeilen | – | gedeckt (v6+) | vorhanden: ca. 40–115 KB je Poll und Router (S, 165 B/Zeile) | ja | a | P (A/B als Ersatz denkbar, 4.8) | Remote-Syslog möglich (2.3) | `const.py:514-522`, `docs/realtime-rca.md` |
| 22 | procd- und Dienst-Ereignisse | ja: `services`, `service_instances`; Logarten `system.service_crash_loop`, NI `system.service_restart/stopped` | – | gedeckt | 0 | ja | a | P | – | `net_rules.py:186-193` |
| 23 | Unerwartete Router-Neustarts (Uptime-Sprung) | ja: `uptime`, `localtime_at`; NI `detect_reboot` → `system_reboot` | – | gedeckt | 0 | ja | a | P | – | `net_rules.py:2024-2075` |
| 24 | Fehlgeschlagene Admin-Logins (dropbear; uhttpd/rpcd `session.login`) | dropbear: Rohzeilen im vorhandenen `log read` (Erfolgszeilen live belegt), heute vom Parser verworfen; uhttpd/rpcd: nein | kein neuer Abruf; Parser und Rohzeilen-Hook (Q-HOOK) | gedeckt | 0 | dropbear loggt standardmäßig (Erfolg belegt); Format der Fehlzeile **nicht belegt**; ob uhttpd/rpcd Fehlversuche loggen: **nicht belegt** | a | P (auch A/B) | – | `tests/test_log_parser.py:3-4`, `:105`; `tests/test_net_infra.py:255` |
| 25 | VLAN-, Bridge- und Zonen-Konfiguration (UCI network/firewall) | network ja: `port_vlan_map` (`uci get network`, jeder Poll, `api.py:4392`); firewall nein | `uci get firewall` alle 30 min; später Drift-Events des Configuration Managers | UCI ohne eigenen ACL-Abschnitt; `firewall` über LuCI-ACL **nicht belegt** | 2–8 KB (S) | ja | b | P | – | `api.py:3947-3949` (Analogie `dhcp`) |
| 26 | Client-VLAN-Zuordnung | ja, indirekt: SSID/Interface → Netz (`ap_interfaces`, UCI wireless), kabelgebunden über FDB und `port_vlan_map` | – | gedeckt | 0 | ja | a | P | – | CS-Plan 1.4 („VLAN je Client nur indirekt über SSID“) |
| 27 | ARP-Tabelle | ja: `arp_table` (`api.py:4745`) | – | gedeckt | 0 | ja | a | P | – | `net_rules.py:2991-2994` (Grenzen der ARP-Konfliktlogik) |
| 28 | Bridge-FDB | ja: `port_fdb_map` (`api.py:4651`) | – | gedeckt | 0 | ja | a | P | – | `api.py:4651` |
| 29 | CS-Historie (Identität, Zeiten) | ja: `ClientHistory` (`client_history.py:741`) | – | – | 0 (HA-seitig) | – | a | P | – | 1.6 |
| 30 | NI-Incidents und -Events | ja: `AlarmMachine`, `EventRing` | – | – | 0 (HA-seitig) | – | a | P | – | 1.4, 1.5 |

**Prüfung „jede Quelle genau eine Zeile und eine Gruppe“:** Es sind 30 Zeilen mit 30 verschiedenen Quellen. Jede hat genau einen Gruppenwert.

| Gruppe | Anzahl | Zeilen |
|---|---|---|
| a | 18 | #6, #7, #10, #11, #13, #15, #17, #18, #19, #21, #22, #23, #24, #26, #27, #28, #29, #30 |
| b | 8 | #1, #2, #3, #8, #9, #14, #20, #25 |
| c | 4 | #4, #5, #12, #16 (#16 nicht empfohlen) |

18 + 8 + 4 = 30.

### 2.3 Auslagerung im Detail (Gruppe c und für den WR3000 zu Teures)

| Quelle | Wie die Daten vom Router kommen | Einmalige Router-Einstellung | Routerkosten | Empfang | Beleg |
|---|---|---|---|---|---|
| Router-Log allgemein (Basis für #5, #12, #24) | logd → `logread -f -r <log_ip> <log_port>`, als eigene procd-Instanz | `system.@system[0].log_ip`, `log_port` (Standard 514), `log_proto` (Standard udp) | ein zusätzlicher `logread`-Prozess (wenige 100 KB RAM, S); **keine Flash-Schreibvorgänge**, solange `log_file` leer bleibt; Netz ca. Lograte × 150 B (S) | Weg A oder B (genau ein Ziel je Router, 4.5) | OpenWrt `package/system/ubox/files/log.init` |
| Firewall-Logs (#5) | nft-`log`-Regel → Kernel-Log → logd → Remote-Syslog | `firewall.<zone>.log=1` und `log_limit` (z. B. 10/minute) | je geloggtes Paket eine Zeile; mit `log_limit` begrenzt; RAM im logd-Ring | A oder B | fw4 `zone-verdict.uc`, `rule.uc`, `fw4.uc` |
| DNS-Abfragelogs (#12) | dnsmasq `--log-queries=extra` → syslog → logd → Remote-Syslog | `dhcp.@dnsmasq[0].logqueries=1`, optional `logfacility` | je Abfrage eine Zeile; CPU gering (S); **Ring-Verdrängung** (4.10) | A oder B | `dnsmasq.init` |
| Volle Conntrack-Tabelle (#4) | Flow-Export (softflowd o. ä.) zum Collector | Paket installieren und konfigurieren | Paket, RAM und CPU je Flow (S); **nicht empfohlen** | nur B | **nicht belegt** (Paketverfügbarkeit, Kosten) |
| ubus-Ereignisstrom (#16) | kein Log-Weg | ACL `:subscribe` | uhttpd-Absturz beobachtet | – | `docs/realtime-rca.md:15-17` |

---

## 3. Erkennungen

**Statuswerte:**

- **verfügbar**: Die Quelle ist Gruppe a.
- **verfügbar mit neuem Abruf**: Die Quelle ist Gruppe b.
- **nicht verfügbar (optional, standardmäßig aus)**: Die Quelle ist Gruppe c.

**Wortwahl:** Das Ergebnis ist ein *Hinweis* oder eine *Hypothese*. „bestätigt“ (`cause_status: confirmed`) gibt es nur mit einem gemessenen Beweis. Syslog-Daten über UDP sind fälschbar und reichen allein nie für „bestätigt“.

**Keine Duplikate:** Wo NI schon einen Incident hat, verweist das Security Center darauf (Spalte „Bestand“) und erzeugt **keinen** eigenen `sec_*`-Typ.

### 3.1 Gerätesicherheit

| Erkennung | Quellen (#) | Gruppe | Status | Bestand / Hinweis |
|---|---|---|---|---|
| Neue oder unbekannte Geräte | 10, 15, 27, 29 | a | verfügbar | `ClientLive.first_seen`. Private MACs (`is_private_mac`) senken die Stufe, weil sie rotieren. „Unbekannt“ heißt nur „noch nie gesehen“, ohne eine Liste bekannter Geräte |
| Änderung der IP/MAC-Zuordnung | 10, 27, 29 | a | verfügbar | `ClientLive.ip_changed`, `_Client.ip_t` |
| Häufige DHCP-Adresswechsel | 10, 29 | a | verfügbar | IP-Wechsel je Zeitfenster aus CS; DHCPACK-Zeilen nur gezählt |
| IP-Konflikt-Indikator | 10, 27 | a | verfügbar | **Bestand** NI `dhcp_conflict` (DHCPDECLINE, `decline_cause` `net_rules.py:3019`). Bewusst kein ARP-Detektor (`net_rules.py:2991-2994`). Kein `sec_*`-Typ |
| MAC-Spoofing-Indikator | 15, 27, 28, 29 | a | verfügbar | Gleiche MAC gleichzeitig an zwei Routern oder Ports außerhalb eines Roamings, oder ein Hostname-Wechsel bei gleicher MAC. Immer *Hypothese*, denn Roaming und Repeater erzeugen ähnliche Muster |
| Gerät in anderem VLAN | 26, 25 | a | verfügbar | Nur indirekt über SSID/Interface oder FDB. Kabelgebundene VLAN-Zuordnung je Client **nicht belegt** |
| Ungewöhnliche Verbindungszeiten | 29 | a | verfügbar | Stunden-Buckets (168 h); braucht mindestens 7 Tage Daten |
| Änderung im Kommunikationsmuster: Volumen | 15, 29 | a | verfügbar | rx/tx je Client aus `get_clients`, nur WLAN |
| Änderung im Kommunikationsmuster: Ziele und Ports | 4 | c | nicht verfügbar (optional, standardmäßig aus) | Braucht Flow-Daten; nicht auf dem WR3000 |

### 3.2 Firewall

| Erkennung | Quellen (#) | Gruppe | Status | Bestand / Hinweis |
|---|---|---|---|---|
| Viele blockierte Verbindungen: Summe je Zone oder Regel | 2 | b | verfügbar mit neuem Abruf | Zählerdifferenz, nur auf Anforderung (SSH). Je Client nur mit #5 |
| Viele blockierte Verbindungen: je Quelle | 5 | c | nicht verfügbar (optional, standardmäßig aus) | |
| Zugriffe auf nicht erlaubte Dienste | 5 | c | nicht verfügbar (optional, standardmäßig aus) | Ziel-Port aus der Logzeile; Felder **nicht belegt** |
| Viele ausgehende Verbindungen / Verbindungsraten | 3 | a | verfügbar (nur router-weit) | **Bestand** NI `system_conntrack_jump`. Je Client: #4 (c) |
| Viele Zielports | 4, 5 | c | nicht verfügbar (optional, standardmäßig aus) | |
| Inter-VLAN-Versuche | 5, 25 | c | nicht verfügbar (optional, standardmäßig aus) | Braucht Logging auf den Zonen mit REJECT/DROP |
| Conntrack-Überlastung (Prozent von Max) | 3 | b | verfügbar mit neuem Abruf | Relativer Sprung schon im **Bestand** (`system_conntrack_jump`). Neu ist nur der Anteil am Max |
| Änderungen der Firewall-Zähler | 2 | b | verfügbar mit neuem Abruf | Auf Anforderung |
| Zugriffe auf Management-Schnittstellen: SSH | 24 | a | verfügbar | dropbear-Fehlzeile **nicht belegt** (Q-LIVE). Eigene Logins der Integration (LLDP-SSH alle 600 s, `tests/test_poll_no_ssh.py:14-15`) über die HA-Adresse ausfiltern |
| Zugriffe auf Management-Schnittstellen: LuCI/rpcd oder aus dem WAN | 5, 24 | c | nicht verfügbar (optional, standardmäßig aus) | uhttpd/rpcd-Fehlversuche **nicht belegt** |

### 3.3 DNS

| Erkennung | Quellen (#) | Gruppe | Status | Bestand / Hinweis |
|---|---|---|---|---|
| DNS-Abfrageraten (router-weit) | 9 | b | verfügbar mit neuem Abruf | Nur wenn `metrics` Abfragezähler liefert: **nicht belegt** |
| DNS-Abfrageraten je Client | 12 | c | nicht verfügbar (optional, standardmäßig aus) | |
| NXDOMAIN-Cluster | 12 | c | nicht verfügbar (optional, standardmäßig aus) | |
| Viele unterschiedliche Domains | 12 | c | nicht verfügbar (optional, standardmäßig aus) | |
| Änderung des DNS-Servers | 11, 25 | a | verfügbar | dnsmasq-Zeilen „using nameserver“ (Format nur als Platzhalter in `tests/test_net_infra.py:259`); `dns-server` im vorhandenen `network.interface dump` **nicht belegt**; DHCP-Option 6 aus `uci get dhcp` |
| DNS-Umgehung | 4, 5 | c | nicht verfügbar (optional, standardmäßig aus) | Port 53/853 an fremde Ziele; DoH ist grundsätzlich nicht erkennbar |
| DNS-Tunneling-Indikator | 12 | c | nicht verfügbar (optional, standardmäßig aus) | Länge und Entropie der Namen; nur Hypothese |

### 3.4 VLAN

| Erkennung | Quellen (#) | Gruppe | Status | Hinweis |
|---|---|---|---|---|
| Port- oder Tagging-Änderung | 25 (network-Teil) | a | verfügbar | `port_vlan_map` je Poll |
| Zonenänderung | 25 (firewall-Teil) | b | verfügbar mit neuem Abruf | Später Drift-Events (Abschnitt 6.1) |
| Management-VLAN-Änderung | 25 (network-Teil) | a | verfügbar | Interface der Entry-Adresse |

### 3.5 WLAN

| Erkennung | Quellen (#) | Gruppe | Status | Bestand / Hinweis |
|---|---|---|---|---|
| Wiederholte fehlgeschlagene WLAN-Authentifizierung | 17 | a | verfügbar | **Bestand** `wifi_auth_failures`, `wifi_auth_wave` (Empfehlung `rec_attack`) |
| Häufige Assoziationsversuche | 19 | a | verfügbar | CS `associations` je Stunde |
| Deauth-Cluster | 18 | a | verfügbar (als Indikator) | **Bestand** `wifi_mass_disconnect`. Gefälschte Deauth-Frames Dritter sieht das AP-Log nicht (ohne Monitor-Mode **nicht belegt**) |
| WPA-Handshake-Fehler | 17 | a | verfügbar | `wifi.handshake_failed`, Teil von `wifi_auth_failures` |
| Versuche über mehrere APs | 17, 30 | a | verfügbar | Gleiche MAC mit Fehlversuchen an ≥ 2 Routern im Fenster; neuer `sec_*`-Typ (Flotten-Scope) |
| Rogue-AP-Indikator | 20 | b | verfügbar mit neuem Abruf | Eigene SSID mit fremder BSSID; nur manuell |

### 3.6 Gerät

| Erkennung | Quellen (#) | Gruppe | Status | Bestand / Hinweis |
|---|---|---|---|---|
| Unerwarteter Router-Neustart | 23 | a | verfügbar | **Bestand** `system_reboot`. „Unerwartet“ ist eine Hypothese: ohne Wartungsmodus und ohne Update-Aktion |
| Fehlgeschlagene Admin-Logins | 24 | a | verfügbar | Nur dropbear. Fehlzeilenformat **nicht belegt**, LuCI/rpcd **nicht belegt** |

**Neue `sec_*`-Typen** (Vorschlag, nur wo kein Bestand passt):

- `sec_new_device`
- `sec_ip_mac_change`
- `sec_dhcp_churn`
- `sec_mac_spoof_hint`
- `sec_vlan_mismatch`
- `sec_unusual_time`
- `sec_traffic_shift`
- `sec_fw_blocked`
- `sec_conntrack_full`
- `sec_fw_counter_change`
- `sec_admin_login_failed`
- `sec_config_change` (VLAN, Zone, Management)
- `sec_wifi_multi_ap_auth`
- `sec_rogue_ap_hint`
- `sec_assoc_burst`

Diese Typen kommen später dazu, wenn ihre Quelle aktiviert wird (Gruppe c):

- `sec_fw_denied_service`
- `sec_port_scan_hint`
- `sec_inter_vlan`
- `sec_dns_rate`
- `sec_nxdomain_cluster`
- `sec_dns_many_domains`
- `sec_dns_bypass_hint`
- `sec_dns_tunnel_hint`

---

## 4. Empfangsort und Empfangswege

### 4.1 Entscheidung des Nutzers

Beide Wege werden gebaut und sind in den Security-Einstellungen wählbar:

- `log_path: "off" | "syslog" | "collector"`;
- Standard `"off"`.

Es ist immer genau ein Weg aktiv. Bei `"off"` gilt:

- Es werden nur Daten der Gruppen a und b genutzt.
- Die Erkennungen der Gruppe c melden „nicht verfügbar“.

### 4.2 Gemeinsame Schnittstelle „Log-Quelle“ (Vorschlag)

```python
class LogSource(Protocol):
    """One delivery path of off-router log lines (A or B)."""
    name: str                                  # "syslog" | "collector"
    async def async_start(self) -> None: ...
    async def async_stop(self) -> None: ...
    def drain(self, max_records: int) -> list[SecLogRecord]: ...   # never blocks
    def stats(self) -> SourceStats: ...       # counters only, no identities
```

**Normalisiertes Format `SecLogRecord`, Version 1:**

| Feld | Inhalt |
|---|---|
| `v` | Schema-Version (1), später an das Event-Schema von Enterprise Core angeglichen |
| `router` | `entry_id` (später Router-ID der Registry) |
| `ts` | UTC-Sekunden, aus Routerzeit plus Zonen-Offset (4.4) |
| `recv` | Empfangszeit in HA bzw. im Collector |
| `path` | `syslog` oder `collector` |
| `pri` | syslog-PRI (Facility, Severity) |
| `proc` | Prozess (`hostapd`, `dnsmasq`, `dropbear`, `kernel`, …) |
| `pid` | PID oder `None` |
| `msg` | Nachrichtentext ohne Kopf, gekürzt auf 512 Zeichen |
| `kind` | normalisierte Art (z. B. `fw.drop`, `auth.ssh_failed`, `dns.query`) oder `None` |
| `fields` | geparste Felder, z. B. `{"zone": "wan", "dir": "in", "dpt": 22}` |
| `key` | Dedup-Schlüssel (4.3) |

**Die Analyse kennt den Weg nicht:**

- Detektoren bekommen nur `SecLogRecord`s.
- Die Parser (`security_logfmt.py`) sind reine Funktionen ohne HA-Import.
- Der Collector benutzt eine Kopie davon (Abschnitt 4.7, Weg B).

### 4.3 Dedup und Hochwassermarke

- **Schlüssel:** `key = sha1(router | ts_sekunde | proc | msg)[:16]` plus Laufindex für identische Zeilen in derselben Sekunde. Syslog hat nur Sekundenauflösung, und wiederholte gleiche Fehlzeilen sollen nicht verschmelzen.
- **Je Router** gibt es eine Menge der Schlüssel der letzten 10 min (höchstens 20 000, nur im RAM) und eine **Hochwassermarke** `hwm[router]`: die größte verarbeitete `ts`. Die Marke wird im Security-Store gespeichert.
- **Wegwechsel:** Der neue Weg nimmt nur Records mit `ts > hwm - 2 s` an. Im Grenzbereich entscheidet die Schlüsselmenge. Damit entstehen keine doppelten Events beim Umschalten. Beim Wechsel auf `off` bleibt die Marke stehen.
- **Collector:** zusätzlich eine fortlaufende `seq` je Collector. Die Integration speichert `after_seq`. `seq` und `hwm` sichern sich gegenseitig, etwa nach einem Collector-Neustart mit neuer `seq`-Basis.
- **Vorhandenes `log read`:** Liefert ein Empfangsweg Records für einen Router, nutzen die Security-Detektoren für die **log-basierten** `sec_*`-Arten nur diesen Weg. Der Rohzeilen-Hook aus dem Poll (Q-HOOK) dient dann nur als Lückenfüller. Dieselbe Zeile zählt nie doppelt, denn `log read` liefert `time` in ms (UTC), und die Sekunde fließt in denselben Schlüssel.

### 4.4 Zeit und Zonen

- logd nutzt für Remote-Zeilen die **lokale Routerzeit ohne Jahr** (`localtime_r` + `asctime_r`, `strncat(buf, c + 4, 16)`; ubox `log/logread.c`).
- Das Jahr kommt aus der Empfangszeit.
- Den Zonen-Offset liefern `coordinator.data.localtime` und `localtime_at` (`get_router_status`, `api.py:1732`).
- Ohne Offset wird der Record mit `ts = recv` angenommen und als „Zeit geschätzt“ markiert.

### 4.5 Ein Ziel je Router

`log.init` liest **ein** `log_ip`, `log_port` und `log_proto` und startet **eine** `logread -r`-Instanz. Ob mehrere Ziele möglich sind, ist **nicht belegt**.

**Folge:** Der Wechsel zwischen A und B heißt, auf jedem Router `log_ip` umzustellen. Das ist eine Routeränderung und braucht Freigabe (Q-SYSLOG).

**Alternative ohne Routeränderung beim Wechsel:** Die Router senden immer an den Collector, und der Collector leitet an HA weiter. Das ist **nicht** vorgesehen, weil Weg A dann vom Collector abhängt.

### 4.6 Empfangsweg A: Syslog-Empfänger in HA

| Punkt | Vorschlag |
|---|---|
| Modul | `security_syslog.py` (eingehend, kein ausgehender Aufruf; deshalb nicht in `api.py`) |
| Transport | UDP über `loop.create_datagram_endpoint`; TCP optional über `asyncio.start_server` mit Zeilenende `\n` oder NUL (`log_trailer_null`) |
| Port | **5514/udp** als Standard (unprivilegiert). 514 ist privilegiert. Router-Einstellung `log_port=5514` |
| Absender | Nur Quell-IPs aus der Router-Registry: heute die Hosts der Config-Entries plus ihre Interface-Adressen aus `network_interfaces`. Alles andere wird verworfen und gezählt. **Annahme**, live prüfen: Der Router sendet von der LAN-Adresse, die HA kennt |
| Zeilenlänge | Kappe 2048 Byte; länger wird abgeschnitten und gezählt. logd-Puffer `LOG_LINE_SIZE + 128`; Wert von `LOG_LINE_SIZE` **nicht belegt** |
| Rate | Token-Bucket je Absender 200 Zeilen/s, global 1000 Zeilen/s |
| Puffer | `deque(maxlen=5000)` Records. Ein voller Puffer verwirft die neueste Zeile und zählt `dropped_buffer` |
| Überlast | **Verwerfen und zählen, nie blockieren.** `datagram_received` macht nur Kappenprüfung und `append` (O(1)). Geparst wird gebündelt alle 5 s, höchstens 2000 Zeilen je Durchgang |
| Zähler | `received`, `dropped_sender`, `dropped_rate`, `dropped_buffer`, `truncated`, `unparsed`, je Router `last_seen` (Diagnose ohne IPs) |
| Rohzeilen | werden **nicht** gespeichert, nur Aggregate und gekürzte Evidenz (`STORE_EVIDENCE`-Muster) |
| HA OS | Ob der Core-Container auf HA OS eingehende UDP/TCP-Pakete auf 5514 ohne Zusatzschritte bekommt (Host-Netz, keine Host-Firewall), ist **nicht belegt**. `contributors.home-assistant.io/os/operating-system/networking/` sagt nur „Home Assistant OS uses NetworkManager for the host network.“ Live-Prüfung: Q-LIVE (HA-Teil). Bei HA in Docker ohne `network_mode: host` ist ein Port-Mapping nötig |
| Sicherheit | Der Listener ist im ganzen LAN erreichbar, und UDP-Quellen sind fälschbar. Deshalb gelten Allowlist, Kappen und „nie bestätigt allein aus Syslog“. Standard aus |

### 4.7 Empfangsweg B: separater Collector

**Ort und Paketierung:**

- Der Collector liegt in `contrib/security-collector/`: `collector.py`, `logfmt.py` (Kopie der Parser), `README.md`, `tests/`.
- Er braucht Python ≥ 3.11 und **nur die Standardbibliothek** (`asyncio`, `http.server` bzw. `asyncio`-HTTP, `ssl`, `sqlite3` optional).
- Er ist **nicht** Teil des HA-Pakets, denn HACS lädt nur `custom_components/openwrt_router/`.
- Eigene pytest-Tests laufen in CI als zusätzlicher Job.

**Schnittstelle Collector ↔ Integration (Version 1):**

| Punkt | Festlegung |
|---|---|
| Transport | HTTPS mit selbstsigniertem Zertifikat und Fingerprint-Pin in HA (Q-TLS), alternativ HTTP nur im LAN |
| Auth | `Authorization: Bearer <token>`, Token ≥ 32 Byte zufällig, im Security-Store unter einem Schlüssel mit `token` im Namen (Diagnose-Redaktion 1.9) |
| Versionierung | Pfad `/v1/…` und Feld `"api": 1` in jeder Antwort. Die Integration lehnt eine unbekannte Hauptversion ab; zusätzliche Felder sind erlaubt |
| `GET /v1/health` | `{"api":1,"version":"…","senders":{"<router-ref>":{"last_seen":…,"received":…}},"dropped":{…}}` |
| `GET /v1/records?after=<seq>&limit=500` | `{"api":1,"next":<seq>,"records":[SecLogRecord…],"dropped":{…}}`, nur Records mit `kind != None` (verdichtet: keine unerkannten Zeilen) |
| `GET /v1/summary?since=<ts>` | Zähler je Router, `kind` und Stunde (für Panel-Diagramme ohne Einzelrecords) |
| Router-Zuordnung | Der Collector kennt die Absender-IPs (Allowlist in seiner Konfiguration). Die Integration ordnet IP → `entry_id` über die Registry zu. Der Collector schickt die IP nur als `sender`-Feld, die Diagnose zeigt sie nie |
| Abruf | Die Integration fragt alle 60 s (gekoppelt an den Poll-Takt, kein eigener Timer je Router), einmal je HA-Instanz |
| Ort im Code | Client-Klasse `SecurityCollectorClient` im markierten Block am Ende von `api.py` (alle ausgehenden HTTP-Aufrufe in `api.py`), mit `async_get_clientsession(hass)` |
| Grenzen im Collector | dieselben wie 4.6 (Zeilenlänge, Rate, Allowlist), Ring 50 000 Records im RAM, 24 h |

Der Collector wird in dieser Aufgabe **nie** installiert oder gestartet. Die Einrichtung auf Proxmox steht unter Q-PROXMOX.

### 4.8 Option: Syslog statt `log read` der NI

Frage: Kann ein aktiver Empfangsweg das `log read` je Poll ersetzen oder entlasten? Ziel wäre, nicht zwei Log-Lesungen nebeneinander zu haben.

**Pro:**

- Spart je Poll und Router 100–700 Zeilen, ca. 40–115 KB (S).
- Die Zeilen kommen sofort an statt bis zu einen Poll später.
- Firewall- und DNS-Zeilen laufen über denselben Strom.

**Contra:**

- UDP verliert Zeilen still.
- Fällt HA oder der Collector aus, sind die Zeilen weg. `log read` kann sie aus dem Ring nachholen; `LogCursor` erkennt Lücken (`system.log_gap`).
- Remote-Zeilen haben keine logd-`id`. NI erkennt neue Zeilen über die logd-`id` (`LogCursor`, `log_parser.py:696-726`).
- `log_coverage` und Score-Abdeckung der NI hängen an `log_ok` (`PollFacts`).
- Ein Ersatz greift in NI und Coordinator ein.

**Empfehlung:** In R1 nicht ersetzen. Das Security Center liest kein zweites Log: Es nutzt Rohzeilen aus dem vorhandenen `log read` (Q-HOOK) oder den gewählten Empfangsweg. Später, als eigene Frage Q-NI-LOG: Bei gesundem Empfangsweg liest NI nur noch jeden 5. Poll als Lückenfüller.

### 4.9 Testbarkeit ohne Routeränderung

Neue Fixtures unter `tests/fixtures/security/` (Vorschlag). Jede Datei trägt im Kopf die Herkunft des Formats.

| Fixture | Format | Herkunft |
|---|---|---|
| `logd_remote_udp.txt` | `<PRI>Mmm dd hh:mm:ss HOST [PREFIX: ][kernel: ]MSG`, ohne Zeilenende (ein Datagramm je Zeile) | **belegt**: ubox `log/logread.c` (`log_notify`, Zweig `LOG_NET`). Tag mit Leerzeichen-Auffüllung (`Nov  7`) folgt aus dem `asctime`-Format: **Annahme** (C-Standard), Tests decken beide Formen ab |
| `logd_remote_tcp.bin` | dieselbe Zeile mit `\n` bzw. NUL am Ende (`log_trailer_null`) | **belegt**: `logread.c`, `log.init` (`-0`) |
| Nachrichtenteil hostapd / dnsmasq-dhcp / dropbear-Erfolg | wie `tests/test_log_parser.py:59-75`, `:105` | **belegt** (live gesehen laut Docstring `:3-4`) |
| `fw4_kernel.txt` | `kernel: [<sek>] <verdict> <zone> <in\|out>: …` bzw. `<policy> <zone> forward: …` oder freier Regel-Präfix | Präfix **belegt** (fw4 `zone-verdict.uc`, `ruleset.uc`, `rule.uc`). `[<sek>]` laut Repo-Fixture `tests/test_net_infra.py:253` (Herkunft **nicht belegt**). Felder danach (`IN= OUT= SRC= DST= PROTO= SPT= DPT=`): **nicht belegt** |
| `dnsmasq_query.txt` | Zeilen von `--log-queries=extra` | Schalter **belegt** (`dnsmasq.init`); Zeilenform **nicht belegt** (Upstream-Quelle nicht erreichbar) |
| `dropbear_fail.txt` | Fehlversuch | **nicht belegt** |

Alle Platzhalter-Formate werden nach Q-LIVE durch live gesehene Zeilen ersetzt. Bis dahin gilt: Der Parser erkennt sie, aber die Erkennung meldet „Format unbestätigt“.

**Tests ohne Router:**

- Weg A: Bytes direkt in `datagram_received`, dazu Kappen-, Allowlist- und Überlasttests.
- Weg B: `aiohttp`-Testserver in HA-Tests; eigene Socket-Tests im Collector.
- Dedup: Umschalten mitten im Strom.

**Jede Erkennung meldet „nicht verfügbar“**, solange ihre Quelle nichts liefert. Das gilt bei abgeschaltetem Weg und bei mehr als 15 min ohne Records eines Routers, der zuvor geliefert hat. Der Zustand erscheint im Panel und in der Diagnose.

### 4.10 Einschalt-Befehle mit Rückweg (alle QUESTION, nichts ausgeführt)

Für alle Befehle gilt:

- **Vorher sichern:** `uci export <config> > /tmp/<config>.vor-security`. Das liegt im RAM; vor einem Neustart auf HA kopieren.
- **Jede Änderung ins Änderungsprotokoll.**
- `<ziel>` ist die HA- oder Collector-Adresse.

**Remote-Syslog (Q-SYSLOG):**

```sh
uci export system > /tmp/system.vor-security
uci set system.@system[0].log_ip='<ziel>'
uci set system.@system[0].log_port='5514'
uci set system.@system[0].log_proto='udp'
uci commit system
/etc/init.d/log restart        # Name des Init-Skripts: Annahme (ubox log.init), live prüfen
# Rückweg:
uci delete system.@system[0].log_ip
uci delete system.@system[0].log_port
uci delete system.@system[0].log_proto
uci commit system
/etc/init.d/log restart
```

**Firewall-Logging (Q-FWLOG, nur Gateway, Zone über ihren Namen finden):**

```sh
uci export firewall > /tmp/firewall.vor-security
uci show firewall | grep "\.name='wan'"        # Index <n> der wan-Zone ermitteln
uci set firewall.@zone[<n>].log='1'
uci set firewall.@zone[<n>].log_limit='10/minute'
uci commit firewall
/etc/init.d/firewall reload
# Rückweg:
uci delete firewall.@zone[<n>].log
uci delete firewall.@zone[<n>].log_limit
uci commit firewall
/etc/init.d/firewall reload
```

**dnsmasq-Abfragelog (Q-DNSLOG; der Neustart unterbricht DNS und DHCP kurz, deshalb im Wartungsfenster):**

```sh
uci export dhcp > /tmp/dhcp.vor-security
uci set dhcp.@dnsmasq[0].logqueries='1'
uci commit dhcp
/etc/init.d/dnsmasq restart
# Rückweg:
uci delete dhcp.@dnsmasq[0].logqueries
uci commit dhcp
/etc/init.d/dnsmasq restart
```

**Risiko:** Jede Abfrage wird eine Zeile im logd-Ring. Der Ring ist standardmäßig klein: `log.init` setzt 64, wenn `log_size` und `log_buffer_size` 0 sind; die Einheit ist **nicht belegt**. Die Zeilen verdrängen hostapd-Zeilen, bevor NI sie per `log read` liest. Das senkt die WLAN-Abdeckung der NI. Mögliche Abhilfe ist ein größerer Ring (`system.@system[0].log_size`, RAM), Wirkung **nicht belegt**. Besser ist ein eigener DNS-Resolver mit Statistik-Schnittstelle auf einem separaten Host (Abschnitt 5).

**Collector auf Proxmox (Q-PROXMOX, Platzhalter `<ctid>`, nichts davon ausgeführt):**

```sh
# Vorher auf dem Host: vzdump bzw. Konfig sichern; nur mit Freigabe des Nutzers.
pct create <ctid> local:vztmpl/<debian-template> --hostname sec-collector \
  --memory 256 --cores 1 --net0 name=eth0,bridge=vmbr0,ip=dhcp --unprivileged 1
pct start <ctid>
pct exec <ctid> -- apt-get install -y python3
# contrib/security-collector nach /opt/sec-collector kopieren, Token und Allowlist setzen,
# systemd-Unit sec-collector.service aktivieren, Ports 5514/udp und 5515/tcp freigeben.
# Rückweg:
pct exec <ctid> -- systemctl disable --now sec-collector
pct stop <ctid>
pct destroy <ctid>
```

---

## 5. Erweiterungspunkte (nur geprüft, nicht gebaut)

| Erweiterung | Auf dem WR3000? | Wo laufen | Andockstelle |
|---|---|---|---|
| Suricata | nein: RAM und CPU reichen für IDS in Leitungsgeschwindigkeit nicht (S); Paketverfügbarkeit **nicht belegt** | eigener Linux-/Proxmox-Host mit Spiegelport | EVE-JSON → Collector (B) → `SecLogRecord` (`kind = ids.alert`) |
| Zeek | nein (S) | Proxmox mit Spiegelport | Zeek-JSON-Logs → Collector → Records/Summary |
| NetFlow/IPFIX | Exporter evtl. auf dem Router (Paket, RAM je Flow, **nicht belegt**) | Exporter Router, Kollektor Proxmox | Flow-Summary → Collector `/v1/summary` (füllt #4: Zielports, Verbindungsraten je Client) |
| banIP | möglich mit kleinen Listen (S, RAM für Sets **nicht belegt**) | Router | banIP-Logzeilen über Syslog (A/B); später ein Status-Abruf (Gruppe b), falls ubus-Schnittstelle vorhanden (**nicht belegt**) |
| CrowdSec | Agent nein (S); Firewall-Bouncer auf dem Router **nicht belegt** | Agent auf Proxmox, liest Syslog vom Collector | CrowdSec-Alarme → Collector → Records |
| AdGuard Home | knapp (RAM, S); nicht empfohlen | Proxmox oder eigener Host | Querylog/Statistik-API → Collector-Summary (füllt die DNS-Erkennungen ohne `logqueries` und ohne Ring-Verdrängung) |
| Unbound | möglich, aber Query-Log wieder im Ring (S) | besser Proxmox | `unbound-control stats` → Collector-Summary |
| Externer Syslog-Collector | – | Proxmox | ist Empfangsweg B |
| Lokale KI-Analyse | nein | Proxmox, nur lokal, keine Daten in die Cloud | liest `/v1/summary` bzw. die Security-Routen der Integration; schreibt nichts zurück |

---

## 6. Abhängigkeiten und Architektur

### 6.1 Was wir von Enterprise Core und dem Configuration Manager brauchen

| Baustein | Wofür | Auf diesem Branch |
|---|---|---|
| Router-ID | stabiles `router` in `SecLogRecord` statt `entry_id` | **nicht vorhanden** |
| Router-Registry | Absender-Allowlist (A/B), IP → Router | **nicht vorhanden**; Ersatz: Config-Entry-Hosts plus `network_interfaces` |
| Capability Detection | welche Gruppe-b/c-Quellen ein Router kann (ACL, Pakete, Remote-Syslog an) | **nicht vorhanden**; heute nur `check_capabilities` (`api.py:1563`) für den Config Flow |
| Event- und Audit-Schema | gemeinsames Format; `SecLogRecord.v` wird daran angeglichen | **nicht vorhanden** |
| Drift-Events | spätere Quelle für VLAN-, Zonen- und Firewall-Änderungen (ersetzt den eigenen `uci get firewall`-Abruf) | **nicht vorhanden** |

Die Branches `claude/enterprise-core-49ade2` und `claude/config-manager-d9fdac` existieren lokal. Ihr Inhalt wurde **nicht gelesen**. `docs/dev/` (Configuration API) fehlt auf diesem Branch.

### 6.2 Modulskizze

**Neue Dateien** (keine Umbauten bestehender Module):

```
custom_components/openwrt_router/
  security_center.py    # SecurityCenter: PollObserver am NI-Engine, Settings, Store, Detektor-Lauf
  security_rules.py     # reine Detektoren (ohne HA-Import) → Evidence für sec_*-Typen
  security_logsrc.py    # LogSource-Protokoll, SecLogRecord, Dedup, Hochwassermarke
  security_logfmt.py    # reine Parser: logd-Remote, fw4, dnsmasq, dropbear
  security_syslog.py    # Empfangsweg A (UDP/TCP-Listener, Kappen, Puffer)
  security_views.py     # Routen /api/openwrt_topology/security/*, Prüfung wie _IntelView._check
  security_entities.py  # Flotten-Sensoren am Anker (claim_fleet), keine Entities je Client
contrib/security-collector/   # Empfangsweg B, nur Standardbibliothek, eigene Tests
tests/fixtures/security/      # Formate aus 4.9
```

**Ergänzungen** nur am Dateiende in einem markierten Block (`# --- Security Center (Phase 2) ---`):

- `api.py`:
  - `get_firewall_config` (`uci get firewall`)
  - `get_conntrack_max`
  - `get_dnsmasq_metrics`
  - `get_net_snmp`
  - `get_ipv6_neighbors` (`getHostHints`)
  - `get_wifi_scan` (`iwinfo scan`)
  - `get_nft_counters` (SSH, auf Anforderung)
  - `SecurityCollectorClient`
- `const.py`:
  - `SEC_STORE_KEY = f"{DOMAIN}.security"`
  - Kappen und Ports
  - Präfix `SEC_TYPE_PREFIX = "sec_"`
  - Unique-ID-Präfix `f"{DOMAIN}_fleet_security_"`
- `__init__.py`: Setup und Unload des Security Centers nach CS, Unload vor NI.

**Store:**

- `openwrt_router.security`, Kappe 512 KB.
- Inhalt: Settings, `hwm` je Router, `after_seq`, Stunden-Aggregate 48 h, Collector-Token (redigiert).
- **Keine** Client-Liste: Identitäten kommen aus CS.

### 6.3 Nötige Hooks in bestehenden Modulen (Ausnahme, Q-HOOK)

| Stelle | Hook | Umfang (S) |
|---|---|---|
| `net_engine.py` vor `_run_machine` (`:968`) | `add_evidence_source(fn)`. Die Quelle gibt `list[Evidence]` für `sec_*` zurück; Fehler werden isoliert wie in `_notify` | ca. 25 Zeilen |
| `net_rules.py` | Schwellwerte der `sec_*`-Typen registrieren (oder in `DEFAULT_SETTINGS` am Ende eines Blocks) | ca. 15 Zeilen |
| `net_rules.py` | `sec_` ausschließen: aus `counted_incidents`/`counts_for_router` (`:5660`, `:5675`) und aus der Wurzel-Verlinkung (`_incident_link`/`_router_link`) | ca. 15 Zeilen |
| `net_engine.py` | `sec_` in `_announce` (`:1817`): eigenes Event `openwrt_router_security_event` statt `openwrt_router_incident_event` | ca. 15 Zeilen |
| `net_events.py` / `prune_incidents` | eigene Kappe 100 für `sec_*` | ca. 10 Zeilen |
| `coordinator.py` `_process_log` (`:1439`) | neue Rohzeilen gekappt (höchstens 700, nur `msg`, `time`, `source`) als `data.new_log_raw` bereitstellen. Kein zweites `log read` | ca. 5 Zeilen |
| `acl_provisioning.py` | ACL v9 für Gruppe b (Q-ACL) | ca. 15 Zeilen |

Bestehende Incidents bleiben unverändert: andere Schlüssel, keine Wurzel, kein Zähler- und Score-Einfluss, eigenes Event.

---

## 7. Geplante Mehrlast (Gruppe b)

Sparsamer Standard: **alles aus**, solange das Security Center aus ist. Wenn es eingeschaltet ist, gelten die Werte unten. Es gibt keinen zusätzlichen Dauer-Poll-Takt: Alles hängt am vorhandenen Poll mit Zykluszähler, wie bei `DHCP_CONFIG_REFRESH_CYCLES`.

| Abruf | Intervall | Datengrenze | Standard | Kosten WR3000 (S) |
|---|---|---|---|---|
| `uci get firewall` | alle 30 Polls (30 min) und bei Start | 64 KB Antwortkappe | an (mit Security Center) | 2–8 KB, ein rpcd-Aufruf |
| file read `nf_conntrack_max` | alle 60 Polls (1 h) | 64 B | an | vernachlässigbar |
| `dnsmasq metrics` | alle 5 Polls | 4 KB | an | < 1 KB |
| file read `/proc/net/snmp` | alle 5 Polls | 4 KiB (rpcd-Grenze) | aus | 1–2 KB |
| `luci-rpc getHostHints` (IPv6) | alle 10 Polls | 256 KB | aus | ca. 100 B je Gerät |
| `iwinfo scan` | **nur manuell** (Panel-Knopf, Admin) | 200 BSS | aus | Kanalwechsel, Wirkung **nicht belegt** |
| `nft -j list ruleset` (SSH) | **nur manuell** | 512 KB | aus | einige 10 KB, CPU-Stoß; dropbear-Logzeilen |
| Conntrack-Tabellendump | **nie** | – | – | – |

**Summe bei eingeschaltetem Standard** (S): etwa 2 + 1 + 12 = 15 zusätzliche Aufrufe je Stunde und Router. Heute sind es etwa 20–25 Aufrufe je Poll, also rund 1200–1500 je Stunde. Die Mehrlast liegt damit bei ≈ 1 %.

---

## 8. Umfang und Reihenfolge

Schätzung der Zeilen ohne Frontend:

| Teil | Code (S) | Tests (S) |
|---|---|---|
| Gemeinsame Schnittstelle, Records, Dedup, Store, Settings | 450 | 400 |
| Detektoren Gruppe a und Docking-Hooks | 700 | 700 |
| Empfangsweg A (Listener) | 350 | 350 |
| Empfangsweg B (Collector im Repo und Client in `api.py`) | 500 + 150 | 400 |
| Gruppe b (Abrufe, ACL v9) | 300 | 300 |
| Panel-Tab „Sicherheit“ (TS) | 600 | – |

Beide Wege zusammen vergrößern das Paket deutlich.

**Vorschlag (Q-ORDER):**

- **R1:** Schnittstelle, Weg A, Detektoren der Gruppe a, Hooks.
- **R2:** Weg B (Collector); die Schnittstelle ist dann schon fertig.
- **R3:** Gruppe b mit ACL v9.

Nichts davon fällt still weg.

---

## 9. DECIDED und QUESTION

### 9.1 DECIDED (klein, vom Master überstimmbar)

- **D-PREFIX:** neue Incident-Typen mit Präfix `sec_`. `incident_area` gibt `None` (`net_rules.py:5453`), also kein Einfluss auf den Health-Score.
- **D-REUSE:** Wo NI schon einen Incident hat, verweist das Security Center darauf und baut keinen neuen. Betroffen sind `system_reboot`, `wifi_auth_failures`, `wifi_auth_wave`, `wifi_mass_disconnect`, `dhcp_conflict`, `system_conntrack_jump`.
- **D-OBSERVER:** Das Security Center ist ein `PollObserver` am NI-Engine wie CS. Es gibt keinen zweiten Coordinator-Listener und kein zweites `log read`.
- **D-NODB:** keine eigene Client-Datenbank. Identität, Zeiten und Wechsel kommen aus CS; der Store hält nur Aggregate und Incident-Referenzen.
- **D-OFF:** Alles ist standardmäßig aus (`log_path: "off"`). Jede Erkennung meldet „nicht verfügbar“, solange ihre Quelle nichts liefert.
- **D-PORT:** Standard-Port 5514/udp (TCP optional), Collector-API auf 5515/tcp.
- **D-MODULES:** Der Listener steht in `security_syslog.py`, weil er eingehend arbeitet. Der Collector-Client steht im markierten Block in `api.py`, weil alle ausgehenden Aufrufe dorthin gehören.
- **D-RECORD:** `SecLogRecord` v1 mit Dedup-Schlüssel und Hochwassermarke je Router; genau ein Weg aktiv.
- **D-TRUST:** Syslog-Daten allein ergeben nie „bestätigt“.
- **D-COLLECTOR:** `contrib/security-collector/`, nur Standardbibliothek, eigene Tests, nicht im HA-Paket.
- **D-NOLOAD:** keine Conntrack-Dumps, kein periodischer WLAN-Scan, keine SSH-Abfrage im Poll.
- **D-ENTITIES:** keine Entities je Client. Am Flotten-Anker gibt es zwei Sensoren: aktive Sicherheitshinweise und Status des Log-Wegs.
- **D-WORDING:** „Hinweis“ und „Hypothese“; „bestätigt“ nur mit gemessenem Beweis.
- **D-SCHEMA:** Das Record-Format trägt eine Version und wird später an das Event-Schema von Enterprise Core angeglichen.

### 9.2 QUESTION

- **Q-HOOK:** Kleine markierte Hooks in `net_engine.py`, `net_rules.py`, `net_events.py`, `coordinator.py` (6.3, ca. 85 Zeilen) erlauben? Ohne sie kann das Security Center keine Incidents in die eine Engine geben.
- **Q-EVENT:** `sec_*` mit eigenem Bus-Event und eigenen Zählern, oder in den bestehenden mitzählen?
- **Q-CAP:** eigene Kappe 100 für `sec_*` im geteilten Store?
- **Q-SYSLOG:** Remote-Syslog auf den Routern einschalten? Befehle und Rückweg stehen in 4.10.
- **Q-FWLOG:** Firewall-Logging (Gateway, wan-Zone, `log_limit`)?
- **Q-DNSLOG:** dnsmasq-Abfragelog? Risiko: Ring-Verdrängung.
- **Q-STREAM:** ubus-Ereignisstrom (subscribe)? uhttpd-Absturz ist bekannt.
- **Q-FLOW:** volle Conntrack-Tabelle oder Flow-Export?
- **Q-ACL:** ACL v9 für Gruppe b: `nf_conntrack_max`, `/proc/net/snmp`, dnsmasq `metrics`. Ein ACL-Deploy schreibt eine Datei auf den Router und startet rpcd neu.
- **Q-UCI-FW:** `uci get firewall` regelmäßig abrufen (alle 30 min)?
- **Q-NFT:** nft-Zähler per SSH auf Anforderung?
- **Q-SCAN:** `iwinfo scan` nur manuell?
- **Q-TLS:** Transport zum Collector?
- **Q-PROXMOX:** Collector-LXC auf Proxmox einrichten? Befehle und Rückweg stehen in 4.10.
- **Q-ORDER:** Reihenfolge der Releases?
- **Q-NI-LOG:** `log read` der NI bei aktivem Empfangsweg reduzieren?
- **Q-LIVE:** Live-Leseprüfungen für alles „nicht belegt“ durch den Master nach Freigabe, nur lesend.
  - **Router**, je einer der Rollen Gateway, AP, Repeater:
    1. `uci show system | grep -E 'log_|hostname'`
    2. `ls /etc/init.d/ | grep -E '^log$'`
    3. `ps w | grep -E 'logd|logread' | grep -v grep`
    4. `uci show firewall | grep -E '\.(log|log_limit|counter)='`
    5. `uci show dhcp | grep -E 'logqueries|logfacility|logdhcp'`
    6. `ubus list | grep -E '^dnsmasq|^hostapd'`
    7. `ubus -v list | grep -A20 '^.dnsmasq'` (nur Methodenliste)
    8. `ubus call dnsmasq metrics` (Objektname aus Schritt 6; nur lesen)
    9. `cat /proc/sys/net/netfilter/nf_conntrack_max`
    10. `cat /proc/net/snmp | wc -c`
    11. `ip -6 neigh | wc -l`
    12. `ubus call luci-rpc getHostHints | grep -c ip6addrs`
    13. `nft list ruleset | wc -c`
    14. `logread | grep dropbear | tail -n 5`, maskiert vor der Weitergabe; Format von Fehlversuchen, nur falls vorhanden
    15. `logread -e 'uhttpd|rpcd' | tail -n 5`
    16. `apk list -I 2>/dev/null | grep -E 'conntrack|softflowd|banip|crowdsec|adguard|unbound'`
    17. `ubus call network.interface dump | grep -c dns-server`
  - **HA OS**, Host-Lesezugriff, nur lesend: `docker inspect homeassistant --format '{{.HostConfig.NetworkMode}}'`. Das zeigt, ob Core im Host-Netz läuft.

---

### 9.3 Entscheidungen des Masters (2026-11-17)

Diese Entscheidungen ersetzen die Empfehlungen in 9.2 und abweichende Angaben in den Abschnitten 6 bis 8.

| Frage | Entscheidung |
|---|---|
| Q-ORDER | R1 (Schnittstelle, Weg A, Detektoren Gruppe a, Hooks), dann R2 (Weg B, Collector), dann R3 (Gruppe b mit ACL). In R1 ist die Auswahl des Log-Wegs schon sichtbar; Weg B steht dort als „noch nicht verfügbar“, nicht versteckt |
| Q-HOOK | Erlaubt, aber erst in Stufe 4 (nach dem Merge von Enterprise Core), rein additiv und markiert. Tests müssen belegen, dass ohne aktives Security Center jedes bestehende Incident, jeder Zähler und jeder Sensorwert unverändert bleibt. Vorher prüfen, ob der Ereignisbus von Enterprise Core einen Teil der Hooks überflüssig macht |
| Q-EVENT | `sec_*` mit eigenem Ereignis über das `CoreEvent`-Schema und eigenen Zählern; nicht in die bestehenden Zähler mitzählen |
| Q-CAP | Eigene Kappe 100 für `sec_*` |
| Q-STREAM | Nein. Kein ubus-Ereignisstrom, solange der uhttpd-Absturz bekannt ist |
| Q-FLOW | Nein. Keine volle Conntrack-Tabelle, kein Flow-Export; nur Erweiterungspunkt |
| Q-UCI-FW | Nein. Kein eigener regelmäßiger `uci get firewall`; Firewall-Konfiguration und Änderungen kommen aus Snapshots und Drift-Ereignissen des Configuration Managers. Der Abruf entfällt damit in 6.2 und 7 |
| Q-NFT, Q-SCAN | Nur manuell auf Anforderung eines Admins über den Guard von Enterprise Core, nicht in R1; spätere Option |
| Q-TLS | Collector-API mit Pflicht-Token; TLS unterstützt und empfohlen, im reinen LAN-Betrieb abschaltbar mit deutlichem Hinweis. Der Collector lauscht standardmäßig nicht auf allen Schnittstellen |
| Q-NI-LOG | Vorerst nein. Der `log read` von Network Intelligence bleibt unverändert, auch bei aktivem Empfangsweg (mögliche Ersparnis siehe 4.8) |
| Q-ACL | Die Rechte für Gruppe b gehen in die gestufte ACL von Enterprise Core (je Fähigkeit einzeln zuschaltbar), keine eigene ACL v9 hier. Ob sie auf die Router kommen, gibt der Nutzer beim Deploy frei |

**Weiter offen, beim Nutzer** (Änderungen an seinen Geräten, werden gebündelt vorgelegt; nichts davon wird vorher ausgeführt): Q-SYSLOG, Q-FWLOG, Q-DNSLOG, Q-PROXMOX, Q-LIVE.

---

## 10. Gelesen und nicht gelesen

**Gelesen:**

- `coordinator.py` (`_async_poll`, `OpenWrtCoordinatorData`, `_ingest_log`, `_process_log`)
- `const.py`
- `api.py` (die in 1.1 genannten Methoden, `check_capabilities`, `get_dhcp_config`, Kommentare `:1889-1891`, `:4651`)
- `acl_provisioning.py`
- `log_parser.py`
- `net_events.py`
- `net_rules.py` (`DEFAULT_SETTINGS`, `AlarmMachine`-Kernstellen, `detect_reboot`, `detect_conntrack`, `detect_dhcp`, `decline_cause`, `finding_evidence`, `ROOT_TIERS`, Link-, Area- und Zählfunktionen)
- `net_engine.py` (`PollFacts`, `PollObserver`, `ingest`, `_run_machine`, `_announce`, `claim_fleet`/`withdraw_fleet`)
- `net_entities.py:1-130`
- `client_history.py` (Modell, Grenzen, Store)
- `client_engine.py` (Struktur, Settings, Unload)
- `topology_panel.py` (Routen, `_IntelView._check`)
- `client_views.py` (Routen)
- `topology_ports.py:245-284`
- `diagnostics.py`
- `__init__.py` (RuntimeData, Setup, Unload)
- `ubus_stream.py:1-70`
- Tests: `tests/test_log_parser.py:1-140`, `tests/test_net_infra.py:235-275`, `tests/test_poll_no_ssh.py:1-20`; Grep über `tests/` und `scripts/mock_router.py`
- Doku: `docs/network-intelligence.md`, `docs/realtime-rca.md`, `docs/plans/2026-11-16-client-stability.md`

**Nicht gelesen** (Aussagen dazu fehlen bewusst):

- `fleet.py`, `dhcp_health.py`, `mac_utils.py`, `oui.py`, `issues.py`, `extended_sensors.py`, `device_tracker.py`, `client_entities.py` (nur Kopf)
- Rest von `ubus_stream.py`
- `tests/test_net_rt_log.py`, `test_net_rt_scenarios.py`, `test_net_wifi.py` (nur Grep)
- Frontend
- Branches `claude/enterprise-core-49ade2` und `claude/config-manager-d9fdac`

### Quellen außerhalb des Repos

Geprüft:

- OpenWrt `package/system/ubox/files/log.init` (raw.githubusercontent.com, openwrt/openwrt, Zweig main)
- ubox `log/logread.c` (openwrt/ubox, Zweig master)
- firewall4 `templates/ruleset.uc`, `templates/zone-verdict.uc`, `templates/rule.uc`, `root/etc/config/firewall`, `ucode/fw4.uc` (openwrt/firewall4, Zweig master)
- OpenWrt `package/network/services/dnsmasq/files/dhcp.conf` und `dnsmasq.init` (Zweig main)

**Stand master/main, nicht gegen den 25.12-Tag geprüft.**

Nicht erreichbar:

- `openwrt.org` (Bot-Schutz): Seiten `system_configuration`, `log.essentials`
- dnsmasq-Upstream-Git (`cache.c`, `ubus.c`; Login-Sperre)

HA:

- `contributors.home-assistant.io/os/operating-system/` und `/networking/`: keine Aussage zu Host-Netz oder Ports des Core-Containers.
- Developer-Blog, 25 neueste Beiträge (Index jetzt unter `contributors.home-assistant.io/blog/`). Relevant für den späteren Bau:
  - „DeviceInfo is now a dataclass“ (2026-10-13): nur noch Keyword-Konstruktion; `via_device` → `via_device_id`.
  - „Deprecated device info constants“ (2026-11-10).
  - „Config entry functions now return None“ (2026-10-23): Custom-Integrationen dürfen weiter `bool` liefern.
  - „Repair issues can belong to a config entry, and be refreshed“ (2026-10-28): für Hinweise wie „Remote-Syslog nicht aktiv“.
  - Kein Beitrag zu Listen-Sockets, Store, Coordinator oder HTTP-Views.
