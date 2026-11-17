# Plan: Enterprise Active Network Diagnostics — Phase A (Bestandsaufnahme)

<!-- Ablage: docs/plans/2026-11-17-net-diagnostics.md · Branch claude/net-diagnostics-f989ed
     (Stand main @ 0dc20cd, v1.42.0). Keine IPs, MACs, Hostnamen echter Geräte, Passwörter
     oder Tokens. Rollen statt Namen (Gateway, AP, HA). -->

Kennzeichnung wie in den Plänen vom 2026-11-16: **verifiziert** (mit `datei:zeile`, Stand
`0dc20cd`, Pfade relativ zu `custom_components/openwrt_router/`), **Annahme** (mit Prüfweg),
**Vorschlag** (Planentscheidung, Freigabe durch den Master), **DECIDED:** (kleine Entscheidung
dieser Sitzung, vom Master überstimmbar), **nicht belegt** (offen, siehe Abschnitt 8).

## Status

- **Stand:** 2026-11-17 · **Phase:** A (nur Bestandsaufnahme und Messwege, kein Code).
- **Branch:** `claude/net-diagnostics-f989ed` · Basis `main@0dc20cd` (1.42.0).
- **Grenzen dieser Sitzung:** nur dieses Dokument geschrieben. Kein Kontakt zu Router, HA,
  Host, VM oder Drucker, keine Pings/DNS/HTTP ins Netz, keine Installation, kein Commit.
  Ausnahme: öffentliche Doku per WebFetch (HA-Contributor-Blog, Abschnitt 9).
- **Externe Befunde** (Router als Messpunkt) stammen aus der Recherche-Notiz der
  Schwestersitzung (Abschnitt 5) und sind mit Quell-URLs übernommen; sie sind
  **nicht** auf echten Routern geprüft.
- **Regel für alles Folgende (Auftrag):** schwere oder häufige Messungen nicht auf den
  Routern. Routerseitige aktive Tests sind **standardmäßig AUS** und hängen an einer
  Capability-Prüfung.

---

## 0. Kurzfazit

1. **Erreichbarkeit der Router-Verwaltung ist schon gut abgedeckt** (Poll-Erfolg,
   `consecutive_failures`, `FleetOutageTracker`, Incidents `router_unreachable` /
   `lan_unreachable`). Neu bauen wäre eine Dublette.
2. **Es gibt bereits eine aktive HA-Messung, die falsch beschriftet ist:** jeder Coordinator
   öffnet je Poll eine TCP-Verbindung von **HA** zu `8.8.8.8:53` (`coordinator.py:769-805`),
   Ergebnis `ping_ms`. Das Frontend zeigt es als „Ping (8.8.8.8)“ des **Gateways**
   (`frontend/topology/src/components/DetailPanel.tsx:100`, `InternetNode.tsx:11-19`). Es misst
   aber HAs Internetweg, nicht den des Routers, und läuft bis zu sechsmal pro Minute
   (einmal je Router) mit identischem Ergebnis.
3. **Viele Daten werden gelesen und weggeworfen:** `network.interface dump` liefert je
   Interface `route` (mit `nexthop`), `dns-server`, `ipv6-address`; `get_wan_status`
   (`api.py:1948-2076`) behält nur die erste IPv4, `default_route` (bool) und Zähler. Der Dump
   wird zudem **zweimal pro Poll** geholt (`api.py:1948` ff. und `api.py:4230-4297`).
   Gateway-Wechsel, DNS-Server der WAN und IPv6-Status sind damit **ohne neuen
   Router-Aufruf** auswertbar (Feldnamen **nicht belegt** in Fixtures, Abschnitt 8).
4. **Für Ping, Vorwärts-DNS und Traceroute auf dem Router gibt es kein ubus-Objekt**; nur
   `file exec` oder SSH (Abschnitt 5). Heute erlaubt die Projekt-ACL `file exec` nur für
   `/etc/init.d/rpcd` (`acl_provisioning.py:135`). Jeder routerseitige aktive Test braucht
   eine ACL-Erweiterung (= Routeränderung, Freigabe nötig) und ist daher Phase-C-Stoff.
5. **Korrelations-Falle:** `lan_unreachable` übernimmt **jedes** Incident und Event in seinem
   Fenster als Kind (`net_rules.py:5186-5187`, `5287-5288`), `wan_down` übernimmt **alle**
   DNS-Events aller Router (`net_rules.py:5312-5318`). Neue Diagnose-Incidents brauchen
   eigene, explizite Link-Regeln, sonst werden sie stumm geschluckt oder schlucken selbst.

---

## 1. Bestandsaufnahme

### 1.1 `OpenWrtAPI` (`api.py:1105`)

| Thema | Ort | Befund (**verifiziert**) |
|---|---|---|
| Transport | `api.py:1113-1310` (`__init__`), URL `api.py:1166` | `aiohttp.ClientTimeout(total=timeout, connect=5)`, `DEFAULT_TIMEOUT=10` (`const.py:36`). Standard `root`, Port 443, `https-insecure` (`const.py:11-13`) |
| Session | `api.py:1397-1483` (`login`) | alte Session wird zerstört; Lebensdauer 300 s, Refresh-Marge 60 s (`const.py:42-43`) |
| Aufrufkern | `api.py:5170-5256` (`_call`), `5324-5435` (`_raw_call`) | Auth-Backoff, ACL-Blocked-Cache (`_acl_cache_key` `api.py:5271`: `file` je Pfad/Kommando, `uci` je Config), Re-Login bei Code 6. **Keine Zeitmessung je Aufruf** |
| Capability-Probe | `api.py:1563-1625` (`check_capabilities`) | prüft system info, network dump, file read/list, luci-rpc dhcp, iwinfo, uci get, hostapd, network.wireless, LLDP. **Nur im Config-Flow** genutzt, nicht zur Laufzeit |
| Router-Status | `api.py:1732-1828` | `system info`: uptime, load, cpu_load, memory, localtime; SSH-Rückfall `/root/ha-system-metrics.sh` |
| WAN | `api.py:1948-2076` (`get_wan_status`) | `network.interface dump`; Auswahl über `wan_interface_tier`. Liefert `connected`, `interface`, `ipv4` (nur erste Adresse), `uptime`, `proto`, `wan_found`, `rx/tx_bytes`, `default_route` (bool aus Route `0.0.0.0/0`, `api.py:2068-2075`). **Nicht** extrahiert: `nexthop`, `dns-server`, IPv6. SSH-Rückfall `api.py:3399` nur connected + Zähler |
| Interfaces | `api.py:4230-4297` | zweiter `network.interface dump` je Poll; behält interface/logical_name/status/erste IPv4/Prefix; SSH-Rückfall `ip -o addr show; ip link show` |
| Geräte/Ports/VLAN | `api.py:4211` (`network.device status`), `api.py:4392` (`get_port_vlan_map`, `uci get network` je Poll) | bridge-vlan/switch_vlan; **Routen-Tabellen und Firewall werden nicht gelesen** |
| DHCP | `api.py:3825` (`get_dhcp_leases`: Datei `/tmp/dhcp.leases`, Rückfall `luci-rpc getDHCPLeases` `api.py:3868`), `api.py:3944` (`get_dhcp_config`: `uci get dhcp`) | nur IPv4-Leases; kein odhcpd-`dhcp`-Objekt, kein `dnsmasq metrics` (grep: keine Treffer) |
| Sonstiges | `api.py:4843` (conntrack count), `api.py:4987` (`service list` + `rc list` 6 h), `api.py:5731` (`get_ddns_status`: `/etc/config/ddns`, `/var/run/ddns/<s>.ip/.err/.update`), `api.py:5855` (`async_subscribe`, SSE) | DDNS-`ip` = per DDNS gemeldete öffentliche IP (einzige Quelle einer öffentlichen IP heute) |
| SSH | `api.py:3016-3040`, `3075`, `3065`, `3166`, `3205` | eine asyncssh-Verbindung je Instanz, Port 22, **`known_hosts=None`** (kein Host-Key-Check), Freigabe nach jedem Poll (`coordinator.py:668-680`). F5-Aggregator-Gerüst wirft `NotImplementedError` (`api.py:3244-3308`) |
| Schreibaufrufe | `api.py:5140-5160` (`control_service` → `rc init`), wireless up/down, `network reload`, `system reboot`, `uci set/commit` | — |
| `_safe_subprocess_exec` | `api.py:228` | keine Aufrufer in Produktion |

### 1.2 `OpenWrtCoordinator` (`coordinator.py`)

- **Intervalle (verifiziert):** 60 s Standard (`const.py:61`), 120 s gedrosselt (`const.py:63`),
  300 s bei SSH-Rückfall (`const.py:66`); Staffelung `_handle_refresh_interval`
  (`coordinator.py:607`). Drossel bei CPU > 100 %, zurück unter 80 %
  (`coordinator.py:1244-1270`, `_interval_for_state` `1274`).
- **Zyklen:** Board alle 10 Polls (`const.py:71`), LLDP 600 s (`const.py:416`), SSH-Slow 600 s
  (`const.py:423`), `rc list` 6 h (`const.py:443`), Topologie-Snapshot alle 10 Polls
  (`const.py:475`), Log jeden Poll ab Poll 2 (`const.py:519`), DHCP-Config 10 / Retry 60
  (`const.py:537/540`), usteer 2 / Retry 30 (`const.py:549-550`).
- **Reihenfolge `_async_poll` (`coordinator.py:682-1272`):** Board → WAN → WLAN → Leases →
  Clients → AP/STA → wan_traffic → **HA-TCP-Probe 8.8.8.8:53 (`769-787`)** → DDNS nur bei
  `wan_connected` (`789-801`) → first_seen → Router-Status → Disk/tmpfs → device status →
  Interfaces → Ports → VLAN-Karte → FDB → ARP → Trunk-Karte → LLDP → Log → DHCP-Config/Pools
  (übersprungen, wenn dnsmasq gestoppt, `coordinator.py:978`) → usteer → CPU-Historie →
  Topologie → Raten → conntrack → Dienste.
- **Fehler:** `UpdateFailed` (`coordinator.py:1125-1199`), `_record_failure`
  (`coordinator.py:1386-1401`) meldet nach 3 Fehlschlägen (`const.py:186`) an den
  Outage-Tracker. SSH-Rückfall-Hinweis `coordinator.py:1213`.
- **`coordinator.data` = `OpenWrtCoordinatorData` (`coordinator.py:298-430`):** router_info,
  uptime, cpu*, memory, memory_pressure, wan_status, wan_connected, wifi_radios, clients,
  client_count, dhcp_leases, disk_space, tmpfs, network_interfaces, port_stats,
  active_connections, updates_available, services, localtime(_at), service_instances,
  wan_status_at, service_actions, wifi_actions, ap/sta_interfaces, features, wan_traffic,
  **ping_ms, ping_checked**, ddns_status, events, cpu_history, port_vlan_map, port_fdb_map,
  arp_table, topology_snapshots, trunk_port_map, lldp_neighbors/status, log_status/stats,
  new_log_events/batch, dfs, dhcp_pools, dhcp_static_macs, client_stability, usteer_connected,
  vlans_stale, error_type, consecutive_failures, last_seen. `as_dict` (`coordinator.py:432-475`)
  für Diagnostics.

### 1.3 `runtime_data` (`__init__.py`)

- `OpenWrtRuntimeData` (`__init__.py:78-90`) = `api` + `coordinator`; Alias
  `OpenWrtConfigEntry` (`__init__.py:94`).
- Setup (`__init__.py:243-480`): login → `ensure_acl` → `reset_acl_blocked` → Staffel-Offset →
  First Refresh → runtime_data → Outage-Tracker → NI-Engine + Listener (`395-420`) + Client
  Stability → Kanalplan → Plattformen (sensor, switch, device_tracker, button, binary_sensor) →
  Panel.
- Unload (`__init__.py:483-563`): Flotte zurückziehen, Plattformen, Panel, dann NI- und
  CS-Unload nur bei `unload_ok`, zuletzt `api.async_close`. `async_remove_entry` (`566`).
- **Router-Identität heute = `entry_id`.** Eine stabile Router-ID gibt es auf `main` nicht
  (Abschnitt 6).

### 1.4 NI-Engine, Regeln, Incidents, Root Cause

**Ablauf (verifiziert):**

1. Singleton in `hass.data` (`net_engine.py:193`, `322-336`). Ingest je Poll:
   `async_ingest_coordinator` (`net_engine.py:731`) → `ingest` (`756-877`): Detektoren,
   Automat, **Poll-Beobachter** (`PollFacts` `267-305`, `PollObserver` `308-318`,
   `add_poll_observer` `881`). Der Beobachter-Hook ist der Erweiterungspunkt ohne zweiten
   Coordinator-Listener (so nutzt ihn Client Stability).
2. Detektoren (`net_rules.py`): `detect_infrastructure` (`1959-1998`: Reboot, CPU, RAM, Uhr,
   conntrack, Dienste, LLDP, Ports, WAN, DHCP); `detect_wan` (`2801-2896`) wertet **nur auf
   einem Gateway** (connected und `default_route` nicht False) und erzeugt
   `wan.failover`, `wan.status`→`wan_down`, `wan.down`, `wan.up`/`wan.reconnect`→
   `wan_unstable`, `_wan_ip` (`2956`) → `wan.ip_changed` (**nur IPv4**; IPv6-only-WAN wird
   übersprungen, `net_rules.py:2793`); `detect_dhcp` (`2988`) nur Pool-Auslastung.
   DHCP-Konflikte nur aus `DHCPDECLINE`-Logzeilen, kein ARP-Konfliktdetektor.
3. Ausfall-Evidence: `_outage_evidence` (`net_engine.py:987-1093`) macht aus dem Tracker
   `router_unreachable` / `lan_unreachable`; Auth-Fehler zählen nicht.
   `lan_unreachable` = alle geladenen Router (mind. 2) weg → Problem liegt bei HA/LAN
   (`fleet.py:1-23`).
4. `AlarmMachine` (`net_rules.py:678`, Doku `679-722`): **ein Incident je (Typ, scope_key)**;
   Typen ohne Regel in `DEFAULT_SETTINGS` (`net_rules.py:130-232`) → Evidence wird ignoriert;
   `ignored` = stumm; `acknowledged` meldet nur noch `resolved`.
5. `_run_machine` (`net_engine.py:968`): update → `_build_topology` (`1122`) → `correlate`
   (`net_rules.py:834-931`) → `_refresh`. Filter/Ausnahmen/Wartung `_filter_evidence`
   (`net_engine.py:1465`), `set_maintenance` (`1381`).

**Wie Wurzeln entschuldigen und verknüpfen (verifiziert):**

- Wurzeltypen und Rang `ROOT_TIERS` (`net_rules.py:4727-4738`): `lan_unreachable` 1;
  `router_unreachable`, `system_reboot` 2; `wan_down` 3; `wifi_radio_change` 4;
  `lan_uplink_down` 5; `lan_port_flap` 6; `wifi_mass_disconnect` 7; alles andere Kind (8).
  Zeitfenster `_ROOT_WINDOWS` (`4754-4763`).
- `correlate` verknüpft Kandidaten im Fenster mit der besten Wurzel (`_RootView.rank`:
  `lan_unreachable` zuerst, dann bestätigt, dann höherer Rang, dann tiefer in der Topologie).
  `_link` (`5402`) setzt `parent_id` und geerbte Ursache; Hypothese kappt Konfidenz auf 0,6.
  `_release_children` (`933`): Freigabe `CHILD_RELEASE_AFTER` 3600 s nach Wurzelfenster.
- `_incident_link` (`net_rules.py:5164-5214`):
  - `lan_unreachable` → **jedes** Incident im Fenster, bestätigt (`5186-5187`).
  - `router_unreachable`/`system_reboot` → `_router_link` (`5258`): Incidents des Routers
    bzw. der Router dahinter, die ebenfalls weg sind; am Gateway `wifi_no_ip` /
    `dhcp_after_connect` als Hypothese.
  - `wan_down` → nur `_WAN_CHILDREN` = `wan_unstable`, `wan_ip_changed` (`4769`) desselben
    Routers (`5190-5192`).
  - `wifi_radio_change` → nur `wifi_mass_disconnect`; `lan_uplink_down` → Router dahinter;
    `lan_port_flap` → `_PORT_FLAP_CHILDREN`; `wifi_mass_disconnect` → Client-Incidents als
    Hypothese.
- `_event_link` (`net_rules.py:5283-5320`): `lan_unreachable` → **alle** Events;
  Router-Wurzeln → Events der betroffenen Router in `_ROUTER_EVENT_CATEGORIES`, Roams weg vom
  Router, LAN-Events am zugewandten Port; `wan_down` → **alle DNS-Events jedes Routers**
  plus WAN-Events (außer `wan.down`) des Routers (`5312-5318`).
- Unterdrückung: `suppressed_child` (`5482-5507`) — Kind ist stumm, solange die Wurzel offen
  ist und im Nachfenster; danach zählt es nur mit eigener Evidence. `counted_incidents`
  (`5660`) nutzt dieselbe Regel für Score und Entities, `counts_for_router` (`5675`).
- Ankündigung `_announce` (`net_engine.py:1817-1883`): `EVENT_INCIDENT` nur für aktive,
  nicht unterdrückte Incidents ≥ `notify_min_severity`, nicht alle in Wartung, nach Settle
  max(90 s, längstes Intervall + 30 s), nicht solange ein Router spät ist (1,25×–4×
  Intervall), Halten max. 900 s (`const.py:596-605`). Veröffentlichung `_publish`
  (`net_engine.py:1941-2009`, Score `router_score`, `area_inputs` `net_rules.py:2398`),
  Dispatcher `SIGNAL_NET_INTEL`.
- DNS heute: `LOG_EVENT_META` (`net_rules.py:1749-1775`) — `dns.query_limit`,
  `dns.no_servers` als Hypothese „dns_resolution“ mit Konfidenz 0,5, **nur Events, keine
  Incident-Regel**. Score-Bereich `dhcp_dns` deckt das Präfix `dns_` ab (`5440-5447`).
  Parser: `log_parser.py:94-96` (query_limit, no_servers, send_failed); odhcpd-Fehler nur
  gezählt (`log_parser.py:126-127`); Kopf `log_parser.py:1-20`: netifd/procd/odhcpd/
  dnsmasq-Zeilenformen nicht live gesehen, „keine Übereinstimmung = keine Daten, nie gesund“.

### 1.5 Client Stability als Persistenzmodell (`client_engine.py`, `client_history.py`)

**verifiziert** — Vorlage für einen späteren Diagnose-Store:

- Schlüssel in `hass.data` `_DATA_KEY` / `_FLUSH_KEY` (`client_engine.py:101-102`); hängt sich
  als NI-Beobachter an (`attach`, `643`), **macht keine Router-Aufrufe** (Doku `1-17`).
- `async_load` (`529`) mit `.bak` bei Schaden; `schedule_save` (`583`) setzt dirty und genau
  ein `async_delay_save` (300 s, `const.py:624-630`).
- Größenlimit: `_data_to_save` (`596`) misst mit `prepare_save_json` (`_store_size` `913`),
  Standard 3 MB, einstellbar 1–8. `_trim` (`619`) in Stufen: Übergänge offliner Clients →
  private geschlossene Stunden > 48 h → alle geschlossenen Stunden → älteste verwerfen.
- Kompaktierung: geschlossene Stunden-Buckets werden in Tages-Buckets gefaltet;
  `HOURS_KEEP` 168, Aufbewahrung 30 (max. 90) Tage, Übergänge 24 h / max. 64, Roh-Ring 1 h /
  120 (nicht gespeichert), `MAX_CLIENTS` 1000 (`client_history.py:130-161`; `prune` `928`,
  `trim_*` `957-995`, `to_dict`/`from_dict` `1576`).
- Flush beim Entladen: `async_unload_client_stability` (`client_engine.py:472`) einmal nach
  dem letzten Router, nur wenn dirty, mit Claim-Future (gleiches Muster wie NI
  `net_engine.py:384-406`, `717`, `725`).
- Infra-Wurzeln: `infra_roots` (`226`), `INFRA_ROOT_TYPES` = `ROOT_TIERS` ohne `wan_down`
  (`107`), Fenster 300 s.

### 1.6 Topologie-Uplinks

- `build_topology` (`net_rules.py:4903-5016`): LLDP-Kanten (beobachtet) per BFS ab Gateways,
  dann ARP+FDB (abgeleitet, nächster Elternrouter), dann gemerkte Kanten bis 24 h.
  `Topology` (`4853`) mit `chain`/`behind`/`observed_path`. Gateways aus `_wan_gateways`.
- Mesh für das Panel: `topology_mesh.py`; `ping_ms` wird nur an Gateway-Knoten gehängt
  (`topology_mesh.py:1821-1840`, Kommentar dort sagt fälschlich, nur Gateways hätten den
  Wert — jeder Coordinator misst ihn).
- Für Diagnose relevant: Die Kette AP → (Switch) → Gateway → WAN ist aus `Topology.chain`
  ableitbar; damit kann eine Messung „AP erreicht Gateway“ einer Kante zugeordnet werden.

### 1.7 Sensoren und Binary Sensoren

- `sensor.py:131-484` (Beschreibungen): uptime, wan_status, client_count, cpu_load, memory*,
  wan_ip, wan_rx/tx, firmware, update_status, disk/tmpfs, active_connections, log_status,
  dfs_events_24h, unstable_clients. Klassen: Interface `765`, InterfaceRate `841`, Radio `918`,
  APInterface `985`, Port `1147`, RouterStatus `1347`, ChannelPlan `1420`, DhcpPool `1485`.
- `binary_sensor.py`: connectivity (`65`), wan_connectivity (`84`), sticky_clients (`157`).
- `net_entities.py`: je Router NetHealth, IncidentsActive, WifiReconnects, WifiAuthErrors,
  WanStability, IncidentCritical, MaintenanceModeSwitch; Flotte Health, Incidents,
  IncidentCritical. Dazu `topology_entities.py`, `client_entities.py`.
- **Kein Entity für `ping_ms`.** Keine Latenz-, DNS- oder Erreichbarkeits-Sensoren außer
  connectivity/wan_connectivity.

### 1.8 `diagnostics.py` (Redaktion)

- `_redact` (`diagnostics.py:192-205`): erst `async_redact_data` mit exakten Schlüsseln
  `DIAGNOSTICS_TO_REDACT` (`const.py:265-284`: address, bssid, chassis_id, domain, host,
  hostname, ip, ipv4, ipv4_addr, ipv4_address, mac, management_ip, router, ssid, ssids,
  username, web_url), dann Teilstring-Treffer `DIAGNOSTICS_REDACT_KEYS` (`const.py:254-261`:
  password, token, ubus_rpc_session, secret, key, auth).
- Client-Listen → Zählwerte (`_client_summary` `166`), LLDP-Felder einzeln geschwärzt (`79-91`),
  Client-Stability-Listen → „<n clients redacted>“ (`103-108`), NI nur Zähler
  (`_intelligence_summary` `142`).
- **Folge für Diagnose:** neue Felder wie `nexthop`, `dns_servers`, `ipv6`, `target`,
  `public_ip` würden **nicht** geschwärzt (kein exakter Schlüssel, kein Teilstring).
  Neue Felder müssen in `DIAGNOSTICS_TO_REDACT` (**Vorschlag**).

### 1.9 HTTP/WS-Routen und Zugriff

- `topology_panel.py`: Panel `openwrt-topology`, statischer Pfad `/openwrt_router_topology`.
  Snapshot `/api/openwrt_topology/snapshot` (`132-178`): `requires_auth`, Admin, außer
  `topology_panel_all_users`, sonst 403; 410 nach letztem Unload.
- `_IntelView` (`topology_panel.py:202-292`): Schreiben nur Admin (403), Lesen Admin oder
  Panel offen (403), 410 deaktiviert, 503 Engine nicht geladen, Fehlertext nur Exception-Typ.
  Routen `/api/openwrt_topology/intelligence/` summary (`299`), events (`312`), incidents
  (`330`), incidents/{id} (`348`), settings (`387`). `client_views.py:780-849`: clients,
  clients/aps, clients/settings, clients/{mac}. Registrierung einmalig je HA-Sitzung
  (`topology_panel.py:575-584`, `_api_views()`).
- **Keine WebSocket-Befehle** in der Integration (grep `websocket`: keine Treffer). Keine
  Dienste (`hass.services.async_register`: keine Treffer).
- **Vorschlag:** Diagnose-Routen als `_IntelView`-Unterklassen unter
  `/api/openwrt_topology/intelligence/diagnostics/...` mit denselben Prüfungen; ein
  „Jetzt testen“-POST (aktive Messung auf Anforderung) **nur Admin** und mit Rate-Limit.

### 1.10 Frontend und Einhängepunkt

- `frontend/topology/src/components/Sidebar.tsx:16`: `SidebarTab` = topology, devices,
  clients, traffic, alerts, **diagnose**, compare, wiring, settings; Einträge `38-50`
  (deutsche Beschriftung, „Diagnose“ nur bei laufender NI, `showDiagnose`).
- `DiagnoseView.tsx` (835 Zeilen, Kopf `1-10`): NI-Tab mit Übersicht, Incidents, Timeline,
  WLAN, Client-Stabilität, Infrastruktur, Detail, Einstellungen; liest nur
  `/api/openwrt_topology/intelligence/*`, aktualisiert mit dem Snapshot (30 s), **kein
  eigener Timer**.
- API-Client `api.ts` (`fetchTopologyData` `1043`, Intel-Fetch `1112`, `IntelApi` `1167`;
  `ping_ms` `77`, `684-687`).
- **Einhängepunkt (Vorschlag):** Es gibt kein „Enterprise“-Menü. „Network Diagnostics“
  sollte **ein Unter-Tab in `DiagnoseView`** werden (neben Infrastruktur), nicht ein neuer
  Sidebar-Eintrag „Diagnose 2“ — sonst zwei gleichnamige Bereiche. Ein späterer
  Sidebar-Bereich „Enterprise“ hängt an der enterprise-core-Sitzung (Abschnitt 6).
  DECIDED: Arbeitstitel im UI „Netzwerkprüfung“, um Verwechslung mit dem Tab „Diagnose“
  zu vermeiden — kurz und deutsch wie die übrigen Tabs.

---

## 2. Je Diagnosebereich: (a) heute · (b) HA misst selbst · (c) Router als Messpunkt

Allgemein zu (b): HA misst **von HAs Netzposition** aus. Ein Ergebnis belegt den Weg
HA → Ziel, nicht den Weg Router → Ziel. HA-Kern bringt `aiodns` mit (**verifiziert** lokal:
`homeassistant` 2026.2.3 verlangt `aiodns==4.0.0`, 2026.11.2 `aiodns==4.0.4`), also sind
DNS-Abfragen an einen gewählten Server ohne neue Requirement möglich. ICMP aus HA:
**nicht belegt** (unprivilegierte ICMP-Sockets je nach HA-Installationsart; `icmplib` ist
keine Kern-Abhängigkeit). TCP-Connect ist überall möglich.

Zu (c): Details, ACLs und Quellen in Abschnitt 5. Alles in (c) ist standardmäßig AUS.

### 2.1 Erreichbarkeitskette

| Glied | (a) heute | (b) HA misst selbst — belegt / belegt nicht | (c) Router als Messpunkt |
|---|---|---|---|
| Router-Verwaltung (ubus) | Poll-Erfolg, `consecutive_failures`, `last_seen`, `error_type` (`coordinator.py:298-430`); Tracker + `router_unreachable`/`lan_unreachable` (`net_engine.py:987-1093`); binary `connectivity` (`binary_sensor.py:65`) | Dauer je ubus-Aufruf (fehlt: `_raw_call` misst nicht, `api.py:5324-5435`). Belegt: rpcd/uhttpd antwortet und wie schnell. Belegt nicht: Paketverlust, Ursache (CPU vs. Netz) | entfällt (der Router misst sich nicht selbst) |
| Router-Interface (LAN/WAN up) | `network.interface dump` je Poll (`api.py:1948`, `4230`), `network.device status` (`api.py:4211`), Port-Zähler | — (HA sieht Interfaces nur über den Router) | gleiche Daten; mehr nicht nötig |
| Gateway (Nexthop der WAN) | nur `default_route` bool (`api.py:2068-2075`); `nexthop` im Dump vorhanden, aber verworfen (Feld **nicht belegt** in Fixtures) | HA kann den Upstream-Gateway des Gateways meist nicht erreichen (anderes Netz, NAT). Belegt nichts über die WAN-Strecke | Ping des Nexthops vom **Gateway**: braucht `file exec` (Abschnitt 5). Belegt: L3 bis zum Provider-Router |
| Interne Ziele (AP → Gateway, Gateway → AP) | Topologie-Kanten LLDP/ARP+FDB (`net_rules.py:4903-5016`), Port-Status | TCP-Connect HA → Router-Verwaltungsport schon implizit im Poll. Belegt: HA ↔ Router. Belegt nicht: AP ↔ Gateway direkt | Ping vom AP zum Gateway: braucht exec. Belegt: Backhaul-Strecke |
| Externe IP | HA-TCP-Probe 8.8.8.8:53 je Coordinator (`coordinator.py:769-787`) → `ping_ms` | Ein zentraler Probe genügt (nicht je Router). Belegt: HA hat Internet. Belegt nicht: Gateway hat Internet (HA kann z. B. über anderen Weg gehen; Annahme: meist derselbe Weg) | Ping vom Gateway zu Referenzzielen: exec. Belegt: Internet aus Sicht des Gateways |
| DNS | nur Logzeilen-Events (Abschnitt 2.2) | `aiodns` an Router-Resolver. Belegt: dnsmasq des Routers antwortet HA | `nslookup` auf dem Router: exec |
| HTTP | — | HTTP-GET HA → Referenz-URL über `async_get_clientsession`. Belegt: HA-Internet inkl. TLS. Belegt nicht: Router-Sicht | `wget`/`uclient-fetch` auf dem Router: exec; **nicht** vorgeschlagen (Last, Missbrauchsfläche) |

### 2.2 DNS

| Teil | (a) heute | (b) HA misst selbst | (c) Router als Messpunkt |
|---|---|---|---|
| Resolver-Dienst läuft | `service list` (dnsmasq in `DEFAULT_SERVICES`, `const.py:561`; Detektor Dienste in `detect_infrastructure`) | — | gleich |
| Resolver antwortet | Logzeilen `dns.query_limit`/`no_servers`/`send_failed` (`log_parser.py:94-96`), nur Events, Hypothese 0,5 (`net_rules.py:1749-1775`), keine Incident-Regel | A-Abfrage per `aiodns` direkt an den LAN-Resolver jedes Routers, 1×/5–15 min. Belegt: dnsmasq antwortet HA, Upstream erreichbar (bei Nicht-Cache-Namen). Belegt nicht: was Clients am AP sehen, wenn sie einen anderen Resolver nutzen | `nslookup <name> 127.0.0.1` (exec). Belegt: lokaler Resolver aus Router-Sicht |
| Upstream-Server | `dns-server` im Dump vorhanden, verworfen | Abfrage HA → Upstream direkt: belegt nur HA-Weg | — |
| Statistik | — | — | `dnsmasq metrics` (ubus, ohne exec): Weiterleitungen, unbeantwortet, Cache. ACL fehlt im Projekt; Schlüssel **nicht belegt** |
| Reverse-DNS | — | — | `network.rrdns lookup`: nur PTR, beliebiger Server → SSRF-relevant, **nicht verwenden** |

### 2.3 DHCP

| Teil | (a) heute | (b) HA misst selbst | (c) Router als Messpunkt |
|---|---|---|---|
| Dienst | `service list` dnsmasq/odhcpd (`net_rules.py:192`), Pools übersprungen bei gestopptem dnsmasq (`coordinator.py:978`) | — | gleich |
| Leases | `get_dhcp_leases` (`api.py:3825`, Datei, Rückfall luci-rpc `3868`) | — | odhcpd `dhcp ipv4leases`/`ipv6leases` (ubus, ohne exec; ACL fehlt) |
| Pool-Auslastung | `dhcp_health.pool_usage`, `detect_dhcp` (`net_rules.py:2988`), Schwellen 90/85 (`net_rules.py:130-232`), `DhcpPool`-Sensor (`sensor.py:1485`) | — | — |
| Konflikte | nur `DHCPDECLINE`-Logzeilen | HA sieht keine Duplikate (kein L2-Zugriff auf alle Segmente). Doppelte IP mit zwei MACs in `arp_table`/Leases über die Flotte ist **heute schon in den Daten**, aber nicht ausgewertet | `arp-scan` braucht exec + Paket; **nicht** vorgeschlagen |
| DHCPv6/RA | nicht gelesen; `parse_dhcp_config` nur IPv4 (`dhcp_health.py`) | — | odhcpd `dhcp ipv6ra` (ubus, ohne exec, ACL fehlt); `uci get dhcp` (`api.py:3944`) liefert ra/dhcpv6-Optionen vermutlich schon heute mit, wird aber nur für IPv4 ausgewertet (**Annahme**, Prüfweg: Live-Form oder Fixture) |
| Antwortprobe | — | DHCP-Discover von HA: braucht Raw-Socket, stört Leases → **nicht** vorgeschlagen | `dnsmasq metrics` DHCP-Zähler (offer/ack/nak/noanswer) |

### 2.4 VLAN & Routing

| Teil | (a) heute | (b) HA misst selbst | (c) Router als Messpunkt |
|---|---|---|---|
| VLAN-Belegung | `get_port_vlan_map` (`api.py:4392`), `trunk_port_map`, `vlans_stale` | — | gleich |
| Interfaces/Subnetze | erste IPv4 + Prefix je Interface (`api.py:4230-4297`) | Erreichbarkeit HA → Router-IP je Subnetz: belegt nur Routing von HA aus | — |
| Routing-Tabelle | nicht gelesen; Routen je Interface im Dump (verworfen) | — | `network.interface dump` `route` je Interface (ohne exec, schon erlaubt). Vollständige Tabelle (`ip route`) nur per exec/SSH |
| Firewall/Zonen | nicht gelesen | — | `uci get firewall` (bestehendes `uci get`-Recht; Inhalt ist Konfiguration, gehört eher zum Configuration Manager, Abschnitt 6) |
| Inter-VLAN-Erreichbarkeit | — | nur aus HAs VLAN | Ping aus Quell-Interface (`ping -I`): exec, Phase C |

### 2.5 WAN-Qualität

| Teil | (a) heute | (b) HA misst selbst | (c) Router als Messpunkt |
|---|---|---|---|
| Reconnects | `wan.up`/`wan.reconnect` → `wan_unstable` 3 je 3600 s (`net_rules.py:2801-2896`, Schwellen `130-232`), `WanStability`-Entity | — | — |
| Down | `wan_down` (Wurzel, Rang 3) | — | — |
| Gateway-Wechsel | **fehlt**; `nexthop` im Dump verworfen | — | Auswertung `route[].nexthop` aus vorhandenem Dump (kein neuer Aufruf) |
| Öffentliche IP-Wechsel | `wan.ip_changed` aus WAN-IPv4 (`_wan_ip` `net_rules.py:2956`); bei CGNAT/Kaskade ist das die private WAN-IP; DDNS-`ip` (`api.py:5731`) als zweite Quelle, nicht ausgewertet | HTTP-„what is my IP“-Dienst aus HA: externe Abhängigkeit, Datenschutz → **nicht** vorgeschlagen; DDNS-Datei genügt, wo vorhanden | — |
| IPv4/IPv6 | nur IPv4; IPv6-only-WAN übersprungen (`net_rules.py:2793`) | IPv6-Erreichbarkeit HA → extern: belegt nur HA | `ipv6-address`/`ipv6-prefix` im Dump (Felder **nicht belegt**), `wan6`-Interface im Dump |
| Failover | `wan.failover` | — | mwan3-Status: nicht untersucht |

### 2.6 Latenz und Verlust

| Teil | (a) heute | (b) HA misst selbst | (c) Router als Messpunkt |
|---|---|---|---|
| HA → Router | implizit Poll-Dauer, nicht gespeichert | ubus-Dauer je Poll (Zeitstempel um `_raw_call`) **ohne neuen Aufruf**; TCP-Connect auf Verwaltungsport 1×/min. Belegt: Antwortzeit inkl. rpcd-Last. Belegt nicht: reine Netzlatenz | — |
| HA → extern | `ping_ms` (TCP 8.8.8.8:53, Einzelwert, kein Verlust) | ein zentraler Probe mit 3 Versuchen → Verlust + Median | — |
| Router → Gateway/extern | — | — | `ping -c 3 -W 1` (exec), Standard AUS, max. 1×/5 min, nur Gateway bzw. ausgewählte APs |
| Pfad | — | — | `traceroute` braucht root/Raw-Socket; nur auf Anforderung, nie periodisch |

---

## 3. Matrix je Messpunkt

Spalten: **heute** = vorhanden auf `main`; **neuer ubus** = neuer read-only ubus-Aufruf bzw.
neues ACL-Recht nötig; **exec** = routerseitiges `file exec`/SSH nötig; **Default**.
„Dump“ = bestehender `network.interface dump`, nur neue Auswertung.

### 3.1 Messpunkt HA

| Testart | heute | neuer ubus | exec | Default |
|---|---|---|---|---|
| Router-Verwaltung erreichbar (Poll) | ja | nein | nein | an (besteht) |
| ubus-Antwortzeit je Router | nein | nein | nein | an (nur Zeitmessung) |
| TCP-Connect Verwaltungsport | nein | nein | nein | aus (Dublette zum Poll; nur auf Anforderung) |
| HA → extern (TCP) | ja, je Coordinator | nein | nein | an, **zentral 1×**, nicht je Router |
| HA → extern (HTTP 204) | nein | nein | nein | aus |
| DNS an Router-Resolver (`aiodns`) | nein | nein | nein | aus, wählbar je Router; Intervall ≥ 5 min |
| DNS an externen Resolver | nein | nein | nein | aus |
| ICMP HA → Router | nein | nein | nein | aus (nicht belegt, ob ICMP aus HA möglich) |

### 3.2 Messpunkt Gateway-Router

| Testart | heute | neuer ubus | exec | Default |
|---|---|---|---|---|
| WAN up/down, Reconnects | ja | nein | nein | an (besteht) |
| WAN-IPv4-Wechsel | ja | nein | nein | an (besteht) |
| Gateway-(Nexthop-)Wechsel | nein | nein (Dump) | nein | an |
| WAN-DNS-Server-Wechsel | nein | nein (Dump) | nein | an |
| IPv6-WAN-Status/Prefix | nein | nein (Dump) | nein | an |
| Öffentliche IP aus DDNS | teilweise (nur Anzeige) | nein | nein | an, wo DDNS vorhanden |
| DHCP-Pool-Auslastung | ja | nein | nein | an (besteht) |
| DHCP-Konflikt aus ARP/Leases | nein (nur DECLINE) | nein | nein | an (Auswertung vorhandener Daten) |
| DHCPv6/RA-Konfiguration | nein | nein (`uci get dhcp` besteht) | nein | an |
| odhcpd Leases v4/v6, RA | nein | ja (`dhcp` ipv4leases/ipv6leases/ipv6ra) | nein | aus, Capability |
| dnsmasq-Zähler | nein | ja (`dnsmasq metrics`) | nein | aus, Capability |
| Ping Nexthop / Referenzziel | nein | ja (ACL `file` exec mit Argumentmuster) | ja | aus, Capability, ≥ 5 min |
| nslookup lokal | nein | ja (ACL) | ja | aus, Capability |
| traceroute | nein | ja (ACL) | ja | aus, nur auf Anforderung |

### 3.3 Messpunkt AP-Router

| Testart | heute | neuer ubus | exec | Default |
|---|---|---|---|---|
| Uplink/Port-Status, LLDP | ja | nein | nein | an (besteht) |
| Interface/Default-Route | ja (bool) | nein | nein | an (besteht) |
| Ping AP → Gateway | nein | ja (ACL) | ja | aus, Capability, ≥ 5 min |
| nslookup AP → Gateway-Resolver | nein | ja (ACL) | ja | aus, Capability |
| DNS-Server-Konfiguration AP | nein | nein (Dump) | nein | an |

---

## 4. Lücken und Dubletten, die zu vermeiden sind

**Dubletten (nicht neu bauen):**

1. Router-Erreichbarkeit: Poll, Tracker, `router_unreachable`, `lan_unreachable`,
   `connectivity`-Sensor. Ein zusätzlicher „Router-Ping“ aus HA bringt dasselbe mit mehr Last.
2. WAN down/Reconnect/IP-Wechsel: `detect_wan` + `wan_down`/`wan_unstable`/`wan_ip_changed`.
3. DHCP-Pool-Auslastung: `detect_dhcp` + `DhcpPool`-Sensor.
4. HA-Internetprobe: existiert bereits (`coordinator.py:769-787`) — je Router doppelt.
   **Vorschlag:** in einen fleetweiten Diagnose-Scheduler verlegen (1 Probe statt N),
   ehrlich beschriften („HA → Internet“), `ping_ms` am Gateway-Knoten durch Router-Sicht
   ersetzen, sobald es sie gibt. Rückweg: alter Code bleibt bis zur Umstellung.
5. Zweiter `network.interface dump` je Poll (`api.py:1948` ff. und `api.py:4230-4297`):
   **Vorschlag:** einmal holen, beide Auswertungen daraus — spart einen Aufruf je Router
   und Minute, bevor neue Auswertungen dazukommen.
6. Capability-Prüfung: `check_capabilities` (`api.py:1563-1625`) existiert, läuft aber nur im
   Config-Flow; `_acl_blocked` merkt sich verweigerte Aufrufe zur Laufzeit. Eine neue
   Capability-Erkennung soll darauf aufbauen bzw. auf die enterprise-core-Erkennung warten
   (Abschnitt 6), nicht eine dritte bauen.
7. Persistenz: Store-Muster aus NI/CS übernehmen (Delay-Save 300 s, Größenkappe mit
   `prepare_save_json`, Flush beim letzten Unload), keinen eigenen Schreib-Timer.

**Lücken (echt neu):**

- Gateway-(Nexthop-)Wechsel, WAN-DNS-Server-Wechsel, IPv6-WAN — Daten liegen vor.
- DNS-Funktionsprüfung (heute nur Logzeilen ohne Incident-Regel).
- DHCP-Konflikt aus vorhandenen ARP-/Lease-Daten; DHCPv6/RA.
- Latenz-/Verlust-Zeitreihe mit Verlust statt Einzelwert.
- Routerseitige Messungen (nur mit ACL-Erweiterung, Phase C).

**Korrelations-Regeln für neue Incident-Typen (Pflicht, Vorschlag):**

- Ohne Eintrag in `DEFAULT_SETTINGS` ignoriert der Automat neue Typen (`net_rules.py:679-722`).
- Mit Eintrag wird jedes neue Incident im Fenster von `lan_unreachable` stumm Kind
  (`5186-5187`); das ist für Diagnose-Incidents richtig (HA selbst ist weg).
- `wan_down` nimmt nur `_WAN_CHILDREN` (`4769`): ein neues `dns_failed` am Gateway während
  WAN-Ausfall würde **nicht** verknüpft und eigenständig alarmieren → `_WAN_CHILDREN` bzw.
  `_incident_link` gezielt erweitern, mit Gegenfall-Tests wie in `tests/test_net_correlation.py`.
- Router-Wurzeln greifen über `_concerns` (`net_rules.py:5143`) auf `scope_key` mit
  Router-Präfix. Diagnose-Incidents mit Scope „HA“ (z. B. „HA → Internet“) brauchen einen
  eigenen Scope ohne Router-Präfix, sonst werden sie bei einem Router-Ausfall fälschlich Kind.
- Ergebnisse von HA-Messungen dürfen **nie** Router-Incidents erzeugen, deren Ursache bei HA
  liegt (gleicher Gedanke wie `lan_unreachable`).

---

## 5. Router als Messpunkt — externe Befunde (zu füllen; Stand: Recherche eingearbeitet)

> Quelle: Recherche-Notiz der Schwestersitzung `net-diagnostics-openwrt-messwege.md`
> (2026-11-17, nur öffentliche Quellen, **nichts auf echten Routern geprüft**). Inhalt als
> Daten übernommen; die dort gelisteten Router-Befehle wurden **nicht** ausgeführt.
> Offene Live-Prüfungen nur mit Freigabe des Nutzers über den Master.

### 5.1 Messwege

- **Kein ubus-Objekt für Ping, Vorwärts-DNS oder Traceroute.** netifd bietet keine
  Probe-Methode (https://raw.githubusercontent.com/openwrt/netifd/master/ubus.c); rpcd-Plugin
  `luci` hat keine (luci-rpc-Methodenliste nicht vollständig belegt). Einziger Weg:
  `file exec` oder SSH.
- **LuCI Network → Diagnostics** nutzt `fs.exec_direct` = ubus `file exec` mit
  ping `-4 -c 5 -W 1 <addr>` / `-6 -c 5 <addr>`, traceroute `-4 -q 1 -w 1 -n -m 20 <addr>`,
  `nslookup <addr>`
  (https://raw.githubusercontent.com/openwrt/luci/master/modules/luci-mod-network/htdocs/luci-static/resources/view/network/diagnostics.js).
  ACL-Gruppe `luci-mod-network-diagnostics` gibt den **nackten** Pfad frei
  (`/bin/ping`, `/usr/bin/ping`, `/bin/traceroute`, `/usr/bin/traceroute`, `/usr/bin/nslookup`
  je `exec`; ping6/traceroute6/arp-scan `exec`+`list`)
  (https://raw.githubusercontent.com/openwrt/luci/master/modules/luci-mod-network/root/usr/share/rpcd/acl.d/luci-mod-network.json).
- **Reverse-DNS** `network.rrdns lookup` (Paket `rpcd-mod-rrdns`; Parameter addrs, server,
  port, limit, timeout): nur PTR, beliebiger Server → SSRF-relevant. **Nicht verwenden**
  (https://raw.githubusercontent.com/openwrt/luci/master/libs/rpcd-mod-rrdns/src/rrdns.c).

### 5.2 rpcd `file exec` und ACL-Muster

Quelle: https://raw.githubusercontent.com/openwrt/rpcd/master/file.c (+ session.c,
include/rpcd/exec.h, main.c).

- Parameter `command`, `params` (nur Strings, max. 254), `env` (mit Session abgelehnt).
- **Zweistufige ACL-Prüfung:** erst der Pfad allein (Scope `file`, Funktion `exec`); passt er,
  werden Argumente **nicht** geprüft. Nur sonst wird `"<pfad> <arg1> …"` (max. 1024 Zeichen)
  per `fnmatch(FNM_NOESCAPE)` geprüft.
- **Folge für die geplante ACL (Vorschlag, nicht live belegt):** volle Kommandozeilen-Muster,
  **nie** den nackten Binärpfad, z. B. `"/bin/ping -c 3 -W 1 *": ["exec"]`. Ein `*` am Ende
  lässt weitere Flags durch → Ziel serverseitig nicht frei wählbar machen; HA übergibt nur
  Ziele aus einer festen Liste (Nexthop aus Dump, Gateway-LAN-IP, konfigurierte
  Referenzziele), Muster möglichst ohne `*` an Flag-Positionen.
- Ausgabe max. 256 KiB je stdout/stderr (Überlauf = Fehler). Timeout Standard 120 s,
  `rpcd -t` 1–600 s, danach SIGKILL; ob das Init-Skript `-t` setzt: nicht belegt.
- **Abgleich mit dem Repo (selbst geprüft, verifiziert):** `acl_provisioning.py:101` gibt auf
  ubus-Ebene `"file": ["read", "stat", "list", "exec"]` frei — stimmt. `acl_provisioning.py:123`
  `"service": ["list", "get_data"]` — stimmt. `acl_provisioning.py:135`
  `"/etc/init.d/rpcd": ["exec"]` — stimmt, steht aber unter **`write.file`**
  (`acl_provisioning.py:131-136`), nicht unter `read.file`. Ping usw. bräuchten neue Einträge
  und damit `ACL_VERSION` 9 + Redeploy über `ensure_acl` (`acl_provisioning.py:148`) mit
  rpcd-Neustart (`_deploy_acl` `244`, `301-305`). Das ist eine **Routeränderung** und der
  Produktentscheid gegen breites `file exec` (ACL v8, rpcd-Neustarts und Speicherlecks,
  `docs/plans/2026-10-28-ssh-polling-und-audit.md:123`) muss neu abgewogen werden.
- **Annahme (eigene, nicht belegt):** Das Projekt meldet sich standardmäßig als `root` an
  (`const.py:12`). Wenn die rpcd-Login-Konfiguration für root alle ACL-Gruppen zulässt
  (OpenWrt-Standard `read '*'`/`write '*'`) und LuCI mit `luci-mod-network` installiert ist,
  hat die HA-Session **schon heute** `exec` auf den nackten `/bin/ping`-Pfad — ohne
  Argumentprüfung. Ein Argumentmuster in der Projekt-ACL schränkt dann nichts ein. Prüfweg:
  `cat /usr/share/rpcd/acl.d/*.json` und `/etc/config/rpcd` auf einem Router (nur mit
  Freigabe). Bis dahin: Capability-Prüfung darf nicht aus „exec erlaubt“ schließen, dass das
  Projekt-Muster greift.

### 5.3 Benötigte Pakete und Binärdateien

- OpenWrt-Busybox-Standard: PING, PING6, NSLOOKUP, TRACEROUTE, TRACEROUTE6, FANCY_PING,
  NSLOOKUP_BIG = y
  (https://raw.githubusercontent.com/openwrt/openwrt/master/package/utils/busybox/Config-defaults.in).
  Ob die Images der eingesetzten Geräte das so bauen: nicht belegt.
- busybox ping: Zusammenfassung gesendet/empfangen, Verlust in ganzen Prozent,
  `round-trip min/avg/max` nur bei ≥ 1 Antwort. busybox nslookup (groß): unterscheidet
  NXDOMAIN, SERVFAIL, „No answer“, Timeout; Antwortzeit nur mit `-debug`; Standard 2 Wdh.,
  5 s; `-timeout=`, `-retry=`, `-type=`. traceroute braucht root.
- `bind-dig`, `mtr`, `iputils-ping`, `drill` nicht im Standardumfang → nicht voraussetzen.
  DECIDED: keine Zusatzpakete vorschlagen — nur Busybox-Werkzeuge, weil Paketinstallation eine
  Routeränderung ist und OpenWrt 25.12 `apk` statt `opkg` nutzt (zwei Wege zu pflegen).

### 5.4 Lesende ubus-Daten ohne exec (Kandidaten)

| Objekt / Methode | Inhalt | Projekt-ACL heute (`acl_provisioning.py:100-129`) |
|---|---|---|
| `network.interface dump` / `.<if> status` | `route`, `dns-server`, `dns-search`, IPv6 (Feldliste nicht aus Quelltext belegt) | **erlaubt** (`105-107`) |
| `network.device status` | Geräte, Carrier, Statistik | **erlaubt** (`104`) |
| odhcpd `dhcp` `ipv4leases` / `ipv6leases` / `ipv6ra` (https://raw.githubusercontent.com/openwrt/odhcpd/master/src/ubus.c) | Leases v4/v6, RA-Status | **fehlt**; auch von keiner gelesenen LuCI-ACL freigegeben |
| `dnsmasq metrics` | ca. 30 Zähler DNS (forwarded, local answered, unanswered, Cache) und DHCP (discover…decline, noanswer, Leases) | **fehlt**; Schlüssel/erste Version nicht belegt |
| `service list` | laufende Dienste | **erlaubt** (`123`); ob dnsmasq/odhcpd als laufend gemeldet werden: nicht belegt |
| `uci get dhcp` | Pools, ra/dhcpv6-Optionen | ubus `uci get` **erlaubt** (`121`), Config-spezifisches Leserecht hängt an rpcd-Login (siehe Annahme 5.2); der Code nutzt es schon (`api.py:3944`) |

### 5.5 Last auf dem Router

- Keine veröffentlichten Zahlen (Zielplattform MT7981). Schätzung der Recherche: Ping mit
  3–5 Paketen und nslookup vernachlässigbar; `file exec` ein fork/exec, wenige ms;
  SSH-Aufbau am teuersten (Schlüsseltausch, vermutlich einige hundert ms). **Muss gemessen
  werden.**
- **Vorschlag Budget:** je Router höchstens 1 aktiver Test je 5 min, max. 3 Pakete, `-W 1`,
  nur über ubus (kein SSH für periodische Tests), nicht bei gedrosseltem Coordinator
  (CPU > 100 %, `coordinator.py:1244-1270`) und nicht im SSH-Rückfall.

### 5.6 Referenzziele

- mwan3-Beispiel `track_ip`: 1.0.0.1, 1.1.1.1, 208.67.222.222, 208.67.220.220 (+ IPv6)
  (https://raw.githubusercontent.com/openwrt/packages/master/net/mwan3/files/etc/config/mwan3);
  öffentliche Resolver Google, Quad9, Cloudflare; HTTP-204: `connectivitycheck.gstatic.com/generate_204`;
  NetworkManager-Prüfintervall Standard 300 s. Nutzungsbedingungen: keine Beschränkung
  gefunden, aber auch keine Erlaubnis — nicht belegt.
- DECIDED: Referenzziele sind Einstellungen mit leerer Standardliste außer dem Nexthop aus dem
  Dump — keine fest eingebauten Fremdziele ohne Zustimmung des Nutzers (Datenschutz, ToS
  ungeklärt). Die bestehende 8.8.8.8-Probe ist davon ausgenommen, bis der Master über ihre
  Zukunft entscheidet (Frage F2).

### 5.7 Offene Live-Prüfungen (nur mit Freigabe des Nutzers über den Master)

Aus der Recherche übernommen, **nicht** ausgeführt: Binärdateien und Pakete auflisten;
`ubus list` und `ubus -v list` für `network.rrdns`, `dnsmasq`, `dhcp`, `luci-rpc`;
`dnsmasq metrics`, `dhcp ipv4leases`, `network.interface dump`, `service list` lesen;
`/usr/share/rpcd/acl.d/*.json` und `/etc/config/rpcd` lesen; exec-ACL mit Argumentmuster
testen (ändert die ACL, eigene Freigabe); Kosten messen (ping, nslookup, SSH-Aufbau).

---

## 6. Abhängigkeiten, die noch nicht auf `main` sind (nur vermerkt)

Nichts davon existiert in `0dc20cd`; hier wird **nichts** davon entworfen.

- **enterprise-core-Sitzung:** stabile Router-ID (heute `entry_id`), Registry,
  Capability-Erkennung, Event-/Audit-Schema, Freigabe-Workflow (Approval). Diagnose braucht
  davon: Router-ID als Schlüssel im Diagnose-Store, Capability-Flags für „exec erlaubt /
  Busybox-Werkzeug vorhanden / odhcpd-ubus vorhanden“, Audit-Eintrag für jede aktive
  Messung auf einem Router, Approval für die ACL-Erweiterung.
- **Configuration Manager** (UCI-Snapshots, Drift): Firewall-/Routing-/DHCP-Konfiguration
  gehört dorthin; Diagnose liest nur Laufzeitzustand. Die ACL-Erweiterung für exec wäre ein
  Drift-Fall.
- **Security Center:** Bewertung von `known_hosts=None` (`api.py:3016-3040`), exec-ACL,
  rrdns-SSRF.
- **Hinweis:** Während dieser Sitzung (ca. 21:23) sind im Worktree zwei **unversionierte**
  Dateien entstanden, die nicht aus dieser Sitzung stammen:
  `custom_components/openwrt_router/diag_targets.py` (Kopf: Ziel-Allowlist, Validierung,
  SSRF-Schutz, reine Standardbibliothek) und `tests/test_diag_targets.py`. Nicht geprüft,
  nicht angefasst. Eine Zielvalidierung (5.2, „nur Ziele aus fester Liste“) sollte darauf
  aufbauen statt eine zweite zu bauen.

---

## 7. Testbefehle

**verifiziert** aus `.github/workflows/tests.yaml`, `pytest.ini`, `tests/conftest.py`:

- CI: Matrix Python 3.13 / 3.14; `pip install homeassistant pytest pytest-asyncio aiohttp
  ruff==0.17.3 asyncssh`; `ruff check custom_components/`; `ruff format --check
  custom_components/`; `pytest tests/ -v --tb=short`. `ha-compat.yaml`: Python 3.14 mit
  neuester HA, gleiche Pakete.
- `pytest.ini`: `testpaths = tests`, `pythonpath = .`, `asyncio_mode = auto`. `conftest.py`
  legt `custom_components` als Namespace-Paket an (`tests/conftest.py:18-34`). Kein
  `requirements*.txt`, kein `pyproject.toml`. `hacs.json`: `homeassistant` 2026.2.0.

**Auf diesem Rechner vorhanden (nur gelesen, nichts installiert):**

| Umgebung | Pfad | Inhalt | Status |
|---|---|---|---|
| Py 3.13 + HA 2026.2.3 | System-Python `py -3.13` | homeassistant 2026.2.3, pytest 9.1.1, pytest-asyncio 1.4.0, asyncssh 2.24.0, aiohttp 3.14.1, **ruff 0.15.20** (nicht 0.17.3) | vorhanden |
| Py 3.14 + HA 2026.11.2 | venv `venv-ha-latest` im Scratchpad einer früheren Sitzung (`%LOCALAPPDATA%\Temp\claude\98f2ff91946e58cf\…\scratchpad\venv-ha-latest`); zweite Kopie `ha-venv314` | Python 3.14.6, homeassistant 2026.11.2, pytest 9.2.0, pytest-asyncio 1.5.0, asyncssh 2.24.1 | vorhanden, aber **flüchtig** (Temp-Ordner) |
| uv | `uv 0.11.31` | verwaltetes CPython 3.14.6; uv-Cache enthält `homeassistant-2026.11.2` und `ruff-0.17.3` | vorhanden |

Befehle (aus dem Worktree-Wurzelverzeichnis):

```bash
# Py 3.13 + HA 2026.2.3
py -3.13 -m pytest tests/ -q --tb=short
# Py 3.14 + HA 2026.11.2 (vorhandenes venv, Pfad ggf. anpassen)
"$LOCALAPPDATA/Temp/claude/98f2ff91946e58cf/11103d04-683b-4ad8-bc34-f53115fb0edb/scratchpad/venv-ha-latest/Scripts/python.exe" -m pytest tests/ -q --tb=short
# ruff wie CI (0.17.3 liegt im uv-Cache; uvx lädt nach, falls der Cache fehlt)
uvx ruff@0.17.3 check custom_components/
uvx ruff@0.17.3 format --check custom_components/
```

- In dieser Sitzung **nicht ausgeführt** (nur Dokument geändert; zudem öffnet ein
  ungepatchter Coordinator-Poll ab Poll 2 eine TCP-Verbindung nach 8.8.8.8:53,
  `coordinator.py:775-779`; `tests/conftest.py` patcht `open_connection` nicht global, nur
  einzelne Testdateien tun es: `test_coordinator.py`, `test_net_engine.py`,
  `test_client_engine.py`, `test_poll_no_ssh.py`, `test_wan_detection.py`). Ob die Suite ohne
  Netz vollständig offline läuft: nicht belegt.
- **Vorschlag für Phase B:** autouse-Fixture in `conftest.py`, die `asyncio.open_connection`
  und jede Diagnose-Messung patcht, damit Tests nie ins Netz gehen.

---

## 8. Nicht belegt

1. Feldnamen und Form von `route[].nexthop`, `dns-server`, `ipv6-address`/`ipv6-prefix` im
   `network.interface dump` der eingesetzten Router. `tests/fixtures/*.json` und
   `scripts/mock_router.py` enthalten keines dieser Felder; nur
   `tests/test_net_infra_review.py:248-256` hat eine synthetische Route mit `nexthop`
   (Dokumentationsadresse), dazu ein `wan6`-Interface — keine Live-Form.
2. Ob ICMP aus HA (unprivilegiert) in der Zielinstallation möglich ist.
3. Ob die Router-Images Busybox ping/nslookup/traceroute so enthalten wie der Standard.
4. rpcd-Login-Konfiguration für root und ob `luci-mod-network`-ACL schon nackte exec-Rechte
   gibt (Annahme 5.2).
5. Ob das rpcd-Init-Skript `-t` setzt (exec-Timeout).
6. `dnsmasq metrics`: Schlüssel, erste Version, nötige ACL. odhcpd-`dhcp`-Objekt auf den
   eingesetzten Versionen vorhanden.
7. Ob `service list` dnsmasq/odhcpd zuverlässig als laufend meldet.
8. Unterschiede 23.05 / 24.10 / 25.12 für LuCI-Diagnostics-ACL und `file exec`.
9. Kosten (CPU, Zeit) von ping/nslookup per `file exec` und SSH-Aufbau auf MT7981.
10. Nutzungsbedingungen öffentlicher Referenzziele.
11. Ob HA denselben Internetweg nutzt wie das Gateway (für die Deutung von `ping_ms`).
12. Ob die Testsuite ohne Netzzugang komplett offline bleibt (Abschnitt 7).
13. Ob netifd/odhcpd/dnsmasq-Logzeilen live so aussehen wie im Parser erwartet
    (`log_parser.py:1-20`, A6 aus dem NI-Plan).
14. Schnittstellen der enterprise-core-Sitzung (Router-ID, Capability, Audit, Approval) —
    nicht auf `main`, nicht gelesen.

---

## 9. Entscheidungen, Fragen, Doku-Prüfung

**DECIDED (diese Sitzung):**

- DECIDED: Arbeitstitel „Netzwerkprüfung“ als Unter-Tab von `DiagnoseView` statt neuem
  Sidebar-Eintrag — es gibt schon „Diagnose“, zwei gleichnamige Bereiche verwirren.
- DECIDED: Phase B nutzt nur Daten ohne Routeränderung (Dump-Auswertung, HA-seitige
  Messungen, ubus-Zeitmessung); alles mit exec ist Phase C — die ACL-Erweiterung ist eine
  Routeränderung mit Freigabepflicht.
- DECIDED: keine Zusatzpakete, nur Busybox-Werkzeuge (5.3).
- DECIDED: keine fest eingebauten neuen Fremdziele (5.6).
- DECIDED: `network.rrdns` wird nicht genutzt — PTR an beliebigen Server ist SSRF-Fläche
  ohne Diagnosenutzen.

**Offene Fragen an den Master:**

- F1: Den zweiten `network.interface dump` je Poll vor Phase B zusammenlegen? (empfohlen: ja,
  eigener kleiner Fix-PR)
- F2: Bestehende 8.8.8.8-Probe: zentralisieren und als „HA → Internet“ umbenennen,
  oder bis Phase B unverändert lassen? (empfohlen: zentralisieren in Phase B)
- F3: exec-ACL in Phase C überhaupt anstreben angesichts des v8-Entscheids gegen breites
  `file exec`? (empfohlen: erst nach Live-Prüfung 5.7 und Annahme 5.2 entscheiden)
- F4: Diagnose-Ergebnisse als eigene Incident-Typen oder nur als Events/Score-Eingang?
  (empfohlen: zuerst Events + Score, Incidents nur für Gateway-/DNS-Wechsel mit expliziten
  Link-Regeln)

**Doku geprüft:** https://developers.home-assistant.io/blog/ (leitet um auf
https://contributors.home-assistant.io/blog/), Liste bis 2026-11-17: keine Deprecation zu
`DataUpdateCoordinator`, `Store`, `HomeAssistantView`, `panel_custom` oder Diagnostics in der
Übersicht; relevant für später: „Repair issues can belong to a config entry, and be refreshed“
(2026-10-28) für Diagnose-Hinweise als Repairs; „Deprecated device info constants“
(2026-11-10, Core 2026.12) betrifft neue Entities. Volltexte nicht gelesen.

## Änderungsprotokoll

- 2026-11-17 Phase A: nur diese Datei angelegt. Keine Verbindung zu Router, HA, Host, VM oder
  Drucker; keine Messung ins Netz; nichts installiert; kein Commit. Rückweg: Datei löschen.
