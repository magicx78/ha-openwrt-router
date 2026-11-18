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
  Schwestersitzung (Abschnitt 5) und sind mit Quell-URLs übernommen.
- **Live-Befunde 2026-11-18:** Der Nutzer hat die nur lesenden Prüfungen aus 5.7 (a)
  freigegeben; die Master-Sitzung hat sie per SSH auf vier Routern ausgeführt (kein Ping,
  kein nslookup, kein traceroute, keine ACL-Probe). Diese Sitzung hat nur die
  Ergebnisdateien ausgewertet, ohne Kontakt zu Geräten. Ergebnisse in **5.8**, Folgen in
  **5.9**. Geräte nur als Rolle: **gateway** (Cudy WR3000 v1, OpenWrt 25.12.1), **ap2**
  (Cudy WR3000 v1, 25.12.1), **ap5** (AVM FRITZ!Repeater 3000, 25.12.6), **ap6** (AVM
  FRITZ!WLAN Repeater 1750E, 25.12.2).
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
   Router-Aufruf** auswertbar. Feldnamen `route`, `nexthop`, `dns-server`, `dns-search`,
   `ipv6-address`, `ipv6-prefix` **belegt am 2026-11-18 auf gateway, ap2, ap5, ap6** (nur
   Schlüssel gezählt, Inhalte nicht geprüft, 5.8).
4. **Für Ping, Vorwärts-DNS und Traceroute auf dem Router gibt es kein ubus-Objekt**; nur
   `file exec` oder SSH (Abschnitt 5; am 2026-11-18 auf allen vier geprüften Routern
   bestätigt: kein solches Objekt in `ubus list`). Heute erlaubt die Projekt-ACL `file exec`
   nur für `/etc/init.d/rpcd` (`acl_provisioning.py:135`). Jeder routerseitige aktive Test
   mit **eigenem** Argumentmuster braucht eine ACL-Erweiterung (= Routeränderung, Freigabe
   nötig) und ist daher Phase-C-Stoff. Achtung (5.8, 5.9): der Login `root` erhält auf allen
   vier Routern **alle** ACL-Gruppen, auch die von LuCI.
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
- **Einhängepunkt — ENTSCHIEDEN (Master, 2026-11-17):** Auf `main` gibt es kein
  „Enterprise“-Menü. „Network Diagnostics“ wird ein **Unter-Tab des neuen
  „Enterprise“-Menü-Containers**, den die enterprise-core-Sitzung anlegt (Abschnitt 6),
  **nicht** ein Unter-Tab von `DiagnoseView`. Deutscher Tab-Name: **„Netzwerkdiagnose“**.
  Das ersetzt den früheren DECIDED-Punkt („Netzwerkprüfung“ in `DiagnoseView`). Bis der
  Container auf `main` ist, hat Network Diagnostics keinen UI-Einhängepunkt (nur Backend).

---

## 2. Je Diagnosebereich: (a) heute · (b) HA misst selbst · (c) Router als Messpunkt

Allgemein zu (b): HA misst **von HAs Netzposition** aus. Ein Ergebnis belegt den Weg
HA → Ziel, nicht den Weg Router → Ziel. HA-Kern bringt `aiodns` mit (**verifiziert** lokal:
`homeassistant` 2026.2.3 verlangt `aiodns==4.0.0`, 2026.11.2 `aiodns==4.0.4`), also sind
DNS-Abfragen an einen gewählten Server ohne neue Requirement möglich. ICMP aus HA:
**nicht belegt** (Grund: betrifft HA, nicht die Router; die Live-Prüfung 2026-11-18 lief
nur auf Routern. Unprivilegierte ICMP-Sockets hängen von der HA-Installationsart ab;
`icmplib` ist keine Kern-Abhängigkeit). TCP-Connect ist überall möglich.

Zu (c): Details, ACLs und Quellen in Abschnitt 5, Live-Befunde in 5.8. Alles in (c) ist
standardmäßig AUS. **Folge aus 5.8:** Die Router sind nicht gleich — ap6 hat weder
dnsmasq noch odhcpd noch usteer laufen, ap5/ap6 haben kein `curl`, die `dnsmasq
metrics`-Schlüssel hängen an der dnsmasq-Version. (c) ist deshalb immer **je Gerät** an
eine Capability gebunden.

### 2.1 Erreichbarkeitskette

| Glied | (a) heute | (b) HA misst selbst — belegt / belegt nicht | (c) Router als Messpunkt |
|---|---|---|---|
| Router-Verwaltung (ubus) | Poll-Erfolg, `consecutive_failures`, `last_seen`, `error_type` (`coordinator.py:298-430`); Tracker + `router_unreachable`/`lan_unreachable` (`net_engine.py:987-1093`); binary `connectivity` (`binary_sensor.py:65`) | Dauer je ubus-Aufruf (fehlt: `_raw_call` misst nicht, `api.py:5324-5435`). Belegt: rpcd/uhttpd antwortet und wie schnell. Belegt nicht: Paketverlust, Ursache (CPU vs. Netz) | entfällt (der Router misst sich nicht selbst) |
| Router-Interface (LAN/WAN up) | `network.interface dump` je Poll (`api.py:1948`, `4230`), `network.device status` (`api.py:4211`), Port-Zähler | — (HA sieht Interfaces nur über den Router) | gleiche Daten; mehr nicht nötig |
| Gateway (Nexthop der WAN) | nur `default_route` bool (`api.py:2068-2075`); `nexthop` im Dump vorhanden, aber verworfen (Feld **belegt am 2026-11-18 auf gateway, ap2, ap5, ap6**; auf den APs genau eine Route mit `nexthop`, auf dem gateway zwei — Inhalt nicht geprüft) | HA kann den Upstream-Gateway des Gateways meist nicht erreichen (anderes Netz, NAT). Belegt nichts über die WAN-Strecke | Ping des Nexthops vom **Gateway**: braucht `file exec` (Abschnitt 5). Belegt: L3 bis zum Provider-Router |
| Interne Ziele (AP → Gateway, Gateway → AP) | Topologie-Kanten LLDP/ARP+FDB (`net_rules.py:4903-5016`), Port-Status | TCP-Connect HA → Router-Verwaltungsport schon implizit im Poll. Belegt: HA ↔ Router. Belegt nicht: AP ↔ Gateway direkt | Ping vom AP zum Gateway: braucht exec. Belegt: Backhaul-Strecke |
| Externe IP | HA-TCP-Probe 8.8.8.8:53 je Coordinator (`coordinator.py:769-787`) → `ping_ms` | Ein zentraler Probe genügt (nicht je Router). Belegt: HA hat Internet. Belegt nicht: Gateway hat Internet (HA kann z. B. über anderen Weg gehen; Annahme: meist derselbe Weg) | Ping vom Gateway zu Referenzzielen: exec. Belegt: Internet aus Sicht des Gateways |
| DNS | nur Logzeilen-Events (Abschnitt 2.2) | `aiodns` an Router-Resolver. Belegt: dnsmasq des Routers antwortet HA. **Nur wo dnsmasq läuft** (2026-11-18: gateway, ap2, ap5; nicht ap6) | `nslookup` auf dem Router: exec (Binärdatei auf allen vier vorhanden) |
| HTTP | — | HTTP-GET HA → Referenz-URL über `async_get_clientsession`. Belegt: HA-Internet inkl. TLS. Belegt nicht: Router-Sicht | `wget`/`uclient-fetch` (auf allen vier vorhanden; `curl` nur gateway, ap2) auf dem Router: exec; **nicht** vorgeschlagen (Last, Missbrauchsfläche) |

### 2.2 DNS

| Teil | (a) heute | (b) HA misst selbst | (c) Router als Messpunkt |
|---|---|---|---|
| Resolver-Dienst läuft | `service list` (dnsmasq in `DEFAULT_SERVICES`, `const.py:561`; Detektor Dienste in `detect_infrastructure`) | — | gleich. **2026-11-18:** dnsmasq als Dienst und ubus-Objekt auf gateway, ap2, ap5; auf ap6 Paket installiert, aber weder Dienst noch ubus-Objekt (ap6 läuft als Relay mit `relayd`) → „dnsmasq fehlt“ ist auf ap6 der Normalzustand, kein Fehler |
| Resolver antwortet | Logzeilen `dns.query_limit`/`no_servers`/`send_failed` (`log_parser.py:94-96`), nur Events, Hypothese 0,5 (`net_rules.py:1749-1775`), keine Incident-Regel | A-Abfrage per `aiodns` direkt an den LAN-Resolver jedes Routers, 1×/5–15 min. Belegt: dnsmasq antwortet HA, Upstream erreichbar (bei Nicht-Cache-Namen). Belegt nicht: was Clients am AP sehen, wenn sie einen anderen Resolver nutzen | `nslookup <name> 127.0.0.1` (exec). Belegt: lokaler Resolver aus Router-Sicht |
| Upstream-Server | `dns-server` im Dump vorhanden, verworfen (Schlüssel **belegt am 2026-11-18** auf allen vier; ob gefüllt: nicht belegt, nur Schlüssel gezählt) | Abfrage HA → Upstream direkt: belegt nur HA-Weg | — |
| Statistik | — | — | `dnsmasq metrics` (ubus, ohne exec): Weiterleitungen, unbeantwortet, Cache. ACL fehlt im Projekt; Schlüssel **belegt am 2026-11-18 auf gateway, ap2, ap5** (Liste in 5.8; Schlüsselsatz hängt an der dnsmasq-Version); auf ap6 nicht vorhanden |
| Reverse-DNS | — | — | `network.rrdns lookup`: nur PTR, beliebiger Server → SSRF-relevant, **nicht verwenden**. **2026-11-18:** Objekt auf allen vier Routern vorhanden (`rpcd-mod-rrdns` überall installiert) |

### 2.3 DHCP

| Teil | (a) heute | (b) HA misst selbst | (c) Router als Messpunkt |
|---|---|---|---|
| Dienst | `service list` dnsmasq/odhcpd (`net_rules.py:192`), Pools übersprungen bei gestopptem dnsmasq (`coordinator.py:978`) | — | gleich |
| Leases | `get_dhcp_leases` (`api.py:3825`, Datei, Rückfall luci-rpc `3868`) | — | odhcpd `dhcp ipv6leases` (ubus, ohne exec; ACL fehlt). **`ipv4leases` widerlegt am 2026-11-18 auf gateway, ap2, ap5:** installiert ist `odhcpd-ipv6only`, das Objekt `dhcp` hat nur `ipv6leases`, `ipv6ra` und den **Schreibaufruf** `add_lease`; IPv4-Leases bleiben bei dnsmasq (Datei/luci-rpc wie heute). Auf ap6 kein `dhcp`-Objekt |
| Pool-Auslastung | `dhcp_health.pool_usage`, `detect_dhcp` (`net_rules.py:2988`), Schwellen 90/85 (`net_rules.py:130-232`), `DhcpPool`-Sensor (`sensor.py:1485`) | — | — |
| Konflikte | nur `DHCPDECLINE`-Logzeilen | HA sieht keine Duplikate (kein L2-Zugriff auf alle Segmente). Doppelte IP mit zwei MACs in `arp_table`/Leases über die Flotte ist **heute schon in den Daten**, aber nicht ausgewertet | `arp-scan` braucht exec + Paket; **nicht** vorgeschlagen |
| DHCPv6/RA | nicht gelesen; `parse_dhcp_config` nur IPv4 (`dhcp_health.py`) | — | odhcpd `dhcp ipv6ra` (ubus, ohne exec, ACL fehlt; Methode **belegt am 2026-11-18 auf gateway, ap2, ap5**, nicht ap6); `luci-rpc getDUIDHints` ebenfalls vorhanden. `uci get dhcp` (`api.py:3944`) liefert ra/dhcpv6-Optionen vermutlich schon heute mit (**nicht belegt** — Grund: die Live-Prüfung hat `uci show dhcp` nur nach Log-Optionen gefiltert) |
| Antwortprobe | — | DHCP-Discover von HA: braucht Raw-Socket, stört Leases → **nicht** vorgeschlagen | `dnsmasq metrics` DHCP-Zähler (`dhcp_discover`, `dhcp_offer`, `dhcp_request`, `dhcp_ack`, `dhcp_nak`, `dhcp_decline`, `noanswer` …, 5.8). Sinnvoll nur am DHCP-Server: auf ap2/ap5 sind alle DHCP-Zähler 0 (dnsmasq dort nur als Resolver) |

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
| Gateway-Wechsel | **fehlt**; `nexthop` im Dump verworfen | — | Auswertung `route[].nexthop` aus vorhandenem Dump (kein neuer Aufruf). Am gateway gibt es `wan` und `wan6`, auf den APs kein `wan`-Interface; deren Default-Route hängt an einem LAN-Interface (je eine Route mit `target`/`nexthop`, 2026-11-18) → auf APs zeigt `nexthop` den **LAN-Gateway**, nicht die WAN-Strecke |
| Öffentliche IP-Wechsel | `wan.ip_changed` aus WAN-IPv4 (`_wan_ip` `net_rules.py:2956`); bei CGNAT/Kaskade ist das die private WAN-IP; DDNS-`ip` (`api.py:5731`) als zweite Quelle, nicht ausgewertet | HTTP-„what is my IP“-Dienst aus HA: externe Abhängigkeit, Datenschutz → **nicht** vorgeschlagen; DDNS-Datei genügt, wo vorhanden | — |
| IPv4/IPv6 | nur IPv4; IPv6-only-WAN übersprungen (`net_rules.py:2793`) | IPv6-Erreichbarkeit HA → extern: belegt nur HA | `ipv6-address`/`ipv6-prefix`/`ipv6-prefix-assignment`/`delegation` im Dump (Schlüssel **belegt am 2026-11-18** auf allen vier; Inhalte nicht geprüft), `wan6`-Interface und ubus-Objekt `odhcp6c.wan` nur am gateway |
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
**[2026-11-18]** = nach den Live-Befunden (5.8) geändert; Begründung in 5.9.

### 3.1 Messpunkt HA

| Testart | heute | neuer ubus | exec | Default |
|---|---|---|---|---|
| Router-Verwaltung erreichbar (Poll) | ja | nein | nein | an (besteht) |
| ubus-Antwortzeit je Router | nein | nein | nein | an (nur Zeitmessung) |
| TCP-Connect Verwaltungsport | nein | nein | nein | aus (Dublette zum Poll; nur auf Anforderung) |
| HA → extern (TCP) | ja, je Coordinator | nein | nein | an, **zentral 1×**, nicht je Router |
| HA → extern (HTTP 204) | nein | nein | nein | aus |
| DNS an Router-Resolver (`aiodns`) | nein | nein | nein | aus, wählbar je Router; Intervall ≥ 5 min. **[2026-11-18]** nur für Router mit laufendem dnsmasq anbieten (gateway, ap2, ap5; nicht ap6) |
| DNS an externen Resolver | nein | nein | nein | aus |
| ICMP HA → Router | nein | nein | nein | aus (nicht belegt, ob ICMP aus HA möglich; HA-seitig, nicht Teil der Router-Prüfung) |

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
| odhcpd Leases v6, RA **[2026-11-18]** | nein | ja (`dhcp` `ipv6leases`/`ipv6ra`; **kein** `ipv4leases` bei `odhcpd-ipv6only`; `add_lease` ist ein Schreibaufruf und wird nicht freigegeben) | nein | aus, Capability |
| dnsmasq-Zähler **[2026-11-18]** | nein | ja (`dnsmasq metrics`; Schlüsselsatz je dnsmasq-Version, gateway 2.93) | nein | aus, Capability |
| Ping Nexthop / Referenzziel **[2026-11-18]** | nein | ja (ACL `file` exec mit Argumentmuster) — **wirkungslos als Grenze**, solange der Login über `read '*'` auch LuCI-Gruppen erhält und eine davon den nackten Pfad freigibt (5.9 K1) | ja | aus, Capability, ≥ 5 min |
| nslookup lokal | nein | ja (ACL; gleiche Einschränkung) | ja | aus, Capability |
| traceroute | nein | ja (ACL; gleiche Einschränkung) | ja | aus, nur auf Anforderung |

### 3.3 Messpunkt AP-Router

| Testart | heute | neuer ubus | exec | Default |
|---|---|---|---|---|
| Uplink/Port-Status, LLDP | ja | nein | nein | an (besteht) |
| Interface/Default-Route | ja (bool) | nein | nein | an (besteht) |
| LAN-Gateway des AP (Nexthop der Default-Route) **[2026-11-18]** | nein | nein (Dump; je AP eine Route mit `nexthop`) | nein | an |
| Ping AP → Gateway | nein | ja (ACL; Einschränkung wie 3.2) | ja | aus, Capability, ≥ 5 min; **[2026-11-18]** auf ap6 (≈ 55 MB RAM, ≈ 12 MB verfügbar) zusätzlich Speicherschwelle |
| nslookup AP → Gateway-Resolver | nein | ja (ACL) | ja | aus, Capability |
| dnsmasq-Zähler am AP **[2026-11-18]** | nein | ja (`dnsmasq metrics`) | nein | aus; nur ap2/ap5 (ap6 ohne dnsmasq); DHCP-Zähler dort 0, nur DNS-Teil aussagekräftig |
| odhcpd am AP **[2026-11-18]** | nein | — | nein | aus; auf ap2/ap5 läuft odhcpd (`odhcpd-ipv6only`, Objekt `dhcp`), ob es dort RA/DHCPv6 bedient: nicht belegt (Inhalt nicht gelesen); auf ap6 nicht vorhanden |
| DNS-Server-Konfiguration AP | nein | nein (Dump) | nein | an |

---

## 4. Lücken und Dubletten, die zu vermeiden sind

**Dubletten (nicht neu bauen):**

1. Router-Erreichbarkeit: Poll, Tracker, `router_unreachable`, `lan_unreachable`,
   `connectivity`-Sensor. Ein zusätzlicher „Router-Ping“ aus HA bringt dasselbe mit mehr Last.
2. WAN down/Reconnect/IP-Wechsel: `detect_wan` + `wan_down`/`wan_unstable`/`wan_ip_changed`.
3. DHCP-Pool-Auslastung: `detect_dhcp` + `DhcpPool`-Sensor.
4. HA-Internetprobe: existiert bereits (`coordinator.py:769-787`) — je Router doppelt.
   **ENTSCHIEDEN (Master, 2026-11-17, korrigiert):** erst **nach dem Merge von Enterprise
   Core in `main`** zentralisieren (eine Messung für die Flotte; baut bestehende Methoden in
   `coordinator.py` um), in Backend-Feld und Panel ehrlich als „HA → Internet“ beschriften; das
   bestehende Feld `ping_ms` (`const.py:463` `KEY_PING_MS`, `coordinator.py:378`, Panel
   `topology_mesh.py:1834`) darf nicht verschwinden, eine Entity-ID darf sich nicht ändern
   (heute gibt es kein Entity dafür, 1.7); jede Bedeutungs- oder Namensänderung kommt in den
   CHANGELOG. Bis dahin unverändert.
5. Zweiter `network.interface dump` je Poll (`api.py:1948` ff. und `api.py:4230-4297`):
   **ENTSCHIEDEN (Master, 2026-11-17, korrigiert):** zusammenlegen, aber erst **nach dem
   Merge von Enterprise Core in `main`** als eigener, klar abgegrenzter Commit mit Test „ein
   Dump je Poll, alle bestehenden Felder unverändert“ (baut bestehende Methoden in `api.py`
   um); nicht jetzt, weil mehrere Sitzungen `api.py` ändern.
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

**Korrelations-Regeln für neue Incident-Typen** — **ENTSCHIEDEN (Master, 2026-11-17):**
Diagnose liefert zuerst Events und Score-Eingang; eigene Incident-Typen nur für
**Gateway-Wechsel** und **DNS-Server-Wechsel**, jeweils mit expliziten Link-Regeln und Tests,
dass sie nichts Fremdes schlucken und nicht geschluckt werden. Das bestehende
Korrelationsverhalten (Abschnitt 4.1) wird **nicht** geändert. Hinweise zum Code dafür:

- Ohne Eintrag in `DEFAULT_SETTINGS` ignoriert der Automat neue Typen (`net_rules.py:679-722`).
- Mit Eintrag wird jedes neue Incident im Fenster von `lan_unreachable` Kind
  (`net_rules.py:5186-5187`) — bestehendes Verhalten, bleibt (4.1, V1).
- `wan_down` nimmt als Incident-Kinder nur `_WAN_CHILDREN` (`net_rules.py:4769`,
  `5190-5193`). Ein neuer Typ wird nur dann Kind von `wan_down`, wenn eine neue, eigene
  Link-Regel das ausdrücklich sagt; bestehende Regeln bleiben unverändert.
- Router-Wurzeln greifen über `_concerns` (`net_rules.py:5143-5150`) auf `scope_key` mit
  Router-Präfix. Diagnose-Incidents mit Scope „HA“ (z. B. „HA → Internet“) brauchen einen
  eigenen Scope ohne Router-Präfix, sonst werden sie bei einem Router-Ausfall Kind.
- Ergebnisse von HA-Messungen dürfen **nie** Router-Incidents erzeugen, deren Ursache bei HA
  liegt (gleicher Gedanke wie `lan_unreachable`).

### 4.1 Was die bestehende Korrelation heute verdecken könnte

Nur Fakten aus dem Code (Stand `0dc20cd`, für diesen Abschnitt erneut gelesen). **Kein
Änderungsvorschlag** — das Verhalten bleibt (ENTSCHIEDEN, Master). Gemeinsame Mechanik:

- **Verknüpfen:** `correlate` (`net_rules.py:834-931`) prüft nur Incidents ohne `parent_id`,
  deren Episodenbeginn (`_link_time` = `reopened_at` oder `first_seen`, `5070-5072`) in der
  Spanne einer Wurzel liegt. Spanne `_root_span` (`5047-5053`): `first_seen − vorher` bis
  Ende `+ nachher`; Ende = `resolved_at` (bzw. jetzt) bei Level-Wurzeln
  (`_LEVEL_ROOTS` `4764-4766`: `lan_unreachable`, `router_unreachable`, `wan_down`,
  `lan_uplink_down`), sonst `last_seen`. Fenster `_ROOT_WINDOWS` (`4754-4763`). Bei mehreren
  Wurzeln gewinnt `lan_unreachable`, dann bestätigt, dann spezifischer (Doku `846-848`).
- **Stumm-Dauer eines Kind-Incidents** (`suppressed_child`, `5482-5507`): stumm, solange die
  Wurzel offen ist; nach ihrer Auflösung bis `resolved_at + nachher`. Danach zählt es nur,
  wenn es **eigene Evidence nach diesem Zeitpunkt** hat (`inc.last_seen > window_end`,
  `5506-5507`); sonst bleibt es stumm, bis es sich selbst auflöst oder bis zur Freigabe:
  `_release_children` (`933-944`) löscht `parent_id` eines **noch offenen** Kindes, wenn die
  Wurzel länger als `nachher + CHILD_RELEASE_AFTER` (3600 s, `4815`) aufgelöst ist
  (`_root_expired` `5075-5079`). Wurzel mit `router_removed`: stumm bis zu dieser Freigabe
  (`5504-5505`). **Höchste Stumm-Dauer ohne eigene neue Evidence: Wurzeldauer + nachher +
  3600 s.**
- **Bus und Score:** `_announce` (`net_engine.py:1817-1883`) überspringt stumme Kinder
  (`1865`); ein Kind, das **während** es stumm ist aufgelöst wird, feuert weder `opened` noch
  `resolved` (Doku `1828-1831`). Wird es wieder Kandidat, beginnt die Settle-Zeit erst dann
  (Kommentar `1868`, Prüfung `1869-1874`, mindestens 90 s, `const.py:596-605`). Score und Entities zählen über
  `counted_incidents` (`net_rules.py:5660`) mit derselben Regel.
- **Events:** verknüpfte Events bekommen nur `parent_id` (`correlate` `908-930`);
  `EventRing.set_parents` (`net_events.py:614-629`) setzt ihn nur, wenn noch keiner da ist,
  und es gibt **keine** Freigabe für Events (kein Gegenstück zu `_release_children` in
  `net_events.py`/`net_engine.py`, grep `parent_id=None`: keine Treffer). Der Score-Bereich
  hängt an Incident-Typen (`_AREA_PREFIX` `5440-5447`), nicht an Events. Ob die Timeline im
  Panel verknüpfte Events ausblendet oder nur gruppiert: **nicht belegt** (Frontend nicht
  geprüft).

| # | Fall | Code | Bedingung | Wie lange verdeckt |
|---|---|---|---|---|
| V1 | Jedes unabhängige Incident in einem `lan_unreachable`-Fenster (z. B. echter `wan_down`, CPU, Port-Flap eines Routers, der in den 120 s davor begann) wird bestätigtes Kind | `net_rules.py:5186-5187`; Rang `ROOT_TIERS` `4727-4738` (jeder Typ hat Rang > 1) | Tracker: alle geladenen Router (mind. 2) zugleich weg (`fleet.py:228`); Episodenbeginn in `[first_seen − 120 s, resolved_at]` (`_ROOT_WINDOWS` `4755`, nachher 0) | solange `lan_unreachable` offen; danach sofort wieder zählbar, **wenn** neue eigene Evidence nach `resolved_at` kommt; sonst bis Selbst-Auflösung oder `resolved_at + 3600 s`. Löst es sich vorher auf: nie auf dem Bus |
| V2 | Jedes Event (jede Kategorie, jeder Router) in diesem Fenster wird Kind von `lan_unreachable` | `net_rules.py:5287-5288` | wie V1, Zeitstempel des Events in der Spanne | dauerhaft (`parent_id` bleibt, keine Freigabe für Events) |
| V3 | Echter DNS-Fehler am Resolver eines **AP** während eines kurzen, unabhängigen `wan_down` am Gateway: die DNS-Events des AP werden Kind von `wan_down` | `_event_link` `net_rules.py:5312-5318` (`Category.DNS` ohne Router-Bedingung) | `wan_down` nur am Gateway (`detect_wan` `2801-2896`); Event-Zeitstempel in `[first_seen − 60 s, resolved_at + 120 s]` (`4758`) | dauerhaft verknüpft (Events). Ein DNS-**Incident** gibt es heute nicht (kein Typ mit Präfix `dns_` in `DEFAULT_SETTINGS` `130-232`; `dns_resolution` ist nur eine Ursachen-Hypothese, `1749-1775`), also kein Bus-Event in beiden Fällen; verdeckt wird die Zuordnung |
| V4 | Echter Wechsel der WAN-IP oder echte WAN-Instabilität desselben Routers rund um einen kurzen `wan_down` wird Kind | `net_rules.py:5190-5192`, `_WAN_CHILDREN` `4769` | gleicher Router (`scope_key`), Episodenbeginn in `[first_seen − 60 s, resolved_at + 120 s]` | Mechanik oben; nachher 120 s |
| V5 | Echtes eigenes Problem eines Routers (CPU, RAM, Dienst, Port) kurz nach einem Neustart wird bestätigtes Kind von `system_reboot` | `_router_link` `net_rules.py:5263-5268`, `_concerns` `5143-5150` | Incident betrifft den Router (`scope_key` = Router oder `Router:`-Präfix, oder Client an ihm); Episodenbeginn ab `first_seen` bis `last_seen + 180 s` (Event-Wurzel, `4757`); vor `first_seen` nur `wifi_*`- und Client-Incidents | Mechanik oben, nachher 180 s. Wann eine `system_reboot`-Wurzel aufgelöst wird: **nicht belegt** (nicht gelesen) |
| V6 | Gleiches bei `router_unreachable`, plus Incidents von Routern dahinter, die ebenfalls weg sind (beobachteter Pfad → bestätigt, sonst Hypothese) | `net_rules.py:5263-5277`, `_behind_down` | Level-Wurzel, Spanne `[first_seen − 120 s, resolved_at + 180 s]` (`4756`) | Mechanik oben, nachher 180 s |
| V7 | Am Gateway-Ausfall: echte `wifi_no_ip` / `wifi_dhcp_after_connect` an **beliebigen** APs werden Kind (Hypothese) | `net_rules.py:5278-5279`, `_GATEWAY_CHILDREN` `4768` | Wurzel `router_unreachable`/`system_reboot` eines Gateways (`topology.gateways`) | Mechanik oben; Konfidenz auf 0,6 gekappt (`1585-1586`) |
| V8 | Router-Events von WLAN/LAN der betroffenen Router und Router dahinter werden Kind einer Router-Wurzel; DHCP-Events am Gateway nur als Hypothese | `net_rules.py:5289-5310` | Event in der Spanne; eigene LAN-Events von vor dem Ausfall ausgenommen (`5290-5295`) | dauerhaft (Events) |
| V9 | Incidents der Router hinter einem ausgefallenen Uplink | `net_rules.py:5201-5207` | `lan_uplink_down`, Router in `view.behind`; bestätigt nur bei beobachtetem Ursprung und Pfad | Mechanik oben, nachher 60 s (`4760`) |
| V10 | Client-Incidents an einem Router während `wifi_mass_disconnect` (Hypothese) | `net_rules.py:5210-5212` | Client-Scope, Router in `child.routers`; Spanne ± 30 s (`4762`) | Mechanik oben, nachher 30 s |
| V11 | Ein kurzes echtes Problem, das komplett innerhalb einer Wurzelspanne beginnt und endet | `net_engine.py:1828-1831`, `1865` | jedes Kind aus V1, V4–V7, V9, V10 | nie auf dem HA-Bus; nur in der Incident-Historie mit `parent_id` |

**Nicht belegt** für diesen Abschnitt (die Live-Prüfung 2026-11-18 betraf nur Router und
ändert daran nichts): wie oft diese Fälle in der echten Flotte vorkommen (Grund: braucht die
Incident-Historie aus HA, HA nicht gelesen); ob das Panel verknüpfte Events ausblendet
(Grund: Frontend nicht geprüft); wann `system_reboot` aufgelöst wird und
`_port_flap_link` (`net_rules.py:5209`) / `_behind_down` im Detail (Grund: Code noch nicht
gelesen, reine Lesearbeit im Repo).

---

## 5. Router als Messpunkt — externe Befunde (zu füllen; Stand: Recherche eingearbeitet)

> Quelle: Recherche-Notiz der Schwestersitzung `net-diagnostics-openwrt-messwege.md`
> (2026-11-17, nur öffentliche Quellen, **nichts auf echten Routern geprüft**). Inhalt als
> Daten übernommen; die dort gelisteten Router-Befehle wurden **nicht** ausgeführt.
> Offene Live-Prüfungen nur mit Freigabe des Nutzers über den Master.

### 5.1 Messwege

- **Kein ubus-Objekt für Ping, Vorwärts-DNS oder Traceroute.** netifd bietet keine
  Probe-Methode (https://raw.githubusercontent.com/openwrt/netifd/master/ubus.c); rpcd-Plugin
  `luci` hat keine. `luci-rpc` hat **belegt am 2026-11-18 auf gateway, ap2, ap5, ap6** genau
  sechs Methoden: `getNetworkDevices`, `getWirelessDevices`, `getHostHints`,
  `getDUIDHints`, `getBoardJSON`, `getDHCPLeases` (Parameter `family`) — keine davon
  misst. In `ubus list` gibt es auf keinem der vier Router ein Mess-Objekt. Einziger Weg:
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
  **Belegt am 2026-11-18 auf gateway, ap2, ap5, ap6:** Objekt `network.rrdns` mit genau
  `lookup` (`addrs`, `timeout`, `server`, `port`, `limit`) vorhanden, Paket
  `rpcd-mod-rrdns` überall installiert. Die Fläche besteht also schon heute auf jedem
  Router; ob die HA-Session sie aufrufen darf, hängt am Inhalt von `luci-mod-status.json`
  (nicht gelesen) → Punkt für das Security Center.

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
  `rpcd -t` 1–600 s, danach SIGKILL. **Teilweise belegt am 2026-11-18 auf gateway, ap2,
  ap5, ap6:** `/etc/config/rpcd` enthält `option timeout 30`. Ob das Init-Skript diesen Wert
  als `-t` übergibt und ob er den exec-Timeout bestimmt: **nicht belegt** (Grund:
  Init-Skript und rpcd-Kommandozeile wurden nicht gelesen; L3/L4 waren nicht im
  Prüfskript). Planung bis dahin: ein exec-Aufruf muss deutlich unter 30 s bleiben.
- **Abgleich mit dem Repo (selbst geprüft, verifiziert):** `acl_provisioning.py:101` gibt auf
  ubus-Ebene `"file": ["read", "stat", "list", "exec"]` frei — stimmt. `acl_provisioning.py:123`
  `"service": ["list", "get_data"]` — stimmt. `acl_provisioning.py:135`
  `"/etc/init.d/rpcd": ["exec"]` — stimmt, steht aber unter **`write.file`**
  (`acl_provisioning.py:131-136`), nicht unter `read.file`. Ping usw. bräuchten neue Einträge
  und damit `ACL_VERSION` 9 + Redeploy über `ensure_acl` (`acl_provisioning.py:148`) mit
  rpcd-Neustart (`_deploy_acl` `244`, `301-305`). Das ist eine **Routeränderung** und der
  Produktentscheid gegen breites `file exec` (ACL v8, rpcd-Neustarts und Speicherlecks,
  `docs/plans/2026-10-28-ssh-polling-und-audit.md:123`) muss neu abgewogen werden.
- **Annahme „nackter exec-Pfad schon heute erlaubt“ — Stand 2026-11-18:** Das Projekt
  meldet sich standardmäßig als `root` an (`const.py:12`).
  - **Belegt am 2026-11-18 auf gateway, ap2, ap5, ap6:** Der rpcd-Login `root` hat
    `list read '*'` und `list write '*'`, bekommt also **jede** installierte ACL-Gruppe.
    Auf allen vier liegt `luci-mod-network.json` in `/usr/share/rpcd/acl.d/` (überall
    gleiche Größe), daneben u. a. `luci-base.json`, `luci-mod-status.json`,
    `luci-mod-system.json` und die Projekt-ACL `ha-openwrt-router.json` (überall gleiche
    Größe). Die Werkzeuge `/bin/ping`, `/bin/ping6`, `/usr/bin/nslookup`,
    `/bin/traceroute`, `/bin/traceroute6` liegen auf allen vier genau unter den Pfaden, die
    die LuCI-Diagnose-Gruppe laut Upstream (5.1) nackt freigibt.
  - **Nicht belegt:** ob die installierte `luci-mod-network.json` die Gruppe
    `luci-mod-network-diagnostics` mit nacktem Pfad enthält (Grund: die Prüfung hat das
    Verzeichnis nur aufgelistet, die Dateien nicht gelesen — L12 war im Prüfskript nur als
    `ls`); welcher Benutzer in den HA-Einträgen tatsächlich konfiguriert ist (Grund: HA
    wurde nicht gelesen).
  - **Folge (abgeleitet):** Wenn die Upstream-Datei unverändert ausgeliefert ist, hat eine
    als `root` angemeldete HA-Session **schon heute** `exec` auf die nackten Pfade, ohne
    Argumentprüfung; ein Argumentmuster in der Projekt-ACL schränkt dann nichts ein. Die
    Capability-Prüfung darf daher nie aus „exec erlaubt“ schließen, dass ein Projekt-Muster
    greift (5.9 K1).

### 5.3 Benötigte Pakete und Binärdateien

- OpenWrt-Busybox-Standard: PING, PING6, NSLOOKUP, TRACEROUTE, TRACEROUTE6, FANCY_PING,
  NSLOOKUP_BIG = y
  (https://raw.githubusercontent.com/openwrt/openwrt/master/package/utils/busybox/Config-defaults.in).
  **Belegt am 2026-11-18 auf gateway, ap2, ap5, ap6:** Paket `busybox` 1.37.0 installiert;
  `ping`, `ping6`, `nslookup`, `traceroute`, `traceroute6`, `wget`, `uclient-fetch`, `iw`,
  `iwinfo` vorhanden; `arping` fehlt überall; `curl` nur auf gateway und ap2. **Nicht
  belegt:** ob `ping`/`nslookup`/`traceroute` Busybox-Applets sind und ob `nslookup` die
  große Variante ist (Grund: nur `command -v`, kein `ls -l`; der Aufruf `busybox` ohne
  Argumente lieferte „applet not found“ statt der Applet-Liste).
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
| `network.interface dump` / `.<if> status` | `route` (mit `target`, `nexthop`, `source`, `mask`, `metric`), `dns-server`, `dns-search`, `dns_metric`, `ipv4-address`, `ipv6-address`, `ipv6-prefix`, `ipv6-prefix-assignment`, `delegation`, `neighbors`, `inactive`, `data` — Schlüssel **belegt am 2026-11-18 auf allen vier** (nur Häufigkeit gezählt). Abgeleitet aus der Häufigkeit: Die Adress-, Routen- und DNS-Schlüssel kommen je Interface **zweimal** vor (einmal oben, einmal in `inactive`) → ein Parser muss die oberste Ebene lesen, nicht `inactive` | **erlaubt** (`105-107`) |
| `network.device status` | Geräte, Carrier, Statistik | **erlaubt** (`104`) |
| odhcpd `dhcp` (https://raw.githubusercontent.com/openwrt/odhcpd/master/src/ubus.c) | **Live 2026-11-18 (gateway, ap2, ap5, Paket `odhcpd-ipv6only`):** `ipv6leases`, `ipv6ra`, `add_lease` (**schreibend**). `ipv4leases` **widerlegt** (Methode fehlt, Aufruf liefert nichts). ap6: kein Objekt | **fehlt**; nur `ipv6leases`/`ipv6ra` freigeben, nie `add_lease` |
| `dnsmasq metrics` | **Live 2026-11-18:** Schlüssel in 5.8; 26 Schlüssel bei dnsmasq 2.91 (ap2), 30 bei 2.93 (gateway, ap5); ap6 ohne Objekt. Daneben gibt es überall, wo dnsmasq läuft, ein Objekt `dnsmasq.dns` (Methoden nicht gelistet) | **fehlt** |
| `service list` | laufende Dienste | **erlaubt** (`123`). **2026-11-18:** dnsmasq und odhcpd erscheinen auf gateway, ap2, ap5, auf ap6 nicht. Ob das `running`-Kennzeichen je Instanz stimmt: **nicht belegt** (Grund: es wurden nur Dienstnamen ausgegeben) |
| `uci get dhcp` | Pools, ra/dhcpv6-Optionen | ubus `uci get` **erlaubt** (`121`); Leserecht für `root` über `read '*'` belegt (5.2). Der Code nutzt es schon (`api.py:3944`). Ob ra/dhcpv6-Optionen enthalten sind: nicht belegt (nur nach Log-Optionen gefiltert) |

### 5.5 Last auf dem Router

- Keine veröffentlichten Zahlen (Zielplattform laut Recherche MT7981; korrigiert im
  nächsten Punkt). Schätzung der Recherche: Ping mit
  3–5 Paketen und nslookup vernachlässigbar; `file exec` ein fork/exec, wenige ms;
  SSH-Aufbau am teuersten (Schlüsseltausch, vermutlich einige hundert ms). **Muss gemessen
  werden.** Stand 2026-11-18: **nicht belegt (aktiver Test, eigene Freigabe nötig)** — die
  Live-Prüfung hat bewusst weder ping noch nslookup noch eine Zeitmessung des SSH-Aufbaus
  ausgeführt (L14–L16 offen).
- **Belegt am 2026-11-18:** Die Flotte ist nicht nur MT7981. gateway und ap2 sind Cudy
  WR3000 v1, ap5 ist ein AVM FRITZ!Repeater 3000, ap6 ein AVM FRITZ!WLAN Repeater 1750E
  mit etwa 55 MB RAM, davon zum Prüfzeitpunkt etwa 12 MB verfügbar. Für ap6 ist jeder
  zusätzliche Prozess (auch ein kurzer fork/exec) relevanter als auf den anderen; eine
  Speicherschwelle als Vorbedingung für aktive Tests ist dort Pflicht (5.9).
- **Vorschlag Budget:** je Router höchstens 1 aktiver Test je 5 min, max. 3 Pakete, `-W 1`,
  nur über ubus (kein SSH für periodische Tests), nicht bei gedrosseltem Coordinator
  (CPU > 100 %, `coordinator.py:1244-1270`) und nicht im SSH-Rückfall.

### 5.6 Referenzziele

- mwan3-Beispiel `track_ip`: 1.0.0.1, 1.1.1.1, 208.67.222.222, 208.67.220.220 (+ IPv6)
  (https://raw.githubusercontent.com/openwrt/packages/master/net/mwan3/files/etc/config/mwan3);
  öffentliche Resolver Google, Quad9, Cloudflare; HTTP-204: `connectivitycheck.gstatic.com/generate_204`;
  NetworkManager-Prüfintervall Standard 300 s. Nutzungsbedingungen: keine Beschränkung
  gefunden, aber auch keine Erlaubnis — **nicht belegt** (Grund: Recherchefrage zu
  Fremddiensten, durch eine Router-Prüfung nicht klärbar; die Live-Prüfung 2026-11-18 hat
  dazu nichts beigetragen).
- DECIDED: Referenzziele sind Einstellungen mit leerer Standardliste außer dem Nexthop aus dem
  Dump — keine fest eingebauten Fremdziele ohne Zustimmung des Nutzers (Datenschutz, ToS
  ungeklärt). Die bestehende 8.8.8.8-Probe ist davon ausgenommen; ihre Zukunft ist
  entschieden (Abschnitt 4 Punkt 4, Abschnitt 9 F2).

### 5.7 Offene Live-Prüfungen (nur mit Freigabe des Nutzers über den Master)

Aus der Recherche übernommen und je Befehl beschrieben; in dieser Sitzung **nichts davon
ausgeführt**. Platzhalter in spitzen Klammern; echte Adressen und Namen gehören nicht in
dieses Dokument. Alle Befehle laufen in einer SSH-Sitzung auf **einem** Router; die
SSH-Anmeldung selbst erzeugt einen Login-Eintrag im Systemlog (dropbear), sonst nichts.

**Stand 2026-11-18:** Der Nutzer hat die nur lesenden Prüfungen freigegeben; der Master hat
sie per SSH auf gateway, ap2, ap5 und ap6 ausgeführt (eigenes Prüfskript, kein ping, kein
nslookup, kein traceroute, keine ACL-Probe). Diese Sitzung hat nur die Ergebnisdateien
gelesen, keinen Router berührt. Abdeckung je Punkt:

| # | Stand 2026-11-18 |
|---|---|
| L1 | **nicht ausgeführt** — nur `command -v` je Werkzeug (Pfad belegt), kein `ls -l`; Applet-Frage offen |
| L2 | **ausgeführt** (`apk list -I`, gefiltert) auf allen vier |
| L3 | **nicht ausgeführt** (nicht im Prüfskript) |
| L4 | **nicht ausgeführt** (nicht im Prüfskript) |
| L5 | **ausgeführt** auf allen vier |
| L6 | **ausgeführt** für `luci-rpc`, `network.rrdns`, `dnsmasq`, `dhcp` (zusätzlich `iwinfo`, `usteer`); `dnsmasq.dns` nicht gelistet |
| L7 | **ausgeführt** (je ein Aufruf); ob das Lesen Zähler zurücksetzt: **nicht belegt** (Grund: nur ein Aufruf je Router, kein Vorher/Nachher) |
| L8 | **teilweise:** `ipv4leases` aufgerufen (leere Ausgabe, Methode fehlt); `ipv6leases`/`ipv6ra` nur als Signatur (L6), nicht aufgerufen |
| L9 | **ausgeführt**, nur Schlüsselhäufigkeit gezählt, keine Werte |
| L10 | **teilweise:** `service list` ohne Filter, nur Dienstnamen ausgegeben, kein `running`-Kennzeichen |
| L11 | **teilweise:** `uci show dhcp` nur nach Log-Optionen gefiltert |
| L12 | **teilweise:** Verzeichnis `acl.d` gelistet (Namen, Größen), Inhalte nicht gelesen |
| L13 | **ausgeführt**, Passwort maskiert |
| L14–L16 | **nicht ausgeführt** — aktive Tests, eigene Freigabe nötig |
| W1 | **nicht ausgeführt** — ändert die ACL, eigene Freigabe nötig |

Ergebnisse: 5.8; Folgerungen: 5.9.

#### 5.7 (a) Nur lesende Befehle — ändern keine Konfiguration

| # | Befehl | Was er liest | Änderung am Router |
|---|---|---|---|
| L1 | `ls -l /bin/ping /bin/ping6 /usr/bin/nslookup /usr/bin/traceroute /bin/busybox` | Dateiattribute und Symlink-Ziele (ob die Werkzeuge Busybox-Applets sind) | keine; liest nur Verzeichniseinträge |
| L2 | `apk info -e <paketname>` (OpenWrt 25.12) bzw. `opkg list-installed` (ältere Versionen) | ob ein Paket installiert ist (z. B. `rpcd-mod-rrdns`, `odhcpd`, `dnsmasq`-Variante) | keine; liest nur die Paketdatenbank, installiert nichts |
| L3 | `ps w \| grep '[r]pcd'` | Kommandozeile des laufenden rpcd (ob `-t <timeout>` gesetzt ist) | keine; liest die Prozessliste |
| L4 | `cat /etc/init.d/rpcd` | ob das Init-Skript `-t` setzt | keine; liest eine Datei |
| L5 | `ubus list` | Namen aller ubus-Objekte (gibt es `dnsmasq`, `dhcp`, `network.rrdns`, `luci-rpc`?) | keine; ruft keine Methode auf |
| L6 | `ubus -v list network.rrdns`, `ubus -v list dnsmasq`, `ubus -v list dhcp`, `ubus -v list luci-rpc` | Methoden und Parameter dieser Objekte | keine; listet nur Signaturen, ruft keine Methode auf |
| L7 | `ubus call dnsmasq metrics` | DNS-/DHCP-Zähler von dnsmasq (Schlüsselnamen) | keine Konfigurationsänderung; ob das Lesen Zähler zurücksetzt: **nicht belegt** (Grund siehe Stand-Tabelle oben) |
| L8 | `ubus call dhcp ipv4leases`, `ubus call dhcp ipv6leases`, `ubus call dhcp ipv6ra` | odhcpd-Leases v4/v6 und RA-Status | keine; Leseaufrufe von odhcpd. Ausgabe enthält MACs/IPs/Hostnamen → nicht in Dokumente kopieren |
| L9 | `ubus call network.interface dump` | Interfaces inkl. `route`/`nexthop`, `dns-server`, IPv6-Felder | keine; derselbe Aufruf, den die Integration ohnehin jede Minute macht. Ausgabe enthält Adressen → nur Feldnamen notieren |
| L10 | `ubus call service list '{"name":"dnsmasq"}'` (ebenso `odhcpd`) | ob procd den Dienst als laufend meldet | keine; Leseaufruf |
| L11 | `uci show dhcp` | DHCP-Konfiguration inkl. ra/dhcpv6-Optionen | keine; liest die Konfiguration, kein `uci set`/`commit` |
| L12 | `cat /usr/share/rpcd/acl.d/*.json` | alle installierten rpcd-ACL-Gruppen (gibt es `luci-mod-network-diagnostics` mit nacktem `/bin/ping`?) | keine; liest Dateien |
| L13 | `cat /etc/config/rpcd` | welche ACL-Gruppen der Login `root` bekommt | keine; liest eine Datei. **Enthält Passwort-Verweise/-Hashes** → Ausgabe nicht kopieren, nur `read`/`write`-Zeilen notieren |
| L14 | `time ping -c 3 -W 1 <Gateway-LAN-Adresse>` (auf einem AP) | Antwortzeit, Verlust und Laufzeit-/CPU-Kosten eines Pings | **keine Konfigurationsänderung**; startet einen Prozess (≈ 3 s) und sendet **3 ICMP-Echo-Pakete an ein internes Ziel** (den Gateway im LAN) |
| L15 | `time nslookup <Testname> 127.0.0.1` | Antwortart des lokalen Resolvers und Laufzeit | **keine Konfigurationsänderung**; startet einen Prozess und sendet DNS-Anfragen an den **eigenen lokalen Resolver** (127.0.0.1; Busybox fragt je nach Variante A und AAAA, bei Timeout bis zu 2 Wiederholungen). Ist der Name nicht im Cache, leitet dnsmasq die Anfrage an den **externen Upstream-Resolver** weiter (wenige DNS-Pakete nach außen) |
| L16 | `time ssh <router-alias> true` (vom Windows-Rechner aus) | Dauer des SSH-Aufbaus | **keine Konfigurationsänderung**; eine SSH-Verbindung, startet kurz eine Shell auf dem Router, Login-Eintrag im Systemlog |

#### 5.7 (b) Einziger Punkt, der die rpcd-ACL des Routers ändert — eigene Freigabe

| # | Schritt | Änderung | Rückweg |
|---|---|---|---|
| W1 | exec-ACL mit Argumentmuster testen: eine **zusätzliche** Test-ACL-Datei unter `/usr/share/rpcd/acl.d/` mit genau einem Eintrag wie `"/bin/ping -c 3 -W 1 *": ["exec"]` anlegen, rpcd neu starten (`/etc/init.d/rpcd restart`), dann per ubus `file exec` einen erlaubten und einen nicht erlaubten Aufruf prüfen | **ändert die ACL des Routers**; der rpcd-Neustart beendet **alle** rpcd-Sitzungen (HA meldet sich neu an, LuCI-Nutzer werden abgemeldet); der erlaubte Testaufruf sendet 3 ICMP-Pakete wie L14 | Test-Datei löschen, rpcd erneut neu starten; die Projekt-ACL `ha-openwrt-router.json` bleibt unberührt. Vorher L12 sichern (Backup der ACL-Dateien), Eintrag mit Befehl und Rückweg ins Änderungsprotokoll |

W1 ist **nicht** von einer Freigabe für (a) gedeckt. Ob W1 überhaupt nötig ist, hängt von
L12/L13 ab (Annahme 5.2: bei nacktem `/bin/ping` aus einer LuCI-Gruppe ist ein
Argumentmuster wirkungslos). **Stand 2026-11-18:** L13 belegt `root` mit `read '*'`; L12
ist ohne Dateiinhalte, also bleibt offen, ob W1 überhaupt etwas Neues zeigen kann (5.9 K1).

### 5.8 Live-Befunde 2026-11-18 (nur lesend, vier Router)

Quelle: Ergebnisdateien des Masters, nur gelesen. Keine Adressen, MACs, Hostnamen, SSIDs,
Lease-Inhalte oder Zählerstände übernommen; Geräte nur als Rolle mit Modell und Version.

**Geräte**

| Gerät | Modell | OpenWrt | rpcd | dnsmasq (Paket) | Rolle laut Dump/Diensten |
|---|---|---|---|---|---|
| gateway | Cudy WR3000 v1 | 25.12.1 | 2026.10.04 | 2.93 | `wan`, `wan6`, `wg0`, `odhcp6c.wan`; dnsmasq + odhcpd laufen als Objekt |
| ap2 | Cudy WR3000 v1 | 25.12.1 | 2025.12.03 | 2.91 | Default-Route im LAN; dnsmasq + odhcpd als Objekt |
| ap5 | AVM FRITZ!Repeater 3000 | 25.12.6 | 2026.10.04 | 2.93 | Default-Route im LAN; dnsmasq + odhcpd als Objekt |
| ap6 | AVM FRITZ!WLAN Repeater 1750E | 25.12.2 | 2025.12.03 | 2.91 (installiert, kein Objekt, nicht in `service list`) | Relay (`relayd` in `service list`); kein `dnsmasq`, `dhcp`, `usteer`; ca. 55 MB RAM |

**Pakete und Werkzeuge (alle vier, sofern nicht anders genannt)**

| Punkt | Befund |
|---|---|
| `busybox` | 1.37.0 überall |
| `rpcd-mod-file` (liefert `file exec`) | überall installiert, gleiche Version wie rpcd |
| `rpcd-mod-luci` | 20240305 überall |
| `rpcd-mod-rrdns` | 20170710 überall, Objekt `network.rrdns` überall |
| `rpcd-mod-rpcsys` | gateway, ap5, ap6; **nicht** auf ap2 (für Diagnose ohne Bedeutung, nur Abweichung) |
| `odhcpd-ipv6only` | gateway, ap2, ap5 (ap6: Objekt fehlt; Paketstatus nicht im Filter sichtbar) |
| `usteer` | gateway, ap2, ap5; nicht ap6 |
| `wpad` | gateway, ap2, ap5 `wpad-mesh-openssl`; ap6 `wpad-mbedtls` |
| `ping`, `ping6`, `nslookup`, `traceroute`, `traceroute6`, `wget`, `uclient-fetch`, `iw`, `iwinfo` | überall vorhanden, Pfade wie in der LuCI-ACL (5.2) |
| `curl` | nur gateway, ap2 |
| `arping` | nirgends |

**ubus-Signaturen**

| Objekt | Methoden | Wo |
|---|---|---|
| `luci-rpc` | `getNetworkDevices`, `getWirelessDevices`, `getHostHints`, `getDUIDHints`, `getBoardJSON`, `getDHCPLeases` | alle vier |
| `network.rrdns` | `lookup` (`addrs`, `timeout`, `server`, `port`, `limit`) | alle vier |
| `dnsmasq` | nur `metrics` | gateway, ap2, ap5 |
| `dnsmasq.dns` | nicht gelistet | gateway, ap2, ap5 |
| `dhcp` (odhcpd) | `ipv6leases`, `ipv6ra`, `add_lease` (`ip`, `mac`, `duid`, `hostid`, `leasetime`, `name`) — **kein** `ipv4leases` | gateway, ap2, ap5 |
| Mess-Objekt (Ping/DNS/Traceroute) | keins | alle vier |

**`dnsmasq metrics` — Schlüssel (Werte nicht übernommen)**

- dnsmasq 2.91 (ap2), 26 Schlüssel: `dns_cache_inserted`, `dns_cache_live_freed`,
  `dns_queries_forwarded`, `dns_auth_answered`, `dns_local_answered`, `dns_stale_answered`,
  `dns_unanswered`, `dnssec_max_crypto_use`, `dnssec_max_sig_fail`, `dnssec_max_work`,
  `bootp`, `pxe`, `dhcp_ack`, `dhcp_decline`, `dhcp_discover`, `dhcp_inform`, `dhcp_nak`,
  `dhcp_offer`, `dhcp_release`, `dhcp_request`, `noanswer`, `leases_allocated_4`,
  `leases_pruned_4`, `leases_allocated_6`, `leases_pruned_6`, `tcp_connections`.
- dnsmasq 2.93 (gateway, ap5), 30 Schlüssel: zusätzlich `dhcp_leasequery`,
  `dhcp_lease_unassigned`, `dhcp_lease_actve` (Schreibweise so ausgeliefert),
  `dhcp_lease_unknown`.
- Auf ap2 und ap5 stehen alle DHCP-Zähler auf 0 (dnsmasq vergibt dort keine Leases);
  welche Zähler dort steigen, wurde nicht im Zeitverlauf beobachtet.

**rpcd-Konfiguration und ACL-Dateien**

- `/etc/config/rpcd` auf allen vier: `option timeout 30`; Login `root` mit
  `list read '*'` / `list write '*'`. Auf dem gateway gibt es zusätzlich einen
  Paket-eigenen Login mit eigener Gruppe (für Diagnose ohne Bedeutung).
- `/usr/share/rpcd/acl.d/` auf allen vier: `ha-openwrt-router.json`, `luci-base.json`,
  `luci-mod-network.json`, `luci-mod-status.json`, `luci-mod-status-index.json`,
  `luci-mod-system.json`, `luci-app-firewall.json`, `luci-app-package-manager.json`,
  `unauthenticated.json`; je nach Gerät dazu Dateien für usteer, DDNS, WireGuard und
  Attended Sysupgrade. Inhalte nicht gelesen.

**`network.interface dump` — Form**

- Schlüssel auf allen vier: `route` mit `target`, `mask`, `nexthop`, `source`, `metric`;
  `dns-server`, `dns-search`, `dns_metric`, `ipv4-address`, `ipv6-address`, `ipv6-prefix`,
  `ipv6-prefix-assignment`, `delegation`, `neighbors`, `l3_device`, `inactive`, `data`.
- `nexthop` (wie `target`, `source`) tritt am gateway zweimal, auf jedem AP einmal auf
  (nur gezählt). Abgeleitet: ein AP hat genau eine Route mit Nexthop; da `wan`/`wan6` dort
  fehlen, liegt sie auf dem LAN-Interface. Über welche Interfaces die zwei Routen des
  gateway laufen: nicht belegt (Grund: nur Häufigkeiten, keine Zuordnung ausgegeben).
- Die Adress-, Routen- und DNS-Schlüssel kommen am gateway je 14-mal bei 7 Interfaces vor
  (je einmal oben und einmal in `inactive`); auf den APs gilt dasselbe Verhältnis.
- Alle Zählungen sind Schlüssel-Häufigkeiten, keine Werte; ob `dns-server` gefüllt ist,
  geht daraus nicht hervor.

### 5.9 Folgerungen für das Design (abgeleitet, Vorschlag — nicht vom Master entschieden)

- **K1 — Argumentmuster sind vermutlich wirkungslos.** `root` bekommt jede ACL-Gruppe
  (belegt); `luci-mod-network.json` liegt überall (belegt); Upstream gibt darin die
  nackten Werkzeugpfade frei (5.1, nicht auf den Geräten gelesen). Folge: Die Projekt-ACL
  kann eine `root`-Session nicht enger machen. Ein Argumentmuster wirkt nur für einen
  eigenen, nicht-`root`-Login ohne LuCI-Gruppen. Vor jeder ACL-Arbeit (W1) zuerst L12 mit
  Dateiinhalten wiederholen. Für F3 heißt das: die Begrenzung muss in HA liegen (feste
  Zielliste, feste Argumente, `diag_targets.py`), nicht im Router.
- **K2 — Capability je Gerät statt je Flotte.** Die vier Router unterscheiden sich in
  Objekten, Paketen, Versionen und RAM. Die Capability-Erkennung (enterprise-core) braucht
  mindestens diese Flags je Router:
  - `has_dnsmasq_ubus` (Objekt `dnsmasq` in `ubus list`) — fehlt auf ap6.
  - `dnsmasq_metric_keys` — Schlüsselmenge als Liste, nicht als Version; die vier
    2.93-Schlüssel optional behandeln.
  - `has_odhcpd_ubus` und `odhcpd_v4 = false` — `ipv4leases` nie aufrufen; v4-Leases
    weiterhin über `luci-rpc getDHCPLeases`.
  - `is_relay` (Dienst `relayd`, kein `dnsmasq`/`dhcp`) — DNS- und DHCP-Prüfungen auf dem
    Gerät aus.
  - `tools` (Pfad je Werkzeug) — `curl` nicht voraussetzen; HTTP-Prüfungen nur mit `wget`
    oder `uclient-fetch`; `arping` gibt es nicht.
  - `mem_available` als Vorbedingung — aktive Tests auf Geräten mit wenig freiem Speicher
    (ap6) aussetzen; Schwelle selbst ist noch nicht belegt (Grund: Abschnitt 8 Punkt 17).
  - Erkennung über vorhandene Wege: `ubus list` bzw. Methoden-nicht-gefunden und
    `_acl_blocked`, kein Versionsvergleich.
- **K3 — exec-Laufzeit.** `option timeout 30` ist überall gesetzt; bis L3/L4 belegen, wie
  rpcd den Wert nutzt, plant jeder exec-Aufruf mit klar unter 30 s (Ping 3 Pakete `-W 1`
  passt).
- **K4 — `dhcp add_lease` nie freigeben.** Die Methode schreibt; eine künftige
  Projekt-ACL nennt `ipv6leases` und `ipv6ra` einzeln, kein `dhcp: ["*"]`.
- **K5 — rrdns ist vorhandene Fläche.** `network.rrdns lookup` mit freiem `server`/`port`
  existiert auf allen vier; für `root` ist sie vermutlich schon erreichbar (K1). Gehört ins
  Security Center, Diagnose nutzt sie weiterhin nicht (DECIDED 9).
- **K6 — Nexthop-Deutung.** Auf APs ist der Nexthop der Default-Route der LAN-Gateway, nicht
  der Provider. Die Kette „AP → Nexthop“ misst also den LAN-Weg zum gateway; „Gateway →
  Nexthop“ ist der WAN-Weg. Die Matrix 3.3 ist entsprechend angepasst.
- **K7 — Parser auf die oberste Ebene.** Wegen `inactive` kommen Adress-, Routen- und
  DNS-Schlüssel je Interface doppelt vor; Dump-Auswertung liest nur die oberste Ebene.
  Testfixtures dafür mit erfundenen Werten (Dokumentationsadressen) und mit befülltem
  `inactive`, damit ein falscher Zugriff auffällt.
- **K8 — Reichweite der Belege.** Belegt sind nur diese vier Router mit 25.12.x. Für
  weitere Geräte der Flotte und ältere Versionen gelten die Aussagen nicht automatisch; die
  Capability-Prüfung darf deshalb keinen Gerätetyp fest annehmen.

---

## 6. Abhängigkeiten, die noch nicht auf `main` sind (nur vermerkt)

Nichts davon existiert in `0dc20cd`; hier wird **nichts** davon entworfen.

- **enterprise-core-Sitzung:** stabile Router-ID (heute `entry_id`), Registry,
  Capability-Erkennung, Event-/Audit-Schema, Freigabe-Workflow (Approval). Diagnose braucht
  davon: Router-ID als Schlüssel im Diagnose-Store, Capability-Flags für „exec erlaubt /
  Busybox-Werkzeug vorhanden / odhcpd-ubus vorhanden“, Audit-Eintrag für jede aktive
  Messung auf einem Router, Approval für die ACL-Erweiterung.
  **Stand laut Master (2026-11-17, nicht selbst geprüft, nichts geholt oder gemergt):** Der
  Vertrag ist auf Branch `origin/claude/enterprise-core-49ade2` veröffentlicht — Commit
  `2827c22` (Plan + Vertrag `docs/dev/configuration-api-v1.md`) und Commit `5c9d248` (Typen:
  `core_models.py`, `core_errors.py`, `core_masking.py`). Bisher nur Typen und Doku;
  Registry, Guard und Event-Bus als laufender Code folgen noch. Die zwei Umbauten aus
  Abschnitt 9 F1/F2 warten auf den Merge dieses Branches in `main`. Außerdem der neue
  „Enterprise“-Menü-Container im Panel, in den „Netzwerkdiagnose“ als Unter-Tab kommt
  (ENTSCHIEDEN, 1.10).
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
  Netz vollständig offline läuft: **nicht belegt** (Grund: braucht einen Testlauf ohne
  Netzzugang auf diesem Rechner; betrifft nicht die Router und war nicht Teil der
  Live-Prüfung 2026-11-18).
- **Vorschlag für Phase B:** autouse-Fixture in `conftest.py`, die `asyncio.open_connection`
  und jede Diagnose-Messung patcht, damit Tests nie ins Netz gehen.

---

## 8. Nicht belegt

Stand nach der Live-Prüfung vom 2026-11-18 (nur lesend; gateway, ap2, ap5, ap6; siehe
5.7 Stand-Tabelle und 5.8). Jeder Punkt hat ein Urteil.

1. Feldnamen und Form von `route[].nexthop`, `dns-server`, `ipv6-address`/`ipv6-prefix` im
   `network.interface dump`. — **Belegt am 2026-11-18 auf gateway, ap2, ap5, ap6**
   (Schlüssel und Häufigkeit, 5.8). Werte und Verschachtelung im Einzelnen nicht gelesen;
   die Fixtures bleiben synthetisch (`tests/test_net_infra_review.py:248-256`) und müssen um
   `inactive` erweitert werden (5.9 K7).
2. Ob ICMP aus HA (unprivilegiert) in der Zielinstallation möglich ist. — **Nicht belegt**
   (Grund: betrifft HA, nicht die Router; HA wurde nicht berührt).
3. Ob die Router-Images Busybox ping/nslookup/traceroute so enthalten wie der Standard. —
   **Belegt am 2026-11-18 auf gateway, ap2, ap5, ap6** für Vorhandensein und Pfad (busybox
   1.37.0). **Nicht belegt**, ob es Applets sind und ob `nslookup` die große Variante ist
   (Grund: kein `ls -l`, `busybox` ohne Argumente gab keine Liste aus; L1).
4. rpcd-Login-Konfiguration für root und ob `luci-mod-network`-ACL schon nackte exec-Rechte
   gibt. — **Belegt am 2026-11-18 auf gateway, ap2, ap5, ap6:** `root` hat `read '*'` /
   `write '*'`, `luci-mod-network.json` ist installiert. **Nicht belegt:** Inhalt der Datei
   (Grund: L12 nur als Verzeichnisliste) und welcher Benutzer in HA konfiguriert ist (Grund:
   HA nicht gelesen).
5. Ob das rpcd-Init-Skript `-t` setzt (exec-Timeout). — **Teilweise:** `option timeout 30`
   **belegt am 2026-11-18 auf allen vier**; ob daraus `-t` wird: **nicht belegt** (Grund:
   L3/L4 nicht ausgeführt).
6. `dnsmasq metrics` und odhcpd-`dhcp`. — **Belegt am 2026-11-18:** `metrics` auf gateway,
   ap2, ap5 mit 26 (2.91) bzw. 30 (2.93) Schlüsseln; auf ap6 kein Objekt. odhcpd-`dhcp` auf
   gateway, ap2, ap5 vorhanden. **Widerlegt am 2026-11-18 auf gateway, ap2, ap5:** die
   Annahme, odhcpd liefere `ipv4leases` — Paket ist `odhcpd-ipv6only`, Methoden sind nur
   `ipv6leases`, `ipv6ra` und das schreibende `add_lease`. Erste dnsmasq-Version mit
   `metrics`: **nicht belegt** (Grund: nur 2.91 und 2.93 gesehen). Nötige ACL: Projekt-ACL
   hat sie nicht (5.4), `root` bekommt sie über `read '*'` vermutlich trotzdem (nicht belegt,
   ACL-Inhalte ungelesen).
7. Ob `service list` dnsmasq/odhcpd zuverlässig als laufend meldet. — **Teilweise:**
   Dienstnamen **belegt am 2026-11-18** (gateway, ap2, ap5 ja; ap6 nein, dafür `relayd`).
   `running`-Kennzeichen: **nicht belegt** (Grund: nur Namen ausgegeben, L10 teilweise).
8. Unterschiede 23.05 / 24.10 / 25.12 für LuCI-Diagnostics-ACL und `file exec`. —
   **Nicht belegt** (Grund: alle vier Router laufen auf 25.12.x; ältere Versionen nicht in
   der Prüfung). Innerhalb 25.12 belegt: zwei rpcd-Stände (2025.12.03, 2026.10.04), beide
   mit `rpcd-mod-file`.
9. Kosten (CPU, Zeit) von ping/nslookup per `file exec` und SSH-Aufbau. — **Nicht belegt
   (aktiver Test, eigene Freigabe nötig)**; L14–L16 nicht ausgeführt. Korrigiert: die
   Flotte ist nicht nur MT7981 (5.5).
10. Nutzungsbedingungen öffentlicher Referenzziele. — **Nicht belegt** (Grund:
    Recherchefrage, durch eine Router-Prüfung nicht klärbar).
11. Ob HA denselben Internetweg nutzt wie das Gateway (für die Deutung von `ping_ms`). —
    **Nicht belegt** (Grund: betrifft HA-Host und dessen Routing; nicht gelesen).
12. Ob die Testsuite ohne Netzzugang komplett offline bleibt (Abschnitt 7). — **Nicht
    belegt** (Grund: braucht einen Offline-Testlauf auf diesem Rechner; nicht Teil der
    Router-Prüfung).
13. Ob netifd/odhcpd/dnsmasq-Logzeilen live so aussehen wie im Parser erwartet
    (`log_parser.py:1-20`, A6 aus dem NI-Plan). — **Nicht belegt** (Grund: die Prüfung hat
    nur dropbear- und uhttpd/rpcd-Logzeilen gelesen, keine von netifd, odhcpd oder dnsmasq).
14. Schnittstellen der enterprise-core-Sitzung (Router-ID, Capability, Audit, Approval) —
    **nicht belegt** (Grund: nicht auf `main`, Branch nicht geholt; laut Master bisher nur
    Typen und Doku, 6).
15. **Neu 2026-11-18:** ob `dnsmasq.dns` Methoden mit Diagnosewert hat — **nicht belegt**
    (Grund: Objekt nur in `ubus list` gesehen, Signatur nicht gelistet).
16. **Neu 2026-11-18:** ob odhcpd auf ap2/ap5 tatsächlich RA/DHCPv6 bedient und wie
    `ipv6leases`/`ipv6ra` antworten — **nicht belegt** (Grund: nur Signaturen, nicht
    aufgerufen).
17. **Neu 2026-11-18:** Speicherschwelle für aktive Tests auf ap6 — **nicht belegt**
    (Grund: nur ein Messpunkt des freien Speichers, kein Verlauf).

---

## 9. Entscheidungen, Fragen, Doku-Prüfung

**DECIDED (diese Sitzung):**

- ~~DECIDED: Arbeitstitel „Netzwerkprüfung“ als Unter-Tab von `DiagnoseView`~~ — **ersetzt**
  durch ENTSCHIEDEN (Master) F5 unten.
- DECIDED: Phase B nutzt nur Daten ohne Routeränderung (Dump-Auswertung, HA-seitige
  Messungen, ubus-Zeitmessung); alles mit exec ist Phase C — die ACL-Erweiterung ist eine
  Routeränderung mit Freigabepflicht.
- DECIDED: keine Zusatzpakete, nur Busybox-Werkzeuge (5.3).
- DECIDED: keine fest eingebauten neuen Fremdziele (5.6).
- DECIDED: `network.rrdns` wird nicht genutzt — PTR an beliebigen Server ist SSRF-Fläche
  ohne Diagnosenutzen.

**Fragen an den Master — entschieden:**

- F1 — Zweiter `network.interface dump` je Poll. **ENTSCHIEDEN (Master, 2026-11-17,
  korrigiert):** zusammenlegen, aber erst **nach dem Merge von Enterprise Core in `main`**
  (nicht in Stufe 3; es baut bestehende Methoden in `api.py` um), als eigener, klar
  abgegrenzter Commit mit einem Test, der belegt: ein Dump je Poll und alle bestehenden
  Felder unverändert. Nicht jetzt, weil mehrere Sitzungen `api.py` ändern.
- F2 — 8.8.8.8-Probe. **ENTSCHIEDEN (Master, 2026-11-17, korrigiert):** erst **nach dem
  Merge von Enterprise Core in `main`** zentralisieren (nicht in Stufe 3; es baut bestehende
  Methoden in `coordinator.py` um), eine Messung für die Flotte, in Backend-Feld und Panel ehrlich als „HA → Internet“ beschriften.
  Das bestehende Sensor-/Datenfeld `ping_ms` darf nicht verschwinden, seine Entity-ID darf
  sich nicht ändern; jede Bedeutungs- oder Namensänderung kommt in den CHANGELOG. Bis dahin
  unverändert. (Bestand: `ping_ms` ist heute ein Datenfeld, `const.py:463`,
  `coordinator.py:378`, `topology_mesh.py:1834`; ein Entity dafür gibt es nicht, 1.7.)
- F3 — exec-ACL für routerseitige Tests. **ENTSCHIEDEN (Master, 2026-11-17): NICHT
  entschieden.** Hängt an den Live-Prüfungen in 5.7, die nur der Nutzer freigeben kann. Bis
  dahin wird der routerseitige Weg nur als Schnittstelle mit Capability-Prüfung gebaut,
  standardmäßig aus, getestet gegen Mocks.
- F4 — Incidents oder Events. **ENTSCHIEDEN (Master, 2026-11-17):** zuerst Events und
  Score-Eingang; eigene Incident-Typen nur für Gateway-Wechsel und DNS-Server-Wechsel, mit
  expliziten Link-Regeln und Tests, dass sie nichts Fremdes schlucken und nicht geschluckt
  werden.
- F5 — Bestehende Korrelation (`lan_unreachable` übernimmt jedes Incident im Fenster,
  `wan_down` übernimmt alle DNS-Events jedes Routers). **ENTSCHIEDEN (Master, 2026-11-17):**
  **nicht** ändern. Was sie verdecken kann: Abschnitt 4.1.
- F6 — UI. **ENTSCHIEDEN (Master, 2026-11-17):** „Network Diagnostics“ wird Unter-Tab des
  neuen „Enterprise“-Menü-Containers, den die enterprise-core-Sitzung anlegt, **nicht**
  Unter-Tab der bestehenden Ansicht „Diagnose“. Deutscher Tab-Name: „Netzwerkdiagnose“.
  Ersetzt den früheren DECIDED-Punkt „Netzwerkprüfung“.
- F7 — Herkunft von `diag_targets.py` / `tests/test_diag_targets.py` im Worktree
  (Abschnitt 6): offen, liegt beim Master.

**Doku geprüft:** https://developers.home-assistant.io/blog/ (leitet um auf
https://contributors.home-assistant.io/blog/), Liste bis 2026-11-17: keine Deprecation zu
`DataUpdateCoordinator`, `Store`, `HomeAssistantView`, `panel_custom` oder Diagnostics in der
Übersicht; relevant für später: „Repair issues can belong to a config entry, and be refreshed“
(2026-10-28) für Diagnose-Hinweise als Repairs; „Deprecated device info constants“
(2026-11-10, Core 2026.12) betrifft neue Entities. Volltexte nicht gelesen.

## Änderungsprotokoll

- 2026-11-17 Phase A: nur diese Datei angelegt. Keine Verbindung zu Router, HA, Host, VM oder
  Drucker; keine Messung ins Netz; nichts installiert; kein Commit. Rückweg: Datei löschen.
- 2026-11-17 Phase A, Nachtrag nach Master-Entscheidungen: Abschnitt 9 F1–F6 als
  ENTSCHIEDEN (Master) eingetragen (UI-Einhängepunkt in 1.10 und Abschnitt 4 angepasst,
  früherer DECIDED-Punkt „Netzwerkprüfung“ ersetzt); neuer Abschnitt 4.1 „Was die bestehende
  Korrelation heute verdecken könnte“ (Code erneut gelesen: `net_rules.py` 834-944,
  4727-4769, 5047-5079, 5143-5150, 5164-5320, 5482-5524; `net_engine.py:1817-1883`;
  `net_events.py:614-629`); Abschnitt 5.7 in (a) nur lesende Befehle und (b) die eine
  ACL-Änderung getrennt. Nur diese Datei geändert; keine Verbindung zu Router, HA, Host, VM
  oder Drucker; kein Commit (macht der Master). Rückweg: `git checkout` des vorigen Stands
  dieser Datei.
- 2026-11-17 Korrektur des Masters: F1 (Dump zusammenlegen) und F2 (8.8.8.8-Probe
  zentralisieren) erst nach dem Merge von Enterprise Core in `main`, nicht in Stufe 3
  (Abschnitt 4 Punkte 4/5 und Abschnitt 9 angepasst); Abschnitt 6 um den veröffentlichten
  enterprise-core-Vertrag ergänzt (Branch und Commits laut Master, nicht geholt). Nur diese
  Datei geändert, kein Commit.
- 2026-11-18 Live-Befunde eingearbeitet: Der Nutzer hat nur lesende Prüfungen freigegeben,
  der Master hat sie per SSH auf gateway, ap2, ap5, ap6 ausgeführt (kein ping, nslookup,
  traceroute, keine ACL-Probe). Diese Sitzung hat nur die Ergebnisdateien gelesen und dieses
  Dokument geändert; keine Verbindung zu Router, HA, Host, VM oder Drucker; keine privaten
  Daten (Adressen, MACs, Hostnamen, SSIDs, Lease-Inhalte, Zählerstände) übernommen.
  Geändert: Status, Kurzfazit, Abschnitt 2 (2.1–2.5), Matrix 3.1–3.3 (Markierung
  „[2026-11-18]“), 5.1–5.5, 5.7 (Stand-Tabelle je Prüfpunkt), neu 5.8 (Befunde) und 5.9
  (Folgerungen K1–K8, Vorschlag), Abschnitt 8 mit Urteil je Punkt und drei neuen offenen
  Punkten, Begründungen bei 4.1, 5.6 und 7. Widerlegt: odhcpd liefert kein `ipv4leases`;
  die Flotte ist nicht nur MT7981. Kein Commit. Rückweg: `git checkout` dieser Datei auf
  den Stand vor diesem Eintrag.
