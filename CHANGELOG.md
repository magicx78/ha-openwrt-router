# Changelog

All notable changes to the OpenWrt Router integration will be documented in this file.

## [1.17.1] - 2026-04-28

### Fixed

- **Entitäten verschwinden nach Update auf v1.17.0** (`device_info` Inkonsistenz): Der neue `RouterStatusSensor` und beide `binary_sensor`-Entities verwendeten als Device-Identifier `(DOMAIN, mac)` statt `(DOMAIN, entry.entry_id)` wie alle anderen Plattformen. Folge: HA legte ein zweites Device im Registry an, das nur die 3 neuen Entities trug — die ~30 alten Sensors hingen weiter am ursprünglichen Device, wirkten aber im UI als wären sie verschwunden. Fix: alle Entities verwenden jetzt einheitlich `entry.entry_id`.
- **Topology: Repeater-Backhaul-Erkennung verbessert** (`topology_mesh.py`): Inter-Router-Edges nutzen jetzt zusätzlich alle Interface-IPs (`network_interfaces`) und AP-BSSIDs (`ap_interfaces`) als Match-Kandidaten. Dadurch werden APs auch dann als WiFi-Uplink erkannt, wenn sie sich über eine sekundäre IP/MAC (z.B. STA-Backhaul) am Gateway anmelden.
- **Topology: Client-Nodes liefern `is_wifi_client`-Flag** (`topology_diagnostic.py`): Clients aus hostapd erhalten jetzt explizit `is_wifi_client: true`, damit das Frontend WLAN- vs Kabel-Anbindung sicher unterscheiden kann.
- **Topology-Panel: Falsche "Nicht registrierter Router"-Warnungen** (`useAlerts.ts`): Severity von `warning` auf `info` herabgesetzt, Patterns enger gefasst (kein generisches `/router/i` und `/gateway/i` mehr — diese matchten Smart-Home-Hubs wie *BresserGateway*). Hersteller-Match alleine löst keine Warnung mehr aus. Persistente Whitelist via `localStorage.openwrt_topology_ignored_routers` hinzugefügt.

## [1.17.0] - 2026-04-28

### Added

- **Router Connectivity Binary Sensor** (`binary_sensor.*_connectivity`): Zeigt `ON` wenn der Router erreichbar ist, `OFF` wenn nicht. Immer verfügbar — auch wenn der Router offline ist. Attribute: `last_seen`, `consecutive_failures`, `error_type`.
- **WAN Connectivity Binary Sensor** (`binary_sensor.*_wan_connectivity`): Zeigt `ON` wenn das Internet verfügbar ist, `OFF` wenn der Router erreichbar ist aber WAN down ist.
- **Router Status Sensor** (`sensor.*_router_status`): Enum-Sensor mit States `online`, `offline`, `auth_error`, `timeout`, `response_error` — zeigt den genauen Fehlertyp bei Ausfällen.
- **Persistente HA-Notification**: Nach 3 aufeinanderfolgenden fehlgeschlagenen Polls erscheint eine Warnung im HA-Notification-Center. Wird automatisch gelöscht wenn der Router wieder erreichbar ist.
- **Automation Blueprint** (`blueprints/automation/openwrt_router_outage_notify.yaml`): Fertiger Blueprint für Push-Benachrichtigungen bei Router-Ausfall. Konfigurierbar: Wartezeit, Notify-Dienst, Nachrichtentext, optionale Wiederherstellungs-Meldung.

## [1.16.2] - 2026-04-28

### Added

- **ACL automatisch einrichten**: Im Checklist-Schritt des Setups erscheint eine Checkbox "Berechtigungen automatisch einrichten", wenn ubus-Permissions fehlen. Ein Klick schreibt die rpcd-ACL-Datei direkt via ubus auf den Router und startet rpcd neu — kein SSH, kein manuelles `scp` nötig. Danach werden die Berechtigungen sofort neu geprüft und die aktualisierte Liste angezeigt.

## [1.16.1] - 2026-04-28

### Fixed

- **Login-Absturz beim Setup** (`AttributeError: _root_warning_logged`): `_root_warning_logged`, `_auth_failure_count` und `_auth_backoff_until` wurden in `api.py` nur in `reset_ssh_fallback_flag()` initialisiert, nicht in `__init__`. Jeder erste `login()`-Aufruf auf einer frischen API-Instanz schlug mit einem `AttributeError` fehl — der Setup-Wizard zeigte einen generischen Fehler ohne Hinweis auf die Ursache.
- **Bestehende Integrationen → HTTPS-Fehler nach Update** (Migration v1→v2): `DEFAULT_PROTOCOL` wurde in v1.16.0 von `"http"` auf `"https-insecure"` geändert. Alte Config-Entries ohne gespeichertes `protocol`-Feld fielen auf den neuen Default zurück und versuchten HTTPS/443 statt HTTP/80 — Verbindungsfehler beim Laden bestehender Integrationen. Fix: `async_migrate_entry` ergänzt `protocol: http` automatisch in alten Entries.

## [1.16.0] - 2026-04-28

### Fixed

- **Standard-Port 443 / HTTPS Self-Signed**: Default-Port war fälschlicherweise 80 (HTTP). Da die meisten OpenWrt-Router HTTPS auf Port 443 nutzen, ist der neue Standard 443 + HTTPS Self-Signed.
- **Login-Bug bei HTTPS**: Die Protokollauswahl wurde bisher erst *nach* dem Verbindungstest angezeigt — der Test verwendete daher immer HTTP, was bei Port 443 unweigerlich scheiterte. Protokoll ist jetzt Teil des ersten Schritts.

### Added

- **Geräte-Auswahl im Setup**: Nach der Router-Verbindung erscheinen Checkboxen für zusätzliche Geräte:
  - ☐ **Fritz!Box DSL-Modem** — DSL-Statistiken, 24h-Speedchart, Ping
  - ☐ **Managed Switch (OpenWrt)** — Port-Statistiken eines separaten Switches
- **Paket-Installationshinweise**: Wenn ubus-Berechtigungen fehlen, zeigt der Checklist-Schritt fertige `opkg`-Befehle zum Kopieren an.

## [1.15.6] - 2026-04-22

### Fixed

- **rpcd Memory Leak (kritisch)**: `file/exec` wurde aus der ACL und aus `get_bridge_fdb` entfernt — rpcd akkumulierte pro Poll-Zyklus Speicher durch großen stdout-Output vom `bridge fdb show`-Befehl (136 MB statt <5 MB). Bridge FDB wird nun via `file/read` auf `/sys/class/net/br-lan/brforward` gelesen (kein Shell-Exec nötig).
- **ACL**: `file/exec` → `file/list` ersetzt; alle Router aktualisiert

## [1.15.5] - 2026-04-22

### Fixed

- **Topology: Polling bei abgelaufener Sitzung** — bei HTTP 401 wird der Refresh-Timer gestoppt statt weiter zu pollen; stattdessen erscheint eine "Sitzung abgelaufen — Seite neu laden"-Meldung. Sobald HA ein neues `hass`-Objekt liefert, wird das Polling automatisch wiederaufgenommen.

## [1.15.4] - 2026-04-21

### Added

- **Config-Flow-Checklist**: Nach Protokollauswahl werden alle ubus-Berechtigungen geprüft (system/info, network/wireless, file/read, file/exec, hostapd/clients, iwinfo, luci-rpc, UCI). Fehlende kritische Caps → rote Warnung mit Anleitung. Fehlende optionale Caps → Info-Hinweis. Setup ist trotzdem möglich.

## [1.15.3] - 2026-04-21

### Added

- **SSH-Fallback-Erkennung**: Wenn ein Router ubus-Calls via SSH auflöst (fehlende ACL-Berechtigungen), erscheint eine persistente HA-Benachrichtigung mit Anleitung + Poll-Intervall wird auf 5 Minuten reduziert bis das Problem behoben ist
- **rpcd-ACL erweitert**: `file/exec`, `file/stat`, `rc/list`, `service/list`, `network.device/status` hinzugefügt — eliminiert SSH-Fallbacks auf korrekt konfigurierten Routern

## [1.15.2] - 2026-04-21

### Changed

- **Polling-Intervall** erhöht von 30s auf 60s — reduziert Router-Last bei mehreren Instanzen
- **Gestaffeltes Polling** — mehrere Coordinatoren verteilen sich automatisch gleichmäßig über das Intervall (0/15/30/45s Offset), keine simultanen Bursts mehr

### Added

- **Adaptives Polling** — bei CPU-Last >100% (Linux Load Average) wird das Intervall automatisch auf 120s verdoppelt; bei Rückkehr unter 80% wird 60s wiederhergestellt

### Fixed

- **CPU-Anzeige** — Wert >100% wird als "Load" statt "CPU" beschriftet und pulsierend rot hervorgehoben (Linux Load Average kann auf Single-Core-Systemen 100% überschreiten)

## [1.15.1] - 2026-04-21

### Fixed

- **Topology: Memory-Leak** — `nodeRefs` Map entfernt jetzt Einträge beim Node-Unmount statt unbegrenzt zu wachsen
- **Topology: CPU-Spike bei mehreren Routern** — `recomputeEdges` (DOM-Layout-Reflow) wird nicht mehr bei jedem Coordinator-Update ausgelöst; stabilisiert durch `dataRef` + AP-ID-Fingerprint als Dependency statt des gesamten `data`-Objekts
- **Topology: Merge-Conflict-Artefakt** — duplizierter CPU-History-Block war fälschlicherweise im `zoomToNode`-Callback eingebettet; `zoomFlyTimerRef` wird jetzt korrekt für Animations-Cleanup verwendet

## [1.13.0] - 2026-04-19

### Fixed

- **Topology: VLAN-Badges bei Offline-Router** — `network_interfaces` und `port_vlan_map` werden jetzt gecacht; bei nicht erreichbarem Router bleiben die VLAN-Badges sichtbar (gedimmt + gestrichelt + ⚠-Icon statt leer)
- **Coordinator**: `_last_known_network_interfaces` + `_last_known_port_vlan_map` als Stale-Cache; `vlans_stale: bool` Flag in `OpenWrtCoordinatorData`
- **Frontend**: `vlansStale`-Prop in `Gateway`-Typ; `vlan-badge--stale` + `vlan-stale-hint` CSS; Tooltip erklärt gecachten Zustand

## [1.12.3] - 2026-04-19

### Fixed

- **Topology: VLAN-Badges** — `OpenWrtAuthError` (ACL-Block, Code -32002) wird jetzt im SSH-Fallback von `get_network_interfaces()` korrekt abgefangen

## [1.12.2] - 2026-04-19

### Fixed

- **Topology: VLAN-Badges** — SSH-Fallback für `get_network_interfaces()` wenn ubus ACL-beschränkt ist; liest VLANs direkt per `ip -o addr show` aus

## [1.12.1] - 2026-04-19

### Fixed

- **Topology: SSID-Badges** zeigen jetzt nur noch die Anzahl (`📶 N`) statt volle Namen — Hover-Tooltip listet alle SSIDs mit Band und Kanal
- **Topology: VLAN-Badges im AP-Node** ergänzt (fehlten komplett)
- **Topology: Uplink-Typ** — WiFi-Client-Erkennung hat Vorrang vor DHCP-Erkennung; WLAN-Repeater werden korrekt als "Mesh" statt "Kabel" angezeigt

## [1.12.0] - 2026-04-19

### Added

- **Minimap** — 160×100 canvas overview (bottom-right corner of topology). Shows all nodes as coloured status dots and the current viewport as a dashed blue rectangle. Click to pan the canvas. Only visible in Topology tab.
- **Right-click context menu** on Gateway and AP nodes — items: Focus, Zoom to node, Clients, VLAN-Overlay, Alerts tab.
- **AP client expansion** — click the client-count button on any AP card to reveal an inline list of connected clients with signal bars, band, and IP.
- **Health mode** (♥ toggle) — colours every node by system health: `ok` (green) → `caution` (amber) → `warning` (orange) → `critical` (red). Scoring based on CPU load, RAM usage, and backhaul signal.
- **Status-change flash animation** — when a node transitions between online/warning/offline states a 650 ms colour-flash plays on the card. The status dot cross-fades via `transition: background-color 300ms`.
- **Layout transition** — AP columns animate out (`max-width: 0, opacity: 0`) when hidden by a filter change, and animate back in when revealed.
- **Gruppen-Modus** (group selector in toolbar) — organise APs into visual groups: by uplink type, by primary VLAN, or by online status.
- **Double-click to zoom** — double-click any node to zoom to 2× centered on that node. Double-click again (or when zoom ≥ 1.75) to reset to fit-view. Transition uses `cubic-bezier(0.4, 0, 0.2, 1)`.
- **Firmware version** — shown in hover tooltip and Inspector "Allgemein" section for Gateway and APs. Backend already computed `release.version`; now surfaced to the frontend.
- **Mini traffic & resource bars in Inspector** — compact horizontal bars for WAN downstream/upstream (Mbps), CPU%, RAM%, and client session RX/TX bytes.
- **Context actions in Inspector** — action bar at the bottom of the Inspector panel: Focus, Clients, Alerts (Gateway adds VLANs button).
- **Event timeline per device** — chronological list of status changes in the Inspector panel. Backend tracks WAN connect/disconnect, CPU ≥ 80% spike, RAM ≥ 90% spike in a ring-buffer (`deque(maxlen=30)`); events survive between polls but reset on HA restart.

### Changed

- `TopologyView`: AP render replaced with `groupAPs()` IIFE supporting flat and grouped layouts.
- `StatusBar`: added Health toggle, VLAN toggle, Group selector.
- `DetailPanel`: added `EventTimeline`, `ResourceBars`, `WanTrafficBars`, `BytesBars`, `MiniBar`, `ActionBtn` components; `DetailPanelActions` interface exported.

### Technical

- New files: `Minimap.tsx`, `ContextMenu.tsx`, `APClientList.tsx`, `useStatusFlash.ts`
- `coordinator.py`: `events` field on `OpenWrtCoordinatorData`, `_record_events()` method, `_event_history` deque, WAN/CPU/RAM state tracking
- `topology_diagnostic.py`: `events` included in router node attributes
- `types.ts`: `RouterEvent`, `firmwareVersion?` on `Gateway`/`AccessPoint`, `events?` on both

---

## [1.11.2] - 2026-04-17

### Added

- **Topology canvas dot-grid**: `.topo-scroll` background uses `radial-gradient` dot pattern (28 px spacing) — scrolls fixed, does not move with pan/zoom
- **Edge glow on hover**: CSS `drop-shadow` per edge type (`gateway-wired` / `ap-mesh` / `internet`) applied via child class — no SVG filter needed
- **Internet node pulse animation**: `internet-pulse` keyframe (3.5s ease-in-out infinite) on the internet node
- **Edge tooltip accent line**: 2px colored `border-top` per edge type in `EdgeTooltip`

### Changed

- Edge background opacity increased: wired `0.12 → 0.18`, mesh `0.10 → 0.16`
- Panel version bump: `20260416d`

### Fixed

- Removed stale `.edge-highlighted .edge-mesh-bg { drop-shadow(...blue...) }` — was applying wrong color on mesh edge hover

---

## [1.11.1] - 2026-04-16

### Fixed

- **fritz1750e frequent re-logins**: `login()` now requests a 24-hour session timeout from rpcd (`"timeout": 86400`). Previously, rpcd used its firmware default (often 30–300 s), causing a new login on nearly every poll cycle.
- **DDNS log spam on devices without DDNS**: `get_ddns_status()` now tracks per-device availability. After the first failed attempt (both `file/read` and `uci/get` paths fail), subsequent poll cycles skip DDNS entirely instead of logging `"DDNS: config unavailable"` every 30 s.
- **Defensive `ipv4-address` parsing**: Added `isinstance` guard when reading the first entry of the `ipv4-address` list from `network.interface.wan/status` — prevents `AttributeError` if the router returns an unexpected non-dict entry.

### Technical

- 30 unused imports removed across 9 files (ruff F401) — CI `ruff check` would have failed on every push
- `topology_diagnostic.py`: misplaced module-level import moved to top of file (ruff E402)
- `topology_mesh.py`: removed dead `router_ids` assignment (ruff F841)
- `__init__.py`: explicit re-export `DOMAIN as DOMAIN` for ruff F401 compliance

### Tests

- 396 passing (no regressions)

---

## [1.11.0] - 2026-04-15

### Added

- **Client Detail Panel — new fields**:
  - **IP address** now shown prominently at the top of the Gerät section
  - **Band** (2.4 GHz / 5 GHz / 6 GHz) — derived from `wifi_radios` via `topology_diagnostic.py`
  - **Verbunden seit** — connection duration from `hostapd connected_time` (e.g. "2h 34m")
  - **Lease bis** — DHCP lease expiry formatted as "22:15 (noch 3h 12m)" or "Abgelaufen"
  - **Status badge** — dot + text label (● Online / ● Warnung / ● Offline)
  - **„In HA anzeigen →"** link — navigates to the device_tracker entity in HA

- **Mobile connector line animation** — animated light-dot flowing through the vertical connector bars in MobileView

### Fixed

- **Topology dark theme not rendering on HA light theme** (critical): CSS custom properties were defined on `:root {}` which does not work when HA renders the panel in a shadow-DOM context. All variables moved to `.topo-app {}` (component root) so they cascade to all descendants regardless of outer DOM context. Literal color fallbacks added before each `var()` reference.
- **StatusDot invisible in detail panel**: `<span class="status-dot">` had no `display: inline-block` — browsers ignore `width`/`height` on inline elements. Fixed in CSS; all status rows now use the new `StatusBadge` component (dot + text).
- **SVG connection lines and animations invisible**: Caused by the same `:root` CSS variable scoping bug — strokes using `var(--blue)` resolved to `undefined`. Fixed by the `.topo-app` variable move.

### Technical

- `topology_diagnostic.py`: Added `_radio_band_map` built from `data.wifi_radios`; `band` field added to client node attributes
- `api.py`: Extracts `connected_time` from `hostapd/get_clients` `sta_data`; stored as `CLIENT_KEY_CONNECTED_SINCE`
- `api.ts`: Added `formatBand()`, `formatConnectedSince()`, `formatLeaseExpiry()` helpers; `Client` type extended with `connectedSince?` and `dhcpExpires?`
- `topology_panel.py`: Version bumped to `20260415e` for cache-busting

## [1.10.1] - 2026-04-14

### Added

- **Panel integrated into openwrt_router**: The topology panel is now part of the `openwrt_router` integration — no separate `openwrt_topology` component needed. The panel registers automatically when the first router entry is set up.
  - `topology_panel.py` — registers sidebar panel, static frontend path, and `/api/openwrt_topology/snapshot` endpoint
  - Moved `frontend/topology-panel.js` into `openwrt_router/frontend/`
  - `manifest.json` updated with `"dependencies": ["frontend", "http", "panel_custom"]`

- **Auto-ACL provisioning**: When a new router is added, the integration automatically checks for the rpcd ACL file (`/usr/share/rpcd/acl.d/ha-openwrt-router.json`). If missing, it deploys it via SSH and restarts rpcd — fixing the common "Authentication failed" error when adding AP clients that have no ACL file.
  - `acl_provisioning.py` — SSH check + deploy + rpcd restart (best-effort, graceful skip if SSH unavailable)
  - Called from `async_setup_entry()` after first coordinator refresh

- **Multi-Router Mesh Topology**: `topology_mesh.py` aggregates per-router snapshots from all configured OpenWrt entries into a single unified mesh view (1 gateway + N AP clients).
  - Automatic role detection: `gateway` (WAN uplink, non-private IP) vs `ap`
  - Inter-router edge detection via DHCP lease cross-reference, WiFi client MAC, or subnet fallback
  - Client deduplication: roaming clients (same MAC on multiple APs) appear once — strongest signal wins

- **FritzBox-style panel redesign**: Topology panel now uses card-style nodes with iOS-inspired dark palette:
  - Card nodes with band-specific border colors (gateway: blue, AP: purple, 2.4 GHz: green, 5 GHz: purple, 6 GHz: magenta)
  - Status dots (green/red/grey) per card
  - Signal quality pills for WiFi clients: `gut` (>-65 dBm) / `mittel` / `schwach` (<-75 dBm)
  - WAN badge (✓/✗) on gateway card
  - Bezier SVG connector lines with per-type styling (dashed WLAN, solid LAN, thick uplinks)
  - CSS variable palette (`--cg`, `--cr`, `--cl`, `--good`, `--fair`, `--poor`)
  - Multi-router group labels + separator lines

### Removed

- **`openwrt_topology/` component**: Entire separate component deleted. Panel functionality moved into `openwrt_router`.

### Technical

- `topology_panel.py` (NEW): Panel registration, API view, idempotent setup
- `acl_provisioning.py` (NEW): `check_and_deploy_acl()`, `_check_acl_exists()`, `_deploy_acl()`, `_ssh_exec()`
- `topology_mesh.py` (NEW): `build_mesh_snapshot()`, `_detect_router_role()`, `_detect_inter_router_edges()`, `_deduplicate_clients()`
- `topology_diagnostic.py`: `build_topology_snapshot()` gains optional `role` and `host_ip` parameters. Router node attributes now include `host_ip`, `wan_proto`, `wan_connected`. Interface labels prefer SSID+band over raw ifname.
- `coordinator.py`: `get_wifi_status()` wrapped in try/except to prevent `ConfigEntryAuthFailed` on ACL-restricted AP routers.
- `api.py`: Post-relogin `-32002` raised as `OpenWrtMethodNotFoundError` (genuine ACL block), not `OpenWrtAuthError`.

### Tests

- 353 passing (+37 new: ACL provisioning, mesh aggregation, role detection, inter-router edges, client deduplication, topology role/host_ip parameters)

---

## [1.9.3] - 2026-04-09

### Fixed

- **DHCP leases empty on OpenWrt 25** (`dhcp_leases` key): `luci-rpc/getDHCPLeases` returns `{"dhcp_leases": [...]}` on OpenWrt 25 instead of `{"leases": [...]}`. All 33 clients now have correct IPs and hostnames. Older OpenWrt versions using `"leases"` or a direct list still work.
- **rpcd -32002 treated as permanent ACL block**: Error code `-32002` from rpcd was raised as `OpenWrtMethodNotFoundError`, which bypassed the re-login retry logic in `_call()`. In practice, `-32002` can also mean a stale session token (e.g. after an rpcd restart). Changing it to `OpenWrtAuthError` triggers the existing re-login-and-retry mechanism. If the retry also returns `-32002` it's a genuine ACL restriction and propagates to the caller.
- **Topology: Router-ID empty string when MAC unavailable**: OpenWrt 25 / Cudy WR3000 v1 does not return a `mac` field in `system board`. Router-ID fell back to `""` (empty string), causing all topology edges to have `"from": ""` and breaking the panel. Now falls back to `hostname`, then to `"router"` literal.
- **Duplicate sensor entity IDs for `wan_rx` / `wan_tx`** (HA log: _"Platform openwrt_router does not generate unique IDs. ID …_wan_rx already exists"_): The static WAN byte-count sensors (`SUFFIX_WAN_RX` / `SUFFIX_WAN_TX`) and the dynamically-created `OpenWrtInterfaceSensor` for the `wan` interface produced identical `unique_id` values. Fixed by adding an `_iface_` disambiguator to the dynamic sensor: `entry_id_iface_wan_rx` / `entry_id_iface_wan_tx`.

### Technical

- `api.py`: `_get_dhcp_leases_luci_rpc()` — try `dhcp_leases` key first, fall back to `leases`, then direct list.
- `api.py`: `_raw_call()` — error code `-32002` raises `OpenWrtAuthError` (was `OpenWrtMethodNotFoundError`).
- `topology_diagnostic.py`: `build_topology_snapshot()` — router_id uses `mac or hostname or "router"` (was `mac` only with literal `"router"` fallback, which didn't handle empty-string MAC).
- `sensor.py`: `OpenWrtInterfaceSensor._attr_unique_id` — changed to `entry_id_iface_{interface}_{direction}`.

### Tests

- 316 passing (+20 new tests: Fix 3, Fix 4, Fix B coverage; new `test_topology_diagnostic.py`)

---

## [1.9.3-patch1] - 2026-04-10

### Fixed

- **Topology sensor attributes exceed HA Recorder 16 KB limit** (WARNING: _"State attributes for sensor.secureap_gateway_network_topology exceed maximum size of 16384 bytes"_): Topology snapshots with 40+ nodes and 33+ clients regularly exceed the recorder limit. The sensor _state_ (node count / active interface count) is still recorded. Attributes are excluded via `_unrecorded_attributes = frozenset({MATCH_ALL})` — they remain available in-memory at all times and the topology panel continues to read them from the live state object.

### Technical

- `topology_entities.py`: `_TopologyEntityBase._unrecorded_attributes = frozenset({MATCH_ALL})` — excludes all topology attributes from SQLite recorder without affecting in-memory availability.

---

## [1.9.2] - 2026-04-07

### Added
- **WiFi switch client list attribute**: Each WiFi switch now exposes a `clients` attribute containing a list of all connected clients on that SSID. Each entry shows:
  - `name` — hostname (falls back to MAC if no hostname)
  - `mac` — MAC address
  - `ip` — IP address (from DHCP lease enrichment)
  - `signal_dbm` — WiFi signal strength in dBm
  - `connected_since` — ISO-8601 timestamp of when the client first appeared
  - `dhcp_expires` — Remaining DHCP lease time (e.g. `"2h 14m"`, `"45m"`, `"<1m"`, `"expired"`)
- **DHCP lease expiry tracking**: `_parse_dhcp_leases()` and `luci-rpc/getDHCPLeases` now store the `expires` Unix timestamp. Expiry is propagated to connected client dicts and displayed as remaining time in switch attributes.

### Technical
- `const.py`: Added `CLIENT_KEY_DHCP_EXPIRES = "dhcp_expires"`.
- `api.py`: DHCP lease dicts now include `"expires"` (Unix timestamp). `_enrich_clients_with_ip()` propagates `CLIENT_KEY_DHCP_EXPIRES` to client dicts.
- `switch.py`: Replaced `_count_clients_for_ssid()` with `_get_clients_for_ssid()` returning full enriched list. Added `_format_dhcp_expires()` helper (converts epoch to human-readable remaining time).

### Tests
- 296 passing (no regressions)

---

## [1.9.1] - 2026-04-06

### Fixed
- **WiFi toggle: `uci/apply` fallback komplett übersprungen**: `uci/commit` blockiert via rpcd ACL → wirft `OpenWrtAuthError` → war NICHT in der except-Klausel → `uci/apply` wurde nie versucht. Fix: `OpenWrtAuthError` zu beiden except-Klauseln hinzugefügt.
- **Connected Clients = 0 bei read-only SSH**: SSH-Fallback lief `ubus call hostapd.*/get_clients` — erfordert ubus-Socket-Zugriff, schlägt bei read-only SSH-Usern fehl. Neuer Fallback: `iw dev {iface} station dump` (Kernel nl80211, rein lesend, kein ubus nötig).

### Technical
- `api.py`: `OpenWrtAuthError` in `set_wifi_state()` except-Klauseln ergänzt (commit + apply).
- `api.py`: Neue Methode `_get_clients_via_iw_ssh()` — parst `iw station dump` Output, wird automatisch aufgerufen wenn ubus SSH-Fallback fehlschlägt.

### Tests
- 294 passing (no regressions)

---

## [1.9.0] - 2026-04-06

### Fixed
- **WiFi switch shows only `(5 GHz)` instead of `OpenWrt (5 GHz)`**: Switch names were set statically at init time when the SSID was not yet available (UCI-method routers like Cudy WR3000 on OpenWrt 25). Replaced static `_attr_name` with a dynamic `name` property that always reads the current SSID and band from coordinator data.
- **2.4 GHz switch shows no band label**: `_detect_band()` returns `"2.4g"` for 2.4 GHz radios, but `_format_band()` only mapped `"2g"`. Added `"2.4g"` as an alias so 2.4 GHz switches correctly show `OpenWrt (2.4 GHz)`.
- **WiFi toggle fails with "uci/commit access denied"**: Replaced `network.wireless/up|down` with `uci/apply` as fallback when `uci/commit` is blocked by rpcd ACL. Staged UCI changes are reverted if both primary and fallback fail.
- **Connected Clients always 0**: rpcd ACL blocks `hostapd.*/get_clients` on Cudy WR3000 / OpenWrt 25. Added SSH fallback (`_get_clients_via_ssh()`) — connects once, runs `ubus call hostapd.<iface> get_clients` per interface.
- **DHCP enrichment disabled**: `file/read /tmp/dhcp.leases` blocked by rpcd ACL. Added `luci-rpc/getDHCPLeases` as automatic fallback. DHCP enrichment now works on ACL-restricted routers.
- **Client SSID empty**: `hostapd.*/get_status` blocked by rpcd ACL. Added `luci-rpc/getWirelessDevices` as cached fallback (fetched once per poll cycle).

### Technical
- `switch.py`: Dynamic `name` property with `_format_band()` alias for `"2.4g"`.
- `api.py`: `set_wifi_state()` → `uci/apply` fallback; `get_connected_clients()` SSH fallback; `get_dhcp_leases()` → `luci-rpc` fallback; SSID via `luci-rpc/getWirelessDevices`.

### Tests
- 294 passing (no regressions)

---

## [1.8.0] - 2026-04-06

### Added
- **AP Interface Sensors**: Per-radio channel, mode, HT mode, HW mode, and connected client count sensors.
  - `sensor.<section>_channel` — active WiFi channel (e.g. 1, 36)
  - `sensor.<section>_mode` — AP mode (`ap`, `client`, `monitor`)
  - `sensor.<section>_ap_clients` — number of currently associated clients
  - `sensor.<section>_ht_mode` — HT/VHT/HE mode (e.g. HE20, HE80, VHT80)
  - `sensor.<section>_hw_mode` — hardware mode or device type (e.g. mt7986, 11ax)
  - Optional (iwinfo only): `frequency` (MHz), `tx_power` (dBm), `bitrate` (Mbps), `signal_quality` (%)
- **UCI fallback** for AP interface discovery: Routers without `iwinfo` access via rpcd (e.g. Cudy WR3000 on OpenWrt 25) now expose AP sensors via UCI wireless config. UCI section names (e.g. `default_radio0`) are used as stable entity identifiers.

### Technical
- `const.py`: Added `RADIO_KEY_CHANNEL`, `RADIO_KEY_FREQUENCY`, `RADIO_KEY_TXPOWER`, `RADIO_KEY_BITRATE`, `RADIO_KEY_HWMODE`, `RADIO_KEY_HTMODE`, `RADIO_KEY_MODE`, `RADIO_KEY_BSSID`.
- `api.py`: New `get_ap_interface_details()` method — iwinfo primary path, UCI fallback. Extends `_parse_iwinfo_info()` and `_parse_wireless_status()` with new fields.
- `coordinator.py`: Added `data.ap_interfaces` field; fetched after clients each poll.
- `sensor.py`: New `OpenWrtAPInterfaceSensor` class; `_add_dynamic_sensors()` extended to iterate `ap_interfaces`.

### Tests
- 294 passing (no regressions)

---

## [1.7.0] - 2026-04-06

### Added
- **Service Management**: Monitor and control procd/rc system services directly from Home Assistant.
  - **Service Switches** (`switch.service_<name>`): Start/stop individual services — `dnsmasq`, `dropbear`, `firewall`, `network`, `uhttpd`, `wpad`. State reflects real-time running status.
  - **Service Restart Buttons** (`button.restart_<name>`): One-click restart per service with dedicated icons.
  - Auto-discovery: Uses `rc/list` (OpenWrt 19+) with `service/list` (procd) as fallback. Only services present on the router appear as entities.
  - Feature-gated: Service entities are only created when `rc/list` or `service/list` is accessible.

### Fixed
- **Active Connections = 0**: Now reads `/proc/sys/net/netfilter/nf_conntrack_count` (fast single-int file) with `/proc/net/nf_conntrack` as fallback.
- **WiFi Switch Access Denied**: Added `network.wireless/up` (or `/down`) as fallback when `uci/commit` is blocked by rpcd ACL.
- **Connected Clients = 0** (OpenWrt 25): Fixed hostapd interface name discovery — probes `phy{N}-ap{M}` naming used since OpenWrt 21+/25, caches result to avoid repeated probing.
- **SSID via hostapd**: Uses `hostapd.*/get_status` to retrieve SSID even when `iwinfo/info` is blocked by rpcd ACL.

### Technical
- `api.py`: Added `get_services()` (rc/list → service/list fallback) and `control_service(name, action)`.
- `const.py`: Added `UBUS_RC_OBJECT`, `UBUS_RC_INIT`, `UBUS_SERVICE_OBJECT`, `DEFAULT_SERVICES`, `KEY_SERVICES`, `FEATURE_HAS_SERVICES`.
- `coordinator.py`: Added `data.services` field; fetches service status each poll when `has_services` feature detected; service probed during feature detection.
- `switch.py`: Added `OpenWrtServiceSwitch` — start/stop toggle per service with per-service icons.
- `button.py`: Added `OpenWrtServiceRestartButton` — restart per service.

### Tests
- 275 passing (no regressions from new service management code)

---

## [1.6.0] - 2026-04-06

### Added
- **Bandwidth Rate Sensors**: Dynamic `sensor.<iface>_rx_rate` / `sensor.<iface>_tx_rate` entities (bytes/s) per network interface — created alongside existing byte-total sensors. Returns `unavailable` on the first poll (two data points needed); `0` on counter wraparound/reset.
- **Traffic Charts/History**: The existing cumulative byte sensors (`state_class: TOTAL_INCREASING`) already enable HA Long-Term Statistics — add them to a Statistics card or Energy Dashboard for per-interface traffic history.

### Technical
- `coordinator.py`: Added `_prev_interface_bytes` dict and `_prev_poll_time` timestamp; injects `rx_rate`/`tx_rate` (B/s) into each interface dict on every poll after the first.
- `sensor.py`: Added `OpenWrtInterfaceRateSensor` class (`DATA_RATE`, `MEASUREMENT`, `B/s`); registered in `_add_dynamic_sensors()` alongside byte-total sensors.

### Tests
- T-R1–R4: Rate is `None` on first poll, correctly calculated on second poll, `0` on counter wraparound, sensor returns `None` before rate is available
- T-S7–S9: `OpenWrtInterfaceRateSensor` unique_id format, device_class/unit, native_value
- **275 tests passing** (was 268)

---

## [1.5.0] - 2026-04-06

### Added
- **QA Strategy Document** (`Anweisungs.md`): Comprehensive 4-level test strategy covering static checks, unit tests, HA-environment integration tests, and manual E2E checklist
- **Test Fixtures** (`tests/fixtures/`): 5 versioned JSON router state fixtures — `router_healthy`, `router_wan_down`, `router_minimal`, `router_broken`, `router_high_traffic`
- **Regression Tests** (`tests/test_regressions.py`): REG-01–REG-05 covering WAN-down interface handling, string rx_bytes robustness, connected_since cleanup, unique_id stability, duplicate entity prevention
- **CI: Ruff Lint + Format Check**: Added `ruff check` and `ruff format --check` step to GitHub Actions workflow before pytest

### Tests
- Extended `test_sensor.py`: dynamic interface sensor creation, WAN-down edge case, None rx_bytes robustness, unique_id stability, radio sensor noise guard
- Extended `test_coordinator.py`: `_client_first_seen` tracking, stability on re-poll, cleanup on disconnect, connected_since propagation, missing MAC skip
- Extended `test_device_tracker.py`: `connected_since` in `extra_state_attributes`, offline state, ISO format validation
- **268 tests passing** (was 247)

---

## [1.4.0] - 2026-04-06

### Added
- **Per-Interface Bandwidth Sensors**: Dynamic `sensor.<iface>_rx` / `sensor.<iface>_tx` entities for every network interface (wan, loopback, br-lan, etc.) using existing `network.interface/dump` data
- **Per-Client Online Time**: `connected_since` ISO timestamp attribute in device tracker entities — tracks when each WiFi client first connected (resets on HA restart)
- **Radio Signal/Noise Sensors**: Dynamic `sensor.<iface>_signal` / `sensor.<iface>_noise` entities per WiFi radio (requires iwinfo support; only created when noise data available)

### Technical
- `coordinator.py`: Added `_client_first_seen` dict tracking UTC connection timestamps per MAC
- `api.py`: Extended `_parse_iwinfo_info()` to extract noise/signal/quality/quality_max from iwinfo response
- `const.py`: Added `CLIENT_KEY_CONNECTED_SINCE`

---

## [1.3.0] - 2026-04-05

### Fixed
- **Entity ID naming**: Sensors no longer include the config entry hash in their entity IDs (e.g. `sensor.openwrt_firmware_version` instead of `sensor.openwrt_router_01knfp2yyvf5j20wwpdze0sp99_firmware`)
- **P1**: `perform_update()` — replaced non-existent `file/write` ubus call with SSH subprocess
- **P2**: `get_network_interfaces()` now reads from `network.interface/dump`; `get_active_connections()` reads `/proc/net/nf_conntrack`
- **P3**: Button entity no longer mutates coordinator data directly (race condition)
- **P4**: `configuration_url` now uses the configured protocol (HTTP/HTTPS) in all entity platforms
- **P5**: Removed unreachable dead code in `get_wan_status()`
- **P6**: Exponential backoff on repeated auth failures (3 strikes → 30 s → 300 s max)
- **P7**: SSH JSON parse calls wrapped in `try/except ValueError`
- **P8**: Logging uses `%s` pattern instead of f-strings
- **WiFi SSH fallback**: Uses direct UCI commands instead of a helper script that may not be present on all routers

### Added
- **Memory Total sensor**: Expose total RAM as a standalone sensor (`memory_total`)
- **Memory Used sensor**: Expose used RAM as a standalone sensor (`memory_used`)

---

## [1.2.0] - 2026-03-24

### Added
- **Comprehensive Test Suite**: 247 tests across 11 files covering all modules
  - API parsing, error handling, session management (63 tests)
  - Coordinator polling, feature detection, error wrapping (33 tests)
  - Config flow host validation and setup steps (25 tests)
  - All entity platforms: sensor, switch, button, device_tracker, diagnostics
  - Integration setup/unload/reload lifecycle tests
- **CI/CD Pipelines**: GitHub Actions for automated quality checks
  - `hassfest.yaml`: Home Assistant manifest validation
  - `hacs.yaml`: HACS repository validation
  - `tests.yaml`: Pytest on Python 3.12 and 3.13
- **Brand Icon**: 256x256 PNG icon for HACS store listing
- **Translations**: English translation file (`translations/en.json`)

### Fixed
- Removed non-existent `entity.py` reference from documentation

---

## [1.1.0] - 2026-03-23

### Added
- **Extended System Monitoring**: Comprehensive metrics for advanced system oversight
  - **System Information**: Platform architecture, OpenWrt version, hostname, model detection
  - **CPU Metrics**: Extended load averages - 1-minute, 5-minute, and 15-minute load as percentage
  - **Memory Details**: Separate sensors for cached, shared, and buffered memory in addition to total/free
  - **Disk Space Monitoring**: Total, used, free capacity and usage percentage for all mounted filesystems
  - **Temporary Storage (tmpfs)**: Dedicated monitoring for /tmp, /run, /dev/shm with usage metrics
  - **Network Connection Tracking**: Active network connection count via nf_conntrack integration
  - **15+ New Sensors**: All metrics exposed as individual sensors for dashboards and automations

### Technical
- Enhanced API methods with graceful fallback for unsupported features
- Improved platform architecture detection from multiple sources
- Comprehensive error handling for missing system features
- Support for systems with/without nf_conntrack module

---

## [1.0.8] - 2026-03-20

### Added
- **Update Management Feature**: Check and perform system/addon package updates
  - "Check for Updates" button: Detects available system packages and addons
  - "Perform Updates" button: Triggers package updates on the router
  - "Update Status" sensor: Shows if updates are available with package counts as attributes
  - Support for selective updates: system packages, addons, or both
  - Proper categorization of updates by type (system vs addon/LuCI packages)

---

## [1.0.7] - 2026-03-20

### Added
- **SSL/HTTPS Support**: Secure connections to OpenWrt routers
  - Config Flow with Protocol Dropdown: HTTP, HTTPS, HTTPS Self-Signed
  - Automatic port adjustment (80 for HTTP, 443 for HTTPS)
  - Self-signed certificate support for private/lab networks
  - Proper SSL context with certificate validation for production use
  - Token transmission now protected over HTTPS when enabled

---

## [1.0.6] - 2026-03-20

### Changed
- **Sensor Visibility**: Move sensors from "Diagnose" to main "Sensoren" section
  - Uptime, Memory Free, WAN IP, Firmware now appear in Sensors (not Diagnostics)
  - Better UX: All important metrics visible without expanding Diagnostics
  - Devices in Home Assistant now show sub-entities under Sensors

---

## [1.0.5] - 2026-03-20

### Changed
- **WiFi Switch Display Enhanced**: Switches now show band information and connected client count
  - Switch names now display: "secure-IoT (2.4 GHz)" instead of just "secure-IoT"
  - Band information (2.4 GHz, 5 GHz, 6 GHz) automatically appended
  - Connected client count visible in switch attributes: "connected_clients"
  - Better UX for managing multiple WiFi networks

---

## [1.0.4] - 2026-03-19

### Fixed
- **Sensor Display Names**: Sensors now show their actual names instead of device hostname
  - Changed `_attr_has_entity_name` from True to False in sensor.py
  - Sensors now display: "WAN Status", "CPU Load", "Memory Usage", "Connected Clients" etc.
  - Previously all sensors showed "sECUREaP-gATEWAy" (the device name)

---

## [1.0.3] - 2026-03-19

### Fixed
- **WAN RX/TX Bytes Now Show Actual Data**: Fixed issue where WAN Download/Upload sensors showed "unavailable"
  - Changed from reading `network.interface/dump` to directly reading `/sys/class/net/{interface}/statistics/`
  - Uses kernel filesystem as source of truth for interface statistics
  - Works on routers like Cudy WR3000 where stats may not be included in network interface dump
  - Example: Now shows actual 93.9 GB RX / 1.9 GB TX instead of unavailable

---

## [1.0.2] - 2026-03-19

### Fixed
- **WAN Statistics Handling**: Show "unavailable" instead of "0 B" when router doesn't provide WAN statistics
  - WAN Download and WAN Upload sensors now properly display unavailable state
  - Added debug logging to identify routers without statistics support

---

## [1.0.1] - 2026-03-19

### Fixed
- **Entity Display Names**: WiFi switch entities now display only the SSID name (e.g., "secure-IoT") instead of the device prefix + SSID. This provides a cleaner, more intuitive UI experience in Home Assistant.
  - Changed `_attr_has_entity_name=False` to remove redundant device name repetition in entity display names
  - Entity IDs remain unchanged (e.g., `switch.secureap_gateway_secure_iot`)

### Changed
- Improved entity naming consistency with Home Assistant best practices

---

## [1.0.0] - 2026-03-11

### Added
- Initial release: Home Assistant custom integration for OpenWrt Router management
- **WiFi Switches**: One switch per detected WiFi SSID (2.4GHz, 5GHz, Guest networks)
- **Sensors**: Uptime, WAN status, connected client count
- **Device Tracker**: Track connected WiFi clients by MAC address
- **Button**: WiFi reload/reboot control
- **Security**: SSRF, token leak, and input validation hardening
- Configuration via Home Assistant UI setup wizard
- Automatic token refresh and retry logic for JSON-RPC API
- Diagnostics with redacted sensitive data

### Architecture
- Async-only design with proper error handling
- Polling coordinator with 30-second update intervals
- ubus/rpcd JSON-RPC communication via HTTP
- Per-SSID controls with UCI configuration backend
