# PROGRESS — OpenWrt HA Integration

Entwicklungsprotokoll · Letzte Session: 2026-10-28 · Aktuell: **v1.39.0**

> Detaillierte Session-Protokolle bis v1.13.0 liegen in der Git-Historie dieser Datei;
> vollständige Release-Details in [CHANGELOG.md](CHANGELOG.md).

---

## Status: v1.38.3 – v1.39.0 — SSH im Poll abgestellt und Audit (2026-10-27/28)

Plan, Befunde, Reviews und Prüfprotokoll:
[docs/plans/2026-10-28-ssh-polling-und-audit.md](docs/plans/2026-10-28-ssh-polling-und-audit.md).

- **v1.38.3 – v1.38.9 (PRs #37–#43, einzeln released):** keine SSH-Anmeldung
  mehr je Poll (N2), Login-Fehler und hostapd-Cache (A1, A2), LLDP-Kanten (A11),
  rpcd-ACL v8 mit aufgelösten Symlink-Pfaden (A16), Port-Zuordnung (A17),
  WAN-Erkennung ohne „erstes up-Interface“ (A4). Hardware-Nachweise im Plan.
- **v1.39.0 (Sammel-Release, PR #45):** Diagnostics nach HA-Konvention
  redigiert (A5), Topologie-Panel und Snapshot-API nur für Admins mit Option
  (A13), Device-Tracker über Router hinweg verfügbar und aus der Registry
  wiederhergestellt (A3), Gateway-Rolle bei WAN-Ausfall, `stale`-Daten und
  LLDP-Fixes (A12), Topologie-Snapshot einmal je Update (A14), „Nach Updates
  suchen“ mit apk/opkg, Install-Button entfernt (A6), Poll-Versatz/Intervall/
  Catch-all (A7), Recorder-Attribute (A8), Schnittstellen-Zähler und
  Sensor-Metadaten (A9), Login-Sperre und ARP über `getHostHints` (A10).
  Jedes Paket mit Tests vor dem Fix, Risikopakete mit unabhängigem Review.

Offen: Installation von 1.39.0 und die gesammelten Hardware-Prüfungen (siehe
TODO), Panel-Sichtprüfung im Browser.

---

## Status: v1.38.2 — Fehlerkorrektur nach 1.37 (2026-10-27)

v1.37.4 lief ab dem 27.10. in HA (Gateway + zwei Dumb-APs). Die Prüfung zeigte
Log-Lärm, eine HA-Deprecation mit Ablaufdatum, falsch skalierte CPU-Werte und
kleinere Fehler. Plan, Befunde und Prüfprotokoll:
[docs/plans/2026-10-27-fehlerkorrektur-nach-1.37.md](docs/plans/2026-10-27-fehlerkorrektur-nach-1.37.md).
Umgesetzt als gestapelte PRs, jeder Merge ein Release:

- **v1.37.5 (PR #33):** Root-rpcd-Warnung einmal je Router und erst nach
  erfolgreichem Login; „network.reload not available“ nach erfolgreichem
  Commit nur noch im Debug-Log; `device_registry.async_get_device` ersetzt
  (Ende in HA 2027.8, Rückfall bis zum Floor 2026.2); Band-Helfer in
  `wifi_band.py`.
- **v1.38.0 (PR #34):** CPU-Last pro Kern (Kernzahl aus `/proc/cpuinfo`),
  Poll-Drosselung pro Kern; **rpcd-ACL v7** (`/proc/cpuinfo`, `network reload`),
  dadurch wendet „WLAN neu laden“ wirklich etwas an.
- **v1.38.1 (PR C):** Kanal, `htmode` und `hwmode` aus dem `config`-Block von
  `network.wireless status`; SSH-Fallback füllt die AP-Interfaces (Kanalplan,
  Sticky-Prüfung); `uci show` mit anonymen Sektionen und `'\''` in SSIDs.
- **v1.38.2 (#36):** WAN-Sensoren (Status, IP, Download, Upload,
  Binärsensor WAN-Verbindung) werden auf Routern ohne WAN-Interface
  deaktiviert angelegt – nur neue Entities, kein Registry-Eingriff
  (Entscheidung E3). Das Panel verwirft für private MACs auch den
  OUI-Hersteller des Servers; die OUI-Tabelle des Panels ist wieder
  synchron zu `oui.py`. Der Release-Workflow übernimmt den CHANGELOG-Abschnitt
  als Release-Text.
- **Betrieb:** Drei Config-Entries ohne erreichbaren Router entfernt
  (Hauptquelle der Retry-Warnungen).

Offen: Auswertung der rpcd-Speichermessung mit ACL v6 (B3), Hardware-Prüfung
von ACL v7 und Kanal-Fix, Panel-Sichtprüfung, Befunde 13 und 14 (siehe
[TODO.md](TODO.md)). Lokal 1297 Tests grün, ruff 0.17.3 sauber.

---

## Status: v1.29–v1.37 — WLAN-Diagnose (2026-10-27)

Restprogramm aus dem Plan
[docs/plans/2026-10-27-wlan-diagnose-features.md](docs/plans/2026-10-27-wlan-diagnose-features.md):
Ausfälle als Repairs (gleichzeitige gebündelt), Optionsschalter für die
erweiterten WLAN-Sensoren, RAM-Druck-Hinweis, Kanalplan mit Konflikt-Repair,
Router-Log-Auswertung (ACL v6) mit WLAN-/DHCP-/DFS-Events, DHCP-Pool-Sensoren
und `dhcp_status`, klebende und instabile WLAN-Clients, `random_mac`.
Nebenbei gefunden und behoben: rpcd-Leck durch `rc/list` (v1.37.1, ca. 6 MB
pro Tag), Bandgrenzen 6 GHz/60 GHz und Banderkennung über UCI `band`
(v1.37.2/3), Panel-Footer, WAN-Rate in Bit/s und HA-Gerätenamen im Panel
(v1.37.4).

---

## Status: v1.28.0 — LLDP-Topologie (2026-09-09)

Der zwei Monate alte Feature-Branch `feature/lldp-topology` (PR #14) wurde auf
`main` nachgezogen und gemergt. Router-zu-Router-Verkabelung kommt jetzt
bevorzugt aus **LLDP** (echte Nachbarn + physische Ports) statt aus
DHCP/ARP/FDB-Heuristik; ohne `lldpd` bleibt alles wie bisher, nur mit
geringerer Confidence.

Beim Merge-Review gefundene und behobene Punkte:

- LLDP-Kanten leiten ihr Medium aus den LLDP-Interface-Namen ab
  (`link_type: lan|wifi`). Vorher stand dort `"lldp"`, wodurch der
  Repeater-Override (`lan_uplink`/`mesh_member`) LLDP-Kanten übersprang — ein
  Repeater mit `lldpd` wurde als „Kabel“ gerendert. Umgekehrt schlägt eine
  LLDP-verifizierte Kupferstrecke jetzt die STA-Heuristik, wie ein WAN-Carrier.
- Die Switch-Inferenz gruppierte nur `lan_uplink`; LLDP unterdrückt genau die.
  Zwei APs hinter einem unmanaged Switch verloren dadurch ihren Switch-Knoten,
  sobald `lldpd` lief. Gruppierung läuft jetzt über `_is_wired_uplink_edge()`.
- `topology_diagnostic.py` verwarf `vendor`/`connection_type`/`confidence`/
  `source`/`web_url`/`last_seen` aus seiner Attribut-Whitelist — das Frontend
  fiel still auf seine eigene OUI-Tabelle zurück, `oui.py` war toter Code.
- `missing_before`/`missing_after` im Config-Flow zählten die optionale
  `lldp_neighbors`-Capability mit → erfolgreicher ACL-Deploy meldete
  „keine Änderung“.
- LLDP hängte an jedem Poll an einem SSH-Connect und cachte ein
  „unavailable“ für die ganze Session. Jetzt Refresh alle 600 s, Retry alle
  1800 s und nach jedem `reset_acl_blocked()` — ein nachträglich installiertes
  `lldpd` wirkt ohne Entry-Reload.

Nebenbei: die CI zieht `ruff` unpinned und ist bei 0.16.6 angekommen, das I001
und PERF102 im Default-Regelsatz hat. Die betroffenen Import-Blöcke wurden
sortiert.

---

## Status: v1.26.4 — Log-Hygiene Multi-Router (2026-08-23)

Drei Prod-Dauerbrenner behoben:

- root-rpcd-Warnung feuerte ~66×/h: `reset_ssh_fallback_flag()` (läuft jeden
  Poll) resettete das Warn-Latch. Jetzt einmal pro Router und Start, mit Host
  in der Meldung.
- `does not generate unique IDs`-ERROR pro Mesh-Client: Neuer HA-Core erzwingt
  bei `ScannerEntity` unique_id = MAC (entry-scoped `_attr_unique_id` wird
  ignoriert). Fix: AP-übergreifende Dedup via Claim-Register in hass.data —
  eine Entity pro Client, die alle geladenen Router durchsucht (Roaming bleibt
  `home`, neues Attribut `connected_ap`).
- Ewiger SSH-Fallback auf 10.10.30.50 („OpenWrt"-Entry): `ensure_acl` ließ
  eine existierende, aber unlesbare (= prä-v5) ACL „as-is" → jetzt Redeploy
  bei permission-blockiertem file/read (Timeouts weiterhin nicht).
- **v1.26.5** (parallele Session): SSL-Kontext nicht mehr synchron im
  Event-Loop — HA-Kontexte via `ssl_util.py` injiziert.
- **v1.26.6 (Nachzügler)**: ACL-Redeploy allein reichte auf .50 nicht — der
  `_acl_blocked`-Cache keyte uci nur auf `("uci","get")`; der verweigerte
  ddns-Probe vergiftete den uci-wireless-Pfad → SSH-Fallback jeden Poll.
  Cache-Key für uci jetzt per Config (wie file per Pfad seit 1.26.3).
  Debug-Erkenntnis: .50 ist ein Mieter-Repeater (SSID Tenant-Klee, STA-Uplink)
  ohne LuCI-superuser-ACL; network.wireless/iwinfo-info dort teils nicht verfügbar.

Offen/Beobachtung: HA (Prod) startete am 22./23.08. mehrfach neu
(home-assistant.log.fault 05:03), Ursache unklar.

---

## Status: v1.20.0 — HA-Kompatibilitäts-Modernisierung (Branch `fix/ha-2026-8-modernization`)

Review der Integration gegen HA-Core-Standards Stand Juli 2026 (aktuell: HA 2026.7):

- **Kritisch behoben:** `DataUpdateCoordinator` bekommt `config_entry=` explizit —
  die implizite ContextVar-Übergabe entfällt in HA 2026.8.
- Toter Sync-Fallback `register_static_path` im Panel entfernt (seit HA 2024.6 obsolet).
- `manifest.json`: `integration_type: hub`; HACS-Floor ehrlich auf **2026.2.0**
  (Code brauchte real schon ≥2024.11).
- **de.json** neu; strings.json/en.json jetzt durchgängig englisch (waren gemischt).
- Blueprint auf Plural-Syntax (`triggers:`/`actions:`/`action:`) + `source_url` + `min_version`.
- CI: Release-Workflow gegated (test + hassfest), Test-Matrix 3.13/3.14
  (Py 3.12 löste nur HA 2024.x auf; HA 2026.3+ braucht Py ≥3.14),
  ha-compat testet jetzt wirklich die gemeldete Latest-HA (Version gepinnt).
- CHANGELOG-Lücke [1.19.0] nachgetragen; README-Badges dynamisch.

Nicht betroffen (verifiziert): Device-Tracker-Deprecations 2026.6
(battery_level/location_name), `show_advanced_options`, Update-Listener+Reload-Pattern.

---

## Meilensteine

| Version | Zeitraum | Inhalt |
|---------|----------|--------|
| **v1.38.x** | 2026-10 | CPU-Last pro Kern + ACL v7, Kanal aus dem `config`-Block, AP-Interfaces im SSH-Fallback, WAN-Sensoren auf APs standardmäßig aus, Release-Texte aus CHANGELOG |
| **v1.37.x** | 2026-10 | `random_mac`, rpcd-`rc/list`-Leck umgangen, Banderkennung, Panel-Fixes, Log-Hygiene, Device-Registry-Deprecation |
| **v1.29–v1.36** | 2026-10 | Repairs (Ausfall, RAM, Kanalkonflikt), Kanalplan, Router-Log + ACL v6, DFS-Events, DHCP-Pools, Client-Stabilität |
| **v1.28.x** | 2026-09/10 | LLDP-Topologie (Router-zu-Router + Ports), reicheres Client-Modell |
| **v1.27.0** | 2026-09 | Reboot-Button pro Router (ubus mit SSH-Fallback) |
| **v1.26.x** | 2026-08 | Log-Hygiene Multi-Router, ScannerEntity-Dedup, ACL v5, SSL-Kontext |
| **v1.20.0** | 2026-07 | HA-Kompatibilität 2026.8, de.json, CI-Modernisierung |
| **v1.19.0** | 2026-05 | rpcd-Session-Leak-Fix (Ursache des Router-OOM), ACL-Re-Validierung |
| **v1.18.0** | 2026-04 | Subprocess- + Panel-Lifecycle-Hardening, 24h-Prod-Sampler |
| **v1.17.x** | 2026-04 | Error-Sensor, Outage-Notifications, sshpass-Security-Fix, dynamische Sensoren default-off |
| **v1.16.0** | 2026-04 | HTTPS-Support (http / https / https-insecure) |
| **v1.15.x** | 2026-04 | rpcd-Memory-Leak-Fix (file/exec raus), Capability-Checklist im Config Flow, SSH-Fallback-Erkennung, adaptives Polling |
| **v1.14.x** | 2026-04 | Wiring-View, Traffic-View, Mobile-View |
| **v1.10–1.13** | 2026-04 | Topology-Panel-Ausbau: 5 Views, Minimap, Kontextmenü, Event-Timeline, VLAN-Badges (+Stale-Cache), CPU-History |
| **v1.0.x** | 2026-03 | Erstrelease: Sensoren, Switches, Buttons, Device Tracker, Update-Management |

---

## Architektur-Kurzreferenz

- `api.py` — alle HTTP/SSH-Calls (ubus JSON-RPC, `_safe_subprocess_exec` für SSH-Fallback)
  · LLDP via `lldpcli` über `_run_ssh` (kippt bewusst **nicht** den Degraded-Status),
  zeitbasiert gecacht (`LLDP_REFRESH_INTERVAL` / `LLDP_UNAVAILABLE_RETRY_INTERVAL`)
- `coordinator.py` — 60s-Poll (adaptiv: 120s bei CPU-Last >100 % pro Kern, 300s bei
  SSH-Fallback), Event-/CPU-History, Feature-Detection beim ersten Refresh
- `acl_provisioning.py` — rpcd-ACL **v7** per SSH (`scripts/ha-openwrt-router.json`
  ist die Vorlage); ein Versionssprung schreibt die ACL neu und startet rpcd
  einmal pro Router neu
- `topology_mesh.py` / `topology_panel.py` — Multi-Router-Aggregation + Sidebar-Panel
  · Kanten-Prioritaet: Method 0 LLDP → DHCP → ARP/Trunk → WiFi → Subnet-Fallback,
  danach Repeater-Override und Switch-Inferenz
- Entities lesen ausschließlich aus `coordinator.data`; runtime_data (typisiert) am Entry

## Bekannte Einschränkungen

| Einschränkung | Ursache | Impact |
|---|---|---|
| Event-History überlebt HA-Restart nicht | `deque` in-memory | Ereignisse gehen beim Neustart verloren |
| `signal=null` für manche Clients | `iw station dump` bracket-format | Signal-Wert fehlt, kein Fehler |
| Ghost-Mode akkumuliert nicht über Restarts | keine Persistenz | frisch gestartete Instanz zeigt keine Ghost-Devices |
| Panel-Static-Path bleibt bis HA-Restart gebunden | aiohttp-Router ist append-only | toter Endpoint nach letztem Unload (View antwortet 410) |
| WAN-Sensoren bestehender AP-Einträge bleiben aktiv | `enabled_default` wirkt nur bei neuen Entities, kein Registry-Eingriff (E3) | auf alten Dumb-AP-Einträgen weiter `unknown`, bei Bedarf manuell deaktivieren |
| Gateway mit WAN unter fremdem Namen (z. B. `lte`) | WAN-Erkennung über `WAN_INTERFACE_NAMES` | WAN-Sensoren neu angelegt deaktiviert, zeigen das erste aktive Interface |
| SSH-Fallback-Pfade nur mit Testdaten geprüft | keine SSH-Fallback-Hardware im Testnetz | Abweichungen echter `uci show`-Ausgaben möglich |

---

## Deployment

```bash
git pull   # main
git push
```

Panel-URL: `http://10.10.10.165:8123/openwrt-topology`
Router-ACL: `/usr/share/rpcd/acl.d/ha-openwrt-router.json` auf Gateway + APs
Offene Arbeiten: siehe [TODO.md](TODO.md)
