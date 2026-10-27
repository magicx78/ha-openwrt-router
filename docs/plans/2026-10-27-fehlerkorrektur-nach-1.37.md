# Plan: Fehlerkorrektur nach v1.37.4

## Status

- **Stand:** 2026-10-27 · **Phase:** freigegeben, in Umsetzung
- **Branch/PR:** `fix/post-1.37-findings` · PR #33 (A) · `fix/acl-v7-cpu-per-core` · PR #34 (B) · `fix/wireless-channel-ssh-fallback` · PR #35 (C) · `fix/wan-sensors-panel-release` · PR #36 (D) · Basis: v1.37.4 (`c5a25f9`)
- **Erledigt:** B1, P1, P2, P6 (PR #33, 1.37.5), P3 (PR #34, 1.38.0), P4 (PR #35, 1.38.1), P5 + B2 (PR #36, 1.38.2) · **Offen:** B3
- **Blocker:** –
- **Nächster Schritt:** Merge-Freigabe #33 → #34 → #35 → PR D durch den Nutzer; nach Installation ACL-v7-Prüfung auf den Routern

## Problem und Zielverhalten

v1.37.4 läuft seit 2026-10-27 in HA. Gateway (`openwrt`) und beide Dumb-APs (`ap2`, `ap4`) sind
geladen, die neuen Sensoren (Router-Log, DHCP-Pools, Kanalplan, DFS, Client-Stabilität) liefern
Werte, es gibt keine Repairs-Meldung der Integration und keine Entity ist `unavailable`.
Die Prüfung hat aber Log-Lärm, eine HA-Deprecation mit Ablaufdatum, falsch skalierte CPU-Werte
und mehrere kleinere Fehler gezeigt. Danach soll das HA-Log der Integration im Normalbetrieb
ruhig sein, die CPU-Last pro Kern stimmen und nichts mehr auf eine Deprecation laufen.

**Nicht-Ziele:** neue Features, Umbau des Panels, Änderungen an der Router-Konfiguration,
die LED-Wand (Funkreichweite, kein Code-Problem).

## Akzeptanzkriterien

- [ ] AK1 Die Warnung „Using 'root' as rpcd user“ erscheint pro Router höchstens einmal je HA-Start und nur nach erfolgreichem Login; nicht erreichbare Router erzeugen sie nicht.
- [ ] AK2 Ein WLAN-Schalter erzeugt keine Warnung „network.reload not available“, wenn die Änderung über `network.wireless up/down` greift.
- [ ] AK3 Unter HA 2026.10 meldet `homeassistant.helpers.frame` keine Deprecation mehr für `openwrt_router`; der HA-Floor aus `hacs.json` (2026.2.0) funktioniert weiter.
- [ ] AK4 Die CPU-Last ist auf die Kernzahl normiert (Lastmittel 1,22 auf 2 Kernen = 61 %), und die Poll-Drosselung greift erst bei echter Überlast (je nach E2).
- [ ] AK5 `_parse_wireless_status` liefert den Kanal aus dem `config`-Block, Tests decken beide Formen ab.
- [ ] AK6 Router ohne WAN (Dumb-AP) haben keine dauerhaft `unknown` WAN-Sensoren mehr (je nach E3).
- [ ] AK7 SSH-Fallback-Router erscheinen im Kanalplan (Sticky-Prüfung unverändert, usteer-Knoten bleiben ohne `ifname`-Option unbekannt); anonyme UCI-Sektionen und SSIDs mit `'` werden richtig gelesen.
- [ ] AK8 Das Panel zeigt bei zufälligen MACs keinen OUI-Hersteller.
- [ ] AK9 `scripts/checks.py --ruff-ci` grün, CI grün, unabhängiges Review ohne offene P0/P1 je PR.

## Befunde (verifiziert am 2026-10-27, v1.37.4)

1. **Root-Warnung als Dauerrauschen.** `api.py:930-933` warnt „einmal pro API-Instanz“, *vor* dem Login. Jeder Setup-Retry erzeugt eine neue Instanz → seit HA-Start 15 Warnungen in rund 60 s, danach alle paar Minuten erneut. **Verifiziert** im HA-Log.
2. **Drei Config-Entries ohne Router.** Drei Einträge stehen dauerhaft auf `setup_retry`. Die Router antworten nicht auf Ping und haben keinen ARP-Eintrag am Gateway. Sie sind die Hauptquelle von Befund 1. **Verifiziert** (Gateway, lesend).
3. **HA-Deprecation `device_registry.async_get_device`** in `topology_mesh.py:1130` und `coordinator.py:1155`. HA nennt 2027.8.0 als Ende. **Verifiziert** im HA-Log.
4. **CPU-Last nicht pro Kern.** `api.py:1294-1299` rechnet `load/65536*100`. Auf den 2-Kern-Routern zeigte der Sensor nach dem HA-Start 122 % bei einem Lastmittel von 1,22, die Drosselung in `coordinator.py` (`cpu > 100` → 120 s) griff, obwohl die Kerne nur zu 61 % belegt waren. Die ACL erlaubt weder `/proc/cpuinfo` noch `/proc/stat`. **Verifiziert** (HA-Log, `nproc`/`loadavg` lesend).
5. **„network.reload not available“** bei jedem WLAN-Schalter (`api.py:2851`). ACL v6 hat kein `network: reload`. Die Änderung greift trotzdem: Gast-WLAN aus/ein um 14:18/14:19, hostapd `AP-DISABLED` bzw. Neuaufbau im Router-Log. **Verifiziert**.
6. **Kanal aus `network.wireless status`.** netifd liefert `channel` nur im `config`-Block (`radio1.channel` leer, `radio1.config.channel` = 36), der Parser liest `radio_data.get("channel")` (`api.py` in `_parse_wireless_status`, ab Zeile 4576). **Verifiziert** (Gateway, lesend).
7. **WAN-Sensoren auf Dumb-APs** (WAN-IP, WAN-Download, WAN-Upload) stehen auf `ap2`/`ap4` dauerhaft auf `unknown`. **Verifiziert** (Template über alle 238 Entities).
8. **SSH-Fallback:** `ap_interfaces` bleibt leer, weil `get_ap_interface_details` den UCI-Zweig nur bei `_wifi_method == "uci"` nimmt; der Regex in `_get_wifi_status_ssh` erkennt `@wifi-iface[n]` nicht und schneidet `'\''` in SSIDs ab. **Verifiziert im Code** (Notiz der Session zu #31); keine SSH-Fallback-Hardware → Validierungslücke.
9. **Panel kennt `random_mac` nicht** (`frontend/topology/src/api.ts`, eigene OUI-Tabelle). **Verifiziert im Code** (Notiz der Session zu P1–P7).
10. **Aufräumen:** `switch._format_band` mit toten Einträgen `2g`/`60g`; `channel_plan`/`client_stability` importieren den privaten Helfer `api._band_from_frequency`. **Verifiziert im Code**.
11. **Release/Doku:** Release-Texte enthalten nur „siehe CHANGELOG.md“; `PROGRESS.md`/`TODO.md` stehen auf 1.28.0; die GitHub-Repo-Beschreibung (von HACS angezeigt) nennt „v1.4.0“. **Verifiziert**.
12. **rpcd-Speicher mit ACL v6:** Messung läuft bis etwa 17:15. Bisher APs flach (`ap2` 2972→3000 kB in 15 min), Gateway schwankt 2400–2860 kB. **Annahme:** kein neues Leck; Auswertung nach Messende.
14. **`uci_section` im Pfad `network.wireless status`:** `_parse_wireless_status` liest `section` aus `config`, netifd liefert es neben `ifname`; deaktivierte Interfaces fehlen dort ganz. Betrifft nur Router mit WLAN-Methode `network.wireless` – die drei Router hier nutzen den UCI-Pfad (live: `uci_section` gesetzt, `ifname` leer). Ein Fix ändert die `unique_id` der WLAN-Schalter solcher Router (Registry) und braucht eine eigene Entscheidung. **Verifiziert im Code und an Live-Attributen**, nicht geändert.
13. **Wiederhergestellte Device-Tracker mit altem AP-Namen:** zwei `device_tracker.secureap_ap3_*` gehören inzwischen zu den Einträgen von Gateway bzw. `ap4`, stehen auf `unavailable` (`restored: true`). Kosmetisch, Ursache vermutlich der Claim-Wechsel im Device-Tracker. **Verifiziert** (Template), niedrige Priorität.

## Neuanalyse nach 1.38.2 (2026-10-27, unabhängiger Agent, Stand der PRs #33–#36)

Nicht Teil dieses Plans; Grundlage für einen Folgeplan (Freigabe offen).

- **N1 (P1) Reauth-Schleife bei falschem Passwort.** `test_connection()` ignoriert den fehlgeschlagenen Login (`api.py` ~1132–1144) und macht aus der verweigerten Board-Abfrage Standardwerte (~1285–1296); `config_flow.py` ~474–489 hält alte Zugangsdaten für gültig, Setup wirft `ConfigEntryAuthFailed`, neuer Reauth. Auch Ersteinrichtung mit falschem Passwort wird angenommen; temporäre API in `_validate_input` (~650) lässt eine rpcd-Session zurück. **Verifiziert** (Skript).
- **N2 (P1) SSH-Logins in jedem Poll trotz funktionierendem ubus.** WAN-Zähler: `_call` liefert `{"data": …}`, der Code erwartet einen String (`api.py` ~1596–1606) → immer SSH; Disk/tmpfs (`~3454`, `~3533`, `~3633`) und Bridge-FDB (`~4018–4071`) ebenfalls per SSH. **Verifiziert auf Hardware (lesend):** HA meldet sich per Passwort rund 6×/min am Gateway und 5×/min an `ap2` an; dropbear-Zeilen belegen 269 von 605 bzw. 510 von 634 Zeilen im Log-Puffer und verdrängen das Router-Log, das P3 (Log-Ingest) liest. Host-Keys werden nicht geprüft (`known_hosts=None`).
- **N3 (P1) hostapd-Interface-Liste dauerhaft gecacht, auch leer** (`api.py` ~2060, ~2129): später aktivierte SSIDs fehlen (Clients, AP-Sensoren, Kanalplan) bis zum Neuladen. **Verifiziert im Code.**
- **N4 (P2)** Device-Tracker hängen an der Verfügbarkeit des besitzenden Routers (`device_tracker.py` ~134): AP-Neustart macht auch Clients anderer APs `unavailable`.
- **N5 (P2)** Tracker werden nach HA-Neustart nicht aus der Registry wiederhergestellt (`device_tracker.py` ~83–131): abwesende Clients `unavailable`, Personen `unknown` (vgl. Befund 13).
- **N6 (P2)** Update-Funktion wirkungslos: `updates_available` nie befüllt (`coordinator.py` ~281), Prüf-Button verwirft das Ergebnis (`button.py` ~248), „Updates installieren“ ruft `opkg` auf apk-basiertem 25.12 (`api.py` ~4317).
- **N7 (P2)** Diagnostics exportieren Client-Daten (MAC, IP, Hostname, Sticky-/Schwach-/Instabil-Listen, WAN-IPv4, Ereignisdetails) unredigiert (`diagnostics.py` ~56–66).
- **N8 (P3)** Interface-Byte-/Raten-Sensoren immer 0 (`network.interface dump` hat kein `statistics`, `api.py` ~3684); standardmäßig aus.
- **N9 (P3)** Recorder schreibt jede Minute neue Attributzeilen (WLAN-Schalter `dhcp_expires`, Client-Liste am Client-Zähler) → ~10 KB/min, MACs/IPs in der Datenbank; Abhilfe `_unrecorded_attributes`.
- **N10 (P3)** Poll-Versatz identisch für alle Einträge (`__init__.py` ~324): alle Router pollen gleichzeitig.
- **N11 (P3)** 300-s-SSH-Fallback-Intervall geht nach einem CPU-Drosselzyklus verloren (`coordinator.py` ~1038 vs. ~1062).
- Nach PR-#36-Review offen: Gateway mit WAN-Namen wie `lte`/`modem` gilt als „ohne WAN“ (`api.py` ~1570, `get_wan_status`).

## Entscheidungen

- 2026-10-27 – **E1:** Die drei Config-Entries ohne Router werden entfernt – die Geräte sind nicht im Netz und erzeugen nur Retries und Log-Lärm – Nutzer. Umgesetzt (B1), keine Automation, kein Skript, keine Szene und kein Helfer verwies darauf.
- 2026-10-27 – **E2:** Kernzahl über ACL v7 (`/proc/cpuinfo` lesen, einmal je Setup), gebündelt mit `network: reload` – behebt Befund 4 und 5 an der Wurzel; rpcd startet beim Deploy einmal pro Router neu, CPU-Werte halbieren sich auf 2-Kern-Routern – Nutzer.
- 2026-10-27 – **E3:** WAN-Sensoren auf Routern ohne WAN standardmäßig deaktiviert anlegen, bestehende Entities bleiben (kein Registry-Eingriff) – Nutzer.

## Arbeitspakete

| ID | Rolle | Inhalt | Dateien | Hängt ab von | Aufwand | Definition of Done |
|---|---|---|---|---|---|---|
| P1 | HA | Root-Warnung einmal je Host und erst nach erfolgreichem Login; „network.reload“-Warnung auf debug, wenn `network.wireless up/down` greift | `api.py`, `tests/test_api.py` | – | S | AK1, AK2, Tests für Retry-Instanzen |
| P2 | HA | `async_get_device` → `async_get_device_by_connection` mit Rückfall für ältere HA-Versionen | `topology_mesh.py`, `coordinator.py`, Tests | – | S | AK3; vorher prüfen, ab welcher HA-Version die neue API existiert |
| P3 | OpenWrt/HA | CPU-Last pro Kern + Drosselschwelle; bei E2=A ACL v7 (`/proc/cpuinfo`, `network: reload`) | `api.py`, `coordinator.py`, `acl_provisioning.py`, `scripts/ha-openwrt-router.json`, Tests | E2 | M | AK4 (+AK2 an der Wurzel); Risikoauslöser ACL → Review Pflicht |
| P4 | OpenWrt | Kanal aus `config`-Block; SSH-Fallback füllt `ap_interfaces`; UCI-Regex für anonyme Sektionen und `'\''` | `api.py`, `tests/test_api.py` | – | M | AK5, AK7; SSH-Teil nur mit Testdaten (Lücke benannt) |
| P5 | HA/Frontend | WAN-Sensoren nur bei Routern mit WAN (je E3); Panel blendet Hersteller bei `random_mac` aus; Bundle neu bauen | `sensor.py`, `frontend/topology/src/api.ts`, `frontend/dist/*` | E3 | M | AK6, AK8; Panel visuell geprüft |
| P6 | Aufräumen | `switch._format_band` bereinigen; Bandhelfer in eigenes Modul `wifi_band.py`; Ursache von Befund 13 klären (nur Analyse, Registry-Eingriff nur mit OK) | `switch.py`, `wifi_band.py`, `api.py`, `channel_plan.py`, `client_stability.py` | P4 | S | keine Verhaltensänderung, Tests grün |
| B1 | Betrieb | E1 umsetzen (Config-Entries entfernen oder deaktivieren) | HA | E1 | S | keine `setup_retry`-Einträge mehr |
| B2 | Doku/Release | Release-Workflow übernimmt den CHANGELOG-Abschnitt; `PROGRESS.md`/`TODO.md` nachziehen; Repo-Beschreibung ohne Versionsnummer (nur mit OK) | `.github/workflows/release.yaml`, `PROGRESS.md`, `TODO.md` | – | S | nächstes Release zeigt die Änderungen in HACS |
| B3 | Validierung | rpcd-Messung nach 17:15 auswerten | – | – | S | Ergebnis im Prüfprotokoll |

**PR-Schnitt (Vorschlag, jeder Merge = ein Release):** PR A = P1+P2+P6 (1.37.5) · PR B = P3 (1.38.0 bei ACL v7, sonst 1.37.6) · PR C = P4 · PR D = P5 · B2 ohne Versionssprung oder mit dem nächsten PR.

## Risiken und Kompatibilität

- HA-Floor 2026.2.0: P2 braucht einen Rückfall, falls `async_get_device_by_connection` dort fehlt.
- ACL v7 (P3, E2=A): Deploy startet rpcd auf jedem erreichbaren Router einmal neu, wie heute bei v6.
- CPU-Sensor: halbierte Werte nach P3, Langzeitstatistik springt; im CHANGELOG nennen.
- P5 mit Registry-Eingriff (E3 „entfernen“) wäre ein Risikoauslöser; Empfehlung vermeidet ihn.
- Kein Config-Entry-Versionswechsel geplant.

## Validierungsplan

- **Lokal:** `scripts/checks.py --ruff-ci` (ruff 0.17.3), neue Tests je AK; bei P5 zusätzlich `--frontend`.
- **CI:** tests (Py 3.13/3.14), hassfest, hacs je PR.
- **Hardware (lesend):** `ubus call network.wireless status` (Profil `openwrt`, Kanal im `config`-Block), `cat /proc/loadavg` + `nproc` gegen den CPU-Sensor, HA-Log nach einem Neustart frei von AK1-/AK2-/AK3-Meldungen.
- **Review:** unabhängig je PR (frischer Agent mit Diff und AK).

## Prüfprotokoll

- 2026-10-27 v1.37.4 in HA – Integration geladen (3/3 erreichbare Router), 238 Entities, 0 `unavailable`, keine Repairs der Integration; ACL v6 auf `openwrt`/`ap2`/`ap4` aktiv; Befunde 1–13 wie oben.
- 2026-10-27 `fix/post-1.37-findings` (PR A) – lokal: ruff 0.17.3 sauber, 1174 Tests grün (vorher 1136; neue Tests für P1/P2 vor dem Fix rot) · Hardware: nicht nötig · Review: folgt.
- 2026-10-27 PR #33 Review (unabhängig): keine P0/P1; P2 (fehlschlagendes `network.reload` nach Commit galt als Commit-Fehler) und P3-Punkte behoben (`0f8985f`), 1179 Tests grün.
- 2026-10-27 `fix/acl-v7-cpu-per-core` (PR B) – lokal: ruff 0.17.3 sauber, 1214 Tests grün (35 neue, 32 davon vor der Änderung rot) · Hardware: ACL v7 nicht verteilt (Lücke: Sensor = loadavg/nproc, Schalter konfiguriert das Radio nur einmal, rpcd-Neustart je Router) · Review: folgt.
- 2026-10-27 PR #34 Review (unabhängig): keine P0–P2; P3 behoben (`6d9aa96`: Retry trotz gecachter ACL-Sperre, 5xx kurzfristig, 4-KiB-Hinweis, CHANGELOG), 1216 Tests grün.
- 2026-10-27 `fix/wireless-channel-ssh-fallback` (PR C) – lokal: 23 neue Tests (13 vor der Änderung rot), nach Merge von #34 grün · Hardware: SSH-Fallback nicht vorhanden (Lücke) · Review: folgt.
- 2026-10-27 PR #35 Review (unabhängig): keine P0/P1; P2 (Sticky-Behauptung, abgeschaltete Radios im Kanalplan) und P3 (Quoting, keine WLAN-Secrets im Speicher, CHANGELOG-Hinweise) behoben; `option ifname` nur im SSH-Pfad, damit bestehende AP-Sensoren ihre ID behalten; 1263 Tests grün.
- 2026-10-27 `fix/wan-sensors-panel-release` (PR #36) – lokal: 34 neue Tests (20 vor der Änderung rot), `tsc` grün, Bundle neu gebaut; „Kein WAN“-Signal live geprüft (Gateway `wan`, APs `guest`) · Panel nicht visuell im echten HA geprüft (Lücke) · Review (unabhängig): keine P0–P2, Doku-Punkte behoben; offen für später: Gateway mit WAN-Namen wie `lte` gilt als „ohne WAN“. Befund 9 war größtenteils schon mit 1.37.4 erledigt.
- 2026-10-27 Neuanalyse (unabhängig) nach PR #36: 11 Befunde N1–N11, N2 auf Hardware bestätigt (SSH-Logins ~5–6/min je Router, dropbear dominiert den Log-Puffer). rpcd mit ACL v6 bis 15:52: APs zweite Hälfte +8/+1 kB/h, Gateway fallend – kein neues Leck (Endauswertung nach 17:15 offen).
- 2026-10-27 B1 – drei Config-Entries entfernt; danach 3 Einträge, alle `loaded`. Sicherung vorher: HA-Backup vom selben Tag, 13:46.
