# Network Time Machine (Phase 6): Plan zur Freigabe

Stand: 2026-11-26 · Basis: v1.49.3 (`main` = `ea8781f`) · vom Nutzer am 2026-11-21 freigegeben (Entscheidungen in Abschnitt 15)

**Umsetzungsstand:** alle Phasen gebaut. Phase A in 1.50.0, Phasen B und C in 1.51.0, Phasen D bis F in
1.52.0 (PR #71, noch nicht gemergt). Was gebaut wurde und welche Grenzen bleiben, steht in
`docs/time-machine.md` und im CHANGELOG; dieses Dokument ist der freigegebene Plan von damals und
wird nicht mehr fortgeschrieben.

<!-- Ablage: docs/plans/2026-11-21-network-time-machine.entwurf-zur-freigabe.md · ungetrackt, bis der
     Nutzer freigibt. Keine Adressen, Hostnamen, SSIDs oder MACs echter Geräte in diesem Dokument. -->

Kennzeichnung: **belegt** (im Code mit `datei:zeile`), **Annahme** (plausibel, nicht belegt; Prüfweg
steht dabei), **nicht gefunden** (gesucht, nicht im Code), **Vorschlag** (Planentscheidung, braucht
Freigabe). Pfade ohne Verzeichnis meinen `custom_components/openwrt_router/`. Die einzige Vorgabe des
Nutzers steht in `docs/plans/2026-11-20-traffic-analytics.md:648`: „historische Netzwerkzustände,
Konfigurationsänderungen, Client-Verbindungen und Störungsverläufe auf einer gemeinsamen Zeitleiste“.

---

## 1. Kurzfassung

Die Time Machine beantwortet eine Frage, die heute nur mit sechs offenen Tabs und Kopfrechnen geht:
**„Was war wann im Netz los, und was ging dem voraus?“** Sie legt Ausfälle, Konfigurationsänderungen,
Client-Verbindungen, WLAN- und Traffic-Auffälligkeiten und Diagnosebefunde aller Router auf eine
Zeitleiste und kann für einen gewählten Zeitpunkt zeigen, wie das Netz ungefähr aussah.

Sie misst fast nichts neu. Die vorhandenen Module wissen das meiste schon; was fehlt, ist eine
gemeinsame Zeitbasis, eine gemeinsame Kennung für Router und Clients und ein Gedächtnis für die
Dinge, die heute nach einem Neustart oder nach 24 Stunden verloren gehen (Ausfälle, Kanalwechsel,
Uplink-Wechsel, Client-Sitzungen).

Sie ist bewusst **nicht**: ein Ersatz für den Home-Assistant-Verlauf, ein Packet- oder Flow-Archiv,
eine Konfigurationssicherung (das bleibt der Configuration Manager), eine Ursachenanalyse mit neuen
Regeln (das bleibt Network Intelligence) oder ein Überwachungswerkzeug für Personen.

## 2. Anwendungsfälle

| Nr. | Frage des Nutzers | Was die Time Machine zeigt |
|---|---|---|
| U1 | „Was hat sich zwischen gestern 20 Uhr und heute geändert?“ | Vergleich zweier Zeitpunkte: Router erreichbar/nicht, Uplinks, Kanäle, Konfigurationsversionen dazwischen (Link auf Diff), geöffnete und geschlossene Vorfälle, Zahl der Clients je AP |
| U2 | „Wann war Client X wo verbunden, und was passierte davor?“ | Verlauf eines Clients: Sitzungen je AP mit Beginn/Ende/Roaming, Abbruchgründe, daneben Vorfälle und Änderungen am jeweiligen AP |
| U3 | „Wie sah das Netz aus, als der Ausfall begann?“ | Zustand zum Zeitpunkt: welche Router erreichbar, welcher Uplink, WAN-Zustand, offene Vorfälle, letzte Konfigurationsversion, Stundenwerte Traffic/Kanalauslastung |
| U4 | „Welche Konfigurationsänderung ging der Störung voraus?“ | Zeitleiste gefiltert auf einen Router, ±2 h um den Vorfall: Drift-, Versions- und Fingerabdruck-Marken vor dem Vorfall, mit Abstand in Minuten (Hinweis, keine Kausalbehauptung) |
| U5 | „Seit wann ist der Repeater so instabil?“ | Verlauf eines Routers über 14 Tage: Ausfälle, Neustarts, Kanalwechsel, DFS, Befunde der Diagnose, Tageswerte |
| U6 | „Hat das nächtliche Backup oder ein Neustart von Home Assistant etwas ausgelöst?“ | Marken für HA-Start/-Stopp und Beobachtungslücken, damit eine Lücke nie als Ausfall gelesen wird |

## 3. Bestandsanalyse

### 3.1 Übersicht je Quelle

| Quelle | Was | Aufbewahrung / Grenze | Zeitformat | Kennungen | Lese-Schnittstelle | Lücke für eine gemeinsame Zeitleiste |
|---|---|---|---|---|---|---|
| **Enterprise Core, Audit-Log** | Alle Core-Ereignisse (`router.*`, `configuration.*`, `security.*`, `core.*`) und Modul-Ereignisse von WiFi RF, Diagnose, Security Center, Traffic, Configuration Manager | Ring „general“ 1000, „security“ 500 Einträge, je 90 Tage, Store `openwrt_router.audit` (`core_audit.py:1-7`, `core_models.py:225-233`); Wiederholungen binnen 24 h nur gezählt (`core_models.py:224`) | `datetime` mit Zeitzone (`core_models.py:4240`) | `router_id` `rtr_…`, `client_ref` `cli_…` (`core_models.py:4172-4182`), `correlation_id`, `incident_ref`, `radio_id` | ja: `AuditLog.events(router_id, types, since, until, correlation_id, ring, limit)` (`core_audit.py:703-730`); für Module `api.events(...)` **ohne `until`**, Standardlimit 50, Höchstwert 500 (`config_api.py:2969-2981`, `core_models.py:234-235`); Abo `subscribe` | Ring „general“ hat **keine Quote je Modul**: ist er voll, fällt der älteste Eintrag gleich welcher Art (`core_audit.py:545-554`). Ein lautes Modul kann Konfigurationsereignisse verdrängen. Beobachtung: Docstring sagt „newest first“, `AuditLog.events` sortiert aufsteigend (`config_api.py:2978`, `core_audit.py:727`) |
| **HA-Bus-Ereignis des Core** | `openwrt_router_core_event`, Nutzlast maskiert (`core_models.py:116-118`) | im HA-Recorder (Annahme: HA-Standard 10 Tage) | ISO | wie oben, Benutzer pseudonymisiert | über HA-Logbuch (`logbook.py:111`) | Duplikat des Audit-Logs, für die Time Machine nicht nötig |
| **Configuration Manager** | Versionen (Sicherungen) mit Grund (manuell, täglich, Drift, vor Wiederherstellung, Vorfall …) (`core_models.py:1003-1015`), Drift-Ereignisse, Diffs | GFS 7 täglich / 4 wöchentlich / 6 monatlich (`core_models.py:2661-2675`), 50 MiB je Router, 250 MiB gesamt (`version_store.py:16-17`); höchstens 4 Drift-Versionen je Router und Tag (`const.py:757`); **Standard aus** (`const.py:729`, `core_models.py:183`) | `datetime` (`core_models.py:2262`) | `router_id`, `backup_id` `bkp_…` | ja: `async_list_backups(router_id, since, limit)` (`config_api.py:1279-1291`), `async_compare(a, b)` nur für Admins, schreibt Audit (`config_api.py:1357-1387`); Route `…/config/routers/{id}/diff` admin-only (`config_views.py:7`, `:1183-1214`); Geheimnisse als Marker `secret` (`config_views.py:402-417`) | Zwischen zwei Versionen ist der Zeitpunkt der Änderung nur auf „zwischen Version A und B“ genau; die Drift-Erkennung (Fingerabdruck aus Poll-Daten, kein Router-Aufruf, `config_snapshot.py:816-828`) läuft höchstens stündlich (`config_const.py:702`). Bei ausgeschaltetem Modul gibt es gar keine Konfigurationsmarken |
| **Security Center** | Zeitleiste (Hinweise, Firewall, WLAN-Anmeldefehler, Traffic-Hinweise), eigene Vorfälle, Geräte mit Vertrauensstatus | Zeitleiste höchstens 2000 Einträge, 14 Tage; Traffic-Notizen höchstens 500; 100 Vorfälle; Store 512 KiB (`const.py:788-806`); **Standard aus** (`security_center.py:471`) | Epoch-Sekunden (`security_center.py:587`) | `router_id`, `client_ref` mit **eigenem Modulschlüssel** | ja: `overview(actor, since, until, router_id, client, category, severity, limit)` (`security_center.py:3197-3260`); MAC nur für Admins (`security_views.py:8-14`) | 14 Tage ist kürzer als die übrigen Quellen; `client_ref` ist nicht mit den Pseudonymen anderer Module vergleichbar (siehe 3.2) |
| **Netzwerkdiagnose** | Messreihen (HA und je Router), Grundlinien, Neustart-Lücken; Befunde und Ursachen als Audit-Ereignisse `net_diagnostics.finding` / `.cause` / `.gateway_changed` / `.dns_server_changed` (`diag_core.py:185-191`, `diag_runtime.py:1440-1470`) | Stundenwerte 7 Tage, Tageswerte 30 Tage, 64 Lückeneinträge (`diag_store.py:21-30`, `const.py:866-872`); **Standard aus** (`diag_runtime.py:320`) | Epoch | `router_id`, Pseudonyme mit eigenem Modulschlüssel (`diag_core.py:914`) | Route `…/diagnostics/history` und `/details` (`diag_views.py:380-395`); Befunde nur über das Audit-Log | Befunde liegen im geteilten Ring „general“ (Verdrängungsrisiko oben) |
| **WiFi RF** | Stunden- und Tageswerte je Radio (Auslastung, Rauschen, Clients, …), Roaming-Bewertung, Empfehlungen; Ereignisse `wifi_rf.*` im Audit-Log (`rf_events.py:61-71`) | Stundenwerte 8 Tage, Tageswerte 31 Tage, höchstens 32 Radios, 2 MB (`const.py:942-947`); Tagesgrenze lokal, Stunden UTC (`rf_store.py:14-17`); **Standard aus** (`const.py:909-911`) | Epoch / `datetime` | `router_id` + UCI-Radioname; keine MAC im Store (`rf_store.py:9-10`) | ja: `radio_utilization`, `client_retry_rates` nur **relativ zu jetzt** (`rf_center.py:32`, CHANGELOG 1.49.1); Route `…/wifi/timeline` mit festen Fenstern (`rf_views.py:203-230`) | Kein Lesen „Stundenwert zum Zeitpunkt T“ über die Schnittstelle |
| **Traffic Analytics** | 5-min-, Stunden-, Tageswerte je Messpunkt; Anomalie-Kandidaten; Belege `evr_…` | Profil „compact“ (Standard): Infrastruktur 5 min 6 h, Stunde 14 Tage, Tag 31 Tage; Clients 6 h / 2 Tage / nicht gespeichert; „standard“: bis 90 Tage (`traffic_history.py:156-172`, `traffic_const.py:610`); 100 Kandidaten, 100 Belege (`traffic_const.py:393`, `:586`) | UTC-Buckets | `router_id`, Netdev-Name, `client_ref` (eigener Modulschlüssel), keine MAC (`traffic_history.py:31-35`) | ja: `TrafficReadApi.points/latest/window/router_window/congestion/evidence` (`traffic_correlate.py:2060-2172`), Fenster nur benannt und relativ zu jetzt (`traffic_const.py:593-600`) | Kein Fenster mit festem Anfang und Ende |
| **Network Intelligence** | Ereignisse aus Router-Log, hostapd, Poll, Flotte, usteer, LLDP, Topologie (`net_events.py:65-76`), Vorfälle mit Ursache und Belegkette, Zählerbuckets | 30 Tage, 3000 Ereignisse, 500 Vorfälle (`net_events.py:27-30`, `net_rules.py:130-133`), Store 1,5 MB (`const.py:609-615`); kein Ein/Aus-Schalter gefunden | Epoch, mit Erkennung von Uhrsprüngen (`net_engine.py:62`, `:314`) | **`entry_id`** statt `router_id` (`net_engine.py:1688-1690`); `subject.mac` **im Klartext** (`net_engine.py:1645-1653`) | ja: `net_query.py` (Ereignisse höchstens 500, Vorfälle 200 je Abfrage, `net_query.py:51-58`), Routen `…/intelligence/events|incidents` (`topology_panel.py:318-367`) | Andere Router-Kennung als der Core; Klartext-MAC im Store |
| **Client Stability** | Zustandsautomat je MAC, Zeit je (MAC, Stunde, AP), Übergänge `start/end/move/gap/resume/blip` (`client_history.py:101-108`) | Übergänge nur **24 h, höchstens 64 je MAC** (`client_history.py:137-138`); Stundenbuckets 7 Tage, Tagesbuckets 30 (bis 90) Tage, 1000 Clients (`client_history.py:146-148`); Store 3 MB (`const.py:647-653`); Standard an (`client_engine.py:202`) | Epoch | **Klartext-MAC** als Schlüssel, `entry_id` | Routen `…/intelligence/clients[/{mac}]`, zeigt MAC/IP/Hostname jedem Panel-Nutzer (`client_views.py:1-11`) | Wer wann wo verbunden war, ist nach 24 h nur noch als Stundensumme je AP vorhanden, nicht als Sitzung |
| **Coordinator** | Kleine Ereignisliste (WAN, CPU), Topologie-Schnappschüsse, CPU-Verlauf | **nur im Speicher**: 30 Ereignisse, 20 Schnappschüsse alle 10 Polls (rund 100 min), CPU 1 h (`coordinator.py:663-669`, `const.py:493-499`) | Epoch | `entry_id`, Schnappschuss mit Klartext-MAC/Hostname/IP (`coordinator.py:1192-1212`) | in `coordinator.data` | Weg nach jedem Neustart |
| **Ausfall-Tracker** (`fleet.py`) | Beginn/Ende von Router- und LAN-Ausfällen | nur im Speicher; HA-Ereignis `openwrt_router_outage_event` (`fleet.py:357-366`, `const.py:213`); Network Intelligence übernimmt sie als Ereignis (`net_engine.py:30-34`) | ISO | `entry_id`, Router-Titel | `add_listener`, `snapshot` (`fleet.py:13-16`) | Eigene Historie nur über Network Intelligence (30 Tage) und Recorder |
| **DFS / Kanalwechsel** | Kanal- oder Breitenwechsel je Radio, mit DFS-Beleg aus dem Log (`const.py:552-556`) | nur letztes Ereignis und 64 Logzeilen im Speicher (`coordinator.py:699-700`); HA-Ereignis `openwrt_router_dfs_event` (`coordinator.py:1968-1976`) | ISO | `entry_id`, phy | nein (nur `coordinator.data`, `coordinator.py:1121`) | Historie nur im Recorder |
| **Log-Ingest WLAN/DHCP** | HA-Ereignisse `openwrt_router_wifi_event` / `_dhcp_event` je Logzeile | höchstens 10 je Abruf, 1 je Art und MAC in 300 s (`const.py:546-549`) | ISO ms | **Klartext-MAC und Hostname** in der Nutzlast (`coordinator.py:1746-1761`) | nein (Recorder/Logbuch, `logbook.py:90-93`) | Gehört in den Recorder, nicht doppelt in die Time Machine |
| **Topologie / Mesh** | Aktuelles Mesh, Kanten, Uplinks (`topology_mesh.py`) | nur aktueller Stand; Network Intelligence merkt sich Kanten bis zu einem Tag im Speicher (`net_engine.py:34`) | — | MAC, `entry_id` | Route `…/snapshot` (`topology_panel.py:141`) | **Keine Topologie-Historie** über Neustarts |
| **Kanalplan** | Konflikte gleicher/überlappender Kanal (`channel_plan.py:1-15`) | nur aktuell, Repairs-Eintrag | — | `entry_id`, phy | nein | keine Historie |
| **Home Assistant selbst** | Zustände aller Entitäten der Integration, u. a. je Client ein `device_tracker` mit Attributen `connected_ap`, `ssid`, `ip_address`, `connected_since` (`device_tracker.py:403-431`); alle oben genannten HA-Ereignisse | Recorder (Annahme: HA-Standard `purge_keep_days` 10; in der Instanz nicht geprüft) | — | `entity_id`, Klartext | HA-Verlauf und Logbuch | Siehe 3.3 |

### 3.2 Querschnitt-Lücken

1. **Zwei Router-Kennungen.** Core, WiFi RF, Traffic, Security Center und Diagnose benutzen
   `router_id` (`rtr_…`); Network Intelligence, Client Stability, Coordinator und die HA-Ereignisse
   benutzen die `entry_id`. Die Abbildung gibt es: `RouterRegistry.router_id_for_entry`
   (`router_registry.py:1759-1761`). Für entfernte Router bleibt der Core-Eintrag als „verwaist“
   erhalten (`enterprise_core.py:19-20`).
2. **Kein gemeinsames Client-Pseudonym.** Jedes Modul pseudonymisiert mit seinem eigenen
   Modulschlüssel (`core_models.py:610-620`, `config_api.py:1130-1168`); WiFi RF, Traffic und
   Security Center erzeugen alle `cli_<16 hex>` (`rf_privacy.py:117-123`,
   `traffic_collect.py:108-114`, `security_model.py:532-534`) — **gleiches Format, verschiedene
   Werte für denselben Client**. Ein naiver Abgleich über `client_ref` wäre falsch. Klartext-MACs
   haben nur Network Intelligence, Client Stability, Coordinator und der Recorder.
3. **Kein „Zustand zum Zeitpunkt T“.** Alle Lese-Schnittstellen liefern Ereignislisten oder Fenster
   relativ zu jetzt. Zustände (welcher Uplink, welcher Kanal, welche Clients wo) werden nirgends
   über einen Neustart hinweg aufbewahrt.
4. **Drei Zeitformate.** `datetime` mit Zeitzone (Core), Epoch-Sekunden (Network Intelligence,
   Client Stability, Security Center, Diagnose), UTC-Buckets bzw. lokale Tage (Traffic, WiFi RF).
   Umrechnung ist einfach; die Uhrsprung-Behandlung (`on_clock_shift`, z. B. `net_engine.py:314`)
   gibt es nur in einigen Modulen.
5. **Unterschiedliche Aufbewahrung.** 24 h (Client-Übergänge), 14 Tage (Security Center,
   Traffic-Stunden), 30 Tage (Network Intelligence), 90 Tage (Audit). Eine Zeitleiste über 30 Tage
   wäre zu Beginn dicht und hinten lückenhaft; das muss sichtbar sein.
6. **Kein modulübergreifendes „Client vergessen“.** Gefunden: Ausschluss einer MAC in Network
   Intelligence, der in Client Stability `forget` auslöst (`client_engine.py:697-698`). Ein Löschen
   eines Clients in Security Center, Traffic oder Recorder auf einen Befehl: nicht gefunden.
7. **Keine Sprungadressen im Panel.** Die Fach-Tabs lesen keine URL-Parameter für ein bestimmtes
   Objekt (`main.tsx:295-302` nur `nomock` und Entwicklerparameter). Für „aus der Zeitleiste in den
   Fach-Tab springen“ fehlt das.

### 3.3 Was die Time Machine NICHT duplizieren soll

- **Entitätszustände** (Sensoren, `device_tracker`, Schalter): liegen im Recorder. Die Time Machine
  verlinkt auf den HA-Verlauf, statt Werte zu kopieren.
- **HA-Ereignisse** WLAN/DHCP/DFS/Ausfall/Vorfall/Core: liegen im Recorder und im Logbuch. Die Time
  Machine erzeugt **keine** neuen HA-Ereignisse (Vorschlag, Frage F6).
- **Inhalte der Fachmodule** (Messreihen, Belege, Diffs, Belegketten): bleiben dort; die Time Machine
  speichert nur Verweise und einen kurzen Code.

## 4. Kernentscheidung Architektur

| | (a) Reine Leseschicht | (b) Begrenzter Zeitleisten-Index mit Verweisen | (c) Eigener Zustandsspeicher mit Netz-Schnappschüssen |
|---|---|---|---|
| Prinzip | Bei jeder Abfrage alle Quellen lesen, zusammenführen, sortieren | Eigener kleiner Store mit **Marken** (Zeit, Art, Router, Client-Pseudonym, Verweis auf die Quelle); speichert nur, was sonst verloren geht oder verdrängt wird; Inhalte bleiben in den Quellen | Alle N Minuten ein vollständiger Netzzustand (Router, Uplinks, Kanäle, Clients je AP, WAN, Zähler) |
| Kann | Zeitleiste über das, was die Quellen heute aufheben | Alles von (a); dazu Ausfälle, Kanal-/Uplink-Wechsel, HA-Lücken, Client-**Sitzungen** über 24 h hinaus; „Zustand zum Zeitpunkt“ durch Rückrechnung aus Marken plus täglichem Kontrollpunkt | „Zustand zum Zeitpunkt“ direkt und genau auf das Raster |
| Kann nicht | Client-Sitzungen älter als 24 h, Ausfälle/Kanalwechsel nach Neustart, „Zustand zum Zeitpunkt“; verdrängte Audit-Einträge sind weg | Zustände zwischen zwei Marken, die keine Quelle meldet (z. B. Signalstärke eines Clients um 14:07) | Was zwischen zwei Schnappschüssen passiert; ohne zusätzliche Marken keine Reihenfolge von Ereignissen |
| Speicher | 0 | geschätzt 1–2,5 MB bei 14 Tagen (Annahme: sieben Router, rund 60 Clients, je Client 10 Sitzungsabschnitte am Tag; Rechnung in 5.6) | geschätzt 10–40 MB bei 5 min und 14 Tagen (4032 Schnappschüsse × 3–10 KB) — für HA-Stores (JSON, eingerückt) zu groß |
| Router-Last | keine | keine | keine, solange nur `coordinator.data` gelesen wird |
| Risiko | Abfragezeit wächst mit allen Quellen (Network Intelligence 3000 + Audit 1500 + Security 2000 Einträge); Fehler einer Quelle muss sichtbar bleiben | Doppelte Wahrheit, wenn Marken Inhalte kopieren (Gegenmittel: nur Verweise und Codes); Pseudonym-Abbildung | Großer Store, lange Schreibzeiten in der Event-Loop (siehe Traffic 1.49.3), viel personenbezogene Information an einer Stelle |
| Aufwand | S–M | M–L | L |

**Empfehlung (Vorschlag): (b), gebaut in der Reihenfolge (a) → (b).** Phase A liefert die reine
Leseschicht (Variante a) und ist für sich nützlich; ab Phase B kommt der begrenzte Index dazu, der
nur das festhält, was die Quellen nicht aufheben. Variante (c) lehne ich ab: der Speicherbedarf passt
nicht zu HA-Stores, und ein 5-Minuten-Schnappschuss aller Clients ist ein Bewegungsprofil, das das
Paket nicht braucht. Den „Zustand zum Zeitpunkt“ liefert (b) aus Marken plus einem kleinen
Kontrollpunkt je Tag und je HA-Start (5.4).

## 5. Datenmodell der empfohlenen Variante (b)

### 5.1 Eine Marke

| Feld | Typ | Bedeutung |
|---|---|---|
| `id` | `tmm_<16 hex>` | eigene Kennung |
| `ts` | float, Epoch-Sekunden UTC | Zeitpunkt; bei Intervallen der Beginn |
| `end` | float oder None | Ende eines Intervalls (Ausfall, Sitzung, Lücke); None = noch offen |
| `kind` | Code aus 5.2 | Art |
| `router_id` | `rtr_…` oder `-` | immer Core-Kennung; `entry_id` wird beim Eintragen umgerechnet |
| `client` | `tmc_<16 hex>` oder None | Pseudonym mit dem Schlüssel des Moduls `time_machine` (eigenes Präfix, damit es nie mit `cli_` anderer Module verwechselt wird) |
| `severity` | info / warning / critical | |
| `source` | Modulname | `core`, `config_manager`, `net_intel`, `client_stability`, `security_center`, `net_diagnostics`, `wifi_rf`, `traffic_analytics`, `time_machine` |
| `ref` | String oder None | Verweis in die Quelle: `evt_…`, `bkp_…`, Vorfall-ID, `evr_…`, NI-Ereignis-ID |
| `code` | String ≤ 64, Muster wie `EVENT_CLASSIFICATION_PATTERN` (`core_models.py:4171`) | maschinenlesbare Kurzbeschreibung, z. B. `uplink_changed`, `channel 36→100` als Parameter |
| `params` | Mapping, höchstens 8 Schlüssel, nur Zahlen und Codes | z. B. alter/neuer Kanal, AP-Router, Abbruchgrund |
| `quality` | `observed` / `derived` / `gap` | gemessen, abgeleitet, oder Beobachtungslücke |

Keine Freitexte, keine MAC, IP, Hostnamen oder SSIDs im Store. Texte entstehen erst im Panel aus
`code` und `params`.

### 5.2 Arten

| Gruppe | Arten | Herkunft | Speichert die TM selbst? |
|---|---|---|---|
| Infrastruktur | `router_down` / `router_up` (Intervall), `lan_down`, `ha_gap` (HA aus), `observation_gap` (Router lieferte keine Daten) | Ausfall-Tracker-Listener (`fleet.py:13-16`), HA-Start/-Stopp | ja |
| Funk | `channel_changed`, `dfs_event`, `radio_down/up` | Vergleich `coordinator.data` zweier Polls; DFS-Feld `coordinator.py:1121` | ja |
| Topologie | `uplink_changed`, `router_role_changed` | Vergleich des Uplinks je Router zwischen Polls | ja |
| Konfiguration | `config_fingerprint_changed` (auch bei Configuration Manager aus; reine Funktion `config_snapshot.py:816`, kein Router-Aufruf), `config_version` (Verweis `bkp_…`), `config_drift` (Verweis `evt_…`) | eigener Vergleich; `async_list_backups`; Audit | Fingerabdruck ja; Versionen und Drift nur als Verweis |
| Störung | `incident_opened/resolved` (NI), `security_incident`, `diag_finding`, `traffic_anomaly`, `rf_event` | Quellen | nur Verweis-Marke, damit sie nicht mit dem Audit-Ring verloren geht (Frage F7) |
| Clients | `client_session` (Intervall je AP), `client_roam`, `client_disconnect` (mit Grundklasse `error/inactivity/leave/infra/unknown`, `client_history.py:74-79`) | Übergänge von Client Stability bzw. NI-Ereignisse | ja, als Sitzungsabschnitte |
| Eigene | `tm_started`, `tm_disabled`, `tm_store_recovered`, `tm_forgot_client`, `tm_exported` | TM | ja |

### 5.3 Kennungen

- Router: immer `router_id`. Verwaiste Router behalten ihre Marken bis zum Ablauf.
- Clients: `tmc_` + HMAC(Schlüssel des Moduls `time_machine`, MAC) über
  `pseudonymise_identifier`-Logik (`core_masking.py:1529-1548`). Die Time Machine bekommt den
  Schlüssel nur, nachdem sie ihr Ereignispräfix `time_machine.` registriert hat
  (`config_api.py:1153-1157`).
- Verknüpfung zu den Pseudonymen anderer Module: **nie über die Werte**. In Phase E bekommen die
  Module eine kleine Lesefunktion „Pseudonym für diese MAC“ (nur im Prozess, nie über HTTP). Den
  Schlüssel eines fremden Moduls holt sich die Time Machine nicht (wäre technisch möglich, weil
  `async_get_module_key` nur „registriert“ prüft, `config_api.py:1153`; Vorschlag: das in Phase A
  per Test verbieten bzw. auf den eigenen Modulnamen beschränken — Frage an Reviewer, nicht an den
  Nutzer).
- Anzeige für Admins: das Panel löst `tmc_` über eine **Speicher-Tabelle** auf, die aus den aktuell
  bekannten Clients (`coordinator.data`, DHCP) gebaut wird. Ob diese Tabelle für verschwundene
  Clients gespeichert wird, ist Frage F2.

### 5.4 Zeitbasis und „Zustand zum Zeitpunkt T“

- Store und Schnittstellen in Epoch-Sekunden UTC; das Panel zeigt Ortszeit.
- Uhrsprung: Die Time Machine übernimmt das Muster `on_clock_shift` (`net_engine.py:314`): ein
  Sprung über 300 s erzeugt eine Marke `clock_shift`, Marken werden nicht umgeschrieben.
- **Kontrollpunkt**: einmal je Ortstag um 00:00 und bei jedem HA-Start ein kompakter Zustand: je Router
  erreichbar/Rolle/Uplink/Kanäle je Radio/WAN an, letzte bekannte `bkp_…`, offene Vorfälle (nur
  IDs), Zahl der Clients je AP. Keine Client-Liste.
- Zustand zum Zeitpunkt T = letzter Kontrollpunkt vor T + alle Marken bis T. Clients je AP zum
  Zeitpunkt T kommen aus den Sitzungs-Intervallen, die T überdecken.
- Werte (Traffic, Kanalauslastung) zum Zeitpunkt T liest die Time Machine aus den Stundenbuckets der
  Fachmodule. Dafür fehlt dort ein Fenster mit festem Anfang und Ende (3.1). Vorschlag: je Modul
  eine zusätzliche Lesefunktion `window_at(start, end)` (kleine Änderung in `traffic_correlate.py`
  und `rf_center.py`, Phase D).

### 5.5 Aufbewahrung und harte Obergrenzen (Vorschlag, Frage F1)

| Grenze | Wert | Verhalten bei Überlauf |
|---|---|---|
| Aufbewahrung | 14 Tage (wählbar 7 / 14 / 30) | älter wird beim Aufräumen (alle 300 s) entfernt |
| Marken gesamt | 15 000 | ältester Eintrag **derselben Quote** weicht, gezählt |
| Quote Clients | 10 000 | Client-Marken verdrängen nie Infrastruktur oder Konfiguration (Lehre aus Security Center 1.49.3) |
| Quote Infrastruktur + Funk + Topologie | 3 000 | eigene Quote |
| Quote Konfiguration + Störung (Verweise) | 2 000 | eigene Quote |
| Marken je Client und Tag | 200 | weitere werden zu einer Sammelmarke `client_flapping` mit Zähler |
| Kontrollpunkte | 31 + 16 HA-Starts | ältester weicht |
| Store-Datei | 2,5 MB | Schreiben kürzt in **einem** Durchgang (Lehre aus Traffic 1.49.3); ist der erste Schreibvorgang zu groß, bleibt der gespeicherte Stand erhalten |
| Antwort einer Abfrage | höchstens 500 Marken, Zeitraum höchstens 31 Tage | `truncated: true` im Ergebnis |

Jede Grenze bekommt einen Test, der sie überschreitet und das Zählen prüft.

### 5.6 Speicherschätzung (Annahme)

Sieben Router, rund 60 Clients, je Client im Mittel 10 Sitzungsabschnitte am Tag (Roaming, Schlaf
der Handys): 600 Client-Marken am Tag, 8 400 in 14 Tagen. Infrastruktur und Funk geschätzt 50 am
Tag. Mit spaltenweiser Kodierung wie im Traffic-Store (`traffic_history.py:31-38`) rund 60–100 Byte
je Marke: 0,6–1 MB, mit Kontrollpunkten unter 1,5 MB. Prüfweg: in Phase C eine Woche lang Zähler
in den Diagnosedaten beobachten.

### 5.7 Defekter Store, Neustart-Lücken, Abschalten

- Store `openwrt_router.time_machine`, Version 1 mit Migrationsfunktion ab Tag 1 (Muster
  `core_store`). Unlesbar: Kopie nach `.bak`, leer starten, Marke `tm_store_recovered`, Zähler in
  den Diagnosedaten. Eine kaputte Marke wird übersprungen und gezählt, nie die ganze Datei.
- HA-Neustart: gespeichert wird `saved_at`; beim Start entsteht eine Marke `ha_gap` von `saved_at`
  bis jetzt. Offene Sitzungen und Ausfälle werden am Lückenbeginn **als „Ende unbekannt“**
  geschlossen, nie als Abbruch gezählt.
- Router liefert keine Daten (Poll-Fehler unter der Ausfallschwelle): `observation_gap`, kein
  `router_down`.
- Ausschalten: kein Listener, kein Schreiben, keine Route mit Daten (Antwort „aus“). Vorhandene
  Daten bleiben bis zum Ablauf, außer der Nutzer löscht sie (Knopf „Verlauf löschen“, admin-only,
  auditpflichtig).

## 6. Datenschutz und Rechte

Die Zeitleiste verknüpft, wann ein Gerät wo war, über Tage. Das ist ein Bewegungsprofil von Personen
im Haushalt und heikler als jedes Einzelmodul. Vorschläge:

1. **Standard aus**, je Integration ein Schalter; Client-Verläufe zusätzlich ein eigener Schalter,
   ebenfalls aus (Frage F3). Ohne Client-Schalter gibt es nur Infrastruktur, Konfiguration und
   Störungen.
2. **Nur Admins sehen Client-Marken.** Nicht-Admins (nur wenn das Panel für alle geöffnet ist,
   `topology_panel.py:118-120`) sehen Infrastruktur-, Konfigurations- und Störungsmarken ohne
   Client-Bezug; Client-Marken werden für sie weggelassen, nicht nur maskiert (Frage F4).
3. **Store ohne Klartext**: nur `tmc_`-Pseudonyme (5.3). Klarnamen entstehen nur in der Antwort an
   einen Admin.
4. **Konfigurations-Diffs**: die Time Machine zeigt nur Bereich, Risiko und Zahl der Änderungen und
   verlinkt auf den Diff des Configuration Managers, der admin-only ist und Geheimnisse als Marker
   zeigt (`config_views.py:402-417`). Keine Geheimnisse in der Time Machine (Frage F5).
5. **Client vergessen**: Dienst `openwrt_router.time_machine_forget_client` (admin, Eingabe MAC):
   löscht alle Marken des Pseudonyms, schreibt `time_machine.client_forgotten` ins Audit (ohne MAC)
   und ruft, wo vorhanden, das Vergessen der anderen Module auf (Client Stability `forget`,
   `client_history.py:943`). Für Security Center, Traffic und Recorder gibt es das heute nicht
   (3.2 Punkt 6); der Dienst meldet das im Ergebnis ehrlich als „nicht gelöscht in: …“.
6. **Export**: admin-only, JSON eines Zeitraums, Clients nur als `tmc_`, Audit-Eintrag im
   Sicherheitsring (`time_machine.exported`, auditpflichtig). Kein CSV mit Klarnamen.
7. **Diagnosedaten** der Integration: nur Zähler und Grenzen, keine Marken.
8. **Keine neuen HA-Ereignisse mit Client-Bezug** (sie landen mit Klartext im Recorder, wie heute
   schon `openwrt_router_wifi_event`, `coordinator.py:1746-1761`).

## 7. Router-Last

Ziel: **null zusätzliche Router-Aufrufe, keine neuen Router-Rechte**, in allen Phasen.

- Alle Marken entstehen aus `coordinator.data`, aus Listenern im Prozess (Ausfall-Tracker,
  Core-Abo `subscribe`, Network Intelligence, Client Stability) und aus den Stores der Module.
- `config_fingerprint_changed` nutzt die reine Funktion `fingerprint_from_coordinator`
  (`config_snapshot.py:816-828`, „no extra router call“).
- Die Time Machine ruft **nie** `async_compare` mit `ConfigRef.live` auf (das würde den Router lesen,
  `config_api.py:1377-1381`), sondern nur Version gegen Version, und auch das erst auf Klick des
  Admins.
- Abnahme je Phase: Test, der die vollständige Router-Aufrufliste eines Polls mit Time Machine an und
  aus mit der von **v1.49.3** vergleicht (Muster `tests/test_api_iwinfo_device.py:192`).

## 8. Oberfläche

Ein Enterprise-Untertab **„Zeitreise“** (`registerEnterpriseTab`, `frontend/topology/src/enterprise/registry.ts`),
nur sichtbar, wenn das Backend die Time Machine meldet.

| Ansicht | Inhalt | 360 px |
|---|---|---|
| **Zeitleiste** | Liste neuester zuerst, gruppiert nach Stunde; Filter Zeitraum (Schnellwahl 1 h / 24 h / 7 d / frei), Router, Art, Schwere, Quelle, Client (Admin); Dichteleiste oben (Marken je Stunde, Lücken grau schraffiert) | Filter in einem aufklappbaren Block; jede Marke eine Karte mit Zeit, Symbol, einem Satz; Dichteleiste horizontal scrollbar nur in ihrem Rahmen |
| **Zustand zum Zeitpunkt** | Zeitpunkt wählen (Datum/Uhrzeit, ±15 min Knöpfe); Router-Tabelle (erreichbar, Rolle, Uplink, Kanäle, WAN, Clients), offene Vorfälle, letzte Konfigurationsversion je Router, Stundenwerte Traffic/Auslastung; Hinweis „abgeleitet aus Kontrollpunkt von … und N Marken“ | Router-Tabelle wird zu Karten (Container-Query wie Configuration Manager) |
| **Vergleich** | Zwei Zeitpunkte; nur Unterschiede: Router, Uplinks, Kanäle, Konfigurationsversionen dazwischen (Link „Diff ansehen“ in den Configuration Manager), Vorfälle geöffnet/geschlossen, Clients je AP ±N | untereinander statt nebeneinander |
| **Verlauf Router** | Spur je Router: Ausfälle, Neustarts, Kanal, Konfiguration, Befunde; Tageswerte | Spuren untereinander |
| **Verlauf Client** (admin) | Sitzungsbalken je AP, Roaming, Abbrüche mit Grund, daneben Vorfälle des jeweiligen AP | Balken werden zur Liste von Sitzungen |

Verknüpfungen: Jede Marke mit `ref` bekommt „In <Fach-Tab> öffnen“. Dafür fehlt in den Fach-Tabs eine
Sprungadresse (3.2 Punkt 7); Phase F baut sie minimal (Tab + Objekt-ID als URL-Parameter). Von der
Topologie aus: im Router-Detail ein Link „Verlauf dieses Routers“. Eine Topologie-Ansicht „wie zum
Zeitpunkt T“ ist **nicht** Teil dieses Pakets (Nicht-Ziel, kann später auf den Kontrollpunkten
aufsetzen). Ehrlichkeit in der Oberfläche: Bereiche ohne Daten (Modul aus, vor der Aufbewahrung,
HA aus) werden als Lücke gezeigt, nie als „nichts passiert“.

## 9. Phasenplan

| Phase | Ziel | Betroffene Dateien (neu / geändert) | Abnahmekriterium | Aufwand | Danach lauffähig |
|---|---|---|---|---|---|
| **A** Leseschicht | Gemeinsame Zeitleiste aus vorhandenen Quellen, ohne eigenen Store | neu `tm_sources.py` (Adapter je Quelle, Umrechnung `entry_id`→`router_id`, Zeitformat), `tm_query.py`, `tm_views.py` (Route `/api/openwrt_router/enterprise/timemachine/timeline`), Panel `enterprise/timemachine/`; geändert `__init__.py` (markierter Block), `const.py` (Optionen), `config_flow.py` (Schalter), `topology_panel.py` (Panel-Version) | Zeitleiste zeigt Audit, Versionen, NI-Ereignisse und -Vorfälle, Security-Zeitleiste mit Filtern; Ausfall einer Quelle erscheint als „Quelle nicht lesbar“; aus = keine Route-Daten, kein Listener; Aufrufliste = 1.49.3 | M | Tab „Zeitreise“ mit Zeitleiste (Ansicht 1) |
| **B** Eigener Index | Marken für Ausfälle, HA-Lücken, Kanal/DFS, Uplink, Fingerabdruck, Verweis-Marken für Störungen und Konfiguration; Kontrollpunkte | neu `tm_store.py`, `tm_marks.py`, `tm_engine.py` (Listener, `@callback`); `tm_sources.py` liest zusätzlich den Index | Grenzen aus 5.5 mit Tests; Neustart erzeugt `ha_gap`; defekter Store → `.bak`; ein Audit-Eintrag, der aus dem Ring fällt, bleibt als Verweis-Marke sichtbar | M–L | Zeitleiste über Neustarts hinweg; Verlauf Router (Ansicht 4) |
| **C** Client-Sitzungen | Sitzungen je Client und AP über 24 h hinaus; Rechte und Vergessen | `tm_clients.py` (aus Client-Stability-Übergängen und NI-Ereignissen), Dienst in `services.yaml`, `strings.json`, Übersetzungen | Standard aus; Nicht-Admin sieht keine Client-Marke (Test je Route); Vergessen löscht alle Marken des Pseudonyms und nennt nicht gelöschte Module; kein Klartext im Store (Test liest die Datei) | L | Verlauf Client (Ansicht 5) |
| **D** Zustand und Vergleich | „Zustand zum Zeitpunkt T“ und Vergleich zweier Zeitpunkte | `tm_state.py`; kleine Lesefunktion `window_at` in `traffic_correlate.py` und `rf_center.py` | Rekonstruktion gegen aufgezeichnete Testläufe (bekannter Zustand zu bekannten Zeiten) stimmt; abgeleitete Werte als „abgeleitet“ gekennzeichnet | M–L | Ansichten 2 und 3 |
| **E** Modulübergreifende Clients, Export | Client-Marken der Module (Security, Traffic, RF) demselben Client zuordnen; Export | je Modul eine Funktion „Pseudonym für MAC“ (nur im Prozess); `tm_export.py` | Kein Abgleich über `cli_`-Werte (Test mit zwei Modulen, gleiche MAC, verschiedene Werte); Export auditpflichtig, ohne Klarnamen | M | Client-Verlauf mit Security-/Traffic-Bezug; Export |
| **F** Sprünge und Abschluss | Sprungadressen in die Fach-Tabs, Link aus der Topologie; Doku, CHANGELOG | Panel `main.tsx`, Fach-Tab-Einstiege; README, CHANGELOG, `docs/dev/` | Browser-Prüfung 360/768/1280 px, hell/dunkel; unabhängige Prüfung vor dem Merge | M | Gesamtpaket |

Empfohlene Auslieferung: A als eigenes Release (früh nützlich, kein Speicher, kein Risiko), B+C als
zweites, D–F als drittes (Frage F8).

## 10. Qualitätsregeln für dieses Paket

Abgeleitet aus CHANGELOG 1.47.1, 1.49.2, 1.49.3:

1. **Standard aus, und „aus bleibt aus“.** Aus = kein Listener, kein Store-Schreiben, keine
   Hintergrundaufgabe, Routen antworten „aus“. Test zählt Listener und Schreibvorgänge bei „aus“.
2. **Aufrufliste gegen den vorherigen Release-Stand.** Ein Test vergleicht die vollständige
   Router-Aufrufliste eines Polls mit Time Machine an und aus mit der von v1.49.3 — nicht nur „an“
   gegen „aus“ (Fehler 1.48.0, CHANGELOG 1.49.2), gegen ein Router-Modell, das die echten
   Ablehnungen nachbildet.
3. **Sicherheitsnetz für unique_ids.** Die Time Machine legt in A–F **keine Entitäten** an (Vorschlag).
   Trotzdem läuft ein Test, der die unique_ids aller vorhandenen Plattformen gegen eine Liste aus
   v1.49.3 prüft (Muster `tests/test_wifi_switch_ids_v1492.py:252`).
4. **Dispatcher- und Listener-Empfänger nur `@callback` oder Coroutine**, nie Lambda; Test durch den
   echten Dispatcher wie `tests/test_diag_dispatcher_thread.py` (Fehler 1.47.1).
5. **Harte Obergrenzen mit Test** für jede Grenze aus 5.5, inklusive „verdrängt nie eine andere
   Quote“ (Fehler Security Center 1.49.3) und „Kürzen in einem Durchgang“ (Traffic 1.49.3).
6. **Unabhängige Prüfung vor jedem Merge**, nicht danach: eine Sitzung, die den Code nicht
   geschrieben hat, prüft Diff, Tests und diesen Plan; Befunde werden vor dem Merge behoben.
7. **Nach jedem Release Kontrolle der Entity-Registry** in der echten Instanz: keine neuen, keine
   verschwundenen Einträge, keine `_2`-Dubletten.
8. **Browser-Prüfung bei 360 / 768 / 1280 px**, helles und dunkles HA-Design, vor dem Release; kein
   seitliches Scrollen der Seite, Untertabs 40 px hoch.
9. **Panel-Version nie wiederverwenden**; jedes neu gebaute Bundle bekommt eine neue
   `_PANEL_VERSION` (`topology_panel.py:73`).
10. **Keine Klartext-Identitäten im eigenen Store**, Test liest die gespeicherte Datei.
11. **Eine fehlende oder kaputte Quelle ist sichtbar**, nie „keine Ereignisse“.

## 11. Risiken

| Nr. | Risiko | Gegenmaßnahme |
|---|---|---|
| R1 | Bewegungsprofil von Haushaltsmitgliedern | Standard aus, eigener Client-Schalter, admin-only, Pseudonyme im Store, Vergessen-Dienst, kurze Aufbewahrung (6) |
| R2 | Falsche Verknüpfung über gleich aussehende `cli_`-Werte verschiedener Module | eigenes Präfix `tmc_`; Verknüpfung nur über Lesefunktion der Module (Phase E); Test |
| R3 | Zeitleiste suggeriert Ursache („Änderung um 14:02, Ausfall um 14:05“) | Texte sagen „davor“, nie „wegen“; Ursachen bleiben Network Intelligence vorbehalten |
| R4 | Lücken werden als „nichts passiert“ gelesen | Lückenmarken, Dichteleiste mit grauen Bereichen, Hinweis je Quelle „aus / nicht geladen / nur bis …“ |
| R5 | Abfrage über alle Quellen blockiert die Event-Loop | Höchstwerte je Quelle und Abfrage (500), Zeitraum höchstens 31 Tage, Messung im Leistungstest (Muster `tests/test_traffic_performance.py`) |
| R6 | Store wächst bei vielen Clients oder Flattern | Quoten, Sammelmarke `client_flapping`, Byte-Grenze (5.5) |
| R7 | Änderungen an fremden Modulen (Phase D, E) brechen deren Verhalten | nur additive Lesefunktionen, deren Tests unverändert grün; keine Änderung an Speicherformaten der Module |
| R8 | Audit-Ring „general“ verdrängt Ereignisse, bevor die TM sie als Marke hat | TM abonniert `subscribe` und legt Verweis-Marken sofort an (Phase B); Quote je Modul im Audit ist **nicht** Teil dieses Pakets (Frage F7) |
| R9 | Zwei Sitzungen ändern gleichzeitig `__init__.py`, `const.py`, Panel | Phasen nacheinander, je Phase ein Branch, markierte Blöcke wie im Traffic-Paket |

## 12. Offene Fragen an den Nutzer

| Nr. | Frage | Möglichkeiten | Empfehlung |
|---|---|---|---|
| F1 | Wie lange soll die Time Machine aufheben? | 7 Tage / **14 Tage** / 30 Tage | 14 Tage (passt zu Security Center und Traffic-Stunden; 30 Tage verdoppelt den Speicher) |
| F2 | Sollen Admins Client-Verläufe mit Hostnamen sehen? | nur Pseudonym / **Hostname, solange der Client bekannt ist** / Hostname immer (Zuordnung wird gespeichert) | Hostname, solange der Client aktuell bekannt ist; verschwundene Clients nur als Pseudonym |
| F3 | Sollen Client-Verläufe überhaupt aufgezeichnet werden? | **ja, eigener Schalter, Standard aus** / ja, an mit der Time Machine / nein, nie | eigener Schalter, Standard aus |
| F4 | Was sehen Nicht-Admins, wenn das Panel für alle offen ist? | **Infrastruktur und Störungen ohne Clients** / nichts (Tab nur für Admins) / alles pseudonymisiert | Infrastruktur und Störungen ohne Clients |
| F5 | Dürfen Konfigurationsänderungen in der Zeitleiste mit Werten erscheinen? | **nur Bereich und Anzahl, Link zum Diff** / Werte ohne Geheimnisse inline / gar nicht | nur Bereich und Anzahl; der Diff bleibt im Configuration Manager (admin-only, Geheimnisse maskiert) |
| F6 | Soll die Time Machine zusätzlich HA-Logbuch-Ereignisse erzeugen? | **nein** / nur Infrastruktur-Marken / alle Marken | nein; der Recorder hat die Ereignisse der Module schon |
| F7 | Soll im selben Paket der Audit-Ring „general“ eine Quote je Modul bekommen? | ja, in Phase B / **eigener kleiner Fix vorab** / nein | eigener kleiner Fix vor Phase B; das Problem besteht unabhängig von der Time Machine |
| F8 | Welche Variante aus Abschnitt 4? | (a) nur Leseschicht / **(b) Index mit Verweisen** / (c) Schnappschüsse | (b), gebaut als A → B |
| F9 | In welchen Releases ausliefern? | **A allein, dann B+C, dann D–F** / alles in einem Release / A+B, dann C–F | A allein, dann B+C, dann D–F |
| F10 | Soll „Client vergessen“ auch in Security Center und Traffic löschen? | **ja, als eigenes Folgepaket** / ja, in Phase C / nein | eigenes Folgepaket; Phase C meldet nicht gelöschte Module ehrlich |

## 13. Nicht-Ziele und Abgrenzung

- **Keine neuen Messungen, keine neuen Router-Aufrufe, keine neuen Router-Rechte.**
- **Keine neue Ursachenanalyse.** Ursachen, Belegketten und Vorfälle bleiben in Network Intelligence
  und Netzwerkdiagnose; die Time Machine verlinkt.
- **Keine Konfigurationssicherung und kein Wiederherstellen** aus der Zeitleiste; das bleibt der
  Configuration Manager mit seiner Freigabe.
- **Keine Kopie von Messreihen.** Traffic- und RF-Werte werden aus deren Stores gelesen.
- **Kein Ersatz für den HA-Verlauf**; Entitätszustände bleiben im Recorder, keine neuen Entitäten.
- **Keine Topologie-Ansicht „zum Zeitpunkt T“** in diesem Paket (später auf Kontrollpunkten möglich).
- **Keine Flow- oder Paketarchive**, keine Stufe-B-Collector-Erweiterung.
- **Keine Benachrichtigungen** aus der Time Machine.

## 14. Was nicht geklärt werden konnte

- Tatsächliche Größe der vorhandenen Stores und Zahl der Clients in der echten Instanz (kein Zugriff
  auf Home Assistant in dieser Sitzung); die Speicherschätzung 5.6 ist eine Annahme.
- `purge_keep_days` des Recorders in der Instanz (Annahme: HA-Standard 10 Tage).
- Ob `subject.mac` bei allen Client-bezogenen NI-Ereignissen gesetzt ist (nur für Logzeilen gesehen,
  `net_engine.py:1645-1653`).
- Ob die abweichende Reihenfolge von `api.events` (Docstring „newest first“, Rückgabe aufsteigend)
  Aufrufer heute schon falsch bedient; gehört in eine Prüfung, nicht in dieses Paket.
- Ob Network Intelligence abschaltbar ist (kein Schalter gefunden).

---

## 15. Entscheidungen des Nutzers (2026-11-21)

Der Plan ist freigegeben. Entschieden im Gespräch:

| Nr. | Entscheidung |
|---|---|
| F1 | Aufbewahrung **14 Tage**. |
| F2 | Admins sehen den **Hostnamen, solange der Client aktuell bekannt ist**; gespeichert wird nur das Pseudonym. |
| F3 | Client-Verläufe: **eigener Schalter, Standard aus**. |
| F9 | Auslieferung in **drei Releases**: A allein, dann B+C, dann D–F. Vor jedem Merge eine unabhängige Prüfung. |

Ohne Widerspruch nach Empfehlung übernommen: F4 (Nicht-Admins: Infrastruktur und Störungen ohne
Clients), F5 (Konfigurationsänderungen nur mit Bereich und Anzahl, Link zum Diff), F6 (keine
zusätzlichen Logbuch-Ereignisse), F7 (Quote je Modul im Audit-Ring als eigener kleiner Fix vorab),
F8 (Variante b, gebaut als A → B), F10 („Client vergessen“ über alle Module als eigenes Folgepaket).
