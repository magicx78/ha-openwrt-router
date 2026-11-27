# Network Time Machine (Phase A ab 1.50.0; Phasen B und C ab 1.51.0: eigener Verlauf und Client-Sessions; Phasen D bis F im Backend: Zustand, Vergleich, Export, Sprungziele)

<!-- Entwicklerdoku zu Phase A (1.50.0) und den Phasen B/C (1.51.0,
     Branch feature/time-machine-b; Abschnitte 15–19, additiv in den Abschnitten davor). Phasen B/C sind am Code von
     tm_marks.py, tm_store.py, tm_engine.py, tm_clients.py gelesen und mit
     tests/test_tm_index_v1510.py, test_tm_clients_v1510.py, test_tm_query_v1510.py geprüft
     (Mocks, FakeDisks, ein Test schreibt eine echte Datei mit HAs Store); nicht auf Routern,
     nicht in einer HA-Instanz; der Tab von 1.51.0 nur mit node-Tests, nicht im Browser. Keine IPs, MACs,
     Hostnamen echter Geräte, Passwörter oder Tokens; Router-Kennungen im Beispiel sind
     Platzhalter. Aussagen sind am Code gelesen (tm_sources.py, tm_query.py, tm_views.py,
     config_flow.py, diagnostics.py, frontend/topology/src/enterprise/timemachine/) und mit den
     Tests tests/test_tm_*.py und timemachine/*.test.mjs geprüft, nicht an Geräten oder in einer
     HA-Instanz ausgeführt; den Tab hat nur die Prüfung vor dem Merge headless im Browser
     angesehen (Abschnitt 14). Messwerte aus
     tests/test_tm_views.py::test_response_time_with_filled_sources auf der Entwicklungs-VM
     (Python 3.13, Mocks), Stand 2026-11-21. Plan: docs/plans/2026-11-21-network-time-machine.md. -->

## Inhalt

1. [Was Phase A tut und was nicht](#1-was-phase-a-tut-und-was-nicht)
2. [Einschalten](#2-einschalten)
3. [Quellen](#3-quellen)
4. [Route und Abfrage](#4-route-und-abfrage)
5. [Antwortformat](#5-antwortformat)
6. [Arten, Gruppen, Schweregrade, Zustände](#6-arten-gruppen-schweregrade-zustände)
7. [Rechte](#7-rechte)
8. [Blättern](#8-blättern)
9. [Fehler](#9-fehler)
10. [Datenschutz](#10-datenschutz)
11. [Diagnosedaten](#11-diagnosedaten)
12. [Leistung](#12-leistung)
13. [Bekannte Grenzen und was nicht geprüft ist](#13-bekannte-grenzen-und-was-nicht-geprüft-ist)
14. [Tab „Zeitreise“](#14-tab-zeitreise)
15. [Phase B: eigener Verlauf](#15-phase-b-eigener-verlauf)
16. [Phase C: Client-Sessions](#16-phase-c-client-sessions)
17. [Doppelte zwischen Quellen](#17-doppelte-zwischen-quellen)
18. [Aktionen](#18-aktionen)
19. [Panel für B/C (1.51.0)](#19-panel-für-bc-1510)
20. [Phase D: Zustand zum Zeitpunkt](#20-phase-d-zustand-zum-zeitpunkt)
21. [Phase D: Vergleich zweier Zeitpunkte](#21-phase-d-vergleich-zweier-zeitpunkte)
22. [Phase E: Clients über Module, Export](#22-phase-e-clients-über-module-export)
23. [Phase F: Sprungziele](#23-phase-f-sprungziele)
24. [Speicher 1.2, Leistung, Grenzen (D bis F)](#24-speicher-12-leistung-grenzen-d-bis-f)

---

## 1. Was Phase A tut und was nicht

Die Time Machine legt die Ereignisse der vorhandenen Module auf **eine Zeitachse**: Audit-Log
des Enterprise Core, Konfigurationsversionen, Ereignisse und Vorfälle von Network Intelligence
und die Zeitleiste des Security Center. Phase A ist eine reine **Leseschicht**: Bei jeder
Anfrage liest sie die Quellen über deren öffentliche Lesefunktionen, rechnet sie in Marken um,
filtert, sortiert und gibt eine Seite zurück.

Phase A hat

- **keinen eigenen Speicher** (kein Store, keine Datei, nur Zähler im Arbeitsspeicher),
- **keine zusätzlichen Router-Aufrufe** und keine neuen Router-Rechte,
- **keinen Listener, keinen Timer, keine Hintergrundaufgabe**, keine HA-Ereignisse,
- **keine Entitäten**; das Panel zeigt die Zeitleiste im Enterprise-Tab „Zeitreise“ (Abschnitt 14),
- **keine Client-Marken**: Ereignisse, die einen einzelnen Client betreffen, werden weggelassen
  und nur gezählt (`omitted_client_marks`, nur für Administratoren; für andere Benutzer 0).

Ausfälle, Kanalwechsel und Uplink-Wechsel, die die Time Machine selbst aus `coordinator.data`
erkennt, bringt Phase B mit einem **eigenen Speicher**, Client-Sessions bringt Phase C hinter
einem **eigenen Schalter** (Abschnitte 15–19). Die Aussagen oben gelten weiter für die fünf
Phase-A-Quellen; ist die Time Machine aus, gilt der ganze Abschnitt unverändert (kein Store,
kein Listener, keine Aufgabe, kein Router-Aufruf, keine Entität; Test
`test_off_by_default_nothing_is_created`).

## 2. Einschalten

In den Optionen eines beliebigen Routers: **„Network Time Machine für alle Router“**
(`time_machine_enabled`), Standard **aus**. Es ist **ein Schalter für die ganze Flotte**:

- Beim Speichern schreibt der Dialog denselben Wert in die Optionen **aller** Router-Einträge
  der Integration; deren übrige Optionen bleiben unverändert. Es wird nichts neu geladen.
- Eingeschaltet gilt die Time Machine, sobald **ein** Eintrag `true` hat; der Dialog zeigt
  diesen Flottenstand als Vorgabe.
- Warum in den Eintragsoptionen und nicht in einem eigenen Store wie Diagnose oder Security
  Center: Phase A darf keinen eigenen Speicher anlegen; die Eintragsoptionen sind der einzige
  dauerhafte Ort ohne neuen Store (wie „Panel für alle Benutzer“ und Traffic).

Ausgeschaltet antwortet die Route mit `status: "off"` und liest **keine** Quelle.

Seit Phase B startet das Einschalten den eigenen Verlauf sofort (ohne Neuladen), das Ausschalten
beendet ihn, schreibt ihn ein letztes Mal und **löscht dabei die Client-Marken**
(Abschnitt 15.6). Der zweite Schalter **„Client-Verläufe in der Time Machine“**
(`time_machine_clients`, Standard **aus**) arbeitet genauso flottenweit (Abschnitt 16.1).

## 3. Quellen

| `id` | liest | Lesegrenze je Anfrage (Speicher fasst) | Admin-only | Hinweise |
|---|---|---|---|---|
| `core_audit` | Audit-Log beider Ringe (`general`, `security`) über `ConfigurationApi.events(since, ring, limit)` | 1001 je Ring (1000 / 500) | ja | `events` kennt kein `until`; jeder Ring wird ganz gelesen und vom Adapter auf das Fenster zugeschnitten |
| `config_versions` | Konfigurationsversionen über `ConfigurationApi.async_list_backups(since, limit)` | 500 (unbegrenzt) | ja | `off/module_off`, wenn kein Router die Konfigurationssicherung eingeschaltet hat; kein `until` (Abschnitt 13) |
| `ni_events` | Ereignisse von Network Intelligence über `net_query.events_page` | 3001 (3000) | nein | Ereignis-ID trägt die `entry_id` und wird nicht ausgegeben |
| `ni_incidents` | Vorfälle von Network Intelligence über `net_query.incidents_page` | Zahl der gespeicherten Vorfälle + 1, mindestens 501 (500 behobene; aktive und bestätigte werden nie gekürzt, der Speicher kann mehr halten) | nein | je Vorfall bis zu drei Marken: eröffnet, wieder eröffnet, behoben; `incidents_page` sortiert nach Status und Schwere ohne Zeitfilter, deshalb liest der Adapter alle Vorfälle und filtert selbst nach Zeit |
| `security_timeline` | Zeitleiste des Security Center über `overview(actor=None, …)` (die maskierte Sicht) | 2001 (2000) | nein | `off/module_off`, wenn das Security Center aus ist |
| `tm_index` | eigener Verlauf (Phase B): Ausfälle, Lücken, Funk, Topologie, Konfigurations-Fingerabdruck, eigene Marken | ganz (höchstens 15000 Marken) | nein (Gruppen wie unten) | `unreadable/not_running`, wenn die Time Machine eingeschaltet ist, aber noch kein Router geladen hat; nie gekürzt |
| `tm_refs` | Verweise auf Audit-Einträge (Phase B, Abschnitt 15.3) | ganz | ja | erscheint nur, wenn der Audit-Eintrag selbst nicht mehr gelesen wird (Abschnitt 17) |
| `tm_clients` | Client-Marken (Phase C) | ganz | ja | `off/clients_off`, solange der Client-Schalter aus ist |

Bis auf die Konfigurationsversionen liegt jede Lesegrenze über dem, was der Speicher der
Quelle fasst (bei den Vorfällen an die tatsächliche Zahl gebunden, Test
`test_more_active_incidents_than_the_cap_are_read_whole`): Eine Lesung ist vollständig, Client-Einträge oder ein anderer Ring können sie
nicht aufbrauchen. Erreicht eine Lesung ihre Grenze doch, ist die Quelle gekürzt
(Abschnitt 8).

Jede Quelle hat ein **Zeitbudget von 2 s**: eine `asyncio`-Frist um ihre `await`s und eine
Frist, die in den Schleifen des Adapters geprüft wird. Die synchronen Lesefunktionen der
Quellmodule (`events`, `events_page`, `incidents_page`, `overview`) werden dabei **nicht
unterbrochen**; überschreitet eine Quelle die Frist, merkt der Adapter das erst danach in
seiner Schleife und meldet `unreadable/timeout`. Rechte, Filter und die Seitengröße wendet die
Zusammenführung an, nicht die Quelle. Die Quellen werden nacheinander gelesen, zwischen ihnen
gibt die Route die Ereignisschleife frei.

**Zeitraster:** `ts` einer Marke ist der Zeitpunkt der Quelle, auf die Millisekunde
**abgerundet**. Die Fensterprüfung nutzt diesen Wert, und `from`/`until` der Anfrage werden auf
die Millisekunde **aufgerundet**; so liegt jede Marke in genau einem Seitenfenster.

Interne Zustände der Quellmodule (`core.loaded`, `core.closed`, `core.registry`,
`engine.loaded`, `center.enabled`) liest nur `tm_sources.py`; ein Vertragstest hält diese
Namen fest.

## 4. Route und Abfrage

```
GET /api/openwrt_router/enterprise/timemachine/timeline
```

Nur `GET`, Anmeldung nötig, kein Body. Jeder Abfrage-Schlüssel höchstens einmal, Werte
höchstens 96 Zeichen, unbekannte Schlüssel werden abgelehnt.

| Parameter | Format | Standard | Bedeutung |
|---|---|---|---|
| `from` | Epoch-Sekunden (bis 6 Nachkommastellen; auf die Millisekunde aufgerundet) | `until` − 24 h | Fensteranfang, eingeschlossen |
| `until` | Epoch-Sekunden | jetzt (nächste volle Sekunde) | Fensterende, **ausgeschlossen** |
| `source` | Komma-Liste der Quellen-IDs aus Abschnitt 3 (seit Phase B auch `tm_index`, `tm_refs`, `tm_clients`) | alle acht | jede ID höchstens einmal |
| `router_id` | `rtr_` + 32 hex | – | nur Marken genau dieses Routers (Flotten-Marken nicht) |
| `kind` | eine Art aus Abschnitt 6 | – | nur diese Art |
| `min_severity` | `info` / `warning` / `critical` | – | ab diesem Schweregrad |
| `limit` | 1 … 500 | 200 | Marken je Seite |
| `cursor` | `<ms>` oder `<ms>:<id>` (`ms`: Epoch-Millisekunden, `id`: `tmm_` + 16 hex) | – | seit 1.51.0: wo die Seite beginnt, aus `next_cursor` der vorigen Seite; nur mit demselben `from`/`until`; muss im Fenster liegen, sonst `out_of_range` (Abschnitt 8) |
| `spans` | `0` / `1` | `0` | seit 1.51.0: `1` liefert die Intervalle, die vor `from` begannen und ins Fenster reichen, im eigenen Feld `spanning` (Abschnitt 8) |

Das Fenster ist halboffen `[from, until)`, höchstens **14 Tage** lang und darf nicht leer sein.

## 5. Antwortformat

```json
{
  "v": 1,
  "status": "ok",
  "generated_at": 1795280722.78,
  "window": {"from": 1794999901.0, "until": 1795089901.0},
  "marks": [
    {
      "id": "tmm_147bf5963cd339c7",
      "ts": 1795003801.0,
      "source": "ni_incidents",
      "kind": "incident_opened",
      "group": "disruption",
      "severity": "critical",
      "router_id": "rtr_00000000000000000000000000000001",
      "router_name": "Router 1",
      "fleet": false,
      "title_key": "ni_incidents.wan_down",
      "text": null,
      "params": {"affected": 0, "occurrences": 3, "reopen_count": 2, "children": 0},
      "ref": {"module": "network_intelligence", "type": "incident", "id": "inc-1", "version_id": null},
      "derived": false
    },
    {
      "id": "tmm_d11287620d5851c9",
      "ts": 1795003801.0,
      "source": "ni_events",
      "kind": "wan_event",
      "group": "infrastructure",
      "severity": "critical",
      "router_id": "rtr_00000000000000000000000000000001",
      "router_name": "Router 1",
      "fleet": false,
      "title_key": "ni_events.wan.down",
      "text": null,
      "params": {},
      "ref": {"module": "network_intelligence", "type": "event", "id": null, "version_id": null},
      "derived": false
    }
  ],
  "sources": [
    {"id": "core_audit", "state": "ok", "reason": null, "count": 0, "oldest": null, "truncated": false, "cut": null},
    {"id": "config_versions", "state": "ok", "reason": null, "count": 0, "oldest": null, "truncated": false, "cut": null},
    {"id": "ni_events", "state": "ok", "reason": null, "count": 1, "oldest": 1795003801.0, "truncated": false, "cut": null},
    {"id": "ni_incidents", "state": "ok", "reason": null, "count": 1, "oldest": 1795003801.0, "truncated": false, "cut": null},
    {"id": "security_timeline", "state": "ok", "reason": null, "count": 0, "oldest": null, "truncated": false, "cut": null}
  ],
  "omitted_client_marks": 1,
  "truncated": true,
  "next_until": 1795003741.0,
  "next_cursor": "1795003741000",
  "spanning": [],
  "spanning_truncated": false
}
```

(gekürzt aus einer Testantwort; Router-Kennung und -Name ersetzt)

### 5.1 Oberste Ebene

| Feld | Bedeutung |
|---|---|
| `v` | Version des Formats, heute `1` |
| `status` | `ok`; `partial`, wenn mindestens eine angefragte Quelle `unreadable` ist; `off`, wenn die Time Machine aus ist |
| `generated_at` | Zeitpunkt der Antwort (Epoch-Sekunden) |
| `window` | das geprüfte Fenster; bei `off` beide `null` |
| `marks` | die Marken dieser Seite, neueste zuerst |
| `sources` | je angefragter Quelle ein Eintrag (Reihenfolge wie Abschnitt 3); bei `off` leer |
| `omitted_client_marks` | Zahl der weggelassenen Client-Ereignisse aller Quellen im Fenster; für Nicht-Admins immer 0 (die Zahl verriete Aktivität in Quellen und Gruppen, die sie nicht sehen) |
| `truncated` | `true`, wenn es ältere Marken im Fenster gibt, die nicht auf dieser Seite stehen |
| `next_until` | `until` der nächsten Seite oder `null` (Abschnitt 8; für Clients vor 1.51.0) |
| `next_cursor` | seit 1.51.0: `cursor` der nächsten Seite oder `null`; mit demselben Fenster zurückschicken (Abschnitt 8) |
| `spanning` | seit 1.51.0: nur mit `spans=1` gefüllt, sonst `[]`: Intervalle, die vor `from` begannen und ins Fenster reichen (`spans_in: true`), neuester Anfang zuerst, höchstens 200, **nicht** auf `limit` angerechnet, gleiche Rechte und Filter wie `marks` |
| `spanning_truncated` | seit 1.51.0: `true`, wenn mehr als 200 solche Intervalle da sind (der Rest fehlt) |

### 5.2 Eintrag in `sources`

| Feld | Bedeutung |
|---|---|
| `id` | Quellen-ID |
| `state` | `ok`, `empty`, `off`, `unreadable` |
| `reason` | fester Grund bei `off` / `unreadable`, sonst `null` (Abschnitt 6.4) |
| `count` | Marken dieser Quelle **auf dieser Seite** |
| `oldest` | Zeitpunkt der ältesten Marke dieser Quelle **auf dieser Seite**; `null` ohne Marken |
| `truncated` | die Lesung der Quelle hat ihre Lesegrenze erreicht |
| `cut` | nur bei `truncated`: `next_page` (ältere Einträge des Fensters kommen mit `next_until`) oder `unreachable` (ältere Einträge des Fensters sind nicht lesbar, Abschnitt 13); sonst `null`. Seit 1.50.0, additiv |
| `duplicates` | seit Phase B, additiv: Marken dieser Quelle, die als Doppel einer anderen Quelle weggelassen wurden (Abschnitt 17), **vor** den Rechten gezählt; nur ein Zähler, keine Zeitpunkte |

`state`, `count` und `oldest` gelten **nach den Rechten**: Ein Nicht-Admin erfährt weder, dass es
Marken gibt, die er nicht sehen darf, noch wann sie liegen.

### 5.3 Eine Marke

| Feld | Bedeutung |
|---|---|
| `id` | `tmm_` + 16 hex, stabil für dasselbe Quell-Ereignis |
| `ts` | Zeitpunkt, Epoch-Sekunden UTC, auf die Millisekunde abgerundet |
| `source` | Quellen-ID |
| `kind`, `group` | Art und Gruppe (Abschnitt 6) |
| `severity` | `info`, `warning`, `critical` |
| `router_id` | `rtr_…` oder `null` (Flotte bzw. ohne Router) |
| `router_name` | Anzeigename des Routers aus dem HA-Eintrag; `null`, wenn der Titel eine IP-Adresse ist, eine MAC-Adresse enthält, leer oder länger als 64 Zeichen ist |
| `fleet` | `true` für Ereignisse der ganzen Flotte (oder mehrerer Router) |
| `title_key` | `<source>.<code>`; Schlüssel für den Text im späteren Panel |
| `text` | nur bei `security_timeline`: der maskierte Text des Security Center, sonst `null` |
| `params` | höchstens 8 Zahlen (z. B. `changes`, `critical_count`, `repeat_count`, `channel`, `occurrences`) |
| `ref` | Verweis in die Quelle: `module`, `type`, `id`, `version_id` (z. B. `bkp_…` bei Versionen und Drift) |
| `derived` | `true`, wenn der Zeitpunkt erschlossen und nicht beobachtet ist (Phase B/C, z. B. Lücke nach unsauberem Ende, Ausfall von vor dem Start); Phase-A-Quellen immer `false` |
| `code` | seit Phase B, an **jeder** Marke: fester Code der eigenen Marke (z. B. `timeout`, `dfs`, `restart`), bei Phase-A-Quellen `null` |
| `end` | Ende eines Intervalls (Epoch-Sekunden) oder `null` (offen bzw. keine Intervall-Art) |
| `end_state` | `open`, `closed`, `unknown` (Ende nicht beobachtet, z. B. HA-Neustart) bzw. `null` bei Punkt-Marken |
| `client` | nur `tm_clients`: Pseudonym `tmc_` + 16 hex, sonst `null` |
| `client_name` | nur `tm_clients`, nur Admins: aktueller Hostname, solange Client-Stabilität den Client kennt, sonst `null`; nie gespeichert |
| `peers` | `{"before": {router_id, router_name} \| null, "after": …}` bei `uplink_changed` (Elternrouter vorher/nachher) und `client_roam` (von/nach), sonst `null` |
| `spans_in` | seit 1.51.0: `true` bei einer Intervall-Marke des eigenen Verlaufs, die **vor** `from` begann und ins Fenster reicht (offen oder mit `end` ≥ `from`); `ts` ist dann ihr Anfang vor dem Fenster. Sonst `false` (auch bei allen Phase-A-Quellen) |

Alle sieben Felder sind **additiv**, `v` bleibt `1`. `title_key` eigener Marken ist
`<source>.<kind>` (z. B. `tm_index.router_down`), der von Verweisen der des Audit-Eintrags
(`core_audit.<type>`).

## 6. Arten, Gruppen, Schweregrade, Zustände

### 6.1 Arten und Gruppen

| Gruppe | Arten (in Phase A erzeugt) | vergeben für später |
|---|---|---|
| `infrastructure` | `router_down`, `router_up`, `lan_down`, `lan_up`, `observation_gap`, `wan_event`, `port_event`, `system_event`; Phase B: `ha_gap` | – |
| `radio` | `channel_changed`, `dfs_event`, `rf_event`; Phase B: `radio_down`, `radio_up` | – |
| `topology` | `uplink_changed`; Phase B: `router_role_changed` | – |
| `configuration` | `config_version`, `config_drift`, `config_event`; Phase B: `config_fingerprint_changed` | – |
| `disruption` | `incident_opened`, `incident_resolved`, `security_incident`, `diag_finding`, `traffic_anomaly`, `net_event` | – |
| `security` | `security_event` | – |
| `administration` | `registry_event`, `core_event`, `audit_event` | – |
| `clients` | Phase C: `client_session`, `client_roam`, `client_disconnect`, `client_flapping` | – |
| `time_machine` | Phase B: `tm_started`, `tm_disabled`, `tm_store_recovered`, `tm_forgot_client`, `tm_cleared`, `clock_shift` | `tm_exported` |

Zuordnung der Quellen:

- `core_audit`: Drift-Typen (`configuration.drift_*`, `configuration.change_critical`,
  `configuration.change_unknown`) → `config_drift`; sonst nach Präfix `wifi_rf.` → `rf_event`,
  `net_diagnostics.` → `diag_finding`, `traffic_analytics.` → `traffic_anomaly`,
  `security_center.` → `security_incident`, `config_manager.` / `configuration.` →
  `config_event`, `router.` → `registry_event`, `security.` → `security_event`, `core.` →
  `core_event`, Rest → `audit_event`.
- `config_versions`: immer `config_version` (Schweregrad `info` bei `ok`, sonst `warning`).
- `ni_events`: `system.router_unreachable/_reachable` → `router_down/_up`,
  `system.lan_unreachable/_reachable` → `lan_down/_up`, `system.log_gap` → `observation_gap`,
  `lan.uplink` → `uplink_changed`, `dfs.new_channel` → `channel_changed`; sonst nach Präfix
  `system.` / `wan.` / `lan.` / `dfs.` / `wifi.` → `system_event` / `wan_event` /
  `port_event` / `dfs_event` / `rf_event`, Rest → `net_event`.
- `ni_incidents`: `incident_opened` (eröffnet und wieder eröffnet), `incident_resolved`.
- `security_timeline`: Vorfall-Einträge → `security_incident`, `drift` → `config_drift`,
  `traffic_indicator` → `traffic_anomaly`, Rest → `security_event`.

### 6.2 Schweregrade

`info` < `warning` < `critical`. Unbekannte Werte der Quellen werden zu `info`.

### 6.3 Zustände einer Quelle

| `state` | Bedeutung |
|---|---|
| `ok` | gelesen, mindestens eine für diesen Benutzer sichtbare Marke im Fenster, **oder** die Lesung wurde gekürzt (`truncated`; eine gekürzte Quelle ist nie `empty`) |
| `empty` | vollständig gelesen, keine für diesen Benutzer sichtbare Marke im Fenster (auch wenn dort nur Client-Ereignisse oder Marken anderer Gruppen lagen) |
| `off` | ausgeschaltet oder für diesen Benutzer nicht sichtbar (kein Fehler) |
| `unreadable` | konnte nicht gelesen werden; die übrigen Quellen werden trotzdem geliefert, `status` ist `partial` |

### 6.4 Gründe (`reason`)

| `reason` | bei | Bedeutung |
|---|---|---|
| `admin_only` | `off` | Quelle nur für Administratoren |
| `module_off` | `off` | Quellmodul ausgeschaltet |
| `not_running` | `unreadable` | Quellmodul nicht eingerichtet |
| `not_loaded` | `unreadable` | eingerichtet, Speicher noch nicht gelesen |
| `timeout` | `unreadable` | Zeitbudget von 2 s überschritten (geprüft in den Schleifen des Adapters, Abschnitt 3) |
| `error` | `unreadable` | die Lesefunktion hat einen Fehler geworfen |
| `bad_format` | `unreadable` | Antwort in unerwarteter Form |
| `clients_off` | `off` | nur `tm_clients`: der Client-Schalter ist aus (seit Phase B, additiv) |

## 7. Rechte

| | Administrator | Nicht-Admin, Panel für alle Benutzer offen | Nicht-Admin, Panel nur für Admins | nicht angemeldet |
|---|---|---|---|---|
| Route | 200 | 200 | 403 | 401 |
| `core_audit`, `config_versions` | ja | `off` / `admin_only` | – | – |
| `ni_events`, `ni_incidents`, `security_timeline` | alle Gruppen | nur `infrastructure`, `radio`, `topology`, `disruption` | – | – |
| Konfigurationsmarken (Bereich, Zahl der Änderungen, `bkp_…`) | ja | nein | – | – |
| Client-Ereignisse der Phase-A-Quellen | nur gezählt | weggelassen, `omitted_client_marks` = 0 | – | – |
| `tm_index` | alle Gruppen | nur `infrastructure`, `radio`, `topology`, `disruption` (keine Konfigurations-Fingerabdrücke, keine eigenen Marken) | – | – |
| `tm_refs`, `tm_clients`, `client_name` | ja | `off` / `admin_only` | – | – |
| Route `…/timemachine/sessions` | 200 | **403** | 403 | 401 |

„Panel für alle Benutzer“ ist die bestehende Option `topology_panel_all_users`. Reihenfolge der
Prüfungen: Anmeldung (401) → Recht (403) → Integration geladen (410) → Body (400) → Abfrage
(400) → Schalter (`off`) → Lesen.

## 8. Blättern

Die Marken sind nach `ts` absteigend und bei gleichem `ts` nach `id` sortiert.

**Mit Cursor (seit 1.51.0, empfohlen).** Jede Antwort mit weiteren Marken nennt
`next_cursor`; die nächste Seite fragt mit `cursor=<next_cursor>` und **demselben** `from` und
`until`. Der Cursor ist eine Stelle in der Sortierung: `<ms>` heißt „alles älter als diese
Millisekunde“, `<ms>:<id>` „in dieser Millisekunde nach dieser `id`, dann älter“. Damit
kommt jede Marke genau einmal, auch wenn **eine Millisekunde mehr Marken als `limit`** hält
(etwa Hunderte Client-Sitzungen, die beim Einschalten zugleich beginnen): die Seite wird
dann in der Millisekunde geteilt und der Cursor trägt die `id`. `next_cursor: null` beendet
den Lauf.

**Ohne Cursor (Clients vor 1.51.0).** Hat eine Seite mehr Marken als `limit`, endet sie vor
dem ältesten Zeitstempel, damit Marken mit **demselben Zeitstempel nie auf zwei Seiten
verteilt** werden; `next_until` ist dann der älteste Zeitstempel der Seite. Die nächste Seite
fragt mit `until=<next_until>` und demselben `from`. Hält eine einzige Millisekunde mehr
Marken als `limit`, kann `next_until` sie nicht teilen: Die Seite zeigt `limit` davon und
`truncated: true`, der Rest dieser Millisekunde ist über `next_until` nicht erreichbar (nur
über `next_cursor`).

Wurde die Lesung einer Quelle gekürzt (`truncated`), ist sie nur oberhalb ihrer **Kante**
vollständig, des ältesten gelesenen Eintrags im Fenster (weggelassene Client-Einträge
eingeschlossen). Die Seite behält dann nur Marken nach der Millisekunde der Kante, und
`next_until` ist die Millisekunde danach (`next_cursor` entsprechend `<ms>` dieser
Millisekunde danach): Die nächste Seite liest die Millisekunde der Kante ganz. Beide stehen
auch dann, wenn die Seite **keine einzige Marke** enthält (etwa weil die gelesenen Einträge nur
Client-Ereignisse waren); die Quelle ist dann nicht `empty`, sondern `ok` mit
`cut: next_page`. Bei mehreren gekürzten Quellen gilt die jüngste Kante. Ist die Millisekunde
der Kante die letzte des Fensters, behält die Seite sie, und was davon nicht gelesen wurde,
fehlt (`truncated: true`).

Liegt `next_until` am oder vor `from`, ist es `null`.

**Intervalle, die ins Fenster reichen (`spans`, 1.51.0).** Eine Intervall-Marke von
`tm_index` oder `tm_clients`, die vor `from` begann und offen ist oder mit `end` ≥ `from`
endet, gehört zum Fenster (Überlappung), steht aber **nie** in `marks`:

- Nur mit `spans=1` kommt sie, im eigenen Feld `spanning` (mit `spans_in: true`), neuester
  Anfang zuerst, höchstens 200 (`spanning_truncated`), nicht auf `limit` angerechnet, mit
  denselben Rechten und Filtern (`router_id`, `kind`, `min_severity`) wie `marks`.
- Ohne `spans` (oder `spans=0`) ist `spanning` immer `[]`. Ein Client fragt `spans=1` auf der
  ersten Seite (und beim Aktualisieren) und blättert danach ohne `spans`: so kommt jede genau
  einmal, gleich auf der ersten Seite, egal wie viele Marken das Fenster hält.
- Ein Client vor 1.51.0 schickt kein `spans` und sieht sie nicht mehr (bis 1.51.0-Entwicklung
  standen sie auf der letzten Seite); `v` bleibt 1.

Tests: `tests/test_tm_overlap_v1510.py`,
`test_s4_an_old_open_outage_comes_with_spans_on_the_first_page`,
`test_s3_250_resumed_sessions_of_one_start_page_without_loss` (beide in
`tests/test_tm_review_v1510.py`).

## 9. Fehler

Fehler haben die Form `{"message", "code", "details": {"field", "reason"}}` und
`Cache-Control: no-store`. Eingaben werden nie zurückgegeben.

| Status | `code` | wann |
|---|---|---|
| 400 | `invalid_request` | unbekannter oder doppelter Schlüssel, zu langer Wert, falsches Format, leeres oder zu großes Fenster, Body vorhanden; `details` nennt Feld und Grund (`unknown_key`, `repeated`, `too_long`, `invalid`, `out_of_range`, `unknown`, `empty`, `too_large`) |
| 401 | – | nicht angemeldet (HA) |
| 403 | `authorization_denied` | kein Admin und Panel nicht für alle offen |
| 410 | `integration_not_loaded` | Integration entladen |
| 413 | `body_too_large` | ein Body über 4 KiB (ein `GET` hat keinen Body; Prüfung des gemeinsamen Body-Lesers) |
| 500 | `internal` | unerwarteter Fehler; im Log steht nur der Fehlertyp |

## 10. Datenschutz

- In Antworten, Logs und Diagnosedaten stehen **keine MAC-Adressen, IP-Adressen, Hostnamen,
  SSIDs oder WLAN-Netdev-Namen**. Router erscheinen als `router_id` und Anzeigename.
- Texte (`text`) kommen nur aus der maskierten Sicht des Security Center und laufen zusätzlich
  durch die Maskierung des Core.
- Die Time Machine holt sich **keinen** Modulschlüssel eines anderen Moduls und verknüpft keine
  `cli_`-Pseudonyme verschiedener Module. Seit Phase C holt sie nur ihren **eigenen**
  Schlüssel (`time_machine` / `pseudonym`), und nur bei eingeschaltetem Client-Schalter oder
  für die Aktion „Client vergessen“; ihr Pseudonym `tmc_…` ist mit keinem anderen Modul
  verknüpfbar.
- Der eigene Speicher (Abschnitt 15) und die Antworten enthalten Clients nur als Pseudonym;
  Hostnamen werden nie gespeichert (Abschnitt 16.3). Test `test_store_holds_pseudonyms_only`
  und `test_real_file_has_no_identifiers_and_the_measured_size` (echte Datei).
- Alle Antworten haben `Cache-Control: no-store`.

## 11. Diagnosedaten

Der Diagnose-Download jedes Routers enthält den Block `time_machine`:

- aus: `{"enabled": false}`; keine Quelle wird gelesen.
- an: `enabled`, `entry_enabled` (Option dieses Eintrags), `api_version`, `window_s` (86400),
  `limits` (Standard- und Höchstfenster, Standard- und Höchstlimit, Zeitbudget; die
  wirkungslose Grenze „Marken einer Quelle je Seite“ ist seit Phase B entfernt), `sources` (je Quelle `state`, `reason`, `count`, `truncated`,
  `omitted_client_marks` der letzten 24 h, gelesen wie ein Admin; die Marken selbst werden
  verworfen) und `counters` (Zahl der Anfragen, `unreadable` je Quelle, Dauer und Markenzahl
  der letzten Anfrage; nur im Arbeitsspeicher).
- Ein Fehler im Block lässt den Download nie scheitern: `{"loaded": false, "error": true}`.
- Seit Phase B zusätzlich: `clients_enabled` (Client-Schalter der Flotte),
  `entry_clients_enabled` (Option dieses Eintrags), in `limits` `retention_s` (1209600),
  `max_marks` (15000), `quotas` und `client_day_cap` (200; `source_mark_cap` entfällt), in
  `sources` auch die drei neuen Quellen, und `index`: die Zähler des eigenen Verlaufs (Marken
  je Kontingent, offene Intervalle, Zahl der Clients, verdrängte, gekürzte, gedeckelte,
  vergessene, gelöschte und kaputte Marken; Bytes der letzten Datei, Grenze, Abdeckung,
  Checkpoints, Schreibzähler; Zähler des Client-Rekorders). Nur Zahlen, keine IDs, keine
  Pseudonyme.

## 12. Leistung

Gemessen mit gefüllten Quellen (Audit 1000 Einträge, 36 Versionen, Security-Center-Zeitleiste
2000 Einträge, Network Intelligence 200 WAN-Wechsel und 150 Client-Ereignisse), Fenster
13 Tage, `limit=500`, jede Quelle ganz gelesen: **51–78 ms** über HTTP, davon **47–74 ms** Lesen
und Zusammenführen (drei Läufe); Antwort **209 KB** mit 498 Marken. Der Test verlangt
großzügig unter 2 s. Gemessen mit Mocks auf der Entwicklungs-VM (Python 3.13), nicht auf einer
HA-Instanz.

Mit vollem eigenem Verlauf (1.51.0, Review K6; 3000 Kanalwechsel, 2000 Verweise, 10000
Client-Sitzungen, sechs Router, Admin, alle drei eigenen Quellen ganz gelesen, je 7 Läufe,
Median): **48 ms** gesamt für eine Zeitleisten-Seite (`limit` 200 oder 500); die längste
Strecke ohne Rückgabe an die Ereignisschleife sank von **28 ms** auf **5 ms**, weil eine
Quelle des eigenen Verlaufs nach je 1000 Marken (`INDEX_YIELD_EVERY`) abgibt
(`test_k6_a_full_client_quota_yields_to_the_event_loop`). Einzelne Läufe erreichen 60 ms in
einem Stück (Speicherbereinigung oder das Sortieren aller Marken in `merge`). Sitzungen
(`limit` 500): Median **3–5 ms**. Nicht umgesetzt: nur die Seite in Wörterbücher wandeln. Das
Entfernen der Doppel, die Rechte, die Filter und der Zustand jeder Quelle (`ok`/`empty` nach
den Rechten) brauchen alle Marken des Fensters; eine vorzeitig abgeschnittene eigene Quelle
würde in jeder Antwort als gekürzt (`cut: next_page`) erscheinen und das Blättern ändern.

## 13. Bekannte Grenzen und was nicht geprüft ist

- Wenn die letzte Millisekunde eines Fensters mehr Einträge einer Quelle hält, als sie in
  einer Lesung liefert, fehlt der Rest (Abschnitt 8); mit den heutigen Lesegrenzen nur bei
  den Konfigurationsversionen denkbar. (Mehr Marken in einer Millisekunde als `limit` gehen
  seit 1.51.0 über `next_cursor` nicht mehr verloren.)
- **Konfigurationsversionen** werden höchstens 500 je Anfrage gelesen, und
  `async_list_backups` kennt kein `until`: Liegen mehr als 500 Versionen zwischen `from` und
  jetzt, sind die älteren im Fenster nicht erreichbar; die Quelle meldet dann
  `truncated: true` mit `cut: unreachable` und ist nie `empty`.
- `truncated` einer Quelle gilt vor den Rechten. Bei den Quellen, die Nicht-Admins sehen, liegt
  die Lesegrenze über der Kapazität des Speichers; das Feld ist für sie daher immer `false`.
- Was die Module nicht behalten, fehlt auch in der Time Machine: Der Ring `general` des
  Audit-Logs hat seit 1.50.0 feste Anteile (Core 400, je Modul 100), verdrängt aber weiterhin
  den ältesten Eintrag eines Besitzers über seinem Anteil (`general_evicted`). Ausfälle und
  Kanalwechsel vor einem HA-Neustart fehlt in Phase A; Phase B hält sie im eigenen Verlauf
  (ab dem Einschalten, nicht rückwirkend).
- Modulschlüssel des Enterprise Core werden nur nach Namen vergeben.
- Drift-Einträge des Audit-Logs tragen keinen Bereich; Bereich und Diff zeigt der
  Configuration Manager.
- Die synchronen Lesefunktionen der Quellmodule werden vom Zeitbudget nicht unterbrochen
  (Abschnitt 3).
- Grenzen der Phasen B/C: Abschnitt 15.7 und 16.6.
- Nicht auf echten Routern und nicht in einer laufenden HA-Instanz geprüft; alle Aussagen
  stammen aus Tests mit Mocks. Den Tab hat die Prüfung vor dem Merge headless in Firefox mit
  der Testantwort angesehen; die danach geänderten Stile (Abschnitt 14: gesperrte Chips,
  Karten ab 860 px, Quellspalte, mittige Chips) sind nur durch Tests geprüft. Den Tab von
  1.51.0 (Abschnitt 14.3) hat die Prüfung vor dem Merge headless in Firefox bei 360, 768 und
  1280 px angesehen; die daraus folgenden Korrekturen (Abschnitt 14.3, „Nach der
  Browser-Prüfung“) sind durch node-Tests geprüft.

## 14. Tab „Zeitreise“

Enterprise-Tab nach Traffic Analytics (`order` 60), Code in
`frontend/topology/src/enterprise/timemachine/`. Er liest nur die Route aus Abschnitt 4 und
fügt der Antwort nichts hinzu; Phase A verlinkt `ref` nicht, es gibt keinen Export und keinen
„Zustand zum Zeitpunkt“.

- **Kopf:** Überschrift, „Aktualisieren“, Einleitung und „Stand TT.MM.JJ, HH:MM“ aus
  `generated_at` in Ortszeit.
- **Filter** (umbrechend): Zeitfenster 1 Stunde / 24 Stunden (Standard) / 7 Tage / 14 Tage;
  Quellen (alle an; eine Quelle mit `off`/`admin_only` ist ausgegraut, „nur für
  Administratoren“, nicht wählbar und wird trotzdem angefragt, damit ihr Zustand sichtbar
  bleibt); Schwere Alle / ab Warnung / nur kritisch; Router („Alle Router“ und die Router der
  geladenen Marken). Diese vier lösen eine neue Anfrage mit `from` und `until` aus; Antworten
  zu alten Filtern werden verworfen. Die Art-Chips filtern nur die geladenen Marken
  („x von y Marken“).
- **Quellen:** je Quelle ein Pill in Worten („12 Marken“, „leer“, „aus · Grund“, „Quelle nicht
  lesbar · Grund“, Zusatz „gekürzt“ bzw. bei `cut: unreachable` „gekürzt, Älteres nicht
  abrufbar“), nie grün. Eine gekürzte Quelle ohne Marke auf der Seite zeigt „0 Marken ·
  gekürzt“, nie „leer“. Bei `partial` steht darüber „Mindestens eine
  Quelle war nicht lesbar; die Zeitleiste ist unvollständig.“
- **Hinweis** bei `omitted_client_marks` > 0 (der Tab prüft die Rolle nicht selbst; er verlässt
  sich darauf, dass der Server Nicht-Admins 0 schickt): „N client-bezogene Ereignisse sind ausgeblendet.
  Client-Verläufe lassen sich in den Optionen einschalten.“ (der zweite Satz seit 1.51.0 nur,
  wenn `tm_clients` `clients_off` meldet; den Satz „… in einer späteren Version“ gibt es nicht
  mehr).
- **Zeitleiste:** neueste zuerst, nach Kalendertag in Ortszeit (Heute, Gestern, „Wochentag,
  TT.MM.JJJJ“), je Marke Uhrzeit (UTC-ISO im `title`), Schwere als Punkt und Wort (Info nie in
  Warnfarbe), Art, Titel, Kennzahlen (nur bekannte Schlüssel), Router („alle Router“ bei
  `fleet`) und Quelle; „abgeleitet“ bei `derived`. Doppelte `id` werden entfernt. „Ältere
  laden“ fragt mit `until=next_until` (seit 1.51.0 mit `cursor=<next_cursor>`, Abschnitt
  14.3); `truncated` ohne `next_until` zeigt „Weitere Marken im
  Zeitfenster wurden gekürzt; Zeitfenster oder Filter enger wählen.“ Eine Seite ohne Marken,
  aber mit `next_until` (der Abschnitt hält nur ausgeblendete Client-Einträge), zeigt „In
  diesem Abschnitt gibt es nur ausgeblendete Einträge. Ältere laden, um weiter
  zurückzugehen.“ und „Ältere laden“, nie „Keine Marken im gewählten Zeitfenster.“
- **Zustände:** aus („Die Zeitreise ist ausgeschaltet.“ mit dem Weg zum Schalter, ohne Filter
  und Liste); lädt (leiser Hinweis, die alte Liste bleibt); 401/403 „Keine Berechtigung für die
  Zeitreise.“; 410 „Die Integration wurde entladen.“; 5xx und Netzwerk „Die Zeitleiste konnte
  nicht geladen werden.“ mit „Erneut versuchen“; 400 „Ungültige Filterkombination.“ mit dem
  Feldnamen, nie mit der Eingabe; leer „Keine Marken im gewählten Zeitfenster.“
- **Abruf:** nur bei sichtbarem Tab und sichtbarer Seite, automatisch höchstens alle 60 s und
  nur die erste Seite; neue Marken kommen nach vorn, geladene ältere Seiten bleiben, auch wenn die
  Aktualisierung antwortet, während „Ältere laden“ läuft. Reicht die neue erste Seite nicht
  bis an die geladene Liste (mehr neue Marken als eine Seite), beginnt die Liste neu und eine
  laufende ältere Seite wird verworfen; eine Lücke in der Mitte entsteht nie. Ist die
  Time Machine aus, nur beim Öffnen und bei „Aktualisieren“.
- **Schmale Breite:** ist die Liste höchstens 860 px breit, wird jede Marke zur Karte
  (Container Query): Zeit, Schwere, Art / Titel / Kennzahlen / Router, Quelle. Die Quellspalte
  der Zeilenansicht ist 11em breit, damit „Netzwerk-Ereignisse“ nicht umbricht. Kein
  seitliches Scrollen bis 360 px; Chips und Knöpfe unter 600 px 40 px hoch wie in den anderen
  Tabs, Chip-Text dort mittig.
- **Gesperrte Chips:** gestrichelter Rand, Text in `--text-muted` (50 % Weiß im Tab) ohne
  Deckkraft-Abschwächung, Zusatz „nur für Administratoren“ in `--text-secondary`; auf dem
  Chip-Hintergrund `#0c1225` 5,29:1 bzw. 6,17:1 (`tmLayout.test.mjs`).

### 14.1 Titel und Rückfall

`tmTexts.ts` hat für jeden `title_key`, den das Backend erzeugen kann, einen deutschen Titel
(259 Schlüssel in 1.50.0, dazu 32 für `tm_index.*` und `tm_clients.*` in 1.51.0, davon 12
Varianten `<title_key>.<code>`, die der Tab bei den eigenen Quellen zuerst nachschlägt).
`tests/test_tm_panel_texts_v1510.py` sammelt die Arten, Codes und Kennzahlen aus
`tm_engine.py`, `tm_clients.py` und `tm_marks.py` und schlägt fehl, wenn ein Titel oder Text
fehlt oder eine Variante einen Code nennt, den das Backend nie schreibt. `tests/test_tm_panel_texts_v1500.py` sammelt die Schlüssel aus den
Konstanten der Quellmodule und schlägt fehl, wenn einer fehlt. Bei Vorfällen setzt der Tab
„Vorfall eröffnet:“ oder „Vorfall behoben:“ davor, weil `title_key` das nicht trägt.

Rückfall, wenn ein Schlüssel fehlt (etwa eine neue Art einer späteren Version oder ein Code,
den der Test nicht sammelt): der Server-`text` (MAC und IP maskiert), sonst „Code
<title_key>“, sonst „Code unbekannt“. Nicht vom Test gesammelt (NOT_COVERED im Test):
Audit-Typen von Modulen, die es noch nicht gibt, oder aus einer neueren gespeicherten Version;
NI-Arten eines neueren Log-Parsers oder von Ereignissen einer älteren Version; Vorfalltypen
einer älteren gespeicherten Version (Regel inzwischen entfernt); später hinzugefügte Arten
des Security Center. Sie fallen auf diese Regel zurück.

### 14.2 Testdaten

`tmFixture.json` ist eine echte Antwort der Route (Admin, zwei Seiten, leer, `partial`,
Nicht-Admin, aus, 400), geschrieben von `tests/test_tm_panel_fixture_v1500.py` mit erfundenen
Werten; der Test schreibt sie neu und vergleicht (`TM_WRITE_FIXTURE=1` schreibt die Datei).
`tmFixtureClients.json` (1.51.0, `tests/test_tm_panel_fixture_v1510.py`) hält die Antworten
der Phasen B/C aus **einer** Welt mit drei Routern: Zeitleiste (ein offener Ausfall und eine
offene Session von vor dem Fenster, ein Wechsel von Router 1 nach Router 2, ein Ausfall mit
Ende), erste Seite mit `limit`, Nicht-Admin, `clients_off`, und die Sessions-Antworten (`ok`,
zwei Seiten, ein Client, leer, `unavailable`, `clients_off`, `off`, 403, 400). Der Test prüft,
dass keine MAC, IP, kein Hostname des Modells und kein Geheimnis in einer Antwort steht.

### 14.3 Neu im Tab in 1.51.0

- **Quellen:** Chips und Pills „Eigener Verlauf“ (`tm_index`), „Verweise“ (`tm_refs`),
  „Client-Verläufe“ (`tm_clients`); die beiden letzten für Nicht-Admins gesperrt. Pill bei
  `clients_off` „Client-Verläufe: aus · in den Optionen einschalten“; bei `duplicates` > 0 der
  Zusatz „· n doppelt“ mit dem Tooltip „n doppelt ausgeblendet“. Über den Pills „Quellen“, nach
  „Ältere laden“ „Quellen (neueste Seite)“ (die Pills zählen die erste Seite).
- **Intervalle:** zweite Zeile „Dauer 4 min 12 s“ (`closed`), „seit 14:03, noch offen“
  (`open`; an einem anderen Tag mit Datum), „Ende unbekannt“ (`unknown`).
- **Block „Läuft seit vor dem Zeitfenster“:** Die erste Seite (auch jede Aktualisierung und
  jeder Neubeginn) fragt mit `spans=1`; der Block zeigt genau das Feld `spanning` dieser
  Antwort (`marks` enthält solche Intervalle nie). Erste Zeile Datum und Uhrzeit des Beginns,
  zweite Zeile die bisherige Dauer: „noch offen, bisher 2 Tage 3 Std.“ (`open`, gerechnet bis
  jetzt), „Dauer …“ (`closed`), „Ende unbekannt“ (`unknown`). Bei `spanning_truncated` steht
  darunter „Weitere laufen seit vor dem Zeitfenster; Zeitfenster oder Filter enger wählen.“
  Der Block bleibt beim Nachladen älterer Seiten stehen und wird nur durch eine neue erste
  Seite ersetzt; Filter wechseln leert ihn. Block und Liste stehen in einem gemeinsamen
  Größen-Container `.tm-timeline` (`tmlist`); der Block wird schon unter 920 px Breite zu
  Karten (die Liste unter 860 px), weil seine Zeitspalte 4,5em breiter ist: am letzten
  Zeilen-Kipppunkt ist seine Titelspalte 284,75 px, die der Liste 281 px. Die Zähler („n von m Marken“) zählen ihn mit, die
  Quell-Pills nicht (sie kommen vom Server und zählen `marks`).
- **Blättern mit Cursor** (Zeitleiste und Sitzungen): „Ältere laden“ schickt dasselbe
  Fenster und dieselben Filter wie die erste Seite plus `cursor=<next_cursor>` (ohne
  `spans`), bis `next_cursor` `null` ist; `until=next_until` wird nicht mehr benutzt. Der
  Cursor gehört zu der Abfrage, mit der er kam (`cursorQuery` im Zustand). Ein abgelehnter
  Cursor (400, Feld `cursor`, Grund `out_of_range` bzw. `invalid`) erscheint als „Die Stelle
  zum Weiterblättern liegt nicht mehr im Zeitfenster. Bitte „Aktualisieren“.“ bzw.
  „Ungültige Stelle zum Weiterblättern. …“, ohne „Erneut versuchen“; auch „Ältere laden“ ist
  dann ausgeblendet (`cursorRefused`), bis eine neue erste Seite (Aktualisieren oder der
  60-s-Abruf) die Liste neu beginnt, ohne Hinweis „Die Liste beginnt neu“ (derselbe Cursor
  würde wieder abgelehnt).
- **Anschluss nach einer Aktualisierung** (`reaches` in `tmLogic.ts`): Eine neue erste Seite
  wird nur vor die geladenen älteren Seiten gesetzt, wenn ihr Ende die geladene Liste
  erreicht. Ihr `next_cursor` muss dafür bis an das `until` der ersten Seite reichen, auf der
  die Liste aufgebaut wurde (exklusiv, in ms): ein Cursor `<ms>` schließt an, wenn
  `ms` ≤ dieses `until`, ein Cursor `<ms>:<id>` nur, wenn `ms` < `until` (sonst fehlen
  Marken derselben Millisekunde dazwischen). Kein `next_cursor` (die Seite ist vollständig)
  schließt immer an. Sonst beginnt die Liste neu (Hinweis unten), nie mit stiller Lücke.
  Beim Anschluss gelten Fenster und Cursor der älteren Seiten weiter; Marken, die vor dem
  neuen `from` liegen, fallen weg. Veraltete Antworten (älteres `seq`, andere Filter-Generation)
  werden verworfen.
- **Clients:** „Client <client_name>“ mit dem Namen vom Server, sonst „Client ·a1ce4d“ (die
  letzten sechs Zeichen des Pseudonyms); nie eine MAC. Das Attribut `title` der Kurzform
  trägt das volle Pseudonym `tmc_…` und nur das (für `time_machine_forget_client` mit
  `client`). Wechsel „von Router 1 nach Router 2“
  aus `peers`. Art-Chip „Clients“.
- **Neubeginn:** beginnt die Liste neu, weil eine Aktualisierung die geladenen älteren Seiten
  nicht erreicht, steht „Viele neue Einträge: Die Liste beginnt neu. Ältere bei Bedarf erneut
  laden.“ mit „Ausblenden“, bis der Nutzer es schließt.
- **Ansicht „Client-Sitzungen“** (nur Admins: `hass.user.is_admin`; Nicht-Admins sehen den
  Umschalter nicht, die Route antwortet ihnen 403): Umschalter „Zeitleiste | Client-Sitzungen“
  oben im Tab, Zustand im Tab (kein URL-Wechsel; beide Listen bleiben beim Umschalten
  erhalten). Zeitfenster-Chips, Router-Auswahl und „Client“ („Alle Clients“ und die Clients
  der geladenen Sitzungen). Liste nach Beginn absteigend, nach Tagen gruppiert; je Zeile
  Beginn, „Dauer …“ / „noch verbunden“ / „Ende unbekannt“, Client, Router, Band („2,4 GHz“,
  „5 GHz“, „6 GHz“; Spalte 8.5em, in der Zeile ohne Umbruch, „Band unbekannt“ braucht
  102,9 px von 106,25 px; in Karten wieder mit Umbruch), „n Wechsel“ bei
  `params.roam` > 0. Lange Routernamen in der Zeile höchstens zwei Zeilen
  (`-webkit-line-clamp: 2`, voller Name im `title`), in Karten ganz. Unter 700 px
  Containerbreite Karten. „Ältere laden“ über `cursor`/`next_cursor`; `truncated` ohne
  `next_cursor` zeigt den Kürzungshinweis.
  Zustände: `off` (Box wie die Zeitleiste), `clients_off` („Client-Verläufe sind
  ausgeschaltet.“, der Weg in die Optionen und „Gespeichert werden Pseudonyme, keine
  MAC-Adressen, IP-Adressen oder Hostnamen. Abgeschlossene Sitzungen werden nach 14 Tagen
  gelöscht.“ — „abgeschlossene“, weil offene Intervalle nicht gekürzt werden, Abschnitt
  15.7), `unavailable` („Client-Sitzungen sind noch nicht verfügbar.“ und der Grund:
  `not_running` „Die Aufzeichnung läuft gerade nicht.“, `not_loaded` „Der gespeicherte
  Verlauf wird noch geladen.“, sonst „Grund unbekannt.“; ein Test hält die Gründe der Route
  und `UNAVAILABLE_TEXT` gleich),
  leer, 403 „Keine Berechtigung für die Client-Sitzungen (nur Administratoren).“, 410, 5xx mit
  „Erneut versuchen“, 400 mit dem Feldnamen. „Aufzeichnung läuft“ / „Aufzeichnung pausiert …“
  aus `recording`.
- **Abruf:** nur die sichtbare Ansicht lädt und fragt nach, höchstens alle 60 s, bei
  `off`/`clients_off` der Sitzungen gar nicht automatisch; veraltete Antworten werden
  verworfen, und eine Liste, die sich nicht lückenlos anschließen lässt, beginnt neu (wie die
  Zeitleiste).
- **Nicht im Tab:** keine Knöpfe für „Client vergessen“ oder „Verlauf löschen“, kein „Zustand
  zum Zeitpunkt“, kein Export, keine Sprünge in andere Tabs.
- **Nach der Browser-Prüfung** (vor dem Merge von 1.51.0): Der Umschalter stand im
  Spalten-Flex `.cfg` und erbte von `.tm-chips` `flex: 1 1 260px`, wurde also 260 px hoch;
  `.tm-chips.tm-views { flex: 0 0 auto; }` behebt das. Zweite Prüfung: Der Block vor dem
  Fenster lag neben dem Container `tmlist` und behielt bei 360 px sein Sechs-Spalten-Raster
  (Titelspalte 0 px); jetzt im gemeinsamen Container (oben). Fokusrahmen nur im Tab
  (`.tm …:focus-visible`, `#60a5fa`, 7,32:1 auf `#0c1225`; vorher `--border-focus` 2,16:1);
  die anderen Tabs bleiben unverändert.
- Tests: `tmSessions.test.mjs` (Logik), `tmLogic.test.mjs` (Cursor, Anschluss),
  `tmRender.test.mjs` (Darstellung aus `tmFixtureClients.json`, dazu eine kleine Kaskade über
  die geladenen Stylesheets, die für jedes Element in einem Spalten-Flex die wirksame
  `flex-basis` prüft und für jede Regel in `@container <name>`, dass ihre Elemente einen
  Vorfahren mit diesem Container-Namen haben), `tmLayout.test.mjs` (Raster, Karten, Bandspalte, Fokuskontrast,
  Zeilenbegrenzung).

## 15. Phase B: eigener Verlauf

Code: `tm_marks.py` (Modell, Kontingente, gepackte Zeile; ohne HA), `tm_store.py` (HA-Store),
`tm_engine.py` (Signale, Lebenszyklus, Aktionen). Er läuft nur, solange die Time Machine an ist
und mindestens ein Router geladen ist; **eine** Instanz für die ganze Flotte.

### 15.1 Speicher

Store `openwrt_router.time_machine`, Version 1.1, über `core_store.create_store` (private
Datei, atomares Schreiben, Migrationsfunktion). Inhalt:

| Schlüssel | Inhalt |
|---|---|
| `saved_at` | Zeitpunkt des Schreibens |
| `stop` | warum mit diesem Schreiben aufgehört wurde: `stop` (HA fährt herunter), `disabled` (ausgeschaltet), `unloaded` (letzter Router entladen) oder `null` (laufend) |
| `routers` | Tabelle der `router_id`s; die Marken verweisen per Index darauf |
| `marks` | eine Zeile je Marke, 13 Felder mit `\|` getrennt: Nummer, Zeit (ms), Art, Router, Schwere, Code, Ende (ms), Endzustand, Client-Pseudonym (16 hex), Zahlen, Verweis (`audit/<id>`), Peers, abgeleitet |
| `next_seq` | nächste Markennummer (stabile `tmm_`-IDs) |
| `coverage` | Zeiträume, in denen der Verlauf lief (höchstens 64); Grundlage für Abschnitt 17 |
| `checkpoints` | Tages- (höchstens 31) und Start-Checkpoints (höchstens 16): je Router nur `u`, Fingerabdruck-Hash, Eltern-Router |
| `state` | je Router letzter Fingerabdruck-Hash (16 hex), Funk (`5g0=36/80`), Eltern-Router, Rolle, damit eine Änderung während eines Neustarts erkannt wird |

Die Zähler (Abschnitt 11) stehen **nicht** in der Datei; sie zählen ab dem Start des Prozesses.

Jedes Feld einer Zeile wird beim Lesen gegen ein Muster geprüft; eine kaputte Zeile wird
übersprungen und gezählt, nie die ganze Datei (`test_bad_rows_are_skipped_not_the_file`).
Eine unlesbare, fremde oder **neuere** Datei bleibt als `.bak` (bzw. HAs `.corrupt.<Zeit>`)
liegen, der Verlauf beginnt leer
mit der Marke `tm_store_recovered` und dem Audit-Eintrag `time_machine.store_recovered`
(`test_broken_store_starts_empty_with_a_copy_and_a_mark`,
`test_newer_store_version_is_kept_as_bak`).

**Schreiben:** nie im Ereignisweg. Eine Änderung stellt **ein** verzögertes Schreiben nach
300 s an (`async_delay_save`, weitere Änderungen hängen sich daran,
`test_writes_are_delayed_and_bundled`); ohne Änderung alle 900 s ein Lebenszeichen
(`test_heartbeat_write_every_15_minutes_without_changes`), damit `saved_at` nach einem Absturz
nur etwa 15 min (plus die 300 s Verzögerung) vor dem Ende liegt. Sofort (ohne Verzögerung)
wird geschrieben nach „Client vergessen“, „Verlauf löschen“, Client-Schalter aus und beim
HA-Stopp; beim Ausschalten und nach dem letzten Router direkt. Das Packen der Zeilen ist
zwischengespeichert: neu gepackt wird nur eine geänderte Marke.

### 15.2 Obergrenzen

| Grenze | Wert | Verhalten |
|---|---|---|
| Aufbewahrung | 14 Tage | eine **geschlossene** Marke fällt weg, wenn ihr Ende (bzw. Zeitpunkt) älter ist; offene bleiben (`test_retention_drops_closed_marks_after_14_days`) |
| Kontingent Infrastruktur | 3000 | Gruppen `infrastructure`, `radio`, `topology`, `time_machine` |
| Kontingent Verweise | 2000 | Gruppen `configuration`, `disruption`, `security`, `administration` (auch `config_fingerprint_changed`) |
| Kontingent Clients | 10000 | Gruppe `clients` |
| gesamt | 15000 | Summe; ein Kontingent verdrängt **nie** ein anderes, innerhalb eines Kontingents fällt die älteste **geschlossene** Marke zuerst (Zähler `evicted_<kontingent>`; `test_quotas_never_evict_each_other_and_count`). Offene Intervalle (laufender Ausfall, laufende Sitzung) fallen erst, wenn sonst nichts mehr im Kontingent ist, dann das älteste zuerst (Zähler `evicted_open`); ihr späteres Ende bucht trotzdem eine ehrliche Marke (`router_up` ohne `duration_s`), der Zustand der Besitzer bleibt sauber (1.51.0, Review S2; `test_s2_*` in `tests/test_tm_review_v1510.py`) |
| je Client und UTC-Tag | 200 neue Marken | darüber zählt eine Marke `client_flapping` (Zahl `suppressed`, Ende = letzter unterdrückter Zeitpunkt; `test_one_client_storm_is_folded_per_day`, über den echten Weg `test_a_flapping_client_never_fills_the_store`) |
| Datei | 2 500 000 Byte | genaue Länge je Zeile; darüber wird **in einem Durchgang** auf 5 % unter die Grenze gekürzt, zuerst älteste Client-, dann Verweis-, dann Infrastruktur-Marken, in jeder Gruppe offene Intervalle zuletzt; bleibt es darüber, wird nicht geschrieben und die letzte gute Datei bleibt (`save_over_size`; `test_size_limit_trims_clients_first_in_one_pass`) |

Gemessen: ein voller Speicher mit 15000 Marken (3000 Kanalwechsel mit sechs Zahlen, 2000
Verweise, 10000 Sessions) ist **1 626 305 Byte** groß (`test_a_full_store_stays_under_the_limit`,
FakeDisks mit HAs eigener JSON-Serialisierung, eingerückt wie HA schreibt).

### 15.3 Signale

Alles kommt aus Daten, die ohnehin da sind: kein zusätzlicher Router-Aufruf
(`test_two_polls_make_the_same_router_calls_with_everything_on`: die Aufrufliste zweier Polls
mit Time Machine, Client-Schalter, Client-Stabilität und Network Intelligence an gleicht der mit
allem aus).

| Art | Quelle | Regel |
|---|---|---|
| `router_down` / `router_up` | `FleetOutageTracker` (Listener) | Intervall ab dem Ausfallbeginn des Trackers, sobald er den Ausfall meldet (Code = Fehlerart, z. B. `timeout`); `router_up` mit `duration_s`. Eine offene Beobachtungslücke desselben Routers wird ersetzt |
| `lan_down` / `lan_up` | `FleetOutageTracker` | ganze Flotte nicht erreichbar: ein Intervall (`fleet`), `critical` |
| `observation_gap` | Coordinator-Listener | Poll fehlgeschlagen, aber (noch) kein gemeldeter Ausfall: offenes Intervall `poll_failed`; unter 120 s wird es verworfen (`test_observation_gaps_short_ones_are_dropped`); `unloaded`, wenn alle Router länger als 600 s entladen waren |
| `ha_gap` | Start | HA war aus: von `saved_at` bis zum Start; `restart` (`info`) nach sauberem Stopp, `unclean` (`warning`, `derived`) nach Absturz |
| `channel_changed` | `ap_interfaces` der Coordinator-Daten | je Funkmodul (`{band}{nr}`) Kanal oder Breite anders als zuvor; Zahlen `band`, `channel_from/to`, `width_from/to`, `dfs`; `warning` mit Code `dfs`, wenn `dfs.last_event` der Daten zum neuen Kanal passt |
| `radio_down` / `radio_up` | dieselben Daten | Funkmodul in zwei Polls hintereinander nicht mehr gemeldet; Beginn = erster fehlender Poll |
| `config_fingerprint_changed` | `config_snapshot.fingerprint_from_coordinator` | Hash (16 hex) zwei Polls gleich und anders als der vorige; nur mit vorigem Wert |
| `uplink_changed`, `router_role_changed` | Topologie von Network Intelligence (nur lesend) | Eltern-Router bzw. Rolle Gateway/Knoten zwei Polls gleich und anders; gemerkte (nicht gesehene) Kanten zählen nicht; `peers` vorher/nachher |
| Verweise (`tm_refs`) | Audit-Log des Enterprise Core (Abonnement) | jeder veröffentlichte Eintrag der Arten `config_drift`, `config_event`, `rf_event`, `diag_finding`, `traffic_anomaly`, `security_incident`, der keinen Client betrifft: Verweis mit Audit-ID, Code = Audit-Typ, Zahlen wie beim Audit-Adapter |
| `clock_shift` | Uhr | Wanduhr springt zwischen zwei Prüfungen (Poll oder Takt) um mehr als 300 s gegenüber der monotonen Uhr (`shift_s`, rückwärts mit `lead_s`), oder beim Start liegt `saved_at` mehr als 300 s in der Zukunft; dann **kein** `ha_gap` (`test_clock_backwards_and_jumps_are_marked_not_gaps`) |
| `tm_started` / `tm_disabled` | Schalter | `first_start`, `switched_on` (mit `off_s`), `switched_off` |

Unterdrückt (Entprellung): Fingerabdruck, Uplink und Rolle brauchen zwei gleiche Polls;
`radio_down` zwei fehlende; ein Poll ganz ohne Funkmodule wird für Kanal und Funk ignoriert.
Takt alle 300 s: Aufbewahrung, Checkpoint um lokale Mitternacht, Lebenszeichen.

### 15.4 Robustheit

| Fall | Verhalten | Test |
|---|---|---|
| HA-Neustart | offene Intervalle enden bei `saved_at` mit `end_state: unknown`, `ha_gap` von `saved_at` bis Start | `test_restart_closes_open_intervals_and_marks_the_ha_gap` |
| Absturz | wie oben, `ha_gap` `unclean`, `derived` | `test_crash_leaves_an_unclean_derived_gap` |
| Router nach dem Start noch als ausgefallen gemeldet | neues `router_down` ab Start, `derived` (kein überlappendes Doppel) | im Neustart-Test |
| Uhr rückwärts | `clock_shift`, keine erfundene Lücke | `test_clock_backwards_and_jumps_are_marked_not_gaps` |
| Router entfernt / deaktiviert | seine offenen Intervalle enden `unknown` | `test_removed_router_ends_its_intervals_as_unknown` |
| aus und wieder an | `tm_disabled`, offene Intervalle `unknown`, beim Einschalten `tm_started switched_on` | `test_switched_off_and_on_again` |
| kaputte / neuere Datei, kaputte Zeile | Abschnitt 15.1 | dort genannt |
| Listener, Takt, HA-Stopp-Listener | existieren nur, solange die Time Machine läuft | `test_ha_stop_listener_and_tick_exist_only_while_on` |

### 15.5 Checkpoints

Täglich um lokale Mitternacht und bei jedem Start ein Checkpoint
`<ts>|day|<rtr>:u=1,fp=<16 hex>,p=<rtr>;…` (bzw. `|start|`): nur Codes und Hashes
(`test_daily_checkpoint_carries_codes_only`). Phase B liest sie nicht aus; sie sind für den
späteren „Zustand zum Zeitpunkt“ vorgesehen.

### 15.6 Ausschalten

Time Machine aus: offene Intervalle enden `unknown`, Marke `tm_disabled`, **alle Client-Marken
werden gelöscht**, ein letztes Schreiben mit `stop: disabled`, alle Listener ab. Die
Infrastruktur-Marken bleiben in der Datei und werden beim nächsten Einschalten nach der
Aufbewahrung gekürzt.

Was genau gelöscht wird (1.51.0, unabhängig vom Schalter „Client-Verläufe“): jede Marke mit
einem Client-Pseudonym (`client_session`, `client_roam`, `client_disconnect`,
`client_flapping`) sowie die Tageszähler und Flatter-Zähler der Clients im Speicher. Wann:
sofort beim Speichern des Optionen-Dialogs, ohne Neuladen. Läuft der Verlauf, schreibt
`async_stop` die Datei sofort; läuft er nicht (etwa kein Router geladen), liest
`async_purge_clients` die Datei einmal und schreibt sie nur, wenn Client-Marken darin waren.
Es bleiben: Ausfälle, Lücken, Änderungen, Verweise, `tm_forgot_client`/`tm_cleared` (ohne
Client), Checkpoints und Abdeckung. Der Optionen-Dialog sagt das (de/en). Tests:
`test_switching_off_deletes_the_clients_and_keeps_the_infrastructure`,
`test_switching_off_without_a_running_engine_deletes_the_clients`,
`test_nothing_is_trimmed_while_the_time_machine_is_off` in `tests/test_tm_overlap_v1510.py`.

**Alte Kopien (1.51.0, Review K4, K-b).** Nur bei den vier Client-Löschungen
(Client-Schalter aus, Time Machine aus — mit laufendem Verlauf oder über
`async_purge_clients` —, „Client vergessen“, „Verlauf löschen“) löscht die Time Machine auch
die Kopien `<datei>.bak` und `<datei>.corrupt.*` ihrer Datei (im Executor; Zähler
`copies_removed`), damit keine alte Kopie die gelöschten Clients behält. Eine solche Kopie
ist danach für die Wiederherstellung verloren. Tests:
`test_k4_purge_deletes_the_old_copies_of_a_real_file` (echte Datei über HAs Store),
`test_k4_every_client_delete_removes_the_copies`.

**Router entfernt (1.51.0, Review K4).** `async_remove_entry` gibt die `router_id` des
entfernten Routers (aus dem Enterprise Core) an `tm_engine.async_remove_router`: Alle Marken
dieses Routers (auch als Peer eines Roamings) und sein `state` werden gelöscht, wie bei der
Network Intelligence. Läuft kein Verlauf, wird die Datei einmal gelesen und nur geschrieben,
wenn sich etwas ändert. Die Kopien `.bak`/`.corrupt.*` bleiben dabei **liegen** (Review K-b):
Router-Kennungen sind keine Personendaten, und die Kopie einer unlesbaren oder neueren Datei
(etwa nach einem Downgrade) hält den Verlauf aller anderen Router für eine Wiederherstellung.
In solchen alten Kopien können darum Marken eines entfernten Routers stehen bleiben. Tests:
`test_k4_removing_a_router_removes_its_marks`,
`test_kb_removing_a_router_keeps_the_copy_of_a_newer_file` (echte Datei),
`test_k4_async_remove_entry_hands_the_router_to_the_time_machine`.

### 15.7 Grenzen (Phase B)

- Intervalle, die vor `from` begannen und ins Fenster reichen, kommen nur mit `spans=1` im
  Feld `spanning` (Abschnitt 8), höchstens 200; darüber fehlt der Rest
  (`spanning_truncated: true`).
- Offene Intervalle werden nicht nach 14 Tagen gekürzt.
- **Solange die Time Machine aus ist, wird nichts gekürzt** (bekannte Grenze, gewollt): Es
  läuft kein Takt, der die Datei liest. Die Infrastruktur-Marken bleiben, bis die Time Machine
  wieder eingeschaltet wird (dann sofort auf 14 Tage gekürzt) oder „Verlauf löschen“ läuft.
  Client-Marken gibt es dann nicht mehr (Abschnitt 15.6).
- Uplink und Rolle nur, solange Network Intelligence läuft; ohne Funkdaten in
  `ap_interfaces` kein Kanalwechsel; sind alle Funkmodule aus (leerer Poll), entsteht kein
  `radio_down`.
- Nicht rückwirkend: Was vor dem Einschalten geschah, steht nur in den Phase-A-Quellen.
- Nach einem Absturz ist der Beginn der HA-Lücke nur auf etwa 15–20 min genau (`derived`;
  Lebenszeichen alle 15 min plus 300 s Schreibverzögerung).
- **HA lief, aber kein Router war geladen** (alle beim Start unerreichbar, Review K10): Die
  HA-Lücke endet beim Einrichten der Integration in diesem HA-Lauf (`async_setup`), der Rest
  bis zum Start des Verlaufs ist eine `observation_gap` mit Code `unloaded`, wenn er mindestens
  600 s dauert (darunter bleibt eine HA-Lücke bis zum Start). Ein LAN-Ausfall in dieser Zeit
  wird nicht erkannt: Ohne geladenen Router gibt es keinen Ausfall-Melder. Wird die
  Integration erst nach dem HA-Start installiert, zählt die Zeit davor ebenfalls als
  HA-Lücke. Tests: `test_k10_*` in `tests/test_tm_review_v1510.py`.

## 16. Phase C: Client-Sessions

Code: `tm_clients.py`. Beobachtet die Übergänge der **Client-Stabilität**
(`ClientStability.add_transition_listener`, neu in `client_engine.py`; die Buchungen der
Client-Stabilität bleiben gleich, Test `test_client_stability_books_the_same_with_a_listener`);
kein eigener Abruf.

### 16.1 Schalter

`time_machine_clients` in den Optionen jedes Routers, Standard **aus**, ein Schalter für die
ganze Flotte (wie `time_machine_enabled` auf alle Einträge geschrieben, an, sobald ein Eintrag
`true` hat). Er wirkt nur, solange die Time Machine an ist und die Client-Stabilität läuft.
Ohne ihn wird **nichts** Client-Bezogenes gespeichert. **Ausschalten löscht alle Client-Marken**
aus Arbeitsspeicher und Datei, sofort geschrieben (`test_client_switch_off_deletes_the_client_history`);
ist die Time Machine schon aus, liest der Dialog die Datei einmal und schreibt sie nur, wenn
Client-Marken darin waren (`test_time_machine_off_deletes_clients_and_purge_when_already_off`).
Seit 1.51.0 löscht auch **das Ausschalten der Time Machine** alle Client-Marken, selbst wenn
dieser Schalter an bleibt (Abschnitt 15.6).

### 16.2 Marken

| Art | wann | Felder |
|---|---|---|
| `client_session` | Client verbunden (START), nach Roaming (MOVE) oder beim Anhängen für einen schon verbundenen Client (`resumed: 1`, `derived`) | Intervall; `band` (2.4/5/6), `roam`, `resumed`, `gaps`, `blips`; Ende `closed` bei beobachteter Trennung, sonst `unknown` |
| `client_roam` | Wechsel des Routers | `peers` von/nach, Code `roam` |
| `client_disconnect` | Trennung (END) | Code = Trennungsklasse der Client-Stabilität, `timed` |
| `client_flapping` | über 200 Marken eines Clients am Tag | `suppressed`, `cap` |

Ist ein Router zeitweise nicht erreichbar, liefert er keine Client-Liste; die Client-Stabilität
bucht dann eine Lücke (`gaps` + 1) und **keine Trennung**
(`test_unreachable_router_invents_no_disconnect`). HA-Neustart mitten in einer Session: die
Session endet bei `saved_at` mit `unknown`, beim Start beginnt eine neue mit `resumed`
(`test_restart_mid_session_ends_unknown_and_resumes`). Eine `resumed`-Session beginnt seit
1.51.0 beim Sitzungsbeginn, den die Client-Stabilität kennt, wenn er in die Laufzeit des
Verlaufs fällt (etwa beim Einschalten der Client-Verläufe); sonst beim Anhängen
(`test_s3_resumed_sessions_keep_the_start_client_stability_knows`). Vorher begannen alle
beim selben Zeitpunkt (Review S3). Roaming über Router hinweg:
`test_session_roam_and_disconnect_across_routers`.

### 16.3 Pseudonym und Name

`client` ist `tmc_` + 16 hex, HMAC der MAC mit dem eigenen Modulschlüssel der Time Machine;
gespeichert werden nur die 16 hex. `client_name` liest der Server bei jeder Antwort aus der
Client-Stabilität, nur für Admins und nur solange sie den Client kennt; gespeichert wird er nie.
Dafür hält der Prozess im Arbeitsspeicher Pseudonym → MAC, begrenzt (Review K9): jeder Client
mit offener Session plus die 512 zuletzt gesehenen anderen (`MACS_RECENT_MAX`); für ältere
ist `client_name` `null`, bis sie wieder einen Übergang haben
(`test_k9_the_mac_table_keeps_open_clients_and_a_bounded_rest`).

### 16.4 Route `GET /api/openwrt_router/enterprise/timemachine/sessions`

Nur Administratoren (jeder andere Benutzer 403, auch bei offenem Panel), kein Body, strenge
Abfrage wie in Abschnitt 4 (400 ohne Echo, unbekannte Schlüssel abgelehnt).

| Parameter | Format | Standard | Bedeutung |
|---|---|---|---|
| `from`, `until` | wie Abschnitt 4 | 24 h bis jetzt | Fenster `[from, until)`, höchstens 14 Tage |
| `client` | `tmc_` + 16 hex | – | nur dieser Client |
| `router_id` | `rtr_` + 32 hex | – | nur Sessions an diesem Router |
| `limit` | 1 … 500 | 200 | Sessions je Seite |
| `cursor` | wie Abschnitt 4 | – | seit 1.51.0: aus `next_cursor`; darf auch vor `from` liegen (Sessions, die vorher begannen), nie nach `until` |

Eine Session gehört zum Fenster, wenn sie vor `until` begann und offen ist oder bei/nach `from`
endete (Überlappung). Sortiert nach Beginn absteigend, bei gleichem Beginn nach `id`.
Blättern über `next_cursor` wie in Abschnitt 8 (teilt auch einen Beginn, den mehr Sessions als
`limit` teilen, und erreicht Sessions, die vor `from` begannen); `next_until` bleibt für
ältere Clients (teilt Sessions mit demselben Beginn nicht und endet am `from`).

```json
{
  "v": 1,
  "status": "ok",
  "reason": null,
  "generated_at": 1795290689.754,
  "window": {"from": 1799997480.0, "until": 1800001140.0},
  "recording": true,
  "sessions": [
    {
      "id": "tmm_85926e9581ae53c0",
      "client": "tmc_f3e24c9bafa1ce4d",
      "client_name": null,
      "router_id": "rtr_22222222222222222222222222222222",
      "router_name": "Router 2",
      "start": 1800000180.0,
      "end": 1800000240.0,
      "end_state": "closed",
      "band": 5,
      "params": {"band": 5, "roam": 1},
      "derived": false
    }
  ],
  "truncated": true,
  "next_until": 1800000180.0,
  "next_cursor": "1800000180000:tmm_85926e9581ae53c0"
}
```

(Testantwort mit `limit=1`, Kennungen erfunden)

| `status` | Bedeutung |
|---|---|
| `ok` | gelesen; `recording` sagt, ob gerade aufgezeichnet wird (Client-Stabilität angebunden) |
| `off` | Time Machine aus; `window` `null` |
| `clients_off` | Client-Schalter aus; keine Sessions |
| `unavailable` | an, aber nicht bereit: `reason` `not_running` oder `not_loaded` |

Tests: `test_sessions_route_rights_errors_and_paging`,
`test_s3_250_resumed_sessions_of_one_start_page_without_loss` (250 Sessions mit demselben
Beginn und 30 weitere, `limit` 200: 280 von 280 über `/sessions` und `/timeline`).

### 16.5 Timeline-Beispiel (Ausschnitt)

```json
{
  "id": "tmm_4df64109bab3f96a",
  "ts": 1800000180.0,
  "source": "tm_clients",
  "kind": "client_roam",
  "group": "clients",
  "severity": "info",
  "router_id": "rtr_22222222222222222222222222222222",
  "router_name": "Router 2",
  "fleet": false,
  "title_key": "tm_clients.client_roam",
  "text": null,
  "params": {},
  "ref": {"module": "time_machine", "type": "mark", "id": "m3", "version_id": null},
  "derived": false,
  "code": "roam",
  "end": null,
  "end_state": null,
  "client": "tmc_f3e24c9bafa1ce4d",
  "client_name": null,
  "peers": {
    "before": {"router_id": "rtr_11111111111111111111111111111111", "router_name": "Router 1"},
    "after": {"router_id": "rtr_22222222222222222222222222222222", "router_name": "Router 2"}
  }
}
```

Quelleneintrag: `{"id": "tm_clients", "state": "ok", "reason": null, "count": 4, "oldest":
1800000000.0, "truncated": false, "cut": null, "duplicates": 0}`.

`omitted_client_marks` behält seine Bedeutung: Client-Einträge der **Phase-A-Quellen**, die
weggelassen werden. Die Marken aus `tm_clients` zählen dort nicht.

### 16.6 Grenzen (Phase C)

- Sessions gibt es nur, solange die Client-Stabilität läuft; wird sie neu eingerichtet, hängt
  sich die Time Machine beim nächsten Takt (höchstens 5 min) wieder an.
- Ohne `cursor` (Clients vor 1.51.0): mehr Sessions mit **demselben Beginn** als `limit`
  oder mehr überlappende Sessions als `limit`, deren Beginn vor `from` liegt, sind über
  `next_until` nicht erreichbar (`truncated: true`); mit `next_cursor` kommt jede.
- „Client vergessen“ für einen gerade verbundenen Client: Die Time Machine zeichnet ihn ab
  seinem nächsten Übergang wieder auf (Review K5): eine neue Session beim nächsten Verbinden
  oder Router-Wechsel; trennt er sich vorher, entsteht nur die Trennungsmarke.
- „Client vergessen“ löscht nur im Verlauf der Time Machine, nicht in Client-Stabilität,
  Network Intelligence, Security Center, Traffic, WiFi RF oder im HA-Recorder (die Antwort
  nennt sie in `not_deleted_in`).
- Der Hostname kommt allein aus der Client-Stabilität; kennt sie den Client nicht mehr, ist
  `client_name` `null`.

## 17. Doppelte zwischen Quellen

Vor den Rechten entfernt und je Quelle in `duplicates` gezählt:

1. **Audit gewinnt über `tm_refs`.** Ein Verweis mit derselben Audit-ID wie ein gelesener
   Eintrag von `core_audit` fällt weg. Erst wenn der Audit-Ring den Eintrag verdrängt hat,
   erscheint der Verweis (`test_the_audit_wins_over_its_reference_until_it_is_gone`).
2. **`tm_index` gewinnt über das gleiche NI-Ereignis** (1.51.0, Review S1). Ein Ereignis von
   `ni_events` mit der Art `router_down`, `router_up`, `lan_down`, `lan_up` oder
   `channel_changed` fällt nur weg, wenn `tm_index` (im Fenster oder als Intervall, das
   hineinreicht) eine Marke **derselben Art und desselben Routers** (Flotten-Marken: beide
   ohne Router) **in zeitlicher Nähe** hält, `NI_MATCH_S` = 180 s:
   - ein „down“ liegt im Intervall des eigenen Ausfalls (ab 180 s vor seinem Beginn bis 180 s
     nach seinem Ende; offen: ohne Ende). Begründung: Beide folgen demselben Ausfall-Melder;
     das eigene Intervall beginnt bei der ersten Störung, NI meldet erst nach zwei weiteren
     fehlgeschlagenen Polls und der Wartezeit (längstes Poll-Intervall + 30 s), also je nach
     Poll-Intervall Minuten später. 180 s sind drei normale Polls (60 s) oder ein Poll mit
     Reserve bei 120 s (CPU-Last);
   - ein „up“ liegt höchstens 180 s neben einem eigenen „up“ oder dem Ende des eigenen
     Intervalls (beide melden dasselbe `report_up`);
   - ein Kanalwechsel liegt höchstens 180 s neben einem eigenen Kanalwechsel desselben
     Routers (ein Poll-Intervall bis 300 s im SSH-Fallback ist nicht abgedeckt: dann bleiben
     beide, lieber doppelt als verloren).
   Im Zweifel bleibt das NI-Ereignis: andere Arten (auch `uplink_changed` aus `lan.uplink`,
   ein Port-Ereignis, das der eigene Verlauf nicht kennt), ein anderer Router, kein passendes
   eigenes Intervall, ein Ereignis ohne Router, ein nicht lesbares `tm_index`. Tests:
   `test_the_index_wins_over_the_same_ni_event_only`, `test_s1_*` in
   `tests/test_tm_review_v1510.py` (eigener Verlauf über den echten Ausfall-Melder).

   **Aufwand (Review M1).** Die eigenen Marken werden je (Art, Router) einmal sortiert
   (`tm_query._OwnSpans`); jedes NI-Ereignis prüft per `bisect` nur die Nachbarn: bei „down“
   das Präfix-Maximum der Obergrenzen aller Intervalle, die früh genug beginnen (Intervalle
   eines Routers dürfen sich überlappen, etwa nach einem Uhrsprung oder einem verdrängten
   offenen Intervall; die Regel bleibt exakt dieselbe), sonst die beiden nächsten Werte.
   Gemessen (ein flatternder Router, 3000 eigene Marken, 3000 NI-Ereignisse, Aufbau der
   Prüfung, je drei Läufe): `drop_duplicates` vorher 143–168 ms, längster Block ohne Abgabe
   143–154 ms; nachher 2–3 ms und 4–5 ms. Verglichene Werte: 4 501 500 linear, 6 000 jetzt.
   Tests: `test_m1_the_fast_rule_decides_like_the_linear_one` (40 Zufallsdaten-Sätze gegen
   die alte lineare Regel, die im Test bleibt, mit Grenzfällen genau bei ±180 s, offenen
   Intervallen, mehreren Routern und Flotten-Marken), `test_m1_overlapping_and_open_intervals_of_one_router`,
   `test_m1_a_flapping_router_costs_log_n_comparisons_per_event` (zählt Vergleiche, keine Zeit).

   **Über Seitengrenzen (Review K-a).** Auf einer Folgeseite (`cursor`) liest die Zeitleiste
   `tm_index` für die Doppel-Prüfung bis `NI_MATCH_S` über den Cursor hinaus (Feld
   `lookahead` der Lesung); angezeigt wird weiter nur bis zum Cursor. So bleibt ein
   NI-Ereignis nicht auf Seite 2 stehen, wenn die eigene, etwas jüngere Marke auf Seite 1 lag.
   Betroffen waren Kanalwechsel **und** „up“ (beide Seiten können bis 180 s auseinander
   liegen); ein „down“ nicht, denn dessen eigenes Intervall beginnt vor dem NI-Ereignis und
   liegt damit auf derselben oder einer späteren Seite (offene und hineinreichende Intervalle
   werden auf jeder Seite gelesen). An den Fenstergrenzen gilt das bewusst nicht: Liegt die
   eigene Marke nach `until` oder vor `from`, gehört sie nicht zu diesem Fenster, und das
   NI-Ereignis ist dort der einzige Eintrag des Ereignisses; jedes Fenster ist für sich
   vollständig (in zwei angrenzenden Fenstern kann dasselbe Ereignis je einmal stehen).
   Test: `test_ka_a_double_split_by_a_page_boundary_is_shown_once` (Kanalwechsel und „up“,
   alle Seiten mit `limit` 3 gegen eine Seite).

   **Filter und Rechte (1.52.0, Rest aus 1.51.0).** Eine eigene Marke macht ein NI-Ereignis
   nur dann zum Doppel, wenn der Nutzer sie unter den Rechten und Filtern der Abfrage sieht
   (`min_severity`, `kind`, `router_id`, `client`). Blendet ein Filter die eigene Marke aus,
   etwa `min_severity=critical` bei einem eigenen Ausfall mit `warning` und einem kritischen
   NI-Ereignis, bleibt das NI-Ereignis: ein Ereignis verschwindet nie mit beiden Einträgen.
   Tests: `test_min_severity_never_drops_both_entries_of_one_event`,
   `test_the_double_rule_with_a_real_ni_event` (echtes NI über den echten Ausfall-Melder, beide
   NI-Ereignisse als Doppel gezählt, `duplicates` 2).

Andere Quellen werden nicht verglichen.

## 18. Aktionen

Beide nur für Administratoren (`async_register_admin_service`), mit Antwort; immer
registriert, bei ausgeschalteter Time Machine Fehler `time_machine_off`.

| Aktion | Felder | Antwort | Wirkung |
|---|---|---|---|
| `openwrt_router.time_machine_forget_client` | `mac` und `client` (`tmc_` + 16 hex, seit 1.51.0) sind im Schema beide optional; genau eines muss gesetzt sein (ein leeres Feld zählt als nicht gesetzt), sonst antwortet die Aktion mit dem übersetzten Fehler `time_machine_mac_or_client`, ohne die Eingabe zu wiederholen (Review K-c) | `{"deleted": n, "not_deleted_in": [...]}` | löscht alle Marken dieses Clients, Marke `tm_forgot_client` (ohne Client), Audit `time_machine.client_forgotten`, sofort geschrieben, alte Kopien der Datei gelöscht (Abschnitt 15.6); ein gerade verbundener Client wird ab seinem nächsten Übergang wieder aufgezeichnet (Abschnitt 16.6); Fehler `time_machine_mac_or_client` (keines oder beide), `time_machine_invalid_mac`, `time_machine_invalid_client`, `time_machine_no_key` |
| `openwrt_router.time_machine_clear_history` | `clients_only` (bool) | `{"deleted": n}` | löscht die Client-Marken oder den ganzen eigenen Verlauf (auch Checkpoints, Abdeckung beginnt neu), Marke `tm_cleared`, Audit `time_machine.history_cleared`, sofort geschrieben |

Die Time Machine speichert die MAC nicht; Home Assistant selbst kann einen Aktionsaufruf mit
seinen Daten aber in Protokoll oder Recorder behalten. Wer das vermeiden will, nimmt das
Pseudonym (`client`), das Tab und `/sessions` zeigen (Review K2; die Feldtexte sagen es).

Tests: `test_forget_action_and_client_stability_exclusion`, `test_clear_history_action`,
`test_k2_forget_takes_the_pseudonym_and_exactly_one_of_both`,
`test_kc_forget_over_the_real_action_answers_translated` (echter Dienstaufruf über HAs
Dienst-Registry: keines, beide, leeres Feld, nur `mac`, nur `client`, ungültiges Pseudonym).

## 19. Panel für B/C (1.51.0)

Das Panel ist mit 1.51.0 nachgezogen (Abschnitt 14.3, `_PANEL_VERSION` `20261121-timemachine5`).
Es liest nur die Routen `timeline` und `sessions` und fügt nichts hinzu. Offen für eine spätere
Version: Bedienelemente für die Aktionen aus Abschnitt 18. „Zustand zum Zeitpunkt“,
Vergleich, Export und Sprünge über `ref` (Phasen D bis F, Abschnitte 20 bis 23) nutzt das
Panel seit 1.52.0 (Abschnitt 25).

## 20. Phase D: Zustand zum Zeitpunkt

`GET /api/openwrt_router/enterprise/timemachine/state` (`tm_state.py`, `tm_views.py`). Nur
lesend: kein Router-Aufruf, kein Listener, keine Aufgabe, kein Speichern. Alles kommt aus dem
eigenen Verlauf (Marken, Abschnitte `seen`, Abdeckung, `lost`, Speicher 1.2, Abschnitt 24)
und aus Lesefunktionen der Module (NI-Incidents, Versionen des Configuration Managers,
Traffic `window_at`, WiFi RF `window_at`).

### 20.1 Abfrage

| Schlüssel | Wert | Standard |
|---|---|---|
| `at` | Unix-Sekunden (wie `from` der Zeitleiste), nicht in der Zukunft, auf ms abgerundet | jetzt |
| `router_id` | `rtr_` + 32 hex | alle Router |
| `clients_limit` | 1 bis 500, **nur Administratoren** | 200 |
| `clients_cursor` | `next_cursor` der vorigen Antwort, **nur Administratoren** | – |

Wie bei der Zeitleiste: unbekannter Schlüssel, doppelter Schlüssel, Wert über 96 Zeichen
→ 400 `invalid_request` mit `field` und festem `reason`, nie mit dem Eingabewert. Ein
Nicht-Admin, der einen Client-Schlüssel schickt, bekommt 400 `admin_only` **bevor** der Wert
gelesen wird (er erfährt also nicht, ob ein Cursor gültig wäre). Ein Cursor nach `at` →
400 `out_of_range`.

### 20.2 Antwort (Beispiel aus `test_state_route_clients_for_admins_with_paging`, gekürzt)

```json
{
 "v": 1, "status": "ok", "reason": null,
 "generated_at": 1800000360.0, "at": 1800000210.0,
 "known": true, "unknown_reason": null,
 "basis": {"retention_from": 1798790760.0, "recorded_from": 1800000000.0,
           "marks_applied": 0, "intervals": 0},
 "routers": [{
   "router_id": "rtr_1111…", "router_name": "Router 1", "entry": "enabled",
   "reachable": {"value": true, "derived": true, "reason": null},
   "role":   {"value": null, "derived": false, "reason": "not_observed"},
   "uplink": {"value": null, "derived": false, "reason": "not_observed"},
   "radios": {"state": "ok", "reason": null, "derived": true,
              "items": [{"key": "5g0", "band": "5g", "channel": 36, "width": 80,
                         "state": "up", "reason": null}]},
   "traffic":     {"state": "off", "reason": "not_running", "hour": 1800000000.0, "wan": []},
   "utilization": {"state": "off", "reason": "not_running", "hour": 1800000000.0, "radios": []}
 }],
 "routers_truncated": false,
 "intervals": [], "intervals_total": 0, "intervals_truncated": false,
 "incidents": {"state": "off", "reason": "not_running", "items": [], "total": 0, "truncated": false},
 "config":    {"state": "off", "reason": "module_off", "items": []},
 "clients": {"state": "ok", "reason": null,
   "items": [{"id": "tmm_ae471cb5ff939bb9", "client": "tmc_f3e24c9bafa1ce4d",
              "client_name": null, "router_id": "rtr_2222…", "router_name": "Router 2",
              "start": 1800000180.0, "end": null, "end_state": "open", "band": 5,
              "derived": false}],
   "per_router": [{"router_id": "rtr_1111…", "router_name": "Router 1", "clients": 1}],
   "total": 2, "truncated": false, "next_cursor": null}
}
```

Felder:

- `known` / `unknown_reason`: ob der Zeitpunkt überhaupt rekonstruierbar ist (Abschnitt 20.3,
  „global unbekannt“). Bei `known: false` sind alle Router-Werte unbekannt mit demselben Grund.
- `basis`: ab wann gelesen werden kann (`retention_from` = jetzt − 14 Tage, `recorded_from` =
  Beginn der ältesten Abdeckung), wie viele Marken angewandt und wie viele Intervalle
  betroffen sind.
- je Router `reachable`, `role` (`gateway` / `ap` / …), `uplink` (`{"router_id",
  "router_name"}` des Elternrouters oder null = direkt am Gateway): jeweils `{"value",
  "derived", "reason"}`.
- je Router `entry` (1.52.2, additiv): der Konfigurationseintrag des Routers **jetzt**,
  `"enabled"`, `"disabled"` (`disabled_by` des Eintrags ist gesetzt; `ConfigEntryDisabler`
  kennt nur `user`, also hat ein Benutzer ihn ausgeschaltet; HA richtet ihn nicht ein) oder null (kein Eintrag, nur Verlauf). Es ist der Stand beim
  Abfragen, nicht der zu `at`; in beiden Blöcken von `/compare` steht derselbe Wert
  (`tm_sources.ENTRY_*`, `RouterMap.disabled`, gelesen in `build_router_map`). Ein
  deaktivierter Eintrag behält seine Kennung in der Router-Registry und erscheint deshalb in
  der Tabelle; seine Werte sind ab dem Deaktivieren unbekannt (`not_observed`), der Verlauf
  davor bleibt. Ein Panel bis 1.52.1 liest das Feld nicht und zeigt die Antwort wie bisher
  (`tests/test_tm_compare_display_v1522.py`).
- `radios.items`: je Funk `key` (Band + Nummer, **nie** ein Netdev- oder phy-Name), `band`,
  `channel`, `width` (MHz; null = unbekannt), `state` (`up` / `down` / null), `reason`.
  `radios.state`: `ok`, `partial` (einzelne Funks unbekannt) oder `unknown` (Grund in
  `reason`). `ok` heißt **vollständig**: Fehlt ein Funk in der Liste, weil er über einen
  Neustart oder ein Neuladen hinweg aus blieb (die Engine kennt ihn, der neue Abschnitt sah ihn
  nie), ist der Block `partial` mit `reason: "not_observed"` (Review E, additiv: vorhandener
  Zustand und Grund), bis der Funk wieder auftaucht
  (`test_e_radio_off_across_a_restart_is_not_ok`).
- `traffic.wan[]`: Stundenwerte der Stunde, die `at` enthält (`hour` = deren Beginn), je
  WAN-Punkt `state`, `reason`, `rx_bytes`, `tx_bytes`, `avg_*_bps`, `peak_*_bps`,
  `download`, `upload`, `time_coverage`, `coverage` (Felder von Traffic, kein Punkt- oder
  Netdev-Name).
- `utilization.radios[]`: Kanalauslastung der Stunde je Band (`band`, `state`, `mean`,
  `minimum`, `maximum`, `count`), ohne Radio-ID.
- `intervals[]`: eigene Intervalle (Ausfall, Beobachtungslücke, HA-Lücke …), die `at`
  überdecken, im Format einer Zeitleisten-Marke (Abschnitt 5.3), höchstens 100
  (`intervals_total`, `intervals_truncated`).
- `incidents.items[]`: NI-Incidents, die zu `at` offen waren (`state: "open"`) oder deren
  Zustand zu `at` unbekannt ist (`state: "unknown"`, `reason: "reopened_since"`: wieder
  geöffnet, wann es vorher gelöst war, ist verloren). Felder `id`, `type`, `severity`,
  `router_id`, `router_name`, `fleet`, `since`, `ref`, `target`. Höchstens 100. Incidents mit
  Client-Bezug erscheinen nie.
- `config.items[]` (nur Administratoren): je Router die **neueste behaltene** Version, die zu
  `at` schon bestand (`version_id`, `created_at`, `code`, `ref`, `target`). Behaltene
  Versionen werden ausgedünnt; das ist nicht zwingend die Konfiguration, die zu `at` lief.
- `clients` (nur Administratoren mit eingeschalteten Client-Verläufen): Sessions, die `at`
  überdecken, neueste zuerst, `clients_limit` je Seite, weiter mit `next_cursor` →
  `clients_cursor`. `per_router` zählt alle (nicht nur die Seite). `client_name` genau wie in
  1.51.0 (Client Stability, nur hier und in der Zeitleiste für Administratoren).

Zustände eines Teils (`state`): `ok`, `partial`, `unknown`, `off` (Modul aus, nicht geladen,
nicht laufend, keine Rechte: `reason` `module_off`, `not_loaded`, `not_running`,
`admin_only`, `clients_off`), `unreadable` (das Modul hat beim Lesen versagt). Jeder Aufruf
eines anderen Moduls (Traffic `window_at`, WiFi RF `window_at`, NI-Incidents, Versionen) ist
einzeln gefangen: ein Fehler macht nur diesen Teil `unreadable` (bei `traffic` und
`utilization` je Router, `reason: "unreadable"`, Listen leer), geloggt wird nur der Fehlertyp
(`test_h_failing_traffic_and_rf_reads_make_parts_unreadable`). `status` der
Antwort ist `partial`, wenn ein Teil `unreadable` ist; ein ausgeschaltetes Modul macht die
Antwort **nicht** `partial`. Time Machine aus: `status: "off"`, alle Teile leer; Store noch
nicht geladen: `status: "unavailable"`, `reason: "not_loaded"`.

### 20.3 Regeln: abgeleitet und unbekannt

Ein Wert ist nie geraten. Es gilt:

- **abgeleitet** (`derived: true`): jeder rekonstruierte Wert. Grundlage je Router ist der
  Abschnitt `seen`, in dem der Router zu `at` verfolgt wurde: dessen Basis (Funk-Kanäle des
  ersten Polls mit Funkdaten, erstes gefestigtes Uplink/Rolle) plus jede Marke des Abschnitts
  bis `at` (Kanalwechsel, Funk aus/an, Uplink- und Rollenwechsel). „Erreichbar“ ist immer
  abgeleitet (in einem verfolgten Abschnitt ohne Ausfall); „nicht erreichbar“ trägt das
  `derived` der Ausfallmarke (abgeleitet bei LAN-Ausfall aus HA-Sicht oder bei Beginn vor dem
  Lauf des Verlaufs).
- **global unbekannt** (`known: false`), in dieser Reihenfolge: vor der Aufbewahrung
  (`beyond_retention`), in doppelt belegter Wanduhrzeit nach einem Rücksprung der Uhr
  (`clock_shift`, Review A, unten), in einer HA-Neustartlücke (`ha_gap`), in einer Beobachtungslücke der
  ganzen Flotte (`observation_gap`), außerhalb jeder Abdeckung des Verlaufs
  (`not_recorded`, auch: vor dem ersten Lauf der Time Machine und vor „Verlauf löschen“;
  die Zeit, die 1.51.0 aufzeichnete, ist **nicht** `not_recorded`, siehe Abschnitt 24), bis zu einer
  verlorenen Marke (`evicted`: eine Marke derselben Quote wurde vor Ablauf der Aufbewahrung
  verdrängt, gekürzt oder gelöscht).
- **Uhrsprung zurück** (Review A, feine Regel seit dem zweiten Review): Springt die Wanduhr
  um mehr als 300 s (`CLOCK_JUMP_S`) zurück, bei einem Poll oder Tick (Wanduhr gegen monotone
  Uhr seit der letzten Prüfung) oder über einen Neustart (gegen `saved_at` der Datei),
  schreibt die Engine die Marke `clock_shift` (`code: "backwards"`, `params.shift_s` < 0,
  `params.lead_s` = Sekunden seit der Prüfung davor, beim Neustart 0). Der Sprung liegt in
  diesen `lead_s` vor `ts`; unbekannt (`clock_shift`) ist nur die Wanduhrzeit
  `[ts − lead_s − 1, ts − shift_s + 1]` (je eine Sekunde für das Runden), die doppelt belegt
  sein kann. Davor wurde die Zeit nur einmal gelebt und bleibt bekannt; es wird **nichts**
  verdrängt (`lost` steigt nicht). Dafür beendet die Engine beim Sprung jeden verfolgten
  Abschnitt und öffnet einen neuen erst, wenn die Wanduhr die alte Zeit überholt hat
  (`_follow_from`, beim Start aus den gespeicherten `clock_shift`-Marken gelesen, auch nach
  einem Neustart in der doppelten Zeit); keine Marke des ersten Durchlaufs gerät so in einen
  späteren Abschnitt. Ein gefestigtes Uplink und eine gefestigte Rolle gehen als Basis in den
  ersten neuen Abschnitt über. Eine Lücke aus fehlgeschlagenen Polls vor dem Sprung bleibt
  eine Lücke (sie wird nicht wie eine kurze Lücke verworfen); `gap_s` ist nie negativ. Eine
  Marke ohne `lead_s` (1.51.0) behält den Beginn `ts + shift_s`. Ein Sprung **vor**
  (`code: "forwards"`) belegt nichts doppelt und macht nichts unbekannt (Tests `test_a_*` in
  `tests/test_tm_review_v1520.py` und `tests/test_tm_review_k_v1520.py`).
- **Uhrsprung zurück, Dauer und Neustart (1.52.1)**, Tests
  `tests/test_tm_clock_jump_v1521.py`:
  - *Aufbewahrung:* Eine `clock_shift`-Marke (rückwärts) bleibt, solange ihre doppelte Zeit
    in den 14 Tagen liegt (`Mark.kept_until` = Ende der doppelten Zeit, `tm_marks.shift_until`;
    `prune` und der Verdrängungs-Wasserstand nutzen es). Vorher wurde sie 14 Tage nach `ts`
    gelöscht; ein Neustart danach vergaß `_follow_from`, und die später datierten Marken des
    ersten Durchlaufs kamen als bekannte Werte zurück.
  - *Sprung vor in der Wartezeit:* Die Linie seit dem letzten Rücksprung lebte nur bis zur
    Wanduhrzeit kurz vor dem Sprung vor (`now − shift`). Die doppelte Zeit dieser Marke endet
    dort (`params.wait_s`, Sekunden ab `ts`, `ceil`; `_jumped_ahead`), aber nie innerhalb
    eines Abschnitts der Linie davor, der vor diesem Punkt begann (`_clean_cut`: dann am Ende
    dieses Abschnitts). `tm_state` spielt in einem Abschnitt jede Marke nach seiner Basis nach
    der Zeit ab, also auch die, die die Linie zurück dort datierte (ein Kanal, den der Router
    nie hatte). Der Verlauf vor einem falschen Rücksprung (z. B. ein Start 400 Tage zurück, den
    NTP eine Minute später korrigiert) ist so sofort wieder bekannt; liegt der Sprung in der
    Aufbewahrung, bleibt zusätzlich der Rest des Abschnitts unbekannt, in den er fiel (ein
    Abschnitt bekommt nach einem Tag eine neue Basis, `REBASE_S`, nicht solange ein Funk
    fehlt oder aus ist). Liegt die Uhr danach noch vor der alten Wanduhrzeit,
    ist der Rest bis dahin wieder doppelt belegt: eine neue Rücksprung-Marke ab jetzt. Der
    Sprung zählt nicht als gewartete Zeit (`_waits` wird um ihn verschoben, ebenso bei einem
    weiteren Rücksprung).
  - *Beim Start schon vorbei:* Ist die Uhr beim Start hinter der alten Wanduhrzeit der
    letzten Rücksprung-Marke (NTP stellte sie bei ausgeschaltetem HA, oder HA war so lange
    aus), endet deren doppelte Zeit beim `saved_at` der Datei (der letzte Lauf schrieb nichts
    danach; `_past_at_start`; ebenso nie innerhalb eines Abschnitts, `_clean_cut`), und die
    HA-Lücke beginnt an der alten Wanduhrzeit statt am falschen `saved_at`.
  - *Nicht gekürzt* wird eine doppelte Zeit, in die eine aufgezeichnete Linie vor geschrieben
    haben kann (`_ahead_inside`: eine `clock_shift`-Marke `forwards` mit kleinerer `seq` und
    `ts` vor dem Ende der doppelten Zeit). Deren Werte sind vielleicht falsch datiert; sie
    bleiben unbekannt. **Ausnahme** beim Sprung vor im Betrieb (`_undoes`, nicht beim Start):
    Der Sprung vor um `shift` hebt den Rücksprung `B` auf, wenn `shift + B.shift_s` zwischen
    −300 und +300 s liegt (beide gegen die monotone Uhr gemessen); hat `B` `lead_s` 0 (beim
    Start geschrieben, die Zeit, die HA davor aus war, steckt nicht in `B.shift_s`), reicht
    `shift + B.shift_s` ≥ −300. Dann läuft die Uhr wieder auf der Linie vor `B` weiter, die
    Linie dazwischen war die falsche, und die doppelte Zeit wird wie oben gekürzt. Das ist der
    Fall eines Geräts ohne Uhrenbatterie, das nach einem harmlosen Sprung vor (zehn Minuten,
    oder das NTP eines früheren Starts weit zurück) wieder weit zurück startet (Tests
    `test_p1_*`). **Grenze, eine bewusste und dokumentierte Ausnahme von „wahr oder
    unbekannt“**, auf zwei Wegen: (1) Eine falsche Zeitquelle geht zweimal um dieselbe Spanne
    vor (`test_a_clock_set_ahead_again_by_the_same_amount_is_trusted`). (2) Nach einem
    Rücksprung, den ein Start fand (die Uhr wurde gestellt, während HA aus war; `lead_s` 0),
    zählt in der restlichen Wartezeit jeder größere Sprung vor, z. B. ein Host, der länger
    angehalten war als die restliche Wartezeit
    (`test_a_jump_back_found_at_a_start_trusts_any_larger_jump_ahead`). Dann gilt die neue
    Uhr als richtig, und die Werte, die die frühere Linie vor aufzeichnete, lesen sich als
    bekannt, zu einem Datum, das um den alten Vorlauf zu spät ist. Es sind echte Messungen mit
    falschem Datum; 1.52.0 zeigte dort „unbekannt“. Gelöscht wird nichts.
  - *Nichts wird gelöscht* (Entscheidung nach dem zweiten Review des PR). Ein früherer Stand
    löschte nach einem Tag Warten, was ein aufgezeichneter Sprung vor „erklärte“
    (`_explained_from`, nach einer Kopie `.bak`). Das Review fand drei Fälle, in denen das
    echten Verlauf löschte, und jede strengere Regel scheitert an demselben Punkt: Ein Sprung
    vor um X und später ein Sprung zurück um X sehen gleich aus, ob die Linie dazwischen vor
    stand (dann wäre Löschen richtig) oder die Linien davor und danach zurück standen (dann
    löscht es die Wahrheit), z. B. wenn die Time Machine zum ersten Mal mit einer Uhr weit
    zurück startet und NTP nur den Sprung vor hinterlässt. Darum löscht die Engine wegen eines
    Uhrsprungs nichts (kein `drop_after`, kein `async_backup`), und die Wartezeit geht immer
    bis zur alten Wanduhrzeit, ohne Obergrenze, außer ein Sprung vor kürzt sie (oben) oder
    „Verlauf löschen“ beendet sie. Schlimmster Fall: so lange ohne Aufzeichnung, wie die Uhr
    zurück stand. Ein Sprung vor, der die Uhr nicht bis zur alten Zeit bringt, verkürzt das
    Warten nur um seine Größe.
  - *Langes Warten:* `_waits` hält je Rücksprung-Marke die Wanduhrzeit des Sprungs (`0` für
    einen Sprung ohne Marke), verschoben um jeden späteren Uhrsprung (Uhrsprünge sind keine
    gewartete Zeit; über Neustarts zählt die Wanduhrzeit des Sprungs). Läuft eine Wartezeit
    `CLOCK_WAIT_LONG_S` (86 400 s; geprüft bei jedem Poll, Tick und Start, `_check_wait`),
    steigt der Zähler `clock_waits_long` und eine Info steht im Log (nur Zahlen), einmal je
    Wartezeit und Lauf. Sonst hat der Wert keine Wirkung.
  - *Uhr vor, dann zurück:* Was die Linie vor datierte, bleibt in der Datei und liegt in der
    doppelten Zeit des Rücksprungs; es liest sich `clock_shift` (unbekannt), solange die
    Marke bleibt, und fällt danach mit der Aufbewahrung weg. Die Zeit, die die Uhr vor stand,
    wird danach ohne Aufzeichnung noch einmal gelebt (`test_a_clock_ahead_then_corrected_*`,
    `test_gap2_*`).

    Einträge anderer Module (Audit-Protokoll, Konfigurations-Backups), die in der ersten
    Zeitlinie datiert sind, stehen weiter in der Liste der Zeitleiste; sie liegen in deren
    eigenem Speicher.
  - *Abschnitte und offene Intervalle am Sprung:* Bei jedem Sprung (vor oder zurück) endet
    jeder verfolgte Abschnitt bei der letzten Prüfung davor; bei einem Rücksprung im Betrieb
    enden offene Intervalle dort mit `unknown` (eine offene Lücke behält `gap_s`), und was
    noch läuft, wird ab jetzt neu erfasst. Sonst beanspruchte ein Abschnitt über einen
    Sprung vor die übersprungene Zeit, oder die neue Linie schloss das Intervall der alten
    bei einer früheren Wanduhrzeit (vom Orakel gefunden).
  - *Neustart:* `_jumps_from_index` liest `_follow_from` und die laufenden Wartezeiten aus den
    Marken (eine mit `wait_s` ist entschieden und wartet nicht mehr); stehen `lost`-Werte mehr
    als 300 s vor jetzt (die Marke selbst wurde verdrängt), wartet die Engine bis dahin
    (`_lost_ahead`; auch wenn danach eine andere Rücksprung-Marke gekürzt wird,
    `_follow_until`).
    `_unseen_jump`: Liegt das Neueste der Datei (Marken der Infrastruktur-Quote, Abschnitte)
    mehr als 300 s nach `saved_at`, sprang die Uhr vor dem Stopp zurück, ohne dass ein Poll
    oder Tick es sah; der Start schreibt dann `clock_shift` bei `saved_at` mit
    `lead_s` = 600 (`UNSEEN_LEAD_S`) und wartet wie sonst. Die doppelte Zeit endet am Neuesten
    jeder Quote (eine Client- oder Modul-Marke kann später datiert sein); Auslöser bleibt nur
    die Infrastruktur.
  - *Löschen:* „Verlauf löschen“ beendet jede Wartezeit, „Nur Client-Verläufe“ nicht.
  - *Ausfallbeginn:* Der Flotten-Tracker kann einen Beginn aus dem ersten Durchlauf
    behalten. Liegt er nach jetzt oder in der doppelten Zeit irgendeiner `clock_shift`-Marke
    (der ganzen, ohne `wait_s`), wird er nicht übernommen (`_outage_since`): Der Ausfall
    beginnt bei der offenen Lücke, die er übernimmt, sonst jetzt; dasselbe gilt für den
    Beginn eines LAN-Ausfalls.
  - *Speicher:* kein neuer Schlüssel, `wait_s` ist ein Marken-Parameter. 1.52.0 und 1.51.0
    laden eine 1.52.1-Datei ohne Verlust (ihr `_migrate` nimmt jede Unterversion von
    Version 1, `unpack` jeden gültigen Parameter); sie warten ohne `wait_s` wieder bis zur
    alten Wanduhrzeit, zeigen aber nichts Falsches: Was eine Linie vor datierte, liegt in der
    doppelten Zeit ohne `wait_s`.
- **LAN-Ausfall** (Review K): Die Marke `lan_down` beginnt, wenn der **letzte** Router
  ausfiel (spätester Beginn der eigenen Ausfälle), nicht beim ersten einzelnen Ausfall. Ein
  Router gilt erst ab seinem eigenen ersten fehlgeschlagenen Poll als „nicht erreichbar“;
  das gilt auch für eine zurückdatierte Marke einer 1.51.0-Datei (deren Beginn zählt für die
  anderen erst ab dem Zeitpunkt, an dem alle ausgefallen waren). Meldet sich ein Router,
  während der LAN-Ausfall läuft, gleicht der nächste Poll die Ausfälle ab
  (`test_k_*`).
- **je Router unbekannt**: eigene Beobachtungslücke (`observation_gap`); Router zu `at` nicht
  verfolgt oder vor seinem ersten Funk-/Topologie-Wert (`not_observed`); Funk und Topologie
  während eines Ausfalls (`router_down`, `lan_down`); eine Marke passt zu keinem oder zu
  mehreren Funks eines Bands (`ambiguous_radio`); eine Marke passt nicht zum Zustand, den
  sie ändert (`inconsistent`); Basis des Abschnitts vor der Aufbewahrung bzw. vor einer
  verlorenen Marke (`beyond_retention`, `evicted`); Uplink und Rolle in den 900 s
  (`TOPOLOGY_SETTLE_S`: zwei Polls des langsamsten Intervalls 300 s plus einer Reserve) vor
  dem **ersten Poll**, der den neuen Wert sah (Review B: `params.since` der Marken
  `uplink_changed` und `router_role_changed`, wenn er vor der Bestätigung liegt; dazwischen
  fehlgeschlagene Polls setzen die Entprellung nicht zurück), bis zur Marke, und vor dem Ende
  eines Abschnitts, auf den kein nahtloser folgt (`settling`: der Wechsel kann bis zu zwei
  Polls früher begonnen haben). Hält die Engine gerade einen unbestätigten Kandidaten, sind
  Uplink und Rolle des offenen Abschnitts ab 900 s vor dessen erstem Poll bis „jetzt“
  `settling` (`test_b_uplink_candidate_failed_polls_then_confirm`).
- **verdrängte Marken je Router** (Review J): Entfernt „Router entfernen“ Marken anderer
  Router, die ihn als Peer nennen (Uplink-Wechsel), ist nur **deren** Verlauf bis zu diesen
  Marken `evicted` (Speicher `lost_routers`), nicht die ganze Flotte. Client- und
  Flotten-Marken mit ihm als Peer heben `lost` der Quote für alle
  (`test_j_forget_router_raises_lost_for_the_peers_only`).
- **offenes Intervall verdrängt** (Review D): Wird ein offenes Intervall (etwa ein laufender
  Ausfall) verdrängt, gilt seine Quote bis zu seinem späteren Ende als verloren, bis dahin bis
  „jetzt“ (auch in der Datei: `lost` wird mit diesem Stand geschrieben)
  (`test_d_evicted_open_outage_stays_unknown_until_its_end`).
- **Breite nach „Funk an“**: unbekannt (null), denn die Marke trägt sie nicht.
- **Clients**: unbekannt vor dem Einschalten der Client-Verläufe bzw. außerhalb deren Abdeckung
  (`not_recorded`), bis zu einer verlorenen Client-Marke (`evicted`); `partial` mit `flapping`
  ab der ersten Marke `client_flapping` (Tagesgrenze 200 Marken je Client erreicht), solange
  der betroffene Client verbunden sein kann, ohne dass eine Session ihn zeigt: bis zu seiner
  nächsten aufgezeichneten Session nach der letzten gedeckelten Marke, auch über Mitternacht
  (Review G, `test_g_a_capped_client_keeps_the_list_partial_past_midnight`). Auch ein
  Trennen oder die `client_flapping`-Marke des nächsten Tags beenden das; war die letzte
  gedeckelte Marke ein Trennen (Parameter `gone`, im Panel „zuletzt getrennt“), endet
  `partial` mit dem Ende der Marke (zweites Review, `test_g_*` in
  `tests/test_tm_review_k_v1520.py`).
- **„Client vergessen“** senkt die Client-Zahlen der Vergangenheit (Zustand, Vergleich) um
  diesen Client, **ohne** die Zeitpunkte als unbekannt oder unvollständig zu markieren
  (gewollt; `test_j_forget_client_lowers_past_counts_without_a_mark`).
- **Verlauf löschen, Neuladen, Neustart** (Review C): Nach „Verlauf löschen“ (auch nur
  Clients), dem Neuladen eines Routers und dem Laden nach einem Neustart setzt die Engine
  laufende Ausfälle (`router_down`, `lan_down`), Beobachtungslücken und aus gebliebene Funks
  ab diesem Moment fort (abgeleitet). Eine Lücke, die über das Löschen läuft, zählt für die
  Lückenschwelle ab ihrem ersten fehlgeschlagenen Poll (Tests `test_c_*`). Ein aus
  gebliebener Funk bleibt auch nach „Verlauf löschen“ vermerkt (Review E, die Liste wird vor
  dem Löschen der Marken gelesen; `test_e_*`).
- **Zeitauflösung** ist der Poll: Ein Wert gilt ab dem Poll, der ihn sah („aus“ ab dem ersten
  Poll, der den Funk vermisste), bis zur nächsten Marke. Ein Ausfall gilt ab dem ersten
  fehlgeschlagenen Poll; ein fehlgeschlagener Poll kürzer als die Lückenschwelle der Engine
  hinterlässt keine Lücke, der Router gilt dort als erreichbar. Ausnahme nach einem Neustart
  (Review L): Bis zum ersten erfolgreichen Poll eines Routers bleibt eine Lücke stehen, auch
  eine kurze; erreichbar ist er erst ab diesem Poll
  (`test_l_after_a_restart_a_router_is_reachable_from_its_first_good_poll`).

Geprüft über die echten Schreibwege (`tests/test_tm_state_v1520.py`): Kanalwechsel genau auf
der Marke, kurz davor und danach, vor dem Start und hinter der Aufbewahrung; Funk aus und an;
Ausfall und Beobachtungslücke; Flottenausfall; Uplink- und Rollenwechsel mit
`settling`; Neustartlücke; neuer Funk teilt den Abschnitt; verdrängte Marken; „Verlauf
löschen“; echte 1.51.0-Datei. Dazu ein Zufalls-Orakel (6 Startwerte, je rund 6000 Abfragen:
ein Router-Leben mit Ausfällen, Lücken, Kanal-, Funk-, Uplink- und Rollenwechseln,
Neustarts und Verdrängung): jede Antwort ist der mitgeführte wahre Zustand **oder**
unbekannt, nie etwas Falsches
(`test_randomised_oracle_never_tells_something_wrong`). Seit dem Review zusätzlich das Orakel
des Reviewers (`tests/test_tm_oracle_review_v1520.py`): drei Router, 400 Poll-Runden, die
Wahrheit allein aus den Eingaben der Polls, Modi `base`, `evict` (Quote 25), `clear`,
`remove` und `jumpfwd`, je 12 feste Startwerte (darunter 4, 32 und 33); jede Abweichung, die
nicht „unbekannt“ sagt, ist ein Fehler. Seit dem zweiten Review auch dessen erweitertes
Orakel (`test_extended_oracle_is_the_truth_or_unknown`): Wanduhr mit Epochen für doppelt
belegte Zeit, Modi mit Uhrsprüngen zurück und vor, Neustarts an beliebiger Stelle (sauber
und unsauber), fehlschlagenden Kandidaten, Flottenausfällen, „Verlauf löschen“ (auch
während eines Ausfalls), Verdrängung (auch offener Intervalle) und aus gebliebenen Funks,
je mit und ohne Auswertung zwischendurch, 14 feste Startwerte. Ein Messtest
(`test_a_one_jump_back_leaves_the_time_before_it_known`) prüft, dass nach einem Sprung
zurück die Zeit davor bekannt bleibt (Anteil bekannter Antworten je beobachtetem
Router-Moment vor dem Sprungziel, 40 Startwerte: Erreichbarkeit 15 % → 71 %, Funk 24 % →
116 % (je Funk eine Antwort, daher über 100 %), Topologie 7 % → 33 %; das entspricht dem
Stand vor der groben Regel).

### 20.4 Rechte

Wie die Zeitleiste (Abschnitt 7): 401 ohne Anmeldung, 403 ohne Zugang zum Enterprise-Tab,
410 wenn die Integration entladen ist. Router-Tabelle, Intervalle der Gruppen für alle
(`NON_ADMIN_GROUPS`), NI-Incidents ohne Client-Bezug und die Stundenwerte von Traffic (WAN)
und WiFi RF (je Band) sehen alle Nutzer mit Zugang. Versionen nur Administratoren
(`config.reason: "admin_only"` für die anderen), Clients nur Administratoren bei
eingeschalteten Client-Verläufen. Ein Nicht-Admin bekommt für gesperrte Teile `state:
"off"` mit `admin_only` und leere Listen, keine Zähler.

## 21. Phase D: Vergleich zweier Zeitpunkte

`GET /api/openwrt_router/enterprise/timemachine/compare?t1=…&t2=…[&router_id=…]`. `t1` und
`t2` sind nötig, `t1 < t2` (sonst 400 `window`/`empty`), höchstens 14 Tage auseinander
(`window`/`too_large`), nicht in der Zukunft. Gleiche Rechte wie `/state`.

Antwort: `v`, `status`, `reason`, `generated_at`, `t1`, `t2`, `before` und `after` (zwei
Zustände wie `/state`, ohne Client-Einträge, nur mit `per_router` und `total`), `changes`.
Beispiel aus `test_compare_route_names_only_the_differences` (`changes`, gekürzt):

```json
{
 "routers": [{
   "router_id": "rtr_1111…", "router_name": "Router 1",
   "reachable": {"from": true, "to": true, "state": "same"},
   "role":   {"from": null, "to": null, "state": "unknown"},
   "uplink": {"from": null, "to": null, "state": "unknown"},
   "radios": [{"key": "5g0", "band": "5g",
               "from": {"channel": 36, "width": 80, "state": "up"},
               "to":   {"channel": 44, "width": 80, "state": "up"},
               "state": "changed", "reason": null}],
   "clients": {"from": 2, "to": 1, "delta": -1}
 }],
 "marks": {"count": 3, "by_group": {"clients": 2, "radio": 1}},
 "incidents": {"state": "off", "reason": "not_running", "opened": [], "resolved": [], "truncated": false},
 "config_versions": {"state": "off", "reason": "module_off", "items": [], "total": 0,
                     "truncated": false, "diffs": []}
}
```

- `changes.routers[]`: nur Router mit einem Unterschied. Je Wert `state` `same`, `changed`
  oder `unknown` (mindestens eine Seite unbekannt, **nie** als Änderung gezählt). Seit 1.52.2
  (additiv) tragen `reachable`, `role` und `uplink` zusätzlich `from_reason` und
  `to_reason`: den Grund der jeweiligen Seite (null, wenn diese Seite bekannt ist). `from` und
  `to` sind wie bisher null auf einer unbekannten Seite; ein bekanntes null (Uplink: „kein
  vorgeschalteter Router“) ist nur an `to_reason: null` bzw. `from_reason: null` zu erkennen.
  Die Werte selbst stehen vollständig in `before` und `after`; der `after`-Block ist genau die
  Antwort von `/state` für `t2` (`test_the_after_block_of_compare_is_the_state_at_the_same_moment`),
  und das Panel liest jede Zelle seit 1.52.2 von dort (Abschnitt 25.3). Ein deaktivierter
  Router (`entry: "disabled"`) steht hier wie jeder andere (unbekannte Werte: `unknown`); das
  Panel blendet ihn aus, wenn er zu beiden Zeitpunkten unbekannt ist. `radios`
  nur Funks, die nicht `same` sind: `changed` (Kanal, Zustand oder Breite anders),
  `unknown` (Funk nur auf einer Seite, eine Seite unbekannt oder eine Breite nach „Funk an“
  unbekannt). Ist der ganze Funk-Block einer Seite unbekannt, steht dort ein Eintrag mit
  `key: null`, `state: "unknown"` und dem Grund. `clients` nur für Administratoren und nur, wenn beide Client-Listen bekannt sind,
  sonst null.
- `marks`: eigene Marken (`tm_index`) mit **`t1 ≤ ts < t2`** je Gruppe, dasselbe halboffene
  Fenster wie die Zeitleiste mit `from=t1&until=t2` (Review F): ein Klick auf „in der
  Zeitleiste zeigen“ zeigt genau die gezählten Marken. `router_id` wirkt als Gleichheit wie
  dort. Client-Marken zählen nur für Administratoren bei eingeschalteten Client-Verläufen.
  Vorfälle und Versionen bleiben `t1 < ts ≤ t2`, passend zu den beiden Zuständen (was zu `t1`
  schon galt, ist kein Unterschied).
- `other_sources` (Review F, additiv): Einträge der **anderen** Quellen der Zeitleiste
  (Audit, NI-Ereignisse und -Incidents, Security Center, …) im selben Fenster, über denselben
  Lesepfad und mit denselben Rechten (jede Quelle über ihren Leser, die Doppel-Regel der
  Zeitleiste, deren Rechte und Filter; `tm_index` wird nur gelesen, wenn NI-Ereignisse im
  Fenster liegen, denn nur für sie braucht die Doppel-Regel die eigenen Marken). Gezählt wird
  nur: keine Zusammenführung, keine Sortierung, keine Seite.
  `{"state": "ok" | "unreadable", "reason": null | "unreadable", "count", "truncated",
  "unreadable": [Quellen-IDs]}`. `count` ist die genaue Zahl bis 500; darüber oder wenn eine
  Quelle gekürzt gelesen wurde, `truncated: true`. Gleich der Zahl der Einträge anderer
  Quellen, die die Zeitleiste für dasselbe Fenster listet
  (`test_f_other_sources_count_ni_events_without_their_doubles`, mit echten NI-Doppeln,
  als Administrator und als Nutzer). Eine
  Quelle, die nicht läuft oder nicht geladen ist, hat nichts im Fenster und ist nicht
  `unreadable`. Ein Vergleich ist erst „nichts geändert“, wenn `marks.count == 0`,
  `other_sources.state == "ok"`, `other_sources.count == 0` und nicht `truncated`
  (`test_f_compare_counts_like_the_timeline_and_names_other_sources`).
- `incidents.opened` / `resolved`: NI-Incidents, die dazwischen geöffnet bzw. gelöst wurden
  (je höchstens 100, `truncated`).
- `config_versions` (nur Administratoren): Versionen dazwischen (höchstens 100) und `diffs`
  je Router (`from_version_id` → `to_version_id`), die das Panel an den
  Configuration-Manager-Vergleich übergeben kann.

## 22. Phase E: Clients über Module, Export

### 22.1 Ein Client über Module

Security Center, Traffic und WiFi RF schreiben Audit-Einträge mit ihrem eigenen
Client-Pseudonym (`client_ref`, `cli_…`, je Modul ein anderer Schlüssel). Die Time Machine
vergleicht diese Werte **nie** untereinander. Jedes Modul hat eine prozessinterne Funktion
„Pseudonym für MAC“ (`client_ref_for_mac`, in `security_center.py`, `traffic_correlate.py`,
`rf_center.py`, rein lesend). Für einen Audit-Eintrag mit `client_ref` rechnet die Time
Machine (`tm_sources.ClientResolver`) für die MACs, die ihr eigener Client-Recorder kennt, das
Pseudonym **des schreibenden Moduls** aus. Passt genau eine MAC, trägt die Marke das
TM-Pseudonym `tmc_…`. Keine oder mehrere passende MACs, ein Fehler im Modul oder ein Modul
ohne Funktion: keine Zuordnung, die Marke ist eine Client-Marke ohne `client` und fällt aus
der Antwort (gezählt in `omitted_client_marks`). Nichts wird zwischengespeichert, „Client
vergessen“ wirkt sofort. Nur für Administratoren mit eingeschalteten Client-Verläufen; der
`client`-Filter der Zeitleiste findet dann die Einträge aller Module: neuer Schlüssel
`client=tmc_…` an `GET …/timemachine/timeline` (1.52.0, additiv, nur Administratoren; ein
Nicht-Admin bekommt 400 `admin_only`, bevor der Wert gelesen wird, ein ungültiger Wert 400
`client`/`invalid`). Eine Marke mit `client` sehen Nicht-Admins in keiner Gruppe.
Test: `test_two_modules_same_mac_different_pseudonyms_one_client` (gleiche MAC, zwei Module,
zwei verschiedene `cli_`-Werte → ein `tmc_`; das Pseudonym des einen Moduls unter dem Namen
des anderen → keine Zuordnung; kein `cli_` und keine MAC in der Antwort; nach „vergessen“
keine Zuordnung mehr).

### 22.2 Export

`GET /api/openwrt_router/enterprise/timemachine/export?from=…&until=…` (`tm_export.py`).
**Nur Administratoren** (sonst 403, ohne Anmeldung 401). Schlüssel wie die Zeitleiste ohne
`limit`, `spans` und `client` (`from`, `until`, `source`, `kind`, `router_id`,
`min_severity`, `cursor`); dieselben 400-Fehler.

- Antwort mit `Content-Disposition: attachment; filename="openwrt-router-time-machine.json"`
  und `Cache-Control: no-store`. Es wird nichts auf die Festplatte geschrieben; die Datei
  speichert der Browser.
- Inhalt: `v`, `kind` (`openwrt_router.time_machine.export`), `status`, `reason`,
  `generated_at`, `window`, `limit` (5000), `marks`, `spanning` (Intervalle, die ins Fenster
  hineinreichen), `sources` (wie die Zeitleiste plus `count` der exportierten Marken),
  `truncated`, `spanning_truncated`, `next_cursor`, `omitted_client_marks`. Jede Marke hat
  die Felder der Zeitleiste (Abschnitt 5.3).
- **Keine Namen und Adressen**: `router_name`, `client_name`, `text` und die Namen in `peers`
  sind immer null; die IDs bleiben. **Client-Marken fehlen ganz** (nur ihre Anzahl in
  `omitted_client_marks`): ein stabiles Pseudonym in einer Datei, die Home Assistant verlässt,
  würde die Bewegungen einer Person verknüpfen.
- **Harte Grenze** 5000 Marken je Antwort (`EXPORT_MAX_MARKS`). Mehr → `truncated: true` und
  `next_cursor`, als `cursor` mit demselben Fenster zurückschicken. Nichts fällt stillschweigend weg.
  Client-Marken werden schon in der Abfrage weggelassen (Review I): eine Seite füllt sich
  mit bis zu 5000 Marken ohne Client, statt dass Client-Marken die Seite verbrauchen.
  `omitted_client_marks` zählt die weggelassenen Client-Marken **des ganzen Fensters** (eigene
  und zugeordnete Audit-Einträge), auf jeder Seite gleich. Die Schleife über die Marken gibt
  alle 1000 Marken an die Ereignisschleife ab (`test_i_export_pages_fill_and_the_loop_yields`).
- **Audit**: Jeder Export schreibt vor der Antwort den Audit-Eintrag `time_machine.exported`
  (sicherheitsrelevant, Nutzer als Akteur, nur Zahlen: `marks`, `spanning`,
  `omitted_client_marks`, `truncated`, `window_s`). Lässt er sich nicht schreiben, gibt es
  keinen Export: 503 `refused`, `reason: "audit_unavailable"`.

Tests: `test_export_is_audited_nameless_and_for_admins_only`,
`test_export_limit_pages_with_the_cursor` (drei Seiten, keine Marke doppelt oder verloren).

## 23. Phase F: Sprungziele

Das Feld `ref` jeder Marke (Abschnitt 5.3) reicht zusammen mit `kind` aus. Es kommt **kein
neues Feld** an die Zeitleisten-Marken (die Panel-Fixtures bleiben gültig). Das Panel bildet
`ref.module`/`ref.type` so ab (Referenz im Backend: `tm_sources.JUMP_TARGETS`, `KIND_TABS`,
`KIND_NO_TAB`, `jump_target()`):

| `ref.module` | `ref.type` | Tab | Objekt |
|---|---|---|---|
| `core_audit` | `event` | nach `kind` (unten) | Audit-Eintrag `ref.id` |
| `core_audit` | `drift` | `config` | Audit-Eintrag `ref.id` |
| `config_manager` | `version` | `config` | Version `ref.version_id` |
| `security_center` | `incident` | `security` | Incident `ref.id` |
| `security_center` | `drift` | `security` | Drift `ref.id` |
| `security_center` | `timeline` | `security` | – (der Tab) |
| `time_machine` | `mark` | `timemachine` | – (der Tab) |
| `network_intelligence` | `event`, `incident` | **keiner** (NI lebt in den eigenen Ansichten des Panels) | – |

`core_audit`/`event` nach `kind`: `config_event`, `config_drift` → `config`;
`security_incident` → `security`; `rf_event` → `wifi`; `diag_finding` → `diagnostics`;
`traffic_anomaly` → `traffic`. Ausdrücklich **kein Tab**: `registry_event`,
`security_event` (Berechtigungen und Speicher des Kerns), `core_event`, `audit_event`. Die
Tab-IDs sind die des Panels (`config`, `security`, `diagnostics`, `traffic`, `wifi`,
`timemachine`). Eine unbekannte Kombination führt nirgends hin.

Die neuen Antworten `/state` und `/compare` tragen bei Incidents und Versionen zusätzlich
`target: {"tab", "object_type", "object_id", "version_id"}` oder null.

Test: `test_every_ref_the_backend_makes_has_a_target_or_explicitly_none` liest jedes
`ref_of(…)` im Paket (AST) und prüft, dass jede erzeugte Kombination in `JUMP_TARGETS` steht
und jede Audit-Art in `KIND_TABS` oder `KIND_NO_TAB`.

## 24. Speicher 1.2, Leistung, Grenzen (D bis F)

**Speicher 1.2** (`.storage/openwrt_router.time_machine`, `minor_version` 1 → 2, rein
additiv): `seen` (je Router höchstens 64 verfolgte Abschnitte mit Basis), `clients_cov`
(wann der Client-Recorder lief), `lost` (je Quote: bis wann Marken vor Ablauf fehlen). Eine
1.51.0-Datei lädt unverändert (die Marken bleiben, die drei Schlüssel fehlen). Die Zeit, die
1.51.0 aufzeichnete, ist danach **global bekannt** (ihre Abdeckung `coverage` bleibt), aber kein
Router war darin verfolgt (kein `seen`): Erreichbarkeit, Rolle, Uplink und Funk sind je Router
`not_observed`, außer was eine aufgezeichnete Marke selbst ergibt (ein laufender Ausfall: „nicht
erreichbar“), Clients `not_recorded`. `not_recorded` (global) ist nur die Zeit außerhalb jeder
Abdeckung. (Bis 1.52.1 stand hier, die Zeit davor sei `not_recorded`; der Test unten prüft das
Obige.) Beim nächsten Speichern wird sie als 1.2 geschrieben, und genau diese
drei Schlüssel kommen dazu (Test mit einer echten 1.51.0-Datei,
`test_a_real_1510_file_loads_unchanged_and_saves_as_12`). Seit dem
Review kommen hinzu, ebenfalls additiv: `lost_routers` (je Router: bis wann seine
Infrastruktur-Marken fehlen, Review J; nur geschrieben, wenn nicht leer) und in einem
`seen`-Abschnitt ein optionales achtes Feld (Zahl der Funks, die über einen Neustart aus
blieben, Review E; nur wenn > 0). Zurück auf 1.51.0 (vom Review bestätigt): Die Datei lädt
ohne Verlust; die zusätzlichen Schlüssel bleiben in der Datei stehen, bis 1.51.0 selbst
speichert (dann fallen sie weg); nach einem erneuten Update ist die Zeit davor wie oben
global bekannt mit unbekannten Router-Werten (`not_observed`). Bei ausgeschalteter Time Machine: kein Lesen, kein
Schreiben (unverändert).

Die Engine schreibt dafür zusätzlich (nur bei eingeschalteter Time Machine, ohne
Router-Aufruf): Abschnitt öffnen/schließen bei jedem Poll bzw. Lücke, neue Basis nach 24 h
(`REBASE_S`) oder nach einer verlorenen Marke, sofern gerade kein Funk fehlt und die Topologie
gefestigt ist.

**Leistung.** Bedingungen beider Messungen: 15 000 Marken (3000 Kanalwechsel, 2000
Audit-Verweise, 10 000 Client-Sessions), Client-Verläufe an, Aufruf der Funktionen ohne HTTP,
VM 103 (Python 3.13), je drei Läufe, „längster Block“ = längste Strecke ohne Abgabe an die
Ereignisschleife.

| Abfrage | 1 Router, Marken in 3 h (`test_cost_of_state_compare_and_export_on_a_full_store`) | 64 Router, Marken über 13 Tage, je Router ein Abschnitt (Export: `test_i_export_pages_fill_and_the_loop_yields[64]`; `/state`, `/compare` und „vorher“: einmalig mit dem Messtest des Reviews, nicht in der Suite) |
|---|---|---|
| `/state` | 8–9 ms (Block 5–6 ms) | 6 ms (2 ms), bei „jetzt“ 8–9 ms (5 ms) |
| `/compare` | 13–15 ms (erster Aufruf), 12–13 ms (weitere); ohne `other_sources` 9–13 ms | 21–26 ms (erster), 18–23 ms (weitere); Fenster 13 Tage |
| `/export` vorher (Stand `d39fd4c`) | 56–63 ms (7–9 ms) | 73–82 ms (18–24 ms), erste Seite 1675 Marken, 4 Seiten |
| `/export` nachher | 22–26 ms (4 ms) | 27–29 ms (4 ms), eine Seite mit allen 5000 Marken ohne Client |

`/compare` las `other_sources` zuerst über die ganze Zeitleiste (alle Marken auch des
eigenen Index in Wörterbücher, zusammenführen, sortieren, Seite von 500): 1 Router 21–25 ms,
64 Router 29–48 ms. Seit 1.52.0 zählt es nur (oben). Einen teuren kalten ersten Aufruf gibt
es nicht (erster Aufruf 1–5 ms über den weiteren). Einzelne Läufe können durch die
Speicherbereinigung von Python einen längeren Block zeigen (wie bei der Zeitleiste, oben);
die Tests zählen deshalb Arbeit, keine Zeit.

Die Tests prüfen **gezählte Arbeit, keine Zeit** (eine Zeitgrenze hält auf einem geteilten
CI-Runner nicht; dort maß der Test für `/compare` einmal einen Block von 0,6 s): Python-Aufrufe ins Paket bei einem
Viertel und beim vollen Speicher (höchstens 6-fach, quadratisch wäre etwa 16-fach), die
meisten Aufrufe zwischen zwei Abgaben an die Ereignisschleife (höchstens 100 000; heute
höchstens 70 013, die Suche über den ganzen Index in `MarkIndex.window`), die Zahl der
Abgaben auf dem vollen Speicher (fällt, wenn eine Schleife nicht mehr abgibt) und ein
Durchlauf des Speichers je Antwort (`Snapshot._take` genau einmal je Marke, auch beim
Vergleich). Jede dieser Prüfungen schlägt an, wenn man eine der Abgaben (Schnappschuss,
Index-Leser, Export) abschaltet oder einen quadratischen Schritt einbaut (einmal von Hand
geprüft). Die Marken werden einmal je Abfrage linear durchlaufen
(Abgabe alle 2000 Marken), danach je Router und Zeitpunkt nur deren eigene Marken; nichts ist
quadratisch in der Zahl der Marken. Harte Grenzen: 64 Router, 100 Intervalle, 100 Incidents,
100 Versionen, 500 Clients je Seite, 5000 Marken je Export-Seite.

**Bekannte Grenzen.**

- Ein Rücksprung der Uhr um mehr als 300 s macht die doppelt belegte Spanne unbekannt und
  verfolgt danach nichts, bis die Wanduhr die alte Zeit überholt hat oder ein Sprung vor die
  Wartezeit beendet (bei einer Stunde Rücksprung also rund eine Stunde ohne Aufzeichnung,
  `not_recorded`; Abschnitt 20.3).
- **Wegen eines Uhrsprungs wird nichts gelöscht** (20.3). Stand die Uhr **zurück** und wird
  nicht vorgestellt (z. B. Start ohne RTC und ohne NTP), wird nichts verfolgt, bis die Uhr
  die alte Zeit erreicht: ohne Obergrenze, schlimmstenfalls so lange, wie die Uhr zurück
  stand (bis „Verlauf löschen“). Ein Sprung vor in dieser Zeit, der die Uhr nicht bis zur
  alten Zeit bringt, verkürzt das nur um seine Größe. Der Verlauf davor bleibt erhalten;
  wird die Uhr vorgestellt, bleibt unbekannt die Zeit, die die Uhr zurück lief, und der Rest
  des Abschnitts, in den sie fiel (meist bis zu einem Tag). Fiel sie in den letzten
  Abschnitt vor dem Stopp, bleibt die Zeit bis zum Stopp unbekannt wie in 1.52.0.
- **Funk dauerhaft aus** (zweites Review, P2-2): Solange ein Funk fehlt oder aus ist, bekommt
  ein Abschnitt keine neue Basis (`REBASE_S`); fällt ein korrigierter Rücksprung in so einen
  langen Abschnitt, bleibt die Zeit bis zu dessen Ende unbekannt, bis zur ganzen Spanne des
  Rücksprungs, für die ganze Aufbewahrung (`_clean_cut`). Offen (`TODO.md`).
- Stand die Uhr **vor** und wurde zurückgestellt: So lange, wie die Uhr vor stand, wird nichts
  verfolgt (eine Minute 400 Tage vor: 400 Tage). Was die Linie vor aufzeichnete, bleibt in der
  Datei und liest sich unbekannt (`clock_shift`), bis es mit der Aufbewahrung wegfällt. Ging
  die Uhr schon beim Start vor (kein gesehener Sprung vor), gilt dasselbe. Bewusste,
  dokumentierte Ausnahme von „wahr oder unbekannt“ (20.3, `_undoes`), auf zwei Wegen: Die Uhr
  wird danach genau um dieselbe Spanne wieder vorgestellt; oder sie wurde zurückgestellt,
  während HA aus war (der Start fand den Rücksprung), und in der restlichen Wartezeit kommt
  irgendein größerer Sprung vor (z. B. ein Host, der länger angehalten war als die restliche
  Wartezeit). Dann gilt die neue Uhr als richtig, und die Werte der früheren Linie vor lesen
  sich als bekannt, zu einem Datum, das um den alten Vorlauf zu spät ist: echte Messungen mit
  falschem Datum, wo 1.52.0 „unbekannt“ zeigte.
- Stellt NTP die Uhr, während HA aus ist, und liegt ein aufgezeichneter Sprung vor in der
  doppelten Zeit (z. B. ein Sprung vor um zehn Minuten zwei Tage vor einem Start 400 Tage
  zurück), bleibt die ganze doppelte Zeit unbekannt, solange sie in der Aufbewahrung liegt:
  im Beispiel der ganze Verlauf vor dem Stopp. Beim Start ist nicht zu sehen, ob die Uhr die
  Linie vor dem Rücksprung fortsetzt (`_past_at_start` nutzt `_undoes` nicht). Gelöscht wird
  nichts. Stellt NTP die Uhr im Betrieb, ist der Verlauf bekannt.
- Ein Sprung vor, dessen Marke schon älter als 14 Tage ist (eine Linie vor, die mehr als
  14 Tage lief), schützt die doppelte Zeit nicht mehr vor dem Kürzen (`_ahead_inside` sieht
  ihn nicht).
- Steht die Uhr mehr als 14 Tage vor, löscht die normale Aufbewahrung (sie rechnet mit der
  Wanduhr) beim nächsten Takt den echten Verlauf davor (so schon vor 1.52.1).
- Einträge anderer Module (Audit-Protokoll, Konfigurations-Backups), die in einer Linie vor
  datiert sind, stehen weiter in der Liste der Zeitleiste.
- Eine 1.52.0-Datei, in der die Uhr die Zeit des ersten Durchlaufs schon wieder erreicht hat,
  wird nicht repariert.
- Nach einem unsauberen Stopp kann ein Uplink- oder Rollenwechsel, den die Engine vor dem
  letzten Schreiben zuerst sah und erst danach bestätigte, in der Rekonstruktion fehlen
  (die Marke geht mit dem Absturz verloren); das erweiterte Orakel findet das bei einzelnen
  Startwerten außerhalb der festen. Offen.
- Zwei Funks auf demselben Band: ein Kanalwechsel kann dem falschen zugeordnet werden, wenn
  beide den Kanal tauschen; das Orakel findet das bei einzelnen Startwerten mit Uhrsprung.
  Offen.
- „Router entfernen“ macht den Verlauf der Router unbekannt, deren Marken ihn als Peer
  nannten; Client- und Flotten-Marken mit ihm heben `lost` für alle.
- „Client vergessen“ senkt frühere Client-Zahlen ohne Markierung.
- Ein Client über der Tagesgrenze macht die Client-Liste `partial`, bis er wieder eine
  Session hat; das kann den Rest des Tages und darüber hinaus dauern.
- Die Versionen sind die neuesten *behaltenen* (ausgedünnt), nicht zwingend die zu `at`
  laufende Konfiguration.
- Kein WAN-Zustand zum Zeitpunkt (der eigene Verlauf hält ihn nicht).
- Der Export enthält keine Client-Verläufe.
- Panel: Abschnitt 25.

## 25. Panel für D bis F (1.52.0)

`_PANEL_VERSION` `20261126-timemachine9` (1.52.1: `20261127-timemachine10`, 1.52.2:
`20261127-timemachine11`). Das Panel liest die Routen `timeline`, `sessions`,
`state`, `compare` und `export` und fügt nichts hinzu. Dateien unter
`frontend/topology/src/enterprise/timemachine/`: `tmState.ts` (Zerlegen der Antworten,
Reducer, Texte und Werte in Worten, Vergleichszeilen, Sprungziele; ohne React),
`TimeMachineState.tsx` (Ansichten „Zustand“ und „Vergleich“ mit ihren Containern), `tmUi.tsx`
(gemeinsame Teile: Rahmen, Fehlerkasten, Marke, Client-Kürzel, Sprung-Schaltfläche, Kontexte
für Sprung und Client-Filter), `TimeMachineView.tsx` (Zeitleiste, Sitzungen, Umschalter,
Export), Texttabellen in `tmTexts.ts`.

### 25.1 Umschalter

„Zeitleiste | Zustand | Vergleich | Client-Sitzungen“; Client-Sitzungen nur für
Administratoren (`hass.user.is_admin`). Eine Ansicht wird erst beim ersten Öffnen eingehängt,
lädt nur, solange sie sichtbar ist, und behält ihren Zustand beim Umschalten. Bei 360 px zwei
Reihen mit je zwei Chips (`flex: 1 1 calc(50% - 3px)`, 40 px hoch), bei 768 und 1280 px eine
Reihe (32 px). Test: `tmRender.test.mjs`, „the four-chip view switch …“.

### 25.2 Zustand

Feld `datetime-local` (Ortszeit, Sekunden, Vorgabe jetzt), „Jetzt“, „−1 h“, „−24 h“,
Router-Auswahl. Das Öffnen der Ansicht lädt sofort mit den vorbelegten Feldern, eine Eingabe
nach 400 ms (`loadDelay`, `TM_DEBOUNCE_MS`; auf einer verborgenen Seite erst, wenn sie wieder
sichtbar ist). Vor der ersten Antwort steht „Zustand wird geladen …“ bzw. „Vergleich wird
geladen …“; der Hinweis „Einen Zeitpunkt wählen.“ / „„Von“ und „Bis“ wählen.“ nur, wenn ein
Feld wirklich leer ist (`waitingBody`; 1.52.1, bis dahin stand er in der Pause vor dem ersten
Laden unter vorbelegten Feldern). Bei „Jetzt“ fragt die Ansicht `at = jetzt − 1 s`
(keine Zukunft durch eine Uhrabweichung), setzt das Feld auf genau diese Zeit
(`stateLoadAt`; Überschrift und Feld stimmen immer überein, auch nach dem Zurückkehren in die
Ansicht) und lädt höchstens alle 60 s neu, solange die Seite sichtbar ist; unter „Jetzt“ ist
der Wert des Felds selbst kein Anlass zum Laden. Antworten einer älteren Abfrage werden
verworfen.

**Leeres Feld nach einer Antwort (1.52.2, Entscheidung des Eigentümers):** Bis 1.52.1 blieb
das alte Ergebnis stehen, wenn ein Feld danach geleert wurde: `load()` kehrte ohne Aktion
zurück, und die Reducer kannten kein Leeren. Jetzt steht sofort der Hinweis („Einen Zeitpunkt
wählen.“ bzw. „„Von“ und „Bis“ wählen.“) statt des alten Ergebnisses (`StateScreen` /
`CompareScreen` prüfen `waitingBody` auch bei einer Antwort), und nach der Eingabepause löscht
die Aktion `clear` beider Reducer (`stateReducer`, `compareReducer`) das Ergebnis und erhöht
`seq`, sodass eine Antwort, die noch unterwegs war, verworfen wird (auch eine Seite „Weitere
laden“). Ein Feld mit einer übersprungenen Uhrzeit ist nicht leer: Es zeigt weiter seinen
eigenen Fehler, die Aktion `clear` nimmt aber auch dort das alte Ergebnis weg (entschieden in
diesem PR: es gehört nicht mehr zum Feld). Ob ein Laden leert oder fragt, entscheiden die
reinen Funktionen `stateLoadStep` und `compareLoadStep` (Aktion `clear` oder `start` und die
Anfrage); beide Container schicken deren Aktion sofort und ohne Bedingung ab (ein Test hält
das am Quelltext fest, die Container laufen in den Tests ohne DOM nicht). Laden beim Öffnen, 400 ms Pause beim Tippen und
Laden einer verborgenen Seite, sobald sie sichtbar ist, bleiben wie in 1.52.1.

Ortszeit an einer Zeitumstellung (`parseLocalInput`, Tests mit Europe/Berlin): Eine Uhrzeit
der übersprungenen Stunde ist kein Zeitpunkt, sondern ein Fehler am Feld („Diese Uhrzeit gibt
es wegen der Zeitumstellung nicht.“, es wird nicht geladen); eine der doppelten Stunde gilt
als ihr erstes Vorkommen, darunter „Diese Uhrzeit gibt es wegen der Zeitumstellung zweimal;
gezeigt wird die erste.“ Gleiches gilt für „Von“ und „Bis“ des Vergleichs.

- `known: false`: nur ein Kasten „Für diesen Zeitpunkt ist kein Zustand bekannt.“ mit dem
  Satz zum Grund (`GLOBAL_REASON_TEXT`), keine Router-Karten.
- Router-Karten: Erreichbar, Rolle, Uplink, Funk. Ein Wert mit `reason` ist „unbekannt“ mit
  dem Grund (`STATE_REASON_TEXT`), gedämpft und ohne Farbe; ein Wert, den der Server trotz
  Grund schickt, wird verworfen. „nicht erreichbar“ in Warnfarbe und als Wort, `derived`
  mit dem Abzeichen „abgeleitet“ (Tooltip). Uplink `null` heißt „kein vorgeschalteter Router“.
  Funk (`radiosView`): ein Grund steht nur einmal (der Block „unbekannt“ mit Grund, danach
  nur „unvollständig“, wenn der Grund derselbe ist); `partial` mit `not_observed` heißt
  „Nicht alle Funkmodule sind bekannt: Eines blieb über einen Neustart aus.“ Ein Teil
  `unreadable` (Verkehr, Funkauslastung, Versionen, Vorfälle) heißt „Konnte nicht gelesen
  werden.“ Der Grund `clock_shift` hat den Satz „Die Uhr von Home Assistant ist
  zurückgesprungen; diese Zeit kommt im Verlauf doppelt vor.“ und den Kurztext „Uhr
  zurückgesprungen, Zeit doppelt“. Uplink- und Rollenwechsel mit Parameter `since` zeigen
  „zuerst gesehen HH:MM:SS“.
- **Deaktivierter Router** (1.52.2, `entry: "disabled"`, `disabledView`): Ist zu diesem
  Zeitpunkt nichts von ihm bekannt, und zwar nur, weil nichts beobachtet wurde (Erreichbar,
  Rolle, Uplink und Funk unbekannt, jeder Grund `not_observed`), zeigt die Karte statt der
  vier Zeilen „unbekannt · noch kein Wert beobachtet“ eine Zeile „deaktiviert · in Home
  Assistant ausgeschaltet, zu diesem Zeitpunkt nichts bekannt“. Sind Werte bekannt (er war
  damals eingeschaltet) oder hat ein unbekannter Wert einen anderen Grund (`evicted`,
  `observation_gap`, `clock_shift`, …), steht die Karte wie sonst mit diesen Gründen, mit dem
  Abzeichen „derzeit deaktiviert“ am Namen (Review 1.52.2: ein anderer Grund ist eine eigene
  Tatsache). Ohne das Feld (Antwort bis
  1.52.1) ist kein Router deaktiviert.
- Marken mit Datum in der Zeitspalte (`MarkRow` mit `start`: laufende Ausfälle und Lücken,
  Block „Läuft seit vor dem Zeitfenster“) tragen `tm-mark--start`: Zeitspalte 9.5em statt
  5em, ab 920 px Breite der Liste (Container `tmlist`) Karten. Ein Strukturtest in
  `tmRender.test.mjs` prüft über die Kaskade jede gerenderte Marke mit Datum (Spalte und
  Karten ab 920 px); mit der alten Regel (an `.tm-spans` gebunden) ist er für die Ausfälle
  des Zustands rot.
- Abschnitte: laufende Ausfälle und Lücken (Marken wie in der Zeitleiste), offene Vorfälle,
  Verkehr und Funkauslastung der Stunde (WAN-Gründe ohne eigenen Text: „keine Messwerte in
  dieser Stunde“), für Administratoren Konfigurationsversionen und verbundene Clients (Zahl
  je Router, Zeilen mit Client, Router, Band und „seit“, „Weitere laden“ mit
  `clients_cursor` und demselben `at`). Nicht-Admins fragen nie nach `clients_cursor`.
- Fehler in Worten, die 400-Fehler von `at` am Feld.
- „In der Zeitleiste zeigen“: Zeitleiste mit eigenem Fenster `at ± 30 min` (obere Grenze
  höchstens jetzt + 1 s).

### 25.3 Vergleich

„Von“/„Bis“ (Vorgabe: die letzten 24 Stunden), Schnellwahl, Router-Auswahl; kein
automatisches Nachladen. Fehler von `t1`, `t2` und dem Fenster (leer, mehr als 14 Tage) am
Feld. Je Router eine Tabelle „Merkmal | Vorher | Nachher“ (`role="table"`), unter 560 px
Breite der Liste Karten. `changed` mit „geändert“, Clients zusätzlich „von 2 auf 1 (−1)“,
`same` hinter „Unverändertes zeigen (n)“, `unknown` ohne Farbe mit Grund. Ist eine Seite
`known: false`, ein Hinweisband mit ihrem Grund, und die davon abhängigen Zellen sind
unbekannt.

**Jede Zelle ist der Wert ihrer Seite (1.52.2).** Bis 1.52.1 baute `compareRows` die Zeilen
aus `changes`: War eine Seite unbekannt, stand auch die bekannte Seite als „unbekannt“ da (ein
bekannter Uplink null wurde zu „unbekannt“; ein Funk-Block mit einer unbekannten Seite war eine
Zeile „Funk unbekannt“ in beiden Spalten) und beide Zellen trugen denselben Grund (oft den
der anderen Seite oder keinen). Gefunden nach einem Update von 1.51.0: „Vorher“ in der Zeit von
1.51.0 (`not_observed`), „Nachher“ jetzt; „Zustand“ zeigte für denselben Zeitpunkt die Werte.
Jetzt nimmt `compareRows` jede Zelle aus `before.routers` bzw. `after.routers` der Antwort,
mit denselben Ansichten wie „Zustand“ (`reachableView`, `roleView`, `uplinkView`,
`radiosView`/`radioView`), und jede unbekannte Zelle hat den Grund **ihrer** Seite
(`beforeReason`, `afterReason`). Funk: eine Zeile je Funk der Seiten, deren Liste bekannt ist
(ein Funk, den die vollständige Liste einer Seite nicht hat: „unbekannt · zu diesem Zeitpunkt
nicht gesehen“; eine unvollständige Liste nennt stattdessen ihren eigenen Grund); nur wenn
beide Listen unbekannt sind, eine Zeile „Funk“ mit dem Grund je Seite. Eine Liste `partial`
mit `not_observed` ohne Einträge hat keinen eigenen Grund; ihre Zelle trägt den Satz „Nicht
alle Funkmodule sind bekannt: …“, keine unbekannte Zelle steht ohne Grund da. Unveränderte Funks stehen jetzt ebenfalls hinter „Unverändertes zeigen“. Eine Zeile
mit einer unbekannten Seite ist `unknown` und nie eine Änderung; ob beide bekannte Seiten
`same` oder `changed` sind, sagt weiter der Server (`changes`, etwa eine Breite nach „Funk
an“). Ausnahme „Erreichbar“: Der Server vergleicht nur wahr/falsch, die Zelle sagt auch
„(LAN)“ (`cause: lan_down`); sagen beide bekannten Zellen Verschiedenes, ist die Zeile
`changed` und zählt als Änderung. Ohne Block (eine Antwort ohne Blöcke oder ein Router, der in
einem Block fehlt) gilt der Weg über `changes`; eine unbekannte Zelle nennt dann
`from_reason` bzw. `to_reason` des Servers, ohne diese Felder den Grund ihrer Seite wie
bisher. `_radio_diff` hat keine Gründe je Seite. Die
Zusammenfassung zählt genau die Zeilen der Tabellen („Keine bekannte Änderung; n Merkmale
sind …“ = Zahl der Zeilen `unknown`).

**Deaktivierter Router (1.52.2).** Ein Router mit `entry: "disabled"`, von dem zu beiden
Zeitpunkten nichts bekannt ist, weil nichts beobachtet wurde (`disabledView` `only` auf beiden
Seiten, siehe 25.2; `compareRouters`), steht nicht unter den Unterschieden, zählt
nicht in „n Merkmale … unbekannt“ und nicht als „Router ohne Unterschied“; darunter steht „1
Router ist deaktiviert und nicht aufgeführt; zu beiden Zeitpunkten ist von ihm nichts
bekannt.“ (mehrere: „n Router sind …“). Ist er zu einem der Zeitpunkte bekannt (vorher
eingeschaltet) oder trägt ein unbekannter Wert einen anderen Grund als `not_observed`, steht
seine Tabelle wie sonst, mit dem Abzeichen „derzeit deaktiviert“. Wären ohne die nicht
aufgeführten Router die Sätze „Zwischen diesen Zeitpunkten hat sich nichts geändert.“ oder
„Die Zustände … sind gleich; …“ fällig, sagt die Zusammenfassung stattdessen „Über 1
deaktivierten Router ist nichts bekannt; sonst hat sich zwischen diesen Zeitpunkten nichts
geändert.“ (mehrere: „Über n deaktivierte Router …“; mit Ereignissen: „…; sonst sind die
Zustände zu beiden Zeitpunkten gleich, und dazwischen gab es Ereignisse.“,
`disabledSummaryText`, Texte in `tmTexts.ts`), nie einen Satz über Router, von denen nichts
bekannt ist.

Darunter „Ereignisse dazwischen“ (Zahl je Art, „In der Zeitleiste zeigen“ mit
dem Fenster `t1`–`t2`, höchstens 14 Tage), Vorfälle, für Administratoren
Konfigurationsänderungen (gezählt werden Versionen; das Backend liefert keine Zahl geänderter
Einstellungen). `changes.other_sources` (Einträge der anderen Module mit `t1 ≤ ts < t2`)
steht unter „Ereignisse dazwischen“ als „Dazu n Einträge aus anderen Modulen.“ (`truncated`:
„mindestens n“); ist es `unreadable`, steht dort „Ob dazwischen etwas geschah, ist unbekannt:
Eine Quelle ließ sich nicht lesen.“ und „Nicht gelesen: <Namen aus `SOURCE_TEXT`>.“ (mehrere:
„Mehrere Quellen ließen sich nicht lesen.“). Fehlt das Feld oder ist es `off`, ist es
ebenfalls unbekannt („Die anderen Module wurden nicht gelesen.“). Zusammenfassung: „Zwischen
diesen Zeitpunkten hat sich nichts geändert.“ nur, wenn beide Seiten bekannt sind, kein
Merkmal unbekannt oder geändert ist, dazwischen keine Marke, kein Vorfall und keine Version
liegt und `other_sources` `ok` mit `count` 0 und ohne `truncated` ist; ist es unbekannt, steht
der Satz zum Unbekannten; sonst „Die Zustände zu beiden Zeitpunkten sind
gleich; dazwischen gab es Ereignisse.“, „n Merkmale haben sich geändert.“ oder „Keine
bekannte Änderung; n Merkmale sind zu einem der Zeitpunkte unbekannt.“ Status `unavailable`
nennt wie im Zustand den Grund in Worten.

### 25.4 Zeitleiste: eigenes Fenster, Client-Filter, Export

- Fünfter Fensterzustand „Eigenes Fenster“, angezeigt als „Fenster: TT.MM. HH:MM – HH:MM“
  (über Mitternacht mit beiden Daten) mit „×“ zurück zu 24 Stunden; kein automatisches
  Nachladen.
- Client-Filter (nur Administratoren): Auswahlfeld „Client“ aus den Clients der geladenen
  Marken, sendet `client=tmc_…`; ein Klick auf ein Client-Kürzel setzt den Filter. Für
  Nicht-Admins wird ein gesetzter Filter nie gesendet (`askedFilters`).
- Export (nur Administratoren): „Exportieren“, dann die Bestätigung im Tab
  (`role="alertdialog"`) mit dem Satz „Der Export enthält die Marken des gewählten
  Zeitfensters ohne Namen und ohne Client-Verläufe. Er wird im Audit-Protokoll vermerkt.“
  Die Antwort wird über den vorhandenen Fetch mit Bearer-Kopfzeile geladen und als Blob
  gespeichert (`openwrt-router-time-machine.json`, weitere Seiten `…-2.json` usw.); kein
  Token in einer URL. Gleiches Fenster und gleiche Filter wie die Zeitleiste, aber ohne
  `spans` und `client` (die Route lehnt beide ab). Bei `truncated` „Weitere Seite
  exportieren“ mit `cursor`. 503 `audit_unavailable`: „Export nicht möglich: Das
  Audit-Protokoll ist nicht verfügbar.“; 403 und 5xx wie sonst.
- Die Bestätigung ist ein modaler Dialog (`aria-modal`, `aria-describedby` auf den Satz): beim
  Öffnen liegt der Fokus auf „Abbrechen“, Escape bricht ab, Tab und Umschalt+Tab bleiben bei
  seinen Schaltflächen, nach dem Schließen geht der Fokus zurück auf „Exportieren“ (während
  des Exports `aria-disabled`, nicht `disabled`, damit er fokussierbar bleibt). Logik als
  reine Funktionen `dialogKey` und `dialogFocus`. Den fokussierten Knopf liest `activeIn`
  aus der Wurzel des Dialogs (`getRootNode()`), denn das Panel liegt in einem Shadow DOM, wo
  `document.activeElement` nur der Shadow-Host ist (vorher lief Tab dort nicht im Kreis;
  Browser-Prüfung). Nach dem Export steht, wenn
  `omitted_client_marks` > 0, „n Client-Einträge sind nicht enthalten.“ (die Zahl gilt für das
  ganze Fenster und ist auf jeder Seite gleich).
- Fokus nach einem Klick (zweite Browser-Prüfung): Der Dialog hat `tabIndex={-1}` (nicht in der
  Tab-Reihenfolge); ein Klick oder Tippen auf seinen Text fokussiert den Dialog selbst, seine
  Tasten bleiben bei ihm (vorher fiel der Fokus auf `<body>`, Umschalt+Tab verließ den Dialog,
  Escape wirkte nicht). Fällt der Fokus trotzdem auf `<body>` (Klick auf eine Stelle ohne
  Fokus außerhalb des Dialogs), hört ein `keydown` am Dokument, solange der Dialog offen ist,
  und wendet dieselbe Regel an (`focusLost`: in der Wurzel des Dialogs nichts fokussiert und
  `document.activeElement` ist `<body>`); einen echten Fokus anderswo lässt es in Ruhe.
- Export ohne Marke (zweite Browser-Prüfung): Hat die Antwort weder `marks` noch `spanning`,
  speichert das Panel keine Datei und sagt warum (`exportEmptyText`, `exportStep`): „Nichts zu
  exportieren, es wurde keine Datei gespeichert.“ und dahinter je Antwort „Die Zeitreise läuft
  gerade nicht.“ bzw. „Der gespeicherte Verlauf wird noch geladen; bitte gleich noch einmal
  versuchen.“ (`unavailable`, Tabelle `EXPORT_UNAVAILABLE_TEXT`), „Die Zeitreise ist
  ausgeschaltet.“ (`off`) oder „Im gewählten Zeitfenster gibt es mit den gewählten Filtern keine
  exportierbaren Marken.“ (`ok`; bei `partial` dazu „Mindestens eine Quelle ließ sich nicht
  lesen.“, bei ausgelassenen Client-Marken „n Client-Einträge werden nie exportiert.“). Eine
  spätere Seite ohne Marke: „Keine weiteren Marken, es wurde keine weitere Datei
  gespeichert.“ Das Audit vermerkt einen leeren `ok`-Export weiterhin (Backend unverändert).
- Client-Kürzel: `title` „<Name> · tmc_…“, ohne Namen nur das Pseudonym. Der Client-Filter ist
  unter 600 px mindestens 24 px hoch und hat bei jeder Breite den Fokusring des Tabs.

### 25.5 Sprünge

Die Schaltfläche „Im Tab <Name> öffnen →“ steht an Marken (aus `ref` und `kind`, Tabelle
Abschnitt 23, Kopie in `tmTexts.ts`: `JUMP_REF_TAB`, `JUMP_KIND_TAB`, `JUMP_OBJECT`) und an
Vorfällen und Versionen von `/state` und `/compare` (aus `target`, geprüft: bekannter Tab,
Kennungen nach ihrem Muster). Keine Schaltfläche ohne Ziel, für die Zeitreise selbst oder für
einen Tab, den der Benutzer nicht hat (`isEnterpriseTabAvailable`). Der Sprung geht über die
Registry (`openEnterpriseTab`): `EnterpriseView` wechselt den Tab und setzt den Fokus auf
dessen Reiter; das Ziel liest seinen Anfangszustand mit `peekEnterpriseEntry` und löscht den
Eintrag mit `clearEnterpriseEntry`.

| Ziel-Tab | Wirkung |
|---|---|
| Security Center | wählt den Vorfall (`object_type` `incident`); Drift und Zeitleiste öffnen nur den Tab |
| Konfiguration | wählt den Router der Version (nicht die Version) |
| WiFi Intelligence, Netzwerkdiagnose, Traffic Analytics | öffnen nur den Tab |
| Topologie | kein Link: die Topologie kennt die Kennungen `rtr_…` nicht |

Ohne Eintrag starten Security Center und Konfiguration wie vorher (Test, auch mit einem
Eintrag für einen anderen Tab). Python-Test `test_tm_panel_texts_v1520.py`: jede Tabelle des
Panels gegen `JUMP_TARGETS`, `KIND_TABS`, `KIND_NO_TAB` und `_OBJECT` in beiden Richtungen,
jeder Tab ein registrierter Panel-Tab mit gleichem Titel, jeder Grund und Zustand mit Text.

### 25.6 Lange Namen

In schmalen Spalten brechen Namen ohne Leerzeichen zwischen Buchstaben um. In Zeilen
(Zeitleiste, Block, Sitzungen, Clients des Zustands) stehen Router- und Client-Namen auf
höchstens zwei Zeilen, der volle Name im `title`; in Karten ganz.

### 25.7 Testdaten und Tests

`tmFixtureState.json` sind echte Antworten der Routen (Admin und Benutzer), geschrieben von
`tests/test_tm_panel_fixture_v1520.py` (neu erzeugen mit `TM_WRITE_FIXTURE=1`).
`tmFixtureCompare.json` (1.52.2) sind Antworten von `tm_state.async_state` /
`async_compare` (die Körper der Routen) aus einer Welt mit drei Routern nach dem Update von
einer 1.51.0-Datei, einem Neustart und Polls, Router 3 deaktiviert, Router 2 hinter Router 1,
danach Router 2 ausgefallen und deaktiviert; geschrieben von
`tests/test_tm_compare_display_v1522.py` (ebenfalls `TM_WRITE_FIXTURE=1`). JS-Tests:
`tmState.test.mjs` (Logik und Client mit nachgebildetem Fetch), `tmRender.test.mjs`
(Darstellung aller Zustände beider Rollen, Sprünge, fremde Tabs, die zwei strukturellen
Stiltests über alle Bildschirme der neuen Ansichten), `tmLayout.test.mjs`.

Der Tab wurde vor dem Merge headless in Firefox bei 360, 768 und 1280 px geprüft (Testserver
mit nachgebildeten Antworten). Das Panel hat kein eigenes helles Design und bleibt auch im
hellen HA-Thema dunkel. **Nicht geprüft:** in einer echten Instanz.
