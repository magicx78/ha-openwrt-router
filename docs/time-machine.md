# Network Time Machine (Phase A: Lese-Schnittstelle und Tab „Zeitreise“, ab 1.50.0)

<!-- Entwicklerdoku zu Phase A (1.50.0). Keine IPs, MACs,
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
erkennen soll, kommen erst mit Phase B (die Arten sind schon vergeben, Abschnitt 6).

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

## 3. Quellen

| `id` | liest | Lesegrenze je Anfrage (Speicher fasst) | Admin-only | Hinweise |
|---|---|---|---|---|
| `core_audit` | Audit-Log beider Ringe (`general`, `security`) über `ConfigurationApi.events(since, ring, limit)` | 1001 je Ring (1000 / 500) | ja | `events` kennt kein `until`; jeder Ring wird ganz gelesen und vom Adapter auf das Fenster zugeschnitten |
| `config_versions` | Konfigurationsversionen über `ConfigurationApi.async_list_backups(since, limit)` | 500 (unbegrenzt) | ja | `off/module_off`, wenn kein Router die Konfigurationssicherung eingeschaltet hat; kein `until` (Abschnitt 13) |
| `ni_events` | Ereignisse von Network Intelligence über `net_query.events_page` | 3001 (3000) | nein | Ereignis-ID trägt die `entry_id` und wird nicht ausgegeben |
| `ni_incidents` | Vorfälle von Network Intelligence über `net_query.incidents_page` | 501 (500) | nein | je Vorfall bis zu drei Marken: eröffnet, wieder eröffnet, behoben; `incidents_page` sortiert nach Status und Schwere ohne Zeitfilter, deshalb liest der Adapter alle Vorfälle und filtert selbst nach Zeit |
| `security_timeline` | Zeitleiste des Security Center über `overview(actor=None, …)` (die maskierte Sicht) | 2001 (2000) | nein | `off/module_off`, wenn das Security Center aus ist |

Bis auf die Konfigurationsversionen liegt jede Lesegrenze über dem, was der Speicher der
Quelle fasst: Eine Lesung ist vollständig, Client-Einträge oder ein anderer Ring können sie
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
| `source` | Komma-Liste der Quellen-IDs aus Abschnitt 3 | alle | jede ID höchstens einmal |
| `router_id` | `rtr_` + 32 hex | – | nur Marken genau dieses Routers (Flotten-Marken nicht) |
| `kind` | eine Art aus Abschnitt 6 | – | nur diese Art |
| `min_severity` | `info` / `warning` / `critical` | – | ab diesem Schweregrad |
| `limit` | 1 … 500 | 200 | Marken je Seite |

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
  "next_until": 1795003741.0
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
| `next_until` | `until` der nächsten Seite oder `null` |

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
| `derived` | in Phase A immer `false` |

## 6. Arten, Gruppen, Schweregrade, Zustände

### 6.1 Arten und Gruppen

| Gruppe | Arten (in Phase A erzeugt) | vergeben für später |
|---|---|---|
| `infrastructure` | `router_down`, `router_up`, `lan_down`, `lan_up`, `observation_gap`, `wan_event`, `port_event`, `system_event` | `ha_gap` |
| `radio` | `channel_changed`, `dfs_event`, `rf_event` | `radio_down`, `radio_up` |
| `topology` | `uplink_changed` | `router_role_changed` |
| `configuration` | `config_version`, `config_drift`, `config_event` | `config_fingerprint_changed` |
| `disruption` | `incident_opened`, `incident_resolved`, `security_incident`, `diag_finding`, `traffic_anomaly`, `net_event` | – |
| `security` | `security_event` | – |
| `administration` | `registry_event`, `core_event`, `audit_event` | – |
| `clients` | – | `client_session`, `client_roam`, `client_disconnect` |
| `time_machine` | – | `tm_started`, `tm_disabled`, `tm_store_recovered`, `tm_forgot_client`, `tm_exported` |

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

## 7. Rechte

| | Administrator | Nicht-Admin, Panel für alle Benutzer offen | Nicht-Admin, Panel nur für Admins | nicht angemeldet |
|---|---|---|---|---|
| Route | 200 | 200 | 403 | 401 |
| `core_audit`, `config_versions` | ja | `off` / `admin_only` | – | – |
| `ni_events`, `ni_incidents`, `security_timeline` | alle Gruppen | nur `infrastructure`, `radio`, `topology`, `disruption` | – | – |
| Konfigurationsmarken (Bereich, Zahl der Änderungen, `bkp_…`) | ja | nein | – | – |
| Client-Ereignisse | nur gezählt | weggelassen, `omitted_client_marks` = 0 | – | – |

„Panel für alle Benutzer“ ist die bestehende Option `topology_panel_all_users`. Reihenfolge der
Prüfungen: Anmeldung (401) → Recht (403) → Integration geladen (410) → Body (400) → Abfrage
(400) → Schalter (`off`) → Lesen.

## 8. Blättern

Die Marken sind nach `ts` absteigend und bei gleichem `ts` nach `id` sortiert. Hat eine Seite
mehr Marken als `limit`, endet sie vor dem ältesten Zeitstempel, damit Marken mit **demselben
Zeitstempel nie auf zwei Seiten verteilt** werden; `next_until` ist dann der älteste
Zeitstempel der Seite. Die nächste Seite fragt mit `until=<next_until>` und demselben `from`.
Weil Marken und Fenstergrenzen auf demselben Millisekunden-Raster liegen, kommt keine Marke
doppelt und keine geht an der Grenze verloren.

Wurde die Lesung einer Quelle gekürzt (`truncated`), ist sie nur oberhalb ihrer **Kante**
vollständig, des ältesten gelesenen Eintrags im Fenster (weggelassene Client-Einträge
eingeschlossen). Die Seite behält dann nur Marken nach der Millisekunde der Kante, und
`next_until` ist die Millisekunde danach: Die nächste Seite liest die Millisekunde der Kante
ganz, Marken desselben Zeitstempels bleiben zusammen. `next_until` steht auch dann, wenn die
Seite **keine einzige Marke** enthält (etwa weil die gelesenen Einträge nur Client-Ereignisse
waren); die Quelle ist dann nicht `empty`, sondern `ok` mit `cut: next_page`. Bei mehreren
gekürzten Quellen gilt die jüngste Kante. Ist die Millisekunde der Kante die letzte des
Fensters, behält die Seite sie, und was davon nicht gelesen wurde, fehlt (`truncated: true`).

Liegt `next_until` am oder vor `from`, ist es `null`.

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
- Die Time Machine holt sich **keinen** Modulschlüssel eines anderen Moduls
  (`async_get_module_key` wird nie aufgerufen, Test) und verknüpft keine `cli_`-Pseudonyme
  verschiedener Module.
- Alle Antworten haben `Cache-Control: no-store`.

## 11. Diagnosedaten

Der Diagnose-Download jedes Routers enthält den Block `time_machine`:

- aus: `{"enabled": false}`; keine Quelle wird gelesen.
- an: `enabled`, `entry_enabled` (Option dieses Eintrags), `api_version`, `window_s` (86400),
  `limits` (Standard- und Höchstfenster, Standard- und Höchstlimit, Marken einer Quelle je
  Seite, Zeitbudget), `sources` (je Quelle `state`, `reason`, `count`, `truncated`,
  `omitted_client_marks` der letzten 24 h, gelesen wie ein Admin; die Marken selbst werden
  verworfen) und `counters` (Zahl der Anfragen, `unreadable` je Quelle, Dauer und Markenzahl
  der letzten Anfrage; nur im Arbeitsspeicher).
- Ein Fehler im Block lässt den Download nie scheitern: `{"loaded": false, "error": true}`.

## 12. Leistung

Gemessen mit gefüllten Quellen (Audit 1000 Einträge, 36 Versionen, Security-Center-Zeitleiste
2000 Einträge, Network Intelligence 200 WAN-Wechsel und 150 Client-Ereignisse), Fenster
13 Tage, `limit=500`, jede Quelle ganz gelesen: **51–78 ms** über HTTP, davon **47–74 ms** Lesen
und Zusammenführen (drei Läufe); Antwort **209 KB** mit 498 Marken. Der Test verlangt
großzügig unter 2 s. Gemessen mit Mocks auf der Entwicklungs-VM (Python 3.13), nicht auf einer
HA-Instanz.

## 13. Bekannte Grenzen und was nicht geprüft ist

- Mehr Marken mit **demselben Zeitstempel** (Millisekunde) als `limit`: die Seite wird dort
  abgeschnitten (`truncated: true`), der Rest dieses Zeitstempels fehlt auf der nächsten Seite.
  Ebenso, wenn die letzte Millisekunde eines Fensters mehr Einträge einer Quelle hält, als sie
  in einer Lesung liefert (Abschnitt 8); mit den heutigen Lesegrenzen nur bei den
  Konfigurationsversionen denkbar.
- **Konfigurationsversionen** werden höchstens 500 je Anfrage gelesen, und
  `async_list_backups` kennt kein `until`: Liegen mehr als 500 Versionen zwischen `from` und
  jetzt, sind die älteren im Fenster nicht erreichbar; die Quelle meldet dann
  `truncated: true` mit `cut: unreachable` und ist nie `empty`.
- `truncated` einer Quelle gilt vor den Rechten. Bei den Quellen, die Nicht-Admins sehen, liegt
  die Lesegrenze über der Kapazität des Speichers; das Feld ist für sie daher immer `false`.
- Was die Module nicht behalten, fehlt auch in der Time Machine: Der Ring `general` des
  Audit-Logs hat seit 1.50.0 feste Anteile (Core 400, je Modul 100), verdrängt aber weiterhin
  den ältesten Eintrag eines Besitzers über seinem Anteil (`general_evicted`). Ausfälle und
  Kanalwechsel vor einem HA-Neustart fehlen bis Phase B.
- Modulschlüssel des Enterprise Core werden nur nach Namen vergeben.
- Drift-Einträge des Audit-Logs tragen keinen Bereich; Bereich und Diff zeigt der
  Configuration Manager.
- Die synchronen Lesefunktionen der Quellmodule werden vom Zeitbudget nicht unterbrochen
  (Abschnitt 3).
- Nicht auf echten Routern und nicht in einer laufenden HA-Instanz geprüft; alle Aussagen
  stammen aus Tests mit Mocks. Den Tab hat die Prüfung vor dem Merge headless in Firefox mit
  der Testantwort angesehen; die danach geänderten Stile (Abschnitt 14: gesperrte Chips,
  Karten ab 860 px, Quellspalte, mittige Chips) sind nur durch Tests geprüft.

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
  Client-Verläufe kommen mit einem eigenen Schalter in einer späteren Version.“
- **Zeitleiste:** neueste zuerst, nach Kalendertag in Ortszeit (Heute, Gestern, „Wochentag,
  TT.MM.JJJJ“), je Marke Uhrzeit (UTC-ISO im `title`), Schwere als Punkt und Wort (Info nie in
  Warnfarbe), Art, Titel, Kennzahlen (nur bekannte Schlüssel), Router („alle Router“ bei
  `fleet`) und Quelle; „abgeleitet“ bei `derived`. Doppelte `id` werden entfernt. „Ältere
  laden“ fragt mit `until=next_until`; `truncated` ohne `next_until` zeigt „Weitere Marken im
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
(259 Schlüssel, 1.50.0). `tests/test_tm_panel_texts_v1500.py` sammelt die Schlüssel aus den
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
