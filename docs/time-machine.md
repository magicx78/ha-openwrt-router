# Network Time Machine (Phase A ab 1.50.0; Phasen B und C ab 1.51.0: eigener Verlauf und Client-Sessions)

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

**Intervalle, die ins Fenster reichen (`spans_in`, 1.51.0).** Eine Intervall-Marke von
`tm_index` oder `tm_clients`, die vor `from` begann und offen ist oder mit `end` ≥ `from`
endet, gehört zum Fenster (Überlappung). Regel beim Blättern:

- Die Menge dieser Marken hängt nur von `from` ab, nicht von `until`: jede Seite desselben
  Fensters liest dieselbe Menge.
- Sie sortieren nach ihrem Anfang, also **unter** allen Marken des Fensters. Darum stehen sie
  nur auf der **letzten** Seite, der Seite, deren Lauf bis `from` reicht. Eine frühere Seite
  endet mit `next_until` über `from` und kann sie nicht erreichen.
- Hat eine gekürzte Quelle ihre Kante noch über `from`, bleiben sie auf dieser Seite weg; sie
  kommen mit der Seite, die bis `from` liest.
- Damit erscheint jede genau **einmal**, ohne Doppel und ohne Endlosschleife: `next_until`
  sinkt mit jeder Seite, und unter `from` gibt es keine nächste Seite.
- Passen mehr von ihnen auf die letzte Seite als `limit`, endet sie mit `truncated: true` und
  `next_until: null` (das nächste Fenster wäre leer); der Rest fehlt.

Ein Fenster mit einer Seite (der Standard des Tabs, 200 Marken) zeigt sie sofort. Tests:
`tests/test_tm_overlap_v1510.py`.

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
HA-Instanz. Mit den drei Quellen der Phasen B/C (ganz gelesen, bis 15000 Marken) ist die
Antwortzeit **nicht neu gemessen**.

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
  Karten ab 860 px, Quellspalte, mittige Chips) sind nur durch Tests geprüft. Der Tab von
  1.51.0 (Abschnitt 14.3) ist **in keinem Browser angesehen**, nur mit node-Tests
  (Logik, serverseitiges Rendern, Stylesheet-Prüfungen) geprüft.

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
  (`open`; an einem anderen Tag mit Datum), „Ende unbekannt“ (`unknown`). Marken mit
  `spans_in` (und jede Marke vor `from`) stehen oben im Block „Läuft seit vor dem
  Zeitfenster“ mit Datum und Uhrzeit des Anfangs; jede Marke nur einmal.
- **Clients:** „Client <client_name>“ mit dem Namen vom Server, sonst „Client ·a1ce4d“ (die
  letzten sechs Zeichen des Pseudonyms); nie eine MAC. Wechsel „von Router 1 nach Router 2“
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
  „5 GHz“, „6 GHz“), „n Wechsel“ bei `params.roam` > 0. Unter 700 px Containerbreite Karten.
  „Ältere laden“ über `next_until`; `truncated` ohne `next_until` zeigt den Kürzungshinweis.
  Zustände: `off` (Box wie die Zeitleiste), `clients_off` („Client-Verläufe sind
  ausgeschaltet.“, der Weg in die Optionen und „Gespeichert werden Pseudonyme, keine
  MAC-Adressen, IP-Adressen oder Hostnamen. Abgeschlossene Sitzungen werden nach 14 Tagen
  gelöscht.“ — „abgeschlossene“, weil offene Intervalle nicht gekürzt werden, Abschnitt
  15.7), `unavailable` („Client-Sitzungen sind noch nicht verfügbar. Grund: …“ in Worten),
  leer, 403 „Keine Berechtigung für die Client-Sitzungen (nur Administratoren).“, 410, 5xx mit
  „Erneut versuchen“, 400 mit dem Feldnamen. „Aufzeichnung läuft“ / „Aufzeichnung pausiert …“
  aus `recording`.
- **Abruf:** nur die sichtbare Ansicht lädt und fragt nach, höchstens alle 60 s, bei
  `off`/`clients_off` der Sitzungen gar nicht automatisch; veraltete Antworten werden
  verworfen, und eine Liste, die sich nicht lückenlos anschließen lässt, beginnt neu (wie die
  Zeitleiste).
- **Nicht im Tab:** keine Knöpfe für „Client vergessen“ oder „Verlauf löschen“, kein „Zustand
  zum Zeitpunkt“, kein Export, keine Sprünge in andere Tabs.
- Tests: `tmSessions.test.mjs` (Logik), `tmRender.test.mjs` (Darstellung aus
  `tmFixtureClients.json`), `tmLayout.test.mjs` (Raster, Karten).

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
| `counters` | Zähler (Abschnitt 11) |

Jedes Feld einer Zeile wird beim Lesen gegen ein Muster geprüft; eine kaputte Zeile wird
übersprungen und gezählt, nie die ganze Datei (`test_bad_rows_are_skipped_not_the_file`).
Eine unlesbare, fremde oder **neuere** Datei bleibt als `.bak` liegen, der Verlauf beginnt leer
mit der Marke `tm_store_recovered` und dem Audit-Eintrag `time_machine.store_recovered`
(`test_broken_store_starts_empty_with_a_copy_and_a_mark`,
`test_newer_store_version_is_kept_as_bak`).

**Schreiben:** nie im Ereignisweg. Eine Änderung stellt **ein** verzögertes Schreiben nach
120 s an (`async_delay_save`, weitere Änderungen hängen sich daran,
`test_writes_are_delayed_and_bundled`); ohne Änderung alle 900 s ein Lebenszeichen
(`test_heartbeat_write_every_15_minutes_without_changes`), damit `saved_at` nach einem Absturz
nur etwa 15 min (plus die 120 s Verzögerung) vor dem Ende liegt. Sofort (ohne Verzögerung)
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
| gesamt | 15000 | Summe; ein Kontingent verdrängt **nie** ein anderes, innerhalb eines Kontingents fällt die älteste Marke zuerst (Zähler `evicted_<kontingent>`; `test_quotas_never_evict_each_other_and_count`) |
| je Client und UTC-Tag | 200 neue Marken | darüber zählt eine Marke `client_flapping` (Zahl `suppressed`, Ende = letzter unterdrückter Zeitpunkt; `test_one_client_storm_is_folded_per_day`, über den echten Weg `test_a_flapping_client_never_fills_the_store`) |
| Datei | 2 500 000 Byte | genaue Länge je Zeile; darüber wird **in einem Durchgang** auf 5 % unter die Grenze gekürzt, zuerst älteste Client-, dann Verweis-, dann Infrastruktur-Marken; bleibt es darüber, wird nicht geschrieben und die letzte gute Datei bleibt (`save_over_size`; `test_size_limit_trims_clients_first_in_one_pass`) |

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
| `clock_shift` | Uhr | Wanduhr springt zwischen zwei Takten (300 s) um mehr als 300 s gegenüber der monotonen Uhr, oder beim Start liegt `saved_at` mehr als 300 s in der Zukunft; dann **kein** `ha_gap` (`test_clock_backwards_and_jumps_are_marked_not_gaps`) |
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

### 15.7 Grenzen (Phase B)

- Seit 1.51.0 erscheint eine Intervall-Marke, die vor `from` begann und ins Fenster reicht,
  mit `spans_in: true` (Abschnitt 8); bei mehr solchen Marken als `limit` fehlt der Rest.
- Offene Intervalle werden nicht nach 14 Tagen gekürzt.
- **Solange die Time Machine aus ist, wird nichts gekürzt** (bekannte Grenze, gewollt): Es
  läuft kein Takt, der die Datei liest. Die Infrastruktur-Marken bleiben, bis die Time Machine
  wieder eingeschaltet wird (dann sofort auf 14 Tage gekürzt) oder „Verlauf löschen“ läuft.
  Client-Marken gibt es dann nicht mehr (Abschnitt 15.6).
- Uplink und Rolle nur, solange Network Intelligence läuft; ohne Funkdaten in
  `ap_interfaces` kein Kanalwechsel; sind alle Funkmodule aus (leerer Poll), entsteht kein
  `radio_down`.
- Nicht rückwirkend: Was vor dem Einschalten geschah, steht nur in den Phase-A-Quellen.
- Nach einem Absturz ist der Beginn der HA-Lücke nur auf etwa 15–17 min genau (`derived`).

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
(`test_restart_mid_session_ends_unknown_and_resumes`). Roaming über Router hinweg:
`test_session_roam_and_disconnect_across_routers`.

### 16.3 Pseudonym und Name

`client` ist `tmc_` + 16 hex, HMAC der MAC mit dem eigenen Modulschlüssel der Time Machine;
gespeichert werden nur die 16 hex. `client_name` liest der Server bei jeder Antwort aus der
Client-Stabilität, nur für Admins und nur solange sie den Client kennt; gespeichert wird er nie.

### 16.4 Route `GET /api/openwrt_router/enterprise/timemachine/sessions`

Nur Administratoren (jeder andere Benutzer 403, auch bei offenem Panel), kein Body, strenge
Abfrage wie in Abschnitt 4 (400 ohne Echo, unbekannte Schlüssel abgelehnt).

| Parameter | Format | Standard | Bedeutung |
|---|---|---|---|
| `from`, `until` | wie Abschnitt 4 | 24 h bis jetzt | Fenster `[from, until)`, höchstens 14 Tage |
| `client` | `tmc_` + 16 hex | – | nur dieser Client |
| `router_id` | `rtr_` + 32 hex | – | nur Sessions an diesem Router |
| `limit` | 1 … 500 | 200 | Sessions je Seite |

Eine Session gehört zum Fenster, wenn sie vor `until` begann und offen ist oder bei/nach `from`
endete (Überlappung). Sortiert nach Beginn absteigend; Blättern über `next_until` wie in
Abschnitt 8 auf dem Beginn: eine Seite teilt Sessions mit demselben Beginn nicht.

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
  "next_until": 1800000180.0
}
```

(Testantwort mit `limit=1`, Kennungen erfunden)

| `status` | Bedeutung |
|---|---|
| `ok` | gelesen; `recording` sagt, ob gerade aufgezeichnet wird (Client-Stabilität angebunden) |
| `off` | Time Machine aus; `window` `null` |
| `clients_off` | Client-Schalter aus; keine Sessions |
| `unavailable` | an, aber nicht bereit: `reason` `not_running` oder `not_loaded` |

Test: `test_sessions_route_rights_errors_and_paging`.

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
- Mehr Sessions mit **demselben Beginn** als `limit`: der Rest dieses Beginns fehlt. Mehr
  überlappende Sessions als `limit`, deren Beginn vor `from` liegt: `truncated: true` ohne
  `next_until` (das nächste Fenster wäre leer).
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
2. **`tm_index` gewinnt über `ni_events`** bei `router_down`, `router_up`, `lan_down`,
   `lan_up`, `channel_changed`, `uplink_changed`, wenn deren Zeitpunkt in einem Zeitraum liegt,
   in dem der eigene Verlauf lief (`coverage`): der eigene Verlauf hat sie als Intervall mit
   Ende. Außerhalb dieser Zeiträume bleiben die NI-Ereignisse; ist `tm_index` nicht lesbar,
   wird nichts entfernt (`test_the_index_wins_over_ni_events_while_it_was_live`).

Andere Quellen werden nicht verglichen.

## 18. Aktionen

Beide nur für Administratoren (`async_register_admin_service`), mit Antwort; immer
registriert, bei ausgeschalteter Time Machine Fehler `time_machine_off`.

| Aktion | Felder | Antwort | Wirkung |
|---|---|---|---|
| `openwrt_router.time_machine_forget_client` | `mac` | `{"deleted": n, "not_deleted_in": [...]}` | löscht alle Marken dieses Clients, Marke `tm_forgot_client` (ohne Client), Audit `time_machine.client_forgotten`, sofort geschrieben; Fehler `time_machine_invalid_mac`, `time_machine_no_key` |
| `openwrt_router.time_machine_clear_history` | `clients_only` (bool) | `{"deleted": n}` | löscht die Client-Marken oder den ganzen eigenen Verlauf (auch Checkpoints, Abdeckung beginnt neu), Marke `tm_cleared`, Audit `time_machine.history_cleared`, sofort geschrieben |

Tests: `test_forget_action_and_client_stability_exclusion`, `test_clear_history_action`.

## 19. Panel für B/C (1.51.0)

Das Panel ist mit 1.51.0 nachgezogen (Abschnitt 14.3, `_PANEL_VERSION` `20261121-timemachine3`).
Es liest nur die Routen `timeline` und `sessions` und fügt nichts hinzu. Offen für eine spätere
Version: „Zustand zum Zeitpunkt“ aus den Checkpoints, Export, Sprünge über `ref` in die
Quell-Tabs, Bedienelemente für die Aktionen aus Abschnitt 18.
