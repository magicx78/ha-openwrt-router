# Traffic Analytics

<!-- Nutzerdoku ab 1.49.0. Keine IPs, MACs, Hostnamen echter Geräte, Passwörter oder Tokens;
     Beispiele nutzen 192.0.2.x / 198.51.100.x (RFC 5737), MACs 02:00:5e:… und example.org.
     Aussagen sind am Code gelesen (traffic_*.py, topology_panel.py, api.py, config_flow.py,
     translations/de.json, Frontend unter enterprise/traffic/) und mit den Tests geprüft, nicht
     an Geräten ausgeführt. Messwerte stammen aus tests/test_traffic_performance.py und
     tests/test_traffic_history.py auf der Entwicklungs-VM (Python 3.13, Mocks), Stand
     2026-11-21. Plan: docs/plans/2026-11-20-traffic-analytics.md, Bauplan:
     docs/plans/2026-11-20-traffic-analytics-bauplan.md. -->

## Inhalt

1. [Was es tut und was nicht](#1-was-es-tut-und-was-nicht)
2. [Einschalten je Router](#2-einschalten-je-router)
3. [Was gemessen wird](#3-was-gemessen-wird)
4. [Der Tab „Traffic Analytics“](#4-der-tab-traffic-analytics)
5. [Sensoren](#5-sensoren)
6. [Verlauf, Profile und Speicherbedarf](#6-verlauf-profile-und-speicherbedarf)
7. [Leistung](#7-leistung)
8. [Externer Collector](#8-externer-collector)
9. [Routen und Rechte](#9-routen-und-rechte)
10. [Datenschutz](#10-datenschutz)
11. [Benötigte Router-Rechte](#11-benötigte-router-rechte)
12. [Bekannte Grenzen und was nicht geprüft ist](#12-bekannte-grenzen-und-was-nicht-geprüft-ist)

---

## 1. Was es tut und was nicht

Traffic Analytics zeigt, wie viel Verkehr über WAN, Ports, Schnittstellen, VLANs und
WLAN-Clients der Router läuft, hebt Auffälligkeiten hervor und schätzt die Auslastung der
Uplinks. Die Zahlen kommen aus den Zählern, die die Integration bei jeder Abfrage ohnehin
liest. Mit eingeschalteter Analyse kommen **keine zusätzlichen Router-Aufrufe** hinzu,
außer Sie schalten eine der drei Zusatzabfragen ein (Abschnitt 2).

Was es **nicht** tut:

- Es liest keine Paketinhalte, keine DNS-Anfragen und keine Webadressen. Es gibt keine
  Deep Packet Inspection.
- Es ruft keinen Collector auf und startet nichts auf dem Router. Ein externer Collector
  kann Flows **schicken** (Abschnitt 8); Home Assistant holt nichts ab.
- Es zeigt den Internetverbrauch eines einzelnen Clients **nicht** sicher. Der Zähler eines
  WLAN-Clients am Access Point umfasst auch Verkehr im eigenen Netz.
- Zusammengefasste Werte eines Collectors (`client_aggregate`, `interface_aggregate`)
  werden in dieser Version abgelehnt (Abschnitt 8.6).
- Es gibt keine eigene Verbindungsliste aus conntrack. Flows gibt es nur, wenn ein
  Collector sie liefert.

Ausgeschaltet (Standard) gibt es keinen Listener, keinen Speicher und keine Entität. Die
Integration verhält sich dann wie vor 1.49.0.

## 2. Einschalten je Router

**Einstellungen → Geräte & Dienste → OpenWrt Router → Konfigurieren** beim jeweiligen
Router:

| Option | Standard | Wirkung |
|---|---|---|
| Traffic-Analyse (`traffic_enabled`) | aus | Misst den Verkehr dieses Routers und legt seine Sensoren an. |
| WLAN-Client-Zähler aus iwinfo (`traffic_station_detail`) | aus | Liest `iwinfo assoclist` je Access-Point-Schnittstelle höchstens alle 5 Minuten. Das ergänzt Client-Zähler, die in der normalen Abfrage fehlen. |
| Schnittstellen-Zähler aus sysfs (`traffic_sysfs_fallback`) | aus | Liest `/sys/class/net/*/statistics` höchstens alle 5 Minuten, nur für Schnittstellen ohne Zähler in der normalen Abfrage. |
| Flow-Offloading prüfen (`traffic_offload_probe`) | aus | Liest alle 6 Stunden die Firewall-Einstellung für Flow-Offloading (`uci get`), weil ausgelagerter Verkehr manche Zähler umgeht. |
| Tiefe des Verlaufs (`traffic_history_profile`) | `compact` | `compact` oder `standard` (Abschnitt 6). |

Einschalten braucht keinen Neustart. Die Sensoren erscheinen nach der nächsten Abfrage.
Ausschalten entfernt die Traffic-Entitäten dieses Routers. Der gespeicherte Verlauf bleibt
erhalten. Wird der letzte Router ausgeschaltet, verschwinden auch die Flottensensoren und
die Client-Sensoren.

Der Collector und die Client-Sensoren gelten für die ganze Flotte. Ein Administrator stellt
sie im Tab unter **Einstellungen** ein (Abschnitt 4).

## 3. Was gemessen wird

| Messbereich | Quelle | Hinweis |
|---|---|---|
| WAN | Zähler der WAN-Schnittstelle des Gateways | Download = RX am WAN, Upload = TX am WAN |
| Port / Schnittstelle | Netdev-Zähler aus der normalen Abfrage, optional sysfs | RX/TX aus Sicht des Routers |
| Station (WLAN) | Stationszähler am Access Point, optional iwinfo | aus Sicht des Clients umgerechnet |
| Client | Summe der Stationszähler eines Clients über alle APs | kein Internetverbrauch (Abschnitt 1) |
| VLAN | Zähler der VLAN-Schnittstellen | nur VLANs mit eigener Schnittstelle |
| Flow | nur von einem externen Collector | Abschnitt 8 |

Jeder Messpunkt hat eine **Abdeckung**: `full`, `partial`, `estimated`, `unavailable`
oder `unknown`, mit Grund (z. B. `hw_offload_unknown`, `hw_offload_on`, nur
Stationszähler). Solange der Offload-Zustand unbekannt ist, stehen WAN-, Bridge- und
VLAN-Zähler auf `partial`. Unbekannt bleibt
unbekannt: Ohne Messung, bei einem Zählersprung oder bei unbekannter Linkgeschwindigkeit
zeigt die Integration „unbekannt“ und nie 0. Lücken werden nicht geschätzt.

## 4. Der Tab „Traffic Analytics“

Der Tab steht im Topologie-Panel. Er hat diese Abschnitte:

- **Übersicht**: Rate am WAN, Spitzen, Abdeckung und Zustand je Router.
- **Verlauf**: Zeitreihe je Messpunkt für 1 h, 24 h, 7 d, 30 d und 90 d (90 d nur mit dem
  Profil `standard`).
- **Top Talkers**: Clients und Ports mit dem meisten Verkehr im gewählten Fenster.
- **Clients & VLANs**: Clients nur mit Pseudonym (`cli_…`), dazu die VLANs.
- **Anomalien**: Auffälligkeiten mit Beleg (Ausschnitt der Messwerte).
- **Kapazität**: Auslastung der Uplinks, wo die Linkgeschwindigkeit bekannt ist.
- **Flows** (nur Administratoren): die zuletzt vom Collector gelieferten Flows, mit
  Pseudonymen statt Adressen.
- **Einstellungen** (nur Administratoren):
  - Router: welche Router die Analyse eingeschaltet haben und mit welchem Profil. Nur
    zum Ansehen, geändert wird in den Integrationsoptionen.
  - Externer Collector: ein/aus und der Benutzer des Collectors. Zur Auswahl stehen nur
    aktive Benutzer ohne Admin-Rechte, die nicht vom System angelegt wurden. Sie
    erscheinen mit Anzeigename, nie mit Benutzer-ID.
  - Client-Sensoren: bis zu 20 Clients, ausgewählt nach Pseudonym.

  Gespeichert wird nur, was sich geändert hat. „Gespeichert.“ erscheint erst, wenn Home
  Assistant die Änderung angenommen hat. Eine abgelehnte Änderung nennt den Grund und
  behält den Entwurf. Speichern geht erst, wenn die Analyse an mindestens einem Router
  läuft.

Andere Benutzer sehen den Tab nur, wenn ein Eintrag das Topologie-Panel für alle Benutzer
freigibt. Dann sehen sie die Abschnitte ohne „Flows“ und „Einstellungen“.

## 5. Sensoren

Je Router mit eingeschalteter Analyse, am vorhandenen Gerät des Routers:

| Sensor | Wann | Einheit |
|---|---|---|
| WAN-Download-Rate | Gateway (Router mit WAN-Messung) | Datenrate |
| WAN-Upload-Rate | Gateway | Datenrate |
| WAN-Verkehr gesamt | Gateway | Bytes, `total_increasing` |
| WAN-Spitzenbandbreite (24 h) | Gateway | Datenrate |
| Uplink-Auslastung | nur bei bekannter Linkgeschwindigkeit | % |
| Uplink-Empfangsfehler | Diagnose, standardmäßig deaktiviert | Anzahl |
| Uplink-Sendefehler | Diagnose, standardmäßig deaktiviert | Anzahl |

Für die ganze Flotte, ohne Gerät:

- Aktive Traffic-Auffälligkeiten (alle Router)
- Abdeckung der Traffic-Messung (alle Router), in % der Messpunkte mit voller Abdeckung

Optional je ausgewähltem Client (höchstens 20): „WLAN-Verkehr am AP, Download …“ und
„… Upload …“, benannt mit dem Pseudonym.

Bei N Routern sind das höchstens 2 + 7·N + 40 Entitäten. Es gibt nie eine Entität je Flow,
VLAN, Port oder kurzlebigem Client.

„WAN-Verkehr gesamt“ zählt die gültigen Zuwächse seit dem Start des Moduls. Nach einem
Neustart von Home Assistant beginnt ein neuer Zählzyklus, den die Statistik von Home
Assistant als Zählerrücksetzung erkennt.

## 6. Verlauf, Profile und Speicherbedarf

Es gilt das tiefste Profil unter den Routern mit eingeschalteter Analyse, für die ganze
Flotte.

| | `compact` (Standard) | `standard` |
|---|---|---|
| Infrastruktur, 5-Minuten-Werte | 6 h | 1 d |
| Infrastruktur, stündlich | 14 d | 14 d |
| Infrastruktur, täglich | 31 d | 90 d |
| Clients, 5-Minuten-Werte | 6 h (nur im Speicher) | 6 h |
| Clients, stündlich | 2 d (nur im Speicher) | 2 d |
| Clients, täglich | – | 30 d |
| Client-Verlauf auf der Platte | nein | ja |

Gespeichert wird in zwei Dateien unter `.storage/`:
`openwrt_router.traffic_fine` (höchstens alle 30 Minuten geschrieben) und
`openwrt_router.traffic_coarse` (5 Minuten nach jedem abgeschlossenen Stundenwert). Jede
Datei ist auf 2 MiB begrenzt, mit festen Teilbudgets. Was nicht passt, fällt als Ältestes
heraus, und die Abdeckung sagt das.

**Gemessen** (Simulation über 30 Tage, Testflotte mit 102 Infrastruktur-Messpunkten und
150 Clients):

| | `compact` | `standard` |
|---|---|---|
| `traffic_fine` bei voller Haltezeit | ca. 0,28 MB | ca. 1,26 MB (Infrastruktur 0,93 + Clients 0,33) |
| `traffic_coarse` bei voller Haltezeit | ca. 1,37 MB | ca. 2,02 MB (1,59 + 0,43) |
| Messpunkte auf der Platte | 102 | 252 |

**Geschätzt, nicht gemessen** (aus den Schreibabständen hochgerechnet): Schreiblast
`compact` ca. 0,28 MB × 48 + 1,37 MB × 24 ≈ 46 MB am Tag, `standard` ca. 108 MB am Tag.
Auf einer SD-Karte ist `compact` deshalb die bessere Wahl.

Arbeitsspeicher: Für die Referenzflotte (6 Router, 102 Messpunkte, 150 Clients) belegte
das Modul nach 7 Stunden Abfragen ca. 5,9 MiB (Einzelmessung mit tracemalloc, kein
CI-Test). Der Test für 2 Router misst +1007 KiB in den ersten 5 Stunden und danach nur
noch +424 KiB, weil die 5-Minuten-Werte dann ihre feste Höchstzahl erreicht haben.

## 7. Leistung

Alle Werte stammen aus `tests/test_traffic_performance.py` auf der Entwicklungs-VM, mit
Mocks statt Routern. Die Grenzen im Test sind absichtlich weit, damit ein langsamer
CI-Rechner nicht scheitert.

| Messung | Gemessen | Grenze im Test |
|---|---|---|
| Router-Aufrufe je Abfrage: Analyse aus / an / gar nicht installiert | jeweils 20, gleiche Reihenfolge | an = aus = ohne |
| Zeit je Abfrage: ohne / aus / an | ca. 7 / 7 / 8–20 ms | Mehrzeit durch „an“ < 1 s je Abfrage |
| Runde über die Flotte (6 Router, 102 Messpunkte, 150 Clients) | Median ca. 10 ms, Maximum 30–80 ms | Median < 2 s |
| Spitzensensor über 71 Stundenwerte | 0,16 ms | < 250 ms |
| Flow-Speicher mit 2000 Flows: einen hinzufügen | 6,3 µs | < 10 ms |
| Flow-Speicher mit 2000 Flows: 200 abfragen | 2–3 ms | < 2 s |
| Collector-Aufruf mit 500 Flows (164 KiB von 256 KiB) | ca. 10 ms | < 5 s |
| Leseroute, langsamste (`capacity`) | ≤ 8,4 ms | < 2 s |
| Leseroute, größte Antwort (`clients`, 150 Clients) | 186 KB | < 1 MiB |
| Speicher, 2 Router über 10 h | +1007 KiB, dann +424 KiB | < 4 MiB, zweite Hälfte < 1,5 × erste + 64 KiB |

## 8. Externer Collector

Ein Collector ist ein eigenes Programm im Netz, das Verbindungsdaten (z. B. aus conntrack
oder NetFlow) sammelt und als Flows an Home Assistant **schickt**. Die Integration bringt
keinen Collector mit.

### 8.1 Einrichten

1. In Home Assistant einen eigenen Benutzer **ohne Admin-Rechte** anlegen,
   z. B. „Traffic-Collector“. Ein Administrator kann nie als Collector schreiben.
2. Als dieser Benutzer anmelden und im Profil ein **langlebiges Zugangstoken** erzeugen.
   Das Token gehört nur in die Konfiguration des Collectors. Home Assistant speichert nur
   die Benutzer-ID, nie das Token.
3. Im Tab Traffic Analytics unter **Einstellungen → Externer Collector** den
   Collector-Eingang einschalten, den Benutzer wählen und speichern.
4. Den Collector auf `https://<ihr-home-assistant>/api/openwrt_topology/traffic/collector/ingest`
   zeigen lassen, mit dem Kopf `Authorization: Bearer <token>`.

### 8.2 Nur HTTPS

Über einfaches HTTP lehnt die Route mit `403 insecure_transport` ab, weil das Token sonst
im Klartext reisen würde. Maßgeblich ist, ob Home Assistant die Anfrage als HTTPS sieht.

**Hinter einem Reverse Proxy** (z. B. NGINX, Caddy, Traefik), der TLS beendet und Home
Assistant über HTTP anspricht, muss der Proxy `X-Forwarded-Proto: https` setzen, **und**
Home Assistant muss ihm vertrauen:

```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 192.0.2.5   # Adresse des Proxys
```

Nur dann übernimmt Home Assistant das Schema aus `X-Forwarded-Proto`. Ohne diese
Einstellung sieht die Route HTTP und lehnt ab, obwohl der Collector HTTPS spricht.

### 8.3 Schema `traffic.collector.v1`

```json
{
  "schema": "traffic.collector.v1",
  "collector": "edge-1",
  "sent_at": 1795000000,
  "records": [
    {
      "kind": "flow",
      "window": {"start": 1794999940, "end": 1795000000},
      "direction": "orig",
      "proto": "tcp",
      "src": "192.0.2.10",
      "dst": "198.51.100.5",
      "src_port": 50000,
      "dst_port": 443,
      "client_mac": "02:00:5e:00:00:01",
      "bytes": 1200,
      "packets": 10,
      "observation": "observed"
    }
  ]
}
```

Hülle:

- `schema` muss genau `traffic.collector.v1` sein.
- `collector` ist ein Name mit höchstens 32 Zeichen, ohne Steuerzeichen.
- `sent_at` ist Unix-Zeit in Sekunden.
- `records` ist eine Liste.
- Andere Schlüssel sind nicht erlaubt.

Felder eines Flows:

| Feld | Pflicht | Werte |
|---|---|---|
| `kind` | ja | `flow` |
| `window` | ja | `{start, end}` in Unix-Sekunden, höchstens 1 h lang |
| `direction` | ja | `orig`, `reply`, `in`, `out` |
| `proto` | ja | `tcp`, `udp`, `icmp`, `other` |
| `router_id` | nein | `rtr_` + 32 Hex-Zeichen (Router-ID des Enterprise-Kerns) |
| `src`, `dst` | nein | IPv4- oder IPv6-Adresse |
| `src_port`, `dst_port` | nein | 0–65535 |
| `client_mac` | nein | MAC-Adresse; wird sofort zu einem Pseudonym `cli_…` |
| `vlan_id` | nein | VLAN-Nummer |
| `bytes`, `packets` | nein | ganze Zahlen ≥ 0 |
| `observation` | nein | `observed`, `aggregated`, `estimated_category` |

### 8.4 Grenzen

- Inhalt höchstens 256 KiB (sonst 413).
- Höchstens 500 Flows je Aufruf.
- JSON-Tiefe höchstens 4, Zeichenketten höchstens 64 Zeichen.
- Höchstens ein Aufruf alle 10 Sekunden (sonst 429 mit `Retry-After`).
- Zeiten höchstens 300 s in der Zukunft und höchstens 24 h alt.
- Flows bleiben standardmäßig 1 Stunde im Arbeitsspeicher, höchstens 500 je Quelle und
  2000 insgesamt. Sie werden nicht auf die Platte geschrieben.
- Höchstens 256 Flow-Quellen (Herkunft je Router) gleichzeitig. Eine stille Quelle wird
  nach der Aufbewahrungszeit vergessen; eine neue Quelle über der Grenze verdrängt die am
  längsten stille samt ihren Flows (Zähler `dropped_feeds`).

**Alles oder nichts:** Ein ungültiger Flow lehnt den ganzen Aufruf ab. Passt ein Aufruf
nicht vollständig in den Flow-Speicher, wird er als Ganzes abgelehnt (503 `store_full`).
Nichts wird teilweise übernommen.

### 8.5 Antworten und Fehlercodes

Angenommen (200):

```json
{"v": 1, "schema": "traffic.collector.v1", "accepted": 1, "rejected": []}
```

Abgelehnte Daten (400 / 503 / 429):

```json
{"v": 1, "schema": "traffic.collector.v1", "code": "records_rejected",
 "accepted": 0, "rejected": [{"index": 0, "reason": "timestamp_too_old"}],
 "rejected_total": 1}
```

Zugriff abgelehnt: `{"message": "…", "code": "…", "details": {…}}`.

| Status | Code | Bedeutung |
|---|---|---|
| 401 | – | kein oder ungültiges Token (prüft Home Assistant selbst) |
| 403 | `authorization_denied` | Collector aus, falscher Benutzer, Admin oder deaktivierter Benutzer |
| 403 | `insecure_transport` | kein HTTPS (Abschnitt 8.2) |
| 409 | `disabled` | an keinem Router ist die Analyse eingeschaltet |
| 410 / 503 | `integration_not_loaded` / `not_running` | Integration entladen oder noch nicht bereit |
| 413 | `body_too_large` | mehr als 256 KiB |
| 429 | `rate_limited` | schneller als ein Aufruf in 10 s |
| 400 | `not_json`, `not_an_object`, `unknown_key`, `too_deep`, `string_too_long` | Aufbau der Hülle |
| 400 | `schema_missing`, `schema_unsupported` | Schema fehlt oder ist ein anderes |
| 400 | `invalid_collector_name`, `invalid_sent_at`, `records_missing`, `too_many_records` | Felder der Hülle |
| 400 | `records_rejected` | mindestens ein Flow ungültig, Gründe je `index` |
| 503 | `store_full` | Flow-Speicher voll, später erneut senden |

Gründe je Flow: `unknown_field`, `not_a_flow_record`, `invalid_field`,
`timestamp_in_future`, `timestamp_too_old`, `window_too_long`, `module_key_missing`
(der Enterprise-Kern hat noch keinen Schlüssel für Pseudonyme), `kind_not_supported` und
`unknown_router`: Die `router_id` gehört zu keinem geladenen Router mit eingeschalteter
Analyse. Flows ohne `router_id` bleiben erlaubt.

**Wiederholter Aufruf:** Wird ein schon angenommener Aufruf erneut gesendet (z. B. nach
einem Timeout), bestätigt ihn das Modul mit der ersten Antwort und übernimmt die Flows
nicht noch einmal (Zähler `duplicate_calls`). Erkannt wird er an Benutzer, `sent_at` und
Inhalt der Flows; gemerkt werden die letzten 512 angenommenen Aufrufe, danach gilt eine
Wiederholung als neuer Aufruf. Auch die Wiederholung muss die Grenze von einem Aufruf je
10 Sekunden einhalten (sonst 429).

Abgelehnte Zugriffe (Collector aus, falscher Benutzer, HTTP) meldet das Modul zusätzlich
als sicherheitsrelevantes Kern-Ereignis `traffic_analytics.collector_rejected`, höchstens
10 je Stunde **je Grund und Benutzer** (der Benutzer nur als gesalzenes Pseudonym im
Arbeitsspeicher, nie im Ereignis). Ein Benutzer, der die Route wiederholt aufruft, kann
so die Meldungen anderer Fehlversuche nicht verdrängen. Höchstens 64 solcher Budgets
gelten gleichzeitig; darüber wird nur gezählt, nicht gemeldet.

### 8.6 Was nicht geht

- `client_aggregate` und `interface_aggregate` gehören zum Schema, werden aber mit
  `kind_not_supported` abgelehnt. Sie bräuchten eine eigene Collector-Zeitreihe neben der
  eigenen Messung, die es in dieser Version nicht gibt.
- Home Assistant fragt keinen Collector ab. Es gibt kein Pull und keinen Webhook nach
  außen.
- Der Collector kann keine Einstellungen ändern und nichts lesen.

## 9. Routen und Rechte

Basis: `/api/openwrt_topology/traffic`. Alle Routen brauchen einen angemeldeten
Benutzer und sprechen nie mit einem Router.

| Route | Wer |
|---|---|
| `GET overview`, `points`, `series`, `talkers`, `clients`, `vlans`, `capacity`, `anomalies`, `recommendations`, `evidence/{evr_…}` | Administratoren; andere nur bei freigegebenem Panel |
| `GET flows`, `GET settings`, `POST settings`, `GET collector/users` | nur Administratoren |
| `POST collector/ingest` | nur der eingetragene Collector-Benutzer (kein Admin), nur HTTPS |

`GET collector/users` nennt Benutzer nur mit Anzeigename und einer Referenz `usr_…`. Die
Referenz hängt an einem Zufallsschlüssel, der bei jedem Start von Home Assistant neu
entsteht. Keine Route gibt eine Benutzer-ID heraus.

Ist die Analyse aus, antworten die Leserouten mit `200` und `status: off`, ohne Verlauf
oder Speicher zu lesen. `POST settings` antwortet dann `409 disabled`.

## 10. Datenschutz

- Clients erscheinen nur als Pseudonym (`cli_…`), auch für Administratoren. Router,
  Messpunkte und Benutzer ebenso (`rtr_…`, `tpt_…`, `usr_…`). MAC-Adressen, Hostnamen,
  SSIDs und AP-Schnittstellennamen stehen in keinem Namen, keiner Unique-ID, keinem
  Attribut und keiner Antwort.
- Flows eines Collectors enthalten IP-Adressen. Sie bleiben nur im Arbeitsspeicher
  (Standard 1 Stunde, höchstens 2000 Flows) und kommen nie auf die Platte. Die Route
  `flows` ist nur für Administratoren und gibt Adressen und Clients nur als Pseudonym
  (`ipa_…`, `cli_…`) heraus.
- Das Log enthält nur Fehlertypen, keine Adressen, Benutzer-IDs oder Tokens (geprüft in
  `tests/test_traffic_quality.py`). Auf DEBUG-Stufe schreibt Home Assistant bei einem
  internen Fehler zusätzlich den Stacktrace.
- Die Diagnosedaten der Integration enthalten nur Zähler.

## 11. Benötigte Router-Rechte

Für die Grundmessung braucht es keine neuen Rechte. Die drei Zusatzabfragen nutzen
Rechte, die die automatische ACL-Einrichtung der Integration schon vergibt:

- `iwinfo assoclist` für `traffic_station_detail`
- Lesen unter `/sys/class/net/` für `traffic_sysfs_fallback`
- `uci get firewall` für `traffic_offload_probe`

Mit 1.49.0 kommen keine neuen ACL-Einträge hinzu. Fehlt einem Router ein Recht, etwa
weil die ACL von Hand angelegt wurde, meldet die Analyse diese Zusatzabfrage als nicht
verfügbar mit dem Grund `permission_denied`. Die Grundmessung läuft weiter.

## 12. Bekannte Grenzen und was nicht geprüft ist

- **Nicht an Geräten geprüft.** Alle Aussagen und Zahlen stammen aus Tests mit Mocks. Noch
  nicht an echten Routern gemessen ist, ob WAN- und Bridge-Zähler bei Hardware-Offload
  Verkehr verfehlen, ob DSA-Port-Zähler hardware-geschalteten Verkehr mitzählen und wie
  sich die Stationszähler von hostapd bei erneuter Anmeldung verhalten. Bis dahin steht
  die Abdeckung dort vorsichtig auf `partial`.
- **Nicht im Browser geprüft.** Der Tab ist mit Render-Tests geprüft, aber nicht in einem
  echten Browser und nicht auf einem 360 px breiten Bildschirm.
- Client-Zähler am AP sind kein Internetverbrauch.
- Ohne bekannte Linkgeschwindigkeit gibt es keine Auslastung, nur Raten.
- Auffälligkeiten erscheinen als Kern-Ereignisse und im Tab. Network Intelligence legt
  daraus noch keine eigenen Vorfälle an.
- Das Security Center nimmt die Traffic-Hinweise seit 1.49.1 als Eintrag in seiner Zeitleiste
  (mit `evidence_ref`) an, höchstens 20 je Stunde. Ein Hinweis wird dort nie allein ein
  Vorfall und zählt nicht für die Vertrauensstufe eines Geräts, weil dieselbe MAC in beiden
  Modulen verschiedene Pseudonyme hat. Die Quelle „Security Center“ zeigt „bereit“, solange
  das Security Center eingeschaltet und mit dem Kern verbunden ist, sonst den Grund.
- Funk-Messpunkte tragen intern den Schnittstellennamen. Seit 1.49.1 ordnet WiFi RF über
  seine Leseschnittstelle jedem Radio (Router-ID + UCI-Radioname) die Stations-Messpunkte zu;
  die Korrelation nennt je Radio Airtime, Wiederholungen und die zugehörigen Punkt-IDs. Der
  Schnittstellenname verlässt dabei keines der beiden Module.
- Zusammengefasste Collector-Werte werden abgelehnt (Abschnitt 8.6).
