# Bauplan Traffic Analytics (Phase 5, Phasen B–L)

<!-- Stand Phase A, 2026-11-20, Basis main v1.46.0. Nur Plan, kein Code.
     Auftrag: docs/plans/2026-11-20-traffic-analytics.md.
     Datenquellen: docs/dev/traffic-capability-matrix.md (Q1–Q14).
     Keine IPs, MACs, Hostnamen echter Geräte, Passwörter oder Tokens. -->

## 1. Grundsätze

1. **Standard aus.** Ohne Einschalten durch einen Admin:
   - kein Store, keine Entität, kein Event und kein Router-Aufruf;
   - nur ein Listener je Coordinator, der sofort zurückkehrt.
2. **Netzwerk nur in `api.py`.**
   - Entitäten lesen nur den Zustand der Engine (Dispatcher-Signal).
   - `coordinator.py` bekommt nur einen Datenblock, kennt aber keine Traffic-Typen.
3. **Keine Parallelstrukturen.** Es gibt keine zweite Registry, keine zweite Client-DB und
   keine zweite Incident- oder Anomalie-Engine. Traffic rechnet Raten, Summen, Baselines und
   Kandidaten. Incidents bleiben bei Network Intelligence (§10).
4. **Unbekannt bleibt unbekannt.**
   - `None` oder `unavailable` mit Grund, nie `0`, nie „ok“.
   - Messbereiche (§4 des Auftrags) werden nie addiert.
   - Ein WLAN-Station-Wert heißt nie „Internetverbrauch“.
5. **Keine fremden Moduldateien.** `config_*`, `security_*`, `core_*`, `net_*`, `diag_*`,
   `client_*`, `config_flow.py`, `enterprise/config/*` und `enterprise/security/*` bleiben
   unverändert. Was fehlt, steht in §10 als „Wunsch an Modul X“.
6. **Router-Schonung.**
   - Kein unbegrenzter conntrack-Dump, kein Paketmitschnitt, kein Exec, kein neues SSH.
   - Zusatzaufrufe sind je Router schaltbar und begrenzt (§6.2).

## 2. Modulschnitt

### 2.1 Python (`custom_components/openwrt_router/`)

| Datei | Verantwortung (ein Satz) | Phase |
|---|---|---|
| `traffic_const.py` | Modulinterne Konstanten (Grenzen, Raster, Fenster, Reason-Codes), damit `const.py` nur Store-Keys, Signale und Unique-ID-Präfixe trägt. | B |
| `traffic_model.py` | Frozen Dataclasses und StrEnums für Messpunkt, Sample, Rate, Bucket, Flow-Record und Anomalie-Kandidat (§3). | B |
| `traffic_counters.py` | Reine Funktionen für Zähler-Deltas mit Reset-, Überlauf-, Neustart-, Lücken- und Plausibilitätsprüfung (§3.3), ohne HA-Abhängigkeit. | B |
| `traffic_collect.py` | Macht aus einem `coordinator.data`-Schnappschuss Samples und plant die schaltbaren Zusatzaufrufe über `api.py` mit Grenzen und Backpressure. | B |
| `traffic_accounting.py` | Ordnet Samples Messbereichen zu, setzt Perspektive (RX/TX), Abdeckung und Datenqualität und verhindert Doppelzählung. | C |
| `traffic_clients.py` | Ordnet WLAN-Station-Zähler über die bestehende Client-Engine Clients zu (`client_ref`) und behandelt Roaming und Re-Assoziation. | D |
| `traffic_vlan.py` | Bildet VLAN-Verkehr nur aus gemessenen VLAN-netdevs ab und trennt ihn von der konfigurierten Zugehörigkeit (`port_vlan_map`). | D |
| `traffic_talkers.py` | Rangliste je Fenster und Bereich mit Kennzeichnung „partiell“ und ohne Mehrfachzählung über APs. | E |
| `traffic_flows.py` | Normalisiert Flow-Records aus dem Collector (und später begrenzten Snapshots), hält sie nur im RAM und begrenzt ihre Zahl. | E |
| `traffic_anomaly.py` | Robuste Baselines (Median/MAD je Wochentag und Stunde), Kandidaten mit Unterdrückungsregeln und Event-Budget. | F |
| `traffic_capacity.py` | Auslastung gegen Link-Geschwindigkeit, Mittel, Spitze, P95 und vorsichtige Trends mit Mindestdatenbasis. | G |
| `traffic_correlate.py` | Liest Ereignisse von NI, Security, Diagnose und WiFi RF und verknüpft sie mit Traffic-Messungen, mit Status je Quelle. | H |
| `traffic_history.py` | Buckets, Verdichtung (Roh → 5 min → 1 h → 1 d), Retention, Quoten und Abfragen mit Punktgrenze. | I |
| `traffic_store.py` | Laden und Speichern über `core_store.create_store`/`async_load_store` (zwei Stores, §5), Größenkappung je Teil. | I |
| `traffic_engine.py` | Lebenszyklus: Setup, Release, Coordinator-Listener, Queue, Core-Registrierung (Event-Präfix, Capability-Detector, Modulschlüssel), Diagnose-Zusammenfassung. | B, L |
| `traffic_views.py` | HTTP-Routen unter `/api/openwrt_topology/traffic` nach dem Muster von `security_views.py` (§7). | J |
| `traffic_entities.py` | Fleet- und Router-Sensoren aus §17, optional begrenzte Client-Sensoren, Entfernen aus der Registry beim Ausschalten. | K |
| `traffic_collector.py` | Versioniertes Eingangsschema für externe Collector, Prüfung, Grenzen und Auth-Abgleich (§8). | K |

### 2.2 Frontend (`frontend/topology/src/enterprise/traffic/`)

| Datei | Inhalt | Phase |
|---|---|---|
| `register.ts` | `registerEnterpriseTab({id:"traffic", order:30, …})` und `bindTrafficHass`/`installTrafficMock` wie `security/register.ts` | J |
| `api.ts`, `types.ts` | Fetch-Wrapper (HA-Token, kein Cache) und Typen 1:1 zu §7 | J |
| `TrafficTab.tsx` | Rahmen mit Unterseiten und Zustand „aus / lädt / Fehler / nicht verfügbar“ | J |
| `Overview.tsx`, `Timeline.tsx`, `TopTalkers.tsx`, `FlowExplorer.tsx`, `Capacity.tsx`, `Coverage.tsx`, `Recommendations.tsx`, `Settings.tsx` | Sichten aus §15 des Auftrags; jede zeigt Abdeckung und Quelle | J |
| `mock.ts` | Testdaten nur hinter `import.meta.env.DEV` (wie `main.tsx` L290-306), nie im Produktivbundle | J |
| `traffic.test.mjs` | `node --test` Vertragsprüfungen (Schema, „nicht verfügbar“ statt 0, Pseudonyme) | J, L |

### 2.3 Tests (`tests/test_traffic_*.py`) — die 33 Bereiche aus §21

| Testdatei | Bereiche |
|---|---|
| `test_traffic_counters.py` | 1 Interface-RX/TX, 2 Datenraten, 3 Counter-Reset, 4 Überlauf, 5 Router-Neustart, 6 Interface-Neustart, 7 Messlücken, 8 Zeitstempel |
| `test_traffic_accounting.py` | 9 NAT, 10 HW-Offloading, 11 Doppelzählung |
| `test_traffic_clients.py` | 12 Client-Zuordnung, 13 Roaming, 25 hohe Client-Anzahl |
| `test_traffic_vlan.py` | 14 VLAN |
| `test_traffic_talkers.py` | 15 Top-Talker |
| `test_traffic_flows.py` | 16 fehlende Flow-Daten, 17 conntrack-Snapshot |
| `test_traffic_anomaly.py` | 18 Anomalie, 19 normale Spitzen, 20 Baselines |
| `test_traffic_capacity.py` | 21 Kapazität, 22 P95 |
| `test_traffic_history.py` | 23 Aggregation, 24 Retention |
| `test_traffic_engine.py` | 26 hohe Ereignislast, 27 Backpressure |
| `test_traffic_views.py` | 28 Dashboard-Verträge, 32 Datenschutz/Zugriff |
| `test_traffic_entities.py` | 29 HA-Entitäten |
| `test_traffic_correlation.py` | 30 Security-Korrelation, 31 Diagnose-Korrelation |
| `test_traffic_collector.py` | Collector-Schema, Auth, Größe (ergänzt 16, 32) |
| `test_traffic_regression.py` | 33 Regressionen |

Bausteine für Bereich 33:
- Aus: 0 zusätzliche ubus-POSTs; das Muster ist `test_active_center_adds_no_router_calls`
  in `test_security_center.py`.
- Bestehende `unique_id`s bleiben unverändert.
- `coordinator.data.as_dict()` bleibt unverändert.
- Die bestehenden Sensoren `wan_rx`, `wan_tx` und Interface-Rate verhalten sich wie
  bisher.

Hilfen:
- `tests/conftest.py`: `mock_coordinator_data` L355 und `network_stub` (autouse, blockt
  echtes Netz) L720.
- `core_testkit.py`: `FakeEntry`, `FakeCoordinator`, `make_hass`, `user_actor`.
- Alle Tests laufen ohne Router.

## 3. Datenmodell

### 3.1 Messpunkt

```
MeasurementPoint (frozen):
  router_id: str | None   # rtr_<32 hex> aus dem Core; None nur für Collector-weite Punkte
  scope: Scope            # INTERFACE | PORT | STATION | CLIENT | VLAN | FLOW | WAN
  device: str | None      # netdev-Name (br-lan, lan2, WAN-l3_device)
  vlan_id: int | None     # 1..4094, nur wenn gemessen (VLAN-netdev)
  radio_id: str | None    # Funk-Identität (siehe Entscheidung E7)
  client_ref: str | None  # cli_<16 hex>, nie MAC/IP/Hostname
  point_id -> "tpt_" + sha256(kanonische Felder)[:16]
```

- Feldnamen sind `router_id`, `radio_id` und `client_ref`, **nie `*_key`**. Grund:
  Felder auf `_key` maskiert der Core als Identifier.
- `point_id` ist deterministisch und braucht keinen Schlüssel. Die Eingaben sind schon
  Pseudonyme oder nicht geheim.
- Ein anderes `device` ergibt einen neuen Messpunkt. Das gilt zum Beispiel für ein anderes
  WAN-`l3_device`.

### 3.2 Enums

| Enum | Werte |
|---|---|
| `Scope` | `interface`, `port`, `station`, `client`, `vlan`, `flow`, `wan` |
| `Coverage` | `full`, `partial`, `estimated`, `unavailable`, `unknown` |
| `Quality` (je Delta) | `ok`, `first_sample`, `gap`, `time_not_advancing`, `router_restart`, `counter_reset`, `wrap_32`, `implausible`, `stale_source`, `source_missing` |
| `Perspective` | `router` (netdev), `station` (AP-Sicht auf Client), `flow_orig` |
| `Source` | `netdev` (Q1), `sysfs` (Q2), `hostapd` (Q7), `iwinfo` (Q8), `conntrack_count` (Q6a), `collector` (Q12), `derived` |
| `CoverageReason` | `station_counters_only`, `roaming_gap`, `hw_offload_unknown`, `hw_offload_on`, `no_wired_client_source`, `needs_flow_source`, `source_disabled`, `module_missing` |

### 3.3 Datensätze

| Typ | Felder |
|---|---|
| `Sample` | `point`, `mono_s` (aus dem Poll), `wall_s`, `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `rx_errors`, `tx_errors`, `rx_dropped`, `tx_dropped` (alle `int \| None`), `link_mbps`, `duplex`, `source`, `router_uptime_s` |
| `Rate` | `point`, `interval_s`, `rx_bps`, `tx_bps`, `rx_delta`, `tx_delta`, Fehler- und Drop-Deltas, `quality`, `coverage`, `coverage_reason` |
| `Bucket` | `start` (ausgerichtet), `resolution_s`, `rx_bytes`, `tx_bytes`, `rx_peak_bps`, `tx_peak_bps`, `covered_s`, `samples`, `quality_mask`; optional `hist_rx`/`hist_tx` (12 log-Klassen, nur Vorrangpunkte, §5) |
| `FlowRecord` | `router_id`, `client_ref`, `vlan_id`, `proto`, `src`, `dst`, `src_port`, `dst_port`, `start`, `end`, `bytes`, `packets`, `direction`, `kind` (`observed`/`aggregated`/`estimated_category`/`unknown`), `source`, `nat_seen` |
| `AnomalyCandidate` | `candidate_id`, `point_id`, `router_id`, `client_ref`, `kind`, `observed`, `baseline_median`, `baseline_mad`, `threshold`, `window_s`, `confidence`, `coverage`, `started`, `last_seen`, `state` (`open`/`ended`), `suppressed_reason`, `incident_ref` (falls NI einen hat) |

**Rechenregeln:**
- Die Abdeckung eines Buckets ist `covered_s / resolution_s`.
- Liegt sie unter 0,5, heißt der Bucket „lückenhaft“ und zählt nicht in P95 oder
  Baselines.
- Summen über Fenster nennen immer die Abdeckung mit.

### 3.4 Zählerverarbeitung (`traffic_counters.delta`)

Die Prüfungen laufen in dieser Reihenfolge. Die erste, die greift, entscheidet.

1. **Gültiger Zähler:** `int ≥ 0`, kein `bool`; sonst `None` und `source_missing`.
   - Bytes = 0 aus dem Default von `get_port_stats` (`api.py` L4377) gibt es hier nicht,
     weil Traffic die Rohwerte aus dem Coordinator-Block liest (§11).
2. **Zeit:** `dt = mono_s − prev.mono_s`, gemessen im Poll, nicht beim Listener.
   - `dt ≤ 0` → `time_not_advancing`.
   - `dt < 5 s` → überspringen, alte Basis bleibt (wie `_WAN_RATE_MIN_INTERVAL_S`,
     `coordinator.py` L149).
3. **Lücke:** `dt > 900 s` (wie `_WAN_RATE_MAX_INTERVAL_S`, L150) oder ein
   `vlans_stale`-Poll → `gap`.
   - Es gibt eine neue Basis und keine Rate.
   - Die Bytes in der Lücke werden keinem Bucket zugeschlagen.
4. **Router-Neustart:** Er gilt als erkannt, wenn
   - `router_uptime_s` bekannt (> 0) ist und kleiner als vorher, oder
   - `router_uptime_s < dt`.
   Dann gilt `router_restart` für **alle** Punkte des Routers.
   - `uptime = 0` heißt unbekannt (`coordinator.py` L326), nicht Neustart.
5. **Rückgang ohne Neustart:**
   - 32-Bit-fähige Quelle (`hostapd`, Annahme in der Matrix Q7) und `prev < 2³²`:
     - Kandidat `wrap_32`: `delta = cur + 2³² − prev`.
     - Er wird nur angenommen, wenn die Rate unter der Plausibilitätsgrenze (6.) liegt.
     - Sonst `counter_reset`.
   - 64-Bit-Quellen: immer `counter_reset`. Das gilt auch für den Neustart eines
     Interfaces.
6. **Plausibilitätsgrenze je Richtung:**
   - Grundwert: `link_mbps × 125 000 × 1,05`.
   - Halbduplex: Grenze für RX + TX zusammen.
   - Ohne Link-Geschwindigkeit gelten Startwerte je Bereich: WAN und Interface 10 Gbit/s,
     Station 2,4 Gbit/s. Das sind Startwerte, nicht kalibriert.
   - Darüber → `implausible`, keine Rate, neue Basis.
7. **Zuordnungswechsel:** ein anderes `device` (WAN-Wechsel) oder ein anderer Router bzw.
   Radio derselben Station → neuer Messpunkt bzw. neue Basis, kein Vergleich.
8. **Nach einem HA-Neustart** (monotone Zeit ist verloren):
   - Der letzte Zählerstand je Punkt ist mit `wall_s` und `router_uptime_s`
     gespeichert.
   - Ein Delta über den Neustart gilt nur, wenn
     - `|Δuptime − Δwall| ≤ 10 s` (Muster `rf_utilization.UPTIME_MISMATCH` im
       WiFi-RF-Zweig), und
     - `Δwall ≤ 900 s`.
   - Sonst `gap`.

### 3.5 Accounting-Regeln (Phase C)

- Erlaubte Summen gibt es nur **innerhalb** eines Bereichs und ohne Überlappung:
  - WAN über alle Gateways;
  - Ports eines Routers nur, wenn keiner davon Uplink eines anderen gezählten Routers
    ist.
- **Nie** summiert werden:
  - Station + Port;
  - Interface + VLAN;
  - Client + WAN;
  - `br-lan` + Ports.
- **Doppelte Sichtung:** Ein Client, der im selben Poll an zwei APs erscheint, zählt nur
  am AP, den `client_engine` als aktuell meldet. Der andere Eintrag bekommt
  `quality=stale_source`.
- **HW-Offload:**
  - Solange `traffic.offload_state` unbekannt ist, tragen WAN und `br-lan`
    `coverage=partial` mit Grund `hw_offload_unknown`.
  - Bei bekannt aktivem HW-Offload ist der Grund `hw_offload_on`.
- **NAT:**
  - WAN-Zähler zeigen den Verkehr am Anschluss.
  - Eine Zuordnung zu Clients ist nur aus Flow-Quellen möglich, sonst `unavailable`.

## 4. Client- und VLAN-Zuordnung (Phase D)

**Identität:**
- `traffic_clients` liest `client_engine.async_get_client_engine(hass).history.live(mac)`.
  Das liefert AP, Band und Zustand (`client_history.ClientLive`) und ist nur lesend.
- `client_ref = pseudonymise_identifier("client", mac, module_key)` mit dem Traffic-Modulschlüssel.
- Eine neue IP ändert nichts, denn der Schlüssel ist die MAC.
- Eine neue (randomisierte) MAC ergibt einen neuen Client. Es wird nichts
  zusammengeführt.

**Grenzen:**
- Nur WLAN-Clients bekommen Bytes.
- Kabelclients erscheinen mit „Port zuletzt gesehen“ aus `port_fdb_map`, aber ohne
  Bytes, als `coverage=unavailable`.

**Roaming:**
- Je Assoziation `(client_ref, router_id, radio_id)` gibt es eine eigene Basis.
- Der Client-Bucket ist die Summe gültiger Deltas aller seiner Assoziationen im Bucket.
  Das ist keine Doppelzählung, weil jede Assoziation nur ihre eigenen Deltas liefert.
- Der Verlust beim Wechsel wird als `roaming_gap` gezählt und markiert die Abdeckung als
  `partial`.

**VLAN:**
- Ein VLAN-Wert entsteht nur aus einem gemessenen VLAN-netdev (Q1).
- Die konfigurierte Zugehörigkeit (`port_vlan_map`) wird nur angezeigt.
- Inter-VLAN-Verkehr ist nur mit einer Flow-Quelle möglich, sonst `unavailable`.

## 5. Speicherung (Phase I)

**Stores** (über `core_store.create_store(hass, version, key, private=True, atomic_writes=True)`
und `async_load_store`; `.bak` und `.corrupt.` behandelt der Core):

| Store | Inhalt | Obergrenze | Schreiben |
|---|---|---|---|
| `openwrt_router.traffic_fine` | 5-min-Buckets, letzter Zählerstand je Punkt | 2,0 MB | alle 30 min (Verzögerung) und beim Stoppen |
| `openwrt_router.traffic_coarse` | 1-h- und 1-d-Buckets, Histogramme, Einstellungen, Kandidaten-Historie | 2,0 MB | nach jedem Stundenwechsel (+300 s Verzögerung) und beim Stoppen |

**Raster und Aufbewahrung:**

| Stufe | Auflösung | Infrastruktur (Interface/Port/VLAN/WAN) | Client/Station | Ort |
|---|---|---|---|---|
| Roh | je Poll (60/120/300 s) | 2 h | 1 h | nur RAM |
| fein | 5 min | 24 h | 6 h | `traffic_fine` |
| Stunde | 1 h | 7 d | 48 h | `traffic_coarse` |
| Tag | 1 d | 90 d (§14 optional) | 30 d | `traffic_coarse` |

**Quoten** (keine Quelle verdrängt eine andere):

| Quote | Grenze | bei Überschreitung |
|---|---|---|
| Infrastruktur-Punkte | 32 je Router, 160 gesamt | neuer Punkt abgelehnt, `dropped_points_infra += 1` |
| Client-Punkte | 200 | Ein Punkt, der > 24 h inaktiv ist, darf ersetzt werden. Ein aktiver nie. Sonst abgelehnt, `dropped_points_client += 1`. |
| Flow-Records (RAM) | 2000 gesamt, 500 je Router, TTL 1 h | ältester Record **derselben Quelle** fällt, `dropped_flows += 1` |
| Anomalie-Kandidaten | 50 offen, 200 Historie | ältester beendeter fällt; offene nie |
| Store-Teil Infrastruktur / Client / Rest | 1,3 / 0,6 / 0,1 MB je Store | älteste Buckets **dieses Teils** fallen, `store_trimmed_<teil> += 1` |
| Queue Coordinator → Engine | 1 Schnappschuss je Router | neuer ersetzt alten unverarbeiteten, `dropped_snapshots += 1` |
| Events an den Core | 30 je Stunde gesamt, 1 je Punkt und Art je 6 h | `dropped_events_budget += 1` |

Alle Zähler stehen in `/overview` (§7) und in den HA-Diagnosedaten.

**Größenabschätzung** für 6 Router, ~100 Infrastruktur-Punkte (≈ 17 je Router) und
~150 Clients:

- **Bucket:** kompakt als JSON-Array, ≈ 45 B.
- **Fein:**
  - Infrastruktur: 100 × 288 × 45 B ≈ 1,3 MB.
  - Clients: 150 × 72 × 45 B ≈ 0,5 MB.
  - Zusammen ≈ 1,8 MB.
- **Grob:**
  - Infrastruktur: 100 × (168 + 90) × 45 B ≈ 1,2 MB.
  - Clients: 150 × (48 + 30) × 45 B ≈ 0,5 MB.
  - Histogramme für ≤ 24 Vorrangpunkte (WAN, Uplinks, VLAN-netdevs), 90 d: ≈ 0,15 MB.
  - Zusammen ≈ 1,85 MB.
- **Platte:** ≈ 3,7 MB, mit `.bak`-Kopien ≈ 7,4 MB.
- **Schreiblast:** fein 48 × 1,8 MB ≈ 86 MB/Tag, grob 24 × 1,85 MB ≈ 44 MB/Tag, zusammen
  ≈ 130 MB/Tag.
- **RAM:**
  - Spaltenweise `array('q')` statt Listen von Python-Ints.
  - Roh: (100 × 120 + 150 × 60) × 10 Werte × 8 B ≈ 1,7 MB.
  - Buckets: ≈ 3,5 MB.
  - Zusammen ≈ 5–6 MB in HA. Auf dem Router entsteht nichts.

Zum Vergleich: Client-Historie 3 MB (`client_history`), Security-Store 512 KB
(`const.SEC_STORE_MAX_BYTES` L772).

**Neustart:**
- Nach dem Laden beginnt jede Reihe mit einer markierten Lücke bis zum ersten gültigen
  Delta (§3.4 Punkt 8).
- Es wird nichts interpoliert.

**Abfragen:**
- Höchstens 500 Punkte je Reihe; das ist die Grenze `MAX_POINTS` wie
  `rf_aggregate.MAX_POINTS` im WiFi-RF-Zweig.
- Das Fenster bestimmt die Auflösung: 1 h → roh/5 min, 24 h → 5 min, 7 d → 1 h,
  30/90 d → 1 d.

**P95:**
- Für ≤ 24 h exakt aus den 5-min-Raten.
- Für 7, 30 und 90 Tage aus den Tageshistogrammen, als „geschätzt (Klassenbreite)“
  gekennzeichnet.

## 6. Erfassung (Phase B)

### 6.1 Stufe A-Standard — nur `coordinator.data`, 0 zusätzliche Router-Aufrufe

**Ablauf:**
- `traffic_engine` hängt sich mit `coordinator.async_add_listener` an jeden Coordinator.
  Das ist ein HA-Standardweg und keine Änderung an `net_*`.
- Der Listener kopiert die Felder synchron und legt sie in die Queue
  (1 Schnappschuss je Router). Die Verarbeitung läuft in einer Task.

**Eingaben** (Quellen siehe Matrix §3):

| Feld | Eingabe |
|---|---|
| `device_counters` (neu, §11) | rohe netdev-Zähler aller Geräte (Q1) |
| `counters_sampled_mono` (neu) | monotone Zeit des Q1-Abrufs |
| `wan_status` | WAN-Gerät und Up-Zustand |
| `wan_traffic` | nur zur Anzeige im Abgleich, nicht als Quelle |
| `port_stats` | Link-Geschwindigkeit und Duplex |
| `clients` | Station-Bytes |
| `uptime` | Neustart-Erkennung |
| `active_connections` + `active_connections_source` (neu) | conntrack-Anzahl, nur wenn die Quelle die Zähldatei ist |
| `port_vlan_map`, `port_fdb_map` | Konfiguration und Zuordnung |
| `vlans_stale` | Lücke |

### 6.2 Stufe A-schaltbar — Zusatzaufrufe (alle Standard aus, je Router, nur in `api.py`)

| Option (Traffic-Einstellungen, je `router_id`) | Aufruf | Grenze | Recht |
|---|---|---|---|
| `traffic_station_detail` | ubus `iwinfo assoclist {"device": <ap-if>}` | alle 300 s; ≤ 4 AP-Interfaces je Router; ≤ 256 Stationen je Antwort; Timeout 10 s; ausgelassen, solange das Modul WiFi RF dieselben Zahlen liefert | v8 (`iwinfo assoclist`) |
| `traffic_sysfs_fallback` | ubus `file read /sys/class/net/<dev>/statistics/<zähler>` | nur für Geräte, die Q1 nicht liefert; ≤ 4 Geräte × 8 Dateien je Router; alle 300 s; `<dev>` nur aus der Q1-/Interface-Liste, Muster `^[A-Za-z0-9._@-]{1,15}$`, kein `/` und kein `..` | v8 (`/sys/class/net/*`, `/sys/devices/*/net/*`) |
| `traffic_offload_probe` | ubus `uci get {"config":"firewall","type":"defaults"}` → nur `flow_offloading`, `flow_offloading_hw` | 1× je Setup und alle 6 h; Antwort ≤ 16 KB, sonst verworfen | Annahme: über den root-Login lesbar; sonst optionale Stufe mit `("uci","firewall","")`, das schon in `OPTIONAL_TIER_ALLOWLIST` steht (`acl_provisioning.py` L723-731, über `CONFIG_BACKUP_UCI_CONFIGS` L516) |

**Gemeinsame Grenzen:**
- Je Router höchstens 1 Traffic-Aufruf gleichzeitig.
- Gesamt höchstens 2 gleichzeitig (Semaphore).
- Kein Aufruf, solange
  - der Coordinator-Poll dieses Routers läuft,
  - der Router gedrosselt ist (CPU, `coordinator._interval_for_state` L1274), oder
  - der Router auf SSH-Fallback steht.
- Nach 3 Fehlern in Folge pausiert der Aufruf 1 h. Der Grund steht in der Capability
  `traffic.*`.

**Nicht angeboten** (Matrix):
- `/proc/net/dev`: Glob-Problem, und Q1 reicht.
- nft-Zähler und rtnetlink: Exec.
- conntrack-Snapshot: unbegrenzt.
- `hostapd get_status` (Airtime): Das gehört zu WiFi RF.

## 7. Routen (Phase J)

Basis `/api/openwrt_topology/traffic`. Alle Routen haben `requires_auth = True` und
`Cache-Control: no-store`. Sie laufen über eine Basisklasse `_TrafficView._respond` nach
`security_views._SecurityView._respond` (L360-405).

**Reihenfolge in `_respond`:**
1. Benutzer fehlt → 403 `authorization_denied`.
2. Schreibend und kein Admin → 403.
3. Kein Admin und Panel nicht für alle offen (`topology_panel._panel_open_to_all`) → 403.
4. Integration entladen (`_PANEL_VIEW_DISABLED_KEY`) → 410.
5. **Erst jetzt** der Funktionsschalter: Traffic aus → 409 `disabled`; nicht geladen → 503
   `not_running`.
6. **Erst jetzt** Body lesen:
   - Größe über der Grenze → 413.
   - JSON-Tiefe > 3 (Einstellungen) → 400 `nested_json`.
   - Unbekannter Schlüssel → 400.
7. Fehler im Handler:
   - `AuthorizationError` → 403 `authorization_denied` mit festem Body.
   - Sonst 500 `internal`; geloggt wird nur der Typ.

| Pfad | Methode | Wer | Body-Grenze | Antwort (grob) |
|---|---|---|---|---|
| `/overview` | GET | Admin; Nicht-Admin bei offenem Panel | – | `{v:1, enabled, generated_at, coverage:{points_full, points_partial, points_unavailable, reasons{}}, wan:[{router_id, down_bps, up_bps, quality, coverage}], talkers_top5:[…], anomalies_open, vlans:[…], flow_sources:[{source, state, reason}], correlation_sources:[{module, state}], drops:{…}}` |
| `/points?router_id&scope` | GET | wie oben | – | `{v:1, points:[{point_id, router_id, scope, device, vlan_id, radio_id, client_ref, label, coverage, source, last_seen}]}`; ≤ 500 |
| `/series?point_id&window` | GET | wie oben | – | `{v:1, point_id, window_s, resolution_s, perspective, points:[{ts, rx_bytes, tx_bytes, rx_peak_bps, tx_peak_bps, coverage}], gaps:[…]}`; ≤ 500 Punkte |
| `/talkers?window&scope&direction&limit` | GET | wie oben | – | `{v:1, window_s, scope, partial:bool, partial_reasons:[…], rows:[{point_id, client_ref, router_id, rx_bytes, tx_bytes, current_bps, share_pct\|null, last_active}]}`; `limit ≤ 50`; `share_pct` nur bei vollständig abgedeckter Summe |
| `/capacity?router_id` | GET | wie oben | – | `{v:1, rows:[{point_id, link_mbps, duplex, avg_pct, peak_pct, p95_pct, p95_estimated, trend:{slope_pct_per_week\|null, basis_days, estimate:true}}]}` |
| `/anomalies?state&limit` | GET | wie oben | – | `{v:1, rows:[AnomalyCandidate ohne Rohwerte]}`; `limit ≤ 100` |
| `/flows?router_id&client_ref&proto&limit` | GET | **nur Admin** | – | `{v:1, source_state, rows:[FlowRecord]}`; `limit ≤ 200`; ohne Quelle 409 `flow_source_unavailable` |
| `/evidence/{evidence_ref}` | GET | wie `/overview` | – | Bucket-Ausschnitt, auf den ein Incident oder Hinweis zeigt (`evr_<16 hex>`, ±1 h) |
| `/settings` | GET, POST | **nur Admin** | 4096 B, Tiefe 3 | `{v:1, enabled, routers:{<router_id>:{station_detail, sysfs_fallback, offload_probe}}, history_profile, client_sensors:[client_ref], collector:{enabled, user_id_pseudonym, schema}}` |
| `/collector/ingest` | POST | nur der freigegebene Collector-Benutzer (§8) | 256 KiB | `{v:1, accepted, rejected:[{index, reason}]}` |

**Datenschutz in den Antworten:**
- **Nicht-Admins:**
  - Sie sehen nur `client_ref` und `router_id`, keine MAC, IP oder Hostnamen.
  - `label` ist dann ein Pseudonym.
  - Keine Flows.
- **Admins:**
  - Sie sehen Hostnamen und IPs aus der Client-Engine nur, wenn die Anfrage über HTTPS
    kam (`request.secure`).
  - Sonst bekommen sie Pseudonyme plus `identifiers_hidden: "insecure_transport"`. Das
    folgt dem Muster `config_views.REASON_INSECURE_TRANSPORT` L562.
- **Collector-Eingang:** Er wird über Klartext-HTTP immer abgelehnt (403
  `insecure_transport`).
- **Pfadparameter:**
  - Feste Regex für `point_id`, `router_id`, `client_ref` und `evidence_ref`.
  - Fenster aus einer festen Liste.
  - Es werden nie Pfade aus Eingaben gebaut. Das ist der Schutz gegen Path Traversal.

## 8. Collector-Schnittstelle Stufe B (nur Eingang, nichts wird installiert)

**Richtung:**
- Der Collector schiebt Daten per Push in HA (`POST /collector/ingest`).
- HA ruft keinen Collector auf. So bleibt jeder ausgehende Netzwerkaufruf in `api.py`, und
  es gibt keinen neuen.

**Auth:**
- Nötig ist ein HA-Benutzer, den ein Admin in den Traffic-Einstellungen als Collector
  einträgt. Gespeichert wird nur seine `user_id`.
- Dieser Benutzer ist **kein** Admin und nutzt ein Long-Lived Token.
- `requires_auth` prüft das Token, die Route prüft `user.id == collector_user_id`.
- Ein anderer Benutzer bekommt 403. Auch ein Admin kann nicht als Collector schreiben.
- Klartext-HTTP wird abgelehnt.
- Fehlversuche werden als Core-Event mit `security_relevant=True` gemeldet (Event-Budget
  §5).

**Grenzen:**
- Body ≤ 256 KiB.
- ≤ 500 Records je Aufruf.
- ≤ 1 Aufruf je 10 s, darüber 429 mit `Retry-After`.
- JSON-Tiefe ≤ 4.
- Strings ≤ 64 Zeichen.
- Unbekannte Felder → Record abgelehnt (nicht der ganze Aufruf).

**Schema `traffic.collector.v1`:**
```
{ "schema": "traffic.collector.v1",          # Pflicht; Major-Abweichung -> 400
  "collector": "<name ≤ 32>",                 # frei, nur Anzeige
  "sent_at": <unix s>,
  "records": [
    { "kind": "flow" | "client_aggregate" | "interface_aggregate",
      "router_id": "rtr_…" | null,            # aus HA bekannt, sonst null
      "window": {"start": <unix s>, "end": <unix s>},   # end-start ≤ 3600
      "direction": "orig" | "reply" | "in" | "out",
      "proto": "tcp" | "udp" | "icmp" | "other",
      "src": "<ip>", "dst": "<ip>", "src_port": int|null, "dst_port": int|null,
      "client_mac": "<mac>" | null,          # wird sofort zu client_ref, nie gespeichert
      "vlan_id": int|null,
      "bytes": int|null, "packets": int|null,
      "observation": "observed" | "aggregated" | "estimated_category" }
  ] }
```

**Zeitregeln:**
- Zeitstempel mehr als 300 s in der Zukunft → Record abgelehnt.
- Älter als 24 h → abgelehnt.

**Ablage:**
- Flows bleiben nur im RAM (Quote §5).
- Persistiert werden nur anonymisierte Aggregate: je `client_ref`, Protokoll und
  Zielport-Klasse, ohne IP.
- `client_aggregate` und `interface_aggregate` werden zu Buckets mit `source=collector`.
  Sie stehen neben den nativen Werten und werden nie mit ihnen addiert.

## 9. Sensoren (§17, Phase K)

Fleet-Sensoren nutzen das Präfix `const.FLEET_UID_PREFIX` (L619), wie
`security_entities.py`. Router-Sensoren hängen am bestehenden Router-Gerät. Alle
Sensoren haben `has_entity_name` und `translation_key`. Ihr Wert ist `None`
(unavailable), solange Traffic aus ist oder die Daten fehlen.

| Sensor | Ebene | device_class | state_class | Einheit |
|---|---|---|---|---|
| WAN Download Rate | Gateway-Router | `DATA_RATE` | `MEASUREMENT` | `bit/s` (Anzeige `Mbit/s` per `suggested_unit_of_measurement`) |
| WAN Upload Rate | Gateway-Router | `DATA_RATE` | `MEASUREMENT` | `bit/s` |
| WAN Traffic Total | Gateway-Router | `DATA_SIZE` | `TOTAL_INCREASING` | `B` (Anzeige `GiB`); Summe gültiger Deltas RX+TX, übersteht Router-Neustarts, Lücken nicht geschätzt |
| Peak Bandwidth (24 h) | Gateway-Router | `DATA_RATE` | `MEASUREMENT` | `bit/s`; höchste 5-min-Download-Rate, Upload als Attribut |
| Active Traffic Anomalies | Fleet | – | `MEASUREMENT` | – (Anzahl) |
| Monitoring Coverage | Fleet | – | `MEASUREMENT` | `%` (Anteil der Punkte mit `full`; `None` ohne Punkte) |
| Interface Utilization | je Router, nur Uplink (WAN bzw. LAN-Uplink laut Topologie) mit bekannter Link-Geschwindigkeit | – | `MEASUREMENT` | `%` |
| Interface RX Errors | je Router, Uplink | – | `TOTAL_INCREASING` | – (Anzahl); `entity_category=diagnostic`, standardmäßig deaktiviert |
| Interface TX Errors | je Router, Uplink | – | `TOTAL_INCREASING` | – (Anzahl); wie oben |
| Client WLAN Download/Upload Rate (optional) | je ausgewähltem Client | `DATA_RATE` | `MEASUREMENT` | `bit/s`; Name „WLAN-Verkehr am AP“, nie „Internet“ |

**Keine unkontrollierte Entitätserzeugung:**
- Je Router höchstens 6 Traffic-Sensoren, dazu 2 Fleet-Sensoren.
- Für Flows, VLANs, Ports und kurzlebige Clients gibt es keine Entitäten; die gibt es
  nur im Panel.
- **Client-Sensoren:**
  - Nur für Clients, die ein Admin in `/settings` ausdrücklich auswählt (≤ 20).
  - `unique_id` aus `client_ref`.
  - Abwählen entfernt sie aus der Registry.
- **Ausschalten:** Alle Traffic-Entitäten werden aus der Entity-Registry entfernt
  (Muster `security_entities._remove_from_registry` L275).
- Die bestehenden Sensoren `wan_rx`/`wan_tx` (`sensor.py` L261-280) und die
  Interface-Sensoren (L554-655) bleiben unverändert.

## 10. Anbindung an bestehende Engines, ohne deren Dateien zu ändern

**Core (heute möglich):**
- `register_event_prefix("traffic_analytics.", module="traffic_analytics")`. Das ist
  erlaubt, weil `core_audit._add_prefix` L372-393 nur Core-, reservierte und fremde
  Präfixe ablehnt.
- `register_capability_detector("traffic_analytics", detect, prefix="traffic.")`
  (`router_registry` L1594-1609) mit diesen Capabilities:
  - `traffic.netdev_counters`;
  - `traffic.station_counters`;
  - `traffic.station_detail`;
  - `traffic.offload_state`;
  - `traffic.flow_collector`.
- `async_get_module_key("traffic_analytics", "identity")` für `client_ref` und
  `evidence_ref`.
- **Events:**
  - `traffic_analytics.anomaly_started`;
  - `traffic_analytics.anomaly_ended`;
  - `traffic_analytics.coverage_changed`;
  - `traffic_analytics.indicator`;
  - `traffic_analytics.collector_rejected`.
- **Event-Felder:** `router_id`, `client_ref`, `radio_id`, `confidence`,
  `classification` und, wenn bekannt, `incident_ref` (Core-Felder B8,
  `core_models.EVENT_REF_FIELDS`).
- Mit `dedup_key` je Punkt und Art.

**Network Intelligence:**
- Nur lesend. Traffic hört auf das Bus-Event `openwrt_router_incident_event` und zeigt
  NI-Befunde zu Ports und conntrack neben den Raten an.
- `lan_port_load`, `lan_port_errors` und `system_conntrack_jump` werden **nicht** noch
  einmal erkannt.
- Traffic-Kandidaten bleiben Kandidaten (Panel + Core-Event), ohne Incident-Lebenszyklus
  und ohne Health-Score.

**Security Center:**
- Traffic sendet `traffic_analytics.indicator` mit `evidence_ref`. Die Indikatoren aus §13
  sind:
  - ungewöhnliche Datenmenge;
  - Verbindungsrate nur mit Flow-Quelle;
  - neue Ziele nur mit Collector.
- Heute verarbeitet das Center diese Events nicht.

**Netzwerkdiagnose / WiFi RF:**
- Nur über Core-Events (`subscribe`), sobald die Module auf main sind.
- Bis dahin ist der Korrelationsstatus `module_missing` (Matrix §6).

**Wünsche an andere Module** (nichts davon baut Traffic selbst):

| Nr. | An | Wunsch | Warum |
|---|---|---|---|
| W1 | `net_engine` | öffentliche Schnittstelle `submit_candidate(module, router_id, kind, severity, evidence_ref, dedup_key)`, die Kandidaten in NI-Befunde/Incidents mit deren Cooldown, Dedup und Health-Score übernimmt | §10 „bestehende Anomaly Engine erweitern“ geht heute nicht; `add_poll_observer` (L881) ist nur lesend |
| W2 | `security_center` | `traffic_analytics.indicator` (Schema v1) als Indikatorquelle der Gruppe b annehmen und `evidence_ref` am Hinweis speichern | §13; heute stehen nft-/conntrack-Indikatoren dort als „nicht gebaut“ |
| W3 | Core (`core_masking`/`config_api`) | gemeinsames Client-Pseudonym über Module (`async_get_client_ref(mac)` mit Core-eigenem Zweck) | `client_ref` hängt am Modulschlüssel (`security_model.client_ref` L515); dieselbe MAC ergibt in Traffic und Security verschiedene `cli_…`, sie lassen sich nicht verknüpfen |
| W4 | Core (`core_models`) | `traffic_analytics` in `MODULE_EVENT_PREFIXES` und `traffic.` in `MODULE_CAPABILITY_NAMESPACES` reservieren (inkl. Vertragstest `test_core_followup_b7_contract.py` und Tabelle §3.1 der API-Doku) | heute kann ein anderes Modul `traffic.` belegen |
| W5 | Core (`core_audit`) | Quote je Modul auch im allgemeinen Audit-Ring | `_append` (L545-554) ist FIFO über alle Module; Traffic-Events könnten fremde Einträge verdrängen; bis dahin gilt das Event-Budget aus §5 |
| W6 | WiFi RF | lesende API je Station (`AssocCounters`) und je Radio (Airtime) sowie die verbindliche Definition von `radio_id` | keine doppelten `iwinfo assoclist`-Aufrufe; einheitliche Radio-Identität |
| W7 | Netzwerkdiagnose | Events oder lesende API mit Latenz/Verlust je `router_id` und Ziel | §12-Korrelation |
| W8 | `client_engine` | Einträge für kabelgebundene Clients (aus ARP/FDB) | heute gibt es nur WLAN, MAC-basiert |

## 11. Markierte Blöcke in bestehenden Dateien

Jeder Block steht zwischen `# --- Traffic Analytics (Phase 5) ---` und
`# --- Ende Traffic Analytics ---` und folgt dem Wrapper-Muster des Security Centers.
Fehler im Block werden geloggt (nur der Typ) und lassen Setup und Poll nie scheitern.

| Datei | Ort | Inhalt |
|---|---|---|
| `const.py` | nach dem Security-Center-Block Teil 2 (Dateiende, nach L825) | `TRAFFIC_FINE_STORE_KEY`, `TRAFFIC_COARSE_STORE_KEY`, Versionen, Store-Obergrenzen, `DATA_TRAFFIC_ANALYTICS`, `DATA_TRAFFIC_VIEWS_BOUND`, `SIGNAL_TRAFFIC_ANALYTICS`, `UID_FLEET_TRAFFIC_ANOMALIES`, `UID_FLEET_TRAFFIC_COVERAGE` |
| `coordinator.py` | Felder in `OpenWrtCoordinatorData` nach `vlans_stale` (L426); Befüllung direkt nach dem `device_status`-Abruf in `_async_poll` (L860-864) | `device_counters`: Kopie von Q1 je Gerät (Bytes, Pakete, Errors, Drops, `speed`, `up`, `carrier`), ≤ 64 Geräte, fehlende Werte bleiben `None`; `counters_sampled_mono = time.monotonic()`; `active_connections_source`. **Nicht** in `as_dict` (L432), sodass die Diagnosedaten gleich bleiben |
| `api.py` | (a) in `get_active_connections` (L4843-4888); (b) neue Methoden vor `async_ssh_run_pinned` (Dateiende) | (a) nur ein Attribut `last_conntrack_count_source` (`count_file` / `table_scan` / `None`), Verhalten unverändert; (b) `async_traffic_station_detail`, `async_traffic_sysfs_counters`, `async_traffic_offload_state` mit den Grenzen aus §6.2 |
| `__init__.py` | Dateiende nach dem Security-Center-Wrapper (L797-849) | Wrapper um `async_setup_entry`/`async_unload_entry`: Engine holen, Coordinator-Listener an- und abmelden, Routen einmal binden (`DATA_TRAFFIC_VIEWS_BOUND`), beim letzten Entry freigeben |
| `sensor.py` | Dateiende nach dem `_sec_wraps`-Block (L1553-1586) | Wrapper, der `traffic_entities.async_setup_traffic_sensors` aufruft |
| `diagnostics.py` | Dateiende nach dem Security-Center-Wrapper (L369-405) | Block `traffic_analytics`: an/aus, Punktzahlen je Bereich, Quoten- und Drop-Zähler, Store-Größen, Capability-Zustände; keine IDs außer `router_id`, keine MAC/IP |
| `strings.json`, `translations/en.json`, `translations/de.json` | `entity.sensor` | `translation_key`s der Sensoren aus §9 |
| `frontend/topology/src/main.tsx` | neben den Register-Importen (L18-19), Bind (L64-66), Dev-Mock (L290-306) | Import `enterprise/traffic/register`, `bindTrafficHass`, `installTrafficMock` |
| `frontend/topology/package.json` | Skript `test` | `src/enterprise/traffic/traffic.test.mjs` ergänzen |

## 12. Risiken und offene Punkte

1. **HW-Offload (MT7981-PPE):** WAN- und `br-lan`-Zähler können offloadeten Verkehr
   verfehlen. Der Umfang ist nicht am Gerät gemessen. Bis zur Messung steht
   `coverage=partial`.
2. **DSA-Port-Zähler:** Ob hardware-geschalteter Verkehr mitgezählt wird, ist offen.
   Port-Summen sind deshalb vorsichtig zu kennzeichnen.
3. **Unbegrenzter conntrack-Fallback** in `api.get_active_connections`
   (L4867-4885). Er bleibt in diesem Plan unverändert, ist aber ein RAM-Risiko auf dem
   Router (siehe Frage F2).
4. **Unbekannt wird heute 0:**
   - `active_connections` (`coordinator.py` L1097, `api.py` L4888);
   - Port-Bytes (`api.py` L4377-4380);
   - SSH-Interface-Fallback (L805-806).
   Traffic umgeht das über die Blöcke in §11. Die bestehenden Sensoren bleiben, wie sie
   sind.
5. **Schreiblast** ≈ 130 MB/Tag und ≈ 7 MB auf der Platte inklusive `.bak`. Das
   Profil `compact` (nur Infrastruktur, 5 min für 6 h) halbiert beides etwa.
6. **Gleichzeitige Aufrufe:** Zusatzaufrufe (§6.2) laufen in derselben ubus-Session wie
   der Poll. Ob `api.py` parallele Aufrufe je Session sauber serialisiert, ist nicht
   geprüft. Deshalb ruft Traffic nie während eines laufenden Polls.
7. **Fremde Module nicht auf main:** Netzwerkdiagnose und WiFi RF liegen nur als Zweige
   vor. Deren öffentliche Schnittstellen sind nicht geprüft; ihr `radio_id` ist nicht
   festgelegt (W6).
8. **Fehlende Korrelation:** Ohne W3 lässt sich ein Traffic-Client nicht mit einem
   Security-Hinweis zum selben Gerät verknüpfen; es bleibt nur Router und Zeitfenster.
9. **Kein Optionsdialog:** `config_flow.py` darf nicht geändert werden. Alle Einstellungen
   liegen deshalb im Traffic-Store und im Panel, wie beim Security Center.
10. **Topologie-Overlay (§16):** Die Topologie-Komponenten außerhalb von `enterprise/`
    wurden in Phase A nicht gelesen. Ort und Umfang des Blocks sind offen.
11. **hostapd-Semantik:** Richtung, Bitbreite und Verhalten bei Re-Assoziation sind
    Annahmen (Matrix Q7) und vor Phase D am Gerät zu prüfen, nur mit Freigabe.
12. **Store-Größe** liegt über der der Client-Historie (3 MB). Wenn das zu viel ist,
    sind die kleinsten Stellschrauben die Client-Feinstufe und der 90-Tage-Teil.

## 13. Entscheidungen (selbst getroffen, klein)

- **E1:** Einstellungen liegen im Traffic-Store und werden über `/settings` (nur Admin)
  bedient, nicht im Optionsdialog. Grund: `config_flow.py` ist tabu, und das Security
  Center macht es genauso.
- **E2:** Traffic hängt sich mit `coordinator.async_add_listener` an, nicht als
  NI-`PollObserver`. Grund: keine Abhängigkeit von `net_*` und kein Eingriff dort.
- **E3:** Rohwerte kommen aus einem neuen Feld `device_counters` im Coordinator, nicht
  aus `port_stats`. Grund: Dort ist unbekannt schon 0, und die bestehenden Sensoren
  sollen sich nicht ändern.
- **E4:** Die monotone Zeit wird im Poll gemessen (`counters_sampled_mono`), nicht im
  Listener. Grund: Die Poll-Dauer schwankt (SSH-Fallback), und der Listener läuft erst
  am Ende des Polls.
- **E5:** `point_id` = `tpt_` + sha256 der kanonischen Felder, ohne Schlüssel. Grund:
  Die Eingaben sind schon Pseudonyme. Die ID muss über Neustarts stabil sein und darf
  nicht vom Modulschlüssel abhängen.
- **E6:** 32-Bit-Überlauf wird nur bei Station-Zählern als Kandidat geprüft. Bei
  netdev-Zählern gilt ein Rückgang immer als Reset. Grund: 64 Bit läuft praktisch nicht
  über, ein falsch angenommener Überlauf erzeugt Riesenspitzen.
- **E7:** `radio_id` ist bis W6 der AP-netdev-Name mit `radio_id_source="ifname"`.
  Grund: Es gibt keine Definition auf main.
- **E8:** Flows bleiben nur im RAM, gespeichert werden nur anonymisierte Aggregate.
  Grund: §8 und §20 (Datensparsamkeit).
- **E9:** Collector-Daten kommen per Push, nur über HTTPS, von genau einem freigegebenen
  Nicht-Admin-Benutzer. Grund: kein neuer ausgehender Aufruf außerhalb von `api.py`,
  kein Geheimnis im Klartext.
- **E10:** Traffic erkennt Port-Last, Port-Fehler und conntrack-Sprünge nicht selbst.
  Grund: NI hat diese Regeln schon (`net_rules.py`); keine zweite Engine.
- **E11:** Es gibt keinen eigenen Sensor „WAN Traffic Total“ aus Rohzählern. Gezählt wird
  die Summe gültiger Deltas. Grund: `wan_rx`/`wan_tx` gibt es schon als Rohzähler; der
  neue Wert soll über Router-Neustarts hinweg weiterlaufen.
- **E12:** Die Speicherung erfolgt in zwei Stores (fein und grob) statt einem. Grund:
  Die groben Daten werden nur stündlich geschrieben, so halbiert sich die Schreiblast.

## 14. Fragen an den Nutzer

- **F1:** Sollen Admins über Klartext-HTTP Hostnamen und IPs sehen? Optionen: nein,
  dann nur Pseudonyme / ja. Empfehlung: nein.
- **F2:** Soll der unbegrenzte conntrack-Fallback (`api.py` L4867-4885) in einem eigenen
  Fix begrenzt oder entfernt werden? Optionen: eigener Fix vor Phase B / so lassen.
  Empfehlung: eigener Fix vor Phase B.
- **F3:** Ist eine Store-Grenze von 4 MB (≈ 130 MB Schreiblast am Tag) in Ordnung?
  Optionen: Standard 4 MB / Profil `compact` als Standard. Empfehlung: `compact` als
  Standard, `standard` wählbar.
- **F4:** Wer setzt die Wünsche W1–W5 an Core, NI und Security um? Optionen: vor Phase F
  bzw. H als eigene Aufträge / Traffic ohne sie fertigstellen. Empfehlung: eigene Aufträge
  vor Phase F.
- **F5:** Dürfen die Geräteprüfungen aus Matrix §7 vor Phase B laufen (nur lesend, mit
  Freigabe je Router)? Optionen: ja, vor Phase B / erst vor Phase D. Empfehlung: ja, vor
  Phase B.

### 14.1 Vorläufige Festlegung der Unter-Sitzung (bis der Master anders entscheidet)

- **F1:** nein. Über Klartext-HTTP gibt es nur Pseudonyme, auch für Admins.
- **F2:** kein Eingriff in diesem Modul. Traffic nutzt die conntrack-Anzahl nur, wenn sie
  aus der Zähldatei stammt. Der Fix am Fallback ist als Folgeauftrag an den Master gemeldet.
- **F3:** Profil `compact` ist Standard, `standard` ist wählbar.
- **F4:** Traffic wird ohne W1–W8 fertig gebaut. Jede Anbindung meldet ohne das Gegenstück
  „nicht verfügbar“. Die Wünsche gehen an den Master.
- **F5:** keine Geräteprüfung durch diese Sitzung. Die Annahmen bleiben in Code und Doku
  als „nicht am Gerät geprüft“ markiert.
