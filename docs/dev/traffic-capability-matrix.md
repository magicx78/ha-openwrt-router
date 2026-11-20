# Traffic Analytics — Data Source Capability Matrix (Phase A)

<!-- Entwicklerdoku, Stand Phase A (2026-11-20), Basis main v1.46.0.
     Keine IPs, MACs, Hostnamen echter Geräte, Passwörter oder Tokens.
     Auftrag: docs/plans/2026-11-20-traffic-analytics.md (§3, §4, §8).
     Bauplan: docs/plans/2026-11-20-traffic-analytics-bauplan.md. -->

## 0. Lesehilfe

- **Code-Belege** nennen Datei und Funktion oder Zeile, die in Phase A gelesen wurde
  (Pfade relativ zu `custom_components/openwrt_router/`).
- **„Annahme, nicht am Gerät geprüft“** steht überall dort, wo eine Aussage nicht aus dem
  Code folgt (Kernel-, Treiber- oder rpcd-Verhalten). Es wurde in Phase A kein Gerät
  angefragt.
- **Router-Flotte:** sechs OpenWrt-Router, davon vier Cudy WR3000 (MT7981, aarch64), im
  Folgenden `router-a` … `router-f`. Ein Router hat WAN (Gateway), die übrigen sind APs mit
  LAN-Uplink. **OpenWrt 25.12** nutzt `apk` statt `opkg`; Paketprüfungen laufen über die
  Core-Capability `pkg.apk` (`core_models.CORE_CAPABILITY_NAMESPACES`), nie über
  `/tmp/opkg_list`.
- **Stufen:**
  - **A-Standard:** aus Daten, die der Poll heute schon holt (`coordinator.data`),
    0 zusätzliche Router-Aufrufe.
  - **A-schaltbar:** ein zusätzlicher, begrenzter Aufruf in `api.py`, je Router einzeln
    einschaltbar, Standard aus.
  - **B-Collector:** nur über einen externen Collector, die Integration installiert nichts.
  - **nicht geplant:** kein Weg ohne Installation, Exec-Recht oder unbegrenzte Last.
- **Router mit ~15 MB freiem RAM:** Kostenangaben sind Größenordnungen.
  Antwortgrößen sind eine **Annahme, nicht am Gerät geprüft**.

## 1. §3-Felder und Kurzschlüssel

| Kürzel | §3-Feld | Kürzel | §3-Feld |
|---|---|---|---|
| RID | Router-ID (`router_id`, `rtr_…`, aus dem Core) | B | RX-/TX-Bytes |
| IF | Interface-ID (netdev-Name) | P | RX-/TX-Pakete |
| PORT | Port-ID (DSA-/Ethernet-Port) | D | RX-/TX-Drops |
| VLAN | VLAN-ID | E | RX-/TX-Errors |
| CLI | Client-ID (`client_ref`, `cli_<16 hex>`) | LS | Link-Geschwindigkeit/Duplex |
| TS | Zeitstempel (HA-seitig, monoton) | SRC | Datenquelle |
| INT | Messintervall | DQ | Datenqualität |

TS, INT, SRC und DQ setzt immer die Integration selbst, nie der Router. Kein Router liefert
einen verlässlichen Zeitstempel je Zähler. Deshalb fehlen diese vier Felder in der
Spalte „liefert“.

## 2. Matrix

Spalten: **liefert** = §3-Felder; **heute** = heute geholt (ja/nein + Code); **neuer
Aufruf** = zusätzlicher Router-Aufruf; **Recht** = neues rpcd-Recht (nur dokumentiert,
nichts wird verteilt); **Bereich** = Messbereich aus §4; **Stufe**.

| # | Quelle | liefert | heute | neuer Aufruf | Recht | Bereich | Stufe |
|---|---|---|---|---|---|---|---|
| Q1 | ubus `network.device status` (netifd) | IF, PORT, VLAN (VLAN-netdev), B, P, D, E, LS | **ja**, 1× je Poll für alle Geräte (`api.get_device_status` L4211; Aufruf in `coordinator._async_poll` L861) und benannt für WAN (`api._read_wan_counters` L2078) | keiner | keins (v8: `network.device status`, `acl_provisioning.py` L123) | Interface, Port, VLAN (Gerät), WAN | **A-Standard** |
| Q2 | `/sys/class/net/<dev>/statistics/*` über ubus `file read` | IF, B, P, D, E (je Datei 1 Zähler) | **teilweise**: nur WAN-Fallback rx/tx_bytes (`api._read_wan_counters` L2078-2166, 2. Weg) | optional: Fallback, wenn Q1 fehlt | keins (v8: `/sys/class/net/*` und `/sys/devices/*/net/*` read, `acl_provisioning.py` L99-102) | Interface, WAN | **A-schaltbar** (nur Fallback) |
| Q3 | `/proc/net/dev` über ubus `file read` | IF, B, P, D, E (alle Geräte in einer Datei) | **nein** (kein Treffer in `api.py`) | `file read /proc/net/dev` | `/proc/net/dev` read; auf rpcd ≥ 2026 zusätzlich `/proc/<pid>/net/dev` (siehe Details) | Interface | **nicht geplant** (Q1 liefert dasselbe) |
| Q4 | rtnetlink (`RTM_GETLINK`, `rtnl_link_stats64`) | IF, B, P, D, E, LS | **indirekt**: netifd liest sie für Q1 | direkt nur per SSH/Exec (`ip -s link`) | Exec-Recht, für optionale Stufen nicht zulässig | Interface, Port | **nicht geplant** (über Q1 abgedeckt) |
| Q5 | nftables-Zähler (`counter` in fw4-Regeln, benannte Zähler) | B, P je Regel/Zähler; kein IF/CLI ohne eigene Regeln | **nein** | `nft -j list counters` nur per Exec/SSH | `file exec` auf `/usr/sbin/nft`; optionale Stufen erlauben nur `read` (`acl_provisioning.py` L720-741) | Flow (regelbezogen), WAN | **B-Collector / nicht geplant** |
| Q6a | conntrack-Anzahl `/proc/sys/net/netfilter/nf_conntrack_count` | eine Zahl je Router | **ja** (`api.get_active_connections` L4843; `coordinator` L1093-1097) | keiner | keins (v8 L111) | Flow (nur Anzahl, router-weit) | **A-Standard** |
| Q6b | conntrack-Snapshot `/proc/net/nf_conntrack` | Quell-/Zieladresse, Ports, Protokoll, Zustand; B/P nur mit `nf_conntrack_acct=1` | **ja, aber unbegrenzt** als Zähl-Fallback (`api.py` L4867-4885: ganze Tabelle lesen, Zeilen zählen) | begrenzter Snapshot ist mit `file read` nicht möglich | v8 hat Read (L107, L110); eine Grenze bräuchte Exec | Flow | **B-Collector**; nativ **nicht geplant** |
| Q7 | ubus `hostapd.<ap> get_clients` | CLI (über MAC → `client_ref`), B, P, Rate, Airtime, Signal | **ja**, je AP-Interface je Poll (`api.get_connected_clients` L2553); behalten werden nur `rx_bytes`/`tx_bytes`/`rx_rate`/`tx_rate` (L2772-2777) | keiner | keins (v8 L121) | WLAN-Station | **A-Standard** |
| Q8 | ubus `iwinfo assoclist {device}` | CLI, B, P, Retries, Failed, `connected_time`, `inactive` | **nur Fallback ohne Bytes** (`api.get_connected_clients` L2789) | `iwinfo assoclist` je AP-Interface | keins (v8 L132-138: `assoclist`) | WLAN-Station | **A-schaltbar**; besser vom Modul WiFi RF beziehen |
| Q9 | Bridge-/Switch-/DSA-Portzähler (über Q1) + Bridge-FDB | PORT, B, P, D, E, LS, Carrier; FDB: MAC → Port (keine Bytes) | **ja**: `api.get_port_stats` L4307-4390 (aus Q1), `api.get_bridge_fdb` L4651, `api.get_port_vlan_map` L4392 | keiner | keins | Port; FDB nur für Zuordnung | **A-Standard** |
| Q10 | NetFlow v9 / IPFIX | Flow-Felder §8 komplett, B, P, Start/Ende | **nein** | keiner (der Router exportiert selbst, z. B. `softflowd`) | keins; Paketinstallation ist Sache des Nutzers | Flow | **B-Collector** |
| Q11 | eBPF (z. B. tc/XDP-Zähler) | je nach Programm IF/CLI/Flow, B, P | **nein** | keiner nativ | nicht über rpcd | Flow, Client | **B-Collector**, sonst nicht geplant |
| Q12 | externer Collector (ntopng, pmacct, eigener Dienst) | normalisierte Flow- und Client-Aggregate, B, P, Start/Ende | **nein**; nur Gerüst für einen Router-Aggregator (`api._call_aggregator` L3245-3345 wirft `NotImplementedError`, Schema `_v` gegen `const.AGGREGATOR_SCHEMA_VERSION` L583) | **keiner** Richtung Router; Eingang in HA (Push, siehe Bauplan §8) | keins | Flow, Client, VLAN, WAN | **B-Collector** |
| Q13 | ubus `network.interface dump` | WAN-Identität (`l3_device`), up/down, Default-Route; keine Zähler | **ja** (`api.get_wan_status` L1948-2076) | keiner | keins | WAN (Zuordnung) | **A-Standard** |
| Q14 | ubus `hostapd.<ap> get_status` | Kanal-Airtime `airtime.utilization` (0-255) | **nein** im Poll | `hostapd get_status` je AP-Interface | keins (v8 L121) | WLAN (Radio), kein Traffic-Bereich | **A-schaltbar**, gehört fachlich zu WiFi RF |

### 2.1 Abdeckung, Blindstellen und Kosten je Quelle

**Q1 `network.device status`**
- **Abdeckung:** jedes netdev, das der Kernel kennt: `br-lan`, VLAN-Geräte (`br-lan.N`,
  `lanX.N`), DSA-Ports, WLAN-Interfaces und WAN-`l3_device`.
- **Was heute verloren geht:**
  - Das Ergebnis ist in `coordinator._async_poll` nur eine lokale Variable `device_status`
    (L860-864). In `coordinator.data` landen nur die Ethernet-/DSA-Ports
    (`get_port_stats`) und rx/tx-Bytes je logischem Interface
    (`get_network_interfaces` L4230).
  - Pakete, Drops und Errors von `br-lan`, VLAN- und WLAN-Geräten werden geholt und
    wieder verworfen.
- **NAT:**
  - Auf dem WAN-Gerät zählt der Kernel nach NAT. Das ist der Verkehr am Anschluss, ohne
    Zuordnung zu Clients.
  - Bei PPPoE ist `l3_device` das PPP-Gerät. Der PPPoE-Overhead fehlt, die Zählung ist
    trotzdem korrekt für IP-Verkehr. **Annahme, nicht am Gerät geprüft.**
- **HW-/SW-Offload:**
  - Mit `flow_offloading_hw` (MT7981-PPE) laufen Pakete etablierter Flows am Kernel
    vorbei. Die netdev-Zähler von WAN und `br-lan` können sie **nicht** enthalten.
  - Mit reinem Software-Offload laufen sie durch den Flowtable-Pfad, und die
    netdev-Zähler zählen sie weiter.
  - **Annahme, nicht am Gerät geprüft.**
  - Der Code liest heute keine Offload-Einstellung (kein Treffer für „offload“ in
    `*.py`).
- **Bridge:**
  - Frames, die die Bridge zwischen zwei Ports weiterleitet, erscheinen auf dem
    `br-lan`-Gerät nicht, nur an den Ports.
  - Bei DSA kann der Switch Port-zu-Port-Verkehr in Hardware schalten. Ob die Zähler der
    DSA-User-Ports dann aus dem Hardware-MIB kommen (inklusive geschaltetem Verkehr) oder
    nur den CPU-Pfad zählen, hängt vom Treiber ab.
  - **Annahme, nicht am Gerät geprüft.**
- **Roaming:** nicht betroffen.
- **32-Bit-Überlauf:**
  - Auf aarch64 sind die Kernel-Zähler 64 Bit. Ob netifd sie als u64 ausgibt, ist eine
    **Annahme, nicht am Gerät geprüft**.
  - Der Code prüft keine Bitbreite. `_as_counter` (`coordinator.py` L154) verwirft nur
    negative Werte.
- **Kosten:**
  - Heute schon bezahlt: 1 Aufruf je Poll.
  - Die Antwort enthält alle Geräte, geschätzt 20-60 KB JSON. **Annahme.**
  - Es entsteht keine Zusatzlast, wenn Traffic die vorhandene Antwort nutzt.

**Q2 `/sys/class/net/<dev>/statistics/*`**
- **Abdeckung:** wie Q1, aber pro Zähler ein eigener `file read`.
- **Kosten:** Für 20 Geräte × 8 Zähler wären das 160 Aufrufe je Poll. Deshalb nur als
  Fallback für einzelne Geräte, wenn Q1 ein Gerät nicht liefert.
- **Fallback-Kette heute:** Q1 benannt, dann Q2, dann SSH `cat`, wenn beide per ACL
  verweigert werden (`api._read_wan_counters` L2078-2166).

**Q3 `/proc/net/dev`**
- **Liefert:** dieselben Zähler wie Q1 in einer Datei.
- **Recht:**
  - `/proc/net/` ist ein zulässiger Präfix für optionale Stufen
    (`acl_provisioning.OPTIONAL_TIER_FILE_READ_PREFIXES` L738-742).
  - rpcd ≥ 2026 prüft den aufgelösten Pfad `/proc/<pid>/net/dev`. Die v8-ACL braucht
    dafür heute schon Globs (`/proc/*/net/arp`, L109-110).
  - Optionale Stufen verbieten Glob-Zeichen (`_PATTERN_CHARS` L745).
  - Damit wäre `/proc/net/dev` als optionales Recht auf neuem rpcd vermutlich
    unbrauchbar. **Annahme, abgeleitet aus dem Kommentar in L108, nicht am Gerät
    geprüft.**
- **Ergebnis:** nicht geplant, Q1 reicht.

**Q4 rtnetlink**
- Kein ubus-Zugang. netifd ist der rtnetlink-Verbraucher; Q1 ist die Sicht darauf.
- Ein direkter Zugriff bräuchte Exec oder SSH. Das ist nicht erlaubt und nicht nötig.

**Q5 nftables**
- **Abdeckung:** Zähler gibt es nur, wo Regeln `counter` tragen. fw4 setzt das bei eigenen
  Regeln. **Annahme.** Eine Client-Zuordnung bräuchte eigene Regeln je Client; das wäre eine
  schreibende Firewall-Änderung und gehört nach §20 nicht in diese Phase.
- **Offload:** Offloadete Flows passieren die Forward-Kette nach dem ersten Paket nicht
  mehr. Die Zähler sind dann zu niedrig. **Annahme.**
- **Recht:** Exec nötig, für optionale Stufen ausgeschlossen. → nicht geplant nativ.

**Q6a conntrack-Anzahl**
- Eine Zahl je Router. Offloadete Flows bleiben in der Tabelle und werden gezählt.
  **Annahme.**
- **Problem heute:** `api.get_active_connections` gibt `0` zurück, wenn beide Wege
  scheitern (L4888). `coordinator` L1097 setzt bei einer Ausnahme `0`. Unbekannt wird
  also als 0 gemeldet. Traffic darf diesen Wert deshalb nur nutzen, wenn er aus dem
  ersten Weg stammt, und braucht dafür einen Hinweis (Bauplan §9, Block `api.py`).
- **Kosten:** winzig.

**Q6b conntrack-Snapshot**
- **Heute:**
  - Der Fallback in `api.get_active_connections` (L4867-4885) liest die **ganze**
    `/proc/net/nf_conntrack` und zählt Zeilen.
  - Bei einigen Tausend Einträgen à ~300 Byte entstehen mehrere hundert KB im
    rpcd-Prozess, bei voller Tabelle mehrere MB. Bei ~15 MB freiem RAM ist das ein
    Risiko. **Annahme zur Größe.**
- **Grenze:** `file read` hat keinen Offset- oder Zeilen-Parameter, eine Grenze ist
  so nicht möglich. **Annahme zu rpcd, nicht am Gerät geprüft.**
- **Inhalt:**
  - Adressen vor NAT (`orig`) und nach NAT (`reply`).
  - Bytes und Pakete nur mit `net.netfilter.nf_conntrack_acct=1`; das ist unter OpenWrt
    standardmäßig aus. **Annahme.**
  - Nur der Zustand jetzt, keine Historie. Kurze Flows zwischen zwei Abfragen fehlen
    ganz.
- **Ergebnis:**
  - Nativ **nicht geplant**.
  - Der vorhandene Fallback wird nicht erweitert, sondern als Risiko gemeldet
    (Bauplan §12).

**Q7 hostapd `get_clients`**
- **Abdeckung:** nur WLAN-Stationen an APs dieser Integration. Kabelgebundene Clients fehlen.
- **Was heute verloren geht:**
  - `packets`, `airtime` und `signal` je Station werden verworfen.
  - Laut synthetischen Fixtures des WiFi-RF-Zweigs liefert hostapd `bytes{rx,tx}`,
    `packets{rx,tx}`, `airtime{rx,tx}` und `rate{rx,tx}`.
  - `bytes.rx or rx_bytes` macht aus einem echten `0` ein `None` (L2772-2775).
- **Fallbacks ohne Bytes:**
  - `iwinfo assoclist` (L2789) und SSH (`api._get_clients_via_ssh` L3447).
  - Traffic muss daraus „nicht verfügbar“ machen, nicht 0.
- **Roaming:**
  - Die Zähler gehören zur Assoziation. Beim Wechsel des AP oder einer Neuverbindung
    beginnen sie bei 0.
  - Was zwischen der letzten Abfrage und dem Wechsel übertragen wurde, fehlt. Das ist
    eine Blindstelle.
- **Lokaler Verkehr:** Station → AP → andere Station am selben AP erscheint zweimal, als
  RX bei A und als TX bei B.
- **Kein Internetverbrauch:**
  - Die Zähler umfassen auch lokalen Verkehr (Drucker, NAS, Streaming im LAN).
  - Gezählt wird die MPDU-Länge inklusive 802.11-Kopf. **Annahme.**
- **Offload (WED):** Station-Zähler kommen aus dem Treiber oder der Firmware und sollten
  offloadeten Verkehr enthalten. **Annahme, nicht am Gerät geprüft.**
- **32 Bit:**
  - nl80211 kennt 32- und 64-Bit-Felder; ein Treiber, der nur 32 Bit liefert, läuft bei
    4 GiB über. **Annahme.**
  - Ein Überlauf ist von einer Neuverbindung nur über eine Plausibilitätsprüfung zu
    unterscheiden (Bauplan §3.3).
- **Kosten:** heute schon bezahlt.

**Q8 `iwinfo assoclist`**
- **Mehrwert gegenüber Q7:** `connected_time` (hostapd liefert keine Verbindungsdauer, im
  Code immer 0), `tx.retries`, `tx.failed` und `inactive`.
- **Kosten:** ein Aufruf je AP-Interface, also bei 6 Routern × 2-3 Interfaces 12-18
  Aufrufe je Intervall.
- Fachlich gehört das zum Modul WiFi RF. Der Zweig `origin/claude/wifi-rf-48d270`
  enthält bereits `rf_clients.assoc_counters_from_assoclist`. Traffic sollte diese
  Zahlen dort beziehen, statt den Aufruf ein zweites Mal zu machen (siehe §4).

**Q9 Ports**
- **Problem heute:**
  - `get_port_stats` füllt fehlende rx/tx-Bytes und -Pakete mit `0`
    (`int(stats.get("rx_bytes", 0))`, `api.py` L4377-4380). Unbekannt wird so zu 0.
  - Die Fehlerzähler (`_PORT_ERROR_COUNTERS` L666) sind korrekt `None`, wenn sie fehlen.
- **Filter:** `br-*`, `lo*`, Namen mit `.` oder `@` fallen heraus (L4307-4390). VLAN-Geräte
  gibt es also nur über Q1, nicht über `port_stats`.
- **Link-Geschwindigkeit:** `_parse_port_speed` (L600) liefert `speed_mbps` und `duplex`.
  Das ist die einzige Quelle für die Plausibilitätsgrenze und für Auslastung in Prozent.
- **WLAN-Interfaces:** Sie haben keine verlässliche Link-Geschwindigkeit, also gibt es
  dort keine Auslastung in Prozent.
- **Bridge-FDB:** `get_bridge_fdb` (L4651) und `coordinator.data.port_fdb_map` (L391) sagen,
  an welchem Port eine MAC zuletzt gesehen wurde. Das ist eine Zuordnung, kein Verkehr.

**Q10 / Q11 / Q12**
- Nicht auf dem Router installiert. Das Gerüst `_call_aggregator` meint einen
  Router-seitigen Aggregator, keinen externen Collector.
- Die Eingangsschnittstelle ist Thema des Bauplans (§8).

**Q14 `hostapd get_status`**
- Liefert Kanal-Airtime, keinen Traffic.
- Dient nur der Korrelation in §12 und gehört zum Modul WiFi RF.

## 3. Was Stufe A heute schon in `coordinator.data` findet

| Feld (`OpenWrtCoordinatorData`) | Inhalt | Zeile | Mangel |
|---|---|---|---|
| `wan_status` | `interface`, `l3_device`, `rx_bytes`, `tx_bytes` (nur wenn WAN up), `default_route` | L335; befüllt `api.get_wan_status` L1948 | SSH-Fallback ohne `interface`/`uptime` (`api._get_wan_status_ssh` L3399) |
| `wan_traffic` | `downstream_bps`, `upstream_bps`, `interval_s`, `sampled_at` | L377; `_compute_wan_traffic` L1290-1338 | kein Sensor; nur in `topology_mesh.py` L1821-1846 genutzt |
| `network_interfaces` | je logischem Interface `rx_bytes`/`tx_bytes` (aus Q1 über `l3_device`), `rx_rate`/`tx_rate` in B/s | L343; Rate L1052-1091 | Rate mit Wanduhr `datetime.now(UTC)` (L1058) statt monotoner Zeit; SSH-Fallback setzt Bytes auf 0 (`api._parse_ip_addr_output` L805-806) |
| `port_stats` | je Port up, Carrier, `speed_mbps`, `duplex`, Bytes, Pakete, Fehler/Drops | L344; `api.get_port_stats` L4307 | Bytes/Pakete fehlend → 0 (L4377-4380) |
| `clients` | je WLAN-Station MAC, Radio, `rx_bytes`/`tx_bytes`, `rx_rate`/`tx_rate` | L338; `api.get_connected_clients` L2553 | `0` → `None`; Fallbacks ohne Bytes |
| `active_connections` | conntrack-Anzahl | L345 | Fehler → 0 (L1097, `api.py` L4888) |
| `uptime` | Router-Uptime in s | L326 | Standard `0` heißt „unbekannt“, nicht „neu gestartet“ |
| `port_vlan_map`, `port_fdb_map`, `arp_table` | konfigurierte VLANs je Port, MAC → Port, IP → MAC | L389-393 | Konfiguration, kein gemessener VLAN-Verkehr |
| `vlans_stale` | Interface-Abruf fehlgeschlagen, Cache alt | L426 | Traffic muss solche Polls als Lücke werten |
| `ping_ms` | TCP-Verbindungszeit vom **HA-Host** | L378 | misst den HA-Pfad, nicht den Router; nur schwacher Hinweis |

Die WAN-Rate ist schon richtig gebaut:
- Sie nutzt monotone Zeit: `wan_sampled_at = time.monotonic()` (L715).
- Sie verwirft Intervalle unter 5 s und über 900 s (L149-150).
- Ein negatives Delta ergibt `{}`.
- Ein Interface-Wechsel startet eine neue Basis (L1316-1326).

Traffic übernimmt diese Regeln für alle Messpunkte, statt eine zweite WAN-Rate zu rechnen.

## 4. RX/TX-Semantik je Messpunkt

Grundregel: **RX/TX sind immer aus Sicht des Geräts, das zählt.** Download und Upload
sind abgeleitete Begriffe und gibt es nur dort, wo die Abbildung eindeutig ist.

| Messpunkt (Bereich) | RX heißt | TX heißt | Download / Upload |
|---|---|---|---|
| WAN-`l3_device` (WAN) | vom Anschluss empfangen | zum Anschluss gesendet | Download = RX, Upload = TX (so auch `_compute_wan_traffic`, `downstream_bps` aus `rx`, L1334) |
| `br-lan` / VLAN-Bridge-Gerät (Interface/VLAN) | vom LAN an den Router selbst (geroutet oder lokal) | vom Router ins LAN | aus Clientsicht: Upload ≈ RX, Download ≈ TX; **ohne** Bridge-Verkehr Port-zu-Port |
| DSA-/Ethernet-Port (Port) | vom Kabel in den Router | vom Router ins Kabel | nur wenn die Topologie die Rolle kennt (Uplink oder Downlink); sonst nur RX/TX |
| WLAN-netdev (Interface) | von WLAN-Clients | an WLAN-Clients | aus Clientsicht wie `br-lan` |
| hostapd-Station (WLAN-Station) | vom Client empfangen (Client-Upload) | an den Client gesendet (Client-Download) | Client-Download = **TX**, Client-Upload = **RX** (gedreht gegenüber WAN); **Annahme zur hostapd-Semantik, nicht am Gerät geprüft** |
| conntrack-Eintrag (Flow) | Richtung `orig` (Initiator) | Richtung `reply` | Flow-Richtung = Initiator; mit NAT ist `orig` vor NAT, `reply` nach NAT |
| Collector-Flow (Flow) | laut Schema-Feld `direction` relativ zum Beobachtungspunkt | – | nur aus dem Schema, nie geraten |

Folgen für das Modell:
- Ein Wert trägt immer `rx_bytes`/`tx_bytes` **und** die Perspektive (`perspective`:
  `router` oder `station`).
- `download`/`upload` werden nur für WAN und Station berechnet, für Ports nur bei
  bekannter Rolle.
- Ein Client-Wert aus Q7 heißt im UI „WLAN-Verkehr am AP“, **nie** „Internetverbrauch“.

## 5. Abdeckungsmodell (was „vollständig“ hieße)

| Frage | beantwortbar mit Stufe A? | Kennzeichnung |
|---|---|---|
| Wie viel ging über das WAN? | ja (Q1/Q13), solange kein HW-Offload aktiv ist | `coverage=full`, bei HW-Offload `partial` (Grund `hw_offload_unknown`, solange die Offload-Einstellung nicht gelesen wird) |
| Wie viel ging über Port X? | ja (Q9) | `full`, aber bei Bytes = 0 aus dem Default (L4377) `unknown` |
| Wie viel hat WLAN-Client Y übertragen? | teilweise (Q7) | `partial` (Grund: `station_counters_only`, Roaming-Lücken) |
| Wie viel hat kabelgebundener Client Z übertragen? | **nein** | `unavailable` (Grund: `no_wired_client_source`) |
| Wie viel Internet hat Client Y verbraucht? | **nein** | `unavailable` (Grund: `needs_flow_source`) |
| Wie viel ging in VLAN N? | nur, wenn ein VLAN-netdev existiert (Q1) | `full` für das VLAN-Gerät; aus Client-Summen **nie** |
| Welche Ziele/Ports? | nein (Q6b/Q10/Q12 nötig) | `unavailable` bis Stufe B |

## 6. Was Network Diagnostics / WiFi RF liefern könnten und wie Traffic ohne sie „nicht verfügbar“ meldet

**Auf main vorhanden: Network Intelligence (`net_engine.py`, `net_rules.py`).**
- **Regeln, die Traffic-nahe Dinge schon erkennen:**
  - `lan_port_load` (≥ 90 % über 5 Polls), `lan_port_errors` (≥ 0,1 %, mindestens 1000
    Pakete, Intervall 300 s) und `lan_port_speed_drop` (`net_rules.py` L196-205,
    `_port_load` L2754, `_port_errors` L2705).
  - `system_conntrack_jump` (3× Median, ≥ 5000; `detect_conntrack` L2209).
- **Schnittstellen:**
  - `PollObserver` (`net_engine.add_poll_observer` L881) liefert nur lesende Poll-Fakten.
  - Es gibt **keine** öffentliche Schnittstelle, über die ein anderes Modul Befunde oder
    Incidents einspeist.
  - Incidents gehen als Bus-Event `openwrt_router_incident_event` hinaus.
- **Für Traffic:** Port-Last und Port-Fehler **nicht** doppelt erkennen. Traffic zeigt die
  NI-Befunde zu einem Port an (lesend über das Bus-Event) und rechnet selbst nur Raten,
  Summen, Perzentile und Baselines.

**Nicht auf main: Active Network Diagnostics** (Zweig `origin/claude/net-diagnostics-f989ed`,
Kopf 63824f6, nur gelesen)
- **Inhalt:**
  - `diag_stats`: `Sample`, `Bucket`, `LatencySummary` mit Latenz, Verlust und Jitter.
  - `diag_baseline`: Phasen `learning`/`normal`/`degraded` und Metriken `latency_ms`,
    `loss_pct`, `jitter_ms`.
  - `diag_core`: Events `net_diagnostics.finding`, `net_diagnostics.cause`,
    `net_diagnostics.gateway_changed` und Capability-Präfix `diag.`.
- **Für §12:** Latenz und Verlust am Gateway und an Zielen.
- **Annahme:** Ob das Modul eine lesende Python-API für Zeitreihen anbietet, wurde nicht
  geprüft. Sicher nutzbar sind nur Core-Events über `ConfigurationApi.subscribe`.

**Nicht auf main: WiFi RF** (Zweig `origin/claude/wifi-rf-48d270`, Kopf 4f96c40, nur gelesen)
- **Inhalt:**
  - `rf_utilization.UtilizationResult` mit `busy_pct`, `rx_pct`, `tx_pct` und `reason`.
  - `rf_clients` mit `retry_rate`, `failure_rate` und `AssocCounters` (Bytes, Pakete,
    Retries, Failed aus `iwinfo assoclist`).
  - `rf_models.CapabilityState` und `metric_missing`. Unbekannt ist dort schon ein
    eigener Zustand.
- **Für §12:** Airtime und Retries neben der Datenrate.

**Regel ohne diese Module:**
- **Korrelationsstatus:** Jeder Korrelationsbaustein hat einen eigenen Status:
  `available`, `module_missing`, `module_disabled`, `no_data` oder `stale`.
- **Gesamtbewertung:**
  - Fehlt eine Quelle, heißt das Ergebnis „unbekannt“ mit dem Satz „Latenz/Verlust:
    nicht verfügbar (Modul Netzwerkdiagnose nicht installiert)“.
  - **Nie** „kein Engpass“ und nie ein grüner Zustand.
- **Hohe Last allein:** Eine hohe WAN-Last ohne Latenz- oder Verlustdaten ergibt
  höchstens „Auslastung hoch“ (Beobachtung), **nie** „Engpass“ (§12 letzter Satz).
- **Unterstützung:** `ping_ms` (HA-Host) darf als „Hinweis, misst den HA-Pfad“ mitlaufen,
  ersetzt aber keine Diagnose.

## 7. Offene Prüfungen am Gerät (nur mit Freigabe, nicht in Phase A)

1. Ist `network.device status` für alle Geräte u64? Wie groß ist die Antwort auf einem
   Cudy WR3000?
2. Zählen die DSA-User-Ports der MT7981 hardware-geschalteten Verkehr?
3. Sind `flow_offloading`/`flow_offloading_hw` gesetzt? Wie stark weichen die WAN-Zähler
   bei aktivem HW-Offload ab?
4. Liefert hostapd `bytes` als 64 Bit? Bleiben die Zähler bei einer Re-Assoziation am
   selben AP erhalten?
5. Ist `nf_conntrack_acct` gesetzt, und wie groß ist `/proc/net/nf_conntrack` bei Last?
6. Ist `/proc/net/dev` auf rpcd ≥ 2026 ohne Glob lesbar?
