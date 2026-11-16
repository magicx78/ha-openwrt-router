# Echtzeitdiagnose und automatische Ursachenanalyse (RT) – Plan

Stand: 2026-11-16 · Autor: Session RT-1 · Basis: `feature/network-intelligence` @ 4cef6a8 (NI P1–P6)
Status: **Phase A (Analyse und Plan).** Kein Produktivcode. Phase B startet erst nach Freigabe durch den
Master, nachdem NI-1 (P5-Review-Fixes, P7, P8) fertig ist; danach Rebase auf den neuen Stand.

Grundsatz: RT **erweitert die NI** (`net_events.py`, `net_rules.py`, `net_engine.py`, `log_parser.py`,
`api.py`, Panel). Es entsteht kein zweites Event-, Incident- oder Alarmsystem. Neue Module gibt es nur
für Dinge, die die NI noch nicht hat: den Event-Stream, die Reason-Code-Tabelle und die KI-Schnittstelle.

Kennzeichnung in diesem Dokument:
- **[live]**: auf den Routern am 2026-11-16 lesend gesehen.
- **[Quelle]**: im Quelltext belegt (Fundstelle angegeben), nicht live gesehen.
- **[ungeprüft]**: Annahme. Wird in Phase B geprüft, bevor Code darauf baut.
- **[RT-Entscheidung]**: kleine Entscheidung von RT-1, Master kann sie kippen.

---

## 1. Kernaussage Machbarkeit

1. **Echtzeit geht ohne neues Paket.** Auf allen sechs Routern bietet `uhttpd-mod-ubus` den Endpunkt
   `GET /ubus/subscribe/<objekt>` als Server-Sent Events (`text/event-stream`) an **[live + Quelle]**.
   - Ohne Session antwortet er mit `{"code":-13,"message":"Permission denied"}` (HTTP 200).
   - Unbekannte Pfade geben 404 zurück **[live]**.
   - Die Session kommt per `Authorization: Bearer <sid>` **[Quelle]**.
2. **Es fehlt nur ein ACL-Recht.** Geprüft wird `uh_ubus_allowed(sid, path, ":subscribe")` **[Quelle]**.
   - Keine ACL-Datei auf den Routern enthält `subscribe` **[live]**.
   - Das HA-ACL (`ha-openwrt-router.json`, Version 8) erlaubt für `hostapd.*` nur `get_clients` und
     `get_status` **[live]**.
   - Nötig ist also eine kleine ACL-Erweiterung (Abschnitt 9). Sie braucht die Freigabe des Nutzers.
3. **hostapd liefert Push-Events über ubus.** Ein einmaliger `ubus subscribe` über SSH (45 s, danach
   beendet) hat auf gateway, ap5 und ap6 sofort `probe`-Events geliefert, auf dem gateway auch einen
   `link-measurement-report` **[live]**.
   - Laut Binärstrings und ucode-Quellen kennt wpad zusätzlich `auth`, `assoc`, `disassoc`,
     `sta-authorized`, `beacon-report`, `bss-transition-query/-response` sowie `bss.add/remove`
     über das Objekt `hostapd` **[Quelle]**.
   - In einer 10-Minuten-Messung auf allen sechs kamen keine auth-, assoc- oder disassoc-Events. Im
     Log gab es in diesem Fenster aber auch keine Verbindungswechsel. Der Live-Nachweis ist daher
     **offen** und Teil des Piloten P0.
   - Live kamen auf dem gateway 802.11k-Berichte (`beacon-report`, `link-measurement-report`) mit
     RCPI (Abschnitt 3.4).
4. **Keine numerischen Reason Codes im Normalbetrieb.**
   - wpad enthält den String `reason_code` nicht **[live]**.
   - Das Log schreibt nur Klartext wie „deauthenticated due to inactivity“, „disconnected due to
     excessive missing ACKs“ oder „local deauth request“ **[live]**.
   - Nummern gibt es nur bei höherem hostapd-Loglevel. Das empfehle ich nicht (RAM auf ap6, Lograte).
   - RT bildet deshalb Klartext **und** Nummer auf dieselben Kategorien ab (Abschnitt 6.3).
5. **Last.** Der Stream kostet auf dem Router praktisch nichts. Auf ap6 änderte sich der freie
   Speicher während der Probe nur um −0,5 MB, und das galt für den SSH-Testprozess, nicht für SSE.
   - Teuer ist das **Datenvolumen der probe-Events**: gateway ≈ 107 Events bzw. 40 KB pro 30 s
     (≈ 1,3 KB/s, ≈ 115 MB/Tag), ap6 ≈ 4 Events bzw. 1,4 KB pro 30 s **[live]**.
   - Probes lassen sich per SSE nicht serverseitig filtern **[Quelle]**. HA verwirft sie sofort beim
     Parsen.
6. **Pro Objekt eine Verbindung.**
   - SSE abonniert genau ein Objekt pro Request, ohne Wildcards **[Quelle]**.
   - Das sind 6 bis 9 HTTPS-Streams pro Router, flottenweit etwa 45.
   - Laut Quelle zählt ubus nicht gegen `max_requests=3` (`ubus_dispatch` ohne `.script`)
     **[Quelle]**.
   - `max_connections=100` reicht **[live]**.
   - Der Speicher pro TLS-Verbindung auf ap6 ist **[ungeprüft]** und Pilotkriterium (Abschnitt 9).
7. **Der Stream hat keinen Timeout und keinen Keepalive.** Er endet, wenn das Objekt verschwindet
   (`remove_cb` → `request_done`, also bei hostapd-Neustart, WLAN-Reload oder Router-Neustart) oder
   wenn die Verbindung abbricht **[Quelle]**.
   - Die ACL wird nur beim Abonnieren geprüft. Ein laufender Stream überlebt daher das Ablaufen des
     300-s-Tokens **[Quelle]**.
   - Ob uhttpds `network_timeout=30` ruhige Streams trennt, ist **[ungeprüft]**. Das klärt der Pilot.
     Der Client kommt mit Backoff ohnehin damit zurecht.
8. **Fallback bleibt der vorhandene Log-Ingest** (`ubus log read` mit Cursor). Er ist nötig und
   bleibt aktiv, weil er dnsmasq, netifd, Kernel und Klartext-Gründe liefert, die der Stream nicht hat.
   - Der logd-Ring ist klein: `log_size=64` KB, etwa 610–630 Zeilen. Das sind auf gateway ≈ 1 Tag,
     auf ap5 ≈ 8,5 h, auf ap6 ≈ 22 h **[live]**.
   - Fällt HA länger aus, entstehen Lücken. Die NI meldet sie bereits als `system.log_gap`.

**Empfehlung:** Echtzeit per HTTP-SSE über die vorhandene ubus-Session.
- Neue Pakete: keine.
- Neue Prozesse auf dem Router: keine.
- SSH: keines.
- Nötig ist eine ACL-Zeile, eingeführt als Pilot auf zwei Routern.
- Wenn ein Stream nicht läuft, arbeitet die NI genau wie heute über Log und Poll weiter.

---

## 2. Lückenanalyse (Abschnitte 2–8 des Auftrags)

Status: **erfüllt** (durch NI, mit Fundstelle) · **teilweise** · **neu**.
Fundstellen relativ zu `custom_components/openwrt_router/`, Zeilen auf Stand 4cef6a8.

### 2.1 Echtzeit-WLAN-Ereignisse (Auftrag §2)

| Anforderung | Status | Fundstelle / Lücke |
|---|---|---|
| Ereignisbasierte, persistente, asynchrone Erfassung | **neu** | Heute nur Polling: `api.get_log_entries` (`api.py:1908`, `stream:false`) alle `LOG_READ_INTERVAL_CYCLES=2` Polls (`const.py:518`). → RT2/RT3 |
| hostapd über ubus | teilweise | Nur Poll `get_clients` und `get_status`. Kein Subscribe. → RT2/RT3 |
| netifd, Syslog, hostapd/wpad-Logs | erfüllt | `log_parser.py` `_HOSTAPD_PATTERNS` (Z.167–218), netifd/kernel/dnsmasq-Muster. `parse_entry` (Z.315) |
| iwinfo und Station-Statistiken | teilweise | Poll (`api.py`). Kein RSSI-Verlauf pro Client |
| Assoc und Disassoc | erfüllt (Log) | `AP-STA-CONNECTED/DISCONNECTED`, `IEEE 802.11: associated/disassociated`. Echtzeit über Stream: neu |
| Auth Failures, WPA-Handshake | erfüllt (Log) | `AP-STA-POSSIBLE-PSK-MISMATCH`, „handshake failed“, EAPOL-Timeout, invalid MIC, SAE. Detektoren `wifi_auth_failures`, `wifi_auth_wave` |
| Deauth | erfüllt (Log) | „deauthenticated [due to X]“ |
| Wiederholte Reconnects | erfüllt | `net_rules._reconnects` (Z.3443–3525), Regel `wifi_reconnect_storm` |
| Roaming, häufige AP-Wechsel | erfüllt | `_roam_finding` (Z.4077), `_band_finding` (Z.4037), `_steer_moves` (Z.4132, usteer) |
| Abbrüche bei schwachem RSSI | teilweise | `_weak_cause` (Z.2966) bestätigt nur bei Messung ≤ −75 dBm, höchstens einen Poll alt. RSSI „vor dem Abbruch“ fehlt → RT5 |
| Gleichzeitige Disconnects | erfüllt | `_mass_disconnect_log` (Z.3595), `_mass_disconnect_poll` (Z.3699) |
| Reason Codes nach Spezifikation | teilweise | Nur Klartext-Normalisierung `log_parser._wifi_reason` (`REASON_*`, Z.65–74). Keine 802.11-Tabelle → RT1 |
| Beobachtet vs. abgeleitet | erfüllt | `Origin` (`net_events.py:55`), `INFERRED_CONFIDENCE_CAP=0.6` (`net_rules.py:69`) |
| Ressourcenschonender Fallback | erfüllt | Log-Cursor, adaptive Zeilenzahl 100–700, `LOG_EVENTS_PER_FETCH` |
| Datenverluste dokumentiert | teilweise | `system.log_gap` (`net_engine.py:187, 1274`). Stream-Lücken fehlen (→ RT3); Nutzerdoku fehlt (P8 + RT10) |

### 2.2 Reconnect- und Roaming-Analyse pro Client (Auftrag §3)

| Anforderung | Status | Fundstelle / Lücke |
|---|---|---|
| Reconnects pro 5/10/60 min | teilweise | Regelfenster 600 s (`DEFAULT_SETTINGS`, `net_rules.py:142`), `client_stability.RECONNECT_WINDOW_SECONDS=300`. Kein 60-min-Fenster pro Client |
| Disconnect-Häufigkeit | teilweise | `client_stability.AssociationTracker.counts` (Z.193), `EventCounters`. Keine Rate pro Client |
| Mittlere Verbindungsdauer | **neu** | `get_clients` liefert kein `connected_time`. Nur aus assoc/disassoc-Paaren ableitbar |
| AP-Wechsel | erfüllt | `wifi_roam_flapping`, `wifi_band_flapping` |
| RSSI vor und nach Abbruch | **neu** | `NetEvent.signal` hat nur einen Wert |
| Auth- und Assoc-Fehler | erfüllt | `wifi_auth_failures`, `wifi.assoc_rejected`, `wifi.sae_failed` |
| Disconnect-Gründe | teilweise | `params["reasons"]` in `wifi.reconnect` (Z.3521), nur Klartext |
| Konfigurierbare Schwellen | teilweise | `DEFAULT_SETTINGS["thresholds"]` und `merge_settings` (Z.247) mit Grenzprüfung. UI erst mit P7-Route `/intelligence/settings` |
| Meldung mit Schweregrad, Nachweisen, Konfidenz | erfüllt | Incident: `severity`, `evidence[]`, `confidence` |
| Empfehlung | **neu** | Kein Empfehlungstext in `net_*.py`, `strings.json` oder `translations` → RT7 |

**Überschneidung mit CS-1** („Client Stability Intelligence“: Historie, Score, AP-Vergleich): §3 ist
fast deckungsgleich. Vorschlag in Abschnitt 11, Frage F3.

### 2.3 Correlation Engine (Auftrag §4)

| Szenario | Status | Fundstelle / Lücke |
|---|---|---|
| A: AP fällt aus, 12 Clients | erfüllt | `router_unreachable` ist Wurzel (Tier 2, `ROOT_TIERS` `net_rules.py:4405`), Kinder über `AlarmMachine.correlate`. Test mit 20 Clients: `test_ak1_ap_outage_with_20_clients_is_one_root` |
| B: LAN-Uplink flappt plus Client-Abbrüche | teilweise | `lan_port_flap`, `lan_uplink_down` (Tier 5), `wifi_mass_disconnect` als Kind. `lan_port_flap` steht **nicht** in `ROOT_TIERS`; kein kombinierter Test → RT7 |
| C: einzelner ESP32 instabil, Rest ok | teilweise | Bleibt `Scope.CLIENT`, Hypothesen in `_reconnects`. Keine ausdrückliche Prüfung „andere Clients am selben AP/Radio unauffällig“ als Indikator → RT7 |
| D: mehrere Clients ohne DNS, IP ok | teilweise | Nur dnsmasq-Logzeilen (`dns.query_limit`, `dns.no_servers`), hypothesis 0,5. Keine Messung der Client-Sicht → RT7 (Option HA-DNS-Probe, F4) |
| E: mehrere APs gleichzeitig | erfüllt | `lan_unreachable` (Tier 1), `build_topology` (Z.4475/4524) trennt LLDP-beobachtet von Trunk-abgeleitet. Abgeleiteter Uplink nur als Warning und mit 0,6 |

### 2.4 Root-Cause (Auftrag §5)

| Baustein | Status | Fundstelle / Lücke |
|---|---|---|
| Sliding Window | erfüllt | `_Track` (`net_rules.py:418`), `WifiState.window_count` |
| Gruppierung, Topologie, zeitliche Kausalität | erfüllt | `_ROOT_WINDOWS` (Z.4428), `correlate`, `_incident_link`, `_event_link` |
| Baselines | teilweise | Nur Conntrack-Median (`detect_conntrack`). Keine Client- oder Funk-Baseline → RT7 (klein: Reconnect-Baseline pro Client, F3-abhängig) |
| Anomalieerkennung | teilweise | Schwellwerte. Bewusst kein statistisches Modell (deterministisch, nachvollziehbar) |
| Konfidenz | erfüllt | `_confidence` (Z.1454), Cap für abgeleitete Ursachen |
| Bestätigt / wahrscheinlich / möglich | teilweise | Zwei Stufen (`CauseStatus`, `net_events.py:92`) plus Zahl → RT6, Abschnitt 5 |
| Schnittstelle lokale KI | **neu** | → RT8, Abschnitt 7 |

### 2.5 Dashboard (Auftrag §6)

| Anforderung | Status | Fundstelle / Lücke |
|---|---|---|
| Incident-Liste, Detail, Timeline, Warnsymbole | offen in **P7** (NI-1) | Routen laut NI-Plan c10. Heute keine Intel-Daten im Panel |
| Konfidenzstufe, Ereigniskette, Empfehlungen, Dauer, Aufklappen der Kinder | **neu** (auf P7) | → RT9 |
| Stream-Status je Router | **neu** | → RT9 |

### 2.6 Performance (Auftrag §7)

| Anforderung | Status | Fundstelle / Lücke |
|---|---|---|
| Keine SSH-Stürme | erfüllt | Engine macht keine Router-Calls (`test_engine_adds_no_router_calls`). Log über ubus. RT bleibt SSH-frei |
| Begrenzte Queues und Historie | erfüllt | `MAX_EVENTS=3000`, `MAX_INCIDENTS=500`, Store ≤ 1,5 MB. Stream-Queue → RT3 |
| Exponential Backoff | teilweise | Nur adaptive Zeilenzahl und `USTEER_RETRY_CYCLES` → RT3 |
| Sauberes Shutdown | erfüllt | `async_unload_net_intelligence`. Stream-Tasks → RT3 |
| Robust bei Router- und HA-Neustart | erfüllt (Log/Poll) | Baseline mit Log-Mark, `.bak`-Store. Stream-Wiederaufbau → RT3 |
| Minimal nötige ACLs dokumentiert | teilweise | `acl_provisioning.py` ACL v8. `:subscribe` neu → Abschnitt 9 |

### 2.7 Die 12 Testszenarien (Auftrag §8) gegen `tests/test_net_*.py`

| # | Szenario | Vorhanden | Lücke → Bauphase |
|---|---|---|---|
| 1 | 8 Reconnects in 10 min | `test_net_wifi.py::test_reconnect_storm_with_weak_signal_confirms_the_cause`, `::test_reconnects_with_good_signal_list_hypotheses_only` | Zusätzlich über Stream-Events (RT5) |
| 2 | Normales Roaming ohne Fehlalarm | `test_band_steering_and_roaming_are_no_reconnect`, `test_net_wifi_review.py::test_m4_ping_pong_roaming_counts_no_reconnect`, `::test_m3_deep_sleep_client_is_no_reconnect_storm` | Mit Stream-Events, inklusive FT-Roam (RT5) |
| 3 | Roaming-Flapping zwischen zwei APs | `test_roam_flapping_with_usteer_is_observed`, `test_roam_flapping_without_usteer_from_poll_differences` | – (Stream-Variante RT5) |
| 4 | AP-Ausfall mit 12 Clients | `test_net_correlation.py::test_ak1_ap_outage_with_20_clients_is_one_root`, `test_net_p6.py::test_ak1_scenario_fires_only_the_outage` | Genau 12 Clients, Stream bricht dabei ab (RT10) |
| 5 | Einzelner instabiler ESP32 | **keiner** im strengen Sinn | Neuer Test mit Vergleich zu den anderen Clients (RT7) |
| 6 | LAN-Uplink-Flapping | `test_net_infra.py::test_scenario_lan_port_flapping_opens_one_port_incident`, `test_net_correlation.py::test_inferred_uplink_down_from_the_topology_port` | Flap **plus** Client-Abbrüche als ein Incident (RT7) |
| 7 | Gemeinsamer DNS-Ausfall | `test_scenario_dns_trouble_is_one_aggregated_hypothesis_event`, `test_wan_down_with_dns_lines_explains_them` | Mehrere Clients, DNS-Sicht (RT7, F4) |
| 8 | Mehrere APs gleichzeitig | `test_ak2_all_routers_down_is_one_lan_incident`, `test_staggered_polls_settle_into_one_root` | – |
| 9 | Dedup | `test_duplicate_log_lines_count_once`, `test_same_event_id_fed_twice_counts_once`, `test_scenario_duplicate_polls_and_lines_count_once` | Stream gegen Log (RT5) |
| 10 | Fehlende Ereignisdaten | `test_missing_log_lowers_coverage_and_never_reads_healthy`, `test_scenario_missing_log_and_missing_acl_rights`, `test_net_score.py::test_no_data_is_unknown_never_100` | Fehlendes `:subscribe`-Recht (RT3) |
| 11 | Router- und HA-Neustart | `test_save_and_restart_restore_everything`, `test_baseline_after_restart_fills_the_gap_from_the_mark`, `test_scenario_router_reboot` | Stream-Wiederaufbau nach Reboot (RT3) |
| 12 | Abbruch und Wiederherstellung Event-Stream | nur Log-Varianten (`test_open_storm_stays_open_while_the_log_is_unreadable`, `test_baseline_starting_after_the_mark_records_a_log_gap`) | **neu** (RT3) |

Die Zuordnung für 5–8 stammt aus Testnamen und Docstrings. In RT10 wird jeder Test einmal gegen das
Szenario gelesen und das Ergebnis in dieser Tabelle nachgetragen.

---

## 3. Messergebnisse pro Router (2026-11-16, nur lesend)

Methode: SSH-Aliase, einmalige Shell-Skripte, keine Schreibzugriffe außer `/tmp`-Dateien der Probe, die
danach gelöscht wurden. Keine Pakete, ACLs oder Konfigurationen geändert. Jeder Testprozess wurde nach
der Laufzeit mit `kill` beendet und „clean“ geprüft. Hinweis: BusyBox hat hier kein `timeout`; der erste
Versuch lief deshalb gar nicht an (geprüft: kein Restprozess).

### 3.1 Inventar

| Router | OpenWrt / Target | uhttpd + mod-ubus | rpcd | wpad | usteer | RAM verfügbar | Uptime |
|---|---|---|---|---|---|---|---|
| gateway | 25.12.1 mediatek/filogic | 2026.08.24 | 2026.10.04 | wpad-mesh-openssl 2025.08.26-r6 | ja | ≈ 117 MB | 11 d |
| ap2 | 25.12.1 mediatek/filogic | 2025.10.03 | 2025.12.03 | wpad-mesh-openssl -r1 | ja | ≈ 120 MB | 11 d |
| ap3 | 25.12.1 mediatek/filogic | 2025.10.03 | 2025.12.03 | wpad-mesh-openssl -r1 | **nein** | ≈ 119 MB | 11 d |
| ap4 | 25.12.1 mediatek/filogic | 2025.10.03 | 2025.12.03 | wpad-mesh-openssl -r1 | ja | ≈ 120 MB | 11 d |
| ap5 | 25.12.6 ipq40xx | 2026.08.24 | 2026.10.04 | wpad-mesh-openssl -r6 | ja | ≈ 88 MB | 5 d |
| ap6 | 25.12.2 ath79 (mips) | 2025.10.03 | 2025.12.03 | wpad-mbedtls -r2 | **nein** | **≈ 16 MB** | 22 h |

Gemeinsam auf allen sechs **[live]**:
- uhttpd: `-u /ubus -t 60 -T 30 -k 20 -A 1 -n 3 -N 100`, HTTPS auf 443.
- `/usr/lib/uhttpd_ubus.so` enthält `subscribe/`, `:subscribe`, `Bearer`, `text/event-stream` und `data: %s`.
- rpcd-Login `root` mit `read='*'`/`write='*'`. Die HA-Session bekommt also jede ACL-Gruppe aus `acl.d`.
- logd `-S 64`, `log_size=64`, `log_proto=udp`. Kein `log_level` für hostapd gesetzt.
- ubus-Objekte: `hostapd`, `hostapd-auth`, `hostapd.phyX-apY` (gateway 6, ap2 7, ap3 6, ap5 8, ap6 7), `iwinfo`, `log`, `network.*`.

### 3.2 SSE-Endpunkt (unauthentifiziert, von diesem PC)

| Router | `GET /ubus/subscribe/hostapd.phy0-ap0` | `GET /ubus/list/` | `GET /ubus/doesnotexist` |
|---|---|---|---|
| gateway | 200 `{"code":-13,"message":"Permission denied"}` | 500 Invalid argument | 404 |
| ap6 | 200 `{"code":-13,"message":"Permission denied"}` | 500 Invalid argument | 404 |

Der Endpunkt existiert auf alter (2025.10.03) und neuer (2026.08.24) uhttpd-Version. Eine echte
Event-Übertragung per SSE konnte ich nicht testen: Ich habe kein Router-Passwort, und eine Session per
SSH anzulegen wäre eine (flüchtige) Änderung → Pilot P0 in Abschnitt 9.

### 3.3 ubus-Push-Events (SSH, `ubus subscribe` auf alle `hostapd.*`, einmalig)

| Router | Dauer | Events | Bytes | RAM verfügbar vorher → währenddessen |
|---|---|---|---|---|
| gateway | 45 s | 136 probe, 1 link-measurement-report | – | 122 080 → 122 268 KB |
| gateway | 30 s | 107 | 40 626 | – |
| ap5 | 45 s | 40 probe | – | 85 688 → 85 480 KB |
| ap6 | 45 s | 55 probe | – | 16 704 → 16 212 KB |
| ap6 | 30 s | 4 | 1 376 | – |

`ubus listen` (globale Events) brachte in 45 s auf allen drei nichts.
CPU laut `top`: `ubusd`, `hostapd` und Testprozess je 0 %.

probe-Payload **[live]**: `address`, `ifname`, `target`, `signal`, `freq`, `ht_capabilities`,
`vht_capabilities` … (≈ 380 Byte).

**10-Minuten-Messung (alle sechs, probes auf dem Router herausgefiltert):** siehe 3.4.

### 3.4 10-Minuten-Messung

Ablauf: 18:07:27–18:17:27, alle sechs gleichzeitig. Abonniert waren `hostapd` und alle `hostapd.*`.
`probe` wurde auf dem Router per `awk` verworfen. Parallel lief `ubus listen`. Danach wurde alles mit
`kill` beendet und auf allen sechs „clean“ geprüft.

| Router | Events (ohne probe) |
|---|---|
| gateway | 51 `beacon-report`, 22 `link-measurement-report` |
| ap2, ap3, ap4, ap5, ap6 | keine |

- `ubus listen` blieb auf allen sechs stumm.
- **Gegenprobe im Log:** Zwischen 18:07 und 18:17 gab es auf **keinem** Router ein
  `AP-STA-CONNECTED/DISCONNECTED`, deauth oder disassoc **[live]**. Dass keine
  `auth`/`assoc`/`disassoc`-Events kamen, sagt also nichts aus. Der Live-Nachweis bleibt Aufgabe von P0.
- **Neu und nützlich [live]:** Der gateway liefert 802.11k-Messberichte per Push, vermutlich auf
  Anfrage von usteer **[ungeprüft]**:
  - `link-measurement-report` mit `address`, `rcpi`, `rsni`.
  - `beacon-report` mit `address`, `bssid`, `channel`, `rcpi`, `rsni`.
  - Laut 802.11 gilt RCPI = 2·(dBm+110), also ist z. B. `rcpi 74` ≈ −73 dBm **[Quelle: 802.11-2020
    §9.4.2.37, Formel in RT1 gegen den Text prüfen]**.
  - Werte wie `rcpi 198–202` bei `antenna-id 3` sind unplausibel und werden verworfen.
  - Damit gibt es für Clients mit 802.11k einen RSSI-Verlauf ohne Polling, eine Option für „RSSI vor
    dem Abbruch“ (Abschnitt 6.1).
  - Volumen: ≈ 7 Events/min auf dem gateway.

### 3.5 Was wpad kann (Binärstrings und ucode-Quellen auf dem gateway)

- Strings in `/usr/sbin/wpad` (exakte Wörter) **[Quelle]**:
  - `probe`, `auth`, `assoc`, `disassoc`, `deauth`, `sta-authorized`, `beacon-report`,
    `bss-transition-query`, `bss-transition-response`, `link-measurement-report`.
  - Dazu `reason` und `status_code`; `reason_code` fehlt.
- `/usr/share/hostap/hostapd.uc` **[Quelle]**:
  - `hostapd`-Objekt: `notify("bss.<type>")` bei BSS-Änderungen (Z.1380).
  - `hostapd-auth`-Objekt: `notify("sta_auth")` und `notify("sta_connected")` **mit 1000 ms Wartezeit
    auf eine Antwort** (Z.1415, 1425).
  - → **RT abonniert `hostapd-auth` nicht.** Ein Abonnent dort beeinflusst Auth-Entscheidungen und
    verzögert jeden Login. **[RT-Entscheidung]**
- Ob `disassoc` einen Reason enthält und wie `auth`/`assoc` ihre Payload ausfüllen, ist
  **[ungeprüft]** und wird in P0 live geprüft. Der Code verlässt sich nicht darauf: Gründe kommen
  weiterhin aus dem Log (Abschnitt 4.5).

### 3.6 Log-Bestand (letzte ≈ 24 h, `logread`)

- Häufigste hostapd-Muster **[live]**:
  - `AP-STA-CONNECTED/DISCONNECTED`, `EAPOL-4WAY-HS-COMPLETED`.
  - `deauthenticated due to inactivity` (ap5: 27, ap6: 19).
  - `disassociated due to inactivity`.
  - Nur ap5: `local deauth request` (4), `disconnected due to excessive missing ACKs` (3),
    `group key handshake failed` (1).
- Der Ring umfasst etwa 610–630 Zeilen (gateway ab 17:09 des Vortags, ap5 ab 09:30 desselben Tags).

---

## 4. Architektur des Event-Streams

### 4.1 Überblick

```
Router (uhttpd)                    HA
GET /ubus/subscribe/hostapd.phyX-apY ──SSE──► api.OpenWrtAPI.async_subscribe()   (einziger HTTP-Ort)
GET /ubus/subscribe/hostapd          ──SSE──►        │ parse → StreamEvent
                                                    ▼
                                       net_stream.RouterEventStream (1 je Router)
                                         • Task je Objekt, Backoff, Discovery
                                         • begrenzte Queue (deque, 512)
                                         • probe-Filter, Rate-Limit
                                                    │ Batch (≤ 2 s / ≤ 64 Events)
                                                    ▼
                                       net_engine.NetIntelligence.ingest_stream()
                                         • Dedup Stream ↔ Log
                                         • NetEvent(source=hostapd, origin=observed)
                                         • WLAN-Detektoren (entprellt, ≤ 1×/5 s)
                                                    ▼
                                       AlarmMachine / Korrelation / Score (unverändert)
```

Der Coordinator pollt weiter wie heute (60 s, adaptiv). Der Stream löst **keinen** Coordinator-Refresh
aus. **[RT-Entscheidung]**: Echtzeit soll nicht zu mehr Router-Last führen.

### 4.2 Verbindung

- `api.py` bekommt `async_subscribe(obj) -> AsyncIterator[tuple[str, dict]]`.
  - Gleiche `async_get_clientsession(hass)`, gleiches TLS-Setup (`ssl_util.py`), `Authorization: Bearer
    <aktueller Token>`.
  - `ClientTimeout(total=None, sock_connect=10, sock_read=STREAM_IDLE_TIMEOUT)`.
- SSE-Parser in `api.py`: Zeilen `event:`, `data:`, Leerzeile. Höchstens 64 KB pro Event, sonst
  verwerfen und zählen. Nicht-JSON-`data` wird verworfen.
- Antwort `{"code":-13}` statt `text/event-stream` heißt: Recht fehlt. Dann kein Retry-Sturm; der
  Stream-Status wird `no_permission`, Retry erst nach 1 h oder nach erfolgreichem ACL-Deploy.
- **Discovery:** `ubus list` über JSON-RPC (`hostapd.*`) beim Start und nach jedem `bss.add/remove`
  oder Reconnect des `hostapd`-Objekts. Abonniert werden `hostapd` und alle `hostapd.<bss>`, nie
  `hostapd-auth`.
- **Ruhe-Erkennung:** Es gibt keinen Server-Keepalive. `STREAM_IDLE_TIMEOUT=600 s`. Bei Stille
  entscheidet der Health-Check im Poll: Ist das Objekt laut `ubus list` noch da und der Stream offen,
  bleibt er offen. Bei TCP-Abbruch reconnect. Ist `network_timeout=30` ein Problem (P0), wird
  stattdessen periodisch neu verbunden; das ist billig, weil ohne Event-Verlust per Log abgesichert.

### 4.3 Backoff und Wiederherstellung

- Exponentiell mit Jitter: 2 s, 4 s, 8 s … höchstens 300 s. Zurücksetzen nach 120 s stabiler Verbindung.
- Router nicht erreichbar (Coordinator meldet `router_unreachable`): Streams pausieren und folgen dem
  Coordinator-Status. Kein eigener Erreichbarkeits-Poll.
- Router-Neustart: Streams enden (`remove_cb` bzw. TCP-Reset), Backoff. Neue Objekt-IDs per Discovery.
  Die Lücke deckt der Log-Ingest ab: Cursor und Baseline bleiben unverändert, Dedup (4.5) verhindert
  Doppelzählung.
- Token abgelaufen bzw. Fehlercode 6 beim Re-Subscribe: das vorhandene Re-Login in `api.py` nutzen.
- **Stream-Lücke als Event:** Jeder Abbruch über 30 s erzeugt ein `system.stream_gap` (wie `log_gap`,
  Severity info, nicht alarmierend). Coverage zeigt `stream: up | degraded | down | no_permission |
  disabled`.

### 4.4 Begrenzung und Last

- Je Router eine `collections.deque(maxlen=512)`. Läuft sie über, wird das älteste verworfen und
  gezählt (`dropped`). Ab dem ersten Verlust entsteht ein `system.stream_gap` mit `reason=overflow`.
- **probe** wird direkt nach dem Parsen verworfen. Die einzige Ausnahme ist ein Zähler pro bekannter
  Client-MAC (Datenschutz, Volumen). Fremde MACs werden nie gespeichert. **[RT-Entscheidung]**
- `link-measurement-report` und `beacon-report` (live auf dem gateway, ≈ 7/min) liefern RCPI für
  bekannte Clients. Gespeichert wird höchstens der letzte Wert pro Client mit Zeitstempel (Quelle für
  „RSSI vor dem Abbruch“). `bss-transition-*` wird nur gezählt.
- Engine-Batch: Flush alle 2 s oder bei 64 Events. Detektoren laufen entprellt höchstens alle 5 s pro
  Router. Kein Event-Loop-Block: Parsen geschieht inkrementell pro Zeile; es gibt keine Blockierung,
  weil alles async ist und kein Executor nötig wird.
- Grob geschätzt: gateway ≈ 3,5 Events/s probe, davon nach dem Filter < 0,1/s. CPU-Last in HA
  vernachlässigbar **[ungeprüft, Messung in RT3 mit Fixture-Replay]**.

### 4.5 Dedup zwischen Stream und Log

- Stream-Events werden `NetEvent(source=Source.HOSTAPD, origin=OBSERVED)`. `Source.HOSTAPD` gibt es
  schon (`net_events.py:62`).
- Schlüssel: `(router, mac, Klasse)` mit Klasse ∈ {connect, disconnect, auth_fail} und Zeitfenster
  ±10 s.
- **Der Stream hat Vorrang.** Eine passende Log-Zeile erzeugt kein zweites Event. Sie **ergänzt** aber
  das Stream-Event um den Klartext-Grund (`params.reason`) und, falls vorhanden, eine Reason-Nummer.
  So bekommt die Ursache „inactivity“ oder „excessive missing ACKs“ auch im Echtzeitfall ihren Grund.
- Kommt die Log-Zeile vor dem Stream (z. B. nach Reconnect), gilt dasselbe umgekehrt: Das erste Event
  zählt, das zweite ergänzt nur.
- Dedup-Speicher: LRU mit höchstens 2048 Schlüsseln pro Router, Ablauf nach 60 s.
- Uhrzeit: Stream-Events bekommen die HA-Empfangszeit (SSE hat keinen Zeitstempel). Log-Zeilen tragen
  die Router-Zeit. Die vorhandene `clock_skew`-Korrektur der NI wird für den Abgleich genutzt.

### 4.6 Shutdown und HA-Neustart

- Tasks über `entry.async_create_background_task` und in `async_unload_entry` abbrechen. Auf das Ende
  wird mit Timeout 5 s gewartet. Danach wird die Response geschlossen, damit uhttpd seinen Abonnenten
  abmeldet (`uh_ubus_subscription_free`, **[Quelle]**). **Korrektur nach P0:** Die Funktion gibt es erst
  ab uhttpd-Commit `506e249` (2025-12-24). In der Version 2025.10.03~ebb92e6b auf ap2–ap4 und ap6 fehlt
  sie. Dort führt ein Client-Abbruch zum bekannten Absturz, siehe 9.5.
- `EVENT_HOMEASSISTANT_STOP`: gleiches Vorgehen.
- Nach HA-Neustart: Streams starten neu. Die Zeit dazwischen deckt der Log-Ingest ab (Baseline mit
  Log-Mark, schon vorhanden).
- Nichts am Stream wird persistiert außer Zählern in der Coverage.

### 4.7 Was in Echtzeit, was nur über Poll oder Log

| Ereignis | Echtzeit (Stream) | Log (≤ 2 Polls) | Poll |
|---|---|---|---|
| Assoc / Connect | ja, `assoc`/`sta-authorized` **[P0 prüfen]** | ja | Client-Liste |
| Disassoc / Deauth | ja, `disassoc` **[P0 prüfen]** | ja, mit Klartext-Grund | Diff |
| Auth-Fehler, PSK falsch, Handshake | teilweise (`auth` mit Status **[ungeprüft]**) | ja | – |
| Roaming | ja (assoc am neuen AP + disassoc am alten) | ja | usteer/Diff |
| RSSI | bei probe/assoc (Momentwert) | nein | `get_clients` |
| BSS weg oder neu (Radio aus, DFS) | ja, `bss.*` | ja | Status |
| WAN, DNS, DHCP, Ports, Uplink, Dienste | nein | ja | ja |
| AP komplett weg | indirekt (alle Streams brechen ab) | nein | ja (`router_unreachable`) |

---

## 5. Konfidenzmodell (drei Stufen, rückwärtskompatibel)

### 5.1 Heute

- `cause_status`: `confirmed` | `hypothesis` (`net_events.py:92`).
- `confidence`: Zahl 0–1.
- `origin`: `observed` | `inferred`.
- Persistiert in Store (Event und Incident), im Bus-Event `openwrt_router_incident_event` (`cause`,
  `cause_status`, `confidence`) und in der Diagnostics-Whitelist. Entities tragen keine
  Ursachen-Attribute (`net_entities.py:190–198`).
- Unbekannte Enum-Werte machen einen Store-Datensatz beim Laden ungültig (`_enum` → `_InvalidRecord`).

### 5.2 Vorschlag: abgeleitete Stufe `cause_level`

- `CauseStatus` und der Store bleiben **unverändert**. Neu ist `cause_level` ∈ {`confirmed`,
  `probable`, `possible`, `unknown`}. Es wird **berechnet**, nie persistiert. Ein Downgrade liest den
  Store also weiter fehlerfrei.
- Reine Funktion `cause_level(cause, cause_status, confidence, evidence)` in `net_rules.py`:

| Stufe | Bedingung |
|---|---|
| `confirmed` (bestätigt) | `cause_status == confirmed`. Das heißt schon heute: direkte Messung vorhanden (Grundregel des Nutzers) |
| `probable` (wahrscheinlich) | `hypothesis` **und** ≥ 2 **unabhängige** Indikatoren **und** `confidence ≥ 0,5` |
| `possible` (möglich) | `hypothesis`, sonst |
| `unknown` | keine Ursache (`cause is None`) oder Datenlage fehlt (Coverage `unknown`) |

- **Unabhängig** heißt: verschiedene Quellenfamilien unter den Belegen. Familien: `log`, `stream`
  (hostapd), `poll`, `usteer`, `lldp`/`topology`, `fleet`, `ha_probe`. Zwei Log-Zeilen sind ein
  Indikator. Die Belege tragen ihre `source` schon (`Evidence.from_event`). RT6 ergänzt sie nur dort, wo
  sie fehlt.
- Abgeleitete Topologie (Trunk-Karte) zählt als Indikator, behauptet aber nie eine physische
  Verbindung. Der vorhandene Cap von 0,6 bleibt.
- Ausgabe additiv:
  - Bus-Event bekommt `cause_level` zusätzlich (bestehende Keys unverändert).
  - API/Panel (P7-Routen) zeigen `cause_level`.
  - Diagnostics-Whitelist ergänzt.
  - Entities: optional Attribut `top_cause_level` am Health-Sensor.
- Übersetzung: `confirmed` = „bestätigt“, `probable` = „wahrscheinlich“, `possible` = „möglich“,
  `unknown` = „unbekannt“.
- Alte Automationen auf `cause_status` laufen unverändert weiter.

### 5.3 Prüfung

- Tabellentest über alle Kombinationen.
- Store-Roundtrip: altes Store-Fixture laden, `cause_level` erscheint, und beim Speichern entsteht kein
  neues Feld im Store.

---

## 6. Weitere fachliche Bausteine

### 6.1 Per-Client-Kennzahlen (Auftrag §3)

Hängt an F3 (Abgrenzung zu CS-1). Benötigt werden:
- Reconnects pro 5/10/60 min.
- Disconnect-Rate.
- Mittlere Verbindungsdauer aus assoc/disassoc-Paaren. Ist nur ein Ende beobachtet, gilt die Dauer als
  `unknown`.
- AP-Wechsel, Auth- und Assoc-Fehler, Gründe.
- RSSI vor und nach dem Abbruch: letzter Poll-Wert vor dem disassoc und erster Wert nach dem
  Reconnect. Ohne Wert jünger als 120 s: `unknown`.

Speicher: LRU pro MAC (≤ 1024 Clients flottenweit), Ringpuffer pro Client mit ≤ 64 Zeitstempeln, nur
im RAM. Die Rekonstruktion nach Neustart geschieht aus dem Event-Store.

### 6.2 Empfehlungen (Auftrag §3, §6)

- Pro Ursache ein Schlüssel `rec_<cause>` in `strings.json`/`translations` (de, en), z. B.:
  - `weak_signal` → „Signal prüfen: AP näher, Antenne, 2,4 GHz erzwingen“.
  - `power_supply` → „Stromversorgung des Geräts prüfen“.
  - `channel_interference` → „Kanal und Störquellen prüfen“.
- Empfehlungen sind Text zur Ursache. Sie lösen nie eine Aktion aus.

### 6.3 Reason Codes (IEEE 802.11-2020, Tabelle 9-49)

- Neues Modul `wifi_reasons.py`: Nummer → Schlüssel, Kategorie (`client`, `ap`, `security`,
  `inactivity`, `unknown`) und ob sie ein Hinweis auf schwaches Signal, Auth-Problem oder AP-Aktion ist.
- Ebenso Klartext → Kategorie für die live gesehenen Formen: inactivity, local deauth request, excessive
  missing ACKs (= `disassoc_low_ack`), group key handshake failed, PSK mismatch.
- Unbekannte Nummern → `unknown`, nie geraten.
- Die Tabelle wird gegen die Spezifikation geprüft und mit Fundstelle im Modul-Docstring zitiert. Keine
  Werte aus dem Gedächtnis: In RT1 wird die Liste mit der hostapd-Quelle
  `src/common/ieee802_11_defs.h` (`WLAN_REASON_*`) abgeglichen.

### 6.4 Szenarien B, C, D (Auftrag §4)

- **B:** `lan_port_flap` des AP-Uplink-Ports als Wurzel-Kandidat. Ein `ROOT_TIERS`-Eintrag zwischen
  Router und Uplink. `wifi_mass_disconnect` und Client-Reconnects am selben AP innerhalb des
  Wurzel-Fensters werden Kinder. Status: `confirmed`, wenn der Port-Flap gemessen ist (netifd/Kernel
  Link-down); `probable`, wenn nur abgeleitet.
- **C:** Neuer Indikator „Peer-Vergleich“: Am selben AP/Radio haben im Fenster ≥ 3 andere Clients keine
  Auffälligkeit, und das Radio war durchgehend aktiv. Dann wird die Ursache `client_side` (Funkstrecke
  oder Gerät), niemals `router_*`. Ist der Peer-Vergleich nicht möglich (zu wenige Clients), gilt
  `possible`.
- **D:** Heute sieht die NI nur dnsmasq-Logzeilen. Option (F4): HA prüft als Client selbst die DNS-Server
  des Netzes (gateway `10.10.10.1`) per UDP-DNS-Anfrage auf einen festen Namen. Das geht mit der stdlib,
  ohne neue Abhängigkeit, und höchstens alle 60 s. „DNS gestört, IP erreichbar“ ist dann eine
  **Messung**. Mehrere Clients mit `no_ip` = nein, aber DHCP ok und DNS-Probe negativ → ein Incident
  „gemeinsame DNS-Störung“.

---

## 7. Schnittstelle für eine spätere lokale KI (ohne Abhängigkeit)

- Neues Modul `net_explain.py`:
  - `class IncidentExplainer(Protocol)` mit `async def explain(snapshot: dict) -> ExplainResult | None`.
  - `snapshot` = redigierte Incident-Sicht. Es ist dieselbe Redaktion wie in den Diagnostics: MACs
    gekürzt, keine Hostnamen, außer der Nutzer erlaubt es.
  - `ExplainResult` = `{text, suggested_cause?, references[]}`.
- Registrierung: `hass.data[DOMAIN]["explainer"]`, Standard `None`. Kein Aufruf ins Netz, keine
  Modelldatei, keine neue Requirement-Zeile.
- Ein späteres Add-on oder eine andere Integration kann sich per Funktion `async_register_explainer`
  eintragen.
- Regeln:
  - Ergebnis nur als Anmerkung `ai_note` am Incident.
  - **Es ändert nie** `cause`, `cause_status`, `cause_level` oder `severity`.
  - Herkunft wird als `origin=inferred, source=ai` gekennzeichnet.
  - Zeitlimit 5 s. Fehler werden still geloggt.
- Test mit einem Fake-Explainer: Anmerkung erscheint, Ursache bleibt gleich, Timeout wird eingehalten.

---

## 8. Bauphasen (Phase B, nach Freigabe)

Reihenfolge wegen Dateikonflikten:
- Ohne Konflikt mit NI-1/CS-1: **RT1, RT2, RT8** (neue Dateien bzw. `api.py`).
- Erst nach NI-1 und Rebase: **RT3–RT7** (Engine-Dateien).
- Nach P7: **RT9**.
- CS-1 und RT dürfen Engine-Dateien nie gleichzeitig ändern; der Master legt die Reihenfolge fest.

| Commit | Inhalt | Dateien | Fertig, wenn |
|---|---|---|---|
| **RT1** | Reason-Code-Tabelle und Klartext-Kategorien | neu `wifi_reasons.py`, `tests/test_wifi_reasons.py` | Tabelle mit hostapd `WLAN_REASON_*` abgeglichen. Tests für alle live gesehenen Klartexte. Ruff und pytest grün |
| **RT2** | SSE-Client in `api.py` | `api.py`, `const.py` (Stream-Konstanten), `tests/test_api_stream.py` | Parser-Tests (Chunks über Zeilengrenzen, große Events, `-13`-Antwort, Abbruch). Gleiche Session und TLS. Keine neue Abhängigkeit |
| **RT3** | Stream-Manager | neu `net_stream.py`; `__init__.py` (Start/Stop); `const.py`; `config_flow.py` (Option `realtime_events`, Default aus); `strings.json`, `translations/*`; `tests/test_net_stream.py` | Szenarien 10/11/12: fehlendes Recht, Router-Reboot (Objekt weg → Discovery), Abbruch mit Backoff (Fake-Clock), Queue-Überlauf → `stream_gap`, sauberes Unload ohne offene Tasks |
| **RT4** | ACL-Erweiterung `:subscribe` | `acl_provisioning.py` (ACL v9), `tests/test_acl_provisioning*.py` | Nur `hostapd` und `hostapd.*` bekommen `:subscribe`. **Deploy erst nach Freigabe des Nutzers.** Siehe Abschnitt 9: Auto-Deploy greift bei jedem HA-Start |
| **RT5** | Engine-Eingang und Dedup | `net_engine.py` (`ingest_stream`), `net_events.py` (Kinds `wifi.assoc`, `wifi.disassoc`, `wifi.auth_failed`, `system.stream_gap`), `net_rules.py` (`LOG_EVENT_META`, Dedup), `log_parser.py` (Reason-Anreicherung), `tests/test_net_stream_engine.py` | Szenarien 1/2/3/9 über Stream-Events. Stream plus Log zählt einmal. Gründe werden aus dem Log ergänzt. Keine zusätzlichen Router-Calls |
| **RT6** | Konfidenzstufe `cause_level` | `net_rules.py`, `net_engine.py` (Bus-Event), `net_events.py` (Diagnostics-Whitelist), `net_entities.py` (Attribut), `tests/test_net_cause_level.py` | Tabellentest. Alter Store lädt. Store-Schema unverändert. Bus-Event additiv |
| **RT7** | Korrelation B/C/D, Per-Client-Kennzahlen, Empfehlungen | `net_rules.py`, `net_engine.py`, `strings.json`, `translations/*`, ggf. `client_stability.py` (F3), ggf. `api.py` (DNS-Probe, F4), `tests/test_net_rt_scenarios.py` | Szenarien 5/6/7 grün. Peer-Vergleich. Empfehlung je Ursache in de und en |
| **RT8** | KI-Schnittstelle | neu `net_explain.py`, kleiner Haken in `net_engine.py` (nach RT5), `tests/test_net_explain.py` | Fake-Explainer-Test. Keine Netz- oder Modellabhängigkeit |
| **RT9** | Panel-Erweiterung auf P7 | `topology_panel.py` (Felder), `frontend/topology/src/*`, `frontend/dist/*` | Je Incident: Stufe, Kette, Messwerte, Empfehlung, Dauer, aufklappbare Kinder. Stream-Status je Router. Betroffene Knoten markiert. `--frontend`-Build grün |
| **RT10** | Szenario-Suite, Doku, CHANGELOG | `tests/test_net_rt_scenarios.py` (Szenario 4 mit genau 12 Clients und Stream-Abbruch), `docs/realtime-rca.md`, `README.md`, `CHANGELOG.md`, dieser Plan (Tabelle 2.7) | Alle 12 Szenarien mit Testnamen belegt. Doku sagt, was Echtzeit ist, was Poll oder Log, welche Ursachen sicher bzw. wahrscheinlich, welche Rechte nötig, welche Grenzen |

Prüfung je Commit: `uvx ruff@0.17.3 check` + `format --check`, `py -3.13 -m pytest` vollständig,
ab RT9 Frontend-Build. Kein Push, kein PR ohne Freigabe.

---

## 9. Nötige Router-Änderungen (nur Vorschlag, Freigabe durch den Nutzer)

### 9.1 P0 – Pilot (vor RT3-Abnahme)

- **Ziel:** SSE live bestätigen. Zu klären sind Event-Payloads (`assoc`, `disassoc`, `auth`,
  `sta-authorized`), das Verhalten von `network_timeout=30` und der Speicher pro TLS-Stream auf ap6.
- **Router:** ap4 (normal) und ap6 (knapp). Nicht gateway.
- **Änderung:**

  1. Backup:
     ```sh
     cp /usr/share/rpcd/acl.d/ha-openwrt-router.json /root/ha-openwrt-router.json.bak-rt
     ```
  2. In `read.ubus` ergänzen:
     ```json
     "hostapd": [":subscribe"],
     "hostapd.*": ["get_clients", "get_status", ":subscribe"]
     ```
  3. `/etc/init.d/rpcd restart`. Das beendet nur die laufenden LuCI- und HA-Sessions; HA meldet sich
     neu an.

- **Messung:** Mit dem Dev-Skript (`scripts/`, HA-Passwort vom Nutzer) 30 min einen Stream je Objekt
  halten. Dabei `free` und `ps` auf dem Router alle 5 min ablesen und einen Client gezielt neu verbinden
  lassen (durch den Nutzer).
- **Rückweg:**
  ```sh
  cp /root/ha-openwrt-router.json.bak-rt /usr/share/rpcd/acl.d/ha-openwrt-router.json && /etc/init.d/rpcd restart
  ```
- **Achtung:** Läuft HA mit der alten Integration (ACL v8), überschreibt `acl_provisioning` die Datei
  beim nächsten HA-Start wieder mit v8. Das passiert, weil es Inhalte vergleicht, nicht Versionen
  (`acl_provisioning.py:179–189`). Für den Pilot ist das ein automatischer Rückweg. Für den Betrieb
  braucht es RT4.
- **Abbruchkriterium ap6:** verfügbarer RAM sinkt dauerhaft um mehr als 2 MB oder unter 12 MB. Dann für
  ap6 nur das `hostapd`-Objekt und die BSS mit IoT-Clients abonnieren, oder ap6 bleibt beim Log-Fallback.

### 9.2 Betrieb (mit RT4)

- `RPCD_ACL_CONTENT` bekommt dieselben zwei Einträge, `ACL_VERSION = 9`.
- Die Integration verteilt die Datei beim nächsten Start auf alle Router per `file write` und startet
  rpcd neu. **Das ist eine automatische Änderung an sechs Routern und braucht die ausdrückliche Freigabe
  des Nutzers vor dem Release.**
- Vorschlag: Der Deploy der v9-Erweiterung geschieht nur, wenn die Option `realtime_events` für den
  Eintrag aktiv ist. **[RT-Entscheidung]**
- **Rückweg:** Option aus. Dann wird beim nächsten Start ACL v8 wiederhergestellt (gleicher
  Provisionierungsweg); oder manuell wie in 9.1.
- **Nicht nötig:** neue Pakete (alle sechs haben `uhttpd-mod-ubus` mit Subscribe), uhttpd-Konfiguration,
  hostapd-Loglevel, usteer, Dauerprozesse auf dem Router.

### 9.3 Änderungsprotokoll Pilot P0 (2026-11-16, ap4 und ap6)

Freigabe: Nutzer über den Master („Ja, ap4 + ap6 (Recommended)“) und direkt in RT-1 („Yes, do the
pilot“). Nur ap4 (10.10.10.4) und ap6 (10.10.10.6). Keine Pakete, kein Reboot, kein WLAN-Reload.
Abweichung von 9.1: Backup unter `/etc/` statt `/root/`, Messung mit `curl` statt Dev-Skript und eigener
Pilot-Session statt HA-Passwort.

| Zeit | Router | Befehl | Rückweg |
|---|---|---|---|
| 18:23 | ap4, ap6 | `cp /usr/share/rpcd/acl.d/ha-openwrt-router.json /etc/ha-openwrt-router.json.bak-rt-20261116T182300` (sha256 `c7740216…1df1`); dazu eine lokale Kopie im Scratchpad | `rm` der Kopie (bleibt vorerst liegen) |
| 18:23:41 / 18:23:44 | ap4 / ap6 | ACL-Datei ersetzt: nur `"hostapd": [":subscribe"]` neu und `":subscribe"` an `"hostapd.*"` angehängt (sha256 `ec7864c4…0a40`), mit `jsonfilter` geprüft | Backup zurückkopieren und rpcd neu starten |
| 18:23:41 / 18:23:44 | ap4 / ap6 | `/etc/init.d/rpcd restart`, vorher gewartet, bis keine HA-Verbindung offen war | — |
| 18:25 | ap4, ap6 | `ubus call session create {"timeout":3600}` und `session grant` mit nur `hostapd`/`hostapd.*` `:subscribe` | `ubus call session destroy` |
| 18:26:01 | PC | 17 × `curl -N -H "Authorization: Bearer <sid>" https://apX/ubus/subscribe/<obj>`: ap4 9 Objekte, ap6 8; ohne `hostapd-auth` | curl beenden |
| 18:45:14 | ap4 | `session destroy`, Backup zurück, sha256 = `c7740216…1df1` geprüft, `rpcd restart` (eine HA-Verbindung war noch offen) | — |
| 18:45:45 | ap6 | dasselbe, keine HA-Verbindung offen | — |

**Stand nach dem Rückbau:** ACL auf beiden Routern bytegleich mit dem Original. Die Pilot-Sessions sind
gelöscht, und die Streams sind beendet. HA pollt beide Router weiter im 61-s-Takt (CPU-Sensor-Historie bis
18:47); beide bleiben `online`.

**Backups gelöscht** (Freigabe des Nutzers, direkt in RT-1 bestätigt): 18:51:18 auf ap4 und ap6
`rm /etc/ha-openwrt-router.json.bak-rt-20261116T182300`. Vorher geprüft: Die Backups und die lokalen
Kopien `ap4.acl.orig.json` und `ap6.acl.orig.json` im Scratchpad haben denselben sha256 `c7740216…1df1`.
Die aktive ACL ist danach unverändert `c7740216…`.
**Rückweg:** `ssh apX 'cat > /etc/ha-openwrt-router.json.bak-rt-20261116T182300' < apX.acl.orig.json`.
Die Kopien im Scratchpad gehen mit dem Ende der Sitzung verloren. Sie sind aber bytegleich mit der
aktiven ACL und mit `RPCD_ACL_CONTENT` v8.

### 9.4 Ergebnis P0 – **Abbruch: uhttpd stürzt ab**

- **Absturz:** Auf beiden Routern ist uhttpd während des Pilots abgestürzt, und procd hat es neu gestartet.
  - ap6, 18:35:20, Kernel-Log: `do_page_fault(): sending SIGSEGV to uhttpd for invalid read access from 00000000`,
    `epc … in libubus.so.20251202`, `ra … in libubox.so.20260213`.
  - ap4 (aarch64, protokolliert keine Segfaults): Alle 9 Streams endeten um 18:26:59–18:27:01. Der neue
    uhttpd-Prozess (PID 28042, vorher 2141) läuft laut `/proc/<pid>/stat` seit 18:27:03.
  - Auf jedem Router endeten alle Streams in derselben Sekunde (curl: sauberes Ende, HTTP 200).
  - Folge für HA: Laut CPU-Sensor-Historie fehlte auf ap6 ein Poll (≈18:35:40). Auf ap4 ist keine Lücke
    zu sehen, die zum Absturz passt; die Lücke um 18:25:55 gehört zum rpcd-Neustart.
- **Ursache:** nicht belegt. Vor dem Absturz kamen nur `probe`-Events, kein `assoc`, `disassoc` oder
  `auth`. Die Abstürze kamen 1 bzw. 9 min nach dem Start. Vermutungen, alle ungeprüft:
  - ein Fehler im Subscribe-Pfad von uhttpd-mod-ubus bei mehreren gleichzeitigen Subscribern;
  - ein Zusammenspiel mit HA-Anfragen bzw. HAs `session destroy` beim Re-Login.
  Bewusst nicht reproduziert, weil das eine neue Freigabe braucht.
- **Gemessen, solange die Streams liefen:**
  - Speicher ap6: MemAvailable 15,5–16,2 MB während der Streams und 16,1–16,5 MB danach, also etwa
    0,3–0,6 MB weniger.
  - uhttpd-RSS:
    - ap6: 2,6–2,7 MB mit 8 Streams, 2,1–2,2 MB danach.
    - ap4: 3,0 MB mit 9 Streams, 2,1–2,3 MB danach.
    - Das sind grob 50–100 kB pro TLS-Stream.
  - CPU: Load unter 0,4. Kein Unterschied zum Normalbetrieb erkennbar.
  - Volumen: Jeder `probe` kommt auf **jedem** BSS des Funkmoduls einzeln an, also mehrfach. ap6 hatte
    ≈134 Events bzw. 49 kB pro BSS-Stream in 9 min. Das Objekt `hostapd` selbst lieferte 0 Events.
  - `network_timeout=30`: Ein Stream ohne Events wird **nicht** nach 30 s getrennt. Die ap6-Streams auf
    `phy0-ap*` blieben von 18:26:01 bis 18:34:47 (8,7 min) ohne ein Event offen und lieferten danach
    noch ein `probe`.
- **Nicht geklärt:**
  - die Payloads von `assoc`, `disassoc`, `auth` und `sta-authorized`, weil kein Client neu verbunden
    hat, solange die Streams liefen;
  - ob ein `session destroy` der Bearer-Session einen laufenden Stream beendet (offene RT2-Frage). Die
    Streams waren beim Rückbau schon tot.
- **Folge:** SSE über uhttpd ist in diesem Zustand **nicht betriebssicher**. HA pollt über denselben
  uhttpd, also trifft ein Absturz auch das normale Polling. RT3 und RT4 bleiben gesperrt, bis die Ursache
  belegt ist. RT2 (Client mit Backoff) bleibt gültig, denn er übersteht Stream-Abbrüche.
- **Vorschlag nächster Schritt:**
  1. Nur lesend den Quelltext von uhttpd-mod-ubus (Subscribe-Pfad, `uh_ubus_subscription_*`) und
     libubus der installierten Version prüfen und nach bekannten Fixes suchen.
  2. Erst danach, mit neuer Freigabe, einen Minimal-Repro auf ap4 mit **einem** Stream.
  3. Bis dahin bleibt Echtzeit beim Log-Fallback.

### 9.5 Analyse Absturz uhttpd (nur lesend, 2026-11-16)

**Ergebnis:** Der Absturz passt zu einem bekannten uhttpd-Fehler im SSE-Subscribe-Pfad. Upstream ist er
behoben, aber erst **nach** der Version 2025.10.03~ebb92e6b, die auf ap2–ap4 und ap6 installiert ist.
Was ihn im Pilot genau ausgelöst hat, ist **nicht belegt**.

**Versionen (nur lesend abgefragt, ap4 und ap6 gleich):**
- uhttpd und uhttpd-mod-ubus 2025.10.03~ebb92e6b-r1
- libubus 2025.12.02~3cc98db1-r1
- libubox 2026.03.13~81563384-r2
- rpcd 2025.12.03~ffb9961c

**Bekannter Fehler und Fix.** Angaben ohne Marke hat RT-1 über die GitHub-API selbst geprüft.
Angaben mit (R) stammen vom Researcher, mit Quelle, und sind von RT-1 nicht nachgeprüft.
- openwrt/uhttpd Issue #1, 17.04.2023: „SIGSEGV in uhttpd when subscribed to ubus messages over HTTP“.
  - Kernel-Log mit demselben Muster wie auf ap6 (R): invalid read von `00000000`, epc in libubus, ra in
    libubox.
  - Repro dort (R): ACL `:subscribe` auf `hostapd.*`, dann ein `curl` mit Bearer auf
    `/ubus/subscribe/hostapd.wlan0`.
  - https://github.com/openwrt/uhttpd/issues/1
- Fix `506e249`, 2025-12-24: „ubus: unregister ubus subscriber on HTTP client disconnect – Fixes a
  potential SIGSEGV when a client disconnects from a /ubus/subscribe/... endpoint without
  unsubscribing“. Das ist der direkte Nachfolger von `ebb92e6b` (GitHub-Vergleich: 1 Commit voraus).
  - https://github.com/openwrt/uhttpd/commit/506e24987b97fbc866005bfb71316bd63601a1ef
  - PR: https://github.com/openwrt/uhttpd/pull/18
- Folgefix `3c48b9e`, 2026-08-03: „ubus: release client refcount on successful /ubus/subscribe“.
  - Advisory GHSA-wvgh-cm54-q6f6 (R). Ohne diesen Fix wird ein Subscribe-Client nie freigegeben; das kann
    `max_connections` erschöpfen (R).
  - https://github.com/openwrt/uhttpd/commit/3c48b9e17d2086f9756b97e5825c2ebdf3ed233a
- Der Branch `openwrt-25.12` liefert eine uhttpd-Version mit beiden Fixes aus (R). gateway und ap5 laufen
  schon mit 2026.08.24 (3.1).
  https://github.com/openwrt/openwrt/commits/openwrt-25.12/package/network/services/uhttpd
- libubus `3cc98db1` ist nur ein CI-Commit (R). Einen libubus-Fix für diesen Fehler gibt es nicht (R).

**Mechanismus bei ebb92e6b** (R, aus dem Quelltext:
https://github.com/openwrt/uhttpd/blob/ebb92e6b339b88bbc6b76501b6603c52d4887ba1/ubus.c und `client.c`):
- `uh_ubus_handle_get_subscribe` prüft die ACL nur beim Start. Danach meldet es den Abonnenten an
  (`ubus_register_subscriber`, `ubus_subscribe`). Der Abonnent liegt direkt in `cl->dispatch.ubus`.
- Abgemeldet wird er nur in `remove_cb` (das Objekt verschwindet) und im Fehlerpfad.
- Beim Ende eines Requests nullt `uh_request_done` den Speicher (`memset(&cl->dispatch, 0, …)`). Der
  Abonnent steht dann aber weiter im Objektbaum von libubus.
- Das nächste Event (hier ein `probe`) liest den genullten Knoten, und es folgt ein SIGSEGV bei Adresse 0.
- Den gleichen Mechanismus beschreibt schon ein Fix von 2020 für den `remove_cb`-Fall:
  https://lists.openwrt.org/pipermail/openwrt-devel/2020-November/032111.html
- Offsets 0x11b3 (libubus) und 0x2913 (libubox): passen zu `ubus_cmp_id` aus dem AVL-Baum.
  **Vermutung**, nicht per Symboltabelle geprüft.

**Auslöser im Pilot: offen.**
- In Issue #1 löst ein Client-Abbruch den Fehler aus. Im Pilot blieben die curl-Streams aber offen, bis
  der Absturz kam. Welcher Weg bei uns zu `uh_request_done` führte, ist **unbekannt**. Infrage kommen der
  Netzwerk-Timeout, ein TLS-Fehler oder `remove_cb`.
- HAs `session destroy` beim Re-Login (`api.py` Z. 1464–1468) berührt den Subscribe-Pfad laut Quelltext
  nicht. Ein Einfluss ist deshalb unwahrscheinlich (**Vermutung**).
- probe-Last allein ist nicht die Ursache: 49 kB in 9 min sind keine Menge. probes sind aber der
  **Zünder**. Nach dem Nullen stürzt uhttpd beim nächsten Event ab. Viel Verkehr heißt also früher
  Absturz, und das passt zu ap4 (1 min) gegenüber ap6 (9 min). **Vermutung.**
- Mehrere Streams in einem Prozess sind keine Bedingung, denn Issue #1 hatte nur einen.
- Sicherheit der Aussagen:
  - „bekannter, in ebb92e6b nicht behobener Fehler“: **hoch**;
  - genauer Auslöser: **niedrig**.

**Folge:**
- Mit uhttpd 2025.10.03 ist SSE nicht betriebssicher. Jeder Stream kann uhttpd abstürzen lassen und damit
  auch HAs Polling unterbrechen.
- Ein Minimal-Repro auf ap4 (alte Version) würde nur den bekannten Fehler bestätigen. Er entfällt.
  **[RT-Entscheidung]**

### 9.6 Alternativen und Empfehlung

| Weg | RAM ap6 | Reconnect | Sicherheit | Router-Last | Passt zur Integration |
|---|---|---|---|---|---|
| A) SSE über uhttpd 2025.10.03 | ≈ 50–100 kB je Stream (9.4) | Backoff (RT2) | ACL `:subscribe` | gering | **nein, Absturz** |
| B) SSE nach uhttpd-Update auf ≥ 2026.08.24 | wie A | wie A | wie A, dazu Paket-Update | gering | gut (RT2 fertig). Braucht `apk upgrade` auf 4 Routern; ob es unter Dauerlast stabil läuft, ist unbelegt |
| C) Dauerhafte SSH-Sitzung mit `ubus subscribe` | dropbear + ubus + sh/awk: **ungemessen**, Vermutung 1–2 MB | eigener Neustart (`-t`) und Backoff | Dauer-Login als root; `known_hosts=None` (`api.py` Z. 3036) | gering, wenn probes auf dem Router gefiltert werden | mittel: widerspricht „kein aggressives SSH“; heute schließt die Integration SSH nach jedem Poll (`api.py` Z. 3065–3073) |
| D) Log-Ingest bei jedem Poll (`LOG_READ_INTERVAL_CYCLES` 2 → 1) | 0 | entfällt, läuft mit dem Poll | unverändert (ACL v8, `log read`) | ein `log read` mehr je Minute | **sehr gut**: Parser, Dedup und Lücken-Erkennung gibt es schon |

**Zu C** (R, aus `ubus` cli.c, Stand master: https://github.com/openwrt/ubus/blob/master/cli.c):
- `ubus subscribe` nimmt mehrere Objekte in einem Aufruf.
- `-t <s>` begrenzt auch `subscribe`. Damit endet der Prozess sicher, ohne BusyBox-`timeout`.
- Es gibt kein `remove_cb`. Verschwindet ein BSS, läuft der Prozess still weiter. Deshalb muss er
  regelmäßig neu gestartet werden.
- probes ließen sich mit `awk` auf dem Router filtern. Ob die Ausgabe dann zeilenweise ankommt, ist
  **ungeprüft**.
- `hostapd-auth` nie abonnieren (3.5).

**Zu D:**
- Verzögerung höchstens ≈ 60 s; bei Drosselung 120 s, beim SSH-Fallback 300 s.
- Die Trennungsgründe stehen im Klartext im Log (3.6), die Event-Payloads werden nicht gebraucht.
- Der logd-Ring (64 kB, ≈ 620 Zeilen) läuft bei 60 s praktisch nicht über.

**Empfehlung: D, also Log-Ingest bei jedem Poll, als Echtzeit-Weg für jetzt.**
- Gründe:
  - keine Änderung an Routern, kein neuer Prozess;
  - kein Risiko für uhttpd und damit für das Polling;
  - ap6 bleibt unberührt;
  - nutzt den vorhandenen Parser und die vorhandene Korrelation;
  - hält die eisernen Regeln ein (Netzwerk nur in `api.py`, kein Dauer-SSH).
- Kosten:
  - Verzögerung bis 60 s statt Sekunden;
  - doppelt so viele `log read`-Aufrufe;
  - kein RCPI-Push (802.11k-Berichte gibt es nur über ubus).
- RT2 bleibt im Code. Es wird erst verdrahtet, wenn B belegt ist.
- C wird nicht weiter verfolgt, solange D reicht. **[RT-Entscheidung]**

**Spätere Option B (eigene Freigabe des Nutzers nötig):**
1. Gegenprobe auf **ap5** (hat schon 2026.08.24) mit **einem** Stream, 30 min.
   - ACL-Erweiterung wie in 9.3, vorher Backup.
   - Alle 60 s messen: `pidof uhttpd`, `VmRSS`, `MemAvailable`, `logread | grep -i segfault`.
   - Danach curl einmal bewusst beenden (das ist der Auslöser aus Issue #1) und 5 min weiter
     beobachten.
   - Abbruch bei einer neuen uhttpd-PID oder einem fehlenden HA-Poll.
   - Rückweg: `session destroy`, Backup zurück, den sha256 gegen den des ap5-Backups prüfen (ap5 hat
     eine eigene Datei), rpcd neu starten.
2. Nur wenn die Gegenprobe sauber läuft: uhttpd-Update auf ap2–ap4 und ap6. Das ist eine Paketänderung
   und braucht eine eigene Freigabe.

---

## 10. Abhängigkeiten zu NI P7

| P7 liefert (laut NI-Plan c10, P7) | RT ergänzt (RT9) |
|---|---|
| Routen `intelligence/summary`, `events`, `incidents`, `incidents/{id}`, `settings` | Felder `cause_level`, `recommendation_key`, `ai_note`, `children[]` mit Kurzinfo, `duration`, Stream-Status je Router |
| Diagnose-Tab mit Incident-Liste und Timeline | Detailansicht: Ereigniskette, Messwerte, Empfehlung, Kinder aufklappbar |
| Warnsymbole am Router-Knoten (`attributes.incidents`) | Markierung betroffener APs **und Clients** und Kennzeichnung „Ursache hier“ am Wurzel-Knoten |
| Einstellungen (Schwellen) | Schwellen für Per-Client-Fenster (5/10/60 min), Option Echtzeit |

RT9 beginnt erst, wenn P7 gemergt ist. Es nutzt dessen Typen in `types.ts`/`api.ts` und baut keine
zweiten Routen.

---

## 11. Offene Fragen (mit Empfehlung)

| # | Frage | Empfehlung |
|---|---|---|
| F1 | Transport: HTTP-SSE (braucht ACL-Recht `:subscribe`) oder dauerhafte SSH-Sitzung mit `ubus subscribe` (keine ACL, aber SSH-Zugang und dropbear-RAM auf ap6)? | **SSE.** Kein SSH, keine Prozesse auf dem Router, gleiche Session wie heute |
| F2 | P0-Pilot auf ap4 und ap6 freigeben (ACL-Zeile, rpcd-Restart, 30 min Messung, Nutzer verbindet einmal ein Gerät neu)? | **Ja.** Ohne P0 bleiben Payload und Timeout-Verhalten unbelegt |
| F3 | Wer besitzt die Per-Client-Kennzahlen (§3): CS-1 oder RT? | **CS-1** besitzt Historie und Score. RT liefert Stream-Events, Reason-Kategorien und RSSI vor/nach. RT7 nutzt die Kennzahlen nur |
| F4 | DNS-Szenario D über einen kleinen HA-seitigen DNS-Test (stdlib-UDP, ≤ 1/min, nur gegen konfigurierte Router)? | **Ja.** Sonst bleibt D eine Hypothese aus Logzeilen |
| F5 | Probe-Events: ganz verwerfen oder für bekannte Clients zählen? | **Nur zählen für bekannte MACs**, fremde nie speichern |
| F6 | Echtzeit-Option: Standard an oder aus? | **Aus**, bis RT4 freigegeben und ausgerollt ist; danach an |
| F7 | `cause_level` persistieren oder nur berechnen? | **Nur berechnen.** Store bleibt kompatibel, auch beim Downgrade |

---

## 12. Prüfprotokoll Phase A

- Geprüft:
  - Alle sechs Router lesend: Pakete, uhttpd-Optionen, ACL-Dateien, rpcd-Logins, ubus-Objekte,
    hostapd-Methoden, RAM, Logbestand.
  - SSE-Endpunkt unauthentifiziert auf gateway und ap6.
  - `ubus subscribe` und `listen` 45 s bzw. 30 s auf gateway, ap5, ap6; 10 min auf allen sechs.
  - wpad-Strings und `hostapd.uc` auf dem gateway.
  - uhttpd-Quelle (`ubus.c`, `file.c`, master auf GitHub) für Subscribe, ACL, Timeout und Request-Limit.
  - Repo: NI-Code und Tests (Lückenanalyse mit Hilfe eines Lese-Agenten, Stichproben selbst gelesen:
    `acl_provisioning.py`, `api.py`-Session, Plan-Abschnitte c10 und P7).
- Nicht geprüft:
  - Echte SSE-Übertragung mit Session (P0).
  - Payload von `assoc`/`disassoc`/`auth`. In den 10 min gab es keinen Verbindungswechsel; das ist per
    Log gegengeprüft.
  - Speicher pro TLS-Stream.
  - Auswirkung von `network_timeout`.
  - Ob die uhttpd-Quelle auf GitHub-master exakt den Router-Versionen 2025.10.03 und 2026.08.24
    entspricht. Die Binärstrings stimmen überein.
  - Tests nicht ausgeführt (Phase A ändert keinen Code).
- Nichts an Routern oder HA geändert.
