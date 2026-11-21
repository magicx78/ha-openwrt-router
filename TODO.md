# TODO — ha-openwrt-router

Stand: 2026-11-21 · Version: v1.50.0

---

## Backlog

### Network Time Machine (Plan `docs/plans/2026-11-21-network-time-machine.md`, 1.50.0 / 1.51.0)

Entwicklerdoku: `docs/time-machine.md`.

- [x] **Phase A** Leseschicht: Route `…/enterprise/timemachine/timeline`, ein Schalter für alle
      Router, Diagnose-Block, Enterprise-Tab „Zeitreise“ (1.50.0).
- [x] **Phase B** Eigener Index: Marken für Ausfälle, HA-Lücken, Kanal/DFS, Uplink und
      Fingerabdruck, Verweis-Marken für Störungen und Konfiguration, Kontrollpunkte (1.51.0).
- [x] **Phase C** Client-Sitzungen über 24 h hinaus, mit eigenem Schalter, Rechten und
      „Client vergessen“; Panel-Ansicht „Client-Sitzungen“ (1.51.0).
- [ ] **Phase D** „Zustand zum Zeitpunkt T“ und Vergleich zweier Zeitpunkte.
- [ ] **Phase E** Client-Marken der Module demselben Client zuordnen (nie über `cli_`-Werte);
      Export.
- [ ] **Phase F** Sprünge in die Fach-Tabs (`ref` verlinken), Link aus der Topologie,
      Browser-Prüfung 360/768/1280 px hell/dunkel.
- [ ] **Bekannte Grenzen von Phase A:** liest nur, was die Module behalten (Ausfälle und
      Kanalwechsel vor einem HA-Neustart fehlen bis Phase B); keine Client-Marken;
      Konfigurationsänderungen nur als Anzahl und Referenz; mehr Marken mit demselben
      Zeitstempel als `limit` werden abgeschnitten; Konfigurationsversionen höchstens 500
      und ohne `until` (ältere dann `cut: unreachable`); das Zeitbudget unterbricht die
      synchronen Lesefunktionen der Module nicht; Modulschlüssel des Core nur nach Namen
      vergeben.
- [ ] **Bekannte Grenzen von 1.51.0:** solange die Time Machine aus ist, wird nichts gekürzt;
      offene Intervalle werden nicht nach 14 Tagen gekürzt; mehr ins Fenster reichende
      Intervalle als `limit` werden abgeschnitten; „Client vergessen“ nur im eigenen Verlauf;
      im Tab keine Bedienung für „Client vergessen“ / „Verlauf löschen“.
- [ ] **Im Browser und in einer echten Instanz prüfen** (Tab „Zeitreise“ mit beiden Ansichten
      bei 360/768/1280 px, hell/dunkel; Rechte als Nicht-Admin; Ausschalten löscht die
      Client-Verläufe in der echten Datei). Bisher nur Tests mit Mocks und Render-Tests.

### Bekannte Grenzen aus 1.49.4

- [ ] **Traffic bei WAN-Wechsel:** Der WAN-Messpunkt hängt am WAN-Gerät des einzelnen Polls.
      Wechselt das WAN-Gerät (Failover mit mwan3, LTE-Ausweichweg, `wan` ↔ `wwan0`), beginnt
      „WAN gesamt“ neu und springt bei der Rückkehr zurück; Home Assistant kann den Rücksprung
      eines `TOTAL_INCREASING`-Sensors als Verbrauch zählen (abgeleitet, nicht in HA
      gemessen), und die Übersicht zeigt bis zu 24 Stunden zwei WAN-Zeilen. Feste WAN-Geräte
      sind nicht betroffen. Stellen: `traffic_collect.py` (`wan_device` aus `l3_device`),
      `traffic_engine.wan_point`/`_add_totals`, `traffic_entities._wan_total`.
- [ ] **Traffic-Uplink-Erkennung:** `trunk_port_map` enthält jeden Host mit ARP-/FDB-Eintrag,
      nicht nur Router; jeder LAN-Port mit bekanntem Host gilt als Uplink, kabelgebundene
      Client-Zuordnungen an diesen Ports entfallen, Access Points bekommen meist „Uplink
      unbekannt“.
- [ ] **MAC-Schwärzung in Freitext** (Core, Configuration Manager, Netzwerkdiagnose) trifft
      selten auch anderes: Teile einer ULID, Zahlenfolgen in Bindestrich- oder
      Doppelpunkt-Form (`26-11-21-15-30-00`), `commit abcdef123456`, Teile eines
      SSH-Fingerprints. Eine MAC direkt hinter einem Bindestrich (`esp-a1b2c3d4e5f6`) wird
      nicht geschwärzt.
- [ ] **An echten Routern prüfen** (nur lesend, mit Freigabe): ob `network.device status` bei
      PPPoE/LTE das WAN-Gerät (`pppoe-wan`, `wwan0`) auflistet.

### Enterprise Core (Plan `docs/plans/2026-11-17-enterprise-core.md`, 1.44.0)

Branch `claude/enterprise-core-49ade2`. Nutzerdoku: `docs/enterprise-core.md`, Vertrag:
`docs/dev/configuration-api-v1.md`, ACL: `docs/dev/acl-tiers.md`.

- [x] Stabile Router-ID, Registry, Identität, Capabilities, Audit-Log (Teil 1).
- [x] Guard mit Freigaben, Versionsspeicher, Configuration API v1 (Teil 2).
- [x] 1.44.0: gestufte ACL über HA-Neustarts erhalten, ACL-Angebot über den Core
      verteilen, `rf.*` aus der verteilten ACL, Option `config_backup_enabled`
      (Standard aus), SSH-Host-Key-Pins je Router mit Bestätigung, Urteile Q3–Q6,
      Andocken von Security Center, Netzwerkdiagnose und WiFi RF.
- [x] **Oberfläche für Freigaben** (1.45.0, nur was der Configuration Manager braucht):
      Export, ACL-Angebot `config_backup_read` und SSH-Pin bestätigen/zurücksetzen
      im Panel „Enterprise → Konfiguration“.
- [ ] **Oberfläche für Freigaben für andere Module und für „Löschen“:** es gibt weiter
      keinen Panel-Tab, Service oder WebSocket-Befehl für `delete`,
      `installation_key_reset` und die Anträge anderer Module.
- [x] **Backup-Engine (`config-manager`) als Provider** (1.45.0): siehe unten.
- [ ] **`rf.*` nur aus der eigenen ACL-Datei:** Rechte aus anderen Dateien in
      `/usr/share/rpcd/acl.d/` sieht der Core nicht (dann `permission_denied`, obwohl
      rpcd es erlaubt).
- [ ] **Gemeinsamer SSH-Pfad prüft keinen Host-Key:** der SSH-Fallback des Polls und
      die übrigen SSH-Aufrufe außerhalb des gepinnten Wegs verbinden weiter mit
      `known_hosts=None` (`api.py`). Der gepinnte Weg (Backup, ACL-Schreiben) meldet
      sich seit 7c82e78 erst bei bestätigtem Key an; der erste Kontakt dort sendet
      keine Zugangsdaten. Prüfen, ob der gemeinsame Pfad dieselben Pins nutzen kann.
- [ ] **Guard-Ablehnungen deduplizieren:** jede Ablehnung schreibt heute einen eigenen
      Eintrag in den Sicherheitsring und kann ältere Core-Einträge verdrängen. Wiederholte
      Ablehnungen je (Akteur, Aktion, Grund) zählen statt neu schreiben (Vertrag §19.5).
- [ ] **Allgemeiner Audit-Ring ohne Modul-Kontingent:** Modul-Ereignisse können dort
      ältere Einträge verdrängen; das Kontingent gilt bisher nur im Sicherheitsring.
- [ ] **`npm ci` im Frontend braucht `--legacy-peer-deps`:** das Lockfile unter
      `frontend/topology/` löst ohne den Schalter nicht auf (ERESOLVE). Liegt schon vor
      PR #55 vor; Peer-Abhängigkeiten bereinigen, damit `npm ci` ohne Schalter läuft.
      1.49.4: lokal lief `npm ci` mit npm 11.19.1 ohne Schalter durch (vor und nach dem
      Entfernen von `vite-plugin-css-injected-by-js`); mit der CI-npm-Version bestätigen.
- [ ] **Ein MAC-Muster für alle Module:** seit 1.49.4 nutzen Core, Configuration Manager,
      Netzwerkdiagnose und Security Center `core_masking.MAC_IN_TEXT_RE`; WiFi RF
      (`rf_privacy._MAC_IN_TEXT`, ohne Buchstabenregel und ohne Leerzeichen-Form) und
      Traffic haben noch eigene Muster. Angleichen, wenn deren Tests es tragen.
- [ ] **Adoption nach dem Archivieren:** Wird ein Eintrag entfernt, liegen seine
      Versionen unter `removed/<router_id>/`; eine spätere Adoption holt sie nicht
      automatisch zurück.
- [ ] **`async_reload_entry` in `__init__.py` ist toter Code** (kein Update-Listener
      registriert). Entfernen oder dokumentieren; nie als Listener anmelden, solange
      die Reauth-Schritte `async_update_reload_and_abort` nutzen (HA-Blog 2026-05-07,
      ab 2026.12 ein Fehler).
- [ ] Auf Hardware prüfen (nur lesend, mit Freigabe): Router-IDs und Capabilities
      nach einem HA-Neustart, `rf.*` je Router.

### Configuration Manager (Pläne `docs/plans/2026-11-17-config-manager.md`, `docs/plans/2026-11-18-config-manager-integration.md`, 1.45.0)

Branch `claude/config-manager-d9fdac`. Nutzerdoku: `docs/configuration-manager.md`.

- [x] Phase 1: Backup (Archiv, UCI-Snapshot, Inventar), Zeitplan, Dienst
      `openwrt_router.create_config_backup`, Versionen mit Dedup und GFS-Aufbewahrung (Core),
      Drift mit Bereichen und Risikostufen, Diff, Restore-Prüfung, Sensoren, Panel-Tab
      „Konfiguration“, Export mit Freigabe, Diagnose.
- [ ] **Automatischer Restore auf UCI-Ebene mit `uci apply`-Rollback** als spätere Phase
      (Phase 2). Phase 1 spielt nichts zurück; die Wiederherstellung bleibt manuell und ist
      nicht automatisch umkehrbar.
- [ ] **Verschlüsselung der Archive** auf der Platte (Phase 1 speichert im Klartext mit
      Dateirechten `0700`/`0600`; Schutz nur über Dateirechte und HA-Backup-Verschlüsselung).
- [ ] **Vergleich zwischen verschiedenen Routern** (Panel und Dienst vergleichen nur
      Versionen desselben Routers).
- [ ] **Löschen von Versionen im Panel** (heute nur die Aufbewahrung; kein Lösch-Weg für
      Admins) und **Beschreibung nachträglich ändern**.
- [ ] **Messung der echten Last** an Geräten: Laufzeit und Größe von `sysupgrade -b`, Last auf
      dem Router während des Archivs, Größe des Speichers nach einigen Wochen.
- [ ] **Dedup über byte-gleiche Dateien** (Core seit 1.44.0) mit echten Archiven prüfen; wenn
      Archive nie byte-gleich sind, wächst der Speicher täglich. Gegebenenfalls Core-Regel
      lockern.
- [ ] **Größenlimit der Aufbewahrung im Core:** manuelle Versionen werden erst nach allen
      anderen entfernt; eine geplante Version kann früher fallen als nötig
      (`tests/test_config_retention_acceptance.py`, strikter `xfail`).
- [ ] **Freier Platz auf dem Router** für die Restore-Prüfung lesen (`insufficient_space`
      kann heute nie auslösen, `Inventory.free_bytes` bleibt leer).
- [ ] **Automatische Drift-Prüfung deckt nur Poll-Daten ab** (Fingerprint); Änderungen an
      Firewall, Dropbear und Ähnlichem ohne Poll-Spur erscheinen erst bei der manuellen Prüfung
      oder beim Vergleich mit dem aktuellen Stand. Prüfen, ob ein seltener Lauf alle 14
      Configs nachziehen soll.
- [ ] **Auf Hardware prüfen** (nur lesend, mit Freigabe): Backup über `cgi-backup` und über
      SSH, Router ohne `rpc-sys`, Router ohne `cgi-io`, Panel im echten Home Assistant als Admin
      und Nicht-Admin, Desktop und Handy.
- [ ] `docs/enterprise-core.md` an 1.45.0 anpassen („Kein Backup-Modul enthalten“, „Keine
      Oberfläche für Freigaben“).
- [ ] **Option „zweiter Admin muss Export freigeben“.** Heute darf der Anfordernde seinen
      eigenen Export freigeben (das Audit vermerkt die Selbstfreigabe); als Option soll eine
      Freigabe durch einen anderen Admin erzwungen werden können.
- [ ] **`authSig` auf GET-Routen ablehnen.** Lesende Routen sollen eine mitgeschickte
      Signatur nicht still annehmen, sondern die Anfrage mit 400 abweisen.
- [ ] **Ausgang des SSH-Archivwegs merken** (PR 59, Nachprüfung). Root auf HTTPS, `cgi-io`
      fehlt, SSH-Port von Home Assistant aus zu: Jeder Tageslauf fordert das Archiv an und
      endet unvollständig (`unreachable`/`timeout`), bis die nächste Probe läuft. Wie beim
      cgi-Weg (`_cgi_seen`) den echten Ausgang des SSH-Wegs merken, damit Anzeige
      (`config.ssh_root`) und Lauf-Entscheidung früher nachziehen. Seit 1.46.1 nennt das
      Panel den SSH-Weg und den nächsten Schritt ehrlich.

### Traffic Analytics (Plan `docs/plans/2026-11-20-traffic-analytics.md`, 1.49.0)

Branch `claude/traffic-analytics-d7ae50`. Nutzerdoku: `docs/traffic-analytics.md`, Bauplan:
`docs/plans/2026-11-20-traffic-analytics-bauplan.md`.

- [x] Phasen A–L: Messmodell, Sammlung aus der vorhandenen Abfrage, Verlauf mit Profilen
      `compact`/`standard`, Auffälligkeiten, Kapazität, Flows aus einem externen Collector,
      Routen, Panel-Tab mit Einstellungen, Sensoren, Diagnose, Leistungs- und Qualitätstests
      (1.49.0).
- [ ] **An echten Routern prüfen** (nur lesend, mit Freigabe; Bauplan §12 Risiken 1, 2, 11):
      WAN- und Bridge-Zähler bei Hardware-Offload, DSA-Port-Zähler bei hardware-geschaltetem
      Verkehr, Richtung und Bitbreite der hostapd-Stationszähler, tatsächliche Schreiblast
      der beiden Profile.
- [ ] **Panel im echten Browser prüfen**, auch bei 360 px Breite, als Admin und Nicht-Admin.
- [ ] **Collector-Aggregate** (`client_aggregate`, `interface_aggregate`) annehmen: braucht
      eine eigene Collector-Zeitreihe neben der eigenen Messung; heute `kind_not_supported`.
- [ ] **W1** NI: öffentliche Schnittstelle für Kandidaten, damit Traffic-Auffälligkeiten
      NI-Vorfälle werden (heute nur Kern-Ereignisse).
- [ ] **W3** Core: gemeinsames Client-Pseudonym über Module (heute ergibt dieselbe MAC in
      Traffic und Security verschiedene `cli_…`).
- [ ] **W4** Core: `traffic_analytics` und `traffic.` als Namensräume reservieren.
- [ ] **W5** Core: Quote je Modul im Audit-Ring.
- [ ] **W6 (Rest)** WiFi RF: lesende API je Station für die Byte-Zähler (`AssocCounters`),
      damit Traffic kein eigenes `iwinfo assoclist` braucht. Airtime je Radio, Retry-Rate je
      Client und die Radio-Kennung gibt es seit 1.49.1.
- [ ] **W7** Netzwerkdiagnose: Latenz/Verlust je Router für die Korrelation.
- [ ] **W8** `client_engine`: kabelgebundene Clients (heute nur WLAN).
- [ ] **W2 (Rest)** Security Center: Traffic-Hinweise einem Gerät zuordnen und als
      Vertrauensindikator zählen; braucht W3 (heute nur Zeitleisten-Eintrag, 1.49.1).
- [ ] **conntrack-Ersatzweg am Gerät prüfen** (nur lesend, mit Freigabe): wie viel rpcd von
      `/proc/net/nf_conntrack` liefert; seit 1.49.1 begrenzt, ein abgeschnittener Wert gilt
      als unbekannt. Seit 1.49.3 gilt eine Antwort ab 3496 Byte als abgeschnitten (4096 minus
      angenommene längste Zeile von 600 Byte): die längste echte Zeile (mit Labels, Zone,
      secctx) messen und `CONNTRACK_LINE_MAX_BYTES` bestätigen.
- [ ] **„Verworfen“-Zeile trennen:** `rolled_buckets`, `replaced_client_points` und
      `expired_points` stehen in `overview()["drops"]`, sind aber keine Verluste (Verdichtung,
      Ersatz, Ablauf). Seit 1.49.4 hat jeder Schlüssel einen deutschen Text
      (`tests/test_traffic_drop_texts_v1494.py`); eigene Zeile oder Hinweis erwägen.

### WiFi RF (1.48.0, Nachprüfung 1.49.3)

- [ ] **Retry-Zählung an echter Hardware bestätigen** (nur lesend, mit Freigabe): seit 1.49.3
      gilt eine 0 als echte 0, sobald ein Client desselben Radios im Fenster Retries > 0
      hatte; `rf.retry_high` braucht mindestens 50 % der Clients gemessen (Startwerte). An
      mt76 mit und ohne WED prüfen, ob ein Radio mit WED nie Retries > 0 meldet.
- [ ] **Dieselbe „0 heißt unbekannt“-Regel in `rf_clients._retries_unverified`** (mt76 ohne
      bekannten WED-Zustand) liegt außerhalb von `rf_evaluate`; heute ohne Wirkung, weil
      `rf_evaluate` keinen Treiber übergibt. Bei einer Treiber-Erkennung gemeinsam regeln.

### Security Center (Plan `docs/plans/2026-11-17-security-center.md`, 1.46.0)

Branch `claude/security-center-6fdcdd`. Nutzerdoku: `docs/security-center.md`.

- [x] Center, Vertrauensbuch, Erkennungen (WLAN, Firewall, DNS, Konfiguration), Syslog-Weg A,
      Routen, Flotten-Sensoren, Diagnose, Panel-Tab (1.46.0).
- [ ] **Collector (Weg B)** bauen: `log_path: collector` meldet heute „nicht verfügbar“.
- [ ] **Quellen der Gruppe b mit ACL:** Conntrack-Maximum, nft-Zähler, `/proc/net/snmp`,
      dnsmasq-Metriken, IPv6-Nachbarn, WLAN-Scan, `uci get firewall`; Rechte über die gestufte
      Core-ACL anbieten (nicht in 1.46.0 gebaut).
- [ ] **Bind-Adresse des Syslog-Empfängers einstellbar** (heute fest `0.0.0.0`, nur IPv4).
- [ ] **Absender mit Hostname:** Router, die mit Hostnamen statt IP eingetragen sind, kommen
      nicht auf die Absenderliste (kein DNS-Lookup).
- [ ] **Zeitzonen-Offset des Routers lernen:** heute ist die Logzeit die Empfangszeit.
- [ ] **Router-Namen in der Security-API:** der Tab zeigt Router als gekürzte ID.
- [ ] **Markierung in der Topologie** (betroffene Router und Geräte) bauen.
- [ ] **Logformate an echten Geräten bestätigen** (nur lesend, mit Freigabe): fw4-Logfelder,
      dnsmasq-Abfragezeile, Kopf der logd-Remote-Zeile, dropbear-Fehlzeile; danach
      `FORMAT_CONFIRMED` anpassen. Offen auch: Port 5514 auf HA OS, Panel im echten Home
      Assistant als Admin und Nicht-Admin.
- [ ] **Nicht angebundene Erkennungen** aus dem Plan: Admin-Anmeldefehler (dropbear), MAC-Spoofing-
      und Verkehrs-Indikator, ungewöhnliche Verbindungszeiten, Rogue-AP-Indikator.
- [ ] **`fw_mgmt_access` ohne Verwaltungsadressen:** das Center übergibt keine `mgmt_addrs`;
      heute zählen nur die Zielports.
- [ ] **Idee: DNS-Namen optional behalten.** Die Option `keep_dns_names` wurde in 1.46.0
      entfernt, weil sie nicht wirkte. Eine spätere Version könnte Abfragenamen als Beispiel an
      DNS-Hinweisen behalten. Datenschutzfolgen vorher klären: Namen verraten Surfverhalten,
      landen im Speicher, in der Zeitleiste und auf dem Core-Bus; nur für Administratoren,
      gekürzt, mit eigener Speicherfrist und Doku-Hinweis.

### Network Diagnostics / Netzwerkdiagnose (Plan `docs/plans/2026-11-17-net-diagnostics.md`, 1.47.0)

Branch `claude/net-diagnostics-f989ed`. Nutzerdoku: `docs/network-diagnostics.md`.

- [ ] **Qualitätswert der Access Points:** seit 1.49.3 „unbekannt“ unter 25 % Abdeckung (ein AP
      ohne WAN und ohne Proben hat rund 7 %). Für eine echte Bewertung brauchen APs eigene
      Messungen (z. B. Gateway-Erreichbarkeit vom AP aus); Grenze 25 % und Deckel
      `50 + 50 × Abdeckung` sind Startwerte.
- [x] Laufzeit (aus / nicht bereit / bereit), Messungen von Home Assistant (TCP, DNS, HTTP) gegen
      bestätigte Ziele mit SSRF-Schutz, Kette Router → Gateway → WAN → Internet → DNS,
      Ursachenklassen, Statistik, Baselines, Netzqualitätswert mit Abdeckung, begrenzter
      Verlaufsspeicher, Routen, 6 Flotten-Sensoren und ein Gateway-Binärsensor je Router,
      Vorfälle `wan_gateway_changed` und `dns_server_changed`, Kontext aus Configuration Manager
      und Security Center, Panel-Tab, Diagnose-Block (1.47.0).
- [ ] **Router-seitige Tests** (Ping, `nslookup`, `traceroute` auf dem Router): heute nur
      Schnittstelle und Fähigkeitsprüfung, kein Ausführer und kein ACL-Recht; braucht eine
      gestufte Core-ACL mit Einzelfreigabe.
- [ ] **Ansicht für die Detail-Route** (`/details`) im Panel.
- [ ] **Ziele und Bereichslisten im Panel bearbeiten:** heute nur Anzeige, Änderung über die
      Route `settings`.
- [ ] **Schwellen an echten Daten abstimmen:** Gewichte und Punktetabellen des Werts,
      Baseline-Schwellen und Lernzeit sind begründete Annahmen.
- [ ] **Jitter-Baseline speisen:** der Baustein existiert, die Laufzeit nutzt ihn nicht.
- [ ] **Gateway-Glied messen:** der Binärsensor „Gateway erreichbar“ ist ohne Router-Messung
      unbekannt (`not_measured`).
- [ ] **TCP-Messung des Coordinators zu `8.8.8.8:53` (`ping_ms`) bereinigen**, eigener PR; sie ist
      unverändert und nicht Teil der Last der Netzwerkdiagnose.
- [ ] **Live-Prüfung gegen echte Router, Ziele und eine echte Home-Assistant-Instanz** (nur mit
      Freigabe); bisher laufen die Tests ohne Geräte und ohne Netz.

### Client-Stabilität (Plan `docs/plans/2026-11-16-client-stability.md`, 1.42.0)

B1–B9 auf `claude/client-stability-f9a22b`. Nutzerdoku: `docs/client-stability.md`.

- [x] Zustandsautomat je MAC, Stunden-/Tagesbuckets, Score, Muster,
      AP-Vergleich, Empfehlungen, API-Routen, Tab „Stabilität“, Sensoren für
      ausgewählte Clients, eigener Store mit Größengrenze.
- [x] 1.43.0: alle Fensterzahlen im Detail, echte letzte 60 min, grober
      7-/30-Tage-Verlauf, Abbruch-/Reconnect-Balken, AP-Wechsel-Streifen,
      Sortierung nach AP/7 Tagen/Trend, Gewichte und Klassengrenzen im Panel,
      SSID im Store (Branch `feature/client-stability-panel-1.43`).
- [ ] **VLAN-Filter** in der Client-Tabelle (nicht in 1.43).
- [ ] **Identität bei wechselnder MAC** verknüpfen (private MAC je Netz oder
      rotierend); heute ist jede MAC ein eigener Client, siehe
      `docs/client-stability.md`.
- [ ] **Numerische 802.11-Reason-Codes** auswerten, wo das Log sie liefert
      (heute nur Text).
- [ ] **B7a: v1.36-Reconnect-Zählung ablösen** (`AssociationTracker` →
      Zählung aus der Client-Stabilität, 300 s → Log-Ereignisse), eigener
      späterer PR. Entschieden (2026-11-17): bis dahin bleiben beide Zählungen;
      die Ablösung ändert das Verhalten des Sensors `unstable_clients`.
- [ ] **Sichtprüfung im echten HA-Frontend**, Desktop und Handy (Tabelle,
      Detail-Charts, Karten-Layout unter 760 px), als Admin und Nicht-Admin;
      seit 1.43 auch Streifen 7/30 Tage, AP-Wechsel-Streifen mit Legende,
      Balken Abbrüche/Reconnects und das Formular für Gewichte/Grenzen.
- [ ] **Kopfleiste läuft unter 420 px rechts aus dem Bild** (Panel-Statusleiste
      mit Filtern, Suche und Schaltern; seit 1.43.1 bekannt, nicht behoben).
- [ ] **Muster beim Stundenwechsel vorberechnen** (der Tabellenabruf mit
      1000 Clients blockiert sonst etwa 1,4 s, weil er die Stundenmuster
      aller Clients rechnet).
- [ ] **7-Tage-Werte beim Stundenwechsel vorberechnen** (1.43, Review
      LOW-2): der erste Tabellenabruf je Stunde, sortiert nach
      7-Tage-Verfügbarkeit oder Trend, läuft bei 150 Clients etwa 0,46 s im
      Event-Loop.
- [ ] **`infra` je Radio statt je Router** bei `wifi_radio_change`: heute
      markiert ein Kanalwechsel 300 s lang den ganzen Router. Braucht in
      `client_history.py` eine `infra`-Zuordnung je Router und Radio.
      1.48.0 Teil 2 (WiFi RF) hat das geprüft und NICHT gebaut (offene
      Frage): Logzeilen kennen ihr Interface (Phy sauber), aber ein Client,
      der nur aus der Liste verschwindet, kennt in `client_history` nur sein
      Band, nicht die Phy; bei zwei Radios im selben Band ist Band→Phy nicht
      eindeutig. Nur die Logzeilen zu verfeinern, würde denselben Abbruch je
      nach Quelle verschieden einstufen. Dafür müsste `ClientObs` die Phy
      mitführen.
- [ ] **Gastclients früher entfernen** (gesamt online < 1 h, seit 7 d weg;
      private MACs ohne Wiederkehr nach 7 d) – geplant in 4.2, nicht gebaut;
      heute erst nach `retention_days` oder beim Kürzen.
- [ ] Auf Hardware prüfen (nur lesend, mit Freigabe): Store-Größe nach einigen
      Tagen, Score plausibel, AP-Ausfall als Messlücke.

### Network Intelligence (Plan `docs/plans/2026-11-16-network-intelligence.md`, geplant 1.40.0)

P1–P7, die Review-Fixes und die Doku (P8) liegen auf `feature/network-intelligence`,
noch nicht gemergt und nicht released. Nutzerdoku: `docs/network-intelligence.md`.

- [x] Ereignisse, Incidents mit Ursache, Health-Score, Entities, HA-Event
      `openwrt_router_incident_event`, Wartungsmodus, Tab „Diagnose“,
      Persistenz über HA-Neustarts (Store `openwrt_router.intelligence`).
- [ ] **`async_unload_entry` soll `None` zurückgeben** (HA-Developer-Blog
      „Config entry functions now return None“, 2026-10-23); heute `bool`.
      Vorher prüfen, ab welcher HA-Version und was der Rückgabewert bei
      fehlgeschlagenem Plattform-Unload bedeutet.
- [ ] **Belege im Incident-Detail gruppieren:** viele gleiche Zeilen
      „system cpu load“ untereinander; gleiche Belege zusammenfassen
      (Anzahl, erster/letzter Zeitpunkt).
- [ ] **Tests im echten HA-Frontend** (Diagnose-Tab, Warnsymbole, Einstellungen
      als Admin und Nicht-Admin), **auf einem echten Handy** und **auf
      Hardware** (AP-Ausfall mit Clients, Store-Größe, Score plausibel,
      Flotten-Entities beim Neuladen eines Routers) – nur lesend und mit
      Freigabe.
- [ ] **Aufräumen aus P8 (Code, eigener Auftrag):** `_record_events` im
      Coordinator entfernen, sobald das Panel umgestellt ist; Panel-Regeln aus
      `useAlerts.ts` bis auf „möglicher Router/Repeater“ entfernen; Tab
      „Alarme“ danach zusammenführen.

### Nach Installation von 1.39.0 (Plan `docs/plans/2026-10-28-ssh-polling-und-audit.md`)

Alles lesend, Installation und HA-Neustart nur nach OK.

- [x] **Diagnose** eines Routers herunterladen und nach MAC-/IP-Mustern,
      Hostnamen und SSIDs durchsuchen (A5).
- [ ] **Panel als Nicht-Admin** öffnen (403-Hinweis, kein Sidebar-Eintrag),
      Option „allen Benutzern anzeigen“ an/aus ohne Neustart; Sitzungsablauf
      ohne Request-Schleife (A13, C11 nie im Browser geprüft).
- [x] **Rollen im Panel:** Gateway + zwei APs; Kanten vorhanden (A12) – über die Snapshot-API,
      Darstellung im Panel nicht angesehen.
- [x] **Poll-Versatz:** im Debug-Log pollt jeder Router weiter, mit
      unterschiedlichen Zeitpunkten (A7).
- [x] **Schnittstellen-Zähler:** `network.device status {}` liefert
      `statistics` für `br-lan`/`wan` (A9).
- [x] **Raten-Sensoren** in HA aktivieren und prüfen, dass sie nicht mehr 0 zeigen (A9) –
      `wan` RX/TX am Gateway aktiviert, Werte im kB/s-Bereich.
- [x] **ARP:** Größe von `/proc/net/arp` am Gateway, `getHostHints`-Antwort (A10).
- [x] **„Nach Updates suchen“** auf Gateway und AP: Dauer, Ausgabe von
      `apk list -u` bzw. `opkg list-upgradable` (A6). Fehlermeldung ohne SSH
      nicht geprüft (kein Router ohne SSH). `ap4` hat 70 Paket-Updates
      offen (u. a. `rpcd`, `ubus`) – Installation nur nach eigener Entscheidung.
- [x] **Tracker:** nach HA-Neustart melden abwesende Clients `not_home` (A3).
- [x] **Recorder:** statt DB-Größe (MariaDB, viele andere Integrationen) direkt in der
      Historie geprüft: `packages`, `system_packages`, `last_check` werden seit 1.39.0
      nicht mehr gespeichert (A8).
- [x] **Dev-Skript `scripts/_add_topology_card.py`** liest das entfernte
      Attribut `topology_snapshot` – gelöscht (kein Dashboard nutzt das Attribut).
- [x] **Frontend-Folgen aus A12:** veraltete (`stale`) Clients/Kanten
      ausgrauen, `lldp_duplicates` als Parallel-Link zeigen, bei mehreren
      Gateways bewusst wählen statt `routerNodes[0]`. Im Browser noch nicht angesehen.
- [ ] Optional: Button „Veraltete Tracker entfernen“ (wie `fritz`).

### Fehlerkorrektur nach 1.37 (Plan `docs/plans/2026-10-27-fehlerkorrektur-nach-1.37.md`)

- [x] P1/P2/P6 (v1.37.5), P3 + ACL v7 (v1.38.0), P4 (v1.38.1), P5 + B2 (v1.38.2),
      B1 (drei Config-Entries ohne Router entfernt).
- [ ] **B3: rpcd-Speichermessung mit ACL v6 auswerten** und ins Prüfprotokoll
      des Plans eintragen.
- [ ] **Hardware-Prüfung nach dem Update** (lesend): ACL v7 auf Gateway und APs
      verteilt, CPU-Sensor gegen `cat /proc/loadavg` + `nproc`, „WLAN neu laden“
      wendet an, Kanal aus dem `config`-Block, HA-Log nach Neustart ohne
      Root-Warnungs-Serie, ohne „network.reload“-Warnung und ohne
      `device_registry`-Deprecation.
- [ ] **Panel-Sichtprüfung** in HA: Clients mit privater MAC ohne Hersteller
      (Liste, Name „Privat-MAC …“, Detailansicht).
- [ ] **Release v1.38.2 prüfen:** Release-Text = CHANGELOG-Abschnitt, und ob
      HACS ihn im Update-Dialog zeigt (in der HACS-Doku nicht beschrieben).
- [ ] **WAN-Entities auf `ap2`/`ap4`** stehen weiter auf `unknown` (E3: kein
      Registry-Eingriff, `enabled_default` wirkt nur bei neuen Entities) –
      bei Bedarf in HA von Hand deaktivieren.
- [ ] **Befund 13:** zwei wiederhergestellte Device-Tracker mit altem AP-Namen in der Entity-ID
      (`unavailable`, `restored: true`) – Ursache klären, Registry-Eingriff
      nur mit OK. Seit 1.39.0 (A3) `not_home` statt `unavailable`; die alten
      Entity-IDs (`secureap_ap3_…`) bleiben.
- [ ] **Befund 14:** `uci_section` im Pfad `network.wireless status` (netifd
      liefert `section` neben `ifname`). Ein Fix ändert die `unique_id` der
      WLAN-Schalter betroffener Router – braucht eine eigene Entscheidung.
- [x] **GitHub-Repo-Beschreibung** ohne fest eingetragene Versionsnummer aktualisiert.

### HA-Modernisierung (Folgearbeiten aus dem Kompatibilitäts-Review 2026-07)

- [x] **Outage als Repairs-Issue** (v1.29.0) — `fleet.FleetOutageTracker` +
      `issues.py`; gleichzeitige Ausfälle aller Router → ein `lan_unreachable`.
- [ ] **SSH-Fallback als Repairs-Issue** — die SSH-Fallback-Meldung (coordinator.py,
      `async_create`) auf `issue_registry` umstellen, als fixable Issue
      (RepairsFlow → `acl_provisioning.ensure_acl()` erneut ausführen). `issues.py`
      und die `issues:`-Sektion in strings.json/en.json/de.json gibt es seit v1.29.0.
- [ ] **Notification-/Event-i18n** — Hardcodierte deutsche Texte im Coordinator
      (SSH-Fallback-Notification, Outage-Notification, Event-Timeline-Meldungen
      „WAN verbunden/getrennt", „CPU-Last erhöht", …) übersetzbar machen.
      Hängt sinnvoll mit der Repairs-Migration zusammen.
- [ ] **`topology_card`-WIP-Modul** — Import ist seit v1.19.0 geguardet; Modul
      fertigstellen oder Guard + Referenzen entfernen.
- [ ] Optional: **pytest-homeassistant-custom-component** als zusätzliche
      Smoke-Test-Ebene (echte `hass`-Fixture für Setup/Unload/Config-Flow) —
      bestehende Mock-Suite bleibt die Basis.

### HACS / Release

- [ ] **HACS Default Store — Neuanlauf.** PR hacs/default#6421 wurde am 2026-03-21
      ungemerged geschlossen. Vor Neu-Einreichung: aktuellen HACS-Submission-Prozess
      prüfen (hacs.xyz/docs/publish), PR an `home-assistant/brands` stellen
      (Voraussetzung fürs Default-Listing), dann neu einreichen.
      Bis dahin: Installation als Custom Repository (siehe INSTALL.md).

### Betrieb / Validierung

- [ ] **Prod-Validierung v1.19/v1.20** — 24h-RSS/rpcd-Beobachtung auf dem
      Produktiv-Gateway nach dem Session-Leak-Fix (Vergleich gegen
      `diagnostics/prod-24h-baseline.jsonl`, Sampler: `scripts/_prod_24h_sample.sh`).
- [x] **Persistente Event-History** — mit Network Intelligence (Store
      `openwrt_router.intelligence`, 30 Tage). Die alte In-Memory-Timeline im
      Inspector (`_record_events`) bleibt bis zum Aufräumen.

### LLDP-Nachlese (aus dem Merge-Review von PR #14, 2026-09-09)

- [ ] **OUI-Tabelle existiert doppelt** — `custom_components/openwrt_router/oui.py`
      (~667 Einträge) ist eine Handkopie von `OUI_TABLE` in
      `frontend/topology/src/api.ts`. Eine Quelle festlegen und die andere
      generieren, sonst driften die beiden auseinander. Ist schon passiert:
      `d2:4e:4f` fehlte ab v1.37.0 nur in `oui.py`, das Panel zog in v1.38.2 nach.
- [ ] **Ungenutzte LLDP-Konstanten** in `const.py` aufräumen:
      `LLDP_CLI_CHECK_CMD`, `LLDP_INIT_ENABLED_CMD`, `CAP_LLDP_NEIGHBORS`
      (dupliziert als String-Literal in `config_flow._LLDP_CAP`), dazu
      `SOURCE_ARP/FDB/DHCP/OUI`, `CLIENT_KEY_VLAN_IDS`, `CONNECTION_TYPE_WIRED`.
- [ ] **Checklist-Hinweis präzisieren** — LLDP braucht nicht nur `lldpd`,
      sondern auch SSH-Zugang. Auf einem Router mit sauberer ACL v5 **ohne**
      Dropbear-Login bleibt LLDP dauerhaft `unavailable`, der Hinweistext nennt
      aber nur die lldpd-Installation.
- [x] **`ruff` in der CI pinnen** — `tests.yaml` und `release.yaml` installieren
      `ruff==0.17.3`.

### Topology Frontend (Wunschliste, unverändert offen)

- [ ] Per-Client Traffic Chart — RX/TX-Verlauf pro WLAN-Client
- [ ] Shift+Click Multi-Device Compare
- [ ] Bridge-FDB-Visualisierung im PortStrip (welcher Port sieht welche MACs)

### Entities / Features (Roadmap)

- [ ] Per-Client Online-Zeit
- [ ] Link-Quality-Metriken (Signal/Noise pro Radio)
- [ ] Parental Control Support

---

## Erledigt (Auszug — Details in CHANGELOG.md)

- [x] v1.49.4 — Traffic-Router-Sensoren am Gateway (WAN-Gerät aus netifd), sysfs-Ausweg
      nur für aktive Schnittstellen, MACs in freiem Text (Core, Configuration Manager,
      Netzwerkdiagnose; im Diagnose-Download deren Blöcke) geschwärzt, deutsche Texte für
      alle Traffic-Verwurfszähler, unbenutztes Vite-Plugin entfernt, 130 unique_ids eines
      Gateways festgeschrieben (Grenzen im Test-Docstring)
- [x] v1.38.x — CPU-Last pro Kern + rpcd-ACL v7, Kanal aus dem `config`-Block,
      AP-Interfaces im SSH-Fallback, WAN-Sensoren auf Routern ohne WAN
      standardmäßig aus, Panel ohne OUI-Hersteller bei privaten MACs,
      Release-Texte aus CHANGELOG.md
- [x] v1.37.x — `random_mac`, rpcd-`rc/list`-Leck umgangen, Banderkennung
      (UCI `band`, 6/60 GHz), Panel-Footer/WAN-Rate/HA-Namen, Log-Hygiene,
      `async_get_device`-Deprecation
- [x] v1.29–v1.36 — Repairs (Ausfall, RAM-Druck, Kanalkonflikt), Schalter
      erweiterte WLAN-Sensoren, Kanalplan, Router-Log + ACL v6, DFS-Events,
      DHCP-Pools, klebende/instabile Clients
- [x] v1.20.0 — HA-Kompatibilitäts-Review: `config_entry=` an DataUpdateCoordinator
      (HA-2026.8-Deadline), toter `register_static_path`-Fallback entfernt,
      `integration_type: hub`, HA-Floor 2026.2.0, deutsche Übersetzung (de.json),
      Blueprint auf Plural-Syntax + source_url, Release-Workflow gegated,
      CI-Matrix 3.13/3.14 (3.12 löste HA 2024.x auf), ha-compat pinnt echte Latest-HA
- [x] v1.19.0 — rpcd-Session-Leak-Fix (destroy bei Re-Login), ACL-Re-Validierung,
      Cache für ACL-geblockte Methoden
- [x] v1.18.0 — Subprocess- + Panel-Lifecycle-Hardening, 24h-Prod-Sampler
- [x] v1.17.x — Error-Sensor + Outage-Notifications, sshpass-Security-Fix (`-e` statt argv)
- [x] v1.16.0 — HTTPS-Support (http / https / https-insecure)
- [x] Fixtures `tests/fixtures/router_*.json`, brand/icon 256×256,
      hassfest/HACS/tests/ha-compat/release CI-Workflows, GitHub Releases
