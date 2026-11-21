# Changelog

All notable changes to the OpenWrt Router integration will be documented in this file.

## [1.51.0] - 2026-11-21

Network Time Machine, Phasen B und C: Die Zeitreise hat einen **eigenen Verlauf, der
HA-Neustarts übersteht**, und **Client-Verläufe hinter einem eigenen Schalter**, der
standardmäßig aus ist. Weiterhin ist die ganze Time Machine **standardmäßig aus**; wer
nichts einschaltet, merkt vom Update nichts (kein Store, kein Listener, keine Aufgabe, kein
Router-Aufruf, keine Entität; Test). **Kein zusätzlicher Router-Aufruf:** Der Verlauf entsteht
nur aus den Coordinator-Daten und den Ereignissen vorhandener Module (Test vergleicht die
Aufrufliste zweier Polls mit allem an und allem aus). Gespeichert werden feste Codes, Zahlen,
Router-Kennungen `rtr_…`, Zeitpunkte und bei Clients ein Pseudonym `tmc_…`; **nicht**
gespeichert werden MAC- und IP-Adressen, Hostnamen, SSIDs, Netdev-Namen und freie Texte.
Grenzen: 14 Tage Aufbewahrung, Kontingente Infrastruktur 3000 / Verweise 2000 / Clients
10000 Marken, die einander nie verdrängen, höchstens 200 Marken je Client und Tag, Datei
höchstens 2,5 MB (voller Speicher gemessen 1,63 MB). Entwicklerdoku: `docs/time-machine.md`,
Abschnitte 14.3 und 15–19. Panel-Version `20261121-timemachine3`.

### Hinzugefügt

- **Eigener Verlauf (Phase B).** Bei eingeschalteter Time Machine ein eigener Speicher
  `openwrt_router.time_machine` mit Router-Ausfällen und Flottenausfällen als Intervall mit
  Ende, Beobachtungslücken, HA-Lücken (sauber/unsauber), Kanal- und DFS-Wechseln, fehlenden
  Funkmodulen, Uplink- und Rollenwechseln, Änderungen des Konfigurations-Fingerabdrucks,
  Verweisen auf Audit-Einträge (bleiben sichtbar, wenn der Audit-Ring sie verdrängt hat),
  Uhrsprüngen und täglichen Checkpoints. Verzögertes, gebündeltes Schreiben; eine kaputte oder
  neuere Datei bleibt als `.bak`, offene Intervalle enden nach einem Neustart als „Ende
  unbekannt“.
- **Client-Verläufe (Phase C)** hinter dem eigenen Schalter `time_machine_clients`
  (Standard aus, einer für alle Router): Sitzungen je Client mit Router, Band, Wechseln und
  Trennungen aus der Client-Stabilität. Hostname nur für Administratoren und nur, solange die
  Client-Stabilität den Client kennt (nie gespeichert); über 200 Marken je Client und Tag
  wird zusammengefasst. **Ausschalten löscht alle gespeicherten Client-Verläufe sofort.**
- **Route `GET …/enterprise/timemachine/sessions`** (nur Administratoren): Sitzungen, die ein
  Fenster überlappen, Filter `client`, `router_id`, Blättern über `next_until`.
- **Zeitleiste:** neue Quellen `tm_index`, `tm_refs` (nur Admins), `tm_clients` (nur Admins);
  additive Felder je Marke `code`, `end`, `end_state`, `client`, `client_name`, `peers`,
  `spans_in` und je Quelle `duplicates`; Grund `clients_off`. Intervalle, die vor dem Fenster
  begannen und hineinreichen, gehören dazu (`spans_in: true`) und erscheinen beim Blättern
  genau einmal, auf der letzten Seite. Doppelte werden entfernt: das Audit gewinnt über
  seinen Verweis, der eigene Verlauf über gleiche NI-Ereignisse, solange er lief. `v` bleibt 1.
- **Tab „Zeitreise“:** Quellen „Eigener Verlauf“, „Verweise“, „Client-Verläufe“ (die beiden
  letzten für Nicht-Admins gesperrt), Zusatz „· n doppelt“; Dauer von Intervallen („Dauer
  4 min 12 s“, „seit 14:03, noch offen“, „Ende unbekannt“) und ein eigener Block „Läuft seit
  vor dem Zeitfenster“; Titel für alle Arten des eigenen Verlaufs (32 neue, Test); Clients als
  „Client <Name>“ oder „Client ·a1ce4d“, nie als MAC; Wechsel „von Router 1 nach Router 2“;
  Art-Chip „Clients“. Neue Ansicht **„Client-Sitzungen“** nur für Administratoren
  (Umschalter „Zeitleiste | Client-Sitzungen“): Zeitfenster, Router und Client wählbar, nach
  Tagen gruppiert, Beginn, Dauer bzw. „noch verbunden“, Client, Router, Band und Wechsel,
  Karten bei schmaler Breite, „Ältere laden“, alle Zustände (aus, Client-Verläufe aus,
  noch nicht verfügbar, leer, Fehler). Hinweis „Viele neue Einträge: Die Liste beginnt neu.“,
  wenn eine Aktualisierung die geladenen älteren Seiten nicht erreicht, und „Quellen
  (neueste Seite)“ nach „Ältere laden“.
- **Aktionen** `openwrt_router.time_machine_forget_client` (`mac`) und
  `openwrt_router.time_machine_clear_history` (`clients_only`), nur für Administratoren; der
  Tab bietet sie nicht an.
- Diagnose: Schalter, Zähler und Grenzen des eigenen Verlaufs.

### Geändert

- **Ausschalten der Time Machine löscht die Client-Verläufe**, auch wenn der Schalter
  „Client-Verläufe“ an bleibt und auch, wenn gerade kein Verlauf läuft (vorher blieben sie dann
  in der Datei). Gelöscht werden alle Marken mit Client-Pseudonym; Ausfälle, Lücken,
  Änderungen, Verweise und Checkpoints bleiben. Der Optionen-Dialog sagt das (de/en).
- **Lesegrenze der NI-Vorfälle:** an die tatsächliche Zahl gespeicherter Vorfälle gebunden;
  sie werden ganz gelesen, auch wenn mehr aktive und bestätigte Vorfälle gespeichert sind als
  die Obergrenze für behobene (Test).
- Tab: der Hinweis zu ausgeblendeten Client-Ereignissen verspricht keine „spätere Version“
  mehr, sondern nennt bei ausgeschalteten Client-Verläufen den Weg in die Optionen.
- `client_engine.py` / `client_history.py`: Beobachter für Übergänge und Vergessen
  (`add_transition_listener`); ohne Beobachter unverändert, mit Beobachter gleiche Buchungen
  (Test), Fehler eines Beobachters erreichen die Historie nicht.
- `net_engine.py`: schreibgeschützte Eigenschaft `topology`.
- Die wirkungslose Konstante `SOURCE_MARK_CAP` und ihr Diagnosewert `source_mark_cap` sind
  entfernt.

### Bekannte Grenzen

- **Solange die Time Machine aus ist, wird nichts gekürzt:** Der Verlauf von Ausfällen und
  Änderungen bleibt in der Datei, bis sie wieder eingeschaltet wird (dann sofort auf 14 Tage
  gekürzt) oder „Verlauf löschen“ läuft.
- Offene Intervalle werden nicht nach 14 Tagen gekürzt.
- Mehr Intervalle, die ins Fenster reichen, als `limit`: der Rest fehlt (`truncated: true`
  ohne `next_until`). Ebenso bei Sitzungen.
- Nicht rückwirkend: Was vor dem Einschalten geschah, steht nur in den Phase-A-Quellen.
- Client-Sitzungen nur, solange die Client-Stabilität läuft; Hostnamen nur aus ihr.
- „Client vergessen“ löscht nur im Verlauf der Time Machine, nicht in anderen Modulen oder im
  HA-Recorder.
- Nach einem Absturz ist der Beginn der HA-Lücke nur auf etwa 15–17 min genau.
- **Nicht an einer echten Instanz und nicht auf Routern geprüft**; alle Aussagen stammen aus
  Tests mit Mocks. Der Tab von 1.51.0 ist in keinem Browser angesehen, nur mit node-Tests
  (Logik, serverseitiges Rendern, Stylesheet).

## [1.50.0] - 2026-11-21

Network Time Machine, Phase A: eine Zeitleiste, die die Ereignisse vorhandener Module auf eine
Achse legt, als Lese-Schnittstelle und als Enterprise-Tab „Zeitreise“. **Standardmäßig aus,
ein Schalter für alle Router.** Kein eigener Speicher, kein zusätzlicher Router-Aufruf (Test
vergleicht die Aufrufe zweier Polls mit Time Machine an und aus), kein Listener, keine
Hintergrundaufgabe, keine Entitäten und keine Client-Marken. Entwicklerdoku:
`docs/time-machine.md`. Panel-Version `20261121-timemachine2`.

### Hinzugefügt

- **Route `GET /api/openwrt_router/enterprise/timemachine/timeline`.** Liest bei jeder Anfrage
  Audit-Log des Enterprise Core, Konfigurationsversionen, Ereignisse und Vorfälle von Network
  Intelligence und die Zeitleiste des Security Center über deren öffentliche Lesefunktionen,
  rechnet sie in Marken um und gibt sie neueste zuerst zurück. Abfrage `from`, `until`
  (halboffen, Standard 24 h, höchstens 14 Tage), `source`, `router_id`, `kind`,
  `min_severity`, `limit` (Standard 200, höchstens 500); jeder Schlüssel höchstens einmal,
  unbekannte werden abgelehnt (400 ohne Echo). Jede Quelle wird bis zur Kapazität ihres
  Speichers ganz gelesen (Ausnahme: Konfigurationsversionen, 500), Rechte, Filter und
  Seitengröße wendet die Zusammenführung an. Blättern über `next_until` auf einem
  Millisekunden-Raster, ohne Marken desselben Zeitstempels zu teilen, ohne Doppel und ohne
  Lücken; eine gekürzte Quelle hält die Seite an ihrer Kante an, ist nie `empty` und sagt
  `cut` (`next_page` / `unreachable`). Je Quelle Zustand (`ok`, `empty`, `off`,
  `unreadable`) mit festem Grund und Zeitbudget von 2 s (in den Schleifen des Adapters
  geprüft); eine fehlerhafte Quelle macht die Antwort `partial`, nie die ganze Anfrage
  kaputt. Administratoren sehen alles; andere
  Benutzer nur bei freigegebenem Topologie-Panel und dann nur Infrastruktur, Funk, Topologie
  und Störungen, ohne Audit-Log und Konfigurationsversionen; Zustand, Zahl und ältester
  Zeitpunkt je Quelle gelten nach den Rechten. Keine MAC- oder IP-Adressen,
  Hostnamen, SSIDs oder WLAN-Netdev-Namen in Antworten, Logs oder Diagnosedaten; Ereignisse
  eines einzelnen Clients werden weggelassen und nur für Administratoren gezählt
  (`omitted_client_marks`, für andere Benutzer 0).
- **Enterprise-Tab „Zeitreise“** (nach Traffic Analytics). Zeitfenster 1 Stunde, 24 Stunden,
  7 oder 14 Tage; Filter nach Quelle, Schwere und Router, dazu Art-Chips, die nur die
  geladenen Marken filtern („x von y Marken“). Je Quelle ein Zustand in Worten („12 Marken“,
  „leer“, „aus“ mit Grund, „Quelle nicht lesbar“ mit Grund, „gekürzt“, „Älteres nicht
  abrufbar“); Quellen, die nur
  Administratoren lesen dürfen, sind für andere Benutzer gesperrt. Marken neueste zuerst nach
  Kalendertagen in Ortszeit (Heute, Gestern, Wochentag mit Datum), mit Uhrzeit (UTC-Zeit im
  Tooltip), Schwere als Punkt und Wort, Art, deutschem Titel für jeden Code, den das Backend
  erzeugen kann (Test), Kennzahlen, Router und Quelle. „Ältere laden“ blättert über
  `next_until`; ein Abschnitt mit nur ausgeblendeten Einträgen sagt das und bietet „Ältere
  laden“ an. Aktualisiert sich nur bei sichtbarem Tab höchstens alle 60 s; eine
  Aktualisierung während „Ältere laden“ lässt keine geladenen Marken verschwinden. Unter der
  Breite einer Zeile werden Marken zu Karten, ohne seitliches Scrollen bis 360 px.
- **Option „Network Time Machine für alle Router“** (`time_machine_enabled`, aus) in den
  Router-Optionen; Speichern schreibt den Wert in alle Router-Einträge und lässt deren übrige
  Optionen unverändert. Aus antwortet die Route `status: off` und liest keine Quelle; der
  Tab zeigt dann nur den Hinweis mit dem Weg zum Schalter.
- **Diagnose-Block `time_machine`**: Schalter, Grenzen, Zustand und Markenzahl je Quelle der
  letzten 24 h und Zähler der Anfragen; nichts Persönliches. Aus nur `{"enabled": false}`.

### Behoben

- **Konfigurationsmanager:** Nach einem HA-Neustart zeigte die Drift-Zusammenfassung den
  ältesten statt den neuesten Audit-Eintrag.
- **Audit-Protokoll:** Ein gesprächiges Modul verdrängt auf dem allgemeinen Ring keine
  Einträge anderer mehr. Jeder Besitzer hat einen festen Anteil (Core 400, je Modul 100);
  verdrängt wird zuerst der älteste Eintrag eines Besitzers über seinem Anteil. Verdrängte
  Einträge werden gezählt (`evicted_general`, je Besitzer `general_evicted`).
- **Enterprise Core:** Die Beschreibung von `events` stimmt wieder: Einträge kommen vom
  ältesten zum neuesten, `limit` behält die neuesten.

### Bekannte Grenzen

- Die Zeitleiste liest nur, was die Module selbst behalten. Ausfälle und Kanalwechsel vor
  einem HA-Neustart fehlen deshalb, bis Phase B einen eigenen Verlauf bringt.
- Keine Client-Marken; Ereignisse einzelner Clients werden nur gezählt.
- Konfigurationsänderungen erscheinen nur als Anzahl und Referenz, ohne Inhalt.
- Mehr Marken mit demselben Zeitstempel (Millisekunde) als `limit` werden abgeschnitten
  (`truncated`).
- Konfigurationsversionen: höchstens 500 je Anfrage und ohne `until`; liegen mehr als 500
  zwischen `from` und jetzt, sind die älteren nicht erreichbar (`cut: unreachable`).
- Das Zeitbudget von 2 s unterbricht die synchronen Lesefunktionen der Quellmodule nicht;
  es greift erst in den Schleifen des Adapters.
- Modulschlüssel des Enterprise Core werden weiterhin nur nach Namen vergeben.
- Nur mit Tests und Mocks geprüft, nicht auf Routern und nicht in einer laufenden HA-Instanz.
  Den Tab hat die Prüfung vor dem Merge headless in Firefox mit Testantworten bei 360, 768 und
  1280 px angesehen, auch nach den Korrekturen (Kontrast gesperrter Chips, Kartenansicht ab
  860 px, Quellspalte).
- Network-Intelligence-Vorfälle: Bei mehr als 500 offenen Vorfällen liegt der Speicher über der
  Lesegrenze; die übrigen fehlen dann und die Quelle sagt `cut: unreachable`.
- Bringt eine Aktualisierung mehr neue Marken als eine Seite, beginnt die Liste im Tab neu;
  zuvor nachgeladene ältere Seiten müssen erneut geladen werden.

## [1.49.4] - 2026-11-21

Behebt die fehlenden Traffic-Sensoren am Gateway und kleine Restpunkte nach 1.49.3:
MAC-Adressen in freiem Text, fehlende deutsche Texte im Traffic-Tab, ein unbenutztes
Frontend-Paket und ein Test, der die unique_ids eines Gateways festhält. Keine neuen
Router-Rechte. Bei ausgeschaltetem Traffic-Modul macht ein Poll dieselben Router-Aufrufe wie
1.49.3; mit eingeschalteter Traffic-Option `traffic_sysfs_fallback` entfallen Lesezugriffe für
inaktive Schnittstellen (unter „Behoben“). Keine bestehende unique_id geändert (für die im
Test abgedeckten Entitäten mit 1.49.3 abgeglichen); mit eingeschaltetem Traffic entstehen am
Gateway die Router-Sensoren neu. Panel-Version `20261121-review2`.

### Geändertes Verhalten, das Nutzer bemerken

- **MAC-Adressen in Meldungen werden geschwärzt.** Freitext des Enterprise Core
  (Fehlermeldungen, Gründe, Hinweise, Beschreibungen), Texte des Configuration Managers und
  alle Ausgaben der Netzwerkdiagnose zeigen statt einer MAC `**REDACTED**`; im
  Diagnose-Download gilt das für die Blöcke Core, Configuration Manager und
  Netzwerkdiagnose. Diffs, Archive und Admin-Ansichten des Configuration Managers zeigen MACs
  weiter, weil sie dort der Inhalt sind (z. B. `@host{"mac":…}` in einem Diff).

### Behoben

- **Traffic Analytics: Das Gateway bekommt jetzt seine Router-Sensoren** (WAN Download, Upload,
  Summe und Spitze, Uplink-Auslastung und Uplink-Fehler). `wan_status` gab das WAN-Gerät von netifd
  (`l3_device`) nicht weiter, deshalb fehlte an echten Routern der WAN-Messpunkt; die Testdaten
  enthielten das Feld von Hand. Gefunden bei der ersten Prüfung an einer echten Installation. Kein
  zusätzlicher Router-Aufruf, keine bestehende unique_id geändert.
- **Traffic Analytics: Die sysfs-Ausweichabfrage liest nur noch Geräte von aktiven Schnittstellen.**
  Vorher las sie für eine inaktive Schnittstelle (z. B. `wan6`) acht nicht vorhandene Dateien und
  zählte das als `source_missing`.
- **MAC-Adressen in freiem Text blieben lesbar** in `redact_text`/`scrub_text` (Core),
  `config_redact_text` (Configuration Manager) und den Ausgaben der Netzwerkdiagnose
  (`log_safe`, Befunde, Ursachen, Ereignisse). Alle nutzen jetzt ein gemeinsames Muster,
  `core_masking.MAC_IN_TEXT_RE`: das geprüfte Muster des Security Centers aus 1.49.3
  (Doppelpunkt, Bindestrich, Punkt, ohne Trenner, mit Leerzeichen; ohne Trenner und mit
  Punkt nur mit mindestens einem Hex-Buchstaben; linear). Das Security Center nutzt es
  unverändert weiter. 12-stellige Zahlen, Zeitstempel, Telefonnummern, Hashes, Core-IDs und
  Pseudonyme (auch `usr_` + 12 Hex) bleiben lesbar. `mask_for_output` und
  `config_mask_for_output` schwärzen MACs in strukturierten Daten nur auf Wunsch
  (`macs=True`).
- **Traffic-Tab: „Verworfen“ zeigte „Code dropped_snapshots“ und „Code stations_dropped“.**
  Auch die übrigen Zähler derselben Zeile (`late_rates`, `dropped_points_*`,
  `store_trimmed_*` usw.) hatten keinen deutschen Text. Jetzt hat jeder Zähler, den die
  Übersicht liefern kann, einen Text; ein Test nimmt die Schlüssel von einer laufenden
  Engine und schlägt fehl, wenn künftig einer ohne Text dazukommt.

### Intern

- **`vite-plugin-css-injected-by-js` entfernt.** `vite.config.ts` lädt es nicht; das gebaute
  Bundle ist byte-gleich.
- **Test gegen wechselnde unique_ids** (`tests/test_unique_ids_snapshot_v1494.py`, Modell in
  `tests/full_router_kit.py`). Ein Gateway mit vollständigen Poll-Daten über ubus
  (Schnittstellen, Ports, DHCP-Pool, Dienste, ein WLAN-Client) und rpcd-getreuem WLAN wird
  zweimal ohne SSH-Ausweichweg abgefragt; danach legen alle Plattformen ihre Entitäten an.
  Festgehalten sind 130 unique_ids: 109 Entitäten bei ausgeschalteten Enterprise-Modulen
  (92 Sensoren, darunter 16 Schnittstellen-, 8 Port-, 32 AP- und 1 DHCP-Pool-Sensor, auch
  die deaktiviert angelegten; 7 Schalter, 1 Device Tracker, 6 Buttons, 3 Binärsensoren),
  12 WLAN-unique_ids des iwinfo-Wegs (Schalter nach Schnittstellenname, Rausch- und
  Signal-Sensoren) und 9 bei eingeschaltetem Traffic (7 Router-, 2 Flotten-Sensoren). Die
  Option „erweiterte WLAN-Sensoren“ ändert keine unique_id. Ohne den Traffic-Teil liefert
  der Stand 1.49.3 dieselben Listen; dort entstehen am Gateway mit Traffic nur die zwei
  Flotten-Sensoren. Je eine geänderte unique_id für Port-, Schnittstellen-, DHCP-Pool-,
  Radio- und AP-Sensor, WLAN-Schalter und Traffic-Sensor macht den Test rot. Nicht
  abgedeckt: WiFi RF, Netzwerkdiagnose, Security Center, Configuration Manager, Network
  Intelligence und Client-Stabilität, Traffic-Client-Sensoren und Traffic an Routern ohne
  WAN, `…_hwmode`-Sensoren, WLAN-Schalter über `network.wireless` und SSH.
- `CLAUDE.md` auf den Stand 1.49.4 gebracht.

### Bekannte Grenzen

- **WAN-Wechsel.** Der Traffic-WAN-Messpunkt hängt am WAN-Gerät des einzelnen Polls.
  Wechselt das WAN-Gerät (Failover mit mwan3, LTE-Ausweichweg, `wan` ↔ `wwan0`), beginnt die
  Summe „WAN gesamt“ neu und springt bei der Rückkehr zurück. Home Assistant kann den
  Rücksprung eines `TOTAL_INCREASING`-Sensors als Verbrauch zählen (aus dem Code abgeleitet,
  nicht in Home Assistant gemessen), und die Übersicht zeigt bis zu 24 Stunden zwei
  WAN-Zeilen. An Routern mit einem festen WAN-Gerät tritt das nicht auf.
- **Uplink-Erkennung.** `trunk_port_map` enthält jeden Host mit ARP- oder FDB-Eintrag, nicht
  nur Router. Traffic hält deshalb jeden LAN-Port mit einem bekannten Host für einen Uplink,
  überspringt kabelgebundene Client-Zuordnungen an diesen Ports, und Access Points bekommen
  meist „Uplink unbekannt“.
- **MAC-Schwärzung in Freitext** (Core, Configuration Manager, Netzwerkdiagnose) trifft selten
  auch anderes: Teile einer ULID, Zahlenfolgen in Bindestrich- oder Doppelpunkt-Form
  (`26-11-21-15-30-00`), `commit abcdef123456`, Teile eines SSH-Fingerprints. Eine MAC direkt
  hinter einem Bindestrich (`esp-a1b2c3d4e5f6`) wird nicht geschwärzt.
- **Nicht an echten Routern geprüft:** ob `network.device status` bei PPPoE oder LTE das
  WAN-Gerät (`pppoe-wan`, `wwan0`) auflistet.

## [1.49.3] - 2026-11-21

Korrekturen aus unabhängigen Prüfungen von WiFi RF, der Folgeliste 1.49.1, Netzwerkdiagnose,
Security Center, Traffic Analytics und Configuration Manager, dazu die Enterprise-Tabs zum ersten Mal in einem
echten Browser angesehen (Firefox, 360 / 768 / 1280 px, helles und dunkles
Home-Assistant-Design, Beispieldaten). Keine neuen Router-Rechte, kein zusätzlicher
Router-Aufruf bei ausgeschalteten Modulen; mit WiFi RF aus macht ein Poll weiter genau die
Router-Aufrufe von 1.47.1 (Hotfix 1.49.2 unverändert). Panel-Version
`20261121-review1`.

### Geändertes Verhalten, das Nutzer bemerken

- **Netzwerkdiagnose: Qualitätswert von Access Points ohne WAN-Messung jetzt „unbekannt“**
  statt 100 (siehe unten). Der Flottenwert stützt sich nur noch auf bewertete Router.
- **Sensor „Aktive Verbindungen“ zeigt „unbekannt“ statt 0**, wenn es keine Zahl gibt
  (Zeitüberschreitung, keine Quelle lesbar), und öfter „unbekannt“ bei Routern ohne
  `nf_conntrack_count`, weil abgeschnittene Tabellen jetzt erkannt werden.
- **Configuration Manager:** bei einer SSH-Zeitüberschreitung ein anderer nächster Schritt.
- **Traffic Analytics:** Bei Polls ohne neue Zählerabfrage bleibt der letzte gültige
  Traffic-Wert stehen, bis er regulär veraltet.

### Behoben

#### WiFi RF

- **Hängende Zusatzabfrage blockierte die übrigen dauerhaft.** Wurde eine Lesung vom
  20-s-Rundenlimit abgebrochen, bekam sie weder Erfolgszeit noch Wartezeit, und der
  Fehlerzähler stieg nicht: `freqlist`/`txpowerlist` wurden bei jedem Poll neu angefragt
  (weder „alle N Polls“ noch 300 s noch Backoff), und weil die Reihenfolge fest war, kam
  ein später Abruf wie `get_status` nie dran (in einer Prüfung 12 Polls lang). Ein Abbruch
  durch das Rundenlimit zählt jetzt als vorübergehender Fehler (Backoff 300 s, 600 s, …,
  höchstens 1 h), auch für die Einrichtungs-Abfragen, und jede Runde beginnt ein Ziel
  später. Betraf Router mit WiFi RF an, deren Antwort auf eine Zusatzabfrage hängt — gerade
  kleine Geräte, die durch die Wiederholung zusätzlich belastet wurden.
- **Start löschte RF-Entitäten eingeschalteter Router.** Die RF-Entitäten werden nach dem
  Setup jedes Eintrags abgeglichen; „an“ kannte dabei nur die bis dahin eingerichteten
  Einträge. War der erste ein Router mit RF aus, entfernte der Abgleich ALLE
  RF-Registry-Einträge, auch die eines danach eingerichteten Routers mit RF an (ebenso beim
  Neuladen eines Eintrags); Bereich, Name und Einstellungen dieser Entitäten gingen
  verloren. Jetzt zählt der Schalter jedes Eintrags der Integration: alles wird nur
  entfernt, wenn RF überall aus ist, sonst nur die Entitäten der Router mit eigenem
  Schalter aus. Netzwerkdiagnose und Security Center haben einen modulweiten Schalter und
  waren nicht betroffen.
- **Kanalauslastung ab `wifi_rf_every_n_polls` ≥ 10 dauerhaft „unbekannt“.** Der erlaubte
  Abstand zweier Messungen war fest 600 s, gelesen wird aber alle `max(300, N × 60 s)` plus
  Pollzeit. Der Abstand folgt jetzt dem tatsächlichen Leseintervall.
- **Retry-Rate je Radio systematisch zu hoch, falsches `rf.retry_high`.** Weil mt76 mit WED
  für alle Clients 0 Retries meldet, galt jede 0 als unbekannt; saubere Clients fielen aus
  dem paketgewichteten Mittel (9 saubere Clients und einer mit 30 % ergaben 30 % statt
  3 %). Hat ein Client desselben Radios im Fenster Retries > 0, zählt der Treiber
  nachweislich, und die 0 der anderen ist eine echte 0 (auch in der Lese-Schnittstelle
  `client_retry_rates`). Nur Nullen bleiben unbekannt. `rf.retry_high` braucht zusätzlich
  mindestens die Hälfte der Clients des Radios gemessen.
- **Lese-Schnittstelle `radio_utilization` stürzte bei `interfaces=None` ab** (TypeError)
  und prüfte bei vielen ungültigen oder doppelten Namen jeden einzelnen. None und
  Nicht-Listen gelten als keine Namen, höchstens 256 Einträge werden angesehen.

#### Netzwerkdiagnose

- **Router ohne WAN-Messung bekam den Qualitätswert 100.** Ohne WAN-Komponente und ohne
  Proben stützte sich der Wert nur auf „0 Neustarts“: 100,0 bei rund 7 % Abdeckung, nur als
  „geringe Aussagekraft“ markiert. Betraf vor allem Access Points (in einer typischen Flotte
  fünf von sechs Routern). Jetzt nach dem Muster des Security Centers: unter 25 %
  Abdeckung kein Wert („unbekannt“), darüber höchstens `50 + 50 × Abdeckung`, unter voller
  Abdeckung höchstens 99. Auch Router mit Teilabdeckung zeigen dadurch etwas niedrigere
  Werte (60 % Abdeckung: höchstens 80).
- **Abgelehnter manueller Lauf verbrauchte einen Platz im Ratenlimit.** Der Guard zählte den
  Lauf schon bei der Freigabe, der Scheduler wurde erst danach gefragt; lehnte er ab (Lauf
  schon in der Warteschlange, eigenes Limit), war der Platz trotzdem weg. Der Scheduler
  antwortet jetzt zuerst.
- **Signal-Empfänger der Entitäten blieb nach dem Ausschalten verbunden.** Er wird jetzt
  getrennt und beim Einschalten neu verbunden.

#### Security Center

- **Zwölfstellige Dezimalzahlen wurden als MAC geschwärzt** (`bytes=123456789012`,
  Telefonnummern, `202611211530`, `2026.1121.1530` wurden zu `<MAC>`). Die Form ohne
  Trennzeichen und die Punkt-Form werden nur noch mit mindestens einem Hex-Buchstaben a–f
  geschwärzt; die Schreibweise mit Leerzeichen (`AA BB CC DD EE FF`) wird jetzt auch
  geschwärzt, außer als Teil eines längeren Hex-Dumps. Folge: eine MAC aus lauter Ziffern
  ohne Trennzeichen (`001122334455`) bleibt in Freitext sichtbar.
- **Traffic-Hinweise konnten die Zeitleiste verdrängen.** Bis zu 20 je Stunde über 14 Tage
  sind 6720 Einträge bei einem Limit von 2000. Traffic-Notizen haben jetzt eine eigene
  Obergrenze von 500 (älteste weicht zuerst) und machen bei vollem Speicher zuerst Platz;
  ein echter Sicherheitseintrag wird nie von einer Traffic-Notiz verdrängt.
- **Erledigte WLAN-Hinweise gingen für nichts verloren.** Mit einem alten Speicherstand mit
  mehr als 50 offenen Nicht-WLAN-Hinweisen in der Klasse „andere“ löschte ein neuer
  WLAN-Hinweis erledigte WLAN-Hinweise, um dann selbst an der vollen Klasse zu scheitern
  (im Test nachgestellt). Alle drei Grenzen werden jetzt zuerst berechnet, gelöscht wird nur,
  wenn der neue Hinweis bleibt.

#### Folgeliste 1.49.1 (aktive Verbindungen)

- **Abgeschnittene conntrack-Tabelle galt oft als vollständig.** rpcd liest procfs mit einem
  `read()` von 4096 Byte, der Kernel liefert nur ganze Zeilen (190–340 Byte), die Antwort
  endet also auf einem Zeilenumbruch und ist oft kürzer als 4000 Byte; in einer Probe galt
  eine abgeschnittene Tabelle in 1170 von 2000 Fällen als vollständig. Jetzt gilt eine
  Antwort ab 3496 Byte (4096 minus angenommene längste Zeile von 600 Byte) als
  abgeschnitten. Betraf Router ohne `/proc/sys/net/netfilter/nf_conntrack_count`.
- **Nach der 5-s-Zeitüberschreitung zeigte der Sensor 0.** Auch wenn keiner der beiden Wege
  lesbar war. Nur eine vollständige Zahl ist jetzt ein Wert, sonst „unbekannt“ (Sensor und
  Network Intelligence).

#### Traffic Analytics

- **Ruft die Integration die Listener ohne neue Abfrage auf (z. B. nach der
  Paket-Update-Prüfung), bleiben die aktuellen Raten erhalten.** Bisher waren WAN-Sensoren
  und Topologie-Werte bis zur nächsten Abfrage leer, im 5-Minuten-Verlauf stand ein falsches
  Qualitätskennzeichen, und Zusatzabfragen liefen außerhalb des Abfragetakts.
- **Der Flow-Speicher vergisst stille Quellen nach der Aufbewahrungszeit und merkt sich
  höchstens 256 Quellen.** Ein Collector darf nur noch Router-IDs geladener Router mit
  eingeschalteter Analyse senden (sonst `unknown_router`). Ein fehlerhafter Collector kann
  den Speicher so nicht mehr unbegrenzt füllen.
- **Router mit mehr als 64 Netzwerkgeräten verlieren den WAN-Zähler nicht mehr.** WAN-Gerät
  und Uplink-Ports werden zuerst übernommen; weggelassene Geräte werden gezählt und als
  Abdeckungsgrund angezeigt.
- **Abgelehnte Collector-Zugriffe haben ein eigenes Meldebudget je Grund und Benutzer.** Ein
  angemeldeter Benutzer, der die Route wiederholt aufruft, kann echte Fehlversuche nicht
  mehr aus dem Security Center verdrängen.
- **Ein doppelt gesendeter Collector-Aufruf (z. B. nach einem Timeout) wird mit der ersten
  Antwort bestätigt und nicht doppelt gezählt.**
- **Nach einem harten Absturz werden Stunden- und Tageswerte nicht mehr doppelt gezählt (bis
  zu 30 Minuten).** Die Verdichtungsmarke steht jetzt auch im groben Speicher; vorhandene
  Dateien bleiben lesbar.
- **Ist der erste Schreibvorgang nach dem Start zu groß, bleibt der gespeicherte
  5-Minuten-Verlauf erhalten, statt geleert zu werden.**
- **Schreibvorgänge über einem Speicherbudget kürzen in einem Durchgang statt in bis zu
  acht.** Die Event-Loop ist dabei rund halb so lang blockiert.

#### Configuration Manager

- **Falscher nächster Schritt.** Eine SSH-Zeitüberschreitung (umfasst Verbindung,
  Archivbau und Übertragung) meldete „SSH (Port 22) nicht erreichbar“, obwohl der Port offen
  war; jetzt „SSH antwortet zu langsam oder das Archiv ist zu groß; später erneut
  versuchen“. Bei einem HTTP-Eintrag empfahl der Schritt „oder das Paket cgi-io
  installieren“, obwohl cgi-io dort ohnehin abgelehnt wird; der Hinweis entfällt dann.

#### Panel

- **Große Byte-Werte als „987.654,3 GB“.** Die Byte-Anzeigen kennen jetzt TB (die
  Archivgröße im Configuration Manager auch GB).
- **Netzwerkdiagnose zeigte die volle Router-ID** (`rtr_aaaa11112222`), die anderen Tabs das
  Kürzel; jetzt „Router aaaa11“ wie dort.
- **Verlauf der Netzwerkdiagnose scrollte bei schmaler Breite** in seinem Rahmen; unter
  560 px Breite wird jede Zeile zur Karte (Container-Query wie im Configuration Manager).
- **Traffic Analytics, Router: weggelassene Netzwerkgeräte waren nicht zu sehen.** Die
  Router-Zeile nennt jetzt „Mehr als 64 Netzwerkgeräte: N nicht gemessen“ (neues Feld
  `devices_omitted` der Übersicht), der Abdeckungsgrund `devices_omitted_over_cap` hat einen
  deutschen Text, und „Verworfen“ zählt auch verdrängte Flow-Quellen (`dropped_feeds`).

#### Darstellung (Browser-Prüfung)

- **Configuration Manager: Router- und Versionsliste liefen bei 768 und 1024 px aus dem
  Bild.** Die Tabellen brauchen 718 bzw. 824 px, wurden aber erst unter 600 px zu Karten;
  dazwischen waren die Schaltflächen „Prüfen“, „Export“, „Wiederherstellen …“ abgeschnitten
  und die Seite scrollte seitlich. Karten jetzt bis 840 px Listenbreite.
- **Helles Home-Assistant-Design: helle Auswahlfelder, Häkchen und Optionsfelder im dunklen
  Panel.** Das Panel ist immer dunkel und sagt das dem Browser jetzt (`color-scheme: dark`);
  betrifft die Einstellungen von Traffic Analytics, Netzwerkdiagnose und Security Center.
  Das Auswahlfeld „Benutzer des Collectors“ ist gestaltet wie die übrigen.
- **Traffic Analytics, Verlauf: Werte brachen mitten in der Zahl um** („40,0 / GB“) ab
  600 px Breite; der Wert bleibt jetzt ganz und rutscht bei Bedarf unter die Bezeichnung.
- **Traffic Analytics, Anomalien: beobachteter, üblicher Wert und Schwelle ohne Einheit**
  („90.000.000“). Jetzt in Mbit/s, bei Datenmengen-Kandidaten in Bytes; unbekannte Arten
  bleiben eine bloße Zahl.
- **Traffic Analytics, Kapazität: die Schwelle eines Befunds ohne Einheit** („Schwelle 80,0“
  neben „92,5 %“). Jetzt mit derselben Einheit wie der Wert.
- **Diagramme: die Skala reicht vom niedrigsten bis zum höchsten Wert, beschriftet war nur
  das obere Ende** (Traffic-Verlauf) bzw. stand „min.“ oben rechts neben dem höchsten Punkt
  (WiFi RF-Zeitverlauf). „niedrigster Wert“ / „min.“ steht jetzt unter der Linie.
- **Lesbarkeit: Bezeichnungen in den Enterprise-Tabs** (z. B. „Download jetzt“, Tabellenköpfe)
  hatten etwa 2,5:1 Kontrast; jetzt etwa 5:1.
- **Enterprise-Untertabs auf dem Handy 31 px hoch**; jetzt 40 px wie die übrigen Schaltflächen.

## [1.49.2] - 2026-11-21

Dringende Korrektur: Seit 1.48.0 hatten die WLAN-Schalter eine andere unique_id. Keine neuen
Router-Rechte.

### Behoben

- **WLAN-Schalter verdoppelt seit 1.48.0.** 1.48.0 fragte in `get_wifi_status` `iwinfo info`
  je Gerät (`iwinfo devices` und dann jedes Gerät) statt wie vorher `iwinfo info {}`. Den
  alten Aufruf lehnt rpcd ab („Invalid argument“), deshalb las die Integration die WLANs
  bis 1.47.1 aus der UCI-Konfiguration. Der neue Aufruf gelang, und die WLANs kamen ohne
  UCI-Sektion. Dadurch bekam jeder WLAN-Schalter statt `<entry_id>_wifi_ssid_<UCI-Sektion>`
  (z. B. `…_lan_5g`) die unique_id `<entry_id>_wifi_ssid_<Schnittstelle>` (z. B.
  `…_phy1-ap0`). Home Assistant legte beim ersten Start mit 1.48.0 neue Schalter neben die
  alten (z. B. `switch.…_5_ghz_2`, teils mit anderem Namen); die alten wurden
  „nicht verfügbar“. Außerdem zeigten die neuen Schalter immer „an“ (auch abgeschaltete
  WLANs fehlten), STA-Schnittstellen (Uplink) erschienen als Schalter, es entstanden neue
  Rauschen/Signal-Sensoren je Schnittstelle (`…_radio_<Schnittstelle>_noise|signal`), und
  jeder Poll machte 1 + N zusätzliche iwinfo-Aufrufe. Betroffen sind Router, deren WLANs bis
  1.47.1 aus der UCI-Konfiguration gelesen wurden (Schalter-unique_id mit UCI-Sektion);
  beobachtet auf OpenWrt 25.12.
  - 1.49.2 macht wieder den Aufruf von 1.47.1. Die Schalter haben wieder ihre alten
    unique_ids; die alten Einträge mit Bereich, Namen und Einstellungen werden wieder
    benutzt, Zustand und Schalten (welche UCI-Sektion) sind wie in 1.47.1.
  - Mit WiFi RF aus macht ein Poll wieder genau die Router-Aufrufe von 1.47.1 (Test
    vergleicht die vollständige Aufrufliste mit der von 1.47.1). Die Aussage im Abschnitt
    1.48.0, ohne den Schalter mache ein Poll „exakt dieselben Router-Aufrufe wie vorher“,
    stimmte nicht: der Test dort verglich nur RF an mit RF aus, nicht mit 1.47.1, und lief
    gegen ein Router-Modell, das `iwinfo info {}` beantwortet.
  - Mit WiFi RF an liest nur die Uplink-Erkennung (STA) iwinfo je Gerät wie in 1.48.0
    (Uplink mit eigener MAC); die Schalter sind auch dann die alten.
  - **Aufräumen:** Beim Start entfernt 1.49.2 einmalig die unter 1.48.0–1.49.1 neu
    angelegten Doppelten (Schalter und Rauschen/Signal-Sensoren mit Schnittstellennamen
    wie `phy1-ap0`, `wlan0` als Schlüssel). Nur Einträge dieses Routers und dieser
    Integration, nur wenn der WLAN-Abruf beim Start gelang und alle WLANs eine UCI-Sektion
    haben, nur wenn der Original-Schalter noch existiert, nie ein Eintrag, dessen Schlüssel
    eine UCI-Sektion oder Schnittstelle des Routers ist, und nur Einträge, die am oder nach
    dem 21.11.2026 angelegt wurden. Router, deren Schalter schon vor 1.48.0 einen
    Schnittstellennamen als Schlüssel hatten, bleiben unberührt. Im Log steht auf INFO,
    wie viele Einträge entfernt wurden.
  - **Bitte selbst prüfen:** Automationen, Skripte und Dashboards, die in der Zwischenzeit
    auf die neuen Schalter (meist mit `_2` am Ende) umgestellt wurden, zeigen nach dem
    Update ins Leere und müssen zurück auf die alten entity_ids. Wurde ein alter Schalter
    gelöscht, bleibt sein Doppelter stehen (nicht verfügbar) und kann von Hand gelöscht
    werden.

## [1.49.1] - 2026-11-21

Folgeaufträge zu den Enterprise-Paketen: Schnittstellen zwischen WiFi RF, Traffic Analytics
und Security Center, ein begrenzter conntrack-Ersatzweg, `npm ci` und MAC-Schwärzung.
Keine neuen Router-Aufrufe, keine neuen Router-Rechte.

### Hinzugefügt

- **WiFi RF: Leseschnittstelle für andere Module (Wunsch W6).**
  `RfCenter.radio_utilization(router_id, window_s, interfaces=())` und
  `RfCenter.client_retry_rates(router_id, window_s)` lesen nur die letzte Auswertung (kein
  Router-Aufruf). Radio-Kennung ist Router-ID + UCI-Radioname, Clients nur als
  `client_ref`; jeder Wert trägt `measured_at`, Unbekanntes ist `None` mit Grund. Wer
  AP-Schnittstellennamen schon kennt, bekommt je Radio nur die eigenen davon zurück.
  Traffic Analytics liest WiFi RF nur noch darüber und nennt im Engpass-Befund je Radio
  Airtime, Wiederholungen und die zugehörigen Stations-Messpunkte.
- **Security Center nimmt Traffic-Hinweise an (Wunsch W2).** `traffic_analytics.indicator`
  wird streng geprüft und als Zeitleisten-Eintrag mit `evidence_ref` gespeichert, höchstens
  20 je Stunde, jede Referenz einmal. Nie allein ein Vorfall, kein Vertrauensindikator
  (verschiedene Pseudonyme, W3). Traffic zeigt den Zustand der Anbindung jetzt ehrlich
  („bereit“, „aus“ oder „nicht geladen“) statt fest „nicht angebunden“.

### Behoben

- **conntrack-Ersatzweg begrenzt (Traffic F2, Risiko 3).** Ohne Zähldatei las
  `get_active_connections` die ganze Tabelle `/proc/net/nf_conntrack` ohne Grenze. Jetzt
  höchstens 5 s, 256 KiB und 2048 Einträge; ein abgeschnittenes Ergebnis ist als Untergrenze
  markiert. Der Sensor „Aktive Verbindungen“ und Network Intelligence werten einen solchen
  Wert als unbekannt statt als zu kleine Zahl.
- **Security Center: MAC-Adressen in Freitext** als 12 Hex-Ziffern oder in Punktform blieben
  lesbar, auch direkt an einem Unterstrich. Jetzt werden alle vier Schreibweisen geschwärzt
  (wie in WiFi RF, dort bestand die Lücke nicht).
- **Panel: `npm ci` läuft wieder.** `vite-plugin-css-injected-by-js` zurück auf 4.0.1 (5.0.0
  verlangt vite 8). Das gebaute Bundle ist unverändert.
- Tests: Das Testarchiv der Wiederherstellungsprüfung ist jetzt bytegleich über mehrere
  Aufrufe (fester gzip-Zeitstempel); ein CI-Lauf war daran einmal gescheitert.

## [1.49.0] - 2026-11-21

Traffic Analytics: Verkehr je Router über WAN, Ports, Schnittstellen, VLANs und WLAN-Clients,
mit Verlauf, Top Talkers, Auffälligkeiten, Kapazität und optionalen Flows eines externen
Collectors. Baut auf dem Enterprise Core von 1.44.0 auf. **Standardmäßig aus, je Router**;
ohne den Schalter macht ein Poll exakt dieselben Router-Aufrufe wie vorher (Test vergleicht
die ubus-Aufrufe ohne Modul, mit Modul aus und mit Modul an). **Keine Paketanalyse, keine
neuen Router-Rechte, Clients nur als Pseudonym.** Nutzerdoku: `docs/traffic-analytics.md`.

### Hinzugefügt

- **Traffic Analytics (Teile B–I: Backend).** Zählerverarbeitung mit Lücken-, Neustart-
  und 32-Bit-Überlauferkennung, Messbereiche mit Abdeckung je Messpunkt (`full`, `partial`,
  `estimated`, `unavailable`, `unknown`) und Schutz gegen Doppelzählung, Zuordnung der
  WLAN-Clients samt Roaming, VLAN-Sicht, Top Talkers, Flow-Speicher nur im Arbeitsspeicher
  (höchstens 2000), Auffälligkeiten mit robusten Baselines, Kapazität mit P95 und
  vorsichtigen Trends, Korrelation und Sicherheitshinweise als Kern-Ereignisse. Verlauf in
  zwei begrenzten Speicherdateien (`traffic_fine`, `traffic_coarse`, je höchstens 2 MiB).
  Drei optionale Zusatzabfragen mit eigenem Schalter, alle aus und begrenzt:
  `iwinfo assoclist` und sysfs-Zähler höchstens alle 5 Minuten, `uci get firewall`
  (Flow-Offloading) alle 6 Stunden. Alle nutzen vorhandene Rechte; fehlt eines, meldet
  die Analyse `permission_denied` und misst ohne diese Abfrage weiter.
- **Traffic Analytics (Teil J: Dashboard und Topologie).** Nur lesende Routen unter
  `/api/openwrt_topology/traffic/`: `overview`, `points`, `series?point_id=…&window=1h|24h|7d|30d|90d`
  (höchstens 500 Werte), `talkers`, `clients`, `vlans`, `capacity`, `anomalies`,
  `recommendations`, `evidence/{ref}` sowie für Administratoren `flows` und `settings`.
  Rechte und Fehler wie bei WiFi RF und der Netzwerkdiagnose (Anmeldung nötig;
  Administratoren, andere Benutzer nur bei freigegebenem Topologie-Panel). Ist das Modul
  aus, antwortet jede Route `status: off` ohne Router-Aufruf und ohne Zugriff auf den
  Verlauf. Nur Pseudonyme, keine MAC-Adressen und keine Gerätenamen.
- **Enterprise-Tab „Traffic Analytics“** mit Übersicht, Verlauf, Top Talkers,
  Clients & VLANs, Anomalien, Kapazität (mit möglichen Engpässen) und für Administratoren
  Flows. Lädt nur, solange der Tab sichtbar ist, höchstens alle 60 s. Unbekanntes steht als
  „—“ mit Grund da, nie als 0; Datenqualität und Gründe nicht liefernder Quellen
  (z. B. WiFi RF, Security Center) sind sichtbar. Tageswerte sind UTC-Tage und werden in
  Ortszeit beschriftet. Der Hinweis bei ausgeschaltetem Modul nennt jetzt den Schalter.
- **Topologie:** Läuft Traffic Analytics, tragen Router-Knoten WAN- und Port-Raten samt
  Auslastung und Abdeckung, Router-Uplinks die gemessene Port-Rate beider Seiten. Ist das
  Modul aus, bleibt der Topologie-Snapshot unverändert.
- **Traffic Analytics (Teil K): Schalter je Router.** In den Router-Optionen
  (Konfigurieren) `traffic_enabled`, standardmäßig aus, dazu die Zusatzabfragen
  `traffic_station_detail`, `traffic_sysfs_fallback`, `traffic_offload_probe` (je einzeln,
  aus) und das Verlaufsprofil `traffic_history_profile` (`compact` vorgegeben, `standard`
  wählbar; es gilt das tiefste Profil der eingeschalteten Router). Wirkt sofort, ohne
  Neuladen; die übrigen Optionen bleiben erhalten. Solange kein Router eingeschaltet ist,
  gibt es keinen Router-Aufruf, keinen Speicherzugriff und keine Entität.
- **Traffic-Sensoren (Teil K).** Je Gateway WAN-Download- und -Upload-Rate, WAN-Verkehr
  gesamt und WAN-Spitzenbandbreite (24 h, aus 5-Minuten-Werten); je Router am Uplink die
  Auslastung (nur mit bekannter Link-Geschwindigkeit) sowie Empfangs- und Sendefehler
  (Diagnose, standardmäßig deaktiviert); für die Flotte aktive Traffic-Auffälligkeiten und
  die Abdeckung der Messung. Optional bis zu 20 Client-Sensoren „WLAN-Verkehr am AP“, nur
  für ausgewählte Clients. Unbekanntes ist „unbekannt“, nie 0. Ausschalten entfernt die
  Traffic-Entitäten des Routers aus der Registry, der Verlauf bleibt.
- **Traffic-Einstellungen schreiben (Teil K):** `POST …/traffic/settings`, nur für
  Administratoren und nur bei laufendem Modul, für den Flow-Collector und die
  Client-Sensoren. Strenge Prüfung, ungültige Eingaben ändern nichts.
- **Optionale Collector-Schnittstelle (Teil K):** `POST …/traffic/collector/ingest`, Schema
  `traffic.collector.v1`, standardmäßig aus. Nur der eingetragene Home-Assistant-Benutzer
  ohne Administratorrechte mit Long-Lived-Token und nur über HTTPS; höchstens 256 KiB,
  500 Einträge und ein Aufruf je 10 s. Ein ungültiger oder zu großer Aufruf wird ganz
  abgelehnt und gezählt, nie teilweise übernommen. Der Flows-Bereich zeigt die
  Collector-Daten, sonst weiter den ehrlichen Hinweis.
- **Diagnose:** Block `traffic_analytics` mit Schalter, Zählern, Speichergrößen und
  Capability-Zuständen; keine MAC, IP, Client-Kennung oder Collector-Benutzer.
- **Einstellungen im Tab „Traffic Analytics“ (Teil L, nur Administratoren).** Zeigt je
  Router, ob die Analyse läuft und mit welchem Profil (geändert wird weiter in den
  Integrationsoptionen). Schaltet den Collector-Eingang, wählt seinen Benutzer und bis zu
  20 Clients für Client-Sensoren. Gesendet werden nur geänderte Werte; „Gespeichert.“
  erscheint erst nach der Antwort von Home Assistant, eine Ablehnung nennt den Grund.
- **Route `GET …/traffic/collector/users`** (nur Administratoren): wählbare Benutzer für den
  Collector (aktiv, kein Admin, nicht vom System angelegt) mit Anzeigename und einer
  Referenz `usr_…`, die bei jedem Start neu verschlüsselt ist. `POST …/traffic/settings`
  nimmt `collector.user_ref`; keine Route gibt eine Benutzer-ID heraus.
- **Leistungs- und Qualitätstests (Teil L):** Router-Aufrufe je Abfrage, Zeit je Abfrage und
  Flottenrunde, Spitzensensor, Flow-Speicher bei 2000 Einträgen, Collector-Aufruf mit 500
  Flows, Zeit und Größe jeder Leseroute, Speicherwachstum über 10 Stunden; kein Lambda am
  Dispatcher; keine MAC, IP, AP-Schnittstelle, Benutzer-ID oder Token im Log auf DEBUG-Stufe.
  Die gemessenen Zahlen stehen in der Nutzerdoku.

### Behoben

Betraf nur den unveröffentlichten Stand im Branch:

- Verlauf im Profil „standard“ hielt Stundenwerte der Infrastruktur nur 7 statt 14 Tage.
  Die Grenzen gelten jetzt je Profil und Speicherdatei; jede Datei bleibt unter 2 MiB.
- Der frühere flottenweite Schalter im Speicher wird nicht mehr gelesen; es zählt nur noch
  die Router-Option `traffic_enabled`.
- Die Route `series` überschrieb den Status und die Gründe des Moduls mit denen des
  Zeitfensters (z. B. zeigte `not_ready` Gründe des Verlaufs); die stehen jetzt in
  `window_reasons`.
- Die Anbindungen an WiFi RF und die Netzwerkdiagnose passen zu deren Schnittstellen in
  1.48.0.

### Bekannte Grenzen

- Nicht an echten Routern geprüft: Zähler bei Hardware-Offload, DSA-Port-Zähler und das
  Verhalten der hostapd-Stationszähler sind Annahmen; bis zur Messung steht die Abdeckung
  dort auf `partial`.
- Der Tab ist nicht in einem echten Browser und nicht bei 360 px Breite angesehen worden.
- Collector-Aggregate (`client_aggregate`, `interface_aggregate`) werden mit
  `kind_not_supported` abgelehnt; der Collector liefert nur Flows.
- Client-Zähler am Access Point sind kein Internetverbrauch.
- Auffälligkeiten werden keine Vorfälle in Network Intelligence, und das Security Center
  wertet die Traffic-Hinweise noch nicht aus (fehlende Schnittstellen dort).
- Dieselbe MAC ergibt in Traffic Analytics und Security Center verschiedene Pseudonyme.
- Funk-Messpunkte tragen noch den Schnittstellennamen als Kennung, nicht die Radio-ID von
  WiFi RF.
- Der conntrack-Ersatzweg von `get_active_connections` liest weiter ohne Obergrenze
  (unverändert, außerhalb dieses Moduls).

## [1.48.0] - 2026-11-21

WiFi RF Intelligence: Funkbild je Radio (Kanalauslastung, Grundrauschen, Retry-Rate, Signal je
Client, Kanalkonflikte, Roaming, Kanalempfehlungen) aus den vorhandenen Poll-Daten und
optionalen, begrenzten Zusatzabfragen. Baut auf dem Enterprise Core von 1.44.0 auf.
**Standardmäßig aus**; ohne den Schalter macht ein Poll exakt dieselben Router-Aufrufe wie
vorher. **Kein Scan, keine neuen Router-Rechte, nur lesende Routen.**

### Hinzugefügt

- **WiFi RF Intelligence (Teil 1: Backend).** Funkbild je Radio aus den
  vorhandenen Poll-Daten (Rauschen, Sendeleistung, Kanalbreite, Signal je Client,
  Airtime) und optionalen Zusatzabfragen. **Alles ist standardmäßig aus**: Ohne den Schalter
  `wifi_rf_enabled` (je Router in den Optionen) macht ein Poll exakt dieselben Router-Aufrufe
  wie vorher (Test zählt die ubus-Aufrufe mit RF an und aus).
  - Zusatzabfragen, je ein eigener Schalter, alle aus und alle begrenzt (alle N Polls,
    Standard 5, mindestens 300 s je Router und Radio, eine Abfrage je Art zur Zeit,
    Zeitlimit je Runde): `hostapd get_status` (Kanalauslastung aus der Differenz der
    Zähler `airtime.time`/`time_busy`, nicht aus dem Byte `utilization`), `iwinfo assoclist`
    (Retry-Rate aus der Zählerdifferenz), `iwinfo freqlist`/`txpowerlist` (nur bei Start und
    nach Kanal- oder Länderwechsel) und `iwinfo survey`; `txpowerlist` und `survey` nur mit
    der passenden Core-Fähigkeit. Last bei 5 Polls: etwa
    +11 % WLAN-Aufrufe (get_status und assoclist zusammen, rund 15 B/s je Router); Survey
    weitere +14 %. Auf dem FRITZ!WLAN Repeater 1750E (54 MB RAM) kann ein ath10k-Survey bis
    3 s dauern — dort Survey aus lassen.
  - Keine neuen ACL-Rechte: Ein fehlendes Recht heißt „nicht unterstützt“ mit Grund, nie ein
    Poll-Fehler. Kein Scan (bleibt „nicht unterstützt“).
  - Nur lesende Routen unter `/api/openwrt_router/enterprise/wifi/`: `overview`, `radios`,
    `channel_map`, `timeline?window=1h|24h|7d|30d`, `roaming`, `recommendations`. Anmeldung
    nötig; Administratoren (Nicht-Admins nur bei freigegebenem Topologie-Panel, ohne
    Roaming-Verlauf); der Roaming-Verlauf einmal je Panel-Sitzung über den Core-Guard.
    RF aus oder nicht bereit ergibt Status `off`/`not_ready`, nie einen Fehler.
  - Ohne Modulschlüssel, Router-ID oder Quelle: „nicht bereit“, keine Bewertung und kein
    „alles gut“. Unbekannte Werte bleiben unbekannt, nie 0. Ein voller Kanal ist nur ein
    Hinweis.
  - Ereignisse im allgemeinen Core-Ring nur bei Änderung (gemessene Kanalkonflikte, anhaltend
    hohe Auslastung, neue/erledigte Empfehlungen; die erste Auswertung nach dem Start ist
    die Basis). `router.forgotten` löscht alle RF-Daten des Routers; Entladen schreibt den
    Verlauf sofort.
  - Diagnose: neuer Block `wifi_rf` (nur Zähler, Zustände und Gründe, maskiert).
- **WiFi RF Intelligence (Teil 2: Anbindung).** Mit RF aus ändert sich nichts
  (Tests vergleichen Befunde, Reparaturhinweise, Vorfälle, Scores und Entitäten mit RF an
  und aus).
  - Kanalplan: Eine Überlappung zweier Router-Radios im selben Kanal bleibt ein Befund. Sie
    wird nur dann zum Hinweis herabgestuft (kein Reparaturhinweis), wenn RF auf beiden Radios
    eine niedrige Auslastung **gemessen** hat und keinen Konflikt sieht. Unbekannt,
    nicht bereit, nicht überwacht oder ausgelastet: der Befund bleibt, wie er war.
    Attribut `rf_status` mit Grund und Messwerten.
  - Network Intelligence: gemessene Kanalkonflikte, anhaltend hohe Auslastung und hohe
    Retry-Rate gehen als reine WLAN-Ereignisse (`rf.channel_conflict`, `rf.channel_busy`,
    `rf.retry_high`) über die vorhandene Befundquelle ein. Sie öffnen, unterdrücken oder
    entschuldigen keinen Vorfall und ändern keinen Score. Sie kommen nur bei einer Änderung,
    höchstens 6 je Poll, derselbe Befund erst nach einer Stunde wieder. Keine Änderung in `net_*`.
  - Client Stability: RF liest den vorhandenen Client-Verlauf (Disconnects, mittlere
    TX-Rate) für die RF-Client-Bewertung; die zusätzliche Quelle senkt nie eine Bewertung
    (Eigenschaftstest). Die Client-Ansicht
    bekommt einen reinen Hinweis `rf_hint` (Radio stark ausgelastet um den Zeitpunkt). Der
    Client-Stability-Score bleibt unverändert.
  - Entitäten (nur mit RF an und nur auf vorhandenen Router-Geräten, RF aus: nicht angelegt
    und aus der Registry entfernt): WLAN-Gesundheit, aktive Roaming-Probleme und
    Kanalempfehlungen (alle Router), AP-Funkgesundheit je Router, Kanalauslastung (%),
    Grundrauschen (dBm) und Retry-Rate (%) je Radio, höchstens 4 Radios je Router.
    Unbekannt bleibt „unbekannt“, nie 0. Attribute ohne MAC, SSID oder BSSID und nicht
    aufgezeichnet. Keine eigene Airtime-Entität (derselbe Zähler wie die Kanalauslastung).
    Ein Fehler darin lässt das Setup nie scheitern.
- **WiFi RF Intelligence (Teil 3: Panel).** Neuer Tab „WiFi Intelligence“ unter Enterprise
  (nach „Konfiguration“, „Security Center“ und „Netzwerkdiagnose“) mit sechs Ansichten:
  Übersicht, Radios, Kanalkarte, RF-Verlauf (einfaches SVG, Fenster 1 h / 24 h / 7 d / 30 d),
  Roaming und Empfehlungen. Der Tab liest nur über die Routen aus Teil 1 (nur GET, keine
  Schalt- oder Übernehmen-Knöpfe) und fragt höchstens alle 60 s ab, und nur solange er
  sichtbar ist. Unbekannte Werte erscheinen als „—“, nie als 0. Der Roaming-Verlauf je Client
  ist nur für Administratoren und erst nach einer Freigabe je Sitzung sichtbar. Das
  Frontend-Bundle ist neu gebaut (Panel-Version `20261121-wifi-rf1`).

### Behoben

- **WiFi RF: Entitäten von Routern, deren Gerät erst nach dem Setup erscheint, werden angelegt.**
  Der Empfänger des Signals `openwrt_router_wifi_rf_updated` war, wie in 1.47.1 bei der
  Netzwerkdiagnose, eine Lambda ohne `@callback` und lief deshalb in einem Worker-Thread, wo
  `hass.async_create_task` scheitert; der Merker „Abgleich läuft“ blieb dann gesetzt. Der
  Empfänger ist jetzt eine `@callback`-Funktion; kann die Aufgabe nicht starten, wird der
  Merker zurückgesetzt. Der Fehler betraf nur den unveröffentlichten Stand dieses Pakets.
- Tests: `tests/test_wifi_rf_dispatcher_thread.py` schickt das Signal durch den echten
  Dispatcher von Home Assistant und prüft Thread, angelegte Entitäten und Merker.

### Bekannte Grenzen

- **Kein Scan.** Nachbarnetze und fremde Kanäle bleiben „nicht unterstützt“; die
  Scan-Prüfungen S1–S5 des Plans (`docs/plans/2026-11-17-wifi-rf.md`, Abschnitt 7.2) sind
  nicht ausgeführt.
- **Nicht an echten Geräten geprüft.** Die Router-Antworten der Tests haben die Feldstruktur aus
  den lesenden Prüfungen vom 2026-11-18, aber erfundene Werte; die fertige Integration lief
  weder gegen echte Router noch in einer echten Home-Assistant-Instanz.
- **Der Tab ist nicht im Browser angesehen**, auch nicht bei 360 px Breite; geprüft sind nur
  Logik- und Render-Tests ohne Browser.
- **Schwellen sind begründete Annahmen**, nicht an echten Daten abgestimmt.

## [1.47.1] - 2026-11-21

### Behoben

- **Netzwerkdiagnose: Gateway-Sensoren von Routern, die ihre ID erst nach dem Setup bekommen,
  werden wieder angelegt.** Der Empfänger des Signals `openwrt_router_net_diagnostics_updated`
  war eine Lambda ohne `@callback`; Home Assistant führte ihn deshalb in einem Worker-Thread
  aus. Dort rief er `hass.async_create_task` auf, was nach einem HA-Neustart einmal als ERROR
  im Log stand („calls hass.async_create_task from a thread other than the event loop“). Der
  Sensor fehlte dann, und weil der Merker „Abgleich läuft“ gesetzt blieb, versuchte es auch
  kein späteres Signal mehr. Der Empfänger ist jetzt eine `@callback`-Funktion und läuft in der
  Ereignisschleife; kann die Aufgabe nicht starten, wird der Merker zurückgesetzt, sodass das
  nächste Signal es erneut versucht.
- Tests: `tests/test_diag_dispatcher_thread.py` schickt das Signal durch den echten Dispatcher
  von Home Assistant und prüft Thread, angelegten Sensor und Merker.

## [1.47.0] - 2026-11-21

Netzwerkdiagnose („Network Diagnostics“): prüft die Kette Router → Gateway → WAN → Internet →
DNS und sagt je Glied, ob es gesund, beeinträchtigt, ausgefallen oder **unbekannt** ist. Sie
baut auf dem Enterprise Core von 1.44.0 auf und nutzt Daten, die die Integration ohnehin liest,
dazu Messungen von Home Assistant aus gegen Ziele, die ein Administrator bestätigt hat.
**Standardmäßig aus**; ausgeschaltet gibt es keinen Beobachter, keine Messung, keinen Socket und
keine Schreibvorgänge. **Kein zusätzlicher Router-Aufruf je Poll** in dieser Version. Jede
aktive Diagnose läuft erst nach einer ausdrücklichen Handlung eines Administrators (manueller
Lauf oder eingeschaltete regelmäßige Messung mit bestätigten Zielen). **Keine neuen
Router-Rechte.** Nutzerdoku: `docs/network-diagnostics.md`.

### Hinzugefügt

- **Laufzeit (`diag_runtime.py`).** Ein Modul je HA-Instanz, angedockt wie das Security Center
  (nach dem Setup eines Eintrags, nach dem Entladen freigegeben; ein Fehler darin lässt weder
  Setup noch Entladen scheitern). Zustand `off` / `not_ready` / `ready`; `not_ready` und
  unbekannte Werte tragen immer einen Grund (zum Beispiel `module_key_missing`,
  `core_unavailable`, `interface_dump_missing`, `no_confirmed_target`), nie „gesund“. Der
  passive Teil wertet je Poll die Daten aus, die der Poll ohnehin lieferte: den WAN-Status und
  neue, nur gelesene Fakten aus dem schon vorhandenen `network.interface dump` (Standardroute,
  nächster Hop, DNS-Server, aktive Schnittstellen). Der Dump wird dafür **nicht** noch einmal
  geholt.
- **Messungen von Home Assistant (`api.py`, Block „Network Diagnostics“).** TCP-Verbindung,
  DNS-Abfrage (A) und HTTP-Abruf einer „no content“-URL, nur gegen **vom Administrator
  eingerichtete Ziele und nur per ID**: externe Ziele müssen bestätigt sein, interne müssen in
  einem konfigurierten internen Netz liegen, die regelmäßige Messung nimmt nur bestätigte Ziele.
  Es gibt keine Funktion, die einen freien Host annimmt. Schutz vor SSRF
  (`diag_targets.py`): nur IP-Literale und Hostnamen nach RFC 1123 (keine URLs, Ports, Zahlen-
  tricks), externe Ziele müssen global routbar und bestätigt sein, interne Ziele müssen in einem
  konfigurierten internen Netz liegen, Loopback nie, Link-Local und Metadaten-Adressen nur bei
  genau dafür konfiguriertem Netz; was ein Hostname auflöst, wird vor dem Verbinden erneut
  geprüft (Schutz vor DNS-Rebinding), interne Namen gehen nie an einen externen Namensserver;
  der HTTP-Abruf sendet keine Zugangsdaten, keine Cookies, keinen Body und folgt keiner
  Weiterleitung. Jede Messung hat eine feste Zeitgrenze und liefert ein normiertes Ergebnis mit
  Codes und Zahlen, nie mit Adresse oder Antworttext. Ein ICMP-Ziel wird auf der HA-Seite
  übersprungen (kein Ping ohne Rechte).
- **Kette und Zustände (`diag_chain.py`, `diag_model.py`).** Je Glied und Adressfamilie
  `Healthy` / `Degraded` / `Failed` / `Unknown` / `NotApplicable`. „Kein Fehler erkannt“ gibt es
  nur, wenn jedes anwendbare Glied direkt gemessen wurde; sonst „teilweise gemessen“ mit der
  Liste der unbekannten Glieder. Das Internet-Glied fällt nur aus, wenn mindestens zwei
  verschiedene Referenzziele in derselben Runde hart scheitern; ein einzelnes scheiterndes Ziel
  ist höchstens beeinträchtigt. Eine Messung von Home Assistant gilt nur dann als indirekter
  Beleg für einen Router, wenn sie ausdrücklich diesen Router nennt; sie bestätigt nie eine
  Ursache und zählt nie als Abdeckung.
- **Ursachenklassen (`diag_causes.py`).** `confirmed` / `probable` / `possible` / `unknown`.
  Bestätigt braucht eine direkte Messung am Ort der Ursache; dieselbe Auffälligkeit an mehreren
  Routern ergibt höchstens `probable`. Gemeinsame Ursachen (zentraler Internetzugang, Pfad eines
  Segments, gemeinsamer Namensserver) verknüpfen nur Router, die technisch davon abhängen, und
  nur Befunde desselben Glieds und derselben Adressfamilie. Verknüpfungen verbergen oder ändern
  keinen Befund.
- **Statistik, Baselines, Wert (`diag_stats.py`, `diag_baseline.py`, `diag_score.py`).**
  Mittel, Jitter, Verlust und Abdeckung je Reihe in den Fenstern 1 h, 24 h, 7 d und 30 d;
  Lücken (keine Messung, Neustart, WAN-Ausfall während ein Router anläuft) fließen nie als
  Verlust ein; eine Antwort (REFUSED, SERVFAIL, HTTP außer 204) ist kein Verlust. Baselines (EWMA mit
  Hysterese) lernen nur Werte unterhalb der Austrittsschwelle und frieren bei einer Störung
  ein; langsame Drift über mehrere Tage wird getrennt erkannt. Netzqualitätswert 0 bis 100 aus sieben
  gewichteten Komponenten **mit Abdeckung und „geringe Aussagekraft“**; Komponenten ohne Daten
  gelten als unbekannt und nie als perfekt, ein Netz ohne Daten hat keinen Wert.
- **Begrenzter Verlaufsspeicher (`diag_store.py`).** `.storage/openwrt_router.net_diagnostics`,
  verzögertes Schreiben, beim Entladen sofort. Eigene Quoten: höchstens 64 Router-Messpunkte,
  32 Reihen für Home Assistant, 8 Reihen je Router, 169 Stunden- und 31 Tages-Buckets je
  Reihe, 64 Neustart-Lücken. Jede Quote ist getrennt: ein voller Messpunkt verdrängt keinen
  anderen. **Jedes Verwerfen wird gezählt** und im Status gezeigt. Ein Neustart von Home
  Assistant oder eines Routers ist eine Lücke, kein Verlust. Reihen ohne Buckets und Reihen
  entfernter Ziele geben ihren Quotenplatz frei (gezählt). Beschädigte Teile starten leer,
  ein unlesbarer Speicher bleibt als `.bak`.
- **HTTP-Routen (`diag_views.py`)** unter `/api/openwrt_topology/diagnostics`: `overview`,
  `history`, `details`, `settings` (lesen und ändern) und `run`. Alle mit Anmeldung. Reihenfolge
  der Prüfungen: Benutzer und Administrator, dann Panel-Zugriff, dann geladene Integration,
  dann laufendes Modul, dann (nur `run`) eingeschaltetes Modul, **erst danach Query und Body**.
  Einstellungen ändern und `run` nur für Administratoren, `run` zusätzlich über den Guard des
  Cores (aktive Aktion, Rate-Limit, Audit). Body höchstens 8 KiB und höchstens Tiefe 3, nur
  bekannte Schlüssel; Ziele nur über ihre ID. Fehler tragen nur eine feste Meldung, einen Code
  und höchstens Feldname und Grund: 400 ungültig, 403 nicht erlaubt, 404 unbekanntes Ziel oder
  unbekannter Router, 409 aus / belegt / Konflikt, 410 Integration entladen, 413 Body zu groß,
  422 Ziel abgelehnt, 429 Rate-Limit (mit `Retry-After`), 503 Modul oder Core läuft nicht.
- **Entitäten (`diag_entities.py`).** Sechs Flotten-Sensoren (Netzqualität, Überwachungs-
  abdeckung, aktive Befunde, Home-Assistant-Internet-Latenz, -Verlust (24 h), DNS-Antwortzeit)
  und je Router, der schon ein Gerät hat, ein Binärsensor „Gateway erreichbar“; höchstens
  6 + N Entitäten, nie eine je Ziel. Es gibt sie nur bei eingeschaltetem Modul; Ausschalten
  entfernt sie aus der Entity-Registry. Ohne Daten ist der Wert `None` (unbekannt), nie 0.
- **Zwei Vorfallstypen der Netzwerk-Intelligenz (`net_rules.py`, `net_engine.py`).**
  `wan_gateway_changed` (nächster Hop eines Routers hat gewechselt) und `dns_server_changed`
  (die Menge seiner DNS-Server hat gewechselt), beide Schwere „info“, ohne Cooldown, nie
  Wurzel. Sie werden nur von Ursachen **desselben Routers** übernommen: `wan_down` dieses
  Routers sowie `router_unreachable` und `system_reboot` dieses Routers (nur wenn die
  Änderung nach Beginn des Ausfalls liegt); `lan_unreachable` übernimmt wie bisher alles in
  seinem Fenster. Eine Wurzel eines anderen Routers übernimmt sie nie, und `wan_down` eines
  anderen Routers nimmt ihre Ereignisse nicht mit. Die bestehende Korrelation, die Schwellen
  (`DEFAULT_SETTINGS`) und die Wurzelränge bleiben unverändert.
- **Kontext eines Befunds (`diag_context.py`).** Konfigurationsänderungen (Configuration
  Manager) und Vorfälle des Security Centers **desselben Routers** im Fenster von 30 min
  werden als Kontext verknüpft, höchstens `probable` und nie stärker als der Befund selbst;
  nur Bereiche, die die Klasse technisch erklären können (ein fehlender Standardweg ist ein
  Routing-Problem, keine VLAN-Änderung). Fehlt eine Quelle oder ist sie aus, steht
  `context_unavailable` mit Grund, nie „keine Änderung“.
- **Panel-Tab „Netzwerkdiagnose“** unter Enterprise (nach „Konfiguration“ und „Security
  Center“): Übersicht, Verlauf, für Administratoren manuelle Diagnose und Einstellungen. Der
  Tab liest nur über die Routen oben; ausgeschaltet erklärt er, was das Modul tut, ohne
  Wert. Das Frontend-Bundle ist neu gebaut.
- **Diagnose-Download:** neuer Block `network_diagnostics` (Zustände, Gründe, Router- und
  Ziel-IDs, Zähler; ohne Adresse, Host oder Domain). Die neuen Adressfelder des Polls
  (`wan_status.diag_facts`) werden zusätzlich geschwärzt; die gemeinsame Schlüsselliste
  `DIAGNOSTICS_TO_REDACT` bleibt unverändert.

### Bekannte Grenzen

- **Keine Tests auf dem Router.** Ping, `nslookup` und `traceroute` auf dem Router gibt es in
  dieser Version nicht. Vorhanden sind nur die Schnittstelle dafür und die Prüfung, ob ein
  Router es könnte; es gibt keinen Ausführer und **kein ACL-Recht**, das es erlauben würde.
  Der Status meldet `router_probes: not_available` (`no_executor`).
- **Kein externes Ziel ist voreingestellt.** Ohne bestätigte Ziele wird nichts Externes
  gemessen; Internet- und DNS-Glied bleiben dann unbekannt. Aus dem Poll allein kommen nur
  Router-, WAN- und Routenfakten. Das Gateway-Glied eines Routers ließe sich nur mit einer
  Messung am Router direkt messen; deshalb ist der Binärsensor „Gateway erreichbar“ in dieser
  Version unbekannt (Grund `not_measured`).
- **Die Detail-Route hat noch keine Ansicht im Panel** (`details` ist nur über HTTP lesbar).
- **Ziele und Bereichslisten sind im Panel nur lesbar.** Sie enthalten Rechnernamen und
  Adressen und werden über die Route `settings` geändert, nicht im Panel.
- **Schwellen sind begründete Annahmen, nicht an echten Daten abgestimmt:** Gewichte und
  Punktetabellen des Werts, Schwellen und Lernzeit der Baselines.
- **Die bestehende TCP-Messung des Coordinators bleibt unverändert:** je Poll und Router eine
  Verbindung von Home Assistant zu `8.8.8.8:53` (`ping_ms`). Ihre Bereinigung folgt in einem
  eigenen PR; sie gehört nicht zur Netzwerkdiagnose und ist in deren Last nicht enthalten.
- **Die Jitter-Basislinie** ist als Baustein vorhanden, wird von der Laufzeit aber noch nicht
  gespeist; Jitter steht nur in den Fenster-Zahlen und im Wert.
- **Nicht getestet** gegen echte Router, echte Ziele oder eine echte Home-Assistant-Instanz;
  die Tests laufen ohne Geräte und ohne Netz.

## [1.46.2] - 2026-11-21

### Behoben

- **Security Center: Die Abdeckung sinkt nicht mehr, wenn eine Quelle dazukommt.** Lieferte
  das Gateway Firewall-Zeilen, fiel die Abdeckung von 71 auf 65 % und der Deckel des
  Sicherheitswerts von 86 auf 82. Zwei Ursachen, beide behoben:
  - Firewall-Log und DNS-Log sind **Flotten-Quellen**: Sie gelten als verfügbar, sobald ein
    Router wirklich Zeilen geliefert hat (nicht bloß eingetragen). Bisher zählte der
    schlechteste Zustand aller Router, und Access Points liefern diese Zeilen nie. Übersicht
    und Log-Pfad-Ansicht sagen jetzt „von N von M Routern“ (`coverage.fleet`,
    `log_path.status[].routers_delivering/routers/rate_limited`) und zeigen dieselben Zahlen.
    Ein ratenbegrenzter Lieferant bleibt „eingeschränkt“ (`rate_limited`). Alle anderen Quellen
    behalten die Regel „schlechtester Zustand“.
  - Einschränkungen senken die Abdeckung **monoton**: Der Abzug eines Faktors entfällt, solange
    eine seiner erwarteten Quellen flottenweit fehlt (sie ist schon als fehlende Quelle
    gezählt), und alle Abzüge zusammen bleiben unter einem halben Quellenanteil
    (`LIMITATION_SHARE_CAP`). Im beobachteten Fall steigt die Abdeckung jetzt auf 79 %, der
    Deckel auf 90.
- **Security Center: `fw_inter_vlan` meldet nicht mehr dauerhaft `dest_zone_unknown`.**
  fw4-Zeilen nennen die Zielzone nie, und die ausgehende Schnittstelle (`OUT=`) wurde zwar
  gelesen, aber nicht genutzt. Die Zielzone kommt jetzt in dieser Reihenfolge aus: einer
  konfigurierten Zuordnung Schnittstelle → Zone (gebaut, heute ohne Lieferant: der
  Configuration Manager gibt Modulen keinen Lesezugriff auf gespeicherte Versionen), einer aus
  den Zeilen gelernten Zuordnung (in den Ketten `in`/`forward` ist die Präfix-Zone die Zone von
  `IN=`; begrenzt, nur im Speicher, nie über der konfigurierten, widersprüchliche Werte bleiben
  unbekannt) und zuletzt `subnet_zones`. Zeilen der Kette `in` mit leerem `OUT=` zählen nicht
  als Inter-VLAN. Kein zusätzlicher Router-Aufruf.
- **Security Center: Ein privates Ziel außerhalb von `subnet_zones` gilt nicht mehr als extern.**
  Es bleibt unbekannt (mit `dest_zone_unknown`); nur öffentliche Ziele zählen als extern.
- **Security Center: fw4-Format bestätigt.** Zwei echte Zeilenformen (`reject … forward:` mit
  UDP und zweitem `LEN=`, `reject … in:` mit leerem `OUT=` und ICMP) liest der Parser;
  `FORMAT_CONFIRMED["fw4_nflog"]` ist wahr, und die Firewall-Erkennungen tragen im Panel nicht
  mehr „Format unbestätigt“ (DNS weiterhin). Nicht belegt bleiben die Kette `out`, die Urteile
  `drop`/`accept`, TCP-Flags und die Feldreihenfolge bei IPv6 (Fixture
  `fw4_kernel_unbelegt.txt`).
- **Security Center: Nach Rückkehr des Modulschlüssels wird nichts sofort automatisch
  erledigt.** Die 24 ruhigen Stunden zählen ab dem ersten Poll mit Schlüssel (oder ab dem
  letzten Befund, wenn der später liegt); vorher war die blinde Zeit als Ruhe gezählt. Ein
  Start, bei dem der Schlüssel sofort da ist, ändert nichts.
- **Security Center: Fehlende Core-Anbindung wird aus dem Poll neu versucht.** Fehlt beim
  Start die Configuration API oder scheitert die Anmeldung der Ereignisse, versucht der Poll
  die Anbindung alle 5 Minuten erneut, solange ein Core läuft. Eine Warnung je Zustand „nicht
  gebunden“ (ohne Identitäten), kein Router-Aufruf, Fehler stören den Poll nie.
- **Security Center: Geräte, die ohne Schlüssel auffällig wurden, bekommen ihren Hinweis.**
  Beim ersten Poll mit Schlüssel holt das Center den Hinweis für jedes dann noch auffällige
  Gerät einmal nach (nur im Speicher, höchstens 256 Geräte). Bisher sammelte das
  Vertrauensbuch die Indikatoren weiter, der Hinweis ging aber verloren.
- **Security Center: Reserve für Konfiguration und Geräte.** Von den 50 Plätzen der Klasse
  „andere“ sind 10 nur für Nicht-WLAN-Quellen; WLAN-Hinweise belegen höchstens 40, eine
  WLAN-Flut blockiert keinen Drift- oder Geräte-Hinweis mehr. Keine Verdrängung: ein neuer
  WLAN-Hinweis bei voller Quote wird gezählt (`incidents_wifi_quota_dropped`) und einmal je
  Stunde in der Zeitleiste vermerkt. Die Zuordnung kommt aus der Datenquelle des Detektors
  (`from_wifi`); ältere Stände mit mehr als 40 WLAN-Hinweisen laden vollständig. Panel und
  Diagnose zeigen den WLAN-Anteil.
- Diagnose: `interface_zones` mit Zählern der Zuordnung (ohne Namen), `wifi_incidents`,
  `missed_device_hints`.
- Doku: Die Abdeckung ist der Anteil der erwarteten **Datenquellen**, nicht der Erkennungen.

## [1.46.1] - 2026-11-20

Configuration Manager: Router, die als „Unvollständig“ dastanden, obwohl sie mehr können.
Keine neue Vertragsangabe, keine Änderung am Core, Maskierung unverändert.

### Behoben

- **Das erste Backup klärt den Archivweg.** Lässt die Prüfung bei einem HTTPS-Eintrag den
  cgi- oder den SSH-Weg „ungeprüft“ (`not_probed`), fordert ein Lauf ohne festen Typ das
  Archiv an. Gelingt es nicht, bleibt der UCI-Snapshot: `uci_snapshot`/`ok`, wenn jeder Weg
  „nicht vorhanden“ oder „keine Rechte“ meldet, sonst `partial`. Vorher sicherte so ein Lauf
  still nur UCI.
- **cgi-Archiv trotz unlesbarer Paketliste.** Mit dem rpcd-Recht `cgi-io: backup`, aber
  unlesbarer Paketliste fragt der Lauf das Archiv an; die Fähigkeit `config.cgi_backup` zeigt
  dabei „noch nicht geprüft“, nicht „verfügbar“. Erst ein echter cgi-Archivlauf belegt sie
  (Archiv erhalten: verfügbar; abgelehnt: dessen Grund), sichtbar ab der nächsten Prüfung.
  Ein Archiv über SSH zählt dafür nicht. Eine gemerkte Ablehnung gilt nur für die Anzeige:
  Der Lauf fragt das Archiv weiter an, nach dem Installieren von `cgi-io` also ohne
  HA-Neustart; bestätigt rpcd das Recht, entfällt eine gemerkte Rechte-Ablehnung.
- **Fehlende optionale UCI-Configs** (`sqm`, `mwan3`, `upnpd`, `openvpn`, `ddns`, `usteer`,
  `firewall`, `dhcp`, `wireless` …) sind „nicht vorhanden“, nicht `uci_failed` und machen
  keine Version `partial`. Ursache: ubus meldet „nicht gefunden“, der SSH-Ersatzweg war wegen
  des noch nicht bestätigten Host-Keys gesperrt, und diese Sperre ersetzte die Antwort. Ein
  „nicht gefunden“ von ubus geht jetzt gar nicht mehr zu SSH; nur eine echte ACL-Sperre
  nimmt den Ersatzweg und bleibt ein Fehler, wenn er scheitert. `network` und `system` gibt
  es auf jedem OpenWrt-Router: Fehlen sie, ist der Lauf `partial` (`incomplete`).
- **Lauf ohne Archivversuch** nennt den Grund je Weg: `archive_not_attempted:cgi.<Ursache>`,
  `archive_not_attempted:ssh.<Ursache>` oder `archive_not_attempted:requested`.
- **Lauf mit gescheitertem Archiv** nennt den Grund je versuchtem Weg:
  `archive_unavailable:<Weg>.<Fehlerklasse>` (bei HTTP zusätzlich
  `archive_unavailable:cgi.insecure_transport`); läuft die Zeit für das Archiv als Ganzes ab,
  bekommt jeder Weg der Kette `<Weg>.timeout`. Das Panel zeigt sie in Klartext.
- **SSH-Port zu ist nicht „Router nicht erreichbar“.** Root auf HTTPS, `cgi-io` fehlt, SSH
  (Port 22) von Home Assistant aus nicht erreichbar: Der Lauf bleibt `partial`
  (`unreachable`/`timeout`), aber das Panel nennt den SSH-Weg statt „Der Router war nicht
  erreichbar“ und als nächsten Schritt, SSH freizugeben oder `cgi-io` zu installieren.
- **Host-Key-Grund sichtbar.** `ssh_host_key:<Grund>` erscheint als fester Code statt
  `**REDACTED**`; nur die festen Gründe des Cores kommen zurück, alles andere bleibt maskiert.
- **Panel „Unvollständig“** zeigt Fehlerart, Gründe in Klartext und den nächsten Schritt
  (zum Beispiel „SSH-Host-Key bestätigen“; bei einem ungeprüften Weg „Jetzt sichern“, weil
  dieser Lauf das Archiv anfordert).
- **Panel „Prüfsumme“** zeigt die Prüfsumme des gespeicherten Inhalts (Archiv, sonst
  UCI-Snapshot) oder „–“, nie mehr die des Inventars, die auf allen Routern gleich aussah.
- **Panel „Leserechte fehlen“** nur noch, wenn sie wirklich fehlen; läuft das Archiv (etwa
  als root per SSH), ist das ACL-Angebot als optional beschrieben.
- **Panel „Letztes Backup“** zeigt „letzter Versuch: unvollständig, <Zeit>“ statt „noch keins“,
  wenn es nur unvollständige Läufe gibt.

### Tests

- Neu: `tests/test_config_partial_v1461.py` (End-to-End Runtime → Core → echter Provider,
  nur die Router-API ist ein Fake), Panel-Tests `configPartial.test.mjs`; der Pin-Speicher für
  SSH-Host-Keys trennt Router strikt nach Router-ID (Test, keine Code-Änderung). Die festen
  Weg-Codes (`archive_not_attempted:…`, `archive_unavailable:…`) kommen unmaskiert durch
  (Test, keine Code-Änderung).

## [1.46.0] - 2026-11-20

Security Center: eine Beobachtungsschicht für das Netz auf dem Enterprise Core von 1.44.0 und
den Modulen Netzwerk-Intelligenz, Client-Stabilität und Configuration Manager. Es **beobachtet
nur**: keine Sperren, keine Quarantäne, keine Scans, keine Firewall-Änderung. **Standardmäßig
aus**; ausgeschaltet gibt es keinen Beobachter, keinen Listener, keinen Socket und keine
Schreibvorgänge. **Kein zusätzlicher Router-Aufruf je Poll.** Nutzerdoku: `docs/security-center.md`.

### Hinzugefügt

- **Security Center (`security_center.py`).** Ein Center je HA-Instanz verbindet die reinen
  Module `security_*` mit Daten, die die Integration schon hat: Netzwerk-Intelligenz (als
  Poll-Beobachter: WLAN-Zeilen, NI-Ereignisse, Uptime, Clients), Client-Stabilität
  (Live-Zustand für das Vertrauensbuch) und den Enterprise Core (Drift-Ereignisse,
  `router.forgotten`, Fähigkeiten, Modulschlüssel). Vergisst der Core einen Router, bevor das
  Center läuft, gleicht das Center beim Start mit der geladenen Router-Registry ab; eine
  unbekannte oder nicht geladene Registry löscht nichts. **Kein zusätzlicher Router-Aufruf je Poll** (Test zählt die ubus-POSTs mit und
  ohne Center).
- **Aus heißt aus:** ohne `enabled` liest das Center nur seinen Speicher; kein Beobachter,
  kein Listener, keine Schreibvorgänge, keine Ereignisse. NI-Vorfälle, NI-Zähler,
  Health-Score und Client-Stabilität sind mit inaktivem und aktivem Center identisch
  (Regressionstest mit drei Durchläufen).
- **Eigene `sec_*`-Hinweise** (offen / erledigt / bestätigt, höchstens 100, eigene Zähler,
  eigene Ereignisse über den Core im Security-Ring). NI-Vorfälle werden nur per ID verknüpft,
  nie geändert oder unterdrückt; deckt ein offener NI-Vorfall einen Befund schon ab, steht nur
  ein verknüpfter Eintrag in der Zeitleiste.
- **Obergrenze der Hinweise:** höchstens 100, aufgeteilt in **zwei feste Quoten ohne
  Verdrängung zwischen ihnen:** höchstens 50 Hinweise vom Syslog-Empfänger (Firewall, DNS;
  Absender per UDP im LAN fälschbar) und höchstens 50 aus allen anderen Quellen (WLAN,
  Konfigurationsänderung, Vertrauensbuch; WLAN-Befunde lassen sich über Funk auslösen). Die
  Klasse folgt aus der Datenquelle des Detektors, nie aus dem Zeileninhalt. In einer vollen
  Klasse macht der älteste erledigte Hinweis dieser Klasse Platz; offene und bestätigte werden
  nie entfernt, bestätigte zählen mit. Sonst wird nur der neue Hinweis dieser Klasse verworfen
  und gezählt (`limits.incidents_log_quota_dropped` bzw. `limits.incidents_other_quota_dropped`,
  je Klasse höchstens ein Zeitleisten-Eintrag je Stunde); die andere Klasse bleibt unberührt.
  Ältere Speicherstände mit mehr als 50 in einer Klasse laden vollständig und heilen sich, wenn
  Hinweise erledigt werden; bis dahin zählt `limits.incidents_cap_dropped`, was an der
  Gesamtgrenze scheitert. Die Herkunft (`from_logs`) übersteht einen Neustart. Ereignisse über
  den Core zu neuen oder wieder geöffneten Hinweisen: höchstens 20 je 10 min, der Rest wird
  gezählt (`limits.events_throttled`).
- **Erneut beobachtet:** Ein neuer Befund zu einem bestätigten Hinweis, der später als 24 h
  nach dem letzten kommt, steht als Eintrag in der Zeitleiste, höchstens einmal je Hinweis und
  24 h (Zeitpunkt am Hinweis, übersteht einen Neustart); steigt die Schwere, immer.
- **Geschlüsselte IDs:** Hinweis-, Ereignis- und Korrelations-IDs sowie Dedup-Marken, die
  gespeichert, gesendet oder ausgegeben werden, sind HMAC-Werte mit dem Modulschlüssel des
  Cores und lassen sich mit einer Liste möglicher MACs nicht zurückrechnen. **Ohne
  Modulschlüssel zeichnet das Center keine Hinweise auf** (Zustand „nicht bereit“, Grund
  `module_key_missing`; Befunde nur gezählt, Gerät bestätigen und benennen ergibt 409
  `not_ready`). Solange setzen Befunde keinen Indikator im Vertrauensbuch und offene Hinweise
  werden nicht automatisch erledigt. Der Poll fragt den gebundenen Core alle 5 Minuten erneut
  nach dem Schlüssel (kein Router-Aufruf), mit einer Warnung je „nicht bereit“-Zustand ohne
  Identitäten. Ältere Speicherstände laden ohne Fehler.
- **Drift → Segmentierung:** eine Konfigurationsänderung in VLAN/Firewall/Interface (Bereiche
  aus dem Vergleich zweier gespeicherter Versionen, kein Router-Kontakt) ergibt genau einen
  Hinweis mit Verweis auf die Drift-ID. Ein Befund kurz nach einer Konfigurationsänderung wird
  nur zeitlich verknüpft, ohne Ursachenbehauptung.
- **Speicher** (`.storage/openwrt_router.security_center`, höchstens 512 KB, verzögertes
  Schreiben, beim Entladen sofort; beschädigte Abschnitte starten leer, ein unlesbarer Speicher
  bleibt als `.bak`): Einstellungen, Vertrauensbuch, Baselines, maskierte Hinweise, Zeitleiste
  (2000 Einträge / 14 Tage), Dedup-Marken. Keine HA-Benutzer-IDs.
- **Manuelle Aktionen** (Gerät bestätigen, Namen setzen, Hinweis-Status, Einstellungen) nur für
  Administratoren über den Core-Guard, jede auditiert. Keine Quarantäne.
- **Übersicht:** Score mit Faktoren und Abdeckung (ohne Quelle `None`, nie „gesund“),
  Hinweise, Zeitleiste mit Filtern, Geräteliste, Verfügbarkeit je Erkennung (verfügbar /
  eingeschränkt / nicht verfügbar mit Grund, „Format unbestätigt“ für Firewall- und DNS-Logs).
  Klartext nur für Administratoren, sonst Pseudonyme. Der Collector-Weg meldet „nicht
  verfügbar“ mit Grund.
- **Syslog-Empfänger (`security_syslog.py`):** lokaler UDP-Listener (Standardport 5514) für
  das Remote-Log der Router (`logd` `log_ip`/`log_port`). Er bindet **nur**, wenn das Center
  an ist und der Log-Weg `syslog` gewählt ist; sonst gibt es keinen Socket. Absender nur aus
  der Router-Registry (IP-Literale der Verwaltungsadressen, keine DNS-Auflösung, mehrdeutige
  Adressen ausgeschlossen); fremde Absender werden verworfen und gezählt. Zeilen über 2048 Byte
  werden abgeschnitten, Token-Buckets je Absender und gesamt sowie ein Puffer mit höchstens
  4000 Einträgen begrenzen Speicher und CPU (alles gezählt). Zeilen erscheinen nie oberhalb
  von DEBUG im Log und werden nie ungefiltert gespeichert. Ein Bind-Fehler (Port belegt,
  keine Berechtigung) macht die Quelle „nicht verfügbar“ mit Grund, das Setup läuft weiter;
  ein neuer Versuch alle 5 min aus dem Poll. Verliert ein Router Zeilen an eine Rate oder den
  vollen Puffer, sind seine Firewall- und DNS-Erkennungen bis 5 min nach der letzten
  verworfenen Zeile „eingeschränkt“ (`rate_limited`), mit Einschränkung im Sicherheitswert und
  geringerer Abdeckung. Ein Wechsel des Log-Wegs schließt den Socket;
  erneut gesendete Zeilen filtert der gemeinsame Deduper. Grenze: UDP-Absender sind im LAN
  fälschbar, die Liste filtert Rauschen, sie authentifiziert keinen Router.
- **HTTP-Routen (`security_views.py`)** unter `/api/openwrt_topology/security`, alle mit
  Anmeldung: Übersicht (mit Filtern), Hinweis-Details, Verfügbarkeit der Erkennungen und
  Einstellungen lesen (Administratoren; andere Benutzer nur bei für alle geöffnetem Panel,
  dann mit Pseudonymen und der Subnetz-Zuordnung nur als Anzahl); Einstellungen ändern
  (hier wird das Center eingeschaltet), Gerät bestätigen oder benennen und Hinweis-Status
  setzen nur für Administratoren. Gerät bestätigen (`/devices/confirm`) und benennen
  (`/devices/name`) tragen die MAC im Body, nie im Pfad. Strenge Prüfung von Query und
  Body (bekannte Schlüssel,
  Typen, Bereiche, höchstens 4 KiB, zu tief verschachteltes JSON ist 400); Fehler tragen nur
  eine feste Meldung, einen Code und höchstens Feldname und Grund. Eine Ablehnung durch den
  Guard des Cores ist 403 `authorization_denied` ohne Angaben des Cores.
- **Flotten-Sensoren (`security_entities.py`):** Sicherheitswert, aktive und kritische
  Sicherheitshinweise, unbestätigte Geräte, Firewall-Protokolleinträge und WLAN-Anmeldefehler
  der letzten Stunde, Abdeckung der Erkennung. Werte nur aus dem Center (keine Router-Aufrufe,
  per Signal aktualisiert); ohne liefernde Quelle `None` (unbekannt), nie 0, auch für aktive
  und kritische Hinweise; ist das Center nicht bereit (kein Modulschlüssel), sind alle sieben
  Sensoren unbekannt. Wert und Abdeckung zählen nur geladene Router; die Hinweise und
  Grundlinien eines entladenen Routers bleiben gespeichert. Die Sensoren gibt es nur bei
  eingeschaltetem Center; Ausschalten entfernt sie aus der Entity-Registry.
- **Panel-Tab „Security Center“** unter Enterprise (neben „Konfiguration“) mit den Bereichen
  Übersicht, Zeitleiste, Geräte, Erkennungen und Einstellungen sowie dem Detail eines
  Hinweises. Der Tab liest nur über die Routen oben; Schreibknöpfe haben nur Administratoren.
  Bei ausgeschaltetem Center erklärt er, was das Center tut und nicht tut. Gerät bestätigen und
  Hinweis-Status setzen fragen vor dem Senden einmal nach; ohne Modulschlüssel zeigt der Tab
  „Nicht bereit“, nie „keine Befunde“.
- **Diagnose:** neuer Block `security_center` am Ende (nur Zähler, Zustände und Gründe;
  maskiert und geschwärzt, keine MAC, Adresse, Hostname, Benutzer-ID oder Schlüssel).

### Hinweise

- **Standardmäßig aus.** Einschalten im Panel unter Enterprise → Security Center (nur
  Administratoren). Es gibt keinen Optionsdialog und keinen Dienst dafür.
- **Keine neuen Router-Rechte.** Die ACL bleibt unverändert; das Security Center schreibt
  nichts auf einen Router. Den Log-Versand der Router (`log_ip`) richtet der Nutzer selbst ein
  (Befehle und Rückweg in `docs/security-center.md`).
- **Firewall- und DNS-Befunde markieren kein Gerät** im Vertrauensbuch: ihre Logzeilen nennen
  eine IP-Adresse, und es gibt kein Nachschlagen IP → MAC.
- **Keine DNS-Namen im Klartext** an DNS-Hinweisen; eine Einstellung dafür gibt es nicht (die
  frühere Option `keep_dns_names` ist entfernt, ein Speicherstand mit ihr lädt weiter).
- **Der Collector-Weg ist noch nicht verfügbar** (`log_path: collector` meldet „nicht
  verfügbar“). Firewall- und DNS-Erkennungen setzen den Syslog-Weg voraus; ihre Logformate sind
  an echten Geräten unbestätigt.
- **Nicht getestet** gegen echte Router oder eine echte Home-Assistant-Instanz; die Tests
  laufen ohne Geräte.

## [1.45.0] - 2026-11-19

Configuration Manager: Konfigurations-Backup für OpenWrt-Router in Home Assistant, auf dem
Enterprise Core von 1.44.0. **Standardmäßig aus** (Option `config_backup_enabled` je Router);
bei ausgeschaltetem Backup gibt es **0 zusätzliche Router-Aufrufe**, keine neue Datei auf der
Platte und keine geänderte `unique_id` oder Entity-ID. Nutzerdoku: `docs/configuration-manager.md`.

### Hinzugefügt

- **Backups mit Versionen:** je Router ein wiederherstellbares Archiv (`sysupgrade -b`-Format,
  über den LuCI-Endpunkt `cgi-backup`, sonst per SSH als root), ein normalisierter
  UCI-Snapshot für Vergleiche und ein Paket- und Systeminventar. Router ohne Archivweg
  bekommen nur den Snapshot. Dedup über den Inhalts-Hash, Aufbewahrung 7 täglich / 4
  wöchentlich / 6 monatlich, geschützte Versionen, Prüfsummen (Core).
- **Zeitplan:** täglicher Lauf zur eingestellten Uhrzeit mit festem Versatz je Router (bis
  59 min), ein Lauf zurzeit (Parallelität 1), Nachholen nach HA-Start, ein Nachversuch nach
  15 min; zusätzlich ein Backup 300 s nach einem erkannten Release-Wechsel.
- **Drift-Erkennung:** Vergleich des aktuellen UCI-Stands mit der Bezugsversion, Bereiche
  und Risikostufen, kritisch bei Management-IP, VLAN, Firewall, SSH-Zugriff, Uplink und
  Web-Verwaltung; bestätigen oder als bekannt markieren, nie automatisches Zurücksetzen;
  „nicht vergleichbar“ ist ein eigener Zustand. Automatische Prüfung nach 5 min Entprellung,
  höchstens einmal je Stunde, höchstens 4 Drift-Versionen je Router und Tag.
- **Diff-Ansicht:** hinzugefügt / entfernt / geändert, nach Bereich und Risiko, Geheimwerte nur
  als „geändert“.
- **Restore-Prüfung:** Kompatibilität (blockierend: anderes Board, anderes Switch-Modell,
  ungültiges Archiv, falsche Prüfsumme), Vorschau und Risiken, Anleitung für die manuelle
  Wiederherstellung und eine Prüfliste danach.
- **Panel:** Enterprise → Konfiguration (nur Administratoren): Übersicht, Router-Detail,
  Versionen, Drift, Vergleich, Export mit Freigabe, Zugang (SSH-Pin, ACL-Angebot).
- **Sensoren je Router:** `config_last_backup`, `config_backup_status`, `config_versions`
  (Diagnose) und der Binärsensor `config_drift`.
- **Dienst `openwrt_router.create_config_backup`** (`device_id`, optional `note`) mit
  Antwort je Router; als Schritt vor einem Firmware-Update gedacht (die Integration hat keinen
  eigenen Update-Pfad).
- **Optionen** `config_backup_schedule` (`daily` / `off`, Vorgabe `daily`),
  `config_backup_time` (Vorgabe `03:30:00`) und `config_drift_check` (Vorgabe an), nur sichtbar,
  wenn der Backup-Provider angemeldet ist oder das Backup an ist.
- **Diagnose:** Block `config_manager` ohne Snapshots, Diffs, Notizen und Benutzer-IDs.

### Sicherheit

- **Nur Administratoren:** alle Routen des Managers (403 für alle anderen, auch bei offenem
  Topologie-Panel), `Cache-Control: no-store`, Benutzer-IDs nur als Pseudonym.
- **Maskierung auf dem Server** für Antworten, Logs, Ereignisse und Diagnose; Geheimwerte
  stehen im Snapshot nur als gesalzene HMAC-Prüfwerte.
- **Archivprüfung ohne Entpacken:** Pfade, Symlinks, Größen- und Verhältnisgrenzen (höchstens
  16 MiB komprimiert, 64 MiB entpackt, 5000 Mitglieder).
- **Export nur mit Freigabe:** Antrag, Bestätigung, genau ein Download je Freigabe (15 min
  gültig), neu berechnete Prüfsumme vor der Auslieferung, Eintrag im Audit-Log.
- **Ablage** unter `<HA-Konfiguration>/openwrt_router/config_backups/` (Ordner `0700`,
  Dateien `0600`), nie unter `www`; nichts geht an externe Dienste.

### Hinweise

- **Standardmäßig aus.** Einschalten je Router in den Optionen (`config_backup_enabled`).
- **Neue Router-Rechte nur auf Angebot.** Die ACL-Stufe `config_backup_read` (`cgi-io: backup`,
  `uci`, `rpc-sys: packagelist`, alle lesend) wird nur bei eingeschaltetem Backup angeboten und
  erst nach ausdrücklicher Einzelfreigabe eines Admins auf den Router geschrieben. **Sie gibt
  Home Assistant Lesezugriff auf alle Geheimnisse des Routers.**
- **Keine automatische Wiederherstellung.** Die Integration spielt nichts auf einen Router
  zurück; die Wiederherstellung machen Sie von Hand (LuCI oder `sysupgrade -r`) und ist nicht
  automatisch umkehrbar.
- **Archive enthalten WLAN-Passwörter, Schlüssel und Passwort-Hashes im Klartext.** Keine eigene
  Verschlüsselung; HA-Backups verschlüsseln.
- Keine Migration nötig: bestehende `unique_id`s und Entity-IDs bleiben; der Manager hängt sich
  nicht in den Poll (`coordinator.py` ist unverändert).

### Sicherheit

- **Host-Key-Pinning für das SSH des Managers:** Archiv per `sysupgrade`, `uci show` und
  Paketliste laufen nur über den gepinnten SSH-Weg des Cores (erster Key ausstehend bis zur
  Bestätigung, abweichender Key abgelehnt); Fehlerklasse `denied` mit Grund `ssh_<grund>`.
- **Routen-Pseudonyme mit Modul-Schlüssel:** Benutzer-Pseudonyme in den Antworten der Routen
  sind mit dem abgeleiteten Modul-Schlüssel des Cores gesalzen.

### Bekannte Einschränkungen

Ausführlich in `docs/configuration-manager.md`, Abschnitt 13.

- SSH des Managers nur mit bestätigtem Host-Key: bis zur Bestätigung im Panel kein Archiv
  und keine UCI-Daten per SSH.
- Größenlimit der Aufbewahrung (Core): eine gute geplante Version kann früher fallen als nötig.
- Dedup verlangt neben dem Inhalts-Hash byte-gleiche Dateien (Core seit 1.44.0).
- Die Warnung „zu wenig Platz auf dem Router“ der Restore-Prüfung erscheint nicht (der freie
  Platz wird nicht gelesen).
- Kein Löschen im Panel, Beschreibung nur beim Anlegen, keine Vergleiche zwischen Routern,
  Freigaben gehen bei einem HA-Neustart verloren.
- Laufzeit und Größe eines echten `sysupgrade -b` wurden nicht an Geräten gemessen.

### Nachträge zum Enterprise Core (aus PR #56, jetzt in 1.45.0)

#### Added

- Enterprise Core: Module bekommen einen eigenen, abgeleiteten Schlüssel
  (`api.async_get_module_key(module, purpose)`, HKDF-SHA256 aus dem
  Installations-Schlüssel); nur für Module mit registriertem Event-Präfix, nie in Log,
  Diagnose oder Event. Er trennt Module gegen Versehen, nicht gegen feindlichen Code im
  selben Prozess.
- Enterprise Core: `pseudonymise_identifier` / `pseudonymise_fields` ersetzen MAC, IP,
  Hostname, SSID, BSSID und Client-Kennungen durch stabile Pseudonyme (`mac_…`, `ipa_…`,
  `hst_…`, `ssd_…`, `bss_…`, `cli_…`) unter einem Modul-Schlüssel.
- Enterprise Core: Module können eigene Events als sicherheitsrelevant markieren
  (Sicherheits-Audit) und eigene Event-Typen als audit-pflichtig registrieren (nie
  zusammengefasst); `register_event_prefix` gibt einen Entferner zurück.
- Enterprise Core: zwei neue Fehler für Module, `RateLimitedError` (`rate_limited`,
  mit `retry_after`, wiederholbar) und `SafetyRefusedError` (`safety_refused`, mit
  `reason`, nicht wiederholbar). Beide Fehlerklassen landen nie in gespeicherten
  Versionsdaten.
- Enterprise Core: neue Guard-Klasse `active` für Aktionen, die am Router oder im Netz
  etwas tun, ohne die Konfiguration zu ändern (Scan, Ping): Benutzer brauchen Admin,
  keine Freigabe, Audit im allgemeinen Ring, optional mit Ratenlimit je Router
  (`rate_limited` mit `retry_after`); das Limit gilt nur für bekannte Router, eine
  erfundene Router-ID wird abgelehnt (`unknown_router`) und kann das Limit eines echten
  Routers nicht mehr zurücksetzen. Module können ein sensibles Lesen als
  Admin-pflichtig für Benutzer registrieren (`sensitive_read=True`).
- Enterprise Core: Core-Events haben fünf optionale Felder für Module:
  `client_ref` (nur als Pseudonym `cli_…`), `confidence`, `classification`,
  `incident_ref`, `radio_id`.

#### Changed

- Enterprise Core, Maskierung: Nennt ein Record sein Feld in mehreren Namensfeldern
  (`key`, `name`, `field`, `param`, `parameter`, `setting`), werden alle geprüft; ein
  geheimer Name maskiert die Werte unabhängig von der Reihenfolge (Vertrag #114).
- Enterprise Core: Drift-Prüfung, Restore-Probelauf und Backup-Prüfung verlangen von
  einem Benutzer Admin-Rechte, wie schon Capture und Vergleich; die Ablehnung steht im
  Sicherheits-Audit. Die Backup-Prüfung braucht immer einen Akteur; ohne ihn wird sie
  abgelehnt (`actor_required`) statt ungeprüft ausgeführt (Sicherheitsprüfung von PR #56).
- Enterprise Core: Die Maskierung zeigt Kennungen unter wenigen Namen wie `rule_key` oder
  `translation_key`, aber nur in strenger Form (Core-ID oder kurzer Slug in
  Kleinbuchstaben); alles andere darunter, auch verschachtelte Daten, bleibt maskiert.
  `client_key`, `device_key`, `router_key`, `radio_key` und weitere Namen, die anderswo
  ein Schlüssel sind, werden wieder vollständig maskiert (Sicherheitsprüfung von PR #56).
  Zähler zeigen Zahlen nur, wenn ihr Name kein geheimes Wort enthält: `pin_total`,
  `otp_total` oder `auth_failures` bleiben maskiert wie bisher, `wan_failures` ist lesbar.
- Enterprise Core: Sicherheitsrelevante Modul-Events haben im Sicherheits-Audit eine
  eigene Quote (100 je Modul, 500 für alle Module) und verdrängen nie mehr Einträge des
  Core; ein flutendes Modul verliert seine eigenen ältesten Einträge (gezählt, einmal im
  Log), nicht die eines anderen Moduls.
- Enterprise Core: Das Benutzer-Pseudonym (`usr_…`) im Core-Event bleibt über Neustarts
  gleich, sobald der Installations-Schlüssel existiert. Ohne Schlüssel ist es je Lauf
  zufällig; das steht einmal im Log und im Zähler `bus_salt_ephemeral`.
- Enterprise Core: Der Entwicklervertrag beschreibt jetzt, was der Code tut (Lesen über
  den Guard, Modulnamen und Capability-Präfixe, alle reservierten Präfixe in einer
  Tabelle, Flotten-Kennung `-`). `registry.get("-")` sagt zusätzlich `fleet: true`.

## [1.44.0] - 2026-11-18

Enterprise Core: ein interner Unterbau für spätere Module (Konfigurations-Backup,
Security Center, Netzwerkdiagnose, WiFi RF). Keine neue Entität, keine geänderte
`unique_id`, keine geänderte Geräte- oder Entity-ID, keine neue Config-Entry-Version und
**0 zusätzliche Router-Aufrufe je Poll**. **Sichtbar wird:** Core-Ereignisse
(`openwrt_router_core_event`) erscheinen im Logbuch, beim ersten Start einmal
`router.registered` je Router, und im Recorder. Ein Fehler im neuen Code lässt weder einen Poll noch das
Setup eines Eintrags scheitern, er wird geloggt. Nutzerdoku: `docs/enterprise-core.md`.

### Added

- **Stabile Router-ID** (`rtr_…`) je Config-Entry, unabhängig von IP und Hostname, mit
  Flotten-Registry (Store `openwrt_router.router_registry`). Identität aus Daten, die der
  Poll ohnehin holt: IP-Wechsel, Hostname-Wechsel und Werksreset behalten die ID;
  gleiche Hardware in zwei Einträgen wird als *Duplikat vermutet* gemeldet, nie
  zusammengelegt; einen getauschten oder neu angelegten Router übernimmt nur ein Admin
  ausdrücklich (Adoption).
- **Capability-Erkennung** je Router (`transport.*`, `data.*`, `stream.*`, `pkg.*`) aus
  den Poll-Daten, neu bewertet nur bei Änderung. Neu in 1.44: `rf.txpowerlist`,
  `rf.survey`, `rf.scan` aus der verteilten rpcd-ACL (mit plain v8: `rf.scan`
  verfügbar, die anderen `permission_denied` mit den fehlenden Rechten; ACL unbekannt:
  `unknown` mit Grund). Module können eigene Capabilities unter ihrem Präfix melden
  (`security.`, `diag.`, `rf.`, `log.`).
- **Configuration API v1** (`async_get_configuration_api(hass, version=1)`) für Module.
  **Ohne Backup-Engine:** Es ist kein Provider eingebaut; alle `config.*`-Capabilities
  bleiben `unavailable`, bis ein Provider installiert ist, und der Core ruft dafür nie
  den Router.
- **Option `config_backup_enabled`** (Standard aus). Aus heißt: `config.*` ist
  `disabled`, der Provider wird nie aufgerufen, die ACL-Stufe `config_backup_read` wird
  abgelehnt. Der Schalter erscheint in den Optionen erst, wenn ein Provider installiert
  ist (oder solange er an ist).
- **Freigaben (Approval-Gate):** kritische Aktionen (Export, Löschen, ACL verteilen,
  SSH-Pin bestätigen/zurücksetzen, Schlüssel-Reset) nur für Admin-Benutzer, mit
  Antrag, Freigabe und einmaliger, an Router und Prüfsumme gebundener Ausführung.
- **Audit-Log** mit zwei Ringen (allgemein 1000, Sicherheit 500 Einträge, 90 Tage),
  HA-Bus-Event, Dedup mit Wiederholungszähler; Events tragen nur IDs, Zähler und
  Fingerprints.
- **Versionsspeicher** für spätere Konfigurations-Backups: GFS-Aufbewahrung (7/4/6),
  Größengrenzen, Prüfsummen, Sweep beim Start. Manuelle und `pre_*`-Versionen werden
  nie ausgedünnt; das Größenlimit nennt sie, falls es sie entfernen muss. Dedup nur bei
  byte-gleichen Artefakten (sha256 des Core). Beim Entfernen eines Eintrags werden
  seine Versionen nach `removed/<router_id>/` verschoben (auditiert).
- **Gestufte rpcd-ACL v9, nur als Angebot:** nichts wird automatisch geschrieben. Ein
  Admin beantragt die Stufen, sieht Unterschied und Risiken, gibt frei; dann sichert der
  Core die alte Datei, schreibt, startet rpcd neu, prüft die Capabilities neu und
  protokolliert Befehl und Rückweg auf dem Sicherheitsring. Eine verteilte gestufte ACL
  bleibt über HA-Neustarts erhalten (`ensure_acl_respecting_offer`, ohne zusätzlichen
  Router-Aufruf).
- **Gepinntes SSH** für den Config-Pfad und das ACL-Verteilen per SSH: eigener Store
  je Router (`openwrt_router.ssh_host_keys`, privat, atomar). Kein stilles TOFU: ein
  erstmals gesehener Host-Key wird *ausstehend*, bis ein Admin ihn bestätigt
  (`ssh_pin_confirm`); ein abweichender Key wird immer abgelehnt und auditiert;
  Zurücksetzen nur über `ssh_pin_reset`. Der bestehende SSH-Fallback des Polls bleibt
  unverändert.
- **Panel:** Navigationseintrag „Enterprise“ mit Untertab-Container; er bleibt
  verborgen, solange kein Modul einen Tab anmeldet.

### Migration

Nichts zu tun. Keine ID-Änderungen; bestehende Einträge bekommen ihre Router-ID beim
nächsten Start ohne Router-Kontakt. Neue Stores: `openwrt_router.router_registry`,
`openwrt_router.audit`, `openwrt_router.config_catalog`,
`openwrt_router.ssh_host_keys` (der Installations-Schlüssel
`openwrt_router.installation_key` erst, wenn ein Provider ihn braucht).

### Fixed

- **Handy: untere Leiste wieder bedienbar.** Unter 420 px lag der Kopf der
  geschlossenen, leeren Detailansicht („Details ×“) über der neuen
  Symbolleiste und fing jeden Tipp ab. Die geschlossene Detailansicht ist
  jetzt unsichtbar und nimmt keine Tipps mehr an; geöffnet sitzt sie über
  der Leiste. Am Desktop unverändert.
- **Speicheranzeige nach dem Start:** bis zum ersten Speichern (bis 5 min
  nach dem Start) steht in den Stabilitäts-Einstellungen „noch nicht
  gespeichert“ statt „–“.
- **Deutsche Zahlen auch in der Fußleiste** und überall, wo Datenraten und
  Datenmengen stehen (Traffic, Detailansicht, Verbindungs-Tooltip):
  „5,0 Mbit/s“, „8,9 GB“.
- **Screenreader:** die Symbole der Seitenleiste nennen wieder ihre Zahl,
  z. B. „Diagnose (3)“.
- **Detailansicht am Handy:** nimmt beim Zuklappen keine Tipps mehr an und
  bleibt bei wenig Bildschirmhöhe samt „×“ vollständig sichtbar.

### Security (Prüfung des Enterprise Core vor dem Release)

- **ACL-Stufen:** optionale Stufen dürfen nur noch exakt freigegebene Leserechte
  enthalten (Allowlist, keine Muster wie `*` oder `fil?`, Dateien nur lesen unter
  `/proc/net`, `/sys/class/net`, `/sys/class/ieee80211`); das Angebot zeigt dem Admin
  jedes Recht, nicht nur eine Prüfsumme.
- **Gepinntes SSH:** beim ersten Kontakt geht kein Passwort an den Router, bevor der
  Host-Key bestätigt ist; die Ausgabe ist begrenzt (Abbruch mit Meldung statt
  unbegrenztem Speicher).
- **Freigaben:** offene Anträge sind je Benutzer und insgesamt begrenzt; abgelaufene
  Anträge und Restore-Pläne geben ihre Daten frei.
- **Audit:** Daten werden vor dem Speichern maskiert (auch escaptes JSON, URL-kodierte
  und verschleierte Namen); Dedup-Fenster begrenzt; die Option „Konfigurations-Backup“
  wird beim Umschalten auditiert; die Diagnose zeigt Benutzer-IDs nur pseudonym.
- **Speicher:** der Startup-Sweep folgt keinen Links/Junctions; ein ersetzter
  Installations-Schlüssel meldet einen Reparaturhinweis; feindliches ACL-JSON vom
  Router (zu groß, zu tief) wird gezählt statt zu werfen; Backup-Namen kollidieren
  nicht mehr.

### Fixed (Enterprise Core)

- setup_retry fegt den Speicher nicht bei jedem Versuch neu; die Freigabe schreibt nur
  geänderte Stores.
- Ein defekter Store unter echtem HA (umbenannt zu `.corrupt.*`) gilt als
  fehlgeschlagenes Laden; Versionsdateien bleiben liegen, solange der Index
  wiederhergestellt wurde.
- `backup_recovered` auch nach einem deduplizierten Erfolg und nach einem Neustart.
- Capabilities: bekannt → unbekannt → anders bekannt meldet die Änderung.
- Einrichtung: wurde die ACL nicht geschrieben, nennt der Fehler den Grund (gestufte
  ACL behalten / ACL nicht lesbar / schon aktuell).

## [1.43.1] - 2026-11-17

Reine Panel-Korrekturen am Tab *Diagnose → Stabilität*; keine neuen
Router-Abfragen, Entitäten und Sensorwerte unverändert.

### Fixed

- **Deutsche Zahlen im ganzen Tab.** Alle Zahlen (Liste, Detail,
  AP-Vergleich, Einstellungen, Empfehlungen) laufen über eine Hilfsfunktion
  mit Dezimalkomma: aus „5.404 Abbrüche“ wird „5,4 Abbrüche/100 h“, aus
  „Speicher: 0.11 MB“ wird „0,11 MB“. Raten haben eine Nachkommastelle und
  die Einheit „/100 h“, Signal ganze dBm, Zähler ganze Zahlen.
- **AP-Vergleich in Rangfolge.** Die Liste kam nach interner AP-Kennung
  sortiert, die Rangnummer zählt aber nach den wenigsten Abbrüchen je
  100 Client-Stunden; die Liste folgt jetzt dem Rang. APs mit zu wenig Daten
  (unter 10 Client-Stunden) stehen danach, nach Namen sortiert, mit „–“.
- **Einstellungen:** Score-Gewichte und Klassengrenzen überlappen am Desktop
  nicht mehr; jedes Feld steht unter seiner Beschriftung in seiner Zelle.
- **Client-Liste:** Kopfzeile am Desktop (Name, Access Point, Zustand,
  Score, Verfügbarkeit 24 h / 7 Tage, Reconnects 24 h, letztes Problem,
  Datenabdeckung, Trend) und eine eigene Trend-Spalte aus denselben Werten
  wie die Trend-Sortierung, mit Text für Screenreader; „–“ heißt zu wenig
  Daten. Das letzte Problem wird bei Platzmangel mit „…“ gekürzt (voller
  Text im Tooltip) und überlappt die Nachbarspalte nicht mehr.
- **Schmale Liste:** die Client-Liste wechselt nach ihrer eigenen Breite
  (unter 820 px) zu Karten, auch bei offener HA-Seitenleiste oder halbem
  Browserfenster.
- **Reconnects ohne Abbrüche** sind kein Widerspruch: das Detail sagt jetzt
  neben der Zahl, dass Reconnects aus dem Router-Log stammen und kurze
  Neuanmeldungen keine Sitzung beenden.
- **Handy:** unter 760 px liegen die sechs Filter hinter einem
  „Filter“-Knopf (zeigt, wie viele gesetzt sind); unter 420 px wird die
  Seitennavigation zur Leiste unten, damit *Diagnose* erreichbar bleibt.

## [1.43.0] - 2026-11-17

### Added

- **Alle Kennzahlen im Client-Detail.** Je Zeitraum jetzt auch beobachtete
  Zeit und Messlücken, Abbrüche je Klasse, Signal Ø / Min / Max, mittlere
  TX-/RX-Rate, fehlgeschlagene Anmeldung, Assoziierung und DHCP getrennt,
  Grund des letzten Abbruchs, Roaming rein und raus, **mittlere
  Sitzungsdauer** und der *Anteil der Messpunkte mit bekannter IP*. Ein Satz
  unter den Zahlen sagt, dass Verfügbarkeit die beobachtete WLAN-Anmeldung
  ist, keine Ende-zu-Ende-Erreichbarkeit.
- **Auffällige Ereignisse:** eine Zahl je Zeitraum aus Abbrüchen mit Fehler
  oder ohne Grund, Flattern und fehlgeschlagener Anmeldung, Assoziierung und
  DHCP (Definition in `docs/client-stability.md`).
- **Echte letzte 60 Minuten.** Das 1-h-Fenster ist jetzt die tatsächliche
  letzte Stunde statt der angebrochenen Uhrstunde. Nach einem Neustart sagt
  das Panel *keine Daten seit Neustart* oder *Signal- und Log-Werte erst seit …*.
- **Grober Verlauf für 7 und 30 Tage:** je Stunde bzw. Tag die Anteile
  online, offline, Messlücke (schraffiert) und unbekannt, nie als offline
  dargestellt, mit Abbruch-Markern je Abschnitt; Hinweis *genaue Zeitpunkte
  nur für 24 h*.
- **Diagramm Abbrüche und Reconnects** als echte Balken (1 h je 5 min,
  sonst je Stunde bzw. Tag).
- **Diagramm „AP-Wechsel/Roaming“:** farbiger Streifen je Access Point und
  Band, Marker für Wechsel und Flattern, Legende mit AP-Namen.
- **Tabelle:** Sortierung nach Access Point, Verfügbarkeit 7 Tage, Trend und
  Verfügbarkeit absteigend; die Spalte *letztes Problem* zeigt auch
  fehlgeschlagene Anmeldung, Assoziierung und DHCP.
- **AP-Vergleich** zeigt zusätzlich Anmeldefehler und Roaming rein/raus je
  100 Client-Stunden, den Anteil schwachen Signals und die Clients mit
  Infrastruktur-Abbrüchen.
- **Score-Gewichte und Klassengrenzen im Panel** (*Einstellungen*, nur
  Admins): Gewichte 0–100, mindestens eines über 0, Grenzen streng
  absteigend, Knopf für die Standardwerte.
- Die letzte SSID je Client wird gespeichert (höchstens 32 Zeichen); der
  SSID-Filter funktioniert damit auch nach einem Neustart.

### Changed

- Die Empfehlung *WLAN-Abdeckung prüfen* kommt jetzt ab **4** statt 10
  Problem-Abbrüchen je 24 h (bei mindestens 30 % schwachem Signal).
- Das 24-h-Fenster bleibt an Stunden ausgerichtet (23 volle Stunden plus die
  laufende); die Antwort nennt den wirklichen Beginn (`stats.start`).
- In der 24-h-Zeitleiste wird die Zeit vor dem ersten gespeicherten
  Verbindungswechsel jetzt aus diesem Wechsel oder dem aktuellen Zustand
  abgeleitet, statt als unbekannt zu erscheinen. Eine Messlücke bleibt
  Messlücke, auch wenn ein Abbruch auf ihren Beginn zurückdatiert wird.
- Direkt nach einem Neustart zählen Reconnects, Anmeldung und Roaming im
  1-h-Score nur anteilig (das Ereignis-Gedächtnis beginnt beim Laden); in
  den ersten 18 Minuten fallen sie ganz heraus.
- Ein Client mit wechselnder privater MAC bleibt je MAC ein eigener Client;
  das ist jetzt getestet und dokumentiert.
- **Last** (Entwickler-PC): je Poll unverändert (1000 Clients, bester Lauf
  etwa 9 ms, wie 1.42.0). Die Speicherdatei wächst um etwa 30–35 Byte je
  Client für die SSID (1000 Clients: 735 kB → 770 kB). Sortieren nach
  7-Tage-Verfügbarkeit oder Trend kostet bei 150 Clients × 30 Tage
  0,33–0,37 s beim ersten Abruf je Stunde, danach etwa 0,05 s. Das
  Panel-Bundle wächst um 12,2 kB.
- Gespeicherte Daten von 1.42.0 werden ohne Verlust gelesen; 1.42.0 liest
  auch Dateien von 1.43.0 (Rückweg möglich). Entity-IDs bleiben gleich.

## [1.42.0] - 2026-11-17

### Added

- **Client-Stabilität (Beta).** Eine Langzeit-Historie je WLAN-Client: wie
  stabil ist das Gerät, seit wann, an welchem AP, und liegt es am Gerät oder
  am Netz? **Keine zusätzlichen Router-Aufrufe:** keine neue ubus-Abfrage,
  kein SSH, kein Datei-Lesen oder -Ausführen, **keine ACL-Änderung**. Die
  Daten kommen aus den Client-Listen und Logzeilen, die die Network
  Intelligence nach jedem Poll ohnehin auswertet. Ausführlich in
  `docs/client-stability.md`.
- **Zustand mit Toleranz.** Je MAC `online`, `grace`, `offline` oder
  `unknown`. Normales Roaming ist kein Abbruch, ein kurzes Fehlen auch nicht
  (offline erst nach 2 Polls und mindestens 150 s in keiner Liste). Ein
  AP-Ausfall oder eine Poll-Lücke ist Messlücke, nie offline. Jeder Abbruch
  bekommt eine Klasse aus dem Log-Grund (`error`, `inactivity`, `leave`,
  `unknown`, `infra`); Abbrüche während einer Network-Intelligence-Wurzel
  am Router des Clients zählen als `infra` und lösen **keinen eigenen
  Alarm** aus. Bei Port-Wurzeln (Uplink aus, Port-Flap) gilt das nur für die
  Router, deren Abbrüche die Network Intelligence damit verknüpft hat (hinter
  dem Port, oder der Besitzer bei Flap seines eigenen Uplink-Ports), nie für
  das Gateway bei einem flatternden WAN-Port. Ein Kanalwechsel markiert
  300 s lang den ganzen Router, nicht nur das betroffene Radio.
- **Stabilitäts-Score** 0–100 aus sieben Teilen (Abbrüche 30, Reconnects 15,
  Sitzungsdauer 15, Signal 20, Anmeldung 10, Roaming 5, wiederkehrende
  Muster 5) mit Klassen *sehr stabil* bis *kritisch*. Bei zu wenig Daten
  ist der Score unbekannt, nie 100. Clients können als *schlafend*
  markiert werden (Inaktivität kostet dann nichts).
- **Muster und Empfehlungen:** Abbrüche zur selben Tageszeit, schlechter
  werdendes Signal, Probleme nur an einem AP; Empfehlungen als
  Beobachtung, Hypothese oder bestätigt, immer mit den Messwerten. Nur Text,
  keine Aktion am Router.
- **AP-Vergleich** je Router und Band über 24 h / 7 d / 30 d, alle Werte je
  100 Client-Stunden.
- **Tab „Stabilität“** unter *Diagnose* im Topologie-Panel: Client-Tabelle mit
  Filtern, Detail mit Zeitleiste, Signal- und Verfügbarkeitsverlauf
  (1 h bis 30 d), AP-Vergleich und Einstellungen. Lädt nur bei offenem Tab,
  höchstens alle 60 s.
- **Sensoren nur für ausgewählte Clients** (höchstens 25, im Detail wählbar):
  Stabilitäts-Score und Verbindungsqualität (an), Reconnects 24 h,
  Verbindungsdauer und letzter Abbruch (aus). Ohne Auswahl entstehen keine
  Entities.
- API-Routen `/api/openwrt_topology/intelligence/clients`, `clients/{mac}`,
  `clients/aps` und `clients/settings` (gleiche Zugriffsregeln wie die
  Network-Intelligence-Routen, Ändern nur für Admins).
- Diagnose-Download: Abschnitt `client_stability` nur mit Zahlen (Clients je
  Zustand, Speichergröße, gekürzte Einträge), ohne MAC, IP oder Hostname.

### Changed

- **Zusätzliche Last in Home Assistant** (gemessen auf einem Entwickler-PC):
  je Poll und Router ein Durchlauf über Client-Liste und neue Logzeilen,
  bei 1000 Clients unter 20 ms (bester Lauf 9 ms). Eine neue Datei
  `.storage/openwrt_router.client_history`, Standardgrenze 3 MB (1–8 MB
  einstellbar), geschrieben höchstens alle 300 s; 150 Clients × 30 Tage, alle
  immer online, ergeben 2,5 MB, das Schreiben dauert dann etwa 22 ms. Das
  Panel kostet nur bei offenem Tab: bei 150 Clients die Tabelle 0,26 s beim
  ersten Abruf je Stunde, danach 0,11 s. An der Grenze von 1000 Clients
  blockiert der erste Tabellenabruf je Stunde den Event-Loop etwa 1,4 s,
  der AP-Vergleich 0,65–0,85 s, das erste Speichern mit Kürzen etwa 0,5 s.
  Das Panel-Bundle wächst um 28,9 kB.
- Die Reconnect-Zählung des v1.36-Sensors `unstable_clients` (Verbinden
  innerhalb von 300 s nach einer Trennung am selben Router) bleibt unverändert; die Stabilitätsansicht zählt nur
  Reconnect-Ereignisse aus dem Router-Log. Beide Zahlen können sich
  unterscheiden.

## [1.41.0] - 2026-11-17

### Added

- **WLAN-Ereignisse fast in Echtzeit (Weg D).** Das Router-Log wird jetzt bei
  jedem Poll gelesen statt bei jedem zweiten; WLAN-Ereignisse erreichen die
  Network Intelligence höchstens einen Poll später (Standard 60 s). Kein
  Push-Stream, keine neue Art von Router-Aufrufen, **keine ACL-Änderung**
  (`log read` aus ACL v6 genügt). Weil `log read` jetzt jeden Poll läuft statt
  jeden zweiten, kommt je Router etwa ein ubus-Aufruf alle zwei Polls dazu;
  auf ruhigen Routern verdoppelt sich die gelesene Log-Menge ungefähr.
  Ausführlich in `docs/realtime-rca.md`.
- **Trennungsgründe.** Jede WLAN-Logzeile trägt die Kategorie ihres
  802.11-Reason-Codes (`radio`, `security`, `ap`, `inactivity`, `client`,
  `unknown`) und den Code. Trennungen der Kategorien `radio` (zum Beispiel
  „missing ACKs“) und `security` werden mit möglichen Ursachen als Ereignis
  gespeichert; Reconnect-Stürme nennen die gesehenen Kategorien.
- **Ursachenstufe `cause_level`:** `confirmed`, `likely`, `possible` oder
  `unknown`. *Wahrscheinlich* nur mit Konfidenz ≥ 0,7 **und** mindestens zwei
  unabhängigen Quellen (Log, Poll, usteer, Topologie, Flotte, Nachbar-Clients,
  Wurzel-Verknüpfung); eine Quelle allein ist höchstens *möglich*. Die Stufe
  wird abgeleitet, nicht gespeichert. Neu im HA-Event
  `openwrt_router_incident_event` (Feld `cause_level`), in der Incident-API
  und im Diagnose-Download (`active_by_cause_level`).
- **Port-Flap als Wurzel.** Ein flatternder Uplink-Port (`lan_port_flap`)
  erklärt die Abbrüche der APs dahinter: Massen-Trennungen,
  Reconnect-Stürme, Clients ohne IP und DHCP-Fehler nach dem Verbinden.
  Anmeldefehler, Band- und Roaming-Flattern erklärt er nicht; sie bleiben
  eigene Incidents und melden sich weiter. Flattert der Port eines
  Nachbar-Routers, ist die Ursache nur über einen per LLDP gesehenen Pfad
  bestätigt, sonst Hypothese. Flattert der eigene Uplink-Port eines APs,
  gelten die Abbrüche an diesem AP immer als bestätigt, auch wenn sein Uplink
  nur abgeleitet ist (die Messung liegt am selben Router); für Router hinter
  ihm gilt wieder die LLDP-Regel. Ein Port, der lange flattert, erklärt nur
  Abbrüche nahe an einem seiner Flaps (je ±60 s). Ein Uplink-Ausfall darüber
  bleibt die Wurzel.
- **Vergleich mit den Nachbar-Clients.** Ein Client mit Reconnects wird mit
  den anderen Clients am selben Radio verglichen. Bleiben mindestens drei
  davon ruhig, steht `client_side` (das Gerät selbst) vorne und die
  Stromversorgung des APs fällt aus der Liste.
- **Empfehlung je Ursache.** Die Incident-API liefert `recommendation_key`
  (`rec_<ursache>`); das Panel zeigt den deutschen Text, die englischen Texte
  stehen in `docs/realtime-rca.md`. Nur Text, keine Aktion am Router.
- **Log-Alter im Diagnose-Tab.** Je Router „Log vor 40 s“, „Log: kein
  Leserecht“ oder der Fehler mit dem Zeitpunkt des letzten guten Lesens
  (`summary` liefert dafür `log` je Router).
- **Log-Lücke nach Lesefehlern.** Kann das Log nach Fehlern wieder gelesen
  werden und meldet der Router verlorene Zeilen, entsteht genau ein
  `system.log_gap`-Ereignis mit `gap_s` und `missed`.
- Szenario-Suite `tests/test_net_rt_scenarios.py` und
  `tests/test_net_rt_log.py`: alle zwölf Szenarien des Plans mit Testnamen
  belegt.

### Changed

- usteer wird in eigenem Rhythmus jeden zweiten Poll ab Poll 3 gelesen
  (`USTEER_READ_INTERVAL_CYCLES = 2`); vorher lief es nur in Polls ohne
  Log-Lesen und wäre mit dem Log bei jedem Poll still ausgefallen.
- „Wahrscheinlich“ verlangt jetzt zwei unabhängige Quellen; ein Incident, der
  bisher als *wahrscheinlich* galt, kann als *möglich* erscheinen.

## [1.40.0] - 2026-11-16

### Added

- **Network Intelligence (Beta).** Aus den Daten, die die Integration ohnehin
  abfragt, entstehen Ereignisse, Incidents mit Ursache und ein Health-Score je
  Router und für die ganze Flotte. **Keine zusätzlichen Router-Aufrufe:** keine
  neuen ubus-Abfragen, keine SSH-Kommandos, keine ACL-Änderung (ACL bleibt v8).
  Ausführlich in `docs/network-intelligence.md`, Überblick im README.
- **Ereignisse.** Neue Logzeilen (WLAN, DHCP, DFS, System) und Änderungen
  zwischen zwei Polls (Port-Link, WAN, Neustart, CPU …) werden zu Ereignissen
  mit Kategorie, Schweregrad und Herkunft (`observed` gemessen, `inferred`
  abgeleitet). Je Router merkt sich die Engine die Log-Position: Zeilen aus der
  Lücke nach einem Neustart werden nachgeholt, mögliche Verluste meldet ein
  `system.log_gap`-Ereignis.
- **Infrastruktur-Incidents:** `router_unreachable`, `lan_unreachable` (alle
  Router zugleich weg), `system_reboot`, `system_cpu_high`, `system_ram_high`,
  `system_service_restart` (dnsmasq, odhcpd, wpad, hostapd, network),
  `system_clock_skew`, `system_conntrack_jump`, `lan_port_flap`,
  `lan_port_speed_drop`, `lan_port_errors`, `lan_port_load`, `lan_uplink_down`,
  `lan_lldp_change`, `wan_down`, `wan_unstable`, `wan_ip_changed` (WAN nur am
  WAN-Gateway), `dhcp_pool_full`, `dhcp_conflict`.
- **WLAN-Incidents:** `wifi_reconnect_storm`, `wifi_auth_failures`,
  `wifi_auth_wave` (flottenweit, verschiedene Clients), `wifi_mass_disconnect`,
  `wifi_no_ip`, `wifi_dhcp_after_connect`, `wifi_band_flapping`,
  `wifi_roam_flapping`, `wifi_weak_clients`, `wifi_radio_change` (DFS, neuer
  Kanal, CAC-Fehler).
- **Alarmlogik je Incident-Typ:** Debounce, Hysterese, Cooldown mit
  Wiederöffnen (`reopen_count`), Auto-Resolve nach 1800 s ohne neue Belege,
  Status `active`, `resolved`, `acknowledged`, `ignored` (Standard 7 Tage).
- **Root-Cause und Korrelation.** Aus LLDP und der Trunk-Port-Zuordnung
  entsteht ein Router-Baum; Folgeprobleme werden ihrer Wurzel
  (`lan_unreachable`, `router_unreachable`, `system_reboot`, `wan_down`,
  `wifi_radio_change`, `lan_uplink_down`, `wifi_mass_disconnect`) als Kinder
  zugeordnet. Jede Ursache trägt `cause_status`: `confirmed` nur bei
  Messdaten, sonst `hypothesis`; eine Verknüpfung über eine abgeleitete
  Topologie-Kante hat höchstens Konfidenz 0,6.
- **Health-Score** 0–100 je Router über fünf Bereiche (WLAN 30, System 25,
  LAN 15, WAN 20, DHCP/DNS 10) mit Abdeckung; unter 50 % Abdeckung
  `unknown`, nie 100 bei fehlenden Daten. Flotten-Score nach Abdeckung
  gewichtet.
- **Neue Entities je Router:** *Network health* (`{entry_id}_net_health`),
  *Active incidents* (`_incidents_active`), *Wi-Fi reconnects (1 h)*
  (`_wifi_reconnects_1h`) und *Wi-Fi authentication errors (1 h)*
  (`_wifi_auth_errors_1h`, beide nur mit AP-Interfaces), *WAN reconnects
  (24 h)* (`_wan_stability`, ohne WAN standardmäßig aus), Binärsensor
  *Critical incident* (`_incident_critical`), Schalter *Maintenance mode*
  (`_maintenance_mode`). **Flotte** (ohne Gerät, einmal je HA-Instanz):
  `openwrt_router_fleet_net_health`, `openwrt_router_fleet_incidents_active`,
  `openwrt_router_fleet_incident_critical`.
- **HA-Event `openwrt_router_incident_event`** genau einmal je Wurzel-Incident
  und Zustand (`opened` nach 90 s Settle-Zeit, `reopened`, `resolved`), ab
  `warning` (einstellbar), nie für Kinder. Felder `state`, `incident_id`,
  `type`, `severity`, `confidence`, `cause`, `cause_status`, `scope`,
  `routers`, `entry_ids`, `device_id`, bei Client-Incidents `mac`. Logbook-Text
  für das Event.
- **Wartungsmodus** je Router (Schalter) und für die Flotte (1/4/24 h im
  Panel): Ereignisse werden markiert gespeichert, keine Incidents, keine
  HA-Events, kein Score-Abzug, keine Nachzügler-Alarme.
- **Tab „Diagnose“ im Topologie-Panel:** Übersicht, Incidents (mit
  Folgeproblemen, Belegen, Ursachenstufe und Empfehlung), Timeline mit Filtern
  (Router, Kategorie, Schweregrad, Zeitraum), WLAN, Infrastruktur,
  Einstellungen. Warnsymbole an den Router-Knoten der Topologie öffnen die
  Diagnose des Routers, auch am Handy. Bestätigen, Ignorieren und Reaktivieren
  nur als Admin.
- **API-Routen** unter `/api/openwrt_topology/intelligence/`: `summary`,
  `events`, `incidents`, `incidents/{incident_id}` (GET, POST Status) und
  `settings` (GET, POST). Lesen wie der Topologie-Snapshot, Schreiben nur
  Admin.
- **Einstellungen** (Schwellen, Gewichte, Strafpunkte, Ausnahmen für MACs,
  SSIDs, Router und Incident-Typen, Aufbewahrung, Ereignis-Limit,
  `notify_min_severity`): im Panel lesbar, ändern nur Admins; streng geprüft
  (Listen höchstens 200 Einträge zu 64 Zeichen).
- **Persistenz über HA-Neustarts:** eine Store-Datei für alle Router
  (`.storage/openwrt_router.intelligence`), Schreiben höchstens alle 300 s,
  Obergrenze 1,5 MB (älteste Ereignisse zuerst gekappt), Standard 30 Tage und
  3000 Ereignisse. Eine unlesbare Datei wird vorher nach
  `openwrt_router.intelligence.bak` kopiert. Beim Entfernen eines Routers
  werden seine Daten gelöscht.
- **Diagnose-Download** um einen Abschnitt `intelligence` ergänzt: nur
  Zähler, Typen, Zeiten, Score, Abdeckung und Wartungsmodus, keine MAC, IP,
  Hostnamen, SSIDs oder Routernamen.

### Changed

- **Topologie-Panel zeigt veraltete Daten an.** Clients und Verbindungen eines
  Routers, der beim letzten Abruf nicht erreichbar war, erscheinen ausgegraut
  mit dem Hinweis „Daten veraltet – Router nicht erreichbar“.
- **Parallele LLDP-Verbindungen sichtbar.** Sieht LLDP zwischen zwei Routern
  mehrere Links, zeigt die AP-Karte ein „N×“-Abzeichen; Detailansicht und
  Tooltip nennen die weiteren Ports.
- **Gateway-Wahl bei mehreren oder keinem Gateway.** Das Panel nimmt nicht mehr
  den ersten Router der Liste, sondern bevorzugt erreichbare Gateways mit
  verbundenem WAN, dann die kleinste Router-ID. Alle anderen Router bleiben als
  AP sichtbar.
- **Topologie-Snapshot:** Router-Knoten tragen `entry_id` und `incidents`
  (gezählte Wurzel-Incidents nach Schweregrad), `meta.intelligence` den
  Flotten-Score und die Abdeckung. Ohne laufende Engine bleibt der Snapshot
  wie bisher.
- **Entladen eines Router-Eintrags:** Die Flotten-Entities ziehen zu Beginn
  des Entladens zum nächsten Router-Eintrag um und behalten ihre Entity-IDs.
- Der Tab „Alarme“ bleibt vorerst neben „Diagnose“ bestehen.

### Fixed

Vor dem ersten Release in den Reviews der Network Intelligence gefunden und
behoben:

- Ein Router hinter einem ausgefallenen Router wird nur dann als dessen
  Folgeproblem geführt, wenn er zur selben Zeit selbst ausfällt; ein
  erreichbarer Router widerlegt die Verknüpfung.
- Ein Folgeproblem, das nach dem Ende seiner Wurzel offen bleibt, zählt nach
  deren Nachfenster wieder selbst (Score, Zähler, HA-Event) statt bis zu einer
  Stunde unsichtbar zu bleiben, aber nur mit eigenen neuen Belegen nach dem
  Nachfenster. Ohne neue Belege bleibt es still, bis es sich selbst auflöst;
  es meldet sich also nicht mehr als „neu“ mit der Ursache einer längst
  behobenen Wurzel. Nach einer weiteren Stunde wird es von der Wurzel gelöst.
- Wird ein ausgefallener Router neu geladen, bleiben die Router hinter ihm
  still, bis sie nach einer Stunde von ihm gelöst werden, statt wenige Minuten
  später als neue Probleme gemeldet zu werden.
- MAC-Ausnahmen mit Bindestrichen (`02-00-5e-10-00-01`) wirken jetzt; MACs
  werden einheitlich als `02:00:5E:10:00:01` gespeichert, auch bereits
  gespeicherte Einstellungen.
- Flotten-Incidents (`wifi_auth_wave`, `lan_unreachable`) senken jetzt den
  Flotten-Score; die Router-Scores bleiben unberührt.
- Ignorieren eines gemeldeten Incidents sendet `resolved` mit
  `reason: ignored`, damit Automationen, die auf das Ende warten, nicht hängen
  bleiben. Das Event hat dafür das neue Feld `reason`.
- Die Dauer eines ignorierten Incidents endet, sobald sein Zustand vorbei ist,
  statt weiterzuwachsen.
- Die Fehlermeldung der Ereignis-Abfrage bei einer unbekannten Kategorie nennt
  die erlaubten Werte wieder.
- Diagnose-Panel: Ein Folgeproblem, das wieder selbst zählt, steht nicht mehr
  eingerückt unter seiner früheren Wurzel.
- Entladen oder Neuladen eines Routers löst seinen offenen Ausfall still auf
  (kein `resolved`-Event, kein Logbook-Eintrag).
- Flotten-Incidents (`lan_unreachable`, `wifi_auth_wave`) zählen nur in den
  Flotten-Entities, nicht zusätzlich je Router.
- Kein Health-Score 100 mehr bei unlesbarem Router-Log: der WLAN-Bereich
  zählt nur mit lesbarem Log, eine leere Client-Liste oder leere
  Speicherwerte gelten nicht als Messung.
- Ein Router mit Anmeldefehler oder einem längst gemeldeten Ausfall hält
  HA-Events nicht mehr bis zu 900 s zurück.
- Der Wartungsschalter übernimmt nach einem Neustart nur `on`/`off`;
  `unavailable` schaltet den Wartungsmodus nicht mehr aus.
- `reopened` kommt nur nach einem vorherigen `opened`; sonst wird `opened`
  gemeldet.
- Eine eigene, gleichnamige Ursache eines Kindes geht beim Lösen von der
  Wurzel nicht mehr verloren (geerbte Ursache ist jetzt ausdrücklich
  markiert).
- WLAN-Erkennung: Reconnect nur bei Down → Up innerhalb 30 s, ein DHCPNAK mit
  folgendem ACK binnen 30 s ist kein Fehler, Massen-Disconnects nur aus einem
  engen Zeitfenster, Auth-Welle zählt verschiedene Clients, MAC-Ausnahmen
  gelten in allen WLAN-Detektoren.
- Korrelation: Ein Funkwechsel erklärt einen Massen-Disconnect nur auf
  demselben Radio als bestätigt (sonst Hypothese); vor einem Ausfall gelten nur
  Client- und WLAN-Probleme des Routers als Folge; gemerkte Topologie-Kanten
  verfallen nach 24 h; schnellere Berechnung bei vielen Incidents.

### Removed

- Dev-Skript `scripts/_add_topology_card.py` (las das in 1.39.0 entfernte
  Attribut `topology_snapshot`).

## [1.39.0] - 2026-10-28

### Security

- **Diagnostics redigieren persönliche und Netzwerkdaten nach HA-Konvention.**
  Bisher entfernte der Diagnose-Download nur Schlüssel, die nach Geheimnis
  klangen (`password`, `token`, `key` …). Host und Benutzername des Routers,
  sein Hostname und seine MAC, die WAN-IP, alle SSIDs und BSSIDs, die
  Interface-IPs, DDNS-Domains und -IPs sowie die komplette Client-Liste mit
  MAC, IP, Hostname und Web-URL jedes Geräts landeten im Klartext in einer
  Datei, die für Bug-Reports gedacht ist. Jetzt läuft zuerst
  `async_redact_data` über eine feste Liste exakter Schlüssel (`host`,
  `username`, `hostname`, `mac`, `bssid`, `ssid`, `ssids`, `ip`, `ipv4`,
  `ipv4_addr`, `ipv4_address`, `address`, `domain`, `web_url`, `chassis_id`,
  `management_ip`, `router`), danach wie bisher der Teilstring-Filter für
  Geheimnisse. Der Titel des Eintrags, standardmäßig der Router-Hostname
  oder der Host, wird ebenfalls redigiert, auch im letzten DFS-Ereignis.
  Bei LLDP-Nachbarn werden der Name und eine Port-ID, die eine MAC ist,
  redigiert. Die Client-Liste wird zu Anzahl, Anzahl je Verbindungsart und
  Minimum/Maximum/Mittel des Signals; die Listen `sticky`, `weak` und
  `unstable` der Client-Stabilität werden zu Zählern. Werte, die zur
  Fehlersuche gebraucht werden (Interface-Namen, Protokoll, Verbindungsstatus,
  Modell, Feature-Flags, Ports), bleiben lesbar.
- **Topologie-Panel und Snapshot-API standardmäßig nur für Administratoren.**
  Bisher sah jeder HA-Benutzer das Panel „Network Topology“, und die API
  `/api/openwrt_topology/snapshot` lieferte jedem angemeldeten Benutzer
  DHCP-Leases, ARP- und FDB-Tabellen pro Port, WAN-IP, DDNS-Angaben und
  Web-URLs der Geräte. Jetzt ist das Panel nur für Administratoren
  registriert, und die API antwortet Nicht-Administratoren mit HTTP 403. Die
  neue Option **„Topologie-Panel allen Benutzern anzeigen“** (Integration →
  Konfigurieren, Standard aus) gibt beides wieder für alle frei. Es gibt nur
  ein Panel für alle Router: Es ist für alle offen, sobald ein geladener
  Router-Eintrag die Option aktiviert hat. Die Freigabe wird beim Laden und
  Entladen eines Eintrags und bei jeder Options-Änderung neu bewertet, ohne
  Neustart; das Panel wird nur neu registriert, wenn sich der Kreis
  tatsächlich ändert. Die Einschränkung gilt nur für das Topologie-Panel und
  die Snapshot-API: Entitätszustände (z. B. Device Tracker mit IP und
  Hostname, Sensoren) bleiben wie in HA üblich für alle Benutzer sichtbar.

### Fixed

- **Fehler beim Aufbau des Topologie-Snapshots werden nicht mehr als leere
  Topologie getarnt.** Die API lieferte bei einem Fehler HTTP 200 mit einer
  leeren Topologie, die wie „alle Router weg“ aussah. Jetzt kommt HTTP 500
  mit einer kurzen Meldung in `meta.error` (nur der Fehlertyp, kein
  Stacktrace, keine Router-Daten). Das Panel meldet bei 0 Routern oder einem
  Fehler keinen kritischen Alarm „WAN offline“ mehr und zeigt statt „No
  routers online“ den Fehler an.
- **Panel lädt nach abgelaufener Sitzung nicht mehr in einer Schleife neu.**
  Nach einem 401 setzte jeder `hass`-Update die Sperre zurück und löste sofort
  die nächste Anfrage aus. Jetzt erneuert das Panel ein abgelaufenes Token
  vor der Anfrage und versucht es nach einem 401 genau einmal erneut (neues
  Token bzw. über `callApi`); erst danach ruht es, bis HA ein neues Token
  liefert oder der Tab wieder sichtbar wird. 401 und 403 werden auch im `callApi`-Fallback erkannt; bei 403
  erklärt das Panel, dass die Topologie Administratoren vorbehalten ist. Ein
  vorübergehender Fehler ersetzt nicht mehr die zuletzt geladene Ansicht —
  sie bleibt stehen, ein kleiner Hinweis oben rechts zeigt den Fehler.
- **Ein Fehler bei der Panel-Registrierung lässt den Eintrag nicht mehr im
  Zustand „Setup-Fehler“ mit geladenen Plattformen zurück.** Panel und
  Lovelace-Karten-Ressource werden nach den Plattformen eingerichtet; ein
  Fehler dort wird jetzt als Warnung geloggt, der Router-Eintrag lädt
  trotzdem. Entlädt sich ein solcher Eintrag, zählt er den Panel-Referenzzähler
  nicht mehr herunter (vorher konnte das das Panel der anderen Router
  entfernen).
- **Geräte-Tracker bleiben bei Ausfall eines einzelnen Routers und nach einem
  Neustart verlässlich.** Bisher wurden WLAN-Clients „nicht verfügbar“, sobald
  der Router, dem ihr Tracker gehört (etwa ein neu startender AP), nicht
  antwortete, auch wenn sie an einem anderen AP hingen; Personen standen dann
  auf „unbekannt“. Nach einem HA-Neustart blieben abwesende Clients „nicht
  verfügbar“ statt „abwesend“, und der Name sprang auf die MAC-Adresse. Jetzt
  bleibt ein Tracker verfügbar, solange irgendein Router antwortet. Ein
  einzelner Poll-Fehler ändert nichts; fällt ein Router länger aus (3 Polls
  oder 5 Minuten), zählen seine alten Client-Daten nicht mehr. Bekannte
  Clients werden beim Start aus der Entitäten-Registry angelegt und melden
  „abwesend“, deaktivierte Tracker ausgenommen; der letzte bekannte Hostname
  bleibt als Name erhalten. Einen veralteten Tracker entfernt man, indem man
  ihn erst deaktiviert und dann löscht.
- **Topologie bei WAN-Ausfall, Offline-Routern und gleichnamigen Routern
  richtig.** Bisher wurde das Gateway bei einem WAN-Ausfall zum AP: Das Panel
  zeigte keine Verbindungen und keine WAN-, Ping- oder DDNS-Daten, genau
  während der Störung. Jetzt behält das zuletzt verbundene Gateway seine Rolle
  während des Ausfalls; startet HA mitten im Ausfall, gewinnt genau ein Router
  mit eingerichtetem Uplink (ein von Hand gesetztes Protokoll wie PPPoE,
  statisch oder Mobilfunk vor dem OpenWrt-Standard `dhcp`). Ein Dumb-AP mit
  übrig gebliebenem WAN-Eintrag wird nicht zum Gateway, und ein Router im
  SSH-Fallback zählt nur, wenn kein anderer Router ein verbundenes WAN meldet.
  Clients und Kanten eines nicht erreichbaren Routers sind als veraltet
  (`stale`) markiert und landen nicht mehr wegen eines alten, besseren Signals
  bei ihm. Router mit gleichem Hostnamen (etwa dreimal „OpenWrt“) erkennt LLDP
  jetzt über die MAC; doppelte LLDP-Beobachtungen desselben Paars bleiben
  stabil und stehen in `lldp_duplicates`. Bei mehreren Gateways bekommt jedes
  seine WAN-Daten, und ein AP hängt nur noch an einem davon.
- **„Nach Updates suchen“ funktioniert jetzt, mit apk und opkg.** Bisher
  meldete der Button nur scheinbar Erfolg, und der Sensor „Update-Status“
  stand immer auf „aktuell“, weil nie eine Paketliste geholt wurde. Jetzt
  fragt der Button per SSH den Paketmanager des Routers ab (apk ab OpenWrt 25,
  sonst opkg), und zwar nur beim Drücken, nie im Poll. Der Sensor zeigt danach
  Anzahl, Paketliste mit installierter und verfügbarer Version und den
  Zeitpunkt der Prüfung; vor der ersten Prüfung steht er auf „unbekannt“.
  Zeitüberschreitung, verweigerter SSH-Login, fehlender Paketmanager oder eine
  noch laufende Prüfung erscheinen als Fehlermeldung in HA. Die rpcd-ACL
  bleibt unverändert.
- **Poll-Versatz und Intervall korrigiert.** Mehrere Router pollten trotz
  Versatz zur selben Zeit, weil jeder Eintrag denselben Versatz bekam; ein
  Schalter konnte kurz nach dem Start bis zu 45 s auf seine Aktualisierung
  warten; und nach einer ACL-Reparatur blieb das 5-Minuten-Intervall des
  SSH-Fallbacks bis zum Neuladen stehen. Jetzt hat jeder Router einen eigenen
  Zeitpunkt, angeforderte Aktualisierungen laufen sofort, und das Intervall
  (60 s, 120 s bei hoher CPU-Last, 300 s im SSH-Fallback) wird bei jedem Poll
  neu bestimmt. Unerwartete Fehler zählen jetzt für die Ausfallmeldung.
- **Schnittstellen-Traffic zeigt echte Werte.** RX/TX-Bytes und -Raten der
  Schnittstellen standen immer auf 0, weil die Abfrage keine Zähler liefert.
  Sie kommen jetzt aus `network.device status`, demselben Aufruf, den die
  Port-Sensoren schon nutzen, also ohne zusätzliche Router-Abfrage. Raten ohne
  gültigen Vorwert (erster Poll, Zähler-Reset, veraltete Daten) zeigen
  „unbekannt“ statt 0. Dazu: Statistik-Klasse für freien und temporären
  Speicher, Signal- und Rauschsensoren als Signalstärke, der CPU-Verlauf deckt
  unabhängig vom Intervall eine Stunde ab, und das Ereignis „WAN verbunden“
  zeigt wieder die IP-Adresse.
- **Keine Login-Versuche mehr während der Sperrzeit; vollständige
  ARP-Tabelle.** Bei falschem Passwort versuchte die Integration trotz Sperre
  in jedem Poll einen Login. Jetzt ruht sie bis zum Ablauf der Sperre, und
  gesperrte Polls zählen nicht als Anmeldefehler, öffnen also nicht vorschnell
  den Dialog zur erneuten Anmeldung. Auf Routern mit vielen Geräten fehlten Einträge, weil rpcd
  `/proc/net/arp` bei 4 KiB abschneidet; sie werden jetzt über die
  Host-Hinweise von LuCI (`luci-rpc getHostHints`) ergänzt, ohne
  ACL-Änderung und ohne SSH.

### Changed

- **Topologie-Sensoren schreiben ihren Zustand nicht mehr bei jedem Poll neu.**
  Bisher baute die Integration den Topologie-Snapshot bei jedem Attributzugriff
  neu, etwa viermal je Poll und Router, und legte ihn samt Zeitstempel
  komplett in die Attribute. Jeder Poll löste damit einen State-Write und
  einen Websocket-Push von bis zu ~80 KB je Router aus. Jetzt entsteht der
  Snapshot einmal je Update, und `sensor.*_network_topology` trägt nur noch
  kleine Zähler (`node_count`, `edge_count`, `interface_count`,
  `client_count`, `inference_used`, `source`, `schema_version`). **Entfernte
  Attribute:** `topology_snapshot`, `interfaces`, `clients` und
  `topology_debug` (mit `generated_at`). Templates, die diese Attribute
  lesen, müssen angepasst werden; die vollständige Topologie liefert
  weiterhin das Topologie-Panel.
- **Flüchtige Attribute landen nicht mehr in der Recorder-Datenbank.**
  Client-Listen, Signalwerte, Uptime- und Restlaufzeiten, `last_seen`, Last-
  und Speicherwerte, Log-Zähler, Paketzähler der Ports und die Paketliste der
  Update-Prüfung erzeugten bei fast jedem Poll einen neuen Datenbankeintrag,
  und die Recorder-Datenbank wuchs entsprechend. Die Attribute sind live
  weiterhin sichtbar, erscheinen aber nicht mehr im Verlauf.
- Die Snapshot-API liest die HA-Instanz über `KEY_HASS` aus
  `homeassistant.helpers.http` statt über `request.app["hass"]`.
- Nicht verwendete Panel-Komponente `MobileView.tsx` und die nie gelesene
  Panel-Konfiguration `apiBase` entfernt.

### Removed

- **Button „Updates installieren“.** Er rief nur opkg auf und meldete immer
  Erfolg; OpenWrt rät von pauschalen Paket-Upgrades ab (Flash,
  Abhängigkeiten). Eine vorhandene Entität bleibt als „nicht verfügbar“
  stehen und kann gelöscht werden.

## [1.38.9] - 2026-10-28

### Fixed

- **WAN-Erkennung: LTE-/Modem-Gateways erkannt, Dumb-APs ohne Schein-WAN.** Die
  Integration nahm bisher das erste Interface aus `network.interface dump`,
  dessen Name mit `wan`, `wwan` oder `pppoe-wan` beginnt, und sonst das erste
  aktive Interface. Auf einem Dumb-AP war das `lan` oder `guest`: Der AP
  meldete ein verbundenes WAN, zeigte den Gast-Verkehr als WAN-Download und
  -Upload und fragte in jedem Poll den DDNS-Status ab. Ein Gateway mit einem
  Mobilfunk-Interface namens `lte`, `modem` oder `umts` galt dagegen als Router
  ohne WAN, und die Topologie stufte es wegen des Protokolls als AP ein. Jetzt
  gilt ein Interface als WAN, wenn sein Name mit `wan` oder `wwan` beginnt
  oder `pppoe-wan` lautet, wenn sein Protokoll nur auf einem Uplink vorkommt
  (`pppoe`, `pppoa`, `qmi`, `mbim`, `ncm`, `modemmanager`, `3g`, `wwan`) oder
  wenn es einen Mobilfunk-Namen trägt (`lte*`, `modem*`, `umts*`, `3g`, `4g`,
  `5g`); `proto none` zählt nie. Da netifd die Interfaces alphabetisch
  auflistet, entscheidet bei mehreren Treffern eine Rangfolge statt der
  Reihenfolge: Ein Mobilfunk-Name ohne Uplink-Protokoll (etwa das statische
  `modem`-Alias aus dem OpenWrt-Wiki) kommt nur zum Zug, wenn es sonst keinen
  Treffer gibt; ansonsten gewinnt ein aktives Interface vor einem inaktiven
  (Reiserouter mit gezogenem WAN-Kabel und WLAN-Uplink `wwan`, mwan3 mit
  ausgefallenem `wan` und LTE-Failover), dann der Name vor dem Protokoll,
  dann die Reihenfolge des Dumps. Den Rückfall auf das erste aktive Interface
  gibt es nicht mehr: Ohne Treffer meldet der Router „kein WAN“ (`wan_found`
  False), die WAN-Sensoren werden auf solchen Routern deaktiviert angelegt,
  `wan_connected` ist False und DDNS wird nicht abgefragt. Ein leerer Dump
  und der SSH-Fallback gelten weiter als „unbekannt“, damit ein Lesefehler die
  WAN-Sensoren eines Gateways nicht versteckt. In der Topologie zählt ein
  Router mit verbundenem Mobilfunk-, IPv6-only- oder Tunnel-Uplink (`dhcpv6`,
  `dslite`, `map`, `6in4`, `6rd`, `6to4`) jetzt als Gateway. Bereits angelegte
  WAN-Entitäten eines APs bleiben bestehen und zeigen „disconnected“ bzw.
  keinen Wert. Nicht erkannt werden weiterhin Uplinks mit anderen Namen ohne
  Uplink-Protokoll (`tethering`, `sta`, `repeater`); siehe README.

## [1.38.8] - 2026-10-28

### Fixed

- **Port-Zuordnung im Topologie-Panel war seit 1.38.3 leer.** Die Bridge-FDB
  wird seit 1.38.3 per ubus gelesen; die Zuordnung Portnummer → Schnittstelle
  dafür kam aus `file list /sys/class/net`, nahm dort aber nur die
  `directory`-Einträge. rpcd (bestätigt mit 2025.12.03 und 2026.10.04) meldet
  jede Schnittstelle zweimal: als `symlink` mit ihrem Namen und als
  `directory` mit dem Linkziel (`../../devices/…/net/lan1`). Damit trug die
  Zuordnung die Linkziele als Namen, jeder FDB-Eintrag fiel durch den Filter
  für physische Ports, und das Panel zeigte an keinem Router Geräte an den
  Ports (Diagnose: `device_count` 0, alle Geräte „nicht zugeordnet“). Vor
  1.38.3 fiel die FDB immer auf SSH zurück, das seine Zuordnung selbst baute,
  deshalb blieb der Fehler unsichtbar. Jetzt zählt nur ein einfacher Name als
  Schnittstelle, unabhängig vom gemeldeten Typ. Die Zuordnung wird außerdem
  nicht mehr bei jedem Poll neu gelesen (ein `file list` plus ein
  `port_no`-Lesen je Schnittstelle), sondern höchstens alle 10 Minuten –
  sofort neu, wenn die FDB eine unbekannte Portnummer enthält (ein Port kam
  zur Bridge dazu) oder nach einem ACL-Deploy. Portnummern, die auch danach
  kein Mitglied auflöst, erzwingen keinen weiteren Neuaufbau je Poll, und
  ein Neuaufbau, der kein Mitglied auflöst (etwa bei Zeitüberschreitungen),
  behält die letzte gute Zuordnung und wird beim nächsten Poll wiederholt.

## [1.38.7] - 2026-10-27

### Fixed

- **rpcd-ACL v8: aufgelöste Pfade für neueres rpcd.** Neueres rpcd (bestätigt
  mit rpcd 2026.10.04 auf OpenWrt 25.12.1 mit aktualisierten Paketen; ältere
  2026er Builds nicht geprüft, rpcd 2025.12.03 nicht betroffen) prüft
  Datei-ACLs zusätzlich gegen das Ziel der Symlinks: `/proc/net/arp` zeigt auf
  `/proc/<pid>/net/arp`, `/sys/class/net/<if>/…` auf `/sys/devices/…/net/<if>/…`,
  `/var/run` auf `/tmp/run`. Diese Ziele fehlten in ACL v7, deshalb lehnte rpcd
  dort das Lesen der Bridge-FDB und der ARP-Tabelle ab, und die Integration
  holte beide weiter per SSH (eine Anmeldung je Poll). Ebenfalls verweigert
  waren der `file read`-Fallback für die WAN-Zähler, die Bridge-Portnummern,
  die `nf_conntrack`-Tabelle und der DDNS-Laufzeitstatus. ACL v8 ergänzt nur Lesepfade (`/proc/*/net/arp`,
  `/proc/*/net/nf_conntrack`, `/sys/devices/*/net/*`, `/tmp/run/ddns`), keine
  neuen Rechte, kein `exec`. Beim nächsten Start der Integration wird die ACL
  neu geschrieben und rpcd einmal je Router neu gestartet; die Datei
  `scripts/ha-openwrt-router.json` für den manuellen Weg ist aktualisiert.

## [1.38.6] - 2026-10-27

### Fixed

- **Topologie: eine LLDP-Kette bleibt eine Kette.** Hängt ein AP hinter einem
  anderen AP (Gateway → AP A → AP B, per LLDP belegt), fügte die
  DHCP-/ARP-Heuristik trotzdem eine zweite Kante Gateway → AP B hinzu, weil
  das Gateway auch für AP B der DHCP-Server ist und ihn in der Bridge-FDB
  hinter demselben Port sieht wie AP A. Die Switch-Erkennung fasste beide
  dann zu einem erfundenen Switch zusammen, die LLDP-Kante Gateway → AP A
  verschwand und AP B hing im Panel am Switch statt an AP A. Jetzt bekommt
  ein Router, dessen Uplink LLDP schon kennt, keine zweite Uplink-Kante von
  einem anderen Router mehr, und die Switch-Erkennung lässt APs aus, die
  hinter einem anderen Router hängen. Zwei APs, die beide direkt am selben
  Gateway-Port hängen, ergeben weiterhin einen Switch. Einschränkungen: Das
  gilt nur für Router mit belegter Richtung der LLDP-Kante (Gateway-Rolle,
  LLDP-Abstand zum Gateway oder ein WAN-Port auf genau einer Seite, der neu
  als Richtungshinweis zählt); ein Paar ohne solchen Beleg behält wie bisher
  seine Gateway-Kanten. Ein Gateway-Port mit einem LLDP-belegten und einem
  nur per DHCP/ARP gefundenen AP (etwa ohne lldpd) ergibt keinen Switch mehr,
  beide Kanten bleiben direkt. Die zweite Strecke einer Kette trägt keinen
  `gateway_port` mehr; das Panel zeigte dafür LED und Geschwindigkeit des
  gleichnamigen Gateway-Ports.

## [1.38.5] - 2026-10-27

### Fixed

- **Später eingeschaltete WLANs tauchen jetzt auf.** Die Liste der
  hostapd-Interfaces wurde beim ersten Poll ermittelt und bis zum Neuladen des
  Eintrags festgehalten, auch wenn sie leer war. Ein danach eingeschaltetes
  WLAN (etwa das Gast-WLAN über den Schalter) lieferte keine Clients, keine
  AP-Sensoren und fehlte im Kanalplan. Die Liste wird jetzt neu ermittelt,
  wenn ein Radio ein unbekanntes Interface meldet, nach jedem WLAN-Schalter
  oder Reload über die Integration und sonst alle 10 Minuten. Der Auslöser
  versteht die Modus-Bezeichnungen aller Quellen (netifd `ap`/`sta`/`mesh`,
  iwinfo `Master`/`Client`/`Mesh Point`); ein Interface, das sich nie
  ermitteln lässt, löst die Neuermittlung nur einmal aus. Eine Neuermittlung,
  die mit einem Fehler endet, behält die bisherige Liste; eine zu Recht leere
  (alle WLANs aus) ersetzt sie. Der SSH-WLAN-Pfad kennzeichnet seine
  UCI-Sektionsnamen jetzt als solche, und ein ACL-Deploy verwirft die Liste.

## [1.38.4] - 2026-10-27

### Fixed

- **Falsches Passwort führte in eine Reauth-Schleife.** Die Verbindungsprüfung
  der Einrichtung und der erneuten Anmeldung ignorierte einen abgelehnten
  Login („Weiter mit Standard-Session“) und machte aus der dann verweigerten
  Board-Abfrage Standardwerte. Ein falsches Passwort wurde deshalb angenommen,
  das Laden des Eintrags schlug mit „Authentifizierung fehlgeschlagen“ fehl
  und öffnete den nächsten Reauth-Dialog, ohne dass das neue Passwort je
  geprüft wurde. Jetzt gilt: Lehnt rpcd den Login ab, meldet die Einrichtung
  „Ungültige Anmeldedaten“ und der Reauth-Dialog fragt nach dem Passwort.
  Standardwerte für Modell und Hostname gibt es nur noch, wenn der Login
  gelingt, aber `system/board` nicht in der rpcd-ACL steht.
- **Kein Reauth-Dialog für einen kranken Router.** Antwortete der
  ubus-Endpunkt nicht als rpcd (HTTP 5xx, HTML statt JSON, rpcd nach
  OOM-Kill), wurde das wie ein falsches Passwort behandelt. Solche Fehler
  führen jetzt zu „Wiederholen“ (`ConfigEntryNotReady`) bzw. zur
  rpcd-Einrichtungshilfe des Reauth-Dialogs, nicht zur Passwortabfrage.
- **Verbindungsprüfung hinterlässt keine rpcd-Session mehr.** Jede Prüfung
  (Einrichtung, Reauth, jeder „Erneut versuchen“-Klick) ließ eine Session mit
  600 s Laufzeit auf dem Router zurück; sie wird jetzt sofort beendet.
- Dazu passend: Der Re-Login nach einem ACL-Deploy wiederholt auch bei einer
  HTTP-Fehlerantwort (rpcd startet gerade neu) statt die Einrichtung
  abzubrechen; im Reauth-Dialog führt eine solche Antwort beim neuen Passwort
  zu „Keine Verbindung“ bzw. zur rpcd-Einrichtungshilfe statt zu „Unbekannter
  Fehler“. Der Hinweis, dass `system/board` nicht lesbar ist, erscheint nur
  noch einmal je Router.

## [1.38.3] - 2026-10-27

### Fixed

- **Keine SSH-Anmeldungen mehr im normalen Poll.** Seit der Umstellung auf den
  SSH-Fallback meldete sich die Integration bei jedem Poll fünf- bis sechsmal
  per Passwort über SSH an jedem Router an, obwohl ubus und die rpcd-ACL alles
  liefern. Die dropbear-Zeilen füllten den Log-Puffer der Router und
  verdrängten das Router-Log, das der Sensor „Router-Log“ liest. Ursachen und
  Abhilfe:
  - **WAN-Download/-Upload:** Die Antwort von `file read` wurde falsch gelesen
    (Dict statt Text), deshalb fiel jeder Poll auf SSH zurück. Die Zähler kommen
    jetzt aus `network.device status` für das WAN-Gerät (`l3_device`, also z. B.
    `wan`, `pppoe-wan` oder `wwan0`; bisher der logische Name), ersatzweise aus
    `file read` mit richtig gelesener Antwort. SSH nur noch, wenn die ACL beide
    Wege sperrt. Bei PPPoE zählt damit das PPP-Gerät statt des physischen Ports;
    die Raten können sich dadurch geringfügig verschieben. Solange das
    WAN-Interface nicht aktiv ist (Zwangstrennung, Kabel gezogen), werden
    keine Zähler gelesen, damit kein Phantom-Peak aus dem Gerätewechsel
    entsteht; die Durchsatz-Sensoren sind dann „unbekannt“.
  - **Speicherplatz und Temporärer Speicher:** Beide Sensoren standen mit dem
    BusyBox-`df` (Standard auf OpenWrt) auf 0.0, weil der SSH-Pfad `df` mit
    einer GNU-Option aufrief, die BusyBox nicht kennt. Die Werte kommen jetzt
    aus `system info` (`root` und `tmp`, auf OpenWrt 24.10 und 25.x geprüft)
    ohne zusätzlichen Aufruf. Router ohne diese Felder nutzen `df -Pk` über
    SSH, höchstens alle 10 Minuten. Die Sensoren springen deshalb von 0.0 auf
    echte Werte; die Mount-Liste enthält auf neuen Routern nur `/` bzw. `/tmp`.
  - **Bridge-FDB (Port-Zuordnung der Topologie):** `file read` auf
    `brforward` fragte die Binärdatei ohne `base64` ab und bekam nichts zurück,
    danach folgten zwei SSH-Anmeldungen je Poll. Jetzt mit `base64`; eine leere,
    aber gültige ubus-Antwort löst keinen SSH-Versuch mehr aus (ebenso bei der
    ARP-Tabelle). SSH bleibt Fallback bei gesperrtem oder fehlgeschlagenem
    ubus-Zugriff.
  - **SSH-Verbindung je Poll:** Alle SSH-Kommandos eines Polls (Fallback, LLDP)
    teilen sich eine asyncssh-Verbindung, die am Ende des Polls und beim
    Entladen geschlossen wird; bisher baute jedes Kommando eine eigene auf. Im
    SSH-Fallback (ubus gesperrt) ist das eine Anmeldung je Poll statt fünf bis
    acht. LLDP bleibt der einzige regelmäßige SSH-Leser (alle 10 Minuten, nur
    mit lldpd).
  Keine ACL-Änderung, kein rpcd-Neustart: ACL v6 und v7 erlauben die
  genutzten ubus-Aufrufe bereits. Ein Test prüft jetzt, dass zwei komplette
  Polls mit funktionierendem ubus keine SSH-Verbindung öffnen.

## [1.38.2] - 2026-10-27

### Changed

- **WAN-Sensoren auf Routern ohne WAN standardmäßig deaktiviert.** Auf
  Dumb-APs standen „WAN-IP-Adresse“, „WAN-Download“ und „WAN-Upload“
  dauerhaft auf „unbekannt“, „WAN-Status“ und der Binärsensor
  „WAN-Verbindung“ zeigten den Zustand irgendeines LAN-Interfaces. Hat ein
  Router in `network.interface dump` kein Interface mit WAN-Namen (`wan`,
  `wan6`, `pppoe-wan`, `wwan` oder ein Name, der so beginnt), legt die
  Integration diese fünf Entities jetzt deaktiviert an. **Das gilt nur für
  neu angelegte Entities** (neuer Router, neue Installation). Bestehende
  Entities bleiben unverändert; wer sie auf einem AP nicht braucht,
  deaktiviert sie in den Entity-Einstellungen. Ein Gateway mit gezogenem
  WAN-Kabel behält seine WAN-Sensoren, das Interface `wan` gibt es dann
  trotzdem. Ebenso behält ein Dumb-AP, auf dem die Standard-Interfaces
  `wan`/`wan6` noch konfiguriert sind, seine WAN-Sensoren. Ist beim Einrichten unklar, ob es ein WAN gibt (WAN-Abfrage
  gesperrt, SSH-Fallback), bleiben sie aktiv. Ein Gateway, dessen WAN
  anders heißt (z. B. `lte`), bekommt sie ebenfalls deaktiviert; dort
  zeigten sie bisher das erste aktive Interface statt des WAN.
- **Release-Texte enthalten jetzt die Änderungen.** Der Release-Workflow
  übernimmt den Abschnitt der Version aus `CHANGELOG.md` als Text des
  GitHub-Release. Bisher stand dort nur „siehe CHANGELOG.md“. Fehlt der
  Abschnitt, bleibt es beim bisherigen Text.

### Fixed

- **Panel: kein OUI-Hersteller bei zufälligen MACs, auch nicht vom Server.**
  Seit 1.37.4 nimmt das Panel für private MACs keinen Hersteller aus seiner
  eigenen OUI-Tabelle. Einen OUI-Hersteller, den der Server mitliefert
  (`vendor`), zeigte es aber weiter an; es verließ sich darauf, dass der
  Server ihn für solche MACs leer lässt (so ist es seit 1.37.0). Jetzt
  verwirft das Panel ihn selbst, in Liste, Name und Detailansicht. Ein
  Hersteller aus dem HA-Geräteregister (Gerät einer anderen Integration mit
  derselben MAC) bleibt, weil er vom Gerät selbst stammt. Der Eintrag
  `d2:4e:4f` (lokal verwalteter Bereich) war seit 1.37.0 nur aus der
  OUI-Tabelle des Servers entfernt und fehlt jetzt auch in der des Panels.

## [1.38.1] - 2026-10-27

### Fixed

- **Kanal der WLAN-Radios war leer.** `network.wireless status` liefert den
  Kanal nur im `config`-Block des Radios (als Text, z. B. `"36"`), nicht auf
  oberster Ebene. Die Integration las die oberste Ebene und bekam immer
  nichts. Jetzt kommt der Kanal aus dem `config`-Block und ist eine Zahl wie
  bei iwinfo und UCI; `auto`, `0` (ebenfalls automatische Wahl) und fehlende
  Werte bleiben leer. Damit ist das Attribut `channel` der Radios gefüllt
  (Diagnose, Topologie und Panel, wenn iwinfo keinen Wert hat). Aus demselben
  Block kommen jetzt auch `htmode` (bisher immer leer) und das ältere
  `hwmode`. Hinweis: Der AP-Sensor „Channel“ von Routern, deren WLAN über UCI
  gelesen wird, zeigt bei `channel '0'` jetzt „unbekannt“ statt 0.
- **Router im SSH-Fallback fehlten im Kanalplan.** Ohne iwinfo über rpcd
  blieb die Liste der AP-Interfaces leer, sobald die Integration das WLAN per
  SSH (`uci show wireless`) las. Jetzt baut sie die AP-Interfaces aus dieser
  Ausgabe, genauso wie bei Routern, deren WLAN sie über UCI liest (Kanal,
  Band, htmode und Radio je SSID). Diese Router erscheinen damit im
  Kanalplan. Außerdem bekommen sie die AP-Sensoren je SSID („Channel“,
  „Mode“, „HT Mode“, „HW Mode“, „AP Clients“), wie überall standardmäßig
  deaktiviert, solange die erweiterten WLAN-Sensoren aus sind. Es gibt keine
  zusätzliche SSH-Verbindung, die Ausgabe der laufenden Abfrage wird
  wiederverwendet. Bis zur nächsten Abfrage behält die Integration davon nur
  die AP-Interfaces, keine WLAN-Schlüssel, SAE-Passwörter oder
  RADIUS-Secrets. Die Sticky-Prüfung ändert sich dadurch nicht: usteer nennt
  die Knoten anderer Router `<host>#hostapd.<Interface>`, die AP-Interfaces
  aus der UCI-Konfiguration heißen aber nach ihrer Sektion
  (`default_radio0`, `@wifi-iface[0]`), weil der Kernel-Name (`phy0-ap0`)
  dort nicht steht. Solche Knoten bleiben unbekannt und zählen wie bisher
  ohne Abgleich von Band und SSID als Alternative.
- **AP-Interfaces aus der UCI-Konfiguration** (WLAN über UCI per rpcd oder
  im SSH-Fallback):
  - Im SSH-Fallback heißt ein AP-Interface nach der Option `ifname` der
    `wifi-iface`, wenn sie gesetzt ist. Dann passen Clients, usteer-Knoten
    (die Sticky-Prüfung gleicht Band und SSID ab) und DFS-Ereignisse dazu,
    und „AP Clients“ zählt richtig. Bei Routern, deren WLAN über UCI per
    rpcd gelesen wird, bleibt der Sektionsname, damit bestehende
    AP-Sensoren ihre ID behalten.
  - Heißt das AP-Interface nach der Sektion, zeigt „AP Clients“ jetzt
    „unbekannt“ statt immer 0: Die
    Clients melden den Kernel-Namen, der Sektionsname passt nie dazu.
  - Abgeschaltete Radios und SSIDs (`disabled '1'` an `wifi-device` oder
    `wifi-iface`) zählen im Kanalplan nicht mehr mit. Ihre AP-Sensoren
    bleiben.
- **SSIDs mit Apostroph und anonyme UCI-Sektionen im SSH-Fallback.** Eine
  SSID wie `Peter's WLAN` wurde nach `Peter` abgeschnitten (`uci show`
  schreibt sie als `'Peter'\''s WLAN'`). WLANs in anonymen Sektionen
  (`wireless.@wifi-iface[0]`, z. B. nach manchen Erstinstallationen) wurden
  gar nicht erkannt. Beides wird jetzt richtig gelesen; anonyme Sektionen
  heißen wie in `uci show`, also `@wifi-iface[0]`. Der WLAN-Schalter
  übergibt den Optionspfad an `uci set` jetzt gequotet, sonst wäre `[0]` für
  die Shell des Routers ein Suchmuster. Hinweise:
  - Diese Namen hängen von der Reihenfolge in `/etc/config/wireless` ab. Wer
    dort eine anonyme Sektion davor einfügt, löscht oder umsortiert,
    verschiebt die Zuordnung der Entities (WLAN-Schalter und AP-Sensoren).
  - Wechselt ein solcher Router später vom SSH-Fallback zu ubus (z. B. wenn
    die ACL v7 ausgerollt ist), meldet rpcd anonyme Sektionen als
    `cfgXXXXXX`. HA legt die WLAN-Schalter dieser SSIDs (und die AP-Sensoren)
    dann unter neuer ID neu an; die alten bleiben als nicht verfügbar zurück.

## [1.38.0] - 2026-10-27

### Changed

- **CPU-Last jetzt pro Kern.** `system info` liefert das Lastmittel (Zahl
  der laufbereiten Prozesse), nicht die Auslastung. Bisher wurde es nur mit
  100 multipliziert: Ein Lastmittel von 1,22 zeigte auf einem 2-Kern-Router
  122 %, obwohl die Kerne zu 61 % belegt waren. Die drei Sensoren
  „CPU-Last“ (1, 5 und 15 Minuten) teilen jetzt durch die Kernzahl und
  zeigen den Anteil an der gesamten CPU-Leistung. **Auf 2-Kern-Routern
  halbieren sich die Werte, die Langzeitstatistik springt einmalig.** Das
  gilt auch für das Panel und dessen Ereignis „CPU-Last erhöht“ (ab 80 %).
  Die Kernzahl liest die Integration einmal je Setup aus `/proc/cpuinfo`.
  Der Sensor „CPU-Last“ hat die neuen Attribute `cpu_cores` sowie
  `load_average_1min`, `load_average_5min` und `load_average_15min` (die
  rohen Lastmittel). Ohne lesbares `/proc/cpuinfo` (ältere ACL) und im
  SSH-Fallback bleibt der bisherige Wert, `cpu_cores` ist dann leer; ein
  fehlgeschlagener Versuch wird höchstens stündlich wiederholt (nach einer
  Zeitüberschreitung oder Serverantwort-Fehler nach 5 Minuten, nach einem
  ACL-Deploy sofort). Auch das bisherige Attribut `load_1min` halbiert sich;
  Automationen mit festen Schwellen auf diese Sensoren bitte anpassen. Die
  alte Historie wird nicht umgerechnet.
- **rpcd-ACL Version 7:** zusätzlich lesend `/proc/cpuinfo` (Kernzahl) und
  schreibend `network reload`. Beim ersten Start nach dem Update schreibt die
  Integration die ACL neu und startet rpcd **einmal pro Router** neu
  (wenige Sekunden ohne Antwort). `scripts/ha-openwrt-router.json` ist
  angepasst.

### Fixed

- **Poll-Drosselung schon bei mäßiger Last.** Die Drosselung verdoppelt das
  Abfrageintervall ab über 100 % CPU-Last und nimmt es unter 80 % zurück.
  Sie rechnete mit dem ungeteilten Wert und griff deshalb auf 2-Kern-Routern
  schon bei einem Lastmittel über 1,0. Die Schwellen bleiben, gelten aber
  jetzt pro Kern: gedrosselt wird erst, wenn mehr Prozesse laufen wollen,
  als Kerne da sind. Die Logzeile nennt Kernzahl und Lastmittel.
- **Button „WLAN neu laden“ löst jetzt wirklich `network reload` aus.** Die
  ACL v6 erlaubte die Methode nicht, der Button meldete nur
  „network.reload not available“ und wendete nichts an. Mit ACL v7 lädt er
  die Netzwerk- und WLAN-Konfiguration neu. Auch nach einem WLAN-Schalter
  läuft `network reload` jetzt durch (bisher griff dort nur der
  Reload-Trigger von procd).

## [1.37.5] - 2026-10-27

### Fixed

- **Warnung „Using 'root' as rpcd user“ als Dauerrauschen.** Sie kam einmal
  pro API-Instanz und noch vor dem Login. Jeder Setup-Retry eines nicht
  erreichbaren Routers baut eine neue Instanz und warnte erneut (bis zu
  15 Meldungen in einer Minute, danach alle paar Minuten). Jetzt erscheint
  die Warnung höchstens einmal pro Router und HA-Start und erst nach einem
  erfolgreichen Login; nicht erreichbare Router und abgelehnte Logins
  erzeugen sie nicht mehr.
- **„network.reload not available“ bei jedem WLAN-Schalter.** Die rpcd-ACL
  erlaubt `network reload` nicht, die Änderung greift trotzdem: Nach
  `uci commit` meldet rpcd `config.change`, und procd lädt die
  WLAN-Konfiguration selbst neu. Nach einem erfolgreichen Commit steht die
  Meldung deshalb nur noch im Debug-Log. Der Button „WLAN neu laden“ warnt
  weiterhin, wenn `network reload` fehlt, weil dort sonst nichts angewendet
  wird. Scheitert `network reload` nach einem erfolgreichen Commit
  (Zeitüberschreitung, Verbindungsabbruch), meldet der Schalter keinen
  Fehler mehr: Die Änderung ist zu diesem Zeitpunkt schon angewendet.
- **HA-Deprecation `device_registry.async_get_device`.** Home Assistant 2026.10
  warnte bei WLAN-, DHCP- und DFS-Ereignissen (Geräte-ID des Routers) und
  beim Topologie-Snapshot (HA-Namen der Clients); die alte Methode entfällt
  mit HA 2027.8. Die Integration nutzt jetzt `async_get_device_by_identifier`
  bzw. `async_get_devices` und fällt auf älteren HA-Versionen (ab 2026.2)
  auf die bisherige Methode zurück. Haben mehrere Integrationen ein Gerät
  mit derselben MAC registriert, gewinnt im Panel das vom Nutzer
  umbenannte.

### Changed

- **Aufgeräumt, ohne Verhaltensänderung:** Die Band-Helfer (Frequenz,
  UCI-`band`, `hwmode`, Kanal → Band) liegen im neuen Modul `wifi_band.py`;
  Kanalplan und Client-Stabilität importieren keinen privaten Helfer aus
  `api.py` mehr. Die WLAN-Schalter kennen die nie gelieferten Bandcodes
  `2g`/`60g` nicht mehr.

## [1.37.4] - 2026-10-27

### Fixed

- **Footer des Topologie-Panels überdeckte die HA-Seitenleiste und die
  Karte.** Er war am Browserfenster fixiert und lag deshalb über der
  Seitenleiste von Home Assistant; seine Höhenvariable stand auf `:root`,
  das im Shadow-DOM von HA nicht greift, sodass Karten und Minimap hinter
  dem Footer verschwanden. Der Footer sitzt jetzt im Layout unter der
  Zeichenfläche, das Panel ist genau eine Fensterhöhe hoch (der
  Vergleich-Tab scrollt jetzt in sich). Die Umbrüche richten sich nach der
  Panel-Breite, nicht nach dem Fenster: unter 860 px entfällt das
  Client-Diagramm, unter 560 px auch die Top-Talker-Liste (bleibt im
  Traffic-Tab).
- **WAN-Traffic war 8× zu niedrig und teils falsch.** Das Backend lieferte
  Byte/s unter dem Namen `downstream_bps`, Footer, Traffic-Tab und
  Inspector zeigten das als Mbit/s an; nur der Kanten-Tooltip rechnete um.
  Außerdem wurde immer durch 60 s geteilt, auch bei 120-s-Poll (CPU-Last)
  oder 300-s-Poll (SSH-Fallback), und nach einem fehlgeschlagenen
  Zähler-Lesen entstand ein Ausreißer über den ganzen Zählerstand.
  `wan_traffic` enthält jetzt echte Bit/s über die gemessene Zeit zwischen
  zwei Zähler-Lesungen, dazu `interval_s` und `sampled_at`; ohne gültigen
  Vorwert, nach einem Zählerrücksprung, nach einem Wechsel des
  WAN-Interfaces oder nach mehr als 15 Minuten Lücke bleibt es leer. Der
  Footer zeigt Mittelungsdauer und Messzeitpunkt. Folge der richtigen
  Einheit: Die Panel-Warnung „Hoher WAN-Traffic“ (ab 900 Mbit/s) verglich
  bisher gegen Byte/s und löste praktisch nie aus – bei Gigabit-Last
  erscheint sie jetzt.
- **Top Talker „(letzte 24 h)“ war falsch beschriftet.** Die Zähler stammen
  vom WLAN-Treiber und laufen seit der letzten Anmeldung am AP; die
  Überschrift lautet jetzt „seit Verbindung“.

### Changed

- **Gerätenamen aus Home Assistant im Panel.** Der Topologie-Snapshot liest
  (nur lesend) Geräte- und Entity-Register: vom Nutzer vergebene Namen
  (Gerät oder Tracker umbenannt) und Gerätenamen anderer Integrationen mit
  derselben MAC (ESPHome, Shelly, …) samt Hersteller und Modell
  (`ha_name`, `ha_name_source`, `ha_manufacturer`, `ha_model`). Das Panel
  benennt Clients überall nach derselben Regel: HA-Name → DHCP-Hostname →
  Hersteller + MAC-Ende → „Privat-MAC …“ → MAC. Das Panel wertet dafür jetzt
  auch `random_mac` aus und nimmt für private MACs keinen Hersteller aus
  seiner eigenen OUI-Tabelle. Top Talker sind anklickbar und wählen den
  Client in der Karte aus.
- **Internet-Knoten in Latenz-Farbe mit Puls.** Kugel und Kante zum Gateway
  färben sich nach der Internet-Latenz, die Home Assistant misst
  (TCP-Verbindung zu 8.8.8.8:53: grün/amber/orange, rot ohne Antwort), zwei
  Pulsringe und ein Datenfluss auf der Kante zeigen eine aktive Verbindung;
  offline steht beides still. Bei „Bewegung reduzieren“ im Betriebssystem
  entfallen die Animationen. Nach einem Neustart zeigt der Knoten bis zur
  ersten Messung „noch keine Messung“ statt „offline“ (neues Snapshot-Feld
  `ping_pending`).

## [1.37.3] - 2026-10-27

### Fixed

- **Rohes UCI-Band beim SSH-Fallback.** Lief der WLAN-Status über den
  SSH-Fallback (`uci show wireless`, wenn weder `network.wireless`, iwinfo
  noch UCI über rpcd antworten), stand im Band der rohe UCI-Wert (`2g`) bzw.
  `unknown` ohne `band`-Option. Das Attribut `band` der SSID-Schalter und
  die Funkmodule im Topologie-Snapshot trugen deshalb `2g` statt `2.4g`
  (das Panel zeigte trotzdem 2.4 GHz). Das Band wird jetzt wie
  bei allen anderen Wegen bestimmt: `band`-Option, eindeutiger `hwmode`,
  Kanalnummer, Name. Funkmodule ohne `band`-Option bekommen dadurch oft ein
  Band und zeigen es im Namen der SSID-Schalter. `band='60g'` gilt wie
  überall als unbekannt, der Schaltername endet dann nicht mehr auf
  „(60 GHz)“. Entity-IDs bleiben gleich.
- **60 GHz im Kanalplan und bei klebenden Clients als 6 GHz gezählt.**
  Kanalplan und Client-Stabilität nutzen jetzt dieselbe Frequenzgrenze wie
  die Banderkennung: Frequenzen über 7125 MHz (802.11ad) zählen nicht als
  6 GHz. Eine als Text gemeldete Frequenz wird bei klebenden Clients jetzt
  ebenfalls ausgewertet.

## [1.37.2] - 2026-10-27

### Fixed

- **Untere 6-GHz-Kanäle als 5 GHz erkannt.** Die Bandgrenze lag bei
  6000 MHz statt bei 5925 MHz, deshalb galten 6-GHz-Funkmodule auf 5935 bis
  5995 MHz (Kanäle 1, 2, 5 und 9) als 5 GHz. Frequenzen über 7125 MHz
  (60 GHz) gelten nicht mehr als 6 GHz, sondern als unbekannt.
- **Band nach Funkmodul-Namen statt nach Konfiguration.** Ohne Frequenz
  (WLAN-Status über `network.wireless` oder UCI) wurde das Band aus dem
  Namen geraten (`radio0` = 2.4 GHz, `radio1` = 5 GHz). Jetzt zählt die
  UCI-Option `band` (ersetzt `hwmode` in neueren OpenWrt-Versionen), danach
  ein eindeutiger alter `hwmode` (11a/11b/11g/11ac), danach die
  Kanalnummer, und erst zuletzt der Name. 11n, 11ax, 11be und `auto` legen
  kein Band mehr fest, 11ad (60 GHz) gilt als unbekannt. Mehrdeutige
  Kanalnummern (1–13 und 149–177 gibt es auch bei 6 GHz) gelten als 2.4
  bzw. 5 GHz. Bei Routern, deren `radio0` ein 5-GHz-Modul ist, ändert sich
  dadurch das angezeigte Band: im Namen der SSID-Schalter, in Attributen,
  in der Topologie und im Kanalplan. Entity-IDs bleiben gleich.
- **`async_reload_entry` übersprang Aufräumschritte** (intern, wird derzeit
  nirgends aufgerufen). Die Funktion rief Unload und Setup direkt auf, sodass
  die `on_unload`-Rückrufe (Ausfall-Tracker, Kanalplan, RAM-Hinweis) nicht
  liefen. Sie lädt den Eintrag jetzt über Home Assistant neu.

## [1.37.1] - 2026-10-27

### Fixed

- **rpcd wuchs auf den Routern um rund 6 MB pro Tag (110 MB nach 17 Tagen).**
  Der Dienst-Status (`dnsmasq`, `firewall` …) wurde bei jedem Poll über rpcd
  `rc/list` geholt. rpcd vor dem 31.05.2026 gibt bei diesem Aufruf seinen
  Request-Kontext nie frei (Upstream-Fix `d06d2a8`, „rc: fix memory leak of
  list request context“). Betroffen ist u. a. OpenWrt 25.12.1 mit rpcd
  2025.12.03. Gemessen auf einem Cudy WR3000: 500 Aufrufe von `rc/list`
  ergaben +2320 kB RSS, also rund 4,7 KB pro Aufruf. Andere Poll-Aufrufe
  (`file/read`, `iwinfo`, `luci-rpc`, `uci`, `session`) kamen auf 0 kB. Ein
  frisch geflashtes Gateway mit rpcd 2026.10.04 leakt nicht.
  - Ob ein Dienst läuft, kommt jetzt bei jedem Poll aus procd
    `service/list`. Das Objekt gehört procd, nicht rpcd, und leakt nicht
    (300 Aufrufe: 0 kB bei rpcd und procd).
  - `rc/list` liefert nur noch das Attribut `enabled`. Es läuft höchstens alle
    6 Stunden (`RC_LIST_REFRESH_INTERVAL`) und nach `enable`/`disable`.
  - `rc/list` läuft jetzt mit `skip_running_check`. Bisher startete jeder
    Aufruf pro Init-Skript einen eigenen „running“-Check (~40 Prozesse,
    ~1,3 s pro Poll).
  - Fehlt `service/list` (ACL), wird wie bisher bei jedem Poll ein volles
    `rc/list` gemacht.

  Ein schon aufgeblähter rpcd gibt den Speicher erst bei einem Neustart frei
  (`/etc/init.d/rpcd restart`). Dauerhaft behebt den Leak ein rpcd-Update
  auf einen Stand ab 2026-05-31.

## [1.37.0] - 2026-10-27

### Added

- **Attribut `random_mac` an WLAN-Clients** (Device-Tracker und
  Client-Daten des Topologie-Snapshots): wahr bei einer lokal verwalteten,
  zufälligen MAC („private WLAN-Adresse“ von Handys, Tablets, Laptops).
  Das Topologie-Panel wertet das Attribut noch nicht aus.

### Fixed

- **Falsche Hersteller bei zufälligen MACs.** Eine lokal verwaltete MAC hat
  keinen Hersteller; der OUI-Abgleich wird für sie übersprungen (`vendor`
  bleibt leer), statt zufällig einen Hersteller zu treffen. Der Eintrag
  `d2:4e:4f` (lokal verwalteter Bereich, kann kein Hersteller sein) ist aus
  der OUI-Tabelle entfernt. Auch Clients aus dem SSH-Fallback bekommen jetzt
  `vendor`, `random_mac` und die übrigen Client-Metadaten.

## [1.36.0] - 2026-10-27

### Added

- **Binärsensor „Klebende WLAN-Clients“** (`sticky_clients`) pro Router:
  ein, solange Clients an diesem Router hängen, obwohl ein besserer AP da
  ist.
  - Mit usteer (pro Router erkannt; Abfrage `usteer get_clients` alle
    2 Polls, nie im selben Poll wie der Log-Abruf): ein anderer Router hört
    den Client seit mindestens 10 Minuten um mindestens 8 dB stärker, im
    selben Band und mit derselben SSID (soweit über die Router-Adresse
    zuordenbar). Andere Funkmodule desselben Routers zählen nicht.
  - Ohne usteer: Signal seit 10 Minuten bei −75 dBm oder schwächer, und ein
    anderer Router bietet ein Funkmodul im selben Band.
  - Attribute `method` (`usteer`/`signal`) und `clients` (MAC, Hostname,
    Signal, seit; mit usteer zusätzlich besserer Knoten und Abstand in dB,
    ohne usteer das Band).
- **Sensor „Instabile WLAN-Clients“** (`unstable_clients`) pro Router:
  Clients mit mindestens 3 Reconnects in 24 h (Anmeldung innerhalb von
  5 Minuten nach einer Abmeldung am selben Interface; Roaming und
  Band-Steering zählen nicht). Attribut `top` mit den 10 auffälligsten
  Clients. Unbekannt, solange das Router-Log nicht lesbar ist.
- **Tracker-Attribute `associations_24h` und `reconnects_24h`**, summiert
  über alle Router, aus dem Router-Log.

## [1.35.0] - 2026-10-27

### Added

- **Sensor „DHCP-Pool …“ pro aktivem DHCP-Pool** (z. B. `lan`, `guest`):
  Anteil des Adressbereichs (Netz + `start` … `start + limit − 1`), der
  durch Leases belegt ist, in %. Attribute `interface`, `leases`, `size`.
  Die Pools stammen aus `uci get dhcp` (beim zweiten Poll, danach alle
  10 Polls, nur solange der Router einen Pool bedient; Dumb-APs mit
  `ignore` werden einmal gefragt).
- **Attribut `dhcp_status` an WLAN-Clients** (Device-Tracker):
  - `ok`: Lease oder ARP-Eintrag bei irgendeinem Router,
  - `pending`: noch keine 180 s verbunden,
  - `dhcp_missing`: seit mindestens 180 s verbunden, aber bei keinem Router
    eine Lease und in keiner ARP-Tabelle (Client hängt z. B. in einer
    DHCP-DISCOVER-Schleife),
  - `static_no_lease`: als statischer Host eingetragen, hat aber keine Lease.
  Kennt kein Router eine Lease (kein DHCP-Server sichtbar) oder ist ein
  Router mit DHCP-Pool gerade nicht erreichbar, bleibt das Attribut leer.

Hinweise: DHCP-Probleme aus dem Router-Log (`nak`, `decline`, `no_address`)
kommen seit 1.33.0 als `openwrt_router_dhcp_event`. Pool-Sensoren und
statische Hosts brauchen Leserechte auf die uci-Config `dhcp`; der Login
`root` hat sie über die LuCI-ACLs, ohne LuCI gibt es keinen Pool-Sensor.
Ein gestoppter dnsmasq blendet die Pools aus, ein anonymer Pool-Abschnitt
heißt nach seinem Interface.

## [1.34.0] - 2026-10-27

### Added

- **DFS-Ereignisse und Kanalwechsel.** Event `openwrt_router_dfs_event`:
  - aus dem Router-Log (hostapd): `radar_detected`, `cac_start`,
    `cac_completed`, `cac_failed`, `nop_finished`, `new_channel`,
    `pre_cac_expired` mit `radio`, `interface`, `frequency`, `channel`;
  - `channel_change`, wenn sich Kanal oder Kanalbreite eines Funkmoduls
    zwischen zwei Abfragen ändert (`old_channel`/`new_channel`,
    `old_width_mhz`/`new_width_mhz`). Ein Kanalwechsel holt das Router-Log
    sofort, damit die passende DFS-Zeile schon bekannt ist.
  - `dfs_related` ist nur wahr, wenn eine passende DFS-Zeile
    (`radar_detected`, `new_channel`, `cac_failed`) desselben 5-GHz-Funkmoduls
    aus den letzten 15 Minuten vorliegt (`evidence` nennt sie). Ein
    Kanalwechsel ohne solche Zeile (manuell, ACS) ist `dfs_related: false`.
    `backhaul: true` kennzeichnet Funkmodule mit WLAN-Uplink, die dem Kanal
    des Partners folgen.
  - Radar-Meldungen haben im Event-Budget Vorrang; die Events stehen im
    Logbuch des Routers.
- **Diagnosesensor „DFS-Ereignisse (24 h)“** (`dfs_events_24h`): Anzahl
  dieser Ereignisse in den letzten 24 Stunden, Attribute `by_type` und
  `last_event`.

## [1.33.0] - 2026-10-27

### Added

- **Router-Log wird ausgewertet** (alle 2 Abfragen über `ubus call log read`).
  Neue Zeilen werden über ihre fortlaufende `id` erkannt. Was beim ersten
  Abruf (und nach einem Neustart von logd) schon im Puffer steht, wird nur
  gezählt. Die Zahl der abgerufenen Zeilen richtet sich nach dem Aufkommen
  (100–700, zuerst 250); fehlten beim letzten Mal Zeilen, holt der nächste
  Abruf den ganzen Puffer.
- **Events für eigene Automationen:**
  - `openwrt_router_wifi_event` mit `type` `psk_mismatch` (falsches
    WLAN-Passwort), `inactivity_timeout` (Client wegen Inaktivität getrennt)
    oder `handshake_failed`,
  - `openwrt_router_dhcp_event` mit `type` `nak`, `decline` oder
    `no_address` (Pool erschöpft).
  - Felder: `entry_id`, `router`, `type`, `mac`, `hostname`, `interface`,
    `time`, `message`, bei DHCP zusätzlich `ip`.
  - Höchstens 10 Events pro Abruf und eines je Typ und MAC in 5 Minuten.
    Falsches Passwort und DHCP-Probleme haben dabei Vorrang vor
    Inaktivitäts-Trennungen. Normale An-/Abmeldungen und DHCPACK werden nur
    gezählt.
  - Die Events erscheinen lesbar im Logbuch, auch auf der Geräteseite des
    Routers (`device_id`).
- **Diagnosesensor „Router-Log“** (`log_status`): `ok`, `pending`,
  `not_permitted` (rpcd-ACL erlaubt `log read` noch nicht oder kein logd)
  oder `error`.
  Attribute: Zähler der letzten 24 h je Art (`counts_24h`), verarbeitete,
  verpasste und Baseline-Zeilen, ausgelöste und unterdrückte Events. Ein
  fehlender Zugriff lässt die Abfrage nie scheitern.

### Changed

- **rpcd-ACL Version 6:** zusätzlich lesend `log read` und
  `usteer get_clients` (für die Client-Stabilität in einem späteren
  Release). Beim ersten Start nach dem Update schreibt die Integration die
  ACL neu und startet rpcd **einmal pro Router** neu (wenige Sekunden ohne
  Antwort). `scripts/ha-openwrt-router.json` ist angepasst.

## [1.32.0] - 2026-10-27

### Added

- **Diagnosesensor „Kanalplan-Befunde“** (`channel_plan`) pro Router. Er
  vergleicht die Funkmodule aller erreichbaren Router miteinander und zählt
  die Befunde, an denen ein Funkmodul dieses Routers beteiligt ist. Das
  Attribut `findings` listet sie auf, `radios` zeigt die eigenen Funkmodule
  (Kanal, Breite):
  - `same_channel`: zwei Funkmodule im selben Band auf demselben Hauptkanal,
  - `overlap`: belegte Kanalbreiten überlappen, z. B. 40 MHz auf 44 und 48
    oder 160 MHz auf 36 (belegt 36–64),
  - `non_standard_24`: 2,4 GHz außerhalb der Kanäle 1, 6 und 11,
  - `dfs`: 5-GHz-Funkmodul mit mindestens einem Teilkanal in 52–144.
  Mehrere SSIDs auf demselben Funkmodul zählen als ein Funkmodul. Router,
  deren letzte Abfrage fehlschlug, bleiben außen vor. Ein Funkmodul mit
  WLAN-Uplink (Repeater, Mesh) muss den Kanal seines Partners nutzen und
  ergibt deshalb nie `same_channel`/`overlap` (Attribut `backhaul`).
- **Reparatur-Hinweis „WLAN-Kanalkonflikte zwischen OpenWrt-Routern“**
  (`channel_plan_conflict`), sobald ein Router in zwei Abfragen in Folge an
  einem Konflikt beteiligt ist. DFS allein löst ihn nicht aus. Er
  verschwindet nach zwei konfliktfreien Auswertungen in Folge; ein
  fehlgeschlagener Poll ändert nichts. Anlass: Bei der
  Live-Diagnose waren ein DFS-Kanal doppelt belegt und überall 160 MHz
  eingestellt, ohne dass Home Assistant das zeigte.
- Kein zusätzlicher Router-Aufruf: `phy` und `center_chan1` kommen aus der
  schon abgefragten `iwinfo info`-Antwort.

## [1.31.0] - 2026-10-27

### Added

- **Reparatur-Hinweis bei Speicherdruck auf einem Router** (`ram_high_<entry_id>`).
  Speicherdruck = 1 − verfügbar/gesamt (`available` aus `system info`). Liegt er
  15 Minuten lang über 85 % oder sind weniger als 16 MB verfügbar, erscheint
  „Hohe RAM-Auslastung auf OpenWrt-Router …“. Er verschwindet von selbst, sobald
  der Druck unter 80 % fällt und wieder mindestens 16 MB frei sind, und beim
  Entladen des Eintrags. Ein einzelner normaler Messwert setzt die Haltezeit
  zurück, Abfragen ohne Speicherwerte ändern nichts. Anlass: Das rpcd-Leck auf
  einem Dumb-AP (110 MB, ca. 93 % Druck) blieb in Home Assistant unsichtbar.
  Fehlt `available` (ältere Firmware, SSH-Fallback), wird er aus
  frei + Puffer + Cache − Shared geschätzt.
- **Attribute `available_mb` und `pressure_pct`** am Sensor „Speichernutzung“
  (`memory_usage`). Der Zustand des Sensors rechnet unverändert
  (gesamt − frei)/gesamt, damit bestehende Verläufe und Automationen gleich
  bleiben.

## [1.30.0] - 2026-10-27

### Added

- **Schalter „Erweiterte WLAN-Sensoren (Funk, AP, Port)“** in den Optionen
  (Einstellungen → Geräte & Dienste → OpenWrt Router → Konfigurieren). Die
  Sensoren pro Funkmodul, pro SSID (AP) und pro Port sind standardmäßig aus,
  weil sie sich mit jedem Radio, jeder SSID und jedem Port vervielfachen.
  Statt rund 40 Einzelklicks schaltet der Schalter sie jetzt gesammelt:
  - **Ein:** aktiviert alle diese Sensoren, die von der Integration
    deaktiviert sind. Später neu hinzukommende Sensoren (neue SSID, neuer
    Port) sind dann ebenfalls aktiv.
  - **Aus:** deaktiviert nur, was der Schalter eingeschaltet hat. Sensoren,
    die vorher schon an waren, bleiben an.
  - Selbst deaktivierte Sensoren (`disabled_by: user`) werden nie angefasst.
  - Die Registry wird nur beim Umschalten geändert, nie beim Setup. Neue
    Sensoren erscheinen nach dem automatischen Neuladen (ca. 30 s).

### Fixed

- **Speichern der Optionen löschte andere Optionen.** Der Options-Flow
  ersetzte alle Optionen durch die Eingaben des Formulars. Jetzt werden sie
  zusammengeführt.

## [1.29.0] - 2026-10-27

### Added

- **Ausfälle als Reparatur-Hinweis, gleichzeitige Ausfälle gebündelt.** Ein
  Router gilt nach 3 fehlgeschlagenen Abfragen als ausgefallen. Statt einer
  `persistent_notification` pro Router gibt es jetzt Repairs-Issues:
  - Sind alle geladenen Router (mindestens zwei) gleichzeitig nicht erreichbar,
    erscheint **ein** Hinweis „Kein OpenWrt-Router erreichbar“
    (`lan_unreachable`). Die Ursache liegt dann fast immer zwischen Home
    Assistant und dem LAN, nicht in den Routern (Beispiel: 20.10., 10:05–10:31,
    alle Router gleichzeitig weg).
  - Sonst ein Hinweis pro Router (`router_unreachable_<entry_id>`).
  - Vor der Einordnung wartet die Integration das längste Poll-Intervall plus
    30 s ab, damit die versetzt pollenden Router alle melden können. Erholen
    sich die Router nach einem LAN-Ausfall versetzt, entstehen keine
    Einzel-Hinweise. Auth-Fehler werden nie gebündelt.
  - Hinweise verschwinden von selbst, sobald der Router wieder antwortet.
- **Event `openwrt_router_outage_event`** bei Beginn und Ende eines Ausfalls,
  mit `scope` (`fleet`/`router`), `state` (`down`/`up`), `entry_ids`,
  `routers`, `since`, `duration_s` und `error_type`. Für eigene
  Automationen, z. B. Push-Nachricht nur beim LAN-weiten Ausfall.

### Fixed

- **Die Ausfall-Meldung verschwand nach der Wiederherstellung nie.** Das Flag
  „Meldung gesendet“ lag auf `coordinator.data`, das jede erfolgreiche Abfrage
  durch ein neues Objekt ersetzt. Beim Erholen war es daher immer `False`. Der
  Fehlerzähler liegt jetzt am Coordinator selbst und zählt auch dann, wenn
  noch keine Daten vorliegen.

## [1.28.3] - 2026-10-27

### Fixed

- **Selbst aktivierte Funk-, AP-, Port- und Interface-Sensoren wurden bei
  jedem Laden wieder deaktiviert.** `_disable_legacy_dynamic_sensors()` war
  als einmalige Aufräumaktion für v1.17.4 gedacht, lief aber in jedem
  `async_setup_entry`. Jede aktive Entität mit `_ap_`/`_radio_`/`_iface_`/
  `_port_`/`_rate` in der Unique-ID stand nach Neustart oder Reload wieder
  auf `disabled_by: integration` (beobachtet: 41 Sensoren). Die Aufräumaktion
  ist jetzt eine einmalige Config-Entry-Migration (Minor-Version 1 → 2). Neue
  Einträge starten direkt bei Minor-Version 2. Ein Eintrag, der schon einmal
  mit ≥ v1.17.4 lief, erkennt man an mindestens einem von der Integration
  deaktivierten dynamischen Sensor. Für ihn wird bei der Migration nichts mehr
  deaktiviert, selbst eingeschaltete Sensoren bleiben also auch beim Update an.

## [1.28.2] - 2026-09-09

### Fixed

- **VLAN-Zuordnung pro Port war immer leer.** `get_port_vlan_map()` las die
  DSA-`bridge-vlan`-Sektionen falsch: `device` wurde als Portname
  interpretiert (es ist die Bridge) und die VLAN-IDs in einem Feld `vids`
  erwartet, das dieser Sektionstyp nicht hat. Die Map kam dadurch immer leer
  zurück und die VLAN-Spalte im Panel blieb dauerhaft `—`. Jetzt korrekt aus
  `vlan` + `ports` (`lan1:u*`, `lan3:t`) gelesen.
- **Kabelgeräte hinter einem AP hießen „Unbekannt".** Die Port-Zuordnung löste
  Namen und IPs nur aus den DHCP-Leases und der ARP-Tabelle *desselben*
  Routers auf. Nur das Gateway betreibt einen DHCP-Server, also blieb auf
  jedem Dumb-AP jedes Kabelgerät namenlos. `build_port_connections()` nimmt
  jetzt optional eine flottenweite Identitätsquelle
  (`identity_leases` / `identity_arp`), die der Mesh-Aggregator aus allen
  Config-Entries zusammenstellt. Ausdrücklich **nur** zur Namensauflösung für
  MACs, die der Router ohnehin in seiner eigenen FDB sieht — fremde Leases
  erzeugen keine Geräte und keine Unassigned-Einträge. Geliehene Identität
  ist als `fleet-dhcp` / `fleet-arp` in der Quelle erkennbar.

## [1.28.1] - 2026-09-09

### Fixed

- **Kanten-Orientierung in einer Kette.** Hängt ein AP hinter einem anderen AP
  (Gateway → AP1 → AP2), zeigte die LLDP-Kante zwischen den beiden APs in die
  falsche Richtung: ohne Gateway-Endpunkt entschied die alphabetische
  Router-ID. Konsumenten indizieren Uplinks über das Kanten-Ziel, dadurch
  überschrieb die verdrehte Kante den Uplink des oberen AP und der untere
  bekam gar keinen — im Panel „Kabel" ohne Ports und ohne Status. Die
  Orientierung folgt jetzt der Hop-Distanz zum Gateway
  (`_lldp_hop_depths`); nur bei echtem Gleichstand bleibt die stabile
  ID-Sortierung.
- **Verkabelungsansicht zeigte immer das Gateway als Quelle.** `WiringView`
  setzte `fromName` fest auf den Gateway-Namen und ignorierte `uplinkTo`. Eine
  Kette wurde dadurch grundsätzlich als Stern dargestellt, egal wie korrekt
  die LLDP-Daten waren. Frontend-Bundle neu gebaut.

## [1.28.0] - 2026-09-09

> **Bessere Geräte- & Topology-Erkennung via LLDP.** Router-zu-Router-Verkabelung
> wird jetzt bevorzugt über **LLDP** erkannt (echte Nachbarn + physische Ports),
> statt sie nur aus DHCP/ARP/FDB zu erraten. Optional — ohne lldpd funktioniert
> alles wie bisher, nur mit geringerer Sicherheit und klarer Kennzeichnung.

### Added

- **LLDP als bevorzugte Quelle für Router-/AP-Nachbarschaften.** Neue Erfassung via
  `lldpcli show neighbors -f json` über den bestehenden asyncssh-Transport (ubus wird
  zuerst best-effort geprüft). Liefert lokalen/entfernten physischen Port, Chassis-ID,
  Management-IP und Capabilities. Läuft als **Method 0** (höchste Priorität) im
  Topology-Merge und überschreibt heuristische Kanten für dasselbe Router-Paar.
- **Bidirektionale Erkennung & Konflikt-Handling.** Sehen sich zwei Router gegenseitig
  → `confidence: high`, beide Portseiten. Einseitig → als solches markiert. Weicht der
  LLDP-Port vom Bridge-FDB-Port ab, **gewinnt LLDP**; der Konflikt ist in Diagnostics
  sichtbar.
- **Dynamische Router-Erkennung aus ConfigEntries.** Bekannte Router werden aus den
  vorhandenen `openwrt_router`-Einträgen ermittelt (IP/MAC/Hostname/Chassis-ID). Ein
  bekannter Router wird nie mehr als normaler Client dargestellt. Keine Annahme über
  IP-Reihenfolge, keine feste Routerzahl (1/2/3/N).
- **Reicheres Geräte-Datenmodell.** Clients tragen jetzt `vendor` (server-seitiges OUI),
  `connection_type` (wired/wireless/router_uplink/unknown), `confidence`, `source`,
  `web_url` (`http://<ip>`) und `last_seen`.
- **Optionale Capability `lldp_neighbors`** im Config-Flow-Checklist (grün/gelb), inkl.
  Installations-Empfehlung für `lldpd`. **Kein** Abbruch des Add-Flows ohne LLDP.
- **Panel-Erweiterung.** Router-Uplinks werden als eigener, verifizierter LLDP-Link mit
  Port-Badges an beiden Enden dargestellt; Detail-/Hover-Ansichten zeigen Nachbar,
  Management-IP (Weblink), Ports, VLAN, Quelle, Confidence, RX/TX u. a.

### Fixed

- **Medium kommt aus LLDP, nicht aus der Heuristik.** LLDP-Kanten tragen jetzt
  `link_type: lan|wifi`, abgeleitet aus den LLDP-Interface-Namen. Ein Repeater, der
  lldpd betreibt, wird dadurch wieder als **WLAN Repeater** dargestellt statt als
  „Kabel"; umgekehrt gewinnt eine LLDP-verifizierte Kupferstrecke gegen die
  STA-Interface-Heuristik — genauso wie ein WAN-Port mit Carrier.
- **Switch-Erkennung berücksichtigt LLDP.** Zwei APs hinter einem unmanaged Switch
  wurden nicht mehr als Switch-Knoten erkannt, sobald lldpd lief, weil die Inferenz
  nur `lan_uplink`-Kanten gruppiert hat.
- **Client-Anreicherung erreicht das Panel.** `vendor`, `connection_type`,
  `confidence`, `source`, `web_url` und `last_seen` werden in die Client-Knoten
  übernommen; vorher hat das Frontend still auf seine eigene OUI-Tabelle
  zurückgegriffen und der server-seitige Lookup war wirkungslos.
- **Optionales LLDP verfälscht das ACL-Deploy-Ergebnis nicht mehr.** Fehlte nur
  `lldp_neighbors`, meldete ein erfolgreicher Deploy fälschlich „keine Änderung".
- **LLDP wird nicht mehr pro Poll über SSH abgefragt.** Nachbarn werden alle
  10 Minuten aufgefrischt; ein „unavailable" wird alle 30 Minuten (und nach jedem
  ACL-Redeploy) erneut geprüft, damit ein nachträglich installiertes `lldpd` ohne
  Reload des Config-Entry wirksam wird.

### Notes

- LLDP ist **optional** und ändert keine bestehenden ACL-Rechte (`ACL_VERSION` bleibt unverändert bei 5).
  Die LLDP-Abfrage löst **nicht** die „SSH-Fallback/degraded"-Warnung aus.
- **Empfehlung** für zuverlässige Router-zu-Router-Erkennung auf **allen** OpenWrt-Routern:
  `opkg update && opkg install lldpd && /etc/init.d/lldpd enable && /etc/init.d/lldpd start`
- Nach dem Update **Home Assistant neu starten** (neue Coordinator-Felder + Frontend-Bundle).

## [1.27.0] - 2026-09-06

> **Router-Neustart aus Home Assistant.** Bisher ließen sich nur einzelne
> Dienste neu starten — für einen vollständigen Geräteneustart musste man
> auf LuCI oder SSH ausweichen.

### Added

- **Reboot-Button pro Router** (`button.<router>_router_neu_starten`)
  Löst `system/reboot` über ubus aus. Blockiert die rpcd-ACL die Methode
  (oder ist sie nicht vorhanden), fällt der Button auf einen abgesetzten
  SSH-`reboot` zurück — dieselben Zugangsdaten wie der übrige SSH-Fallback.
  Ein Timeout des ubus-Calls gilt nicht als Fehlschlag: der Router kappt die
  Verbindung beim Herunterfahren, deshalb entscheidet in dem Fall der
  SSH-Fallback. Nach dem Druck wird bewusst kein Coordinator-Refresh
  ausgelöst — der nächste reguläre Poll holt den Router wieder ab.
  Neu: `OpenWrtAPI.reboot()`.

## [1.26.6] - 2026-08-23

> **Nachzügler zum SSH-Fallback-Fix aus 1.26.4.** Auf der Prod-Instanz zeigte
> sich nach dem ACL-Redeploy: 10.10.30.50 fiel trotz korrekter v5-ACL weiter
> in den SSH-Fallback — Ursache war der ACL-Block-Cache, nicht die ACL.

### Fixed

- **ACL-Block-Cache: uci-Denial einer Config blockierte ALLE Configs**
  rpcd erzwingt uci-ACLs pro Config-Datei, der `_acl_blocked`-Cache keyte
  aber nur auf `("uci", "get")`. Der (verweigerte) ddns-Probe vergiftete
  damit den uci-wireless-Fallback für den Rest der Session — jeder weitere
  Poll lief in den SSH-Fallback samt „SSH-Fallback aktiv“-Notification und
  300s-Intervall. Analog zum file-Pfad-Fix aus 1.26.3 enthält der Cache-Key
  für `uci` jetzt den Config-Namen.

## [1.26.5] - 2026-08-23

> **Blocking-Call-Warnung beim Setup behoben.** Der SSL-Kontext wird nicht
> mehr synchron im Event-Loop gebaut — HA Core warnte bei jedem Setup mit
> „Detected blocking call to set_default_verify_paths … inside the event loop".

### Fixed

- **`ssl.create_default_context()` blockierte den Event-Loop**
  `OpenWrtAPI.__init__` baute den SSL-Kontext synchron (das CA-Bundle wird
  dabei von der Platte geladen). Alle HA-Aufrufer — `async_setup_entry` und
  die drei Config-Flow-Stellen — injizieren jetzt Home Assistants prozessweit
  gecachte Kontexte (`homeassistant.util.ssl.client_context()` bzw.
  `client_context_no_verify()`) über den neuen Konstruktor-Parameter
  `ssl_context`. Die Protokoll-Auswahl kapselt das neue HA-seitige Modul
  `ssl_util.py`; `api.py` bleibt bewusst HA-frei. Der synchrone Aufbau
  existiert nur noch als Fallback für Standalone-/CLI-Nutzung außerhalb
  eines Event-Loops.

## [1.26.4] - 2026-08-23

> **Log-Hygiene auf Multi-Router-Setups.** Drei Dauerbrenner beseitigt: die
> minütliche root-Warnung, die unique_id-Kollision, wenn mehrere APs denselben
> WLAN-Client sehen, und der ewige SSH-Fallback (samt wiederkehrender
> HA-Notification) auf Routern mit einer prä-v5-ACL.

### Fixed

- **Router mit alter ACL blieben für immer im SSH-Fallback**
  Konnte `ensure_acl()` die deployte ACL-Datei nicht lesen (von alten ACLs
  blockiert), obwohl `file/stat` ihre Existenz zeigte, ließ es sie
  „unverifiable — as-is" liegen — der Router blieb dauerhaft im SSH-Fallback
  mit 300s-Polling, und die Notification „SSH-Fallback aktiv" kam nach jedem
  HA-Neustart wieder. Da jede ACL seit v5 das Lesen ihres eigenen Pfads
  erlaubt, ist eine unlesbare deployte ACL per Definition veraltet → sie wird
  jetzt neu deployt (transiente Lesefehler wie Timeouts deployen weiterhin
  NICHT, um rpcd-Restarts bei Netz-Blips zu vermeiden).

- **root-Warnung spammte ~66×/Stunde statt einmal**
  `reset_ssh_fallback_flag()` läuft am Anfang jedes Poll-Zyklus und setzte
  dabei auch das `_root_warning_logged`-Latch zurück — die Warnung
  „Using 'root' as rpcd user grants full router access" feuerte damit bei
  jedem Re-Login (~1×/Minute pro Router) erneut. Das Latch bleibt jetzt für
  die Lebensdauer der API-Instanz gesetzt (einmal pro Router und Start);
  die Meldung nennt zusätzlich den Router-Host.

- **„Platform openwrt_router does not generate unique IDs" bei Mesh-Clients**
  HA-Core leitet die unique_id von `ScannerEntity` zwingend aus
  `mac_address` ab (das bisherige entry-scoped `_attr_unique_id` wurde
  dadurch ignoriert). Sehen mehrere Router/APs denselben Client, versuchte
  jeder Eintrag eine Entity mit derselben MAC-unique_id anzulegen — HA
  verwarf die Duplikate mit einem ERROR pro Client und Neustart. Clients
  werden jetzt AP-übergreifend dedupliziert: Ein hass.data-Claim-Register
  sorgt dafür, dass genau EIN Config-Entry die Entity pro MAC anlegt
  (Claims werden beim Unload wieder freigegeben).

### Changed

- **Roaming-fähige Device-Tracker**: Die (eine) Tracker-Entity pro Client
  sucht die MAC jetzt auf ALLEN geladenen Routern — ein Client, der zwischen
  Mesh-APs roamt, bleibt `home` und meldet im neuen Attribut `connected_ap`
  den Hostnamen des APs, mit dem er gerade verbunden ist. Vorher meldete der
  Tracker `not_home`, sobald der Client den Router des besitzenden Entries
  verließ.

## [1.26.3] - 2026-08-16

> **ACL-Deployment repariert.** Das automatische rpcd-ACL-Deployment war auf
> ACL-restriktierten Routern komplett wirkungslos — betroffene Router blieben
> dauerhaft im SSH-Fallback mit reduziertem Poll-Intervall und erhöhter Last.

### Fixed

- **ACL-Auto-Deploy: `NameError` machte jeden Deploy-Versuch wirkungslos**
  `acl_provisioning.py` verwendete `OpenWrtAuthError`/`OpenWrtResponseError` in
  except-Klauseln, ohne sie zu importieren. Sobald der Router `file/read` oder
  `file/write` per ACL blockierte (genau der Fall, den das Deployment lösen
  soll), flog ein `NameError`, den `async_setup_entry` still als „provisioning
  skipped" verschluckte. Die ACL wurde nie geschrieben, der SSH-Fallback blieb
  dauerhaft aktiv. Die Exceptions werden jetzt auf Modulebene importiert;
  7 bestehende Tests, die genau diese Pfade abdecken, laufen wieder grün.

- **ACL-Deploy: SSH-Fallback wurde bei blockiertem `file/write` nie erreicht**
  Ein ACL-blockiertes `file/write` kommt aus `_call` als
  `OpenWrtMethodNotFoundError` an (Konvertierung nach bestätigtem Re-Login) —
  `_deploy_acl` fing aber nur `OpenWrtAuthError`/`OpenWrtResponseError` ab.
  Der Fehler propagierte, statt den SSH-Fallback-Deploy auszulösen. Gleiches
  galt für den (nicht-fatalen) rpcd-Neustart via `file/exec`.

- **ACL-Block-Cache blockierte alle `file`-Pfade statt nur den verbotenen**
  Der `_acl_blocked`-Cache arbeitete pro `(Objekt, Methode)`. rpcd erzwingt
  `file`-ACLs aber pro Pfad: Ein einziger nicht freigegebener Pfad (z.B.
  `/proc/net/nf_conntrack` bei alter ACL) schickte damit **alle** `file/read`-
  Aufrufe der Session in den SSH-Fallback — der Haupttreiber der erhöhten
  Router-Last. Für das `file`-Objekt enthält der Cache-Key jetzt den Pfad
  (bzw. das `command` bei `file/exec`).

### Changed

- **rpcd-ACL v5** (`RPCD_ACL_CONTENT`, wird beim nächsten Start automatisch
  deployt):
  - `/sys/class/net` → `list` — der Capability-Check probt `file/list` auf dem
    Verzeichnis selbst; der bestehende Glob `/sys/class/net/*` deckt das nicht ab.
  - `/usr/share/rpcd/acl.d/ha-openwrt-router.json` → `read` — `ensure_acl()`
    kann die deployte ACL jetzt via ubus verifizieren statt bei jedem Start
    per SSH neu zu schreiben. Bewusst nur `read`: `write` auf `acl.d` würde
    jeder rpcd-HTTP-Session erlauben, die eigenen Rechte zu erweitern.
  - `/etc/init.d/rpcd` → `exec` (write-Scope) — rpcd-Neustart nach einem
    ACL-Deploy funktioniert damit auch über ubus.

- **`scripts/ha-openwrt-router.json` mit `RPCD_ACL_CONTENT` synchronisiert**
  Die Datei für das manuelle scp-Deployment war auf einem alten Stand (ohne
  `file/stat`, `file/exec`, conntrack-/sysfs-Pfade) — ein manuelles Deployment
  nach Anleitung hat das SSH-Fallback-Problem daher nicht behoben. Ein neuer
  Test verhindert künftiges Auseinanderlaufen.

- **SSH-Fallback-Notification präzisiert** — verweist jetzt auf den
  Berechtigungs-Check im Options-Flow (automatisches Deployment) und nennt den
  korrekten Repo-Pfad `scripts/ha-openwrt-router.json` für den manuellen Weg.

### Fixed (CI / weitere durch den Lint-Gate aufgedeckte Bugs)

- **Update-Buttons: `NameError` statt Fehlerbehandlung** — `button.py` fing in
  den Check-/Perform-Updates-Handlern vier nie importierte Exception-Klassen
  (gleiche Bug-Klasse wie im ACL-Deploy). Ein Button-Press darf nie in HA
  hochschlagen: die Handler fangen jetzt breit und loggen mit Traceback.
  Die zwei zugehörigen, vorher roten Tests laufen wieder grün.

- **Coordinator: ACL-Block nach dem ersten Poll warf rohe Exception** —
  `OpenWrtMethodNotFoundError` wurde entgegen der dokumentierten Absicht von
  `_first_poll_optional` nicht in `UpdateFailed` gewrappt; HA loggte das als
  „unexpected error". Eigener except-Zweig ergänzt (Test wieder grün).

- **Topology: Router-ID mit trailing Underscore ohne MAC** — ohne MAC und ohne
  `host_ip` wurde die Node-ID als `"<hostname>_"` gebaut; die vier
  `TestRouterIdFallback`-Tests laufen wieder grün.

- **CI-Lint-Gate repariert** — `ruff check` (aktuelles ruff 0.16) fand 57
  Verstöße und brach den Test-Job vor dem Testlauf ab: Import-Sortierung,
  veraltete `noqa`, `ClassVar`-Annotationen für Klassen-Dicts, `startswith`-
  Tupel, `dict.values()`, gezielte `noqa` für bewusste best-effort-excepts.
  `ruff check` und `ruff format --check` laufen jetzt sauber durch.

- **Topology: Repeater-Override ignorierte den WAN-Carrier** — der von
  v1.26.x angelegte Helper `_has_wan_carrier()` wurde nie aufgerufen; der
  Override nutzte weiterhin die alte `gateway_port`-Ausnahme. Folgen: Ein
  verkabelter AP mit konfiguriertem STA-Interface wurde als „WLAN Repeater"
  gezeichnet, und ein 802.11s-Mesh-AP hinter einem Trunk-Port blieb als
  „Kabel" stehen (FDB-Sichtbarkeit ist kein Kabel-Beweis — Mesh-APs stehen
  genauso in der FDB). Jetzt entscheidet der Link-Carrier des WAN-Ports;
  die drei zugehörigen, vorher roten Tests laufen wieder grün.

- **Topology: Rolle „Gateway" trotz WAN-IP == eigener LAN-IP** — ein Dumb-AP,
  dessen gebridgter „WAN" die eigene Host-IP meldet, wird jetzt als AP
  klassifiziert statt als Gateway.

## [1.26.0] - 2026-08-15

> **Stabilitäts- und Bugfix-Release.** Über 30 Korrekturen in 12 Dateien —
> Topology-Darstellung, API-Zuverlässigkeit, Exception-Handling und ACL-Deployment.

### Fixed

- **Topology: Doppelte Verbindungen bei Switch-Erkennung**
  Wenn mehrere APs am gleichen Gateway-Port hingen, wurden die direkten
  Gateway→AP Edges nicht entfernt, obwohl ein Switch-Node eingefügt wurde.
  Die Topologie zeigte dann sowohl Gateway→AP als auch Gateway→Switch→AP.
  `_detect_switch_nodes` gibt jetzt `replaced_edge_ids` zurück, die in
  `build_mesh_snapshot` vor dem Hinzufügen der Switch-Edges entfernt werden.

- **Topology: Falsche WiFi-Uplink-Richtung in Mesh-Setups**
  Wenn ein AP den Gateway in seiner Client-Liste sah (möglich bei Mesh),
  wurde die Edge fälschlicherweise als `AP → Gateway` statt `Gateway → AP`
  erstellt. Die Richtung wird jetzt anhand der Router-Rolle (gateway/ap)
  korrekt bestimmt.

- **Topology: Gateways mit privater WAN-IP als AP klassifiziert**
  Router hinter ISP-Modems/FritzBoxen haben oft private WAN-IPs (z. B.
  192.168.178.2). `_detect_router_role` prüfte fälschlicherweise auf
  „public IP" und markierte diese als "ap". Jetzt gilt jeder Router mit funktionierender
  WAN-Verbindung (dhcp/pppoe/static) als Gateway.

- **Topology: Crash bei fehlendem Gateway in `_detect_switch_nodes`**
  Die Funktion gab bei fehlendem Gateway nur 2 statt 3 Werte zurueck,
  was einen `ValueError` ausloeste. Der Return-Wert ist jetzt immer
  `(switch_nodes, switch_edges, replaced_ids)`.

- **Topology: FDB-Key-Normalisierung verhindert doppelte Devices**
  `build_port_connections` mixte normalisierte und nicht-normalisierte
  MAC-Adressen. Geraete mit Bindestrich-MACs (z. B. "AA-BB-CC-DD-EE-FF")
  wurden als "unassigned" hinzugefuegt, obwohl sie bereits im FDB waren.
  FDB-Keys werden jetzt einmalig normalisiert.

- **Topology: Router-ID-Kollisionen bei identischem Hostname**
  Wenn zwei Router keine MAC hatten und denselben Hostname (z. B. "OpenWrt")
  verwendeten, kollidierten ihre IDs. Die ID enthält jetzt die Host-IP als
  Fallback: `{hostname}_{host_ip}`.

- **API: `_call_file_read_shell` war ein Stub**
  Die Methode gab immer `{}` zurueck, wodurch `get_disk_space()` und
  `get_tmpfs_stats()` nie echte Daten lieferten. Jetzt wird der SSH-Fallback
  verwendet, um Shell-Kommandos auszufuehren.

- **API: Race Condition bei `async_close`**
  Waehrend des Shutdowns konnten parallele `_call()`-Tasks noch laufen,
  was zu "Session expired"-Fehlern fuehrte. Ein `_closing`-Flag blockiert
  jetzt neue Calls waehrend des Shutdowns.

- **API: Doppelte UTF-8-Dekodierung in SSH-Fallbacks**
  `_asyncssh_run` mit `binary=False` dekodiert bereits in `str`. Die
  SSH-Fallback-Methoden dekodierten den Rueckgabewert ein zweites Mal.
  Die redundante Dekodierung wurde entfernt.

- **API: Falsche `enabled=True` bei procd Services**
  `service/list` liefert keine `enabled`-Info, aber der Code setzte
  hartcodiert `True`. Jetzt wird `None` verwendet (unbekannt).

- **ACL: `file/exec` fehlte in der ACL**
  Nach dem ACL-Deploy wird `file/exec` aufgerufen, um rpcd zu restarten —
  aber `exec` war nicht in der ACL erlaubt. Der Restart schlug immer fehl.
  `file` Permissions jetzt: `["read", "stat", "list", "exec"]`.

- **Exception-Handler: `asyncio.CancelledError` wurde verschluckt**
  In `coordinator.py`, `topology_panel.py` und `button.py` fingen
  `except Exception`-Bloecke auch `asyncio.CancelledError` ab, was
  HA-Shutdown blockieren konnte. Die Handler wurden auf spezifische
  Exception-Typen eingeschraenkt.

- **Sensor: 0 dBm als "unknown" klassifiziert**
  `_signal_quality` behandelte `0 dBm` als "unknown". 0 dBm ist ein
  extrem starkes Signal (direkt neben der Antenne) und wird jetzt
  korrekt als "good" bewertet.

- **Sensor: ISO-Zeitstempel mit `Z`-Suffix**
  `_seconds_since` konnte `2026-08-15T18:00:00Z` nicht parsen
  (Python < 3.11). Das `Z`-Suffix wird jetzt in `+00:00` umgewandelt.

### Changed

- `manifest.json`: Version 1.25.0 -> 1.26.0
- `acl_provisioning.py`: ACL_VERSION 3 -> 4
- `topology_panel.py`: Panel-Version auf 20260815-v1.26.0 aktualisiert

## [1.25.0] - 2026-07-04

> **Fokussierung auf OpenWrt.** Die optionalen Zusatz-Features **Fritz!Box (TR-064/DSL)**
> und **Managed Switch** wurden vollständig entfernt. Die Integration ist jetzt reine
> OpenWrt-Router-Funktionalität.

### Removed

- **Fritz!Box (TR-064/DSL-Modem):** SOAP/TR-064-Client (`fritzbox.py`), Coordinator-Polling,
  Config-/Options-Flow-Felder sowie die DSL-Kennzahlen (Sync-/Max-Rate, SNR-Marge,
  Leitungsdämpfung) und der DSL-Verlaufsgraph. DSL-Werte stammen vom vorgelagerten
  DSL-Modem und lassen sich nicht aus OpenWrt-Daten ableiten.
- **Managed Switch (externes Gerät):** der `switch_dev`-Config-Flow-Step und die
  `switch_*`-Konfigurationsfelder. Dieser Zweig war ein ungenutzter Setup-Stub (wurde nie
  gepollt oder als Entität ausgewertet).

### Changed

- **WAN-Durchsatz jetzt immer nativ:** Download-/Upload-Rate (`wan_traffic`) wird
  ausschließlich aus den OpenWrt-WAN-Interface-Zählern (rx/tx-Byte-Delta pro Poll)
  berechnet. Der bisherige Fritz!Box-Pfad entfällt; Live-Werte in „WAN Aktivität",
  Footer und Edge-Tooltip bleiben erhalten.
- **Config-Flow verkürzt:** `user → checklist` (der Zwischen-Step „Zusätzliche Geräte"
  entfällt). Optionen enthalten nur noch das Topology-Debug-Flag.

> **Hinweis:** Nach dem Update ist ein **Neustart von Home Assistant** empfohlen (entfernte
> Plattform-/Frontend-Assets). Bestehende Router-Einträge bleiben unverändert; verwaiste
> `fritzbox_*`/`switch_*`-Schlüssel in den Optionen werden ignoriert.

## [1.24.1] - 2026-07-03

> **Topology-Fix.** Ein per WLAN angebundener **Mesh-AP** (z. B. 10.10.30.50 in VLAN 30)
> wurde in der Topologie fälschlich als **„Kabel"** angezeigt.

### Fixed

- **Mesh-AP als „Kabel" statt WLAN:** Die Repeater-/WLAN-Erkennung
  (`topology_mesh._has_active_sta_interface`) verlangte eine Client-STA-Assoziation
  (BSSID **und** Signal). Ein 802.11s-**Mesh-Point**-Backhaul liefert beides nicht wie ein
  klassischer STA-Client — dadurch griff das „Repeater-Override" nicht und der über die
  Gateway-Bridge-FDB gelernte AP blieb ein `lan_uplink` („Kabel"). Ein Mesh-Point-Interface
  gilt jetzt allein durch seine (aktive) Präsenz als WLAN-Uplink.
- **Cross-Subnet-Mesh ohne Kante:** Ein Mesh-AP in einem **anderen** Subnetz/VLAN (VLAN 30
  unter einem VLAN-10-Gateway) wurde von keiner Erkennungsmethode erfasst (Subnetz-Fallback
  greift nur im gleichen /24) und fiel auf den Frontend-Default „Kabel" zurück. Ein
  unverbundener AP mit aktivem Mesh-/STA-Interface bekommt jetzt einen verifizierten
  `wifi_uplink` zum Gateway — auch über VLAN-Grenzen hinweg.
- **Härtung:** `get_sta_interface_details` (UCI-Fallback) überspringt jetzt **deaktivierte**
  wifi-ifaces, damit ein deaktivierter Mesh-/STA-Eintrag keinen kabelgebundenen AP
  fälschlich auf WLAN kippt.

> Hinweis: Der Mesh-AP erscheint danach als **„WLAN-Repeater"** (die UI unterscheidet aktuell
> `wired` / `mesh` / `repeater`; ein verifizierter WLAN-Uplink ist `repeater`). Wichtig ist:
> nicht mehr „Kabel".

### Tests

- `test_topology_mesh.py`: Mesh-AP (mode=mesh point, ohne bssid/signal) → `wifi_uplink`;
  gekabelter Mesh-fähiger AP (WAN-Carrier) bleibt `lan_uplink`; Cross-Subnet-Mesh-AP bekommt
  `wifi_uplink`-Fallback; Router ohne STA/Mesh in fremdem Subnetz bekommt weiterhin keine
  Kante. `_has_active_sta_interface`-Unit-Tests. `test_api.py`: UCI-Fallback überspringt
  deaktivierte ifaces. Gesamtsuite: 597 grün.

## [1.24.0] - 2026-07-03

> **Multi-Router-Release.** Mehrere OpenWrt-Router (z. B. 10.10.10.1, .2, .4 — baugleiche
> Cudy WR3000) ließen sich nicht zuverlässig parallel hinzufügen: Router 1 klappte, der
> zweite/dritte brach ab oder kam nach grüner Checklist nicht sauber hoch. Ursache waren
> die `unique_id`-Ableitung und die Reihenfolge des ACL-Deploys im Setup — beides ist jetzt
> gefixt. Neuer Multi-Router-Smoke-Test beweist: .1/.2/.4 existieren danach als eigene
> Einträge/Geräte, ohne falschen `already_configured`-Abbruch.

### Fixed

- **Zweiter/dritter Router wurde als „bereits konfiguriert" abgewiesen:** Die `unique_id`
  wurde aus dem Router-MAC gebildet (`config_flow.py`). OpenWrts `system board` liefert aber
  meist gar kein Top-Level-`mac`-Feld, und baugleiche Geräte können denselben Platzhalter-
  bzw. leeren MAC melden — dann kollidierten alle Router auf eine `unique_id` und der zweite
  brach mit `already_configured` ab. Die `unique_id` ist jetzt **host-basiert**
  (`host:port`, siehe neue Helper `_compute_unique_id`): unterschiedliche (feste) IPs sind
  immer getrennte Einträge, ein echtes erneutes Hinzufügen desselben Hosts wird weiterhin
  korrekt verhindert.
- **Router kam nach grüner Checklist nicht sauber hoch / erst nach Reload:** Der ACL-Deploy
  lief in `async_setup_entry` **nach** dem ersten Datenabruf. Dabei cachte der API-Client die
  vor dem Deploy noch ACL-geblockten ubus-Methoden dauerhaft (`_acl_blocked`) und schaltete
  sie auch nach dem Deploy weiter kurz — der Router lief bis zum nächsten Reload degradiert.
  Jetzt wird die ACL **vor** dem ersten Refresh deployt, danach neu eingeloggt und der
  Block-Cache geleert (neue Methode `api.reset_acl_blocked()`), sodass der erste Poll bereits
  die frisch freigegebenen Methoden nutzt.

### Changed

- **First-Refresh-Härtung:** Wird beim allerersten Poll (Setup) eine Kern-ubus-Methode noch
  durch die gerade erst deployte ACL blockiert (`OpenWrtMethodNotFoundError`), fällt der
  Coordinator auf leere Defaults zurück statt `ConfigEntryNotReady` zu werfen — der Router
  kommt hoch statt in „Wird wiederholt" zu hängen. Echte Verbindungs-/Timeout-/Auth-/
  Response-Fehler propagieren unverändert; im Dauerbetrieb bleibt das strikte Fail-Fast.
- **`network_wireless`-Capability** gilt jetzt auch als erfüllt, wenn Wireless über
  hostapd **oder** UCI erreichbar ist (nicht nur `network.wireless/status` oder `iwinfo`).
  Kein falscher „Kritisch"-Alarm mehr auf Stock-Cudy-Firmware, die für
  `network.wireless/status` rc 2 liefert und kein iwinfo hat.

### Tests

- Neuer Multi-Router-Smoke-Test (`test_config_flow.py`): fügt .1/.2/.4 nacheinander in
  dieselbe Domain ein, treibt das echte `_abort_if_unique_id_configured()` und beweist drei
  getrennte Einträge ohne Abbruch; erneutes Hinzufügen desselben Hosts bricht korrekt ab.
- `_compute_unique_id`-Unit-Tests (distinct hosts, geteilte/leere/all-zero MAC → trotzdem
  eindeutig), Setup-Reihenfolge-Test (ACL vor First-Refresh + `reset_acl_blocked`),
  First-Poll-Härtungs-Tests, `network_wireless`-via-UCI-Test. Gesamtsuite: 587 grün.

## [1.23.0] - 2026-07-03

> **Checklist-Release.** Nach einem erfolgreichen ACL-Deploy blieben „Datei-Lesezugriff" und
> „WLAN-Status" trotzdem rot (fälschlich als „Kritische Berechtigungen fehlen"), obwohl die
> Integration funktioniert. Am echten Cudy WR3000 (10.10.10.1) verifiziert: jetzt alle 9 Punkte grün.

### Fixed

- **Datei-Lesezugriff blieb rot:** Das rpcd-`file`-Objekt prüft Lesezugriff PRO PFAD. Die ACL
  gewährte unter `read.file` nur ddns-Pfade — `/etc/openwrt_release`, `/sys/class/net/*` (Bridge-FDB,
  Interface-Statistiken, Port-Nummern), `/proc/net/arp` und conntrack waren blockiert und fielen auf
  SSH zurück. Diese read-only System-Pfade sind jetzt in der ACL → file/read läuft direkt über ubus
  (schneller, kein SSH nötig). `ACL_VERSION` 2→3 löst beim nächsten Start ein automatisches Redeploy aus.
- **WLAN-Status blieb rot:** Manche Firmware (Cudy Stock) liefert für `network.wireless/status`
  ubus INVALID_ARGUMENT. Die WLAN-Daten kommen ohnehin über iwinfo/hostapd — die Capability gilt
  jetzt als erfüllt, wenn `network.wireless` ODER `iwinfo` funktioniert. Kein falscher „Kritisch"-Alarm mehr.
- **Manuelle Anleitung repariert:** Der Checklist-Hinweis zeigte `scp ha-openwrt-router.json root@…`,
  was auf eine Datei verweist, die der Nutzer nicht hat. Jetzt: Verweis auf die Auto-Deploy-Checkbox
  (inkl. der dropbear-`PasswordAuth`-Befehle, die der SSH-Fallback braucht) plus ein funktionierender
  manueller `cat > acl.d/… <<'EOF'`-Block, dynamisch aus dem echten ACL-Inhalt erzeugt.

### Notes

- Auto-Deploy der ACL (Checkbox) benötigt aktives SSH-Passwort-Login am Router
  (dropbear `PasswordAuth on`, bei manchen Geräten zusätzlich `RootPasswordAuth on`).

## [1.22.0] - 2026-07-03

> **Transport-Release.** Der SSH-Fallback läuft jetzt pure-Python über **asyncssh** —
> kein `sshpass`/`ssh`-Binary auf dem HA-Host mehr nötig. Auf HAOS und typischen
> Containern war der Fallback vorher faktisch tot (sshpass nicht installiert). Alle
> Wrapper-Signaturen und Rückgabe-Verträge bleiben unverändert.

### Fixed

- **SSH-Fallback auf Hosts ohne `sshpass` tot:** Die gesamte SSH-Fallback-Schicht
  (hostapd-Clients, WLAN-Status, Bridge-FDB, ARP, WAN-Statistiken, opkg-Update,
  ACL-Deploy) schlug auf HAOS/Containern still fehl, weil `sshpass` dort nicht
  existiert (Spawn-Fehler). Transport ist jetzt in-process asyncssh — das Passwort
  landet nur noch als asyncssh-`password`-Argument, nie in argv/env/Log.
  Am echten Cudy WR3000 verifiziert (6/6 Datenquellen inkl. SSH-Fallbacks).

### Changed

- `manifest.json`: `requirements: ["asyncssh>=2.22.0"]` (HA installiert die Abhängigkeit
  automatisch beim Update), `loggers: ["asyncssh"]`.
- Der Key-Auth-Retry (bei abgelehntem Passwort → `~/.ssh`-Keys/Agent) gilt jetzt auch
  für die sechs Direkt-Callsites und detachte Kommandos, nicht nur die Wrapper.
- `_safe_subprocess_exec` bleibt (regressionsgetestet), hat aber keine produktiven
  Aufrufer mehr.

### Tests

- `test_sshpass_security_v1179.py` → `test_ssh_transport.py` (11 Tests, asyncssh gemockt);
  die Detached-Wrapping-Tests aus `test_subprocess_lifecycle.py` dorthin portiert.

### Docs / Security

- README/SSH_SETUP: sshpass → asyncssh. **Klartext-Router-Passwort aus `SSH_SETUP.md`
  entfernt** (stand dort in Zeile 73 — bleibt in der Git-Historie; Passwort-Rotation empfohlen).

> **Router-Hinweis:** Der SSH-Fallback braucht `dropbear` mit aktivem `PasswordAuth`
> (bei manchen Geräten zusätzlich `RootPasswordAuth`). Ist er aus, meldet der
> Checklist-Schritt seit v1.20.1 einen klaren Fehler statt still zu scheitern.

## [1.21.0] - 2026-07-03

> **Port-Zuordnungs-Release.** Die Topology zeigte Geräte an falschen physischen Ports —
> Ursache war ein fehlerhaftes Binär-Parsing der Bridge-FDB (8 statt 16 Bytes pro Eintrag,
> `is_local` ignoriert) plus ein Case-Mismatch beim DHCP-Lease-Lookup. Jetzt gibt es ein
> echtes Port→Gerät-Datenmodell mit Confidence-Stufen — und die Port-Kacheln zeigen, was
> dranhängt.

### Fixed

- **brforward-Parsing korrigiert:** `/sys/class/net/br-lan/brforward` besteht aus
  16-Byte-`struct __fdb_entry`-Records — der alte 8-Byte-Parser las jeden zweiten
  Eintrag als Müll und ignorierte `is_local`, wodurch **Router-eigene MACs als
  angeschlossene Geräte an Ports erschienen**. Multicast/Broadcast/Null-MACs werden
  gefiltert, `port_hi` wird berücksichtigt, VLAN-Subinterface-Member (`lan1.10`)
  zählen zum physischen Port.
- **Lease-Lookup case-normalisiert:** DHCP-Leases sind UPPERCASE-gekeyt, FDB-MACs
  lowercase — der Hostname-Lookup lief dadurch immer ins Leere und Ports zeigten
  rohe MACs statt Gerätenamen.
- **Deterministische Gerätewahl:** `connected_device` folgte der zufälligen
  FDB-Reihenfolge und konnte bei jedem Poll wechseln. Geräte werden jetzt nach
  Confidence → Name → MAC sortiert.

### Added

- **Port→Gerät-Datenmodell** (`topology_ports.py`): pro Port `connected_devices[]`
  mit Name/IP/MAC/Quelle (`fdb+dhcp+arp`) und Confidence (`high`/`medium`/`low`/
  `none`), `primary_device`, `device_count`, `has_downstream_switch`, `web_url`.
  Keine Fake-Zuordnungen: Identitäten ohne verlässlichen FDB-Port landen im
  `unassigned`-Bucket (`unknown_port`), reine Lease-Geister werden verworfen,
  WLAN-Clients erscheinen nie auf LAN-Ports, der WAN-Port bekommt nie FDB-Geräte.
- **ARP-Tabelle als Datenquelle:** `get_arp_table()` (MAC→IPv4) via ubus
  `file/read /proc/net/arp` mit SSH-Fallback — löst Geräte mit statischer IP ohne
  DHCP-Lease auf; `get_trunk_port_map()` nutzt die vorgeholten Maps (kein doppelter
  FDB-Read pro Zyklus mehr).
- **Topology-UI — Port-Kacheln:** zweite Zeile mit Gerätename/IP, `n Geräte`,
  `Switch/AP`, `Internet` (WAN) oder `Unbekannt`; Hover-Tooltip listet bis zu
  6 Geräte mit Confidence-Punkt; **Klick öffnet ein Port-Detail-Panel** mit
  Status/Speed/VLANs und allen Geräten inkl. klickbarem `http://<ip>`-Link
  (neuer Tab, `rel="noopener noreferrer"`, IP wird client-seitig validiert).
- **Geräte-Icons pro Port:** unter der Port-Leiste erscheinen die kabelgebundenen
  Geräte als gruppierte Dots je LAN-Port (max. 4 + Overflow) — Mesh-APs am
  Trunk-Port mit Router-Icon und „Zum Access Point"-Sprung.
- **Mesh: Nearest-Switch-Regel:** Geräte, die ein AP selbst auf seiner
  Access-Seite sieht, werden dem AP zugerechnet und nicht mehr flach auf den
  Gateway-Trunk-Port gelegt; der AP selbst erscheint dort als primäres Gerät.
- **Debug-Option** (`topology_port_debug`, Optionen-Dialog): liefert im
  auth-geschützten Snapshot pro Port die Roh-Zuordnung (FDB-MACs, DHCP/ARP-Treffer,
  gefilterte MACs, finaler Stand, Begründung). HA-Diagnostics enthalten stattdessen
  eine **PII-freie `port_mapping`-Zusammenfassung** (Counts, Confidence, Quellen);
  die neue `arp_table` wird dort wie die DHCP-Leases als Count redacted.

### Changed

- Alte Snapshots ohne die neuen Felder rendert das Panel unverändert wie bisher
  (alle neuen Felder optional; Legacy-`connected_device`-String bleibt erhalten
  und zeigt am Trunk-Port weiterhin den AP-Hostnamen).

## [1.20.1] - 2026-07-03

> **Checklist-Fix-Release.** „Berechtigungen automatisch einrichten" im Setup zeigte bei
> Fehlschlag kommentarlos dieselbe Form erneut — und konnte auf ACL-restriktiven Routern
> (z. B. Cudy WR3000) prinzipbedingt nie funktionieren.

### Fixed

- **Feedback beim ACL-Deploy:** Der Checklist-Schritt zeigt jetzt das Ergebnis an —
  `acl_deploy_failed` (ubus **und** SSH abgelehnt), `acl_already_current` (ACL war schon
  aktuell — Ursache liegt woanders), `acl_deploy_no_change` (geschrieben, aber Rechte nach
  Re-Check unverändert) sowie eine grüne Erfolgszeile. Vor dem Re-Check: 2 s Karenz +
  ein Login-Retry (rpcd-Neustart-Race).
- **Phantom-Zeile entfernt:** „Datei-Ausführung (Bridge FDB, ARP)" wurde nie geprobt und war
  bei JEDEM Router dauerhaft rot — dadurch war der grüne Gesamtstatus unerreichbar und die
  Deploy-Checkbox erschien immer. `file/exec` wird seit 1.15.6 zur Laufzeit nicht mehr genutzt.
- **rpcd-Session-Leck im Checklist-Schritt:** Die Wegwerf-API-Instanzen (Deploy + Re-Check)
  werden jetzt via `async_close()` geschlossen.

### Added

- **SSH-Fallback für das ACL-Deploy:** Blockiert der Router ubus `file/write` (Henne-Ei:
  das Deploy braucht genau die file-Rechte, die die ACL erst gewähren würde), wird die ACL
  per SSH mit denselben Zugangsdaten geschrieben und rpcd neu gestartet (sshpass -e —
  Passwort nie in argv). *SemVer-Anmerkung: streng genommen ein Minor-Feature; als Patch
  veröffentlicht, weil es das seit 1.15.4 beworbene Auto-Deploy erst flächendeckend
  funktionsfähig macht.*

### Changed

- `ensure_acl`/`check_and_deploy_acl` werfen bei fehlgeschlagenem, aber nötigem Deploy jetzt
  `AclDeployError` statt still `False` (Setup bleibt unberührt — `async_setup_entry` fängt
  weiterhin alle Fehler best-effort ab).

## [1.20.0] - 2026-07-03

> **HA-Kompatibilitäts-Release.** Review gegen HA-Core-Standards Stand Juli 2026
> (aktuell HA 2026.7): eine harte Deadline behoben, CI ehrlich gemacht, Übersetzungen
> vervollständigt. Keine Verhaltensänderung auf HA ≥ 2026.2.

### Fixed

- **HA-2026.8-Deadline:** `DataUpdateCoordinator` erhält `config_entry=` jetzt explizit —
  die implizite ContextVar-Übergabe wird in HA 2026.8 entfernt; ohne den Fix bräche u. a.
  der Reauth-Start aus dem Coordinator.
- **Toter Code entfernt:** Sync-Fallback `hass.http.register_static_path` im Topology-Panel
  (durch den Modul-Import von `StaticPathConfig` ohnehin unerreichbar; seit HA 2024.6 obsolet).

### Changed

- **Mindest-HA-Version ehrlich deklariert:** hacs.json-Floor von 2024.1.0 auf **2026.2.0**
  (der Code benötigte real bereits ≥ 2024.11 — Options-/Reauth-Flow crashten auf älteren Cores).
- `manifest.json`: `integration_type: "hub"` ergänzt.
- README: dynamische Versions-/Test-Badges (Badge war bei 1.15.6 eingefroren),
  explizite Mindest-HA-Angabe.

### Added

- **Deutsche Übersetzung** (`translations/de.json`, 109 Keys). Die EN-Quelle
  (strings.json/en.json) ist jetzt durchgängig englisch — Checklist-Step und einige
  Entity-Namen waren zuvor deutsch im EN-Master.
- Blueprint „Router Ausfall-Benachrichtigung": moderne Plural-Syntax
  (`triggers:`/`actions:`, `action:` statt `service:`), `source_url`, `min_version`.
- CHANGELOG: fehlender [1.19.0]-Eintrag nachgetragen (Release war ohne Changelog erschienen).

### CI

- **Release-Gate:** `release.yaml` erstellt Releases nur noch nach grünen `test`- und
  `hassfest`-Jobs.
- **Test-Matrix 3.13/3.14** (vorher 3.12/3.13): Unter Python 3.12 löste pip nur HA 2024.x
  auf, unter 3.13 maximal HA 2026.2 — HA 2026.3+ verlangt Python ≥ 3.14. Der wöchentliche
  ha-compat-Check pinnt jetzt die tatsächlich neueste HA-Version statt still gegen eine
  ältere zu testen.

### Notes / Offen

- Geplant (siehe TODO.md): Migration der SSH-Fallback-/Outage-Notifications auf das
  Repairs-System (`issue_registry`) inkl. i18n der bisher hart deutschen Meldungstexte.
- Nicht betroffen von aktuellen Deprecations (verifiziert): Device-Tracker-Änderungen
  2026.6 (`battery_level`/`location_name`), `show_advanced_options`,
  Update-Listener+Reload-Pattern.

## [1.19.0] - 2026-05-28

> **Stabilitäts-Release nach rpcd-OOM-Forensik.** Adressiert die in der 24h-Production-Diagnose
> nachgewiesene Restursache: rpcd-Session-Leck auf dem Router durch Re-Login-Churn.

### Fixed

- **rpcd-Session-Leck:** Beim Re-Login wird die vorherige ubus-Session jetzt aktiv via
  `session.destroy` zerstört, statt auf dem Router zu verwaisen (Ursache des rpcd-OOM auf
  Produktiv-Hardware).
- **Re-Login-Churn gestoppt:** ACL-geblockte ubus-Methoden werden pro Session gecacht und nicht
  mehr bei jedem Poll erneut versucht — vorher provozierte jeder Poll neue Login-Zyklen.
- **ACL-Re-Validierung:** Die rpcd-ACL wird bei jedem Start gegen den Soll-Inhalt geprüft und bei
  Drift aktualisiert (vorher nur bei Erstinstallation deployed).
- **Setup-Robustheit:** Optionaler `topology_card`-Import ist geguardet — Setup übersteht das
  Fehlen des WIP-Moduls.

### CI / Tests

- `ruff format` über die Codebase (CI-Format-Check).
- Sync-Sensor-Tests nutzen `asyncio.run` (Fix für CI auf Python 3.12+).

### Docs / Diagnostics

- v1.19-Scope-Dokument nach v1.17.9-Crash-Forensik (`docs/v1.19-scope.md`).
- 24h-Production-Baseline als JSONL (`diagnostics/prod-24h-baseline.jsonl`).

## [1.18.0] - 2026-04-29

> **Hardening-Release.** Kein garantierter Fix für die sporadischen HA-Crashes unter Last — der Beweis kommt aus der parallel laufenden 24h-Production-Diagnose. v1.18.0 schließt nachweisbare Lecks im Subprocess- und Panel-Lifecycle und liefert das Mess-Tooling, mit dem v1.19 die Restursache adressieren kann.

### Hardening — Subprocess-Lifecycle (F4)

- **Zentraler Helper `_safe_subprocess_exec`** in `api.py`. Alle 11 vormals direkten `asyncio.create_subprocess_exec`-Aufrufe wurden durch `_run_ssh` / `_run_ssh_binary` / `_run_ssh_detached` ersetzt; alle drei Helper laufen über denselben leak-freien Spawn-Pfad. Garantierte Cleanup-Sequenz `terminate → shielded wait(2s) → kill → shielded wait(2s)` auf JEDEM Exit-Pfad: success, non-zero rc, timeout, spawn-fail (`OSError`/`ValueError`), generic exception, `CancelledError` mid-flight UND `CancelledError` mid-cleanup.
- **6 vormals leak-prone Stellen** in `api.py` migriert: `get_wan_status` rx/tx-Fallback, `_set_wifi_state_ssh`, `_get_wifi_status_ssh`, `_get_network_interfaces_ssh`, `get_bridge_fdb` (binär, NUL-safe), `perform_system_update` (opkg, detached).
- **Doppel-Cancel-Härte (Release-Gate-Fix)**: beide `proc.wait()` im finally-Block sind jetzt `asyncio.shield`-gewrappt; ein Cancel während des Cleanups markiert intern `cleanup_cancelled=True`, eskaliert aber trotzdem bis SIGKILL + finalem Reap und re-raised `CancelledError` erst danach. Resultat: keine Zombies und keine Pipe-FDs mehr offen, auch unter HA-Shutdown-Druck.
- **Sentinels** für nicht-OS-Returncodes: `SUBPROCESS_RC_TIMEOUT=-1`, `SUBPROCESS_RC_FAILED_TO_SPAWN=-2`, `SUBPROCESS_RC_CANCELLED=-3`. Caller distinguieren ohne `None`-Optional-Dance.

### Hardening — Panel-Lifecycle (F3)

- **Reference-Counting** in `topology_panel.py`: jede `async_setup_entry` bumpt `_PANEL_REFCOUNT_KEY`, jede `async_unload_entry` dekrementiert. Beim Last-Unload wird die Sidebar via `async_remove_panel` entfernt und der Snapshot-View **soft-disabled** — `OpenWrtMeshSnapshotView.get()` antwortet ab dann mit `HTTP 410 Gone`, bis ein neuer Entry den Flag zurücksetzt. Akzeptierter Trade-off: der statische Frontend-Pfad bleibt registriert (HA aiohttp router ist append-only, byte-konstant, kein Leak).
- **Setup-Failure-Recovery (Release-Gate-Fix)**: pro-Stage-Flags `_PANEL_STATIC_BOUND_KEY` / `_PANEL_VIEW_BOUND_KEY` lassen einen Retry nach partialer Failure die fehlende Stage ergänzen, ohne bereits gebundene Resources doppelt zu registrieren. Master-Flag `_PANEL_REGISTERED_KEY` wird nur nach vollständigem Erfolg gesetzt; Refcount wird bei Failure rolled-back. `asyncio.Lock` (`_PANEL_SETUP_LOCK_KEY`) serialisiert concurrent Setup-Calls bei HA-Boot mit mehreren Config-Entries.
- **`async_unload_entry`** ruft jetzt zusätzlich `async_teardown_topology_panel(hass)` und `entry.runtime_data.api.async_close()` (defensive try/except, beide nicht-blockierend bei Router-Ausfall — kein RPC).

### Fixed

- **opkg-Update Quote-Bug (pre-existing, jetzt behoben).** Der Filter-Command `grep -v -E '^addon-|^luci-' | cut -d' ' -f1` enthielt Single-Quotes, die das alte naive Wrapping `nohup sh -c '<cmd>' &` zerbrochen haben — die remote-Bash hat Pipe-Tokens statt Regex-OR interpretiert. `_run_ssh_detached` quoted `remote_cmd` jetzt POSIX-konform via `shlex.quote()`. Verifiziert mit `shlex.split(remote, posix=True)` round-trip-Test.

### Added

- **F5 Aggregator-Skeleton (deaktiviert).** Method `_call_aggregator()` und Schema-Version-Validator `_parse_aggregator_response()` in `api.py`; `CONF_USE_AGGREGATOR` / `DEFAULT_USE_AGGREGATOR=False` / `AGGREGATOR_SCHEMA_VERSION="1.18.0"` / `AGGREGATOR_REMOTE_SCRIPT_PATH="/root/ha-collect.sh"` in `const.py`. `_call_aggregator()` raises `NotImplementedError` bis das Remote-Script in v1.19+ deployed wird. Aktivierung erfolgt erst nach 24h-Diagnose-Auswertung.
- **24h-Production-Sampler** `scripts/_prod_24h_sample.sh`. Read-only, pure `/proc` + `ps` + `find` (kein `lsof` nötig — funktioniert in Containern). 60s-Intervall, JSONL-Output mit RSS / VmSize / Threads / FD-Total / FD-by-Type (socket / pipe / file) / Subprocess-Count / Zombie-Count. Auswertungs-Decision-Rules im Skript-Header dokumentiert.
- **API**: neue `OpenWrtAPI.async_close()` Methode dropped Session-Token + Caches ohne RPC. Wird von `async_unload_entry` aufgerufen.

### Tests

- **484 grün** (+36 neue gegenüber v1.17.9):
  - `tests/test_subprocess_lifecycle.py` — 11 Tests inkl. Cancel-during-cleanup-Eskalation, NUL-Bytes-Round-Trip, Quote-Round-Trip via `shlex.split`.
  - `tests/test_panel_lifecycle.py` — 13 Tests inkl. Refcount-Idempotenz, Re-Arm nach Last-Unload, Setup-Failure-Rollback (sowohl static-path als auch panel-register), Retry-überspringt-bereits-gebundene-Stages.
  - `tests/test_aggregator_skeleton.py` — 11 Tests für Feature-Flag-Defaults, Schema-Version-Drift, JSON-Parse-Validation.

### Notes & Disclaimer

- **Dies ist kein Crash-Fix-Release im strengen Sinn.** Wir haben echte Lecks in 6 Subprocess-Pfaden geschlossen und das Panel-Lifecycle gehärtet, aber ob die sporadischen HA-Crashes unter Last damit verschwinden, beweist erst die parallel laufende 24h-Production-Diagnose. Falls FD-Trend nach v1.18.0 weiterhin monoton steigt, geht es in v1.19 mit dem Aggregator-Pfad (F5) weiter.
- **Backward-compatible**: keine Migrations-Schritte nötig, keine Config-Entry-Schema-Änderung, kein Entity-Bruch.
- **F5 Aggregator** ist deaktiviert (Default-Off) — nur Skeleton-Code, raises `NotImplementedError` bei Aktivierung.

## [1.17.9] - 2026-04-29

### Security

- **🔴 sshpass-Passwort wurde via Kommandozeile exponiert.** Bis v1.17.8 wurden alle SSH-Fallback-Calls in `api.py` als `sshpass -p <password> ssh ...` ausgeführt. Damit landete das Klartext-Passwort in `/proc/<pid>/cmdline` und war für jeden Prozess auf demselben System (HA-Container, WSL2, Docker-Host) via `ps aux` sichtbar. Fix: alle 12 SSH-Aufrufstellen in `api.py` auf `sshpass -e` umgestellt; das Passwort wird jetzt via `SSHPASS`-Env-Variable an den Subprocess übergeben (neue Helper `_ssh_env()` + erweitertes `_build_ssh_cmd`). Affected paths: WAN-Status, RX/TX-Bytes, hostapd-Clients, iw station-dump, WiFi-Control, UCI-Show, Network-Interfaces, Bridge-FDB, opkg-Update.
- 4 neue Regressions-Tests (`tests/test_sshpass_security_v1179.py`): Quellcode-Scan auf `-p <pw>`-Pattern, `_ssh_env()`-Helper-Verträglichkeit, `_build_ssh_cmd`-Verifikation für Password- und Key-Auth-Pfad.

### Changed

- **`manifest.json`: `requirements` ist jetzt leer.** Der Eintrag `aiohttp>=3.9.0` war redundant — `aiohttp` ist von Home Assistant als Core-Dependency immer mitgeliefert. Externer pip-Eintrag konnte den HACS-Resolver verlangsamen und theoretisch zu Versionskonflikten mit der HA-internen aiohttp-Version führen. HA-Konvention: `requirements` listet nur Libraries die HA NICHT mitbringt.

### Tests

- 448 grün (+4 neu, +3 von v1.17.8 Memory-Suite).

## [1.17.8] - 2026-04-29

### Fixed

- **Wiring-View: Medium-Mapping war semantisch invertiert.** In `WiringView.tsx` wurde `uplinkType='mesh'` (Backend `mesh_member`, unverifizierter Subnet-Fallback) als "WLAN" angezeigt und `uplinkType='repeater'` (Backend `wifi_uplink`, per STA-MAC verifiziert) als "Mesh?". Korrektes Mapping: `wired→Kabel`, `repeater→WLAN`, `mesh→Mesh?`.
- **Wiring-View: "-60 dBm"-Default täuschte echtes Signal vor.** `api.ts` setzte `backhaulSignal: number` mit `?? -60` — `mesh_member`-Edges (kein Signal-Attribut) zeigten dadurch reproduzierbar "-60 dBm" als ob es ein Messwert wäre. Neues Flag `backhaulSignalKnown` markiert echte RSSI-Werte; Wiring-Status zeigt sonst `verbunden` (WLAN) oder `vermutet · <ip>` (Mesh?).
- **Wiring-View: Default-Hostname "OpenWrt" → unkonfigurierter Router.** Frisch geflashte Router (Hostname `openwrt`/`lede`) werden jetzt als kursiv-gedimmtes "`<ip>` (unkonfiguriert)" angezeigt, statt als gleichwertige Wiring-Zeile.
- **Wiring-View: STA-Port für WLAN-Repeater.** Backend setzt `ap_port=null` bei `wifi_uplink`-Edges (kein physischer Port). WiringView zeigt jetzt `STA` für Medium=WLAN, statt leerem `—`.

### Tests

- 441 Tests grün (unverändert — Bugs liegen ausschließlich im Frontend-Adapter und der View-Komponente; Backend-Edge-Schema ist korrekt).

## [1.17.7] - 2026-04-29

### Fixed

- **Topology: AP3 wurde fälschlich als "WLAN Repeater" angezeigt, obwohl er per Kabel angeschlossen war.** Der v1.17.5 Repeater-Override in `topology_mesh._detect_inter_router_edges()` löste sich bereits aus, sobald *irgendein* `sta_interfaces`-Eintrag für einen Router vorhanden war. UCI-Fallback in `api.get_sta_interface_details()` listet aber auch deaktivierte/abgemeldete Wireless-Sections — ohne `bssid` und ohne `signal`. Solche Stale-Einträge stempelten Kabel-APs zu Repeatern. Fix: zwei Helfer `_has_active_sta_interface(data)` (verlangt `bssid`+`signal`) und `_has_wan_carrier(data)` (prüft `port_stats[wan].up`); der Override greift jetzt nur, wenn die STA-Iface aktiv assoziiert ist *und* der WAN-Port keinen Link-Carrier hat. Echte WLAN-Repeater (z. B. OpenWrt) bleiben unverändert auf `wifi_uplink`.

### Added

- **Neue Sidebar-Ansicht "Verkabelung"** — strukturierte Tabelle aller Inter-Router-Verbindungen: Quelle/Port → Ziel/Port, Medium (Kabel/WLAN/Mesh?), VLAN-Tags und Status (Speed bzw. dBm). Sortiert nach Medium (Kabel zuerst). Klick auf eine Zeile öffnet das DetailPanel des Ziel-APs.
- **Farbige VLAN-Badges in Gateway- und AP-Karten** — jede VLAN-ID hat jetzt eine konsistente Farbe (gleiche 7-Farb-Palette wie Port-Chips und Edge-Labels). VLAN 30 sieht überall identisch aus.
- **Minimap-Header mit Titel "Übersicht"** — der Mini-Map-Container wirkte ohne Beschriftung wie ein orphanes Fragment am unteren rechten Rand. Jetzt klar als Übersichtsfenster erkennbar.

### Changed

- **Aktiv/inaktiv-Kontrast der LAN-Port-Chips deutlich erhöht.** Down-Ports erhalten gestrichelten Rahmen, opacity 0.45 und keinen LED-Glow. Die VLAN-Färbung greift nur noch auf Up-Ports — der Link-Status ist damit das dominante visuelle Signal, unabhängig vom konfigurierten VLAN.
- **Shared VLAN-Color-Utility:** `VLAN_COLORS` + `vlanColor()` aus `PortStrip.tsx` extrahiert nach `utils/vlanColor.ts`. Wird jetzt von PortStrip, GatewayNode, APNode und WiringView gemeinsam genutzt — garantiert deterministische Konsistenz pro VLAN-ID.

### Tests

- `tests/test_topology_mesh.py` um 3 neue Cases ergänzt:
  - `test_repeater_override_skipped_when_wan_carrier_up` — der eigentliche AP3-Fall
  - `test_repeater_override_skipped_when_sta_inactive` — UCI-Stale-Eintrag wird ignoriert
  - `test_repeater_override_active_when_sta_assoc_and_wan_down` — Regressionsschutz für echte Repeater
- Total: 441 Tests grün (+3).

## [1.17.6] - 2026-04-29

### Fixed

- **Hotfix für v1.17.5: Browser-Cache-Bust für Topology-Panel.** `_PANEL_VERSION` in `topology_panel.py` wurde seit 9 Tagen nicht inkrementiert (steckte auf `"20260420d"`). Der `?v=…`-Query-Parameter am Bundle-URL war damit konstant — Browser luden weiter das gecachte alte Bundle und WLAN-Repeater-Badge / Port-Inline-Label aus v1.17.5 wurden nicht sichtbar. Bump auf `"20260429a"`. Wer nach Update immer noch das alte UI sieht, einmal Hard-Reload (Strg+F5) im Topology-Panel.

## [1.17.5] - 2026-04-29

### Fixed

- **Topology: WLAN-Repeater wurden fälschlich als "Kabel" angezeigt.** Method 2 (WiFi-Client-Cross-Reference) in `topology_mesh.py` scheiterte, weil die STA-MAC eines Repeater-Routers nicht im Lookup landete — `router_macs` enthielt nur LAN-MAC + AP-Mode-BSSIDs. Method 1 (DHCP-Lease) hat den Edge dann als `lan_uplink` abgefangen → Frontend mappte das auf `'wired'` → Badge "Kabel". Fix: neue Methode `OpenWrtAPI.get_sta_interface_details()` (iwinfo + UCI-Fallback) sammelt STA-Interface-MACs; `topology_mesh._detect_inter_router_edges()` schreibt sie ins `router_macs`-Lookup. Zusätzlich: Repeater-Override stuft bestehende `lan_uplink`-Edges auf `wifi_uplink` um, sobald `sta_interfaces` für den Ziel-Router vorhanden ist (deckt den Fall ab, dass das Gateway zusätzlich einen DHCP-Lease vergibt).

### Changed

- **Topology-Edges tragen jetzt Port-Info zwischen Routern.** Inter-Router-Edges (`lan_uplink`) liefern in den Attributen zusätzlich `ap_port` (`"wan"`) und `vlan_tags` (Liste von VLAN-IDs am Gateway-Port via `port_vlan_map`). Frontend zeichnet daraus inline auf der Verbindung ein Label wie `LAN3 · V30 · 1G` (Untagged) bzw. `T:10,20,30` (Trunk) plus AP-seitig `WAN`. Tooltip zeigt VLAN strukturiert (`Trunk 10, 20, 30` oder einzelne ID).
- **Neuer UplinkType `'repeater'`** — Badge "WLAN Repeater" (amber) statt "Mesh"; `'mesh'` ist jetzt explizit Subnet-Fallback ("Mesh?", unverifiziert). MobileView und EdgeTooltip wurden synchron aktualisiert.

### Added

- `OpenWrtCoordinatorData.sta_interfaces` — Liste der STA-Mode-Wireless-Interfaces (für WLAN-Repeater-Erkennung).
- 4 neue Tests in `tests/test_topology_mesh.py` (STA-MAC-Lookup, Repeater-Override, VLAN-Tag-Anreicherung, Port-Info bei Subnet-Fallback) + 1 in `test_coordinator.py` (`as_dict` exportiert `sta_interfaces`). Total: 438 Tests grün.

## [1.17.4] - 2026-04-29

### Changed

- **Sensor-Explosion zurückgefahren:** Mit dem Fix in v1.17.3 kamen plötzlich ~180 Entitäten pro Router zum Vorschein — viele davon (per-VLAN, per-Switch-Port, per-Radio-Detail, per-AP-Metrik) sind für die meisten Setups unnötig und wurden daher zu Standard-Disabled umgestellt:
  - `OpenWrtInterfaceSensor`, `OpenWrtInterfaceRateSensor`: Per-Interface RX/TX/Rate
  - `OpenWrtPortSensor`: Per-Switch-Port Status/Speed/RX/TX
  - `OpenWrtRadioSensor`: Per-Radio Signal/Noise (dBm)
  - `OpenWrtAPInterfaceSensor`: Per-AP-Interface Channel/Frequency/TX-Power/Bitrate/HW-Mode/HT-Mode/Mode/Quality/Clients
- **VLAN-Bridge-Interfaces** (`br-lan.40`, `eth0.30` etc. — alles mit `.` im Namen) werden gar nicht mehr als Sensoren angelegt. Per-VLAN-Status liefert ohnehin `gateway.vlans` als Attribut.

### Fixed

- **One-shot Migration für bestehende Installationen:** Wer von v1.17.3 oder früher migriert, hatte alle dynamischen Sensoren bereits als enabled im Registry. Beim ersten Setup nach dem Update werden diese nun automatisch via `RegistryEntryDisabler.INTEGRATION` deaktiviert (Patterns: `_iface_`, `_rate`, `_radio_`, `_ap_`, `_port_`). Idempotent — manuell wieder aktivierte Sensoren bleiben aktiviert.

## [1.17.3] - 2026-04-29

### Fixed

- **Wahrer Grund für die "verschwundenen" Entitäten** (Folge zu v1.17.1/v1.17.2): Die Diagnose über zwei Releases hinweg war falsch — es gab keine doppelten Devices. Der echte Fehler: alle Entities mit `device_info.configuration_url` lieferten `https-insecure://host:port` zurück, was HA's `_validate_configuration_url` mit `ValueError: invalid configuration_url` ablehnt. Resultat: 25+ Sensoren scheiterten beim Hinzufügen, nur die 3 Entities ohne `configuration_url` (Connectivity, WAN Connectivity, Router Status) kamen durch. Fix: neuer Helper `url_scheme_for()` in `const.py` der den internen Marker `https-insecure` für URL-Generierung auf `https` collapsed; alle 18 `configuration_url`-Konstruktionen in `sensor.py`, `switch.py`, `button.py`, `device_tracker.py`, `topology_entities.py` umgestellt.

## [1.17.2] - 2026-04-29

### Fixed

- **Doppelte Geräte im HA-Registry nach v1.17.0** (Folge-Fix zu v1.17.1): v1.17.1 stellte den korrekten Device-Identifier wieder her, aber HA verschiebt bestehende Entity↔Device-Verknüpfungen nicht automatisch — Nutzer sahen weiterhin zwei OpenWrt-Geräte (eines mit 3 Entitäten, eines mit den restlichen ~30). Beim Setup läuft jetzt automatisch eine Device-Registry-Migration: Orphan-MAC-Devices werden erkannt, ihre Entitäten auf das kanonische `entry_id`-Device umgehängt, und das Orphan-Device gelöscht. Idempotent — auf neu installierten Systemen passiert nichts.

## [1.17.1] - 2026-04-28

### Fixed

- **Entitäten verschwinden nach Update auf v1.17.0** (`device_info` Inkonsistenz): Der neue `RouterStatusSensor` und beide `binary_sensor`-Entities verwendeten als Device-Identifier `(DOMAIN, mac)` statt `(DOMAIN, entry.entry_id)` wie alle anderen Plattformen. Folge: HA legte ein zweites Device im Registry an, das nur die 3 neuen Entities trug — die ~30 alten Sensors hingen weiter am ursprünglichen Device, wirkten aber im UI als wären sie verschwunden. Fix: alle Entities verwenden jetzt einheitlich `entry.entry_id`.
- **Topology: Repeater-Backhaul-Erkennung verbessert** (`topology_mesh.py`): Inter-Router-Edges nutzen jetzt zusätzlich alle Interface-IPs (`network_interfaces`) und AP-BSSIDs (`ap_interfaces`) als Match-Kandidaten. Dadurch werden APs auch dann als WiFi-Uplink erkannt, wenn sie sich über eine sekundäre IP/MAC (z.B. STA-Backhaul) am Gateway anmelden.
- **Topology: Client-Nodes liefern `is_wifi_client`-Flag** (`topology_diagnostic.py`): Clients aus hostapd erhalten jetzt explizit `is_wifi_client: true`, damit das Frontend WLAN- vs Kabel-Anbindung sicher unterscheiden kann.
- **Topology-Panel: Falsche "Nicht registrierter Router"-Warnungen** (`useAlerts.ts`): Severity von `warning` auf `info` herabgesetzt, Patterns enger gefasst (kein generisches `/router/i` und `/gateway/i` mehr — diese matchten Smart-Home-Hubs wie *BresserGateway*). Hersteller-Match alleine löst keine Warnung mehr aus. Persistente Whitelist via `localStorage.openwrt_topology_ignored_routers` hinzugefügt.

## [1.17.0] - 2026-04-28

### Added

- **Router Connectivity Binary Sensor** (`binary_sensor.*_connectivity`): Zeigt `ON` wenn der Router erreichbar ist, `OFF` wenn nicht. Immer verfügbar — auch wenn der Router offline ist. Attribute: `last_seen`, `consecutive_failures`, `error_type`.
- **WAN Connectivity Binary Sensor** (`binary_sensor.*_wan_connectivity`): Zeigt `ON` wenn das Internet verfügbar ist, `OFF` wenn der Router erreichbar ist aber WAN down ist.
- **Router Status Sensor** (`sensor.*_router_status`): Enum-Sensor mit States `online`, `offline`, `auth_error`, `timeout`, `response_error` — zeigt den genauen Fehlertyp bei Ausfällen.
- **Persistente HA-Notification**: Nach 3 aufeinanderfolgenden fehlgeschlagenen Polls erscheint eine Warnung im HA-Notification-Center. Wird automatisch gelöscht wenn der Router wieder erreichbar ist.
- **Automation Blueprint** (`blueprints/automation/openwrt_router_outage_notify.yaml`): Fertiger Blueprint für Push-Benachrichtigungen bei Router-Ausfall. Konfigurierbar: Wartezeit, Notify-Dienst, Nachrichtentext, optionale Wiederherstellungs-Meldung.

## [1.16.2] - 2026-04-28

### Added

- **ACL automatisch einrichten**: Im Checklist-Schritt des Setups erscheint eine Checkbox "Berechtigungen automatisch einrichten", wenn ubus-Permissions fehlen. Ein Klick schreibt die rpcd-ACL-Datei direkt via ubus auf den Router und startet rpcd neu — kein SSH, kein manuelles `scp` nötig. Danach werden die Berechtigungen sofort neu geprüft und die aktualisierte Liste angezeigt.

## [1.16.1] - 2026-04-28

### Fixed

- **Login-Absturz beim Setup** (`AttributeError: _root_warning_logged`): `_root_warning_logged`, `_auth_failure_count` und `_auth_backoff_until` wurden in `api.py` nur in `reset_ssh_fallback_flag()` initialisiert, nicht in `__init__`. Jeder erste `login()`-Aufruf auf einer frischen API-Instanz schlug mit einem `AttributeError` fehl — der Setup-Wizard zeigte einen generischen Fehler ohne Hinweis auf die Ursache.
- **Bestehende Integrationen → HTTPS-Fehler nach Update** (Migration v1→v2): `DEFAULT_PROTOCOL` wurde in v1.16.0 von `"http"` auf `"https-insecure"` geändert. Alte Config-Entries ohne gespeichertes `protocol`-Feld fielen auf den neuen Default zurück und versuchten HTTPS/443 statt HTTP/80 — Verbindungsfehler beim Laden bestehender Integrationen. Fix: `async_migrate_entry` ergänzt `protocol: http` automatisch in alten Entries.

## [1.16.0] - 2026-04-28

### Fixed

- **Standard-Port 443 / HTTPS Self-Signed**: Default-Port war fälschlicherweise 80 (HTTP). Da die meisten OpenWrt-Router HTTPS auf Port 443 nutzen, ist der neue Standard 443 + HTTPS Self-Signed.
- **Login-Bug bei HTTPS**: Die Protokollauswahl wurde bisher erst *nach* dem Verbindungstest angezeigt — der Test verwendete daher immer HTTP, was bei Port 443 unweigerlich scheiterte. Protokoll ist jetzt Teil des ersten Schritts.

### Added

- **Geräte-Auswahl im Setup**: Nach der Router-Verbindung erscheinen Checkboxen für zusätzliche Geräte:
  - ☐ **Fritz!Box DSL-Modem** — DSL-Statistiken, 24h-Speedchart, Ping
  - ☐ **Managed Switch (OpenWrt)** — Port-Statistiken eines separaten Switches
- **Paket-Installationshinweise**: Wenn ubus-Berechtigungen fehlen, zeigt der Checklist-Schritt fertige `opkg`-Befehle zum Kopieren an.

## [1.15.6] - 2026-04-22

### Fixed

- **rpcd Memory Leak (kritisch)**: `file/exec` wurde aus der ACL und aus `get_bridge_fdb` entfernt — rpcd akkumulierte pro Poll-Zyklus Speicher durch großen stdout-Output vom `bridge fdb show`-Befehl (136 MB statt <5 MB). Bridge FDB wird nun via `file/read` auf `/sys/class/net/br-lan/brforward` gelesen (kein Shell-Exec nötig).
- **ACL**: `file/exec` → `file/list` ersetzt; alle Router aktualisiert

## [1.15.5] - 2026-04-22

### Fixed

- **Topology: Polling bei abgelaufener Sitzung** — bei HTTP 401 wird der Refresh-Timer gestoppt statt weiter zu pollen; stattdessen erscheint eine "Sitzung abgelaufen — Seite neu laden"-Meldung. Sobald HA ein neues `hass`-Objekt liefert, wird das Polling automatisch wiederaufgenommen.

## [1.15.4] - 2026-04-21

### Added

- **Config-Flow-Checklist**: Nach Protokollauswahl werden alle ubus-Berechtigungen geprüft (system/info, network/wireless, file/read, file/exec, hostapd/clients, iwinfo, luci-rpc, UCI). Fehlende kritische Caps → rote Warnung mit Anleitung. Fehlende optionale Caps → Info-Hinweis. Setup ist trotzdem möglich.

## [1.15.3] - 2026-04-21

### Added

- **SSH-Fallback-Erkennung**: Wenn ein Router ubus-Calls via SSH auflöst (fehlende ACL-Berechtigungen), erscheint eine persistente HA-Benachrichtigung mit Anleitung + Poll-Intervall wird auf 5 Minuten reduziert bis das Problem behoben ist
- **rpcd-ACL erweitert**: `file/exec`, `file/stat`, `rc/list`, `service/list`, `network.device/status` hinzugefügt — eliminiert SSH-Fallbacks auf korrekt konfigurierten Routern

## [1.15.2] - 2026-04-21

### Changed

- **Polling-Intervall** erhöht von 30s auf 60s — reduziert Router-Last bei mehreren Instanzen
- **Gestaffeltes Polling** — mehrere Coordinatoren verteilen sich automatisch gleichmäßig über das Intervall (0/15/30/45s Offset), keine simultanen Bursts mehr

### Added

- **Adaptives Polling** — bei CPU-Last >100% (Linux Load Average) wird das Intervall automatisch auf 120s verdoppelt; bei Rückkehr unter 80% wird 60s wiederhergestellt

### Fixed

- **CPU-Anzeige** — Wert >100% wird als "Load" statt "CPU" beschriftet und pulsierend rot hervorgehoben (Linux Load Average kann auf Single-Core-Systemen 100% überschreiten)

## [1.15.1] - 2026-04-21

### Fixed

- **Topology: Memory-Leak** — `nodeRefs` Map entfernt jetzt Einträge beim Node-Unmount statt unbegrenzt zu wachsen
- **Topology: CPU-Spike bei mehreren Routern** — `recomputeEdges` (DOM-Layout-Reflow) wird nicht mehr bei jedem Coordinator-Update ausgelöst; stabilisiert durch `dataRef` + AP-ID-Fingerprint als Dependency statt des gesamten `data`-Objekts
- **Topology: Merge-Conflict-Artefakt** — duplizierter CPU-History-Block war fälschlicherweise im `zoomToNode`-Callback eingebettet; `zoomFlyTimerRef` wird jetzt korrekt für Animations-Cleanup verwendet

## [1.13.0] - 2026-04-19

### Fixed

- **Topology: VLAN-Badges bei Offline-Router** — `network_interfaces` und `port_vlan_map` werden jetzt gecacht; bei nicht erreichbarem Router bleiben die VLAN-Badges sichtbar (gedimmt + gestrichelt + ⚠-Icon statt leer)
- **Coordinator**: `_last_known_network_interfaces` + `_last_known_port_vlan_map` als Stale-Cache; `vlans_stale: bool` Flag in `OpenWrtCoordinatorData`
- **Frontend**: `vlansStale`-Prop in `Gateway`-Typ; `vlan-badge--stale` + `vlan-stale-hint` CSS; Tooltip erklärt gecachten Zustand

## [1.12.3] - 2026-04-19

### Fixed

- **Topology: VLAN-Badges** — `OpenWrtAuthError` (ACL-Block, Code -32002) wird jetzt im SSH-Fallback von `get_network_interfaces()` korrekt abgefangen

## [1.12.2] - 2026-04-19

### Fixed

- **Topology: VLAN-Badges** — SSH-Fallback für `get_network_interfaces()` wenn ubus ACL-beschränkt ist; liest VLANs direkt per `ip -o addr show` aus

## [1.12.1] - 2026-04-19

### Fixed

- **Topology: SSID-Badges** zeigen jetzt nur noch die Anzahl (`📶 N`) statt volle Namen — Hover-Tooltip listet alle SSIDs mit Band und Kanal
- **Topology: VLAN-Badges im AP-Node** ergänzt (fehlten komplett)
- **Topology: Uplink-Typ** — WiFi-Client-Erkennung hat Vorrang vor DHCP-Erkennung; WLAN-Repeater werden korrekt als "Mesh" statt "Kabel" angezeigt

## [1.12.0] - 2026-04-19

### Added

- **Minimap** — 160×100 canvas overview (bottom-right corner of topology). Shows all nodes as coloured status dots and the current viewport as a dashed blue rectangle. Click to pan the canvas. Only visible in Topology tab.
- **Right-click context menu** on Gateway and AP nodes — items: Focus, Zoom to node, Clients, VLAN-Overlay, Alerts tab.
- **AP client expansion** — click the client-count button on any AP card to reveal an inline list of connected clients with signal bars, band, and IP.
- **Health mode** (♥ toggle) — colours every node by system health: `ok` (green) → `caution` (amber) → `warning` (orange) → `critical` (red). Scoring based on CPU load, RAM usage, and backhaul signal.
- **Status-change flash animation** — when a node transitions between online/warning/offline states a 650 ms colour-flash plays on the card. The status dot cross-fades via `transition: background-color 300ms`.
- **Layout transition** — AP columns animate out (`max-width: 0, opacity: 0`) when hidden by a filter change, and animate back in when revealed.
- **Gruppen-Modus** (group selector in toolbar) — organise APs into visual groups: by uplink type, by primary VLAN, or by online status.
- **Double-click to zoom** — double-click any node to zoom to 2× centered on that node. Double-click again (or when zoom ≥ 1.75) to reset to fit-view. Transition uses `cubic-bezier(0.4, 0, 0.2, 1)`.
- **Firmware version** — shown in hover tooltip and Inspector "Allgemein" section for Gateway and APs. Backend already computed `release.version`; now surfaced to the frontend.
- **Mini traffic & resource bars in Inspector** — compact horizontal bars for WAN downstream/upstream (Mbps), CPU%, RAM%, and client session RX/TX bytes.
- **Context actions in Inspector** — action bar at the bottom of the Inspector panel: Focus, Clients, Alerts (Gateway adds VLANs button).
- **Event timeline per device** — chronological list of status changes in the Inspector panel. Backend tracks WAN connect/disconnect, CPU ≥ 80% spike, RAM ≥ 90% spike in a ring-buffer (`deque(maxlen=30)`); events survive between polls but reset on HA restart.

### Changed

- `TopologyView`: AP render replaced with `groupAPs()` IIFE supporting flat and grouped layouts.
- `StatusBar`: added Health toggle, VLAN toggle, Group selector.
- `DetailPanel`: added `EventTimeline`, `ResourceBars`, `WanTrafficBars`, `BytesBars`, `MiniBar`, `ActionBtn` components; `DetailPanelActions` interface exported.

### Technical

- New files: `Minimap.tsx`, `ContextMenu.tsx`, `APClientList.tsx`, `useStatusFlash.ts`
- `coordinator.py`: `events` field on `OpenWrtCoordinatorData`, `_record_events()` method, `_event_history` deque, WAN/CPU/RAM state tracking
- `topology_diagnostic.py`: `events` included in router node attributes
- `types.ts`: `RouterEvent`, `firmwareVersion?` on `Gateway`/`AccessPoint`, `events?` on both

---

## [1.11.2] - 2026-04-17

### Added

- **Topology canvas dot-grid**: `.topo-scroll` background uses `radial-gradient` dot pattern (28 px spacing) — scrolls fixed, does not move with pan/zoom
- **Edge glow on hover**: CSS `drop-shadow` per edge type (`gateway-wired` / `ap-mesh` / `internet`) applied via child class — no SVG filter needed
- **Internet node pulse animation**: `internet-pulse` keyframe (3.5s ease-in-out infinite) on the internet node
- **Edge tooltip accent line**: 2px colored `border-top` per edge type in `EdgeTooltip`

### Changed

- Edge background opacity increased: wired `0.12 → 0.18`, mesh `0.10 → 0.16`
- Panel version bump: `20260416d`

### Fixed

- Removed stale `.edge-highlighted .edge-mesh-bg { drop-shadow(...blue...) }` — was applying wrong color on mesh edge hover

---

## [1.11.1] - 2026-04-16

### Fixed

- **fritz1750e frequent re-logins**: `login()` now requests a 24-hour session timeout from rpcd (`"timeout": 86400`). Previously, rpcd used its firmware default (often 30–300 s), causing a new login on nearly every poll cycle.
- **DDNS log spam on devices without DDNS**: `get_ddns_status()` now tracks per-device availability. After the first failed attempt (both `file/read` and `uci/get` paths fail), subsequent poll cycles skip DDNS entirely instead of logging `"DDNS: config unavailable"` every 30 s.
- **Defensive `ipv4-address` parsing**: Added `isinstance` guard when reading the first entry of the `ipv4-address` list from `network.interface.wan/status` — prevents `AttributeError` if the router returns an unexpected non-dict entry.

### Technical

- 30 unused imports removed across 9 files (ruff F401) — CI `ruff check` would have failed on every push
- `topology_diagnostic.py`: misplaced module-level import moved to top of file (ruff E402)
- `topology_mesh.py`: removed dead `router_ids` assignment (ruff F841)
- `__init__.py`: explicit re-export `DOMAIN as DOMAIN` for ruff F401 compliance

### Tests

- 396 passing (no regressions)

---

## [1.11.0] - 2026-04-15

### Added

- **Client Detail Panel — new fields**:
  - **IP address** now shown prominently at the top of the Gerät section
  - **Band** (2.4 GHz / 5 GHz / 6 GHz) — derived from `wifi_radios` via `topology_diagnostic.py`
  - **Verbunden seit** — connection duration from `hostapd connected_time` (e.g. "2h 34m")
  - **Lease bis** — DHCP lease expiry formatted as "22:15 (noch 3h 12m)" or "Abgelaufen"
  - **Status badge** — dot + text label (● Online / ● Warnung / ● Offline)
  - **„In HA anzeigen →"** link — navigates to the device_tracker entity in HA

- **Mobile connector line animation** — animated light-dot flowing through the vertical connector bars in MobileView

### Fixed

- **Topology dark theme not rendering on HA light theme** (critical): CSS custom properties were defined on `:root {}` which does not work when HA renders the panel in a shadow-DOM context. All variables moved to `.topo-app {}` (component root) so they cascade to all descendants regardless of outer DOM context. Literal color fallbacks added before each `var()` reference.
- **StatusDot invisible in detail panel**: `<span class="status-dot">` had no `display: inline-block` — browsers ignore `width`/`height` on inline elements. Fixed in CSS; all status rows now use the new `StatusBadge` component (dot + text).
- **SVG connection lines and animations invisible**: Caused by the same `:root` CSS variable scoping bug — strokes using `var(--blue)` resolved to `undefined`. Fixed by the `.topo-app` variable move.

### Technical

- `topology_diagnostic.py`: Added `_radio_band_map` built from `data.wifi_radios`; `band` field added to client node attributes
- `api.py`: Extracts `connected_time` from `hostapd/get_clients` `sta_data`; stored as `CLIENT_KEY_CONNECTED_SINCE`
- `api.ts`: Added `formatBand()`, `formatConnectedSince()`, `formatLeaseExpiry()` helpers; `Client` type extended with `connectedSince?` and `dhcpExpires?`
- `topology_panel.py`: Version bumped to `20260415e` for cache-busting

## [1.10.1] - 2026-04-14

### Added

- **Panel integrated into openwrt_router**: The topology panel is now part of the `openwrt_router` integration — no separate `openwrt_topology` component needed. The panel registers automatically when the first router entry is set up.
  - `topology_panel.py` — registers sidebar panel, static frontend path, and `/api/openwrt_topology/snapshot` endpoint
  - Moved `frontend/topology-panel.js` into `openwrt_router/frontend/`
  - `manifest.json` updated with `"dependencies": ["frontend", "http", "panel_custom"]`

- **Auto-ACL provisioning**: When a new router is added, the integration automatically checks for the rpcd ACL file (`/usr/share/rpcd/acl.d/ha-openwrt-router.json`). If missing, it deploys it via SSH and restarts rpcd — fixing the common "Authentication failed" error when adding AP clients that have no ACL file.
  - `acl_provisioning.py` — SSH check + deploy + rpcd restart (best-effort, graceful skip if SSH unavailable)
  - Called from `async_setup_entry()` after first coordinator refresh

- **Multi-Router Mesh Topology**: `topology_mesh.py` aggregates per-router snapshots from all configured OpenWrt entries into a single unified mesh view (1 gateway + N AP clients).
  - Automatic role detection: `gateway` (WAN uplink, non-private IP) vs `ap`
  - Inter-router edge detection via DHCP lease cross-reference, WiFi client MAC, or subnet fallback
  - Client deduplication: roaming clients (same MAC on multiple APs) appear once — strongest signal wins

- **FritzBox-style panel redesign**: Topology panel now uses card-style nodes with iOS-inspired dark palette:
  - Card nodes with band-specific border colors (gateway: blue, AP: purple, 2.4 GHz: green, 5 GHz: purple, 6 GHz: magenta)
  - Status dots (green/red/grey) per card
  - Signal quality pills for WiFi clients: `gut` (>-65 dBm) / `mittel` / `schwach` (<-75 dBm)
  - WAN badge (✓/✗) on gateway card
  - Bezier SVG connector lines with per-type styling (dashed WLAN, solid LAN, thick uplinks)
  - CSS variable palette (`--cg`, `--cr`, `--cl`, `--good`, `--fair`, `--poor`)
  - Multi-router group labels + separator lines

### Removed

- **`openwrt_topology/` component**: Entire separate component deleted. Panel functionality moved into `openwrt_router`.

### Technical

- `topology_panel.py` (NEW): Panel registration, API view, idempotent setup
- `acl_provisioning.py` (NEW): `check_and_deploy_acl()`, `_check_acl_exists()`, `_deploy_acl()`, `_ssh_exec()`
- `topology_mesh.py` (NEW): `build_mesh_snapshot()`, `_detect_router_role()`, `_detect_inter_router_edges()`, `_deduplicate_clients()`
- `topology_diagnostic.py`: `build_topology_snapshot()` gains optional `role` and `host_ip` parameters. Router node attributes now include `host_ip`, `wan_proto`, `wan_connected`. Interface labels prefer SSID+band over raw ifname.
- `coordinator.py`: `get_wifi_status()` wrapped in try/except to prevent `ConfigEntryAuthFailed` on ACL-restricted AP routers.
- `api.py`: Post-relogin `-32002` raised as `OpenWrtMethodNotFoundError` (genuine ACL block), not `OpenWrtAuthError`.

### Tests

- 353 passing (+37 new: ACL provisioning, mesh aggregation, role detection, inter-router edges, client deduplication, topology role/host_ip parameters)

---

## [1.9.3] - 2026-04-09

### Fixed

- **DHCP leases empty on OpenWrt 25** (`dhcp_leases` key): `luci-rpc/getDHCPLeases` returns `{"dhcp_leases": [...]}` on OpenWrt 25 instead of `{"leases": [...]}`. All 33 clients now have correct IPs and hostnames. Older OpenWrt versions using `"leases"` or a direct list still work.
- **rpcd -32002 treated as permanent ACL block**: Error code `-32002` from rpcd was raised as `OpenWrtMethodNotFoundError`, which bypassed the re-login retry logic in `_call()`. In practice, `-32002` can also mean a stale session token (e.g. after an rpcd restart). Changing it to `OpenWrtAuthError` triggers the existing re-login-and-retry mechanism. If the retry also returns `-32002` it's a genuine ACL restriction and propagates to the caller.
- **Topology: Router-ID empty string when MAC unavailable**: OpenWrt 25 / Cudy WR3000 v1 does not return a `mac` field in `system board`. Router-ID fell back to `""` (empty string), causing all topology edges to have `"from": ""` and breaking the panel. Now falls back to `hostname`, then to `"router"` literal.
- **Duplicate sensor entity IDs for `wan_rx` / `wan_tx`** (HA log: _"Platform openwrt_router does not generate unique IDs. ID …_wan_rx already exists"_): The static WAN byte-count sensors (`SUFFIX_WAN_RX` / `SUFFIX_WAN_TX`) and the dynamically-created `OpenWrtInterfaceSensor` for the `wan` interface produced identical `unique_id` values. Fixed by adding an `_iface_` disambiguator to the dynamic sensor: `entry_id_iface_wan_rx` / `entry_id_iface_wan_tx`.

### Technical

- `api.py`: `_get_dhcp_leases_luci_rpc()` — try `dhcp_leases` key first, fall back to `leases`, then direct list.
- `api.py`: `_raw_call()` — error code `-32002` raises `OpenWrtAuthError` (was `OpenWrtMethodNotFoundError`).
- `topology_diagnostic.py`: `build_topology_snapshot()` — router_id uses `mac or hostname or "router"` (was `mac` only with literal `"router"` fallback, which didn't handle empty-string MAC).
- `sensor.py`: `OpenWrtInterfaceSensor._attr_unique_id` — changed to `entry_id_iface_{interface}_{direction}`.

### Tests

- 316 passing (+20 new tests: Fix 3, Fix 4, Fix B coverage; new `test_topology_diagnostic.py`)

---

## [1.9.3-patch1] - 2026-04-10

### Fixed

- **Topology sensor attributes exceed HA Recorder 16 KB limit** (WARNING: _"State attributes for sensor.secureap_gateway_network_topology exceed maximum size of 16384 bytes"_): Topology snapshots with 40+ nodes and 33+ clients regularly exceed the recorder limit. The sensor _state_ (node count / active interface count) is still recorded. Attributes are excluded via `_unrecorded_attributes = frozenset({MATCH_ALL})` — they remain available in-memory at all times and the topology panel continues to read them from the live state object.

### Technical

- `topology_entities.py`: `_TopologyEntityBase._unrecorded_attributes = frozenset({MATCH_ALL})` — excludes all topology attributes from SQLite recorder without affecting in-memory availability.

---

## [1.9.2] - 2026-04-07

### Added
- **WiFi switch client list attribute**: Each WiFi switch now exposes a `clients` attribute containing a list of all connected clients on that SSID. Each entry shows:
  - `name` — hostname (falls back to MAC if no hostname)
  - `mac` — MAC address
  - `ip` — IP address (from DHCP lease enrichment)
  - `signal_dbm` — WiFi signal strength in dBm
  - `connected_since` — ISO-8601 timestamp of when the client first appeared
  - `dhcp_expires` — Remaining DHCP lease time (e.g. `"2h 14m"`, `"45m"`, `"<1m"`, `"expired"`)
- **DHCP lease expiry tracking**: `_parse_dhcp_leases()` and `luci-rpc/getDHCPLeases` now store the `expires` Unix timestamp. Expiry is propagated to connected client dicts and displayed as remaining time in switch attributes.

### Technical
- `const.py`: Added `CLIENT_KEY_DHCP_EXPIRES = "dhcp_expires"`.
- `api.py`: DHCP lease dicts now include `"expires"` (Unix timestamp). `_enrich_clients_with_ip()` propagates `CLIENT_KEY_DHCP_EXPIRES` to client dicts.
- `switch.py`: Replaced `_count_clients_for_ssid()` with `_get_clients_for_ssid()` returning full enriched list. Added `_format_dhcp_expires()` helper (converts epoch to human-readable remaining time).

### Tests
- 296 passing (no regressions)

---

## [1.9.1] - 2026-04-06

### Fixed
- **WiFi toggle: `uci/apply` fallback komplett übersprungen**: `uci/commit` blockiert via rpcd ACL → wirft `OpenWrtAuthError` → war NICHT in der except-Klausel → `uci/apply` wurde nie versucht. Fix: `OpenWrtAuthError` zu beiden except-Klauseln hinzugefügt.
- **Connected Clients = 0 bei read-only SSH**: SSH-Fallback lief `ubus call hostapd.*/get_clients` — erfordert ubus-Socket-Zugriff, schlägt bei read-only SSH-Usern fehl. Neuer Fallback: `iw dev {iface} station dump` (Kernel nl80211, rein lesend, kein ubus nötig).

### Technical
- `api.py`: `OpenWrtAuthError` in `set_wifi_state()` except-Klauseln ergänzt (commit + apply).
- `api.py`: Neue Methode `_get_clients_via_iw_ssh()` — parst `iw station dump` Output, wird automatisch aufgerufen wenn ubus SSH-Fallback fehlschlägt.

### Tests
- 294 passing (no regressions)

---

## [1.9.0] - 2026-04-06

### Fixed
- **WiFi switch shows only `(5 GHz)` instead of `OpenWrt (5 GHz)`**: Switch names were set statically at init time when the SSID was not yet available (UCI-method routers like Cudy WR3000 on OpenWrt 25). Replaced static `_attr_name` with a dynamic `name` property that always reads the current SSID and band from coordinator data.
- **2.4 GHz switch shows no band label**: `_detect_band()` returns `"2.4g"` for 2.4 GHz radios, but `_format_band()` only mapped `"2g"`. Added `"2.4g"` as an alias so 2.4 GHz switches correctly show `OpenWrt (2.4 GHz)`.
- **WiFi toggle fails with "uci/commit access denied"**: Replaced `network.wireless/up|down` with `uci/apply` as fallback when `uci/commit` is blocked by rpcd ACL. Staged UCI changes are reverted if both primary and fallback fail.
- **Connected Clients always 0**: rpcd ACL blocks `hostapd.*/get_clients` on Cudy WR3000 / OpenWrt 25. Added SSH fallback (`_get_clients_via_ssh()`) — connects once, runs `ubus call hostapd.<iface> get_clients` per interface.
- **DHCP enrichment disabled**: `file/read /tmp/dhcp.leases` blocked by rpcd ACL. Added `luci-rpc/getDHCPLeases` as automatic fallback. DHCP enrichment now works on ACL-restricted routers.
- **Client SSID empty**: `hostapd.*/get_status` blocked by rpcd ACL. Added `luci-rpc/getWirelessDevices` as cached fallback (fetched once per poll cycle).

### Technical
- `switch.py`: Dynamic `name` property with `_format_band()` alias for `"2.4g"`.
- `api.py`: `set_wifi_state()` → `uci/apply` fallback; `get_connected_clients()` SSH fallback; `get_dhcp_leases()` → `luci-rpc` fallback; SSID via `luci-rpc/getWirelessDevices`.

### Tests
- 294 passing (no regressions)

---

## [1.8.0] - 2026-04-06

### Added
- **AP Interface Sensors**: Per-radio channel, mode, HT mode, HW mode, and connected client count sensors.
  - `sensor.<section>_channel` — active WiFi channel (e.g. 1, 36)
  - `sensor.<section>_mode` — AP mode (`ap`, `client`, `monitor`)
  - `sensor.<section>_ap_clients` — number of currently associated clients
  - `sensor.<section>_ht_mode` — HT/VHT/HE mode (e.g. HE20, HE80, VHT80)
  - `sensor.<section>_hw_mode` — hardware mode or device type (e.g. mt7986, 11ax)
  - Optional (iwinfo only): `frequency` (MHz), `tx_power` (dBm), `bitrate` (Mbps), `signal_quality` (%)
- **UCI fallback** for AP interface discovery: Routers without `iwinfo` access via rpcd (e.g. Cudy WR3000 on OpenWrt 25) now expose AP sensors via UCI wireless config. UCI section names (e.g. `default_radio0`) are used as stable entity identifiers.

### Technical
- `const.py`: Added `RADIO_KEY_CHANNEL`, `RADIO_KEY_FREQUENCY`, `RADIO_KEY_TXPOWER`, `RADIO_KEY_BITRATE`, `RADIO_KEY_HWMODE`, `RADIO_KEY_HTMODE`, `RADIO_KEY_MODE`, `RADIO_KEY_BSSID`.
- `api.py`: New `get_ap_interface_details()` method — iwinfo primary path, UCI fallback. Extends `_parse_iwinfo_info()` and `_parse_wireless_status()` with new fields.
- `coordinator.py`: Added `data.ap_interfaces` field; fetched after clients each poll.
- `sensor.py`: New `OpenWrtAPInterfaceSensor` class; `_add_dynamic_sensors()` extended to iterate `ap_interfaces`.

### Tests
- 294 passing (no regressions)

---

## [1.7.0] - 2026-04-06

### Added
- **Service Management**: Monitor and control procd/rc system services directly from Home Assistant.
  - **Service Switches** (`switch.service_<name>`): Start/stop individual services — `dnsmasq`, `dropbear`, `firewall`, `network`, `uhttpd`, `wpad`. State reflects real-time running status.
  - **Service Restart Buttons** (`button.restart_<name>`): One-click restart per service with dedicated icons.
  - Auto-discovery: Uses `rc/list` (OpenWrt 19+) with `service/list` (procd) as fallback. Only services present on the router appear as entities.
  - Feature-gated: Service entities are only created when `rc/list` or `service/list` is accessible.

### Fixed
- **Active Connections = 0**: Now reads `/proc/sys/net/netfilter/nf_conntrack_count` (fast single-int file) with `/proc/net/nf_conntrack` as fallback.
- **WiFi Switch Access Denied**: Added `network.wireless/up` (or `/down`) as fallback when `uci/commit` is blocked by rpcd ACL.
- **Connected Clients = 0** (OpenWrt 25): Fixed hostapd interface name discovery — probes `phy{N}-ap{M}` naming used since OpenWrt 21+/25, caches result to avoid repeated probing.
- **SSID via hostapd**: Uses `hostapd.*/get_status` to retrieve SSID even when `iwinfo/info` is blocked by rpcd ACL.

### Technical
- `api.py`: Added `get_services()` (rc/list → service/list fallback) and `control_service(name, action)`.
- `const.py`: Added `UBUS_RC_OBJECT`, `UBUS_RC_INIT`, `UBUS_SERVICE_OBJECT`, `DEFAULT_SERVICES`, `KEY_SERVICES`, `FEATURE_HAS_SERVICES`.
- `coordinator.py`: Added `data.services` field; fetches service status each poll when `has_services` feature detected; service probed during feature detection.
- `switch.py`: Added `OpenWrtServiceSwitch` — start/stop toggle per service with per-service icons.
- `button.py`: Added `OpenWrtServiceRestartButton` — restart per service.

### Tests
- 275 passing (no regressions from new service management code)

---

## [1.6.0] - 2026-04-06

### Added
- **Bandwidth Rate Sensors**: Dynamic `sensor.<iface>_rx_rate` / `sensor.<iface>_tx_rate` entities (bytes/s) per network interface — created alongside existing byte-total sensors. Returns `unavailable` on the first poll (two data points needed); `0` on counter wraparound/reset.
- **Traffic Charts/History**: The existing cumulative byte sensors (`state_class: TOTAL_INCREASING`) already enable HA Long-Term Statistics — add them to a Statistics card or Energy Dashboard for per-interface traffic history.

### Technical
- `coordinator.py`: Added `_prev_interface_bytes` dict and `_prev_poll_time` timestamp; injects `rx_rate`/`tx_rate` (B/s) into each interface dict on every poll after the first.
- `sensor.py`: Added `OpenWrtInterfaceRateSensor` class (`DATA_RATE`, `MEASUREMENT`, `B/s`); registered in `_add_dynamic_sensors()` alongside byte-total sensors.

### Tests
- T-R1–R4: Rate is `None` on first poll, correctly calculated on second poll, `0` on counter wraparound, sensor returns `None` before rate is available
- T-S7–S9: `OpenWrtInterfaceRateSensor` unique_id format, device_class/unit, native_value
- **275 tests passing** (was 268)

---

## [1.5.0] - 2026-04-06

### Added
- **QA Strategy Document** (`Anweisungs.md`): Comprehensive 4-level test strategy covering static checks, unit tests, HA-environment integration tests, and manual E2E checklist
- **Test Fixtures** (`tests/fixtures/`): 5 versioned JSON router state fixtures — `router_healthy`, `router_wan_down`, `router_minimal`, `router_broken`, `router_high_traffic`
- **Regression Tests** (`tests/test_regressions.py`): REG-01–REG-05 covering WAN-down interface handling, string rx_bytes robustness, connected_since cleanup, unique_id stability, duplicate entity prevention
- **CI: Ruff Lint + Format Check**: Added `ruff check` and `ruff format --check` step to GitHub Actions workflow before pytest

### Tests
- Extended `test_sensor.py`: dynamic interface sensor creation, WAN-down edge case, None rx_bytes robustness, unique_id stability, radio sensor noise guard
- Extended `test_coordinator.py`: `_client_first_seen` tracking, stability on re-poll, cleanup on disconnect, connected_since propagation, missing MAC skip
- Extended `test_device_tracker.py`: `connected_since` in `extra_state_attributes`, offline state, ISO format validation
- **268 tests passing** (was 247)

---

## [1.4.0] - 2026-04-06

### Added
- **Per-Interface Bandwidth Sensors**: Dynamic `sensor.<iface>_rx` / `sensor.<iface>_tx` entities for every network interface (wan, loopback, br-lan, etc.) using existing `network.interface/dump` data
- **Per-Client Online Time**: `connected_since` ISO timestamp attribute in device tracker entities — tracks when each WiFi client first connected (resets on HA restart)
- **Radio Signal/Noise Sensors**: Dynamic `sensor.<iface>_signal` / `sensor.<iface>_noise` entities per WiFi radio (requires iwinfo support; only created when noise data available)

### Technical
- `coordinator.py`: Added `_client_first_seen` dict tracking UTC connection timestamps per MAC
- `api.py`: Extended `_parse_iwinfo_info()` to extract noise/signal/quality/quality_max from iwinfo response
- `const.py`: Added `CLIENT_KEY_CONNECTED_SINCE`

---

## [1.3.0] - 2026-04-05

### Fixed
- **Entity ID naming**: Sensors no longer include the config entry hash in their entity IDs (e.g. `sensor.openwrt_firmware_version` instead of `sensor.openwrt_router_01knfp2yyvf5j20wwpdze0sp99_firmware`)
- **P1**: `perform_update()` — replaced non-existent `file/write` ubus call with SSH subprocess
- **P2**: `get_network_interfaces()` now reads from `network.interface/dump`; `get_active_connections()` reads `/proc/net/nf_conntrack`
- **P3**: Button entity no longer mutates coordinator data directly (race condition)
- **P4**: `configuration_url` now uses the configured protocol (HTTP/HTTPS) in all entity platforms
- **P5**: Removed unreachable dead code in `get_wan_status()`
- **P6**: Exponential backoff on repeated auth failures (3 strikes → 30 s → 300 s max)
- **P7**: SSH JSON parse calls wrapped in `try/except ValueError`
- **P8**: Logging uses `%s` pattern instead of f-strings
- **WiFi SSH fallback**: Uses direct UCI commands instead of a helper script that may not be present on all routers

### Added
- **Memory Total sensor**: Expose total RAM as a standalone sensor (`memory_total`)
- **Memory Used sensor**: Expose used RAM as a standalone sensor (`memory_used`)

---

## [1.2.0] - 2026-03-24

### Added
- **Comprehensive Test Suite**: 247 tests across 11 files covering all modules
  - API parsing, error handling, session management (63 tests)
  - Coordinator polling, feature detection, error wrapping (33 tests)
  - Config flow host validation and setup steps (25 tests)
  - All entity platforms: sensor, switch, button, device_tracker, diagnostics
  - Integration setup/unload/reload lifecycle tests
- **CI/CD Pipelines**: GitHub Actions for automated quality checks
  - `hassfest.yaml`: Home Assistant manifest validation
  - `hacs.yaml`: HACS repository validation
  - `tests.yaml`: Pytest on Python 3.12 and 3.13
- **Brand Icon**: 256x256 PNG icon for HACS store listing
- **Translations**: English translation file (`translations/en.json`)

### Fixed
- Removed non-existent `entity.py` reference from documentation

---

## [1.1.0] - 2026-03-23

### Added
- **Extended System Monitoring**: Comprehensive metrics for advanced system oversight
  - **System Information**: Platform architecture, OpenWrt version, hostname, model detection
  - **CPU Metrics**: Extended load averages - 1-minute, 5-minute, and 15-minute load as percentage
  - **Memory Details**: Separate sensors for cached, shared, and buffered memory in addition to total/free
  - **Disk Space Monitoring**: Total, used, free capacity and usage percentage for all mounted filesystems
  - **Temporary Storage (tmpfs)**: Dedicated monitoring for /tmp, /run, /dev/shm with usage metrics
  - **Network Connection Tracking**: Active network connection count via nf_conntrack integration
  - **15+ New Sensors**: All metrics exposed as individual sensors for dashboards and automations

### Technical
- Enhanced API methods with graceful fallback for unsupported features
- Improved platform architecture detection from multiple sources
- Comprehensive error handling for missing system features
- Support for systems with/without nf_conntrack module

---

## [1.0.8] - 2026-03-20

### Added
- **Update Management Feature**: Check and perform system/addon package updates
  - "Check for Updates" button: Detects available system packages and addons
  - "Perform Updates" button: Triggers package updates on the router
  - "Update Status" sensor: Shows if updates are available with package counts as attributes
  - Support for selective updates: system packages, addons, or both
  - Proper categorization of updates by type (system vs addon/LuCI packages)

---

## [1.0.7] - 2026-03-20

### Added
- **SSL/HTTPS Support**: Secure connections to OpenWrt routers
  - Config Flow with Protocol Dropdown: HTTP, HTTPS, HTTPS Self-Signed
  - Automatic port adjustment (80 for HTTP, 443 for HTTPS)
  - Self-signed certificate support for private/lab networks
  - Proper SSL context with certificate validation for production use
  - Token transmission now protected over HTTPS when enabled

---

## [1.0.6] - 2026-03-20

### Changed
- **Sensor Visibility**: Move sensors from "Diagnose" to main "Sensoren" section
  - Uptime, Memory Free, WAN IP, Firmware now appear in Sensors (not Diagnostics)
  - Better UX: All important metrics visible without expanding Diagnostics
  - Devices in Home Assistant now show sub-entities under Sensors

---

## [1.0.5] - 2026-03-20

### Changed
- **WiFi Switch Display Enhanced**: Switches now show band information and connected client count
  - Switch names now display: "secure-IoT (2.4 GHz)" instead of just "secure-IoT"
  - Band information (2.4 GHz, 5 GHz, 6 GHz) automatically appended
  - Connected client count visible in switch attributes: "connected_clients"
  - Better UX for managing multiple WiFi networks

---

## [1.0.4] - 2026-03-19

### Fixed
- **Sensor Display Names**: Sensors now show their actual names instead of device hostname
  - Changed `_attr_has_entity_name` from True to False in sensor.py
  - Sensors now display: "WAN Status", "CPU Load", "Memory Usage", "Connected Clients" etc.
  - Previously all sensors showed "sECUREaP-gATEWAy" (the device name)

---

## [1.0.3] - 2026-03-19

### Fixed
- **WAN RX/TX Bytes Now Show Actual Data**: Fixed issue where WAN Download/Upload sensors showed "unavailable"
  - Changed from reading `network.interface/dump` to directly reading `/sys/class/net/{interface}/statistics/`
  - Uses kernel filesystem as source of truth for interface statistics
  - Works on routers like Cudy WR3000 where stats may not be included in network interface dump
  - Example: Now shows actual 93.9 GB RX / 1.9 GB TX instead of unavailable

---

## [1.0.2] - 2026-03-19

### Fixed
- **WAN Statistics Handling**: Show "unavailable" instead of "0 B" when router doesn't provide WAN statistics
  - WAN Download and WAN Upload sensors now properly display unavailable state
  - Added debug logging to identify routers without statistics support

---

## [1.0.1] - 2026-03-19

### Fixed
- **Entity Display Names**: WiFi switch entities now display only the SSID name (e.g., "secure-IoT") instead of the device prefix + SSID. This provides a cleaner, more intuitive UI experience in Home Assistant.
  - Changed `_attr_has_entity_name=False` to remove redundant device name repetition in entity display names
  - Entity IDs remain unchanged (e.g., `switch.secureap_gateway_secure_iot`)

### Changed
- Improved entity naming consistency with Home Assistant best practices

---

## [1.0.0] - 2026-03-11

### Added
- Initial release: Home Assistant custom integration for OpenWrt Router management
- **WiFi Switches**: One switch per detected WiFi SSID (2.4GHz, 5GHz, Guest networks)
- **Sensors**: Uptime, WAN status, connected client count
- **Device Tracker**: Track connected WiFi clients by MAC address
- **Button**: WiFi reload/reboot control
- **Security**: SSRF, token leak, and input validation hardening
- Configuration via Home Assistant UI setup wizard
- Automatic token refresh and retry logic for JSON-RPC API
- Diagnostics with redacted sensitive data

### Architecture
- Async-only design with proper error handling
- Polling coordinator with 30-second update intervals
- ubus/rpcd JSON-RPC communication via HTTP
- Per-SSID controls with UCI configuration backend
