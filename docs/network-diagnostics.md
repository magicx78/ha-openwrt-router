# Netzwerkdiagnose (Network Diagnostics)

<!-- Nutzer- und Entwicklerdoku ab 1.47.0. Keine IPs, MACs, Hostnamen echter Geräte,
     Passwörter oder Tokens; Beispiele nutzen 192.0.2.x (RFC 5737) und example.org. Aussagen
     sind am Code gelesen (diag_runtime.py, diag_scheduler.py, diag_targets.py, diag_model.py,
     diag_chain.py, diag_causes.py, diag_stats.py, diag_baseline.py, diag_score.py,
     diag_store.py, diag_views.py, diag_entities.py, diag_context.py, diag_core.py, der Block
     "Network Diagnostics" am Ende von api.py, net_rules.py, net_engine.py, diagnostics.py,
     const.py, Frontend unter enterprise/diagnostics/), nicht an Geräten ausgeführt. Der Plan
     mit der Messmatrix und den Live-Befunden vom 2026-11-18 steht in
     docs/plans/2026-11-17-net-diagnostics.md. Aufbau und Zusagen des Cores:
     docs/enterprise-core.md. -->

## Inhalt

1. [Was es tut und was nicht](#1-was-es-tut-und-was-nicht)
2. [Einschalten](#2-einschalten)
3. [Einstellungen](#3-einstellungen)
4. [Kette und Zustände](#4-kette-und-zustände)
5. [Messmatrix je Messpunkt](#5-messmatrix-je-messpunkt)
6. [Wert, Baselines und Statistik](#6-wert-baselines-und-statistik)
7. [Speicher und Quoten](#7-speicher-und-quoten)
8. [Zusatzlast](#8-zusatzlast)
9. [Benötigte Router-Rechte und Pakete](#9-benötigte-router-rechte-und-pakete)
10. [Routen](#10-routen)
11. [Entitäten](#11-entitäten)
12. [Vorfallstypen und Verknüpfungsregeln](#12-vorfallstypen-und-verknüpfungsregeln)
13. [Kontext eines Befunds](#13-kontext-eines-befunds)
14. [Datenschutz und Diagnose-Download](#14-datenschutz-und-diagnose-download)
15. [Grenzen](#15-grenzen)

## 1. Was es tut und was nicht

Die Netzwerkdiagnose prüft die Kette **Router → Gateway → WAN → Internet → DNS** und sagt je
Glied, ob es gesund, beeinträchtigt, ausgefallen oder unbekannt ist. Dazu nutzt sie

- Daten, die die Integration mit jedem Poll ohnehin liest (WAN-Status und die Fakten aus dem
  schon vorhandenen `network.interface dump`: Standardroute, nächster Hop, DNS-Server, aktive
  Schnittstellen), und
- Messungen **von Home Assistant aus** (TCP, DNS, HTTP) gegen Ziele, die ein Administrator
  eingerichtet hat.

Sie baut auf dem Enterprise Core (ab 1.44.0) auf und nutzt, wenn vorhanden, den Configuration
Manager und das Security Center als Kontext.

Ausdrücklich **nicht**:

- **keine Tests auf dem Router** (kein Ping, kein `nslookup`, kein `traceroute` auf einem
  Router) in dieser Version ([Abschnitt 9](#9-benötigte-router-rechte-und-pakete));
- **keine Änderung** an einem Router, keine Sperre, keine Konfiguration;
- **kein externes Ziel ist voreingestellt:** ohne eingerichtete Ziele wird nichts Externes
  gemessen;
- **kein zusätzlicher Router-Aufruf je Poll**;
- **kein Beleg für Gesundheit aus fehlenden Daten:** ein Glied ohne Messung ist `unknown`,
  nie `healthy`, und ein Wert ohne Daten ist `None`, nie 0 oder 100.

Eine Messung von Home Assistant belegt den Weg **Home Assistant → Ziel**, nicht den Weg Router
→ Ziel. Deshalb fließt sie nicht in die Kette eines Routers ein (siehe
[Abschnitt 5](#5-messmatrix-je-messpunkt)).

## 2. Einschalten

**Standardmäßig AUS.** Es gibt keinen Optionsdialog und keinen Dienst dafür:

1. Panel öffnen, **Enterprise → Netzwerkdiagnose**.
2. Das Modul einschalten. Das darf **nur ein Home-Assistant-Administrator**; die Änderung läuft
   über den Guard des Cores und wird auditiert.

Ausgeschaltet gilt: kein Beobachter, keine Messung, kein Socket, keine Schreibvorgänge, keine
Entitäten (vorhandene werden aus der Entity-Registry entfernt), keine Router-Aufrufe. Das
Modul liest dann nur seinen Speicher (`.storage/openwrt_router.net_diagnostics`). Die
Lese-Routen antworten mit `{"state": "off", …}`.

Eingeschaltet ist der Zustand `ready` oder `not_ready` mit Gründen (zum Beispiel
`module_key_missing`, `core_unavailable`, `events_not_registered`, `engine_unavailable`,
`scheduler_not_running`). Ein Router ohne Daten ist `unknown` mit Grund (`no_data_yet`,
`stale`, `poll_failed`, `interface_dump_missing`, `router_id_unknown`). `poll_failed` liest das
Modul live am Coordinator (letzter Poll fehlgeschlagen), nicht erst aus einem neuen Poll. Ist ein
Router `unknown`, liefern Übersicht und Detail für ihn **keine Kette und keinen Befund** (`null`,
die Oberfläche zeigt alle Glieder unbekannt), nie den letzten gesunden Stand.

Der HA-Messpunkt veraltet nach `max(3600 s, 3 × interval_s)`: danach sind Zustand, Kette, Befund
und die Zahl aktiver Befunde für ihn unbekannt (Grund `stale`). Eine Runde ohne jede Messung
setzt seinen Befund auf unbekannt; auch ein manueller Lauf gibt dann keinen alten Befund zurück.

Eingeschaltet, aber ohne Ziele und ohne regelmäßige Messung, wertet das Modul nur die Polls aus
und sendet **kein Paket**. Aktiv gemessen wird erst nach einer ausdrücklichen Handlung eines
Administrators: ein manueller Lauf oder die eingeschaltete regelmäßige Messung mit bestätigten
Zielen.

## 3. Einstellungen

Gelesen und geändert über die Route `settings` (nur Administratoren). Im Panel stellt ein
Administrator Schalter, regelmäßige Messung, Intervall und „Namensserver ist intern“ ein; die
übrigen Felder zeigt das Panel nur an.

| Einstellung | Wert | Vorgabe | Wirkung |
|---|---|---|---|
| `enabled` | Schalter | aus | Gesamtschalter. |
| `periodic` | Schalter | aus | Regelmäßige Runde gegen die bestätigten Ziele. Ohne bestätigtes Ziel läuft sie nicht. |
| `interval_s` | 60 bis 86400 | 300 | Sekunden zwischen zwei regelmäßigen Runden. |
| `targets` | Liste, höchstens 16 | leer | Messziele: `id`, `kind` (`tcp` / `dns` / `http`; `icmp` wird auf der HA-Seite übersprungen), `scope` (`internal` / `external`), `host`, `port`, `confirmed`, optional `stage`. |
| `internal_networks` | Liste von Netzen, höchstens 32 | leer | Netze, in denen interne Ziele liegen dürfen. |
| `local_domains` | Liste, höchstens 32 | leer | Namen, die als intern gelten. |
| `dns_query_name` | Name | nicht gesetzt | Name, den DNS-Messungen abfragen (A). Ohne Name wird ein DNS-Ziel übersprungen (`no_query_name`), es geht kein Paket. |
| `http_path` | Pfad | `/generate_204` | Pfad des HTTP-Abrufs („no content“). |
| `ha_resolver_internal` | Schalter | aus | Erklärt den Namensserver von Home Assistant für intern. Sonst darf er keinen internen Namen auflösen. |

Regeln für Ziele (`diag_targets.py`):

- Ein Ziel wird **immer per ID** angesprochen. Eine freie Adresse nimmt keine Messung an.
- Ein **externes** Ziel muss global routbar und **bestätigt** sein; ein **internes** muss in
  einem konfigurierten internen Netz liegen. Loopback ist nie erlaubt; Link-Local und
  Metadaten-Adressen nur, wenn genau dafür ein Netz konfiguriert ist.
- Ein Hostname wird erst aufgelöst, dann prüft die Registry **jede** aufgelöste Adresse erneut
  (Schutz vor DNS-Rebinding). Interne Namen gehen nie an einen als extern geltenden
  Namensserver. Ist `ha_resolver_internal` aus, ist ein internes Hostname-Ziel im Status
  unbrauchbar (Grund `internal_name`).
- Scheitert das Auflösen eines bestätigten Hostname-Ziels (keine oder ungültige Adresse), zählt
  das als **gescheiterte Beobachtung des DNS-Glieds** am HA-Messpunkt (ohne Verlaufsprobe, nie
  das Internet-Glied). Ein einzelner gescheiterter Name neben beantworteten macht das Glied nur
  beeinträchtigt; scheitern alle, ist es ein DNS-Problem.
- Die **regelmäßige** Runde nimmt nur bestätigte Ziele. Ein **manueller** Lauf nimmt die
  angegebenen Ziel-IDs (ohne Angabe alle nicht-ICMP-Ziele); ein abgelehntes Ziel wird mit
  Grund gemeldet, ohne Paket.
- Der HTTP-Abruf sendet keine Zugangsdaten, keine Cookies und keinen Body, liest nur die
  Statuszeile und folgt keiner Weiterleitung (3xx ist ein fehlgeschlagenes Ergebnis).

Beispiel für ein Ziel (nur Schema, `192.0.2.53` steht für einen Namensserver im eigenen
Netz):

```json
{"id": "lan-dns", "kind": "dns", "scope": "internal", "host": "192.0.2.53", "port": 53,
 "confirmed": true}
```

## 4. Kette und Zustände

Je Glied und Adressfamilie (IPv4, IPv6) einer der Zustände:

| Zustand | Bedeutung |
|---|---|
| `healthy` | direkt gemessen und in Ordnung |
| `degraded` | beeinträchtigt (zum Beispiel ein einzelnes scheiterndes Ziel, ICMP ohne Antwort) |
| `failed` | ausgefallen; nur ein harter, nicht-ICMP-Fehler kann ein Glied ausfallen lassen |
| `unknown` | keine brauchbare Messung; senkt die Abdeckung |
| `not_applicable` | gilt nicht (zum Beispiel eine nicht eingerichtete Adressfamilie, ein AP ohne WAN) |

Regeln (`diag_chain.py`):

- „Kein Fehler erkannt“ gibt es nur, wenn **jedes anwendbare Glied direkt gemessen** wurde;
  sonst ist das Ergebnis „teilweise gemessen“ mit der Liste der unbekannten Glieder.
- Das Internet-Glied fällt nur aus, wenn mindestens **zwei verschiedene** Referenzziele in
  derselben Runde hart scheitern. Scheitert eines von mehreren, ist das Glied gesund mit Grund
  `single_external_service`; ein einziges konfiguriertes Ziel macht es höchstens
  `degraded`.
- Unterhalb eines ausgefallenen Glieds werden Fehler maskiert (Folgefehler); misst ein tiefer
  liegendes Glied direkt gesund, steht ein Widerspruch im Ergebnis.
- Indirekte Belege (Messung eines anderen Punkts) begrenzen ein Glied auf `degraded`, bestätigen
  nie eine Ursache und zählen nie als Abdeckung.

Klassifizierung eines Befunds: `no_fault_detected`, `insufficient_data`, `partially_measured`,
`router_offline`, `management_unreachable`, `lan_problem`, `gateway_problem`,
`routing_problem`, `wan_problem`, `dns_problem`, `single_external_service_unreachable`,
`ipv4_only_disturbance`, `ipv6_only_disturbance`, `possible_firewall_restriction`,
`icmp_unanswered`, `gateway_changed`, `dns_server_changed` (`Classification` in
`diag_model.py`).

Ursachenklassen (`diag_causes.py`): `confirmed` braucht eine **direkte** Messung am Ort der
Ursache; dieselbe Auffälligkeit an mehreren Routern ergibt höchstens `probable`; `possible`
und `unknown` sind schwächer. Gemeinsame Ursachen (`central_internet_access`, `segment_path`,
`common_gateway`, `common_resolver`) verknüpfen nur Router, die technisch davon abhängen, und
nur Befunde desselben Glieds und derselben Adressfamilie; fehlen Abhängigkeitsdaten, gibt es
keinen Link. Ein Link verbirgt oder ändert nie einen Befund. Jeder Befund ohne gemeinsame
Ursache bekommt eine eigene lokale Ursache.

Ein Router, der weniger als 300 s läuft, gilt als gerade neu gestartet: sein Befund ist
`settling` und wird erst nach dieser Zeit gemeldet (`DIAG_SETTLE_SECONDS`).

## 5. Messmatrix je Messpunkt

„Direkt“ heißt: am Messpunkt selbst gemessen oder Tatsache aus dem Poll dieses Routers.
„Indirekt“ heißt: gemessen an einem anderen Punkt, aber für dieses Glied genannt. Stand ist der
gebaute Stand 1.47.0, nicht der Plan.

### Messpunkt Home Assistant (eine Kette für ganz Home Assistant)

| Glied | Direkt | Indirekt | Gar nicht |
|---|---|---|---|
| Router | – | – | nicht Teil der HA-Kette |
| Gateway | nur wenn ein Ziel ausdrücklich dem Glied `gateway` zugeordnet ist (Feld `stage`) | – | sonst unbekannt |
| WAN | – | – | unbekannt |
| Internet | TCP- und HTTP-Messung gegen bestätigte Ziele (Standardzuordnung) | – | ohne Ziele unbekannt |
| DNS | DNS-Messung gegen eingerichtete Namensserver mit `dns_query_name` | – | ohne Ziel oder Namen unbekannt |

### Messpunkt Router (eine Kette je Router, nur aus dem Poll)

| Glied | Direkt | Indirekt | Gar nicht |
|---|---|---|---|
| Router | Poll kam an (Verwaltung erreichbar); Schnittstellen aktiv; ausgefallene LAN-Schnittstellen (höchstens 16, nur Name und VLAN-Kennzeichen) | – | – |
| Gateway | – | – | unbekannt; der nächste Hop wird nur für die Wechselerkennung gelesen, nicht angesprochen |
| WAN | WAN verbunden (IPv4) und Standardroute vorhanden (IPv4, IPv6); je Router eine Reihe `wan_up` | – | IPv6-WAN-Zustand: keiner im Poll (unbekannt); Router ohne WAN: `not_applicable` |
| Internet | – | – | unbekannt (kein Router-Test) |
| DNS | – | – | unbekannt (kein Router-Test); die DNS-Server werden nur für die Wechselerkennung gelesen |

Folgen daraus:

- Eine Messung von Home Assistant geht **nicht** in die Kette eines Routers ein: die Laufzeit
  gibt keiner Messung einen Router als Subjekt (`subject` kommt in `diag_runtime.py` nicht
  vor). Deshalb ist auch die Kette eines Routers ohne Router-Messung höchstens „teilweise
  gemessen“, solange Gateway, Internet und DNS unbekannt sind.
- Der Binärsensor „Gateway erreichbar“ je Router bleibt in dieser Version unbekannt (Grund
  `not_measured`).
- Router-Tests (Ping, `nslookup`, `traceroute`) wären die Messung am Router; es gibt sie nicht
  ([Abschnitt 9](#9-benötigte-router-rechte-und-pakete)).

## 6. Wert, Baselines und Statistik

### Statistik (`diag_stats.py`)

Je Reihe (Messpunkt, Ziel-ID, Art, Adressfamilie) Stunden- und Tages-Buckets. Ein Probe-Ergebnis
ist `answered`, `lost` oder `gap` (keine Messung: Neustart, Wartung, Messweg selbst
abgelaufen). Eine **Antwort ist kein Verlust**: REFUSED, SERVFAIL oder ein HTTP-Status außer
204 zählen als beantwortet (mit Antwortzeit); der Fehler bleibt in der Bewertung des Glieds.
Verlust ist nur eine ausgebliebene Antwort. `Verlust % = lost / (answered + lost) × 100`; Lücken zählen nie in den Nenner,
sie senken nur die **Abdeckung** `(answered + lost) / erwartet`. Ohne Messung sind alle Zahlen
`None`.

- Mittel: arithmetisches Mittel der Antwortzeiten.
- Jitter: Mittel der Beträge der Unterschiede aufeinanderfolgender Antworten (mindestens zwei
  Antworten, sonst `None`).
- Ausreißer: Antwort über `max(Median × 3, Median + 10 ms)`, beurteilt ab 5 Antworten;
  gezählt, nicht entfernt.
- Fenster: 1 h, 24 h, 7 d und 30 d; Aufbewahrung 7 Tage für Stunden-, 30 Tage für
  Tages-Buckets.

### Netzqualitätswert (`diag_score.py`)

Je Komponente werden Messwerte linear zwischen Stützpunkten auf 0 bis 100 Punkte abgebildet
(außerhalb begrenzt). Der Wert ist der gewichtete Mittelwert der Komponenten **mit Daten**,
auf 0,1 gerundet; ohne Daten ist er `None`.

| Komponente | Gewicht | Eingabe | Punkte (Eingabe → Punkte) |
|---|---|---|---|
| `wan_availability` | 25 | WAN verbunden, % | 90 → 0, 95 → 40, 99 → 80, 99,9 → 100 |
| `packet_loss` | 20 | Verlust, % | 0 → 100, 1 → 80, 2,5 → 50, 5 → 20, 10 → 0 |
| `latency` | 15 | mittlere Antwortzeit, ms | 20 → 100, 50 → 80, 100 → 50, 200 → 20, 400 → 0 |
| `jitter` | 10 | Jitter, ms | 5 → 100, 15 → 70, 30 → 40, 60 → 0 |
| `dns` | 15 | Fehler, % und Antwortzeit, ms (die schlechtere) | Fehler 0 → 100, 1 → 80, 5 → 40, 10 → 0; Zeit 30 → 100, 100 → 80, 300 → 40, 1000 → 0 |
| `gateway_reachability` | 10 | Gateway antwortet, % | 90 → 0, 95 → 40, 99 → 80, 99,9 → 100 |
| `router_stability` | 5 | ungeplante Neustarts | 0 → 100, 1 → 70, 3 → 30, 5 → 0 |

Regeln:

- Eine Komponente ohne Daten ist `unknown`: sie fehlt im Mittel und trägt 0 zur Abdeckung bei;
  sie gilt **nie** als perfekt.
- Gemessen, aber ohne Antwort (`no_answer`) ist nicht unbekannt: 0 Punkte mit ihrer Abdeckung.
  Ein toter Pfad ist nie besser als ein schlechter.
- **Abdeckung** = `Σ(Gewicht × Abdeckung der Komponente) / Σ Gewicht` über die anwendbaren
  Komponenten. `not_applicable` (zum Beispiel WAN bei einem AP) lässt Wert und Abdeckung
  unberührt.
- **Geringe Aussagekraft** (`low_confidence`), wenn die Abdeckung unter 0,5 liegt, die
  Beobachtung kürzer als 1 h ist oder es keinen Wert gibt. Der Wert wird trotzdem gezeigt.
- **Abdeckung deckelt den Wert** (seit 1.49.3, nach dem Muster des Security Centers): unter
  einer Abdeckung von 0,25 gibt es **keinen** Wert (`None`, „unbekannt“); darüber höchstens
  `50 + 50 × Abdeckung`, unter voller Abdeckung höchstens 99, 100 nur bei voller Abdeckung.
  Vorher bekam ein Access Point ohne WAN-Messung und ohne Proben, gestützt nur auf
  „0 Neustarts“ (Abdeckung rund 7 %), den Wert 100. Solche Router zählen jetzt als nicht
  bewertet und fließen nicht in den Flottenwert ein.
- **Gesamtnetz:** gewichteter Mittelwert der gemessenen Router (Gewicht 1), aber höchstens 25
  Punkte über dem schlechtesten Mitglied, das nicht gering aussagekräftig ist: ein schlechter
  Router versteckt sich nicht hinter guten. Ein nicht gemessenes Mitglied senkt die Abdeckung,
  nicht den Wert.

Alle Punkte und Gewichte sind **begründete Annahmen**, nicht an echten Daten abgestimmt.

### Baselines (`diag_baseline.py`)

Je (Reihe, Metrik) ein gleitender Mittelwert und eine gleitende Abweichung (RFC 6298:
`alpha` = 1/8, `beta` = 1/4) mit Hysterese. Phasen:

- `learning`: bis 12 Werte gesehen wurden; kein Urteil, jeder Wert wird gelernt.
- `normal`: ein Wert über der Eintrittsschwelle ist ein Ausreißer (gezählt, nicht gelernt);
  3 Ausreißer in Folge schalten auf `degraded`. Gelernt werden nur Werte unter der
  Austrittsschwelle.
- `degraded`: die Baseline ist eingefroren (die Störung wird nie gelernt); 4 Werte in Folge
  unter der Austrittsschwelle schalten zurück auf `normal`.

Schwellen: `Eintritt = Mittel + max(rel × Mittel, abs, k × Abweichung)` mit `k` = 4; `Austritt`
entsprechend mit `k` = 1.

| Metrik | Eintritt rel | Eintritt abs | Austritt rel | Austritt abs | Drift rel | Drift abs |
|---|---|---|---|---|---|---|
| Latenz (ms) | 1,0 | 20 | 0,5 | 10 | 0,25 | 5 |
| Verlust (%) | 1,0 | 5 | 0,5 | 2 | 0,5 | 1 |
| Jitter (ms) | 1,0 | 10 | 0,5 | 5 | 0,5 | 3 |

Langzeit-Drift wird auf UTC-Tages-Buckets beurteilt: 3 Tage in Folge über der Driftschwelle der
eingefrorenen Referenz, jeder Tag mit mindestens 12 gemessenen Proben. Ein Neustart von Home
Assistant oder eines Routers setzt die Zähler zurück und behält die Baseline. Verlust wird als
Verlust der letzten 3 Runden gefüttert.

Die Laufzeit speist die Latenz- und die Verlust-Baseline. Die Jitter-Baseline ist als Baustein
vorhanden, wird aber von der Laufzeit noch nicht gespeist.

Alle Schwellen sind **begründete Annahmen**, nicht an echten Daten abgestimmt.

## 7. Speicher und Quoten

`.storage/openwrt_router.net_diagnostics`, verzögertes Schreiben nach 60 s, sofortiges Schreiben
beim Entladen des letzten Eintrags. Beschädigte Buckets, Reihen, Baselines und Abschnitte werden
verworfen und gezählt; ein unlesbarer Speicher bleibt als `.bak`, das Modul startet leer.

| Grenze | Wert | Konstante |
|---|---|---|
| Router-Messpunkte | 64 | `DIAG_MAX_POINTS` |
| Reihen des HA-Messpunkts | 32 | `DIAG_MAX_SERIES_HA` |
| Reihen je Router-Messpunkt | 8 | `DIAG_MAX_SERIES_PER_ROUTER` |
| Stunden-Buckets je Reihe | 169 (7 × 24 + 1) | `DIAG_MAX_HOUR_BUCKETS` |
| Tages-Buckets je Reihe | 31 | `DIAG_MAX_DAY_BUCKETS` |
| Neustart-Lücken | 64 | `DIAG_MAX_GAP_RECORDS` |
| Messziele | 16 (die Registry erlaubt bis 64) | `DIAG_MAX_TARGETS` |

Jede Quote gilt getrennt: ein voller Messpunkt verweigert nur **neue** Reihen dieses Punkts, seine
vorhandenen Reihen und alle anderen Messpunkte laufen weiter; ein weiterer Router über 64 wird
abgelehnt, bekannte werden nie verdrängt. **Jedes Verwerfen wird gezählt** (`points_refused`,
`series_refused`, `samples_out_of_order`, `hours_dropped`, `days_dropped`, `gaps_dropped`, …)
und im Status gezeigt. Eine Probe, die älter ist als die neueste ihrer Reihe, wird verworfen und
gezählt. Ein Neustart ist eine **Lücke**, nie ein Verlust; auch ein WAN-Ausfall, solange der
Router nach einem Neustart noch anläuft, ist eine Lücke.

Eine Reihe ohne Buckets nach der Aufbewahrung wird gelöscht und gibt ihren Quotenplatz frei
(`series_expired`). Wird ein Ziel aus den Einstellungen entfernt, werden seine HA-Reihen,
Baselines und Runden-Fenster gelöscht (`series_removed`).

## 8. Zusatzlast

Alle Zahlen sind Näherungen ohne Paketverlust und ohne Wiederholung. Sie stehen so im Code
(`DIAG_PACKETS_PER_PROBE`) und im Status unter `load`.

| Messung | Pakete je Messung | Verbindungen |
|---|---|---|
| TCP-Verbindung | 7 (3 Handshake, 4 Abbau) | 1 |
| DNS-Abfrage | 2 (Frage, Antwort) | 0 (UDP) |
| HTTP-Abruf | 11 | 1 |
| ICMP | 0 (auf der HA-Seite übersprungen) | 0 |
| Auflösen eines Hostnamens (nur bei Hostname-Zielen) | etwa 2 bis 4 (Resolver von Home Assistant) | 0 |

Zeitgrenzen je Messung: TCP 3 s, DNS 2 s, HTTP 5 s, Auflösen 3 s. Eine Runde misst
**nacheinander** (nie zwei Pakete gleichzeitig); ihre Zeitgrenze beträgt 154 s
(`16 × (3 + 5 + 1) + 10`: je Ziel Auflösen, die längste Messung und 1 s für das Schließen).
Läuft sie doch ab, bleiben die schon gemessenen Ziele erhalten, der Rest ist ungemessen
(`rounds_partial`).

**Formel** (regelmäßige Messung, nur Home Assistant):

```
Runden je Tag   = 86400 / interval_s
Pakete je Runde = Σ über die bestätigten Ziele (Pakete der Art; Hostname-Ziele + 2 bis 4)
Pakete je Tag   = Runden je Tag × Pakete je Runde
Aufrufe je Runde = Anzahl der bestätigten Ziele (eine Messung je Ziel)
```

| Zustand | Messungen von HA | Aufrufe am Router je Poll | Pakete am Router je Tag |
|---|---|---|---|
| Modul **aus** | 0 | 0 | 0 |
| Modul an, **keine Ziele** (oder regelmäßig aus) | 0 (nur manuelle Läufe nach Administrator-Handlung) | 0 | 0 |
| Modul an, regelmäßig, **N bestätigte Ziele**, Standardintervall 300 s | 288 Runden × N Messungen je Tag | 0 | 0 |

**Rechenbeispiel** (Standardintervall 300 s): drei IP-Ziele, je eines für TCP, DNS und HTTP.

- Runden je Tag: 86400 / 300 = **288**.
- Pakete je Runde: 7 + 2 + 11 = **20**; Verbindungen je Runde: 2 (TCP und HTTP).
- Pakete je Tag: 288 × 20 = **5760**; Verbindungen je Tag: 288 × 2 = **576**;
  DNS-Abfragen je Tag: **288**; Messungen je Tag: 288 × 3 = **864**.
- Wären alle drei Ziele Hostnamen, kämen je Runde 6 bis 12 Pakete für das Auflösen dazu:
  26 bis 32 je Runde, also 7488 bis 9216 je Tag.

**Obere Grenze** (rechnerisch): 16 HTTP-Ziele bei dem kleinsten Intervall von 60 s ergeben
16 × 11 = 176 Pakete je Runde und 1440 Runden, also 253 440 Pakete je Tag. Zeitgrenzen können
Runden verlängern, die Zahl ist deshalb eine Obergrenze, kein Erwartungswert.

**Je Router:** Die Messungen gehen von Home Assistant zu den Zielen, nicht zu den Routern, und
hängen nicht von der Zahl der Router ab. Zeigt ein bestätigtes internes Ziel auf einen Router,
trifft ihn dieser Verkehr.

**Manuelle Läufe:** höchstens **10 Läufe in 600 s** für die HA-Seite (`RateLimit`), gleich dem
Limit des Guards; das sind rechnerisch höchstens 1440 Läufe je Tag. Ein Lauf über dem Limit
wird mit 429 und `Retry-After` abgewiesen. Der Planer lässt höchstens 2 Läufe gleichzeitig zu und
nie zwei Läufe desselben Schlüssels; die Laufzeit des Moduls hat nur den HA-Schlüssel.

**Passiv:** Das Auswerten eines Polls (Kette, Wechselerkennung, Statistik) ist reine Rechnung auf
den Daten des Polls. Sie ruft den Router nicht an; ein Test zählt die Router-Aufrufe.

**Nicht Teil dieser Last:** Der Coordinator öffnet weiterhin je Poll und Router eine
TCP-Verbindung von Home Assistant zu `8.8.8.8:53` (`ping_ms`, Zeitgrenze 3 s; der erste Poll
überspringt sie). Beim Standard-Poll von 60 s sind das bis zu 1440 Verbindungen je Router und Tag.
Diese Messung ist unverändert; ihre Bereinigung folgt in einem eigenen PR.

## 9. Benötigte Router-Rechte und Pakete

**Für diese Version: keine neuen.** Die Netzwerkdiagnose liest, was die Integration ohnehin vom
Router liest (`network.interface dump` ist schon Teil des Polls), und schreibt nichts auf einen
Router. Die rpcd-ACL wird durch das Einschalten nicht verändert. Es sind **keine zusätzlichen
OpenWrt-Pakete** nötig.

Router-seitige Tests sind **nicht enthalten**. Vorhanden sind nur:

- eine Fähigkeitsprüfung je Router im Core (Daten aus dem Dump; `exec_permitted` ist immer
  falsch), und
- die Schnittstelle und eine im Guard registrierte kritische Aktion
  (`net_diagnostics.enable_router_probes`) für eine spätere Version.

Es gibt keinen Ausführer: der Status meldet `router_probes: not_available` mit Grund
`no_executor`. Ein Router-Test bräuchte `file exec` auf `ping`, `nslookup` oder `traceroute`;
keine Stufe der optionalen ACL erlaubt das heute. Nach den Live-Befunden vom 2026-11-18 sind
solche Programme auf den vier geprüften Routern vorhanden, `dnsmasq` läuft aber nicht auf jedem
(ein Relay-AP hat keinen); das ist im Plan festgehalten und für spätere Versionen relevant.

## 10. Routen

Basis `/api/openwrt_topology/diagnostics`. Alle verlangen eine Anmeldung und antworten mit
`Cache-Control: no-store`. Keine Route ruft einen Router; nur `run` sendet Pakete, von Home
Assistant aus.

| Route | Methode | Wer | Zweck |
|---|---|---|---|
| `/overview` | GET | lesen | Wert, Abdeckung, aktive Befunde, Kette je Router und für Home Assistant, letzter Lauf |
| `/history` | GET | lesen | die vier Fenster (1 h, 24 h, 7 d, 30 d) je Reihe |
| `/details` | GET | lesen; Detail nur Administrator | ein Befund mit Kontext. Query `router_id` (ohne: HA-Messpunkt) |
| `/settings` | GET | **Administrator** | Einstellungen (Ziele ohne Host) |
| `/settings` | POST | **Administrator** | Einstellungen ändern; hier wird das Modul eingeschaltet |
| `/run` | POST | **Administrator** | manuelle Diagnose. Body `{"target_ids": ["…"]}`, nur eingerichtete Ziel-IDs, nie ein Host |

Reihenfolge der Prüfungen (`diag_views.py`): Benutzer und Administrator (403), dann Panel-Zugriff
(Nicht-Administratoren nur bei für alle geöffnetem Panel, sonst 403), dann geladene Integration
(410), dann laufendes Modul (503), dann nur bei `run` eingeschaltetes Modul (409 `disabled`),
**erst danach Query und Body**. Der Body ist auf 8 KiB und Tiefe 3 begrenzt, nur bekannte
Schlüssel. Nicht-Administratoren sehen immer die kurze, maskierte Fassung; Detail über die
Kurzfassung hinaus nur für Administratoren nach der „sensitive read“-Prüfung des Cores.

Fehlerzuordnung: 400 ungültig, 403 nicht erlaubt (`authorization_denied`), 404 unbekanntes Ziel
oder unbekannter Router, 409 `disabled` / `busy` / `conflict` / `not_available`, 410 Integration
entladen, 413 Body zu groß, 422 Ziel abgelehnt (`refused`, mit Grund), 429 Rate-Limit mit
`Retry-After`, 500 sonst, 503 Modul oder Core läuft nicht. Fehlerantworten tragen nur eine feste
Meldung, einen Code und höchstens Feldname und Grund, nie Eingabe, Ausnahmetext, Adresse, Host
oder Domain.

## 11. Entitäten

Eine feste, begrenzte Menge: höchstens **6 + N** Entitäten für N Router, nie eine je Ziel. Es
gibt sie **nur bei eingeschaltetem Modul**; Ausschalten entfernt sie aus der Entity-Registry,
Einschalten legt sie sofort an. Die Werte kommen aus dem Modul (keine Router-Aufrufe) und werden
per Signal aktualisiert. Ohne Daten ist der Wert `None`.

| Sensor (englischer Name) | Wert |
|---|---|
| Network quality score (all routers) | Netzqualitätswert; Attribute: Abdeckung, geringe Aussagekraft, Routerzahlen |
| Network monitoring coverage (all routers) | Abdeckung in Prozent |
| Active network diagnostics findings | Zahl der aktiven Befunde, nach Klassifizierung |
| Home Assistant internet latency | Antwortzeit der letzten Runde, ms |
| Home Assistant internet loss (24 h) | Verlust der letzten 24 h, % |
| DNS response time | DNS-Antwortzeit, ms |

Unique-IDs der Flottensensoren: `openwrt_router_fleet_diag_…`. Dazu je Router, der **schon ein
Gerät hat**, ein Binärsensor „Gateway reachable“ (`<entry_id>_diag_gateway_reachable`), erst
wenn die Core-ID des Routers bekannt ist. Er ist an oder aus nur aus einer **direkten**
Messung des Gateway-Glieds; in dieser Version gibt es die nicht, er ist unbekannt (Grund
`not_measured`).

## 12. Vorfallstypen und Verknüpfungsregeln

Zwei neue Vorfallstypen der Netzwerk-Intelligenz, gespeist aus den Änderungsbefunden eines Polls
(Vergleich mit dem vorigen Poll desselben Routers; während ein Router gerade neu gestartet ist,
wird nichts verglichen):

| Typ | Bedeutung | Schwere |
|---|---|---|
| `wan_gateway_changed` | der nächste Hop (Gateway) eines Routers hat gewechselt | info, ohne Cooldown |
| `dns_server_changed` | die Menge der DNS-Server des Routers hat gewechselt | info, ohne Cooldown |

Verknüpfungsregeln (`net_rules.py`):

- Beide sind **nie Wurzel**; sie übernehmen und unterdrücken nichts.
- Sie werden nur von einer Ursache **desselben Routers** übernommen: `wan_down` dieses Routers
  (ein neuer WAN-Lease bringt neuen Hop und neue Resolver), `router_unreachable` oder
  `system_reboot` dieses Routers (nur wenn die Änderung nach Beginn des Ausfalls liegt; eine
  Änderung von davor ist kein Folgefehler).
- `lan_unreachable` übernimmt wie bisher **jeden** Vorfall und jedes Ereignis in seinem Fenster
  (unverändertes bestehendes Verhalten).
- Eine Wurzel eines **anderen** Routers übernimmt sie nie (auch nicht ein Router dahinter, ein
  Uplink-, Port-, Funk- oder Massenabmelde-Vorfall), und `wan_down` eines anderen Routers nimmt
  ihre Ereignisse nicht mit.
- Die **bestehende Korrelation** (Schwellen in `DEFAULT_SETTINGS`, Wurzelränge, alle anderen
  Verknüpfungen) bleibt unverändert; die Typen haben feste Regeln und sind nicht einstellbar.

Die Ereignisse über den Core tragen nur Codes, Zähler, Router-IDs und Pseudonyme; es entstehen
keine Core-Vorfälle.

## 13. Kontext eines Befunds

(`diag_context.py`) Zwei nur lesende Quellen: Konfigurationsänderungen des Configuration
Managers (Drift, kritische Änderung, Backup) und Vorfälle des Security Centers.

- Es zählen nur Änderungen **desselben Routers** im Fenster von 1800 s (30 min) vor dem Befund;
  eine Drift, die bis zu 1800 s danach erkannt wird, kann vorher geschehen sein und ist höchstens
  `possible`. Höchstens 16 Verknüpfungen je Befund; der Speicher für Drift-Notizen hält 16 je
  Router (die älteste fällt zuerst, gezählt als `config_notes_dropped` unter `limits` im
  Status). Nach einem Verwerfen ist der Konfigurationskontext dieses Routers `partial` (Grund
  `config_notes_dropped`), nicht vollständig. Die Übersicht des Security Centers wird höchstens
  alle 60 s je Router gelesen.
- Ein Kontext ist höchstens `probable` und nie stärker als der Befund selbst; er hebt dessen
  Ursachenklasse nie an. Nur Bereiche, die die Klasse technisch erklären können, zählen (ein
  fehlender Standardweg ist ein Routing-Problem, keine VLAN- oder Firewall-Änderung).
- Eine Firewall-Änderung neben einem blockierten ICMP- oder TCP-Ziel bei sonst funktionierendem
  Netz ergibt die Vermutung `possible_firewall_restriction` (`possible`).
- Fehlt eine Quelle, ist sie aus oder nicht bereit, steht `context_unavailable` mit Grund,
  nie „keine Änderung“. Eine Quelle, die erst nach Beginn des Fensters lauscht, ergibt `partial`.

## 14. Datenschutz und Diagnose-Download

- Ausgaben, Logs und Ereignisse tragen Codes, Zahlen, Router-IDs, Ziel-IDs und Pseudonyme,
  nie Adresse, Host, Domain, Antworttext oder Benutzer-ID. Logs über DEBUG tragen von einer
  Ausnahme nur den Typ.
- Pseudonyme in Ereignissen entstehen mit dem Modulschlüssel des Cores. **Ohne Modulschlüssel**
  wird kein Befund-Ereignis gesendet (gezählt als `events_not_ready`); der Zustand ist
  `not_ready` mit `module_key_missing`. Der Schlüssel wird höchstens alle 300 s neu erfragt.
- Der Diagnose-Download enthält den Block `network_diagnostics` (Zustände, Gründe, Router- und
  Ziel-IDs, Zähler; ohne die Reihen-Einzelheiten). Er läuft durch die Maskierung des Cores und
  eine eigene Schwärzung der Schlüssel `address`, `dns_servers`, `gateway`, `host`, `hosts`,
  `internal_networks`, `ipv4_gateway`, `ipv6_gateway`, `local_domains`, `next_hop`,
  `dns_query_name`, `http_path`. Auch `wan_status.diag_facts` mit den neuen Adressfeldern des
  Polls wird so geschwärzt. Die gemeinsame Liste `DIAGNOSTICS_TO_REDACT` bleibt unverändert.

## 15. Grenzen

- **Keine Router-Tests** (Ping, `nslookup`, `traceroute` auf dem Router): nur Schnittstelle und
  Fähigkeitsprüfung, kein Ausführer, kein ACL-Recht.
- **Kein externes Ziel voreingestellt.** Ohne eingerichtete Ziele sind Internet und DNS
  unbekannt, auch der Wert ist dann in diesen Komponenten leer.
- **Das Gateway-Glied eines Routers ist unbekannt**, der Binärsensor „Gateway erreichbar“ ebenso.
- **Die Route `details` hat noch keine Ansicht im Panel.**
- **Ziele und Bereichslisten sind im Panel nur lesbar**; geändert werden sie über die Route
  `settings`.
- **Gewichte, Punktetabellen und Baseline-Schwellen sind begründete Annahmen**, nicht an echten
  Daten abgestimmt. Die Jitter-Baseline wird noch nicht gespeist.
- **Die bestehende TCP-Messung des Coordinators zu `8.8.8.8:53`** bleibt unverändert und
  getrennt.
- **Nicht gegen echte Geräte getestet:** weder gegen Router noch gegen Ziele noch in einer
  echten Home-Assistant-Instanz; die Tests laufen ohne Geräte und ohne Netz. Offen sind die
  Live-Prüfungen aus dem Plan.
- **ICMP von Home Assistant aus gibt es nicht** (ein ICMP-Ziel wird übersprungen).
- **Der Zähler `probe_packets`** zählt die Näherung je Art, auch für eine übersprungene
  DNS-Messung ohne Abfragenamen; er ist eine Größenordnung, keine Messung.
