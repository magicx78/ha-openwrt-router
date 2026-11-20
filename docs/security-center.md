# Security Center

<!-- Nutzerdoku ab 1.46.0. Keine IPs, MACs, Hostnamen echter Geräte, Passwörter oder Tokens;
     Beispiele nutzen 192.0.2.x (RFC 5737), MACs 02:00:00:… und example.org. Aussagen sind am
     Code gelesen (security_center.py, security_syslog.py, security_views.py,
     security_entities.py, security_rules.py, security_trust.py, security_logfmt.py,
     security_logsrc.py, const.py, Frontend unter enterprise/security/), nicht an Geräten
     ausgeführt. Router-Zahlen und Logformate stammen aus der lesenden Prüfung vom 2026-11-18,
     die im Plan docs/plans/2026-11-17-security-center.md festgehalten ist. Aufbau und Zusagen
     des Cores: docs/enterprise-core.md; Konfigurationsstände für die Drift-Erkennung:
     docs/configuration-manager.md. -->

## Inhalt

1. [Was es tut und was nicht](#1-was-es-tut-und-was-nicht)
2. [Einschalten](#2-einschalten)
3. [Erkennungen](#3-erkennungen)
4. [Fähigkeitsmatrix der Datenquellen](#4-fähigkeitsmatrix-der-datenquellen)
5. [Log-Empfang](#5-log-empfang)
6. [Remote-Logging am Router einschalten (macht der Nutzer selbst)](#6-remote-logging-am-router-einschalten-macht-der-nutzer-selbst)
7. [Routen und Rechte](#7-routen-und-rechte)
8. [Flotten-Sensoren](#8-flotten-sensoren)
9. [Datenschutz](#9-datenschutz)
10. [Zusatzlast](#10-zusatzlast)
11. [Benötigte Router-Rechte (ACL)](#11-benötigte-router-rechte-acl)
12. [Bekannte Einschränkungen](#12-bekannte-einschränkungen)
13. [Erweiterungen (nur dokumentiert, nicht gebaut)](#13-erweiterungen-nur-dokumentiert-nicht-gebaut)

## 1. Was es tut und was nicht

Das Security Center wertet Daten aus, die diese Integration größtenteils ohnehin von Ihren
OpenWrt-Routern liest (WLAN-Ereignisse, Geräteliste, Konfigurationsänderungen), und macht
daraus **Hinweise**. Optional wertet es Syslog-Zeilen aus, die Ihre Router an Home Assistant
schicken. Es baut auf dem Enterprise Core (ab 1.44.0), der Netzwerk-Intelligenz, der
Client-Stabilität und, für Konfigurationsänderungen, dem Configuration Manager (ab 1.45.0) auf.

**Es beobachtet nur.** Ausdrücklich nicht:

- **keine Sperren** von Geräten oder Adressen,
- **keine Quarantäne** und keine Durchsetzung (der Zustand „quarantined“ wird nie gesetzt),
- **keine Scans** (kein WLAN-Scan, kein Port-Scan, keine aktive Abfrage von Geräten),
- **keine Firewall-Änderung** und überhaupt keine Änderung an einem Router,
- **kein zusätzlicher Router-Aufruf je Poll** ([Abschnitt 10](#10-zusatzlast)),
- nichts an externe Dienste.

Ein Ergebnis ist ein **Hinweis** oder ein **Indikator**, nie ein Beleg für einen Angriff. Hinweise
nennen keine Ursache. „Bestätigt“ ist nur ein Status, den Sie selbst setzen. Die
Auswertung setzt ihn nie, denn Logzeilen und Zähler beweisen nichts. Das Security Center
ersetzt weder eine Firewall noch ein Intrusion-Detection-System.

**Keine Duplikate:** Deckt ein offener Vorfall der Netzwerk-Intelligenz einen Befund schon ab
(zum Beispiel wiederholte WLAN-Anmeldefehler), legt das Center keinen eigenen Hinweis an und
verknüpft nur einen Eintrag in der Zeitleiste. Vorfälle der Netzwerk-Intelligenz werden nie
geändert oder unterdrückt; ihre Zähler und der Health-Score bleiben gleich, ob das Center an
ist oder nicht.

## 2. Einschalten

**Standardmäßig AUS.** Es gibt keinen Optionsdialog und keinen Dienst dafür:

1. Panel öffnen, **Enterprise → Security Center**.
2. Im Bereich **Einstellungen** das Center einschalten. Das darf **nur ein
   Home-Assistant-Administrator**; die Änderung wird im Audit-Log des Cores festgehalten.

Ausgeschaltet gilt: kein Beobachter, kein Listener, **kein Socket**, keine Schreibvorgänge,
keine Ereignisse, keine Sensoren. Das Center liest dann nur seinen eigenen Speicher
(`.storage/openwrt_router.security_center`). Das Panel zeigt „Das Security Center ist
ausgeschaltet“ und erklärt, was es tut.

| Einstellung | Auswahl | Vorgabe | Wirkung |
|---|---|---|---|
| `enabled` | Schalter | aus | Gesamtschalter. Wirkt sofort, ohne Neuladen. |
| `log_path` | `off` / `syslog` / `collector` | `off` | Woher ausgelagerte Router-Logs kommen. Es ist höchstens ein Weg aktiv ([Abschnitt 5](#5-log-empfang)). `collector` ist **noch nicht verfügbar**. |
| `syslog_port` | 1024 bis 65535 | 5514 | UDP-Port des Syslog-Empfängers. |
| `keep_dns_names` | Schalter | aus | Nur dann dürfen DNS-Namen im Klartext als Beispiel an einem Hinweis stehen ([Abschnitt 9](#9-datenschutz)). |
| `thresholds` | je Erkennung ein Schwellwert | leer (Vorgaben der Erkennung) | Schwellwerte einzelner Erkennungen (höchstens 32 Einträge, nur bekannte Erkennungs-IDs). |
| `subnet_zones` | Zuordnung Subnetz → Zonenname | leer | Hilft `fw_inter_vlan`, das Zielsegment einer Verbindung zu erkennen ([Abschnitt 3](#3-erkennungen)). |

## 3. Erkennungen

Jede Erkennung hat eine Verfügbarkeit, die das Panel unter **Erkennungen** zeigt:

- **verfügbar**: die Datenquelle liefert.
- **eingeschränkt**: sie liefert, aber mit einer genannten Einschränkung (zum Beispiel ein
  Router ohne Datenquelle oder ein Zielsegment, das nicht zuzuordnen ist).
- **nicht verfügbar** mit Grund (zum Beispiel `collector_not_available`, `sender_not_allowed`,
  `no_data_yet`, `stale`). **Nie** „keine Befunde“, solange eine Quelle fehlt: fehlende Daten sind
  keine Entwarnung. `stale` heißt: seit mehr als 15 Minuten keine Zeile mehr.
- **Format unbestätigt**: Der Parser kennt das Zeilenformat nur aus Quellcode und
  Beschreibung, es wurde an einem echten Gerät nicht gesehen ([Abschnitt 12](#12-bekannte-einschränkungen)).
  Das Panel markiert so alle Firewall- und DNS-Erkennungen.

### WLAN (Quelle: Router-Log und Ereignisse der Netzwerk-Intelligenz, ohne neuen Abruf)

| Erkennung | Was sie meldet | Hinweis |
|---|---|---|
| `wifi_auth_repeat` | wiederholte WLAN-Anmeldefehler eines Geräts | Entspricht dem Vorfall `wifi_auth_failures` der Netzwerk-Intelligenz; bei offenem NI-Vorfall nur verknüpft. |
| `wifi_auth_many_clients` | Anmeldefehler vieler Geräte an einem Zugangspunkt | Gegenstück: `wifi_auth_wave`. |
| `wifi_assoc_burst` | auffällig viele Verbindungsversuche | |
| `wifi_deauth_cluster` | gehäufte Abmeldungen | Indikator; Gegenstück: `wifi_mass_disconnect`. Gefälschte Abmelde-Frames Dritter sieht das Log eines Zugangspunkts nicht. |
| `wifi_multi_ap_auth` | Anmeldefehler eines Geräts an mehreren Zugangspunkten | Braucht mindestens zwei Router mit Daten. |

### Firewall (Quelle: Firewall-Protokoll per Syslog; **Format unbestätigt**)

| Erkennung | Was sie meldet | Voraussetzung und Grenze |
|---|---|---|
| `fw_blocked` | ungewöhnlich viele blockierte Verbindungen (gegen eine gelernte Grundlinie) | Der Router muss Verwerfen/Ablehnen loggen ([Abschnitt 6](#6-remote-logging-am-router-einschalten-macht-der-nutzer-selbst)). |
| `fw_port_scan_hint` | Hinweis auf eine Port-Abfrage | Nur ein Indikator. |
| `fw_mgmt_access` | wiederholt blockierte Zugriffe aus beobachteten Zonen (`guest`, `iot`) auf Verwaltungs-Ports | Prüft Zielports (22, 23, 80, 443, 8080, 8443); Verwaltungsadressen werden vom Center nicht übergeben. |
| `fw_inter_vlan` | wiederholt blockierte Verbindungen zwischen Netzsegmenten | fw4-Zeilen nennen die Zielzone nicht. Ohne `subnet_zones` sind solche Zeilen „nicht zuzuordnen“; die Erkennung meldet dann die Einschränkung `dest_zone_unknown`, statt zu raten. |

### Konfiguration (Quelle: Drift-Ereignisse des Configuration Managers)

| Erkennung | Was sie meldet | Voraussetzung |
|---|---|---|
| `vlan_segmentation_drift` | eine Konfigurationsänderung in den Bereichen VLAN, Firewall oder Interface | Backup und Drift-Prüfung des Configuration Managers sind für den Router an. Die Bereiche kommen aus dem Vergleich zweier gespeicherter Versionen, ohne Router-Kontakt. **Ohne Backups des Configuration Managers keine Drift-Erkennung.** Ein Befund kurz nach einer Konfigurationsänderung wird nur zeitlich verknüpft, ohne Ursachenbehauptung. |

### DNS (Quelle: DNS-Abfrage-Log per Syslog; **Format unbestätigt**)

| Erkennung | Was sie meldet |
|---|---|
| `dns_rate` | ungewöhnlich viele DNS-Anfragen (gegen eine gelernte Grundlinie) |
| `dns_nxdomain_cluster` | gehäufte Anfragen an nicht vorhandene Namen |
| `dns_many_domains` | auffällig viele verschiedene Namen |
| `dns_tunnel_hint` | Hinweis auf ungewöhnliche Namen (Länge, Aufbau); nur ein Indikator, kein Beleg für Tunneling |

### Geräte (Vertrauensbuch, Quelle: Clients aus dem Poll und Client-Stabilität)

Das Center führt keine zweite Client-Datenbank; es merkt sich nur Vertrauenszustand, Name,
Zeiten, letzte IP und letzten Hostnamen sowie Indikatoren.

- **Neues Gerät:** eine MAC, die noch nie gesehen wurde. Das heißt nur „noch nicht gesehen“.
  Ein Gerät mit zufälliger (privater) MAC bekommt eine niedrigere Stufe, weil solche MACs
  rotieren.
- **Unvollständige Daten** ergeben „unbekannt“, nie „bekannt“.
- **IP-Wechsel:** nur eine Häufung (Vorgabe: mindestens 4 Wechsel in einer Stunde) ist ein
  Indikator; eine neue Adresse nach einer DHCP-Erneuerung ist normal. Ein
  **Hostname-Wechsel** bei gleicher MAC ist ebenfalls ein Indikator.
- **Auffällig** wird ein Gerät erst, wenn mindestens zwei *verschiedene* Indikatorarten
  innerhalb einer Stunde zusammenkommen (zum Beispiel Anmeldefehler an mehreren Zugangspunkten
  und eine IP-Häufung). Eine unbekannte MAC allein ist nie auffällig.
- **Bestätigen** (Administrator) macht ein Gerät „bekannt“ und räumt seine aktuellen
  Indikatoren; neue zählen wieder. Einen Anzeigenamen setzen darf ebenfalls nur ein
  Administrator.

**Nicht gebaut** (steht im Plan, ist im Code aber nicht angebunden): Indikatoren für
MAC-Spoofing und Verkehrsänderungen, Erkennung ungewöhnlicher Verbindungszeiten, Erkennung
fehlgeschlagener Admin-Anmeldungen (SSH/LuCI), Erkennungen aus Zählern von nft, conntrack,
dnsmasq oder `/proc/net/snmp`, Rogue-AP-Indikator. Ein Router-Neustart wird nur genutzt, um
die Zeitfenster **dieses Routers** zurückzusetzen; einen eigenen Hinweis dazu gibt es nicht
(den Vorfall `system_reboot` meldet die Netzwerk-Intelligenz).

## 4. Fähigkeitsmatrix der Datenquellen

Gruppen: **a** = Daten liegen schon in der Integration (0 neue Router-Aufrufe), **b** = ein
neuer, sparsamer Abruf, **c** = braucht eine Änderung am Router oder einen Log-Weg.
Stand dieser Tabelle ist der gebaute Stand 1.46.0, nicht der Plan.

| Quelle | Gruppe | Stand 1.46.0 | Voraussetzung |
|---|---|---|---|
| WLAN-Ereignisse (`log read`, Ereignisse der Netzwerk-Intelligenz) | a | genutzt | Netzwerk-Intelligenz an |
| Verbundene WLAN-Clients (hostapd) | a | genutzt (Geräteliste, Vertrauensbuch) | – |
| Client-Historie (Zeiten, IP, Hostname) | a | genutzt | Client-Stabilität an; sonst nur die Clients des Polls |
| Router-Uptime | a | genutzt (setzt Fenster dieses Routers zurück) | – |
| Vorfälle der Netzwerk-Intelligenz | a | nur Verknüpfung, lesend | – |
| Konfigurationsänderung (Drift, Core) | b | genutzt | Configuration Manager: Backup und Drift-Prüfung an |
| Firewall-Log (`fw4` mit `log`) | c | genutzt über Syslog (Weg A) | Router-Logging und Syslog; Format unbestätigt |
| DNS-Abfrage-Log (dnsmasq `logqueries`) | c | genutzt über Syslog (Weg A) | Router-Logging und Syslog; Format unbestätigt |
| Admin-Anmeldungen (dropbear) | a | **keine Erkennung**; der Parser kennt die Erfolgszeilen (live gesehen), die Fehlzeile ist unbestätigt | – |
| DHCP-Leases, ARP-Tabelle, Bridge-FDB | a | nicht direkt gelesen (IP und Hostname kommen über die Clients des Polls) | – |
| Conntrack-Maximum, nft-Zähler, `/proc/net/snmp`, dnsmasq-Metriken, IPv6-Nachbarn, WLAN-Scan, `uci get firewall` | b | **nicht gebaut** | später, mit gestufter Core-ACL ([Abschnitt 11](#11-benötigte-router-rechte-acl)) |
| Volle Conntrack-Tabelle, ubus-Ereignisstrom | – | bewusst nicht vorgesehen (über ubus nicht lesbar bzw. auf Routern instabil) | – |
| Flow-Export, IDS, DNS-Resolver mit Statistik | c | nur als Erweiterung dokumentiert ([Abschnitt 13](#13-erweiterungen-nur-dokumentiert-nicht-gebaut)) | – |

## 5. Log-Empfang

Zwei Wege sind vorgesehen; in den Einstellungen ist höchstens **einer** aktiv, Standard ist
`off` (dann nutzen nur die Erkennungen ohne Log-Weg Daten, alle Firewall- und DNS-Erkennungen
melden „nicht verfügbar“).

### Weg A: Syslog-Empfänger in Home Assistant (gebaut)

Ein lokaler UDP-Listener, eine Zeile je Datagramm. Er sendet nichts und ruft keinen Router.

| Punkt | Festlegung |
|---|---|
| Wann er bindet | **nur**, wenn das Center an ist **und** `log_path` = `syslog`. Sonst gibt es keinen Socket. |
| Adresse und Port | `0.0.0.0` (alle IPv4-Adressen), UDP-Port 5514 (einstellbar 1024 bis 65535). Kein IPv6. |
| Absenderliste | Nur Absender, deren Adresse die Verwaltungsadresse eines Routers aus der Router-Registry ist (IP-Literale, **keine DNS-Auflösung**). Ist eine Adresse zwei Routern zugeordnet, gilt sie für keinen. Alles andere wird verworfen und gezählt. Die Router-Zuordnung kommt von der Liste, nie vom HOST-Feld der Zeile. |
| Zeilenlänge | höchstens 2048 Byte; länger wird abgeschnitten und gezählt. |
| Raten | Token-Bucket je Absender (50 Zeilen/s, Spitze 500) und gesamt (200 Zeilen/s, Spitze 2000); mehr wird verworfen und gezählt. |
| Puffer | höchstens 4000 Zeilen; ein voller Puffer verwirft die neuesten und zählt. Ab 500 gepufferten Zeilen wird vor dem nächsten Poll ausgewertet. |
| Zeit | Die Zeit einer Zeile ist ihre **Empfangszeit**; der Zeitzonen-Versatz des Routers wird nicht gelernt. Eine Zeile mit einer Zeit weit in der Zukunft bekommt die Empfangszeit und verschiebt nichts. |
| Doppelte Zeilen | Ein gemeinsamer Deduper filtert erneut gesendete Zeilen; Marken bleiben über Wechsel des Log-Wegs erhalten. |
| Rohzeilen | Es werden **nie** Rohzeilen gespeichert und nie oberhalb von DEBUG protokolliert; nur Zähler und gekürzte Belege. |
| Bind-Fehler | (Port belegt, keine Berechtigung) macht die Quelle „nicht verfügbar“ mit Grund; das Setup läuft weiter. Ein neuer Versuch folgt höchstens alle 5 Minuten aus dem Poll. |
| Wechsel des Wegs | Ein Wechsel von `syslog` weg oder auf `off` schließt den Socket. |

**Grenze: UDP-Absender sind im LAN fälschbar.** Die Absenderliste filtert Rauschen und
Fehlkonfigurationen, sie **authentifiziert keinen Router**. Deshalb reichen Syslog-Daten allein
nie für „bestätigt“.

Auf Home Assistant OS ist **nicht geprüft**, ob der Core-Container UDP auf Port 5514 ohne
Zusatzschritte erreicht. Läuft Home Assistant in Docker ohne Host-Netz, ist ein Port-Mapping
nötig (Annahme, nicht geprüft). Der Port ist kein Ersatz für Netzsegmentierung: Der Empfänger
ist im ganzen LAN erreichbar.

### Weg B: Collector (noch nicht verfügbar)

Ein separater Dienst außerhalb von Home Assistant, der Logs sammelt und der Integration
verdichtete Datensätze liefert, ist als zweiter Weg vorgesehen, aber **nicht gebaut**.
Wählt man `log_path` = `collector`, melden Firewall- und DNS-Erkennungen „nicht verfügbar“
mit dem Grund `collector_not_available`.

## 6. Remote-Logging am Router einschalten (macht der Nutzer selbst)

> **Die Integration ändert nichts am Router.** Die folgenden Befehle führen Sie selbst per SSH
> aus, nach eigener Entscheidung. Sichern Sie vorher, halten Sie jede Änderung in Ihrem
> Änderungsprotokoll fest und führen Sie sie nur dann aus, wenn Sie den Rückweg kennen. Die
> Befehle stammen aus dem Plan und sind **in dieser Doku nicht ausgeführt** worden.

`<ziel>` ist die Adresse von Home Assistant (Beispiel `192.0.2.10`). Der Router muss die
Zeilen von **der Verwaltungsadresse** senden, unter der die Integration ihn kennt; sonst
verwirft der Empfänger sie als „fremder Absender“ (Annahme: der Router sendet von der
LAN-Adresse, die Home Assistant kennt).

Gilt für alle Befehle: Die Sicherung (`uci export …`) liegt im RAM des Routers; kopieren Sie sie
vor einem Router-Neustart nach Home Assistant. OpenWrt kennt je Router **ein** Log-Ziel
(`log_ip`); ob mehrere möglich sind, ist nicht geprüft.

**Remote-Syslog** (Voraussetzung für Firewall- und DNS-Erkennungen):

```sh
uci export system > /tmp/system.vor-security
uci set system.@system[0].log_ip='192.0.2.10'
uci set system.@system[0].log_port='5514'
uci set system.@system[0].log_proto='udp'
uci commit system
/etc/init.d/log restart
# Rückweg:
uci delete system.@system[0].log_ip
uci delete system.@system[0].log_port
# log_proto NICHT löschen, wenn es vorher gesetzt war: den Wert aus
# /tmp/system.vor-security wiederherstellen.
uci commit system
/etc/init.d/log restart
```

Ein zusätzlicher `logread`-Prozess läuft dann auf dem Router (Größenordnung wenige hundert KB
RAM, geschätzt, nicht gemessen). Solange `log_file` leer bleibt, entstehen keine Flash-Schreibvorgänge.

**Firewall-Logging** (nur eine Zone, mit Ratenbegrenzung; die Zone über ihren Namen suchen):

```sh
uci export firewall > /tmp/firewall.vor-security
uci show firewall | grep "\.name='wan'"        # Index <n> der Zone ermitteln
uci set firewall.@zone[<n>].log='1'
uci set firewall.@zone[<n>].log_limit='10/minute'
uci commit firewall
/etc/init.d/firewall reload
# Rückweg:
uci delete firewall.@zone[<n>].log
uci delete firewall.@zone[<n>].log_limit
uci commit firewall
/etc/init.d/firewall reload
```

**DNS-Abfrage-Log** (dnsmasq; der Neustart unterbricht DNS und DHCP kurz, deshalb in einem
Wartungsfenster):

```sh
uci export dhcp > /tmp/dhcp.vor-security
uci set dhcp.@dnsmasq[0].logqueries='1'
uci commit dhcp
/etc/init.d/dnsmasq restart
# Rückweg:
uci delete dhcp.@dnsmasq[0].logqueries
uci commit dhcp
/etc/init.d/dnsmasq restart
```

**Risiko des DNS-Abfrage-Logs:** Jede Abfrage wird eine Zeile im kleinen Log-Ring des Routers
(Standard 64, Einheit nicht geprüft). Auf einem Gateway mit vielen Clients verdrängen diese
Zeilen WLAN-Zeilen, bevor die Netzwerk-Intelligenz sie liest, und senken deren
WLAN-Abdeckung. Ein größerer Ring (`system.@system[0].log_size`) kostet RAM; die Wirkung ist
nicht geprüft. Besser ist ein eigener DNS-Resolver mit Statistik auf einem separaten Host
([Abschnitt 13](#13-erweiterungen-nur-dokumentiert-nicht-gebaut)).

## 7. Routen und Rechte

Alle Routen liegen unter `/api/openwrt_topology/security`, verlangen eine Anmeldung und
antworten mit `Cache-Control: no-store`. Keine Route ruft einen Router.

| Route | Methode | Wer | Zweck |
|---|---|---|---|
| `/overview` | GET | lesen | Score, Abdeckung, Hinweise, Zeitleiste, Geräte. Query: `since`, `until`, `router_id`, `client`, `category`, `severity`, `limit` |
| `/incidents/{id}` | GET | lesen | ein Hinweis (`sec_…`) mit seinen Zeitleisten-Einträgen |
| `/incidents/{id}/status` | POST | **Administrator** | Status setzen: `open`, `resolved`, `confirmed` |
| `/detections` | GET | lesen | Verfügbarkeit je Erkennung, Zustand je Router und Quelle, Log-Weg |
| `/settings` | GET | lesen | Einstellungen (Subnetz-Zuordnung für Nicht-Administratoren nur als Anzahl) |
| `/settings` | POST | **Administrator** | Einstellungen ändern; hier wird das Center eingeschaltet |
| `/devices/{mac}/confirm` | POST | **Administrator** | Gerät als bekannt bestätigen (optional mit Namen) |
| `/devices/{mac}/name` | POST | **Administrator** | Anzeigenamen setzen oder mit `null` löschen |

- **Lesen:** Administratoren; andere angemeldete Benutzer nur, solange das Topologie-Panel
  für alle Benutzer geöffnet ist (sonst 403). Nicht-Administratoren sehen Pseudonyme statt MAC,
  IP und Hostname.
- **Schreiben:** nur Administratoren (403 vor dem Lesen des Bodys); das Center fragt zusätzlich
  den Guard des Cores, jede Aktion wird auditiert.
- **Weitere Antworten:** 410 nach dem Entladen der Integration, 503 solange kein Center läuft,
  409 `disabled` bei Schreibaktionen, solange das Center aus ist (ausgenommen das
  Einschalten selbst).
- **Eingaben** werden streng geprüft: nur bekannte Schlüssel, Typen und Bereiche, höchstens
  4 KiB JSON, zu tief verschachteltes JSON ergibt 400. Fehlerantworten tragen nur eine feste
  Meldung, einen Code und höchstens Feldname und Grund.

Das Panel zeigt den Tab **Enterprise → Security Center** jedem angemeldeten Benutzer; das
Backend entscheidet, was er sieht. Schreibknöpfe haben nur Administratoren. Router erscheinen
im Tab als gekürzte ID, nicht mit Namen.

## 8. Flotten-Sensoren

Sieben Sensoren für die ganze Flotte (ohne Gerät, Unique-ID `openwrt_router_fleet_security_…`),
einer je HA-Instanz. Sie gibt es **nur bei eingeschaltetem Center**; Ausschalten entfernt sie
aus der Entity-Registry, Einschalten legt sie sofort an. Die Werte kommen aus dem Center (keine
Router-Aufrufe) und werden per Signal aktualisiert.

| Sensor (englischer Name) | Wert |
|---|---|
| Security score (all routers) | Sicherheitswert 0 bis 100, mit Faktoren und Abdeckung im Panel |
| Active security hints (all routers) | offene und bestätigte eigene Hinweise |
| Critical security hints (all routers) | davon kritische |
| Unconfirmed devices (all routers) | Geräte, die nicht bestätigt sind (neu, unbekannt, auffällig) |
| Firewall log entries, last hour (all routers) | blockierte Firewall-Protokollzeilen der letzten Stunde |
| Wi-Fi authentication failures, last hour (all routers) | WLAN-Anmeldefehler der letzten Stunde |
| Security detection coverage (all routers) | Anteil der Erkennungen mit liefernder Quelle, in Prozent |

Liefert keine Quelle Daten, ist der Wert `None` (unbekannt), **nie 0**: keine Daten heißen nicht
„nichts passiert“. Ohne Quelle bleibt auch der Sicherheitswert unbekannt und wird nie als
„gesund“ gezeigt. Die beiden Stundenzähler liegen nur im Speicher und beginnen nach einem
Neustart von Home Assistant bei null.

## 9. Datenschutz

- **Pseudonyme statt Klartext:** Nur Administratoren sehen MAC, IP und Hostname im Klartext;
  alle anderen Pseudonyme (`cli_…`) oder die Maske. Der Schlüssel für die Pseudonyme kommt vom
  Core.
- **Maskierung auf dem Server** für Antworten, Ereignisse, Logs und Diagnose.
- **DNS-Namen standardmäßig aus:** Ohne `keep_dns_names` steht an einem DNS-Hinweis kein
  Klartextname.
- **Keine HA-Benutzer-IDs** im Speicher des Centers; der Core hält sie in seinem Audit-Speicher
  und stellt ein eigenes Pseudonym auf den Bus.
- **Keine Rohzeilen:** Syslog-Zeilen werden nie ungefiltert gespeichert und nie oberhalb von
  DEBUG protokolliert; Evidenz ist gekürzt und maskiert.
- **Diagnose:** Der Block `security_center` enthält nur Zähler, Zustände und Gründe, keine MAC,
  Adresse, Hostname, Benutzer-ID oder Schlüssel.
- **Speicher:** `.storage/openwrt_router.security_center`, höchstens 512 KB; Einstellungen,
  Vertrauensbuch, Grundlinien, maskierte Hinweise, Zeitleiste (höchstens 2000 Einträge und 14
  Tage), Dedup-Marken. Beschädigte Abschnitte starten leer, ein unlesbarer Speicher bleibt als
  `.bak`. Nichts geht an externe Dienste.

## 10. Zusatzlast

- **Router:** **kein zusätzlicher Router-Aufruf je Poll.** Das Center hängt als Beobachter am
  vorhandenen Poll der Netzwerk-Intelligenz; ein Test zählt die ubus-POSTs mit und ohne Center.
  Die geplanten neuen Abrufe der Gruppe b (siehe [Abschnitt 4](#4-fähigkeitsmatrix-der-datenquellen))
  sind **nicht gebaut**; deshalb gelten für diesen Stand keine Zahlen dazu.
- **Ausgeschaltet:** 0 Router-Aufrufe, kein Socket, keine Schreibvorgänge.
- **Home Assistant:** Der Syslog-Empfänger hat feste Obergrenzen (Zeilenlänge, Raten, Puffer,
  [Abschnitt 5](#5-log-empfang)); zu viele Zeilen werden verworfen und gezählt, nie blockiert.
  Der Speicher ist auf 512 KB begrenzt, die Zeitleiste auf 2000 Einträge, eigene Hinweise auf 100.
- **Router bei Remote-Logging:** Das ist Ihre Änderung ([Abschnitt 6](#6-remote-logging-am-router-einschalten-macht-der-nutzer-selbst)):
  ein zusätzlicher `logread`-Prozess und je Zeile Netzverkehr; die Größenordnung ist nicht
  gemessen.

## 11. Benötigte Router-Rechte (ACL)

**Für den gebauten Stand: keine neuen.** Das Center nutzt nur, was die Integration ohnehin liest,
und schreibt nichts auf einen Router; die rpcd-ACL bleibt unverändert und wird durch das
Einschalten nicht neu geschrieben. Die Quellen der Gruppe b, die später dazukommen können
(zum Beispiel Conntrack-Maximum, dnsmasq-Metriken, `/proc/net/snmp`), brauchen zusätzliche
Lese-Rechte. Sie sollen über die **gestufte Core-ACL** angeboten werden, also erst nach
ausdrücklicher Einzelfreigabe eines Administrators, wie beim Configuration Manager.

## 12. Bekannte Einschränkungen

- **Syslog-Empfänger:** bindet auf `0.0.0.0` (nur IPv4), und nur, wenn das Center an ist und der
  Log-Weg `syslog` gewählt ist. Er ist im ganzen LAN erreichbar.
- **Absenderliste:** kommt aus der Router-Registry. **Router, die mit einem Hostnamen statt
  einer IP eingetragen sind, kommen nicht auf die Liste** (es gibt keinen DNS-Lookup); ihre
  Firewall- und DNS-Quellen melden `sender_not_allowed`.
- **Logzeit = Empfangszeit.** Der Zeitzonen-Versatz des Routers wird nicht gelernt.
- **UDP-Absender sind fälschbar;** die Liste authentifiziert keinen Router.
- **Logformate unbestätigt an echten Geräten:** die fw4-Logfelder, die dnsmasq-Abfragezeile,
  der Kopf der logd-Remote-Zeile und die dropbear-Fehlzeile. Live gesehen wurden nur die
  dropbear-Erfolgs-, Verbindungs- und Ende-Zeilen (lokale Form). Die Firewall- und
  DNS-Erkennungen laufen mit Platzhalterformaten und sind im Panel als „Format unbestätigt“
  markiert. Bis zur Bestätigung ist ein Ausbleiben von Hinweisen kein Beleg.
- **Port 5514 auf Home Assistant OS ist ungeprüft** ([Abschnitt 5](#5-log-empfang)).
- **Ohne Backups des Configuration Managers keine Drift-Erkennung** (`vlan_segmentation_drift`
  meldet dann „nicht verfügbar“).
- **Stundenzähler nur im Speicher** (Sensoren „last hour“): nach einem Neustart von Home
  Assistant beginnen sie bei null.
- **Kein Test gegen echte Router oder eine echte Home-Assistant-Instanz.** Die Tests laufen
  ohne Geräte; das Panel wurde nicht in einem echten Home Assistant geprüft.
- **Topologie-Markierung nicht gebaut:** betroffene Router oder Geräte werden in der
  Topologie-Ansicht nicht markiert.
- **Router erscheinen im Tab als gekürzte ID,** nicht mit Namen.
- **Collector (Weg B) nicht verfügbar** ([Abschnitt 5](#5-log-empfang)).
- **Keine Quarantäne, keine Sperre, keine Durchsetzung:** auch bei einem auffälligen Gerät
  ändert das Center nichts am Netz.
- **Ein Ziel je Router:** Der Versand an Home Assistant verdrängt ein vorhandenes Remote-Log-Ziel
  des Routers (`log_ip`).

## 13. Erweiterungen (nur dokumentiert, nicht gebaut)

Diese Erweiterungen sind **nicht Teil von 1.46.0**; sie zeigen, wo sie später andocken könnten.
Auf den geprüften Routern (Cudy WR3000, ein FRITZ!Repeater 3000 und ein FRITZ!WLAN Repeater
1750E mit nur 55 MiB RAM) ist keines der Pakete installiert.

| Erweiterung | Ort | Andockstelle |
|---|---|---|
| Suricata (IDS) | eigener Linux-/Proxmox-Host mit Spiegelport, nicht auf dem Router | EVE-JSON über einen Collector als Datensatz-Art `ids.alert` |
| Zeek | eigener Host mit Spiegelport | Zeek-JSON-Logs über einen Collector |
| NetFlow/IPFIX | Exporter evtl. auf dem Router, Kollektor auf einem Host | verdichtete Flow-Daten für Zielports und Verbindungsraten je Gerät |
| banIP | Router, nur kleine Listen | banIP-Logzeilen über Syslog; später ein Status-Abruf |
| CrowdSec | Agent auf einem Host, liest Syslog | Alarme über einen Collector |
| AdGuard Home | eigener Host (auf dem Router knapp, auf dem 1750E praktisch ausgeschlossen) | Query-Log/Statistik, ersetzt DNS-Abfrage-Logs ohne Verdrängung im Router-Ring |
| Unbound | besser auf einem Host | `unbound-control stats` |
| Lokale KI-Analyse | eigener Host, nur lokal, keine Daten in die Cloud | liest die Security-Routen; schreibt nichts zurück |

Ob die Pakete im OpenWrt-Feed verfügbar sind und was sie kosten, wurde nicht geprüft.
