# Auftrag des Nutzers (2026-11-20), unverändert im Inhalt · umgesetzt in 1.49.0

## Status

- **Stand:** 2026-11-21 · **Phase:** A–L gebaut (Bestandsaufnahme, Modell, Sammlung, Verlauf, Auffälligkeiten, Kapazität, Flows, Collector, Routen, Panel-Tab mit Einstellungen, Sensoren, Leistungs- und Qualitätstests), Version 1.49.0 im Branch, noch nicht veröffentlicht
- **Branch/PR:** `claude/traffic-analytics-d7ae50` · noch kein PR (öffnet der Master)
- **Erledigt:** alle Phasen aus dem Bauplan; Schalter je Router in den Integrationsoptionen, Profile `compact` (Standard) und `standard` mit stündlichen Werten für 14 Tage; Collector-Eingang `traffic.collector.v1` (nur Flows, alles oder nichts, nur HTTPS, eigener Nicht-Admin-Benutzer); Einstellungsformular im Tab mit Route `GET collector/users` (Benutzer nur als `usr_…`); Nutzerdoku `docs/traffic-analytics.md`. Nachweis nur durch automatische Tests ohne Geräte (Backend-Suite auf Python 3.13 und 3.14, Frontend-Logik- und Render-Tests, Leistungstests mit gemessenen Zahlen in der Nutzerdoku §7)
- **Abweichungen:** der Schalter liegt im Optionsdialog, `config_flow.py` ist dafür geändert (Bauplan §1.5 und §12.9 sahen das nicht vor); Collector-Aggregate (`client_aggregate`, `interface_aggregate`) werden mit `kind_not_supported` abgelehnt; Auffälligkeiten gehen als Kern-Ereignisse hinaus, nicht als NI-Vorfälle (W1 fehlt); Security Center wertet die Hinweise nicht aus (W2 fehlt)
- **Nicht getan:** nichts am echten Router oder in einer echten Home-Assistant-Instanz geprüft (Bauplan §12 Risiken 1, 2 und 11 offen); Tab nicht im Browser angesehen, auch nicht bei 360 px Breite; Wünsche W1–W8 an andere Module; conntrack-Ersatzweg in `api.get_active_connections` ohne Obergrenze (Risiko 3, Frage F2) unverändert
- **Blocker:** keine
- **Nächster Schritt:** PR für 1.49.0 prüfen und öffnen (Master); danach lesende Prüfung am Gerät (nur mit Freigabe) und Ansicht des Tabs bei 360 px; Wünsche W1–W8 mit den Modulen klären

Claude Code – Phase 5: Enterprise Advanced Traffic Analytics & Network Flow Intelligence
Repository: https://github.com/magicx78/ha-openwrt-router
Projekt: OpenWrt Enterprise Network Management
Modul: Advanced Traffic Analytics, Flow Intelligence & Network Capacity Planning
Priorität: P1
Zielumgebung: Home Assistant, OpenWrt, vier Cudy WR3000, Multi-AP, VLANs, zahlreiche IoT-/ESPHome-Geräte und weitere Netzwerkclients

## 1. Projektziel
Implementiere eine professionelle, zentrale Netzwerkverkehrsanalyse innerhalb der bestehenden Home-Assistant-Integration.
Orientiere dich funktional an UniFi Network, Aruba Central, ntopng, NetFlow-Analyzern und Enterprise-Network-Observability-Systemen.
Das Modul soll den Netzwerkverkehr nicht nur als einfache RX-/TX-Zähler darstellen, sondern zuverlässig analysieren, historisieren, korrelieren und verständlich visualisieren.

Kernfunktionen
* Bandbreitenüberwachung pro Router
* Traffic-Analyse pro Interface und Port
* Netzwerkverkehr pro Client
* Traffic-Verteilung nach VLAN
* Top-Talker-Erkennung
* Historische Bandbreitenanalyse
* Flow-Analyse, soweit geeignete Datenquellen verfügbar sind
* Kommunikationsbeziehungen zwischen Netzwerkgeräten
* Erkennung ungewöhnlicher Traffic-Spitzen
* Erkennung langfristiger Veränderungen
* Traffic- und Bandbreitenprognosen
* Kapazitätsplanung
* Korrelation mit Netzwerkstörungen
* Integration in Security Intelligence
* Zentrale Visualisierung im Enterprise-Dashboard

Die Implementierung muss lokal, modular, datensparsam und ressourcenschonend funktionieren.
Keine kostenpflichtigen Cloud-Dienste und keine externen KI-Modelle erforderlich.

## 2. Verpflichtende Repository-Bestandsanalyse
Analysiere zunächst das vollständige Repository.
Berücksichtige:
* CLAUDE.md und sämtliche Projektanweisungen
* OpenWrtAPI
* OpenWrtCoordinator
* RuntimeData
* Unified Router Identity
* Router Registry
* Capability Detection
* Enterprise Configuration Manager
* Network Intelligence
* Security Intelligence
* Active Network Diagnostics
* WiFi RF Intelligence
* Client Stability Intelligence
* Incident Correlation Engine
* Bestehende Interface- und Traffic-Sensoren
* Topologie-Panel
* Bestehende historische Daten
* Vorhandene APIs und Tests

Prüfe, welche Traffic-Metriken bereits verfügbar sind.
Nutze existierende Datensammler, Identitäten, Events und Persistenzmechanismen.
Keine zweite Router Registry, keine parallele Client-Datenbank und keine unnötigen zusätzlichen SSH-Prozesse entwickeln.
Fehlende vorgelagerte Enterprise-Module müssen als optionale Abhängigkeiten behandelt werden, sofern dies mit der vorhandenen Architektur möglich ist.

## 3. Traffic Data Collection Layer
Entwickle beziehungsweise erweitere eine zentrale Datenerfassung für Netzwerkverkehr.
Prüfe folgende OpenWrt-Datenquellen:
* ubus
* netifd
* `/sys/class/net/*/statistics`
* `/proc/net/dev`
* rtnetlink / Interface-Statistiken
* nftables Counters
* conntrack
* hostapd- und WLAN-Station-Statistiken
* Bridge-/Switch-Port-Statistiken
* Optional NetFlow/IPFIX
* Optional unterstützte eBPF-Mechanismen

Erfasse, soweit verfügbar:
* Router-ID
* Interface-ID
* Port-ID
* VLAN-ID
* Client-ID
* Zeitstempel
* RX-Bytes
* TX-Bytes
* RX-/TX-Pakete
* RX-/TX-Drops
* RX-/TX-Errors
* Link-Geschwindigkeit
* Datenquelle
* Messintervall
* Datenqualität

Zählerverarbeitung
Berechne Datenraten aus tatsächlichen Counter-Deltas.
Berücksichtige:
* Counter-Reset
* Counter-Überlauf
* Router-Neustart
* Interface-Neustart
* Fehlende Messpunkte
* Zeitabweichungen
* Unterschiedliche Abfrageintervalle
* Geänderte Interface-Zuordnungen

Keine negativen oder unrealistischen Datenraten durch ungültige Counter-Deltas erzeugen.
Verwende monotone Zeitmessung für Intervalle, soweit technisch möglich.

## 4. Traffic Accounting & Datenkorrektheit
Dies ist ein besonders wichtiger Bestandteil.
Entwickle ein nachvollziehbares Traffic-Accounting-Modell.
Unterscheide ausdrücklich:
1. Interface-Traffic
2. Port-Traffic
3. WLAN-Station-Traffic
4. Client-attribuierten Traffic
5. VLAN-attribuierten Traffic
6. Flow-basierten Traffic
7. WAN-Traffic

Diese Messbereiche dürfen nicht unkontrolliert addiert werden.

Vermeidung falscher Traffic-Daten
Berücksichtige:
* NAT
* Hardware Flow Offloading
* Software Flow Offloading
* Bridge-Verkehr
* Mehrfach beobachtete Pakete
* Inter-VLAN-Routing
* WLAN-Roaming
* Unterschiedliche Messpunkte
* Nicht erfassten lokalen Verkehr
* Unvollständige Client-Zuordnung

Ein Client-Wert darf nicht als vollständiger Internetverbrauch bezeichnet werden, wenn lediglich WLAN-Station-Counter verfügbar sind.
Kennzeichne die Messabdeckung transparent.
Definiere eine eindeutige Semantik für RX/TX aus Sicht des jeweiligen Messpunkts.
Implementiere Plausibilitätsprüfungen und dokumentiere Grenzen der Messgenauigkeit.

## 5. Client Traffic Intelligence
Implementiere eine historische Verkehrsübersicht pro Netzwerkgerät.
Soweit die Datenlage es erlaubt:
* Aktuelle Downloadrate
* Aktuelle Uploadrate
* Empfangene Datenmenge
* Gesendete Datenmenge
* Traffic innerhalb der letzten Stunde
* Traffic innerhalb von 24 Stunden
* Traffic innerhalb von 7 Tagen
* Traffic innerhalb von 30 Tagen
* Durchschnittliche Datenrate
* Maximale beobachtete Datenrate
* Aktueller Router beziehungsweise AP
* Zugehöriges VLAN
* Netzwerkaktivität im Zeitverlauf

Nutze die bestehende Client Registry.
Berücksichtige mobile Geräte, wechselnde IP-Adressen, MAC-Randomisierung und WLAN-Roaming.
Eine wechselnde IP darf nicht automatisch zu einer neuen Client-Identität führen.
Führe Geräte bei unklarer Identität nicht automatisch zusammen.

Client-Detailansicht
Ergänze historische Traffic-Grafiken und die zugehörigen Messinformationen.

## 6. Top Talkers & Heavy Hitters
Implementiere eine zentrale Top-Talker-Analyse.
Ermittle:
* Geräte mit höchstem beobachtetem Traffic
* Clients mit höchster aktueller Bandbreite
* Auffällige Upload-Verbraucher
* Auffällige Download-Verbraucher
* Interfaces mit höchster Auslastung
* VLANs mit hohem Traffic
* Wiederkehrende Traffic-Spitzen

Unterstütze verschiedene Zeiträume:
* 5 Minuten
* 1 Stunde
* 24 Stunden
* 7 Tage
* 30 Tage

Zeige die Anzahl beobachteter Bytes und den jeweiligen Messbereich.
Verhindere, dass ein Client, der über mehrere Access Points erfasst wird, aufgrund überschneidender Beobachtungen doppelt gezählt wird.
Bei unvollständiger Erfassung muss die Auswertung ausdrücklich als partiell gekennzeichnet werden.

## 7. VLAN Traffic Analytics
Erstelle eine Verkehrsübersicht je VLAN.
Analysiere:
* Beobachtete Datenmengen
* Aktuelle Bandbreite
* Historische Auslastung
* Anzahl aktiver Clients
* Top-Talker innerhalb des VLANs
* Inter-VLAN-Traffic, sofern messbar
* WAN-bezogenen VLAN-Traffic, sofern zuverlässig zuordenbar
* Auffällige Veränderungen

Unterscheide konfigurierte VLAN-Zugehörigkeit von tatsächlich gemessener VLAN-Verkehrszuordnung.
Verwende vorhandene Topologie- und Konfigurationsdaten.
Keine rechnerisch erfundenen VLAN-Gesamtwerte.

## 8. Network Flow Intelligence
Implementiere eine optionale Flow-Analyse.
Prüfe geeignete Datenquellen:
* conntrack
* nftables
* NetFlow
* IPFIX
* Externe Flow Collector
* Optional unterstützte eBPF-Technologien

Erfasse bei verfügbarer Datenquelle:
* Quelladresse
* Zieladresse
* Quellport
* Zielport
* Transportprotokoll
* Beginn und Ende, soweit bekannt
* Übertragene Bytes und Pakete, soweit messbar
* Zugehöriger Router
* Zugehöriger Client
* Zugehöriges VLAN
* Flow-Richtung
* Mess- beziehungsweise Exportquelle

Besondere Anforderungen
Conntrack-Snapshots sind keine vollständige Flow-Historie.
Hardware-Offloading kann die Messbarkeit beeinflussen.
NAT kann Quell- und Zielzuordnungen verändern.
Nicht sichtbare Verbindungen dürfen nicht als nicht vorhanden interpretiert werden.
Unterscheide:
* Beobachteten Flow
* Aggregierte Verbindung
* Geschätzte Verkehrskategorie
* Unbekannte Zuordnung

Implementiere klare Datenqualitätskennzeichnungen.

Datenschutz
Speichere Flow-Metadaten nur im notwendigen Umfang.
Unterstütze konfigurierbare Aufbewahrung und optional anonymisierte Langzeitstatistiken.
Keine automatische Speicherung vollständiger Paketdaten.

## 9. Application & Protocol Visibility
Implementiere eine vorsichtige Klassifikation des Netzwerkverkehrs.
Nutze verfügbare Metadaten wie:
* Protokoll
* Ports
* Verbindungsrichtung
* DNS-Zuordnungen, soweit zulässig und verfügbar
* Optional externe Klassifikationsdaten

Unterscheide beispielsweise:
* DNS
* NTP
* HTTP/HTTPS
* MQTT
* SSH
* RTSP
* Andere bekannte Protokolle
* Unbekannt

Wichtig:
Eine Portnummer beweist nicht, welche Anwendung den Verkehr erzeugt.
TLS-verschlüsselter Datenverkehr darf nicht ohne geeignete Grundlage einer bestimmten Anwendung zugeordnet werden.
Kennzeichne heuristische Klassifikationen und deren Genauigkeit.
Keine TLS-Entschlüsselung oder Deep Packet Inspection als Voraussetzung.

## 10. Traffic Anomaly Detection
Erweitere die bestehende Anomaly Detection Engine.
Erkenne unter anderem:
* Ungewöhnliche Upload-Spitzen
* Ungewöhnliche Download-Spitzen
* Stark erhöhte Verbindungsraten
* Dauerhafte hohe Auslastung
* Plötzliche Traffic-Rückgänge
* Veränderte Kommunikationsmuster
* Auffällige nächtliche Aktivität
* Ungewöhnlich hohe Inter-VLAN-Kommunikation
* Wiederholte kurzfristige Bursts
* Ungewöhnliche Datenmengen einzelner IoT-Geräte

Verwende historische Baselines und statistische Verfahren.
Berücksichtige Gerätetypen und reguläre Verhaltensmuster.
Ein Kamera-Stream darf nicht automatisch als verdächtiger hoher Datenverkehr gewertet werden.
Softwareupdates, Backups und regelmäßige Synchronisationen müssen bei der Bewertung berücksichtigt werden.
Erzeuge keine unkontrollierten Alarmfluten.

## 11. Network Capacity Planning
Implementiere eine langfristige Auslastungsanalyse.
Ermittle:
* Durchschnittliche Interface-Auslastung
* Spitzenlast
* 95. Perzentil der gemessenen Datenrate
* Historische Auslastungsentwicklung
* Wiederkehrende Engpässe
* Annäherung an physische Link-Kapazitäten
* Mögliche Uplink-Bottlenecks
* VLAN-bezogene Lastentwicklung
* Kapazitätstrends

Berücksichtige die tatsächliche Linkgeschwindigkeit und Duplex-Informationen, soweit verfügbar.
Entwickle vorsichtige Trendprognosen auf Basis ausreichend langer Messreihen.
Prognosen müssen als Schätzungen gekennzeichnet werden.
Bei zu geringer Datenbasis darf keine belastbare Vorhersage behauptet werden.

## 12. Traffic Quality & Congestion Intelligence
Kombiniere Traffic-Metriken mit Active Network Diagnostics und WiFi RF Intelligence.
Erkenne mögliche Zusammenhänge zwischen:
* Hoher Interface-Auslastung
* Erhöhtem Paketverlust
* Steigender Latenz
* Hoher WLAN-Airtime
* Erhöhten Retransmissions
* WAN-Engpässen
* Interface-Drops
* Verbindungsausfällen

Beispiel:
WARNUNG: Möglicher WAN-Uplink-Engpass
Router: Cudy-01
Beobachtung:
* WAN-Auslastung dauerhaft hoch
* Gleichzeitig erhöhte Latenz
* Wiederkehrende Paketverluste

Bewertung:
Möglicher Kapazitätsengpass oder Queueing-Problem.
Empfehlung:
WAN-Kapazität, SQM-Konfiguration und zusätzliche Messpunkte prüfen.
Behaupte keinen bestätigten Engpass allein aufgrund hoher Bandbreitennutzung.

## 13. Integration mit Security Intelligence
Verbinde Traffic Analytics mit der bestehenden Security Engine.
Ermögliche die Nutzung folgender Indikatoren:
* Auffällige ausgehende Verbindungen
* Ungewöhnliche Traffic-Mengen
* Neue Kommunikationsziele
* Veränderte Protokollverteilung
* Ungewöhnliche Inter-VLAN-Kommunikation
* Verdächtige Verbindungsraten

Sicherheitsvorfälle sollen die entsprechenden Traffic-Messungen als technische Nachweise referenzieren können.
Keine zweite Anomalie- oder Incident Engine entwickeln.
Traffic-Anomalien sind nicht automatisch Sicherheitsangriffe.

## 14. Historical Traffic Intelligence
Implementiere eine effiziente Historisierung.
Zeiträume:
* 1 Stunde
* 24 Stunden
* 7 Tage
* 30 Tage
* Optional 90 Tage

Verwende passende zeitliche Aggregation.
Speichere:
* Zeitfenster
* Messpunkt
* Empfangene Bytes
* Gesendete Bytes
* Durchschnittliche Datenrate
* Spitzenwerte
* Messabdeckung
* Datenquelle

Implementiere:
* Begrenzte Rohdatenhaltung
* Verdichtung älterer Messwerte
* Daten-Retention
* Effiziente Abfragen
* Schutz vor unbegrenztem Speicherwachstum
* Wiederherstellung nach HA-Neustart
* Robuste Behandlung von Messlücken

Verwende vorhandene Persistenzmechanismen oder begründe technisch eine ergänzende Speicherung.

## 15. Enterprise Traffic Analytics Dashboard
Erweitere das vorhandene Dashboard um:
Enterprise → Traffic Analytics

Network Traffic Overview
Zeige:
* Gesamter beobachteter Traffic
* Aktueller WAN-Durchsatz
* Top-Talker
* Aktive Traffic-Anomalien
* Auslastung wichtiger Interfaces
* Traffic nach VLAN
* Verfügbare Flow-Datenquellen
* Monitoring Coverage

Traffic Timeline
Interaktive Grafik für:
* RX/TX
* Download/Upload
* Zeiträume
* Router
* Interfaces
* VLANs
* Clients

Top Talkers
Sortierbare Tabelle mit:
* Gerät
* Router/AP
* VLAN
* Empfangene Bytes
* Gesendete Bytes
* Aktuelle Bandbreite
* Traffic-Anteil, sofern mathematisch sinnvoll
* Letzte Aktivität

Flow Explorer
Wenn geeignete Flow-Daten vorhanden sind:
* Quelle
* Ziel
* Protokoll
* Port
* Bytes
* Zeitraum
* Zugehöriger Client
* Zugehöriges VLAN

Mit Filtern und begrenzter Ergebnismenge.

Capacity Overview
Zeige:
* Interface-Auslastung
* Durchschnittliche Auslastung
* Spitzenlast
* 95. Perzentil
* Mögliche Engpässe
* Langfristige Trends

Traffic Recommendations
Stelle Empfehlungen mit Messdaten, Konfidenz und möglichen Ursachen dar.
Keine automatisch erzeugten Empfehlungen ohne belastbare Datengrundlage.

## 16. Topologieintegration
Nutze die bestehende physische Netzwerktopologie.
Erweitere sie optional um:
* Aktuelle Port-Datenraten
* Uplink-Auslastung
* Interface-Fehler
* Traffic zwischen bekannten Komponenten, soweit messbar
* Auslastungswarnungen
* Historische Traffic-Informationen

Physische Verbindungen und logische Flow-Beziehungen müssen getrennt dargestellt werden.
Keine erfundenen Links zwischen Geräten.
Eine Kommunikationsbeziehung ist nicht automatisch eine physische Verbindung.

## 17. Home-Assistant-Entitäten
Implementiere ausgewählte Sensoren.
Beispiele:
* Network WAN Download Rate
* Network WAN Upload Rate
* Network WAN Traffic Total
* Network Peak Bandwidth
* Network Active Traffic Anomalies
* Network Monitoring Coverage
* Router Interface Utilization
* Router Interface RX Errors
* Router Interface TX Errors

Nutze bestehende Device- und Entity-Registrierungen.
Verhindere unkontrollierte Entity-Erzeugung für dynamische Flows und kurzfristige Clients.
Client-spezifische Sensoren sollen optional aktivierbar sein.
Achte auf korrekte Home-Assistant-Einheiten, Device Classes und State Classes.

## 18. Performance und Ressourcenmanagement
Die vier Cudy WR3000 dürfen nicht überlastet werden.
Verbindliche Anforderungen:
* Keine aggressiven SSH-Abfragen
* Keine unbegrenzten conntrack-Dumps
* Keine vollständige Paketaufzeichnung
* Keine unkontrollierten Flow-Exports
* Begrenzte parallele Abfragen
* Adaptive Polling-Intervalle
* Result Caching
* Asynchrone Verarbeitung
* Begrenzte Datenqueues
* Backpressure
* Speicherlimits
* CPU-schonende Aggregation
* Sauberes Shutdown-Verhalten

Schwere Flow-Analysen sollen optional auf einen externen Collector ausgelagert werden können.
Die normale Home-Assistant-Integration muss ohne zusätzliche Dienste lauffähig bleiben.

## 19. Optionale externe Collector-Architektur
Bereite eine modulare Schnittstelle für externe Traffic Collector vor.
Mögliche spätere Integrationen:
* NetFlow/IPFIX Collector
* ntopng
* Externe Flow-Aggregation
* Unterstützte eBPF-Collector
* Proxmox-basierter Analytics-Service

Installiere keine zusätzlichen Dienste automatisch.
Definiere eine versionierte, dokumentierte Schnittstelle, damit externe Messsysteme normalisierte Traffic-Daten liefern können.
Berücksichtige Authentifizierung, sichere Übertragung, Datenlimits und Schema-Versionierung.

## 20. Sicherheit und Datenschutz
Traffic-Daten können sensible Nutzungsinformationen enthalten.
Implementiere:
* Authentifizierte Dashboard- und API-Zugriffe
* Autorisierungsprüfung
* Begrenzte Speicherung von Flow-Metadaten
* Keine Secrets in Logs
* Keine Speicherung von Paket-Payloads
* Optionale Anonymisierung
* Konfigurierbare Retention
* Sichere Exportfunktionen
* Schutz vor Path Traversal
* Validierung externer Collector-Daten
* Schutz gegen übergroße Payloads
* Sichere Verarbeitung von IP-/MAC-Adressen
* Keine externen Uploads ohne Freigabe

Schreibende Änderungen an Firewall, SQM, VLAN oder Routing gehören nicht zu dieser Phase.

## 21. Automatisierte Tests
Implementiere Tests für:
1. Interface-RX/TX-Erfassung
2. Berechnung von Datenraten
3. Counter-Reset
4. Counter-Überlauf
5. Router-Neustart
6. Interface-Neustart
7. Messlücken
8. Falsche oder fehlende Zeitstempel
9. NAT-bezogene Zuordnungen
10. Hardware-Offloading
11. Vermeidung doppelter Traffic-Zählung
12. Client-Traffic-Zuordnung
13. WLAN-Roaming
14. VLAN-Traffic-Zuordnung
15. Top-Talker-Ranking
16. Fehlende Flow-Daten
17. conntrack-Snapshot-Auswertung
18. Traffic-Anomalieerkennung
19. Normale Traffic-Spitzen
20. Traffic-Baselines
21. Interface-Kapazitätsbewertung
22. 95.-Perzentil-Berechnung
23. Historische Datenaggregation
24. Daten-Retention
25. Hohe Client-Anzahlen
26. Hohe Ereignislast
27. Backpressure
28. Dashboard-Datenverträge
29. Home-Assistant-Entitäten
30. Security-Intelligence-Korrelation
31. Netzwerkdiagnose-Korrelation
32. Datenschutz und Zugriffsschutz
33. Regressionen bestehender Funktionen

Alle Tests müssen ohne reale Router ausführbar sein.

## 22. Implementierungsphasen
Arbeite selbstständig in folgender Reihenfolge:
Phase A: Repository-Analyse und Data Source Capability Matrix
Phase B: Traffic Data Collection und Counter Processing
Phase C: Traffic Accounting und Datenqualitätsmodell
Phase D: Client- und VLAN-Traffic Intelligence
Phase E: Top Talkers und Flow Intelligence
Phase F: Traffic Anomaly Detection
Phase G: Network Capacity Planning
Phase H: Security- und Diagnostics-Korrelation
Phase I: Historische Traffic Analytics
Phase J: Enterprise Traffic Dashboard und Topologieintegration
Phase K: Home-Assistant-Entitäten und optionale Collector-Schnittstelle
Phase L: Performance-Tests, Dokumentation und Qualitätssicherung

Führe nach jeder Phase die relevanten Tests aus und behebe Regressionen vor dem nächsten Schritt.

## 23. Abnahmekriterien
Die Implementierung gilt als erfolgreich, wenn:
1. Netzwerkverkehr pro Router und Interface zuverlässig erfasst wird.
2. Datenraten mathematisch korrekt aus Counter-Deltas berechnet werden.
3. Client- und VLAN-Traffic nur bei ausreichender Datenlage zugeordnet wird.
4. Top-Talker nachvollziehbar identifiziert werden.
5. Flow-Daten optional und korrekt interpretiert werden.
6. Traffic-Anomalien anhand historischer Baselines erkannt werden.
7. Netzwerkengpässe durch mehrere Indikatoren eingegrenzt werden.
8. Historische Traffic-Grafiken verfügbar sind.
9. Das Dashboard die Messabdeckung transparent darstellt.
10. Die bestehende Topologie sinnvoll erweitert wird.
11. Security Intelligence und Active Network Diagnostics dieselben Messdaten verwenden können.
12. Keine doppelte Traffic-Zählung als Gesamtverbrauch ausgegeben wird.
13. Home Assistant und OpenWrt nicht unnötig belastet werden.
14. Bestehende Funktionen erhalten bleiben.
15. Alle relevanten Tests erfolgreich sind.

## 24. Abschluss und Dokumentation
Aktualisiere:
* README
* CHANGELOG
* Entwicklerdokumentation
* Traffic-Datenmodell
* Collector-Schnittstellen
* Capability-Matrix
* Datenschutzdokumentation
* Benötigte OpenWrt-Berechtigungen
* Performance- und Skalierungsgrenzen

Dokumentiere ausdrücklich den Unterschied zwischen:
* Interface-Traffic
* Client-Traffic
* VLAN-Traffic
* Flow-Traffic
* WAN-Traffic

Erstelle eine Abschlussübersicht mit allen geänderten Dateien, implementierten Funktionen, erfolgreichen Tests und bekannten Einschränkungen.
Beginne jetzt mit der vollständigen Repository-Analyse und implementiere Phase 5 anschließend produktionsreif.
Keine reine Konzeptarbeit, keine Mock-Daten in der produktiven Oberfläche, keine unnötigen Architektur-Neuschreibungen und keine unkontrollierten Routerabfragen.
Nutze konsequent die vorhandene Enterprise-Core-Architektur und integriere sämtliche neuen Funktionen in das bestehende Dashboard.
Führe keine schreibenden Änderungen auf produktiven Routern ohne ausdrückliche Freigabe durch.

---

# Technische Empfehlung des Nutzers (zweiter Teil der Nachricht)

Ich würde die Implementierung in zwei Leistungsstufen aufbauen:

Stufe A: Native OpenWrt Traffic Analytics
Läuft direkt über die bestehende Integration. Nutzt Interface-Counter, WLAN-Station-Statistiken, nftables und verfügbare conntrack-Metriken. Keine zusätzliche Hardware erforderlich.

Stufe B: Advanced Flow Analytics auf Proxmox
Optionaler Collector in einer eigenen LXC oder VM. Hier könnten später ntopng, NetFlow/IPFIX und umfangreichere historische Analysen laufen, ohne die vier Cudy WR3000 oder Home Assistant mit der Verarbeitung zu belasten.

Besonders wichtig: Hardware-Offloading kann verhindern, dass einzelne Traffic-Datenquellen den gesamten Datenverkehr sehen. Deshalb sollte Claude Code eine explizite Messabdeckung implementieren, anstatt unvollständige Daten als vollständigen Geräteverbrauch darzustellen.

Danach folgt Phase 6: Network Time Machine. Damit rekonstruieren wir historische Netzwerkzustände, Konfigurationsänderungen, Client-Verbindungen und Störungsverläufe auf einer gemeinsamen Zeitleiste.
