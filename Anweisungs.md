# Anweisungs.md

## Ziel

Diese Anleitung definiert einen **aussagekräftigen Test- und Analyseprozess** für eine Home-Assistant-Integration, die über **HACS** verteilt wird. Ziel ist nicht, möglichst viele grüne Häkchen zu produzieren, sondern Fehler, Seiteneffekte, Regressions und unklare Zustände früh zu finden und reproduzierbar zu beheben.

---

## Was ein guter Test hier leisten muss

Ein Test ist nur dann wertvoll, wenn er mindestens eines davon absichert:

1. **Funktionalität**: Das Feature arbeitet wie erwartet.
2. **Fehlerverhalten**: Timeouts, Auth-Fehler, leere Antworten, kaputte Payloads und Offline-Zustände brechen die Integration nicht chaotisch auseinander.
3. **Regression-Schutz**: Ein bereits gelöstes Problem kommt nicht still wieder zurück.
4. **Home-Assistant-Konformität**: Setup, Config Flow, Entity Lifecycle, Coordinator-Updates, Unique IDs, Device Registry und Unload/Reload folgen den HA-Mustern.
5. **HACS-/Release-Tauglichkeit**: Struktur, Metadaten, Versionierung und Installierbarkeit sind konsistent.

---

## Teststrategie in vier Stufen

### 1. Statische Prüfungen

Diese Checks laufen **bei jedem Commit**:

* `ruff check .`
* `ruff format --check .`
* `python -m compileall custom_components`
* `pytest -q`

Zusätzlich sinnvoll:

* Prüfung auf tote Imports und ungenutzte Variablen
* Prüfung, ob `manifest.json`, `hacs.json`, `README.md`, `CHANGELOG.md` und `version` konsistent sind
* Prüfung, ob neue Entities eine stabile `unique_id` haben

**Ziel:** Syntaxfehler, API-Missbrauch, Stilbrüche und offensichtliche Regressionen sofort stoppen.

---

### 2. Unit-Tests mit gezielten Mocks

Unit-Tests sollen die Integrationslogik **ohne echtes Gerät** prüfen. Nicht das Netzwerk, sondern euer Code steht vor Gericht.

#### Mindestens abdecken

* Erfolgreiches `async_setup_entry`
* Fehlerhaftes `async_setup_entry`
  * Login schlägt fehl
  * Gerät nicht erreichbar
  * Unerwartete API-Antwort
* `async_unload_entry`
* `async_reload_entry`
* Config Flow
  * gültige Zugangsdaten
  * ungültige Zugangsdaten
  * Timeout
  * Double-setup / bereits konfigurierte Instanz
* Options Flow
* Coordinator-Refresh
  * erfolgreiche Aktualisierung
  * teilweise fehlende Felder
  * kompletter Ausfall
* Entity-Erzeugung
  * richtige Anzahl
  * richtige Namen
  * richtige `unique_id`
  * richtige `device_info`
  * richtige `available`-Logik
* Sensor-Werte bei Null, `None`, `unknown`, leerer Liste, fehlendem Key
* Bandbreiten-/Traffic-Sensoren
  * Interface vorhanden
  * Interface fehlt
  * Interface liefert leere Werte
  * WAN down / logisch nicht vorhanden
* Regressionsfälle aus echten Bugs als eigene Tests

#### Regel

Für **jeden behobenen Bug** wird zuerst ein fehlschlagender Test geschrieben oder ergänzt. Dann erst kommt der Fix. Sonst ist es nur Hoffen in schöner Verpackung.

---

### 3. Integrationsnahe Tests mit Home-Assistant-Testumgebung

Hier wird die Integration innerhalb der HA-Testumgebung geprüft, also näher an der Realität.

#### Abdecken

* Plattformen werden korrekt geladen
* Entities landen sauber im State Machine von HA
* Device Registry und Entity Registry sind stabil
* Neustart der Integration erzeugt **keine Duplikate**
* Entfernen und erneutes Hinzufügen funktioniert sauber
* Diagnostikdaten und Logs sind verwertbar, aber enthalten keine Secrets
* Fehler führen zu sinnvollen Log-Meldungen, nicht zu Traceback-Spam

#### Besonders wichtig

* Test, dass bei API-Ausfall alte States nicht sinnlos überschrieben werden
* Test, dass `available` korrekt zwischen online/offline wechselt
* Test, dass fehlende optionale Router-Felder nicht die ganze Integration zerlegen

---

### 4. Manuelle End-to-End-Prüfung vor Release

Vor jedem Release einmal gegen ein echtes oder reproduzierbar simuliertes Zielsystem prüfen.

#### Checkliste

* Frische Installation über HACS
* Neustart von Home Assistant
* Integration hinzufügen über UI
* Zugangsdaten testen
* Alle erwarteten Entities erscheinen
* Werte ändern sich plausibel bei Traffic / Verbindungswechsel / Reconnect
* Reload aus HA funktioniert
* Remove + Re-Add funktioniert
* Logs bleiben sauber
* HACS zeigt korrekte Version
* Release Notes passen zur tatsächlich ausgelieferten Version

---

## Pflicht-Testfälle für buganfällige Bereiche

### A. Netzwerk und Router-Antworten

* Router offline
* Router antwortet langsam
* Router liefert HTTP 200 mit kaputter JSON
* Router liefert JSON ohne erwartete Keys
* Router liefert Werte als String statt Zahl
* Router liefert negative oder unrealistische Zählerstände
* Interface ist nicht vorhanden
* Interface ist vorhanden, aber `down`
* WAN ohne logischen Namen
* IPv6-Interface separat vorhanden

### B. Entity-Stabilität

* `unique_id` ändert sich nicht zwischen Releases
* Umbenennung von Friendly Names zerstört keine Registry-Zuordnung
* Neue Sensoren ergänzen bestehende Geräte sauber
* Entfernte Sensoren hinterlassen keine Geisterzustände

### C. Lifecycle

* mehrfaches Setup derselben Config Entry
* Reload nach Options-Änderung
* Unload bei temporär kaputtem Coordinator
* HA-Neustart mit bereits vorhandener Config Entry

### D. Fehlerbilder aus der Praxis

* WAN down erzeugt `unknown` statt Absturz
* Interface-Zähler fehlen und Sensor wird trotzdem erstellt
* UCI-/ubus-Datenformat unterscheidet sich je nach Router-Modell
* Speicher-/Disk-Werte kommen als `0.0`, obwohl Feld fehlt

---

## Testdaten: so bauen

Lege feste Fixtures an für mindestens diese Router-Zustände:

1. **Healthy Router** — alles vorhanden, WAN online, WLAN aktiv
2. **WAN Down** — kein logischer WAN-Name, Status `disconnected`, IPv6 optional
3. **Minimal Router** — reduzierte API-Antwort, optionale Felder fehlen
4. **Broken Payload** — falsche Typen, fehlende Keys, leere Listen
5. **High-Traffic Router** — große Counter-Werte, schnelle Updates

Diese Fixtures gehören versioniert ins Repo, damit Fehler reproduzierbar bleiben.

---

## Definition eines guten Fixes

Ein Fix ist erst fertig, wenn alle fünf Punkte erfüllt sind:

1. Ursache verstanden und dokumentiert
2. Fehlverhalten mit Test reproduziert
3. Fix minimal und gezielt implementiert
4. Regressionstest grün
5. Kein Seiteneffekt in Setup, Entities oder Coordinator

### Mini-Schema für Bugfixes

```
Bug beobachten
→ Ursache eingrenzen
→ fehlschlagenden Test schreiben
→ Fix implementieren
→ gesamten Testlauf ausführen
→ Release Notes + progress.md aktualisieren
```

---

## Empfohlene Projektstruktur für Tests

```
tests/
  conftest.py
  test_init.py
  test_config_flow.py
  test_options_flow.py
  test_coordinator.py
  test_sensor.py
  test_device_tracker.py
  test_diagnostics.py
  test_regressions.py
  fixtures/
    router_healthy.json
    router_wan_down.json
    router_minimal.json
    router_broken.json
    router_high_traffic.json
```

---

## Konkrete Qualitätsregeln für die Integration

### Logging

* Keine Zugangsdaten im Log
* Keine Endlos-Warnungen bei erwartbaren Zuständen
* Ein echter Fehler bekommt eine klare Meldung mit Kontext
* Debug-Logs dürfen Diagnose liefern, aber nicht fluten

### Sensoren

* Fehlende Rohdaten führen zu `unknown` oder `unavailable`, nicht zu Exceptions
* Zählerwerte müssen robust gegen `None`, String und fehlende Keys sein
* Sensoren für optionale Interfaces dürfen erstellt werden, wenn sinnvoll, aber ohne harte Annahmen

### Coordinator

* API-Fehler sauber abfangen
* Vorherige valide Daten nicht blind mit Müll überschreiben
* Update-Intervalle nicht unnötig aggressiv wählen
