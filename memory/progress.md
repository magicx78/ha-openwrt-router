# Progress — ha-openwrt-router

## Letzter Stand: 2026-03-20 (v1.0.8 abgeschlossen — Update Management Feature Ready)

---

## Router-Info
- **Modell:** Cudy WR3000 v1
- **Hostname:** secureap-gateway
- **Host:** 10.10.10.1:80
- **SSIDs (phy0, 2.4GHz):** secure-IoT, Guest-WLAN, WWW.PC2HELP.DE, Tenant-Klee
- **SSIDs (phy1, 5GHz):** <--_-->, secure-IoT

---

## Erledigte Major Tasks

### ✅ TASK-01: Per-SSID WiFi Switches mit SSID-Namen
**Status:** DONE
- `switch.py`: 1 Switch pro SSID, zeigt SSID-Namen statt Device-Hostname
- Entity IDs: `switch.secureap_gateway_secure_iot`, `switch.secureap_gateway_guest_wlan`, etc.

### ✅ TASK-02: Alte band-basierte Orphaned Switches entfernen
**Status:** DONE — 3 alte Switches gelöscht
- ✓ `switch.openwrt_dev` (wifi_24ghz)
- ✓ `switch.secureap_gateway` (wifi_5ghz)
- ✓ `switch.secureap_gateway_2` (guest_wifi)

### ✅ TASK-03: WiFi Switch Display Namen korrigieren
**Status:** DONE
- `switch.py` Zeile 82: `_attr_has_entity_name = False`
- Switches zeigen nur SSID-Namen: "secure-IoT" statt "secureap-gateway secure-IoT"

### ✅ TASK-04: WAN RX/TX Bytes aus falsch Quelle lesen
**Status:** DONE — v1.0.3 erfolgreich
- Problem: Cudy WR3000 antwortet leer auf `network.interface/dump` → Statistiken-Feld fehlte
- Lösung: Read direkt aus `/sys/class/net/{iface}/statistics/rx_bytes` und `tx_bytes`
- **Ergebnis:** 93.9 GB RX / 1.9 GB TX jetzt korrekt sichtbar (bestätigt im LuCI Screenshot)
- `api.py` Lines 280-340: `get_wan_status()` aktualisiert

### ✅ TASK-05: Sensor Display Namen korrigieren
**Status:** DONE — v1.0.4 abgeschlossen
- Problem: Alle Sensoren zeigten "sECUREaP-gATEWAy" (Device-Hostname) statt echte Namen
- `sensor.py` Zeile 228: `_attr_has_entity_name = False`
- **Ergebnis:** Sensoren zeigen jetzt "WAN Status", "CPU Load", "Memory Usage", "Connected Clients" etc.
- Entity Registry gelöscht für Rebuild — HA startet neu mit korrekten Namen

### ✅ TASK-06: GitHub Releases + HACS Setup
**Status:** DONE — Release-Workflow vollständig
- 5x GitHub Releases erstellt (v1.0.0 - v1.0.4) mit Release-Notes
- manifest.json + hacs.json aktualisiert und validiert
- HACS_REGISTRATION.md dokumentiert (Anleitung für Default Store PR)
- HACS-Validierung bestanden ✅

### ✅ TASK-07: WiFi Switch UX Enhancement
**Status:** DONE — v1.0.5 abgeschlossen
- Feature: Switch-Namen mit Band-Info ergänzt
  - Vorher: "secure-IoT" → Nachher: "secure-IoT (2.4 GHz)"
  - Band automatisch aus wifi_interfaces ermittelt
- Feature: Connected-Client-Count hinzugefügt
  - Neue extra_state_attribute: "connected_clients"
  - Zählt Clients pro SSID aus coordinator.data.clients
- `switch.py` erweitert um:
  - `_format_band()`: Konvertiert Band-Code zu lesbar (2.4 GHz, 5 GHz, etc.)
  - `_count_clients_for_ssid()`: Zählt Clients für SSID
- Commit: 82e4395, GitHub Release v1.0.5 erstellt

### ✅ TASK-08: Sensor Visibility Verbesserung
**Status:** DONE — v1.0.6 abgeschlossen
- Problem: Sensoren waren unter "Diagnose" versteckt, nicht sichtbar in "Sensoren"
- Lösung: `entity_category=EntityCategory.DIAGNOSTIC` entfernt
  - Uptime: jetzt sichtbar ✅
  - Memory Free: jetzt sichtbar ✅
  - WAN IP: jetzt sichtbar ✅
  - Firmware: jetzt sichtbar ✅
- Result: Alle Sensoren erscheinen in Home Assistant Sensors Tab
- Commit: 4a3efb7, GitHub Release v1.0.6 erstellt

### ✅ TASK-09: SSL/HTTPS Support
**Status:** DONE — v1.0.7 abgeschlossen
- Feature: Sichere HTTPS-Verbindungen zu OpenWrt Routern
  - Config Flow mit Protocol Dropdown: HTTP, HTTPS, HTTPS Self-Signed
  - Automatische Port-Anpassung (80 für HTTP, 443 für HTTPS)
  - Self-signed Certificate Support für private/Lab-Netzwerke
  - Proper SSL Context mit Certificate Validation für Production
  - Token-Übertragung geschützt wenn HTTPS aktiviert
- `api.py`: SSL Context Handling und HTTPS URL-Konstruktion
- `config_flow.py`: Multi-Step Protocol-Auswahl
- Commit: Vollständig implementiert, GitHub Release v1.0.7 erstellt

### ✅ TASK-10: Update Management Feature
**Status:** DONE — v1.0.8 abgeschlossen ✨
- Feature: Komplett System/Addon Package Update Management
- **[UPDATE-01] api.py**: Core Update API
  - `get_available_updates()`: Scannt verfügbare System- und Addon-Pakete
  - `perform_update(update_type)`: Triggert Updates (system/addons/both)
  - Automatische Kategorisierung nach Package-Namen
- **[UPDATE-02] const.py**: Update-Konstanten
  - SUFFIX_UPDATE_STATUS, SUFFIX_UPDATES_AVAILABLE
  - SUFFIX_CHECK_UPDATES, SUFFIX_PERFORM_UPDATES
  - KEY_UPDATES_AVAILABLE für Coordinator
- **[UPDATE-03] button.py**: Benutzer-Buttons
  - "Check for Updates" Button: Scannt für verfügbare Pakete
  - "Perform Updates" Button: Startet Update-Prozess
  - Proper Logging und Error Handling
- **[UPDATE-04] sensor.py**: Update Status Display
  - "Update Status" Sensor: zeigt "available" oder "current"
  - Attributes: system_updates_count, addon_updates_count
  - Package-Listen für detaillierte Inspektion
- **[UPDATE-05] coordinator.py**: Daten-Management
  - updates_available Field zu OpenWrtCoordinatorData
  - Initialisiert mit leerer Update-Liste
  - Wird über Polls weitergeleitet
- **[UPDATE-06] strings.json**: UI Übersetzungen
  - Button Namen und Beschreibungen
  - Sensor Namen und Labels
- **[UPDATE-07] manifest.json**: Version zu 1.0.8
- **[UPDATE-08] CHANGELOG.md**: Release Notes
- Commit: 8358bd5, GitHub Tag v1.0.8 erstellt
- Status: **Bereit für HACS Default Store PR**

---

## Version-Releases

| Version | Date | Feature / Fix |
|---------|------|----------|
| **1.0.8** | 2026-03-20 | **Update Management**: Check and perform system/addon package updates |
| **1.0.7** | 2026-03-20 | **SSL/HTTPS**: Secure connections, config flow with protocol dropdown |
| **1.0.6** | 2026-03-20 | **Sensor Visibility**: Alle Sensoren sichtbar unter "Sensoren", nicht unter "Diagnose" |
| **1.0.5** | 2026-03-20 | **UX Enhancement**: WiFi Switches zeigen Band-Info + Client-Count |
| **1.0.4** | 2026-03-19 | Sensor Display Names: Zeigen jetzt echte Namen statt Device-Hostname |
| **1.0.3** | 2026-03-19 | WAN RX/TX Bytes: Jetzt aus `/sys/class/net/` Kernel FS statt leerer API Response |
| **1.0.2** | 2026-03-19 | WAN Stats: Show "unavailable" statt "0 B" wenn Router keine Stats hat |
| **1.0.1** | 2026-03-19 | Entity Display Names: WiFi Switches zeigen nur SSID-Namen |
| **1.0.0** | 2026-03-11 | Initial Release: Switches, Sensors, Device Tracker, Button |

---

## HACS Status

- [x] `hacs.json` vorhanden
- [x] `custom_components/openwrt_router/` korrekte Struktur
- [x] `README.md` vorhanden und aktualisiert mit v1.0.8
- [x] `brand/icon.png` vorhanden (256×256px)
- [x] GitHub Tags für alle Releases erstellt (v1.0.0-v1.0.8)
- [x] CHANGELOG.md vollständig dokumentiert
- [x] manifest.json mit `issue_tracker` Key und v1.0.8
- [x] v1.0.8 Implementation: Update Management Feature
- [x] GitHub Release v1.0.8 erstellt
- [x] HACS Default Store PR #6421 eingereicht
- [x] Dokumentation aktualisiert (README.md, HACS_REGISTRATION.md)
- ⏳ **Nächster Schritt:** Auf HACS Maintainer Review warten (typisch 1-7 Tage)

---

## Bekannte Probleme — GELÖST ✅

1. ❌ **Sensor "Device Hostname" statt echte Namen** → ✅ GELÖST v1.0.4
2. ❌ **WAN Download/Upload "Unavailable"** → ✅ GELÖST v1.0.3
3. ❌ **WiFi Switch Namen zeigen Device-Hostname** → ✅ GELÖST v1.0.1
4. ❌ **Keine Secure HTTPS Connection möglich** → ✅ GELÖST v1.0.7
5. ❌ **Keine Update-Management Features** → ✅ GELÖST v1.0.8

---

## Geplante Features (TODO)

- [ ] Bandwidth Sensoren (RX/TX bytes pro Interface)
- [ ] Traffic Statistiken (in/out per port)
- [ ] DHCP Lease Enrichment (Client-IPs in Device Tracker)
- [ ] Per-Client Online-Zeit
- [ ] Link Quality Metriken (Signal/Noise)
- [ ] Parental Control API

---

## Next Steps

Projekt ist aktuell **IN REVIEW** auf v1.0.8:
- ✅ Update Management Feature vollständig implementiert
- ✅ Alle Komponenten getestet und validiert
- ✅ Code committed, Releases getaggt
- ✅ GitHub Release v1.0.8 publiziert
- ✅ HACS Default Store PR #6421 eingereicht
- ✅ Dokumentation komplett aktualisiert (README, HACS_REGISTRATION)

**Aktuell warten auf:**
1. ⏳ HACS Maintainer Review (PR #6421) — typisch 1-7 Tage
2. Sobald genehmigt → Nutzer können direkt über Default Store installieren
3. Community-Feedback und Feature-Requests über GitHub Issues

