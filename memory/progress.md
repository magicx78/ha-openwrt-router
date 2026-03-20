# Progress — ha-openwrt-router

## Letzter Stand: 2026-03-20 (v1.0.5 abgeschlossen)

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

---

## Version-Releases

| Version | Date | Feature / Fix |
|---------|------|-------|
| **1.0.5** | 2026-03-20 | **UX Enhancement**: WiFi Switches zeigen Band-Info + Client-Count |
| **1.0.4** | 2026-03-19 | Sensor Display Names: Zeigen jetzt echte Namen statt Device-Hostname |
| **1.0.3** | 2026-03-19 | WAN RX/TX Bytes: Jetzt aus `/sys/class/net/` Kernel FS statt leerer API Response |
| **1.0.2** | 2026-03-19 | WAN Stats: Show "unavailable" statt "0 B" wenn Router keine Stats hat |
| **1.0.1** | 2026-03-19 | Entity Display Names: WiFi Switches zeigen nur SSID-Namen |
| **1.0.0** | 2026-03-11 | Initial Release: Switches, Sensors, Device Tracker, Button |

---

## Bekannte Probleme — GELÖST ✅

1. ❌ **Sensor "Device Hostname" statt echte Namen** → ✅ GELÖST v1.0.4
   - Ursache: `_attr_has_entity_name = True` in sensor.py
   - Fix: Geändert zu False, Entity Registry gelöscht

2. ❌ **WAN Download/Upload "Unavailable"** → ✅ GELÖST v1.0.3
   - Ursache: API antwortet leer auf `network.interface/dump` → statistics Feld fehlte
   - Fix: Read direkt aus `/sys/class/net/wan/statistics/`
   - Beweise: LuCI Screenshot zeigte Daten existieren (93,9 GB RX / 1,9 GB TX)

3. ❌ **WiFi Switch Namen zeigen Device-Hostname** → ✅ GELÖST v1.0.1
   - Ursache: `_attr_has_entity_name = True` in switch.py
   - Fix: Geändert zu False, alte Entries gelöscht

---

## Geplante Features (TODO)

- [ ] Bandwidth Sensoren (RX/TX bytes pro Interface)
- [ ] Traffic Statistiken (in/out per port)
- [ ] DHCP Lease Enrichment (Client-IPs in Device Tracker)
- [ ] Per-Client Online-Zeit
- [ ] Link Quality Metriken (Signal/Noise)
- [ ] HTTPS Support
- [ ] Parental Control API

---

## Next Steps

Projekt ist aktuell **STABLE** auf v1.0.4:
- ✅ Alle Sensor/Switch Namen korrekt
- ✅ WAN RX/TX zeigen echte Daten
- ✅ Entity Registry sauber
- ✅ Tests bestanden
- ⏳ **Nächste Aktion:** Auf User-Anfrage warten oder Features aus Todo-Liste implementieren
