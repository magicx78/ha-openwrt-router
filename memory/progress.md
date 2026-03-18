# Progress — ha-openwrt-router

## Letzter Stand: 2026-03-18

---

## Router-Info
- **Modell:** Cudy WR3000 v1
- **Hostname:** secureap-gateway
- **Host:** 10.10.10.1:80
- **SSIDs (phy0, 2.4GHz):** secure-IoT, Guest-WLAN, WWW.PC2HELP.DE, Tenant-Klee
- **SSIDs (phy1, 5GHz):** <--_-->, secure-IoT

---

## Erledigte Tasks

### ✅ TASK-01: Per-SSID WiFi Switches mit SSID-Namen
**Status:** DONE — verifiziert in HA
**Was wurde geändert:**
- `switch.py` komplett neu: 1 Switch pro SSID, `_attr_name = ssid`
- `api.py`: UCI-Fallback in `get_wifi_status()` für Router ohne echte Radios (x86-VM)
- `strings.json`: Alte band-basierte Switch-Keys entfernt

**Ergebnis:**
- 6 neue Entities korrekt erstellt mit echten SSID-Namen
- `switch.secureap_gateway_secure_iot`, `switch.secureap_gateway_guest_wlan` etc.

---

## Offene Tasks

### ⚠️ TASK-02: Alte Orphaned Entities bereinigen
In HA Entity Registry existieren noch 3 alte band-basierte Switches:
- `switch.openwrt_dev` (wifi_24ghz)
- `switch.secureap_gateway` (wifi_5ghz)
- `switch.secureap_gateway_2` (guest_wifi)
→ User muss diese in HA Settings → Entities → löschen

### 📋 TASK-03: Entity-Anzeigenamen in HA verbessern (optional)
Aktuell zeigt HA: "secureap-gateway secure-IoT"
Das "secureap-gateway" Prefix ist der Gerätename (erwartetes HA-Verhalten mit `_attr_has_entity_name=True`)
Falls User nur "secure-IoT" ohne Prefix will: `_attr_has_entity_name = False`

### 📋 TASK-04: Commit & Release vorbereiten
- `git commit` für switch.py + api.py + strings.json Änderungen
- CHANGELOG.md updaten
- Version in manifest.json erhöhen

---

## Geplante Features (aus README)
- [ ] Bandwidth Sensoren (RX/TX bytes pro Interface)
- [ ] DHCP Lease Enrichment (Client-IPs in Device Tracker)
- [ ] HTTPS Support
- [ ] Per-Client Online-Zeit

---

## Nächste Schritte
1. User löscht alte Entities in HA UI
2. Entscheidung: Prefix "secureap-gateway" behalten oder entfernen?
3. git commit
