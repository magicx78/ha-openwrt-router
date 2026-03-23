# PLAN: Erweiterte Monitoring-Metriken für ha-openwrt-router

**Ziel:** Umfassende System-, Speicher-, Festplatten- und Netzwerk-Monitoring Sensoren implementieren.

**Status:** 🔵 IN PLANUNG
**Erstellt:** 2026-03-23
**Ziel-Version:** v1.1.0 (nach HACS Genehmigung)

---

## 📊 Feature-Übersicht

### ✅ Bereits vorhanden (extrahieren aus bestehenden API-Daten)
- **Hostname** → `get_router_info()` ✓
- **Model** → `get_router_info()` ✓
- **OpenWrt Version** → `get_router_info().release` ✓
- **Uptime** → `get_router_status()` ✓
- **CPU Load (1-min %)** → `get_router_status()` ✓
- **Memory (Total/Free/Used)** → `get_router_status().memory` ✓

### 🔴 Zu implementieren (neue API-Calls oder Ergänzungen)
- **Platform Architecture** → `get_router_info()` (board_name, target_arch)
- **CPU Load (5/15-min)** → Ergänzung zu bestehender load array
- **Memory Details** → Erweiterung (Cached, Shared, Buffered)
- **Disk Space** → NEW: Total, Used, Free, % (alle Mounts)
- **tmpfs** → NEW: Total, Used, Free, %
- **Network Interfaces** (ALL) → Erweiterung (nicht nur WAN)
  - RX/TX bytes (rate + total)
  - RX/TX packets
  - RX/TX errors
  - RX/TX dropped packets
- **Active Network Connections** → NEW: Connection tracking

---

## 🏗️ Architektur-Ansatz

```
api.py
  ├─ get_router_info() — erweitert um platform_arch
  ├─ get_router_status() — ergänzt cpu_load um load_5min, load_15min
  ├─ get_system_memory() — neue Details: cached, shared, buffered
  ├─ get_disk_space() — NEW: liest /sys/class/net/(df Daten)
  ├─ get_tmpfs_stats() — NEW: Temporary Storage Stats
  ├─ get_network_interfaces() — NEW: RX/TX metrics pro Interface
  └─ get_active_connections() — NEW: Connection tracking (nf_conntrack)

coordinator.py
  └─ OpenWrtCoordinatorData
      ├─ router_info — erweitert um platform_arch
      ├─ cpu_load — ergänzt um load_avg_5min, load_avg_15min
      ├─ memory — erweitert um cached, shared, buffered
      ├─ disk_space: dict = {} — NEW
      ├─ tmpfs: dict = {} — NEW
      ├─ network_interfaces: list = [] — NEW
      └─ active_connections: int = 0 — NEW

sensor.py
  └─ SENSOR_DESCRIPTIONS — +15 neue Sensoren
      ├─ platform_architecture (info)
      ├─ cpu_load_5min (%)
      ├─ cpu_load_15min (%)
      ├─ memory_cached (MB)
      ├─ memory_shared (MB)
      ├─ memory_buffered (MB)
      ├─ disk_total (GB)
      ├─ disk_used (GB)
      ├─ disk_free (GB)
      ├─ disk_usage_percent (%)
      ├─ tmpfs_total (MB)
      ├─ tmpfs_used (MB)
      ├─ tmpfs_free (MB)
      ├─ tmpfs_usage_percent (%)
      ├─ network_eth0_rx_bytes (rate)
      ├─ network_eth0_tx_bytes (rate)
      ├─ [weitere Interfaces dynamisch]
      └─ active_connections (count)
```

---

## 📋 Detaillierte Tasks

### PHASE 1: API-Layer Erweiterung (api.py)

#### [TASK-001] Erweitere get_router_info() um Platform Architecture
**Ziel:** Platform/Architecture aus board_name extrahieren
```python
# Input: result = {"board_name": "cudy,wr3000-v1", "target_arch": "arm_..."}
# Output:
# {
#   "platform_architecture": "arm_cortex-a9",  # aus board_name / uname -m
#   ...
# }
```
**OpenWrt API:** `system/board` + optional `system/uname` für arch
**Blocker:** Keine. Board_name existiert bereits.

#### [TASK-002] Ergänze get_router_status() um Load Averages (5/15-min)
**Ziel:** Komplette Load Average (1/5/15 min) + Prozent je Minute
```python
# Input: raw_load = [65536, 131072, 196608]  # je * 65536 kodiert
# Output:
# {
#   "load": [1.0, 2.0, 3.0],  # dekodiert
#   "cpu_load": 50.0,  # 1-min als %
#   "cpu_load_5min": 60.0,  # 5-min als %
#   "cpu_load_15min": 65.0,  # 15-min als %
# }
```
**Zusatz:** Speichere cpu_count; berechne % basierend auf cores

#### [TASK-003] Erweitere Memory Details (Cached, Shared, Buffered)
**Ziel:** Separator die bestehenden memory Fields
```python
# Input: memory = {"total": 268435456, "free": 134217728, "cached": 33554432, ...}
# Output bereits da, nur nicht alle Felder in coordinator abgebildet
# Zusätzliche extraction:
# - memory.cached (bytes)
# - memory.shared (bytes)
# - memory.buffered (bytes)
```
**Blocker:** Keine. Daten kommen bereits von ubus system/info

#### [TASK-004] NEW: get_disk_space() — Disk Usage pro Mount
**Ziel:** Total/Used/Free/% für alle Disk Mounts
```python
# OpenWrt API: Kein direkter ubus call, muss über file.read() gelesen werden
# Option 1: `df -h` via rpcd file.read
# Option 2: Read /proc/mounts + /sys/class/block für Rohstats

# Output:
# {
#   "mounts": [
#     {"mount": "/", "total_mb": 4000, "used_mb": 1500, "free_mb": 2500, "usage_percent": 37.5},
#     {"mount": "/overlay", "total_mb": 512, ...}
#   ],
#   "primary": { # Root mount summary
#     "total_mb": 4000,
#     "used_mb": 1500,
#     "free_mb": 2500,
#     "usage_percent": 37.5
#   }
# }
```
**OpenWrt API:** `file.read_stat()` oder  Shell-Execution über rpcd

#### [TASK-005] NEW: get_tmpfs_stats() — Temporary Storage
**Ziel:** tmpfs Usage (/tmp, /var/run, /dev/shm etc)
```python
# Quelle: /proc/mounts oder mount command
# Ziel:
# {
#   "total_mb": 128,
#   "used_mb": 64,
#   "free_mb": 64,
#   "usage_percent": 50.0,
#   "mounts": [
#     {"mount": "/tmp", "total_mb": 64, "used_mb": 32, ...},
#     {"mount": "/run", "total_mb": 32, "used_mb": 16, ...}
#   ]
# }
```
**OpenWrt API:** Read /proc/mounts oder statfs

#### [TASK-006] NEW: get_network_interfaces() — RX/TX Metrics ALL Interfaces
**Ziel:** Erweiterte Netzwerk-Stats für ALLE Interfaces (nicht nur WAN)
```python
# Quelle: /sys/class/net/{iface}/statistics/
# Für jeden Interface:
# {
#   "interface": "eth0",
#   "rx_bytes": 1000000,
#   "rx_packets": 10000,
#   "rx_errors": 5,
#   "rx_dropped": 2,
#   "tx_bytes": 500000,
#   "tx_packets": 5000,
#   "tx_errors": 1,
#   "tx_dropped": 0,
#   "rx_bytes_rate": 1200.5,  # bytes/sec (berechnet: Δ bytes / Δ time)
#   "tx_bytes_rate": 600.2,
#   "status": "up" | "down"
# }

# Output: List aller Interfaces mit obigen Stats
```
**OpenWrt API:** Read /sys/class/net/ + statische Calls via file.read()
**Notiz:** Rate-Berechnung = (current_bytes - last_bytes) / time_delta

#### [TASK-007] NEW: get_active_connections() — Connection Tracking
**Ziel:** Aktive Netzwerk-Verbindungen zählen
```python
# Quelle: /proc/net/nf_conntrack oder nf_conntrack_count Dateien
# Output:
# {
#   "established": 45,
#   "time_wait": 12,
#   "close_wait": 3,
#   "total": 60
# }
```
**OpenWrt API:** Read /proc/net/nf_conntrack oder conntrack Tools

---

### PHASE 2: Coordinator-Erweiterung (coordinator.py)

#### [TASK-008] Erweitere OpenWrtCoordinatorData Struktur
**Ziel:** Neue Felder für alle neuen Metriken hinzufügen
```python
class OpenWrtCoordinatorData:
    # Bestehend:
    router_info: dict
    uptime: int
    cpu_load: float
    memory: dict

    # NEU:
    cpu_load_5min: float = 0.0
    cpu_load_15min: float = 0.0
    disk_space: dict = {}
    tmpfs: dict = {}
    network_interfaces: list = []
    active_connections: int = 0
```

#### [TASK-009] Integriere neue API-Calls in _async_update_data()
**Ziel:** Rufe neue API-Methoden auf und speichere in data
```python
# Neue Aufrufe in _async_update_data():
data.disk_space = await self.api.get_disk_space()
data.tmpfs = await self.api.get_tmpfs_stats()
data.network_interfaces = await self.api.get_network_interfaces()
data.active_connections = await self.api.get_active_connections()

# Ergänzungen zu bestehenden:
status = await self.api.get_router_status()
data.cpu_load_5min = status.get("cpu_load_5min", 0.0)
data.cpu_load_15min = status.get("cpu_load_15min", 0.0)
```

---

### PHASE 3: Sensor Definitions (sensor.py)

#### [TASK-010] Füge 15+ neue Sensoren hinzu
**Ziel:** Alle neuen Metriken in HA als Sensoren darstellen

**Neue Sensoren:**

| Key | Translation | Unit | Device Class | State Class | Icon |
|-----|-------------|------|--------------|------------|------|
| platform_architecture | platform_architecture | - | - | - | mdi:cpu-64-bit |
| cpu_load_5min | cpu_load_5min | % | - | measurement | mdi:speedometer |
| cpu_load_15min | cpu_load_15min | % | - | measurement | mdi:speedometer |
| memory_cached | memory_cached | MB | data_size | measurement | mdi:memory |
| memory_shared | memory_shared | MB | data_size | measurement | mdi:memory |
| memory_buffered | memory_buffered | MB | data_size | measurement | mdi:memory |
| disk_total | disk_total | GB | data_size | - | mdi:harddisk |
| disk_used | disk_used | GB | data_size | measurement | mdi:harddisk |
| disk_free | disk_free | GB | data_size | - | mdi:harddisk |
| disk_usage_percent | disk_usage_percent | % | - | measurement | mdi:percent |
| tmpfs_total | tmpfs_total | MB | data_size | - | mdi:memory |
| tmpfs_used | tmpfs_used | MB | data_size | measurement | mdi:memory |
| tmpfs_free | tmpfs_free | MB | data_size | - | mdi:memory |
| tmpfs_usage_percent | tmpfs_usage_percent | % | - | measurement | mdi:percent |
| active_connections | active_connections | - | - | measurement | mdi:lan |
| network_rx_bytes | network_rx_bytes | B | data_size | total | mdi:download |
| network_tx_bytes | network_tx_bytes | B | data_size | total | mdi:upload |
| network_rx_packets | network_rx_packets | - | - | total | mdi:packets |
| network_tx_packets | network_tx_packets | - | - | total | mdi:packets |

Zusätzlich: **Dynamic Interface Sensors** (eth0, wlan0, etc.) mit RX/TX rate

---

### PHASE 4: Constants & Strings (const.py, strings.json)

#### [TASK-011] Neue Entity-Suffixes in const.py
```python
SUFFIX_PLATFORM_ARCHITECTURE = "platform_architecture"
SUFFIX_CPU_LOAD_5MIN = "cpu_load_5min"
SUFFIX_CPU_LOAD_15MIN = "cpu_load_15min"
SUFFIX_MEMORY_CACHED = "memory_cached"
SUFFIX_MEMORY_SHARED = "memory_shared"
SUFFIX_MEMORY_BUFFERED = "memory_buffered"
SUFFIX_DISK_TOTAL = "disk_total"
SUFFIX_DISK_USED = "disk_used"
SUFFIX_DISK_FREE = "disk_free"
SUFFIX_DISK_USAGE = "disk_usage"
SUFFIX_TMPFS_TOTAL = "tmpfs_total"
SUFFIX_TMPFS_USED = "tmpfs_used"
SUFFIX_TMPFS_FREE = "tmpfs_free"
SUFFIX_TMPFS_USAGE = "tmpfs_usage"
SUFFIX_ACTIVE_CONNECTIONS = "active_connections"
SUFFIX_NETWORK_RX_BYTES = "network_rx_bytes"
SUFFIX_NETWORK_TX_BYTES = "network_tx_bytes"
# ... etc
```

#### [TASK-012] Translations in strings.json & en.json
**Ziel:** Benutzerfreundliche Namen + Beschreibungen für alle neuen Sensoren

---

### PHASE 5: Tests & Validierung

#### [TASK-013] Unit Tests für neue API-Methoden
**Ziel:** test_api.py erweitern mit Mock-Daten für:
- get_disk_space()
- get_tmpfs_stats()
- get_network_interfaces()
- get_active_connections()

#### [TASK-014] Integration Tests im coordinator
**Ziel:** test_coordinator.py — prüfe dass neue Felder korrekt gefüllt werden

#### [TASK-015] Manuelles Testing auf echtem Router
**Ziel:** Testen mit echtem Cudy WR3000 v1
- Prüfe: Alle Sensoren zeigen Werte
- Prüfe: Keine Fehler in HA Logs
- Prüfe: Performance-Impact (sollte minimal sein)

---

### PHASE 6: Dokumentation & Release

#### [TASK-016] Aktualisiere README.md
**Ziel:** Neue Features dokumentieren + in Entity-Tabelle
- Feature-Beschreibung
- Neue Entity IDs
- OpenWrt Requirements (falls neue Pakete nötig)

#### [TASK-017] Aktualisiere CHANGELOG.md
**Version:** v1.1.0
```
## [1.1.0] - 2026-03-2X
### Added
- Extended system monitoring: Platform Architecture, detailed CPU/Memory stats
- Disk Space monitoring: Total, Used, Free, Usage % for all mounts
- Temporary Storage (tmpfs) monitoring
- Network Interface statistics: RX/TX bytes/packets/errors/dropped for all interfaces
- Active connection tracking (nf_conntrack integration)
```

#### [TASK-018] GitHub Release erstellen
**Ziel:** v1.1.0 Tag + Release Notes

---

## 🔧 OpenWrt API Dependencies

### Muss verfügbar sein:
- ✅ `system/board` — model, board_name
- ✅ `system/info` — load, memory, uptime
- ✅ `file` module (rpcd-mod-file) — read /sys/ Dateien
- ⚠️ `/proc/mounts` — Disk/tmpfs stats (evtl. nicht lesbar)
- ⚠️ `/proc/net/nf_conntrack` — Connection tracking (nur wenn nf_conntrack aktiv)

### Fallback-Handling:
- Wenn `/proc/mounts` nicht lesbar → Sensor als "unavailable"
- Wenn nf_conntrack nicht aktiv → Connection Sensor als "unavailable"
- Wenn Interface-Stats nicht lesbar → leere oder "0" values

---

## 📈 Komplexität & Abhängigkeiten

| Phase | Komplexität | Abhängigkeiten | EST. Größe |
|-------|-------------|----------------|-----------|
| PHASE 1 (API) | **HOCH** | rpcd-mod-file | +200 LOC |
| PHASE 2 (Coordinator) | Mittel | PHASE 1 | +50 LOC |
| PHASE 3 (Sensoren) | Mittel | PHASE 2 | +300 LOC |
| PHASE 4 (Config) | Niedrig | PHASE 3 | +150 LOC |
| PHASE 5 (Tests) | Mittel | PHASE 4 | +200 LOC |
| PHASE 6 (Docs) | Niedrig | PHASE 5 | - |
| **GESAMT** | | | **~1000 LOC** |

---

## 🚨 Bekannte Challenges

1. **Disk/tmpfs Stats:** Nicht über ubus verfügbar → muss `/proc/mounts`, `statfs()` oder `df` lesen
2. **Connection Tracking:** Benötigt `nf_conntrack` Modul (nicht auf allen OpenWrt aktiv)
3. **Interface Rate-Berechnung:** Braucht State zwischen Polls (last_values speichern im coordinator)
4. **Performance:** Zu viele API-Calls können Polling-Interval überlasten
5. **Fehlerbehandlung:** Wenn Files nicht lesbar (Permission, nicht vorhanden) → graceful fallback

---

## ✅ Definition of Done (für jeden Task)

- [ ] Code implementiert + Syntax korrekt
- [ ] Type Hints vollständig
- [ ] Error Handling für API-Fehler
- [ ] Logging mit _LOGGER.debug()
- [ ] Tests schreiben + passing
- [ ] Code Review bestanden
- [ ] Dokumentation aktualisiert
- [ ] GitHub Commit

---

## 📍 Nächste Schritte

1. **User Alignment:** Diesen Plan bestätigen lassen
2. **PHASE 1 starten:** API-Erweiterungen implementieren
3. **Paralleles Testing:** Auf echtem Router testen
4. **Iteratives Feedback:** Features nach Priorität

---

**Plan Status:** 🔵 PENDING USER APPROVAL
**Coordinator:** Claude Haiku 4.5
**Erstellt:** 2026-03-23 19:45 UTC
