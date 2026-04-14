# PROGRESS — OpenWrt HA Integration

Entwicklungsprotokoll · Letzte Session: 2026-04-14

---

## Status: ✅ v1.10.0 — Alles in openwrt_router integriert

- Panel läuft als Teil von `openwrt_router` (kein separates `openwrt_topology` mehr)
- FritzBox-Style Visualisierung live: Karten-Nodes, Bezier-Linien, Signal-Pills
- ACL-Provisioning automatisch beim Hinzufügen eines neuen Routers
- 353 Tests grün, committed `8490022`, gepusht auf `feature/topology-ha-test`

---

## Was wurde gebaut (2026-04-12 → 2026-04-14)

### Teil 1 — Panel in openwrt_router integriert

| Datei | Aktion |
|-------|--------|
| `topology_panel.py` | NEU — Panel-Registrierung + API-View in openwrt_router |
| `frontend/topology-panel.js` | VERSCHOBEN aus openwrt_topology/frontend/ |
| `__init__.py` | +panel setup + ACL-provisioning nach erstem Refresh |
| `manifest.json` | `"dependencies": ["frontend", "http", "panel_custom"]` |
| `openwrt_topology/` | GELÖSCHT (Repo + HA-Server) |

### Teil 2 — Auto-ACL Provisioning

| Datei | Aktion |
|-------|--------|
| `acl_provisioning.py` | NEU — SSH Check + Deploy + rpcd restart |
| `tests/test_acl_provisioning.py` | NEU — 9 Tests |

Fixt: "Authentication failed" beim Hinzufügen neuer AP-Router ohne ACL-Datei.

### Teil 3 — Multi-Router Mesh Topology

| Datei | Aktion |
|-------|--------|
| `topology_mesh.py` | NEU — Aggregation aller Router-Entries |
| `topology_diagnostic.py` | Erweitert: `role` + `host_ip` Parameter, SSID+Band Labels |
| `coordinator.py` | `get_wifi_status()` try/except für ACL-geblockte APs |
| `api.py` | Post-relogin `-32002` → `OpenWrtMethodNotFoundError` |
| `tests/test_topology_mesh.py` | NEU — 28 Tests |

### Teil 4 — FritzBox-Style Panel Redesign

| Feature | Detail |
|---------|--------|
| Karten-Nodes | Abgerundete Boxen, Band-spezifische Border-Farben |
| Status-Dots | Grün/Rot/Grau pro Karte |
| Signal-Pills | gut (>-65 dBm) / mittel / schwach (<-75 dBm) |
| WAN-Badge | ✓/✗ auf Gateway-Karte |
| Bezier-Linien | Geschwungene SVG-Paths statt gerader Linien |
| CSS-Variablen | `--cg`, `--cr`, `--cl`, `--good`, `--fair`, `--poor` |
| Multiband-Farben | Gateway blau, AP lila, 2.4 GHz grün, 5 GHz lila, 6 GHz magenta |

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Impact |
|---|---|---|
| `signal=null` für manche Clients | `iw station dump` gibt `[-65, -68]` bracket-format | Signal-Wert fehlt, kein Fehler |
| `rx_bytes/tx_bytes` per AP-Interface = null | Kein Interface-Statistik im Coordinator | Keine Validierung möglich |

---

## TODO — Offene Issues

### P2 — Qualität / Stabilität

- [ ] **sshpass nicht im HA-Container**
  - SSH-Fallbacks in `api.py` schlagen fehl wenn `sshpass` fehlt
  - HA Docker-Image hat kein `sshpass` → Log-Error bei SSH-Fallback
  - Lösung: try/except graceful degradation in `api.py` SSH-Methoden (bereits in `acl_provisioning.py`)

### P3 — Features / Roadmap

- [ ] **Bandwidth Sensoren** (RX/TX bytes/s pro Interface)
  - Basis: `network.interface.*/statistics` via rpcd (in ACL vorhanden)
  - Rate: Δbytes / Δtime zwischen Poll-Zyklen

- [ ] **Topology Panel Verbesserungen**
  - Inactive Interfaces (0/0 rx/tx) visuell hervorheben
  - Client-Karte: DHCP-Expires anzeigen
  - Filter: "Nur aktive Clients", "Nur 5 GHz"
  - 4. AP (IP noch unbekannt) hinzufügen

- [ ] **HTTPS Support** — TLS-Option in config_flow

- [ ] **HACS Default Store Vorbereitung**
  - `brand/icon.png` 256×256px erstellen
  - `hassfest` + `hacs/action` CI Workflows testen
  - GitHub Release publishen

### P4 — Aufräumen

- [ ] **CLAUDE.md aktualisieren**
  - Neue Dateien (`topology_diagnostic.py`, `topology_entities.py`, `topology_mesh.py`, `topology_panel.py`, `acl_provisioning.py`, `frontend/`) im Dateibaum ergänzen
  - `openwrt_topology/` aus Struktur entfernen

---

## Deployments (aktueller Stand)

Alle Dateien via WSL `cp` nach `/opt/ha-config/custom_components/openwrt_router/` deployed.

| Lokal | HA-Pfad |
|-------|---------|
| `custom_components/openwrt_router/*.py` | `/opt/ha-config/custom_components/openwrt_router/` |
| `custom_components/openwrt_router/frontend/topology-panel.js` | `/opt/ha-config/custom_components/openwrt_router/frontend/` |

Panel URL: `http://10.10.10.165:8123/openwrt-topology`
Router ACL: `/usr/share/rpcd/acl.d/ha-openwrt-router.json` auf Gateway + APs
