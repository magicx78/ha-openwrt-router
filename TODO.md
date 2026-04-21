# TODO — ha-openwrt-router

Stand: 2026-04-19 · Version: v1.12.1

---

## Backlog

### Backend / API

- [ ] `get_port_vlan_map()` — Tests schreiben (DSA + legacy swconfig Fixtures)
- [ ] `get_bridge_fdb()` — Tests schreiben (SSH-Output-Fixture)
- [ ] CPU-History in `coordinator.py` — Unit-Test für deque/rolling window
- [ ] Persistente Event-History — `hass.data` oder JSON-Datei statt in-memory deque (überlebt HA-Restart nicht)
- [ ] HTTPS-Support — TLS-Option in config_flow + api.py

### Topology Frontend

- [ ] Per-Client Traffic Chart — RX/TX Verlauf pro WLAN-Client
- [ ] Shift+Click Multi-Device Compare — Zwei Geräte nebeneinander vergleichen
- [ ] VLAN-Badge Klick → Filter: nur Ports mit dieser VLAN-ID hervorheben
- [ ] Bridge FDB Visualisierung im PortStrip (welcher Port hat welche MACs)

### Entities / Sensoren

- [ ] Bandwidth Sensoren (RX/TX bytes pro Interface) — aus ROADMAP
- [ ] Traffic Statistiken — aus ROADMAP
- [ ] DHCP Lease Enrichment (Client-IPs in Device Tracker) — aus ROADMAP
- [ ] Per-Client Online-Zeit — aus ROADMAP
- [ ] Link Quality Metriken (Signal/Noise pro Radio) — aus ROADMAP
- [ ] Parental Control Support — aus ROADMAP

### HACS / Release

- [ ] HACS Default Store Submission vorbereiten
  - [ ] `brand/icon.png` 256×256px erstellen
  - [ ] `manifest.json` → `issue_tracker` Key prüfen
  - [ ] GitHub Release publizieren (nicht nur Tag)
  - [ ] `hassfest` + `hacs/action` CI Workflows prüfen/ergänzen

### Tests

- [ ] Fixtures für Router-Zustände anlegen (`tests/fixtures/`)
  - [ ] `router_healthy.json`
  - [ ] `router_wan_down.json`
  - [ ] `router_minimal.json`
  - [ ] `router_broken.json`
- [ ] Topology Mesh Tests erweitern (port_vlan_map, port_fdb_map)

---

## Erledigt (letzte Sessions)

- [x] v1.12.1 — `get_port_vlan_map()` (DSA + swconfig), `get_bridge_fdb()`, CPU-History (1h rolling), Topology UI Polish (VLAN-Badges, SpeedChart CPU, PortStrip VLAN-Overlay)
- [x] v1.12.1 — SSH-Fallback in `get_network_interfaces()` — `OpenWrtAuthError` abgefangen
- [x] v1.12.0 — Alle 12 UI/UX-Spec Features implementiert (Minimap, Kontextmenü, AP Client-Expansion, Health-Modus, Status-Flash, Layout-Transition, Gruppen-Modus, Doppelklick-Zoom, Firmware-Version, Mini Traffic/Ressourcen-Bars, Kontextaktionen Inspector, Event-Timeline)
- [x] v1.11.2 — Canvas Dot-Grid, Edge-Glow bei Hover, Internet-Node Pulse
- [x] v1.11.1 — 24h rpcd Session-Timeout, DDNS Log-Spam-Fix, IPv4-Parsing-Guard
- [x] v1.11.0 — Client Detail Panel, DDNS-Status, SpeedChart 24h DSL/Ping
- [x] v1.10.1 — Topology Panel 5 Views, Edge-Tooltip, Fritz!Box TR-064 Fix
- [x] Auto-ACL Provisioning via SSH
- [x] Multi-Router Mesh Topology (`topology_mesh.py`)
