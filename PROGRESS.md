# PROGRESS — OpenWrt HA Integration

Entwicklungsprotokoll · Letzte Session: 2026-04-19 · Aktuell: **v1.12.0**

---

## Status: ✅ v1.12.0 — Topology UI/UX Spec vollständig umgesetzt

Alle 12 Features der UI/UX-Spec implementiert. Panel ist produktionsreif.

---

## Was wurde gebaut (2026-04-19) — v1.12.0

### Topology Panel — vollständige UI/UX Spec

Alle Features wurden auf Branch `claude/openwrt-topology-traffic-panel-yF35C` entwickelt
und per Merge-Commit in `main` integriert.

| # | Feature | Commits | Dateien |
|---|---------|---------|---------|
| 1 | **Minimap** | `c978e14` | `Minimap.tsx` (neu), `TopologyView.tsx`, `topology.css` |
| 2 | **Rechtsklick-Kontextmenü** | `6304fdc` | `ContextMenu.tsx` (neu), `GatewayNode.tsx`, `APNode.tsx` |
| 3 | **AP Client-Expansion** | `14c91e8` | `APClientList.tsx` (neu), `APNode.tsx` |
| 4 | **Health-Modus** | `dadd8b1` | `GatewayNode.tsx`, `APNode.tsx`, `StatusBar.tsx` |
| 5 | **Status-Flash-Animation** | `13a638c` | `useStatusFlash.ts` (neu), `GatewayNode.tsx`, `APNode.tsx` |
| 6 | **Layout-Transition** | `af8c9f4` | `TopologyView.tsx`, `topology.css` |
| 7 | **Gruppen-Modus** | `1dddd84` | `TopologyView.tsx` (groupAPs), `StatusBar.tsx` |
| 8 | **Doppelklick-Zoom** | `af8c9f4` | `TopologyView.tsx`, `topology.css` |
| 9 | **Firmware-Version** | `15ec994` | `types.ts`, `api.ts`, `NodeTooltip.tsx`, `DetailPanel.tsx` |
| 10 | **Mini Traffic/Ressourcen-Bars** | `5966e6b` | `DetailPanel.tsx`, `topology.css` |
| 11 | **Kontextaktionen Inspector** | `5966e6b` | `DetailPanel.tsx`, `TopologyView.tsx` |
| 12 | **Event-Timeline pro Gerät** | `4028da9` | `coordinator.py`, `topology_diagnostic.py`, `DetailPanel.tsx` |

### Neue Dateien (Frontend)

| Datei | Beschreibung |
|-------|--------------|
| `Minimap.tsx` | 160×100 SVG Canvas-Übersicht, Viewport-Rect, Click-to-Pan |
| `ContextMenu.tsx` | Rechtsklick-Menü mit Keyboard-Dismiss |
| `APClientList.tsx` | Inline-Clientliste mit Signal-Balken |
| `useStatusFlash.ts` | Hook — setzt 650 ms `.status-flash` bei Status-Wechsel |

### Backend-Änderungen (Python)

**`coordinator.py`:**
- `events: list[dict]` Feld in `OpenWrtCoordinatorData`
- `_event_history: deque(maxlen=30)` Ring-Buffer
- `_prev_wan_connected`, `_cpu_warn_active`, `_mem_warn_active` für State-Tracking
- `_record_events()` — erkennt WAN-Wechsel, CPU ≥ 80%, RAM ≥ 90%

**`topology_diagnostic.py`:**
- `"events": data.events if data.events else []` in Router-Node-Attributes

**`manifest.json`:** version `1.11.2` → `1.12.0`

---

## Was wurde gebaut (2026-04-17) — v1.11.2

| Änderung | Detail |
|----------|--------|
| Canvas Dot-Grid | `radial-gradient` Hintergrundmuster (28 px, scrollt mit Container) |
| Edge-Glow bei Hover | CSS `drop-shadow` per Kanten-Typ |
| Internet-Node Pulse | `internet-pulse` Keyframe (3.5s, infinite) |
| Edge-Tooltip Akzent-Linie | 2px `border-top` farbig nach Kanten-Typ |

---

## Was wurde gebaut (2026-04-16) — v1.11.1

| Fix | Detail |
|-----|--------|
| 24h rpcd Session-Timeout | `login()` sendet jetzt `"timeout": 86400` |
| DDNS Log-Spam | Nach erstem Fehlschlag kein weiteres DDNS-Polling |
| `ipv4-address` Parsing | `isinstance`-Guard gegen non-dict Entries |
| Ruff CI | 30 ungenutzte Imports entfernt; E402/F841/F401 fixes |

---

## Was wurde gebaut (2026-04-15) — v1.11.0

- **Client Detail Panel**: IP, Band, Connected since, DHCP-Expires, HA device_tracker Link
- **DDNS-Status** pro Service im Gateway-Detailpanel
- **SpeedChart**: 24h DSL- und Ping-Verlauf im Gateway-Inspector

---

## Was wurde gebaut (2026-04-14) — v1.10.1

- **Topology Panel — 5 Views**: Topology, Devices, Clients, Alarms, Settings
- **Edge-Tooltip**: Hover auf Kanten → Link-Typ, Signal, WAN-Traffic
- **Fritz!Box TR-064** Fix: SOAP-Namespace-Fehler behoben

---

## Was wurde gebaut (2026-04-12 → 2026-04-14)

### Panel in openwrt_router integriert

| Datei | Aktion |
|-------|--------|
| `topology_panel.py` | NEU — Panel-Registrierung + API-View in openwrt_router |
| `__init__.py` | +panel setup + ACL-provisioning nach erstem Refresh |
| `manifest.json` | `"dependencies": ["frontend", "http", "panel_custom"]` |

### Auto-ACL Provisioning

| Datei | Aktion |
|-------|--------|
| `acl_provisioning.py` | NEU — SSH Check + Deploy + rpcd restart |
| `tests/test_acl_provisioning.py` | NEU — 9 Tests |

### Multi-Router Mesh Topology

| Datei | Aktion |
|-------|--------|
| `topology_mesh.py` | NEU — Aggregation aller Router-Entries |
| `topology_diagnostic.py` | Erweitert: `role` + `host_ip` Parameter |
| `tests/test_topology_mesh.py` | NEU — 28 Tests |

---

## Bekannte Einschränkungen

| Einschränkung | Ursache | Impact |
|---|---|---|
| Event-History überlebt HA-Restart nicht | `deque` in-memory | Ereignisse gehen beim Neustart verloren |
| `signal=null` für manche Clients | `iw station dump` bracket-format | Signal-Wert fehlt, kein Fehler |
| Ghost-Mode akkumuliert | Keine Persistenz zwischen HA-Restarts | Neu gestartete HA-Instanz zeigt keine Ghost-Devices |

---

## Roadmap

- [ ] **HACS Default Store** — Submission vorbereiten
- [ ] **Persistente Event-History** — `hass.data` oder Datei statt in-memory deque
- [ ] **Per-Client Traffic Chart** — Verlauf RX/TX pro Client
- [ ] **Shift+Click Multi-Device Compare** — Zwei Geräte vergleichen
- [ ] **Parental Control Support**
- [ ] **HTTPS Support** — TLS-Option in config_flow

---

## Dateistruktur (aktuell)

```
custom_components/openwrt_router/
├── __init__.py               # Setup, Panel-Registrierung, ACL-Provisioning
├── api.py                    # ALLE HTTP/SSH-Calls
├── coordinator.py            # 30s Poll-Zyklus, Event-History, DSL-History
├── config_flow.py            # UI Setup Wizard
├── topology_panel.py         # API-Endpoint + Sidebar-Panel Registrierung
├── topology_diagnostic.py   # Per-Router Snapshot Builder
├── topology_mesh.py          # Multi-Router Aggregation
├── topology_entities.py      # HA Entities für Topology-Daten
├── acl_provisioning.py       # SSH ACL-Datei Deploy
├── fritzbox.py               # TR-064 DSL/Traffic
├── sensor.py / switch.py / button.py / device_tracker.py
└── frontend/
    ├── dist/
    │   └── topology-bundle.js   # Vite Build-Output
    └── topology/
        └── src/
            ├── TopologyView.tsx          # Haupt-Canvas
            ├── topology.css              # ~2500 Zeilen CSS
            ├── types.ts                  # Domain-Typen inkl. RouterEvent
            ├── api.ts                    # Snapshot-Adapter
            ├── layout.ts                 # Edge-Berechnung
            ├── useStatusFlash.ts
            ├── useAlerts.ts
            ├── useGhostDevices.ts
            └── components/
                ├── APClientList.tsx      # Inline-Clientliste
                ├── APNode.tsx
                ├── AlertsView.tsx
                ├── ClientStrip.tsx
                ├── ConnectionLayer.tsx
                ├── ContextMenu.tsx       # Rechtsklick-Menü
                ├── DetailPanel.tsx       # Inspector (EventTimeline, ResourceBars, ...)
                ├── DevicesView.tsx
                ├── GatewayNode.tsx
                ├── Icons.tsx
                ├── InternetNode.tsx
                ├── Minimap.tsx           # Canvas-Übersicht
                ├── NodeTooltip.tsx
                ├── PortStrip.tsx
                ├── Sidebar.tsx
                ├── SignalBar.tsx
                ├── SpeedChart.tsx
                ├── StatusBar.tsx
                └── TrafficView.tsx
```

---

## Deployment

```bash
# Windows — nach jedem Build
git pull   # holt commits von main
git push   # pushed zu GitHub
```

Panel URL: `http://10.10.10.165:8123/openwrt-topology`
Router ACL: `/usr/share/rpcd/acl.d/ha-openwrt-router.json` auf Gateway + APs
