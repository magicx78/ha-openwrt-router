# ha-openwrt-router — Claude Code Context

## Projekt

Home Assistant custom integration für OpenWrt Router via ubus/rpcd JSON-RPC.
GitHub: https://github.com/magicx78/ha-openwrt-router
Domain: `openwrt_router`
HACS: Custom Repository (Ziel: Default Store)

## Projektstruktur

```
ha-openwrt-router/
├── custom_components/openwrt_router/
│   ├── __init__.py             # async_setup_entry, async_unload_entry, runtime_data
│   ├── manifest.json           # domain, version, codeowners (alphabetisch sortiert für hassfest)
│   ├── const.py                # DOMAIN, Defaults, Konfig-Keys
│   ├── api.py                  # ALLE Netzwerkaufrufe — OpenWrtAPI Klasse + SSH-Fallback
│   ├── coordinator.py          # OpenWrtCoordinator (DataUpdateCoordinator)
│   ├── config_flow.py          # UI Setup Wizard
│   ├── sensor.py               # Uptime, WAN Status, Client Count, RX/TX, etc.
│   ├── switch.py               # WiFi Radios (2.4/5/6 GHz, Guest)
│   ├── binary_sensor.py        # Connectivity, WAN-Connectivity
│   ├── device_tracker.py       # WiFi Clients per MAC
│   ├── button.py               # WiFi Reload, Update, etc.
│   ├── diagnostics.py           # Redacted diagnostics
│   ├── acl_provisioning.py     # Auto-Setup rpcd ACL via SSH
│   ├── fritzbox.py             # Optional DSL stats (TR-064)
│   ├── topology.py             # Per-Router topology snapshot (legacy)
│   ├── topology_diagnostic.py  # Snapshot builder per router
│   ├── topology_mesh.py        # Multi-router mesh aggregator + edge detection
│   ├── topology_entities.py    # Topology-related entities
│   ├── topology_panel.py       # Sidebar panel registration + API view
│   ├── strings.json            # UI Strings
│   ├── translations/en.json
│   ├── brand/                  # icon.png + icon.svg (für HACS Validation)
│   └── frontend/               # React/TS Topology Panel
│       ├── dist/topology-bundle.js   # Built bundle (341 kB)
│       └── topology/src/             # Vite project (App, components/, utils/)
├── tests/
│   ├── conftest.py
│   ├── test_api.py             # ubus + SSH-Fallback
│   ├── test_button.py
│   ├── test_config_flow.py
│   ├── test_coordinator.py
│   ├── test_dhcp_leases.py
│   ├── test_diagnostics.py
│   ├── test_sensor.py
│   ├── test_switch.py
│   ├── test_topology_mesh.py   # Mesh aggregator (inter-router edges)
│   ├── test_memory_leak_v1178.py    # Heap + RSS regression checks
│   ├── test_sshpass_security_v1179.py  # No '-p <pw>' in argv
│   └── …                       # 448 Tests total
├── scripts/                    # mock_router.py, dev_start.py, _dev_rss_sample.sh, …
├── .github/workflows/
│   ├── hassfest.yaml           # HA manifest validation
│   ├── hacs.yaml               # HACS validation
│   ├── tests.yaml              # ruff check + ruff format + pytest (3.12, 3.13)
│   ├── ha-compat.yaml          # HA version compatibility matrix
│   └── release.yaml            # Auto release on tag push
├── brand/                      # Repo-Root brand assets (Original)
│   ├── icon.png                # 256x256px
│   └── icon.svg
├── hacs.json                   # name, homeassistant min, render_readme
├── README.md
└── CHANGELOG.md
```

## Architektur — Eiserne Regeln

```
api.py          ← ALLE HTTP-Calls. Nie woanders.
coordinator.py  ← Polling (30s), Fehlerbehandlung, Daten-Distribution
sensor.py       ← Lesen aus coordinator.data — kein Netzwerk
switch.py       ← Lesen + Schreiben über api.py — kein direktes HTTP
config_flow.py  ← Ruft api.async_test_connection() auf
__init__.py     ← Verkabelt alles, sonst nichts
```

**Entities rufen niemals direkt HTTP auf.**
**coordinator.py kennt keine Entity-Typen.**

## OpenWrt API — Kommunikation

Alle Calls via HTTP POST `http://{host}:{port}/ubus` als JSON-RPC:

```python
payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "call",
    "params": [auth_token, namespace, method, params]
}
```

Auth-Token: 32-Zeichen Session-Token von `session.login`.
Error Code 6 = Token abgelaufen → neu einloggen und retry.

Wichtige ubus-Calls:
- `system / info / {}` → uptime, memory
- `network.interface.wan / status / {}` → WAN up/down, IP
- `hostapd.{iface} / get_clients / {}` → verbundene WLAN-Clients
- `network.wireless / status / {}` → Radio-Status
- `network.wireless / up|down / {}` → Radio ein/aus
- `luci-rpc / getDHCPLeases / {}` → DHCP-Leases (MAC → IP → Hostname)

## Python-Standards

- `from __future__ import annotations` auf jeder Datei
- Type Hints überall
- `_LOGGER = logging.getLogger(__name__)` in jedem Modul
- `async_get_clientsession(hass)` — niemals eigene aiohttp Session
- `UpdateFailed` in `_async_update_data` werfen, nie schlucken
- `@dataclass(frozen=True)` für EntityDescription
- Defensive: `data.get("key")` statt `data["key"]` in Entity-Properties

## Geplante Features (TODO aus README)

- [ ] Bandwidth Sensoren (RX/TX bytes pro Interface)
- [ ] Traffic Statistiken
- [ ] DHCP Lease Enrichment (Client-IPs in Device Tracker)
- [ ] Per-Client Online-Zeit
- [ ] Link Quality Metriken (Signal/Noise pro Radio)
- [ ] HTTPS Support
- [ ] Parental Control Support

## HACS Status (Stand v1.17.9 / fa0bd19)

### Custom Repository — voll funktional ✅
- [x] `hacs.json` vorhanden (cleaned: `category` + `iot_class` raus, gehören in manifest.json)
- [x] `custom_components/openwrt_router/` korrekte Struktur
- [x] `README.md` vorhanden
- [x] `brand/icon.png` (256×256, 16 KB) im Repo-Root UND in `custom_components/openwrt_router/brand/`
- [x] GitHub Releases published (v1.17.5, v1.17.6, v1.17.8, v1.17.9; v1.17.7 nur Tag)
- [x] `hassfest` + `hacs/action` CI Workflows alle grün
- [x] `manifest.json` mit `issue_tracker` + alphabetisch sortiert (hassfest-konform)
- [x] GitHub Topics gesetzt: home-assistant, hacs, openwrt, custom-component, ubus, rpcd, …

### HACS Default Store — noch nicht eingereicht
- [ ] PR an `home-assistant/brands` Repo (für Default-Store-Listing nötig)
- [ ] PR an `hacs/default` Repo
- [ ] HA Core Quality Scale ggf. auf Gold/Platinum erhöhen (aktuell silver)

## Commit-Konventionen

```
feat(sensor): add bandwidth RX/TX sensors
fix(api): handle token expiry with automatic retry
chore(ci): add hassfest GitHub Actions workflow
docs(readme): add DHCP enrichment to roadmap
```

## Branch-Strategie

```
main    → stabile Releases (getaggt)
dev     → aktive Entwicklung
feature/* → neue Features
fix/*   → Bugfixes
```
