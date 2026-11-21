# ha-openwrt-router — Claude Code Context

## Projekt

Home Assistant custom integration für OpenWrt Router via ubus/rpcd JSON-RPC.
GitHub: https://github.com/magicx78/ha-openwrt-router
Domain: `openwrt_router`
HACS: Custom Repository (Ziel: Default Store)
Stand: Version 1.50.0 (2026-11-21)

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
│   ├── topology.py             # Per-Router topology snapshot (legacy)
│   ├── topology_diagnostic.py  # Snapshot builder per router
│   ├── topology_mesh.py        # Multi-router mesh aggregator + edge detection
│   ├── topology_entities.py    # Topology-related entities
│   ├── topology_panel.py       # Sidebar panel registration + API view (_PANEL_VERSION)
│   │   # Enterprise-Module (je Option ein/aus):
│   ├── enterprise_core.py, core_*.py     # Core: Router-Identität, Registry, Audit, Guard, Maskierung (core_masking)
│   ├── config_*.py             # Config Manager: Backups, Diff, Restore (config_manager, config_provider, config_views)
│   ├── security_*.py           # Security Center (security_center, security_model, security_rules, security_views)
│   ├── diag_*.py               # Netzwerkdiagnose (diag_runtime, diag_core, diag_chain, diag_views)
│   ├── rf_*.py, wifi_rf_entities.py  # WiFi RF Intelligence (rf_center, rf_collector, rf_privacy, rf_views)
│   ├── traffic_*.py            # Traffic Analytics (traffic_engine, traffic_output, traffic_views)
│   ├── net_*.py                # Network Intelligence (net_engine, net_rules, net_query)
│   ├── tm_*.py                 # Network Time Machine Phase A (tm_sources, tm_query, tm_views); Tab „Zeitreise“ in frontend/…/enterprise/timemachine
│   ├── strings.json            # UI Strings
│   ├── translations/en.json
│   ├── brand/                  # icon.png + icon.svg (für HACS Validation)
│   └── frontend/               # React/TS Topology Panel
│       ├── dist/topology-bundle.js   # Built bundle (~813 kB), eingecheckt
│       └── topology/src/             # Vite project (App, components/, utils/, enterprise/)
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
│   ├── test_wifi_switch_ids_v1492.py   # rpcd-getreues Router-Modell + Aufrufliste 1.47.1
│   ├── test_unique_ids_snapshot_v1494.py  # 130 unique_ids eines Gateways (Grenzen im Docstring)
│   ├── full_router_kit.py      # Gateway-Modell: volle ubus-Poll-Daten + rpcd-getreues WLAN
│   └── …                       # rund 8 900 Tests (1.50.0)
├── scripts/                    # mock_router.py, dev_start.py, _dev_rss_sample.sh, …
├── .github/workflows/
│   ├── hassfest.yaml           # HA manifest validation
│   ├── hacs.yaml               # HACS validation
│   ├── tests.yaml              # ruff check + ruff format + pytest (3.13, 3.14)
│   ├── ha-compat.yaml          # HA version compatibility matrix
│   └── release.yaml            # Auto release on main push (gated: tests + hassfest)
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
coordinator.py  ← Polling (60s, adaptiv: 120s bei CPU-Last, 300s bei SSH-Fallback)
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
- Empfänger an `async_dispatcher_connect` sind `@callback`-Funktionen oder
  Coroutinen, nie ein Lambda.

## Lehren aus 1.49.x

- Änderungen an Router-Aufrufen in `api.py` oder an unique_ids brauchen einen
  Test gegen die aufgezeichnete Aufrufliste bzw. die unique_ids des vorigen
  Release-Stands (`tests/test_wifi_switch_ids_v1492.py`,
  `tests/test_unique_ids_snapshot_v1494.py`).
- `tests/test_unique_ids_snapshot_v1494.py` hält 130 unique_ids eines Gateways fest
  (Modell `tests/full_router_kit.py`, zwei Polls ohne SSH): 109 bei ausgeschalteten
  Enterprise-Modulen (statische, WAN-, Schnittstellen-, Port-, AP- und DHCP-Pool-Sensoren,
  WLAN- und Dienst-Schalter, Device Tracker, Buttons, Binärsensoren), 12 WLAN-unique_ids
  des iwinfo-Wegs (Schalter nach ifname, Rausch-/Signal-Sensoren), 9 mit Traffic. Nicht
  abgedeckt: WiFi RF, Netzwerkdiagnose, Security Center, Configuration Manager, Network
  Intelligence, Client-Stabilität, Traffic-Client-Sensoren, `…_hwmode`, WLAN über
  `network.wireless`/SSH. Neue Entitätsarten dort ergänzen.
- Das Test-Router-Modell verhält sich wie echtes rpcd: `iwinfo info {}` ohne
  `device` → Status 2 (Invalid argument), kein `network.wireless`.
- Frontend neu gebaut → `_PANEL_VERSION` auf einen nie ausgelieferten Wert
  setzen, sonst behalten Browser das alte Bundle.

## Geplante Features

Siehe [TODO.md](TODO.md) — Bandwidth/Traffic, DHCP-Enrichment und HTTPS sind
inzwischen ausgeliefert; offen sind u. a. Repairs-Migration, Notification-i18n,
Per-Client-Online-Zeit, Link-Quality, Parental Control.

## HACS Status (Stand v1.20.0, 2026-07)

### Custom Repository — voll funktional ✅
- [x] `hacs.json` vorhanden (cleaned: `category` + `iot_class` raus, gehören in manifest.json)
- [x] `custom_components/openwrt_router/` korrekte Struktur
- [x] `README.md` vorhanden
- [x] `brand/icon.png` (256×256, 16 KB) im Repo-Root UND in `custom_components/openwrt_router/brand/`
- [x] GitHub Releases published (v1.17.5, v1.17.6, v1.17.8, v1.17.9; v1.17.7 nur Tag)
- [x] `hassfest` + `hacs/action` CI Workflows alle grün
- [x] `manifest.json` mit `issue_tracker` + alphabetisch sortiert (hassfest-konform)
- [x] GitHub Topics gesetzt: home-assistant, hacs, openwrt, custom-component, ubus, rpcd, …

### HACS Default Store — erster Anlauf geschlossen
- [x] PR an `hacs/default` eingereicht (#6421, 2026-03-20) — **2026-03-21 ungemerged
      geschlossen**; Neuanlauf siehe HACS_REGISTRATION.md
- [ ] PR an `home-assistant/brands` Repo (für Default-Store-Listing nötig)
- [ ] Neu-Einreichung nach aktuellem HACS-Prozess (hacs.xyz/docs/publish)

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
