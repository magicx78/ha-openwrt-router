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
│   ├── acl_provisioning.py     # rpcd ACL v8 (ensure_acl_respecting_offer) + tiered ACL v9 offer
│   ├── enterprise_core.py      # Enterprise Core lifecycle (setup/unload/remove hooks, flush)
│   ├── core_models.py          # Core contract: constants, enums, dataclasses, pure rules, protocols
│   ├── core_errors.py          # ErrorClass + ConfigApiError hierarchy
│   ├── core_masking.py         # The one secret masking (mask_secrets, mask_for_output, redact_text)
│   ├── core_store.py           # Store helper (.bak + rebuild, private/atomic)
│   ├── core_audit.py           # Audit log: general + security ring, bus event, dedup
│   ├── core_guard.py           # ActionGuard: verified actors, approvals, WriteAuthorization ledger
│   ├── core_security.py        # SSH host-key pins per router + ACL-deploy / pin approval flows
│   ├── router_identity.py      # Router identity + fingerprint from coordinator.data
│   ├── router_registry.py      # Stable router ids, fleet registry, adoption, capability detectors
│   ├── capabilities.py         # Capability derivation (transport/data/stream/pkg/config/rf)
│   ├── version_store.py        # Config version store (files, GFS retention, archive on removal)
│   ├── config_api.py           # Configuration API v1 (ConfigurationManager, provider calls)
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
│   ├── core_testkit.py / core_test_provider.py  # Enterprise Core fakes (hass, stores, provider)
│   ├── test_enterprise_core_v144.py  # 1.44.0: ACL offer, rf caps, option, SSH pins, docking
│   ├── test_memory_leak_v1178.py    # Heap + RSS regression checks
│   ├── test_sshpass_security_v1179.py  # No '-p <pw>' in argv
│   └── …                       # 3978 Tests total (1.44.0)
├── scripts/                    # mock_router.py, dev_start.py, _dev_rss_sample.sh, …
├── .github/workflows/
│   ├── hassfest.yaml           # HA manifest validation
│   ├── hacs.yaml               # HACS validation
│   ├── tests.yaml              # ruff check + ruff format + pytest (3.12, 3.13)
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
