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
│   ├── __init__.py          # async_setup_entry, async_unload_entry
│   ├── manifest.json        # domain, version, requirements
│   ├── const.py             # DOMAIN, Defaults, Konfig-Keys
│   ├── api.py               # ALLE Netzwerkaufrufe — OpenWrtAPI Klasse
│   ├── coordinator.py       # OpenWrtCoordinator (DataUpdateCoordinator)
│   ├── config_flow.py       # UI Setup Wizard
│   ├── entity.py            # OpenWrtEntity Basisklasse
│   ├── sensor.py            # Uptime, WAN Status, Client Count
│   ├── switch.py            # WiFi Radios (2.4/5/6 GHz, Guest)
│   ├── device_tracker.py    # WiFi Clients per MAC
│   ├── button.py            # WiFi Reload
│   ├── diagnostics.py       # Redacted diagnostics
│   ├── strings.json         # UI Strings
│   └── translations/en.json
├── tests/
│   ├── conftest.py
│   ├── test_api.py
│   ├── test_coordinator.py
│   └── test_config_flow.py
├── scripts/
├── .github/workflows/
│   ├── hassfest.yaml        # HA manifest validation
│   ├── hacs.yaml            # HACS validation
│   └── tests.yaml           # pytest
├── brand/
│   └── icon.png             # 256x256px — für HACS Default Store
├── hacs.json
├── README.md
└── CHANGELOG.md
```

## Architektur — Eiserne Regeln

```
api.py          ← ALLE HTTP-Calls. Nie woanders.
coordinator.py  ← Polling (30s), Fehlerbehandlung, Daten-Distribution
entity.py       ← Basisklasse: device_info, unique_id
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

## HACS Status

- [x] `hacs.json` vorhanden
- [x] `custom_components/openwrt_router/` korrekte Struktur
- [x] `README.md` vorhanden
- [ ] `brand/icon.png` fehlt noch (256×256px)
- [ ] GitHub Release noch nicht published (nur Tag)
- [ ] `hassfest` + `hacs/action` CI Workflows fehlen noch
- [ ] `manifest.json` braucht `issue_tracker` Key

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
