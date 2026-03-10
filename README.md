# OpenWrt Router – Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)

A Home Assistant custom integration for [OpenWrt](https://openwrt.org/) routers, communicating via the built-in **ubus / rpcd JSON-RPC API**.

## Features

- **Sensors**: Router uptime, WAN status, connected client count
- **Switches**: Toggle WiFi radios (2.4 GHz, 5 GHz, 6 GHz, Guest)
- **Device Tracker**: Track WiFi clients (marks as `not_home` when disconnected)
- **Button**: Reload WiFi configuration
- **Diagnostics**: Redacted diagnostic data for bug reports

## Requirements

- OpenWrt **19.07** or newer (tested on 24.10)
- `rpcd` with `rpcd-mod-rpcsys` installed on the router
- HTTP access to the router (port 80 by default)

### Enable rpcd on OpenWrt

```sh
opkg update
opkg install rpcd rpcd-mod-rpcsys
uci set rpcd.@rpcd[0].socket='/var/run/ubus/ubus.sock'
uci set rpcd.@rpcd[0].timeout=30
uci commit rpcd
service rpcd restart
```

## Installation

### Via HACS (recommended)

1. Open HACS → Integrations → ⋮ → Custom repositories
2. Add `https://github.com/YOUR_USERNAME/ha-openwrt-router` as **Integration**
3. Install **OpenWrt Router**
4. Restart Home Assistant

### Manual

1. Copy `custom_components/openwrt_router/` into your HA config directory
2. Restart Home Assistant

## Configuration

Add the integration via **Settings → Devices & Services → Add Integration → OpenWrt Router**.

| Field    | Default | Description                     |
|----------|---------|---------------------------------|
| Host     | –       | Router IP address or hostname   |
| Port     | 80      | HTTP port of the router         |
| Username | root    | rpcd/ubus username              |
| Password | –       | rpcd/ubus password              |

## Entities

### Sensors
| Entity | Description |
|--------|-------------|
| `sensor.openwrt_uptime` | Router uptime in seconds |
| `sensor.openwrt_wan_status` | WAN connection state |
| `sensor.openwrt_connected_clients` | Number of associated WiFi clients |

### Switches
| Entity | Description |
|--------|-------------|
| `switch.openwrt_wifi_2_4ghz` | Enable/disable 2.4 GHz radio |
| `switch.openwrt_wifi_5ghz` | Enable/disable 5 GHz radio |
| `switch.openwrt_wifi_6ghz` | Enable/disable 6 GHz radio (if available) |
| `switch.openwrt_guest_wifi` | Enable/disable guest SSID |

> Switches are only created when the corresponding radio/SSID is detected.

### Device Tracker
One `device_tracker` entity is created per detected WiFi client (identified by MAC address).

### Button
| Entity | Description |
|--------|-------------|
| `button.openwrt_reload_wifi` | Trigger a WiFi configuration reload |

## Architecture

```
Config Flow → Config Entry → OpenWrtRuntimeData
                                 ├── api: OpenWrtAPI
                                 └── coordinator: OpenWrtCoordinator (30s poll)
                                           ↕
                                   OpenWrt Router (ubus JSON-RPC HTTP POST /ubus)
```

## Known Limitations / TODO

- Bandwidth sensors (RX/TX bytes per interface) — planned
- Traffic statistics — planned
- DHCP lease enrichment (client IP addresses) — partial stub
- Per-client online time — planned
- Link quality metrics (signal/noise per radio) — planned
- Parental control support — planned
- HTTPS support — planned

## Contributing

PRs welcome! Please open an issue first for major changes.

## License

MIT
