# OpenWrt Router – Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![HA Version](https://img.shields.io/badge/Home%20Assistant-2024.1%2B-blue)](https://www.home-assistant.io/)

A custom Home Assistant integration for OpenWrt routers using ubus / rpcd JSON-RPC.

## Features

- **Sensors**: Uptime, WAN status, connected client count
- **Switches**: WiFi 2.4 GHz, 5 GHz, 6 GHz, Guest WiFi (auto-detected)
- **Device Tracker**: All associated WiFi clients (marks as `not_home` when disconnected)
- **Button**: Reload WiFi configuration
- **Diagnostics**: Safe diagnostic dump (passwords/tokens redacted)

## Requirements

- OpenWrt 19.07 or later (tested on 24.10)
- `rpcd` and `uhttpd` running on the router
- A user with ubus access (usually `root`)

## Installation via HACS

1. In HACS → Integrations → ⋮ → Custom repositories
2. Add: `https://github.com/YOUR_GITHUB_USERNAME/ha-openwrt-router` (Category: Integration)
3. Install "OpenWrt Router"
4. Restart Home Assistant

## Manual Installation

1. Copy `custom_components/openwrt_router/` to your HA `config/custom_components/` folder
2. Restart Home Assistant
3. Go to **Settings → Devices & Services → Add Integration → OpenWrt Router**

## Configuration

| Field    | Default | Description                        |
|----------|---------|------------------------------------|
| Host     | –       | Router IP or hostname              |
| Port     | 80      | HTTP port                          |
| Username | root    | rpcd username                      |
| Password | –       | Router password                    |

## Architecture

```
Config Flow → Config Entry → DataUpdateCoordinator (30s) → Entities
                                        ↕
                                    OpenWrtAPI
                                        ↕
                             OpenWrt Router (ubus/rpcd)
```

## Roadmap / TODOs

- [ ] Bandwidth sensors (RX/TX per interface)
- [ ] Traffic statistics
- [ ] Per-client online time
- [ ] Parental control support
- [ ] Link quality metrics
- [ ] HTTPS support
- [ ] Options flow (custom scan interval)

## Contributing

Pull requests welcome! Please open an issue first for major changes.

## License

MIT
