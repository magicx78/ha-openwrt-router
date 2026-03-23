# OpenWrt Router – Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)

A production-ready Home Assistant custom integration for [OpenWrt](https://openwrt.org/) routers, communicating via the built-in **ubus / rpcd JSON-RPC API**.

**Current Version:** v1.1.0 — Extended System Monitoring, Platform Info, Advanced Metrics ✅

## Features

### Extended System Monitoring (v1.1.0)
- **System Information**: Platform architecture, OpenWrt version, hostname, model
- **Advanced CPU Metrics**: 1/5/15-minute load averages as percentage
- **Memory Details**: Total, used, free, cached, shared, buffered memory
- **Disk Space**: Total, used, free capacity and usage percentage (all mounts)
- **Temporary Storage (tmpfs)**: Usage tracking for /tmp, /run, /dev/shm, etc.
- **Network Connections**: Active connection count (nf_conntrack integration)

### Monitoring & Status
- **Sensors**: Router uptime, WAN status, connected client count, CPU load (1/5/15min), memory usage, disk/tmpfs stats, firmware version, update status
- **WAN Statistics**: Download/Upload bytes with automatic data source detection
- **Device Tracker**: Track WiFi clients (marks as `not_home` when disconnected)

### Control & Management
- **Switches**: Toggle WiFi radios per SSID (2.4 GHz, 5 GHz, 6 GHz, Guest) with band info and connected client count
- **Button Actions**:
  - Reload WiFi configuration
  - Check for system/addon package updates
  - Perform selective updates (system packages, addons, or both)

### Security & Integration
- **SSL/HTTPS Support**: Secure connections with self-signed certificate support for lab/private networks
- **Diagnostics**: Redacted diagnostic data for bug reports
- **Configuration Flow**: Multi-step setup wizard with protocol selection (HTTP/HTTPS/HTTPS Self-Signed)

## Version & Compatibility

| Version | Release Date | Key Features |
|---------|---|---|
| **1.1.0** | 2026-03-23 | Extended monitoring: CPU/Memory/Disk/tmpfs/Network metrics, Platform info |
| 1.0.8 | 2026-03-20 | Update Management, selective package updates |
| 1.0.7 | 2026-03-20 | SSL/HTTPS Support, self-signed certificates |
| 1.0.6 | 2026-03-20 | Sensor visibility improvements |
| 1.0.5 | 2026-03-20 | WiFi switch UX (band info, client count) |
| 1.0.4 | 2026-03-19 | Sensor display names |
| 1.0.3 | 2026-03-19 | WAN statistics from kernel |
| 1.0.1 | 2026-03-19 | Entity naming consistency |
| 1.0.0 | 2026-03-11 | Initial release |

**Tested on:** OpenWrt 24.10 (Cudy WR3000 v1) | Should work on 19.07+

## Requirements

- OpenWrt **19.07** or newer (tested on 24.10)
- `rpcd` with `rpcd-mod-rpcsys` installed on the router
- HTTP or HTTPS access to the router

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

### Via HACS (Recommended)

**Option 1: Custom Repository** (Current)
1. Open HACS → Integrations → ⋮ → Custom repositories
2. Add `https://github.com/magicx78/ha-openwrt-router` as **Integration**
3. Search for and install **OpenWrt Router**
4. Restart Home Assistant

**Option 2: Default Store** (Coming Soon)
Once PR [#6421](https://github.com/hacs/default/pull/6421) is approved by HACS maintainers, you'll be able to install directly:
1. Open HACS → Integrations → Search for **OpenWrt Router**
2. Install the integration
3. Restart Home Assistant

### Manual Installation

1. Copy `custom_components/openwrt_router/` into your Home Assistant config directory
2. Restart Home Assistant

## Configuration

Add the integration via **Settings → Devices & Services → Add Integration → OpenWrt Router**.

| Field    | Default | Description                                    |
|----------|---------|------------------------------------------------|
| Host     | –       | Router IP address or hostname                  |
| Protocol | HTTP    | Connection protocol: HTTP, HTTPS, or HTTPS Self-Signed |
| Port     | 80*     | HTTP port of the router (auto: 80 for HTTP, 443 for HTTPS) |
| Username | root    | rpcd/ubus username                             |
| Password | –       | rpcd/ubus password                             |

> *Port automatically adjusts based on selected protocol. Can be manually overridden.

## Entities

### Sensors
| Entity | Description |
|--------|-------------|
| `sensor.{hostname}_uptime` | Router uptime |
| `sensor.{hostname}_wan_status` | WAN connection state (up/down) |
| `sensor.{hostname}_connected_clients` | Number of associated WiFi clients |
| `sensor.{hostname}_cpu_load` | CPU load percentage |
| `sensor.{hostname}_memory_usage` | RAM usage percentage |
| `sensor.{hostname}_memory_free` | Free RAM in MB |
| `sensor.{hostname}_wan_ip` | WAN IP address |
| `sensor.{hostname}_wan_download` | WAN RX bytes (from kernel `/sys/class/net/`) |
| `sensor.{hostname}_wan_upload` | WAN TX bytes (from kernel `/sys/class/net/`) |
| `sensor.{hostname}_firmware` | Current firmware version |
| `sensor.{hostname}_update_status` | Update availability ("current" or "available") with package counts |

> Entity IDs use actual router hostname (e.g., `secureap-gateway`). Sensors display localized friendly names in Home Assistant UI.

### Switches
| Entity | Description |
|--------|-------------|
| `switch.{hostname}_{ssid_slug}` | Toggle specific SSID (shows band info: "SSID (2.4 GHz)", "SSID (5 GHz)") |
| `switch.{hostname}_secure_iot` | Example: Toggle "secure-IoT" WiFi (2.4 GHz) |
| `switch.{hostname}_guest_wlan` | Example: Toggle "Guest-WLAN" WiFi (2.4 GHz) |

> One switch per detected SSID with band information and connected client count as attributes. Only created when SSID is detected.

### Device Tracker
One `device_tracker` entity per detected WiFi client (identified by MAC address):
- Marked as `home` when connected
- Marked as `not_home` when disconnected
- Source type: `router`

### Buttons
| Entity | Description |
|--------|-------------|
| `button.{hostname}_reload_wifi` | Trigger WiFi configuration reload |
| `button.{hostname}_check_updates` | Scan for available system/addon package updates |
| `button.{hostname}_perform_updates` | Trigger update process (choose: system, addons, or both) |

## Architecture

```
Config Flow → Config Entry → OpenWrtRuntimeData
                                 ├── api: OpenWrtAPI
                                 └── coordinator: OpenWrtCoordinator (30s poll)
                                           ↕
                                   OpenWrt Router (ubus JSON-RPC HTTP POST /ubus)
```

## Implemented Features ✅

- [x] **v1.0.8**: Update Management (check for updates, selective package updates)
- [x] **v1.0.7**: SSL/HTTPS Support (secure connections, self-signed cert support)
- [x] **v1.0.6**: Sensor visibility (main Sensors section, not Diagnostics)
- [x] **v1.0.5**: WiFi switch UX (band info, connected client count)
- [x] **v1.0.4**: Sensor display names (actual sensor names instead of device hostname)
- [x] **v1.0.3**: WAN statistics (kernel filesystem as authoritative source)
- [x] **v1.0.1**: Entity naming consistency

## Planned Features (Roadmap)

- [ ] Bandwidth monitoring (RX/TX bytes per interface)
- [ ] Per-interface traffic statistics
- [ ] DHCP lease enrichment (client IP addresses in Device Tracker)
- [ ] Per-client online time tracking
- [ ] Link quality metrics (signal/noise per radio)
- [ ] Parental control support

## Contributing

PRs welcome! Please open an issue first for major changes.

## License

MIT
