# OpenWrt Router – Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![Version](https://img.shields.io/badge/version-1.4.0-blue.svg)](https://github.com/magicx78/ha-openwrt-router/releases/tag/v1.4.0)

A production-ready Home Assistant custom integration for [OpenWrt](https://openwrt.org/) routers, communicating via the built-in **ubus / rpcd JSON-RPC API**.

**Current Version:** v1.4.0 — Per-Interface Bandwidth Sensors, Per-Client Online Time, Radio Quality ✅

## Features

### System Monitoring
- **System Information**: Platform architecture, OpenWrt version, hostname, model
- **CPU Metrics**: 1/5/15-minute load averages as percentage
- **Memory Details**: Total, used, free, cached, shared, buffered memory (MB)
- **Disk Space**: Total, used, free capacity and usage percentage
- **Temporary Storage (tmpfs)**: Usage tracking for /tmp, /run, /dev/shm
- **Network Connections**: Active connection count (nf_conntrack)

### Network & Traffic (v1.4.0)
- **Per-Interface Bandwidth Sensors**: Automatic RX/TX byte sensors per network interface (lan, loopback, wan, wan6, ...) — discovered dynamically
- **WAN Statistics**: WAN download/upload bytes, WAN IP, WAN status
- **Radio Signal/Noise**: dBm sensors per WiFi radio (on iwinfo-capable routers)

### WiFi & Clients
- **Switches**: Toggle WiFi radios per SSID (2.4 GHz, 5 GHz, 6 GHz, Guest) with band info and connected client count
- **Device Tracker**: Track WiFi clients by MAC — marked `home`/`not_home` automatically
  - **Per-Client Online Time** (v1.4.0): `connected_since` timestamp attribute per tracked client
  - **DHCP Enrichment**: IP address and hostname from DHCP lease table
  - Signal strength attribute per client

### Management & Control
- **Update Management**: Check for system/addon package updates, perform selective updates
- **Button Actions**: Reload WiFi, Check Updates, Perform Updates
- **SSL/HTTPS**: Secure connections with self-signed certificate support
- **Diagnostics**: Redacted diagnostic export for bug reports
- **Config Flow**: Multi-step setup wizard with protocol selection

## Version History

| Version | Release Date | Key Features |
|---------|---|---|
| **1.4.0** | 2026-04-06 | Per-interface bandwidth sensors, per-client online time, radio signal/noise |
| **1.3.0** | 2026-04-05 | Clean entity IDs, memory sensors (total/used), HACS issue_tracker |
| 1.2.0 | 2026-04 | Entity ID fixes, P1–P8 bug fixes, SSL improvements |
| 1.1.0 | 2026-03-23 | Extended monitoring: CPU/Memory/Disk/tmpfs metrics, platform info |
| 1.0.8 | 2026-03-20 | Update Management, selective package updates |
| 1.0.7 | 2026-03-20 | SSL/HTTPS Support, self-signed certificates |
| 1.0.0 | 2026-03-11 | Initial release |

**Tested on:** OpenWrt 25.12.1 (MediaTek Filogic) | Compatible with 19.07+

## Requirements

- OpenWrt **19.07** or newer (tested on 25.12.1)
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
Once approved by HACS maintainers, you'll be able to install directly from the HACS default store.

### Manual Installation

1. Copy `custom_components/openwrt_router/` into your Home Assistant config directory
2. Restart Home Assistant

## Configuration

Add via **Settings → Devices & Services → Add Integration → OpenWrt Router**.

| Field    | Default | Description |
|----------|---------|-------------|
| Host     | –       | Router IP address or hostname |
| Protocol | HTTP    | HTTP, HTTPS, or HTTPS Self-Signed |
| Port     | 80*     | Auto-adjusts to 443 for HTTPS |
| Username | root    | rpcd/ubus username |
| Password | –       | rpcd/ubus password |

## Entities

### Sensors (Static)
| Entity | Description |
|--------|-------------|
| `sensor.{hostname}_uptime` | Router uptime (formatted) |
| `sensor.{hostname}_wan_status` | WAN connection state |
| `sensor.{hostname}_connected_clients` | Associated WiFi client count |
| `sensor.{hostname}_cpu_load` | 1-min CPU load % |
| `sensor.{hostname}_cpu_load_5_minute` | 5-min CPU load % |
| `sensor.{hostname}_cpu_load_15_minute` | 15-min CPU load % |
| `sensor.{hostname}_memory_total` | Total RAM (MB) |
| `sensor.{hostname}_memory_used` | Used RAM (MB) |
| `sensor.{hostname}_memory_free` | Free RAM (MB) |
| `sensor.{hostname}_memory_usage` | RAM usage % |
| `sensor.{hostname}_memory_cached` | Cached RAM (MB) |
| `sensor.{hostname}_memory_shared` | Shared RAM (MB) |
| `sensor.{hostname}_memory_buffered` | Buffered RAM (MB) |
| `sensor.{hostname}_disk_total` | Disk total (GB) |
| `sensor.{hostname}_disk_used` | Disk used (GB) |
| `sensor.{hostname}_disk_free` | Disk free (GB) |
| `sensor.{hostname}_disk_usage` | Disk usage % |
| `sensor.{hostname}_temporary_storage_*` | tmpfs total/used/free/usage |
| `sensor.{hostname}_wan_ip_address` | WAN IP |
| `sensor.{hostname}_wan_download` | WAN RX bytes |
| `sensor.{hostname}_wan_upload` | WAN TX bytes |
| `sensor.{hostname}_firmware_version` | OpenWrt version |
| `sensor.{hostname}_update_status` | Update availability |
| `sensor.{hostname}_platform_architecture` | CPU architecture |
| `sensor.{hostname}_active_network_connections` | nf_conntrack count |

### Sensors (Dynamic — v1.4.0)
| Entity | Description |
|--------|-------------|
| `sensor.{hostname}_{iface}_rx` | RX bytes for interface (lan, wan, loopback, ...) |
| `sensor.{hostname}_{iface}_tx` | TX bytes for interface |
| `sensor.{hostname}_{iface}_signal` | WiFi radio signal dBm (iwinfo routers) |
| `sensor.{hostname}_{iface}_noise` | WiFi radio noise floor dBm (iwinfo routers) |

### Switches
One switch per detected SSID with band info and connected client count:
- `switch.{hostname}` — 2.4 GHz radio
- `switch.{hostname}_5_ghz` — 5 GHz radio
- `switch.{hostname}_6_ghz` — 6 GHz radio (if present)
- `switch.{hostname}_guest` — Guest SSID (if present)

### Device Tracker
One `device_tracker` entity per detected WiFi client:
- `home` when connected, `not_home` when disconnected
- Attributes: `mac`, `ip_address`, `ssid`, `radio`, `signal`, **`connected_since`** (v1.4.0)

### Buttons
| Entity | Description |
|--------|-------------|
| `button.{hostname}_reload_wifi` | Reload WiFi configuration |
| `button.{hostname}_check_for_updates` | Scan for available updates |
| `button.{hostname}_perform_updates` | Trigger update process |

## Architecture

```
Config Flow → Config Entry → OpenWrtRuntimeData
                                 ├── api: OpenWrtAPI       ← ALL HTTP calls
                                 └── coordinator: OpenWrtCoordinator (30s poll)
                                           ↕
                                   OpenWrt Router (ubus JSON-RPC POST /ubus)
```

**Rule:** Entities never call the API directly. All network calls go through `api.py`.

## Implemented Features ✅

- [x] **v1.4.0**: Per-interface bandwidth sensors (dynamic RX/TX per network interface)
- [x] **v1.4.0**: Per-client online time (`connected_since` attribute in device tracker)
- [x] **v1.4.0**: Radio signal/noise sensors (iwinfo-capable routers)
- [x] **v1.3.0**: Clean entity IDs (no hash suffix), memory total/used sensors
- [x] **v1.2.0**: Bug fixes (P1–P8), SSL improvements, DHCP enrichment
- [x] **v1.1.0**: Extended system monitoring (CPU/Memory/Disk/tmpfs/Platform)
- [x] **v1.0.8**: Update Management (check + perform updates)
- [x] **v1.0.7**: SSL/HTTPS + self-signed certificate support
- [x] **v1.0.5**: WiFi switch UX (band info, client count)
- [x] **v1.0.3**: WAN statistics (kernel source)

## Roadmap

- [ ] Bandwidth rate sensors (bytes/s, not just total)
- [ ] Parental control support
- [ ] Per-interface traffic charts/history

## Contributing

PRs welcome! Please open an issue first for major changes.

## License

MIT
