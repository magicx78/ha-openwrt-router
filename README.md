# OpenWrt Router – Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![Version](https://img.shields.io/badge/version-1.12.0-blue.svg)](https://github.com/magicx78/ha-openwrt-router/releases/tag/v1.12.0)
[![Tests](https://img.shields.io/badge/tests-396%20passing-brightgreen.svg)](https://github.com/magicx78/ha-openwrt-router/actions)

A production-ready Home Assistant custom integration for [OpenWrt](https://openwrt.org/) routers, communicating via the built-in **ubus / rpcd JSON-RPC API**. Supports multi-AP mesh networks with a live topology panel.

---

## Installation

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=magicx78&repository=ha-openwrt-router&category=integration)

**Via HACS (Recommended)**
1. Click the button above — or open HACS → Integrations → ⋮ → Custom repositories
2. Add `https://github.com/magicx78/ha-openwrt-router` as **Integration**
3. Search for and install **OpenWrt Router**
4. Restart Home Assistant

**Manual**
1. Copy `custom_components/openwrt_router/` into your HA config directory
2. Restart Home Assistant

---

## Topology Panel

A built-in network map panel is automatically registered when the integration is set up. It shows your entire mesh network — gateway, APs, wired uplinks, WiFi backhaul, and all connected clients — in a live, interactive view.

### Sidebar views

| Tab | Description |
|-----|-------------|
| **Topology** | Zoom/pan network map with animated edges, traffic overlay, and focus mode |
| **Devices** | Gateway + APs as list rows — status, uplink type, backhaul signal, client count |
| **Clients** | All WiFi clients with search (name / IP / MAC / vendor), band filter, status filter |
| **Alarms** | Only offline or warning devices and clients, grouped |
| **Settings** | HA links, polling interval, GitHub link, about |

### Topology interactions

| Action | Result |
|--------|--------|
| **Click** node | Select — dim others, open Inspector panel on the right |
| **Double-click** node | Zoom to 2× centered on node; double-click again to reset |
| **Right-click** node | Context menu: Focus, Zoom, Clients, VLAN-Overlay, Alerts |
| **Hover** node | Quick-info tooltip — IP, uptime, CPU/RAM, firmware, SSIDs, VLANs |
| **Hover** edge | Link type, signal strength, WAN traffic |
| **Click** AP client count | Inline client list with signal bars and band |
| **Minimap** (bottom-right) | Click to pan canvas; shows all nodes as coloured dots |

### Topology modes (toolbar)

| Toggle | Description |
|--------|-------------|
| ♥ Health | Colour nodes by CPU / RAM / signal — green → amber → red |
| ≋ Heatmap | Signal-strength glow on each AP |
| 👻 Ghost | Show recently-offline devices greyed out |
| VLAN | Highlight edges and nodes by VLAN subnet membership |
| Traffic | Animated flow arrows on links |
| **Group** selector | Organise APs into visual groups: by type, VLAN, or online status |

### Inspector panel (right sidebar)

Opens when a node is clicked. Shows:
- **Gateway**: model, firmware, LAN/WAN IP, uptime, ping, CPU/RAM bars, WAN traffic bars, DSL stats + 24 h chart, SSIDs, ports, VLANs, DDNS status, event timeline
- **Access Point**: model, firmware, IP, uplink type + backhaul signal, CPU/RAM bars, SSIDs, client list, event timeline
- **Client**: hostname, IP, MAC, vendor, band, signal, connected since, DHCP expiry, session traffic, HA device-tracker link

### Event timeline

The Inspector panel shows a per-device event timeline — status changes recorded in memory since the last HA restart:

- WAN connected / disconnected
- CPU spike ≥ 80% / recovery
- RAM spike ≥ 90% / recovery

### Animations

- Nodes animate in/out when filters change (layout transition)
- Status-change flash on online ↔ offline ↔ warning transitions
- Programmatic zoom uses smooth cubic-bezier transition

---

## Features

### System Monitoring
- **System Info**: Platform architecture, OpenWrt version, hostname, model
- **CPU**: 1/5/15-minute load averages as percentage
- **Memory**: Total, used, free, cached, shared, buffered (MB)
- **Disk**: Total, used, free capacity and usage percentage
- **tmpfs**: Monitoring for /tmp, /run, /dev/shm
- **Connections**: Active network connection count (nf_conntrack)
- **TCP Ping**: Round-trip latency to 8.8.8.8:53 in ms

### Network & Traffic
- **Per-Interface Bandwidth**: Dynamic RX/TX byte sensors per network interface (wan, lan, loopback, …)
- **Bandwidth Rate**: RX/TX in bytes/s for real-time monitoring
- **Per-Port Sensors**: Link state, speed, RX/TX bytes per physical Ethernet port
- **WAN Statistics**: WAN download/upload bytes, WAN IP, WAN status
- **Radio Signal/Noise**: dBm sensors per WiFi radio (iwinfo-capable routers)

### Fritz!Box Integration (TR-064)
- **DSL Stats**: Sync speed (down/up kbps), SNR, attenuation, uptime from the Fritz!Box TR-064 API
- **DSL History**: 24-hour rolling chart (1440 data points, 1 per minute)
- **WAN Traffic**: Real-time bytes/s downstream and upstream
- Configured via Options Flow (⚙️ gear icon on the integration entry)

### DDNS / DynDNS
- **DDNS Service Status**: Reads `/etc/config/ddns` — service name, domain, last update, current IP
- **Status**: `ok` / `error` / `unknown` per configured DDNS service

### WiFi & Clients
- **WiFi Switches**: Toggle per SSID with correct SSID + Band label (`OpenWrt (2.4 GHz)`, `Guest (5 GHz)`, …)
- **WiFi Switch Client List**: Each switch exposes a `clients` attribute with all connected clients (name, MAC, IP, signal, online time, DHCP expiry)
- **AP Interface Sensors**: Per-radio channel, frequency, TX power, HT mode, HW mode, client count
- **Device Tracker**: Track WiFi clients by MAC — `home` / `not_home` with IP, hostname, signal, `connected_since`

### Management & Control
- **Service Management**: Start/stop/restart procd system services (dnsmasq, dropbear, firewall, network, uhttpd, wpad)
- **Update Management**: Check for and perform system/package updates
- **Buttons**: Reload WiFi, Check Updates, Perform Updates, Restart Service
- **SSL/HTTPS**: Secure connections with self-signed certificate support
- **Auto-ACL Provisioning**: Automatically deploys the rpcd ACL file via SSH when a router is first added

### Resilience
- **Session renewal**: rpcd sessions request a 24-hour TTL; auto re-login on expiry
- **Retry logic**: exponential backoff on repeated auth failures
- **ACL fallback chain**: automatic fallbacks for every blocked rpcd call

---

## ACL Fallback Support

Works on **ACL-restricted routers** (e.g. Cudy WR3000 on OpenWrt 25) where standard rpcd calls are blocked. All fallback chains are automatic — no manual router configuration required.

| Blocked Call | Fallback |
|---|---|
| `uci/commit` | → `uci/apply` → SSH `uci set + commit + wifi reload` |
| `hostapd.*/get_clients` | → SSH `ubus call` → SSH `iw station dump` (kernel, read-only) |
| `file/read /tmp/dhcp.leases` | → `luci-rpc/getDHCPLeases` |
| `hostapd.*/get_status` (SSID) | → `iwinfo/info` → `luci-rpc/getWirelessDevices` |
| `network.wireless/status` | → `iwinfo/info` → UCI wireless config |

---

## Configuration

Add via **Settings → Devices & Services → Add Integration → OpenWrt Router**.

| Field | Default | Description |
|-------|---------|-------------|
| Host | – | Router IP address or hostname |
| Protocol | HTTP | HTTP, HTTPS, or HTTPS Self-Signed |
| Port | 80* | Auto-adjusts to 443 for HTTPS |
| Username | root | rpcd/ubus username |
| Password | – | rpcd/ubus password |
| SSH Username | – | Optional: for SSH fallback (client counting, WiFi toggle) |
| SSH Password | – | Optional: SSH password |

**Fritz!Box options**: configure via ⚙️ gear icon on the integration entry after setup.

---

## Requirements

- OpenWrt **19.07** or newer (tested on 25.12.1)
- `rpcd` with `rpcd-mod-rpcsys` installed on the router

### Enable rpcd on OpenWrt

```sh
# OpenWrt 25.x (apk)
apk add rpcd rpcd-mod-rpcsys

# OpenWrt 24.x and older (opkg)
opkg update && opkg install rpcd rpcd-mod-rpcsys

uci set rpcd.@rpcd[0].socket='/var/run/ubus/ubus.sock'
uci set rpcd.@rpcd[0].timeout=30
uci commit rpcd
service rpcd restart
```

---

## Entities

### Sensors (Static)
| Entity | Description |
|--------|-------------|
| `sensor.{name}_uptime` | Router uptime |
| `sensor.{name}_wan_status` | WAN connection state |
| `sensor.{name}_connected_clients` | Total WiFi client count |
| `sensor.{name}_cpu_load` | 1-min CPU load % |
| `sensor.{name}_cpu_load_5_minute` | 5-min CPU load % |
| `sensor.{name}_cpu_load_15_minute` | 15-min CPU load % |
| `sensor.{name}_memory_*` | RAM details (MB / %) |
| `sensor.{name}_disk_*` | Disk details (GB / %) |
| `sensor.{name}_temporary_storage_*` | tmpfs usage |
| `sensor.{name}_wan_ip_address` | WAN IP |
| `sensor.{name}_wan_download/upload` | WAN RX/TX bytes |
| `sensor.{name}_firmware_version` | OpenWrt version |
| `sensor.{name}_ping_ms` | TCP latency to 8.8.8.8:53 |
| `sensor.{name}_update_status` | Update availability |
| `sensor.{name}_active_network_connections` | nf_conntrack count |
| `sensor.{name}_dsl_*` | DSL sync speed, SNR, attenuation (Fritz!Box) |
| `sensor.{name}_wan_traffic_*` | WAN bytes/s down/up (Fritz!Box) |
| `sensor.{name}_ddns_*` | DDNS service status and last IP |

### Sensors (Dynamic)
| Entity | Description |
|--------|-------------|
| `sensor.{name}_{iface}_rx/tx` | RX/TX bytes per interface |
| `sensor.{name}_{iface}_rx_rate/tx_rate` | RX/TX bytes/s |
| `sensor.{name}_{iface}_signal/noise` | WiFi signal/noise dBm |
| `sensor.{name}_{iface}_channel` | WiFi channel |
| `sensor.{name}_{iface}_ap_clients` | Clients per radio |
| `sensor.{name}_{port}_link/speed/rx/tx` | Per-port Ethernet stats |

> **Traffic Charts**: RX/TX byte sensors use `state_class: total_increasing` — add to a **Statistics card** or **Energy Dashboard** for traffic history graphs.

### Switches
- **WiFi Switches**: one per SSID — `switch.{ssid}_2_4_ghz`, `switch.{ssid}_5_ghz`, `switch.{ssid}_6_ghz`
- **Service Switches**: `switch.service_{name}` for dnsmasq, dropbear, firewall, network, uhttpd, wpad

### Buttons
| Entity | Description |
|--------|-------------|
| `button.{name}_reload_wifi` | Reload WiFi configuration |
| `button.{name}_check_for_updates` | Scan for available updates |
| `button.{name}_perform_updates` | Trigger update process |
| `button.restart_{service}` | Restart system service |

### Device Tracker
One entity per WiFi client — `home` / `not_home` with attributes: `mac`, `ip_address`, `hostname`, `ssid`, `radio`, `signal`, `connected_since`.

---

## Architecture

```
Config Flow → Config Entry → OpenWrtRuntimeData
                                 ├── api: OpenWrtAPI       ← ALL HTTP/SSH calls
                                 └── coordinator: OpenWrtCoordinator (30 s poll)
                                           ↕
                                   OpenWrt Router (ubus JSON-RPC POST /ubus)

Topology Panel (sidebar)
  └── /api/openwrt_topology/snapshot  ← aggregates all coordinator data
        └── topology_mesh.py          ← multi-router mesh view
```

**Rule:** Entities never call the API directly. All network calls go through `api.py`.

---

## Version History

| Version | Date | Key Features |
|---------|------|---|
| **1.12.0** | 2026-04-19 | Full topology UI/UX spec: minimap, context menus, health mode, event timeline, group mode, inspector mini-charts, firmware version, zoom-to-node, status animations |
| **1.11.1** | 2026-04-16 | 24h rpcd session timeout; DDNS skip for devices without DDNS; ruff CI fix |
| **1.11.0** | 2026-04-15 | Client Detail Panel (IP, band, connected since, lease expiry, HA link) |
| **1.10.1** | 2026-04-14 | Topology panel 5 views; edge tooltip; Phase 2 UI; Fritz!Box TR-064 fix |
| **1.9.2** | 2026-04-07 | WiFi switch `clients` attribute — per-client name, MAC, IP, signal, DHCP expiry |
| **1.9.0** | 2026-04-06 | Full ACL fallback chain; WiFi switch SSID+Band label |
| **1.8.0** | 2026-04-06 | AP interface sensors (channel, mode, htmode, ap_clients) |
| **1.7.0** | 2026-04-06 | Service management (start/stop/restart) |
| **1.6.0** | 2026-04-06 | Bandwidth rate sensors (bytes/s) |
| **1.4.0** | 2026-04-06 | Per-interface bandwidth; per-client online time; radio signal/noise |
| **1.2.0** | 2026-04 | Full test suite (247 tests); CI/CD pipelines; HACS icon |
| **1.0.0** | 2026-03-11 | Initial release |

**Tested on:** OpenWrt 25.12.1 (MediaTek Filogic, Cudy WR3000 v1) | Compatible with OpenWrt 19.07+

---

## Roadmap

- [ ] HACS Default Store submission
- [ ] Parental control support
- [ ] Shift+click multi-device compare in topology
- [ ] Persistent event history (survive HA restarts)
- [ ] Per-client traffic history chart

---

## Contributing

PRs welcome! Please open an issue first for major changes.

## License

MIT
