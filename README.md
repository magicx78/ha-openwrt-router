# OpenWrt Router – Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![Version](https://img.shields.io/badge/version-1.9.2-blue.svg)](https://github.com/magicx78/ha-openwrt-router/releases/tag/v1.9.2)

A production-ready Home Assistant custom integration for [OpenWrt](https://openwrt.org/) routers, communicating via the built-in **ubus / rpcd JSON-RPC API**.

**Current Version:** v1.9.2 — WiFi switch client list (name, MAC, IP, DHCP expiry, signal) ✅

---

## Features

### System Monitoring
- **System Information**: Platform architecture, OpenWrt version, hostname, model
- **CPU Metrics**: 1/5/15-minute load averages as percentage
- **Memory Details**: Total, used, free, cached, shared, buffered memory (MB)
- **Disk Space**: Total, used, free capacity and usage percentage
- **Temporary Storage (tmpfs)**: Usage tracking for /tmp, /run, /dev/shm
- **Network Connections**: Active connection count (nf_conntrack)

### Network & Traffic
- **Per-Interface Bandwidth Sensors**: Automatic RX/TX byte sensors per network interface (lan, loopback, wan, wan6, …) — discovered dynamically
- **Bandwidth Rate Sensors** (v1.6.0): RX/TX in bytes/s for real-time traffic monitoring
- **WAN Statistics**: WAN download/upload bytes, WAN IP, WAN status
- **Radio Signal/Noise**: dBm sensors per WiFi radio (on iwinfo-capable routers)

### WiFi & Clients
- **WiFi Switches**: Toggle per SSID with correct **SSID + Band** label — `OpenWrt (2.4 GHz)`, `OpenWrt (5 GHz)`, `Guest-WLAN (2.4 GHz)`, etc.
- **WiFi Switch Client List** (v1.9.2): Each switch exposes a `clients` attribute with all connected clients showing name, MAC, IP, signal strength, online time and remaining DHCP lease time
- **AP Interface Sensors** (v1.8.0): Per-radio channel, frequency, TX power, HT mode, HW mode, connected client count
- **Device Tracker**: Track WiFi clients by MAC — marked `home`/`not_home` automatically
  - **Per-Client Online Time** (v1.4.0): `connected_since` timestamp per tracked client
  - **DHCP Enrichment**: IP address and hostname from DHCP lease table
  - Signal strength attribute per client

### Management & Control
- **Service Management** (v1.7.0): Monitor and control procd/rc system services
  - Start/Stop switches: `dnsmasq`, `dropbear`, `firewall`, `network`, `uhttpd`, `wpad`
  - Restart buttons per service — auto-discovered from router
- **Update Management**: Check for system/package updates, perform selective updates
- **Button Actions**: Reload WiFi, Check Updates, Perform Updates
- **SSL/HTTPS**: Secure connections with self-signed certificate support
- **Diagnostics**: Redacted diagnostic export for bug reports
- **Config Flow**: Multi-step setup wizard with protocol selection

---

## WiFi Switch Client List (v1.9.2)

Each WiFi switch now exposes a `clients` attribute listing every device currently connected to that SSID:

```yaml
# Example: switch.secure_iot_2_4_ghz attributes
ssid: "secure-IoT"
band: "2.4g"
connected_clients: 8
clients:
  - name: "mein-laptop"               # hostname from DHCP, falls back to MAC
    mac: "B8:27:EB:AA:BB:01"
    ip: "192.168.1.101"
    signal_dbm: -55
    connected_since: "2026-04-07T10:00:00+00:00"
    dhcp_expires: "11h 42m"           # remaining DHCP lease time
  - name: "B8:27:EB:CC:DD:EE"         # no hostname → MAC shown
    mac: "B8:27:EB:CC:DD:EE"
    ip: "192.168.1.108"
    signal_dbm: -72
    connected_since: "2026-04-07T11:15:00+00:00"
    dhcp_expires: "23h 58m"
```

**Display in HA**: Open the switch entity detail page → scroll to Attributes. Or use a Markdown card:
```yaml
type: markdown
content: |
  {% for c in state_attr('switch.secure_iot_2_4_ghz', 'clients') %}
  **{{ c.name }}** — {{ c.ip }} — {{ c.signal_dbm }} dBm — expires {{ c.dhcp_expires }}
  {% endfor %}
```

---

## ACL Fallback Support (v1.9.x)

This integration works on **ACL-restricted routers** (e.g. Cudy WR3000 on OpenWrt 25) where standard rpcd calls are blocked. All fallback chains are automatic — no router configuration required.

| Blocked Call | Fallback |
|---|---|
| `uci/commit` | → `uci/apply` → SSH `uci set + commit + wifi reload` |
| `hostapd.*/get_clients` | → SSH `ubus call` → SSH `iw station dump` (read-only) |
| `file/read /tmp/dhcp.leases` | → `luci-rpc/getDHCPLeases` |
| `hostapd.*/get_status` (SSID lookup) | → `iwinfo/info` → `luci-rpc/getWirelessDevices` |
| `network.wireless/status` | → `iwinfo/info` → UCI wireless config |

> **Read-only SSH**: The `iw dev {iface} station dump` fallback reads directly from the kernel nl80211 layer — no ubus socket access required.

---

## Version History

| Version | Date | Key Features |
|---------|------|---|
| **1.9.2** | 2026-04-07 | WiFi switch `clients` attribute — per-client name, MAC, IP, signal, DHCP expiry |
| **1.9.1** | 2026-04-07 | Fix `OpenWrtAuthError` bypass of `uci/apply`; `iw` read-only SSH fallback for clients |
| **1.9.0** | 2026-04-06 | WiFi switch shows SSID+Band correctly; full ACL fallback chain |
| **1.8.0** | 2026-04-06 | AP Interface Sensors (channel, mode, htmode, ap_clients); UCI fallback |
| **1.7.0** | 2026-04-06 | Service management (start/stop/restart); OpenWrt 25 bugfixes |
| **1.6.0** | 2026-04-06 | Bandwidth rate sensors (bytes/s); traffic chart support |
| **1.5.0** | 2026-04-06 | QA strategy, regression tests, ruff CI |
| **1.4.0** | 2026-04-06 | Per-interface bandwidth sensors; per-client online time; radio signal/noise |
| 1.3.0 | 2026-04-05 | Clean entity IDs; memory total/used; HACS issue_tracker |
| 1.2.0 | 2026-04 | Entity ID fixes; P1–P8 bug fixes; SSL improvements |
| 1.1.0 | 2026-03-23 | Extended monitoring: CPU/Memory/Disk/tmpfs |
| 1.0.8 | 2026-03-20 | Update Management |
| 1.0.7 | 2026-03-20 | SSL/HTTPS support |
| 1.0.0 | 2026-03-11 | Initial release |

**Tested on:** OpenWrt 25.12.1 (MediaTek Filogic, Cudy WR3000) | Compatible with 19.07+

---

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

---

## Installation

### Via HACS (Recommended)

**Option 1: Custom Repository**
1. Open HACS → Integrations → ⋮ → Custom repositories
2. Add `https://github.com/magicx78/ha-openwrt-router` as **Integration**
3. Search for and install **OpenWrt Router**
4. Restart Home Assistant

**Option 2: Default Store** (Coming Soon)

### Manual Installation

1. Copy `custom_components/openwrt_router/` into your HA config directory
2. Restart Home Assistant

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

> **SSH Fallback**: Configure SSH credentials to enable fallback for routers with restricted rpcd ACL. Only read access is needed for client counting (`iw station dump`). Write access enables WiFi toggle fallback.

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
| `sensor.{name}_memory_total/used/free/usage/cached/shared/buffered` | RAM details (MB/%) |
| `sensor.{name}_disk_total/used/free/usage` | Disk details (GB/%) |
| `sensor.{name}_temporary_storage_*` | tmpfs usage |
| `sensor.{name}_wan_ip_address` | WAN IP |
| `sensor.{name}_wan_download/upload` | WAN RX/TX bytes |
| `sensor.{name}_firmware_version` | OpenWrt version |
| `sensor.{name}_update_status` | Update availability |
| `sensor.{name}_platform_architecture` | CPU architecture |
| `sensor.{name}_active_network_connections` | nf_conntrack count |

### Sensors (Dynamic)
| Entity | Description |
|--------|-------------|
| `sensor.{name}_{iface}_rx/tx` | RX/TX bytes per interface |
| `sensor.{name}_{iface}_rx_rate/tx_rate` | RX/TX bytes/s (v1.6.0) |
| `sensor.{name}_{iface}_signal/noise` | WiFi signal/noise dBm (iwinfo) |
| `sensor.{name}_{iface}_channel` | WiFi channel (v1.8.0) |
| `sensor.{name}_{iface}_mode` | AP mode: Master/Client (v1.8.0) |
| `sensor.{name}_{iface}_ap_clients` | Clients per radio (v1.8.0) |
| `sensor.{name}_{iface}_frequency` | Frequency in MHz (v1.8.0) |
| `sensor.{name}_{iface}_ht_mode` | HT/VHT/HE mode (v1.8.0) |

> **Traffic Charts**: RX/TX byte sensors use `state_class: total_increasing` — add to a **Statistics card** or **Energy Dashboard** for traffic history graphs.

### Switches

**WiFi Switches** — one per detected SSID, label shows **SSID + Band**:
- `switch.{ssid}_2_4_ghz` — e.g. `OpenWrt (2.4 GHz)`
- `switch.{ssid}_5_ghz` — e.g. `OpenWrt (5 GHz)`
- `switch.{ssid}_6_ghz` — 6 GHz (if present)
- Guest SSIDs with `mdi:wifi-star` icon

Each WiFi switch has these attributes:

| Attribute | Description |
|-----------|-------------|
| `ssid` | Network name |
| `band` | Band code (`2.4g`, `5g`, `6g`) |
| `connected_clients` | Number of connected clients |
| `clients` | List of connected clients (name, mac, ip, signal_dbm, connected_since, dhcp_expires) |
| `ifname` | Interface name (e.g. `phy0-ap0`) |
| `uci_section` | UCI section name |
| `is_guest` | Guest network flag |

**Service Switches** — `switch.service_{name}` for dnsmasq, dropbear, firewall, network, uhttpd, wpad

### Device Tracker
One entity per WiFi client:
- `home` when connected, `not_home` when disconnected
- Attributes: `mac`, `ip_address`, `hostname`, `ssid`, `radio`, `signal`, `connected_since`

### Buttons
| Entity | Description |
|--------|-------------|
| `button.{name}_reload_wifi` | Reload WiFi configuration |
| `button.{name}_check_for_updates` | Scan for available updates |
| `button.{name}_perform_updates` | Trigger update process |
| `button.restart_{service}` | Restart dnsmasq / dropbear / firewall / … |

---

## Architecture

```
Config Flow → Config Entry → OpenWrtRuntimeData
                                 ├── api: OpenWrtAPI       ← ALL HTTP/SSH calls
                                 └── coordinator: OpenWrtCoordinator (30s poll)
                                           ↕
                                   OpenWrt Router (ubus JSON-RPC POST /ubus)
```

**Rule:** Entities never call the API directly. All network calls go through `api.py`.

---

## Roadmap

- [ ] Parental control support
- [ ] Per-interface traffic history (long-term statistics)
- [ ] HACS Default Store submission

---

## Contributing

PRs welcome! Please open an issue first for major changes.

## License

MIT
