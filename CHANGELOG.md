# Changelog

All notable changes to the OpenWrt Router integration will be documented in this file.

## [1.0.8] - 2026-03-20

### Added
- **Update Management Feature**: Check and perform system/addon package updates
  - "Check for Updates" button: Detects available system packages and addons
  - "Perform Updates" button: Triggers package updates on the router
  - "Update Status" sensor: Shows if updates are available with package counts as attributes
  - Support for selective updates: system packages, addons, or both
  - Proper categorization of updates by type (system vs addon/LuCI packages)

---

## [1.0.7] - 2026-03-20

### Added
- **SSL/HTTPS Support**: Secure connections to OpenWrt routers
  - Config Flow with Protocol Dropdown: HTTP, HTTPS, HTTPS Self-Signed
  - Automatic port adjustment (80 for HTTP, 443 for HTTPS)
  - Self-signed certificate support for private/lab networks
  - Proper SSL context with certificate validation for production use
  - Token transmission now protected over HTTPS when enabled

---

## [1.0.6] - 2026-03-20

### Changed
- **Sensor Visibility**: Move sensors from "Diagnose" to main "Sensoren" section
  - Uptime, Memory Free, WAN IP, Firmware now appear in Sensors (not Diagnostics)
  - Better UX: All important metrics visible without expanding Diagnostics
  - Devices in Home Assistant now show sub-entities under Sensors

---

## [1.0.5] - 2026-03-20

### Changed
- **WiFi Switch Display Enhanced**: Switches now show band information and connected client count
  - Switch names now display: "secure-IoT (2.4 GHz)" instead of just "secure-IoT"
  - Band information (2.4 GHz, 5 GHz, 6 GHz) automatically appended
  - Connected client count visible in switch attributes: "connected_clients"
  - Better UX for managing multiple WiFi networks

---

## [1.0.4] - 2026-03-19

### Fixed
- **Sensor Display Names**: Sensors now show their actual names instead of device hostname
  - Changed `_attr_has_entity_name` from True to False in sensor.py
  - Sensors now display: "WAN Status", "CPU Load", "Memory Usage", "Connected Clients" etc.
  - Previously all sensors showed "sECUREaP-gATEWAy" (the device name)

---

## [1.0.3] - 2026-03-19

### Fixed
- **WAN RX/TX Bytes Now Show Actual Data**: Fixed issue where WAN Download/Upload sensors showed "unavailable"
  - Changed from reading `network.interface/dump` to directly reading `/sys/class/net/{interface}/statistics/`
  - Uses kernel filesystem as source of truth for interface statistics
  - Works on routers like Cudy WR3000 where stats may not be included in network interface dump
  - Example: Now shows actual 93.9 GB RX / 1.9 GB TX instead of unavailable

---

## [1.0.2] - 2026-03-19

### Fixed
- **WAN Statistics Handling**: Show "unavailable" instead of "0 B" when router doesn't provide WAN statistics
  - WAN Download and WAN Upload sensors now properly display unavailable state
  - Added debug logging to identify routers without statistics support

---

## [1.0.1] - 2026-03-19

### Fixed
- **Entity Display Names**: WiFi switch entities now display only the SSID name (e.g., "secure-IoT") instead of the device prefix + SSID. This provides a cleaner, more intuitive UI experience in Home Assistant.
  - Changed `_attr_has_entity_name=False` to remove redundant device name repetition in entity display names
  - Entity IDs remain unchanged (e.g., `switch.secureap_gateway_secure_iot`)

### Changed
- Improved entity naming consistency with Home Assistant best practices

---

## [1.0.0] - 2026-03-11

### Added
- Initial release: Home Assistant custom integration for OpenWrt Router management
- **WiFi Switches**: One switch per detected WiFi SSID (2.4GHz, 5GHz, Guest networks)
- **Sensors**: Uptime, WAN status, connected client count
- **Device Tracker**: Track connected WiFi clients by MAC address
- **Button**: WiFi reload/reboot control
- **Security**: SSRF, token leak, and input validation hardening
- Configuration via Home Assistant UI setup wizard
- Automatic token refresh and retry logic for JSON-RPC API
- Diagnostics with redacted sensitive data

### Architecture
- Async-only design with proper error handling
- Polling coordinator with 30-second update intervals
- ubus/rpcd JSON-RPC communication via HTTP
- Per-SSID controls with UCI configuration backend
