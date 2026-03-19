# Changelog

All notable changes to the OpenWrt Router integration will be documented in this file.

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
