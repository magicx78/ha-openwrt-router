# Changelog

All notable changes to the OpenWrt Router integration will be documented in this file.

## [1.4.0] - 2026-04-06

### Added
- **Per-Interface Bandwidth Sensors**: Dynamic `sensor.<iface>_rx` / `sensor.<iface>_tx` entities for every network interface (wan, loopback, br-lan, etc.) using existing `network.interface/dump` data
- **Per-Client Online Time**: `connected_since` ISO timestamp attribute in device tracker entities — tracks when each WiFi client first connected (resets on HA restart)
- **Radio Signal/Noise Sensors**: Dynamic `sensor.<iface>_signal` / `sensor.<iface>_noise` entities per WiFi radio (requires iwinfo support; only created when noise data available)

### Technical
- `coordinator.py`: Added `_client_first_seen` dict tracking UTC connection timestamps per MAC
- `api.py`: Extended `_parse_iwinfo_info()` to extract noise/signal/quality/quality_max from iwinfo response
- `const.py`: Added `CLIENT_KEY_CONNECTED_SINCE`

---

## [1.3.0] - 2026-04-05

### Fixed
- **Entity ID naming**: Sensors no longer include the config entry hash in their entity IDs (e.g. `sensor.openwrt_firmware_version` instead of `sensor.openwrt_router_01knfp2yyvf5j20wwpdze0sp99_firmware`)
- **P1**: `perform_update()` — replaced non-existent `file/write` ubus call with SSH subprocess
- **P2**: `get_network_interfaces()` now reads from `network.interface/dump`; `get_active_connections()` reads `/proc/net/nf_conntrack`
- **P3**: Button entity no longer mutates coordinator data directly (race condition)
- **P4**: `configuration_url` now uses the configured protocol (HTTP/HTTPS) in all entity platforms
- **P5**: Removed unreachable dead code in `get_wan_status()`
- **P6**: Exponential backoff on repeated auth failures (3 strikes → 30 s → 300 s max)
- **P7**: SSH JSON parse calls wrapped in `try/except ValueError`
- **P8**: Logging uses `%s` pattern instead of f-strings
- **WiFi SSH fallback**: Uses direct UCI commands instead of a helper script that may not be present on all routers

### Added
- **Memory Total sensor**: Expose total RAM as a standalone sensor (`memory_total`)
- **Memory Used sensor**: Expose used RAM as a standalone sensor (`memory_used`)

---

## [1.2.0] - 2026-03-24

### Added
- **Comprehensive Test Suite**: 247 tests across 11 files covering all modules
  - API parsing, error handling, session management (63 tests)
  - Coordinator polling, feature detection, error wrapping (33 tests)
  - Config flow host validation and setup steps (25 tests)
  - All entity platforms: sensor, switch, button, device_tracker, diagnostics
  - Integration setup/unload/reload lifecycle tests
- **CI/CD Pipelines**: GitHub Actions for automated quality checks
  - `hassfest.yaml`: Home Assistant manifest validation
  - `hacs.yaml`: HACS repository validation
  - `tests.yaml`: Pytest on Python 3.12 and 3.13
- **Brand Icon**: 256x256 PNG icon for HACS store listing
- **Translations**: English translation file (`translations/en.json`)

### Fixed
- Removed non-existent `entity.py` reference from documentation

---

## [1.1.0] - 2026-03-23

### Added
- **Extended System Monitoring**: Comprehensive metrics for advanced system oversight
  - **System Information**: Platform architecture, OpenWrt version, hostname, model detection
  - **CPU Metrics**: Extended load averages - 1-minute, 5-minute, and 15-minute load as percentage
  - **Memory Details**: Separate sensors for cached, shared, and buffered memory in addition to total/free
  - **Disk Space Monitoring**: Total, used, free capacity and usage percentage for all mounted filesystems
  - **Temporary Storage (tmpfs)**: Dedicated monitoring for /tmp, /run, /dev/shm with usage metrics
  - **Network Connection Tracking**: Active network connection count via nf_conntrack integration
  - **15+ New Sensors**: All metrics exposed as individual sensors for dashboards and automations

### Technical
- Enhanced API methods with graceful fallback for unsupported features
- Improved platform architecture detection from multiple sources
- Comprehensive error handling for missing system features
- Support for systems with/without nf_conntrack module

---

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
