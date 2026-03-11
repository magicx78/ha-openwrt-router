"""DataUpdateCoordinator for the OpenWrt Router integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtTimeoutError,
    OpenWrtResponseError,
)
from .const import (
    CLIENT_KEY_MAC,
    BOARD_REFRESH_CYCLES,
    DOMAIN,
    FEATURE_AVAILABLE_RADIOS,
    FEATURE_DHCP_LEASES,
    FEATURE_HAS_5GHZ,
    FEATURE_HAS_6GHZ,
    FEATURE_HAS_GUEST_WIFI,
    FEATURE_HAS_IWINFO,
    FEATURE_UCI_AVAILABLE,
    KEY_CLIENT_COUNT,
    KEY_CLIENTS,
    KEY_CPU_LOAD,
    KEY_DHCP_LEASES,
    KEY_FEATURES,
    KEY_MEMORY,
    KEY_ROUTER_INFO,
    KEY_UPTIME,
    KEY_WAN_CONNECTED,
    KEY_WAN_STATUS,
    KEY_WIFI_RADIOS,
    RADIO_KEY_BAND,
    RADIO_KEY_ENABLED,
    RADIO_KEY_IS_GUEST,
    SCAN_INTERVAL_SECONDS,
)

_LOGGER = logging.getLogger(__name__)


class OpenWrtCoordinatorData:
    """Typed container for data fetched by the coordinator each poll cycle.

    Attributes:
        router_info: Static board information (model, hostname, release).
        uptime: System uptime in seconds.
        cpu_load: 1-minute CPU load average as percentage (0-100).
        memory: Memory stats dict (total, free, shared, buffered bytes).
        wan_status: WAN interface status dict.
        wan_connected: Convenience bool derived from wan_status.
        wifi_radios: List of normalised radio / SSID descriptors.
        clients: List of currently associated WiFi clients (ip/hostname enriched).
        client_count: Number of connected clients.
        dhcp_leases: MAC → {ip, hostname} mapping from the DHCP lease table.
        features: Feature detection map (populated on first refresh).
    """

    def __init__(self) -> None:
        """Initialise with sensible defaults."""
        self.router_info: dict[str, Any] = {}
        self.uptime: int = 0
        self.cpu_load: float = 0.0
        self.memory: dict[str, Any] = {}
        self.wan_status: dict[str, Any] = {}
        self.wan_connected: bool = False
        self.wifi_radios: list[dict[str, Any]] = []
        self.clients: list[dict[str, Any]] = []
        self.client_count: int = 0
        self.dhcp_leases: dict[str, dict[str, str]] = {}
        self.features: dict[str, Any] = {}

    def as_dict(self) -> dict[str, Any]:
        """Return data as a plain dict (used for diagnostics)."""
        return {
            KEY_ROUTER_INFO: self.router_info,
            KEY_UPTIME: self.uptime,
            KEY_CPU_LOAD: self.cpu_load,
            KEY_MEMORY: self.memory,
            KEY_WAN_STATUS: self.wan_status,
            KEY_WAN_CONNECTED: self.wan_connected,
            KEY_WIFI_RADIOS: self.wifi_radios,
            KEY_CLIENTS: self.clients,
            KEY_CLIENT_COUNT: self.client_count,
            KEY_DHCP_LEASES: self.dhcp_leases,
            KEY_FEATURES: self.features,
        }


class OpenWrtCoordinator(DataUpdateCoordinator[OpenWrtCoordinatorData]):
    """Coordinator that polls the OpenWrt router every SCAN_INTERVAL_SECONDS.

    Architecture notes:
    - A single coordinator instance per config entry is created in __init__.py.
    - All entities subscribe to the coordinator and read from coordinator.data.
    - Entities never call the API directly.
    - Feature detection runs once on the first successful refresh and is
      stored in coordinator.data.features.
    """

    def __init__(self, hass: HomeAssistant, api: OpenWrtAPI, entry_title: str) -> None:
        """Initialise the coordinator.

        Args:
            hass: Home Assistant instance.
            api: Authenticated OpenWrtAPI instance.
            entry_title: Human-readable config entry title for logging.
        """
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry_title}",
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
        )
        self.api = api
        self._features_detected = False
        self._board_poll_count = 0

    # ------------------------------------------------------------------
    # DataUpdateCoordinator interface
    # ------------------------------------------------------------------

    async def _async_update_data(self) -> OpenWrtCoordinatorData:
        """Fetch all data from the router.

        Called automatically by HA on the update interval.

        Returns:
            Populated OpenWrtCoordinatorData instance.

        Raises:
            ConfigEntryAuthFailed: Credentials are invalid (triggers re-auth flow).
            UpdateFailed: Any other error that prevents data retrieval.
        """
        data = OpenWrtCoordinatorData()

        try:
            # --- Feature detection (runs once after first successful login) ---
            if not self._features_detected:
                await self._detect_features(data)

            # --- Static router info (model, hostname) ---
            # Fetched on first cycle and every BOARD_REFRESH_CYCLES thereafter.
            # Hostname changes are rare; this avoids a wasted call every 30 s.
            self._board_poll_count += 1
            if self._board_poll_count == 1 or self._board_poll_count % BOARD_REFRESH_CYCLES == 0:
                data.router_info = await self.api.get_router_info()
            else:
                data.router_info = self.data.router_info if self.data else {}

            # --- Dynamic system status ---
            status = await self.api.get_router_status()
            data.uptime = status.get("uptime", 0)
            data.cpu_load = status.get("cpu_load", 0.0)
            data.memory = status.get("memory", {})

            # --- WAN status ---
            data.wan_status = await self.api.get_wan_status()
            data.wan_connected = data.wan_status.get("wan_connected", False) or data.wan_status.get("connected", False)

            # --- WiFi radios ---
            data.wifi_radios = await self.api.get_wifi_status()

            # --- DHCP leases (for IP / hostname enrichment) ---
            data.dhcp_leases = await self.api.get_dhcp_leases()

            # --- Connected clients (pass radios+leases to avoid redundant API calls) ---
            data.clients = await self.api.get_connected_clients(
                leases=data.dhcp_leases,
                radios=data.wifi_radios,
            )
            data.client_count = len(data.clients)

            # Carry forward features (they don't change between polls)
            data.features = self.data.features if self.data else {}

        except OpenWrtAuthError as err:
            # HA will trigger a re-auth config flow for the user
            raise ConfigEntryAuthFailed(
                f"Authentication failed for OpenWrt router: {err}"
            ) from err

        except OpenWrtConnectionError as err:
            raise UpdateFailed(
                f"Cannot connect to OpenWrt router: {err}"
            ) from err

        except OpenWrtTimeoutError as err:
            raise UpdateFailed(
                f"OpenWrt router request timed out: {err}"
            ) from err

        except OpenWrtResponseError as err:
            raise UpdateFailed(
                f"Unexpected response from OpenWrt router: {err}"
            ) from err

        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("Unexpected error fetching OpenWrt data")
            raise UpdateFailed(f"Unexpected error: {err}") from err

        return data

    # ------------------------------------------------------------------
    # Feature detection
    # ------------------------------------------------------------------

    async def _detect_features(self, data: OpenWrtCoordinatorData) -> None:
        """Run feature detection and store results in data.features.

        Only called once per coordinator lifetime (on first successful refresh).
        Results are then carried forward in subsequent polls.

        Args:
            data: The OpenWrtCoordinatorData being built for this poll.
        """
        _LOGGER.debug("Running OpenWrt feature detection")
        try:
            features = await self.api.detect_features()
            data.features = features
            self._features_detected = True

            _LOGGER.info(
                "OpenWrt feature detection complete: "
                "iwinfo=%s, 5GHz=%s, 6GHz=%s, guest=%s, radios=%s, dhcp_leases=%s",
                features.get(FEATURE_HAS_IWINFO),
                features.get(FEATURE_HAS_5GHZ),
                features.get(FEATURE_HAS_6GHZ),
                features.get(FEATURE_HAS_GUEST_WIFI),
                features.get(FEATURE_AVAILABLE_RADIOS),
                features.get(FEATURE_DHCP_LEASES),
            )
        except Exception as err:  # noqa: BLE001
            # Feature detection failure is non-fatal – continue with empty features
            _LOGGER.warning(
                "Feature detection failed, some entities may not be created: %s", err
            )
            data.features = {}
            # Still mark as done to avoid spamming on every poll
            self._features_detected = True

    # ------------------------------------------------------------------
    # Convenience accessors (used by entities)
    # ------------------------------------------------------------------

    @property
    def router_info(self) -> dict[str, Any]:
        """Return static router info from latest data."""
        if self.data:
            return self.data.router_info
        return {}

    @property
    def features(self) -> dict[str, Any]:
        """Return detected feature map."""
        if self.data:
            return self.data.features
        return {}

    def get_radio_by_band(self, band: str) -> dict[str, Any] | None:
        """Return the first radio matching the given band string.

        Args:
            band: '2.4g', '5g', or '6g'.

        Returns:
            Radio dict or None if not found.
        """
        if not self.data:
            return None
        for radio in self.data.wifi_radios:
            if radio.get(RADIO_KEY_BAND) == band:
                return radio
        return None

    def get_guest_radio(self) -> dict[str, Any] | None:
        """Return the first radio marked as a guest network.

        Returns:
            Radio dict or None if no guest network detected.
        """
        if not self.data:
            return None
        for radio in self.data.wifi_radios:
            if radio.get(RADIO_KEY_IS_GUEST, False):
                return radio
        return None

    def get_client_by_mac(self, mac: str) -> dict[str, Any] | None:
        """Look up a client by MAC address.

        Args:
            mac: Uppercase MAC address string (e.g. 'AA:BB:CC:DD:EE:FF').

        Returns:
            Client dict or None.
        """
        if not self.data:
            return None
        mac_upper = mac.upper()
        for client in self.data.clients:
            if client.get(CLIENT_KEY_MAC, "").upper() == mac_upper:
                return client
        return None

    def is_client_connected(self, mac: str) -> bool:
        """Return True if the given MAC is in the current client list."""
        return self.get_client_by_mac(mac) is not None

    # ------------------------------------------------------------------
    # Feature flag helpers
    # ------------------------------------------------------------------

    @property
    def has_iwinfo(self) -> bool:
        """Return True if iwinfo is available on the router."""
        return bool(self.features.get(FEATURE_HAS_IWINFO, False))

    @property
    def has_5ghz(self) -> bool:
        """Return True if a 5 GHz radio was detected."""
        return bool(self.features.get(FEATURE_HAS_5GHZ, False))

    @property
    def has_6ghz(self) -> bool:
        """Return True if a 6 GHz radio was detected."""
        return bool(self.features.get(FEATURE_HAS_6GHZ, False))

    @property
    def has_guest_wifi(self) -> bool:
        """Return True if a guest WiFi SSID was detected."""
        return bool(self.features.get(FEATURE_HAS_GUEST_WIFI, False))

    @property
    def uci_available(self) -> bool:
        """Return True if UCI is available (required for WiFi switches)."""
        return bool(self.features.get(FEATURE_UCI_AVAILABLE, False))

    @property
    def available_radios(self) -> list[str]:
        """Return list of detected radio interface names."""
        return list(self.features.get(FEATURE_AVAILABLE_RADIOS, []))

    @property
    def has_dhcp_leases(self) -> bool:
        """Return True if DHCP lease file is readable on the router."""
        return bool(self.features.get(FEATURE_DHCP_LEASES, False))

    # TODO: add bandwidth_data property once bandwidth sensors are implemented
    # TODO: add traffic_stats property once traffic statistics are implemented
    # TODO: add per_client_online_time once client time tracking is implemented
