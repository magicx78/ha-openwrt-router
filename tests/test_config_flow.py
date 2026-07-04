"""Tests for the OpenWrt Router config flow (config_flow.py)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtResponseError,
    OpenWrtRpcdSetupError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.config_flow import (
    OpenWrtConfigFlow,
    _validate_host,
)
from custom_components.openwrt_router.const import (
    CONF_PROTOCOL,
    DEFAULT_PROTOCOL,
    DOMAIN,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_INVALID_HOST,
    ERROR_RPCD_SETUP,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS_INSECURE,
)


# =====================================================================
# _validate_host (pure function)
# =====================================================================


class TestValidateHost:
    def test_valid_ip(self):
        assert _validate_host("192.168.1.1") is None

    def test_valid_hostname(self):
        assert _validate_host("router.local") is None

    def test_valid_hostname_with_underscore(self):
        assert _validate_host("my_router") is None

    def test_loopback_rejected(self):
        assert _validate_host("127.0.0.1") == ERROR_INVALID_HOST

    def test_link_local_rejected(self):
        assert _validate_host("169.254.1.1") == ERROR_INVALID_HOST

    def test_unspecified_rejected(self):
        assert _validate_host("0.0.0.0") == ERROR_INVALID_HOST

    def test_ipv6_loopback_rejected(self):
        assert _validate_host("::1") == ERROR_INVALID_HOST

    def test_empty_rejected(self):
        assert _validate_host("") == ERROR_INVALID_HOST

    def test_whitespace_only_rejected(self):
        assert _validate_host("   ") == ERROR_INVALID_HOST

    def test_special_chars_rejected(self):
        assert _validate_host("router;rm -rf") == ERROR_INVALID_HOST

    def test_valid_ipv6(self):
        assert _validate_host("2001:db8::1") is None

    def test_valid_ip_with_whitespace_stripped(self):
        assert _validate_host("  192.168.1.1  ") is None


# =====================================================================
# _compute_unique_id (pure) — multi-router identity
# =====================================================================


class TestComputeUniqueId:
    """The config-entry unique_id must be host-based so that different routers
    (different static IPs) never collapse into one entry — even when identical
    hardware reports the same or an empty MAC in `system board`. This is the
    core regression for adding 10.10.10.1 / .2 / .4 in parallel.
    """

    def test_distinct_hosts_distinct_ids(self):
        a = OpenWrtConfigFlow._compute_unique_id({}, "10.10.10.1", 80)
        b = OpenWrtConfigFlow._compute_unique_id({}, "10.10.10.2", 80)
        c = OpenWrtConfigFlow._compute_unique_id({}, "10.10.10.4", 80)
        assert len({a, b, c}) == 3

    def test_same_host_same_id(self):
        assert OpenWrtConfigFlow._compute_unique_id(
            {}, "10.10.10.1", 80
        ) == OpenWrtConfigFlow._compute_unique_id({}, "10.10.10.1", 80)

    def test_empty_mac_is_host_based(self):
        assert (
            OpenWrtConfigFlow._compute_unique_id({"mac": ""}, "10.10.10.1", 80)
            == "10.10.10.1_80"
        )

    def test_shared_zero_mac_still_distinct(self):
        # Identical Cudy units reporting the SAME all-zero MAC must NOT collide.
        board = {"mac": "00:00:00:00:00:00"}
        a = OpenWrtConfigFlow._compute_unique_id(board, "10.10.10.1", 80)
        b = OpenWrtConfigFlow._compute_unique_id(board, "10.10.10.2", 80)
        assert a != b

    def test_shared_real_mac_still_distinct(self):
        # Even a valid-looking but cloned MAC must not merge two hosts.
        board = {"mac": "aa:bb:cc:dd:ee:ff"}
        a = OpenWrtConfigFlow._compute_unique_id(board, "10.10.10.1", 80)
        b = OpenWrtConfigFlow._compute_unique_id(board, "10.10.10.2", 80)
        assert a != b

    def test_host_case_normalized(self):
        assert (
            OpenWrtConfigFlow._compute_unique_id({}, "Router.LAN", 80)
            == "router.lan_80"
        )


# =====================================================================
# Multi-router smoke test — the decisive proof for 10.10.10.1/.2/.4
# =====================================================================


def _entry_stub(uid: str):
    e = MagicMock()
    e.unique_id = uid
    e.source = "user"
    return e


def _flow_with_registry(registry: dict, my_uid: str):
    """Build a flow whose real _abort_if_unique_id_configured() is backed by a
    shared unique_id → entry registry (mirrors hass.config_entries)."""
    flow = OpenWrtConfigFlow()
    flow.hass = MagicMock()
    flow.handler = DOMAIN
    flow.context = {"source": "user", "unique_id": my_uid}
    flow.hass.config_entries.async_entry_for_domain_unique_id = MagicMock(
        side_effect=lambda handler, uid: registry.get(uid)
    )
    return flow


class TestMultiRouterSmoke:
    """Drive the REAL _abort_if_unique_id_configured() for three routers at
    distinct IPs and prove they all get their own entry with no false
    already_configured abort — while a genuine re-add of the same host is still
    rejected. This is the end-to-end guard for the reported bug.
    """

    def test_three_routers_add_in_parallel_without_abort(self):
        from homeassistant.data_entry_flow import AbortFlow

        registry: dict = {}
        hosts = ["10.10.10.1", "10.10.10.2", "10.10.10.4"]

        # Add all three routers one after another into the same domain.
        for host in hosts:
            uid = OpenWrtConfigFlow._compute_unique_id({}, host, 80)
            flow = _flow_with_registry(registry, uid)
            # Must NOT raise for a distinct host.
            flow._abort_if_unique_id_configured()
            registry[uid] = _entry_stub(uid)

        # All three now coexist as separate entries.
        assert sorted(registry) == [
            "10.10.10.1_80",
            "10.10.10.2_80",
            "10.10.10.4_80",
        ]

        # Re-adding an already-configured host is still correctly rejected.
        dup_uid = OpenWrtConfigFlow._compute_unique_id({}, "10.10.10.1", 80)
        dup_flow = _flow_with_registry(registry, dup_uid)
        with pytest.raises(AbortFlow) as exc:
            dup_flow._abort_if_unique_id_configured()
        assert exc.value.reason == "already_configured"

    def test_identical_hardware_same_mac_still_three_entries(self):
        """Same shared MAC across all units must not merge them (the old bug)."""
        from homeassistant.data_entry_flow import AbortFlow

        board = {"mac": "00:00:00:00:00:00", "hostname": "OpenWrt"}
        registry: dict = {}
        for host in ["10.10.10.1", "10.10.10.2", "10.10.10.4"]:
            uid = OpenWrtConfigFlow._compute_unique_id(board, host, 80)
            flow = _flow_with_registry(registry, uid)
            try:
                flow._abort_if_unique_id_configured()
            except AbortFlow:  # pragma: no cover - would be the regression
                pytest.fail(f"router {host} wrongly aborted as already_configured")
            registry[uid] = _entry_stub(uid)
        assert len(registry) == 3


# =====================================================================
# Config Flow Steps
# =====================================================================


def _make_flow():
    """Create an OpenWrtConfigFlow with a mock hass."""
    flow = OpenWrtConfigFlow()
    flow.hass = MagicMock()
    flow.context = {"source": "user"}
    return flow


# Shared valid user_input for the user step (now includes protocol)
_VALID_USER_INPUT = {
    "host": "192.168.1.1",
    "port": 443,
    "protocol": PROTOCOL_HTTPS_INSECURE,
    "username": "root",
    "password": "test",
}


class TestUserStep:
    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow = _make_flow()
        result = await flow.async_step_user(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "user"

    @pytest.mark.asyncio
    async def test_invalid_host_shows_error(self):
        flow = _make_flow()
        result = await flow.async_step_user(
            user_input={
                "host": "127.0.0.1",
                "port": 443,
                "protocol": PROTOCOL_HTTPS_INSECURE,
                "username": "root",
                "password": "test",
            }
        )
        assert result["type"] == "form"
        assert result["errors"]["host"] == ERROR_INVALID_HOST

    @pytest.mark.asyncio
    async def test_auth_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtAuthError("bad")):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_INVALID_AUTH

    @pytest.mark.asyncio
    async def test_timeout_error(self):
        flow = _make_flow()
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtTimeoutError("slow")
        ):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_TIMEOUT

    @pytest.mark.asyncio
    async def test_connection_error(self):
        flow = _make_flow()
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtConnectionError("down")
        ):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT

    @pytest.mark.asyncio
    async def test_response_error(self):
        flow = _make_flow()
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtResponseError("bad")
        ):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT

    @pytest.mark.asyncio
    async def test_unknown_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=RuntimeError("oops")):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_UNKNOWN

    @pytest.mark.asyncio
    async def test_success_proceeds_to_checklist(self):
        """After successful connection the flow moves straight to the checklist step."""
        flow = _make_flow()
        board_info = {
            "hostname": "OpenWrt-Dev",
            "model": "Test",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

        with (
            patch.object(flow, "_validate_input", return_value=board_info),
            patch.object(flow, "async_set_unique_id", new_callable=AsyncMock),
            patch.object(flow, "_abort_if_unique_id_configured"),
            patch.object(
                flow,
                "async_step_checklist",
                return_value={"type": "form", "step_id": "checklist"},
            ) as mock_checklist,
        ):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)

        mock_checklist.assert_called_once()
        assert result["step_id"] == "checklist"

    @pytest.mark.asyncio
    async def test_protocol_stored_in_user_data(self):
        """Protocol selected in user step is stored and used for the connection test."""
        flow = _make_flow()
        board_info = {
            "hostname": "OpenWrt-Dev",
            "model": "Test",
            "mac": "aa:bb:cc:dd:ee:ff",
        }

        with (
            patch.object(
                flow, "_validate_input", return_value=board_info
            ) as mock_validate,
            patch.object(flow, "async_set_unique_id", new_callable=AsyncMock),
            patch.object(flow, "_abort_if_unique_id_configured"),
            patch.object(
                flow,
                "async_step_checklist",
                return_value={"type": "form", "step_id": "checklist"},
            ),
        ):
            await flow.async_step_user(user_input=_VALID_USER_INPUT)

        mock_validate.assert_called_once_with(
            "192.168.1.1", 443, "root", "test", PROTOCOL_HTTPS_INSECURE
        )
        assert flow._user_data[CONF_PROTOCOL] == PROTOCOL_HTTPS_INSECURE

    @pytest.mark.asyncio
    async def test_unique_id_is_host_based_not_mac(self):
        """unique_id must be host:port, ignoring the (unreliable) board MAC —
        so a second identical router isn't wrongly aborted as already_configured.
        """
        flow = _make_flow()
        board_info = {
            "hostname": "OpenWrt",
            "model": "Cudy WR3000",
            "mac": "aa:bb:cc:dd:ee:ff",
        }
        set_uid = AsyncMock()
        with (
            patch.object(flow, "_validate_input", return_value=board_info),
            patch.object(flow, "async_set_unique_id", set_uid),
            patch.object(flow, "_abort_if_unique_id_configured"),
            patch.object(
                flow,
                "async_step_checklist",
                return_value={"type": "form", "step_id": "checklist"},
            ),
        ):
            await flow.async_step_user(user_input=_VALID_USER_INPUT)

        set_uid.assert_awaited_once_with("192.168.1.1_443")


class TestNoSwitchOrFritzboxSteps:
    """Switch/Fritz!Box add-on features were removed — those steps must not exist."""

    def test_flow_has_no_switch_or_fritzbox_steps(self):
        flow = _make_flow()
        for step in ("async_step_devices", "async_step_fritzbox", "async_step_switch_dev"):
            assert not hasattr(flow, step), f"{step} should have been removed"

    @pytest.mark.asyncio
    async def test_options_flow_only_exposes_topology_debug(self):
        from unittest.mock import PropertyMock

        from custom_components.openwrt_router.config_flow import OpenWrtOptionsFlow

        options_flow = OpenWrtOptionsFlow()
        entry = MagicMock()
        entry.options = {}
        with patch.object(
            OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry:
            mock_entry.return_value = entry
            result = await options_flow.async_step_init(user_input=None)

        assert result["type"] == "form"
        keys = {str(k) for k in result["data_schema"].schema}
        assert keys == {"topology_port_debug"}
        assert not any("fritzbox" in k for k in keys)


class TestUserStepRpcdSetup:
    """status=6 on session/login → wrong credentials, not rpcd setup issue."""

    @pytest.mark.asyncio
    async def test_auth_error_status6_maps_to_invalid_auth(self):
        flow = _make_flow()
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtAuthError("permission denied")
        ):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_INVALID_AUTH

    @pytest.mark.asyncio
    async def test_response_error_maps_to_cannot_connect(self):
        flow = _make_flow()
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtResponseError("garbled")
        ):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT


def _make_reauth_flow(entry_data: dict):
    """Create a flow with a mocked reauth entry."""
    flow = OpenWrtConfigFlow()
    flow.hass = MagicMock()
    flow.context = {"source": "reauth", "entry_id": "test_id"}
    mock_entry = MagicMock()
    mock_entry.data = entry_data
    flow._get_reauth_entry = MagicMock(return_value=mock_entry)
    return flow, mock_entry


_REAUTH_DATA = {
    "host": "10.10.10.4",
    "port": 443,
    "protocol": PROTOCOL_HTTPS_INSECURE,
    "username": "root",
    "password": "secret",
}


class TestReauthDiagnosis:
    """async_step_reauth should diagnose first, never blindly ask for password."""

    @pytest.mark.asyncio
    async def test_existing_credentials_work_auto_resolves(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with (
            patch.object(flow, "_validate_input", return_value={"hostname": "AP4"}),
            patch.object(
                flow,
                "async_update_reload_and_abort",
                return_value={"type": "abort", "reason": "reauth_successful"},
            ),
        ):
            result = await flow.async_step_reauth({})
        assert result["type"] == "abort"

    @pytest.mark.asyncio
    async def test_response_error_routes_to_rpcd_setup_step(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtResponseError("garbled")
        ):
            result = await flow.async_step_reauth({})
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_rpcd_setup"

    @pytest.mark.asyncio
    async def test_connection_error_routes_to_cannot_connect_step(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtConnectionError("down")
        ):
            result = await flow.async_step_reauth({})
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_cannot_connect"

    @pytest.mark.asyncio
    async def test_timeout_error_routes_to_cannot_connect_step(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtTimeoutError("slow")
        ):
            result = await flow.async_step_reauth({})
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_cannot_connect"

    @pytest.mark.asyncio
    async def test_auth_error_routes_to_confirm_step(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", side_effect=OpenWrtAuthError("bad")):
            result = await flow.async_step_reauth({})
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_confirm"


class TestReauthRpcdSetupStep:
    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        result = await flow.async_step_reauth_rpcd_setup(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_rpcd_setup"

    @pytest.mark.asyncio
    async def test_retry_success_auto_resolves(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with (
            patch.object(flow, "_validate_input", return_value={"hostname": "AP4"}),
            patch.object(
                flow,
                "async_update_reload_and_abort",
                return_value={"type": "abort", "reason": "reauth_successful"},
            ),
        ):
            result = await flow.async_step_reauth_rpcd_setup(user_input={})
        assert result["type"] == "abort"

    @pytest.mark.asyncio
    async def test_retry_still_failing_shows_error(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtResponseError("still garbled")
        ):
            result = await flow.async_step_reauth_rpcd_setup(user_input={})
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_RPCD_SETUP

    @pytest.mark.asyncio
    async def test_retry_auth_error_switches_to_confirm(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtAuthError("wrong pw")
        ):
            result = await flow.async_step_reauth_rpcd_setup(user_input={})
        assert result["step_id"] == "reauth_confirm"


class TestReauthCannotConnectStep:
    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        result = await flow.async_step_reauth_cannot_connect(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_cannot_connect"

    @pytest.mark.asyncio
    async def test_retry_success_auto_resolves(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with (
            patch.object(flow, "_validate_input", return_value={"hostname": "AP4"}),
            patch.object(
                flow,
                "async_update_reload_and_abort",
                return_value={"type": "abort", "reason": "reauth_successful"},
            ),
        ):
            result = await flow.async_step_reauth_cannot_connect(user_input={})
        assert result["type"] == "abort"

    @pytest.mark.asyncio
    async def test_retry_still_failing_shows_error(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtConnectionError("still down")
        ):
            result = await flow.async_step_reauth_cannot_connect(user_input={})
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT

    @pytest.mark.asyncio
    async def test_retry_rpcd_setup_switches_step(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(
            flow, "_validate_input", side_effect=OpenWrtRpcdSetupError("rpcd")
        ):
            result = await flow.async_step_reauth_cannot_connect(user_input={})
        assert result["step_id"] == "reauth_rpcd_setup"


class TestMigrateEntry:
    """async_migrate_entry must add CONF_PROTOCOL to pre-v1.16.0 entries."""

    @pytest.mark.asyncio
    async def test_v1_without_protocol_gets_http(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from custom_components.openwrt_router import async_migrate_entry
        from custom_components.openwrt_router.const import CONF_PROTOCOL, PROTOCOL_HTTP

        entry = MagicMock()
        entry.version = 1
        entry.entry_id = "test-v1-entry"
        entry.data = {
            "host": "192.168.1.1",
            "port": 80,
            "username": "root",
            "password": "pw",
        }

        hass = MagicMock()
        captured: dict = {}

        def _update(e, data=None, version=None, **kw):
            if data:
                captured["data"] = data
            if version is not None:
                captured["version"] = version

        hass.config_entries.async_update_entry.side_effect = _update

        result = await async_migrate_entry(hass, entry)

        assert result is True
        assert captured["data"][CONF_PROTOCOL] == PROTOCOL_HTTP
        assert captured["version"] == 2

    @pytest.mark.asyncio
    async def test_v1_with_existing_protocol_preserved(self):
        from custom_components.openwrt_router import async_migrate_entry
        from custom_components.openwrt_router.const import (
            CONF_PROTOCOL,
            PROTOCOL_HTTPS_INSECURE,
        )

        entry = MagicMock()
        entry.version = 1
        entry.entry_id = "test-v1-entry-with-proto"
        entry.data = {
            "host": "192.168.1.1",
            "port": 443,
            "username": "root",
            "password": "pw",
            CONF_PROTOCOL: PROTOCOL_HTTPS_INSECURE,
        }

        hass = MagicMock()
        captured: dict = {}

        def _update(e, data=None, version=None, **kw):
            if data:
                captured["data"] = data
            if version is not None:
                captured["version"] = version

        hass.config_entries.async_update_entry.side_effect = _update

        result = await async_migrate_entry(hass, entry)

        assert result is True
        assert captured["data"][CONF_PROTOCOL] == PROTOCOL_HTTPS_INSECURE


class TestBuildSchemas:
    def test_user_schema_defaults(self):
        schema = OpenWrtConfigFlow._build_user_schema(None)
        assert schema is not None

    def test_user_schema_with_previous_input(self):
        schema = OpenWrtConfigFlow._build_user_schema(
            {
                "host": "10.0.0.1",
                "port": 8080,
                "protocol": PROTOCOL_HTTPS_INSECURE,
                "username": "admin",
            }
        )
        assert schema is not None

    def test_user_schema_includes_protocol(self):
        """Protocol must be part of the user step schema (not a separate step)."""
        schema = OpenWrtConfigFlow._build_user_schema(None)
        keys = [str(k) for k in schema.schema]
        assert any("protocol" in k for k in keys)

    def test_protocol_schema_still_available(self):
        """_build_protocol_schema kept for backward compatibility."""
        schema = OpenWrtConfigFlow._build_protocol_schema()
        assert schema is not None


# =====================================================================
# Checklist step — deploy_acl outcome feedback (v1.20.1)
# =====================================================================

from custom_components.openwrt_router import config_flow as cf_module  # noqa: E402
from custom_components.openwrt_router.acl_provisioning import AclDeployError  # noqa: E402
from custom_components.openwrt_router.const import (  # noqa: E402
    ERROR_ACL_ALREADY_CURRENT,
    ERROR_ACL_DEPLOY_FAILED,
    ERROR_ACL_DEPLOY_NO_CHANGE,
)

_ALL_CAPS_OK = {cap: True for cap in OpenWrtConfigFlow._CAPABILITY_LABELS}


def _make_checklist_flow(capabilities: dict | None = None):
    """Flow pre-seeded as if the user just arrived at the checklist step."""
    flow = _make_flow()
    flow._user_data = dict(_VALID_USER_INPUT)
    flow._board_info = {"hostname": "TestWrt", "model": "Cudy WR3000 v1"}
    flow._capabilities = capabilities if capabilities is not None else {}
    return flow


class _ApiFactory:
    """Stands in for the OpenWrtAPI class; records created instances."""

    def __init__(self, capabilities: dict):
        self.instances: list[MagicMock] = []
        self._capabilities = capabilities

    def __call__(self, *args, **kwargs):
        inst = MagicMock()
        inst.login = AsyncMock()
        inst.async_close = AsyncMock()
        inst.check_capabilities = AsyncMock(return_value=self._capabilities)
        self.instances.append(inst)
        return inst


class TestChecklistStep:
    """deploy_acl must surface its outcome instead of silently re-showing."""

    @staticmethod
    def _no_grace(monkeypatch):
        monkeypatch.setattr(cf_module, "_ACL_RECHECK_GRACE_S", 0)
        monkeypatch.setattr(cf_module, "_ACL_LOGIN_RETRY_DELAY_S", 0)

    @pytest.mark.asyncio
    async def test_deploy_failed_shows_error(self, monkeypatch):
        """AclDeployError → form re-shown with acl_deploy_failed."""
        self._no_grace(monkeypatch)
        flow = _make_checklist_flow()
        factory = _ApiFactory(capabilities={})
        with (
            patch.object(cf_module, "async_get_clientsession", MagicMock()),
            patch.object(cf_module, "OpenWrtAPI", factory),
            patch(
                "custom_components.openwrt_router.acl_provisioning.check_and_deploy_acl",
                AsyncMock(side_effect=AclDeployError("write_blocked", "denied")),
            ),
        ):
            result = await flow.async_step_checklist({"deploy_acl": True})

        assert result["type"] == "form"
        assert result["step_id"] == "checklist"
        assert result["errors"]["base"] == ERROR_ACL_DEPLOY_FAILED
        # deploy api + recheck api were both closed
        assert len(factory.instances) == 2
        for inst in factory.instances:
            inst.async_close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_deploy_success_rechecks_on_fresh_api(self, monkeypatch):
        """Successful deploy → re-check on a fresh api, success note, no errors."""
        self._no_grace(monkeypatch)
        flow = _make_checklist_flow(capabilities={})  # everything missing before
        factory = _ApiFactory(capabilities=dict(_ALL_CAPS_OK))
        with (
            patch.object(cf_module, "async_get_clientsession", MagicMock()),
            patch.object(cf_module, "OpenWrtAPI", factory),
            patch(
                "custom_components.openwrt_router.acl_provisioning.check_and_deploy_acl",
                AsyncMock(return_value=True),
            ),
        ):
            result = await flow.async_step_checklist({"deploy_acl": True})

        assert result["type"] == "form"
        assert result["errors"] == {}
        assert result["description_placeholders"]["status"].startswith(
            "✅ **ACL erfolgreich deployt**"
        )
        assert len(factory.instances) == 2
        recheck = factory.instances[1]
        recheck.check_capabilities.assert_awaited_once()
        for inst in factory.instances:
            inst.async_close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_deploy_noop_shows_already_current(self, monkeypatch):
        """ensure_acl returns False (up to date) → acl_already_current."""
        self._no_grace(monkeypatch)
        flow = _make_checklist_flow()
        factory = _ApiFactory(capabilities={})
        with (
            patch.object(cf_module, "async_get_clientsession", MagicMock()),
            patch.object(cf_module, "OpenWrtAPI", factory),
            patch(
                "custom_components.openwrt_router.acl_provisioning.check_and_deploy_acl",
                AsyncMock(return_value=False),
            ),
        ):
            result = await flow.async_step_checklist({"deploy_acl": True})

        assert result["errors"]["base"] == ERROR_ACL_ALREADY_CURRENT

    @pytest.mark.asyncio
    async def test_deploy_no_change_shows_error(self, monkeypatch):
        """Deploy wrote the file but capabilities stayed identical → warning."""
        self._no_grace(monkeypatch)
        before = dict(_ALL_CAPS_OK, network_wireless=False)
        flow = _make_checklist_flow(capabilities=before)
        factory = _ApiFactory(capabilities=dict(before))  # unchanged after
        with (
            patch.object(cf_module, "async_get_clientsession", MagicMock()),
            patch.object(cf_module, "OpenWrtAPI", factory),
            patch(
                "custom_components.openwrt_router.acl_provisioning.check_and_deploy_acl",
                AsyncMock(return_value=True),
            ),
        ):
            result = await flow.async_step_checklist({"deploy_acl": True})

        assert result["errors"]["base"] == ERROR_ACL_DEPLOY_NO_CHANGE

    @pytest.mark.asyncio
    async def test_submit_without_deploy_creates_entry(self):
        """Unticked checkbox → entry is created (unchanged behaviour)."""
        flow = _make_checklist_flow()
        flow.async_create_entry = MagicMock(
            return_value={"type": "create_entry", "title": "TestWrt"}
        )

        result = await flow.async_step_checklist({})

        assert result["type"] == "create_entry"
        flow.async_create_entry.assert_called_once()
        assert flow.async_create_entry.call_args.kwargs["title"] == "TestWrt"

    def test_has_no_file_exec_row(self):
        """The never-probed phantom row must stay gone (was always red)."""
        assert "file_exec" not in OpenWrtConfigFlow._CAPABILITY_LABELS
