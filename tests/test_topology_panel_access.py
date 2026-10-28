"""test_topology_panel_access.py — v1.39.0 topology panel access control.

Verifies:
  * the snapshot API answers 403 to non-admin users by default
  * admins get 200
  * the "show topology panel to all users" option opens the API to non-admins
  * a snapshot build error is reported as HTTP 500 with ``meta.error``
    instead of being masked as an empty topology
  * the sidebar panel's ``require_admin`` follows the option, combined across
    entries (public if ANY loaded entry has it on) and re-evaluated when
    options change or entries unload
  * a panel setup failure does not fail the config entry (C10 guard)
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.components.http import KEY_HASS_USER
from homeassistant.helpers.http import KEY_HASS

from custom_components.openwrt_router.const import CONF_TOPOLOGY_PANEL_ALL_USERS
from custom_components.openwrt_router.topology_panel import (
    _PANEL_REFCOUNT_KEY,
    _PANEL_URL_PATH,
    _PANEL_VIEW_DISABLED_KEY,
    OpenWrtMeshSnapshotView,
    async_setup_topology_panel,
    async_teardown_topology_panel,
    async_update_topology_panel_access,
)

_PANEL_MOD = "custom_components.openwrt_router.topology_panel"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_hass() -> MagicMock:
    hass = MagicMock()
    hass.data = {}
    hass.http = MagicMock()
    hass.http.async_register_static_paths = AsyncMock()
    hass.http.register_view = MagicMock()
    return hass


def _make_entry(entry_id: str, all_users: bool = False) -> SimpleNamespace:
    return SimpleNamespace(
        entry_id=entry_id,
        options={CONF_TOPOLOGY_PANEL_ALL_USERS: all_users},
    )


class _FakeRequest(dict):
    """aiohttp-like request: item access for KEY_HASS_USER, .app for hass."""

    def __init__(self, hass: MagicMock, is_admin: bool) -> None:
        super().__init__()
        self.app = {KEY_HASS: hass}
        self[KEY_HASS_USER] = SimpleNamespace(is_admin=is_admin)


@pytest.fixture
def hass():
    return _make_hass()


@pytest.fixture
def panel_apis():
    with (
        patch(f"{_PANEL_MOD}.async_register_panel", new=AsyncMock()) as register,
        patch(f"{_PANEL_MOD}.async_remove_panel", new=MagicMock()) as remove,
    ):
        yield register, remove


def _fake_snapshot() -> dict:
    return {"nodes": [], "edges": [], "meta": {"node_count": 0}}


# ---------------------------------------------------------------------------
# Snapshot API: admin check
# ---------------------------------------------------------------------------


async def test_non_admin_gets_403_by_default(hass, panel_apis):
    await async_setup_topology_panel(hass, _make_entry("a"))

    with patch(
        "custom_components.openwrt_router.topology_mesh.build_mesh_snapshot",
        return_value=_fake_snapshot(),
    ) as build:
        response = await OpenWrtMeshSnapshotView().get(
            _FakeRequest(hass, is_admin=False)
        )

    assert response.status == 403
    build.assert_not_called()


async def test_admin_gets_200(hass, panel_apis):
    await async_setup_topology_panel(hass, _make_entry("a"))

    with patch(
        "custom_components.openwrt_router.topology_mesh.build_mesh_snapshot",
        return_value=_fake_snapshot(),
    ):
        response = await OpenWrtMeshSnapshotView().get(
            _FakeRequest(hass, is_admin=True)
        )

    assert response.status == 200


async def test_option_on_lets_non_admin_through(hass, panel_apis):
    await async_setup_topology_panel(hass, _make_entry("a", all_users=True))

    with patch(
        "custom_components.openwrt_router.topology_mesh.build_mesh_snapshot",
        return_value=_fake_snapshot(),
    ):
        response = await OpenWrtMeshSnapshotView().get(
            _FakeRequest(hass, is_admin=False)
        )

    assert response.status == 200


async def test_option_on_in_any_entry_opens_api(hass, panel_apis):
    await async_setup_topology_panel(hass, _make_entry("a", all_users=False))
    await async_setup_topology_panel(hass, _make_entry("b", all_users=True))

    with patch(
        "custom_components.openwrt_router.topology_mesh.build_mesh_snapshot",
        return_value=_fake_snapshot(),
    ):
        response = await OpenWrtMeshSnapshotView().get(
            _FakeRequest(hass, is_admin=False)
        )

    assert response.status == 200


# ---------------------------------------------------------------------------
# Snapshot API: build error → 500
# ---------------------------------------------------------------------------


async def test_build_error_returns_500_with_meta_error(hass, panel_apis):
    await async_setup_topology_panel(hass, _make_entry("a"))

    with patch(
        "custom_components.openwrt_router.topology_mesh.build_mesh_snapshot",
        side_effect=KeyError("secret-detail-from-router"),
    ):
        response = await OpenWrtMeshSnapshotView().get(
            _FakeRequest(hass, is_admin=True)
        )

    assert response.status == 500
    body = json.loads(response.body)
    assert body["meta"]["error"]
    # Short and safe: no exception message / stack trace leaks out.
    assert "secret-detail-from-router" not in response.body.decode()
    assert "Traceback" not in response.body.decode()
    assert body["nodes"] == []


async def test_unexpected_build_error_also_returns_500(hass, panel_apis):
    await async_setup_topology_panel(hass, _make_entry("a"))

    with patch(
        "custom_components.openwrt_router.topology_mesh.build_mesh_snapshot",
        side_effect=AttributeError("boom"),
    ):
        response = await OpenWrtMeshSnapshotView().get(
            _FakeRequest(hass, is_admin=True)
        )

    assert response.status == 500
    assert json.loads(response.body)["meta"]["error"]


# ---------------------------------------------------------------------------
# Sidebar panel: require_admin follows the option
# ---------------------------------------------------------------------------


async def test_panel_requires_admin_by_default(hass, panel_apis):
    register, _remove = panel_apis

    await async_setup_topology_panel(hass, _make_entry("a"))

    assert register.await_args.kwargs["require_admin"] is True


async def test_panel_open_when_option_on(hass, panel_apis):
    register, _remove = panel_apis

    await async_setup_topology_panel(hass, _make_entry("a", all_users=True))

    assert register.await_args.kwargs["require_admin"] is False


async def test_second_entry_with_option_reregisters_panel_public(hass, panel_apis):
    register, remove = panel_apis

    await async_setup_topology_panel(hass, _make_entry("a"))
    await async_setup_topology_panel(hass, _make_entry("b", all_users=True))

    assert register.await_count == 2
    assert register.await_args.kwargs["require_admin"] is False
    remove.assert_called_once()
    assert remove.call_args.args[1] == _PANEL_URL_PATH
    assert hass.data[_PANEL_REFCOUNT_KEY] == 2


async def test_options_change_reregisters_panel(hass, panel_apis):
    register, remove = panel_apis
    entry = _make_entry("a")
    await async_setup_topology_panel(hass, entry)
    assert register.await_args.kwargs["require_admin"] is True

    entry.options = {CONF_TOPOLOGY_PANEL_ALL_USERS: True}
    await async_update_topology_panel_access(hass, entry)

    assert register.await_count == 2
    assert register.await_args.kwargs["require_admin"] is False
    remove.assert_called_once()

    # No change → no churn.
    await async_update_topology_panel_access(hass, entry)
    assert register.await_count == 2

    entry.options = {CONF_TOPOLOGY_PANEL_ALL_USERS: False}
    await async_update_topology_panel_access(hass, entry)
    assert register.await_count == 3
    assert register.await_args.kwargs["require_admin"] is True


async def test_options_flow_applies_panel_access(hass, panel_apis):
    """Saving the option in the Configure dialog re-registers the panel
    right away (no update listener, no reload)."""
    from unittest.mock import PropertyMock

    from custom_components.openwrt_router.config_flow import OpenWrtOptionsFlow

    register, _remove = panel_apis
    entry = _make_entry("a")
    await async_setup_topology_panel(hass, entry)
    assert register.await_args.kwargs["require_admin"] is True

    flow = OpenWrtOptionsFlow()
    flow.hass = hass
    with patch.object(
        OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
    ) as mock_entry:
        mock_entry.return_value = entry
        result = await flow.async_step_init(
            user_input={CONF_TOPOLOGY_PANEL_ALL_USERS: True}
        )

    assert result["type"] == "create_entry"
    assert result["data"][CONF_TOPOLOGY_PANEL_ALL_USERS] is True
    assert register.await_args.kwargs["require_admin"] is False


async def test_option_on_loaded_entry_without_panel_setup_applies(hass, panel_apis):
    """A loaded entry whose panel setup failed (rolled back) still gets its
    option applied when saved — no reload needed — and is counted, so its
    later unload decrements correctly."""
    from homeassistant.config_entries import ConfigEntryState

    register, _remove = panel_apis
    await async_setup_topology_panel(hass, _make_entry("a"))
    entry_b = _make_entry("b")
    entry_b.state = ConfigEntryState.LOADED  # loaded, but not in the access map

    await async_update_topology_panel_access(hass, entry_b, True)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 2
    assert register.await_args.kwargs["require_admin"] is False

    await async_teardown_topology_panel(hass, entry_b)
    assert hass.data[_PANEL_REFCOUNT_KEY] == 1
    assert register.await_args.kwargs["require_admin"] is True


async def test_option_on_not_loaded_entry_is_ignored(hass, panel_apis):
    from homeassistant.config_entries import ConfigEntryState

    register, _remove = panel_apis
    await async_setup_topology_panel(hass, _make_entry("a"))
    entry_b = _make_entry("b")
    entry_b.state = ConfigEntryState.SETUP_RETRY

    await async_update_topology_panel_access(hass, entry_b, True)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 1
    assert register.await_count == 1


async def test_unloading_the_only_public_entry_restricts_panel(hass, panel_apis):
    register, _remove = panel_apis
    entry_a = _make_entry("a")
    entry_b = _make_entry("b", all_users=True)
    await async_setup_topology_panel(hass, entry_a)
    await async_setup_topology_panel(hass, entry_b)
    assert register.await_args.kwargs["require_admin"] is False

    await async_teardown_topology_panel(hass, entry_b)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 1
    assert register.await_args.kwargs["require_admin"] is True
    with patch(
        "custom_components.openwrt_router.topology_mesh.build_mesh_snapshot",
        return_value=_fake_snapshot(),
    ):
        response = await OpenWrtMeshSnapshotView().get(
            _FakeRequest(hass, is_admin=False)
        )
    assert response.status == 403


async def test_teardown_of_entry_whose_setup_failed_keeps_panel(hass):
    """An entry whose panel setup failed (and was rolled back) must not
    decrement the refcount of the entries that are still loaded."""
    with (
        patch(f"{_PANEL_MOD}.async_register_panel", new=AsyncMock()),
        patch(f"{_PANEL_MOD}.async_remove_panel", new=MagicMock()) as remove,
    ):
        await async_setup_topology_panel(hass, _make_entry("a"))
        # Entry b never reached a successful panel setup.
        await async_teardown_topology_panel(hass, _make_entry("b"))

    assert hass.data[_PANEL_REFCOUNT_KEY] == 1
    assert hass.data[_PANEL_VIEW_DISABLED_KEY] is False
    remove.assert_not_called()


async def test_setup_twice_for_same_entry_counts_once(hass, panel_apis):
    entry = _make_entry("a")
    await async_setup_topology_panel(hass, entry)
    await async_setup_topology_panel(hass, entry)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 1


# ---------------------------------------------------------------------------
# C10: panel setup failure must not fail the config entry
# ---------------------------------------------------------------------------


async def test_panel_setup_failure_does_not_fail_entry(caplog):
    from custom_components.openwrt_router import async_setup_entry
    from custom_components.openwrt_router.const import (
        CONF_HOST,
        CONF_PASSWORD,
        CONF_PORT,
        CONF_PROTOCOL,
        CONF_USERNAME,
        PROTOCOL_HTTP,
    )

    hass = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    entry = MagicMock()
    entry.entry_id = "entry_c10"
    entry.title = "OpenWrt-Test"
    entry.options = {}
    entry.data = {
        CONF_HOST: "router.invalid",
        CONF_PORT: 80,
        CONF_USERNAME: "root",
        CONF_PASSWORD: "x",
        CONF_PROTOCOL: PROTOCOL_HTTP,
    }

    mock_api = AsyncMock()
    mock_api.reset_acl_blocked = MagicMock()
    mock_coordinator = MagicMock()
    mock_coordinator.async_config_entry_first_refresh = AsyncMock()
    mock_coordinator.router_info = {"model": "TestRouter"}

    with (
        patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ),
        patch("custom_components.openwrt_router.OpenWrtAPI", return_value=mock_api),
        patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ),
        patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            AsyncMock(return_value=False),
        ),
        patch(
            f"{_PANEL_MOD}.async_setup_topology_panel",
            AsyncMock(side_effect=RuntimeError("panel boom")),
        ),
        caplog.at_level(logging.WARNING),
    ):
        result = await async_setup_entry(hass, entry)

    assert result is True
    hass.config_entries.async_forward_entry_setups.assert_awaited_once()
    # No update listener: it would clash with async_update_reload_and_abort
    # in the reauth steps (deprecated in HA 2026.6, error from 2026.12).
    entry.add_update_listener.assert_not_called()
    assert any(
        "topology panel" in rec.getMessage().lower()
        and rec.levelno == logging.WARNING
        for rec in caplog.records
    )
