"""test_panel_lifecycle.py — F3 (v1.18.0) Topology panel reference counting.

Verifies:
  * setup is idempotent across multiple config entries (counter increments,
    actual registrations happen only once per HA session)
  * each unload decrements the counter, never goes below zero
  * last-entry unload removes the sidebar panel and soft-disables the
    snapshot view (HTTP 410)
  * a fresh setup after a full unload re-arms the view (live data again)
  * the view returns 410 when the disabled flag is set
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.topology_panel import (  # noqa: E402
    OpenWrtMeshSnapshotView,
    _PANEL_REFCOUNT_KEY,
    _PANEL_REGISTERED_KEY,
    _PANEL_STATIC_BOUND_KEY,
    _PANEL_URL_PATH,
    _PANEL_VIEW_BOUND_KEY,
    _PANEL_VIEW_DISABLED_KEY,
    async_setup_topology_panel,
    async_teardown_topology_panel,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_hass() -> MagicMock:
    """Mock HA with a real dict for hass.data and AsyncMocked HTTP layer."""
    hass = MagicMock()
    hass.data = {}
    hass.http = MagicMock()
    hass.http.async_register_static_paths = AsyncMock()
    hass.http.register_view = MagicMock()
    # Some HA versions use the deprecated sync variant — provide it too
    hass.http.register_static_path = MagicMock()
    return hass


@pytest.fixture
def hass():
    return _make_hass()


@pytest.fixture
def patch_panel_apis():
    """Patch the HA panel/frontend helpers used inside topology_panel."""
    with (
        patch(
            "custom_components.openwrt_router.topology_panel.async_register_panel",
            new=AsyncMock(),
        ) as register,
        patch(
            "custom_components.openwrt_router.topology_panel.async_remove_panel",
            new=MagicMock(),
        ) as remove,
    ):
        yield register, remove


# ---------------------------------------------------------------------------
# Setup / refcount semantics
# ---------------------------------------------------------------------------


async def test_first_setup_registers_and_bumps_refcount(hass, patch_panel_apis):
    register_panel, _remove_panel = patch_panel_apis

    await async_setup_topology_panel(hass)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 1
    assert hass.data[_PANEL_REGISTERED_KEY] is True
    assert hass.data[_PANEL_VIEW_DISABLED_KEY] is False
    register_panel.assert_awaited_once()
    hass.http.register_view.assert_called_once()
    # static path registered (either modern or legacy variant)
    assert (
        hass.http.async_register_static_paths.await_count == 1
        or hass.http.register_static_path.call_count == 1
    )


async def test_second_setup_only_bumps_refcount(hass, patch_panel_apis):
    """A second config entry must NOT re-register static path / view / panel
    — only the refcount increments."""
    register_panel, _remove_panel = patch_panel_apis

    await async_setup_topology_panel(hass)
    await async_setup_topology_panel(hass)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 2
    register_panel.assert_awaited_once()  # still 1 — not 2
    hass.http.register_view.assert_called_once()


async def test_setup_clears_view_disabled_flag(hass, patch_panel_apis):
    """A fresh setup after a full teardown must re-arm the snapshot view."""
    hass.data[_PANEL_VIEW_DISABLED_KEY] = True  # simulate previous teardown

    await async_setup_topology_panel(hass)

    assert hass.data[_PANEL_VIEW_DISABLED_KEY] is False


# ---------------------------------------------------------------------------
# Teardown semantics
# ---------------------------------------------------------------------------


async def test_teardown_with_remaining_entries_keeps_panel_alive(
    hass, patch_panel_apis
):
    _register_panel, remove_panel = patch_panel_apis

    await async_setup_topology_panel(hass)
    await async_setup_topology_panel(hass)
    # 2 entries → unload one
    await async_teardown_topology_panel(hass)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 1
    assert hass.data.get(_PANEL_VIEW_DISABLED_KEY) is False
    remove_panel.assert_not_called()


async def test_last_teardown_removes_panel_and_soft_disables_view(
    hass, patch_panel_apis
):
    _register_panel, remove_panel = patch_panel_apis

    await async_setup_topology_panel(hass)
    await async_teardown_topology_panel(hass)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 0
    assert hass.data[_PANEL_VIEW_DISABLED_KEY] is True
    remove_panel.assert_called_once_with(hass, _PANEL_URL_PATH)


async def test_teardown_without_setup_clamps_to_zero(hass, patch_panel_apis):
    """Defensive: if teardown runs without a matching setup the counter must
    not go negative."""
    _register_panel, remove_panel = patch_panel_apis

    await async_teardown_topology_panel(hass)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 0
    assert hass.data[_PANEL_VIEW_DISABLED_KEY] is True
    remove_panel.assert_called_once()


async def test_setup_after_full_teardown_rearms_view(hass, patch_panel_apis):
    """Full lifecycle: setup → unload → setup → view live again."""
    _register_panel, _remove_panel = patch_panel_apis

    await async_setup_topology_panel(hass)
    await async_teardown_topology_panel(hass)
    assert hass.data[_PANEL_VIEW_DISABLED_KEY] is True

    await async_setup_topology_panel(hass)
    assert hass.data[_PANEL_VIEW_DISABLED_KEY] is False
    assert hass.data[_PANEL_REFCOUNT_KEY] == 1


# ---------------------------------------------------------------------------
# View-level 410 behaviour
# ---------------------------------------------------------------------------


async def test_snapshot_view_returns_410_when_disabled(hass):
    """The view must answer 410 Gone once the soft-disable flag is set."""
    hass.data[_PANEL_VIEW_DISABLED_KEY] = True

    view = OpenWrtMeshSnapshotView()
    request = MagicMock()
    request.app = {"hass": hass}

    response = await view.get(request)

    assert response.status == 410


async def test_snapshot_view_returns_data_when_enabled(hass):
    """When NOT disabled, the view should call build_mesh_snapshot and 200."""
    hass.data[_PANEL_VIEW_DISABLED_KEY] = False

    view = OpenWrtMeshSnapshotView()
    request = MagicMock()
    request.app = {"hass": hass}

    fake_snapshot = {"nodes": [], "edges": [], "meta": {"node_count": 0}}
    with patch(
        "custom_components.openwrt_router.topology_mesh.build_mesh_snapshot",
        return_value=fake_snapshot,
    ):
        response = await view.get(request)

    # HomeAssistantView.json() returns a web.Response with status 200 by default.
    assert response.status == 200


# ---------------------------------------------------------------------------
# Setup-failure rollback (regression for v1.18.0 release-gate finding)
# ---------------------------------------------------------------------------


async def test_setup_panel_register_failure_rolls_back_refcount(hass):
    """If async_register_panel raises, refcount must drop back to its
    pre-call value AND the master flag must NOT be set — otherwise the
    next setup attempt would early-return without ever registering the
    sidebar panel.
    """
    boom = AsyncMock(side_effect=RuntimeError("simulated boom"))
    with (
        patch(
            "custom_components.openwrt_router.topology_panel.async_register_panel",
            new=boom,
        ),
        patch(
            "custom_components.openwrt_router.topology_panel.async_remove_panel",
            new=MagicMock(),
        ),
    ):
        with pytest.raises(RuntimeError, match="simulated boom"):
            await async_setup_topology_panel(hass)

    # Refcount must be rolled back to 0 — otherwise this entry's failed
    # setup leaks a count and prevents a future last-unload from soft-
    # disabling the view.
    assert hass.data[_PANEL_REFCOUNT_KEY] == 0
    # Master flag must NOT have been set — otherwise the retry would skip
    # the sidebar registration entirely.
    assert hass.data.get(_PANEL_REGISTERED_KEY) is not True
    # Stage flags for static / view ARE set — those resources got bound
    # to aiohttp's append-only router and must NOT be re-registered on retry.
    assert hass.data[_PANEL_STATIC_BOUND_KEY] is True
    assert hass.data[_PANEL_VIEW_BOUND_KEY] is True


async def test_setup_retry_after_failure_only_registers_panel(hass):
    """A retry after a failed first setup must:
      * NOT re-register static path (would raise: append-only router)
      * NOT re-register view (same reason)
      * register the sidebar panel (this was the missing piece)
      * end up with refcount=1 and master flag set
    """
    # First attempt — async_register_panel blows up
    fail_register = AsyncMock(side_effect=RuntimeError("first try fails"))
    with (
        patch(
            "custom_components.openwrt_router.topology_panel.async_register_panel",
            new=fail_register,
        ),
        patch(
            "custom_components.openwrt_router.topology_panel.async_remove_panel",
            new=MagicMock(),
        ),
    ):
        with pytest.raises(RuntimeError):
            await async_setup_topology_panel(hass)

    # Sanity check: stage flags carry forward, master flag does not, refcount=0
    assert hass.data[_PANEL_STATIC_BOUND_KEY] is True
    assert hass.data[_PANEL_VIEW_BOUND_KEY] is True
    assert hass.data[_PANEL_REFCOUNT_KEY] == 0

    # Reset call counters on the http mocks so the retry assertion is clean
    static_calls_before = hass.http.async_register_static_paths.await_count
    view_calls_before = hass.http.register_view.call_count

    # Second attempt — register_panel works
    ok_register = AsyncMock()
    with (
        patch(
            "custom_components.openwrt_router.topology_panel.async_register_panel",
            new=ok_register,
        ),
        patch(
            "custom_components.openwrt_router.topology_panel.async_remove_panel",
            new=MagicMock(),
        ),
    ):
        await async_setup_topology_panel(hass)

    # Static and view must NOT have been registered again
    assert hass.http.async_register_static_paths.await_count == static_calls_before
    assert hass.http.register_view.call_count == view_calls_before
    # Sidebar panel WAS registered this time
    ok_register.assert_awaited_once()
    # Refcount + master flag in correct state
    assert hass.data[_PANEL_REFCOUNT_KEY] == 1
    assert hass.data[_PANEL_REGISTERED_KEY] is True


async def test_setup_static_path_failure_rolls_back_refcount(hass):
    """If the FIRST stage (static path) raises, neither stage flag should
    be set and refcount must roll back."""
    hass.http.async_register_static_paths = AsyncMock(
        side_effect=RuntimeError("disk gone")
    )
    with (
        patch(
            "custom_components.openwrt_router.topology_panel.async_register_panel",
            new=AsyncMock(),
        ),
        patch(
            "custom_components.openwrt_router.topology_panel.async_remove_panel",
            new=MagicMock(),
        ),
    ):
        with pytest.raises(RuntimeError, match="disk gone"):
            await async_setup_topology_panel(hass)

    assert hass.data[_PANEL_REFCOUNT_KEY] == 0
    assert hass.data.get(_PANEL_REGISTERED_KEY) is not True
    # Static stage failed — its flag must NOT have been set
    assert hass.data.get(_PANEL_STATIC_BOUND_KEY) is not True
    # View stage never reached
    assert hass.data.get(_PANEL_VIEW_BOUND_KEY) is not True


async def test_full_unload_clears_master_flag_so_next_setup_re_registers_panel(hass):
    """After the last entry unloads, async_remove_panel removes the sidebar
    from HA's frontend registry.  The next setup MUST re-register it —
    therefore the master flag must be cleared by teardown."""
    register_panel = AsyncMock()
    remove_panel = MagicMock()
    with (
        patch(
            "custom_components.openwrt_router.topology_panel.async_register_panel",
            new=register_panel,
        ),
        patch(
            "custom_components.openwrt_router.topology_panel.async_remove_panel",
            new=remove_panel,
        ),
    ):
        await async_setup_topology_panel(hass)
        await async_teardown_topology_panel(hass)
        await async_setup_topology_panel(hass)

    # Sidebar must have been registered TWICE (first setup + setup-after-teardown)
    assert register_panel.await_count == 2
    # Static and view bound exactly once (append-only, NOT re-registered)
    assert hass.http.async_register_static_paths.await_count == 1
    assert hass.http.register_view.call_count == 1
