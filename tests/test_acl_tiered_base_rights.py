"""A kept tiered ACL without the base read rights is kept, but made visible.

``ensure_acl_outcome(respect_offer=True)`` leaves an approved tiered ACL
alone. Since review finding 5 of PR #55 it does that silently only when
the ACL grants every base read right (``rights_from_acl(acl) >=
_base_read_rights()``). Otherwise it still does not overwrite it, but logs
a warning and setup opens a repair issue (de/en) that goes away once the
rights are complete again. The respecting path parses with
``parse_acl_text`` so ``MAX_ACL_NESTING_DEPTH`` / ``MAX_ACL_TEXT_BYTES``
apply. The plain v8 path is unchanged (pinned literally in
test_enterprise_core_v144).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from core_testkit import FakeDisks, FakeEntry, drain, make_hass
from homeassistant.helpers import issue_registry as ir
from test_acl_tiers import _api as acl_api
from test_enterprise_core_lifecycle import _setup_mocks

import custom_components.openwrt_router as integration
from custom_components.openwrt_router.acl_provisioning import (
    ACL_FILE_PATH,
    MAX_ACL_NESTING_DEPTH,
    MAX_ACL_TEXT_BYTES,
    RPCD_ACL_CONTENT,
    TIER_RF_SURVEY,
    AclEnsureOutcome,
    build_acl,
    ensure_acl_outcome,
    ensure_acl_respecting_offer,
    render_acl,
)
from custom_components.openwrt_router.issues import (
    ISSUE_ACL_BASE_RIGHTS_MISSING,
    acl_base_rights_issue_id,
)

ROOT = Path(__file__).resolve().parent.parent


def _tiered_without(obj: str, method: str) -> dict[str, Any]:
    """An approved-looking tiered ACL with one base read right removed."""
    acl = build_acl([TIER_RF_SURVEY])
    ubus = acl["root"]["read"]["ubus"]
    ubus[obj] = [m for m in ubus[obj] if m != method]
    if not ubus[obj]:
        del ubus[obj]
    return acl


def _methods(api) -> list[str]:
    return [c.args[1] for c in api._call.await_args_list]


# -- ensure_acl_outcome ---------------------------------------------------------------


async def test_incomplete_tiered_kept_and_warned(caplog):
    api = acl_api(render_acl(_tiered_without("system", "info")))
    outcome = await ensure_acl_outcome(api, respect_offer=True)
    assert outcome.written is False
    assert outcome.reason == "tiered_kept"
    assert outcome.missing_base_rights == ("read ubus:system.info",)
    assert _methods(api) == ["read"]  # one file/read, nothing written
    api._run_ssh.assert_not_awaited()
    assert "lacks 1 base read right" in caplog.text
    assert "read ubus:system.info" in caplog.text


async def test_complete_tiered_kept_silently(caplog):
    api = acl_api(render_acl(build_acl([TIER_RF_SURVEY])))
    outcome = await ensure_acl_outcome(api, respect_offer=True)
    assert outcome.reason == "tiered_kept"
    assert outcome.missing_base_rights == ()
    assert "base read right" not in caplog.text


async def test_v8_and_redeploy_report_no_missing_rights():
    api = acl_api(json.dumps(RPCD_ACL_CONTENT))
    assert (await ensure_acl_outcome(api, respect_offer=True)).missing_base_rights == ()
    api = acl_api(None)  # missing -> v8 deployed
    outcome = await ensure_acl_outcome(api, respect_offer=True)
    assert outcome.written and outcome.missing_base_rights == ()


def _deep_tiered_text() -> str:
    """A tiered marker plus nesting just beyond the explicit limit.

    Depth MAX+2 is far below any interpreter recursion limit, so a bare
    json.loads parses it on every platform; only the explicit check refuses.
    """
    acl = build_acl([TIER_RF_SURVEY])
    text = render_acl(acl)
    nest = "[" * (MAX_ACL_NESTING_DEPTH + 2) + "]" * (MAX_ACL_NESTING_DEPTH + 2)
    return text[: text.rindex("}")] + f', "x": {nest}}}'


async def test_respecting_path_applies_the_nesting_limit():
    text = _deep_tiered_text()
    json.loads(text)  # valid JSON: the old bare json.loads kept it as tiered
    api = acl_api(text)
    outcome = await ensure_acl_outcome(api, respect_offer=True)
    assert outcome.written is True
    assert outcome.reason == "corrupted"
    assert _methods(api) == ["read", "write", "exec"]  # v8 deployed


async def test_respecting_path_applies_the_size_limit():
    acl = build_acl([TIER_RF_SURVEY])
    acl["root"]["padding"] = "x" * (MAX_ACL_TEXT_BYTES + 1)
    api = acl_api(json.dumps(acl))
    outcome = await ensure_acl_outcome(api, respect_offer=True)
    assert outcome.written is True
    assert outcome.reason == "corrupted"


async def test_plain_path_ignores_tiers_as_before():
    """No offer respected: a tiered ACL is replaced with v8 (unchanged)."""
    api = acl_api(render_acl(_tiered_without("system", "info")))
    outcome = await ensure_acl_outcome(api)
    assert outcome.written is True and outcome.reason == "outdated"
    assert outcome.missing_base_rights == ()


# -- repair issue through async_setup_entry -------------------------------------------


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _setup_with(hass, entry, outcome: AclEnsureOutcome | None, issues) -> None:
    async def fake_ensure(api, *, observe=None):
        if outcome is None:
            raise RuntimeError("ensure failed")
        observe(outcome)
        return outcome.written

    api, coordinator = _setup_mocks([])
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    with (
        patch(f"{integration.__name__}.async_get_clientsession", return_value=MagicMock()),
        patch(f"{integration.__name__}.OpenWrtAPI", return_value=api),
        patch(f"{integration.__name__}.OpenWrtCoordinator", return_value=coordinator),
        patch(
            f"{integration.__name__}.acl_provisioning.ensure_acl_respecting_offer",
            fake_ensure,
        ),
        patch(f"{integration.__name__}._merge_orphan_mac_devices"),
    ):
        assert await integration.async_setup_entry(hass, entry) is True


@pytest.fixture
def issues():
    with patch("custom_components.openwrt_router.issues.ir") as mock_ir:
        mock_ir.IssueSeverity = ir.IssueSeverity
        yield mock_ir


def _kept(missing: tuple[str, ...]) -> AclEnsureOutcome:
    return AclEnsureOutcome(False, "tiered_kept", True, {}, missing_base_rights=missing)


async def test_issue_opened_and_cleared(disks, tmp_path, issues):
    entry = FakeEntry("01JACL", title="Office AP")
    hass = make_hass([entry])
    hass.config.config_dir = str(tmp_path)
    hass.config.path = MagicMock(side_effect=lambda *p: str(tmp_path.joinpath(*p)))
    issue_id = acl_base_rights_issue_id(entry.entry_id)

    await _setup_with(
        hass, entry, _kept(("read ubus:system.info", "read uci:network")), issues
    )
    (create,) = [
        c for c in issues.async_create_issue.call_args_list if c.args[2] == issue_id
    ]
    kwargs = create.kwargs
    assert kwargs["translation_key"] == ISSUE_ACL_BASE_RIGHTS_MISSING
    assert kwargs["severity"] is ir.IssueSeverity.WARNING
    assert kwargs["is_persistent"] is False
    assert "config_entry_id" not in kwargs  # HA 2026.2.3 has no such parameter
    placeholders = kwargs["translation_placeholders"]
    assert placeholders["router"] == "Office AP"
    assert placeholders["count"] == "2"
    assert "read ubus:system.info" in placeholders["rights"]
    assert placeholders["path"] == ACL_FILE_PATH

    # the rights are complete again at the next setup: the issue goes
    await entry.run_on_unload()
    await drain(hass)
    issues.reset_mock()
    await _setup_with(hass, entry, _kept(()), issues)
    deleted = [c.args[2] for c in issues.async_delete_issue.call_args_list]
    assert issue_id in deleted
    assert all(
        c.args[2] != issue_id for c in issues.async_create_issue.call_args_list
    )


async def test_issue_cleared_on_unload_untouched_when_unknown(
    disks, tmp_path, issues
):
    entry = FakeEntry("01JACL2")
    hass = make_hass([entry])
    hass.config.config_dir = str(tmp_path)
    hass.config.path = MagicMock(side_effect=lambda *p: str(tmp_path.joinpath(*p)))
    issue_id = acl_base_rights_issue_id(entry.entry_id)

    await _setup_with(hass, entry, _kept(("read ubus:system.info",)), issues)
    issues.reset_mock()
    await entry.run_on_unload()  # unload clears it (non-persistent issue)
    assert issue_id in [c.args[2] for c in issues.async_delete_issue.call_args_list]

    issues.reset_mock()
    await _setup_with(hass, entry, None, issues)  # ensure failed: unknown
    assert all(
        c.args[2] != issue_id for c in issues.async_create_issue.call_args_list
    )


def test_issue_translations_exist():
    comp = ROOT / "custom_components" / "openwrt_router"
    for name in ("strings.json", "translations/en.json", "translations/de.json"):
        data = json.loads((comp / name).read_text(encoding="utf-8"))
        issue = data["issues"][ISSUE_ACL_BASE_RIGHTS_MISSING]
        for key in ("title", "description"):
            assert issue[key], (name, key)
        for placeholder in ("{router}", "{count}", "{rights}", "{path}"):
            assert placeholder in issue["description"], (name, placeholder)


async def test_respecting_wrapper_passes_missing_rights_to_the_observer():
    api = acl_api(render_acl(_tiered_without("system", "info")))
    seen: list[AclEnsureOutcome] = []
    assert await ensure_acl_respecting_offer(api, observe=seen.append) is False
    assert seen[0].missing_base_rights == ("read ubus:system.info",)
