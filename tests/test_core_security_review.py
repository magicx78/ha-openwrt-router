"""Named tests for the security and correctness reviews of 2026-11-18.

One test (or a small group) per finding, numbered like the review:
1-11 security review, 12-18 correctness review. Every test failed on the
code before the fix (commit 6c01e40) and passes after it. Modules are
imported as modules and the new names read inside the tests, so on the old
code each test fails on its own instead of the whole file failing to load.
Mocks only: no router, no Home Assistant instance except the in-process
one of finding 13, no host.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from datetime import timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from core_test_provider import (  # noqa: F401 - short tmp_path (Windows)
    restart,
    short_tmp_path,
    start_env,
    stop_env,
)
from core_testkit import (
    ADMIN_ID,
    FakeDisks,
    FakeEntry,
    bus_events,
    core_of,
    drain,
    make_hass,
    router_data,
    setup_router,
    user_actor,
)
from test_acl_tiers import _api as acl_api
from test_ssh_hostkey_pinning import (
    _PW,
    KEY_A,
    FakeRouter,
    MemoryPinStore,
    _patched,
)
from test_ssh_hostkey_pinning import _api as ssh_api

from custom_components.openwrt_router import acl_provisioning as acl_mod
from custom_components.openwrt_router import api as api_mod
from custom_components.openwrt_router import capabilities as caps_mod
from custom_components.openwrt_router import config_flow as cf_module
from custom_components.openwrt_router import core_audit as audit_mod
from custom_components.openwrt_router import core_guard as guard_mod
from custom_components.openwrt_router import core_masking as mask_mod
from custom_components.openwrt_router import core_store as store_mod
from custom_components.openwrt_router import diagnostics as diag_mod
from custom_components.openwrt_router import enterprise_core as core_mod
from custom_components.openwrt_router.acl_provisioning import (
    RPCD_ACL_CONTENT,
    TIER_READ,
    TIER_RF_SURVEY,
    AclEnsureOutcome,
    AclRight,
    AclTier,
    AclTierRegistry,
    build_acl,
    observe_deployed_acl,
)
from custom_components.openwrt_router.core_models import (
    ArtifactKind,
    BackupReason,
    CoreEventType,
)
from custom_components.openwrt_router.enterprise_core import (
    async_setup_entry_core,
)

ADMIN = user_actor(ADMIN_ID)
PW = "Hunter2Hunter2"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _count(hass, event_type: CoreEventType) -> int:
    return len(bus_events(hass, event_type.value))


# ---------------------------------------------------------------------------
# 1. Optional ACL tiers: allowlist instead of denylist
# ---------------------------------------------------------------------------

_HOSTILE_RIGHTS = {
    "ubus wildcard": AclRight("read", "ubus", "*", "*"),
    "ubus glob ?": AclRight("read", "ubus", "fil?", "exec"),
    "ubus glob *": AclRight("read", "ubus", "f*", "write"),
    "password_set": AclRight("read", "ubus", "rpc-sys", "password_set"),
    "factory": AclRight("read", "ubus", "rpc-sys", "factory"),
    "reboot": AclRight("read", "ubus", "system", "reboot"),
    "setPassword": AclRight("read", "ubus", "luci", "setPassword"),
    "file /bin/sh *": AclRight("read", "file", "/bin/sh", "*"),
    "file [w]rite": AclRight("read", "file", "/etc/passwd", "[w]rite"),
    "file [e]xec": AclRight("read", "file", "/bin/*", "[e]xec"),
    "file *": AclRight("read", "file", "*", "read"),
    "acl dir //": AclRight("read", "file", "/usr/share/rpcd//acl.d/x.json", "read"),
    "proc ..": AclRight("read", "file", "/proc/net/../../etc/shadow", "read"),
    "uci *": AclRight("read", "uci", "*"),
    "cgi-io *": AclRight("read", "cgi-io", "*"),
    "write section": AclRight("write", "ubus", "iwinfo", "survey"),
}


def _tier(right: AclRight, tier_id: str = "t_review") -> AclTier:
    return AclTier(
        tier_id=tier_id,
        title="review",
        capabilities=("rf.review",),
        rights=frozenset({right}),
        risk="test",
    )


@pytest.mark.parametrize("name", sorted(_HOSTILE_RIGHTS))
def test_f01_optional_tier_refuses_write_and_wildcard_rights(name):
    right = _HOSTILE_RIGHTS[name]
    registry = AclTierRegistry(acl_mod._default_tiers())
    with pytest.raises(acl_mod.AclTierRightRefusedError) as err:
        registry.register(_tier(right))
    assert err.value.right == right
    assert right.describe() in str(err.value)  # the refusal names the right
    assert "t_review" not in registry.capability_tiers().values()


def test_f01_allowlisted_and_extension_rights_are_accepted(monkeypatch):
    registry = AclTierRegistry(acl_mod._default_tiers())
    registry.register(_tier(AclRight("read", "ubus", "iwinfo", "survey"), "t_ok"))
    registry.register(
        _tier(AclRight("read", "file", "/proc/net/arp", "read"), "t_proc")
    )
    with pytest.raises(acl_mod.AclTierRightRefusedError):
        registry.register(
            _tier(AclRight("read", "ubus", "luci", "getTraceroute"), "t_trace")
        )
    monkeypatch.setattr(
        acl_mod,
        "OPTIONAL_TIER_EXTENSIONS",
        frozenset({("ubus", "luci", "getTraceroute")}),
    )
    registry.register(
        _tier(AclRight("read", "ubus", "luci", "getTraceroute"), "t_trace")
    )


def test_f01_base_tier_cannot_be_widened():
    base = next(t for t in acl_mod._default_tiers() if t.mandatory)
    widened = AclTier(
        tier_id="read2",
        title=base.title,
        capabilities=base.capabilities,
        rights=base.rights | {AclRight("read", "ubus", "system", "reboot")},
        risk=base.risk,
        mandatory=True,
    )
    tiers = [t for t in acl_mod._default_tiers() if not t.mandatory]
    with pytest.raises(acl_mod.AclTierRightRefusedError) as err:
        AclTierRegistry([widened, *tiers])
    assert err.value.reason == "base_tier_fixed"


def test_f01_offer_lists_every_right_for_the_admin():
    offer = acl_mod.describe_offer(acl_mod.ACL_VERSION, [TIER_RF_SURVEY])
    text = offer.rights_text()
    survey = AclRight("read", "ubus", "iwinfo", "survey").describe()
    assert survey in text and f"[{TIER_RF_SURVEY}]" in text
    data = offer.to_dict()
    assert survey in data["rights"] and data["rights_text"] == text
    assert len(data["rights"]) == len(offer.rights) > 10


# ---------------------------------------------------------------------------
# 2. Pinned SSH: no credentials before the host key is confirmed
# ---------------------------------------------------------------------------


class _PendingStore(MemoryPinStore):
    """Confirm policy: a first key becomes pending, nothing is trusted."""

    async def async_save_pin(self, pin):
        self.saved.append(pin)
        raise api_mod.OpenWrtHostKeyError("pin_pending", "waiting for an admin")


async def test_f02_first_contact_sends_no_credentials():
    api, store, router = ssh_api(), _PendingStore(), FakeRouter(KEY_A)
    with _patched(router), pytest.raises(api_mod.OpenWrtHostKeyError) as err:
        await api_mod.async_ssh_run_pinned(api, "uci show", pin_store=store)
    assert err.value.reason == "pin_pending"
    assert router.auth_attempts == []  # stopped in the handshake
    (probe,) = router.connect_kwargs
    assert probe["password"] is None and probe["client_keys"] is None
    assert _PW not in repr(router.connect_kwargs)
    assert [p.fingerprint for p in store.saved] == [KEY_A.get_fingerprint("sha256")]


async def test_f02_tofu_logs_in_only_on_a_second_pinned_connection():
    api, store, router = ssh_api(), MemoryPinStore(), FakeRouter(KEY_A)
    with _patched(router):
        result = await api_mod.async_ssh_run_pinned(api, "true", pin_store=store)
    assert result.pinned_now is True
    probe, login = router.connect_kwargs
    assert probe["password"] is None
    assert [k.public_data for k in login["known_hosts"][0]] == [KEY_A.public_data]
    assert router.auth_attempts == [_PW]


# ---------------------------------------------------------------------------
# 3. Pinned SSH: output is capped
# ---------------------------------------------------------------------------


def _pinned_store():
    return MemoryPinStore(api_mod.HostKeyPin.from_key(KEY_A, "192.168.1.1"))


async def test_f03_stdout_above_the_cap_aborts_with_too_large():
    router = FakeRouter(KEY_A, stdout=b"x" * 50_000)
    with _patched(router), pytest.raises(api_mod.OpenWrtSshOutputTooLargeError) as err:
        await api_mod.async_ssh_run_pinned(
            ssh_api(), "cat big", pin_store=_pinned_store(), max_output_bytes=10_000
        )
    assert err.value.error_class == "too_large"
    assert err.value.limit_bytes == 10_000
    assert err.value.received_bytes > 10_000
    (process,) = router.processes
    assert process.closed  # aborted, not read to the end
    assert process.stdout.pos < 50_000


async def test_f03_stderr_is_capped_and_marked():
    router = FakeRouter(KEY_A, stdout=b"ok\n", stderr=b"e" * 20_000)
    with _patched(router):
        result = await api_mod.async_ssh_run_pinned(
            ssh_api(), "true", pin_store=_pinned_store()
        )
    assert len(result.stderr) == api_mod.PINNED_SSH_STDERR_MAX_BYTES
    assert result.stderr_truncated is True
    assert result.stdout == "ok\n"


async def test_f03_default_cap_is_the_artifact_limit_plus_margin():
    router = FakeRouter(KEY_A, stdout=b"ok\n")
    with _patched(router):
        result = await api_mod.async_ssh_run_pinned(
            ssh_api(), "true", pin_store=_pinned_store()
        )
    assert result.stderr_truncated is False
    assert api_mod.PINNED_SSH_DEFAULT_MAX_OUTPUT_BYTES > 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# 4. Approvals: request data dropped on expiry, open approvals capped
# ---------------------------------------------------------------------------


async def test_f04_expired_approvals_drop_their_request_data(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    made = await env.api.async_create_backup(
        env.rid, reason=BackupReason.MANUAL, actor=ADMIN
    )
    for _ in range(5):
        await env.api.async_request_export(
            made.record.backup_id, actor=ADMIN, artifact=ArtifactKind.UCI
        )
    manager, guard = env.manager, env.manager.guard
    assert len(manager._exports) == 5
    base = guard.now()
    guard._clock = lambda: base + timedelta(hours=3)
    guard._expire(guard.now())
    assert {a.status.value for a in guard._approvals.values()} == {"expired"}
    assert len(manager._exports) == 0
    assert manager.stats["requests_dropped_on_expiry"] == 5
    await stop_env(env)


async def test_f04_open_approvals_are_capped_per_principal(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    made = await env.api.async_create_backup(
        env.rid, reason=BackupReason.MANUAL, actor=ADMIN
    )
    cap = guard_mod.MAX_OPEN_APPROVALS_PER_PRINCIPAL
    for _ in range(cap):
        await env.api.async_request_export(
            made.record.backup_id, actor=ADMIN, artifact=ArtifactKind.UCI
        )
    with pytest.raises(Exception) as err:
        await env.api.async_request_export(
            made.record.backup_id, actor=ADMIN, artifact=ArtifactKind.UCI
        )
    assert guard_mod.REASON_TOO_MANY_OPEN in repr(err.value.__dict__) + str(err.value)
    guard = env.manager.guard
    assert guard.stats["approvals_capped"] == 1
    assert len(env.manager._exports) == cap
    denied = env.api.events(types=[CoreEventType.AUTHORIZATION_DENIED.value])
    assert any(e.data.get("reason") == guard_mod.REASON_TOO_MANY_OPEN for e in denied)
    await stop_env(env)


async def test_f04_dry_run_plans_expire_by_ttl(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    manager = env.manager
    manager._plans["plan_old"] = object()
    manager._plan_made["plan_old"] = manager.now() - timedelta(hours=3)
    manager._plans["plan_new"] = object()
    manager._plan_made["plan_new"] = manager.now()
    manager._prune_plans()
    assert set(manager._plans) == {"plan_new"}
    assert manager.stats["plans_expired"] == 1
    await stop_env(env)


# ---------------------------------------------------------------------------
# 5. Switching config_backup_enabled is audited
# ---------------------------------------------------------------------------


async def test_f05_config_option_change_is_audited(disks, tmp_path):
    env = await start_env(disks, tmp_path, options={})
    entry = env.entries[0]
    cf_module._apply_config_backup_option(env.hass, entry, True, user_id=ADMIN_ID)
    cf_module._apply_config_backup_option(env.hass, entry, False)
    await drain(env.hass)
    events = env.api.events(types=[CoreEventType.CONFIG_OPTION_CHANGED.value])
    assert len(events) == 2
    oldest, newest = events  # oldest first
    assert oldest.data["new"] is True and oldest.data["old"] is False
    assert oldest.data["actor_known"] is True
    assert oldest.actor is not None and oldest.actor.user_id == ADMIN_ID
    assert newest.data["new"] is False and newest.data["actor_known"] is False
    assert newest.router_id == env.rid
    from custom_components.openwrt_router import core_models

    mandatory = core_models.AUDIT_MANDATORY_EVENT_TYPES
    assert CoreEventType.CONFIG_OPTION_CHANGED in mandatory
    assert newest.audit_ring.value == "security"
    await stop_env(env)


# ---------------------------------------------------------------------------
# 6. Masking: persisted audit data and the listed text shapes
# ---------------------------------------------------------------------------

_LEAKY_TEXTS = {
    "json escaped in a string": json.dumps(json.dumps({"password": PW})),
    "url-encoded key": "pass%77ord=" + PW,
    "fullwidth p": f"ｐassword={PW}",
    "cyrillic a": f"pаssword={PW}",
    "zero-width": f"pass\u200bword={PW}",
    "sshpass -p": f"sshpass -p {PW} ssh root@x",
    "tab": f"psk\t{PW}",
    "xml": f"<password>{PW}</password>",
    "exception text": repr(ValueError(f"login failed for root/{PW}")),
}


@pytest.mark.parametrize("name", sorted(_LEAKY_TEXTS))
def test_f06_redact_text_covers_the_listed_shapes(name):
    assert PW not in mask_mod.redact_text(_LEAKY_TEXTS[name])


def test_f06_structured_masking():
    data = {
        "router_id": f"psk={PW}",
        "pw": PW,
        "change": {"key": "password", "value": PW},
        "diff": [{"option": "key", "config": "wireless", "new": PW}],
        "value": "readable",
        "keys": ["readable"],
        "backup_id": "bkp_" + "a" * 32,
        "presented_fingerprint": "SHA256:gkol/1a5iBp7AVlPyaLsiRLQk5f+iCLJVrSNPI6K2+Y",
        "target": "removed/rtr_" + "b" * 32,
    }
    out = mask_mod.mask_for_output(data)
    assert PW not in json.dumps(out)
    # value/keys are no secret names (diffs stay readable); ids, archive
    # paths and fingerprints keep their strict shapes
    assert out["value"] == "readable" and out["keys"] == ["readable"]
    assert out["backup_id"] == data["backup_id"]
    fingerprint = "presented_fingerprint"
    assert out[fingerprint] == data[fingerprint]
    assert out["target"] == data["target"]


async def test_f06_audit_masks_data_before_it_is_kept_and_persisted(disks):
    hass = make_hass()
    log = audit_mod.AuditLog(hass)
    await log.async_load()
    log.emit(
        CoreEventType.ROUTER_REGISTERED,
        router_id="rtr_" + "c" * 32,
        data={"note": f"password={PW}", "router_id": f"psk={PW}"},
    )
    await log.async_flush()
    assert PW not in json.dumps([dict(e.data) for e in log.events()])
    assert PW not in json.dumps(disks[audit_mod.AUDIT_STORE_KEY].data)


def test_f06_new_patterns_stay_linear_on_hostile_input():
    """Hostile input stays fast AND the escaped secret after it is masked."""
    tail = ' \\"password\\": \\"' + PW + '\\"'
    hostile = [
        "\\" * 60_000 + '"password\\": ',
        '\\"password\\": \\"' + "\\" * 60_000,
        "sshpass " + "-p " * 20_000,
        "<password>" * 10_000,
        "root/" * 15_000,
        "psk\t" * 15_000,
        "pass%77ord=" * 6_000,
    ]
    for text in hostile:
        start = time.perf_counter()
        out = mask_mod.redact_text(text + "\n" + tail)
        assert time.perf_counter() - start < 2.0, text[:20]
        assert PW not in out, text[:20]


# ---------------------------------------------------------------------------
# 7. Audit dedup windows are pruned and capped
# ---------------------------------------------------------------------------


async def test_f07_dedup_windows_are_pruned_and_capped(disks, monkeypatch):
    from datetime import UTC, datetime

    monkeypatch.setattr(audit_mod, "MAX_DEDUP_SCOPES", 50)
    log = audit_mod.AuditLog(make_hass())
    await log.async_load()
    start = datetime.now(UTC)
    for i in range(120):
        log.emit(
            CoreEventType.BACKUP_FAILED,
            router_id="rtr_" + "d" * 32,
            dedup_key=f"k{i}",
            data={"error_class": f"k{i}"},
            now=start + timedelta(seconds=i),
        )
    assert len(log._dedup) <= 50
    assert log.stats["dedup_scopes_dropped"] > 0
    assert log.summary()["dedup_scopes"] == len(log._dedup)
    later = start + timedelta(days=2)  # every window has passed
    log.emit(
        CoreEventType.BACKUP_FAILED,
        router_id="rtr_" + "d" * 32,
        dedup_key="fresh",
        data={"error_class": "fresh"},
        now=later,
    )
    assert log.stats["dedup_scopes_pruned"] > 0  # passed windows forgotten
    assert len(log._dedup) == 1


# ---------------------------------------------------------------------------
# 8. The sweep never follows symlinks
# ---------------------------------------------------------------------------


def _symlink_or_skip(target: str, link: str) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError) as err:
        pytest.skip(f"symlinks not available here ({err})")


def _junction_or_skip(target: str, link: str) -> None:
    if os.name != "nt" or not hasattr(os.path, "isjunction"):
        pytest.skip("directory junctions only on Windows with Python 3.12+")
    import subprocess

    done = subprocess.run(
        ["cmd", "/c", "mklink", "/J", link, target],
        capture_output=True,
        check=False,
    )
    if done.returncode != 0:
        pytest.skip(f"mklink /J failed ({done.returncode})")


async def test_f08_sweep_skips_symlinked_router_folders(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / ("bkp_" + "e" * 32 + ".uci.partial")
    victim.write_bytes(b"keep me")
    os.makedirs(env.versions._root, exist_ok=True)
    link = os.path.join(env.versions._root, "rtr_" + "f" * 32)
    _symlink_or_skip(str(outside), link)
    report = await env.versions.async_sweep()
    assert victim.exists()  # nothing deleted or moved through the link
    assert report.symlinks_skipped == 1
    assert report.to_dict()["symlinks_skipped"] == 1
    assert env.versions.stats["sweep_symlinks_skipped"] == 1
    await stop_env(env)


async def test_f08_sweep_skips_windows_junctions(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / ("bkp_" + "e" * 32 + ".uci.partial")
    victim.write_bytes(b"keep me")
    os.makedirs(env.versions._root, exist_ok=True)
    link = os.path.join(env.versions._root, "rtr_" + "f" * 32)
    _junction_or_skip(str(outside), link)
    report = await env.versions.async_sweep()
    assert victim.exists()
    assert report.symlinks_skipped == 1
    os.rmdir(link)  # removes the junction only
    await stop_env(env)


# ---------------------------------------------------------------------------
# 9. A replaced (corrupt) installation key file is audited and reported
# ---------------------------------------------------------------------------


async def test_f09_corrupt_key_file_replacement_is_audited(disks, tmp_path):
    from custom_components.openwrt_router.core_models import (
        INSTALLATION_KEY_STORE_KEY,
    )

    disks[INSTALLATION_KEY_STORE_KEY].corrupt = True  # HA renamed it
    env = await start_env(disks, tmp_path)
    reported: list[str] = []
    env.versions.key_replaced_hook = reported.append
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    assert env.versions.stats["keys_replaced"] == 1
    assert len(reported) == 1
    events = env.api.events(types=[CoreEventType.INSTALLATION_KEY_REPLACED.value])
    assert len(events) == 1 and events[0].data["key_id"] == reported[0]
    await stop_env(env)


async def test_f09_first_key_without_a_file_is_not_a_replacement(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    reported: list[str] = []
    env.versions.key_replaced_hook = reported.append
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    assert env.versions.stats["keys_created"] == 1
    assert env.versions.stats["keys_replaced"] == 0 and reported == []
    await stop_env(env)


# ---------------------------------------------------------------------------
# 10. Hostile ACL JSON
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("[" * 100_000 + "]" * 100_000, "too_large"),
        ("[" * 30_000 + "]" * 30_000, "too_deep"),
        ("{not json", "invalid_json"),
        (None, "missing"),
    ],
    # Short explicit ids: the generated ids of the huge strings exceed 32767
    # characters, which aborts pytest on Windows (temp dir name from the id).
    ids=["huge_100k_brackets", "deep_30k_brackets", "invalid_json", "none"],
)
def test_f10_parse_acl_text_never_raises(text, why):
    parsed, reason = acl_mod.parse_acl_text(text)
    assert parsed is None and reason == why


async def test_f10_ensure_acl_survives_deep_nesting():
    api = acl_api("[" * 30_000 + "]" * 30_000)
    assert await acl_mod.ensure_acl(api) is True  # rewritten as corrupted
    assert [c.args[1] for c in api._call.await_args_list] == ["read", "write", "exec"]


def test_f10_huge_version_number_is_not_parsed():
    import copy
    import re

    acl = copy.deepcopy(build_acl([TIER_RF_SURVEY]))
    group = acl["root"]
    group["description"] = re.sub(
        r"v\d+;", "v" + "9" * 5000 + ";", group["description"], count=1
    )
    assert "9" * 5000 in group["description"]
    assert acl_mod.parse_tiered_acl(acl) is None  # no int() of 5000 digits
    assert acl_mod.classify_deployed_acl(acl).value == "foreign"


def test_f10_two_backups_in_one_second_get_different_names():
    names = {
        acl_mod.ACL_BACKUP_PREFIX + "x-" + acl_mod.secrets.token_hex(4)
        for _ in range(20)
    }
    assert len(names) == 20
    src = Path(acl_mod.__file__).read_text(encoding="utf-8")
    assert "secrets.token_hex(4)" in src


# ---------------------------------------------------------------------------
# 11. Diagnostics: no Home Assistant user ids
# ---------------------------------------------------------------------------


async def test_f11_diagnostics_pseudonymise_actor_user_ids(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    entry_id = env.entries[0].entry_id
    first = diag_mod._enterprise_core_summary(env.hass, entry_id)
    second = diag_mod._enterprise_core_summary(env.hass, entry_id)
    assert ADMIN_ID not in json.dumps(first)
    users = {
        e["actor"]["user_id"]
        for e in first["audit_entries"]
        if isinstance(e.get("actor"), dict) and e["actor"].get("user_id")
    }
    assert users and all(u.startswith("usr_") and len(u) == 16 for u in users)
    users2 = {
        e["actor"]["user_id"]
        for e in second["audit_entries"]
        if isinstance(e.get("actor"), dict) and e["actor"].get("user_id")
    }
    assert users.isdisjoint(users2)  # fresh salt per download
    await stop_env(env)


# ---------------------------------------------------------------------------
# 12. A router in setup_retry does not churn the stores
# ---------------------------------------------------------------------------


async def test_f12_setup_retry_does_not_rewrite_the_stores(disks, tmp_path):
    entry = FakeEntry("01JA")
    hass = make_hass([entry])
    hass.config.path = lambda *p: str(tmp_path.joinpath(*p))
    skipped = 0
    for _ in range(10):  # ten ConfigEntryNotReady retries
        await async_setup_entry_core(hass, entry)
        skipped += core_of(hass).versions.stats["sweeps_skipped"]
        await entry.run_on_unload()
        await drain(hass)
    writes = {key: len(disk.saves) for key, disk in disks.disks.items()}
    assert all(count <= 1 for count in writes.values()), writes
    assert skipped == 9  # one sweep, nine skips (counted)


async def test_f12_a_core_that_wrote_versions_is_swept_again(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    env = await restart(env)
    assert env.versions.stats["sweeps"] == 1
    assert env.versions.stats["sweeps_skipped"] == 0
    slot = env.hass.data[core_mod.DATA_ENTERPRISE_CORE]
    slot.last_sweep_at -= core_mod.SWEEP_MIN_INTERVAL_SECONDS + 1
    env = await restart(env)
    assert env.versions.stats["sweeps"] == 1  # interval passed: swept
    await stop_env(env)


# ---------------------------------------------------------------------------
# 13. Corrupt store on a real Home Assistant Store
# ---------------------------------------------------------------------------


def _windows_safe_rename():
    """HA names the copy ``.corrupt.<ISO time>``; ':' is invalid on Windows."""
    import homeassistant.helpers.storage as ha_storage

    if os.name != "nt":
        return patch.object(ha_storage, "os", ha_storage.os)
    real_rename = os.rename

    class _Os:
        def __getattr__(self, name):
            return getattr(os, name)

        @staticmethod
        def rename(src, dst):
            real_rename(src, dst[:2] + dst[2:].replace(":", "-"))

    return patch.object(ha_storage, "os", _Os())


async def test_f13_real_store_with_invalid_json_is_a_failed_load(tmp_path):
    from homeassistant.core import HomeAssistant

    storage = tmp_path / ".storage"
    storage.mkdir()
    key = "openwrt_router.router_registry"
    (storage / key).write_text('{"version": 1, "minor_version": 1, "data": {TRUNC')
    hass = HomeAssistant(str(tmp_path))
    try:
        store = store_mod.CoreStore(
            hass, 1, key, minor_version=1, migrate=lambda *a: a[2]
        )
        with _windows_safe_rename():
            loaded = await store_mod.async_load_store(hass, store, key)
        assert loaded.failed is True and loaded.data is None
        assert loaded.corrupt_path is not None
        assert os.path.basename(loaded.corrupt_path).startswith(key + ".corrupt.")
    finally:
        await hass.async_stop(force=True)


async def test_f13_registry_reports_a_renamed_corrupt_store(disks):
    from custom_components.openwrt_router.core_models import (
        ROUTER_REGISTRY_STORE_KEY,
    )

    disks[ROUTER_REGISTRY_STORE_KEY].corrupt = True
    hass = make_hass([FakeEntry("01JA")])
    await setup_router(hass, FakeEntry("01JA"), router_data())
    core = core_of(hass)
    assert core.registry.load_failed is True
    assert _count(hass, CoreEventType.STORE_RECOVERED) >= 1


async def test_f13_recovered_index_keeps_unindexed_version_files(disks, tmp_path):
    from custom_components.openwrt_router.core_models import (
        CONFIG_CATALOG_STORE_KEY,
    )

    env = await start_env(disks, tmp_path)
    made = await env.api.async_create_backup(
        env.rid, reason=BackupReason.MANUAL, actor=ADMIN
    )
    folder = os.path.join(env.versions._root, env.rid)
    files_before = sorted(os.listdir(folder))
    await stop_env(env)
    disks[CONFIG_CATALOG_STORE_KEY].corrupt = True  # index lost, files remain
    env = await restart(env)
    report = env.versions.last_sweep
    assert report.orphaned_moved == 0
    assert report.unindexed_kept >= 1
    assert sorted(os.listdir(folder)) == files_before
    assert env.versions.index_recovered_at is not None
    assert made.record.backup_id  # created before the loss
    await stop_env(env)


# ---------------------------------------------------------------------------
# 14. Backup failure after a restart is not hidden
# ---------------------------------------------------------------------------


async def _try_backup(env, reason=BackupReason.MANUAL):
    from custom_components.openwrt_router.core_errors import ConfigApiError

    try:
        return await env.api.async_create_backup(env.rid, reason=reason, actor=ADMIN)
    except ConfigApiError as err:
        return err


async def test_f14_failure_recovery_failure_across_a_restart(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.provider.fail["collect"] = ConnectionResetError("gone")
    await _try_backup(env)
    env = await restart(env)
    env.provider.fail.pop("collect")
    await _try_backup(env)
    assert _count(env.hass, CoreEventType.BACKUP_RECOVERED) == 1
    env.provider.fail["collect"] = ConnectionResetError("gone again")
    await _try_backup(env)
    assert _count(env.hass, CoreEventType.BACKUP_FAILED) == 2
    await stop_env(env)


async def test_f14_unchanged_config_counts_as_recovery(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    scheduled = BackupReason.SCHEDULED
    await _try_backup(env, scheduled)  # a first version
    env.provider.fail["collect"] = ConnectionResetError("gone")
    await _try_backup(env, scheduled)
    env.provider.fail.pop("collect")
    again = await _try_backup(env, scheduled)  # same content: deduplicated
    assert again.created is False
    assert _count(env.hass, CoreEventType.BACKUP_RECOVERED) == 1
    await stop_env(env)


# ---------------------------------------------------------------------------
# 15. "HA-owned data unchanged" guards notice config-entry calls
# ---------------------------------------------------------------------------

_MUTANT_CALLS = {
    "async_update_entry": lambda hass, entry: hass.config_entries.async_update_entry(
        entry, unique_id="CHANGED"
    ),
    "async_remove": lambda hass, entry: hass.config_entries.async_remove(
        entry.entry_id
    ),
    "async_reload": lambda hass, entry: hass.config_entries.async_reload(
        entry.entry_id
    ),
    "async_forward_entry_setups": lambda hass, entry: (
        hass.config_entries.async_forward_entry_setups(entry, ["sensor"])
    ),
}


@pytest.mark.parametrize("mutant", sorted(_MUTANT_CALLS))
async def test_f15_guard_tests_catch_config_entry_mutations(disks, tmp_path, mutant):
    import test_core_migration as m05
    import test_enterprise_core_lifecycle as m16

    from custom_components.openwrt_router.router_registry import RouterRegistry

    real = RouterRegistry.ensure_entry
    act = _MUTANT_CALLS[mutant]

    def _mutated(self, entry):
        result = act(self.hass, entry)
        if asyncio.iscoroutine(result):
            result.close()  # recorded by the mock; never awaited by a core
        return real(self, entry)

    with patch.object(RouterRegistry, "ensure_entry", _mutated):
        with pytest.raises(AssertionError):
            await m05.test_case05_seven_entries_one_never_reachable(disks)
        with pytest.raises(AssertionError):
            await m16.test_case16_working_core_changes_nothing_ha_owns(
                disks, tmp_path / "c16"
            )


# ---------------------------------------------------------------------------
# 16. Capability last-known state survives an unknown in between
# ---------------------------------------------------------------------------


def _rf_events(hass):
    return [
        e
        for e in bus_events(hass, CoreEventType.ROUTER_CAPABILITIES_CHANGED.value)
        if any(c["capability"] == "rf.survey" for c in e["data"]["changes"])
    ]


async def test_f16_known_unknown_other_known_is_a_change(disks):
    entry = FakeEntry("01JA")
    hass = make_hass([entry])
    await setup_router(hass, entry, router_data())
    registry = core_of(hass).registry
    tiered = build_acl([TIER_READ, TIER_RF_SURVEY])
    for outcome in (
        AclEnsureOutcome(False, "tiered_kept", True, tiered),
        AclEnsureOutcome(False, "transient", False),
        AclEnsureOutcome(True, "missing", True, RPCD_ACL_CONTENT),
    ):
        registry.note_deployed_acl("01JA", observe_deployed_acl(outcome))
    changes = [
        c
        for e in _rf_events(hass)
        for c in e["data"]["changes"]
        if c["capability"] == "rf.survey"
    ]
    assert {"capability": "rf.survey", "from": "available", "to": "unavailable"} in [
        {k: c[k] for k in ("capability", "from", "to")} for c in changes
    ]


def test_f16_merge_reports_against_the_last_known_state():
    from datetime import UTC, datetime

    state = caps_mod.CapabilityState

    def status(value):
        return {
            "rf.survey": caps_mod.CapabilityStatus(
                capability="rf.survey",
                state=value,
                reason="test",
                source="test",
                detected_at=datetime.now(UTC),
            )
        }

    known: dict = {}
    available = status(state.AVAILABLE)
    unknown = status(state.UNKNOWN)
    unavailable = status(state.UNAVAILABLE)
    first = caps_mod.merge({}, available, last_known=known)
    second = caps_mod.merge(first.capabilities, unknown, last_known=known)
    third = caps_mod.merge(second.capabilities, unavailable, last_known=known)
    assert third.first_detections == 0
    assert [(c["from"], c["to"]) for c in third.changes] == [
        ("available", "unavailable")
    ]


# ---------------------------------------------------------------------------
# 17. Config flow: own messages for a kept tiered ACL and a failed read
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "error"),
    [
        ("tiered_kept", "acl_tiered_kept"),
        ("transient", "acl_check_transient"),
        ("current", "acl_already_current"),
        (None, "acl_already_current"),
    ],
)
def test_f17_not_written_reason_maps_to_its_own_message(reason, error):
    assert cf_module._acl_not_written_error(reason) == error


@pytest.mark.parametrize("error", ["acl_tiered_kept", "acl_check_transient"])
def test_f17_messages_exist_in_every_language(error):
    base = Path(cf_module.__file__).parent
    for name in ("strings.json", "translations/en.json", "translations/de.json"):
        data = json.loads((base / name).read_text(encoding="utf-8"))
        assert data["config"]["error"][error], (name, error)


async def test_f17_config_flow_passes_the_outcome_reason(monkeypatch):
    seen = {}

    async def fake_offer(api, *, observe=None):
        seen["observe"] = observe
        observe(AclEnsureOutcome(False, "tiered_kept", True, {}))
        return False

    monkeypatch.setattr(acl_mod, "ensure_acl_respecting_offer", fake_offer)
    flow = cf_module.OpenWrtConfigFlow()
    flow.hass = make_hass()
    flow._user_data = {
        "host": "192.168.1.1",
        "port": 80,
        "username": "root",
        "password": _PW,
        "protocol": "http",
    }
    flow._board_info = {}
    flow._capabilities = {}
    api = AsyncMock()
    api.check_capabilities = AsyncMock(return_value={})
    with (
        patch.object(cf_module, "OpenWrtAPI", return_value=api),
        patch.object(cf_module, "async_get_clientsession"),
        patch.object(cf_module, "_ACL_RECHECK_GRACE_S", 0),
        patch.object(cf_module, "_ACL_LOGIN_RETRY_DELAY_S", 0),
    ):
        result = await flow.async_step_checklist({"deploy_acl": True})
    assert seen["observe"] is not None
    assert result["errors"]["base"] == "acl_tiered_kept"


# ---------------------------------------------------------------------------
# 18. The ACL call pin compares against literal 1.43 expectations
# ---------------------------------------------------------------------------


async def test_f18_pin_catches_a_change_made_to_both_variants():
    import test_enterprise_core_v144 as v144

    real = acl_mod._deploy_acl

    async def _extra_call(api, reason):
        await api._call("file", "list", {"path": "/"})  # a new router call
        return await real(api, reason)

    pin = v144.test_respecting_offer_makes_exactly_the_calls_of_ensure_acl
    with (
        patch.object(acl_mod, "_deploy_acl", _extra_call),
        pytest.raises(AssertionError),
    ):
        await pin("missing")


def test_f18_pin_has_literal_expectations_per_scenario():
    import test_enterprise_core_v144 as v144

    assert set(v144._EXPECTED) == set(v144._SCENARIOS)
    assert v144._V8_BYTES.startswith("sha256:")
    assert sys.modules["test_enterprise_core_v144"] is v144
