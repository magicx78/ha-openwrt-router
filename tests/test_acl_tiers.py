"""Tests for the tiered ACL offer in acl_provisioning.py (next ACL version).

Pins three promises:
  * the automatic path (ensure_acl, ACL v8) is untouched — same content,
    same writes; tiered ACLs never reach a router through it;
  * every tier adds exactly its rights; the new base tier has no iwinfo scan;
  * nothing is written by the new code unless an acl_deploy WriteAuthorization
    bound to this router and this exact ACL is consumed first.
Routers are mocks only.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router import acl_provisioning as acl_mod
from custom_components.openwrt_router.acl_provisioning import (
    ACL_BACKUP_PREFIX,
    ACL_FILE_PATH,
    ACL_VERSION,
    CAPABILITY_RF_SCAN,
    CAPABILITY_RF_SURVEY,
    CAPABILITY_RF_TXPOWERLIST,
    CONFIG_BACKUP_UCI_CONFIGS,
    DEFAULT_TIER_REGISTRY,
    RPCD_ACL_CONTENT,
    TIER_CONFIG_BACKUP_READ,
    TIER_READ,
    TIER_RF_SCAN,
    TIER_RF_SURVEY,
    TIERED_ACL_VERSION,
    AclDeployError,
    AclOfferDeployError,
    AclOfferRefusedError,
    AclRight,
    AclTier,
    AclTierError,
    AclTierRegistry,
    DeployedAclKind,
    acl_binding_checksum,
    acl_checksum,
    async_deploy_acl_offer,
    build_acl,
    classify_deployed_acl,
    describe_offer,
    ensure_acl,
    ensure_acl_respecting_offer,
    granted_capabilities,
    missing_permissions,
    parse_tiered_acl,
    render_acl,
    rights_from_acl,
)
from custom_components.openwrt_router.api import (
    OpenWrtConnectionError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.core_errors import AuthorizationError
from custom_components.openwrt_router.core_models import (
    OPTION_CONFIG_BACKUP_ENABLED,
    Actor,
    ActorKind,
    Capability,
    GuardedAction,
    _mint_write_authorization,
)

ROUTER = "rtr_" + "a" * 32
OTHER_ROUTER = "rtr_" + "b" * 32
NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)
# Changed deliberately (security review finding 10): the backup name ends in
# a random suffix; the fixture below makes it fixed for these tests.
BACKUP_SUFFIX = "a1b2c3d4"
BACKUP = ACL_BACKUP_PREFIX + "20261118T120000Z-" + BACKUP_SUFFIX


@pytest.fixture(autouse=True)
def _fixed_backup_suffix(monkeypatch):
    monkeypatch.setattr(acl_mod.secrets, "token_hex", lambda n: BACKUP_SUFFIX)


V8_TEXT = json.dumps(RPCD_ACL_CONTENT, indent=2)
OPTS_ON = {OPTION_CONFIG_BACKUP_ENABLED: True}

# sha256 of json.dumps(RPCD_ACL_CONTENT, indent=2) — the exact bytes ensure_acl
# writes — computed from the file at 62cd6c8, before the tier work.
V8_SHA256 = "c774021615dbc83d2241b96666b864675383132f0147ad5496f8d1fc0bb71df1"


def _scan_right() -> AclRight:
    return AclRight("read", "ubus", "iwinfo", "scan")


class FakeGuard:
    """Ledger + single use like ActionGuardProtocol.consume (contract 6.5)."""

    def __init__(self) -> None:
        self.ledger: set[str] = set()
        self.calls: list[dict] = []

    def issue(self, *, router_id=ROUTER, tiers=(), acl=None, action=None, **kw):
        acl = acl if acl is not None else build_acl(tiers)
        auth = _mint_write_authorization(
            action=str(action or GuardedAction.ACL_DEPLOY),
            router_id=router_id,
            actor=Actor(kind=ActorKind.USER, user_id="admin", is_admin=True),
            checksum=kw.get("checksum", acl_binding_checksum(router_id, acl)),
            ttl=kw.get("ttl", timedelta(minutes=5)),
            now=kw.get("now"),
        )
        self.ledger.add(auth.authorization_id)
        return auth

    def consume(self, authorization, *, action, router_id, checksum=None):
        self.calls.append(
            {"action": action, "router_id": router_id, "checksum": checksum}
        )
        if authorization.authorization_id not in self.ledger:
            raise AuthorizationError(
                "unknown", details={"reason": "unknown_authorization"}
            )
        authorization._consume(action=action, router_id=router_id, checksum=checksum)


def _api(read=None):
    """Mock OpenWrtAPI. ``read``: text on the router, an exception, or None."""
    api = MagicMock()
    api._host = "10.10.10.2"
    api._password = "s3cret-router-pw"
    api._run_ssh = AsyncMock(return_value=None)

    def _side_effect(obj, method, params):
        if method == "read":
            if isinstance(read, Exception):
                raise read
            if read is None:
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            return {"data": read}
        return {}

    api._call = AsyncMock(side_effect=_side_effect)
    return api


def _calls(api):
    return [(c.args[1], c.args[2]) for c in api._call.await_args_list]


def _writes(api):
    return [p for m, p in _calls(api) if m == "write"]


def _execs(api):
    return [p for m, p in _calls(api) if m == "exec"]


# ---------------------------------------------------------------------------
# The automatic path is unchanged
# ---------------------------------------------------------------------------


class TestDefaultPathUnchanged:
    def test_v8_content_and_version_untouched(self):
        assert ACL_VERSION == 8
        assert hashlib.sha256(V8_TEXT.encode()).hexdigest() == V8_SHA256
        # v8 still reads iwinfo scan — removing it is only part of the offer.
        assert "scan" in RPCD_ACL_CONTENT["root"]["read"]["ubus"]["iwinfo"]
        assert "description" in RPCD_ACL_CONTENT["root"]
        assert parse_tiered_acl(RPCD_ACL_CONTENT) is None

    @pytest.mark.asyncio
    async def test_ensure_acl_writes_exactly_v8_bytes(self):
        api = _api(read=None)
        assert await ensure_acl(api) is True
        writes = _writes(api)
        assert writes == [{"path": ACL_FILE_PATH, "data": V8_TEXT}]
        assert not any(w["path"].startswith(ACL_BACKUP_PREFIX) for w in writes)

    @pytest.mark.asyncio
    async def test_ensure_acl_still_replaces_a_tiered_acl_with_v8(self):
        """Known property of the unchanged path: it would undo an offer.

        That is why ensure_acl_respecting_offer exists; the caller switch is
        a follow-up in __init__.py / config_flow.py.
        """
        api = _api(read=render_acl(build_acl([TIER_RF_SURVEY])))
        assert await ensure_acl(api) is True
        assert _writes(api)[0]["data"] == V8_TEXT

    def test_importing_the_module_builds_offers_without_router_access(self):
        # The registry is built at import from data only.
        assert [t.tier_id for t in DEFAULT_TIER_REGISTRY.tiers()] == [
            TIER_READ,
            TIER_CONFIG_BACKUP_READ,
            TIER_RF_SURVEY,
            TIER_RF_SCAN,
        ]


# ---------------------------------------------------------------------------
# Tier model
# ---------------------------------------------------------------------------


class TestReadTier:
    def test_read_tier_is_v8_minus_scan_plus_txpowerlist(self):
        base = DEFAULT_TIER_REGISTRY.get(TIER_READ).rights
        v8 = rights_from_acl(RPCD_ACL_CONTENT)
        assert v8 - base == {_scan_right()}
        assert base - v8 == {AclRight("read", "ubus", "iwinfo", "txpowerlist")}

    def test_scan_not_in_new_read_tier(self):
        acl = build_acl([])
        assert "scan" not in acl["root"]["read"]["ubus"]["iwinfo"]
        assert _scan_right() not in rights_from_acl(acl)

    def test_claimed_read_rights_present(self):
        ubus = build_acl([])["root"]["read"]["ubus"]
        assert ubus["hostapd.*"] == ["get_clients", "get_status"]
        assert set(ubus["iwinfo"]) == {
            "info",
            "assoclist",
            "devices",
            "freqlist",
            "txpowerlist",
        }
        assert "status" in ubus["network.wireless"]

    def test_existing_controls_kept_in_base(self):
        """Wi-Fi switches, reload button and rpcd restart keep working."""
        write = build_acl([])["root"]["write"]
        assert write["ubus"]["network.wireless"] == ["down", "up"]
        assert write["ubus"]["network"] == ["reload"]
        assert write["file"] == {"/etc/init.d/rpcd": ["exec"]}

    def test_base_is_mandatory(self):
        assert DEFAULT_TIER_REGISTRY.normalize([TIER_RF_SCAN]) == (
            TIER_READ,
            TIER_RF_SCAN,
        )
        assert DEFAULT_TIER_REGISTRY.get(TIER_READ).mandatory is True


class TestOptionalTiers:
    @pytest.mark.parametrize(
        "tier_id", [TIER_CONFIG_BACKUP_READ, TIER_RF_SURVEY, TIER_RF_SCAN]
    )
    def test_each_tier_adds_exactly_its_rights(self, tier_id):
        base = rights_from_acl(build_acl([]))
        with_tier = rights_from_acl(build_acl([tier_id]))
        assert with_tier - base == DEFAULT_TIER_REGISTRY.get(tier_id).rights
        assert base <= with_tier

    def test_config_backup_tier_rights(self):
        tier = DEFAULT_TIER_REGISTRY.get(TIER_CONFIG_BACKUP_READ)
        assert tier.rights == {
            AclRight("read", "cgi-io", "backup"),
            AclRight("read", "ubus", "rpc-sys", "packagelist"),
            *(AclRight("read", "uci", c) for c in CONFIG_BACKUP_UCI_CONFIGS),
        }
        assert len(CONFIG_BACKUP_UCI_CONFIGS) == 14
        assert tier.option == OPTION_CONFIG_BACKUP_ENABLED
        assert set(tier.capabilities) == {
            Capability.CONFIG_CGI_BACKUP,
            Capability.CONFIG_UCI_READ,
            Capability.CONFIG_PACKAGELIST,
        }
        assert "SECRETS" in tier.risk

    def test_config_backup_tier_json_shape(self):
        read = build_acl([TIER_CONFIG_BACKUP_READ])["root"]["read"]
        assert read["cgi-io"] == ["backup"]
        assert read["uci"] == sorted(CONFIG_BACKUP_UCI_CONFIGS)
        assert read["ubus"]["rpc-sys"] == ["packagelist"]

    def test_rf_tiers(self):
        assert DEFAULT_TIER_REGISTRY.get(TIER_RF_SURVEY).rights == {
            AclRight("read", "ubus", "iwinfo", "survey")
        }
        assert DEFAULT_TIER_REGISTRY.get(TIER_RF_SCAN).rights == {_scan_right()}
        assert "off its channel" in DEFAULT_TIER_REGISTRY.get(TIER_RF_SCAN).risk

    def test_no_unwanted_rights_anywhere(self):
        everything = rights_from_acl(
            build_acl([t.tier_id for t in DEFAULT_TIER_REGISTRY.tiers()])
        )
        iwinfo = {r.method for r in everything if r.object == "iwinfo"}
        assert not iwinfo & {"countrylist", "phyname"}
        assert not any(
            r.object == "iw" or r.object.startswith("iw ") for r in everything
        )
        file_exec = {r for r in everything if r.scope == "file" and r.method == "exec"}
        assert file_exec == {AclRight("write", "file", "/etc/init.d/rpcd", "exec")}
        for tier in DEFAULT_TIER_REGISTRY.tiers():
            if not tier.mandatory:
                assert all(r.section == "read" for r in tier.rights)


class TestBuildAndChecksum:
    def test_deterministic_and_order_insensitive(self):
        a = build_acl([TIER_RF_SCAN, TIER_RF_SURVEY])
        b = build_acl([TIER_RF_SURVEY, TIER_RF_SCAN, TIER_RF_SURVEY, TIER_READ])
        assert a == b
        assert render_acl(a) == render_acl(b)
        assert acl_checksum(a) == acl_checksum(b)

    def test_checksum_is_sha256_of_written_text(self):
        acl = build_acl([TIER_RF_SURVEY])
        assert acl_checksum(acl) == hashlib.sha256(render_acl(acl).encode()).hexdigest()
        assert acl_checksum(acl) != acl_checksum(build_acl([]))

    def test_marker_round_trip(self):
        acl = build_acl([TIER_RF_SCAN])
        info = parse_tiered_acl(acl)
        assert info is not None
        assert info.version == TIERED_ACL_VERSION
        assert info.tiers == (TIER_READ, TIER_RF_SCAN)
        assert parse_tiered_acl(json.loads(render_acl(acl))) == info

    def test_unknown_tier_refused(self):
        with pytest.raises(AclTierError):
            build_acl(["root_shell"])
        with pytest.raises(AclTierError):
            build_acl(TIER_RF_SCAN)  # a bare string, not a list

    def test_rights_round_trip(self):
        tiers = [TIER_CONFIG_BACKUP_READ, TIER_RF_SCAN]
        expected = frozenset().union(
            *(DEFAULT_TIER_REGISTRY.get(t).rights for t in (TIER_READ, *tiers))
        )
        assert rights_from_acl(build_acl(tiers)) == expected

    def test_permission_strings(self):
        assert _scan_right().permission == "ubus:iwinfo.scan"
        assert AclRight("read", "cgi-io", "backup").permission == "cgi-io:backup"
        assert AclRight("read", "uci", "wireless").permission == "uci:wireless"
        assert (
            AclRight("read", "file", "/proc/cpuinfo", "read").permission
            == "file:/proc/cpuinfo:read"
        )

    def test_malformed_rights_refused(self):
        with pytest.raises(AclTierError):
            AclRight("admin", "ubus", "x", "y")
        with pytest.raises(AclTierError):
            AclRight("read", "ubus", "iwinfo")
        with pytest.raises(AclTierError):
            AclRight("read", "uci", "network", "read")


class TestRegistry:
    def _tier(self, **kw):
        base = {
            "tier_id": "diag_traceroute",
            "title": "Traceroute",
            "capabilities": ("diag.traceroute",),
            "rights": frozenset({AclRight("read", "ubus", "luci", "getTraceroute")}),
            "risk": "test",
            "module": "net_diagnostics",
        }
        base.update(kw)
        return AclTier(**base)

    def test_later_module_registers_a_tier(self, monkeypatch):
        # Changed deliberately (security review finding 1): a new right must
        # first be added to the reviewed extension table.
        monkeypatch.setattr(
            acl_mod,
            "OPTIONAL_TIER_EXTENSIONS",
            frozenset({("ubus", "luci", "getTraceroute")}),
        )
        reg = AclTierRegistry(DEFAULT_TIER_REGISTRY.tiers())
        reg.register(self._tier())
        assert reg.capability_tiers()["diag.traceroute"] == "diag_traceroute"
        acl = build_acl(["diag_traceroute"], registry=reg)
        assert acl["root"]["read"]["ubus"]["luci"] == ["getTraceroute"]
        # the shared default registry is not affected
        with pytest.raises(AclTierError):
            DEFAULT_TIER_REGISTRY.get("diag_traceroute")

    @pytest.mark.parametrize(
        "right",
        [
            AclRight("read", "file", "/usr/bin/traceroute", "exec"),
            AclRight("read", "file", "/tmp/x", "write"),
            AclRight("write", "ubus", "network", "restart"),
            AclRight("read", "ubus", "file", "exec"),
            AclRight("read", "file", "/usr/share/rpcd/acl.d/*", "read"),
        ],
    )
    def test_unsafe_optional_rights_refused(self, right):
        reg = AclTierRegistry(DEFAULT_TIER_REGISTRY.tiers())
        with pytest.raises(AclTierError):
            reg.register(self._tier(rights=frozenset({right})))

    def test_duplicates_and_second_base_refused(self):
        reg = AclTierRegistry(DEFAULT_TIER_REGISTRY.tiers())
        with pytest.raises(AclTierError):
            reg.register(DEFAULT_TIER_REGISTRY.get(TIER_RF_SCAN))
        with pytest.raises(AclTierError):
            reg.register(self._tier(tier_id="base2", mandatory=True))

    def test_invalid_definitions_refused(self):
        with pytest.raises(AclTierError):
            self._tier(tier_id="Bad-Id")
        with pytest.raises(AclTierError):
            self._tier(capabilities=("traceroute",))
        with pytest.raises(AclTierError):
            self._tier(rights=frozenset())
        with pytest.raises(AclTierError):
            self._tier(risk="")

    def test_offerable_follows_option(self):
        def ids(opts):
            return [t.tier_id for t in DEFAULT_TIER_REGISTRY.offerable(opts)]

        assert TIER_CONFIG_BACKUP_READ not in ids(None)
        assert TIER_CONFIG_BACKUP_READ not in ids({OPTION_CONFIG_BACKUP_ENABLED: False})
        assert TIER_CONFIG_BACKUP_READ in ids(OPTS_ON)
        assert TIER_RF_SCAN in ids(None)


class TestDescribeOffer:
    def test_v8_to_read_tier(self):
        offer = describe_offer(ACL_VERSION, [])
        assert [r.describe() for r in offer.added] == ["read ubus:iwinfo.txpowerlist"]
        assert [r.describe() for r in offer.removed] == ["read ubus:iwinfo.scan"]
        assert offer.current_kind is DeployedAclKind.LEGACY_CURRENT
        assert offer.acl == build_acl([])
        assert offer.acl_checksum == acl_checksum(build_acl([]))

    def test_v8_dict_equals_version_shorthand(self):
        assert describe_offer(RPCD_ACL_CONTENT, []) == describe_offer(ACL_VERSION, [])

    def test_v8_to_read_plus_scan_removes_nothing(self):
        offer = describe_offer(ACL_VERSION, [TIER_RF_SCAN])
        assert offer.removed == ()
        assert [r.describe() for r in offer.added] == ["read ubus:iwinfo.txpowerlist"]

    def test_config_tier_needs_option(self):
        with pytest.raises(AclTierError):
            describe_offer(ACL_VERSION, [TIER_CONFIG_BACKUP_READ], options={})
        offer = describe_offer(ACL_VERSION, [TIER_CONFIG_BACKUP_READ], options=OPTS_ON)
        added = {r.permission for r in offer.added}
        assert {"cgi-io:backup", "ubus:rpc-sys.packagelist", "uci:wireless"} <= added
        assert dict(offer.risks)[TIER_CONFIG_BACKUP_READ].startswith("Gives")

    def test_nothing_deployed(self):
        offer = describe_offer(None, [])
        assert offer.removed == ()
        assert set(offer.added) == rights_from_acl(build_acl([]))
        assert offer.current_kind is DeployedAclKind.MISSING

    def test_same_offer_is_unchanged(self):
        offer = describe_offer(build_acl([TIER_RF_SURVEY]), [TIER_RF_SURVEY])
        assert offer.unchanged
        assert offer.current_kind is DeployedAclKind.TIERED_CURRENT

    def test_binding_checksum_and_to_dict(self):
        offer = describe_offer(ACL_VERSION, [TIER_RF_SURVEY])
        assert offer.binding_checksum(ROUTER) == acl_binding_checksum(
            ROUTER, build_acl([TIER_RF_SURVEY])
        )
        data = json.loads(json.dumps(offer.to_dict()))
        assert data["acl_version"] == TIERED_ACL_VERSION
        assert data["removed"] == ["read ubus:iwinfo.scan"]
        assert "acl_json" not in data

    def test_other_versions_not_nameable(self):
        with pytest.raises(AclTierError):
            describe_offer(7, [])
        with pytest.raises(AclTierError):
            describe_offer(True, [])


class TestClassifyAndCapabilities:
    def test_classify(self):
        tiered = build_acl([TIER_RF_SCAN])
        assert classify_deployed_acl(None) is DeployedAclKind.MISSING
        assert classify_deployed_acl(RPCD_ACL_CONTENT) is DeployedAclKind.LEGACY_CURRENT
        assert classify_deployed_acl(tiered) is DeployedAclKind.TIERED_CURRENT
        edited = json.loads(json.dumps(tiered))
        edited["root"]["read"]["ubus"]["iwinfo"].append("countrylist")
        assert classify_deployed_acl(edited) is DeployedAclKind.TIERED_OTHER
        assert classify_deployed_acl({"root": {}}) is DeployedAclKind.FOREIGN

    def test_granted_capabilities(self):
        v8 = granted_capabilities(RPCD_ACL_CONTENT)
        assert v8[CAPABILITY_RF_SCAN] is True
        assert v8[CAPABILITY_RF_SURVEY] is False
        assert v8[CAPABILITY_RF_TXPOWERLIST] is False
        assert v8[Capability.CONFIG_CGI_BACKUP] is False
        read_only = granted_capabilities(build_acl([]))
        assert read_only[CAPABILITY_RF_SCAN] is False
        assert read_only[CAPABILITY_RF_TXPOWERLIST] is True
        assert read_only[Capability.DATA_IWINFO] is True

    def test_missing_permissions_for_scan_after_read_tier(self):
        assert missing_permissions(build_acl([]), CAPABILITY_RF_SCAN) == (
            "ubus:iwinfo.scan",
        )
        assert missing_permissions(RPCD_ACL_CONTENT, CAPABILITY_RF_SCAN) == ()
        assert missing_permissions(build_acl([]), "unknown.cap") == ()


# ---------------------------------------------------------------------------
# Deploy: refusals (nothing reaches the router)
# ---------------------------------------------------------------------------


def _assert_untouched(api):
    api._call.assert_not_awaited()
    api._run_ssh.assert_not_awaited()


class TestDeployRefusals:
    @pytest.mark.asyncio
    async def test_no_authorization(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api,
                [],
                router_id=ROUTER,
                authorization=None,
                guard_consume=guard.consume,
            )
        assert exc.value.reason == "no_authorization"
        assert guard.calls == []
        _assert_untouched(api)

    @pytest.mark.asyncio
    async def test_not_a_write_authorization(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        fake = MagicMock(consumed=True, action="acl_deploy", router_id=ROUTER)
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api,
                [],
                router_id=ROUTER,
                authorization=fake,
                guard_consume=guard.consume,
            )
        assert exc.value.reason == "no_authorization"
        _assert_untouched(api)

    @pytest.mark.asyncio
    async def test_wrong_router(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        auth = guard.issue(router_id=OTHER_ROUTER)
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api,
                [],
                router_id=ROUTER,
                authorization=auth,
                guard_consume=guard.consume,
            )
        assert exc.value.reason == "router_mismatch"
        assert auth.consumed  # fail closed: a failed consume uses it up
        _assert_untouched(api)

    @pytest.mark.asyncio
    async def test_wrong_checksum_other_tiers(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        auth = guard.issue(tiers=[TIER_RF_SURVEY])  # approved: survey
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api,
                [TIER_RF_SCAN],  # attempted: scan
                router_id=ROUTER,
                authorization=auth,
                guard_consume=guard.consume,
            )
        assert exc.value.reason == "checksum_mismatch"
        _assert_untouched(api)

    @pytest.mark.asyncio
    async def test_wrong_action(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        auth = guard.issue(action=GuardedAction.EXPORT)
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api,
                [],
                router_id=ROUTER,
                authorization=auth,
                guard_consume=guard.consume,
            )
        assert exc.value.reason == "action_mismatch"
        _assert_untouched(api)

    @pytest.mark.asyncio
    async def test_reused_authorization(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        auth = guard.issue()
        await async_deploy_acl_offer(
            api, [], router_id=ROUTER, authorization=auth, guard_consume=guard.consume
        )
        api2 = _api(V8_TEXT)
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api2,
                [],
                router_id=ROUTER,
                authorization=auth,
                guard_consume=guard.consume,
            )
        assert exc.value.reason == "already_used"
        _assert_untouched(api2)

    @pytest.mark.asyncio
    async def test_expired_authorization(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        auth = guard.issue(now=datetime.now(UTC) - timedelta(hours=1))
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api,
                [],
                router_id=ROUTER,
                authorization=auth,
                guard_consume=guard.consume,
            )
        assert exc.value.reason == "expired"
        _assert_untouched(api)

    @pytest.mark.asyncio
    async def test_authorization_not_from_this_guard(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        stranger = FakeGuard().issue()
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api,
                [],
                router_id=ROUTER,
                authorization=stranger,
                guard_consume=guard.consume,
            )
        assert exc.value.reason == "unknown_authorization"
        _assert_untouched(api)

    @pytest.mark.asyncio
    async def test_stub_guard_that_does_not_consume(self):
        """A consume that does nothing must not open the write path."""
        api, guard = _api(V8_TEXT), FakeGuard()
        auth = guard.issue()
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api,
                [],
                router_id=ROUTER,
                authorization=auth,
                guard_consume=lambda *a, **k: None,
            )
        assert exc.value.reason == "not_consumed"
        _assert_untouched(api)

    @pytest.mark.asyncio
    async def test_guard_crash_fails_closed(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        auth = guard.issue()

        def _boom(*a, **k):
            raise RuntimeError("ledger store broken")

        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api, [], router_id=ROUTER, authorization=auth, guard_consume=_boom
            )
        assert exc.value.reason == "consume_failed"
        _assert_untouched(api)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "options", [None, {}, {OPTION_CONFIG_BACKUP_ENABLED: False}]
    )
    async def test_config_tier_refused_while_option_off(self, options):
        api, guard = _api(V8_TEXT), FakeGuard()
        auth = guard.issue(tiers=[TIER_CONFIG_BACKUP_READ])
        with pytest.raises(AclOfferRefusedError) as exc:
            await async_deploy_acl_offer(
                api,
                [TIER_CONFIG_BACKUP_READ],
                router_id=ROUTER,
                authorization=auth,
                guard_consume=guard.consume,
                options=options,
            )
        assert exc.value.reason == "option_disabled"
        assert not auth.consumed  # refused before the guard was asked
        _assert_untouched(api)

    @pytest.mark.asyncio
    async def test_unknown_tier(self):
        api, guard = _api(V8_TEXT), FakeGuard()
        with pytest.raises(AclTierError):
            await async_deploy_acl_offer(
                api,
                ["everything"],
                router_id=ROUTER,
                authorization=guard.issue(),
                guard_consume=guard.consume,
            )
        _assert_untouched(api)

    def test_refusal_is_an_authorization_error(self):
        err = AclOfferRefusedError("x", "m", router_id=ROUTER)
        assert isinstance(err, AuthorizationError)
        assert err.details == {"reason": "x"}


# ---------------------------------------------------------------------------
# Deploy: authorized paths (mock router)
# ---------------------------------------------------------------------------


def _pinned_runner(api):
    """Stand-in for the core's pinned SSH runner (records on api._run_ssh)."""

    async def runner(cmd, timeout):
        return await api._run_ssh(cmd, timeout=timeout)

    return runner


async def _deploy(api, tiers=(), *, options=None, guard=None, pinned=True):
    guard = guard or FakeGuard()
    auth = guard.issue(tiers=tiers)
    result = await async_deploy_acl_offer(
        api,
        tiers,
        router_id=ROUTER,
        authorization=auth,
        guard_consume=guard.consume,
        options=options,
        now=NOW,
        ssh_runner=_pinned_runner(api) if pinned else None,
    )
    assert auth.consumed
    assert guard.calls == [
        {
            "action": "acl_deploy",
            "router_id": ROUTER,
            "checksum": acl_binding_checksum(ROUTER, build_acl(tiers)),
        }
    ]
    return result


class TestDeployUbus:
    @pytest.mark.asyncio
    async def test_backup_then_write_then_one_restart(self):
        api = _api(V8_TEXT)
        result = await _deploy(api, [TIER_RF_SURVEY])
        calls = _calls(api)
        assert [m for m, _ in calls] == ["read", "write", "write", "exec"]
        assert calls[1][1] == {"path": BACKUP, "data": V8_TEXT}
        expected = render_acl(build_acl([TIER_RF_SURVEY]))
        assert calls[2][1] == {"path": ACL_FILE_PATH, "data": expected}
        assert calls[3][1] == {"command": "/etc/init.d/rpcd", "params": ["restart"]}
        api._run_ssh.assert_not_awaited()
        assert result.changed and result.transport == "ubus"
        assert result.backup_path == BACKUP
        assert result.previous_checksum == V8_SHA256
        assert result.previous_content == V8_TEXT
        assert result.rollback_command == (
            f"cp -p {BACKUP} {ACL_FILE_PATH} && /etc/init.d/rpcd restart"
        )
        assert result.rpcd_restarted is True
        assert result.acl_checksum == acl_checksum(build_acl([TIER_RF_SURVEY]))
        data = json.loads(json.dumps(result.to_dict()))
        assert data["rollback_command"] == result.rollback_command
        assert "previous_content" not in data

    @pytest.mark.asyncio
    async def test_config_tier_with_option_on(self):
        api = _api(V8_TEXT)
        result = await _deploy(api, [TIER_CONFIG_BACKUP_READ], options=OPTS_ON)
        written = json.loads(_writes(api)[1]["data"])
        assert written["root"]["read"]["cgi-io"] == ["backup"]
        assert result.tiers == (TIER_READ, TIER_CONFIG_BACKUP_READ)

    @pytest.mark.asyncio
    async def test_identical_acl_on_router_is_not_rewritten(self):
        """Read tier already deployed: approval used, but no write, no restart."""
        api = _api(render_acl(build_acl([])))
        result = await _deploy(api, [])
        assert [m for m, _ in _calls(api)] == ["read"]
        api._run_ssh.assert_not_awaited()
        assert result.changed is False
        assert result.transport == "none"
        assert result.rollback_command is None
        assert result.rpcd_restarted is False

    @pytest.mark.asyncio
    async def test_restart_failure_is_non_fatal(self):
        api = _api(V8_TEXT)

        def _side_effect(obj, method, params):
            if method == "read":
                return {"data": V8_TEXT}
            if method == "exec":
                raise OpenWrtResponseError("exec denied")
            return {}

        api._call.side_effect = _side_effect
        result = await _deploy(api, [])
        assert result.changed is True
        assert result.rpcd_restarted is False
        assert len(_execs(api)) == 1

    @pytest.mark.asyncio
    async def test_unreachable_before_anything_written(self):
        api = _api(OpenWrtConnectionError("down"))
        with pytest.raises(AclOfferDeployError) as exc:
            await _deploy(api, [])
        assert exc.value.reason == "unreachable"
        assert exc.value.written is False
        assert _writes(api) == []
        assert isinstance(exc.value, AclDeployError)

    @pytest.mark.asyncio
    async def test_timeout_during_acl_write_reports_way_back(self):
        api = _api(V8_TEXT)

        def _side_effect(obj, method, params):
            if method == "read":
                return {"data": V8_TEXT}
            if method == "write" and params["path"] == ACL_FILE_PATH:
                raise OpenWrtTimeoutError("timeout")
            return {}

        api._call.side_effect = _side_effect
        with pytest.raises(AclOfferDeployError) as exc:
            await _deploy(api, [])
        assert exc.value.reason == "unreachable"
        assert exc.value.written is None  # unknown
        assert exc.value.backup_path == BACKUP
        assert exc.value.rollback_command.startswith(f"cp -p {BACKUP} ")
        assert _execs(api) == []


class TestDeploySsh:
    @pytest.mark.asyncio
    async def test_backup_write_blocked_goes_to_ssh(self):
        api = _api(V8_TEXT)

        def _side_effect(obj, method, params):
            if method == "read":
                return {"data": V8_TEXT}
            if method == "write":
                raise OpenWrtMethodNotFoundError("ACL blocks file/write")
            raise AssertionError(f"unexpected {method}")

        api._call.side_effect = _side_effect
        api._run_ssh = AsyncMock(
            return_value="HA_ACL_BACKED_UP\nHA_ACL_OFFER_DEPLOYED\n"
        )
        result = await _deploy(api, [TIER_RF_SCAN])
        api._run_ssh.assert_awaited_once()
        cmd = api._run_ssh.await_args.args[0]
        # backup strictly before the write, atomic rename, one restart
        assert cmd.index(f"cp -p {ACL_FILE_PATH} {BACKUP}") < cmd.index("printf")
        assert f"mv {ACL_FILE_PATH}.new {ACL_FILE_PATH}" in cmd
        assert cmd.count("/etc/init.d/rpcd restart") == 1
        assert "s3cret-router-pw" not in cmd
        assert render_acl(build_acl([TIER_RF_SCAN])).splitlines()[1] in cmd
        assert _execs(api) == []  # no second restart via ubus
        assert len(_writes(api)) == 1  # only the rejected backup attempt
        assert result.transport == "ssh"
        assert result.backup_path == BACKUP
        assert result.rollback_command.startswith(f"cp -p {BACKUP} ")

    @pytest.mark.asyncio
    async def test_acl_write_blocked_after_ubus_backup(self):
        api = _api(V8_TEXT)

        def _side_effect(obj, method, params):
            if method == "read":
                return {"data": V8_TEXT}
            if method == "write" and params["path"] == ACL_FILE_PATH:
                raise OpenWrtResponseError("denied")
            if method == "write":
                return {}
            raise AssertionError(f"unexpected {method}")

        api._call.side_effect = _side_effect
        api._run_ssh = AsyncMock(
            return_value="HA_ACL_BACKED_UP\nHA_ACL_OFFER_DEPLOYED\n"
        )
        result = await _deploy(api, [])
        assert _execs(api) == []
        assert api._run_ssh.await_args.args[0].count("rpcd restart") == 1
        assert result.transport == "ssh"

    @pytest.mark.asyncio
    async def test_unreadable_acl_never_written_without_shell_backup(self):
        """ubus cannot tell missing from blocked: no ubus write at all."""
        api = _api(OpenWrtMethodNotFoundError("blocked or missing"))
        api._run_ssh = AsyncMock(return_value="HA_ACL_OFFER_DEPLOYED\n")
        result = await _deploy(api, [])
        assert _writes(api) == []
        cmd = api._run_ssh.await_args.args[0]
        assert f"[ ! -e {ACL_FILE_PATH} ] ||" in cmd
        # no backup marker: there was no file -> way back is removing ours
        assert result.backup_path is None
        assert result.rollback_command == (
            f"rm -f {ACL_FILE_PATH} && /etc/init.d/rpcd restart"
        )
        assert result.previous_content is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("stdout", [None, "", "HA_ACL_BACKED_UP\n", "cp: denied"])
    async def test_ssh_without_deploy_marker_fails(self, stdout):
        api = _api(OpenWrtResponseError("blocked"))
        api._run_ssh = AsyncMock(return_value=stdout)
        with pytest.raises(AclOfferDeployError) as exc:
            await _deploy(api, [])
        assert exc.value.reason == "write_blocked"
        assert exc.value.written is False
        if stdout and "BACKED_UP" in stdout:
            assert exc.value.rollback_command.startswith(f"cp -p {BACKUP} ")
        else:
            assert exc.value.rollback_command is None


class TestDeploySshOnlyPinned:
    """1.44.0: the offer's SSH fallback only runs over the pinned path."""

    @pytest.mark.asyncio
    async def test_without_pinned_runner_refuses_before_any_ssh(self):
        api = _api(OpenWrtMethodNotFoundError("blocked or missing"))
        guard = FakeGuard()
        auth = guard.issue(tiers=())
        with pytest.raises(AclOfferDeployError) as exc:
            await async_deploy_acl_offer(
                api,
                (),
                router_id=ROUTER,
                authorization=auth,
                guard_consume=guard.consume,
                now=NOW,
            )
        assert exc.value.reason == "ssh_pin_unavailable"
        assert exc.value.written is False
        api._run_ssh.assert_not_awaited()  # never the shared, unpinned SSH
        assert _writes(api) == []

    @pytest.mark.asyncio
    async def test_ubus_path_needs_no_runner(self):
        api = _api(V8_TEXT)
        result = await _deploy(api, [], pinned=False)
        assert result.transport == "ubus"
        api._run_ssh.assert_not_awaited()


class TestRestartAtMostOnce:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("read", "write_blocked", "ssh_out"),
        [
            (V8_TEXT, False, None),
            (V8_TEXT, True, "HA_ACL_BACKED_UP\nHA_ACL_OFFER_DEPLOYED\n"),
            (OpenWrtResponseError("x"), False, "HA_ACL_OFFER_DEPLOYED\n"),
        ],
        ids=["ubus", "ubus_blocked_ssh", "unreadable_ssh"],
    )
    async def test_one_restart_for_all_tiers(self, read, write_blocked, ssh_out):
        api = _api(read)
        if write_blocked:

            def _side_effect(obj, method, params):
                if method == "read":
                    return {"data": V8_TEXT}
                if method == "write":
                    raise OpenWrtMethodNotFoundError("blocked")
                return {}

            api._call.side_effect = _side_effect
        api._run_ssh = AsyncMock(return_value=ssh_out)
        all_tiers = [t.tier_id for t in DEFAULT_TIER_REGISTRY.tiers()]
        await _deploy(api, all_tiers, options=OPTS_ON)
        ssh_restarts = sum(
            c.args[0].count("/etc/init.d/rpcd restart")
            for c in api._run_ssh.await_args_list
        )
        assert len(_execs(api)) + ssh_restarts == 1
        acl_writes = [w for w in _writes(api) if w["path"] == ACL_FILE_PATH]
        assert len(acl_writes) + api._run_ssh.await_count == 1


# ---------------------------------------------------------------------------
# ensure_acl_respecting_offer
# ---------------------------------------------------------------------------


class TestEnsureRespectingOffer:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tiers", [[], [TIER_RF_SCAN, TIER_RF_SURVEY]])
    async def test_tiered_acl_is_left_alone(self, tiers):
        api = _api(render_acl(build_acl(tiers)))
        assert await ensure_acl_respecting_offer(api) is False
        assert [m for m, _ in _calls(api)] == ["read"]
        api._run_ssh.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_outdated_tiered_acl_is_left_alone_too(self):
        old = build_acl([])
        old["root"]["read"]["ubus"]["iwinfo"].remove("txpowerlist")
        api = _api(json.dumps(old))
        assert await ensure_acl_respecting_offer(api) is False
        assert _writes(api) == []

    @pytest.mark.asyncio
    async def test_v8_delegates_without_write(self):
        api = _api(V8_TEXT)
        assert await ensure_acl_respecting_offer(api) is False
        assert _writes(api) == []

    @pytest.mark.asyncio
    async def test_old_legacy_acl_is_still_upgraded_to_v8(self):
        api = _api(json.dumps({"root": {"read": {"ubus": {}}}}))
        assert await ensure_acl_respecting_offer(api) is True
        assert _writes(api) == [{"path": ACL_FILE_PATH, "data": V8_TEXT}]

    @pytest.mark.asyncio
    async def test_read_error_delegates(self):
        api = _api(None)  # NOT_FOUND
        assert await ensure_acl_respecting_offer(api) is True
        assert _writes(api)[0]["data"] == V8_TEXT


# ---------------------------------------------------------------------------
# Structure: who may write at all
# ---------------------------------------------------------------------------


def _router_writers(tree: ast.Module) -> dict[str, ast.AST]:
    """Top-level functions that send file/write, file/exec or an SSH command."""
    writers: dict[str, ast.AST] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for call in ast.walk(node):
            if not isinstance(call, ast.Call) or not isinstance(
                call.func, ast.Attribute
            ):
                continue
            if call.func.attr == "_run_ssh":
                writers[node.name] = node
            if call.func.attr == "_call" and len(call.args) >= 2:
                arg = call.args[1]
                if isinstance(arg, ast.Constant) and arg.value in ("write", "exec"):
                    writers[node.name] = node
    return writers


def _callers(tree: ast.Module, name: str) -> set[str]:
    out = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for call in ast.walk(node):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == name
                ):
                    out.add(node.name)
    return out


class TestOnlyAuthorizedWrites:
    def test_write_paths_are_known(self):
        tree = ast.parse(inspect.getsource(acl_mod))
        assert set(_router_writers(tree)) == {
            "_deploy_acl",  # legacy v8 path (unchanged)
            "_deploy_acl_ssh",  # legacy v8 path (unchanged, the only _run_ssh)
            "async_deploy_acl_offer",
        }
        # 1.44.0: one shared ensure implementation; the offer's SSH goes
        # through the injected pinned runner only, never api._run_ssh.
        assert _callers(tree, "_deploy_acl") == {"ensure_acl_outcome"}
        assert _callers(tree, "_deploy_acl_ssh") == {"_deploy_acl"}
        assert _callers(tree, "_deploy_offer_ssh") == {"async_deploy_acl_offer"}
        offer_ssh = inspect.getsource(acl_mod._deploy_offer_ssh)
        assert "_run_ssh" not in offer_ssh
        assert "await ssh_runner(" in offer_ssh

    def test_legacy_path_only_ever_writes_v8(self):
        src = inspect.getsource(acl_mod._deploy_acl) + inspect.getsource(
            acl_mod._deploy_acl_ssh
        )
        assert src.count("json.dumps(RPCD_ACL_CONTENT, indent=2)") == 2
        assert "build_acl" not in src

    def test_authorization_checked_before_first_router_call(self):
        fn = next(
            n
            for n in ast.parse(inspect.getsource(acl_mod)).body
            if isinstance(n, ast.AsyncFunctionDef)
            and n.name == "async_deploy_acl_offer"
        )
        check_line = min(
            c.lineno
            for c in ast.walk(fn)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name)
            and c.func.id == "_check_authorization"
        )
        io_lines = [
            c.lineno
            for c in ast.walk(fn)
            if isinstance(c, ast.Call)
            and (
                (
                    isinstance(c.func, ast.Attribute)
                    and c.func.attr in ("_call", "_run_ssh")
                )
                or (
                    isinstance(c.func, ast.Name)
                    and c.func.id in ("_read_current_acl", "_deploy_offer_ssh")
                )
            )
        ]
        assert io_lines
        assert check_line < min(io_lines)
