"""Type-level tests for the hardened Configuration API v1 contract.

Covers the review's blockers 1-3 and findings 4, 6, 9-16 plus the
config-manager rulings (dedup candidate, baselines, installation key,
event types, provider context, snapshot format). Pure types only: no hass
instance, no router, no store.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router.core_errors import (
    ApprovalInvalidError,
    ApprovalRequiredError,
    AuthorizationError,
    BackupMetadataError,
    ErrorClass,
    InstallationKeyLostError,
    InvalidStorageRefError,
    VersionProtectedError,
)
from custom_components.openwrt_router.core_masking import MASK
from custom_components.openwrt_router.core_models import (
    ACTOR_VERIFICATION_TTL,
    AUDIT_MANDATORY_EVENT_TYPES,
    FLEET_BACKUP_CONCURRENCY,
    SECURITY_EVENT_TYPES,
    SNAPSHOT_FORMAT_UCI_NORMALIZED,
    ActionGuardProtocol,
    Actor,
    ActorKind,
    ApprovalRequest,
    ApprovalStatus,
    ArtifactKind,
    ArtifactRef,
    AuditRing,
    BackupLinks,
    BackupReason,
    BackupRecord,
    BackupType,
    Baseline,
    BaselineRule,
    CapabilityState,
    CapabilityStatus,
    ChangeKind,
    CompatibilityIssue,
    ConfigBackupProvider,
    ConfigChange,
    ConfigDiff,
    ConfigRef,
    ConfigSnapshot,
    ConfigurationApiProtocol,
    CoreEvent,
    CoreEventType,
    DriftAck,
    DriftAckState,
    DriftReport,
    GuardedAction,
    IdentityFlag,
    IdentityStatus,
    InstallationKeyState,
    KeepReason,
    ProviderContext,
    RestoreResult,
    RestoreStatus,
    RestoreStep,
    RetentionPolicy,
    RouterIdentity,
    RouterRecord,
    StorageRef,
    ValidationInfo,
    ValidationStatus,
    VerifiedActor,
    VersionMeta,
    VersionReadView,
    VersionStatus,
    VersionStoreProtocol,
    WriteAuthorization,
    async_actor_from_context,
    async_verify_actor,
    audit_ring_for,
    binding_checksum,
    check_redeem,
    dedup_candidate,
    default_router_id,
    drift_event_types,
    installation_key_id,
    installation_key_state,
    integrity_failed,
    is_core_event_type,
    new_id,
    plan_retention,
    policy_denial_reason,
    resolve_artifact_path,
    select_baseline,
    should_deduplicate,
    validate_deletion,
    validate_locator,
)
from custom_components.openwrt_router.net_events import Severity

T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
RID = default_router_id("entry-a")
OTHER_RID = default_router_id("entry-b")


def _hass(user=None):
    hass = MagicMock()
    hass.auth.async_get_user = AsyncMock(return_value=user)
    return hass


def _user(*, admin=True, active=True, system=False):
    return MagicMock(is_admin=admin, is_active=active, system_generated=system)


async def _verified(kind=ActorKind.USER, *, admin=True, user_id="u1", module=None):
    actor = Actor(kind=kind, user_id=user_id, module=module, is_admin=True)
    return await async_verify_actor(_hass(_user(admin=admin)), actor, now=T0)


def _bid(n: int) -> str:
    return "bkp_" + f"{n:032x}"


def _art(kind: str = "archive", size: int = 10) -> ArtifactRef:
    return ArtifactRef(
        storage=StorageRef(locator=f"v.{kind}"), sha256="a" * 64, size_bytes=size
    )


def _rec(n: int, **kw) -> BackupRecord:
    values = {
        "backup_id": _bid(n),
        "router_id": RID,
        "created_at": T0 + timedelta(hours=n),
        "backup_type": BackupType.FULL_ARCHIVE,
        "reason": BackupReason.SCHEDULED,
        "created_by": Actor.system(),
        "content_hash": "c" * 64,
        "artifacts": {"archive": _art()},
    }
    values.update(kw)
    return BackupRecord(**values)


def _meta(**kw) -> VersionMeta:
    values = {
        "backup_type": BackupType.FULL_ARCHIVE,
        "reason": BackupReason.SCHEDULED,
        "content_hash": "c" * 64,
    }
    values.update(kw)
    return VersionMeta(**values)


# ---------------------------------------------------------------------------
# Blocker 1: admin rights are verified, never self-declared
# ---------------------------------------------------------------------------


class TestVerifiedActor:
    def test_cannot_be_built_directly(self):
        with pytest.raises(TypeError):
            VerifiedActor(actor=Actor(kind=ActorKind.USER), verified_at=T0)

    async def test_self_declared_admin_is_ignored(self):
        actor = Actor(kind=ActorKind.USER, user_id="u1", is_admin=True)
        verified = await async_verify_actor(_hass(_user(admin=False)), actor)
        assert verified.is_admin is False
        assert verified.actor.is_admin is False

    async def test_admin_is_recomputed(self):
        actor = Actor(kind=ActorKind.USER, user_id="u1", is_admin=False)
        verified = await async_verify_actor(_hass(_user()), actor, now=T0)
        assert verified.is_admin is True
        assert verified.verified_at == T0
        assert verified.verification_id.startswith("vac_")

    async def test_system_generated_user_is_not_admin(self):
        actor = Actor(kind=ActorKind.USER, user_id="u1")
        verified = await async_verify_actor(_hass(_user(system=True)), actor)
        assert verified.is_admin is False

    @pytest.mark.parametrize("user", [None, _user(active=False)])
    async def test_unknown_or_inactive_user_rejected(self, user):
        with pytest.raises(AuthorizationError) as err:
            await async_verify_actor(
                _hass(user), Actor(kind=ActorKind.USER, user_id="u1")
            )
        assert err.value.details["reason"] == "unknown_user"

    async def test_non_user_actors_never_admin(self):
        hass = _hass()
        verified = await async_verify_actor(hass, Actor.for_module("cm"))
        assert verified.is_admin is False
        hass.auth.async_get_user.assert_not_called()

    async def test_context_helper_checks_system_generated(self):
        from homeassistant.core import Context

        hass = _hass(_user(system=True))
        actor = await async_actor_from_context(hass, Context(user_id="u1"))
        assert actor.is_admin is False

    async def test_freshness(self):
        verified = await _verified()
        assert verified.is_fresh(T0 + ACTOR_VERIFICATION_TTL)
        assert not verified.is_fresh(T0 + ACTOR_VERIFICATION_TTL + timedelta(1))


class TestPolicy:
    def test_plain_actor_is_unverified(self):
        actor = Actor(kind=ActorKind.USER, user_id="u1", is_admin=True)
        assert policy_denial_reason("backup", actor, now=T0) == "unverified_actor"

    async def test_stale_verification(self):
        actor = await _verified()
        later = T0 + timedelta(minutes=5)
        assert (
            policy_denial_reason("backup", actor, now=later)
            == "actor_verification_expired"
        )

    async def test_admin_user(self):
        actor = await _verified()
        for action in GuardedAction:
            expected = "system_only" if action is GuardedAction.PRUNE else None
            assert policy_denial_reason(action, actor, now=T0) == expected

    async def test_non_admin_user_may_not_mutate(self):
        # Ruling on config-manager point 13: non-admin users only read.
        actor = await _verified(admin=False)
        assert policy_denial_reason("backup", actor, now=T0) == "not_admin"
        assert policy_denial_reason("restore", actor, now=T0) == "not_admin"

    async def test_automation(self):
        actor = await _verified(ActorKind.AUTOMATION, user_id=None)
        assert policy_denial_reason("backup", actor, now=T0) is None
        assert (
            policy_denial_reason("restore", actor, now=T0) == "automation_not_allowed"
        )
        assert policy_denial_reason("protect", actor, now=T0) == "not_admin"

    async def test_module_and_system(self):
        module = await _verified(ActorKind.MODULE, user_id=None, module="cm")
        assert policy_denial_reason("delete", module, now=T0) is None
        assert policy_denial_reason("export", module, now=T0) == "not_admin"
        assert policy_denial_reason("prune", module, now=T0) == "system_only"
        system = await _verified(ActorKind.SYSTEM, user_id=None)
        assert policy_denial_reason("prune", system, now=T0) is None

    async def test_unknown_action(self):
        actor = await _verified()
        assert policy_denial_reason("format_disk", actor, now=T0) == "unknown_action"

    async def test_installation_key_reset_is_critical_admin_only(self):
        module = await _verified(ActorKind.MODULE, user_id=None, module="cm")
        assert policy_denial_reason("installation_key_reset", module, now=T0) == (
            "not_admin"
        )


# ---------------------------------------------------------------------------
# Blocker 2: no raw artifact access for modules, safe locators
# ---------------------------------------------------------------------------


class TestArtifactAccess:
    @pytest.mark.parametrize(
        "locator",
        ["", "..", "../x", "a/b", "a\\b", ".hidden", "x..y", "x y", None, "é"],
    )
    def test_bad_locators(self, locator):
        with pytest.raises(InvalidStorageRefError):
            validate_locator(locator)
        with pytest.raises(InvalidStorageRefError):
            StorageRef(locator=locator)  # type: ignore[arg-type]

    def test_bad_locator_in_metadata_is_metadata_error(self):
        data = _rec(1).to_dict()
        data["artifacts"]["archive"]["storage"]["locator"] = "../../etc/shadow"
        with pytest.raises(BackupMetadataError):
            BackupRecord.from_dict(data)

    def test_resolve_inside(self, tmp_path):
        path = resolve_artifact_path(str(tmp_path), "bkp_1.tar.gz")
        assert os.path.dirname(path) == os.path.realpath(tmp_path)

    def test_resolve_symlink_escape(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        router = tmp_path / "router"
        router.mkdir()
        try:
            (router / "link").symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks not permitted on this system")
        with pytest.raises(InvalidStorageRefError):
            resolve_artifact_path(str(router), "link")

    def test_modules_get_no_byte_access(self):
        assert not hasattr(VersionReadView, "async_read_artifact")
        assert not hasattr(ConfigBackupProvider, "async_read_artifact")
        assert hasattr(VersionStoreProtocol, "async_read_artifact")
        assert not hasattr(ConfigurationApiProtocol, "async_read_artifact")


# ---------------------------------------------------------------------------
# Blocker 3: only the requester redeems; export binds the artifact kind
# ---------------------------------------------------------------------------


def _approval(requester: Actor, **kw) -> ApprovalRequest:
    values = {
        "approval_id": new_id("apr_"),
        "action": GuardedAction.EXPORT,
        "router_id": RID,
        "subject_id": _bid(1),
        "checksum": binding_checksum(_bid(1), ArtifactKind.ARCHIVE),
        "requested_by": requester,
        "requested_at": T0,
        "expires_at": T0 + timedelta(minutes=15),
        "status": ApprovalStatus.APPROVED,
    }
    values.update(kw)
    return ApprovalRequest(**values)


class TestRedeem:
    async def _redeem(self, approval, actor, **kw):
        call = {
            "action": GuardedAction.EXPORT,
            "router_id": RID,
            "checksum": binding_checksum(_bid(1), ArtifactKind.ARCHIVE),
            "now": T0,
        }
        call.update(kw)
        check_redeem(approval, actor, **call)

    async def test_requester_redeems(self):
        actor = await _verified()
        await self._redeem(_approval(actor.actor), actor)

    async def test_other_admin_cannot_redeem(self):
        requester = await _verified(user_id="u1")
        other = await _verified(user_id="u2")
        with pytest.raises(ApprovalInvalidError) as err:
            await self._redeem(_approval(requester.actor), other)
        assert err.value.details["reason"] == "not_requester"

    async def test_requester_lost_admin(self):
        requester = await _verified()
        demoted = await _verified(admin=False)
        with pytest.raises(ApprovalInvalidError) as err:
            await self._redeem(_approval(requester.actor), demoted)
        assert err.value.details["reason"] == "not_admin"

    async def test_unverified_actor(self):
        requester = await _verified()
        with pytest.raises(AuthorizationError):
            await self._redeem(_approval(requester.actor), requester.actor)

    async def test_pending(self):
        actor = await _verified()
        approval = _approval(actor.actor, status=ApprovalStatus.PENDING)
        with pytest.raises(ApprovalRequiredError):
            await self._redeem(approval, actor)

    @pytest.mark.parametrize(
        ("kw", "reason"),
        [
            ({"checksum": binding_checksum(_bid(1), "uci")}, "checksum_mismatch"),
            ({"router_id": OTHER_RID}, "router_mismatch"),
            ({"action": GuardedAction.DELETE}, "action_mismatch"),
        ],
    )
    async def test_binding(self, kw, reason):
        actor = await _verified()
        with pytest.raises(ApprovalInvalidError) as err:
            await self._redeem(_approval(actor.actor), actor, **kw)
        assert err.value.details["reason"] == reason

    async def test_expired(self):
        actor = await _verified()
        approval = _approval(actor.actor, expires_at=T0)
        with pytest.raises(ApprovalInvalidError) as err:
            await self._redeem(approval, actor)
        assert err.value.details["reason"] == "expired"

    @pytest.mark.parametrize(
        "status", [ApprovalStatus.USED, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED]
    )
    async def test_final_states(self, status):
        actor = await _verified()
        with pytest.raises(ApprovalInvalidError) as err:
            await self._redeem(_approval(actor.actor, status=status), actor)
        assert err.value.details["reason"] == status.value

    def test_export_binding_includes_artifact_kind(self):
        assert binding_checksum(_bid(1), "archive") != binding_checksum(_bid(1), "uci")


# ---------------------------------------------------------------------------
# Findings 4 and 7: dedup scope and audit rings
# ---------------------------------------------------------------------------


class TestEventDedupAndRings:
    def _event(self, type_, **kw):
        return CoreEvent(
            event_id=new_id("evt_"), ts=T0, type=type_, source="core", **kw
        )

    def test_scope_includes_router_and_type(self):
        a = self._event(CoreEventType.BACKUP_FAILED, router_id=RID, dedup_key="timeout")
        b = self._event(
            CoreEventType.BACKUP_FAILED, router_id=OTHER_RID, dedup_key="timeout"
        )
        c = self._event(
            CoreEventType.DRIFT_DETECTED, router_id=RID, dedup_key="timeout"
        )
        assert len({a.dedup_scope, b.dedup_scope, c.dedup_scope}) == 3
        assert self._event("x.y", dedup_key="k").dedup_scope == ("-", "x.y", "k")

    @pytest.mark.parametrize("type_", sorted(AUDIT_MANDATORY_EVENT_TYPES))
    def test_mandatory_types_ignore_dedup(self, type_):
        assert self._event(type_, router_id=RID, dedup_key="k").dedup_scope is None

    def test_repeat_counter_round_trip(self):
        event = self._event(
            CoreEventType.BACKUP_FAILED,
            dedup_key="timeout",
            repeat_count=3,
            last_repeat_at=T0,
        )
        restored = CoreEvent.from_dict(event.to_dict())
        assert restored.repeat_count == 3
        assert restored.last_repeat_at == T0

    def test_negative_repeat_rejected(self):
        with pytest.raises(ValueError):
            self._event(CoreEventType.BACKUP_FAILED, repeat_count=-1)

    def test_rings(self):
        assert audit_ring_for(CoreEventType.BACKUP_CREATED) is AuditRing.GENERAL
        assert audit_ring_for(CoreEventType.BACKUP_EXPORTED) is AuditRing.SECURITY
        assert audit_ring_for("security.anything") is AuditRing.SECURITY
        assert audit_ring_for(CoreEventType.INSTALLATION_KEY_LOST) is AuditRing.SECURITY
        assert CoreEventType.ROUTER_ADOPTED in SECURITY_EVENT_TYPES


# ---------------------------------------------------------------------------
# Finding 6 / ruling 2: version dedup
# ---------------------------------------------------------------------------


class TestVersionDedup:
    def test_hit(self):
        candidate = dedup_candidate([_rec(1), _rec(2)], BackupType.FULL_ARCHIVE)
        assert candidate.backup_id == _bid(2)
        assert should_deduplicate(candidate, _meta(), ["archive"])

    def test_candidate_skips_failed_bad_and_other_types(self):
        records = [
            _rec(1),
            _rec(2, status=VersionStatus.FAILED, error_class=ErrorClass.TIMEOUT),
            _rec(3, validation=ValidationInfo(status=ValidationStatus.CORRUPT)),
            _rec(4, backup_type=BackupType.UCI_SNAPSHOT),
        ]
        assert dedup_candidate(records, BackupType.FULL_ARCHIVE).backup_id == _bid(1)
        assert dedup_candidate([], BackupType.FULL_ARCHIVE) is None

    def test_partial_candidate_allowed_with_same_status(self):
        partial = _rec(
            1,
            backup_type=BackupType.PARTIAL,
            status=VersionStatus.PARTIAL,
            error_class=ErrorClass.PERMISSION,
            content_hash=None,
            uci_hash="d" * 64,
            artifacts={"uci": _art("uci")},
        )
        assert dedup_candidate([partial], BackupType.PARTIAL) is partial
        meta = _meta(
            backup_type=BackupType.PARTIAL,
            status=VersionStatus.PARTIAL,
            error_class=ErrorClass.PERMISSION,
            content_hash=None,
            uci_hash="d" * 64,
        )
        assert should_deduplicate(partial, meta, ["uci"])

    def test_partial_never_against_ok(self):
        meta = _meta(status=VersionStatus.PARTIAL, error_class=ErrorClass.TIMEOUT)
        assert not should_deduplicate(_rec(1), meta, ["archive"])

    @pytest.mark.parametrize(
        "reason",
        [
            BackupReason.MANUAL,
            BackupReason.PRE_FIRMWARE_UPDATE,
            BackupReason.PRE_RESTORE,
            BackupReason.PRE_CHANGE,
            BackupReason.INCIDENT,
        ],
    )
    def test_reasons_that_always_create(self, reason):
        assert not should_deduplicate(_rec(1), _meta(reason=reason), ["archive"])

    def test_incident_link_always_creates(self):
        meta = _meta(links=BackupLinks(incident_id="inc_1"))
        assert not should_deduplicate(_rec(1), meta, ["archive"])

    def test_failed_never_takes_part(self):
        failed = _rec(1, status=VersionStatus.FAILED, error_class=ErrorClass.TIMEOUT)
        assert not should_deduplicate(failed, _meta(), ["archive"])
        meta = _meta(status=VersionStatus.FAILED, error_class=ErrorClass.TIMEOUT)
        assert not should_deduplicate(_rec(1), meta, ["archive"])

    def test_hash_and_artifacts_must_match(self):
        assert not should_deduplicate(
            _rec(1), _meta(content_hash="e" * 64), ["archive"]
        )
        assert not should_deduplicate(_rec(1), _meta(), ["archive", "uci"])
        assert not should_deduplicate(None, _meta(), ["archive"])


# ---------------------------------------------------------------------------
# Finding 9: retention run by the core
# ---------------------------------------------------------------------------


class TestRetention:
    def test_keeps_protected_and_newest_valid(self):
        records = [
            _rec(1, protected=True),
            _rec(2),
            _rec(3, validation=ValidationInfo(status=ValidationStatus.CORRUPT)),
        ]
        result = plan_retention(RID, records, RetentionPolicy(max_versions=1), now=T0)
        assert result.kept[_bid(1)] is KeepReason.PROTECTED
        assert result.kept[_bid(2)] is KeepReason.NEWEST_VALID
        assert result.deleted == (_bid(3),)

    def test_nothing_silent(self):
        records = [_rec(n) for n in range(1, 6)]
        result = plan_retention(
            RID, records, RetentionPolicy(max_versions=2), now=T0 + timedelta(days=1)
        )
        assert set(result.deleted) | set(result.kept) == {r.backup_id for r in records}
        assert not set(result.deleted) & set(result.kept)
        assert len(result.kept) == 2

    def test_age_and_size(self):
        records = [_rec(1, artifacts={"archive": _art(size=60)}), _rec(2)]
        now = T0 + timedelta(days=10)
        by_age = plan_retention(
            RID, records, RetentionPolicy(max_age=timedelta(1)), now=now
        )
        assert by_age.deleted == (_bid(1),)  # _rec(2) is the newest valid
        by_size = plan_retention(
            RID, records, RetentionPolicy(max_bytes_per_router=50), now=now
        )
        assert by_size.deleted == (_bid(1),)

    def test_foreign_router_rejected(self):
        with pytest.raises(ValueError):
            plan_retention(OTHER_RID, [_rec(1)], RetentionPolicy())

    @pytest.mark.parametrize(
        "kw",
        [
            {"max_versions": 0},
            {"max_versions": True},
            {"max_bytes_per_router": -1},
            {"max_age": timedelta(0)},
        ],
    )
    def test_policy_validation(self, kw):
        with pytest.raises(ValueError):
            RetentionPolicy(**kw)


# ---------------------------------------------------------------------------
# Finding 10: store split, deletion rules, created_by from authorization
# ---------------------------------------------------------------------------


class TestStoreSplit:
    def test_read_view_has_no_write_methods(self):
        for name in (
            "async_put_version",
            "async_delete_versions",
            "async_set_protected",
            "async_sweep",
        ):
            assert not hasattr(VersionReadView, name)
            assert hasattr(VersionStoreProtocol, name)

    def test_meta_has_no_created_by(self):
        with pytest.raises(TypeError):
            VersionMeta(
                backup_type=BackupType.FULL_ARCHIVE,
                reason=BackupReason.MANUAL,
                created_by=Actor.system(),  # type: ignore[call-arg]
            )

    def test_deletion_rejects_foreign_ids(self):
        foreign = _rec(2, router_id=OTHER_RID)
        with pytest.raises(AuthorizationError) as err:
            validate_deletion([_rec(1), foreign], router_id=RID)
        assert err.value.details["reason"] == "router_mismatch"
        assert err.value.details["version_ids"] == [_bid(2)]

    def test_deletion_rejects_protected(self):
        with pytest.raises(VersionProtectedError) as err:
            validate_deletion([_rec(1, protected=True), _rec(2)], router_id=RID)
        assert err.value.details["version_ids"] == [_bid(1)]
        validate_deletion([_rec(2)], router_id=RID)


# ---------------------------------------------------------------------------
# Finding 11: free text is scrubbed
# ---------------------------------------------------------------------------


class TestFreeTextScrub:
    def test_free_text_fields(self):
        leak = "option key 'hunter2'"
        assert "hunter2" not in str(ValidationInfo(details=leak).to_dict())
        assert "hunter2" not in str(
            CompatibilityIssue(code="x", message=leak).to_dict()
        )
        step = RestoreStep(order=1, action="uci_set", target="t", description=leak)
        assert "hunter2" not in str(step.to_dict())
        result = RestoreResult(
            approval_id="a",
            plan_id="p",
            router_id=RID,
            status=RestoreStatus.FAILED,
            started_at=T0,
            finished_at=T0,
            message=leak,
        )
        assert "hunter2" not in str(result.to_dict())

    def test_error_message_scrubbed(self):
        err = AuthorizationError("password=hunter2")
        assert "hunter2" not in err.to_dict()["message"]

    def test_note_is_user_text_and_kept(self):
        assert _rec(1, note="psk=mine").to_dict()["note"] == "psk=mine"


# ---------------------------------------------------------------------------
# Finding 12: enum coercion
# ---------------------------------------------------------------------------


class TestEnumCoercion:
    def test_strings_become_enums(self):
        record = _rec(1, backup_type="full_archive", reason="scheduled")
        assert record.backup_type is BackupType.FULL_ARCHIVE
        assert record.reason is BackupReason.SCHEDULED
        status = CapabilityStatus(
            capability="config.backup",
            state="available",
            reason="ok",
            source="s",
            detected_at=T0,
        )
        assert status.state is CapabilityState.AVAILABLE

    @pytest.mark.parametrize(
        "build",
        [
            lambda: Actor(kind="robot"),
            lambda: _rec(1, status="meh"),
            lambda: _meta(reason="boredom"),
            lambda: CoreEvent(
                event_id="e", ts=T0, type="x.y", source="s", severity="loud"
            ),
            lambda: DriftAck(
                router_id=RID, drift_id="d", state="maybe", actor=Actor.system(), ts=T0
            ),
            lambda: ValidationInfo(status="fine"),
            lambda: ApprovalRequest(
                approval_id="a",
                action="export",
                router_id=RID,
                subject_id="s",
                checksum="c",
                requested_by=Actor.system(),
                requested_at=T0,
                expires_at=T0,
                status="perhaps",
            ),
        ],
    )
    def test_invalid_values_raise(self, build):
        with pytest.raises(ValueError):
            build()


# ---------------------------------------------------------------------------
# Finding 13: read-only mappings
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_record_artifacts_read_only_and_detached(self):
        artifacts = {"archive": _art()}
        record = _rec(1, artifacts=artifacts)
        artifacts["uci"] = _art("uci")
        assert set(record.artifacts) == {"archive"}
        assert isinstance(record.artifacts, MappingProxyType)
        with pytest.raises(TypeError):
            record.artifacts["uci"] = _art("uci")  # type: ignore[index]

    def test_unknown_artifact_kind_rejected(self):
        with pytest.raises(ValueError):
            _rec(1, artifacts={"firmware": _art()})

    def test_event_data_deep_read_only(self):
        event = CoreEvent(
            event_id="e", ts=T0, type="x.y", source="s", data={"a": {"b": [1]}}
        )
        with pytest.raises(TypeError):
            event.data["a"]["b"] = 2  # type: ignore[index]
        assert event.data["a"]["b"] == (1,)
        assert event.to_dict()["data"] == {"a": {"b": [1]}}

    def test_snapshot_configs_read_only(self):
        snap = ConfigSnapshot(
            router_id=RID, captured_at=T0, configs={"wireless": {"sections": {}}}
        )
        with pytest.raises(TypeError):
            snap.configs["wireless"]["x"] = 1  # type: ignore[index]

    def test_router_capabilities_read_only(self):
        identity = RouterIdentity(router_id=RID, entry_id="entry-a")
        record = RouterRecord(identity=identity, capabilities={})
        with pytest.raises(TypeError):
            record.capabilities["x"] = None  # type: ignore[index]


# ---------------------------------------------------------------------------
# Finding 15: identity flags
# ---------------------------------------------------------------------------


class TestIdentityFlags:
    @pytest.mark.parametrize(
        ("flags", "status"),
        [
            (set(), IdentityStatus.CONFIRMED),
            ({IdentityFlag.UNVERIFIED}, IdentityStatus.UNVERIFIED),
            (
                {IdentityFlag.DUPLICATE_SUSPECTED, IdentityFlag.UNVERIFIED},
                IdentityStatus.DUPLICATE_SUSPECTED,
            ),
            (
                {IdentityFlag.CHANGED, IdentityFlag.DUPLICATE_SUSPECTED},
                IdentityStatus.CHANGED,
            ),
        ],
    )
    def test_primary_status(self, flags, status):
        identity = RouterIdentity(router_id=RID, entry_id="e", identity_flags=flags)
        assert identity.status is status
        data = identity.to_dict()
        assert data["status"] == status.value
        assert data["identity_flags"] == sorted(f.value for f in flags)

    def test_default_unverified_and_coerced(self):
        identity = RouterIdentity(router_id=RID, entry_id="e")
        assert identity.status is IdentityStatus.UNVERIFIED
        coerced = RouterIdentity(
            router_id=RID, entry_id="e", identity_flags={"changed"}
        )
        assert coerced.identity_flags == frozenset({IdentityFlag.CHANGED})
        with pytest.raises(ValueError):
            RouterIdentity(router_id=RID, entry_id="e", identity_flags={"weird"})


# ---------------------------------------------------------------------------
# Finding 16: consume only through the guard
# ---------------------------------------------------------------------------


class TestConsumeThroughGuard:
    def test_no_public_consume(self):
        assert not hasattr(WriteAuthorization, "consume")
        assert hasattr(WriteAuthorization, "_consume")
        assert hasattr(ActionGuardProtocol, "consume")


# ---------------------------------------------------------------------------
# Minor: from_dict rejects bad types
# ---------------------------------------------------------------------------


class TestFromDictTypes:
    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("protected", "yes"),
            ("contains_secrets", 1),
            ("note", 5),
            ("created_at", "2026-11-17T12:00:00"),
            ("last_seen_at", 12),
            ("warnings", "uci_missing"),
            ("warnings", ["Not A Code!"]),
        ],
    )
    def test_record_rejects(self, key, value):
        data = _rec(1).to_dict()
        data[key] = value
        with pytest.raises(BackupMetadataError):
            BackupRecord.from_dict(data)

    def test_event_naive_ts_rejected(self):
        data = CoreEvent(event_id="e", ts=T0, type="x.y", source="s").to_dict()
        data["ts"] = "2026-11-17T12:00:00"
        with pytest.raises(ValueError):
            CoreEvent.from_dict(data)

    def test_actor_admin_flag_type(self):
        with pytest.raises(TypeError):
            Actor.from_dict({"kind": "user", "is_admin": "true"})


# ---------------------------------------------------------------------------
# config-manager rulings
# ---------------------------------------------------------------------------


class TestQueueOrder:
    def test_fleet_concurrency_default(self):
        assert FLEET_BACKUP_CONCURRENCY == 1


class TestVersionMetaRules:
    def test_error_class_exactly_for_partial_and_failed(self):
        with pytest.raises(ValueError):
            _meta(status=VersionStatus.PARTIAL)
        with pytest.raises(ValueError):
            _meta(error_class=ErrorClass.TIMEOUT)
        meta = _meta(
            backup_type=BackupType.PARTIAL,
            status=VersionStatus.PARTIAL,
            error_class=ErrorClass.PERMISSION,
        )
        assert meta.error_class is ErrorClass.PERMISSION

    def test_warnings_are_codes(self):
        meta = _meta(warnings=("config_missing_in_archive:firewall", "uci_missing:sqm"))
        assert len(meta.warnings) == 2
        with pytest.raises(ValueError):
            _meta(warnings=("free text with spaces",))
        with pytest.raises(TypeError):
            _meta(warnings="uci_missing")
        with pytest.raises(ValueError):
            _meta(warnings=tuple(f"w{i}" for i in range(51)))

    def test_record_round_trips_new_fields(self):
        record = _rec(1, warnings=("uci_missing:sqm",), installation_key_id="ab" * 8)
        assert BackupRecord.from_dict(record.to_dict()) == record

    def test_old_record_without_new_fields(self):
        data = _rec(1).to_dict()
        del data["warnings"]
        del data["installation_key_id"]
        assert BackupRecord.from_dict(data).warnings == ()


class TestBaseline:
    def _ack(self, n, state=DriftAckState.KNOWN, version=None, router=RID):
        return DriftAck(
            router_id=router,
            drift_id=f"drf_{n}",
            state=state,
            actor=Actor.system(),
            ts=T0 + timedelta(days=n),
            version_id=version,
        )

    def test_known_ack_needs_version(self):
        with pytest.raises(ValueError):
            self._ack(1)
        with pytest.raises(ValueError):
            self._ack(1, DriftAckState.ACKNOWLEDGED, version=_bid(1))
        ack = self._ack(1, version=_bid(1))
        assert DriftAck.from_dict(ack.to_dict()) == ack

    def test_priority(self):
        records = [_rec(1), _rec(2), _rec(3)]
        acks = [self._ack(1, version=_bid(1)), self._ack(2, version=_bid(2))]
        explicit = select_baseline(RID, records, acks, explicit_backup_id=_bid(3))
        assert (explicit.version_id, explicit.rule) == (_bid(3), BaselineRule.EXPLICIT)
        known = select_baseline(RID, records, acks)
        assert (known.version_id, known.rule) == (_bid(2), BaselineRule.KNOWN_ACK)
        assert known.drift_id == "drf_2"
        newest = select_baseline(RID, records, [])
        assert (newest.version_id, newest.rule) == (_bid(3), BaselineRule.NEWEST_VALID)

    def test_known_ack_with_gone_version_skipped(self):
        records = [_rec(1), _rec(2, status=VersionStatus.FAILED, error_class="timeout")]
        acks = [self._ack(1, version=_bid(2)), self._ack(2, version=_bid(9))]
        baseline = select_baseline(RID, records, acks)
        assert baseline.rule is BaselineRule.NEWEST_VALID
        assert baseline.version_id == _bid(1)

    def test_none_and_bad_explicit(self):
        assert select_baseline(RID, [], []) is None
        with pytest.raises(ValueError):
            select_baseline(RID, [_rec(1)], [], explicit_backup_id=_bid(7))
        with pytest.raises(ValueError):
            select_baseline(
                RID, [_rec(1, router_id=OTHER_RID)], [], explicit_backup_id=_bid(1)
            )

    def test_baseline_to_dict(self):
        baseline = Baseline(router_id=RID, version_id=_bid(1), rule="known_ack")
        assert baseline.to_dict()["rule"] == "known_ack"


class TestInstallationKey:
    @pytest.mark.parametrize(
        ("readable", "versions", "acks", "state"),
        [
            (True, True, True, InstallationKeyState.OK),
            (False, False, False, InstallationKeyState.UNINITIALISED),
            (False, True, False, InstallationKeyState.LOST),
            (False, False, True, InstallationKeyState.LOST),
        ],
    )
    def test_state(self, readable, versions, acks, state):
        assert (
            installation_key_state(
                key_readable=readable, has_versions=versions, has_acks=acks
            )
            is state
        )

    def test_key_id_is_stable_short_and_not_the_key(self):
        key = os.urandom(32)
        assert installation_key_id(key) == installation_key_id(key)
        assert len(installation_key_id(key)) == 16
        assert installation_key_id(key) not in key.hex()
        assert installation_key_id(key) != installation_key_id(os.urandom(32))
        with pytest.raises(ValueError):
            installation_key_id(b"short")

    def test_reset_is_a_guarded_critical_action(self):
        assert GuardedAction.INSTALLATION_KEY_RESET == "installation_key_reset"

    def test_lost_error(self):
        err = InstallationKeyLostError()
        assert err.code == "installation_key_lost"
        assert err.error_class is ErrorClass.NOT_AVAILABLE

    def test_lost_event_is_security_and_mandatory(self):
        assert CoreEventType.INSTALLATION_KEY_LOST == "core.installation_key_lost"
        assert CoreEventType.INSTALLATION_KEY_LOST in AUDIT_MANDATORY_EVENT_TYPES

    async def test_provider_context_passes_lost_error_through(self):
        async def _lost() -> bytes:
            raise InstallationKeyLostError()

        ctx = ProviderContext(
            registry=MagicMock(),
            read=AsyncMock(),
            installation_key=_lost,
            installation_key_state="lost",
        )
        assert ctx.installation_key_state is InstallationKeyState.LOST
        with pytest.raises(InstallationKeyLostError):
            await ctx.async_get_installation_key()

    async def test_provider_context_returns_key(self):
        ctx = ProviderContext(
            registry=MagicMock(),
            read=AsyncMock(),
            installation_key=AsyncMock(return_value=b"k" * 32),
        )
        assert await ctx.async_get_installation_key() == b"k" * 32
        assert "k" * 32 not in repr(ctx)


def _diff(*changes: ConfigChange) -> ConfigDiff:
    return ConfigDiff(
        base=ConfigRef.backup(_bid(1)),
        other=ConfigRef.live(RID),
        compared_at=T0,
        changes=changes,
    )


class TestDriftEvents:
    def _report(self, **kw) -> DriftReport:
        values = {
            "router_id": RID,
            "baseline_backup_id": _bid(1),
            "checked_at": T0,
            "drifted": True,
            "diff": _diff(),
            "drift_id": "drf_1",
        }
        values.update(kw)
        return DriftReport(**values)

    def test_core_derives_event_types(self):
        assert drift_event_types(self._report()) == (CoreEventType.DRIFT_DETECTED,)
        assert drift_event_types(self._report(critical_count=2, unknown_count=1)) == (
            CoreEventType.DRIFT_DETECTED,
            CoreEventType.CHANGE_CRITICAL,
            CoreEventType.CHANGE_UNKNOWN,
        )
        assert drift_event_types(self._report(drifted=False)) == ()

    def test_rebaseline_is_never_drift(self):
        with pytest.raises(ValueError):
            self._report(rebaseline=True)
        report = self._report(drifted=False, rebaseline=True, secrets_comparable=False)
        assert drift_event_types(report) == ()
        assert report.to_dict()["rebaseline"] is True

    def test_counts_validated(self):
        with pytest.raises(ValueError):
            self._report(critical_count=-1)

    def test_not_comparable_changes_are_no_drift(self):
        secret = ConfigChange(
            kind=ChangeKind.NOT_COMPARABLE,
            config="wireless",
            section="r0",
            option="key",
            before={"secret": "aaaa"},
            after={"secret": "bbbb"},
        )
        plain = ConfigChange(
            kind=ChangeKind.MODIFIED, config="system", section="s", option="hostname"
        )
        diff = _diff(secret, plain)
        assert diff.comparable_changes == (plain,)
        assert diff.to_dict()["counts"]["not_comparable"] == 1
        assert diff.to_dict()["changes"][0]["before"] == MASK

    def test_integrity_failed(self):
        assert integrity_failed(ValidationInfo(status=ValidationStatus.CORRUPT))
        assert integrity_failed(ValidationInfo(status=ValidationStatus.MISSING))
        assert not integrity_failed(ValidationInfo(status=ValidationStatus.VALID))

    def test_core_namespaces(self):
        for event_type in CoreEventType:
            assert is_core_event_type(event_type)
        assert not is_core_event_type("self_healing.run_started")
        assert CoreEventType.INTEGRITY_FAILED == "configuration.integrity_failed"


class TestProviderSignatures:
    def test_context_in_every_router_or_store_call(self):
        import inspect

        for name in (
            "async_probe",
            "async_capture",
            "async_collect",
            "async_validate",
            "async_compare",
            "async_detect_drift",
            "async_prepare_restore",
            "async_execute_restore",
        ):
            params = inspect.signature(getattr(ConfigBackupProvider, name)).parameters
            assert "ctx" in params, name
            assert "read" not in params, name
        compare = inspect.signature(ConfigBackupProvider.async_compare).parameters
        assert {"base_router", "other_router"} <= set(compare)


class TestSnapshotFormat:
    def test_default_format_and_provider_hash(self):
        snap = ConfigSnapshot(
            router_id=RID,
            captured_at=T0,
            configs={
                "wireless": {
                    "sections": {
                        "r0": {
                            "type": "wifi-iface",
                            "options": {"key": {"secret": "a"}},
                        }
                    },
                    "order": ["r0"],
                }
            },
            uci_hash="f" * 64,
        )
        assert snap.format == SNAPSHOT_FORMAT_UCI_NORMALIZED == "uci_normalized"
        data = snap.to_dict()
        assert data["uci_hash"] == "f" * 64
        assert data["checksum"] != data["uci_hash"]
        assert data["configs"]["wireless"]["sections"]["r0"]["options"]["key"] == MASK

    def test_bad_uci_hash(self):
        with pytest.raises(ValueError):
            ConfigSnapshot(router_id=RID, captured_at=T0, configs={}, uci_hash="x")


def test_severity_reexported():
    # Contract consumers import Severity from core_models.
    assert Severity.INFO
