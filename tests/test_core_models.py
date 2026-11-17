"""Tests for the enterprise core contract types (plan 2026-11-17).

Pure types only: no hass fixture, no router, no store.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from homeassistant.core import Context
from homeassistant.exceptions import HomeAssistantError

from custom_components.openwrt_router import core_errors, core_models
from custom_components.openwrt_router.core_errors import (
    ApiVersionError,
    AuthorizationError,
    BackupMetadataError,
    ConfigApiError,
    ErrorClass,
    ProviderError,
    RouterUnavailableError,
    UnsupportedStorageFormatError,
)
from custom_components.openwrt_router.core_masking import (
    MASK,
    is_secret_key,
    mask_secrets,
)
from custom_components.openwrt_router.core_models import (
    ACTION_CLASSES,
    ADMIN_USER_ONLY_ACTIONS,
    BACKUP_METADATA_VERSION,
    CONFIG_CAPABILITIES,
    CONFIGURATION_API_VERSION,
    FEATURE_CAPABILITIES,
    NOTE_MAX_LENGTH,
    PROBED_CAPABILITIES,
    RESERVED_NAMESPACES,
    STORAGE_FORMAT_PLAIN_V1,
    SYSTEM_ONLY_ACTIONS,
    ActionClass,
    ActionGuardProtocol,
    Actor,
    ActorKind,
    ArtifactKind,
    ArtifactRef,
    AuthorizationDecision,
    BackupLinks,
    BackupReason,
    BackupRecord,
    BackupType,
    Capability,
    CapabilityState,
    CapabilityStatus,
    ChangeKind,
    CompatibilityCheck,
    CompatibilityInfo,
    ConfigBackupProvider,
    ConfigChange,
    ConfigRef,
    CoreEvent,
    CoreEventType,
    DecisionState,
    DriftAck,
    DriftAckState,
    EventResult,
    GuardedAction,
    HardwareFingerprint,
    RestorePlan,
    RestoreStep,
    StorageRef,
    ValidationInfo,
    ValidationStatus,
    VersionMeta,
    VersionRecord,
    VersionStatus,
    VersionStoreProtocol,
    WriteAuthorization,
    _mint_write_authorization,
    async_actor_from_context,
    binding_checksum,
    canonical_checksum,
    dedup_key,
    default_router_id,
    ensure_supported_api_version,
    ensure_supported_storage_format,
    is_valid_id,
    new_id,
    normalize_mac,
)
from custom_components.openwrt_router.net_events import Severity

T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
SHA = "a" * 64


def _actor() -> Actor:
    return Actor(
        kind=ActorKind.USER,
        user_id="u1",
        context_id="ctx1",
        parent_context_id=None,
        module="config_manager",
        is_admin=True,
    )


def _artifact(name: str, sha: str = SHA, size: int = 100) -> ArtifactRef:
    return ArtifactRef(
        storage=StorageRef(locator=f"bkp_{'1' * 32}.{name}"),
        sha256=sha,
        size_bytes=size,
    )


def _record(**overrides) -> BackupRecord:
    values = {
        "backup_id": "bkp_" + "1" * 32,
        "router_id": default_router_id("entry-a"),
        "created_at": T0,
        "last_seen_at": T0 + timedelta(days=1),
        "backup_type": BackupType.FULL_ARCHIVE,
        "reason": BackupReason.PRE_FIRMWARE_UPDATE,
        "status": VersionStatus.PARTIAL,
        "error_class": ErrorClass.PERMISSION,
        "fetch_method": "cgi",
        "content_hash": "b" * 64,
        "uci_hash": "c" * 64,
        "openwrt_version": "24.10.0",
        "hardware_model": "Example Router",
        "board_name": "vendor,board",
        "compatibility": CompatibilityInfo(
            format="sysupgrade_tar_gz",
            format_version=1,
            openwrt_version="24.10.0",
            target="mediatek/filogic",
            board_name="vendor,board",
            model="Example Router",
            architecture="aarch64_cortex-a53",
            package_manager="opkg",
        ),
        "artifacts": {
            ArtifactKind.ARCHIVE: _artifact("tar.gz", SHA, 12000),
            ArtifactKind.INVENTORY: _artifact("json", "d" * 64, 345),
        },
        "validation": ValidationInfo(
            status=ValidationStatus.VALID, checked_at=T0, details="ok"
        ),
        "links": BackupLinks(incident_id="inc_1", correlation_id="cor_1"),
        "created_by": _actor(),
        "contains_secrets": True,
        "protected": True,
        "note": "before upgrade",
    }
    values.update(overrides)
    return BackupRecord(**values)


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------


class TestIdentifiers:
    def test_router_id_is_deterministic_and_pinned(self):
        # The namespace must never change: it defines every router id.
        ns = uuid.UUID("5fc97c09-217a-4ccb-af32-d954b049fecf")
        assert core_models.ROUTER_ID_NAMESPACE == ns
        expected = "rtr_" + uuid.uuid5(ns, "entry-a").hex
        assert default_router_id("entry-a") == expected
        assert default_router_id("entry-a") == default_router_id("entry-a")
        assert default_router_id("entry-a") != default_router_id("entry-b")

    def test_router_id_format(self):
        rid = default_router_id("x")
        assert is_valid_id(rid, "rtr_")
        assert len(rid) == 4 + 32

    def test_router_id_rejects_empty_entry(self):
        with pytest.raises(ValueError):
            default_router_id("")

    def test_new_id_is_random(self):
        a, b = new_id("bkp_"), new_id("bkp_")
        assert a != b
        assert is_valid_id(a, "bkp_")
        assert not is_valid_id(a, "rtr_")
        assert not is_valid_id("bkp_XYZ", "bkp_")

    def test_normalize_mac(self):
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac("eth0") is None
        assert normalize_mac(None) is None

    def test_fingerprint_keeps_only_universal_macs(self):
        fp = HardwareFingerprint.build(
            board_name="vendor,board",
            model="Example",
            macs=["00:00:5E:00:53:01", "02:00:00:00:00:01", "junk", None],
        )
        assert fp.macs == frozenset({"00:00:5e:00:53:01"})
        other = HardwareFingerprint.build(
            board_name="vendor,board", model="Example", macs=["00005e005301"]
        )
        assert fp.mac_overlap(other) == frozenset({"00:00:5e:00:53:01"})


# ---------------------------------------------------------------------------
# Round trips and metadata versions
# ---------------------------------------------------------------------------


class TestBackupRecord:
    def test_round_trip(self):
        record = _record()
        data = record.to_dict()
        json.dumps(data)  # JSON-safe
        assert data["metadata_version"] == BACKUP_METADATA_VERSION
        assert BackupRecord.from_dict(data) == record

    def test_round_trip_minimal(self):
        record = BackupRecord(
            backup_id="bkp_" + "3" * 32,
            router_id=default_router_id("entry-a"),
            created_at=T0,
            backup_type=BackupType.UCI_SNAPSHOT,
            reason=BackupReason.SCHEDULED,
            status=VersionStatus.FAILED,
            error_class=ErrorClass.UNREACHABLE,
            created_by=Actor.system(),
        )
        data = record.to_dict()
        assert data["sha256"] is None
        assert data["size_bytes"] == 0
        assert BackupRecord.from_dict(data) == record

    def test_derived_fields_and_alias(self):
        record = _record()
        assert record.version_id == record.backup_id
        assert record.sha256 == SHA  # the archive's sha256
        assert record.size_bytes == 12000 + 345
        assert VersionRecord is BackupRecord
        data = record.to_dict()
        assert data["artifacts"]["archive"]["storage"]["storage_format"] == (
            STORAGE_FORMAT_PLAIN_V1
        )

    def test_note_length_limited(self):
        _record(note="x" * NOTE_MAX_LENGTH)
        with pytest.raises(ValueError):
            _record(note="x" * (NOTE_MAX_LENGTH + 1))
        with pytest.raises(ValueError):
            VersionMeta(
                backup_type=BackupType.FULL_ARCHIVE,
                reason=BackupReason.MANUAL,
                created_by=_actor(),
                note="x" * (NOTE_MAX_LENGTH + 1),
            )

    def test_release_change_reason(self):
        assert BackupReason("release_change") is BackupReason.RELEASE_CHANGE

    def test_from_dict_does_not_mutate_input(self):
        data = _record().to_dict()
        snapshot = json.dumps(data, sort_keys=True)
        BackupRecord.from_dict(data)
        assert json.dumps(data, sort_keys=True) == snapshot

    @pytest.mark.parametrize("version", [BACKUP_METADATA_VERSION + 1, 99])
    def test_newer_version_rejected(self, version):
        data = _record().to_dict()
        data["metadata_version"] = version
        with pytest.raises(BackupMetadataError) as err:
            BackupRecord.from_dict(data)
        assert err.value.code == "backup_metadata_invalid"

    @pytest.mark.parametrize("version", [None, 0, -1, "1", True])
    def test_missing_or_bad_version_rejected(self, version):
        data = _record().to_dict()
        if version is None:
            del data["metadata_version"]
        else:
            data["metadata_version"] = version
        with pytest.raises(BackupMetadataError):
            BackupRecord.from_dict(data)

    def test_migration_chain_upgrades_old_version(self, monkeypatch):
        def _v0_to_v1(data):
            new = dict(data)
            new["note"] = "migrated"
            new["metadata_version"] = 1
            return new

        monkeypatch.setitem(core_models.METADATA_MIGRATIONS, 0, _v0_to_v1)
        data = _record().to_dict()
        data["metadata_version"] = 0
        assert BackupRecord.from_dict(data).note == "migrated"

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("content_hash", "xyz"),
            ("uci_hash", "A" * 64),
            ("backup_id", "not-an-id"),
            ("router_id", "rtr_short"),
            ("backup_type", "floppy"),
            ("reason", "boredom"),
            ("status", "meh"),
            ("error_class", "oops"),
            ("note", "x" * (NOTE_MAX_LENGTH + 1)),
            ("created_at", "yesterday"),
            ("artifacts", ["archive"]),
            (
                "artifacts",
                {
                    "archive": {
                        "storage": {"locator": "f"},
                        "sha256": "x",
                        "size_bytes": 1,
                    }
                },
            ),
            (
                "artifacts",
                {
                    "archive": {
                        "storage": {"locator": "f"},
                        "sha256": SHA,
                        "size_bytes": -1,
                    }
                },
            ),
        ],
    )
    def test_invalid_fields_rejected(self, key, value):
        data = _record().to_dict()
        data[key] = value
        with pytest.raises(BackupMetadataError):
            BackupRecord.from_dict(data)

    def test_not_a_mapping_rejected(self):
        with pytest.raises(BackupMetadataError):
            BackupRecord.from_dict(["nope"])  # type: ignore[arg-type]

    def test_naive_datetime_rejected_at_construction(self):
        with pytest.raises(ValueError):
            _record(created_at=datetime(2026, 1, 1))


class TestActorAndEvent:
    def test_actor_round_trip(self):
        actor = _actor()
        assert Actor.from_dict(actor.to_dict()) == actor
        assert Actor.from_dict(Actor.system().to_dict()) == Actor.system()

    def test_actor_non_user_is_never_admin(self):
        actor = Actor.from_dict({"kind": "module", "module": "x", "is_admin": True})
        assert actor.is_admin is False

    def test_event_round_trip_and_masking(self):
        event = CoreEvent(
            event_id=new_id("evt_"),
            ts=T0,
            type=CoreEventType.BACKUP_CREATED,
            router_id=default_router_id("entry-a"),
            entry_id="entry-a",
            source="config_manager",
            severity=Severity.INFO,
            result=EventResult.SUCCESS,
            actor=_actor(),
            correlation_id="cor_1",
            data={"backup_id": "bkp_x", "wifi": {"key": "hunter2"}},
        )
        data = event.to_dict()
        json.dumps(data)
        assert data["data"]["wifi"]["key"] == MASK
        assert data["data"]["backup_id"] == "bkp_x"
        restored = CoreEvent.from_dict(data)
        assert restored.type == CoreEventType.BACKUP_CREATED
        assert restored.severity is Severity.INFO
        assert restored.actor == event.actor
        assert restored.ts == T0

    def test_event_keeps_unknown_type_from_newer_version(self):
        data = {
            "event_id": new_id("evt_"),
            "ts": T0.isoformat(),
            "type": "configuration.something_new",
            "source": "x",
            "severity": "info",
            "result": "info",
        }
        assert CoreEvent.from_dict(data).type == "configuration.something_new"

    def test_event_type_values_are_dotted_and_unique(self):
        values = [t.value for t in CoreEventType]
        assert len(values) == len(set(values))
        assert all("." in v for v in values)


class TestActorFromContext:
    async def test_admin_user(self):
        hass = MagicMock()
        hass.auth.async_get_user = AsyncMock(return_value=MagicMock(is_admin=True))
        actor = await async_actor_from_context(hass, Context(user_id="u1"), "cm")
        assert actor.kind is ActorKind.USER
        assert actor.is_admin is True
        assert actor.user_id == "u1"
        assert actor.module == "cm"

    async def test_unknown_user_is_not_admin(self):
        hass = MagicMock()
        hass.auth.async_get_user = AsyncMock(return_value=None)
        actor = await async_actor_from_context(hass, Context(user_id="gone"))
        assert actor.kind is ActorKind.USER
        assert actor.is_admin is False

    async def test_module_automation_system(self):
        hass = MagicMock()
        hass.auth.async_get_user = AsyncMock()
        mod = await async_actor_from_context(hass, Context(), "self_healing")
        assert mod.kind is ActorKind.MODULE
        auto = await async_actor_from_context(hass, Context(parent_id="p1"))
        assert auto.kind is ActorKind.AUTOMATION
        assert auto.parent_context_id == "p1"
        system = await async_actor_from_context(hass, None)
        assert system.kind is ActorKind.SYSTEM
        hass.auth.async_get_user.assert_not_called()


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------


class TestMaskSecrets:
    @pytest.mark.parametrize(
        "key",
        [
            "password",
            "sae_password",
            "key",
            "key1",
            "wpa_psk",
            "psk",
            "PrivateKey",
            "private_key",
            "preshared_key",
            "auth_secret",
            "token",
            "ubus_rpc_session",
            "credentials",
            "passphrase",
            "api-key",
        ],
    )
    def test_secret_keys(self, key):
        assert is_secret_key(key)

    @pytest.mark.parametrize(
        "key",
        ["ssid", "monkey", "author", "keyboard", "hostname", "encryption", "", 7],
    )
    def test_plain_keys(self, key):
        assert not is_secret_key(key)

    def test_nested_and_not_mutated(self):
        data = {
            "wireless": {
                "default_radio0": {"ssid": "Home", "key": "hunter2"},
                "list": [{"sae_password": "x"}, ("token", {"auth": "y"})],
            },
            "wg0": {"private_key": {"nested": "deep"}},
            "password": None,
            "secret": "",
        }
        before = json.dumps(data, sort_keys=True, default=list)
        masked = mask_secrets(data)
        assert json.dumps(data, sort_keys=True, default=list) == before
        radio = masked["wireless"]["default_radio0"]
        assert radio == {"ssid": "Home", "key": MASK}
        assert masked["wireless"]["list"][0] == {"sae_password": MASK}
        assert masked["wireless"]["list"][1] == ("token", {"auth": MASK})
        assert masked["wg0"]["private_key"] == MASK
        assert masked["password"] is None  # absence is not a secret
        assert masked["secret"] == MASK

    def test_extra_keys_and_scalars(self):
        assert mask_secrets({"serial": "S1"}, extra_keys={"serial"}) == {"serial": MASK}
        assert mask_secrets("plain") == "plain"
        assert mask_secrets(5) == 5

    def test_depth_guard(self):
        deep: dict = {}
        cur = deep
        for _ in range(100):
            cur["n"] = {}
            cur = cur["n"]
        masked = mask_secrets(deep)
        json.dumps(masked)  # terminates, stays serialisable

    def test_config_change_masks_secret_option(self):
        change = ConfigChange(
            kind=ChangeKind.MODIFIED,
            config="wireless",
            section="default_radio0",
            option="key",
            before="old-secret",
            after="new-secret",
        )
        data = change.to_dict()
        assert data["before"] == MASK
        assert data["after"] == MASK
        assert data["secret"] is True


# ---------------------------------------------------------------------------
# Errors and API version
# ---------------------------------------------------------------------------


def _error_classes() -> list[type[ConfigApiError]]:
    return [
        obj
        for obj in vars(core_errors).values()
        if isinstance(obj, type) and issubclass(obj, ConfigApiError)
    ]


class TestErrors:
    def test_codes_unique(self):
        classes = _error_classes()
        assert len(classes) >= 17
        codes = [cls.code for cls in classes]
        assert len(codes) == len(set(codes))
        assert all(code and code == code.lower() for code in codes)

    def test_all_are_ha_errors(self):
        for cls in _error_classes():
            assert issubclass(cls, HomeAssistantError)

    def test_every_error_has_an_error_class(self):
        for cls in _error_classes():
            assert isinstance(cls.default_error_class, ErrorClass)

    def test_config_manager_error_classes_exist(self):
        # The eleven error_class values of config-manager plan section 12.2.
        expected = {
            "unreachable",
            "timeout",
            "auth",
            "permission",
            "not_available",
            "too_large",
            "incomplete",
            "invalid",
            "checksum_mismatch",
            "storage_full",
            "storage_error",
        }
        assert expected <= {c.value for c in ErrorClass}

    def test_error_class_override_and_to_dict(self):
        err = ProviderError("x", error_class=ErrorClass.TIMEOUT, cause=OSError("p"))
        data = err.to_dict()
        assert data["error_class"] == "timeout"
        assert data["details"] == {"cause": "OSError"}
        assert isinstance(err.__cause__, OSError)

    def test_storage_format(self):
        assert ensure_supported_storage_format("plain-v1") == "plain-v1"
        with pytest.raises(UnsupportedStorageFormatError) as err:
            ensure_supported_storage_format("aesgcm-v9")
        assert err.value.code == "storage_format_unsupported"
        assert err.value.error_class is ErrorClass.INVALID

    def test_to_dict_masks_details(self):
        err = RouterUnavailableError(
            "router offline",
            router_id="rtr_x",
            details={"password": "p", "host_state": "down"},
        )
        data = err.to_dict()
        json.dumps(data)
        assert data["code"] == "router_unavailable"
        assert data["retryable"] is True
        assert data["router_id"] == "rtr_x"
        assert data["details"] == {"password": MASK, "host_state": "down"}

    def test_retryable_override(self):
        assert ProviderError("x").retryable is False
        assert ProviderError("x", retryable=True).retryable is True

    def test_api_version(self):
        assert ensure_supported_api_version(CONFIGURATION_API_VERSION) == 1
        with pytest.raises(ApiVersionError) as err:
            ensure_supported_api_version(2)
        assert err.value.supported_versions == (1,)
        assert err.value.to_dict()["details"]["supported_versions"] == [1]
        with pytest.raises(ApiVersionError):
            ensure_supported_api_version(True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------


class TestCapabilities:
    def test_names_dotted_unique(self):
        values = [c.value for c in Capability]
        assert len(values) == len(set(values))
        assert all("." in v for v in values)

    def test_config_capabilities(self):
        assert CONFIG_CAPABILITIES == {
            c for c in Capability if c.value.startswith("config.")
        }

    def test_feature_mapping_uses_existing_feature_keys(self):
        from custom_components.openwrt_router import const

        feature_values = {v for k, v in vars(const).items() if k.startswith("FEATURE_")}
        assert set(FEATURE_CAPABILITIES) <= feature_values

    def test_probed_capabilities_are_config_capabilities(self):
        assert PROBED_CAPABILITIES <= CONFIG_CAPABILITIES
        assert Capability.CONFIG_UCI_READ in PROBED_CAPABILITIES

    def test_reserved_namespaces_unused_by_core(self):
        values = [c.value for c in Capability]
        assert not [v for v in values if v.startswith(RESERVED_NAMESPACES)]

    def test_status_detail_is_serialised_and_masked(self):
        status = CapabilityStatus(
            capability=Capability.CONFIG_UCI_READ,
            state=CapabilityState.AVAILABLE,
            reason="ok",
            source="probe:config_manager",
            detected_at=T0,
            detail={"wireless": True, "firewall": False, "token": "t"},
        )
        data = status.to_dict()
        json.dumps(data)
        assert data["detail"] == {"wireless": True, "firewall": False, "token": MASK}
        assert status.available


# ---------------------------------------------------------------------------
# Guard policy, decisions, drift acks, dedup
# ---------------------------------------------------------------------------


class TestGuardPolicy:
    def test_every_action_has_a_class(self):
        assert set(ACTION_CLASSES) == set(GuardedAction)

    def test_export_is_critical_although_it_does_not_write(self):
        assert ACTION_CLASSES[GuardedAction.EXPORT] is ActionClass.CRITICAL
        assert GuardedAction.EXPORT in ADMIN_USER_ONLY_ACTIONS

    def test_delete_restore_critical_prune_system_only(self):
        assert ACTION_CLASSES[GuardedAction.DELETE] is ActionClass.CRITICAL
        assert ACTION_CLASSES[GuardedAction.RESTORE] is ActionClass.CRITICAL
        assert ACTION_CLASSES[GuardedAction.PRUNE] is ActionClass.MUTATING
        assert SYSTEM_ONLY_ACTIONS == {GuardedAction.PRUNE}
        assert not SYSTEM_ONLY_ACTIONS & ADMIN_USER_ONLY_ACTIONS

    def test_binding_checksum_order_and_content(self):
        assert binding_checksum("bkp_a", True) == binding_checksum("bkp_a", True)
        assert binding_checksum("bkp_a", True) != binding_checksum("bkp_a", False)
        assert binding_checksum("a", "b") != binding_checksum("b", "a")

    def test_decision_to_dict(self):
        auth = _auth(action=GuardedAction.BACKUP, checksum=None)
        decision = AuthorizationDecision(
            state=DecisionState.APPROVED,
            action=GuardedAction.BACKUP,
            router_id="rtr_a",
            audit_id="evt_1",
            authorization=auth,
        )
        data = decision.to_dict()
        json.dumps(data)
        assert decision.approved
        assert data["authorization"]["action"] == "backup"
        assert "authorization" not in repr(decision)


class TestDriftAckAndDedup:
    def test_drift_ack_round_trip(self):
        ack = DriftAck(
            router_id=default_router_id("entry-a"),
            drift_id="drf_1",
            state=DriftAckState.KNOWN,
            actor=_actor(),
            ts=T0,
            note="new baseline",
        )
        data = ack.to_dict()
        json.dumps(data)
        assert DriftAck.from_dict(data) == ack

    def test_drift_ack_rejects_naive_ts_and_long_note(self):
        base = {
            "router_id": "rtr_a",
            "drift_id": "d",
            "state": DriftAckState.ACKNOWLEDGED,
            "actor": _actor(),
        }
        with pytest.raises(ValueError):
            DriftAck(**base, ts=datetime(2026, 1, 1))
        with pytest.raises(ValueError):
            DriftAck(**base, ts=T0, note="x" * (NOTE_MAX_LENGTH + 1))

    def test_dedup_key(self):
        assert dedup_key("rtr_a", "drf_1") == "rtr_a:drf_1"
        assert dedup_key(None, ErrorClass.TIMEOUT) == "-:timeout"

    def test_event_carries_dedup_key(self):
        event = CoreEvent(
            event_id=new_id("evt_"),
            ts=T0,
            type=CoreEventType.BACKUP_FAILED,
            source="config_manager",
            dedup_key=dedup_key("rtr_a", ErrorClass.TIMEOUT),
        )
        assert CoreEvent.from_dict(event.to_dict()).dedup_key == "rtr_a:timeout"


# ---------------------------------------------------------------------------
# Restore plan checksum
# ---------------------------------------------------------------------------


def _plan(**overrides) -> RestorePlan:
    values = {
        "plan_id": "pln_" + "2" * 32,
        "backup_id": "bkp_" + "1" * 32,
        "source_router_id": default_router_id("entry-a"),
        "target_router_id": default_router_id("entry-a"),
        "provider_id": "config_manager",
        "created_at": T0,
        "compatibility": CompatibilityCheck(compatible=True),
        "steps": (RestoreStep(order=1, action="uci_set", target="wireless.r0.key"),),
    }
    values.update(overrides)
    return RestorePlan(**values)


class TestRestorePlan:
    def test_checksum_is_stable_and_content_bound(self):
        plan = _plan()
        assert plan.checksum == _plan().checksum
        assert len(plan.checksum) == 64
        other = _plan(target_router_id=default_router_id("entry-b"))
        assert other.checksum != plan.checksum
        assert plan.to_dict()["checksum"] == plan.checksum

    def test_canonical_checksum_ignores_key_order(self):
        assert canonical_checksum({"a": 1, "b": 2}) == canonical_checksum(
            {"b": 2, "a": 1}
        )

    def test_config_ref(self):
        assert ConfigRef.live("rtr_x").is_live
        assert not ConfigRef.backup("bkp_x").is_live
        with pytest.raises(ValueError):
            ConfigRef()


# ---------------------------------------------------------------------------
# WriteAuthorization
# ---------------------------------------------------------------------------


def _auth(**kwargs) -> WriteAuthorization:
    values = {
        "action": GuardedAction.RESTORE,
        "router_id": "rtr_a",
        "actor": _actor(),
        "checksum": "c" * 64,
        "now": T0,
    }
    values.update(kwargs)
    return _mint_write_authorization(**values)


class TestWriteAuthorization:
    def test_cannot_construct_directly(self):
        with pytest.raises(TypeError):
            WriteAuthorization(  # type: ignore[call-arg]
                authorization_id="wau_x",
                action=GuardedAction.BACKUP,
                router_id="rtr_a",
                actor=_actor(),
                issued_at=T0,
                expires_at=T0,
            )

    def test_single_use(self):
        auth = _auth()
        auth.consume(
            action=GuardedAction.RESTORE,
            router_id="rtr_a",
            checksum="c" * 64,
            now=T0,
        )
        assert auth.consumed
        with pytest.raises(AuthorizationError) as err:
            auth.consume(
                action=GuardedAction.RESTORE,
                router_id="rtr_a",
                checksum="c" * 64,
                now=T0,
            )
        assert err.value.details["reason"] == "already_used"

    @pytest.mark.parametrize(
        ("kwargs", "reason"),
        [
            ({"action": GuardedAction.DELETE}, "action_mismatch"),
            ({"router_id": "rtr_b"}, "router_mismatch"),
            ({"checksum": "d" * 64}, "checksum_mismatch"),
            ({"checksum": None}, "checksum_mismatch"),
        ],
    )
    def test_mismatch_rejected_and_burns(self, kwargs, reason):
        auth = _auth()
        call = {
            "action": GuardedAction.RESTORE,
            "router_id": "rtr_a",
            "checksum": "c" * 64,
            "now": T0,
        }
        call.update(kwargs)
        with pytest.raises(AuthorizationError) as err:
            auth.consume(**call)
        assert err.value.details["reason"] == reason
        # A failed attempt burns the authorization (fail closed).
        with pytest.raises(AuthorizationError) as err:
            auth.consume(
                action=GuardedAction.RESTORE,
                router_id="rtr_a",
                checksum="c" * 64,
                now=T0,
            )
        assert err.value.details["reason"] == "already_used"

    def test_expired(self):
        auth = _auth(ttl=timedelta(seconds=10))
        with pytest.raises(AuthorizationError) as err:
            auth.consume(
                action=GuardedAction.RESTORE,
                router_id="rtr_a",
                checksum="c" * 64,
                now=T0 + timedelta(seconds=11),
            )
        assert err.value.details["reason"] == "expired"

    def test_unbound_checksum_allows_none(self):
        auth = _auth(action=GuardedAction.BACKUP, checksum=None)
        auth.consume(action=GuardedAction.BACKUP, router_id="rtr_a", now=T0)
        assert auth.to_dict()["consumed"] is True

    def test_attributes_read_only(self):
        auth = _auth()
        with pytest.raises(AttributeError):
            auth.router_id = "rtr_b"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Provider protocol
# ---------------------------------------------------------------------------


class _FakeProvider:
    provider_id = "fake"
    provider_api_version = 1

    def supported(self, router):
        return True

    async def async_probe(self, conn): ...
    async def async_capture(self, conn, request): ...
    async def async_collect(self, conn, request): ...
    async def async_validate(self, record, read): ...
    async def async_compare(self, base, other, read): ...
    async def async_detect_drift(self, conn, baseline, read, acks): ...
    async def async_prepare_restore(self, conn, record, target, read): ...
    async def async_execute_restore(self, conn, plan, authorization): ...


def test_provider_protocol_runtime_checkable():
    assert isinstance(_FakeProvider(), ConfigBackupProvider)
    assert not isinstance(object(), ConfigBackupProvider)


def test_provider_without_probe_is_not_a_provider():
    class _Old(_FakeProvider):
        async_probe = None  # type: ignore[assignment]

    # runtime_checkable only checks presence; a None member counts as absent.
    assert not isinstance(_Old(), ConfigBackupProvider)


def test_service_protocols_are_runtime_checkable():
    assert not isinstance(object(), VersionStoreProtocol)
    assert not isinstance(object(), ActionGuardProtocol)


def test_storage_ref_defaults_and_round_trip():
    ref = StorageRef(locator="a.tar.gz")
    assert ref.storage_format == STORAGE_FORMAT_PLAIN_V1
    assert ref.encrypted is False
    assert StorageRef.from_dict(ref.to_dict()) == ref
    # Records written before storage_format existed read as plain-v1.
    assert StorageRef.from_dict({"locator": "a"}).storage_format == "plain-v1"
    with pytest.raises(ValueError):
        StorageRef.from_dict({"locator": ""})


def test_artifact_ref_round_trip():
    ref = _artifact("uci.json")
    assert ArtifactRef.from_dict(ref.to_dict()) == ref
