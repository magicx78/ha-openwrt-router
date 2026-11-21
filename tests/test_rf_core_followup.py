"""RF on the Core follow-up of PR #56 (contract §19.1 #100-#113).

One class per point of the follow-up order:

1. no RF field name is a Core secret name; router/radio ids and numbers
   survive the Core masking (``router_key``/``radio_key`` are masked again);
2. counters carry no secret word (``auth_failures`` showed no number);
3. SSID/BSSID/MAC pseudonyms come from the Core; ``mask_rf_output`` only
   adds what the Core does not do;
4. the neighbor key is the Core module key of ``wifi_rf``;
5./6./7. Core error classes, ``sensitive_read`` and ``active`` (rf_guard);
8. typed ``CoreEvent`` fields ``radio_id``/``client_ref``/``confidence``/
   ``classification``.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

import pytest
from core_testkit import (
    ADMIN_ID,
    USER_ID,
    FakeDisks,
    add_users,
    make_hass,
    user_actor,
)

from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_errors import (
    AuthorizationError,
    CapabilityUnavailableError,
    InstallationKeyLostError,
    RateLimitedError,
    SafetyRefusedError,
)
from custom_components.openwrt_router.core_guard import ActionGuard
from custom_components.openwrt_router.core_masking import (
    IDENTIFIER_INVALID,
    MASK,
    is_secret_key,
    mask_for_output,
    pseudonymise_fields,
    pseudonymise_identifier,
    redact_text,
)
from custom_components.openwrt_router.core_models import (
    CLIENT_REF_PATTERN,
    EVENT_ID_PREFIX,
    EVENT_REF_FIELDS,
    MODULE_KEY_PURPOSE_PATTERN,
    ActionClass,
    Actor,
    ConfigurationApiProtocol,
    CoreEvent,
    DecisionState,
    EventResult,
    default_router_id,
    derive_module_key,
    new_id,
)
from custom_components.openwrt_router.net_events import Severity
from custom_components.openwrt_router.rf_aggregate import roll_up, series_for_window
from custom_components.openwrt_router.rf_clients import (
    ClientRfWindow,
    assess_client,
    summarize_radio_clients,
)
from custom_components.openwrt_router.rf_conflicts import (
    RadioView,
    detect_conflicts,
)
from custom_components.openwrt_router.rf_events import (
    channel_conflict_event,
    channel_utilization_event,
    emit_kwargs,
    recommendation_events,
    scan_executed_event,
    scan_refused_event,
    scan_requested_event,
)
from custom_components.openwrt_router.rf_guard import (
    POLL_READS,
    RF_ACTIONS,
    SCAN_ACTION,
    SENSITIVE_READ_ACTIONS,
    register_rf_actions,
    rf_policy_denial,
    scan_refusal_error,
)
from custom_components.openwrt_router.rf_health import (
    aggregate_health,
    component_from_metric,
    item_from,
    radio_health,
    score_utilization,
)
from custom_components.openwrt_router.rf_identity import RadioRef
from custom_components.openwrt_router.rf_load import (
    ApLoadInput,
    RadioLoad,
    assess_load,
    distribution,
)
from custom_components.openwrt_router.rf_models import (
    METRIC_NOISE,
    SOURCE_HOSTAPD_STATUS,
    SOURCE_IWINFO_ASSOCLIST,
    SOURCE_IWINFO_FREQLIST,
    SOURCE_IWINFO_SURVEY,
    SOURCE_IWINFO_TXPOWERLIST,
    CapabilityState,
    RadioCapabilities,
    metric_measured,
)
from custom_components.openwrt_router.rf_privacy import (
    RF_IDENTIFIER_FIELDS,
    RF_PSEUDONYM_PURPOSE,
    client_ref,
    mask_rf_output,
    rf_key_request,
)
from custom_components.openwrt_router.rf_recommend import Recommendation
from custom_components.openwrt_router.rf_roaming import (
    PART_HANDSHAKE,
    WEIGHTS,
    AlternativeAp,
    ClientRoamWindow,
    RoamEvent,
    StickyInput,
    assess_sticky,
    detect_flapping,
    roaming_quality,
)
from custom_components.openwrt_router.rf_scan_policy import (
    ScanDecision,
    ScanReason,
    sanitize_neighbors,
)
from custom_components.openwrt_router.rf_utilization import (
    SurveySample,
    UtilizationThresholds,
    summarize,
    utilization_from_delta,
)

PKG = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"
RF_FILES = sorted(PKG.glob("rf_*.py"))
R1 = default_router_id("e1")
R2 = default_router_id("e2")
MAC = "aa:bb:cc:dd:ee:01"
OWN_BSSID = "02:11:22:33:44:55"
FOREIGN_BSSID = "06:aa:bb:cc:dd:ee"
INSTALLATION_KEY = b"\x42" * 32
KEY = derive_module_key(INSTALLATION_KEY, "wifi_rf", RF_PSEUDONYM_PURPOSE)
NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _modules():
    return [
        importlib.import_module(f"custom_components.openwrt_router.{p.stem}")
        for p in RF_FILES
    ]


def _plain(value):
    """as_dict forms all the way down (what RF hands out)."""
    if hasattr(value, "as_dict"):
        value = value.as_dict()
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


# ---------------------------------------------------------------------------
# Every RF output form
# ---------------------------------------------------------------------------


def _m(value, source=SOURCE_HOSTAPD_STATUS):
    return metric_measured(value, source, measured_at=1.0)


def _window():
    return ClientRfWindow(
        client_mac=MAC,
        radio=RadioRef(R1, "radio0"),
        band="5g",
        driver="mt7915e",
        window_s=3600.0,
        rssi_mean=-82.0,
        rssi_min=-88.0,
        rssi_stddev=2.0,
        weak_share=0.9,
        noise=_m(-95, "iwinfo.info"),
        rate_tx_mean=20.0,
        rate_tx_trend=-40.0,
        tx_packets=1000,
        tx_retries=400,
        tx_failed=50,
        disconnects=4,
        disconnects_weak=3,
        mobility="stationary",
        demand="high",
        samples=60,
        retries_reliable=True,
    )


def _roam_window():
    a, b = RadioRef(R1, "radio0"), RadioRef(R2, "radio0")
    events = tuple(
        RoamEvent(
            client_mac=MAC,
            ts=100.0 * i,
            from_radio=a if i % 2 == 0 else b,
            to_radio=b if i % 2 == 0 else a,
            from_band="5g",
            to_band="5g",
            rssi_before=-75.0,
            rssi_after=-70.0,
            gap_s=0.5,
            handshake_failures=(None, 2, 0)[i % 3],
            reauth=False,
        )
        for i in range(6)
    )
    return ClientRoamWindow(
        client_mac=MAC, window_s=3600.0, online_s=3600.0, events=events, mobility=None
    )


def _load_input():
    radio = RadioLoad(
        ref=RadioRef(R1, "radio1"),
        band="5g",
        client_count=40,
        utilization=_m(85.0),
        airtime_share_top_client=None,
        rssi_mean=None,
        retry_rate=_m(0.4, SOURCE_IWINFO_ASSOCLIST),
        driver="mt7915e",
        tx_bytes_rate=None,
        rx_bytes_rate=None,
        problem_clients=5,
    )
    return [ApLoadInput(router_id=R1, radios=(radio,))]


def _survey(at, busy):
    return SurveySample(
        radio_id="radio0",
        mhz=5180,
        taken_at=at,
        uptime_s=at,
        active_ms=int(at * 1000),
        busy_ms=busy,
        rx_ms=busy // 2,
        tx_ms=busy // 4,
    )


def _outputs():
    view = RadioView(
        router_id=R1,
        radio_id="radio0",
        band="2.4g",
        channel=6,
        width_mhz=20,
        utilization=_m(78.0),
    )
    other = RadioView(
        router_id=R2, radio_id="radio0", band="2.4g", channel=6, width_mhz=20
    )
    assessment = assess_client(_window())
    roams = _roam_window()
    rec = Recommendation(
        kind="channel",
        target=RadioRef(R1, "radio0"),
        problem="p",
        evidence=(f"utilization:{R1}/radio0:78.0%:hostapd.get_status",),
        action="a",
        action_params={"channel": 1},
        expected_effect="e",
        confidence=0.5,
        risk=(),
    )
    component = component_from_metric("utilization", _m(40.0), score_utilization)
    radio_score = radio_health([component])
    health = aggregate_health([item_from(f"{R1}/radio0", radio_score, 3)])
    sticky = assess_sticky(
        StickyInput(
            client_mac=MAC,
            current_radio=RadioRef(R1, "radio0"),
            current_rssi=_m(-85.0, SOURCE_IWINFO_ASSOCLIST),
            dwell_s=7200.0,
            weak_share=0.9,
            alternatives=(
                AlternativeAp(
                    radio=RadioRef(R2, "radio0"),
                    rssi=_m(-60.0, SOURCE_IWINFO_ASSOCLIST),
                    basis="measured_same_client",
                    age_s=10.0,
                    band="5g",
                ),
            ),
            band="5g",
        )
    )
    points = [(float(t), 50.0) for t in range(0, 3600, 60)]
    return {
        "ref": RadioRef(R1, "radio0"),
        "conflicts": detect_conflicts([view, other]),
        "capabilities": RadioCapabilities(
            R1, "radio0", {METRIC_NOISE: CapabilityState.MEASURED}
        ),
        "metric": _m(-95, "iwinfo.info"),
        "assessment": assessment,
        "summary": summarize_radio_clients([assessment]),
        "flaps": detect_flapping(roams.events),
        "roaming": roaming_quality(roams),
        "sticky": sticky,
        "neighbors": sanitize_neighbors(
            [
                {"bssid": OWN_BSSID, "channel": 6, "signal": -40},
                {"bssid": FOREIGN_BSSID, "channel": 6, "signal": -70},
            ],
            [OWN_BSSID],
            key=KEY,
        ),
        "recommendation": rec,
        "component": component,
        "radio_health": radio_score,
        "health": health,
        "load": assess_load(_load_input()),
        "distribution": distribution(_load_input()),
        "utilization": utilization_from_delta(
            _survey(100.0, 10_000), _survey(160.0, 40_000)
        ),
        "utilization_summary": summarize(
            [(float(t), 95.0) for t in range(0, 3600, 60)],
            now=3600.0,
            window_s=3600.0,
            thresholds=UtilizationThresholds(),
            expected_interval_s=60.0,
        ),
        "series": series_for_window(
            points, roll_up(points, 3600), {}, now=3600.0, window="1h"
        ),
        "scan_decision": ScanDecision(False, ScanReason.RATE_LIMIT_RADIO, 12.0),
    }


# ---------------------------------------------------------------------------
# 1. Field names and the Core masking
# ---------------------------------------------------------------------------


def _output_names() -> set[str]:
    """Every field name an RF output can carry.

    Dataclass fields, keys of every dict display in RF source (as_dict,
    event data, error details) and keys of module-level mappings (metric
    and part names used as keys in as_dict forms).
    """
    names: set[str] = set()
    for mod in _modules():
        for attr, obj in vars(mod).items():
            if attr.startswith("__"):
                continue  # __builtins__ is a dict of builtin names
            if isinstance(obj, type) and obj.__module__ == mod.__name__:
                if is_dataclass(obj):
                    names.update(f.name for f in fields(obj))
            elif isinstance(obj, Mapping):
                names.update(k for k in obj if isinstance(k, str))
    for path in RF_FILES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Dict):
                names.update(
                    k.value
                    for k in node.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                )
    return names


def _enum_values() -> set[str]:
    values: set[str] = set()
    for mod in _modules():
        for obj in vars(mod).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, Enum)
                and obj.__module__ == mod.__name__
            ):
                values.update(m.value for m in obj if isinstance(m.value, str))
    return values


def _code_heads() -> set[str]:
    """Evidence code names: the literal text before the first ``:``."""
    heads: set[str] = set()
    for path in RF_FILES:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.JoinedStr) and node.values:
                first = node.values[0]
                if isinstance(first, ast.Constant) and ":" in str(first.value):
                    heads.add(str(first.value).split(":", 1)[0])
    return {h for h in heads if h and h.replace("_", "").isalnum()}


class TestFieldNames:
    def test_the_names_are_collected(self):
        names = _output_names()
        assert {"router_id", "radio_id", "client_mac", "bssid"} <= names
        assert {"handshake_failures", "worst_member_id", "member_id"} <= names

    def test_no_rf_field_name_is_a_core_secret_name(self):
        assert sorted(n for n in _output_names() if is_secret_key(n)) == []

    def test_the_old_names_are_gone_because_the_core_masks_them(self):
        old = {"router_key", "radio_key", "worst_key", "key"}
        old |= {"client_key", "auth_failures"}
        # ``radio_keys`` (plural) is no Core secret name, renamed for consistency
        assert not (old | {"radio_keys"}) & _output_names()
        for name in old:
            assert is_secret_key(name), name
        assert mask_for_output({"router_key": R1})["router_key"] == MASK

    def test_no_enum_value_is_secret_or_redacted(self):
        for value in _enum_values():
            assert not is_secret_key(value), value
            assert redact_text(value) == value, value

    def test_no_evidence_code_is_secret_or_redacted(self):
        heads = _code_heads()
        assert {"roams_with_handshake_failures", "handshake_unknown"} <= heads
        for head in heads:
            assert not is_secret_key(head), head
            for text in (f"{head}:3", f"{head}:{R1}/radio0", f"{head}:1/2"):
                assert redact_text(text) == text, text

    def test_radio_ref_is_router_id_and_radio_id(self):
        assert RadioRef(R1, "radio0").as_dict() == {
            "router_id": R1,
            "radio_id": "radio0",
        }

    def test_core_masking_leaves_every_output_form_unchanged(self):
        # Every id and every number stays readable: the Core changes nothing
        # (it does not touch MACs either; that is point 3).
        plain = _plain(_outputs())
        assert plain["flaps"]  # the window really flaps
        assert mask_for_output(plain) == plain

    @pytest.mark.parametrize("name", sorted(_outputs()))
    def test_each_output_form_survives_the_core(self, name):
        plain = _plain(_outputs()[name])
        assert mask_for_output(plain) == plain


# ---------------------------------------------------------------------------
# 2. Counters without a secret word
# ---------------------------------------------------------------------------


class TestCounters:
    def test_the_old_counter_showed_no_number(self):
        assert mask_for_output({"auth_failures": 2}) == {"auth_failures": MASK}
        assert mask_for_output({"handshake_failures": 2}) == {"handshake_failures": 2}

    def test_handshake_part_and_codes_survive(self):
        score = roaming_quality(_roam_window())
        parts = {p.name: p for p in score.parts}
        assert PART_HANDSHAKE == "handshake" and "auth" not in WEIGHTS
        part = parts[PART_HANDSHAKE]
        assert "roams_with_handshake_failures:2/4" in part.evidence
        assert "handshake_unknown:2" in part.evidence
        plain = _plain(score)
        assert mask_for_output(plain) == plain
        for code in part.evidence:
            assert redact_text(code) == code


# ---------------------------------------------------------------------------
# 3. Pseudonyms come from the Core
# ---------------------------------------------------------------------------


class TestCorePseudonyms:
    """The former Core gap (``TestCoreGap``) is closed: the Core pseudonymises."""

    def test_core_pseudonymises_ssid_bssid_mac_and_client(self):
        data = {"ssid": "Home", "bssid": OWN_BSSID, "mac": MAC, "client_mac": MAC}
        core = pseudonymise_fields(data, KEY, RF_IDENTIFIER_FIELDS)
        assert core == {
            "ssid": pseudonymise_identifier("ssid", "Home", KEY),
            "bssid": pseudonymise_identifier("bssid", OWN_BSSID, KEY),
            "mac": pseudonymise_identifier("mac", MAC, KEY),
            "client_mac": pseudonymise_identifier("client", MAC, KEY),
        }
        assert mask_rf_output(data, key=KEY) == core

    def test_the_core_masking_alone_still_shows_them(self):
        data = {"ssid": "Home", "bssid": OWN_BSSID, "mac": MAC}
        assert mask_for_output(data) == data

    def test_client_pseudonym_is_a_core_client_ref(self):
        masked = mask_rf_output(_outputs(), key=KEY)
        ref = masked["assessment"]["client_mac"]
        assert CLIENT_REF_PATTERN.fullmatch(ref)
        assert ref == client_ref(MAC, KEY)
        assert ref == pseudonymise_identifier("client", MAC, KEY)
        assert masked["roaming"]["client_mac"] == ref
        assert all(f["client_mac"] == ref for f in masked["flaps"])


class TestWhatRfAddsToTheCore:
    """Why ``mask_rf_output`` stays: three things the Core helper does not do."""

    def test_objects_with_as_dict(self):
        ref = RadioRef(R1, "radio0")
        window = _roam_window()
        # the Core walks mappings and lists only; an RF object passes as is
        assert pseudonymise_fields(window, KEY, RF_IDENTIFIER_FIELDS) is window
        flaps = detect_flapping(window.events)
        masked = mask_rf_output(flaps, key=KEY)
        assert MAC not in repr(masked)
        assert mask_rf_output(ref, key=KEY) == {"router_id": R1, "radio_id": "radio0"}

    def test_macs_in_free_text(self):
        data = {"evidence": [f"client:{MAC}", f"x {MAC.upper()} y"]}
        assert pseudonymise_fields(data, KEY, RF_IDENTIFIER_FIELDS) == data
        pseudo = pseudonymise_identifier("mac", MAC, KEY)
        assert mask_rf_output(data, key=KEY) == {
            "evidence": [f"client:{pseudo}", f"x {pseudo} y"]
        }

    def test_idempotent_where_the_core_is_not(self):
        data = {"bssid": OWN_BSSID, "client_mac": MAC, "evidence": [f"a:{MAC}"]}
        core_once = pseudonymise_fields(data, KEY, RF_IDENTIFIER_FIELDS)
        core_twice = pseudonymise_fields(core_once, KEY, RF_IDENTIFIER_FIELDS)
        assert core_twice["bssid"] == IDENTIFIER_INVALID
        once = mask_rf_output(data, key=KEY)
        assert mask_rf_output(once, key=KEY) == once

    def test_without_a_key_identifiers_become_the_mask(self):
        # installation key lost: no pseudonym, never the raw value
        data = {"bssid": OWN_BSSID, "client_mac": MAC, "evidence": [f"a:{MAC}"]}
        assert mask_rf_output(data, key=None) == {
            "bssid": MASK,
            "client_mac": MASK,
            "evidence": [f"a:{MASK}"],
        }

    def test_neighbor_pseudonym_is_kept_own_bssid_pseudonymised(self):
        masked = mask_rf_output(_outputs(), key=KEY)["neighbors"]
        own = next(n for n in masked if n["own"])
        foreign = next(n for n in masked if not n["own"])
        assert own["bssid"] == pseudonymise_identifier("bssid", OWN_BSSID, KEY)
        assert foreign["bssid"] == pseudonymise_identifier("bssid", FOREIGN_BSSID, KEY)


# ---------------------------------------------------------------------------
# 4. The neighbor key is the Core module key
# ---------------------------------------------------------------------------


class _ModuleKeys:
    """Stands in for ``api``; derives with the real Core helper."""

    def __init__(self, installation_key: bytes | None) -> None:
        self.installation_key = installation_key
        self.calls: list[tuple[str, str]] = []

    async def async_get_module_key(self, module: str, purpose: str = "") -> bytes:
        self.calls.append((module, purpose))
        if self.installation_key is None:
            raise InstallationKeyLostError("lost")
        return derive_module_key(self.installation_key, module, purpose)


class TestModuleKey:
    async def test_key_is_the_wifi_rf_module_key(self):
        api = _ModuleKeys(INSTALLATION_KEY)
        key = await rf_key_request(api)
        assert api.calls == [("wifi_rf", RF_PSEUDONYM_PURPOSE)]
        assert key == derive_module_key(INSTALLATION_KEY, "wifi_rf", "pseudonym")
        assert MODULE_KEY_PURPOSE_PATTERN.fullmatch(RF_PSEUDONYM_PURPOSE)

    async def test_neighbor_hashes_use_exactly_that_key(self):
        key = await rf_key_request(_ModuleKeys(INSTALLATION_KEY))
        (n,) = sanitize_neighbors(
            [{"bssid": FOREIGN_BSSID, "signal": -60}], [], key=key
        )
        assert n.bssid == pseudonymise_identifier(
            "bssid",
            FOREIGN_BSSID,
            derive_module_key(INSTALLATION_KEY, "wifi_rf", "pseudonym"),
        )

    async def test_a_lost_key_is_not_replaced(self):
        with pytest.raises(InstallationKeyLostError):
            await rf_key_request(_ModuleKeys(None))

    def test_the_core_offers_this_call(self):
        params = inspect.signature(ConfigurationApiProtocol.async_get_module_key)
        assert list(params.parameters) == ["self", "module", "purpose"]


# ---------------------------------------------------------------------------
# 5. Core error classes for refused scans
# ---------------------------------------------------------------------------


class TestScanErrors:
    @pytest.mark.parametrize(
        ("reason", "error"),
        [
            (ScanReason.SCAN_UNSUPPORTED, CapabilityUnavailableError),
            (ScanReason.SCAN_UNAVAILABLE, CapabilityUnavailableError),
            (ScanReason.NOT_ADMIN, AuthorizationError),
            (ScanReason.AUTO_DISABLED, AuthorizationError),
            (ScanReason.UPLINK_RADIO, SafetyRefusedError),
            (ScanReason.UPLINK_UNKNOWN, SafetyRefusedError),
            (ScanReason.CAC_ACTIVE, SafetyRefusedError),
            (ScanReason.CAC_UNKNOWN, SafetyRefusedError),
            (ScanReason.RATE_LIMIT_RADIO, RateLimitedError),
            (ScanReason.RATE_LIMIT_ROUTER, RateLimitedError),
        ],
    )
    def test_each_reason_has_its_core_class(self, reason, error):
        err = scan_refusal_error(ScanDecision(False, reason, 12.0), router_id=R1)
        assert type(err) is error
        assert err.details["reason"] == reason.value
        if error is SafetyRefusedError:
            assert err.reason == reason.value and err.retryable is False
        if error is RateLimitedError:
            assert err.retry_after == 12.0 and err.retryable is True

    @pytest.mark.parametrize(
        ("reason", "wait"),
        [(ScanReason.RATE_LIMIT_RADIO, 3600.0), (ScanReason.RATE_LIMIT_ROUTER, 300.0)],
    )
    def test_rate_limit_without_a_wait_takes_the_full_interval(self, reason, wait):
        err = scan_refusal_error(ScanDecision(False, reason, None), router_id=R1)
        assert isinstance(err, RateLimitedError)
        assert err.retry_after == wait


# ---------------------------------------------------------------------------
# 6. sensitive_read through the Core
# ---------------------------------------------------------------------------


class TestSensitiveReads:
    def test_registered_as_core_sensitive_reads(self):
        names = {a.name for a in SENSITIVE_READ_ACTIONS}
        assert names == {
            "wifi_rf.neighbor_list",
            "wifi_rf.client_rf",
            "wifi_rf.client_roam_history",
        }
        for action in SENSITIVE_READ_ACTIONS:
            assert action.action_class is ActionClass.READ
            assert action.sensitive_read is True
            assert action.admin_user_only is False
            assert action.rate_limit is None
            assert action in RF_ACTIONS

    async def test_the_core_guard_enforces_them(self, disks):
        hass = make_hass()
        add_users(hass)
        audit = AuditLog(hass)
        await audit.async_load()
        guard = ActionGuard(hass, audit)
        register_rf_actions(guard)
        register_rf_actions(guard)  # same definition again: no-op
        admin = await guard.async_verify_actor(user_actor(ADMIN_ID))
        plain = await guard.async_verify_actor(user_actor(USER_ID))
        module = await guard.async_verify_actor(Actor.for_module("wifi_rf"))
        for action in SENSITIVE_READ_ACTIONS:
            assert guard.action_class(action.name) is ActionClass.READ
            assert rf_policy_denial(action.name, plain) == "not_admin"
            assert rf_policy_denial(action.name, admin) is None
            assert rf_policy_denial(action.name, module) is None
            denied = guard.authorize(action.name, R1, plain)
            assert denied.state is DecisionState.DENIED
            assert denied.reason == "not_admin"
            assert (
                guard.authorize(action.name, R1, admin).state is DecisionState.APPROVED
            )


# ---------------------------------------------------------------------------
# 7. Periodic reads are reads, not active actions (DECIDED)
# ---------------------------------------------------------------------------


class TestPollReads:
    def test_survey_assoclist_and_setup_lists_are_listed(self):
        sources = {r.source for r in POLL_READS}
        assert {
            SOURCE_IWINFO_SURVEY,
            SOURCE_IWINFO_ASSOCLIST,
            SOURCE_IWINFO_TXPOWERLIST,
            SOURCE_IWINFO_FREQLIST,
        } <= sources

    def test_they_are_reads_and_no_guard_action(self):
        action_names = {a.name for a in RF_ACTIONS}
        for read in POLL_READS:
            assert read.action_class is ActionClass.READ
            assert read.name not in action_names
            assert read.name.startswith("wifi_rf.")
        assert not [a for a in RF_ACTIONS if a.action_class is ActionClass.ACTIVE]

    def test_periodic_reads_keep_a_time_floor(self):
        periodic = [r for r in POLL_READS if r.cadence == "periodic"]
        assert {r.source for r in periodic} >= {
            SOURCE_IWINFO_SURVEY,
            SOURCE_IWINFO_ASSOCLIST,
        }
        for read in periodic:
            assert read.min_interval_s >= 300.0
        for read in POLL_READS:
            if read.cadence == "setup":
                assert read.min_interval_s is None

    def test_the_scan_stays_critical_and_admin_only(self):
        assert SCAN_ACTION.action_class is ActionClass.CRITICAL
        assert SCAN_ACTION.admin_user_only is True
        assert SCAN_ACTION.rate_limit is None


# ---------------------------------------------------------------------------
# 8. Typed CoreEvent fields
# ---------------------------------------------------------------------------


def _admin():
    return Actor.for_module("wifi_rf")


class TestTypedEventFields:
    def test_utilization_event_names_the_radio_in_radio_id(self):
        summary = _outputs()["utilization_summary"]
        event = channel_utilization_event(RadioRef(R1, "radio0"), summary, now=NOW)
        assert event.radio_id == "radio0"
        assert event.router_id == R1
        assert "radio" not in event.data and "radio_id" not in event.data

    def test_scan_events_name_the_radio_in_radio_id(self):
        refused = ScanDecision(False, ScanReason.CAC_ACTIVE)
        for event in (
            scan_requested_event(R1, "radio1", actor=_admin(), now=NOW),
            scan_refused_event(R1, "radio1", refused, actor=_admin(), now=NOW),
            scan_executed_event(
                R1, "radio1", actor=_admin(), now=NOW, neighbor_count=3, own_count=1
            ),
        ):
            assert event.radio_id == "radio1"
            assert "radio" not in event.data and "radio_id" not in event.data

    def test_conflict_event_classification_and_members(self):
        (conflict,) = [
            c for c in _outputs()["conflicts"] if c.status.value == "measured"
        ] or [None]
        if conflict is None:
            pytest.skip("no measured conflict in the fixture")
        event = channel_conflict_event(conflict, now=NOW)
        assert event.classification == conflict.kind.value
        assert "kind" not in event.data
        assert {tuple(m) for m in event.data["members"]} == {("router_id", "radio_id")}

    def test_recommendation_event_has_typed_fields(self):
        rec = _outputs()["recommendation"]
        (event,) = recommendation_events([], [rec], now=NOW)
        assert event.router_id == R1
        assert event.radio_id == "radio0"
        assert event.classification == "channel"
        assert event.confidence == 0.5
        assert "target" not in event.data and "confidence" not in event.data

    def test_emit_kwargs_carries_every_typed_field(self):
        event = scan_requested_event(R1, "radio1", actor=_admin(), now=NOW)
        kwargs = emit_kwargs(event)
        for name in EVENT_REF_FIELDS:
            assert kwargs[name] == getattr(event, name)

    async def test_the_core_audit_log_keeps_the_typed_fields(self, disks):
        hass = make_hass()
        audit = AuditLog(hass)
        await audit.async_load()
        audit.register_event_prefix("wifi_rf.", module="wifi_rf")
        rec = _outputs()["recommendation"]
        (event,) = recommendation_events([], [rec], now=NOW)
        stored = audit.emit(**emit_kwargs(event)).event
        assert stored.radio_id == "radio0"
        assert stored.classification == "channel"
        assert stored.confidence == 0.5

    def test_client_ref_is_accepted_a_mac_is_not(self):
        base = {
            "event_id": new_id(EVENT_ID_PREFIX),
            "ts": NOW,
            "type": "wifi_rf.example",
            "source": "wifi_rf",
            "severity": Severity.INFO,
            "result": EventResult.INFO,
        }
        assert CoreEvent(**base, client_ref=client_ref(MAC, KEY)).client_ref
        with pytest.raises(ValueError):
            CoreEvent(**base, client_ref=MAC)

    def test_event_data_passes_the_core_unchanged(self):
        rec = _outputs()["recommendation"]
        events = recommendation_events([], [rec], now=NOW)
        events.append(scan_requested_event(R1, "radio1", actor=_admin(), now=NOW))
        for event in events:
            plain = dict(event.data)
            assert mask_for_output(plain) == plain
