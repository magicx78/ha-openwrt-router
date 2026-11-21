"""Security Center: fixes of the independent review of PR 58.

One block per finding (1, 2, 4, 5, 6, 8 against 98882e1; 3 against 4fd871d;
7 lives in the panel tests). Every test started red. No Home Assistant
instance, no router: the center runs on in-memory stores, the core on
FakeDisks, the syslog receiver on loopback.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import voluptuous as vol
from config_manager_kit import cm_env, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import FakeDisks
from test_net_engine import FakeDisk, make_hass
from test_security_center import (
    ADMIN,
    MODULE_KEY,
    NO_SCHEDULE,
    RID1,
    T0,
    _core_center,
    center_for,
    disks,  # noqa: F401 - fixture
    sec_disk,
)
from test_security_review2 import auth_event, poll_facts
from test_security_syslog import LOOP, NOV18, Clock, fw_line
from test_security_views import http, users

from custom_components.openwrt_router.const import (
    SEC_INCIDENT_AUTO_RESOLVE_SECONDS,
    SEC_INCIDENT_CAP,
)
from custom_components.openwrt_router.core_errors import AuthorizationError
from custom_components.openwrt_router.security_center import (
    INDICATOR_OF,
    SecurityCenterError,
    async_release_security_center,
    default_settings,
    merge_settings,
)
from custom_components.openwrt_router.security_entities import SENSORS
from custom_components.openwrt_router.security_model import SecurityEvent
from custom_components.openwrt_router.security_rules import (
    DnsRateDetector,
    FirewallMgmtAccessDetector,
    VlanDriftDetector,
    default_detectors,
)
from custom_components.openwrt_router.security_syslog import (
    SyslogLimits,
    SyslogReceiver,
)
from custom_components.openwrt_router.security_trust import (
    NoticeKind,
    TrustNotice,
    TrustState,
)
from custom_components.openwrt_router.security_views import SETTINGS_FIELDS

LOG_QUOTA = 50  # decided: at most 50 of the 100 hints come from log lines


@pytest.fixture
def core_disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


async def keyed_center(hass: Any, *entries: str) -> Any:
    """An enabled center without core but with a module key (ready)."""
    center = await center_for(hass, *entries)
    center._module_key = MODULE_KEY
    return center


def forged(i: int, ts: float) -> SecurityEvent:
    """A firewall finding as forged syslog lines make it (own source each)."""
    src = f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}"
    return FirewallMgmtAccessDetector()._event(
        router_id=RID1, now=ts, key=(RID1, "guest", src)
    )


def wifi_hint(n: int, ts: float) -> SecurityEvent:
    return auth_event(RID1, mac=f"02:00:5e:20:{n // 256:02x}:{n % 256:02x}", now=ts)


def other_hint(n: int, ts: float) -> SecurityEvent:
    """A hint of the "other" class: Wi-Fi up to its share (40), then drift.

    Since 1.46.2 only 40 of the 50 places take Wi-Fi hints; filling the class
    needs non-Wi-Fi hints too (``test_security_low1462``).
    """
    if n < 40:
        return wifi_hint(n, ts)
    return VlanDriftDetector()._event(
        router_id=RID1,
        now=ts,
        key=(RID1, f"drf_{n}", "vlan"),
        evidence=(f"drift_id=drf_{n}", "areas=vlan"),
    )


def log_hints(center: Any) -> list[dict[str, Any]]:
    return [i for i in center.incidents.values() if i.get("from_logs") is True]


# --- 1: forged log lines cannot crowd out other hints ---------------------------------


async def test_review3_1_forged_log_lines_cannot_crowd_out_wifi_hints(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    for i in range(300):
        center._record(forged(i, T0 + i), T0 + i)
    assert len(log_hints(center)) == LOG_QUOTA
    assert len(center.incidents) == LOG_QUOTA
    assert center.counters["incidents_log_quota_dropped"] == 300 - LOG_QUOTA
    notes = [t for t in center.timeline if t["kind"] == "log_quota_reached"]
    assert len(notes) == 1  # once per window
    # real Wi-Fi (and drift) findings still find room ...
    for n in range(SEC_INCIDENT_CAP - LOG_QUOTA):
        center._record(other_hint(n, T0 + 400 + n), T0 + 400 + n)
    assert len(center.incidents) == SEC_INCIDENT_CAP
    assert center.counters["incidents_cap_dropped"] == 0
    # ... and a full class of other sources displaces no log hint any more
    # (review 4, #1 replaces the displacement): the new hint is dropped
    before = set(center.incidents)
    center._record(other_hint(999, T0 + 600), T0 + 600)
    center._record(other_hint(998, T0 + 601), T0 + 601)
    assert set(center.incidents) == before
    assert len(log_hints(center)) == LOG_QUOTA
    assert center.counters["incidents_other_quota_dropped"] == 2
    notes = [t for t in center.timeline if t["kind"] == "other_quota_reached"]
    assert len(notes) == 1  # limited like the cap note
    # visible in the overview and the diagnostics
    limits = center.overview(actor=None, now=T0 + 700)["limits"]
    assert limits["log_incident_quota"] == LOG_QUOTA
    assert limits["incidents_log_quota_dropped"] == 300 - LOG_QUOTA
    assert limits["incidents_other_quota_dropped"] == 2
    counters = center.diagnostics()["counters"]
    assert counters["incidents_other_quota_dropped"] == 2
    assert counters["incidents_log_quota_dropped"] == 300 - LOG_QUOTA


async def test_review3_1_resolved_log_hints_make_room_in_the_quota(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    for i in range(LOG_QUOTA):
        center._record(forged(i, T0 + i), T0 + i)
    first = min(log_hints(center), key=lambda i: i["last_seen"])
    first["status"] = "resolved"
    center._record(forged(500, T0 + 900), T0 + 900)
    assert first["id"] not in center.incidents
    assert len(log_hints(center)) == LOG_QUOTA
    assert center.counters["incidents_log_quota_dropped"] == 0
    # a DNS finding is a log hint too
    dns = DnsRateDetector()._event(router_id=RID1, now=T0 + 901, key=(RID1, "x"))
    center._record(dns, T0 + 901)
    assert center.counters["incidents_log_quota_dropped"] == 1


async def test_review3_1_origin_survives_a_restart_and_old_stores_load(
    disks,  # noqa: F811
) -> None:
    first = await keyed_center(make_hass(), "r1")
    first._record(forged(1, T0), T0)
    first._record(wifi_hint(1, T0), T0)
    await first.async_flush()
    second = await keyed_center(make_hass(), "r1")
    origins = sorted((i["category"], i["from_logs"]) for i in second.incidents.values())
    assert origins == [("firewall", True), ("wifi", False)]
    # a store from before the field: by category, nothing crashes
    stored = second._data_to_save()
    for item in stored["incidents"]:
        item.pop("from_logs")
    sec_disk(disks).data = stored
    third = await keyed_center(make_hass(), "r1")
    origins = sorted((i["category"], i["from_logs"]) for i in third.incidents.values())
    assert origins == [("firewall", True), ("wifi", False)]


# --- 2: firewall and DNS findings mark no device --------------------------------------


def test_review3_2_firewall_and_dns_findings_mark_no_device() -> None:
    wifi = {d.id for d in default_detectors().detectors if d.id.startswith("wifi_")}
    assert set(INDICATOR_OF) <= wifi
    assert not any(k.startswith(("fw_", "dns_")) for k in INDICATOR_OF)


# --- 3: the option keep_dns_names is gone ---------------------------------------------


async def test_review3_3_keep_dns_names_is_removed(disks) -> None:  # noqa: F811
    assert "keep_dns_names" not in default_settings()
    assert "keep_dns_names" not in SETTINGS_FIELDS
    with pytest.raises(vol.Invalid):
        merge_settings(default_settings(), {"keep_dns_names": True})
    hass = users(make_hass())
    center = await keyed_center(hass, "r1")
    before = dict(center.settings)
    with pytest.raises(SecurityCenterError) as caught:
        await center.async_update_settings({"keep_dns_names": True}, actor=ADMIN)
    assert caught.value.reason == "invalid_settings"
    async with http(hass) as h:
        resp = await h.post("/settings", body={"keep_dns_names": False})
    assert resp.status == 400
    assert resp.data["details"]["reason"] == "unknown_key"
    assert center.settings == before
    # a store from before still loads; the key is dropped, the rest stays
    stored = center._data_to_save()
    stored["settings"] = {
        **stored["settings"],
        "keep_dns_names": True,
        "thresholds": {"dns_rate": 77},
    }
    sec_disk(disks).data = stored
    again = await keyed_center(users(make_hass()), "r1")
    assert "keep_dns_names" not in again.settings
    assert again.settings["thresholds"] == {"dns_rate": 77}
    assert "keep_dns_names" not in again.settings_view(admin=True)["settings"]
    assert "keep_dns_names" not in again._data_to_save()["settings"]
    dns = [d for d in again.detectors.detectors if d.id.startswith("dns_")]
    assert dns and all(d.keep_names is False for d in dns)


# --- 4: a core AuthorizationError is a 403 --------------------------------------------


@pytest.mark.parametrize("where", ["verify", "consume"])
async def test_review3_4_guard_authorization_error_is_403(
    core_disks, tmp_path, where: str
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk())
    hass = users(env.hass)
    guard = type(env.api.guard)
    error = AuthorizationError(
        "internal: user 1234 unknown", details={"reason": "unknown_user"}
    )
    target = "async_verify_actor" if where == "verify" else "consume"
    mock = AsyncMock(side_effect=error) if where == "verify" else None
    with patch.object(guard, target, mock or _raiser(error)):
        with pytest.raises(SecurityCenterError) as caught:
            await center.async_update_settings({"syslog_port": 5515}, actor=ADMIN)
        assert caught.value.reason == "authorization_failed"
        async with http(hass) as h:
            resp = await h.post("/settings", body={"syslog_port": 5515})
        assert resp.status == 403
        assert resp.data["code"] == "authorization_denied"
        assert resp.data["details"] == {"reason": "authorization_failed"}
        h.assert_no_secret("1234", "unknown_user", "internal")
    assert center.counters["actions_denied"] >= 2
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


def _raiser(error: Exception) -> Any:
    def consume(*_a: Any, **_kw: Any) -> None:
        raise error

    return consume


# --- 5: a confirmed hint seen again gets a timeline entry ------------------------------


async def test_review3_5_confirmed_hint_seen_again_after_a_quiet_time(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    center._record(auth_event(RID1, now=T0), T0)
    (inc,) = center.incidents.values()
    inc["status"] = "confirmed"

    def again() -> list[dict[str, Any]]:
        return [t for t in center.timeline if t["kind"] == "incident_seen_again"]

    soon = T0 + 600
    center._record(auth_event(RID1, now=soon), soon)
    assert again() == []  # within the auto-resolve time: merged silently
    late = soon + SEC_INCIDENT_AUTO_RESOLVE_SECONDS + 60
    center._record(auth_event(RID1, now=late), late)
    (entry,) = again()
    assert entry["incident_id"] == inc["id"] and entry["ts"] == late
    assert entry["client_ref"] and entry["client_ref"].startswith("cli_")
    center._record(auth_event(RID1, now=late + 60), late + 60)
    assert len(again()) == 1
    assert len(center.incidents) == 1 and inc["status"] == "confirmed"
    # an open hint merges without an entry, as before
    inc["status"] = "open"
    later = late + 2 * SEC_INCIDENT_AUTO_RESOLVE_SECONDS
    center._record(auth_event(RID1, now=later), later)
    assert len(again()) == 1


# --- 6: no hint before the module key, the view says "not ready" ----------------------


async def test_review3_6_without_module_key_nothing_is_recorded(
    disks,  # noqa: F811
) -> None:
    center = await center_for(make_hass(), "r1", module_key=None)
    assert center.active and not center.module_key_available
    assert not hasattr(center, "_run_key")
    center.on_poll(poll_facts("r1", T0))
    center._record(auth_event(RID1), T0)
    center._apply_notices(
        [
            TrustNotice(
                kind=NoticeKind.NEW_DEVICE,
                state=TrustState.NEW,
                at=T0,
                mac="02:00:5e:10:00:01",
            )
        ],
        RID1,
        T0,
    )
    assert center.incidents == {}
    assert center.timeline == []
    assert center.counters["findings_not_ready"] == 1
    center._publish(T0)
    view = center.fleet_view
    assert view["ready"] is False
    assert view["not_ready_reason"] == "module_key_missing"
    for key in (
        "score",
        "coverage",
        "hints_active",
        "hints_critical",
        "unknown_devices",
        "firewall_events_1h",
        "wifi_auth_failures_1h",
    ):
        assert view[key] is None, key
    for description in SENSORS:
        assert description.value_fn(view) is None, description.key
    overview = center.overview(actor=None, now=T0)
    assert overview["ready"] is False
    assert overview["not_ready_reason"] == "module_key_missing"
    assert overview["score"]["score"] is None
    assert center.diagnostics()["not_ready_reason"] == "module_key_missing"
    # with the key the same finding is recorded
    center._module_key = MODULE_KEY
    center._record(auth_event(RID1), T0 + 60)
    assert len(center.incidents) == 1
    center._publish(T0 + 60)
    assert center.fleet_view["ready"] is True
    assert center.overview(actor=None, now=T0 + 60)["not_ready_reason"] is None


async def test_review3_6_device_actions_wait_for_the_module_key(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk())
    center.trust.observe(_obs("02:00:5e:10:00:01"), T0)
    center._module_key = None
    with patch.object(center, "_async_fetch_module_key", AsyncMock()):
        with pytest.raises(SecurityCenterError) as caught:
            await center.async_confirm_device("02:00:5e:10:00:01", actor=ADMIN)
        assert caught.value.reason == "module_key_missing"
        async with http(users(env.hass)) as h:
            resp = await h.post("/devices/confirm", body={"mac": "02:00:5e:10:00:01"})
        assert resp.status == 409 and resp.data["code"] == "not_ready"
    assert center.trust.get("02:00:5e:10:00:01").confirmed_at is None
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


def _obs(mac: str) -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(mac=mac, private_mac=None)


# --- 8: lines lost to the rate limit make the log source "limited" --------------------


async def test_review3_8_rate_limited_log_lines_limit_the_detections(
    disks,  # noqa: F811
) -> None:
    clock = Clock()
    made: list[SyslogReceiver] = []

    def factory(*, port: int, on_backlog: Any = None) -> SyslogReceiver:
        rx = SyslogReceiver(
            port=0,
            host=LOOP,
            clock=clock,
            on_backlog=on_backlog,
            limits=SyslogLimits(
                sender_rate=0.0, sender_burst=5, total_rate=0.0, total_burst=1000
            ),
        )
        made.append(rx)
        return rx

    center = await center_for(make_hass(), "r1", enabled=False)
    center._module_key = MODULE_KEY
    center.syslog_factory = factory
    center.senders_of = lambda: {LOOP: RID1}
    center.settings = merge_settings(
        center.settings, {"enabled": True, "log_path": "syslog"}
    )
    await center.async_activate()
    center._module_key = MODULE_KEY
    rx = center.syslog
    assert rx is not None and rx.listening

    def fw_detection(view: dict[str, Any]) -> dict[str, Any]:
        return next(d for d in view["detections"] if d["id"] == "fw_blocked")

    def activity(view: dict[str, Any]) -> dict[str, Any]:
        return next(
            f for f in view["score"]["factors"] if f["id"] == "network_activity"
        )

    for i in range(5):
        rx.receive(fw_line(i, NOV18), (LOOP, 514))
    center.on_poll(poll_facts("r1", NOV18))
    calm = center.overview(actor=None, now=NOV18)
    assert fw_detection(calm)["availability"] != "limited"
    assert "rate_limited" not in activity(calm)["limitations"]

    for i in range(5, 10):  # the sender's burst is used up: lines are lost
        rx.receive(fw_line(i, NOV18), (LOOP, 514))
    assert rx.stats().dropped_rate == 5
    center.on_poll(poll_facts("r1", NOV18 + 1))
    busy = center.overview(actor=None, now=NOV18 + 1)
    det = fw_detection(busy)
    assert det["availability"] == "limited"
    assert "rate_limited" in det["reason"] and "rate_limited" in det["limitations"]
    assert "rate_limited" in activity(busy)["limitations"]
    # 1.46.2: no extra deduction while the factor's DNS source is missing
    # fleet-wide (the gap is counted once); the drop with all sources is
    # in test_cov_ratelimit_supplier_stays_limited
    assert busy["coverage"]["value"] <= calm["coverage"]["value"]
    assert busy["log_path"]["rate_limited_routers"] == 1
    view = center.detections_view(now=NOV18 + 1)
    assert fw_detection(view)["availability"] == "limited"
    assert center.diagnostics()["log_rate_limited_routers"] == 1

    clock.now = NOV18 + 301  # hold time over: no more "limited"
    center.on_poll(poll_facts("r1", NOV18 + 301))
    later = center.overview(actor=None, now=NOV18 + 301)
    assert "rate_limited" not in fw_detection(later)["limitations"]
    assert "rate_limited" not in activity(later)["limitations"]
    center.close()
