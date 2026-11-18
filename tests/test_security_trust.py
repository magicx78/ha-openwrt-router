"""Tests for security_trust (Security Center stage 2, pure logic)."""

from __future__ import annotations

import json
import logging

import pytest

from custom_components.openwrt_router.client_history import ClientLive
from custom_components.openwrt_router.core_masking import pseudonymise_user_id
from custom_components.openwrt_router.core_models import Actor, ActorKind
from custom_components.openwrt_router.security_model import (
    Assessment,
    DataSource,
    EventResult,
    SecCategory,
    Severity,
)
from custom_components.openwrt_router.security_trust import (
    Indicator,
    IsolationProof,
    NoticeKind,
    TrustActionKind,
    TrustBook,
    TrustState,
)

T0 = 1_700_000_000.0
MAC = "3c:22:fb:10:20:30"  # globally administered
PRIVATE = "da:a1:19:00:00:01"  # locally administered (randomised)
ROUTER = "rtr_" + "c" * 32


def live(
    mac: str = MAC,
    *,
    ip: str | None = "192.168.1.20",
    hostname: str | None = "laptop",
    first_seen: float | None = T0,
    private_mac: bool | None = None,
) -> ClientLive:
    """A real ``ClientLive`` (proves the Protocol fits Client Stability)."""
    return ClientLive(
        mac=mac,
        private_mac=private_mac if private_mac is not None else mac == PRIVATE,
        state="online",
        since=first_seen,
        ap="ap1",
        band="5g",
        rssi=-60,
        session_start=first_seen,
        session_start_known=True,
        first_seen=first_seen,
        last_seen=first_seen,
        last_disconnect=None,
        hostname=hostname,
        hostname_changed=None,
        ip=ip,
        ip_changed=None,
    )


def kinds(notices: tuple) -> list[NoticeKind]:
    return [n.kind for n in notices]


def test_case01_new_unknown_device() -> None:
    book = TrustBook()
    notices = book.observe(live(), T0 + 10)
    assert kinds(notices) == [NoticeKind.NEW_DEVICE]
    notice = notices[0]
    assert notice.severity is Severity.INFO
    assert notice.assessment is Assessment.NOTICEABLE
    assert book.state(MAC, T0 + 10) is TrustState.NEW
    # an unknown MAC alone is never suspicious, and the notice is not repeated
    assert book.observe(live(), T0 + 20) == ()
    assert book.state(MAC, T0 + 20) is not TrustState.SUSPICIOUS
    event = notice.to_event(router_id=ROUTER)
    assert event.category is SecCategory.DEVICE
    assert event.data_source == DataSource.CLIENT_HISTORY
    assert event.assessment is not Assessment.CONFIRMED
    # after the new period the device is unrecognized, still not suspicious
    assert book.state(MAC, T0 + 3 * 86400) is TrustState.UNRECOGNIZED


def test_case01_device_long_known_to_client_stability_is_no_new_alarm() -> None:
    book = TrustBook()
    assert book.observe(live(first_seen=T0 - 30 * 86400), T0) == ()


def test_case02_known_device_with_changed_ip() -> None:
    book = TrustBook()
    book.observe(live(), T0)
    assert book.confirm(MAC, T0 + 1, name="Office laptop")
    assert book.observe(live(ip="192.168.1.99"), T0 + 600) == ()
    assert book.state(MAC, T0 + 600) is TrustState.KNOWN
    record = book.get(MAC)
    assert record is not None and record.name == "Office laptop"
    assert record.ip == "192.168.1.99"


def test_case02_frequent_ip_changes_are_one_indicator_not_suspicious() -> None:
    book = TrustBook(ip_churn_min=4)
    book.observe(live(), T0)
    book.confirm(MAC, T0)
    seen: list[NoticeKind] = []
    for i in range(1, 7):
        seen += kinds(book.observe(live(ip=f"10.0.0.{i}"), T0 + 60 * i))
    assert seen == [NoticeKind.IP_CHURN]  # once, at the crossing
    record = book.get(MAC)
    assert record is not None
    assert Indicator.IP_CHURN in record.active_indicators(T0 + 400, 3600)
    assert book.state(MAC, T0 + 400) is TrustState.KNOWN  # one indicator only


def test_case03_mac_randomization() -> None:
    book = TrustBook()
    notices = book.observe(live(PRIVATE), T0)
    assert kinds(notices) == [NoticeKind.PRIVATE_MAC]
    assert notices[0].assessment is Assessment.NORMAL
    assert notices[0].severity is Severity.INFO
    # private flag missing: derived from the locally administered bit
    book2 = TrustBook()
    assert kinds(book2.observe(_Obs(PRIVATE), T0)) == [NoticeKind.PRIVATE_MAC]


class _Obs:
    """Minimal observation with unknown fields (Protocol, not ClientLive)."""

    def __init__(self, mac: str, first_seen: float | None = T0) -> None:
        self.mac = mac
        self.private_mac = None
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.ip = None
        self.hostname = None


def test_missing_data_is_unknown_never_safe() -> None:
    book = TrustBook()
    assert book.state(MAC, T0) is TrustState.UNRECOGNIZED  # untracked
    notices = book.observe(_Obs(MAC, first_seen=None), T0)
    assert kinds(notices) == [NoticeKind.INCOMPLETE]
    assert book.state(MAC, T0) is TrustState.UNRECOGNIZED
    assert book.observe(_Obs(MAC, first_seen=None), T0 + 60) == ()  # once
    assert book.observe(_Obs("not-a-mac"), T0) == ()
    assert book.state("garbage", T0) is TrustState.UNRECOGNIZED


def test_suspicious_needs_two_independent_indicators() -> None:
    book = TrustBook()
    book.observe(live(), T0)
    assert book.add_indicator(MAC, Indicator.PORT_SCAN, T0 + 10) == ()
    assert book.add_indicator(MAC, Indicator.PORT_SCAN, T0 + 20) == ()  # same kind
    assert book.state(MAC, T0 + 20) is TrustState.NEW
    notices = book.add_indicator(MAC, Indicator.DNS_ANOMALY, T0 + 30)
    assert kinds(notices) == [NoticeKind.SUSPICIOUS]
    assert notices[0].assessment is Assessment.SUSPICIOUS
    assert book.state(MAC, T0 + 30) is TrustState.SUSPICIOUS
    # indicators age out of their window
    assert book.state(MAC, T0 + 30 + 2 * 3600) is TrustState.NEW
    # the minimum cannot be configured below two indicators
    assert TrustBook(suspicious_min_indicators=1).suspicious_min_indicators == 2


def test_quarantine_only_with_proof_and_never_left_automatically() -> None:
    book = TrustBook()
    book.observe(live(), T0)
    with pytest.raises(TypeError):
        book.quarantine(MAC, "trust me", T0)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        IsolationProof(method="", verified_at=T0)
    proof = IsolationProof(method="vlan_isolated", verified_at=T0, reference="chg-1")
    assert book.quarantine(MAC, proof, T0 + 1)
    assert book.state(MAC, T0 + 1) is TrustState.QUARANTINED
    assert not book.confirm(MAC, T0 + 2)  # refused while quarantined
    book.observe(live(), T0 + 10 * 86400)
    assert book.state(MAC, T0 + 10 * 86400) is TrustState.QUARANTINED
    restored = TrustBook.from_dict(json.loads(json.dumps(book.to_dict())))
    assert restored.state(MAC, T0 + 20 * 86400) is TrustState.QUARANTINED
    assert book.release_quarantine(MAC)
    assert book.state(MAC, T0 + 10 * 86400) is TrustState.UNRECOGNIZED
    assert not book.quarantine("aa:aa:aa:aa:aa:aa", proof, T0)  # untracked


def test_manual_confirm_and_naming() -> None:
    book = TrustBook()
    assert not book.set_name(MAC, "x")  # untracked
    book.observe(live(), T0)
    book.add_indicator(MAC, Indicator.PORT_SCAN, T0)
    book.add_indicator(MAC, Indicator.MGMT_ACCESS, T0)
    assert book.state(MAC, T0) is TrustState.SUSPICIOUS
    assert book.confirm(MAC, T0 + 1)
    assert book.state(MAC, T0 + 1) is TrustState.KNOWN
    assert book.set_name(MAC, "Printer\x00 hall")
    record = book.get(MAC)
    assert record is not None and record.name == "Printer hall"
    assert book.confirm("aa:bb:cc:dd:ee:01", T0, name="pre-registered")
    assert book.state("aa:bb:cc:dd:ee:01", T0) is TrustState.KNOWN


HA_USER = "0d5a2f3b9c8e4a71b6f0e2d4c6a8b0f1"
SALT = b"t" * 16


def test_manual_actions_carry_the_actor_only_as_pseudonym() -> None:
    book = TrustBook(actor_salt=SALT)
    user = Actor(kind=ActorKind.USER, user_id=HA_USER, context_id="ctx-9")
    book.observe(live(), T0)
    proof = IsolationProof(method="vlan_isolated", verified_at=T0)
    actions = [
        book.confirm(MAC, T0 + 1, name="Kids tablet", actor=user),
        book.set_name(MAC, "Kids tablet", actor=user),
        book.quarantine(MAC, proof, T0 + 2, actor=user),
        book.release_quarantine(MAC, actor=user),
    ]
    assert [a.kind for a in actions] == [  # type: ignore[union-attr]
        TrustActionKind.CONFIRMED,
        TrustActionKind.RENAMED,
        TrustActionKind.QUARANTINED,
        TrustActionKind.RELEASED,
    ]
    pseudonym = pseudonymise_user_id(HA_USER, SALT)
    for action in actions:
        assert action is not None
        assert action.actor is not None and action.actor.user_id == pseudonym
        event = action.to_event(router_id=ROUTER)
        assert event.result is EventResult.SUCCESS
        assert event.category is SecCategory.DEVICE
        core = event.to_core_event(identity_key=b"k" * 32)
        assert core.actor is not None and core.actor.user_id == pseudonym
        text = json.dumps(core.to_dict()) + json.dumps(event.to_dict())
        text += repr(action) + repr(event)
        for secret in (HA_USER, "ctx-9", "Kids tablet"):
            assert secret not in text
    assert actions[2].to_event().severity is Severity.WARNING  # type: ignore[union-attr]
    # two actions never share a dedup scope (each is its own audit entry)
    scopes = {a.to_event().dedup_scope for a in actions}  # type: ignore[union-attr]
    assert len(scopes) == len(actions)
    # without an actor (automation, test) the action has none
    assert book.set_name(MAC, None).actor is None  # type: ignore[union-attr]
    # a refused action returns nothing
    assert book.set_name("aa:aa:aa:aa:aa:aa", "x", actor=user) is None


def test_hostname_change_is_an_indicator() -> None:
    book = TrustBook()
    book.observe(live(hostname="a"), T0)
    book.observe(live(hostname="b"), T0 + 1)
    record = book.get(MAC)
    assert record is not None
    assert record.active_indicators(T0 + 1, 3600) == (Indicator.HOSTNAME_CHANGE,)


def test_cap_evicts_oldest_unconfirmed_and_reports_confirmed_overflow() -> None:
    book = TrustBook(max_entries=3)
    macs = [f"3c:22:fb:00:00:0{i}" for i in range(5)]
    book.observe(live(macs[0]), T0)
    book.confirm(macs[0], T0)
    book.observe(live(macs[1]), T0 + 1)
    book.observe(live(macs[2]), T0 + 2)
    book.observe(live(macs[3]), T0 + 3)  # evicts macs[1], the oldest unconfirmed
    assert book.get(macs[1]) is None
    assert book.get(macs[0]) is not None  # confirmed stays
    assert len(book) == 3
    full = TrustBook(max_entries=2)
    full.confirm(macs[0], T0)
    full.confirm(macs[1], T0)
    notices = full.observe(live(macs[2]), T0)
    assert kinds(notices) == [NoticeKind.CAPACITY]
    assert full.capacity_overflow == 1
    assert full.get(macs[0]) is not None and full.get(macs[1]) is not None


def test_case18_ha_restart_trust_roundtrip() -> None:
    book = TrustBook()
    book.observe(live(), T0)
    book.observe(live(PRIVATE), T0)
    book.confirm(MAC, T0 + 5, name="Laptop")
    book.add_indicator(PRIVATE, Indicator.DNS_ANOMALY, T0 + 6)
    data = json.loads(json.dumps(book.to_dict()))
    restored = TrustBook.from_dict(data)
    assert restored.to_dict() == book.to_dict()
    assert restored.state(MAC, T0 + 7) is TrustState.KNOWN
    # no repeated new-device notice after the restart
    assert restored.observe(live(PRIVATE), T0 + 8) == ()
    damaged = TrustBook.from_dict({"records": [{"mac": "bad"}, None, 5]})
    assert len(damaged) == 0
    assert len(TrustBook.from_dict("garbage")) == 0


def test_case21_trust_privacy(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    book = TrustBook(max_entries=1)
    book.confirm(MAC, T0, name="Kids tablet")
    notices = book.observe(live(PRIVATE, hostname="kids-tablet"), T0)
    text = repr(book) + repr(book.get(MAC)) + "".join(repr(n) for n in notices)
    text += repr(notices[0].to_event(router_id=ROUTER)) if notices else ""
    for ident in (MAC, PRIVATE, "192.168.1.20", "kids-tablet", "Kids tablet"):
        assert ident not in text
        for record in caplog.records:
            assert ident not in record.getMessage()


def _fake(i: int) -> str:
    return f"00:aa:00:00:{i // 256:02x}:{i % 256:02x}"


def test_review_h4_suspicious_device_survives_mac_flood() -> None:
    book = TrustBook(max_entries=100)
    book.observe(live(first_seen=T0 - 10 * 86400), T0)
    book.add_indicator(MAC, Indicator.AUTH_FAILURES, T0)
    assert kinds(book.add_indicator(MAC, Indicator.PORT_SCAN, T0)) == [
        NoticeKind.SUSPICIOUS
    ]
    notices: list = []
    for i in range(500):  # forged MACs that only ever appear in indicators
        notices += book.add_indicator(_fake(i), Indicator.AUTH_FAILURES, T0 + 1)
    assert book.state(MAC, T0 + 2) is TrustState.SUSPICIOUS
    assert len(book) <= 100
    unobserved = [m for m in (_fake(i) for i in range(500)) if book.get(m)]
    assert 0 < len(unobserved) <= book.max_indicator_only
    # every displaced entry with indicators is counted and reported
    assert book.capacity_overflow == 500 - len(unobserved)
    assert NoticeKind.CAPACITY in kinds(tuple(notices))


def test_review_h4_full_protected_area_reports_instead_of_evicting() -> None:
    book = TrustBook(max_entries=4)
    macs = [f"3c:22:fb:00:01:0{i}" for i in range(5)]
    for mac in macs[:4]:
        book.observe(live(mac), T0)
        book.add_indicator(mac, Indicator.PORT_SCAN, T0)
    notices = book.observe(live(macs[4]), T0 + 1)
    assert kinds(notices) == [NoticeKind.CAPACITY]
    assert all(book.get(m) is not None for m in macs[:4])
    assert book.capacity_overflow == 1
    # once the indicators are old, such an entry may make room again
    late = T0 + book.indicator_window_s + 10
    assert NoticeKind.CAPACITY not in kinds(book.observe(live(macs[4]), late))
    assert book.get(macs[4]) is not None and len(book) == 4
