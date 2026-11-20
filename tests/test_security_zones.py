"""Security Center 1.46.2, part 2: destination zone for ``fw_inter_vlan``.

Observed on v1.46.0: ``fw_inter_vlan`` reported ``dest_zone_unknown`` all the
time. fw4 never names the destination zone, and the detector only knew a
``dest_zone`` field (always None) and the manual ``subnet_zones`` map (empty
by default); ``OUT=`` was parsed but never used.

Interface -> zone, in this order (security_zones.ZoneBook):
(1) configured (tier for the Configuration Manager's snapshots; no public
    read path for a module today, so nothing feeds it in production),
(2) learned from the lines: the prefix zone of an ``in``/``forward`` line
    belongs to its ``IN=`` interface,
(3) the manual ``subnet_zones`` map; a PRIVATE destination outside it is
    unknown, only a public one is external.

Every test started red. Lines are built like the real fw4 lines (masked;
RFC 5737 addresses, ``02:00:00`` MACs, invented interfaces and zones).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from config_manager_kit import cm_env, stop
from core_test_provider import short_tmp_path  # noqa: F401 - fixture
from test_net_engine import FakeDisk, make_hass
from test_security_center import (
    NO_SCHEDULE,
    AreaProvider,
    _core_center,
    center_for,
    core_disks,  # noqa: F401 - fixture
    disks,  # noqa: F401 - fixture
)
from test_security_rules import R1, R2, results_events, statuses

from custom_components.openwrt_router.security_center import (
    async_release_security_center,
)
from custom_components.openwrt_router.security_logfmt import parse_remote_line
from custom_components.openwrt_router.security_logsrc import KeyAssigner
from custom_components.openwrt_router.security_model import LogPath
from custom_components.openwrt_router.security_rules import (
    DEST_ZONE_UNKNOWN,
    FirewallInterVlanDetector,
    default_detectors,
)
from custom_components.openwrt_router.security_zones import (
    MAX_IFACES_PER_ROUTER,
    ZONE_TTL_S,
    ZoneBook,
)

RECV = datetime(2026, 11, 17, 12, 0, 30, tzinfo=UTC).timestamp()
GW = "192.0.2.1"
TENANT_HOST = "192.0.2.80"
LAN_HOST = "192.0.2.20"
# private destinations outside a subnet map (invented values, no real net)
PRIVATE_V4 = "10.255.30.7"
PRIVATE_V6 = "fdff:0:0:30::7"
PUBLIC = "198.51.100.9"  # documentation range: counts as public here


def line(
    zone: str,
    chain: str,
    in_if: str,
    out_if: str = "",
    *,
    src: str = TENANT_HOST,
    dst: str = LAN_HOST,
    verdict: str = "reject",
    icmp: bool = False,
) -> str:
    """A fw4 message part in the structure seen on a real router."""
    head = (
        f"kernel: [12345.678901] {verdict} {zone} {chain}: IN={in_if} OUT={out_if} "
        f"MAC=02:00:00:00:00:aa:02:00:00:00:00:30:08:00 SRC={src} DST={dst} "
    )
    if icmp:
        return head + (
            "LEN=84 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=ICMP TYPE=8 CODE=0 ID=7 SEQ=1"
        )
    return head + (
        "LEN=120 TOS=0x00 PREC=0x00 TTL=63 ID=4242 PROTO=UDP SPT=40000 DPT=1900 LEN=100"
    )


def records(*messages: str, router: str = R1, second: int = 10) -> list[Any]:
    assigner = KeyAssigner()
    out = []
    for i, msg in enumerate(messages):
        result = parse_remote_line(
            f"<4>Nov 17 12:00:{(second + i) % 60:02d} ap-test {msg}",
            router=router,
            path=LogPath.SYSLOG.value,
            recv=RECV,
            tz_offset_s=0,
            assigner=assigner,
        )
        assert result.record is not None and result.record.kind, msg
        out.append(result.record)
    return out


def forward_lines(n: int = 5, **kw: Any) -> list[str]:
    return [line("lab", "forward", "br-lan.7", "br-lan.2", **kw)] * n


def forwards(n: int = 5, **kw: Any) -> list[Any]:
    return records(*forward_lines(n, **kw))


TEACH_LAN = line("lan", "in", "br-lan.2", src=LAN_HOST, dst=GW)


def evaluate(det: FirewallInterVlanDetector, router: str = R1) -> Any:
    (result,) = det.evaluate(RECV, statuses(router, now=RECV))
    return result


# --- B: known OUT interface -> finding without the limitation ----------------------------


def test_zone_out_known_interface_gives_a_finding_without_limitation() -> None:
    det = FirewallInterVlanDetector()
    for rec in records(TEACH_LAN) + forwards(5):
        det.feed(rec)
    result = evaluate(det)
    assert result.limitation is None and result.unattributed == 0
    (event,) = results_events((result,))
    assert event.src is not None and event.src.zone == "lab"
    assert event.dst is not None and event.dst.zone == "lan"
    assert DEST_ZONE_UNKNOWN not in (result.limitation or "")


def test_zone_out_unknown_interface_keeps_the_limitation() -> None:
    det = FirewallInterVlanDetector()
    for rec in forwards(5):  # br-lan.2 never seen as IN=: zone unknown
        det.feed(rec)
    result = evaluate(det)
    assert results_events((result,)) == []  # never guessed
    assert result.limitation == DEST_ZONE_UNKNOWN
    assert result.unattributed == 5


def test_zone_out_same_zone_is_no_inter_vlan_finding() -> None:
    det = FirewallInterVlanDetector()
    teach = line("lab", "in", "br-lan.8", src=LAN_HOST, dst=GW)
    same = line("lab", "forward", "br-lan.7", "br-lan.8")
    for rec in records(teach, *[same] * 6):
        det.feed(rec)
    result = evaluate(det)
    assert results_events((result,)) == []
    assert result.limitation is None and result.unattributed == 0


def test_zone_in_chain_with_empty_out_is_never_inter_vlan() -> None:
    """Chain "in" (target is the router itself, ``OUT=`` empty): no
    inter-VLAN line, so neither a finding nor an unattributed count."""
    det = FirewallInterVlanDetector()
    guest_in = line("guest", "in", "br-lan.5", dst=GW, icmp=True)
    for rec in records(*[guest_in] * 8):
        assert rec.fields["out_if"] is None
        det.feed(rec)
    result = evaluate(det)
    assert results_events((result,)) == [] and result.unattributed == 0
    # the line taught br-lan.5 -> guest: the detector can attribute now
    assert result.limitation is None


def test_zone_out_forward_without_out_interface_stays_unknown() -> None:
    det = FirewallInterVlanDetector()
    blank = line("lab", "forward", "br-lan.7", "")
    for rec in records(TEACH_LAN, *[blank] * 5):
        det.feed(rec)
    result = evaluate(det)
    assert results_events((result,)) == []
    assert result.limitation == DEST_ZONE_UNKNOWN and result.unattributed == 5


# --- order of the tiers -------------------------------------------------------------------


def test_zone_tier_configured_beats_learned() -> None:
    book = ZoneBook()
    book.set_configured(R1, {"br-lan.2": "office"})
    det = FirewallInterVlanDetector(zone_book=book)
    for rec in records(TEACH_LAN) + forwards(5):  # learns lan for br-lan.2
        det.feed(rec)
    assert book.zone_of(R1, "br-lan.2", RECV) == "office"
    (event,) = results_events((evaluate(det),))
    assert event.dst is not None and event.dst.zone == "office"


def test_zone_tier_forged_line_cannot_flip_a_configured_zone() -> None:
    book = ZoneBook()
    book.set_configured(R1, {"br-lan.7": "lab", "br-lan.2": "lan"})
    det = FirewallInterVlanDetector(zone_book=book)
    forged = line("lan", "in", "br-lan.7", dst=GW)  # UDP lines can be forged
    for rec in records(*[forged] * 20):
        det.feed(rec)
    assert book.zone_of(R1, "br-lan.7", RECV) == "lab"
    for rec in forwards(5):
        det.feed(rec)
    (event,) = results_events((evaluate(det),))
    assert (event.src.zone, event.dst.zone) == ("lab", "lan")  # type: ignore[union-attr]
    # a configured entry is never touched by learning
    assert book.stats()["configured"] == 2


def test_zone_tier_learned_beats_the_subnet_map() -> None:
    det = FirewallInterVlanDetector(dest_subnets={"192.0.2.0/27": "iot"})
    for rec in records(TEACH_LAN) + forwards(5):
        det.feed(rec)
    (event,) = results_events((evaluate(det),))
    assert event.dst is not None and event.dst.zone == "lan"


def test_zone_learn_conflict_is_unknown_never_a_majority() -> None:
    book = ZoneBook()
    det = FirewallInterVlanDetector(zone_book=book)
    forged = line("guest", "in", "br-lan.2", src=LAN_HOST, dst=GW)
    for rec in records(TEACH_LAN, *[forged] * 10):
        det.feed(rec)
    assert book.zone_of(R1, "br-lan.2", RECV) is None  # two zones: ambiguous
    assert book.stats()["conflicts"] >= 1
    for rec in forwards(5):
        det.feed(rec)
    result = evaluate(det)
    assert results_events((result,)) == []
    assert result.limitation == DEST_ZONE_UNKNOWN and result.unattributed == 5
    # once the other zone was not seen for the hold time, the one left counts
    later = RECV + ZONE_TTL_S + 60
    book.learn(R1, "br-lan.2", "lan", later)
    assert book.zone_of(R1, "br-lan.2", later) == "lan"


def test_zone_learn_only_from_in_and_forward() -> None:
    """The ``out`` chain is not seen on a real router: nothing learned."""
    book = ZoneBook()
    det = FirewallInterVlanDetector(zone_book=book)
    out_line = line("lan", "out", "", "br-lan.2", src=GW, verdict="reject")
    for rec in records(out_line):
        det.feed(rec)
    assert book.zone_of(R1, "br-lan.2", RECV) is None
    assert book.stats()["learned"] == 0


def test_zone_learn_is_bounded_per_router_and_per_router_count() -> None:
    book = ZoneBook(max_routers=1)
    for i in range(MAX_IFACES_PER_ROUTER + 10):
        book.learn(R1, f"br-x.{i}", "lan", RECV)
    stats = book.stats()
    assert stats["learned"] == MAX_IFACES_PER_ROUTER
    assert stats["refused"] == 10
    book.learn(R2, "br-lan.2", "lan", RECV)  # router table full
    assert book.zone_of(R2, "br-lan.2", RECV) is None
    assert book.stats()["refused"] == 11
    # bad names are not stored at all
    book.learn(R1, "x" * 40, "lan", RECV)
    book.learn(R1, "br-lan.99", "bad zone", RECV)
    assert book.stats()["learned"] == MAX_IFACES_PER_ROUTER
    # an expired entry makes room
    later = RECV + ZONE_TTL_S + 1
    book.learn(R1, "br-new.1", "iot", later)
    assert book.zone_of(R1, "br-new.1", later) == "iot"


def test_zone_book_outlives_a_detector_rebuild_but_not_forget() -> None:
    book = ZoneBook()
    first = default_detectors(zone_book=book)
    first.feed_records(records(TEACH_LAN))
    second = default_detectors(zone_book=book)  # settings changed
    inter = next(d for d in second.detectors if d.id == "fw_inter_vlan")
    assert inter.zones is book and book.zone_of(R1, "br-lan.2", RECV) == "lan"
    second.forget_router(R1)
    assert book.zone_of(R1, "br-lan.2", RECV) is None and book.size() == 0


# --- MITTEL: a private destination outside the map is unknown, not external ----------------


@pytest.mark.parametrize("dst", [PRIVATE_V4, PRIVATE_V6, "169.254.1.7", "fe80::7"])
def test_zone_map_private_destination_outside_the_map_is_unknown(dst: str) -> None:
    det = FirewallInterVlanDetector(dest_subnets={"192.0.2.0/27": "lan"})
    blank = line("lab", "forward", "br-lan.7", "", dst=dst)
    for rec in records(*[blank] * 5):
        det.feed(rec)
    result = evaluate(det)
    assert results_events((result,)) == []
    assert result.limitation == DEST_ZONE_UNKNOWN and result.unattributed == 5


def test_zone_map_public_destination_outside_the_map_is_external() -> None:
    det = FirewallInterVlanDetector(dest_subnets={"192.0.2.0/27": "lan"})
    blank = line("lab", "forward", "br-lan.7", "", dst=PUBLIC)
    for rec in records(*[blank] * 5):
        det.feed(rec)
    result = evaluate(det)
    assert results_events((result,)) == []
    assert result.limitation is None and result.unattributed == 0


# --- C: the format is confirmed: the panel mark goes for fw4 only --------------------------


async def test_fw4_conf_detections_mark_only_the_dns_formats(disks) -> None:  # noqa: F811
    center = await center_for(make_hass(), "r1", enabled=True)
    marks = {d["id"]: d["format_unconfirmed"] for d in center._detections()}
    fw = {k for k in marks if k.startswith("fw_")}
    dns = {k for k in marks if k.startswith("dns_")}
    assert fw == {"fw_blocked", "fw_port_scan_hint", "fw_mgmt_access", "fw_inter_vlan"}
    assert len(dns) == 4
    assert {k for k, v in marks.items() if v} == dns  # dnsmasq stays unconfirmed
    center.close()


# --- no router call ---------------------------------------------------------------------------


class _Lines:
    """A drained receiver: hands the parsed records to the center once."""

    def __init__(self, recs: list[Any], now: float) -> None:
        self._recs = recs
        self._now = now

    def drain(self, _max: int) -> list[Any]:
        out, self._recs = self._recs, []
        return out

    def now(self) -> float:
        return self._now


async def test_zone_norc_learning_and_attribution_make_no_router_call(
    core_disks,  # noqa: F811
    tmp_path,
) -> None:
    env = await cm_env(
        core_disks, tmp_path, options=NO_SCHEDULE, provider=AreaProvider()
    )
    center = await _core_center(env, FakeDisk())
    assert center.active
    calls0 = len(env.router_calls())
    provider0 = len(env.provider.calls)
    now = env.clock.utc().timestamp()
    recs = [
        replace(rec, ts=now, recv=now)
        for rec in records(TEACH_LAN, *forward_lines(6), router=env.rid)
    ]
    center._drain_from(_Lines(recs, now))
    assert center.zones.zone_of(env.rid, "br-lan.2", now) == "lan"
    # The source status of the test env is not "available" (no syslog
    # path), so the detectors of the center are evaluated as on a delivering
    # router; the center's own evaluate stage runs too.
    center._evaluate(now)
    (result,) = (
        r
        for r in center.detectors.evaluate(now, statuses(env.rid, now=now))
        if r.detector_id == "fw_inter_vlan"
    )
    assert result.limitation is None and len(result.events) == 1
    await env.tick()
    assert len(env.router_calls()) == calls0 == 0
    assert len(env.provider.calls) == provider0  # no capture, no compare
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)
