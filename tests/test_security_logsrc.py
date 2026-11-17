"""Tests for security_logsrc.py: record format v1, dedup, high-water mark,
liveness and the "off" source (plan 2026-11-17 security center, 4.2-4.4).

Placeholders only: RFC 5737 addresses, 02:00:00 MACs, example.org.
"""

from __future__ import annotations

from types import MappingProxyType

import pytest

from custom_components.openwrt_router.security_logsrc import (
    KIND_SOURCES,
    PATH_OFF,
    SCHEMA_VERSION,
    Deduper,
    KeyAssigner,
    Liveness,
    LogSource,
    NullLogSource,
    SecLogRecord,
    SourceStats,
    make_key,
    safe_text,
    second_token,
)
from custom_components.openwrt_router.security_model import (
    Availability,
    DataSource,
    LogPath,
    SourceStatus,
)

T0 = 1_795_000_000.0  # 2026-11-18, epoch seconds
FAIL = "Bad password attempt for 'root' from 198.51.100.23:51515"


def _rec(
    assigner: KeyAssigner,
    router: str,
    ts: float,
    msg: str,
    *,
    recv: float | None = None,
    kind: str | None = "auth.ssh_failed",
    path: str = LogPath.SYSLOG.value,
) -> SecLogRecord:
    second = second_token(ts, estimated=False, local_wall=None)
    return SecLogRecord(
        router=router,
        ts=ts,
        recv=ts + 0.2 if recv is None else recv,
        path=path,
        pri=85,
        proc="dropbear",
        pid=3001,
        msg=msg,
        kind=kind,
        fields={"src": "198.51.100.23"},
        key=assigner.assign(router, second, "dropbear", msg),
    )


def _stream(router, start, count, *, prefix="line", recv_delay=0.2, assigner=None):
    """``count`` distinct lines, one per second from ``start``."""
    assigner = assigner or KeyAssigner()
    return [
        _rec(assigner, router, start + i, f"{prefix} {i}", recv=start + i + recv_delay)
        for i in range(count)
    ]


def _feed(deduper, records, batch=50):
    out = []
    for i in range(0, len(records), batch):
        chunk = records[i : i + batch]
        out += deduper.filter(chunk, now=max(r.recv for r in chunk))
    return out


# =====================================================================
# Record format
# =====================================================================


class TestRecord:
    def test_fields_are_read_only(self):
        rec = _rec(KeyAssigner(), "r1", T0, FAIL)
        assert isinstance(rec.fields, MappingProxyType)
        with pytest.raises(TypeError):
            rec.fields["x"] = 1  # type: ignore[index]

    def test_round_trip(self):
        rec = _rec(KeyAssigner(), "r1", T0, FAIL)
        assert SecLogRecord.from_dict(rec.to_dict()) == rec
        assert rec.to_dict()["v"] == SCHEMA_VERSION == 1

    def test_unknown_fields_and_higher_minor_are_accepted(self):
        data = _rec(KeyAssigner(), "r1", T0, FAIL).to_dict()
        data.update({"v": "1.4", "sender": "x", "future": {"a": 1}})
        data["fields"] = {**data["fields"], "new_field": "x", "Bad Key": 1}
        rec = SecLogRecord.from_dict(data)
        assert rec is not None
        assert rec.fields["new_field"] == "x"
        assert "Bad Key" not in rec.fields
        assert SecLogRecord.from_dict({**data, "v": 1.2}) is not None

    @pytest.mark.parametrize(
        "patch",
        [
            {"v": 2},
            {"v": "2.0"},
            {"v": None},
            {"v": True},
            {"router": ""},
            {"router": 5},
            {"ts": "1"},
            {"ts": float("nan")},
            {"recv": None},
            {"key": "zz"},
            {"key": None},
        ],
    )
    def test_unusable_dicts_give_none(self, patch):
        data = {**_rec(KeyAssigner(), "r1", T0, FAIL).to_dict(), **patch}
        assert SecLogRecord.from_dict(data) is None

    @pytest.mark.parametrize("data", [None, [], "x", 5, {}])
    def test_non_mappings_give_none(self, data):
        assert SecLogRecord.from_dict(data) is None

    def test_from_dict_cleans_and_caps_again(self):
        data = _rec(KeyAssigner(), "r1", T0, FAIL).to_dict()
        data["msg"] = "evil\n<13>Nov 17 12:00:00 fake\x1b[31m" + "x" * 2000
        data["proc"] = "drop\x00bear"
        data["kind"] = "NOT A KIND"
        data["pri"] = 999
        data["fields"] = {f"f{i}": "y" * 1000 for i in range(100)}
        rec = SecLogRecord.from_dict(data)
        assert "\n" not in rec.msg and "\x1b" not in rec.msg and "[31m" not in rec.msg
        assert len(rec.msg) <= 512
        assert rec.proc == "dropbear"
        assert rec.kind is None and rec.pri is None
        assert len(rec.fields) <= 32
        assert all(len(v) <= 255 for v in rec.fields.values())

    def test_repr_hides_message_and_fields(self):
        text = repr(_rec(KeyAssigner(), "r1", T0, FAIL))
        assert "198.51.100.23" not in text and "root" not in text

    def test_satisfies_detector_protocol_shape(self):
        rec = _rec(KeyAssigner(), "r1", T0, FAIL)
        assert (rec.router, rec.ts, rec.kind) == ("r1", T0, "auth.ssh_failed")
        assert rec.fields.get("src") == "198.51.100.23"

    def test_safe_text_removes_ansi_and_controls(self):
        assert safe_text("a\x1b[1;31mred\x1b[0m\tb\u202ec", 50) == "aredbc"


# =====================================================================
# Keys
# =====================================================================


class TestKeys:
    def test_identical_lines_in_one_second_get_distinct_keys(self):
        assigner = KeyAssigner()
        keys = [assigner.assign("r1", "100", "dropbear", FAIL) for _ in range(3)]
        assert len(set(keys)) == 3
        assert [k.split(":")[1] for k in keys] == ["0", "1", "2"]

    def test_index_restarts_with_the_next_second(self):
        assigner = KeyAssigner()
        assigner.assign("r1", "100", "p", "m")
        assert assigner.assign("r1", "101", "p", "m").endswith(":0")

    def test_router_is_part_of_the_key(self):
        assert make_key("r1", "100", "p", "m") != make_key("r2", "100", "p", "m")

    def test_new_stream_reproduces_the_same_keys(self):
        first, second = KeyAssigner(), KeyAssigner()
        a = [first.assign("r1", "100", "p", "m") for _ in range(2)]
        b = [second.assign("r1", "100", "p", "m") for _ in range(2)]
        assert a == b

    def test_estimated_time_uses_router_wall_clock(self):
        assert second_token(5.7, estimated=False, local_wall=None) == "5"
        assert second_token(999.0, estimated=True, local_wall=42) == "L42"


# =====================================================================
# Deduper
# =====================================================================


class TestDeduper:
    def test_same_line_from_two_routers_stays_two_records(self):
        assigner = KeyAssigner()
        a = _rec(assigner, "router-a", T0, FAIL)
        b = _rec(assigner, "router-b", T0, FAIL)
        out = Deduper().filter([a, b], now=T0 + 1)
        assert out == [a, b]

    def test_mark_of_router_a_never_drops_router_b(self):
        deduper = Deduper()
        assigner = KeyAssigner()
        deduper.filter([_rec(assigner, "router-a", T0 + 86_400, "late")], now=T0 + 1)
        early = _stream("router-b", T0, 5, assigner=assigner)
        assert deduper.filter(early, now=T0 + 10) == early
        assert deduper.hwm("router-a") == T0 + 86_400
        assert deduper.hwm("router-b") == T0 + 4

    def test_identical_lines_in_one_second_do_not_merge(self):
        assigner = KeyAssigner()
        recs = [_rec(assigner, "r1", T0, FAIL) for _ in range(3)]
        assert Deduper().filter(recs, now=T0 + 1) == recs

    def test_exact_repeat_is_dropped(self):
        deduper = Deduper()
        rec = _rec(KeyAssigner(), "r1", T0, FAIL)
        assert deduper.filter([rec], now=T0 + 1) == [rec]
        assert deduper.filter([rec], now=T0 + 2) == []
        assert deduper.stats().dup_key == 1

    def test_path_switch_mid_stream_has_no_duplicates(self):
        """Path A delivers 0..49, path B re-sends 40..49 and goes on to 59."""
        deduper = Deduper()
        path_a = _stream("r1", T0, 50)
        out = _feed(deduper, path_a)
        assigner_b = KeyAssigner()
        path_b = [
            _rec(
                assigner_b,
                "r1",
                T0 + i,
                f"line {i}",
                recv=T0 + 60 + i * 0.01,
                path=LogPath.COLLECTOR.value,
            )
            for i in range(40, 60)
        ]
        out += deduper.filter(path_b, now=T0 + 61)
        assert [r.msg for r in out] == [f"line {i}" for i in range(60)]

    def test_path_switch_keeps_second_identical_line_lost_by_old_path(self):
        """A delivered only the first of two identical lines; B sends both."""
        deduper = Deduper()
        assigner_a = KeyAssigner()
        out = deduper.filter([_rec(assigner_a, "r1", T0, FAIL)], now=T0 + 1)
        assigner_b = KeyAssigner()
        resend = [
            _rec(assigner_b, "r1", T0, FAIL, recv=T0 + 5, path="collector")
            for _ in range(2)
        ]
        out += deduper.filter(resend, now=T0 + 5)
        assert len(out) == 2
        assert {r.key for r in out} == {resend[0].key, resend[1].key}

    def test_case19_log_rotation(self):
        """Re-sent log ring, a router reboot with the clock going back and a
        second re-send: no record twice, no new line lost."""
        deduper = Deduper()
        router = "r1"
        # 1000 s of live log, one line per second
        live = _stream(router, T0, 1000)
        accepted = _feed(deduper, live)
        assert len(accepted) == 1000
        # logread restarts and re-sends the whole ring in one burst (the
        # first ~400 lines are older than the 10 min key window), then new
        # lines follow.
        replay_assigner = KeyAssigner()
        burst_at = T0 + 1100
        replay = [
            _rec(replay_assigner, router, T0 + i, f"line {i}", recv=burst_at + i * 1e-3)
            for i in range(1000)
        ]
        fresh = [
            _rec(
                replay_assigner,
                router,
                T0 + 1100 + i,
                f"new {i}",
                recv=burst_at + 2 + i,
            )
            for i in range(10)
        ]
        out = _feed(deduper, replay + fresh)
        assert [r.msg for r in out] == [f"new {i}" for i in range(10)]
        assert deduper.stats().dup_old > 0
        # Router reboot: the clock starts three days behind (sysfixtime),
        # logread sends the boot burst, live lines follow, then NTP fixes it.
        boot = KeyAssigner()
        behind = T0 - 3 * 86_400
        up = T0 + 1200
        boot_lines = [
            _rec(boot, router, behind + i, f"boot {i}", recv=up + i * 1e-3)
            for i in range(20)
        ]
        boot_lines += [
            _rec(boot, router, behind + 20 + i, f"boot {20 + i}", recv=up + 20 + i)
            for i in range(20)
        ]
        after_ntp = [
            _rec(boot, router, up + 45 + i, f"ntp {i}", recv=up + 45 + i)
            for i in range(5)
        ]
        out = _feed(deduper, boot_lines + after_ntp, batch=7)
        msgs = [r.msg for r in out]
        expected = [f"boot {i}" for i in range(40)] + [f"ntp {i}" for i in range(5)]
        assert sorted(msgs) == sorted(expected)
        assert len(msgs) == len(set(msgs))
        # logread restarts again after the reboot: everything re-sent is old
        again = KeyAssigner()
        resend = [
            _rec(again, r.router, r.ts, r.msg, recv=up + 100 + n * 1e-3)
            for n, r in enumerate(boot_lines + after_ntp)
        ]
        assert _feed(deduper, resend) == []

    def test_reboot_without_ntp_starts_new_epoch_after_hold(self):
        deduper = Deduper(hold_s=60)
        assigner = KeyAssigner()
        deduper.filter([_rec(assigner, "r1", T0, "before")], now=T0 + 1)
        behind = T0 - 86_400
        lines = [
            _rec(assigner, "r1", behind + i, f"after {i}", recv=T0 + 10 + i)
            for i in range(30)
        ]
        assert deduper.filter(lines, now=T0 + 40) == []  # held, undecided
        released = deduper.flush(now=T0 + 80)
        assert [r.msg for r in released] == [f"after {i}" for i in range(30)]
        assert deduper.hwm("r1") == behind + 29
        nxt = _rec(assigner, "r1", behind + 100, "later", recv=T0 + 110)
        assert deduper.filter([nxt], now=T0 + 110) == [nxt]
        assert deduper.stats().epoch_resets == 1

    def test_restart_with_stored_mark_drops_resent_ring(self):
        deduper = Deduper()
        _feed(deduper, _stream("r1", T0, 900))
        restored = Deduper.from_dict(deduper.to_dict())
        assert restored.hwm("r1") == T0 + 899
        replay = _stream("r1", T0, 900, recv_delay=0)
        replay = [
            SecLogRecord.from_dict({**r.to_dict(), "recv": T0 + 1000 + n * 1e-3})
            for n, r in enumerate(replay)
        ]
        fresh = _stream("r1", T0 + 1001, 3, prefix="fresh", recv_delay=0.5)
        out = _feed(restored, replay + fresh)
        # only the boundary second (hwm - grace) may pass again, plus new lines
        assert [r.msg for r in out if r.msg.startswith("fresh")] == [
            "fresh 0",
            "fresh 1",
            "fresh 2",
        ]
        assert len(out) <= 3 + 2

    @pytest.mark.parametrize(
        "data",
        [None, [], {"v": 2, "hwm": {"r1": 5.0}}, {"v": 1, "hwm": "x"}],
    )
    def test_from_dict_tolerates_bad_data(self, data):
        assert Deduper.from_dict(data).footprint()["routers"] == 0

    def test_from_dict_skips_bad_entries(self):
        restored = Deduper.from_dict(
            {"v": 1, "hwm": {"r1": 5.0, "r2": "x", "": 3.0, "r3": None}, "x": 1}
        )
        assert restored.hwm("r1") == 5.0
        assert restored.footprint()["routers"] == 1

    def test_key_set_is_bounded(self):
        deduper = Deduper(max_keys=100)
        _feed(deduper, _stream("r1", T0, 500))
        assert deduper.footprint()["keys"] == 100

    def test_hold_buffer_is_bounded(self):
        deduper = Deduper(max_held=10)
        assigner = KeyAssigner()
        deduper.filter([_rec(assigner, "r1", T0, "x")], now=T0)
        old = [
            _rec(assigner, "r1", T0 - 1000 - i, f"o{i}", recv=T0 + 1) for i in range(50)
        ]
        deduper.filter(old, now=T0 + 1)
        assert deduper.footprint()["held"] == 10
        assert deduper.stats().held_overflow == 40

    def test_router_cap_passes_records_untouched(self):
        deduper = Deduper(max_routers=1)
        assigner = KeyAssigner()
        recs = [_rec(assigner, "a", T0, FAIL), _rec(assigner, "b", T0, FAIL)]
        assert deduper.filter(recs, now=T0) == recs
        assert deduper.stats().untracked == 1


# =====================================================================
# Liveness and the "off" source
# =====================================================================


class TestLiveness:
    def test_case07_missing_dns_logs_not_available(self):
        live = Liveness()
        assigner = KeyAssigner()
        live.observe([_rec(assigner, "r1", T0, "fw line", kind="fw.drop")])
        dns = live.status("r1", DataSource.DNS_QUERY_LOG, now=T0 + 5)
        assert isinstance(dns, SourceStatus)
        assert dns.availability is Availability.NOT_AVAILABLE
        assert not dns.usable
        fw = live.status("r1", DataSource.FIREWALL_LOG, now=T0 + 5)
        assert fw.availability is Availability.AVAILABLE
        statuses = live.statuses("r1", now=T0 + 5)
        assert statuses[DataSource.DNS_QUERY_LOG].availability is not (
            Availability.AVAILABLE
        )
        # an unknown router is never "fine"
        assert (
            live.status("other", DataSource.DNS_QUERY_LOG, now=T0).availability
            is Availability.NOT_AVAILABLE
        )

    def test_stale_after_fifteen_minutes(self):
        live = Liveness()
        live.observe([_rec(KeyAssigner(), "r1", T0, "q", kind="dns.query")])
        assert (
            live.status("r1", DataSource.DNS_QUERY_LOG, now=T0 + 899).availability
            is Availability.AVAILABLE
        )
        assert (
            live.status("r1", DataSource.DNS_QUERY_LOG, now=T0 + 901).availability
            is Availability.STALE
        )

    def test_path_capability_is_tracked(self):
        live = Liveness()
        live.observe([_rec(KeyAssigner(), "r1", T0, "x", kind=None)])
        assert live.last_ok("r1", "security.center.log_path.syslog") == T0 + 0.2
        assert live.last_ok("r1", DataSource.FIREWALL_LOG) is None

    def test_disabled_path_is_not_available(self):
        live = Liveness()
        live.observe([_rec(KeyAssigner(), "r1", T0, "x", kind="fw.drop")])
        status = live.status("r1", DataSource.FIREWALL_LOG, now=T0, enabled=False)
        assert status.availability is Availability.NOT_AVAILABLE

    def test_kind_sources_cover_detector_kinds(self):
        assert KIND_SOURCES["fw.drop"] == DataSource.FIREWALL_LOG
        assert KIND_SOURCES["fw.reject"] == DataSource.FIREWALL_LOG
        assert KIND_SOURCES["dns.query"] == DataSource.DNS_QUERY_LOG


class TestNullSource:
    async def test_off_delivers_nothing(self):
        source = NullLogSource()
        assert isinstance(source, LogSource)
        assert source.name == PATH_OFF
        await source.async_start()
        assert source.drain(100) == []
        await source.async_stop()
        assert source.stats() == SourceStats()
        status = source.status(DataSource.FIREWALL_LOG, now=T0)
        assert status.availability is Availability.NOT_AVAILABLE

    def test_source_stats_hold_counters_only(self):
        stats = SourceStats.from_counts(
            {"received": 3, "parsed": 2, "router": "r1", "invalid": True, "x": 1}
        )
        data = stats.to_dict()
        assert data["received"] == 3 and data["parsed"] == 2 and data["invalid"] == 0
        assert all(isinstance(v, int) for v in data.values())
        assert "router" not in data and "x" not in data
