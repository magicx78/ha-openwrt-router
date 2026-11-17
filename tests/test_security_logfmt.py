"""Tests for security_logfmt.py: logd remote head, time, framing, caps,
injection, fw4 / dnsmasq / dropbear message parts and the hand-over to the
detectors (plan 2026-11-17 security center, 4.2-4.4, 4.9).

Fixtures: tests/fixtures/security/ (README.md there names the evidence).
Placeholders only: RFC 5737 addresses, 02:00:00 MACs, example.org.
"""

from __future__ import annotations

import logging
import random
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path

import pytest

from custom_components.openwrt_router.security_logfmt import (
    FORMAT_CONFIRMED,
    OUTCOME_INVALID,
    OUTCOME_PARSED,
    OUTCOME_UNPARSED,
    StreamSplitter,
    parse_dnsmasq_query,
    parse_dropbear,
    parse_fw4,
    parse_message,
    parse_remote_header,
    parse_remote_line,
    resolve_time,
)
from custom_components.openwrt_router.security_logsrc import (
    MAX_LINE_BYTES,
    MAX_MSG_CHARS,
    Deduper,
    KeyAssigner,
    Liveness,
    SourceStats,
)
from custom_components.openwrt_router.security_model import (
    Availability,
    DataSource,
    LogPath,
    SourceStatus,
)
from custom_components.openwrt_router.security_rules import (
    DetectorSet,
    DnsManyDomainsDetector,
    FirewallMgmtAccessDetector,
    FirewallPortScanDetector,
    default_detectors,
)

FIXTURES = Path(__file__).parent / "fixtures" / "security"
RECV = datetime(2026, 11, 17, 12, 0, 30, tzinfo=UTC).timestamp()
HEAD = "<4>Nov 17 12:00:10 ap-test "
IDENTIFIERS = (
    "02:00:00",
    "192.0.2.",
    "198.51.100.",
    "203.0.113.",
    "2001:db8",
    "example.org",
    "example.com",
    "ap-test",
)


def _lines(name: str) -> list[str]:
    text = (FIXTURES / name).read_text("utf-8")
    return [line for line in text.splitlines() if line and not line.startswith("#")]


def _parse(data, *, offset=0, assigner=None, router="r1", recv=RECV, **kw):
    return parse_remote_line(
        data,
        router=router,
        path=LogPath.SYSLOG.value,
        recv=recv,
        tz_offset_s=offset,
        assigner=assigner or KeyAssigner(),
        **kw,
    )


def _record(message: str, **kw):
    result = _parse(HEAD + message, **kw)
    assert result.record is not None
    return result.record


# =====================================================================
# Fixtures end to end
# =====================================================================


class TestFixtures:
    def test_udp_datagrams(self):
        results = [_parse(line.encode()) for line in _lines("logd_remote_udp.txt")]
        kinds = [r.record.kind for r in results]
        assert kinds == [
            "wifi.connected",
            "wifi.psk_mismatch",
            "dhcp.ack",
            "auth.ssh_ok",
            None,
        ]
        assert [r.outcome for r in results] == [OUTCOME_PARSED] * 4 + [OUTCOME_UNPARSED]
        # message parts seen live: no "unconfirmed" marker
        assert not any(r.record.unconfirmed for r in results)
        first = results[0].record
        assert (first.proc, first.pid, first.pri) == ("hostapd", None, 30)
        assert first.fields["mac"] == "02:00:00:00:00:01".upper()
        dhcp = results[2].record
        assert (dhcp.proc, dhcp.pid) == ("dnsmasq-dhcp", 1234)
        assert dhcp.fields["ip"] == "192.0.2.10"

    def test_tcp_stream_with_newline_and_nul(self):
        data = (FIXTURES / "logd_remote_tcp.bin").read_bytes()
        assert b"\n" in data and b"\x00" in data
        splitter = StreamSplitter()
        lines = []
        for i in range(0, len(data), 37):  # arbitrary chunk borders
            lines += splitter.feed(data[i : i + 37])
        lines += splitter.flush()
        assert [line.data.decode() for line in lines] == _lines("logd_remote_udp.txt")
        assert not any(line.truncated for line in lines)
        results = [_parse(line.data, truncated=line.truncated) for line in lines]
        assert all(r.record is not None for r in results)

    def test_fw4_lines(self):
        recs = [_record(line) for line in _lines("fw4_kernel.txt")]
        assert [r.kind for r in recs] == [
            "fw.drop",
            "fw.reject",
            "fw.reject",
            "fw.drop",
            "fw.accept",
        ]
        first = recs[0].fields
        assert first["zone"] == "wan" and first["dir"] == "in"
        assert first["src"] == "198.51.100.7" and first["dst"] == "203.0.113.2"
        assert first["proto"] == "tcp"
        assert first["dpt"] == 22 and first["spt"] == 40000
        assert isinstance(first["dpt"], int)
        assert first["in_if"] == "wan" and first["out_if"] is None
        assert first["dest_zone"] is None
        fwd = recs[2].fields
        assert fwd["dir"] == "forward" and fwd["zone"] == "iot"
        assert fwd["proto"] == "icmp" and fwd["dpt"] is None
        assert recs[3].fields["src"] == "2001:db8::7"
        assert all(r.unconfirmed and r.fields["fmt"] == "fw4_nflog" for r in recs)
        assert all(r.proc == "kernel" for r in recs)

    def test_dnsmasq_lines(self):
        recs = [_record(line) for line in _lines("dnsmasq_query.txt")]
        assert [r.kind for r in recs] == [
            "dns.query",
            None,  # forwarded: not a query or answer
            "dns.reply",
            "dns.query",
            "dns.reply",
            "dns.reply",
            "dns.query",
        ]
        query = recs[0].fields
        assert query["client"] == "192.0.2.10"
        assert query["name"] == "www.example.org"
        assert query["rcode"] is None and query["qtype"] == "A" and query["qid"] == 41
        assert recs[2].fields["rcode"] == "NOERROR"
        nx = recs[4].fields
        assert nx["rcode"] == "NXDOMAIN" and nx["client"] == "192.0.2.11"
        assert recs[5].fields["rcode"] == "NODATA"
        assert recs[6].fields["client"] == "192.0.2.12"
        assert recs[6].fields["qid"] is None
        assert all(r.unconfirmed for r in recs if r.kind)

    def test_dropbear_lines(self):
        fail = [_record(line) for line in _lines("dropbear_fail.txt")]
        assert [r.kind for r in fail] == ["auth.ssh_failed"] * 3
        assert fail[0].fields["user"] == "root"
        assert fail[0].fields["src"] == "198.51.100.23"
        assert fail[0].fields["spt"] == 51515
        assert fail[0].fields["reason"] == "bad_password"
        assert fail[1].fields["user"] is None
        assert fail[1].fields["reason"] == "unknown_user"
        assert fail[2].fields["user"] == "admin"
        assert fail[2].fields["src"] == "2001:db8::24"
        assert all(r.unconfirmed for r in fail)
        ok = [_record(line) for line in _lines("dropbear_ok.txt")]
        assert [r.kind for r in ok] == ["auth.ssh_ok"] * 2
        assert ok[0].fields["method"] == "password" and not ok[0].unconfirmed
        assert ok[1].fields["method"] == "pubkey" and ok[1].unconfirmed

    def test_confirmation_table(self):
        unconfirmed = {k for k, v in FORMAT_CONFIRMED.items() if not v}
        assert unconfirmed == {
            "fw4_nflog",
            "dnsmasq_query",
            "dnsmasq_reply",
            "dropbear_bad_password",
            "dropbear_unknown_user",
            "dropbear_pubkey_ok",
        }


# =====================================================================
# Head
# =====================================================================


class TestHeader:
    @pytest.mark.parametrize(
        ("line", "day"),
        [
            ("<30>Nov  7 08:15:42 h procd: x", 7),
            ("<30>Nov 17 08:15:42 h procd: x", 17),
            ("<30>Nov 7 08:15:42 h procd: x", 7),
        ],
    )
    def test_both_day_forms(self, line, day):
        head = parse_remote_header(line)
        assert head.day == day and head.month == 11
        assert (head.hour, head.minute, head.second) == (8, 15, 42)

    def test_priority_split(self):
        head = parse_remote_header("<85>Nov 17 12:00:00 h dropbear[1]: x")
        assert (head.facility, head.severity) == (10, 5)

    def test_without_host(self):
        head = parse_remote_header("<30>Nov 17 12:00:00 dropbear[7]: hello")
        assert head.host is None and head.proc == "dropbear" and head.pid == 7

    def test_kernel_and_prefix(self):
        head = parse_remote_header("<4>Nov 17 12:00:00 h myprefix: kernel: [1.5] x")
        assert head.proc == "kernel" and head.msg == "[1.5] x"
        head = parse_remote_header("<4>Nov 17 12:00:00 h pre: dropbear[1]: x")
        assert head.proc == "dropbear"
        head = parse_remote_header("<4>Nov 17 12:00:00 h pre: hostapd: x", prefix="pre")
        assert head.proc == "hostapd" and head.msg == "x"

    def test_hostapd_interface_is_no_prefix(self):
        head = parse_remote_header("<30>Nov 17 12:00:00 h hostapd: phy0-ap1: AP-X")
        assert head.proc == "hostapd" and head.msg == "phy0-ap1: AP-X"

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "no head at all",
            "<192>Nov 17 12:00:00 h p: x",
            "<30>Foo 17 12:00:00 h p: x",
            "<30>Nov 32 12:00:00 h p: x",
            "<30>Nov 17 24:00:00 h p: x",
            "<30>Nov 17 12:60:00 h p: x",
            "<30>Nov 17 12:00 h p: x",
            "<3000>Nov 17 12:00:00 h p: x",
        ],
    )
    def test_invalid_heads(self, line):
        assert parse_remote_header(line) is None
        assert _parse(line).outcome == OUTCOME_INVALID

    def test_unknown_message_is_kept_and_counted(self):
        result = _parse("<30>Nov 17 12:00:00 h crond[5]: USER root pid 9 cmd x")
        assert result.outcome == OUTCOME_UNPARSED
        assert result.record.kind is None and result.record.proc == "crond"


# =====================================================================
# Time
# =====================================================================


def _utc(*args) -> float:
    return datetime(*args, tzinfo=UTC).timestamp()


class TestTime:
    def test_offset_is_applied(self):
        rec = _parse("<30>Nov 17 13:00:10 h p: x", offset=3600).record
        assert rec.ts == _utc(2026, 11, 17, 12, 0, 10)
        assert "ts_estimated" not in rec.fields

    def test_december_line_received_in_january(self):
        recv = _utc(2027, 1, 1, 0, 0, 5)
        rec = _parse("<30>Dec 31 23:59:58 h p: x", recv=recv).record
        assert rec.ts == _utc(2026, 12, 31, 23, 59, 58)

    def test_december_line_with_zone_offset_across_new_year(self):
        recv = _utc(2026, 12, 31, 23, 30, 0)  # router (UTC+1) is past midnight
        rec = _parse("<30>Jan  1 00:29:59 h p: x", recv=recv, offset=3600).record
        assert rec.ts == _utc(2026, 12, 31, 23, 29, 59)

    def test_january_line_received_in_december(self):
        recv = _utc(2026, 12, 31, 23, 59, 59)  # router clock slightly ahead
        rec = _parse("<30>Jan  1 00:00:01 h p: x", recv=recv).record
        assert rec.ts == _utc(2027, 1, 1, 0, 0, 1)

    @pytest.mark.parametrize("offset", [None, "3600", True, 15 * 3600, float("nan")])
    def test_missing_offset_estimates_time(self, offset):
        result = _parse("<30>Nov 17 08:00:00 h p: x", offset=offset)
        assert result.record.ts == RECV
        assert result.ts_estimated
        assert result.record.fields["ts_estimated"] is True

    def test_estimated_records_keep_the_same_key_on_resend(self):
        line = "<85>Nov 17 08:00:00 h dropbear[1]: x"
        first = _parse(line, offset=None, recv=RECV).record
        later = _parse(line, offset=None, recv=RECV + 3600).record
        assert first.key == later.key

    def test_impossible_date_is_invalid(self):
        head = parse_remote_header("<30>Feb 30 12:00:00 h p: x")
        assert resolve_time(head, RECV, 0) is None
        assert _parse("<30>Feb 30 12:00:00 h p: x").outcome == OUTCOME_INVALID

    @pytest.mark.parametrize("recv", [0.0, float("inf"), float("nan"), True, "1"])
    def test_bad_receive_time_is_invalid(self, recv):
        assert _parse(HEAD + "p: x", recv=recv).outcome == OUTCOME_INVALID


# =====================================================================
# Caps, framing and injection
# =====================================================================


class TestCapsAndInjection:
    def test_overlong_datagram_is_cut_and_marked(self):
        data = (HEAD + "dropbear[1]: " + "x" * 5000).encode()
        assert len(data) > MAX_LINE_BYTES
        result = _parse(data)
        assert result.truncated and result.record.fields["truncated"] is True
        assert len(result.record.msg) <= MAX_MSG_CHARS

    def test_long_message_is_capped(self):
        rec = _parse(HEAD + "dropbear[1]: " + "y" * 1000).record
        assert len(rec.msg) == MAX_MSG_CHARS and rec.fields["truncated"] is True

    def test_invalid_utf8_is_tolerated(self):
        result = _parse(HEAD.encode() + b"dropbear[1]: bad \xff\xfe\xc3 bytes")
        assert result.record is not None and "bad" in result.record.msg

    def test_trailers_are_ignored(self):
        for trailer in (b"\n", b"\x00", b"\r\n"):
            rec = _parse((HEAD + "procd: x").encode() + trailer).record
            assert rec.msg == "x"

    def test_embedded_newline_and_head_stay_one_record(self):
        forged = (
            HEAD
            + "dropbear[1]: Bad password attempt for 'x\n<85>Nov 17 12:00:11 ap-test "
            "dropbear[1]: Password auth succeeded for 'root' from 192.0.2.5:1' "
            "from 198.51.100.9:2"
        )
        result = _parse(forged.encode())
        rec = result.record
        assert rec.kind == "auth.ssh_failed"
        assert rec.fields["src"] == "198.51.100.9"
        assert "\n" not in rec.msg

    def test_control_and_ansi_sequences_are_removed(self):
        rec = _parse(HEAD + "procd: a\x1b[31mred\x1b[0m\x07b\x0bc\u202ed\x00e").record
        assert rec.msg == "aredbcde"
        assert all(ch.isprintable() for ch in rec.msg)

    def test_stream_overlong_line_is_bounded(self):
        splitter = StreamSplitter(max_line=100)
        out = splitter.feed(b"a" * 150)
        assert out[0].truncated and len(out[0].data) == 100
        assert splitter.feed(b"b" * 10_000) == []  # rest of the long line
        out = splitter.feed(b"c\nnext\x00")
        assert [line.data for line in out] == [b"next"]
        assert splitter.feed(b"x" * 50) == [] and splitter.flush()[0].data == b"x" * 50

    def test_stream_long_line_within_one_chunk(self):
        splitter = StreamSplitter(max_line=10)
        out = splitter.feed(b"0123456789abc\nok\n\n\x00")
        assert [(line.data, line.truncated) for line in out] == [
            (b"0123456789", True),
            (b"ok", False),
        ]

    def test_parsers_never_raise_on_random_bytes(self):
        rng = random.Random(1234)
        assigner = KeyAssigner()
        for _ in range(3000):
            size = rng.randint(0, 300)
            junk = bytes(rng.randrange(256) for _ in range(size))
            if rng.random() < 0.5:
                junk = HEAD.encode() + junk
            result = _parse(junk, assigner=assigner)
            assert result.outcome in (OUTCOME_PARSED, OUTCOME_UNPARSED, OUTCOME_INVALID)

    @pytest.mark.parametrize(
        "line",
        [
            "<1>" + "Nov" + " " * 3000,
            HEAD + "kernel: [" + " " * 2000,
            HEAD + "kernel: drop wan in: " + "SRC=" * 600,
            HEAD + "kernel: drop wan in: " + "IN=" + "a" * 2000,
            HEAD + "dnsmasq[1]: 1 " + "a/" * 1000,
            HEAD + "dnsmasq[1]: query[" + "A" * 2000,
            HEAD + "dropbear[1]: Bad password attempt for '" + " from " * 400,
            HEAD + "dropbear[1]: Login attempt for nonexistent user '" + "'" * 2000,
            HEAD + "a" * 63 + "[" + "1" * 2000,
            HEAD + "hostapd: " + "phy0: " * 400,
            HEAD + "\x1b[" + "0" * 2000,
        ],
    )
    def test_pathological_input_is_fast(self, line):
        start = time.perf_counter()
        for _ in range(20):
            _parse(line.encode())
        assert time.perf_counter() - start < 1.0


# =====================================================================
# Message parsers directly
# =====================================================================


class TestMessageParsers:
    def test_fw4_without_addresses_is_unknown(self):
        assert parse_fw4("drop wan in: IN=wan OUT= PROTO=TCP") is None
        assert parse_fw4("something else SRC=192.0.2.1 DST=192.0.2.2") is None

    def test_fw4_bad_values_become_none(self):
        kind, fields = parse_fw4(
            "DROP lan in: IN=br-lan SRC=192.0.2.1 DST=192.0.2.2 DPT=99999 SPT=x"
        )
        assert kind == "fw.drop"
        assert fields["dpt"] is None and fields["spt"] is None

    def test_fw4_rejects_bad_addresses(self):
        assert parse_fw4("drop wan in: SRC=999.1.1.1 DST=192.0.2.2") is None

    def test_dns_rejects_odd_lines(self):
        assert parse_dnsmasq_query("query[A] from") is None
        assert parse_dnsmasq_query("using nameserver 192.0.2.1#53") is None

    def test_dropbear_needs_from(self):
        assert parse_dropbear("Bad password attempt for 'root'") is None
        assert parse_dropbear("Child connection from 192.0.2.10:50000") is None

    def test_other_processes_reuse_log_parser(self):
        kind, fields = parse_message("netifd", "Interface 'wan' is now up")
        assert kind == "iface.up" and fields["unconfirmed"] is True
        kind, fields = parse_message("dnsmasq", "no servers found in /tmp/x")
        assert kind == "dns.no_servers"
        assert parse_message("", "anything") == (None, {})


# =====================================================================
# Hand-over to the detectors (security_rules.DetectorSet)
# =====================================================================


class TestDetectorHandOver:
    def test_fw4_records_reach_port_scan_indicator(self):
        template = _lines("fw4_kernel.txt")[1]  # reject guest in: … DPT=443
        assigner = KeyAssigner()
        records = [
            _parse(
                HEAD.replace("12:00:10", f"12:00:{i:02d}")
                + template.replace("DPT=443", f"DPT={1000 + i}"),
                assigner=assigner,
            ).record
            for i in range(25)
        ]
        detectors = DetectorSet([FirewallPortScanDetector(threshold=20)])
        detectors.feed_records(records)
        live = Liveness()
        live.observe(records)
        statuses = {"r1": live.statuses("r1", now=RECV)}
        assert statuses["r1"][DataSource.FIREWALL_LOG].availability is (
            Availability.AVAILABLE
        )
        results = {r.detector_id: r for r in detectors.evaluate(RECV, statuses)}
        scan = results["fw_port_scan_hint"]
        assert scan.status is Availability.AVAILABLE
        assert len(scan.events) == 1
        assert "distinct_ports=25" in scan.events[0].evidence
        assert scan.events[0].src.zone == "guest"
        # one guest line hits port 443 on the router: management indicator
        mgmt_all = [_parse(HEAD + line).record for line in _lines("fw4_kernel.txt")]
        mgmt_set = DetectorSet([FirewallMgmtAccessDetector(threshold=1)])
        mgmt_set.feed_records(mgmt_all)
        (res,) = mgmt_set.evaluate(RECV, statuses)
        assert len(res.events) == 1

    def test_dns_records_reach_dns_detectors(self):
        assigner = KeyAssigner()
        records = [
            _parse(
                HEAD + f"dnsmasq[1]: {i} 192.0.2.10/5{i:04d} query[A] "
                f"host{i}.example.org from 192.0.2.10",
                assigner=assigner,
            ).record
            for i in range(30)
        ]
        live = Liveness()
        live.observe(records)
        statuses = {"r1": live.statuses("r1", now=RECV)}
        dset = DetectorSet([DnsManyDomainsDetector(threshold=20)])
        dset.feed_records(records)
        (res,) = dset.evaluate(RECV, statuses)
        assert res.status is Availability.AVAILABLE
        assert len(res.events) == 1
        assert "distinct_domains=30" in res.events[0].evidence

    def test_without_dns_records_dns_detectors_report_not_available(self):
        live = Liveness()
        live.observe([_record(_lines("fw4_kernel.txt")[0])])
        statuses = {"r1": live.statuses("r1", now=RECV)}
        results = default_detectors().evaluate(RECV, statuses)
        dns = [r for r in results if r.detector_id.startswith("dns_")]
        assert dns and all(r.status is Availability.NOT_AVAILABLE for r in dns)
        assert all(not r.events for r in dns)


# =====================================================================
# Load and privacy
# =====================================================================


def _load_lines(count: int) -> list[bytes]:
    out = []
    for i in range(count):
        sec = i // 50  # 50 lines per second
        stamp = f"Nov 17 {10 + sec // 3600:02d}:{sec // 60 % 60:02d}:{sec % 60:02d}"
        octet = i % 250 + 1
        kind = i % 4
        if kind == 0:
            msg = (
                f"kernel: drop wan in: IN=wan OUT= SRC=198.51.100.{octet} "
                f"DST=203.0.113.2 PROTO=TCP SPT={1024 + i % 60000} DPT={i % 1000}"
            )
        elif kind == 1:
            msg = (
                f"dnsmasq[1]: {i} 192.0.2.{octet}/4000 query[A] "
                f"h{i}.example.org from 192.0.2.{octet}"
            )
        elif kind == 2:
            msg = f"dropbear[9]: Bad password attempt for 'root' from 198.51.100.{octet}:2"
        else:
            msg = f"hostapd: phy0-ap0: AP-STA-CONNECTED 02:00:00:00:00:{octet:02x}"
        out.append(f"<30>{stamp} ap-test {msg}".encode())
    return out


def _run_load(lines: list[bytes]) -> tuple[int, dict[str, int], Deduper]:
    """Parse, dedup and observe ``lines`` in listener-sized batches."""
    assigner = KeyAssigner()
    deduper = Deduper()
    live = Liveness()
    counts: dict[str, int] = {}
    base = _utc(2026, 11, 17, 10, 0, 0)
    accepted = 0
    for b in range(0, len(lines), 2000):
        batch = []
        for n, data in enumerate(lines[b : b + 2000]):
            recv = base + (b + n) / 50 + 0.5
            result = _parse(data, assigner=assigner, recv=recv)
            counts[result.outcome] = counts.get(result.outcome, 0) + 1
            if result.record is not None:
                batch.append(result.record)
        new = deduper.filter(batch, now=base + (b + 2000) / 50 + 1)
        live.observe(new)
        accepted += len(new)
    return accepted, counts, deduper


def test_case20_high_event_load():
    """100 000 lines: bounded memory, run time in the seconds range."""
    lines = _load_lines(100_000)
    start = time.perf_counter()
    accepted, counts, deduper = _run_load(lines)
    elapsed = time.perf_counter() - start
    assert counts.get(OUTCOME_INVALID, 0) == 0
    assert accepted == 100_000  # distinct lines: nothing swallowed
    size = deduper.footprint()
    assert size["keys"] <= 20_000 and size["held"] == 0
    assert elapsed < 30, f"took {elapsed:.1f} s"
    stats = SourceStats.from_counts({"received": len(lines), **counts})
    assert stats.parsed == 100_000
    # Memory: the state stops growing at the key cap (traced on a shorter
    # run, tracemalloc slows Python down several times).
    tracemalloc.start()
    _run_load(lines[:30_000])
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 64 * 1024 * 1024
    print(f"case20: {elapsed:.2f} s for 100k lines, peak {peak / 1e6:.1f} MB (30k)")


def test_case21_privacy_no_identifiers_logged(caplog):
    caplog.set_level(logging.DEBUG)
    lines = _load_lines(400) + [
        b"\xff\xfe garbage",
        (HEAD + "kernel: drop wan in: SRC=198.51.100.1").encode(),
    ]
    assigner = KeyAssigner()
    deduper = Deduper(hold_s=0)
    base = _utc(2026, 11, 17, 10, 0, 0)
    records = [
        r.record
        for r in (_parse(d, assigner=assigner, recv=base + 1) for d in lines)
        if r.record
    ]
    deduper.filter(records, now=base + 2)
    deduper.filter(records, now=base + 3)  # duplicates
    behind = [
        _parse(d, assigner=KeyAssigner(), recv=base + 5000, offset=-86_400).record
        for d in lines[:50]
    ]
    deduper.filter(behind, now=base + 5000)
    deduper.flush(now=base + 9000)
    for entry in caplog.records:
        if entry.levelno > logging.DEBUG:
            text = entry.getMessage()
            assert not any(ident in text for ident in IDENTIFIERS), text
    for stats in (deduper.stats().to_dict(), SourceStats().to_dict()):
        assert all(isinstance(v, int) for v in stats.values())
        assert not any(ident in str(stats) for ident in IDENTIFIERS)
    assert "r1" not in repr(deduper) and "r1" not in repr(Liveness())
    status = Liveness().status("r1", DataSource.DNS_QUERY_LOG, now=base)
    assert isinstance(status, SourceStatus)
