"""Pure parsers for off-router log lines (Security Center, plan 4.2-4.4, 4.9).

No I/O, no clock, no Home Assistant import of its own. Input is foreign and
forgeable (router output, UDP from the LAN): it is capped, cleaned of
control characters and ANSI sequences, matched only against fixed patterns
with bounded quantifiers, and never used in a command, format string or
HTML. The parsers never raise; unknown content gives ``kind=None`` and is
counted, not dropped.

Formats and their evidence (details: ``tests/fixtures/security/README.md``):

* logd remote line ``<PRI>Mmm dd hh:mm:ss HOST [PREFIX: ][kernel: ]MSG``:
  from the upstream source (ubox ``log/logread.c``, ``LOG_NET`` branch), not
  seen live. Both day forms (``Nov  7``, ``Nov 17``) are accepted.
* hostapd / dnsmasq-dhcp lines (via ``log_parser``) and the dropbear
  ``Password auth succeeded`` line: seen live (``tests/test_log_parser.py``).
* fw4 netfilter fields after the log prefix, dnsmasq ``--log-queries=extra``
  lines and the dropbear failure lines: **not confirmed**, built from the
  upstream formats. Their records carry ``fields["unconfirmed"] = True``.

Every recognised record has ``fields["fmt"]`` (format id, see
``FORMAT_CONFIRMED``) so the analysis can show "format unconfirmed".
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Final, NamedTuple

from .log_parser import (
    CATEGORY_DHCP,
    CATEGORY_WIFI,
    DHCP_ACK,
    DHCP_DECLINE,
    DHCP_NAK,
    DHCP_NO_ADDRESS,
    WIFI_CONNECTED,
    WIFI_DISCONNECTED,
    WIFI_HANDSHAKE_FAILED,
    WIFI_INACTIVITY,
    WIFI_PSK_MISMATCH,
    parse_entry,
)
from .security_logsrc import (
    MAX_LINE_BYTES,
    MAX_MSG_CHARS,
    MAX_ROUTER_CHARS,
    KeyAssigner,
    SecLogRecord,
    cap_fields,
    safe_text,
    second_token,
)

_LOGGER = logging.getLogger(__name__)

# Outcome of one line; the names match the ``SourceStats`` counters.
OUTCOME_PARSED: Final = "parsed"
OUTCOME_UNPARSED: Final = "unparsed"
OUTCOME_INVALID: Final = "invalid"

FMT_FW4: Final = "fw4_nflog"
FMT_DNS_QUERY: Final = "dnsmasq_query"
FMT_DNS_REPLY: Final = "dnsmasq_reply"
FMT_SSH_BAD_PASSWORD: Final = "dropbear_bad_password"
FMT_SSH_UNKNOWN_USER: Final = "dropbear_unknown_user"
FMT_SSH_PASSWORD_OK: Final = "dropbear_password_ok"
FMT_SSH_PUBKEY_OK: Final = "dropbear_pubkey_ok"
FMT_LOG_PARSER: Final = "log_parser"

# False = built from upstream documentation, never seen on a real router
# (plan 4.9). Replace the fixture and flip the flag after the live check.
FORMAT_CONFIRMED: Final[Mapping[str, bool]] = MappingProxyType(
    {
        FMT_FW4: False,
        FMT_DNS_QUERY: False,
        FMT_DNS_REPLY: False,
        FMT_SSH_BAD_PASSWORD: False,
        FMT_SSH_UNKNOWN_USER: False,
        FMT_SSH_PASSWORD_OK: True,  # tests/test_log_parser.py:105
        FMT_SSH_PUBKEY_OK: False,
    }
)
# log_parser kinds whose line format was seen live (tests/test_log_parser.py
# :3-4, :59-75; plan 4.9). Other log_parser kinds are marked unconfirmed.
CONFIRMED_LOG_PARSER_KINDS: Final = frozenset(
    {
        f"{CATEGORY_WIFI}.{WIFI_CONNECTED}",
        f"{CATEGORY_WIFI}.{WIFI_DISCONNECTED}",
        f"{CATEGORY_WIFI}.{WIFI_PSK_MISMATCH}",
        f"{CATEGORY_WIFI}.{WIFI_INACTIVITY}",
        f"{CATEGORY_WIFI}.{WIFI_HANDSHAKE_FAILED}",
        f"{CATEGORY_DHCP}.{DHCP_ACK}",
        f"{CATEGORY_DHCP}.{DHCP_NAK}",
        f"{CATEGORY_DHCP}.{DHCP_DECLINE}",
        f"{CATEGORY_DHCP}.{DHCP_NO_ADDRESS}",
    }
)

_MAX_TZ_OFFSET_S: Final = 14 * 3600
_RECV_MIN: Final = 946_684_800.0  # 2000-01-01
_RECV_MAX: Final = 4_102_444_800.0  # 2100-01-01
_MAX_NF_TOKENS: Final = 48
_MAX_NAME_CHARS: Final = 253
_MAX_USER_CHARS: Final = 64

_MONTHS: Final = {
    m: i + 1
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun")
        + ("Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    )
}
_HEAD_RE = re.compile(
    r"<(\d{1,3})>([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d) "
)
_PROC_RE = re.compile(r"([A-Za-z0-9_./-]{1,64})(?:\[(\d{1,10})\])?: ")
_KTIME_RE = re.compile(r"\[ {0,12}\d{1,10}\.\d{1,9}\] ?")
_FW4_RE = re.compile(
    r"(?i:(drop|reject|accept)) ([A-Za-z0-9_-]{1,32}) (in|out|forward): "
)
_IFACE_RE = re.compile(r"[A-Za-z0-9_.@-]{1,16}")
_PROTO_RE = re.compile(r"[A-Za-z0-9]{1,16}")
_QTYPE_RE = re.compile(r"[A-Za-z0-9]{1,12}")
_NAME_RE = re.compile(r"[!-~]{1,253}")
_NF_KEYS: Final = {
    "IN": "in_if",
    "OUT": "out_if",
    "SRC": "src",
    "DST": "dst",
    "PROTO": "proto",
    "SPT": "spt",
    "DPT": "dpt",
}
_REPLY_SOURCES: Final = frozenset({"reply", "cached", "cached-stale", "config"})


@dataclass(frozen=True, kw_only=True, slots=True)
class RemoteHeader:
    """Head of a logd remote line; ``msg`` is the cleaned, capped message."""

    pri: int
    facility: int
    severity: int
    month: int
    day: int
    hour: int
    minute: int
    second: int
    host: str | None
    proc: str
    pid: int | None
    msg: str
    truncated: bool

    def __repr__(self) -> str:
        """No host or message (identities)."""
        return f"RemoteHeader(pri={self.pri}, proc={self.proc!r})"


@dataclass(frozen=True, kw_only=True, slots=True)
class LineResult:
    """Outcome of :func:`parse_remote_line` (``outcome`` = counter name)."""

    outcome: str
    record: SecLogRecord | None = None
    truncated: bool = False
    ts_estimated: bool = False


class StreamLine(NamedTuple):
    """One line cut from a TCP stream."""

    data: bytes
    truncated: bool


# =============================================================================
# Transport framing
# =============================================================================


class StreamSplitter:
    """Split a TCP byte stream at ``\\n`` or NUL (``log_trailer_null``).

    The rest buffer never exceeds ``max_line`` bytes: a longer line is cut
    there (``truncated=True``) and its remainder up to the next terminator
    is discarded. Empty lines are skipped.
    """

    def __init__(self, max_line: int = MAX_LINE_BYTES) -> None:
        """Create an empty splitter."""
        self.max_line = max(1, int(max_line))
        self._rest = b""
        self._skipping = False

    def feed(self, chunk: bytes) -> list[StreamLine]:
        """Complete lines contained in ``chunk`` plus the buffered rest."""
        out: list[StreamLine] = []
        parts = chunk.replace(b"\x00", b"\n").split(b"\n")
        for piece in parts[:-1]:
            if self._skipping:
                self._skipping = False
                continue
            self._emit(self._rest + piece, out)
            self._rest = b""
        tail = parts[-1]
        if self._skipping:
            return out
        rest = self._rest + tail
        if len(rest) > self.max_line:
            out.append(StreamLine(rest[: self.max_line], True))
            rest = b""
            self._skipping = True
        self._rest = rest
        return out

    def flush(self) -> list[StreamLine]:
        """The unterminated rest (connection closed)."""
        out: list[StreamLine] = []
        if not self._skipping:
            self._emit(self._rest, out)
        self._rest = b""
        self._skipping = False
        return out

    def _emit(self, line: bytes, out: list[StreamLine]) -> None:
        line = line.rstrip(b"\r")
        if not line:
            return
        if len(line) > self.max_line:
            out.append(StreamLine(line[: self.max_line], True))
        else:
            out.append(StreamLine(line, False))


# =============================================================================
# Head and time
# =============================================================================


def parse_remote_header(
    data: bytes | str, *, prefix: str | None = None, truncated: bool = False
) -> RemoteHeader | None:
    """Head of one logd remote line, None if it is no valid syslog line.

    ``data`` is one UDP datagram or one stream line (a trailing ``\\n``,
    ``\\r`` or NUL is ignored). ``prefix`` is the router's ``log_prefix``
    if known; without it a leading ``word: `` directly followed by
    ``kernel: `` or ``proc[pid]: `` is taken as prefix.
    """
    raw = data.encode("utf-8", "replace") if isinstance(data, str) else bytes(data)
    if len(raw) > MAX_LINE_BYTES:
        raw, truncated = raw[:MAX_LINE_BYTES], True
    text = safe_text(raw.rstrip(b"\r\n\x00").decode("utf-8", "replace"), MAX_LINE_BYTES)
    head = _HEAD_RE.match(text)
    if head is None:
        return None
    pri = int(head.group(1))
    month = _MONTHS.get(head.group(2))
    day, hour, minute, sec = (int(head.group(i)) for i in range(3, 7))
    if pri > 191 or month is None or not 1 <= day <= 31:
        return None
    if hour > 23 or minute > 59 or sec > 60:
        return None
    host, rest = _split_host(text[head.end() :])
    rest = _strip_prefix(rest, prefix)
    proc, pid, body = _split_proc(rest)
    msg = body
    if len(body) > MAX_MSG_CHARS:
        msg, truncated = safe_text(body, MAX_MSG_CHARS), True
    return RemoteHeader(
        pri=pri,
        facility=pri >> 3,
        severity=pri & 7,
        month=month,
        day=day,
        hour=hour,
        minute=minute,
        second=min(sec, 59),
        host=host,
        proc=proc,
        pid=pid,
        msg=msg,
        truncated=truncated,
    )


def _split_host(rest: str) -> tuple[str | None, str]:
    first, sep, after = rest.partition(" ")
    if sep and first and not first.endswith(":") and len(first) <= 64:
        return first, after
    return None, rest


def _strip_prefix(rest: str, prefix: str | None) -> str:
    if prefix:
        return rest.removeprefix(f"{prefix}: ")
    first = _PROC_RE.match(rest)
    if first is None or first.group(2) is not None or first.group(1) == "kernel":
        return rest
    after = rest[first.end() :]
    second = _PROC_RE.match(after)
    if after.startswith("kernel: ") or (second and second.group(2) is not None):
        return after
    return rest


def _split_proc(rest: str) -> tuple[str, int | None, str]:
    if rest.startswith("kernel: "):
        return "kernel", None, rest[8:]
    match = _PROC_RE.match(rest)
    if match is None:
        return "", None, rest
    pid = match.group(2)
    return match.group(1), int(pid) if pid else None, rest[match.end() :]


def valid_offset(tz_offset_s: Any) -> float | None:
    """The zone offset in seconds if plausible (|x| <= 14 h), else None."""
    if isinstance(tz_offset_s, bool) or not isinstance(tz_offset_s, int | float):
        return None
    if not math.isfinite(tz_offset_s) or abs(tz_offset_s) > _MAX_TZ_OFFSET_S:
        return None
    return float(tz_offset_s)


def resolve_time(
    header: RemoteHeader, recv: float, tz_offset_s: float | None
) -> tuple[float, bool, int] | None:
    """``(ts, estimated, local_wall)`` of a head; None if the date is impossible.

    The year comes from the receive time: of the previous, current and next
    year the one closest to the router's "now" wins (a December line
    received in January belongs to the old year). ``local_wall`` is the
    router's wall clock as epoch seconds read as UTC. Without a valid zone
    offset ``ts`` is ``recv`` and ``estimated`` is True (plan 4.4).
    """
    offset = valid_offset(tz_offset_s)
    local_now = recv + (offset or 0.0)
    year = datetime.fromtimestamp(local_now, UTC).year
    best: float | None = None
    for candidate_year in (year - 1, year, year + 1):
        try:
            stamp = datetime(
                candidate_year,
                header.month,
                header.day,
                header.hour,
                header.minute,
                header.second,
                tzinfo=UTC,
            ).timestamp()
        except ValueError:
            continue
        if best is None or abs(stamp - local_now) < abs(best - local_now):
            best = stamp
    if best is None:
        return None
    if offset is None:
        return recv, True, int(best)
    return best - offset, False, int(best)


# =============================================================================
# Message part
# =============================================================================


def parse_message(proc: str, msg: str) -> tuple[str | None, dict[str, Any]]:
    """``(kind, fields)`` of a message part; ``(None, {})`` if unknown."""
    hit: tuple[str, dict[str, Any]] | None = None
    if proc == "kernel":
        hit = parse_fw4(msg)
    elif proc == "dnsmasq":
        hit = parse_dnsmasq_query(msg)
    elif proc == "dropbear":
        hit = parse_dropbear(msg)
    if hit is None and proc:
        hit = _parse_with_log_parser(proc, msg)
    if hit is None:
        return None, {}
    return hit


def _mark(fields: dict[str, Any], fmt: str, confirmed: bool) -> dict[str, Any]:
    fields["fmt"] = fmt
    if not confirmed:
        fields["unconfirmed"] = True
    return fields


def _ip(value: str) -> str | None:
    if not value or len(value) > 45:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _port(value: str) -> int | None:
    if value.isdigit() and len(value) <= 5 and int(value) <= 65535:
        return int(value)
    return None


def parse_fw4(body: str) -> tuple[str, dict[str, Any]] | None:
    """fw4 kernel log line → ``fw.drop``/``fw.reject``/``fw.accept``.

    Prefix ``<verdict> <zone> in|out: `` or ``<policy> <zone> forward: ``
    (fw4 ``zone-verdict.uc``), optionally behind ``[<uptime>]``, then the
    netfilter fields (``IN= OUT= SRC= DST= PROTO= SPT= DPT=`` …, format
    unconfirmed). Fields: ``zone`` (zone of the log rule), ``dest_zone``
    (always None: the line does not name it), ``dir``, ``src``, ``dst``,
    ``proto`` (lower case), ``spt``/``dpt`` (int or None), ``in_if``,
    ``out_if``. None without SRC and DST.
    """
    stamp = _KTIME_RE.match(body)
    if stamp:
        body = body[stamp.end() :]
    match = _FW4_RE.match(body)
    if match is None:
        return None
    found: dict[str, Any] = {}
    for token in body[match.end() :].split(" ", _MAX_NF_TOKENS)[:_MAX_NF_TOKENS]:
        name, sep, value = token.partition("=")
        target = _NF_KEYS.get(name)
        if not sep or target is None or target in found:
            continue
        found[target] = _nf_value(target, value)
    if found.get("src") is None or found.get("dst") is None:
        return None
    fields = {
        "zone": match.group(2),
        "dest_zone": None,
        "dir": match.group(3),
        "src": found["src"],
        "dst": found["dst"],
        "proto": found.get("proto"),
        "spt": found.get("spt"),
        "dpt": found.get("dpt"),
        "in_if": found.get("in_if"),
        "out_if": found.get("out_if"),
    }
    kind = f"fw.{match.group(1).lower()}"
    return kind, _mark(fields, FMT_FW4, FORMAT_CONFIRMED[FMT_FW4])


def _nf_value(target: str, value: str) -> str | int | None:
    if target in ("src", "dst"):
        return _ip(value)
    if target in ("spt", "dpt"):
        return _port(value)
    if target == "proto":
        return value.lower() if _PROTO_RE.fullmatch(value) else None
    return value if _IFACE_RE.fullmatch(value) else None


def parse_dnsmasq_query(body: str) -> tuple[str, dict[str, Any]] | None:
    """dnsmasq ``--log-queries[=extra]`` line → ``dns.query``/``dns.reply``.

    Forms (unconfirmed): ``[<id> <addr>/<port> ]query[<type>] <name> from
    <client>`` and ``[<id> <addr>/<port> ]reply|cached|config <name> is
    <answer>``. ``dns.query``: ``client``, ``name``, ``rcode`` (None: the
    query line has no answer), ``qtype``, ``qid``. ``dns.reply``: ``client``
    (only with ``extra``), ``name``, ``rcode`` (``NXDOMAIN``, ``NODATA``,
    ``SERVFAIL``, ``REFUSED`` or ``NOERROR``), ``source``, ``qid``.
    """
    tokens = body.split(" ", 7)[:7]
    qid: int | None = None
    requester: str | None = None
    if len(tokens) >= 2 and tokens[0].isdigit() and len(tokens[0]) <= 10:
        addr, sep, _port_text = tokens[1].rpartition("/")
        if sep:
            qid, requester, tokens = int(tokens[0]), _ip(addr), tokens[2:]
    if len(tokens) < 4:
        return None
    source, name, verb, dest = tokens[:4]
    if not _NAME_RE.fullmatch(name) or len(name) > _MAX_NAME_CHARS:
        return None
    name = name.lower()
    if source.startswith("query[") and source.endswith("]") and verb == "from":
        qtype = source[6:-1]
        fields = {
            "client": _ip(dest) or requester,
            "name": name,
            "rcode": None,
            "qtype": qtype if _QTYPE_RE.fullmatch(qtype) else None,
            "qid": qid,
        }
        return "dns.query", _mark(
            fields, FMT_DNS_QUERY, FORMAT_CONFIRMED[FMT_DNS_QUERY]
        )
    if source in _REPLY_SOURCES and verb == "is":
        fields = {
            "client": requester,
            "name": name,
            "rcode": _rcode(dest),
            "source": source,
            "qid": qid,
        }
        return "dns.reply", _mark(
            fields, FMT_DNS_REPLY, FORMAT_CONFIRMED[FMT_DNS_REPLY]
        )
    return None


def _rcode(answer: str) -> str:
    if answer == "NXDOMAIN":
        return "NXDOMAIN"
    if answer.startswith("NODATA"):
        return "NODATA"
    if answer in ("SERVFAIL", "REFUSED"):
        return answer
    return "NOERROR"


_SSH_FORMS: Final = (
    ("Bad password attempt for '", "auth.ssh_failed", FMT_SSH_BAD_PASSWORD),
    ("Login attempt for nonexistent user", "auth.ssh_failed", FMT_SSH_UNKNOWN_USER),
    ("Password auth succeeded for '", "auth.ssh_ok", FMT_SSH_PASSWORD_OK),
    ("Pubkey auth succeeded for '", "auth.ssh_ok", FMT_SSH_PUBKEY_OK),
)
_SSH_DETAIL: Final = {
    FMT_SSH_BAD_PASSWORD: ("reason", "bad_password"),
    FMT_SSH_UNKNOWN_USER: ("reason", "unknown_user"),
    FMT_SSH_PASSWORD_OK: ("method", "password"),
    FMT_SSH_PUBKEY_OK: ("method", "pubkey"),
}


def parse_dropbear(body: str) -> tuple[str, dict[str, Any]] | None:
    """dropbear login line → ``auth.ssh_failed``/``auth.ssh_ok``.

    Fields: ``user`` (None if the line names none), ``src``, ``spt`` and
    ``reason`` (failed) or ``method`` (ok). Only the password success line
    is confirmed live; the others follow the upstream source.
    """
    for lead, kind, fmt in _SSH_FORMS:
        if not body.startswith(lead):
            continue
        rest = body[len(lead) :]
        user: str | None = None
        if lead.endswith("'"):
            user, quote, rest = rest.partition("'")
            if not quote:
                return None
        elif rest.startswith(" '"):
            user, _quote, rest = rest[2:].partition("'")
        _head, sep, addr = rest.rpartition(" from ")
        if not sep:
            return None
        host, _colon, port = addr.strip().rpartition(":")
        detail, value = _SSH_DETAIL[fmt]
        fields = {
            "user": user[:_MAX_USER_CHARS] if user else None,
            "src": _ip(host),
            "spt": _port(port),
            detail: value,
        }
        return kind, _mark(fields, fmt, FORMAT_CONFIRMED[fmt])
    return None


def _parse_with_log_parser(proc: str, msg: str) -> tuple[str, dict[str, Any]] | None:
    """Reuse ``log_parser.parse_entry`` (hostapd, dnsmasq-dhcp, netifd …)."""
    kernel = proc == "kernel"
    entry = {
        "msg": f"kernel: {msg}" if kernel else f"{proc}: {msg}",
        "id": 0,
        "time": 0,
        "source": 0 if kernel else 1,
    }
    event = parse_entry(entry)
    if event is None:
        return None
    fields = {
        name: value
        for name, value in (
            ("mac", event.mac),
            ("iface", event.interface),
            ("ip", event.ip),
            ("name", event.name),
            ("reason", event.reason),
            ("frequency", event.frequency),
            ("channel", event.channel),
        )
        if value is not None
    }
    kind = event.key
    return kind, _mark(fields, FMT_LOG_PARSER, kind in CONFIRMED_LOG_PARSER_KINDS)


# =============================================================================
# Line → record
# =============================================================================


def parse_remote_line(
    data: bytes | str,
    *,
    router: str,
    path: str,
    recv: float,
    tz_offset_s: float | None,
    assigner: KeyAssigner,
    prefix: str | None = None,
    truncated: bool = False,
) -> LineResult:
    """One received line → :class:`LineResult` (never raises).

    ``router`` is the caller's opaque id of the sender (never taken from
    the line's HOST field), ``path`` the delivery path (``LogPath`` value),
    ``recv`` the receive time, ``assigner`` the stream's key assigner and
    ``truncated`` the flag of a :class:`StreamLine`.
    """
    try:
        return _parse_remote_line(
            data,
            router=router,
            path=path,
            recv=recv,
            tz_offset_s=tz_offset_s,
            assigner=assigner,
            prefix=prefix,
            truncated=truncated,
        )
    except Exception as err:  # noqa: BLE001 - foreign input must never raise
        _LOGGER.debug("Remote log line not parsed (%s)", type(err).__name__)
        return LineResult(outcome=OUTCOME_INVALID)


def _parse_remote_line(
    data: bytes | str,
    *,
    router: str,
    path: str,
    recv: float,
    tz_offset_s: float | None,
    assigner: KeyAssigner,
    prefix: str | None,
    truncated: bool,
) -> LineResult:
    if (
        not isinstance(router, str)
        or not 0 < len(router) <= MAX_ROUTER_CHARS
        or isinstance(recv, bool)
        or not isinstance(recv, int | float)
        or not _RECV_MIN <= recv <= _RECV_MAX
    ):
        return LineResult(outcome=OUTCOME_INVALID)
    header = parse_remote_header(data, prefix=prefix, truncated=truncated)
    if header is None:
        return LineResult(outcome=OUTCOME_INVALID)
    timing = resolve_time(header, float(recv), tz_offset_s)
    if timing is None:
        return LineResult(outcome=OUTCOME_INVALID, truncated=header.truncated)
    ts, estimated, local_wall = timing
    kind, fields = parse_message(header.proc, header.msg)
    if estimated:
        fields["ts_estimated"] = True
    if header.truncated:
        fields["truncated"] = True
    second = second_token(ts, estimated=estimated, local_wall=local_wall)
    record = SecLogRecord(
        router=router,
        ts=ts,
        recv=float(recv),
        path=path,
        pri=header.pri,
        proc=header.proc,
        pid=header.pid,
        msg=header.msg,
        kind=kind,
        fields=cap_fields(fields),
        key=assigner.assign(router, second, header.proc, header.msg),
    )
    return LineResult(
        outcome=OUTCOME_PARSED if kind else OUTCOME_UNPARSED,
        record=record,
        truncated=header.truncated,
        ts_estimated=estimated,
    )
