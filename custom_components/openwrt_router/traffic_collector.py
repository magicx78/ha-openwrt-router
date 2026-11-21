"""Intake of an optional external traffic collector (plan §8, Phase K).

The collector **pushes** normalised records into Home Assistant
(``POST /api/openwrt_topology/traffic/collector/ingest``); Home Assistant
never calls a collector, so every outgoing network call stays in ``api.py``
and nothing new is installed or started.

**Off by default, twice.** The intake exists only while traffic analytics
runs (a router has ``traffic_enabled``) *and* an administrator switched the
collector on in the traffic settings and named its Home Assistant user.

**Authentication** (plan §8, the one way the plan gives): the request
carries a long-lived access token of that one user (checked by Home
Assistant's ``requires_auth``), and the route compares ``user.id`` with the
stored ``user_id``. That user must exist, be active and must **not** be an
administrator; an administrator can never write as the collector. Plain
HTTP is refused (``insecure_transport``): the token would travel in clear
text. Only the user id is stored; no token or secret is ever stored,
logged, returned or put into diagnostics.

**Schema** ``traffic.collector.v1``::

    {"schema": "traffic.collector.v1", "collector": "<name, <= 32>",
     "sent_at": <unix s>, "records": [<record>, ...]}

with records as ``traffic_flows.normalise_collector_flow`` reads them
(kind ``flow``). A different schema (also another major version) is a 400
``schema_unsupported``. The record kinds ``client_aggregate`` and
``interface_aggregate`` of the plan are part of the schema but not taken in
this build (``kind_not_supported``): their buckets would need a separate
collector series next to the native one (plan §8 "Ablage"), see the report.

**Limits:** body <= 256 KiB (413), JSON depth <= 4, strings <= 64
characters, <= 500 records, at most one call per 10 s (429 with
``Retry-After``), ``sent_at`` and record times not more than 300 s ahead
and not older than 24 h.

**All or nothing.** A call is checked completely before anything is kept:
one invalid record rejects the whole call (400 ``records_rejected`` with
``index`` and a fixed reason per refused record; a ``router_id`` of no
loaded router with traffic on is ``unknown_router``), and a call that would not
fit the bounded flow store at once is refused as a whole (503
``store_full``). Nothing is ever taken in part. Every refusal is counted;
refusals of the authorisation (wrong user, collector off, plain HTTP) are
also reported as the core event ``traffic_analytics.collector_rejected``
(``security_relevant``), at most ``EVENT_BUDGET_PER_HOUR`` per hour for each
reason and user (at most ``MAX_EVENT_KEYS`` such budgets at once).
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from collections import Counter, deque
from collections.abc import Callable, Mapping
from typing import Any, Final

from .traffic_const import (
    FEED_COLLECTOR,
    FLOW_MAX_AGE_S,
    FLOW_MAX_FUTURE_S,
    MODULE_NAME,
    REJECT_BAD_FIELD,
)
from .traffic_flows import FlowRejected, FlowStore, normalise_collector_flow
from .traffic_model import FlowRecord

_LOGGER = logging.getLogger(__name__)

SCHEMA_V1: Final = "traffic.collector.v1"
INGEST_PATH: Final = "/collector/ingest"
BODY_MAX_BYTES: Final = 256 * 1024
MAX_RECORDS: Final = 500
MAX_DEPTH: Final = 4
MAX_STRING: Final = 64
NAME_MAX: Final = 32
MIN_INTERVAL_S: Final = 10.0
# Security events per hour and per (reason, user): one signed-in user that
# keeps knocking cannot use up the budget of a real failed attempt (T4).
EVENT_BUDGET_PER_HOUR: Final = 10
# Budget keys held at once (hard bound of the bookkeeping).
MAX_EVENT_KEYS: Final = 64
MAX_REJECTED_LISTED: Final = 50
EVENT_REJECTED: Final = "traffic_analytics.collector_rejected"
ENVELOPE_FIELDS: Final = frozenset({"schema", "collector", "sent_at", "records"})
AGGREGATE_KINDS: Final = frozenset({"client_aggregate", "interface_aggregate"})

# fixed reason tokens (never a value from the request)
REJECT_NOT_JSON: Final = "not_json"
REJECT_NOT_OBJECT: Final = "not_an_object"
REJECT_UNKNOWN_KEY: Final = "unknown_key"
REJECT_TOO_DEEP: Final = "too_deep"
REJECT_STRING_TOO_LONG: Final = "string_too_long"
REJECT_SCHEMA_MISSING: Final = "schema_missing"
REJECT_SCHEMA_UNSUPPORTED: Final = "schema_unsupported"
REJECT_BAD_NAME: Final = "invalid_collector_name"
REJECT_BAD_SENT_AT: Final = "invalid_sent_at"
REJECT_RECORDS_MISSING: Final = "records_missing"
REJECT_TOO_MANY: Final = "too_many_records"
REJECT_KIND_NOT_SUPPORTED: Final = "kind_not_supported"
REJECT_RECORDS: Final = "records_rejected"
REJECT_STORE_FULL: Final = "store_full"
REJECT_BODY_TOO_LARGE: Final = "body_too_large"
REJECT_AUTH: Final = "authorization_denied"
REJECT_TRANSPORT: Final = "insecure_transport"
REJECT_RATE: Final = "rate_limited"
REJECT_COLLECTOR_OFF: Final = "collector_off"
# per record: a router id of no loaded router with traffic on (review T2)
REJECT_UNKNOWN_ROUTER: Final = "unknown_router"

# state of the collector source (panel, capability)
STATE_OFF: Final = "off"
STATE_WAITING: Final = "waiting"
STATE_RECEIVING: Final = "receiving"
STATE_SILENT: Final = "silent"


class CollectorRejected(Exception):
    """A refused call: HTTP status, fixed reason, refused records (index, reason)."""

    def __init__(
        self,
        status: int,
        reason: str,
        *,
        rejected: list[tuple[int, str]] | None = None,
        retry_after: int | None = None,
    ) -> None:
        """Refusal with a fixed reason token."""
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.rejected = list(rejected or [])
        self.retry_after = retry_after


def _structure_reason(value: Any) -> str | None:
    """Depth and string length of the whole body (iterative, bounded)."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, str):
            if len(item) > MAX_STRING:
                return REJECT_STRING_TOO_LONG
            continue
        if isinstance(item, dict):
            if depth >= MAX_DEPTH:
                return REJECT_TOO_DEEP
            for key, sub in item.items():
                if len(key) > MAX_STRING:
                    return REJECT_STRING_TOO_LONG
                stack.append((sub, depth + 1))
        elif isinstance(item, list):
            if depth >= MAX_DEPTH:
                return REJECT_TOO_DEEP
            stack.extend((sub, depth + 1) for sub in item)
    return None


def _time_ok(value: Any, now: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    if not math.isfinite(value):
        return False
    return now - FLOW_MAX_AGE_S <= value <= now + FLOW_MAX_FUTURE_S


def parse_envelope(raw: bytes, *, now: float) -> list[Any]:
    """The checked envelope of one call; returns its raw records.

    Raises :class:`CollectorRejected` (400) with a fixed reason.
    """
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise CollectorRejected(400, REJECT_NOT_JSON) from None
    except RecursionError:
        raise CollectorRejected(400, REJECT_TOO_DEEP) from None
    if not isinstance(data, dict):
        raise CollectorRejected(400, REJECT_NOT_OBJECT)
    reason = _structure_reason(data)
    if reason is not None:
        raise CollectorRejected(400, reason)
    if set(data) - ENVELOPE_FIELDS:
        raise CollectorRejected(400, REJECT_UNKNOWN_KEY)
    schema = data.get("schema")
    if schema is None:
        raise CollectorRejected(400, REJECT_SCHEMA_MISSING)
    if schema != SCHEMA_V1:
        raise CollectorRejected(400, REJECT_SCHEMA_UNSUPPORTED)
    name = data.get("collector")
    if name is not None and (
        not isinstance(name, str)
        or len(name) > NAME_MAX
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
    ):
        raise CollectorRejected(400, REJECT_BAD_NAME)
    if not _time_ok(data.get("sent_at"), now):
        raise CollectorRejected(400, REJECT_BAD_SENT_AT)
    records = data.get("records")
    if not isinstance(records, list):
        raise CollectorRejected(400, REJECT_RECORDS_MISSING)
    if len(records) > MAX_RECORDS:
        raise CollectorRejected(400, REJECT_TOO_MANY)
    return records


def validate_records(
    records: list[Any],
    *,
    now: float,
    module_key: bytes | None,
    known_routers: frozenset[str] | None = None,
) -> list[FlowRecord]:
    """Every record as a FlowRecord, or one refusal for the whole call.

    ``known_routers``: the router ids a record may name (the loaded routers
    with traffic on); a record without router id stays allowed. None: no
    check (pure tests of the schema).
    """
    out: list[FlowRecord] = []
    rejected: list[tuple[int, str]] = []
    for index, raw in enumerate(records):
        if isinstance(raw, Mapping) and raw.get("kind") in AGGREGATE_KINDS:
            rejected.append((index, REJECT_KIND_NOT_SUPPORTED))
            continue
        try:
            flow = normalise_collector_flow(raw, now=now, module_key=module_key)
        except FlowRejected as err:
            rejected.append((index, err.reason))
        except (TypeError, ValueError):
            rejected.append((index, REJECT_BAD_FIELD))
        else:
            if (
                known_routers is not None
                and flow.router_id is not None
                and flow.router_id not in known_routers
            ):
                rejected.append((index, REJECT_UNKNOWN_ROUTER))
            else:
                out.append(flow)
    if rejected:
        raise CollectorRejected(400, REJECT_RECORDS, rejected=rejected)
    return out


class CollectorIntake:
    """Counters, rate limit and event budget of the intake (memory only)."""

    def __init__(self) -> None:
        """Nothing received yet."""
        self.counters: Counter[str] = Counter()
        self._last_call: float | None = None
        self.last_accepted_wall: float | None = None
        # (reason, user pseudonym) -> event times of the last hour
        self._events: dict[tuple[str, str], deque[float]] = {}
        # per-run salt: the budget keys are pseudonyms, never a user id
        self._salt = os.urandom(16)
        # ConfigurationApi.emit while the core is bound (None: not published)
        self.emit: Callable[..., Any] | None = None

    def clear(self) -> None:
        """Module off: forget the rate state (counters stay)."""
        self._last_call = None
        self.last_accepted_wall = None
        self._events.clear()

    # -- checks ------------------------------------------------------------------------

    def check_rate(self, now_mono: float) -> None:
        """At most one call per MIN_INTERVAL_S (429 with Retry-After)."""
        last = self._last_call
        if last is not None and 0 <= now_mono - last < MIN_INTERVAL_S:
            wait = max(1, math.ceil(MIN_INTERVAL_S - (now_mono - last)))
            self.refused(REJECT_RATE)
            raise CollectorRejected(429, REJECT_RATE, retry_after=wait)
        self._last_call = now_mono

    def refused(self, reason: str, *, records: int = 0) -> None:
        """Count one refused call (and its records)."""
        self.counters["rejected_calls"] += 1
        self.counters[f"rejected_{reason}"] += 1
        self.counters["rejected_records"] += records

    def _budget_key(self, reason: str, user_id: Any) -> tuple[str, str]:
        user = user_id if isinstance(user_id, str) else ""
        digest = hashlib.blake2s(user.encode(), key=self._salt, digest_size=8)
        return reason, digest.hexdigest()

    def _within_budget(self, key: tuple[str, str], now_wall: float) -> bool:
        """True if ``key`` may send one more event this hour (not booked)."""
        for other in list(self._events):
            times = self._events[other]
            while times and now_wall - times[0] > 3600:
                times.popleft()
            if not times:
                del self._events[other]
        times = self._events.get(key)
        if times is None:
            if len(self._events) >= MAX_EVENT_KEYS:
                self.counters["events_keys_full"] += 1
                return False
            return True
        if len(times) >= EVENT_BUDGET_PER_HOUR:
            self.counters["events_over_budget"] += 1
            return False
        return True

    def auth_refused(
        self, reason: str, now_wall: float, *, user_id: Any = None
    ) -> None:
        """Count a refused authorisation and report it (budgeted event).

        The budget is kept per reason and per user (``user_id`` only as a
        salted pseudonym in memory, never in the event or the counters).
        """
        self.refused(reason)
        key = self._budget_key(reason, user_id)
        if not self._within_budget(key, now_wall):
            return
        if self.emit is None:
            self.counters["events_not_published"] += 1
            return
        self._events.setdefault(key, deque()).append(now_wall)
        try:
            from .net_events import Severity

            self.emit(
                EVENT_REJECTED,
                source=MODULE_NAME,
                severity=Severity.WARNING,
                dedup_key=f"collector:{reason}",
                data={"reason": reason},
                security_relevant=True,
                classification="collector_rejected",
            )
        except Exception as err:  # noqa: BLE001 - reporting never breaks the intake
            self.counters["events_failed"] += 1
            _LOGGER.debug("Collector event failed (%s)", type(err).__name__)
            return
        self.counters["events_published"] += 1

    # -- intake ------------------------------------------------------------------------

    def ingest(
        self,
        raw: bytes,
        *,
        now_wall: float,
        module_key: bytes | None,
        flows: FlowStore,
        known_routers: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        """Check and keep one call (all or nothing); the answer body."""
        try:
            records = parse_envelope(raw, now=now_wall)
        except CollectorRejected as err:
            self.refused(err.reason)
            raise
        try:
            parsed = validate_records(
                records,
                now=now_wall,
                module_key=module_key,
                known_routers=known_routers,
            )
        except CollectorRejected as err:
            self.refused(err.reason, records=len(records))
            unknown = sum(1 for _i, r in err.rejected if r == REJECT_UNKNOWN_ROUTER)
            if unknown:
                self.counters["rejected_records_unknown_router"] += unknown
            raise
        if not flows.can_take(parsed, origin=FEED_COLLECTOR, now=now_wall):
            self.refused(REJECT_STORE_FULL, records=len(parsed))
            raise CollectorRejected(503, REJECT_STORE_FULL)
        for record in parsed:
            flows.add(record, origin=FEED_COLLECTOR, now=now_wall)
        self.counters["accepted_calls"] += 1
        self.counters["accepted_records"] += len(parsed)
        self.last_accepted_wall = now_wall
        return {"v": 1, "schema": SCHEMA_V1, "accepted": len(parsed), "rejected": []}

    def state(self, *, enabled: bool, now_wall: float, ttl_s: float) -> str:
        """``off`` / ``waiting`` (nothing yet) / ``receiving`` / ``silent``."""
        if not enabled:
            return STATE_OFF
        last = self.last_accepted_wall
        if last is None:
            return STATE_WAITING
        return STATE_RECEIVING if now_wall - last <= ttl_s else STATE_SILENT

    def summary(self) -> dict[str, Any]:
        """Counts only (no user id, no token, no address)."""
        return {
            "schema": SCHEMA_V1,
            "limits": limits(),
            **dict(sorted(self.counters.items())),
        }


def limits() -> dict[str, Any]:
    """The fixed limits of the intake (panel, diagnostics)."""
    return {
        "body_max_bytes": BODY_MAX_BYTES,
        "max_records": MAX_RECORDS,
        "max_depth": MAX_DEPTH,
        "max_string": MAX_STRING,
        "min_interval_s": MIN_INTERVAL_S,
        "max_future_s": FLOW_MAX_FUTURE_S,
        "max_age_s": FLOW_MAX_AGE_S,
    }


def rejected_body(err: CollectorRejected) -> dict[str, Any]:
    """The answer of a refused call: fixed tokens and indexes only."""
    return {
        "v": 1,
        "schema": SCHEMA_V1,
        "code": err.reason,
        "accepted": 0,
        "rejected": [
            {"index": index, "reason": reason}
            for index, reason in err.rejected[:MAX_REJECTED_LISTED]
        ],
        "rejected_total": len(err.rejected),
    }


__all__ = [
    "BODY_MAX_BYTES",
    "INGEST_PATH",
    "MAX_RECORDS",
    "SCHEMA_V1",
    "CollectorIntake",
    "CollectorRejected",
    "limits",
    "parse_envelope",
    "rejected_body",
    "validate_records",
]
