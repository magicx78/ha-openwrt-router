"""Network Time Machine, Phase B: the HA store of the own index.

Pattern of the other enterprise modules (``traffic_store``, ``core_audit``):
``core_store.create_store`` (versioned, migrate function from day one,
private file, atomic writes) and ``core_store.async_load_store`` (an
unreadable, foreign or newer store is kept as ``.bak`` / HA's
``.corrupt.`` copy and the index starts empty; the setup never fails), a
delayed save armed at most once, an explicit flush when the Time Machine
is switched off or its last router goes, and HA's own final write at
shutdown.

Store ``openwrt_router.time_machine`` (version 1.2 since 1.52.0), data:

* ``saved_at``: wall time of the write; ``stop``: why the index stopped
  with this write (``stop`` = HA shut down, ``disabled`` = switched off,
  ``unloaded`` = last router unloaded), None for a regular write. The
  engine turns ``saved_at`` into an ``ha_gap`` mark at the next start and
  closes intervals left open as "end unknown" (plan §5.7).
* ``routers`` (table of router ids) and ``marks`` (one packed row per mark,
  ``tm_marks.pack``); ``next_seq`` keeps mark ids stable.
* ``coverage``: when the index was live (``[start, end]`` pairs, at most
  ``COVERAGE_MAX``); ``tm_query`` uses it to drop doubles of other sources.
* ``checkpoints`` (plan §5.4, packed rows) and ``state`` (the last known
  fingerprint hash, radios, uplink parent and role per router, so a change
  during a restart is still seen).

Additive in 1.2 (1.52.0, Phase D "state at a moment"; a 1.1 file has none of
them, so the time before the upgrade is "unknown" there, never guessed):

* ``seen``: per router the stretches in which the engine followed its polls
  (:class:`Segment`, packed rows, at most ``SEEN_MAX`` per router): start,
  end, and the first radios and the first settled uplink/role read in the
  stretch (the base the marks of the stretch are applied to).
* ``clients_cov``: when the client recorder was attached (pairs like
  ``coverage``).
* ``lost``: per quota, up to when marks are gone without the retention
  (``tm_marks.MarkIndex.lost``).

**Size.** The rows are packed once and cached (a row is packed again only
after its mark changed). A payload over ``STORE_MAX_BYTES`` is trimmed in
one pass, oldest client marks first, then references, then infrastructure,
using the exact length of every row; a payload still over the limit is
not written and the last good one is kept (``save_over_size``). The first
write keeps the file as read (review lesson of Traffic 1.49.3).
"""

from __future__ import annotations

import logging
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from homeassistant.core import HomeAssistant
from homeassistant.helpers.json import prepare_save_json

from . import core_store
from .const import (
    TIME_MACHINE_STORE_KEY,
    TIME_MACHINE_STORE_MINOR_VERSION,
    TIME_MACHINE_STORE_VERSION,
)
from .tm_marks import (
    QUOTA_CLIENTS,
    QUOTA_INFRA,
    QUOTA_REFS,
    BadRow,
    MarkIndex,
    pack,
    unpack,
    valid_router_id,
)

_LOGGER = logging.getLogger(__name__)

STORE_MAX_BYTES: Final = 2_500_000  # plan §5.5
TRIM_HEADROOM: Final = 0.05  # a trim goes 5 % below the limit
# Bytes HA's indented JSON adds per row: six spaces, two quotes, comma, newline.
ROW_OVERHEAD: Final = 10
# Changes are bundled for 5 min (review K1: fewer writes on SD cards; a crash
# loses at most this plus the heartbeat, see docs §15.1).
SAVE_DELAY_S: Final = 300.0
COVERAGE_MAX: Final = 64
SEEN_MAX: Final = 64  # followed stretches per router (1.52.0)
CHECKPOINTS_DAY_MAX: Final = 31
CHECKPOINTS_START_MAX: Final = 16
STOP_HA: Final = "stop"
STOP_DISABLED: Final = "disabled"
STOP_UNLOADED: Final = "unloaded"
STOP_REASONS: Final = (STOP_HA, STOP_DISABLED, STOP_UNLOADED)
TRIM_ORDER: Final = (QUOTA_CLIENTS, QUOTA_REFS, QUOTA_INFRA)

_CHECKPOINT = re.compile(r"[0-9]{1,16}\|(?:start|day)\|[0-9a-z_.,;=/+:-]{0,4000}")
_STATE = re.compile(
    r"[0-9a-f]{0,16}\|[0-9a-z_.=/+]{0,400}\|(?:rtr_[0-9a-f]{32})?\|[gn]?"
)

_SEEN = re.compile(
    r"[0-9]{1,16}\|[0-9]{0,16}\|[0-9]{0,16}\|[0-9a-z_.=/+]{0,400}"
    r"\|[0-9]{0,16}\|(?:rtr_[0-9a-f]{32})?\|[gn]?"
)

_COUNTERS: Final = (
    "writes",
    "save_over_size",
    "load_failed",
    "trimmed_rows",
    "copies_removed",
)


def _migrate(old_major: int, old_minor: int, data: Any) -> dict[str, Any]:
    """Version 1.x: additive minors. A newer or foreign major raises, so the
    loader keeps a ``.bak`` copy and the index starts empty."""
    if old_major != TIME_MACHINE_STORE_VERSION or not isinstance(data, dict):
        raise NotImplementedError(f"time machine store version {old_major} unknown")
    return dict(data)


def store_bytes(payload: Any) -> int:
    """Bytes of the store file exactly as HA's ``Store`` writes it."""
    wrapped = {
        "version": TIME_MACHINE_STORE_VERSION,
        "minor_version": TIME_MACHINE_STORE_MINOR_VERSION,
        "key": TIME_MACHINE_STORE_KEY,
        "data": payload,
    }
    _mode, data = prepare_save_json(wrapped)
    return len(data.encode("utf-8") if isinstance(data, str) else data)


def _finite(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def pack_radios(radios: Mapping[str, tuple[int, int]]) -> str:
    """``5g0=36/80+2.4g0=6/20`` (store form, sorted)."""
    return "+".join(f"{k}={c}/{w}" for k, (c, w) in sorted(radios.items()))


def unpack_radios(raw: str) -> dict[str, tuple[int, int]]:
    """Inverse of :func:`pack_radios`; odd parts are skipped."""
    out: dict[str, tuple[int, int]] = {}
    for part in raw.split("+") if raw else []:
        key, _, value = part.partition("=")
        chan, _, width = value.partition("/")
        if key and chan.isdigit() and width.isdigit():
            out[key] = (int(chan), int(width))
    return out


def _ms(value: float | None) -> str:
    return "" if value is None else str(math.floor(value * 1000))


def _sec(raw: str) -> float | None:
    return int(raw) / 1000 if raw else None


@dataclass(slots=True)
class Segment:
    """One stretch in which the engine followed a router's polls (1.2).

    ``radios_at`` / ``radios``: the first poll of the stretch with radios
    and the engine's radio state after it; ``topo_at`` / ``parent`` /
    ``role``: the first settled (two polls) uplink and role of the stretch.
    Every change after them is a mark (``tm_state`` applies them); a radio
    that appears without a mark starts a new stretch (the engine splits).
    """

    start: float
    end: float | None = None
    radios_at: float | None = None
    radios: dict[str, tuple[int, int]] = field(default_factory=dict)
    topo_at: float | None = None
    parent: str = ""
    role: str = ""

    @property
    def is_open(self) -> bool:
        """Still followed."""
        return self.end is None

    def pack(self) -> str:
        """``start|end|radios_at|radios|topo_at|parent|role`` (ms)."""
        return "|".join(
            (
                _ms(self.start),
                _ms(self.end),
                _ms(self.radios_at),
                pack_radios(self.radios),
                _ms(self.topo_at),
                self.parent,
                self.role,
            )
        )

    @classmethod
    def unpack(cls, raw: Any) -> Segment | None:
        """From :meth:`pack` (None for anything that does not validate)."""
        if not isinstance(raw, str) or not _SEEN.fullmatch(raw):
            return None
        start, end, radios_at, radios, topo_at, parent, role = raw.split("|")
        seg = cls(
            int(start) / 1000,
            _sec(end),
            _sec(radios_at),
            unpack_radios(radios),
            _sec(topo_at),
            parent,
            role,
        )
        if seg.end is not None and seg.end < seg.start:
            return None
        return seg


@dataclass(slots=True)
class LoadResult:
    """What the engine needs from the stored file."""

    failed: bool = False
    saved_at: float | None = None
    stop: str | None = None


class TimeMachineStore:
    """Loads, packs, size-checks and writes the own index."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        clock: Callable[[], float] = time.time,
        max_bytes: int = STORE_MAX_BYTES,
    ) -> None:
        """Nothing opened yet."""
        self.hass = hass
        self.clock = clock
        self.max_bytes = max_bytes
        self.index = MarkIndex()
        self.coverage: list[list[float | None]] = []
        self.checkpoints: list[str] = []
        self.state: dict[str, str] = {}
        # 1.2 (1.52.0): followed stretches per router, client recording
        self.seen: dict[str, list[Segment]] = {}
        self.clients_cov: list[list[float | None]] = []
        self.stop_reason: str | None = None
        self.counters: dict[str, int] = dict.fromkeys(_COUNTERS, 0)
        self.last_bytes: int | None = None
        self._store: Any = None
        self._routers: list[str] = []
        self._rix: dict[str, int] = {}
        self._rows: dict[int, str] = {}
        self._pending = False
        self._last_good: dict[str, Any] | None = None
        self.closed = False

    # -- load ----------------------------------------------------------------------------

    async def async_load(self) -> LoadResult:
        """Read the store once; never raises (a broken file starts empty)."""
        self._store = core_store.create_store(
            self.hass,
            TIME_MACHINE_STORE_VERSION,
            TIME_MACHINE_STORE_KEY,
            minor_version=TIME_MACHINE_STORE_MINOR_VERSION,
            migrate=_migrate,
            private=True,
            atomic_writes=True,
        )
        loaded = await core_store.async_load_store(
            self.hass, self._store, TIME_MACHINE_STORE_KEY
        )
        if loaded.failed:
            self.counters["load_failed"] += 1
            return LoadResult(failed=True)
        data = loaded.data or {}
        try:
            return self._restore(data)
        except Exception as err:  # noqa: BLE001 - a damaged file starts empty
            _LOGGER.warning(
                "Time Machine store not restored (%s); starting empty",
                type(err).__name__,
            )
            self.counters["load_failed"] += 1
            self.index = MarkIndex()
            self.coverage, self.checkpoints, self.state = [], [], {}
            self.seen, self.clients_cov = {}, []
            await core_store.async_backup_store(
                self.hass, self._store, TIME_MACHINE_STORE_KEY
            )
            return LoadResult(failed=True)

    def _restore(self, data: Mapping[str, Any]) -> LoadResult:
        raw_routers = data.get("routers")
        routers = [
            r if valid_router_id(r) else ""
            for r in (raw_routers if isinstance(raw_routers, list) else [])
        ]
        marks = []
        rows = data.get("marks")
        for row in rows if isinstance(rows, list) else []:
            try:
                marks.append(unpack(row, routers))
            except BadRow:
                self.index.counters["bad_marks"] += 1
        self.index.restore(marks)
        next_seq = data.get("next_seq")
        if isinstance(next_seq, int) and not isinstance(next_seq, bool):
            self.index.next_seq = max(self.index.next_seq, next_seq)
        self.index.changed = False
        self.coverage = _pairs(data.get("coverage"))
        # 1.2 (absent in a 1.1 file: the time before is unknown, never guessed)
        self.clients_cov = _pairs(data.get("clients_cov"))
        self.index.restore_lost(data.get("lost"))
        self.index.changed = False
        self.seen = {}
        seen = data.get("seen")
        for rid, rows in seen.items() if isinstance(seen, dict) else ():
            if not valid_router_id(rid) or not isinstance(rows, list):
                continue
            segs = [s for s in map(Segment.unpack, rows) if s is not None]
            segs.sort(key=lambda s: s.start)
            if segs:
                self.seen[rid] = segs[-SEEN_MAX:]
        self.checkpoints = [
            c
            for c in data.get("checkpoints") or []
            if isinstance(c, str) and _CHECKPOINT.fullmatch(c)
        ]
        state = data.get("state")
        self.state = {
            rid: value
            for rid, value in (state.items() if isinstance(state, dict) else ())
            if valid_router_id(rid)
            and isinstance(value, str)
            and _STATE.fullmatch(value)
        }
        saved_at = data.get("saved_at")
        stop = data.get("stop")
        self._last_good = dict(data) if data else None
        return LoadResult(
            failed=False,
            saved_at=float(saved_at) if _finite(saved_at) else None,
            stop=stop if stop in STOP_REASONS else None,
        )

    # -- payload -------------------------------------------------------------------------

    def _row(self, seq: int) -> str:
        row = self._rows.get(seq)
        if row is None:
            mark = self.index.marks[seq]
            for router in (mark.router, *(mark.peers or ())):
                if router is not None and router not in self._rix:
                    self._rix[router] = len(self._routers)
                    self._routers.append(router)
            row = self._rows[seq] = pack(mark, self._rix)
        return row

    def _fresh_rows(self) -> None:
        """Drop cached rows of changed or deleted marks."""
        for seq in self.index.touched:
            self._rows.pop(seq, None)
        self.index.touched.clear()
        if len(self._rows) > len(self.index.marks):
            marks = self.index.marks
            self._rows = {s: r for s, r in self._rows.items() if s in marks}

    def _trim(self, excess: int) -> int:
        """Drop the oldest marks (clients, then references, then
        infrastructure) worth ``excess`` bytes; one pass. Closed marks go
        first, open intervals last (review S2)."""
        dropped: set[int] = set()
        for quota in TRIM_ORDER:
            if excess <= 0:
                break
            for mark in sorted(
                (m for m in self.index.marks.values() if m.quota == quota),
                key=lambda m: (m.is_open, m.ts, m.seq),
            ):
                if excess <= 0:
                    break
                excess -= len(self._row(mark.seq).encode()) + ROW_OVERHEAD
                dropped.add(mark.seq)
        self.index.note_lost((self.index.marks[s] for s in dropped), self.clock())
        self.index.remove_where(lambda m: m.seq not in dropped)
        self.counters["trimmed_rows"] += len(dropped)
        return len(dropped)

    def _build(self) -> dict[str, Any]:
        self._fresh_rows()
        marks = [self._row(seq) for seq in self.index.marks]
        used = {
            r
            for m in self.index.marks.values()
            for r in (m.router, *(m.peers or ()))
            if r is not None
        }
        if len(used) < len(self._routers):
            # compact the table (rows of the dropped routers are re-packed)
            self._routers = [r for r in self._routers if r in used]
            self._rix = {r: i for i, r in enumerate(self._routers)}
            self._rows.clear()
            marks = [self._row(seq) for seq in self.index.marks]
        return {
            "saved_at": round(self.clock(), 3),
            "stop": self.stop_reason,
            "next_seq": self.index.next_seq,
            "routers": list(self._routers),
            "marks": marks,
            "coverage": [list(pair) for pair in self.coverage],
            "checkpoints": list(self.checkpoints),
            "state": dict(sorted(self.state.items())),
            # 1.2 (1.52.0)
            "seen": {
                rid: [s.pack() for s in segs]
                for rid, segs in sorted(self.seen.items())
                if segs
            },
            "clients_cov": [list(pair) for pair in self.clients_cov],
            "lost": {q: round(v, 3) for q, v in sorted(self.index.lost.items())},
        }

    def payload(self) -> dict[str, Any]:
        """Data of the store (called by HA at write time, in the loop)."""
        self._pending = False
        payload = self._build()
        size = store_bytes(payload)
        if size > self.max_bytes:
            target = int(self.max_bytes * (1 - TRIM_HEADROOM))
            if self._trim(size - target):
                payload = self._build()
                size = store_bytes(payload)
        if size > self.max_bytes:
            self.counters["save_over_size"] += 1
            _LOGGER.warning("Time Machine store over its size limit; not written")
            return dict(self._last_good or {})
        self.last_bytes = size
        self.counters["writes"] += 1
        self.index.changed = False
        self._last_good = payload
        return payload

    # -- writes --------------------------------------------------------------------------

    def schedule(self, delay: float = SAVE_DELAY_S) -> None:
        """Arm one delayed write (none while one is pending or after close).

        ``delay=0`` (forget, clear, HA stop) re-arms a pending write so it
        happens now; HA's ``async_delay_save`` replaces the pending timer.
        """
        if self._store is None or self.closed or (self._pending and delay > 0):
            return
        self._pending = True
        self._store.async_delay_save(self.payload, delay)

    async def async_remove_copies(self) -> int:
        """Delete the ``.bak`` / ``.corrupt.*`` copies of the file (review
        K4: after client data was deleted no old copy keeps it)."""
        store = self._store or core_store.create_store(
            self.hass,
            TIME_MACHINE_STORE_VERSION,
            TIME_MACHINE_STORE_KEY,
            minor_version=TIME_MACHINE_STORE_MINOR_VERSION,
            migrate=_migrate,
            private=True,
            atomic_writes=True,
        )
        removed = await core_store.async_remove_copies(
            self.hass, store, TIME_MACHINE_STORE_KEY
        )
        self.counters["copies_removed"] += removed
        return removed

    async def async_flush(self, stop: str | None = None) -> None:
        """Write now (switched off, last router gone); never raises."""
        if self._store is None:
            return
        self.stop_reason = stop
        try:
            await self._store.async_save(self.payload())
        except Exception as err:  # noqa: BLE001 - HA's final write retries
            _LOGGER.warning("Time Machine store not written (%s)", type(err).__name__)

    # -- coverage and checkpoints ------------------------------------------------------

    def cover_from(self, start: float) -> None:
        """The index is live from ``start`` on."""
        self.coverage.append([start, None])
        self.coverage = self.coverage[-COVERAGE_MAX:]

    def cover_until(self, end: float) -> None:
        """The index stopped at ``end`` (closes an open coverage pair)."""
        for pair in self.coverage:
            if pair[1] is None:
                pair[1] = max(float(pair[0] or 0), end)

    def prune_meta(self, now: float, retention_s: float) -> None:
        """Coverage pairs and checkpoints older than the retention go."""
        cutoff = now - retention_s
        self.coverage = [
            p for p in self.coverage if p[1] is None or float(p[1]) >= cutoff
        ]
        self.clients_cov = [
            p for p in self.clients_cov if p[1] is None or float(p[1]) >= cutoff
        ]
        for rid in list(self.seen):
            kept = [s for s in self.seen[rid] if s.end is None or s.end >= cutoff]
            if kept:
                self.seen[rid] = kept
            else:
                del self.seen[rid]
        keep: list[str] = []
        day = start = 0
        for row in reversed(self.checkpoints):
            ts = int(row.split("|", 1)[0]) / 1000
            reason = row.split("|", 2)[1]
            if ts < cutoff:
                continue
            if reason == "day":
                day += 1
                if day > CHECKPOINTS_DAY_MAX:
                    continue
            else:
                start += 1
                if start > CHECKPOINTS_START_MAX:
                    continue
            keep.append(row)
        self.checkpoints = list(reversed(keep))

    # -- followed stretches and client recording (1.2) ----------------------------

    def seen_current(self, rid: str | None) -> Segment | None:
        """The open stretch of a router (None: not followed now)."""
        segs = self.seen.get(rid or "")
        return segs[-1] if segs and segs[-1].is_open else None

    def seen_open(self, rid: str, now: float) -> Segment:
        """The open stretch of a router, a new one from ``now`` if none."""
        seg = self.seen_current(rid)
        if seg is None:
            seg = Segment(start=now)
            segs = self.seen.setdefault(rid, [])
            segs.append(seg)
            del segs[:-SEEN_MAX]
        return seg

    def seen_close(self, rid: str | None, end: float) -> None:
        """A router is no longer followed from ``end`` on."""
        seg = self.seen_current(rid)
        if seg is not None:
            seg.end = max(seg.start, end)

    def seen_close_all(self, end: float) -> None:
        """No router is followed from ``end`` on (stop, restart)."""
        for rid in list(self.seen):
            self.seen_close(rid, end)

    def seen_split(
        self, rid: str, now: float, *, parent: str = "", role: str = ""
    ) -> Segment:
        """End the open stretch at ``now`` and start the next one (a radio
        appeared without a mark, or the base rolls forward). A settled
        uplink and role go on as ``parent`` / ``role``: the engine's current
        state, not the old stretch's base (marks changed it since)."""
        old = self.seen_current(rid)
        self.seen_close(rid, now)
        seg = self.seen_open(rid, now)
        if old is not None and old.topo_at is not None and role:
            seg.topo_at, seg.parent, seg.role = now, parent, role
        return seg

    def seen_restart(self, now: float, topology: Mapping[str, tuple[str, str]]) -> None:
        """The whole history was cleared: followed stretches start anew;
        ``topology`` holds the engine's settled ``(parent, role)`` per
        router (they go on: the debounce does not see them again until
        they change)."""
        seen: dict[str, list[Segment]] = {}
        for rid in list(self.seen):
            old = self.seen_current(rid)
            if old is None:
                continue
            seg = Segment(start=now)
            parent, role = topology.get(rid, ("", ""))
            if old.topo_at is not None and role:
                seg.topo_at, seg.parent, seg.role = now, parent, role
            seen[rid] = [seg]
        self.seen = seen

    def clients_from(self, start: float) -> None:
        """The client recorder records from ``start`` on."""
        if any(p[1] is None for p in self.clients_cov):
            return
        self.clients_cov.append([start, None])
        self.clients_cov = self.clients_cov[-COVERAGE_MAX:]

    def clients_until(self, end: float) -> None:
        """The client recorder stopped at ``end``."""
        for pair in self.clients_cov:
            if pair[1] is None:
                pair[1] = max(float(pair[0] or 0), end)

    def add_checkpoint(self, row: str) -> bool:
        """Append one packed checkpoint (False if it does not validate)."""
        if not _CHECKPOINT.fullmatch(row):
            return False
        self.checkpoints.append(row)
        return True

    def stats(self) -> dict[str, Any]:
        """Sizes and counters (no ids)."""
        return {
            "bytes": self.last_bytes,
            "max_bytes": self.max_bytes,
            "coverage": len(self.coverage),
            "checkpoints": len(self.checkpoints),
            **self.counters,
        }


def _pairs(raw: Any) -> list[list[float | None]]:
    """``[start, end|None]`` pairs as stored (valid ones, the newest
    ``COVERAGE_MAX``)."""
    out: list[list[float | None]] = []
    for pair in raw if isinstance(raw, list) else []:
        if (
            isinstance(pair, list)
            and len(pair) == 2
            and _finite(pair[0])
            and (pair[1] is None or _finite(pair[1]))
        ):
            out.append([float(pair[0]), pair[1]])
    return out[-COVERAGE_MAX:]


__all__ = [
    "CHECKPOINTS_DAY_MAX",
    "CHECKPOINTS_START_MAX",
    "SAVE_DELAY_S",
    "SEEN_MAX",
    "STOP_DISABLED",
    "STOP_HA",
    "STOP_UNLOADED",
    "STORE_MAX_BYTES",
    "LoadResult",
    "Segment",
    "TimeMachineStore",
    "pack_radios",
    "store_bytes",
    "unpack_radios",
]
