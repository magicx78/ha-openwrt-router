"""Network Time Machine, Phase C: client sessions from Client Stability.

Plan ``docs/plans/2026-11-21-network-time-machine.md`` §5.3, §9 (Phase C),
F2/F3. Runs only while the Time Machine *and* its own client switch
(``time_machine_clients``, default off) are on. It observes the
transitions the Client Stability history books anyway
(``ClientStability.add_transition_listener``; no router call, no poll of
its own) and turns them into marks of the own index:

* ``start`` opens a ``client_session`` (router, band); ``move`` (roaming,
  also across routers) closes it and opens the next one, plus a
  ``client_roam`` with the routers before/after as ``peers``; ``end``
  closes it (``closed`` when the moment is known, else ``unknown``) and
  adds a ``client_disconnect`` with the class as code; ``gap`` / ``blip``
  only count on the open session (a measurement gap is no disconnect);
  ``resume`` without an open session opens one (``resumed`` = 1).
* At attach (start, switch on, HA restart) every client the history holds
  as online gets a session from now on (``resumed`` = 1, ``derived``):
  sessions open before a restart were closed as "end unknown".

**Privacy.** A client is stored only as the 16 hex of its pseudonym
``tmc_…`` (HMAC with the module key ``time_machine`` / ``pseudonym``); no
MAC, IP, host name or SSID reaches the store. The pseudonym -> MAC map is
held in memory only, so administrators can see the current host name while
Client Stability still knows the client (F2); the history itself has no
names. A client forgotten by Client Stability (exclusion) is forgotten here
too. The per-client daily cap and the client quota of ``tm_marks`` keep a
storm of one client or of many from filling the store or touching the
infrastructure marks.
"""

from __future__ import annotations

import contextlib
import logging
import math
from typing import Any, Final

from .tm_marks import END_CLOSED, END_OPEN, END_UNKNOWN

_LOGGER = logging.getLogger(__name__)

CLIENT_PREFIX: Final = "tmc_"
TS_SKEW_MAX_S: Final = 86_400.0
_ONLINE: Final = frozenset({"online", "grace"})
# Pseudonym -> MAC (memory only, for the host name): every client with an
# open session plus this many recently seen others (review K9).
MACS_RECENT_MAX: Final = 512
_BAND_NUM: Final = {"2.4g": 2.4, "5g": 5, "6g": 6}


def band_num(band: Any) -> float | int | None:
    """2.4 / 5 / 6 for a band spelling, else None."""
    from .client_history import band_key

    return _BAND_NUM.get(band_key(band) or "")


class ClientRecorder:
    """Client sessions of one running Time Machine engine."""

    def __init__(self, engine: Any, key: bytes) -> None:
        """Nothing attached yet."""
        self.engine = engine
        self._key = key
        self.attached_to: Any = None
        self._remove: Any = None
        self._open: dict[str, int] = {}  # pseudonym hex -> open session seq
        # memory only: pseudonym hex -> MAC, oldest first (bounded, K9)
        self._macs: dict[str, str] = {}
        self.counters: dict[str, int] = {"transitions": 0, "skipped": 0}
        for mark in engine.index.open_marks():
            if mark.kind == "client_session" and mark.client is not None:
                self._open[mark.client] = mark.seq

    @property
    def attached(self) -> bool:
        """Observing a running Client Stability."""
        return self.attached_to is not None

    # -- attach --------------------------------------------------------------------------

    def attach(self) -> None:
        """Observe the running Client Stability (again after it was replaced)."""
        from .client_engine import async_get_client_engine

        cs = async_get_client_engine(self.engine.hass)
        if cs is self.attached_to:
            return
        self.detach()
        if cs is None or not hasattr(cs, "add_transition_listener"):
            return
        self._remove = cs.add_transition_listener(self)
        self.attached_to = cs
        # 1.52.0: clients are recorded from here on (``clients_cov``)
        self.engine.store.clients_from(self.engine.clock())
        self._resume_online(cs)

    def detach(self) -> None:
        """Stop observing (stored marks stay)."""
        if self._remove is not None:
            with contextlib.suppress(Exception):  # a closed engine removes its own
                self._remove()
            self.engine.store.clients_until(self.engine.clock())
        self._remove = None
        self.attached_to = None
        self._macs.clear()

    def reset_open(self) -> None:
        """All open sessions were closed by the engine."""
        self._open.clear()

    def _resume_online(self, cs: Any) -> None:
        now = self.engine.clock()
        history = cs.history
        for mac in history.macs():
            client = self.pseudonym(mac)
            if client is None:
                continue
            self._remember(client, mac)
            live = history.live(mac)
            if live is None or live.state not in _ONLINE or client in self._open:
                continue
            self._open_session(
                client,
                self._resume_start(live, now),
                self.engine.router_id(live.ap),
                live.band,
                resumed=True,
                derived=True,
            )
        self.engine.store.schedule()

    def _resume_start(self, live: Any, now: float) -> float:
        """Start of a session already running when the recording begins.

        Client Stability's own start when it knows it and it lies while the
        Time Machine was running; else ``now``. Before 1.51.0 every resumed
        session began at ``now``: hundreds shared one millisecond (review S3).
        """
        start = getattr(live, "session_start", None)
        if (
            getattr(live, "session_start_known", False) is True
            and isinstance(start, int | float)
            and not isinstance(start, bool)
            and math.isfinite(start)
            and self.engine._live_from <= start <= now
        ):
            return float(start)
        return now

    # -- identity ------------------------------------------------------------------------

    def _remember(self, client: str, mac: str) -> None:
        """Keep the MAC of a client seen now; forget the oldest closed ones."""
        macs = self._macs
        macs.pop(client, None)
        macs[client] = mac
        extra = len(macs) - len(self._open) - MACS_RECENT_MAX
        if extra <= 0:
            return
        for old in [c for c in macs if c not in self._open][:extra]:
            del macs[old]

    def pseudonym(self, mac: Any) -> str | None:
        """16 hex of ``tmc_…`` (None for something that is no MAC)."""
        from .core_masking import pseudonymise_identifier

        try:
            return pseudonymise_identifier("client", mac, self._key)[4:]
        except (TypeError, ValueError):
            return None

    def name_of(self, client: str | None) -> str | None:
        """Current host name while Client Stability knows the client (F2)."""
        mac = self._macs.get(client or "")
        cs = self.attached_to
        if mac is None or cs is None:
            return None
        live = cs.history.live(mac)
        name = getattr(live, "hostname", None) if live is not None else None
        return name if isinstance(name, str) and name else None

    # -- transitions ---------------------------------------------------------------------

    def _ts(self, value: Any) -> float:
        now = self.engine.clock()
        if (
            not isinstance(value, int | float)
            or isinstance(value, bool)
            or not math.isfinite(value)
            or abs(value - now) > TS_SKEW_MAX_S
        ):
            return now
        return float(value)

    def _open_session(
        self,
        client: str,
        ts: float,
        router: str | None,
        band: Any,
        *,
        resumed: bool = False,
        roam: bool = False,
        derived: bool = False,
    ) -> None:
        params: dict[str, Any] = {}
        num = band_num(band)
        if num is not None:
            params["band"] = num
        if resumed:
            params["resumed"] = 1
        if roam:
            params["roam"] = 1
        mark = self.engine.index.add(
            ts=ts,
            kind="client_session",
            router=router,
            client=client,
            code="session",
            end_state=END_OPEN,
            params=params,
            derived=derived,
        )
        if mark is not None:
            self._open[client] = mark.seq

    def transition(self, mac: str, tr: Any, band: Any) -> None:
        """One transition of the Client Stability history (sync, short)."""
        if self.engine.closed or not self.engine.clients_wanted:
            return
        from .client_history import (
            TR_BLIP,
            TR_END,
            TR_GAP,
            TR_MOVE,
            TR_RESUME,
            TR_START,
        )

        client = self.pseudonym(mac)
        if client is None:
            self.counters["skipped"] += 1
            return
        self.counters["transitions"] += 1
        self._remember(client, mac)
        index = self.engine.index
        ts = self._ts(tr.ts)
        router = self.engine.router_id(tr.ap)
        open_seq = self._open.get(client)
        if index.get(open_seq) is None or not index.get(open_seq).is_open:
            self._open.pop(client, None)
            open_seq = None
        if tr.kind == TR_START:
            if open_seq is not None:
                index.close(open_seq, ts, END_UNKNOWN)
            self._open_session(client, ts, router, band)
        elif tr.kind == TR_MOVE:
            before = index.get(open_seq)
            if before is not None and before.router == router:
                return
            if before is not None:
                index.close(open_seq, ts, END_CLOSED)
                index.add(
                    ts=ts,
                    kind="client_roam",
                    router=router,
                    client=client,
                    code="roam",
                    peers=(before.router, router),
                )
            self._open_session(
                client,
                ts,
                router,
                band,
                roam=before is not None,
                resumed=before is None,
            )
        elif tr.kind == TR_END:
            timed = bool(getattr(tr, "timed", True))
            if open_seq is not None:
                index.close(open_seq, ts, END_CLOSED if timed else END_UNKNOWN)
                self._open.pop(client, None)
            index.add(
                ts=ts,
                kind="client_disconnect",
                router=router,
                client=client,
                code=getattr(tr, "cls", None) or "unknown",
                params={"timed": timed},
                derived=not timed,
            )
        elif tr.kind == TR_GAP:
            index.bump(open_seq, "gaps")
        elif tr.kind == TR_BLIP:
            index.bump(open_seq, "blips")
        elif tr.kind == TR_RESUME and open_seq is None:
            self._open_session(client, ts, router, band, resumed=True)
        else:
            return
        self.engine.store.schedule()

    def forgot(self, mac: str) -> None:
        """Client Stability forgot a client (exclusion): forget it here too."""
        client = self.pseudonym(mac)
        if client is None:
            return
        self._open.pop(client, None)
        self._macs.pop(client, None)
        if self.engine.index.forget_client(client):
            self.engine.store.schedule()

    def forget_mac(self, mac: str) -> int:
        """The forget service: every mark of one client (count)."""
        client = self.pseudonym(mac)
        if client is None:
            return 0
        return self.forget_client(client)

    def forget_client(self, client: str) -> int:
        """The forget service by pseudonym (16 hex): every mark (count).

        A client still connected is recorded again from its next transition
        (a new session at its next connect or move, review K5).
        """
        self._open.pop(client, None)
        self._macs.pop(client, None)
        return self.engine.index.forget_client(client)

    def stats(self) -> dict[str, Any]:
        """Counts only."""
        return {
            "attached": self.attached,
            "open_sessions": len(self._open),
            **self.counters,
        }


__all__ = ["CLIENT_PREFIX", "ClientRecorder", "band_num"]
