"""Self-Healing: the link to the Configuration Manager (package G).

Developer document: ``docs/self-healing.md`` §7.2. Release 1.53.0 is
Observe only: nothing here calls a router, runs a restore or changes a
configuration. The one write is the core's own: a comparison over a damaged
or deleted artifact marks that version corrupt or missing (below).

What it does: it turns what the Configuration Manager ALREADY holds into the
facts Self-Healing needs, and nothing more.

* the version index of the core (``core.versions.records()``, in memory):
  which versions exist, when they were taken, their status, validation,
  archive checksum and content hash;
* optionally the comparison of two STORED versions
  (``ConfigurationApi.async_compare`` with two backup references - it reads
  the stored artifacts, never the live configuration). Over a damaged
  artifact (a wrong checksum or size) the core's version store marks that
  version ``corrupt``, over a deleted artifact file ``missing``; it saves its
  index once and fires ``configuration.integrity_failed`` (once per damaged
  version; no router call). Nothing else is written.

Out of it come:

* :attr:`ConfigLink.config_fact` - ``heal_playbooks.ConfigFact`` for playbook
  F (``diff_proven``, ``changed_areas``, ``changed_at``, the version a
  restore would use, whether that version is a restorable archive);
* the preflight's configuration facts (:attr:`ConfigLink.backups` in the
  exact shape of ``heal_preflight``, :attr:`ConfigLink.config_captured`,
  :attr:`ConfigLink.backup_present` with verified / unverified / age, and
  :attr:`ConfigLink.service_config_unapplied`).

Rules (strict, from earlier reviews): unknown stays unknown and never
becomes "safe"; "no version in a readable index" is a known "no", an
unreadable index is unknown; collectors never raise, they report unknown with
a reason code (:data:`REASONS`); frozen dataclasses validate again on
``dataclasses.replace``.

**Window.** Only changes inside :data:`CONFIG_CHANGE_WINDOW_S` (24 h) before
the incident start count. The newest version seen strictly before the start
is compared with the newest version seen at or before (start - window), so
the comparison shows everything that changed inside the window (an earlier
change in one area is not hidden by a later one elsewhere). A change is
proven only when the store shows that every change it compares happened
inside the window; anything else is unknown with a reason code.

**Never a known "no change".** The store can never prove that nothing
changed: a change may not have been captured yet, an A -> B -> A may have
left no version of B, a new content may have been captured exactly at the
start. So ``diff_proven`` from this module is True or unknown, never False
(the same rule as ``config_change_24h``). When the store shows no change in
the window the reason is ``no_change_seen``; :attr:`Selection.no_change_seen`
is a display flag for that, never a fact.

**Time.** A stored comparison only says that the configuration changed
somewhere between the last observation of the old content and the first
observation of the new one. ``changed_at`` is that LATER bound of the LAST
change in the window (the time it was first seen in the store);
``changed_after`` is the earlier one. Playbook F takes a change as the
incident's cause only when ``changed_at < started_at``; with the later bound
that implies the real change time is strictly before the start too. The
earlier bound would not (see the document, §7.2).

**What it can never say.** The Configuration Manager reads the SAVED UCI
configuration only; it never sees what is running. So
``service_config_unapplied`` is always unknown (``running_config_not_tracked``)
and a service restart stays blocked by the preflight. A restore is a dry run
at best: :attr:`ConfigLink.restore_executable` is always False.

No router address, host name, client name, secret or configuration content is
kept here: only core ids, codes, counts and times. Content hashes are compared
and never put into an output.
"""

from __future__ import annotations

import dataclasses
import logging
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final

from . import heal_catalog as hc
from . import heal_playbooks as hb
from .core_models import ROUTER_ID_PREFIX, is_valid_id
from .heal_model import TIME_MAX
from .heal_preflight import SNAPSHOT_MAX_AGE_S, Fact, known, unknown

_LOGGER = logging.getLogger(__name__)

LINK_VERSION: Final = 1
# The module the stored comparison is asked for (heal_engine.MODULE; a test
# compares them - heal_engine pulls in Home Assistant).
ACTOR_MODULE: Final = "self_healing"
# The change window: only changes in the 24 h before the incident start (or
# the snapshot) count, for playbook F and for heal_policy ``config_change_24h``.
CONFIG_CHANGE_WINDOW_S: Final = 86400
# at most this many versions per router are kept (newest)
ROWS_MAX: Final = 1000
# the preflight's bound of the backups fact (heal_preflight _TUPLE_MAX)
FACT_ROWS_MAX: Final = 64

SOURCE_VERSIONS: Final = "core.versions"
SOURCE_RECORDS: Final = "core.versions.records"
SOURCE_RUNNING: Final = "config_manager.saved_config_only"

# Version status and validation codes (core_models VersionStatus /
# ValidationStatus values) and backup types (BackupType values).
USABLE_STATUSES: Final = ("ok", "partial")
DIFF_STATUS: Final = "ok"
DIFF_VALIDATIONS: Final = ("valid", "unverified")
BACKUP_TYPES: Final = ("full_archive", "uci_snapshot", "partial")

# The values of the preflight summary facts.
CAPTURED_VALUES: Final = ("current", "outdated", "none")
BACKUP_VALUES: Final = ("verified", "unverified", "outdated", "none")

RESTORE_STATEMENT: Final = "restore_unsupported_dry_run_only"

# Every reason code this module reports (closed; a test pins it literally).
REASONS: Final = (
    "core_not_running",
    "versions_not_loaded",
    "source_error",
    "invalid_router_id",
    "no_usable_version",
    "window_base_missing",
    "change_too_old",
    "no_change_seen",
    "changed_and_reverted",
    "change_may_predate_window",
    "ambiguous_order",
    "diff_not_read",
    "diff_other_versions",
    "diff_failed",
    "diff_unreadable",
    "diff_truncated",
    "diff_area_unknown",
    "config_one_sided",
    "secrets_not_comparable",
    "snapshot_time_ahead",
    "backup_time_ahead",
    "running_config_not_tracked",
    "restore_dry_run_not_run",
    RESTORE_STATEMENT,
)

REASON_TEXT_DE: Final[Mapping[str, str]] = MappingProxyType(
    {
        "core_not_running": "Der Enterprise-Core läuft nicht.",
        "versions_not_loaded": "Der Versionsindex ist noch nicht geladen.",
        "source_error": "Der Versionsindex ist nicht lesbar.",
        "invalid_router_id": "Die Router-Kennung ist ungültig.",
        "no_usable_version": "Keine brauchbare Version im Speicher.",
        "window_base_missing": (
            "Keine Version vor dem Beginn des Zeitfensters; ob sich im "
            "Zeitfenster etwas geändert hat, ist nicht belegt."
        ),
        "change_too_old": (
            "Im Zeitfenster wurde keine Version gesehen; eine Änderung, falls "
            "es eine gab, ist älter oder nicht belegt."
        ),
        "no_change_seen": (
            "Im Speicher ist im Zeitfenster keine Änderung zu sehen; das "
            "belegt nicht, dass sich nichts geändert hat (eine Änderung kann "
            "noch nicht gesichert oder schon zurückgenommen sein)."
        ),
        "changed_and_reverted": (
            "Im Zeitfenster wurde ein anderer Inhalt gesehen, am Ende aber "
            "wieder der alte; es hat sich etwas geändert und wurde "
            "zurückgenommen."
        ),
        "change_may_predate_window": (
            "Die erste Änderung kann vor dem Zeitfenster liegen; der "
            "Vergleich ist nicht auf das Zeitfenster begrenzt."
        ),
        "ambiguous_order": (
            "Zwei Versionen mit verschiedenem Inhalt tragen dieselbe Zeit; die "
            "Reihenfolge ist unklar."
        ),
        "diff_not_read": "Der Vergleich der gespeicherten Versionen wurde nicht gelesen.",
        "diff_other_versions": "Der Vergleich gehört zu anderen Versionen.",
        "diff_failed": "Der Vergleich der gespeicherten Versionen ist gescheitert.",
        "diff_unreadable": "Der Vergleich hat eine unerwartete Form.",
        "diff_truncated": "Der Vergleich ist abgeschnitten.",
        "diff_area_unknown": "Eine Änderung hat keinen bekannten Bereich.",
        "config_one_sided": (
            "Eine Konfiguration liegt nur in einer der beiden Versionen vor; "
            "der Vergleich ist unvollständig."
        ),
        "secrets_not_comparable": (
            "Geheime Werte sind nicht vergleichbar (anderer Installationsschlüssel)."
        ),
        "snapshot_time_ahead": "Die neueste Version liegt in der Zukunft.",
        "backup_time_ahead": "Die neueste geprüfte Sicherung liegt in der Zukunft.",
        "running_config_not_tracked": (
            "Der Configuration Manager liest nur die gespeicherte Konfiguration; "
            "ob sie läuft, weiß er nicht."
        ),
        "restore_dry_run_not_run": (
            "Der Probelauf der Wiederherstellung wurde nicht ausgeführt (er "
            "spricht mit dem Router)."
        ),
        RESTORE_STATEMENT: (
            "Eine Wiederherstellung ist nicht ausführbar: es gibt nur einen "
            "Probelauf, wiederherstellen geht nur von Hand."
        ),
    }
)

# Codes and the defence against addresses: the same rules as heal_preflight
# (a test compares the results).
_CODE_RE: Final = re.compile(r"[a-z][a-z0-9_.:|/-]{0,95}")
_IPV4_RE: Final = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_MAC_RE: Final = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
_HASH_RE: Final = re.compile(r"[0-9a-f]{64}")
_RISK_RANK: Final = {risk: rank for rank, risk in enumerate(hb.CHANGE_RISKS)}
_NOT_COMPARABLE: Final = "not_comparable"
# ChangeKind values besides not_comparable (core_models; a test compares).
_KINDS: Final = ("added", "removed", "modified", "reordered")


class ConfigLinkError(ValueError):
    """Bad input to the pure part (the message names the field, never a value)."""


def _fail(what: str) -> ConfigLinkError:
    return ConfigLinkError(f"invalid {what}")


# ---------------------------------------------------------------------------
# Lenient readers (data from other modules is untrusted)
# ---------------------------------------------------------------------------


def _time(value: Any) -> float | None:
    """Seconds since the epoch: a number in range or an AWARE datetime."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        out = float(value)
    else:
        stamp = getattr(value, "timestamp", None)
        if not callable(stamp) or getattr(value, "tzinfo", None) is None:
            return None
        try:
            out = float(stamp())
        except (TypeError, ValueError, OverflowError):
            return None
    if not math.isfinite(out) or not 0.0 <= out <= TIME_MAX:
        return None
    return out


def _code(value: Any) -> str:
    """A code the preflight can carry, else ``unknown`` (heal_preflight)."""
    value = getattr(value, "value", value)
    if (
        isinstance(value, str)
        and _CODE_RE.fullmatch(value) is not None
        and _IPV4_RE.search(value) is None
        and _MAC_RE.search(value) is None
        and "::" not in value
    ):
        return str(value)
    return "unknown"


def _member(value: Any, choices: Iterable[str]) -> str | None:
    value = getattr(value, "value", value)
    if not isinstance(value, str):
        return None
    for choice in choices:
        if choice == value:
            return choice
    return None


def _backup_id(value: Any) -> str | None:
    if isinstance(value, str) and is_valid_id(value, hc.BACKUP_ID_PREFIX):
        return str(value)
    return None


# ---------------------------------------------------------------------------
# Inputs: what the Configuration Manager holds
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class VersionRow:
    """One version of the index, normalised (anything odd becomes None).

    ``created_at`` / ``last_seen_at``: when the content was stored and, for
    a deduplicated repeat, last seen again (epoch seconds; a ``last_seen_at``
    before ``created_at`` is dropped). ``status`` / ``validation``: the codes
    the preflight reads (``unknown`` for anything that is no code).
    ``has_checksum``: the archive carries a sha256 (only a full archive can
    be restored by hand). ``content_hash``: the UCI content hash, compared
    only, never put into an output.
    """

    backup_id: Any = None
    created_at: Any = None
    last_seen_at: Any = None
    status: Any = None
    validation: Any = None
    has_checksum: Any = None
    content_hash: Any = None
    backup_type: Any = None

    def __post_init__(self) -> None:
        """Normalise (never raises)."""
        put = object.__setattr__
        put(self, "backup_id", _backup_id(self.backup_id))
        created = _time(self.created_at)
        put(self, "created_at", created)
        seen = _time(self.last_seen_at)
        put(
            self,
            "last_seen_at",
            seen
            if seen is not None and created is not None and seen >= created
            else None,
        )
        put(self, "status", _code(self.status))
        put(self, "validation", _code(self.validation))
        put(self, "has_checksum", self.has_checksum is True)
        put(
            self,
            "content_hash",
            self.content_hash
            if isinstance(self.content_hash, str)
            and _HASH_RE.fullmatch(self.content_hash)
            else None,
        )
        put(self, "backup_type", _member(self.backup_type, BACKUP_TYPES))

    @property
    def complete(self) -> bool:
        """It has an id and a time (else the index row is not counted)."""
        return self.backup_id is not None and self.created_at is not None

    @property
    def usable(self) -> bool:
        """Status ok and validation valid or unverified (core ``usable``)."""
        return self.status == DIFF_STATUS and self.validation in DIFF_VALIDATIONS

    @property
    def comparable(self) -> bool:
        """It can take part in a stored comparison (usable, with content)."""
        return self.complete and self.usable and self.content_hash is not None

    @property
    def restorable_by_hand(self) -> bool:
        """A usable full archive with a checksum (LuCI / sysupgrade -r)."""
        return (
            self.usable
            and self.has_checksum is True
            and self.backup_type == "full_archive"
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class ConfigKnowledge:
    """The version index of one router as the core holds it in memory.

    ``rows`` None: the index is not readable (``reason`` says why; a code
    of :data:`REASONS`, anything else becomes ``source_error``). A readable
    index without versions is ``rows=()`` - a known "nothing stored".
    """

    router_id: Any
    rows: Any = None
    reason: Any = None

    def __post_init__(self) -> None:
        """Normalise (never raises)."""
        put = object.__setattr__
        if not isinstance(self.router_id, str) or not is_valid_id(
            self.router_id, ROUTER_ID_PREFIX
        ):
            put(self, "router_id", None)
            put(self, "rows", None)
            put(self, "reason", "invalid_router_id")
            return
        put(self, "router_id", str(self.router_id))
        if self.rows is None or isinstance(self.rows, str | bytes | Mapping):
            reason = self.reason if self.rows is None else "source_error"
            put(self, "rows", None)
            put(
                self,
                "reason",
                reason
                if isinstance(reason, str) and reason in REASONS
                else "source_error",
            )
            return
        try:
            items = list(self.rows)
        except Exception:  # noqa: BLE001 - an odd container is unreadable
            put(self, "rows", None)
            put(self, "reason", "source_error")
            return
        rows: dict[str, VersionRow] = {}
        for item in items:
            if type(item) is not VersionRow:
                continue
            row = dataclasses.replace(item)  # validated again
            if row.complete and row.backup_id not in rows:
                rows[str(row.backup_id)] = row
        ordered = sorted(rows.values(), key=lambda r: (r.created_at, r.backup_id))
        put(self, "rows", tuple(ordered[-ROWS_MAX:]))
        put(self, "reason", None)

    @property
    def readable(self) -> bool:
        """The index could be read (it may be empty)."""
        return self.rows is not None


@dataclass(frozen=True, kw_only=True, slots=True)
class StoredDiff:
    """The comparison of two STORED versions, normalised.

    ``proven`` True: comparable changes in ``areas`` (complete: every
    change has a known area, nothing truncated, every secret comparable).
    False: the comparison shows no change (``areas`` empty); the link turns
    that into an unknown ``no_change_seen``, never a known "no".
    None: unknown (``reason`` required).
    """

    base_id: Any
    other_id: Any
    proven: Any = None
    areas: Any = None
    change_risk: Any = None
    reason: Any = None

    def __post_init__(self) -> None:
        """Normalise; an inconsistent combination becomes unknown."""
        put = object.__setattr__
        put(self, "base_id", _backup_id(self.base_id))
        put(self, "other_id", _backup_id(self.other_id))
        proven = self.proven if isinstance(self.proven, bool) else None
        areas: frozenset[str] | None = None
        reason = self.reason if isinstance(self.reason, str) else None
        if proven is not None:
            try:
                raw = frozenset(self.areas) if self.areas is not None else None
            except TypeError:
                raw = None
            if raw is None or not raw <= hb.CONFIG_AREAS or bool(raw) is not proven:
                proven, reason = None, "diff_unreadable"
            else:
                areas = frozenset(a for a in hb.CONFIG_AREAS if a in raw)
        if (
            self.base_id is None
            or self.other_id is None
            or self.base_id == self.other_id
        ):
            proven, areas, reason = None, None, "diff_unreadable"
        risk = _member(self.change_risk, hb.CHANGE_RISKS) if proven is True else None
        if proven is not None:
            reason = None
        elif reason not in REASONS:
            reason = "diff_unreadable"
        put(self, "proven", proven)
        put(self, "areas", areas)
        put(self, "change_risk", risk)
        put(self, "reason", reason)


def stored_diff_from(diff: Any, base_id: str, other_id: str) -> StoredDiff:
    """Normalise a core ``ConfigDiff`` of the stored versions ``base_id`` ->
    ``other_id`` (never raises).

    Unknown (``proven`` None) when the diff is not of these two STORED
    versions, is truncated, lists a config found on one side only
    (``config_one_sided``), has secrets that cannot be compared (another
    installation key) or has a comparable change without a known area.
    ``change_risk`` is the highest risk, None if any risk is unknown.
    """
    try:
        return _stored_diff_from(diff, base_id, other_id)
    except Exception as err:  # noqa: BLE001 - an odd diff is unreadable
        _LOGGER.debug("Self-Healing: stored diff unreadable (%s)", type(err).__name__)
        return StoredDiff(base_id=base_id, other_id=other_id, reason="diff_unreadable")


def _ref_backup(ref: Any) -> str | None:
    if getattr(ref, "router_id", None) is not None:
        return None  # a LIVE reference: never this module's
    return _backup_id(getattr(ref, "backup_id", None))


def _one_sided(change: Any) -> bool:
    """A config readable on one side only (the provider's whole-config mark:
    no section, no option), not a secret that cannot be compared."""
    return getattr(change, "section", None) == "" and (
        getattr(change, "option", None) is None
    )


def _stored_diff_from(diff: Any, base_id: str, other_id: str) -> StoredDiff:
    def unknown_diff(reason: str) -> StoredDiff:
        return StoredDiff(base_id=base_id, other_id=other_id, reason=reason)

    changes = getattr(diff, "changes", None)
    if not isinstance(changes, tuple | list):
        return unknown_diff("diff_unreadable")
    if (
        _ref_backup(getattr(diff, "base", None)) != base_id
        or _ref_backup(getattr(diff, "other", None)) != other_id
    ):
        return unknown_diff("diff_other_versions")
    if getattr(diff, "truncated", None) is not False:
        return unknown_diff("diff_truncated")
    kinds = [
        _member(getattr(change, "kind", None), (_NOT_COMPARABLE, *_KINDS))
        for change in changes
    ]
    if None in kinds:
        return unknown_diff("diff_unreadable")
    blind = [c for c, k in zip(changes, kinds, strict=True) if k == _NOT_COMPARABLE]
    if any(_one_sided(c) for c in blind):
        return unknown_diff("config_one_sided")
    if blind:
        return unknown_diff("secrets_not_comparable")
    areas: set[str] = set()
    risks: list[str | None] = []
    for change in changes:
        area = _member(getattr(change, "area", None), hb.CONFIG_AREAS)
        if area is None:
            return unknown_diff("diff_area_unknown")
        areas.add(area)
        risks.append(_member(getattr(change, "risk", None), hb.CHANGE_RISKS))
    risk = (
        None
        if not risks or None in risks
        else max(risks, key=lambda r: _RISK_RANK[str(r)])
    )
    return StoredDiff(
        base_id=base_id,
        other_id=other_id,
        proven=bool(areas),
        areas=frozenset(areas),
        change_risk=risk,
    )


# ---------------------------------------------------------------------------
# Which versions: the last change in the store (and its time bounds)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class VersionPair:
    """The change inside the window, as two versions and three bounds.

    ``base_id``: the newest version seen at or before the window start;
    ``other_id``: the newest version seen before the window end. Every
    change between them happened after ``first_changed_after`` (the last
    time the base content was seen before the first other content; at or
    after the window start). The LAST change happened in ``(changed_after,
    changed_at]``: ``changed_after`` is the last time the content before it
    was seen, ``changed_at`` the first time the final content was seen.
    ``plan_backup_id``: the version a restore to the content before the
    window's changes would use (the newest restorable archive of the base
    content right before the first change, else ``base_id``).
    """

    base_id: str
    other_id: str
    first_changed_after: float
    changed_after: float
    changed_at: float
    plan_backup_id: str
    plan_backup_restorable: bool

    def __post_init__(self) -> None:
        """Validate (derived data; a wrong value is a programming error)."""
        for name in ("base_id", "other_id", "plan_backup_id"):
            if _backup_id(getattr(self, name)) is None:
                raise _fail(f"pair.{name}")
        if self.base_id == self.other_id:
            raise _fail("pair.other_id")
        for name in ("first_changed_after", "changed_after", "changed_at"):
            if _time(getattr(self, name)) is None:
                raise _fail(f"pair.{name}")
        if not self.first_changed_after <= self.changed_after < self.changed_at:
            raise _fail("pair.changed_at")
        if not isinstance(self.plan_backup_restorable, bool):
            raise _fail("pair.plan_backup_restorable")


@dataclass(frozen=True, kw_only=True, slots=True)
class Selection:
    """Result of :func:`select_versions`.

    ``pair``: the change to compare (None: no change to compare).
    ``reason``: why it is unknown (None only when there is a pair).
    ``no_change_seen``: a DISPLAY flag - the store shows only the base content
    inside the window (reason ``no_change_seen``). It is never a fact: the
    store cannot prove that nothing changed.
    """

    latest: VersionRow | None  # the newest usable version (before the end)
    pair: VersionPair | None
    reason: str | None
    no_change_seen: bool = False
    window_end: float | None = None


def _check_cutoff(before: Any) -> float | None:
    if before is None:
        return None
    out = _time(before)
    if out is None:
        raise _fail("before")
    return out


def select_versions(knowledge: ConfigKnowledge, *, before: Any) -> Selection:
    """The configuration changes inside the window that ends at ``before``.

    The window is ``(before - CONFIG_CHANGE_WINDOW_S, before)``. Every
    comparable version is an observation of its content at ``created_at``
    and, if deduplicated, again at ``last_seen_at``; only observations
    strictly before ``before`` count. The base is the newest observation at
    or before the window start, the other end the newest observation. The
    store proves a change inside the window only when the base content was
    seen at or after the window start right before the first other content;
    see :data:`REASONS` for every other outcome. It never proves that
    nothing changed (``no_change_seen`` is unknown).
    """
    if type(knowledge) is not ConfigKnowledge:
        raise _fail("knowledge")
    end = _check_cutoff(before)
    if end is None:
        raise _fail("before")
    if knowledge.rows is None:
        return Selection(latest=None, pair=None, reason=knowledge.reason)
    start = end - CONFIG_CHANGE_WINDOW_S

    def unknown_sel(reason: str) -> Selection:
        return Selection(latest=latest, pair=None, reason=reason, window_end=end)

    usable = [r for r in knowledge.rows if r.usable and r.created_at < end]
    latest = max(usable, key=lambda r: (r.created_at, r.backup_id), default=None)
    obs: list[tuple[float, str, VersionRow]] = []
    for row in knowledge.rows:
        if not row.comparable:
            continue
        for t in dict.fromkeys((row.created_at, row.last_seen_at)):
            if t is not None and t < end:
                obs.append((float(t), str(row.backup_id), row))
    if not obs:
        return unknown_sel("no_usable_version")
    obs.sort(key=lambda o: (o[0], o[1]))
    b = max((i for i, o in enumerate(obs) if o[0] <= start), default=None)
    if b is None:
        return unknown_sel("window_base_missing")
    base_t, _bid, base = obs[b]
    contents_at: dict[float, set[str]] = {}
    for t, _i, row in obs:
        if t >= base_t:
            contents_at.setdefault(t, set()).add(str(row.content_hash))
    if any(len(c) > 1 for c in contents_at.values()):
        return unknown_sel("ambiguous_order")
    window = obs[b + 1 :]
    if not window:
        return unknown_sel("change_too_old")
    old = base.content_hash
    if all(o[2].content_hash == old for o in window):
        # what the store shows, not a proof (module docstring)
        return Selection(
            latest=latest,
            pair=None,
            reason="no_change_seen",
            no_change_seen=True,
            window_end=end,
        )
    final = obs[-1][2].content_hash
    if final == old:
        return unknown_sel("changed_and_reverted")
    f = next(i for i in range(b + 1, len(obs)) if obs[i][2].content_hash != old)
    first_after = obs[f - 1][0]
    if first_after < start:
        return unknown_sel("change_may_predate_window")
    i = len(obs) - 1
    while obs[i][2].content_hash == final:
        i -= 1
    plan = base
    j = f - 1
    while j >= 0 and obs[j][2].content_hash == old:
        if obs[j][2].restorable_by_hand:
            plan = obs[j][2]
            break
        j -= 1
    pair = VersionPair(
        base_id=str(base.backup_id),
        other_id=str(obs[-1][2].backup_id),
        first_changed_after=first_after,
        changed_after=obs[i][0],
        changed_at=obs[i + 1][0],
        plan_backup_id=str(plan.backup_id),
        plan_backup_restorable=plan.restorable_by_hand,
    )
    return Selection(latest=latest, pair=pair, reason=None, window_end=end)


# ---------------------------------------------------------------------------
# The link: ConfigFact for playbook F, the preflight's configuration facts
# ---------------------------------------------------------------------------


def _fact_rows(rows: tuple[VersionRow, ...]) -> tuple[tuple[Any, ...], ...]:
    """The preflight's backups rows, newest first (heal_preflight shape)."""
    out = [
        (
            str(r.backup_id),
            int(r.created_at),  # type: ignore[arg-type]
            r.status,
            r.validation,
            r.has_checksum is True,
        )
        for r in rows
    ]
    out.sort(key=lambda r: (r[1], r[0]), reverse=True)
    return tuple(out[:FACT_ROWS_MAX])


def _captured(rows: tuple[tuple[Any, ...], ...], wall: float) -> Fact:
    usable = [r for r in rows if r[2] in USABLE_STATUSES]
    if not usable:
        return known("none", SOURCE_RECORDS)
    age = wall - usable[0][1]
    if age < 0:
        return unknown("snapshot_time_ahead", SOURCE_RECORDS)
    if age > SNAPSHOT_MAX_AGE_S:
        return known("outdated", SOURCE_RECORDS, age)
    return known("current", SOURCE_RECORDS, age)


def _backup(rows: tuple[tuple[Any, ...], ...], wall: float) -> Fact:
    valid = [r for r in rows if r[2] == "ok" and r[3] == "valid" and r[4] is True]
    if not valid:
        waiting = [r for r in rows if r[2] == "ok" and r[3] == "unverified"]
        if not waiting:
            return known("none", SOURCE_RECORDS)
        age = wall - waiting[0][1]
        return known("unverified", SOURCE_RECORDS, age if age >= 0 else None)
    age = wall - valid[0][1]
    if age < 0:
        return unknown("backup_time_ahead", SOURCE_RECORDS)
    if age > SNAPSHOT_MAX_AGE_S:
        return known("outdated", SOURCE_RECORDS, age)
    return known("verified", SOURCE_RECORDS, age)


_NOT_TRACKED: Final = unknown("running_config_not_tracked", SOURCE_RUNNING)


@dataclass(frozen=True, kw_only=True, slots=True)
class ConfigLink:
    """What the Configuration Manager knows about one router, as facts.

    Inputs: ``knowledge`` (the version index), ``wall_at`` (the wall time of
    the snapshot; it ages the versions like the preflight), ``before`` (the
    incident's start, wall seconds: the end of the change window; only
    versions seen strictly before it count; None: the window ends at
    ``wall_at``) and ``diff`` (a stored comparison read earlier by
    :func:`async_read_stored_diff` with the same window end; used only if it
    is of the selected pair). Everything else is derived in ``__post_init__`` and cannot be
    handed in (``dataclasses.replace`` derives it again).
    """

    knowledge: ConfigKnowledge
    wall_at: float
    before: float | None = None
    diff: StoredDiff | None = None
    selection: Selection = field(init=False)
    config_fact: hb.ConfigFact = field(init=False)
    backups: Fact = field(init=False)
    config_captured: Fact = field(init=False)
    backup_present: Fact = field(init=False)
    service_config_unapplied: Fact = field(init=False)
    reasons: Mapping[str, str] = field(init=False)
    restore_executable: bool = field(init=False)

    def __post_init__(self) -> None:
        """Validate the inputs and derive every fact."""
        put = object.__setattr__
        if type(self.knowledge) is not ConfigKnowledge:
            raise _fail("knowledge")
        knowledge = dataclasses.replace(self.knowledge)  # validated again
        put(self, "knowledge", knowledge)
        wall = _time(self.wall_at)
        if wall is None:
            raise _fail("wall_at")
        put(self, "wall_at", wall)
        put(self, "before", _check_cutoff(self.before))
        diff = self.diff
        if diff is not None:
            if type(diff) is not StoredDiff:
                raise _fail("diff")
            diff = dataclasses.replace(diff)
            put(self, "diff", diff)
        sel = select_versions(
            knowledge, before=wall if self.before is None else self.before
        )
        put(self, "selection", sel)
        reasons: dict[str, str] = {}
        put(self, "config_fact", self._config_fact(knowledge, sel, diff, reasons))
        reasons["restore_check"] = "restore_dry_run_not_run"
        reasons["service_config_unapplied"] = "running_config_not_tracked"
        reasons["restore"] = RESTORE_STATEMENT
        put(self, "reasons", MappingProxyType(dict(sorted(reasons.items()))))
        put(self, "restore_executable", False)
        put(self, "service_config_unapplied", _NOT_TRACKED)
        if knowledge.rows is None:
            gone = unknown(str(knowledge.reason), SOURCE_VERSIONS)
            for name in ("backups", "config_captured", "backup_present"):
                put(self, name, gone)
            return
        rows = _fact_rows(knowledge.rows)
        put(self, "backups", known(rows, SOURCE_RECORDS))
        put(self, "config_captured", _captured(rows, wall))
        put(self, "backup_present", _backup(rows, wall))

    @staticmethod
    def _config_fact(
        knowledge: ConfigKnowledge,
        sel: Selection,
        diff: StoredDiff | None,
        reasons: dict[str, str],
    ) -> hb.ConfigFact:
        if knowledge.rows is None:
            reasons["version_known"] = str(knowledge.reason)
            reasons["diff_proven"] = str(knowledge.reason)
            return hb.ConfigFact()
        pair = sel.pair
        if pair is None:
            latest = sel.latest
            if latest is None:
                reasons["diff_proven"] = str(sel.reason)
                reasons["version_known"] = "no_usable_version"
                return hb.ConfigFact(version_known=False, backup_present=False)
            known_latest = {
                "version_known": True,
                "version_id": latest.backup_id,
                "backup_present": latest.restorable_by_hand,
            }
            reasons["diff_proven"] = str(sel.reason)
            return hb.ConfigFact(**known_latest)
        base = {
            "version_known": True,
            "version_id": pair.plan_backup_id,
            "backup_present": pair.plan_backup_restorable,
        }
        if diff is None:
            reasons["diff_proven"] = "diff_not_read"
            return hb.ConfigFact(**base)
        if (diff.base_id, diff.other_id) != (pair.base_id, pair.other_id):
            reasons["diff_proven"] = "diff_other_versions"
            return hb.ConfigFact(**base)
        if diff.proven is None:
            reasons["diff_proven"] = str(diff.reason)
            return hb.ConfigFact(**base)
        if diff.proven is False:
            # the comparison shows no change: still no proof of "none"
            reasons["diff_proven"] = "no_change_seen"
            return hb.ConfigFact(**base)
        return hb.ConfigFact(
            **base,
            diff_proven=True,
            changed_areas=diff.areas,
            change_risk=diff.change_risk,
            changed_at=pair.changed_at,
        )

    @property
    def pair(self) -> VersionPair | None:
        """The last change the store shows (None: no pair, see ``reasons``)."""
        return self.selection.pair

    def preflight_overrides(self) -> dict[str, Fact]:
        """Facts to put into ``heal_preflight.PreflightFacts`` (by
        ``dataclasses.replace``): ``backups`` and ``service_config_unapplied``."""
        return {
            "backups": self.backups,
            "service_config_unapplied": self.service_config_unapplied,
        }

    def config_change_24h(self, areas: Iterable[str]) -> bool | None:
        """``heal_policy`` ``config_change_24h`` for a target in ``areas``.

        True only when a stored comparison proves a change in one of
        ``areas`` inside the window, and every compared change happened
        within the 24 h before ``wall_at`` (the earlier bound of the first
        one is inside) and not after it. Never False: the store cannot prove
        that nothing changed after its newest version. None otherwise (the
        policy counts None as a change). ``areas``: a list of area codes; a
        str is no list (its letters are no areas).
        """
        fact, pair = self.config_fact, self.pair
        if fact.diff_proven is not True or fact.changed_areas is None or pair is None:
            return None
        if isinstance(areas, str):
            return None
        wanted = frozenset(a for a in areas if isinstance(a, str))
        if not wanted & fact.changed_areas:
            return None
        if (
            pair.first_changed_after >= self.wall_at - CONFIG_CHANGE_WINDOW_S
            and pair.changed_at <= self.wall_at
        ):
            return True
        return None

    def to_dict(self) -> dict[str, Any]:
        """JSON form: core ids, codes, counts and times only (no hash)."""
        cf = self.config_fact
        pair = self.pair
        return {
            "link_version": LINK_VERSION,
            "router_id": self.knowledge.router_id,
            "config_fact": {
                "version_known": cf.version_known,
                "version_id": cf.version_id,
                "diff_proven": cf.diff_proven,
                "changed_areas": None
                if cf.changed_areas is None
                else sorted(cf.changed_areas),
                "change_risk": cf.change_risk,
                "restore_check": cf.restore_check,
                "backup_present": cf.backup_present,
                "changed_at": cf.changed_at,
            },
            "change": None
            if pair is None
            else {
                "base_id": pair.base_id,
                "other_id": pair.other_id,
                "first_changed_after": pair.first_changed_after,
                "changed_after": pair.changed_after,
                "changed_at": pair.changed_at,
                "plan_backup_id": pair.plan_backup_id,
                "plan_backup_restorable": pair.plan_backup_restorable,
            },
            "window": {
                "end": self.selection.window_end,
                "length_s": CONFIG_CHANGE_WINDOW_S,
                "no_change_seen": self.selection.no_change_seen,
            },
            "preflight": {
                "backups": self.backups.to_dict(),
                "config_captured": self.config_captured.to_dict(),
                "backup_present": self.backup_present.to_dict(),
                "service_config_unapplied": self.service_config_unapplied.to_dict(),
            },
            "restore_executable": self.restore_executable,
            "reasons": dict(self.reasons),
        }


# ---------------------------------------------------------------------------
# Collectors (memory, never raise) and the stored comparison (store only)
# ---------------------------------------------------------------------------


def _row_of(record: Any) -> VersionRow:
    validation = getattr(record, "validation", None)
    sha = getattr(record, "sha256", None)
    return VersionRow(
        backup_id=getattr(record, "backup_id", None),
        created_at=getattr(record, "created_at", None),
        last_seen_at=getattr(record, "last_seen_at", None),
        status=getattr(record, "status", None),
        validation=getattr(validation, "status", None),
        has_checksum=isinstance(sha, str) and len(sha) == 64,
        content_hash=getattr(record, "uci_hash", None),
        backup_type=getattr(record, "backup_type", None),
    )


def knowledge_from_versions(versions: Any, router_id: Any) -> ConfigKnowledge:
    """The router's index from the core's version store (memory only).

    Never raises: no store is ``core_not_running``, a store that is not
    loaded ``versions_not_loaded``, anything that breaks while reading
    ``source_error``, and so are entries of which not one is readable (an id
    and a time); an empty index is a known "nothing stored". Versions of
    another router are left out.

    Not the same as the preflight's own collector (``heal_preflight``
    ``_backup_facts``) on an odd store, on purpose (a test pins each): a
    duplicate id is kept once (the first), a version of another router and a
    time outside ``0..TIME_MAX`` are left out, entries of which none is
    readable are ``source_error``, and so is a store that answers None (the
    preflight says ``versions_unknown``). On a clean store both agree.
    """
    if not isinstance(router_id, str) or not is_valid_id(router_id, ROUTER_ID_PREFIX):
        return ConfigKnowledge(router_id=None)
    if versions is None:
        return ConfigKnowledge(router_id=router_id, reason="core_not_running")
    try:
        if getattr(versions, "loaded", True) is not True:
            return ConfigKnowledge(router_id=router_id, reason="versions_not_loaded")
        rows = []
        for record in versions.records(router_id):
            other = getattr(record, "router_id", router_id)
            if isinstance(other, str) and other != router_id:
                continue
            rows.append(_row_of(record))
    except Exception as err:  # noqa: BLE001 - an unreadable index is unknown
        _LOGGER.debug(
            "Self-Healing: version index not readable (%s)", type(err).__name__
        )
        return ConfigKnowledge(router_id=router_id, reason="source_error")
    if rows and not any(row.complete for row in rows):
        # entries were there, but not one could be read: not "no backup"
        return ConfigKnowledge(router_id=router_id, reason="source_error")
    return ConfigKnowledge(router_id=router_id, rows=tuple(rows))


def _running_core(hass: Any) -> Any:
    from .enterprise_core import async_get_core

    core = async_get_core(hass)
    if core is None or not getattr(core, "loaded", False) or core.closed:
        return None
    return core


def collect_config_knowledge(hass: Any, router_id: Any) -> ConfigKnowledge:
    """The router's version index from what Home Assistant holds in memory.

    No router call, no store read, no load; never raises.
    """
    try:
        core = _running_core(hass)
        versions = None if core is None else core.versions
    except Exception as err:  # noqa: BLE001 - a broken core is "not running"
        _LOGGER.debug("Self-Healing: core not readable (%s)", type(err).__name__)
        versions = None
    return knowledge_from_versions(versions, router_id)


def config_link_for(
    hass: Any,
    router_id: Any,
    *,
    wall_now: float,
    before: float | None = None,
    diff: StoredDiff | None = None,
) -> ConfigLink:
    """The link from memory (sync, no I/O): the call for the engine's
    ``HealFactsProvider``. ``diff``: a stored comparison read before (else
    the change stays unknown, ``diff_not_read``). Raises
    :class:`ConfigLinkError` only for its own bad inputs."""
    return ConfigLink(
        knowledge=collect_config_knowledge(hass, router_id),
        wall_at=wall_now,
        before=before,
        diff=diff,
    )


async def async_read_stored_diff(
    api: Any, knowledge: ConfigKnowledge, *, before: Any
) -> StoredDiff | None:
    """Compare the two STORED versions of the window ending at ``before``.

    ``api``: the core's ``ConfigurationApi``. ``before``: the same window
    end the sync call (:func:`config_link_for`) gets. Both references are
    backup references, so the core reads the stored artifacts and never the
    live configuration: no router call. What it may write: over a damaged
    artifact the core's version store marks that version ``corrupt`` (a
    deleted artifact file: ``missing``), saves its index once and fires
    ``configuration.integrity_failed`` - once per damaged version (the
    version is then no longer compared); the result here is
    ``diff_failed``. Nothing else is written. None when the store
    shows no change to compare or the inputs are odd. Never raises (a
    cancellation still propagates).
    """
    try:
        selection = select_versions(knowledge, before=before)
    except ConfigLinkError:
        return None
    pair = selection.pair
    if pair is None:
        return None
    try:
        from .core_models import Actor, ConfigRef

        diff = await api.async_compare(
            ConfigRef.backup(pair.base_id),
            ConfigRef.backup(pair.other_id),
            actor=Actor.for_module(ACTOR_MODULE),
        )
    except Exception as err:  # noqa: BLE001 - a failed comparison is unknown
        _LOGGER.debug("Self-Healing: stored comparison failed (%s)", type(err).__name__)
        return StoredDiff(
            base_id=pair.base_id, other_id=pair.other_id, reason="diff_failed"
        )
    return stored_diff_from(diff, pair.base_id, pair.other_id)


async def async_config_link_for(
    hass: Any, router_id: Any, *, wall_now: float, before: float | None = None
) -> ConfigLink:
    """Memory plus the stored comparison of the last change (no router call).

    For a later package to run off the decision path (for example when an
    incident opens) and to hand the :class:`StoredDiff` to
    :func:`config_link_for` with the same ``before``. The comparison reads
    the store only; over a damaged or deleted artifact the core writes once (see
    :func:`async_read_stored_diff`). Raises :class:`ConfigLinkError` only
    for its own bad inputs; everything it reads becomes unknown on error.
    """
    knowledge = collect_config_knowledge(hass, router_id)
    diff: StoredDiff | None = None
    try:
        core = _running_core(hass)
        api = None if core is None else core.manager.api(1)
    except Exception as err:  # noqa: BLE001 - no API: the change stays unknown
        _LOGGER.debug(
            "Self-Healing: configuration API missing (%s)", type(err).__name__
        )
        api = None
    if api is not None:
        end = wall_now if before is None else before
        diff = await async_read_stored_diff(api, knowledge, before=end)
    return ConfigLink(knowledge=knowledge, wall_at=wall_now, before=before, diff=diff)


__all__ = [
    "ACTOR_MODULE",
    "BACKUP_VALUES",
    "CAPTURED_VALUES",
    "CONFIG_CHANGE_WINDOW_S",
    "LINK_VERSION",
    "REASONS",
    "REASON_TEXT_DE",
    "RESTORE_STATEMENT",
    "ConfigKnowledge",
    "ConfigLink",
    "ConfigLinkError",
    "Selection",
    "StoredDiff",
    "VersionPair",
    "VersionRow",
    "async_config_link_for",
    "async_read_stored_diff",
    "collect_config_knowledge",
    "config_link_for",
    "knowledge_from_versions",
    "select_versions",
    "stored_diff_from",
]
