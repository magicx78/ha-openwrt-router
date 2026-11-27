"""Self-Healing: the link to the Configuration Manager (package G).

Developer document: ``docs/self-healing.md`` §7.2. Release 1.53.0 is
Observe only: nothing here calls a router, runs a restore, writes a store or
changes a configuration.

What it does: it turns what the Configuration Manager ALREADY holds into the
facts Self-Healing needs, and nothing more.

* the version index of the core (``core.versions.records()``, in memory):
  which versions exist, when they were taken, their status, validation,
  archive checksum and content hash;
* optionally the comparison of two STORED versions
  (``ConfigurationApi.async_compare`` with two backup references - it reads
  the stored artifacts, never the live configuration).

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

**Time.** A stored comparison only says that the configuration changed
somewhere between the last observation of the old content and the first
observation of the new one. ``changed_at`` is that LATER bound (the time the
change was first seen in the store); ``changed_after`` is the earlier one.
Playbook F takes a change as the incident's cause only when ``changed_at <
started_at``; with the later bound that implies the real change time is
strictly before the start too. The earlier bound would not (see the
document, §7.2).

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
# "a configuration change in 24 h" (heal_policy ``config_change_24h``)
CHANGE_WINDOW_S: Final = 86400
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
    "single_content",
    "ambiguous_order",
    "diff_not_read",
    "diff_other_versions",
    "diff_failed",
    "diff_unreadable",
    "diff_truncated",
    "diff_area_unknown",
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
        "single_content": (
            "Alle gespeicherten Versionen haben denselben Inhalt; eine Änderung "
            "ist im Speicher nicht belegt."
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
    False: the two versions are the same configuration (``areas`` empty).
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
    versions, is truncated, has a comparable change without a known area,
    or has secrets that cannot be compared (another installation key).
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
    areas: set[str] = set()
    risks: list[str | None] = []
    for change in changes:
        kind = _member(getattr(change, "kind", None), (_NOT_COMPARABLE, *_KINDS))
        if kind is None:
            return unknown_diff("diff_unreadable")
        if kind == _NOT_COMPARABLE:
            return unknown_diff("secrets_not_comparable")
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
    """The last change the store shows, as two versions and two bounds.

    ``base_id``: the newest observation of the content before the change;
    ``other_id``: the newest observation of the content after it.
    The change happened in ``(changed_after, changed_at]``: ``changed_after``
    is the last time the old content was seen, ``changed_at`` the first time
    the new content was seen. ``plan_backup_id``: the version a restore to
    the old content would use (the newest restorable archive of that
    content, else ``base_id``).
    """

    base_id: str
    other_id: str
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
        for name in ("changed_after", "changed_at"):
            if _time(getattr(self, name)) is None:
                raise _fail(f"pair.{name}")
        if not self.changed_after < self.changed_at:
            raise _fail("pair.changed_at")
        if not isinstance(self.plan_backup_restorable, bool):
            raise _fail("pair.plan_backup_restorable")


@dataclass(frozen=True, kw_only=True, slots=True)
class Selection:
    """Result of :func:`select_versions`."""

    latest: VersionRow | None  # the newest usable version (before the cutoff)
    pair: VersionPair | None
    reason: str | None  # why there is no pair


def _check_cutoff(before: Any) -> float | None:
    if before is None:
        return None
    out = _time(before)
    if out is None:
        raise _fail("before")
    return out


def select_versions(knowledge: ConfigKnowledge, *, before: Any = None) -> Selection:
    """The last change of the stored content, seen strictly before ``before``.

    Every comparable version is an observation of its content at
    ``created_at`` and, if deduplicated, again at ``last_seen_at``. Sorted
    by time, the newest observation gives the current content; walking back,
    the first observation of another content is the base. Equal times of
    two contents at that boundary are ``ambiguous_order`` (no pair).
    """
    if type(knowledge) is not ConfigKnowledge:
        raise _fail("knowledge")
    cutoff = _check_cutoff(before)
    if knowledge.rows is None:
        return Selection(latest=None, pair=None, reason=knowledge.reason)

    def early(t: float | None) -> bool:
        return t is not None and (cutoff is None or t < cutoff)

    usable = [r for r in knowledge.rows if r.usable and early(r.created_at)]
    latest = max(usable, key=lambda r: (r.created_at, r.backup_id), default=None)
    obs: list[tuple[float, str, VersionRow]] = []
    for row in knowledge.rows:
        if not row.comparable:
            continue
        for t in dict.fromkeys((row.created_at, row.last_seen_at)):
            if early(t):
                obs.append((float(t), str(row.backup_id), row))  # type: ignore[arg-type]
    if not obs:
        return Selection(latest=latest, pair=None, reason="no_usable_version")
    obs.sort(key=lambda o: (o[0], o[1]))
    content = obs[-1][2].content_hash
    i = len(obs) - 1
    while i >= 0 and obs[i][2].content_hash == content:
        i -= 1
    if i < 0:
        return Selection(latest=latest, pair=None, reason="single_content")
    base_t, _bid, base = obs[i]
    changed_at = obs[i + 1][0]
    if base_t == changed_at:
        return Selection(latest=latest, pair=None, reason="ambiguous_order")
    plan = base
    j = i
    while j >= 0 and obs[j][2].content_hash == base.content_hash:
        if obs[j][2].restorable_by_hand:
            plan = obs[j][2]
            break
        j -= 1
    pair = VersionPair(
        base_id=str(base.backup_id),
        other_id=str(obs[-1][2].backup_id),
        changed_after=base_t,
        changed_at=changed_at,
        plan_backup_id=str(plan.backup_id),
        plan_backup_restorable=plan.restorable_by_hand,
    )
    return Selection(latest=latest, pair=pair, reason=None)


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
    incident's start, wall seconds; only versions seen strictly before it
    count for the change) and ``diff`` (a stored comparison read earlier by
    :func:`async_read_stored_diff`; used only if it is of the selected
    pair). Everything else is derived in ``__post_init__`` and cannot be
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
        sel = select_versions(knowledge, before=self.before)
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
            reasons["diff_proven"] = str(sel.reason)
            latest = sel.latest
            if latest is None:
                reasons["version_known"] = "no_usable_version"
                return hb.ConfigFact(version_known=False, backup_present=False)
            return hb.ConfigFact(
                version_known=True,
                version_id=latest.backup_id,
                backup_present=latest.restorable_by_hand,
            )
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
            return hb.ConfigFact(**base, diff_proven=False, changed_areas=frozenset())
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
        ``areas`` that happened within the last 24 h (its earlier bound is
        inside the window). Never False: the store cannot prove that nothing
        changed after its newest version. None otherwise (the policy counts
        None as a change).
        """
        fact, pair = self.config_fact, self.pair
        if fact.diff_proven is not True or fact.changed_areas is None or pair is None:
            return None
        wanted = frozenset(a for a in areas if isinstance(a, str))
        if not wanted & fact.changed_areas:
            return None
        if (
            pair.changed_after >= self.wall_at - CHANGE_WINDOW_S
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
                "changed_after": pair.changed_after,
                "changed_at": pair.changed_at,
                "plan_backup_id": pair.plan_backup_id,
                "plan_backup_restorable": pair.plan_backup_restorable,
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
    ``source_error``. Versions of another router are left out.
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
    api: Any, knowledge: ConfigKnowledge, *, before: Any = None
) -> StoredDiff | None:
    """Compare the two STORED versions of the last change (store only).

    ``api``: the core's ``ConfigurationApi``. Both references are backup
    references, so the core reads the stored artifacts and never the live
    configuration (no router call, no audit entry, nothing written).
    None when the store shows no change (nothing to compare) or the inputs
    are odd; a failed comparison is ``diff_failed``. Never raises (a
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
    :func:`config_link_for`. Raises :class:`ConfigLinkError` only for its own
    bad inputs; everything it reads becomes unknown on error.
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
        diff = await async_read_stored_diff(api, knowledge, before=before)
    return ConfigLink(knowledge=knowledge, wall_at=wall_now, before=before, diff=diff)


__all__ = [
    "ACTOR_MODULE",
    "BACKUP_VALUES",
    "CAPTURED_VALUES",
    "CHANGE_WINDOW_S",
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
