"""Collect backup archive, UCI configs and inventory from one router.

Plan: docs/plans/2026-11-17-config-manager.md, sections 2.3, 3.1, 4 and
11.2. The collector only calls the four ``config_*`` methods of
``OpenWrtAPI`` (all router traffic stays in api.py) and turns their outcome
into small result objects with an error class from ``config_const``.

It keeps no state and never retries: the configuration manager (group Ia)
decides about retries, remembers skippable methods for
``FETCH_SKIP_TTL_S`` and passes them back in as ``skip``.

Fetch chain for the archive (plan 2.3, D1), in ``order`` (default cgi, ssh):

- ``permission`` / ``not_available``: next method; the method is reported
  in ``ArchiveFetch.skippable_methods`` so the caller can skip it for 24 h.
- ``unreachable`` / ``timeout``: stop at once, the next method would ask the
  same dead router (``CHAIN_ABORT_ERRORS``).
- ``too_large``: stop as well. Every method streams the same
  ``sysupgrade -b`` archive, so a second method would only transfer the
  same oversized archive again.
- ``incomplete``, ``auth``, ``invalid``: next method, not remembered. The
  methods have separate transports and logins (cgi-io session vs. SSH
  password/key), so a cut transfer or a refused ubus login says nothing
  about the other method.
- SSH is only tried for the root user: the archive holds root-only files.

Secrets: archive bytes and raw UCI values hold plaintext secrets. They are
kept out of every ``repr`` and log line; logs carry method, error class,
duration and size only. Raw UCI data should go straight into
:func:`snapshot_from_uci` (or use :func:`collect_uci_snapshot`, which never
hands it out).

No Home Assistant imports.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, Literal

from .api import (
    OpenWrtAuthError,
    OpenWrtConfigFetchError,
    OpenWrtConnectionError,
    OpenWrtMethodNotFoundError,
    OpenWrtTimeoutError,
)
from .config_const import (
    CHAIN_ABORT_ERRORS,
    CHAIN_SKIP_ERRORS,
    DEFAULT_ARCHIVE_LIMITS,
    ERR_AUTH,
    ERR_INCOMPLETE,
    ERR_INVALID,
    ERR_NOT_AVAILABLE,
    ERR_PERMISSION,
    ERR_TIMEOUT,
    ERR_TOO_LARGE,
    ERR_UNREACHABLE,
    ERROR_CLASSES,
    FETCH_METHOD_CGI,
    FETCH_METHOD_SSH,
    FETCH_METHODS,
    FETCH_PACKAGELIST,
    FETCH_TIMEOUTS,
    FETCH_UCI,
    INVENTORY_MAX_PACKAGES,
    ROUTER_FIELD_MAX_CHARS,
    ArchiveLimits,
)
from .config_inventory import (
    APK_SINCE,
    PACKAGE_MANAGER_APK,
    PACKAGE_MANAGER_OPKG,
    Inventory,
    parse_release,
)
from .config_snapshot import UciSnapshot, build_snapshot

if TYPE_CHECKING:
    from .api import OpenWrtAPI

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "ArchiveFetch",
    "FetchAttempt",
    "FetchMethod",
    "UciCollection",
    "UciFetch",
    "classify_error",
    "collect_archive",
    "collect_inventory",
    "collect_uci",
    "collect_uci_snapshot",
    "snapshot_from_uci",
]

FetchMethod = Literal["cgi", "ssh"]

# Errors that end the archive chain: dead router (plan 2.3) and an archive
# over the size cap (the same archive on every method).
ARCHIVE_STOP_ERRORS: Final[frozenset[str]] = CHAIN_ABORT_ERRORS | {ERR_TOO_LARGE}
# Errors that end a UCI run: dead router, and a failed login that every
# further call would repeat (and feed the auth backoff with).
UCI_STOP_ERRORS: Final[frozenset[str]] = CHAIN_ABORT_ERRORS | {ERR_AUTH}

# Bugs, not router answers: never turned into an error class.
PROGRAMMING_ERRORS: Final[tuple[type[Exception], ...]] = (
    TypeError,
    ValueError,
    AttributeError,
    LookupError,
    NameError,
    AssertionError,
    NotImplementedError,
    ArithmeticError,
)

# ---------------------------------------------------------------------------
# Result objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FetchAttempt:
    """One try of one archive method; ``error_class`` None means success."""

    method: FetchMethod
    error_class: str | None
    duration_s: float

    @property
    def skippable(self) -> bool:
        """True if the caller may skip this method for ``FETCH_SKIP_TTL_S``."""
        return self.error_class in CHAIN_SKIP_ERRORS


@dataclass(frozen=True, slots=True)
class ArchiveFetch:
    """Outcome of :func:`collect_archive`.

    ``data`` is the archive (never in ``repr``, never logged) or None.
    ``method`` is the method that delivered it, ``error_class`` the reason
    when none did. ``attempts`` lists the methods actually called, in
    order; ``skipped`` the methods not called because they were in ``skip``
    or need root. A chain stopped by ``unreachable``/``timeout``/
    ``too_large`` leaves later methods out of both.
    """

    data: bytes | None = field(repr=False)
    method: FetchMethod | None
    error_class: str | None
    attempts: tuple[FetchAttempt, ...]
    skipped: tuple[FetchMethod, ...] = ()

    @property
    def ok(self) -> bool:
        """True if an archive was fetched."""
        return self.data is not None

    @property
    def size(self) -> int:
        """Archive size in bytes (0 without archive)."""
        return len(self.data) if self.data is not None else 0

    @property
    def skippable_methods(self) -> frozenset[FetchMethod]:
        """Methods that answered ``permission``/``not_available``.

        The caller remembers them per router for ``FETCH_SKIP_TTL_S`` and
        passes them as ``skip``; a manual backup clears that memory.
        """
        return frozenset(a.method for a in self.attempts if a.skippable)


@dataclass(frozen=True, slots=True)
class UciFetch:
    """Raw UCI configs of one router, as returned by ``config_uci_get``.

    ``raw`` maps every requested config to its ubus-shaped values or None
    (failed or not tried). It holds secrets in plaintext until
    ``config_snapshot.build_snapshot`` digests them: pass it straight to
    :func:`snapshot_from_uci` and do not keep, log or store it. It is not
    part of ``repr``.

    ``failed`` lists ``(config, error_class)`` for configs that answered
    with an error (``not_available`` = config not installed, ``permission``
    = neither ubus nor SSH may read it). ``error_class`` is set when the
    run stopped early (``unreachable``, ``timeout``, ``auth``);
    ``not_tried`` then lists the configs never asked.
    """

    configs: tuple[str, ...]
    raw: Mapping[str, Mapping[str, Any] | None] = field(repr=False)
    failed: tuple[tuple[str, str], ...]
    not_tried: tuple[str, ...]
    error_class: str | None
    duration_s: float


@dataclass(frozen=True, slots=True)
class UciCollection:
    """Outcome of :func:`collect_uci_snapshot`: snapshot plus fetch status.

    Holds no raw data. ``snapshot`` is left out of ``repr`` because it
    carries (non-secret) configuration values.
    """

    snapshot: UciSnapshot = field(repr=False)
    failed: tuple[tuple[str, str], ...]
    not_tried: tuple[str, ...]
    error_class: str | None
    duration_s: float


# ---------------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------------


def classify_error(err: BaseException) -> str:
    """Map an exception of a router fetch to an ``ERR_*`` error class.

    - ``error_class`` attribute of the ``OpenWrtConfigFetch*Error`` family
      (an unknown value counts as ``incomplete``),
    - ``OpenWrtTimeoutError`` / ``TimeoutError`` (= ``asyncio.TimeoutError``)
      -> ``timeout``,
    - ``OpenWrtConnectionError`` / other ``OSError`` -> ``unreachable``,
    - ``OpenWrtAuthError`` (incl. backoff) -> ``auth``,
    - ``OpenWrtMethodNotFoundError`` -> ``not_available``,
    - any other ``Exception`` (unexpected answer) -> ``invalid``.

    Meant for router fetches only; storage errors are classified by
    enterprise-core.

    Raises:
        The given exception itself if it is a programming error
        (``PROGRAMMING_ERRORS``) or no ``Exception`` at all
        (``asyncio.CancelledError``, ``KeyboardInterrupt``): those must
        never become an error class.
    """
    if not isinstance(err, Exception) or isinstance(err, PROGRAMMING_ERRORS):
        raise err
    declared = getattr(err, "error_class", None)
    if isinstance(declared, str) and declared in ERROR_CLASSES:
        return declared
    if isinstance(err, OpenWrtConfigFetchError):
        return ERR_INCOMPLETE
    # TimeoutError subclasses OSError: check it first.
    if isinstance(err, (OpenWrtTimeoutError, TimeoutError)):
        return ERR_TIMEOUT
    if isinstance(err, (OpenWrtConnectionError, OSError)):
        return ERR_UNREACHABLE
    if isinstance(err, OpenWrtAuthError):
        return ERR_AUTH
    if isinstance(err, OpenWrtMethodNotFoundError):
        return ERR_NOT_AVAILABLE
    return ERR_INVALID


# ---------------------------------------------------------------------------
# Archive
# ---------------------------------------------------------------------------


def _check_order(order: Sequence[str]) -> tuple[FetchMethod, ...]:
    if isinstance(order, str):
        raise TypeError("order must be a sequence of method names, not str")
    methods: list[FetchMethod] = []
    for method in order:
        if method not in FETCH_METHODS:
            raise ValueError(f"unknown backup fetch method: {method!r}")
        if method not in methods:
            methods.append(method)  # type: ignore[arg-type]
    if not methods:
        raise ValueError("order names no backup fetch method")
    return tuple(methods)


async def collect_archive(
    api: OpenWrtAPI,
    *,
    order: Sequence[str] = FETCH_METHODS,
    is_root: bool,
    skip: Collection[str] = frozenset(),
    limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS,
    timeouts: Mapping[str, float] = FETCH_TIMEOUTS,
) -> ArchiveFetch:
    """Fetch the ``sysupgrade -b`` archive along the fallback chain.

    ``order`` lists the methods (``cgi``, ``ssh``; duplicates ignored),
    ``is_root`` tells whether the SSH user is root, ``skip`` holds methods
    the caller remembered as skippable. Each method gets
    ``limits.max_compressed`` as byte cap and ``timeouts[method]`` as
    timeout. See the module docstring for the chain rules.

    If no method delivers, ``error_class`` is the class of the last attempt;
    it is ``permission`` when SSH was left out for a non-root user and
    nothing better is known (no attempt, or the last one was
    ``permission``/``not_available``: only root SSH would have helped), and
    ``not_available`` when every method was skipped.

    Raises:
        ValueError: ``order`` is empty or names an unknown method.
        asyncio.CancelledError and programming errors: passed through.
    """
    methods = _check_order(order)
    attempts: list[FetchAttempt] = []
    skipped: list[FetchMethod] = []
    root_needed = False
    for method in methods:
        if method in skip:
            skipped.append(method)
            _LOGGER.debug("config backup via %s: skipped (remembered)", method)
            continue
        if method == FETCH_METHOD_SSH and not is_root:
            skipped.append(method)
            root_needed = True
            _LOGGER.debug("config backup via %s: skipped (needs root)", method)
            continue
        started = time.monotonic()
        try:
            if method == FETCH_METHOD_CGI:
                data = await api.config_fetch_backup_cgi(
                    max_bytes=limits.max_compressed, timeout=timeouts[method]
                )
            else:
                data = await api.config_fetch_backup_ssh(
                    max_bytes=limits.max_compressed, timeout=timeouts[method]
                )
        except Exception as err:
            if isinstance(err, PROGRAMMING_ERRORS):
                raise
            error_class = classify_error(err)
            duration = time.monotonic() - started
            attempts.append(FetchAttempt(method, error_class, duration))
            _LOGGER.debug(
                "config backup via %s: %s after %.1fs", method, error_class, duration
            )
            if error_class in ARCHIVE_STOP_ERRORS:
                return ArchiveFetch(
                    None, None, error_class, tuple(attempts), tuple(skipped)
                )
            continue
        duration = time.monotonic() - started
        archive = data if isinstance(data, bytes) else bytes(data)
        attempts.append(FetchAttempt(method, None, duration))
        _LOGGER.debug(
            "config backup via %s: ok, %d bytes in %.1fs",
            method,
            len(archive),
            duration,
        )
        return ArchiveFetch(archive, method, None, tuple(attempts), tuple(skipped))

    last = attempts[-1].error_class if attempts else None
    if root_needed and (last is None or last in CHAIN_SKIP_ERRORS):
        error_class = ERR_PERMISSION
    else:
        error_class = last or ERR_NOT_AVAILABLE
    _LOGGER.debug("config backup: no archive (%s)", error_class)
    return ArchiveFetch(None, None, error_class, tuple(attempts), tuple(skipped))


# ---------------------------------------------------------------------------
# UCI
# ---------------------------------------------------------------------------


async def collect_uci(
    api: OpenWrtAPI,
    configs: Sequence[str],
    *,
    timeouts: Mapping[str, float] = FETCH_TIMEOUTS,
) -> UciFetch:
    """Read the given UCI configs one after another (never in parallel).

    One ``config_uci_get`` per config (ubus, SSH ``uci show`` on an ACL
    block, inside api.py), each bounded by ``timeouts["uci"]``. A config
    that fails is ``None`` in ``raw`` and listed in ``failed``; the run
    goes on. ``unreachable``, ``timeout`` or ``auth`` stop the run, so a
    dead router or a refused login does not cost a dozen more calls.

    The result holds plaintext secrets: hand it to :func:`snapshot_from_uci`
    right away and drop it, or use :func:`collect_uci_snapshot`.

    Raises:
        TypeError: ``configs`` is a single string.
        asyncio.CancelledError and programming errors (e.g. ValueError for
        an invalid config name from api.py): passed through.
    """
    if isinstance(configs, str):
        raise TypeError("configs must be a sequence of config names, not str")
    names = tuple(dict.fromkeys(configs))
    raw: dict[str, Mapping[str, Any] | None] = dict.fromkeys(names)
    failed: list[tuple[str, str]] = []
    not_tried: tuple[str, ...] = ()
    stop_class: str | None = None
    started = time.monotonic()
    for pos, name in enumerate(names):
        call_started = time.monotonic()
        try:
            async with asyncio.timeout(timeouts[FETCH_UCI]):
                values = await api.config_uci_get(name)
        except Exception as err:
            if isinstance(err, PROGRAMMING_ERRORS):
                raise
            error_class = classify_error(err)
            failed.append((name, error_class))
            _LOGGER.debug(
                "uci %s: %s after %.1fs",
                name,
                error_class,
                time.monotonic() - call_started,
            )
            if error_class in UCI_STOP_ERRORS:
                stop_class = error_class
                not_tried = names[pos + 1 :]
                break
            continue
        if not isinstance(values, Mapping):
            failed.append((name, ERR_INVALID))
            _LOGGER.debug("uci %s: %s (no mapping)", name, ERR_INVALID)
            continue
        raw[name] = values

    duration = time.monotonic() - started
    _LOGGER.debug(
        "uci snapshot read: %d of %d configs in %.1fs, %d failed, %d not tried%s",
        sum(1 for value in raw.values() if value is not None),
        len(names),
        duration,
        len(failed),
        len(not_tried),
        f", stopped ({stop_class})" if stop_class else "",
    )
    return UciFetch(
        configs=names,
        raw=MappingProxyType(raw),
        failed=tuple(failed),
        not_tried=not_tried,
        error_class=stop_class,
        duration_s=duration,
    )


def snapshot_from_uci(
    fetch: UciFetch, secret_digest: Callable[[str], str]
) -> UciSnapshot:
    """Normalize and digest the raw configs of ``fetch`` into a snapshot.

    The snapshot covers exactly the requested configs; failed and not tried
    ones land in ``UciSnapshot.missing``.
    """
    return build_snapshot(fetch.raw, secret_digest, configs=fetch.configs)


async def collect_uci_snapshot(
    api: OpenWrtAPI,
    configs: Sequence[str],
    secret_digest: Callable[[str], str],
    *,
    timeouts: Mapping[str, float] = FETCH_TIMEOUTS,
) -> UciCollection:
    """:func:`collect_uci` + :func:`snapshot_from_uci`; raw data never leaves.

    Normalization runs inline: a dozen small configs, no executor needed.
    """
    fetch = await collect_uci(api, configs, timeouts=timeouts)
    snapshot = snapshot_from_uci(fetch, secret_digest)
    return UciCollection(
        snapshot=snapshot,
        failed=fetch.failed,
        not_tried=fetch.not_tried,
        error_class=fetch.error_class,
        duration_s=fetch.duration_s,
    )


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def router_text(value: Any) -> str | None:
    """A non-empty, bounded string or None (router_info fills gaps with "").

    Values longer than ``ROUTER_FIELD_MAX_CHARS`` are dropped: they come
    from the router and later run through masking and comparisons.
    """
    if isinstance(value, str):
        value = value.strip()
        if len(value) > ROUTER_FIELD_MAX_CHARS:
            return None
        return value or None
    return None


def _packages(result: Mapping[Any, Any]) -> dict[str, str | None]:
    """Bounded package map: long names dropped, long versions unknown."""
    packages: dict[str, str | None] = {}
    for name, version in result.items():
        if len(packages) >= INVENTORY_MAX_PACKAGES:
            break
        name_text = router_text(name)
        if name_text is None:
            continue
        packages[name_text] = router_text(version)
    return packages


def _package_manager(version: str | None) -> str | None:
    release = parse_release(version)
    if release is None:
        return None
    return PACKAGE_MANAGER_APK if release >= APK_SINCE else PACKAGE_MANAGER_OPKG


async def collect_inventory(
    api: OpenWrtAPI,
    router_info: Mapping[str, Any],
    *,
    timeouts: Mapping[str, float] = FETCH_TIMEOUTS,
) -> Inventory:
    """Build the inventory from ``router_info`` plus the package list.

    ``router_info`` is what the coordinator already holds from
    ``api.get_router_info()`` (``model``, ``board_name``, ``kernel``,
    ``release.version/revision/target``); no extra ``system board`` call.
    The package list comes from ``config_packagelist`` (rpc-sys, else SSH
    apk/opkg), bounded by ``timeouts["packagelist"]``. Without it the
    inventory is ``partial`` (plan D17), whatever the reason. The package
    manager is derived from the release (apk from 25.12). ``package_source``
    stays None: api.py does not report which source answered.

    Raises:
        TypeError: ``router_info`` is not a mapping.
        asyncio.CancelledError and programming errors: passed through.
    """
    if not isinstance(router_info, Mapping):
        raise TypeError("router_info must be a mapping")
    release = router_info.get("release")
    release = release if isinstance(release, Mapping) else {}
    version = router_text(release.get("version"))

    packages: dict[str, str | None] | None = None
    started = time.monotonic()
    try:
        async with asyncio.timeout(timeouts[FETCH_PACKAGELIST]):
            result = await api.config_packagelist()
    except Exception as err:
        if isinstance(err, PROGRAMMING_ERRORS):
            raise
        _LOGGER.debug(
            "package list: %s after %.1fs",
            classify_error(err),
            time.monotonic() - started,
        )
    else:
        if isinstance(result, Mapping) and result:
            packages = _packages(result)
        _LOGGER.debug(
            "package list: %d packages in %.1fs",
            len(packages or {}),
            time.monotonic() - started,
        )

    return Inventory(
        board_name=router_text(router_info.get("board_name")),
        model=router_text(router_info.get("model")),
        release_version=version,
        release_revision=router_text(release.get("revision")),
        target=router_text(release.get("target")),
        kernel=router_text(router_info.get("kernel")),
        package_manager=_package_manager(version),
        packages=packages,
        package_source=None,
        partial=packages is None,
    )
