"""Package and system inventory of a router (data shape only).

Plan: docs/plans/2026-11-17-config-manager.md, sections 4 (D17) and 11.2.
The collector (``config_collector``, G5) fills an :class:`Inventory`; the
restore check (``config_restore``) compares two of them. This module holds
only the result object and version helpers.

Pure module: no Home Assistant imports, no I/O.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, NamedTuple

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "APK_SINCE",
    "PACKAGE_MANAGER_APK",
    "PACKAGE_MANAGER_OPKG",
    "PACKAGE_SOURCE_RPC_SYS",
    "PACKAGE_SOURCE_SSH_APK",
    "PACKAGE_SOURCE_SSH_OPKG",
    "Inventory",
    "Release",
    "parse_release",
]

PACKAGE_MANAGER_APK: Final = "apk"
PACKAGE_MANAGER_OPKG: Final = "opkg"

PACKAGE_SOURCE_RPC_SYS: Final = "rpc-sys"
PACKAGE_SOURCE_SSH_APK: Final = "ssh-apk"
PACKAGE_SOURCE_SSH_OPKG: Final = "ssh-opkg"

# "24.10.4", "25.12.0-rc1", "22.03"; "SNAPSHOT" has no number.
_RELEASE_RE: Final = re.compile(r"\s*(\d{2})\.(\d{2})(?:\.(\d+))?")


class Release(NamedTuple):
    """Numeric OpenWrt release, ordered (``year``, ``month``, ``patch``)."""

    year: int
    month: int
    patch: int

    @property
    def series(self) -> tuple[int, int]:
        """The release series, e.g. (24, 10); a change here is a major change."""
        return (self.year, self.month)


# First release series that ships apk instead of opkg (plan 8.2).
APK_SINCE: Final = Release(25, 12, 0)


def parse_release(version: str | None) -> Release | None:
    """Parse ``release.version`` from ``system board``; None if not numeric.

    Release candidates count as their final release (``25.12.0-rc1`` ->
    25.12.0); snapshots (``SNAPSHOT``) are unknown.
    """
    if not isinstance(version, str):
        return None
    match = _RELEASE_RE.match(version)
    if match is None:
        return None
    return Release(int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


@dataclass(frozen=True, slots=True)
class Inventory:
    """Board, release and packages of one router at one point in time.

    ``packages`` maps package name to version (None if unknown); the whole
    mapping is None when no package list could be read. ``free_bytes`` is
    the free space of the writable overlay if known. ``partial`` marks an
    inventory with board/release only (D17). ``archive_members`` lists the
    member names of the matching backup archive, if any.
    """

    board_name: str | None = None
    model: str | None = None
    release_version: str | None = None
    release_revision: str | None = None
    target: str | None = None
    kernel: str | None = None
    package_manager: str | None = None
    packages: Mapping[str, str | None] | None = None
    package_source: str | None = None
    free_bytes: int | None = None
    archive_members: tuple[str, ...] = field(default=())
    partial: bool = False

    def __post_init__(self) -> None:
        if self.packages is not None:
            object.__setattr__(self, "packages", MappingProxyType(dict(self.packages)))
        object.__setattr__(self, "archive_members", tuple(self.archive_members))

    @property
    def release(self) -> Release | None:
        """Parsed ``release_version``."""
        return parse_release(self.release_version)

    @property
    def effective_package_manager(self) -> str | None:
        """``package_manager``, or derived from the release (apk from 25.12)."""
        if self.package_manager:
            return self.package_manager
        release = self.release
        if release is None:
            return None
        return PACKAGE_MANAGER_APK if release >= APK_SINCE else PACKAGE_MANAGER_OPKG
