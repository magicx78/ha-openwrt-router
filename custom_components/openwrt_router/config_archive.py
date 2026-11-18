"""In-memory validation of router backup archives (``sysupgrade -b``).

Plan: docs/plans/2026-11-17-config-manager.md, sections 7, 11.3 and 14.2.

The archive comes from a router and may be damaged or hostile. It is never
unpacked to disk. The checks run on a gzip stream that this module decodes
itself with a hard output cap, so a compression bomb stops after at most
``cap + OUTPUT_CHUNK_BYTES`` decoded bytes no matter what the tar headers
claim. tarfile only ever sees that capped stream (stream mode ``r|``, no
seeking), and member contents are read just to hash them.

Rules (plan section 7, same intent as ``tarfile.data_filter`` without
extracting): member names must be relative, without ``..``, NUL, control
characters or backslashes, and short enough; only regular files,
directories and symlinks are allowed; symlinks must stay inside the archive
tree or point below ``ARCHIVE_SYMLINK_ABS_PREFIXES``; no member may sit
below a symlink.

Pure logic: no Home Assistant imports, no network, no file access. The
functions are synchronous and CPU-bound; callers run them in the executor.
Nothing here logs file contents or member names (names can be secret paths,
see plan 14.2); logs carry reason codes and counts only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import posixpath
import re
import tarfile
import zlib
from collections.abc import Collection, Iterable
from dataclasses import dataclass, replace
from typing import Final

from .config_const import (
    ARCHIVE_CONFIG_PREFIX,
    ARCHIVE_REQUIRED_CONFIGS,
    ARCHIVE_SYMLINK_ABS_PREFIXES,
    DEFAULT_ARCHIVE_LIMITS,
    ERR_INCOMPLETE,
    ERR_INVALID,
    ERR_TOO_LARGE,
    GZIP_MAGIC,
    STREAM_CHUNK_BYTES,
    WARN_CONFIG_MISSING_IN_ARCHIVE,
    ArchiveLimits,
)
from .config_mask import is_secret_path

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants local to the archive check
# ---------------------------------------------------------------------------

MEMBER_FILE: Final = "file"
MEMBER_DIR: Final = "dir"
MEMBER_SYMLINK: Final = "symlink"

# Below this many decoded bytes the ratio limit is not applied: tiny tar
# archives are mostly zero padding and compress far beyond 200:1, and a
# "bomb" this small does no harm.
RATIO_CHECK_FLOOR_BYTES: Final = 1024 * 1024
# Compressed bytes fed to zlib per call and decoded bytes taken out per call.
# The output chunk bounds how far decoding can overshoot the cap.
INPUT_CHUNK_BYTES: Final = STREAM_CHUNK_BYTES
OUTPUT_CHUNK_BYTES: Final = 65536
# sysupgrade writes one gzip member; RFC 1952 allows several. Each member
# costs a new decoder, so the count is bounded against tiny-member floods.
MAX_GZIP_MEMBERS: Final = 64
# Versioned so a future change of the content hash input is explicit.
CONTENT_HASH_SCHEME: Final = "openwrt_router.archive_content.v1"

_TAR_BLOCK: Final = 512
# Decoded bytes kept after delivery to tarfile. Must exceed tarfile's
# read-ahead (one record, 10240 bytes) plus one header block.
_TAIL_KEEP: Final = 65536
_DISPLAY_MAX: Final = 300
_ZLIB_GZIP_WBITS: Final = 16 + zlib.MAX_WBITS
_CONTROL_CHARS: Final = re.compile(r"[\x00-\x1f\x7f]")
_SHA256_HEX: Final = re.compile(r"[0-9a-fA-F]{64}")
# Raw header fields as every tar writes them: optional leading spaces, octal
# digits, then spaces/NULs only. No sign, no base-256, nothing after the NUL.
_OCTAL_FIELD: Final = re.compile(rb" *([0-7]*)[ \x00]*")
# A pax "size" record as POSIX defines it; Python's int() would also take
# "+97", " 97", "9_7" or non-ASCII digits, which other tars read differently.
_PAX_DECIMAL: Final = re.compile(r"0|[1-9][0-9]{0,17}")
# Header blocks that may precede a member, each at most once. Global pax
# headers ("g") and Solaris "X" headers are refused: tarfile and GNU/busybox
# tar apply them differently.
_EXTENSION_TYPES: Final = frozenset(
    {tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
)

# Finding codes. The error class (ERR_*) says how bad it is, the code why.
CODE_NOT_GZIP: Final = "not_gzip"
CODE_COMPRESSED_TOO_LARGE: Final = "compressed_too_large"
CODE_TRUNCATED: Final = "truncated"
CODE_CORRUPT_GZIP: Final = "corrupt_gzip"
CODE_TRAILING_GZIP_DATA: Final = "trailing_gzip_data"
CODE_TOO_MANY_GZIP_MEMBERS: Final = "too_many_gzip_members"
CODE_UNCOMPRESSED_TOO_LARGE: Final = "uncompressed_too_large"
CODE_RATIO_EXCEEDED: Final = "ratio_exceeded"
CODE_NOT_A_TAR: Final = "not_a_tar"
CODE_BAD_TAR_HEADER: Final = "bad_tar_header"
CODE_TRUNCATED_TAR: Final = "truncated_tar"
CODE_MISSING_END_OF_ARCHIVE: Final = "missing_end_of_archive"
CODE_TRAILING_TAR_DATA: Final = "trailing_tar_data"
CODE_TOO_MANY_MEMBERS: Final = "too_many_members"
CODE_MEMBER_TOO_LARGE: Final = "member_too_large"
CODE_NUL_IN_NAME: Final = "nul_in_name"
CODE_CONTROL_CHAR_IN_NAME: Final = "control_char_in_name"
CODE_BACKSLASH_IN_NAME: Final = "backslash_in_name"
CODE_NAME_NOT_UTF8: Final = "name_not_utf8"
CODE_ABSOLUTE_PATH: Final = "absolute_path"
CODE_PATH_TRAVERSAL: Final = "path_traversal"
CODE_NAME_TOO_LONG: Final = "name_too_long"
CODE_EMPTY_NAME: Final = "empty_name"
CODE_DUPLICATE_MEMBER: Final = "duplicate_member"
CODE_PATH_THROUGH_SYMLINK: Final = "path_through_symlink"
CODE_HARDLINK: Final = "hardlink"
CODE_DEVICE_FILE: Final = "device_file"
CODE_FIFO: Final = "fifo"
CODE_SPARSE_FILE: Final = "sparse_file"
CODE_UNSUPPORTED_TYPE: Final = "unsupported_type"
CODE_SYMLINK_TARGET_INVALID: Final = "symlink_target_invalid"
CODE_SYMLINK_ABSOLUTE: Final = "symlink_absolute"
CODE_SYMLINK_ESCAPE: Final = "symlink_escape"
CODE_NO_ETC_CONFIG: Final = "no_etc_config"
CODE_MISSING_REQUIRED_CONFIG: Final = "missing_required_config"

# ---------------------------------------------------------------------------
# Result objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ArchiveFinding:
    """A reason code, optionally with the member path it is about.

    Paths of rejected names are escaped and shortened; they are never file
    contents. Do not log them (they may be secret paths, plan 14.2).
    """

    code: str
    path: str | None = None


@dataclass(frozen=True, slots=True)
class MemberInfo:
    """One archive member. Never carries the content.

    ``sha256`` is the digest of the content (files), of the UTF-8 link
    target (symlinks) or None (directories). For ``secret`` members
    (``config_mask.is_secret_path``) the digest is for change detection
    inside HA only: a short secret file is brute-forceable from it, so it
    must not reach the frontend.
    """

    name: str
    type: str
    size: int
    mode: int
    sha256: str | None
    secret: bool


@dataclass(frozen=True, slots=True)
class ArchiveReport:
    """Outcome of ``validate_archive``.

    ``ok`` is True exactly when ``error`` is None. ``findings`` explains the
    error; ``warnings`` never block. A structurally sound archive that only
    lacks required configs (``incomplete``) keeps ``members``, ``configs``,
    ``extra_paths`` and ``content_hash``; every other failure leaves them
    empty/None. ``uncompressed_size`` counts decoded tar bytes (headers and
    padding included) up to the point the check stopped.
    """

    ok: bool
    error: str | None
    findings: tuple[ArchiveFinding, ...]
    members: tuple[MemberInfo, ...]
    configs: frozenset[str]
    extra_paths: tuple[str, ...]
    archive_sha256: str
    content_hash: str | None
    uncompressed_size: int
    warnings: tuple[ArchiveFinding, ...] = ()


class ArchiveError(Exception):
    """Raised by ``extract_uci_texts`` for an archive that failed the check.

    The message holds the error class and reason codes only.
    """

    def __init__(self, error: str, findings: tuple[ArchiveFinding, ...]) -> None:
        codes = ",".join(finding.code for finding in findings)
        super().__init__(f"{error}: {codes}")
        self.error = error
        self.findings = findings


class UciTexts(dict[str, str]):
    """Config name -> UCI file text. ``repr``/``str`` show names and sizes only.

    The texts contain secrets in clear text; keeping them out of the
    representation stops accidental logging via ``%s``/``%r``.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        sizes = ", ".join(
            f"{name}: {len(text)} chars" for name, text in sorted(self.items())
        )
        return f"<UciTexts {sizes}>"

    __str__ = __repr__


class _Abort(Exception):
    """Internal: stop the check with an error class and one finding."""

    def __init__(self, error: str, code: str, path: str | None = None) -> None:
        super().__init__(code)
        self.error = error
        self.finding = ArchiveFinding(code, path)


# ---------------------------------------------------------------------------
# Capped gzip stream
# ---------------------------------------------------------------------------


class _CappedGunzip:
    """Read-only gzip decoder for tarfile's stream mode with a hard cap.

    ``read`` returns fewer bytes than asked only once the whole gzip stream
    (CRC32 and length of every member checked by zlib) has ended cleanly.
    """

    def __init__(self, data: memoryview, cap: int, cap_code: str) -> None:
        self._src = data
        self._pos = 0
        self._decoder = zlib.decompressobj(_ZLIB_GZIP_WBITS)
        self._gzip_members = 1
        self._pending = b""
        self._buf = bytearray()
        self._done = False
        self._cap = cap
        self._cap_code = cap_code
        self._tail = bytearray()
        self.total_out = 0
        self.delivered = 0

    def read(self, size: int = -1) -> bytes:
        while not self._done and (size < 0 or len(self._buf) < size):
            self._buf += self._produce()
        if size < 0 or size >= len(self._buf):
            out = bytes(self._buf)
            self._buf.clear()
        else:
            out = bytes(self._buf[:size])
            del self._buf[:size]
        self.delivered += len(out)
        self._tail += out
        if len(self._tail) > 2 * _TAIL_KEEP:
            del self._tail[:-_TAIL_KEEP]
        return out

    def since(self, offset: int) -> bytes:
        """Return the delivered bytes from absolute stream ``offset`` on."""
        start = self.delivered - len(self._tail)
        if offset < start:  # pragma: no cover - tarfile never reads that far ahead
            raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
        return bytes(self._tail[offset - start :])

    def drain(self) -> tuple[int, bool]:
        """Decode the rest of the stream. Return (byte count, all zero)."""
        count = 0
        all_zero = True
        while chunk := self.read(OUTPUT_CHUNK_BYTES):
            count += len(chunk)
            if all_zero and chunk.count(0) != len(chunk):
                all_zero = False
        return count, all_zero

    def _produce(self) -> bytes:
        while True:
            if self._decoder.eof:
                self._next_gzip_member()
                if self._done:
                    return b""
                continue
            if self._pending:
                chunk: bytes | memoryview = self._pending
            elif self._pos < len(self._src):
                chunk = self._src[self._pos : self._pos + INPUT_CHUNK_BYTES]
                self._pos += len(chunk)
            else:
                chunk = b""
            try:
                out = self._decoder.decompress(chunk, OUTPUT_CHUNK_BYTES)
            except zlib.error as err:
                raise _Abort(ERR_INCOMPLETE, CODE_CORRUPT_GZIP) from err
            self._pending = self._decoder.unconsumed_tail
            if out:
                self.total_out += len(out)
                if self.total_out > self._cap:
                    raise _Abort(ERR_INVALID, self._cap_code)
                return out
            if not chunk and not self._decoder.eof:
                raise _Abort(ERR_INCOMPLETE, CODE_TRUNCATED)

    def _next_gzip_member(self) -> None:
        unused = self._decoder.unused_data
        head = (unused + self._src[self._pos : self._pos + 2].tobytes())[:2]
        if head == GZIP_MAGIC:
            self._gzip_members += 1
            if self._gzip_members > MAX_GZIP_MEMBERS:
                raise _Abort(ERR_INVALID, CODE_TOO_MANY_GZIP_MEMBERS)
            self._decoder = zlib.decompressobj(_ZLIB_GZIP_WBITS)
            self._pending = unused
            return
        # Zero padding after the last member is tolerated, like gzip does.
        rest = self._src[self._pos :]
        self._pos = len(self._src)
        if unused.count(0) != len(unused) or rest.tobytes().count(0) != len(rest):
            raise _Abort(ERR_INVALID, CODE_TRAILING_GZIP_DATA)
        self._done = True


# ---------------------------------------------------------------------------
# Name and link checks
# ---------------------------------------------------------------------------


def _display(raw: str) -> str:
    """Escape a rejected name for the report (never logged)."""
    return raw.encode("unicode_escape").decode("ascii")[:_DISPLAY_MAX]


def _is_utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _check_name(raw: str, limits: ArchiveLimits) -> str:
    """Validate a member name and return its normalised form ('' = root)."""
    if "\x00" in raw:
        raise _Abort(ERR_INVALID, CODE_NUL_IN_NAME, _display(raw))
    if _CONTROL_CHARS.search(raw):
        raise _Abort(ERR_INVALID, CODE_CONTROL_CHAR_IN_NAME, _display(raw))
    if "\\" in raw:
        raise _Abort(ERR_INVALID, CODE_BACKSLASH_IN_NAME, _display(raw))
    if not _is_utf8(raw):
        raise _Abort(ERR_INVALID, CODE_NAME_NOT_UTF8, _display(raw))
    if raw.startswith("/"):
        raise _Abort(ERR_INVALID, CODE_ABSOLUTE_PATH, _display(raw))
    parts = raw.split("/")
    if ".." in parts:
        raise _Abort(ERR_INVALID, CODE_PATH_TRAVERSAL, _display(raw))
    if len(raw.encode("utf-8")) > limits.max_name_length:
        raise _Abort(ERR_INVALID, CODE_NAME_TOO_LONG, _display(raw))
    return "/".join(part for part in parts if part not in ("", "."))


def _check_symlink(name: str, target: str, limits: ArchiveLimits) -> None:
    """Allow relative targets inside the archive tree or allowed absolutes."""
    if (
        not target
        or _CONTROL_CHARS.search(target)
        or "\\" in target
        or not _is_utf8(target)
        or len(target.encode("utf-8")) > limits.max_name_length
    ):
        raise _Abort(ERR_INVALID, CODE_SYMLINK_TARGET_INVALID, name)
    if target.startswith("/"):
        resolved = posixpath.normpath(target)
        if not resolved.startswith(ARCHIVE_SYMLINK_ABS_PREFIXES):
            raise _Abort(ERR_INVALID, CODE_SYMLINK_ABSOLUTE, name)
        return
    stack = name.split("/")[:-1]
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                raise _Abort(ERR_INVALID, CODE_SYMLINK_ESCAPE, name)
            stack.pop()
        else:
            stack.append(part)


def _member_kind(member: tarfile.TarInfo) -> str:
    """Map a tar member type to MEMBER_* or raise for forbidden types."""
    if member.issparse():
        raise _Abort(ERR_INVALID, CODE_SPARSE_FILE)
    if member.isreg():
        return MEMBER_FILE
    if member.isdir():
        return MEMBER_DIR
    if member.issym():
        return MEMBER_SYMLINK
    if member.islnk():
        raise _Abort(ERR_INVALID, CODE_HARDLINK)
    if member.ischr() or member.isblk():
        raise _Abort(ERR_INVALID, CODE_DEVICE_FILE)
    if member.isfifo():
        raise _Abort(ERR_INVALID, CODE_FIFO)
    raise _Abort(ERR_INVALID, CODE_UNSUPPORTED_TYPE)


def _blocks(size: int) -> int:
    """Round a byte count up to whole tar blocks."""
    return -(-size // _TAR_BLOCK) * _TAR_BLOCK


def _octal(field: bytes) -> int:
    match = _OCTAL_FIELD.fullmatch(field)
    if match is None:
        raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
    return int(match.group(1) or b"0", 8)


def _header_block(block: bytes) -> tuple[bytes, int]:
    """Check one raw header block; return (type flag, size field)."""
    if len(block) != _TAR_BLOCK:
        raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
    # Unsigned sum only (POSIX); tarfile also takes the signed variant.
    if _octal(block[148:156]) != 256 + sum(block[:148]) + sum(block[156:]):
        raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
    return block[156:157], _octal(block[124:136])


def _check_headers(raw: bytes, member: tarfile.TarInfo) -> None:
    """Re-read the raw header blocks of ``member``; refuse any ambiguity.

    ``raw`` runs from the member's first header block (``member.offset``)
    to its data. tarfile is lenient where other tar implementations are
    not (pax numbers through ``int()``, base-256 and signed size fields,
    signed checksums, stacked and global pax headers). The restore runs
    busybox or GNU tar, so every header must mean the same to all of them.
    """
    pos = 0
    seen: set[bytes] = set()
    while True:
        kind, size = _header_block(raw[pos : pos + _TAR_BLOCK])
        pos += _TAR_BLOCK
        if pos >= len(raw):
            break
        if kind not in _EXTENSION_TYPES or kind in seen:
            raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
        seen.add(kind)
        pos += _blocks(size)
    if pos != len(raw) or size != member.size:
        raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
    pax = member.pax_headers
    if not pax:
        return
    if tarfile.XHDTYPE not in seen or any(key.startswith("GNU.sparse.") for key in pax):
        raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
    if "size" in pax and not _PAX_DECIMAL.fullmatch(pax["size"]):
        raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
    path = pax.get("path")
    if path is not None and (
        tarfile.GNUTYPE_LONGNAME in seen
        or (
            path != member.name
            and not (member.isdir() and path.rstrip("/") == member.name)
        )
    ):
        raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
    linkpath = pax.get("linkpath")
    if linkpath is not None and (
        tarfile.GNUTYPE_LONGLINK in seen or linkpath != member.linkname
    ):
        raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)


def _config_name(name: str) -> str | None:
    """Return the config name for ``etc/config/<name>``, else None."""
    if not name.startswith(ARCHIVE_CONFIG_PREFIX):
        return None
    rest = name[len(ARCHIVE_CONFIG_PREFIX) :]
    if not rest or "/" in rest:
        return None
    return rest


# ---------------------------------------------------------------------------
# Tar walk
# ---------------------------------------------------------------------------


class _Scan:
    """Collects member facts while tarfile walks the capped stream."""

    def __init__(self, limits: ArchiveLimits, keep_texts: bool) -> None:
        self._limits = limits
        self._keep_texts = keep_texts
        self._count = 0
        self._declared = 0
        self.members: dict[str, MemberInfo] = {}
        self.symlinks: set[str] = set()
        self.texts: dict[str, bytes] = {}

    def add(self, tar: tarfile.TarFile, member: tarfile.TarInfo, raw: bytes) -> None:
        """Record one member; ``raw`` holds its header blocks."""
        limits = self._limits
        self._count += 1
        if self._count > limits.max_members:
            raise _Abort(ERR_INVALID, CODE_TOO_MANY_MEMBERS)
        name = _check_name(member.name, limits)
        try:
            kind = _member_kind(member)
            _check_headers(raw, member)
        except _Abort as abort:
            raise _Abort(abort.error, abort.finding.code, name or None) from None
        if not name:
            if kind == MEMBER_DIR:
                return  # "./" root entry
            raise _Abort(ERR_INVALID, CODE_EMPTY_NAME, _display(member.name))
        previous = self.members.get(name)
        if previous is not None:
            if previous.type == MEMBER_DIR and kind == MEMBER_DIR:
                return
            raise _Abort(ERR_INVALID, CODE_DUPLICATE_MEMBER, name)

        size = 0
        digest: str | None = None
        if kind == MEMBER_FILE:
            size = member.size
            if size < 0:
                raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER, name)
            if size > limits.max_member_size:
                raise _Abort(ERR_INVALID, CODE_MEMBER_TOO_LARGE, name)
            self._declared += size
            if self._declared > limits.max_uncompressed_total:
                raise _Abort(ERR_INVALID, CODE_UNCOMPRESSED_TOO_LARGE, name)
            config = _config_name(name) if self._keep_texts else None
            digest = self._read(tar, member, size, name, keep=config)
        elif kind == MEMBER_SYMLINK:
            _check_symlink(name, member.linkname, limits)
            digest = hashlib.sha256(member.linkname.encode("utf-8")).hexdigest()
            self.symlinks.add(name)

        self.members[name] = MemberInfo(
            name=name,
            type=kind,
            size=size,
            mode=member.mode & 0o7777,
            sha256=digest,
            secret=is_secret_path(name),
        )

    def _read(
        self,
        tar: tarfile.TarFile,
        member: tarfile.TarInfo,
        size: int,
        name: str,
        *,
        keep: str | None,
    ) -> str:
        handle = tar.extractfile(member)
        if handle is None:  # pragma: no cover - regular files always have one
            raise _Abort(ERR_INVALID, CODE_UNSUPPORTED_TYPE, name)
        hasher = hashlib.sha256()
        parts: list[bytes] = []
        remaining = size
        try:
            while remaining:
                chunk = handle.read(min(remaining, OUTPUT_CHUNK_BYTES))
                if not chunk:
                    raise _Abort(ERR_INCOMPLETE, CODE_TRUNCATED_TAR, name)
                remaining -= len(chunk)
                hasher.update(chunk)
                if keep is not None:
                    parts.append(chunk)
        except tarfile.ReadError as err:
            # The capped stream only runs short after a clean gzip end, so
            # this is a tar cut off inside member data.
            raise _Abort(ERR_INCOMPLETE, CODE_TRUNCATED_TAR, name) from err
        if keep is not None:
            self.texts[keep] = b"".join(parts)
        return hasher.hexdigest()

    def check_symlink_parents(self) -> None:
        """No member may live below a symlink (extraction would follow it)."""
        if not self.symlinks:
            return
        for name in self.members:
            parts = name.split("/")
            for depth in range(1, len(parts)):
                if "/".join(parts[:depth]) in self.symlinks:
                    raise _Abort(ERR_INVALID, CODE_PATH_THROUGH_SYMLINK, name)


_TAR_ERRORS: Final = (
    tarfile.TarError,
    EOFError,
    ValueError,
    OverflowError,
    UnicodeError,
)


def _walk(stream: _CappedGunzip, scan: _Scan) -> None:
    """Walk all members, then verify end-of-archive and the gzip trailer."""
    # Opened outside "with" so open errors get their own class; the TarFile
    # is closed by the "with tar:" block right below.
    try:
        tar = tarfile.open(  # noqa: SIM115
            fileobj=stream,  # type: ignore[call-overload]
            mode="r|",
            encoding="utf-8",
            errors="surrogateescape",
        )
    except _TAR_ERRORS as err:
        stream.drain()  # a broken gzip stream wins over "not a tar"
        raise _Abort(ERR_INVALID, CODE_NOT_A_TAR) from err

    # "end" is where the next header must start: right after the data of the
    # last member the check accepted. tarfile can move its own offset past
    # bytes it never reported (a pax header that fails after the following
    # header was read, review C1), so its offset is only trusted when it
    # agrees with ours.
    end = 0
    with tar:
        while True:
            try:
                member = tar.next()
            except _TAR_ERRORS as err:
                stream.drain()
                # After the drain, "delivered" is the full tar stream length.
                if tar.offset >= stream.delivered:
                    raise _Abort(ERR_INCOMPLETE, CODE_TRUNCATED_TAR) from err
                raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER) from err
            if tar.pax_headers:  # a global pax header was read
                raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
            if member is None:
                break
            if member.offset != end or member.offset_data <= end:
                raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
            raw = stream.since(end)[: member.offset_data - end]
            scan.add(tar, member, raw)
            end = member.offset_data
            if member.isreg():
                end += _blocks(member.size)
            if tar.offset != end:
                raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
        if tar.offset != end:
            raise _Abort(ERR_INVALID, CODE_BAD_TAR_HEADER)
        # tarfile stops silently at a zero block, an empty read, a cut-off
        # header or a header with a bad checksum. Only the first is a real
        # end of archive: everything from there on must be zeros.
        trailer = stream.since(end)

    rest_count, rest_zero = stream.drain()
    length = len(trailer) + rest_count
    if trailer.count(0) == len(trailer) and rest_zero:
        if length < _TAR_BLOCK:
            raise _Abort(ERR_INCOMPLETE, CODE_MISSING_END_OF_ARCHIVE)
        return
    if length < _TAR_BLOCK:
        raise _Abort(ERR_INCOMPLETE, CODE_MISSING_END_OF_ARCHIVE)
    raise _Abort(ERR_INVALID, CODE_TRAILING_TAR_DATA)


def _failed(
    error: str, finding: ArchiveFinding, archive_sha256: str, uncompressed: int
) -> ArchiveReport:
    return ArchiveReport(
        ok=False,
        error=error,
        findings=(finding,),
        members=(),
        configs=frozenset(),
        extra_paths=(),
        archive_sha256=archive_sha256,
        content_hash=None,
        uncompressed_size=uncompressed,
    )


def _scan(
    data: bytes, limits: ArchiveLimits, *, keep_texts: bool
) -> tuple[ArchiveReport, dict[str, bytes]]:
    view = memoryview(data).cast("B")
    archive_sha256 = hashlib.sha256(view).hexdigest()

    if len(view) > limits.max_compressed:
        finding = ArchiveFinding(CODE_COMPRESSED_TOO_LARGE)
        _LOGGER.debug("Archive rejected: %s/%s", ERR_TOO_LARGE, finding.code)
        return _failed(ERR_TOO_LARGE, finding, archive_sha256, 0), {}
    if view[:2].tobytes() != GZIP_MAGIC:
        finding = ArchiveFinding(CODE_NOT_GZIP)
        _LOGGER.debug("Archive rejected: %s/%s", ERR_INVALID, finding.code)
        return _failed(ERR_INVALID, finding, archive_sha256, 0), {}

    ratio_cap = max(RATIO_CHECK_FLOOR_BYTES, limits.max_ratio * len(view))
    if ratio_cap < limits.max_uncompressed_total:
        stream = _CappedGunzip(view, ratio_cap, CODE_RATIO_EXCEEDED)
    else:
        stream = _CappedGunzip(
            view, limits.max_uncompressed_total, CODE_UNCOMPRESSED_TOO_LARGE
        )
    scan = _Scan(limits, keep_texts)
    try:
        _walk(stream, scan)
        scan.check_symlink_parents()
    except _Abort as abort:
        _LOGGER.debug(
            "Archive rejected: %s/%s after %d decoded bytes",
            abort.error,
            abort.finding.code,
            stream.total_out,
        )
        return _failed(abort.error, abort.finding, archive_sha256, stream.total_out), {}

    members = tuple(sorted(scan.members.values(), key=lambda member: member.name))
    configs = frozenset(
        config
        for member in members
        if member.type == MEMBER_FILE and (config := _config_name(member.name))
    )
    extra_paths = tuple(
        member.name for member in members if member.name.split("/", 1)[0] != "etc"
    )
    findings: tuple[ArchiveFinding, ...]
    if not configs:
        findings = (ArchiveFinding(CODE_NO_ETC_CONFIG),)
    else:
        findings = tuple(
            ArchiveFinding(CODE_MISSING_REQUIRED_CONFIG, ARCHIVE_CONFIG_PREFIX + name)
            for name in sorted(ARCHIVE_REQUIRED_CONFIGS - configs)
        )
    error = ERR_INCOMPLETE if findings else None
    _LOGGER.debug(
        "Archive checked: %d members, %d configs, %d decoded bytes, result %s",
        len(members),
        len(configs),
        stream.total_out,
        error or "ok",
    )
    report = ArchiveReport(
        ok=error is None,
        error=error,
        findings=findings,
        members=members,
        configs=configs,
        extra_paths=extra_paths,
        archive_sha256=archive_sha256,
        content_hash=content_hash(members),
        uncompressed_size=stream.total_out,
    )
    return report, scan.texts


# ---------------------------------------------------------------------------
# Public API (plan section 11.3)
# ---------------------------------------------------------------------------


def validate_archive(
    data: bytes, limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS
) -> ArchiveReport:
    """Check a ``sysupgrade -b`` archive (tar.gz) in memory.

    Never raises for bad input; every problem ends up in the report with an
    error class (``too_large``, ``invalid``, ``incomplete``) and a reason
    code. Synchronous and CPU-bound: run it in the executor.
    """
    report, _ = _scan(data, limits, keep_texts=False)
    return report


def content_hash(members: Iterable[MemberInfo]) -> str:
    """SHA-256 over the sorted (name, type, mode, digest) of all members.

    Leaves out mtime, uid/gid, user/group names, member order, tar format
    and the gzip header, so two ``sysupgrade -b`` runs over the same files
    give the same hash (plan D2).
    """
    rows = sorted([m.name, m.type, m.mode, m.sha256 or ""] for m in members)
    payload = json.dumps(
        [CONTENT_HASH_SCHEME, rows], ensure_ascii=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def verify_checksum(data: bytes, expected_sha256: str) -> bool:
    """Return True if ``data`` hashes to ``expected_sha256`` (hex, any case)."""
    if not isinstance(expected_sha256, str) or not _SHA256_HEX.fullmatch(
        expected_sha256
    ):
        return False
    actual = hashlib.sha256(data).hexdigest()
    return hmac.compare_digest(actual, expected_sha256.lower())


def extract_uci_texts(
    data: bytes, limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS
) -> UciTexts:
    """Return the UCI files directly under ``etc/config/``, in memory only.

    Runs the full ``validate_archive`` check in the same pass and raises
    ``ArchiveError`` if it fails (including ``incomplete``). Keys are config
    names (``network``), values the file text (UTF-8, invalid bytes
    replaced). Symlinks and sub-directories are skipped.

    The texts hold secrets in clear text. The caller must pass them straight
    to the snapshot normalisation with a secret digest
    (``config_snapshot.normalize_uci``) and drop them; never log, store or
    return them. The returned ``UciTexts`` hides the texts from ``repr``.
    """
    report, raw = _scan(data, limits, keep_texts=True)
    if not report.ok:
        raise ArchiveError(report.error or ERR_INVALID, report.findings)
    return UciTexts(
        {name: text.decode("utf-8", "replace") for name, text in sorted(raw.items())}
    )


def with_uci_cross_check(
    report: ArchiveReport, uci_configs: Collection[str]
) -> ArchiveReport:
    """Add ``config_missing_in_archive`` warnings (plan 7, point 4).

    ``uci_configs`` are the configs the router reported over ubus at the
    same time. A config missing from the archive is a warning only. Failed
    reports are returned unchanged.
    """
    if not report.ok:
        return report
    existing = set(report.warnings)
    added = tuple(
        finding
        for name in sorted(set(uci_configs) - report.configs)
        if (
            finding := ArchiveFinding(
                WARN_CONFIG_MISSING_IN_ARCHIVE, ARCHIVE_CONFIG_PREFIX + name
            )
        )
        not in existing
    )
    if not added:
        return report
    return replace(report, warnings=report.warnings + added)
