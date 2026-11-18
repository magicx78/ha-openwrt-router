"""Normalized UCI snapshots for configuration comparison and drift.

Plan: docs/plans/2026-11-17-config-manager.md, sections 3, 11.4 and 14.1.

Three sources describe the same router configuration:

- ubus ``uci get {"config": X}`` (the ``values`` mapping),
- ``uci show X`` over SSH (:func:`parse_uci_show`),
- the UCI file text from ``/etc/config/X`` or a backup archive
  (:func:`parse_uci_file`).

All parsers return the ubus shape ``{section: {".type", ".name",
".anonymous", ".index", option: value}}``. :func:`normalize_uci` turns that
into a source-independent form, :func:`build_snapshot` hashes it.

Normalized form of one config (``UciSnapshot.configs[config]``)::

    {
        "sections": {
            "<section key>": {"type": "<section type>", "options": {...}},
        },
        "order": ["<section key>", ...],   # source order of the sections
    }

Section keys:

- named section: its name (``lan``, ``default_radio0``)
- anonymous section of a type with identity fields:
  ``@<type>`` + canonical JSON of those fields, e.g.
  ``@rule{"name":"Allow-Ping"}`` or
  ``@bridge-vlan{"device":"br-lan","vlan":"10"}``
- other anonymous sections: ``@<type>[n]``, n = position among the
  anonymous sections of that type *without* identity (0-based)
- identity collisions: the first of the colliding sections (ordered by
  content) keeps the key, the others get ``#2``, ``#3``, ...

Random ``cfgXXXXXX`` names never appear. Values are not converted (``"1"``
stays ``"1"``), lists keep their order. A one-element list is stored like an
option, because ``uci show`` prints both the same way. Secret option values
are replaced by ``{"secret": "<hmac16>"}`` (per element for lists); the
digest covers config, section type, option and value, not the section key
(:func:`secret_digest_input`).

Pure module: no Home Assistant imports, no I/O, never logs values.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from .config_const import (
    SECRET_MARKER_KEY,
    UCI_CONFIGS,
    UCI_TEXT_MAX_BYTES,
    UPLINK_INTERFACE_NAMES,
)
from .config_mask import is_secret_option

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "ANON_PREFIX",
    "NORM_OPTIONS",
    "NORM_ORDER",
    "NORM_SECTIONS",
    "NORM_TYPE",
    "SECTION_IDENTITY_FIELDS",
    "UciParseResult",
    "UciSnapshot",
    "UciTextTooLargeError",
    "build_snapshot",
    "canonical_json",
    "fingerprint_from_coordinator",
    "normalize_uci",
    "parse_uci_file",
    "parse_uci_file_detailed",
    "parse_uci_show",
    "parse_uci_show_detailed",
    "secret_digest_input",
]

# ---------------------------------------------------------------------------
# Constants of the normalized form
# ---------------------------------------------------------------------------

NORM_SECTIONS: Final = "sections"
NORM_ORDER: Final = "order"
NORM_TYPE: Final = "type"
NORM_OPTIONS: Final = "options"
ANON_PREFIX: Final = "@"
_COLLISION_SEP: Final = "#"

# Identity of anonymous sections per (config, section type): candidate field
# tuples, the first candidate whose fields are all set (non-empty) wins.
# Without a match the section falls back to type + position.
SECTION_IDENTITY_FIELDS: Final[
    Mapping[tuple[str, str], tuple[tuple[str, ...], ...]]
] = MappingProxyType(
    {
        ("firewall", "rule"): (("name",),),
        ("firewall", "redirect"): (("name",),),
        ("firewall", "zone"): (("name",),),
        ("firewall", "nat"): (("name",),),
        ("firewall", "ipset"): (("name",),),
        ("firewall", "forwarding"): (("src", "dest"),),
        ("firewall", "include"): (("path",),),
        ("dhcp", "host"): (("mac",), ("name",)),
        ("dhcp", "domain"): (("name",),),
        ("dhcp", "cname"): (("cname",),),
        ("dhcp", "dhcp"): (("interface",),),
        ("wireless", "wifi-iface"): (
            ("device", "ifname"),
            ("device", "mode", "ssid"),
            ("device", "ssid"),
            ("device", "mode", "mesh_id"),
            ("device", "mesh_id"),
        ),
        ("network", "bridge-vlan"): (("device", "vlan"),),
        ("network", "switch_vlan"): (("device", "vlan"),),
        ("network", "switch_port"): (("device", "port"),),
        ("network", "switch"): (("name",),),
        ("network", "device"): (("name",),),
        ("network", "route"): (
            ("interface", "target", "netmask"),
            ("interface", "target"),
            ("target",),
        ),
        ("network", "route6"): (("interface", "target"), ("target",)),
        ("system", "led"): (("name",), ("sysfs",)),
        ("rpcd", "login"): (("username",),),
        ("sqm", "queue"): (("interface",),),
    }
)

# UCI names (libuci uci_validate_name / uci_validate_type).
_NAME_RE: Final = re.compile(r"[A-Za-z0-9_]+")
_TYPE_RE: Final = re.compile(r"[A-Za-z0-9_\-]+")

# One `uci show` record: "<config>.<section>=<type>" or
# "<config>.<section>.<option>=<value>"; anonymous sections as "@type[n]".
_SHOW_HEAD_RE: Final = re.compile(
    r"(?P<config>[A-Za-z0-9_\-]+)\."
    r"(?P<section>@[A-Za-z0-9_\-]+\[-?\d+\]|[A-Za-z0-9_]+)"
    r"(?:\.(?P<option>[A-Za-z0-9_]+))?=(?P<value>.*)",
    re.DOTALL,
)

_FINGERPRINT_VERSION: Final = 1

# ---------------------------------------------------------------------------
# Result objects
# ---------------------------------------------------------------------------


class UciTextTooLargeError(Exception):
    """A UCI text above ``UCI_TEXT_MAX_BYTES``; it was not parsed (review M6).

    Not a ValueError: callers map it to the ``too_large`` error class
    instead of treating it as a programming error.
    """


@dataclass(frozen=True, slots=True)
class UciParseResult:
    """Parsed UCI text in ubus shape plus the number of skipped statements."""

    sections: dict[str, dict[str, Any]]
    skipped: int
    package: str | None = None


@dataclass(frozen=True, slots=True)
class UciSnapshot:
    """Normalized UCI configs of one router at one point in time.

    ``configs`` holds the normalized form per config (secrets already as
    digest markers), ``content_hash`` the SHA-256 hex of its canonical JSON,
    ``missing`` the requested configs that were not readable/present.
    """

    configs: Mapping[str, Mapping[str, Any]]
    content_hash: str
    missing: frozenset[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def canonical_json(obj: Any) -> str:
    """Return the canonical JSON used for hashing (sorted keys, compact)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(obj: Any) -> str:
    data = canonical_json(obj).encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(data).hexdigest()


def _new_section(stype: str, name: str, anonymous: bool, index: int) -> dict[str, Any]:
    return {".type": stype, ".name": name, ".anonymous": anonymous, ".index": index}


def _check_size(text: str) -> None:
    """Refuse texts above UCI_TEXT_MAX_BYTES before any parsing (review M6).

    Counts characters: a text within the byte cap never has more characters
    than bytes, so this is never stricter than the cap on the raw bytes.
    """
    if len(text) > UCI_TEXT_MAX_BYTES:
        raise UciTextTooLargeError(
            f"UCI text of {len(text)} characters exceeds {UCI_TEXT_MAX_BYTES}"
        )


# ---------------------------------------------------------------------------
# UCI file format (/etc/config/*, `uci export`)
# ---------------------------------------------------------------------------


def _statements(text: str) -> Iterator[tuple[list[str], bool]]:
    """Split UCI file text into statements of tokens, like libuci's parser.

    Yields ``(tokens, broken)``. A statement ends at an unquoted newline or
    ``;``. ``#`` outside quotes starts a comment. Single quotes are literal,
    double quotes and unquoted text take ``\\`` escapes, ``\\`` + newline
    continues the line, quoted values may span lines, adjacent quoted and
    unquoted parts form one token (``'it'\\''s'``). A quote still open at the
    end of the text yields one broken statement and ends the scan.
    """
    n = len(text)
    i = 0
    tokens: list[str] = []
    buf: list[str] = []
    in_token = False

    def end_token() -> None:
        nonlocal buf, in_token
        if in_token:
            tokens.append("".join(buf))
        buf = []
        in_token = False

    while i < n:
        c = text[i]
        if c in "\n;":
            end_token()
            if tokens:
                yield tokens, False
                tokens = []
            i += 1
        elif c in " \t\r\f\v":
            end_token()
            i += 1
        elif c == "#":
            end_token()
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
        elif c == "\\":
            if i + 1 < n and text[i + 1] != "\n":
                buf.append(text[i + 1])
                in_token = True
            i += 2
        elif c == "'":
            close = text.find("'", i + 1)
            if close < 0:
                yield tokens, True
                return
            buf.append(text[i + 1 : close])
            in_token = True
            i = close + 1
        elif c == '"':
            j = i + 1
            part: list[str] = []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n:
                    if text[j + 1] != "\n":
                        part.append(text[j + 1])
                    j += 2
                    continue
                part.append(text[j])
                j += 1
            if j >= n:
                yield tokens, True
                return
            buf.extend(part)
            in_token = True
            i = j + 1
        else:
            buf.append(c)
            in_token = True
            i += 1
    end_token()
    if tokens:
        yield tokens, False


def parse_uci_file_detailed(text: str) -> UciParseResult:
    """Parse UCI file text into the ubus shape, counting skipped statements.

    Understands ``package``, ``config``, ``option``, ``list``, single and
    double quotes (incl. ``'\\''``), backslash continuation, multi-line
    quoted values, comments and blank lines. Broken statements are skipped
    and counted, never raised: unknown keywords, wrong argument counts,
    invalid names, options outside a section (also below a broken
    ``config`` line), options without or with an empty value, and an
    unterminated quote at the end of the text.

    Anonymous sections get the key ``@<type>[n]`` (n counts all sections of
    the type, named ones included, as ``uci show`` does) with
    ``.anonymous = True``. A repeated named section continues the first one
    (libuci in non-strict mode), ``list`` after ``option`` turns the value
    into a list, ``option`` after ``list`` replaces it.
    """
    if not isinstance(text, str):
        raise TypeError("UCI text must be str")
    _check_size(text)
    sections: dict[str, dict[str, Any]] = {}
    type_counts: dict[str, int] = {}
    current: dict[str, Any] | None = None
    package: str | None = None
    skipped = 0

    for tokens, broken in _statements(text.replace("\r\n", "\n")):
        if broken:
            skipped += 1
            continue
        keyword, args = tokens[0], tokens[1:]
        if keyword == "package":
            if len(args) == 1 and _TYPE_RE.fullmatch(args[0]):
                package = package or args[0]
            else:
                skipped += 1
            continue
        if keyword == "config":
            current = None
            if not 1 <= len(args) <= 2 or not _TYPE_RE.fullmatch(args[0]):
                skipped += 1
                continue
            stype = args[0]
            if len(args) == 2:
                name = args[1]
                if not _NAME_RE.fullmatch(name):
                    skipped += 1
                    continue
                if name in sections:
                    current = sections[name]
                    current[".type"] = stype
                    continue
                anonymous = False
            else:
                name = f"{ANON_PREFIX}{stype}[{type_counts.get(stype, 0)}]"
                anonymous = True
            type_counts[stype] = type_counts.get(stype, 0) + 1
            current = _new_section(stype, name, anonymous, len(sections))
            sections[name] = current
            continue
        if keyword in ("option", "list"):
            if (
                current is None
                or len(args) != 2
                or not _NAME_RE.fullmatch(args[0])
                or (keyword == "option" and args[1] == "")
            ):
                skipped += 1
                continue
            option, value = args
            if keyword == "option":
                current[option] = value
            else:
                existing = current.get(option)
                if isinstance(existing, list):
                    existing.append(value)
                elif isinstance(existing, str):
                    current[option] = [existing, value]
                else:
                    current[option] = [value]
            continue
        skipped += 1

    if skipped:
        _LOGGER.debug("UCI file text: %d statement(s) skipped", skipped)
    return UciParseResult(sections=sections, skipped=skipped, package=package)


def parse_uci_file(text: str) -> dict[str, dict[str, Any]]:
    """Parse UCI file text (``/etc/config/*``) into the ubus ``uci get`` shape."""
    return parse_uci_file_detailed(text).sections


# ---------------------------------------------------------------------------
# `uci show <config>` (SSH fallback)
# ---------------------------------------------------------------------------


# One piece of a POSIX shell word, as ``shlex`` (POSIX mode) reads it:
# 'single' | "double" (backslash escapes " and \ only) | \x | plain | blanks.
# Possessive and with disjoint alternatives, so matching stays linear.
_SHELL_PIECE_RE: Final = re.compile(
    r"'([^']*+)'"
    r'|"((?:[^"\\]++|\\.)*+)"'
    r"|\\(.)"
    r"|([^ \t\r\n'\"\\]++)"
    r"|([ \t\r\n]++)",
    re.DOTALL,
)
_DQ_ESCAPE_RE: Final = re.compile(r'\\(["\\])')


def _show_words(raw: str) -> list[str] | None:
    """Unquote a `uci show` value (POSIX shell quoting); None if unbalanced.

    Same result as ``shlex.split(raw)``, but in linear time with C-speed
    regex steps: shlex reads character by character in Python, which took
    seconds on a value near UCI_TEXT_MAX_BYTES (review M6).
    """
    words: list[str] = []
    current: list[str] | None = None
    pos, end = 0, len(raw)
    while pos < end:
        piece = _SHELL_PIECE_RE.match(raw, pos)
        if piece is None:
            return None  # open quote or trailing backslash
        pos = piece.end()
        single, double, escaped, plain, _blank = piece.groups()
        if piece.lastindex == 5:
            if current is not None:
                words.append("".join(current))
                current = None
            continue
        if current is None:
            current = []
        if single is not None:
            current.append(single)
        elif double is not None:
            current.append(_DQ_ESCAPE_RE.sub(r"\1", double))
        else:
            current.append(escaped if escaped is not None else plain)
    if current is not None:
        words.append("".join(current))
    return words


# Shell quote state at a line start inside a `uci show` record.
_Q_OUT: Final = 0  # unquoted; only reached after a backslash-newline
_Q_SINGLE: Final = 1
_Q_DOUBLE: Final = 2
_OUT_SPECIAL_RE: Final = re.compile(r"['\"\\]")
_DQ_SPECIAL_RE: Final = re.compile(r'["\\]')


def _quote_state(state: int, text: str) -> int | None:
    """Quote state after ``text`` (one line), like ``shlex`` in POSIX mode.

    Returns None if the record ends with this line (unquoted, no trailing
    backslash), else the state the next line starts in. A backslash escapes
    the next character outside single quotes; at the line end it escapes
    the newline.
    """
    pos, end = 0, len(text)
    while True:
        if state == _Q_SINGLE:
            close = text.find("'", pos)
            if close < 0:
                return _Q_SINGLE
            state, pos = _Q_OUT, close + 1
            continue
        special = (_DQ_SPECIAL_RE if state == _Q_DOUBLE else _OUT_SPECIAL_RE).search(
            text, pos
        )
        if special is None:
            return None if state == _Q_OUT else state
        char, pos = special.group(), special.end()
        if char == "\\":
            if pos >= end:
                return state  # escaped newline: the record goes on
            pos += 1
        elif state == _Q_DOUBLE:
            state = _Q_OUT
        else:
            state = _Q_SINGLE if char == "'" else _Q_DOUBLE


def _record_end(
    lines: list[str], state: int, first: int, memo: dict[tuple[int, int], int]
) -> int:
    """Last line of a record that continues at ``first`` in ``state``; -1 if none.

    ``memo`` keeps the answer per (state, line), so every line is scanned at
    most once per state over the whole text: a value whose quote never
    closes no longer makes the parser quadratic (review M6).
    """
    path: list[tuple[int, int]] = []
    result = -1
    k = first
    while k < len(lines):
        cached = memo.get((state, k))
        if cached is not None:
            result = cached
            break
        path.append((state, k))
        after = _quote_state(state, lines[k])
        if after is None:
            result = k
            break
        state, k = after, k + 1
    for key in path:
        memo[key] = result
    return result


def parse_uci_show_detailed(text: str, config: str) -> UciParseResult:
    """Parse ``uci show <config>`` output into the ubus shape.

    Same result shape as :func:`parse_uci_file` and as ``_parse_uci_show`` in
    api.py, plus ``.anonymous`` and ``.name``. A value whose quote is still
    open continues on the next lines (multi-line values); if it never closes,
    only its first line is skipped. Lines of other configs are ignored,
    lines that are no `uci show` record are skipped and counted.
    """
    if not isinstance(text, str):
        raise TypeError("uci show text must be str")
    _check_size(text)
    lines = text.replace("\r\n", "\n").split("\n")
    sections: dict[str, dict[str, Any]] = {}
    memo: dict[tuple[int, int], int] = {}
    skipped = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        match = _SHOW_HEAD_RE.fullmatch(line)
        if match is None:
            skipped += 1
            i += 1
            continue
        # Find the record end with a linear quote scan first; unquoting then
        # runs once on the whole record.
        state = _quote_state(_Q_OUT, match.group("value"))
        end = i if state is None else _record_end(lines, state, i + 1, memo)
        words: list[str] | None = None
        if end > i:
            match = _SHOW_HEAD_RE.fullmatch("\n".join(lines[i : end + 1]))
        if end >= 0 and match is not None:
            words = _show_words(match.group("value"))
        if words is None or match is None:
            skipped += 1
            i += 1
            continue
        i = end + 1
        if match.group("config") != config:
            continue
        key = match.group("section")
        section = sections.get(key)
        if section is None:
            section = _new_section("", key, key.startswith(ANON_PREFIX), len(sections))
            sections[key] = section
        option = match.group("option")
        if option is None:
            if len(words) != 1 or not _TYPE_RE.fullmatch(words[0]):
                skipped += 1
                continue
            section[".type"] = words[0]
        elif not words:
            section[option] = ""
        else:
            section[option] = words[0] if len(words) == 1 else words

    if skipped:
        _LOGGER.debug("uci show output: %d line(s) skipped", skipped)
    return UciParseResult(sections=sections, skipped=skipped, package=config)


def parse_uci_show(text: str, config: str) -> dict[str, dict[str, Any]]:
    """Parse ``uci show <config>`` output into the ubus ``uci get`` shape."""
    return parse_uci_show_detailed(text, config).sections


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


def _plain_value(value: Any) -> Any:
    """Return a JSON-safe value without converting UCI strings.

    Lists stay lists in their order; a one-element list becomes its element
    (``uci show`` prints both alike). Non-JSON objects become ``str``.
    """
    if isinstance(value, (list, tuple)):
        items = [_plain_scalar(item) for item in value]
        return items[0] if len(items) == 1 else items
    return _plain_scalar(value)


def _plain_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return str(value)


def _ordered_sections(raw: Mapping[str, Any]) -> list[tuple[str, Any]]:
    """Return the sections in source order (``.index`` if every one has it)."""
    items = [(str(key), body) for key, body in raw.items()]
    indices: list[int] = []
    for _key, body in items:
        index = body.get(".index") if isinstance(body, Mapping) else None
        if not isinstance(index, int) or isinstance(index, bool):
            return items
        indices.append(index)
    order = sorted(range(len(items)), key=lambda pos: (indices[pos], pos))
    return [items[pos] for pos in order]


def _identity(
    config: str, stype: str, options: Mapping[str, Any]
) -> dict[str, Any] | None:
    for fields in SECTION_IDENTITY_FIELDS.get((config, stype), ()):
        if any(is_secret_option(config, stype, field) for field in fields):
            continue
        values = {field: options.get(field) for field in fields}
        if all(value not in (None, "", []) for value in values.values()):
            return values
    return None


def secret_digest_input(config: str, section_type: str, option: str, value: Any) -> str:
    """Return the text fed to ``secret_digest`` for one secret value.

    Canonical JSON array ``[config, section_type, option, value]``: each part
    is quoted and escaped on its own, so no split of the parts can collide
    with another (plain ``a/b/c`` concatenation could). The section key is
    deliberately not part of it (see :func:`normalize_uci`). ``value`` is
    taken as ``str`` so ubus, ``uci show`` and file text agree.
    """
    return canonical_json([config, section_type, option, str(value)])


def _protect(
    config: str,
    stype: str,
    option: str,
    value: Any,
    secret_digest: Callable[[str], str],
) -> Any:
    """Replace a secret option value by its digest marker (per list element)."""
    if not is_secret_option(config, stype, option):
        return value

    def marker(item: Any) -> dict[str, str]:
        digest = secret_digest(secret_digest_input(config, stype, option, item))
        return {SECRET_MARKER_KEY: digest}

    if isinstance(value, list):
        return [marker(item) for item in value]
    return marker(value)


def normalize_uci(
    config: str,
    raw: Mapping[str, Any],
    secret_digest: Callable[[str], str],
) -> dict[str, Any]:
    """Normalize one config from any source shape (see module docstring).

    ``raw`` is ``{section: {".type": ..., option: value}}`` as returned by
    ubus ``uci get`` (``values``), :func:`parse_uci_show`, api.py's
    ``_parse_uci_show`` or :func:`parse_uci_file`. Keys starting with ``.``
    are metadata and dropped; a section is anonymous if ``.anonymous`` is
    true or its key starts with ``@``. ``secret_digest`` receives
    :func:`secret_digest_input` (config, section type, option, value) for
    every secret value, per element for lists.

    The section key is not part of the digest input: for anonymous sections
    it can contain an identity value such as the SSID, and renaming the SSID
    must not look like a changed WLAN key. Known and accepted consequence:
    the same secret in two sections of the same type and config (two SSIDs
    sharing one key) gives the same digest, so their equality is visible
    inside HA. Outside HA the marker is masked anyway
    (``config_mask.mask_for_output``).
    """
    prepared: list[tuple[str, str, dict[str, Any]]] = []
    fallback_counts: dict[str, int] = {}
    dropped = 0
    for key, body in _ordered_sections(raw):
        if not isinstance(body, Mapping):
            dropped += 1
            continue
        stype = body.get(".type")
        stype = stype if isinstance(stype, str) else ""
        options = {
            opt: _plain_value(value)
            for opt, value in sorted(body.items(), key=lambda kv: str(kv[0]))
            if isinstance(opt, str) and not opt.startswith(".")
        }
        anonymous = body.get(".anonymous") is True or key.startswith(ANON_PREFIX)
        if not anonymous:
            base = key
        else:
            ident = _identity(config, stype, options)
            if ident is not None:
                base = f"{ANON_PREFIX}{stype}{canonical_json(ident)}"
            else:
                position = fallback_counts.get(stype, 0)
                fallback_counts[stype] = position + 1
                base = f"{ANON_PREFIX}{stype}[{position}]"
        protected = {
            opt: _protect(config, stype, opt, value, secret_digest)
            for opt, value in options.items()
        }
        prepared.append((base, stype, protected))

    if dropped:
        _LOGGER.debug("UCI %s: %d malformed section(s) dropped", config, dropped)

    # Collisions: order members by content, so the same set of sections gets
    # the same keys whatever their position.
    groups: dict[str, list[int]] = {}
    for pos, (base, _stype, _opts) in enumerate(prepared):
        groups.setdefault(base, []).append(pos)
    final_keys: list[str] = [base for base, _stype, _opts in prepared]
    for base, members in groups.items():
        if len(members) < 2:
            continue
        ranked = sorted(
            members,
            key=lambda pos: (
                canonical_json(
                    {NORM_TYPE: prepared[pos][1], NORM_OPTIONS: prepared[pos][2]}
                ),
                pos,
            ),
        )
        for rank, pos in enumerate(ranked):
            final_keys[pos] = base if rank == 0 else f"{base}{_COLLISION_SEP}{rank + 1}"

    sections: dict[str, Any] = {}
    for pos, (_base, stype, protected) in enumerate(prepared):
        sections[final_keys[pos]] = {NORM_TYPE: stype, NORM_OPTIONS: protected}
    return {NORM_SECTIONS: sections, NORM_ORDER: final_keys}


def build_snapshot(
    raw_configs: Mapping[str, Mapping[str, Any] | None],
    secret_digest: Callable[[str], str],
    *,
    configs: Iterable[str] | None = UCI_CONFIGS,
) -> UciSnapshot:
    """Normalize and hash the configs of one router.

    ``configs`` names the configs that belong to the snapshot (default: the
    fixed list ``UCI_CONFIGS``, so an archive with more files hashes like
    the ubus snapshot). A listed config whose raw value is absent, None or
    not a mapping lands in ``missing``. ``configs=None`` takes every config
    in ``raw_configs``.
    """
    names = list(raw_configs) if configs is None else list(dict.fromkeys(configs))
    normalized: dict[str, dict[str, Any]] = {}
    missing: set[str] = set()
    for name in names:
        raw = raw_configs.get(name)
        if not isinstance(raw, Mapping):
            missing.add(name)
            continue
        normalized[name] = normalize_uci(name, raw, secret_digest)
    ignored = sum(
        1 for name in raw_configs if name not in normalized and name not in missing
    )
    if ignored:
        _LOGGER.debug("UCI snapshot: %d config(s) outside the list ignored", ignored)
    return UciSnapshot(
        configs=normalized,
        content_hash=_sha256_hex(normalized),
        missing=frozenset(missing),
    )


# ---------------------------------------------------------------------------
# Cheap fingerprint from coordinator data (plan 3.3, D3)
# ---------------------------------------------------------------------------


def _field(data: Any, key: str) -> Any:
    """Read ``key`` from a mapping or an attribute object (coordinator data)."""
    if isinstance(data, Mapping):
        return data.get(key)
    return getattr(data, key, None)


def _fp_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    return str(value)


def _fp_dicts(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _fp_sorted(items: Iterable[Any]) -> list[Any]:
    return sorted(items, key=canonical_json)


def fingerprint_from_coordinator(data: Any) -> str:
    """Return a SHA-256 hex over configuration-near coordinator fields.

    Only a trigger for a full snapshot (plan D3): no extra router call. Uses
    board/release and hostname, WAN interface + protocol, per radio entry
    the UCI section, radio, SSID, band, enabled and mode, interface names
    with IPv4 address/prefix (not for uplinks, whose address is dynamic),
    the port VLAN map, DHCP pool name/interface/size and the enabled flag of
    services. Counters, uptime, clients, leases, signal, channel, bitrate,
    running states and link status are left out. Lists are order-free.
    ``data`` is a mapping or the coordinator data object; missing or odd
    fields count as empty.
    """
    info = _field(data, "router_info")
    info = info if isinstance(info, Mapping) else {}
    release = info.get("release")
    release = release if isinstance(release, Mapping) else {}
    board = {
        "model": _fp_scalar(info.get("model")),
        "board_name": _fp_scalar(info.get("board_name")),
        "hostname": _fp_scalar(info.get("hostname")),
        "distribution": _fp_scalar(release.get("distribution")),
        "version": _fp_scalar(release.get("version")),
        "revision": _fp_scalar(release.get("revision")),
        "target": _fp_scalar(release.get("target")),
    }

    wan = _field(data, "wan_status")
    wan = wan if isinstance(wan, Mapping) else {}
    wan_iface = _fp_scalar(wan.get("interface"))
    wan_part = {"interface": wan_iface, "proto": _fp_scalar(wan.get("proto"))}

    radios = _fp_sorted(
        {
            "section": _fp_scalar(radio.get("uci_section")),
            "radio": _fp_scalar(radio.get("name")),
            "ssid": _fp_scalar(radio.get("ssid")),
            "band": _fp_scalar(radio.get("band")),
            "enabled": _fp_scalar(radio.get("enabled")),
            "mode": _fp_scalar(radio.get("mode")),
        }
        for radio in _fp_dicts(_field(data, "wifi_radios"))
    )

    uplinks = set(UPLINK_INTERFACE_NAMES)
    if isinstance(wan_iface, str) and wan_iface:
        uplinks.add(wan_iface)
    interfaces = []
    for iface in _fp_dicts(_field(data, "network_interfaces")):
        name = _fp_scalar(iface.get("logical_name") or iface.get("interface"))
        entry: dict[str, Any] = {"name": name}
        if name not in uplinks and iface.get("interface") not in uplinks:
            entry["ipv4"] = _fp_scalar(iface.get("ipv4_addr"))
            entry["prefix"] = _fp_scalar(iface.get("prefix_len"))
        interfaces.append(entry)

    vlan_map = _field(data, "port_vlan_map")
    vlans: dict[str, list[str]] = {}
    if isinstance(vlan_map, Mapping):
        for port, ids in vlan_map.items():
            items = ids if isinstance(ids, (list, tuple, set, frozenset)) else [ids]
            vlans[str(port)] = sorted(str(item) for item in items)

    pools = _fp_sorted(
        {
            "name": _fp_scalar(pool.get("name")),
            "interface": _fp_scalar(pool.get("interface")),
            "size": _fp_scalar(pool.get("size")),
        }
        for pool in _fp_dicts(_field(data, "dhcp_pools"))
    )

    services = _fp_sorted(
        {"name": _fp_scalar(svc.get("name")), "enabled": svc.get("enabled")}
        for svc in _fp_dicts(_field(data, "services"))
        if isinstance(svc.get("enabled"), bool)
    )

    return _sha256_hex(
        {
            "v": _FINGERPRINT_VERSION,
            "board": board,
            "wan": wan_part,
            "radios": radios,
            "interfaces": _fp_sorted(interfaces),
            "vlans": vlans,
            "dhcp_pools": pools,
            "services": services,
        }
    )
