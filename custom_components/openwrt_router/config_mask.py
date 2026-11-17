"""Secret detection and masking for the configuration manager.

Plan: docs/plans/2026-11-17-config-manager.md, sections 11.5 and 14.

Two layers (plan D5):
- In memory, secret UCI values are replaced by ``{"secret": "<hmac16>"}``
  using ``secret_digest_factory`` (done by config_snapshot), so a key change
  is visible as a different digest without the plaintext.
- On the way out (HTTP response, log, event, diagnostics), ``mask_for_output``
  and ``redact_text`` are the last barrier. They over-mask on purpose: an
  unknown name that looks like a secret is masked.

Pure module: no Home Assistant imports, no I/O. Never logs values.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import posixpath
import re
from collections.abc import Callable, Mapping
from dataclasses import fields, is_dataclass
from enum import Enum
from fnmatch import fnmatchcase
from typing import Any, Final

from .config_const import (
    MASK_PLACEHOLDER,
    SECRET_ARCHIVE_PATHS,
    SECRET_CONTEXT_OPTIONS,
    SECRET_DIGEST_LENGTH,
    SECRET_DIGEST_MIN_KEY_BYTES,
    SECRET_EXTRA_NAMES,
    SECRET_MARKER_KEY,
    SECRET_OPTION_PATTERNS,
    SECRET_OPTION_WHITELIST,
    SECRET_OPTIONS,
)

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "is_secret_name",
    "is_secret_option",
    "is_secret_path",
    "mask_for_output",
    "redact_text",
    "secret_digest_factory",
]

_CONTEXT_NAMES: Final[frozenset[str]] = frozenset(
    name for rule in SECRET_CONTEXT_OPTIONS for name in rule.options
)
_ALWAYS_SECRET: Final[frozenset[str]] = (
    SECRET_OPTIONS | SECRET_EXTRA_NAMES | _CONTEXT_NAMES
)
_ARCHIVE_PATTERNS: Final[tuple[str, ...]] = tuple(
    p.lower() for p in SECRET_ARCHIVE_PATHS
)

# Record shapes recognised by mask_for_output (see _mask_mapping).
_OPTION_VALUE_KEYS: Final = frozenset(
    {"old", "new", "value", "values", "before", "after", "current", "previous"}
)
_PATH_KEYS: Final = ("path", "name", "member", "file", "filename")
_CONTENT_KEYS: Final = frozenset(
    {"content", "contents", "data", "text", "body", "raw", "value", "lines"}
)
_MAX_DEPTH: Final = 64


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _normalise_name(name: str) -> str:
    """Lower-case, '-' as '_', no quotes/leading dashes, last dotted segment."""
    norm = name.strip().strip("'\"").lower().replace("-", "_").lstrip("_")
    return norm.rsplit(".", 1)[-1]


def is_secret_name(name: str) -> bool:
    """Return True if an option/field name carries a secret, in any config.

    Exact names (14.1), context names (treated as secret everywhere) and
    credential names from HTTP/CLI output are always secret. Other names are
    secret if the safety-net pattern matches and they are not whitelisted.
    """
    if not isinstance(name, str):
        return False
    norm = _normalise_name(name)
    if not norm:
        return False
    if norm in _ALWAYS_SECRET:
        return True
    if norm in SECRET_OPTION_WHITELIST:
        return False
    return any(pattern.search(norm) for pattern in SECRET_OPTION_PATTERNS)


def is_secret_option(config: str, section_type: str, option: str) -> bool:
    """Return True if UCI ``config.<section_type>.option`` holds a secret."""
    if is_secret_name(option):
        return True
    cfg = (config or "").lower()
    stype = (section_type or "").lower()
    opt = _normalise_name(option or "")
    return any(
        opt in rule.options
        and fnmatchcase(cfg, rule.config)
        and fnmatchcase(stype, rule.section_type)
        for rule in SECRET_CONTEXT_OPTIONS
    )


def _normalise_path(path: str) -> str:
    norm = path.replace("\\", "/").replace("\x00", "").strip()
    if not norm:
        return ""
    norm = posixpath.normpath(norm).lstrip("/")
    while norm.startswith("../"):
        norm = norm[3:]
    return "" if norm in (".", "..") else norm.lower()


def is_secret_path(path: str) -> bool:
    """Return True if an archive member's content must never be shown."""
    if not isinstance(path, str):
        return False
    norm = _normalise_path(path)
    if not norm:
        return False
    return any(fnmatchcase(norm, pattern) for pattern in _ARCHIVE_PATTERNS)


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------


def secret_digest_factory(key: bytes) -> Callable[[str], str]:
    """Return ``digest(value) -> hex`` = first 16 hex chars of HMAC-SHA256.

    The caller builds ``value`` (plan 3.2: ``config/section/option/value``).
    The installation key comes from enterprise-core and must be bytes with at
    least 16 bytes (32 recommended).
    """
    if isinstance(key, str) or not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("secret digest key must be bytes")
    raw = bytes(key)
    if len(raw) < SECRET_DIGEST_MIN_KEY_BYTES:
        raise ValueError(
            f"secret digest key must have at least {SECRET_DIGEST_MIN_KEY_BYTES} bytes"
        )

    def digest(value: str) -> str:
        data = value.encode("utf-8", errors="surrogatepass")
        return hmac.new(raw, data, hashlib.sha256).hexdigest()[:SECRET_DIGEST_LENGTH]

    return digest


# ---------------------------------------------------------------------------
# Free text
# ---------------------------------------------------------------------------

# PEM blocks, also unterminated ones (stderr is cut at 4 KiB).
_PEM_RE: Final = re.compile(
    r"-----BEGIN [^\r\n-]*-----.*?(?:-----END [^\r\n-]*-----|\Z)", re.DOTALL
)
# scheme://user:password@host
_URL_CRED_RE: Final = re.compile(r"(\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@]*):[^\s/@]*@")
_AUTH_SCHEME_RE: Final = re.compile(
    r"\b(Bearer|Basic|Digest)[ \t]+[A-Za-z0-9._~+/=\-]+", re.IGNORECASE
)
# Heads after which a value follows. Only the head is consumed by finditer,
# so a non-secret match never swallows a secret later on the same line.
_UCI_HEAD_RE: Final = re.compile(
    r"\b(?:option|list)[ \t]+(['\"]?)(?P<name>[A-Za-z0-9_.\-]+)\1[ \t]+"
)
_ASSIGN_HEAD_RE: Final = re.compile(
    r"(?P<q>[\"']?)(?P<name>[A-Za-z0-9_.@\[\]\-]+)(?P=q)[ \t]*[=:][ \t]*"
)
_FLAG_HEAD_RE: Final = re.compile(
    r"(?<![\w\-])(?P<name>--?[A-Za-z][A-Za-z0-9_\-]*)[ \t]+(?=[^\s\-])"
)
# Value: complete double-quoted, complete single-quoted (UCI '\'' escapes),
# otherwise the rest of the line (over-masking on purpose).
_VALUE_RE: Final = re.compile(
    r"\"(?:[^\"\\\r\n]|\\.)*\"|'(?:'\\''|[^'\r\n])*'|[^\r\n]*"
)
_UCI_VALUE_RE: Final = re.compile(r"[^\r\n]*")
# crypt(3) hashes as in /etc/shadow.
_CRYPT_RE: Final = re.compile(r"\$(?:1|2[abxy]?|5|6|7|y|gy|sha1|md5|apr1)\$[^\s:'\"]+")
# 32-byte keys in base64 (WireGuard private/preshared keys).
_WG_KEY_RE: Final = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])"
)
# 32 hex chars standing alone: ubus session token shape.
_HEX32_RE: Final = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32}(?![0-9A-Za-z])")


def _quoted_mask(value: str) -> str:
    if value[:1] in ("'", '"') and len(value) >= 2 and value[-1] == value[0]:
        return f"{value[0]}{MASK_PLACEHOLDER}{value[0]}"
    return MASK_PLACEHOLDER


def _mask_after_heads(
    text: str, head_re: re.Pattern[str], value_re: re.Pattern[str]
) -> str:
    out: list[str] = []
    pos = 0
    for match in head_re.finditer(text):
        if match.start() < pos or not is_secret_name(match.group("name")):
            continue
        value = value_re.match(text, match.end())
        end = value.end() if value else match.end()
        if end == match.end():
            continue
        out.append(text[pos : match.end()])
        out.append(_quoted_mask(text[match.end() : end]))
        pos = end
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def redact_text(text: str) -> str:
    """Remove secrets from free text (error messages, stderr, log lines).

    Covers PEM blocks, URL credentials, Authorization schemes, UCI file lines
    (``option key '…'``), ``uci show``/``name=value``/``name: value``/JSON
    pairs with a secret name, ``--flag value``, crypt hashes, base64 32-byte
    keys and 32-hex session tokens.
    """
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return text
    text = _PEM_RE.sub(MASK_PLACEHOLDER, text)
    text = _URL_CRED_RE.sub(rf"\1:{MASK_PLACEHOLDER}@", text)
    text = _AUTH_SCHEME_RE.sub(rf"\1 {MASK_PLACEHOLDER}", text)
    text = _mask_after_heads(text, _UCI_HEAD_RE, _UCI_VALUE_RE)
    text = _mask_after_heads(text, _ASSIGN_HEAD_RE, _VALUE_RE)
    text = _mask_after_heads(text, _FLAG_HEAD_RE, _VALUE_RE)
    text = _CRYPT_RE.sub(MASK_PLACEHOLDER, text)
    text = _WG_KEY_RE.sub(MASK_PLACEHOLDER, text)
    return _HEX32_RE.sub(MASK_PLACEHOLDER, text)


# ---------------------------------------------------------------------------
# Structured output
# ---------------------------------------------------------------------------


def _secret_value(value: Any) -> Any:
    """Mask a value under a secret name. None/bool carry no secret."""
    if value is None or isinstance(value, bool):
        return value
    return MASK_PLACEHOLDER


def _path_value(value: Any) -> Any:
    """Mask a value keyed by a secret path; presence and sizes stay."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return MASK_PLACEHOLDER


def _is_marker(mapping: Mapping[Any, Any]) -> bool:
    if len(mapping) != 1:
        return False
    ((only_key, value),) = mapping.items()
    return (
        isinstance(only_key, str)
        and only_key.lower() == SECRET_MARKER_KEY
        and isinstance(value, str)
    )


def _mask_mapping(mapping: Mapping[Any, Any], stack: set[int], depth: int) -> Any:
    if _is_marker(mapping):
        return MASK_PLACEHOLDER

    masked_keys: set[str] = set()
    option = mapping.get("option")
    if isinstance(option, str):
        config = mapping.get("config")
        section_type = mapping.get("section_type", mapping.get("type"))
        if is_secret_option(
            config if isinstance(config, str) else "",
            section_type if isinstance(section_type, str) else "",
            option,
        ):
            masked_keys |= _OPTION_VALUE_KEYS
    for path_key in _PATH_KEYS:
        path = mapping.get(path_key)
        if isinstance(path, str) and is_secret_path(path):
            masked_keys |= _CONTENT_KEYS
            break

    result: dict[Any, Any] = {}
    for key, value in mapping.items():
        if isinstance(key, str):
            if key.lower() in masked_keys or is_secret_name(key):
                result[key] = _secret_value(value)
                continue
            if is_secret_path(key):
                result[key] = _path_value(value)
                continue
        result[key] = _mask(value, stack, depth + 1)
    return result


def _mask(obj: Any, stack: set[int], depth: int) -> Any:
    if obj is None or isinstance(obj, (bool, int, float, Enum)):
        return obj
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return MASK_PLACEHOLDER
    if isinstance(obj, BaseException):
        return redact_text(str(obj))

    is_dc = is_dataclass(obj) and not isinstance(obj, type)
    if not (is_dc or isinstance(obj, (Mapping, list, tuple, set, frozenset))):
        return obj

    if depth > _MAX_DEPTH:
        _LOGGER.debug("mask_for_output: nesting deeper than %d masked", _MAX_DEPTH)
        return MASK_PLACEHOLDER
    ident = id(obj)
    if ident in stack:
        _LOGGER.debug("mask_for_output: cyclic reference masked")
        return MASK_PLACEHOLDER
    stack.add(ident)
    try:
        if is_dc:
            as_map = {f.name: getattr(obj, f.name) for f in fields(obj)}
            return _mask_mapping(as_map, stack, depth)
        if isinstance(obj, Mapping):
            return _mask_mapping(obj, stack, depth)
        items = [_mask(item, stack, depth + 1) for item in obj]
        if isinstance(obj, list):
            return items
        if isinstance(obj, tuple):
            if hasattr(obj, "_fields"):  # namedtuple
                return type(obj)(*items)
            return tuple(items)
        if isinstance(obj, frozenset):
            return frozenset(items)
        return set(items)
    finally:
        stack.discard(ident)


def mask_for_output(obj: Any) -> Any:
    """Return a masked copy of ``obj`` for JSON responses, logs and events.

    Never mutates ``obj``. Handles nested dict/Mapping, list, tuple, set and
    dataclass instances (dataclasses become dicts). Rules:
    - ``{"secret": …}`` digest markers become ``"***"``.
    - Values under a secret key name become ``"***"`` (None/bool stay).
    - Records with ``option`` (diff changes) mask old/new/value when the option
      is secret; records with ``path``/``name`` of a secret archive member mask
      their content fields.
    - Values keyed by a secret archive path are masked (sizes/flags stay).
    - bytes are always masked; every string goes through ``redact_text``.
    - Cycles and nesting deeper than 64 levels are masked.
    """
    return _mask(obj, set(), 0)
