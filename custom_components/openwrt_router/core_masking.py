"""The one secret masking of the integration (plan 2026-11-17).

Pure functions, no HA import, no import from any ``config_*`` module. Used
by the enterprise core (audit log, bus events, ``to_dict()``, diagnostics)
and by the configuration provider (snapshots, HTTP responses, logs). It is
the superset of the former ``config_mask`` / ``config_const`` name lists of
the config-manager branch and the core's word rules.

Two modes of detection:

PRECISE, :func:`is_snapshot_secret` ("is this UCI option a secret?"): the
decision whether a snapshot stores a UCI value as a ``{"secret": <hmac16>}``
digest marker. Exactly config-manager's rules: ``SECRET_OPTIONS``, the
context rules, its credential names, then ``SECRET_OPTION_WHITELIST``, then
``SECRET_OPTION_PATTERNS``. Readable switches like ``sae_pwe``,
``PasswordAuth`` or openvpn ``auth`` stay plain text so a diff shows them.

BROAD, :func:`is_secret_key` (alias :func:`is_secret_name`) for mapping
keys and :func:`is_secret_option` for change records: the decision for
output (audit, bus, diagnostics, API ``to_dict``). It masks everything the
precise mode masks and more:

1. exact names (UCI options, context names, HTTP/CLI credential names,
   ``DIAGNOSTICS_REDACT_KEYS``) on the full and on the normalised name
   (lower case, ``-`` as ``_``, quotes and leading dashes stripped, last
   dotted segment), always secret;
2. readable names (core metadata, ``key_mgmt``, ``PasswordAuth`` …) are
   exempt from the rules below, never from rule 1;
3. the precise pattern (``pass``, ``secret``, ``token`` … ``_key$``) unless
   whitelisted; it beats the id/hash/count suffixes (``password_hash``);
4. id/hash/count suffixes (``*_id``, ``*_hash``, ``*_count`` …) are readable;
5. secret substrings and secret words after splitting at ``_ - .``, spaces
   and CamelCase / acronym boundaries, with trailing digits dropped
   (``WEPKey`` -> ``wep key``, ``key1`` -> ``key``), and the words joined
   (``api-key``).

A change record (mapping with ``option`` and ``config``) of an option that
is readable in that config (``READABLE_CONTEXT_OPTIONS``) keeps its values,
so a diff stays useful; without a known config the broad rule masks.

Over-masking is preferred to a leak. Two walkers share one implementation:
:func:`mask_secrets` (key based, used in core ``to_dict()``) and
:func:`mask_for_output` (additionally redacts every free-text string, the
last barrier before HTTP, logs and events). :func:`redact_text` (alias
:func:`scrub_text`) cleans free text; free-text fields must never carry
configuration values in the first place.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import posixpath
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from fnmatch import fnmatchcase
from typing import Any, Final

from .const import DIAGNOSTICS_REDACT_KEYS, DIAGNOSTICS_REDACTED

_LOGGER = logging.getLogger(__name__)

MASK: Final = DIAGNOSTICS_REDACTED
TRUNCATED: Final = "**TRUNCATED**"
MAX_DEPTH: Final = 64

# Snapshot form of a secret value: {"secret": "<hmac16>"}.
SECRET_MARKER_KEY: Final = "secret"
SECRET_DIGEST_LENGTH: Final = 16
SECRET_DIGEST_MIN_KEY_BYTES: Final = 16

# --- names ------------------------------------------------------------------

# Exact UCI option names, independent of the config.
SECRET_OPTIONS: Final = frozenset(
    {
        "acct_secret",
        "api_key",
        "apikey",
        "auth_key",
        "auth_secret",
        "dae_secret",
        "key",
        "key1",
        "key2",
        "key3",
        "key4",
        "mesh_psk",
        "nas_secret",
        "passwd",
        "password",
        "pin",
        "pincode",
        "pre_shared_key",
        "preshared_key",
        "priv_key_pwd",
        "private_key",
        "psk",
        "r0kh",
        "r1kh",
        "sae_password",
        "secret",
        "shared_secret",
        "token",
        "wps_pin",
    }
)


@dataclass(frozen=True, slots=True)
class SecretContextRule:
    """Options that are secret inside a config / section type (fnmatch globs).

    The names are treated as secret everywhere as well; the rule documents
    where they come from and serves :func:`is_snapshot_secret`.
    """

    config: str
    section_type: str
    options: frozenset[str]


SECRET_CONTEXT_OPTIONS: Final = (
    SecretContextRule(
        "ddns",
        "service",
        frozenset({"password", "param_enc", "param_opt", "update_url"}),
    ),
    SecretContextRule("rpcd", "login", frozenset({"password"})),
    SecretContextRule("network", "interface", frozenset({"password", "pincode"})),
    SecretContextRule(
        "network", "wireguard_*", frozenset({"private_key", "preshared_key"})
    ),
    SecretContextRule(
        "openvpn", "*", frozenset({"auth_user_pass", "askpass", "secret", "key"})
    ),
)

# Credential names of HTTP bodies, headers and command output that
# config-manager treats as secret option names (precise mode).
_UCI_CREDENTIAL_NAMES: Final = frozenset(
    {
        "authorization",
        "cookie",
        "proxy_authorization",
        "session_id",
        "sessionid",
        "set_cookie",
        "ubus_rpc_session",
    }
)
# All credential names of HTTP bodies, headers and command output.
SECRET_EXTRA_NAMES: Final = _UCI_CREDENTIAL_NAMES | frozenset(
    {"session", "sid", "sysauth"}
)

_CONTEXT_NAMES: Final = frozenset(
    name for rule in SECRET_CONTEXT_OPTIONS for name in rule.options
)
# Precise mode: always secret, whatever the config.
_SNAPSHOT_EXACT: Final = SECRET_OPTIONS | _UCI_CREDENTIAL_NAMES | _CONTEXT_NAMES
SECRET_EXACT_KEYS: Final = (
    _SNAPSHOT_EXACT
    | SECRET_EXTRA_NAMES
    | frozenset(k.lower() for k in DIAGNOSTICS_REDACT_KEYS)
)

# config-manager's safety net for unknown option names (re.search against
# the normalised name).
SECRET_OPTION_PATTERNS: Final = (
    re.compile(
        r"(pass|secret|token|psk|private|credential|pwd|apikey|_key$|^key\d*$|pin$)"
    ),
)
# Names the pattern hits whose value is not secret and is needed; lifts only
# the pattern, never an exact name. dropbear PasswordAuth/RootPasswordAuth
# are on/off switches: the diff must show "on -> off" (HA may lose access).
SECRET_OPTION_WHITELIST: Final = frozenset(
    {
        "ft_psk_generate_local",
        "keepalive",
        "key_mgmt",
        "passwordauth",
        "persistent_keepalive",
        "rootpasswordauth",
    }
)

# Readable names: exempt from pattern, substrings and words (not from exact).
SAFE_KEYS: Final = SECRET_OPTION_WHITELIST | frozenset(
    {
        "auth_port",
        "auth_server",
        "contains_secrets",
        "dedup_key",
        "sha256",
    }
)


@dataclass(frozen=True, slots=True)
class ReadableContextRule:
    """Options whose values are not secret inside a config (fnmatch globs).

    Only lifts the broad word rules for change records that name their
    config; an option that is a snapshot secret is never lifted.
    """

    config: str
    section_type: str
    options: frozenset[str]


# Real OpenWrt options the broad words ("auth", "sae", "wpa", "key") would
# hit; config-manager stores them in plain text, so a diff shows them.
READABLE_CONTEXT_OPTIONS: Final = (
    ReadableContextRule(
        "wireless",
        "*",
        frozenset(
            {
                "auth_cache",
                "auth_type",
                "r0_key_lifetime",
                "sae_pwe",
                "sae_require_mfp",
                "wpa_disable_eapol_key_retries",
                "wpa_group_rekey",
                "wpa_strict_rekey",
            }
        ),
    ),
    ReadableContextRule(
        "dropbear", "*", frozenset({"maxauthtries", "passwordauth", "rootpasswordauth"})
    ),
    # PPP / modem authentication type (pap, chap, both, none).
    ReadableContextRule("network", "*", frozenset({"auth"})),
    # openvpn "auth" is a digest algorithm name (SHA256). "tls_auth" holds a
    # key FILE path, not the key: config-manager classifies it as readable;
    # the file's content is protected by SECRET_ARCHIVE_PATHS
    # (etc/openvpn/*, *.key). Inline keys are not a UCI option.
    ReadableContextRule(
        "openvpn", "*", frozenset({"auth", "auth_nocache", "key_direction", "tls_auth"})
    ),
    # usteer key_value: not a key; config-manager keeps it readable.
    ReadableContextRule("usteer", "*", frozenset({"key_value"})),
)
# Suffixes of counters, hashes and ids (never secret values).
SAFE_SUFFIXES: Final = ("_count", "_hash", "_sha256", "_id", "_ids")

# Secret wherever they appear in the normalised name.
SECRET_SUBSTRINGS: Final = (
    "apikey",
    "credential",
    "pass",
    "private",
    "psk",
    "pwd",
    "secret",
    "token",
)
# Whole words that mark a secret.
SECRET_WORDS: Final = frozenset(
    {
        "apikey",
        "auth",
        "authorization",
        "bearer",
        "community",  # SNMP community string
        "cookie",
        "credential",
        "credentials",
        "key",
        "passphrase",
        "passwd",
        "password",
        "pin",
        "pincode",
        "presharedkey",
        "private",
        "privatekey",
        "privkey",
        "psk",
        "pwd",
        "sae",
        "secret",
        "session",
        "sysauth",  # LuCI session cookie
        "token",
        "wepkey",
        "wpa",
    }
)

# Archive members whose content never leaves HA (path and presence only).
# fnmatch globs against the normalised lower-case member name; "*" also
# matches "/".
SECRET_ARCHIVE_PATHS: Final = (
    "etc/shadow",
    "etc/shadow-",
    "etc/passwd",
    "etc/passwd-",
    "etc/dropbear/*",
    "root/.ssh/*",
    "*/.ssh/*",
    "etc/uhttpd.key",
    "etc/config/rpcd",
    "etc/config/wireless",
    "etc/config/network",
    "etc/config/ddns",
    "etc/config/openvpn",
    "etc/config/acme",
    "etc/wireguard/*",
    "etc/openvpn/*",
    "etc/acme/*",
    "etc/ssl/private/*",
    "etc/luci-uploads/*",
    "etc/ipsec.secrets",
    "etc/swanctl/*",
    "etc/ppp/chap-secrets",
    "etc/ppp/pap-secrets",
    "etc/crontabs/*",
    "*.psk",
    "*.key",
    "*.p12",
    "*.pfx",
)

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_TRAILING_DIGITS = re.compile(r"\d+$")


def _normalise_name(name: str) -> str:
    """Lower case, ``-`` as ``_``, no quotes/leading dashes, last dotted part."""
    norm = name.strip().strip("'\"").lower().replace("-", "_").lstrip("_")
    return norm.rsplit(".", 1)[-1]


def _words(name: str) -> list[str]:
    """Split ``name`` into lower-case words without trailing digits."""
    spaced = _CAMEL.sub(" ", name)
    return [
        _TRAILING_DIGITS.sub("", part.lower()) for part in _SPLIT.split(spaced) if part
    ]


def _matches_pattern(norm: str) -> bool:
    """config-manager's safety net: pattern hit and not whitelisted."""
    return norm not in SECRET_OPTION_WHITELIST and any(
        pattern.search(norm) for pattern in SECRET_OPTION_PATTERNS
    )


def is_secret_key(name: object, extra_keys: Iterable[str] = ()) -> bool:
    """BROAD: True if a mapping key or option ``name`` may name a secret."""
    if not isinstance(name, str) or not name.strip():
        return False
    lowered = name.lower()
    norm = _normalise_name(name)
    extra = {k.lower() for k in extra_keys}
    if {lowered, norm} & (SECRET_EXACT_KEYS | extra):
        return True
    if norm in SAFE_KEYS or lowered in SAFE_KEYS:
        return False
    if _matches_pattern(norm):
        return True
    if norm.endswith(SAFE_SUFFIXES):
        return False
    if any(sub in norm for sub in SECRET_SUBSTRINGS):
        return True
    words = _words(name.rsplit(".", 1)[-1])
    if any(word in SECRET_WORDS for word in words):
        return True
    # "api-key" / "api_key" written as two words
    return "".join(words) in SECRET_WORDS


# Name used by the configuration provider; same function.
is_secret_name = is_secret_key


def _in_context(
    rules: Iterable[SecretContextRule | ReadableContextRule],
    config: str,
    section_type: str,
    option: str,
) -> bool:
    """True if a rule lists ``option`` for this config / section type."""
    cfg = (config or "").lower()
    stype = (section_type or "").lower()
    opt = _normalise_name(option or "")
    return any(
        opt in rule.options
        and fnmatchcase(cfg, rule.config)
        and fnmatchcase(stype, rule.section_type)
        for rule in rules
    )


def is_snapshot_secret(config: str, section_type: str, option: str) -> bool:
    """PRECISE: True if UCI ``config.<section_type>.option`` is a secret.

    The snapshot decision (store a ``{"secret": <hmac16>}`` marker instead
    of the value), identical to config-manager's ``is_secret_option``.
    Output paths use the broad :func:`is_secret_option` / :func:`is_secret_key`.
    """
    if not isinstance(option, str):
        return False
    norm = _normalise_name(option)
    if not norm:
        return False
    if norm in _SNAPSHOT_EXACT or _matches_pattern(norm):
        return True
    return _in_context(SECRET_CONTEXT_OPTIONS, config, section_type, option)


def is_secret_option(config: str, section_type: str, option: str) -> bool:
    """BROAD: True if output must mask the values of this UCI option.

    Masks every snapshot secret and every name :func:`is_secret_key` flags,
    except options listed as readable for this config
    (``READABLE_CONTEXT_OPTIONS``), so a diff of ``sae_pwe`` stays useful.
    """
    if is_snapshot_secret(config, section_type, option):
        return True
    if not is_secret_key(option):
        return False
    return not _in_context(READABLE_CONTEXT_OPTIONS, config, section_type, option)


def _normalise_path(path: str) -> str:
    """Posix, relative, lower case; ``..`` cannot climb out."""
    norm = path.replace("\\", "/").replace("\x00", "").strip()
    if not norm:
        return ""
    norm = posixpath.normpath(norm).lstrip("/")
    while norm.startswith("../"):
        norm = norm[3:]
    return "" if norm in (".", "..") else norm.lower()


def is_secret_path(path: object) -> bool:
    """Return True if an archive member's content must never be shown."""
    if not isinstance(path, str):
        return False
    norm = _normalise_path(path)
    return bool(norm) and any(
        fnmatchcase(norm, pattern) for pattern in SECRET_ARCHIVE_PATHS
    )


# --- digest -------------------------------------------------------------------


def secret_digest_factory(key: bytes) -> Callable[[str], str]:
    """Return ``digest(value) -> hex``: first 16 hex chars of HMAC-SHA256.

    ``key`` is the installation key (bytes, at least 16, normally 32). The
    caller builds ``value`` (e.g. ``config/section/option/value``).
    """
    if isinstance(key, str) or not isinstance(key, bytes | bytearray | memoryview):
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


# --- free text ------------------------------------------------------------------

# PEM blocks, also unterminated ones (stderr may be cut).
_PEM_RE: Final = re.compile(
    r"-----BEGIN [^\r\n-]*-----.*?(?:-----END [^\r\n-]*-----|\Z)", re.DOTALL
)
# scheme://user:password@host
_URL_CRED_RE: Final = re.compile(r"(\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@]*):[^\s/@]*@")
_AUTH_SCHEME_RE: Final = re.compile(
    r"\b(Bearer|Basic|Digest)[ \t]+[A-Za-z0-9._~+/=\-]+", re.IGNORECASE
)
# Heads after which a value follows; only the head is consumed by finditer,
# so a harmless pair never swallows a secret later on the same line.
_UCI_HEAD_RE: Final = re.compile(
    r"\b(?:option|list)[ \t]+(['\"]?)(?P<name>[A-Za-z0-9_.\-]+)\1[ \t]+"
)
_ASSIGN_HEAD_RE: Final = re.compile(
    r"(?P<q>[\"']?)(?P<name>[A-Za-z0-9_.@\[\]\-]+)(?P=q)[ \t]*[=:][ \t]*"
)
_FLAG_HEAD_RE: Final = re.compile(
    r"(?<![\w\-])(?P<name>--?[A-Za-z][A-Za-z0-9_\-]*)[ \t]+(?=[^\s\-])"
)
# A value: a complete double- or single-quoted string (UCI '\'' escapes),
# otherwise the rest of the line. Spaces, commas and semicolons do not end
# it: "correct horse battery staple" and "r0kh=<mac> <id> <key>" are one
# value each (over-masking on purpose).
_VALUE_RE: Final = re.compile(
    r"\"(?:[^\"\\\r\n]|\\.)*\"|'(?:'\\''|[^'\r\n])*'|[^\r\n]*"
)
_LINE_VALUE_RE: Final = re.compile(r"[^\r\n]*")
# crypt(3) hashes as in /etc/shadow.
_CRYPT_RE: Final = re.compile(r"\$(?:1|2[abxy]?|5|6|7|y|gy|sha1|md5|apr1)\$[^\s:'\"]+")
# 32-byte keys in base64 (WireGuard private/preshared keys).
_WG_KEY_RE: Final = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])"
)
# 32 hex standing alone (ubus session token shape); prefixed ids
# (``bkp_<32 hex>``) and longer hashes are left alone.
_HEX32_RE: Final = re.compile(r"(?<![0-9A-Za-z_])[0-9A-Fa-f]{32}(?![0-9A-Za-z_])")
# Opaque runs of 32+ token characters; ids and pure hex hashes are kept.
_LONG_TOKEN_RE: Final = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{32,}")
_KEEP_TOKEN_RE: Final = re.compile(r"[a-z]{3}_[0-9a-f]{32}|[0-9a-f]{40,}")
# Names, not tokens: paths and hostnames are words joined by "/", "-", "_".
# Each part is one word (lower, Capitalised or UPPER), at most one more
# CamelCase hump of 3+ letters ("OpenWrt"), digits only around it; random
# base64/base64url mixes case and digits inside a part, so it does not split
# into such parts. "+" and "=" never occur in names.
_NAME_PART_RE: Final = re.compile(
    r"[0-9]*(?:[A-Z]?[a-z]+|[A-Z]+)(?:[A-Z][a-z]{2,}|[A-Z]{3,})?[0-9]*|[0-9]+"
)
_NAME_SEP_RE: Final = re.compile(r"[/_-]+")


def _quoted_mask(value: str) -> str:
    """MASK, keeping surrounding quotes."""
    if value[:1] in ("'", '"') and len(value) >= 2 and value[-1] == value[0]:
        return f"{value[0]}{MASK}{value[0]}"
    return MASK


def _mask_after_heads(
    text: str, head_re: re.Pattern[str], value_re: re.Pattern[str]
) -> str:
    """Mask the value after every head whose name is secret."""
    out: list[str] = []
    pos = 0
    for match in head_re.finditer(text):
        if match.start() < pos or not is_secret_key(match.group("name")):
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


def _is_name(token: str) -> bool:
    """True for a path or hostname made of words (not an opaque token)."""
    parts = [part for part in _NAME_SEP_RE.split(token) if part]
    return len(parts) >= 2 and all(_NAME_PART_RE.fullmatch(part) for part in parts)


def _mask_long_token(match: re.Match[str]) -> str:
    """Mask an opaque run unless it is an id, a hex hash or a name."""
    token = match.group(0)
    if _KEEP_TOKEN_RE.fullmatch(token) or _is_name(token):
        return token
    return MASK


def redact_text(text: object) -> str:
    """Remove secrets from free text (messages, stderr, log lines).

    Covers PEM blocks, URL credentials, Authorization schemes, UCI lines
    (``option key '…'``), ``uci show`` / ``name=value`` / ``name: value`` /
    JSON pairs and ``--flag value`` with a secret name (value to the closing
    quote or the end of the line), crypt hashes, base64 32-byte keys, 32-hex
    session tokens and other opaque runs of 32+ characters.
    ``<prefix>_<32 hex>`` ids, hex hashes and word-built names (archive
    paths, hostnames) are kept.
    """
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return text
    text = _PEM_RE.sub(MASK, text)
    text = _URL_CRED_RE.sub(rf"\1:{MASK}@", text)
    text = _AUTH_SCHEME_RE.sub(rf"\1 {MASK}", text)
    text = _mask_after_heads(text, _UCI_HEAD_RE, _LINE_VALUE_RE)
    text = _mask_after_heads(text, _ASSIGN_HEAD_RE, _VALUE_RE)
    text = _mask_after_heads(text, _FLAG_HEAD_RE, _VALUE_RE)
    text = _CRYPT_RE.sub(MASK, text)
    text = _WG_KEY_RE.sub(MASK, text)
    text = _HEX32_RE.sub(MASK, text)
    return _LONG_TOKEN_RE.sub(_mask_long_token, text)


def scrub_text(text: str | None) -> str | None:
    """:func:`redact_text` for optional free-text fields; None stays None."""
    return None if text is None else redact_text(text)


# --- structured data ----------------------------------------------------------

# Record shapes: a mapping with "option" (diff change) masks these keys when
# the option is secret; one with a secret "path"/"name" masks its content.
_OPTION_VALUE_KEYS: Final = frozenset(
    {"old", "new", "value", "values", "before", "after", "current", "previous"}
)
_PATH_KEYS: Final = ("path", "name", "member", "file", "filename")
_CONTENT_KEYS: Final = frozenset(
    {"content", "contents", "data", "text", "body", "raw", "value", "lines"}
)


def mask_value(value: Any) -> Any:
    """Mask one secret value; None and bool carry no secret and stay."""
    if value is None or isinstance(value, bool):
        return value
    return MASK


def _path_value(value: Any) -> Any:
    """Mask a value keyed by a secret path; presence and sizes stay."""
    if value is None or isinstance(value, bool | int | float):
        return value
    return MASK


def _is_marker(mapping: Mapping[Any, Any]) -> bool:
    """True for a ``{"secret": "<digest>"}`` marker."""
    if len(mapping) != 1:
        return False
    ((only_key, value),) = mapping.items()
    return (
        isinstance(only_key, str)
        and only_key.lower() == SECRET_MARKER_KEY
        and isinstance(value, str)
    )


@dataclass(frozen=True, slots=True)
class _Walk:
    """Options of one masking run."""

    extra: frozenset[str]
    redact_strings: bool


def _record_masked_keys(mapping: Mapping[Any, Any]) -> frozenset[str]:
    """Keys a diff or archive record masks because of its option or path."""
    masked: set[str] = set()
    option = mapping.get("option")
    if isinstance(option, str):
        config = mapping.get("config")
        section_type = mapping.get("section_type", mapping.get("type"))
        if is_secret_option(
            config if isinstance(config, str) else "",
            section_type if isinstance(section_type, str) else "",
            option,
        ):
            masked |= _OPTION_VALUE_KEYS
    for path_key in _PATH_KEYS:
        path = mapping.get(path_key)
        if isinstance(path, str) and is_secret_path(path):
            masked |= _CONTENT_KEYS
            break
    return frozenset(masked)


def _mask_mapping(
    mapping: Mapping[Any, Any], walk: _Walk, stack: set[int], depth: int
) -> Any:
    """Mask one mapping (also a dataclass converted to one)."""
    if _is_marker(mapping):
        return MASK
    masked_keys = _record_masked_keys(mapping)
    result: dict[Any, Any] = {}
    for key, value in mapping.items():
        if isinstance(key, str):
            if key.lower() in masked_keys or is_secret_key(key, walk.extra):
                result[key] = mask_value(value)
                continue
            if is_secret_path(key):
                result[key] = _path_value(value)
                continue
            if walk.redact_strings and isinstance(value, str):
                lowered = key.lower()
                if lowered in SAFE_KEYS or lowered.endswith(SAFE_SUFFIXES):
                    result[key] = value  # ids and hashes stay readable
                    continue
        result[key] = _mask(value, walk, stack, depth + 1)
    return result


def _mask_sequence(obj: Any, walk: _Walk, stack: set[int], depth: int) -> Any:
    """Mask the items of a list, tuple, namedtuple or set."""
    items = [_mask(item, walk, stack, depth + 1) for item in obj]
    if isinstance(obj, list):
        return items
    if isinstance(obj, tuple):
        if hasattr(obj, "_fields"):  # namedtuple
            return type(obj)(*items)
        return tuple(items)
    if not walk.redact_strings:  # key-only mode: JSON-safe sorted list
        return sorted(items, key=str)
    if isinstance(obj, frozenset):
        return frozenset(items)
    return set(items)


def _mask(obj: Any, walk: _Walk, stack: set[int], depth: int) -> Any:
    """Recursive worker of mask_secrets / mask_for_output."""
    if obj is None or isinstance(obj, bool | int | float | Enum):
        return obj
    if isinstance(obj, str):
        return redact_text(obj) if walk.redact_strings else obj
    if isinstance(obj, bytes | bytearray | memoryview):
        return MASK
    if isinstance(obj, BaseException):
        return redact_text(str(obj))
    is_dc = is_dataclass(obj) and not isinstance(obj, type)
    if not (is_dc or isinstance(obj, Mapping | list | tuple | set | frozenset)):
        return obj
    if depth > MAX_DEPTH:
        _LOGGER.debug("masking: nesting deeper than %d truncated", MAX_DEPTH)
        return TRUNCATED
    ident = id(obj)
    if ident in stack:
        _LOGGER.debug("masking: cyclic reference masked")
        return MASK
    stack.add(ident)
    try:
        if is_dc:
            as_map = {f.name: getattr(obj, f.name) for f in fields(obj)}
            return _mask_mapping(as_map, walk, stack, depth)
        if isinstance(obj, Mapping):
            return _mask_mapping(obj, walk, stack, depth)
        return _mask_sequence(obj, walk, stack, depth)
    finally:
        stack.discard(ident)


def mask_secrets(data: Any, *, extra_keys: Iterable[str] = ()) -> Any:
    """Key-based masked copy of ``data``; the input is never modified.

    Values under a secret key, digest markers, secret option records and
    secret archive paths are masked; bytes become MASK; dataclasses and
    mappings (also read-only proxies) become ``dict``; sets become sorted
    lists (JSON-safe). Plain strings stay as they are (ids, timestamps).
    Nesting deeper than MAX_DEPTH becomes TRUNCATED, cycles become MASK.
    """
    walk = _Walk(extra=frozenset(extra_keys), redact_strings=False)
    return _mask(data, walk, set(), 0)


def mask_for_output(data: Any, *, extra_keys: Iterable[str] = ()) -> Any:
    """Like :func:`mask_secrets`, and every string goes through redact_text.

    The last barrier before HTTP responses, logs and events. Strings under
    id/hash keys (``*_id``, ``*_ids``, ``*_hash``, ``sha256``) stay; sets
    and namedtuples keep their type.
    """
    walk = _Walk(extra=frozenset(extra_keys), redact_strings=True)
    return _mask(data, walk, set(), 0)
