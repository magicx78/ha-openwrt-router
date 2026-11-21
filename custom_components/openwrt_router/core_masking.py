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

Two value-aware exceptions (follow-up B4, narrowed by review of PR #56):
identifier names (``IDENTIFIER_KEY_NAMES``: ``rule_key``, ``scope_key`` …)
stay secret names, but the walkers show a value under them if it is a
strict identifier (:func:`is_identifier_value`: core id or short lower-case
slug, no key material); anything else, also a dict or list, is masked.
Counter names (``COUNTER_SUFFIXES``) keep a NUMBER readable unless a secret
word is part of the name. The precise snapshot rule is unchanged
(``option rule_key`` in a UCI diff stays masked).

Network identifiers (MAC, IP, hostname, SSID, BSSID) in structured data are
not masked here; modules that must hide them use
:func:`pseudonymise_identifier` / :func:`pseudonymise_fields` with their
module key. MACs in free text (:func:`redact_text`, :func:`scrub_text`,
``mask_for_output(..., macs=True)``) are masked since 1.49.4.

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
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from datetime import date, time, timedelta
from decimal import Decimal
from enum import Enum
from fnmatch import fnmatchcase, translate
from functools import lru_cache
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
    ip_address,
)
from pathlib import PurePath
from typing import Any, Final
from urllib.parse import unquote
from uuid import UUID

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
# "pw" (security review 2026-11-18, broad mode only): a common short name
# for a password in scripts and JSON bodies.
SECRET_EXTRA_NAMES: Final = _UCI_CREDENTIAL_NAMES | frozenset(
    {"pw", "session", "sid", "sysauth"}
)

_CONTEXT_NAMES: Final = frozenset(
    name for rule in SECRET_CONTEXT_OPTIONS for name in rule.options
)
# Real OpenWrt secrets missing from config-manager's list (security review
# 2026-11-18): 6in4 "updatekey" (tunnel broker key) and ppp "pppd_options"
# (may carry "password …"). They change the precise mode: the snapshot
# stores a digest marker for them.
SECRET_OPTIONS_ADDED: Final = frozenset({"pppd_options", "updatekey"})
# Precise mode: always secret, whatever the config.
_SNAPSHOT_EXACT: Final = (
    SECRET_OPTIONS | _UCI_CREDENTIAL_NAMES | _CONTEXT_NAMES | SECRET_OPTIONS_ADDED
)
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
    # openvpn "auth" is a digest algorithm name (SHA256). "tls_auth",
    # "tls_crypt(_v2)" and "pkcs12" hold a key FILE path, not the key:
    # config-manager classifies tls_auth as readable; the file's content is
    # protected by SECRET_ARCHIVE_PATHS (etc/openvpn/*, *.key, *.p12). An
    # inline key block in such a value is masked anyway (_has_inline_key).
    ReadableContextRule(
        "openvpn",
        "*",
        frozenset(
            {
                "auth",
                "auth_nocache",
                "key_direction",
                "pkcs12",
                "tls_auth",
                "tls_crypt",
                "tls_crypt_v2",
            }
        ),
    ),
    # usteer key_value: not a key; config-manager keeps it readable.
    ReadableContextRule("usteer", "*", frozenset({"key_value"})),
)
# Suffixes of counters, hashes and ids (never secret values).
SAFE_SUFFIXES: Final = ("_count", "_hash", "_sha256", "_id", "_ids")
# Names of identifiers that end in "key" (follow-up B4, narrowed by review
# M1 of PR #56), compared as the name's words joined by "_" without dropping
# digits (``ruleKey``, ``RULE-KEY`` -> ``rule_key``; ``rule_key2`` is not
# one). They stay SECRET names for :func:`is_secret_key`; only the walkers
# and :func:`redact_text` show a value under them, and only a strict
# identifier value (:func:`is_identifier_value`). A name is listed only if
# it never names a secret anywhere. Removed in M1 because they do:
# ``client_key`` (MQTT/TLS client private key), ``device_key`` (IoT device
# keys), ``message_key``/``msg_key`` (Signal/MTProto message keys),
# ``router_key`` (Tor router identity key), ``entry_key`` (keystore key
# entry), ``cache_key``/``lookup_key`` (often built from credentials),
# ``event_key`` (webhook/event service keys), ``radio_key`` (no safe
# meaning; modules have ``radio_id``).
IDENTIFIER_KEY_NAMES: Final = frozenset(
    {
        "finding_key",
        "incident_key",
        "recommendation_key",
        "rule_key",
        "scope_key",
        "sort_key",
        "translation_key",
    }
)
# A value under an identifier name stays readable only in one of these
# shapes: a core id (``rtr_<32 hex>``, ``cli_<16 hex>`` …) or a short
# lower-case slug; and never if it looks like key material.
IDENTIFIER_VALUE_MAX_LENGTH: Final = 64
_IDENTIFIER_VALUE_RE: Final = re.compile(
    r"[a-z]{3}_[0-9a-f]{32}|[a-z]{3}_[0-9a-f]{16}"
    rf"|[a-z0-9][a-z0-9_.:-]{{0,{IDENTIFIER_VALUE_MAX_LENGTH - 1}}}"
)
# Counter names: a number under such a name is readable; a string or any
# other value is not. Never for a name with a word of SECRET_WORDS
# (``pin_total``, ``auth_failures``; review L1 of PR #56).
COUNTER_SUFFIXES: Final = (
    "_attempts",
    "_errors",
    "_fail",
    "_failed",
    "_failures",
    "_retries",
    "_total",
)

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
        "accesskey",
        "apikey",
        "auth",
        "authkey",
        "authorization",
        "bearer",
        "community",  # SNMP community string
        "cookie",
        "credential",
        "credentials",
        "crypt",  # openvpn tls_crypt / tls_crypt_v2 (path or key)
        "key",
        "otp",  # one-time password
        "passphrase",
        "passwd",
        "password",
        "pin",
        "pincode",
        "pkcs",  # pkcs12 / pkcs8 (trailing digits are dropped)
        "presharedkey",
        "private",
        "privatekey",
        "privkey",
        "psk",
        "pw",
        "pwd",
        "sae",
        "sauth",  # LuCI session cookie variant
        "secret",
        "session",
        "sharedkey",
        "sysauth",  # LuCI session cookie
        "token",
        "updatekey",
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


# Look-alike letters (Cyrillic, Greek) mapped to the Latin letter they mimic;
# NFKC already folds fullwidth and other compatibility forms.
_CONFUSABLES: Final = str.maketrans(
    {
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u043a": "k",
        "\u0456": "i",
        "\u0455": "s",
        "\u0458": "j",
        "\u0501": "d",
        "\u0410": "A",
        "\u0412": "B",
        "\u0415": "E",
        "\u041a": "K",
        "\u041c": "M",
        "\u041d": "H",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0422": "T",
        "\u0425": "X",
        "\u0405": "S",
        "\u0406": "I",
        "\u03b1": "a",
        "\u03b5": "e",
        "\u03bf": "o",
        "\u03c1": "p",
        "\u03ba": "k",
        "\u03c4": "t",
        "\u03bd": "v",
        "\u03b9": "i",
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0396": "Z",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a5": "Y",
        "\u03a7": "X",
    }
)


def _canonical_name(name: str) -> str:
    """``name`` as a reader sees it: URL-decoded, format characters
    (zero-width) removed, NFKC-folded, look-alike letters mapped to Latin.

    Plain ASCII names without ``%`` are returned as they are.
    """
    if name.isascii() and "%" not in name:
        return name
    canon = name
    for _ in range(2):  # pass%2577ord -> pass%77ord -> password
        if "%" not in canon:
            break
        canon = unquote(canon)
    canon = "".join(ch for ch in canon if unicodedata.category(ch) != "Cf")
    return unicodedata.normalize("NFKC", canon).translate(_CONFUSABLES)


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


_MAX_KEY_NESTING: Final = 8


def is_secret_key(name: object, extra_keys: Iterable[str] = ()) -> bool:
    """BROAD: True if a mapping key or option ``name`` may name a secret.

    Non-str keys: bytes are decoded, tuples / frozensets are secret if any
    element is (nesting deeper than 8 counts as secret), numbers and None
    name nothing, any other object is judged by ``str(key)``.
    """
    if not isinstance(name, str):
        return _is_secret_non_str_key(name, extra_keys, 0)
    if not name.strip():
        return False
    if extra_keys:
        extra = {k.lower() for k in extra_keys}
        if name.lower() in extra or _normalise_name(name) in extra:
            return True
    return _is_secret_str_key(name)


def _is_secret_non_str_key(key: object, extra_keys: Iterable[str], depth: int) -> bool:
    """is_secret_key for bytes, tuple, frozenset, number and object keys."""
    if key is None or isinstance(key, bool | int | float):
        return False
    if isinstance(key, bytes | bytearray | memoryview):
        return is_secret_key(bytes(key).decode("utf-8", "replace"), extra_keys)
    if isinstance(key, tuple | frozenset):
        if depth >= _MAX_KEY_NESTING:
            return True  # when in doubt, mask
        return any(
            is_secret_key(item, extra_keys)
            if isinstance(item, str)
            else _is_secret_non_str_key(item, extra_keys, depth + 1)
            for item in key
        )
    return is_secret_key(str(key), extra_keys)


@lru_cache(maxsize=4096)
def _is_secret_str_key(name: str) -> bool:
    """The broad rules of :func:`is_secret_key` without extra keys.

    A name with URL escapes, zero-width or look-alike characters is also
    judged in its canonical form (:func:`_canonical_name`).
    """
    canon = _canonical_name(name)
    if canon != name and canon.strip() and _is_secret_plain_key(canon):
        return True
    return _is_secret_plain_key(name)


def _is_secret_plain_key(name: str) -> bool:
    """The broad rules on one spelling of a name."""
    lowered = name.lower()
    norm = _normalise_name(name)
    if lowered in SECRET_EXACT_KEYS or norm in SECRET_EXACT_KEYS:
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


def _is_identifier_plain(name: str) -> bool:
    """True if one spelling of ``name`` is in IDENTIFIER_KEY_NAMES.

    Words keep their digits (``rule_key2`` and ``rule2_key`` are not
    identifiers; ``key1``…``key4`` are WEP keys).
    """
    spaced = _CAMEL.sub(" ", name.rsplit(".", 1)[-1])
    joined = "_".join(part.lower() for part in _SPLIT.split(spaced) if part)
    return joined in IDENTIFIER_KEY_NAMES


def is_identifier_name(name: object) -> bool:
    """True for a field that names an identifier ending in "key".

    Exact secret names never count; the canonical spelling (URL escapes,
    zero-width, look-alikes) must agree, so ``rule%5Fkey`` is judged like
    ``rule_key``. Such a name is still a secret name for
    :func:`is_secret_key`; the walkers show a value under it only if
    :func:`is_identifier_value` accepts it.
    """
    return isinstance(name, str) and bool(name.strip()) and _identifier_str(name)


def is_identifier_value(value: object) -> bool:
    """True if ``value`` may be shown under an identifier name.

    Only a string: a core id (``rtr_<32 hex>``, ``cli_<16 hex>`` …) or a
    lower-case slug ``[a-z0-9][a-z0-9_.:-]*`` of at most
    IDENTIFIER_VALUE_MAX_LENGTH characters that does not look like key
    material. Numbers (a PIN is a number), containers, mixed case, blanks
    and symbols are not identifier values.
    """
    return (
        isinstance(value, str)
        and _IDENTIFIER_VALUE_RE.fullmatch(value) is not None
        and (
            _CORE_ID_RE.fullmatch(value) is not None
            or not looks_like_key_material(value)
        )
    )


@lru_cache(maxsize=4096)
def _identifier_str(name: str) -> bool:
    canon = _canonical_name(name)
    for spelling in {name, canon}:
        if (
            spelling.lower() in SECRET_EXACT_KEYS
            or _normalise_name(spelling) in SECRET_EXACT_KEYS
            or not _is_identifier_plain(spelling)
        ):
            return False
    return True


def is_counter_name(name: object) -> bool:
    """True for a counter name (``wan_failures``): numbers stay readable.

    Never for exact secret names, config-manager's pattern, a secret
    substring (``password_failures``) or a name with any word of
    SECRET_WORDS (``pin_total``, ``wps_pin_attempts``, ``otp_total``,
    ``auth_failures``): a PIN or one-time password is a number, so the
    counter rule never lifts a secret word (review L1 of PR #56).
    """
    return isinstance(name, str) and _counter_str(name)


@lru_cache(maxsize=4096)
def _counter_str(name: str) -> bool:
    for spelling in {name, _canonical_name(name)}:
        norm = _normalise_name(spelling)
        words = _words(spelling.rsplit(".", 1)[-1])
        if (
            not norm.endswith(COUNTER_SUFFIXES)
            or norm in SECRET_EXACT_KEYS
            or spelling.lower() in SECRET_EXACT_KEYS
            or _matches_pattern(norm)
            or any(sub in norm for sub in SECRET_SUBSTRINGS)
            or any(word in SECRET_WORDS for word in words)
            or "".join(words) in SECRET_WORDS
        ):
            return False
    return True


# Key material under an identifier name: PEM, base64/base64url of 16+ bytes,
# 32+ hex. Core ids and word-built names are not key material.
_KEY_MATERIAL_RE: Final = re.compile(r"[A-Za-z0-9+/_-]{22,}={0,2}|[0-9A-Fa-f]{32,}")
_CORE_ID_RE: Final = re.compile(r"[a-z]{3}_[0-9a-f]{32}|[a-z]{3}_[0-9a-f]{16}")


def looks_like_key_material(value: object) -> bool:
    """True if a string (or any string in a list/tuple) may be a key."""
    if isinstance(value, list | tuple):
        return any(looks_like_key_material(item) for item in value)
    if not isinstance(value, str):
        return False
    if _INLINE_KEY in value:
        return True
    for token in re.split(r"[\s,;'\"]+", value):
        if (
            token
            and _KEY_MATERIAL_RE.fullmatch(token)
            and not _CORE_ID_RE.fullmatch(token)
            and not _is_name(token)
        ):
            return True
    return False


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
    return bool(norm) and _SECRET_PATH_RE.match(norm) is not None


# SECRET_ARCHIVE_PATHS as one regex (same globs as fnmatchcase, one pass).
_SECRET_PATH_RE: Final = re.compile(
    "|".join(translate(pattern) for pattern in SECRET_ARCHIVE_PATHS)
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
# Longer free text is cut (at a whitespace, so no fragment of a token is
# left) and ends with TRUNCATED; the remainder is dropped, never passed on.
MAX_TEXT_LENGTH: Final = 65536
# scheme://user:password@host; anchored on the literal "://" so a long run
# of scheme characters is scanned once, not once per start position.
_URL_CRED_RE: Final = re.compile(r"(://[^\s/:@]*):[^\s/@]*@")
_AUTH_SCHEME_RE: Final = re.compile(
    r"\b(Bearer|Basic|Digest)[ \t]+[A-Za-z0-9._~+/=\-]+", re.IGNORECASE
)
# Heads after which a value follows; only the head is consumed by finditer,
# so a harmless pair never swallows a secret later on the same line.
_UCI_HEAD_RE: Final = re.compile(
    r"\b(?:option|list)[ \t]+(['\"]?)(?P<name>[A-Za-z0-9_.\-]+)\1[ \t]+"
)
# The name starts only at the start of a run of name characters and is
# taken possessively (it can only end at the run's end): linear runtime.
# Name characters of free-text heads: word characters in any script, the
# separators of UCI / JSON paths, "%" (URL escapes) and the invisible format
# characters an attacker could slip into a name (zero-width, soft hyphen).
_NAME_CHARS: Final = r"\w.@\[\]\-%\u00ad\u200b-\u200f\u2060-\u2064\ufeff"
_ASSIGN_HEAD_RE: Final = re.compile(
    rf"(?P<q>[\"']?)(?<![{_NAME_CHARS}])(?P<name>[{_NAME_CHARS}]++)"
    r"(?P=q)[ \t]*[=:][ \t]*"
)
# JSON inside a JSON string: \"name\": \"value\" (any number of backslashes,
# the same before both quotes of the name).
_ESCAPED_HEAD_RE: Final = re.compile(
    rf"(?<!\\)(?P<bs>\\++)\"(?P<name>[{_NAME_CHARS}]++)(?P=bs)\"[ \t]*:[ \t]*"
)
# name<TAB>value (hostapd/wpa_cli, "uci -d '\t'", tab separated dumps).
_TAB_HEAD_RE: Final = re.compile(
    rf"(?<![{_NAME_CHARS}])(?P<name>[{_NAME_CHARS}]++)\t[ \t]*(?=\S)"
)
# <name attr="…">value</name> (XML / HTML forms).
_XML_HEAD_RE: Final = re.compile(
    rf"<(?P<name>[{_NAME_CHARS}:]++)(?:[ \t][^<>\r\n]*+)?>"
)
_XML_VALUE_RE: Final = re.compile(r"[^<]*+")
# sshpass -p PASSWORD (also -pPASSWORD): every -p on such a line.
_SSHPASS_LINE_RE: Final = re.compile(r"\bsshpass\b[^\r\n]*+")
_SSHPASS_P_RE: Final = re.compile(
    r"(?<!\S)(?P<flag>-p)(?P<sep>[ \t]*+)(?P<value>'[^'\r\n]*+'|\"[^\"\r\n]*+\"|\S++)"
)
# user/password and user:password after a login name, as in exception
# texts ("login failed for root/…"); the login name must stand alone.
_LOGIN_PAIR_RE: Final = re.compile(
    r"(?<![^\s'\"(\[=,;])(?P<user>root|admin|user|username|login)"
    r"(?P<sep>[/:])(?P<value>[^\s'\")\],;/]++)(?!/)",
    re.IGNORECASE,
)
_FLAG_HEAD_RE: Final = re.compile(
    r"(?<![\w\-])(?P<name>--?[A-Za-z][A-Za-z0-9_\-]*)[ \t]+(?=[^\s\-])"
)
# A value: complete double- or single-quoted strings (UCI '\'' escapes),
# several separated by blanks as ``uci show`` prints a list
# (``'pw-one' 'pw-two'``); if another quote follows (unterminated), or the
# value is unquoted, the rest of the line. Spaces, commas and semicolons do
# not end it: "correct horse battery staple" and "r0kh=<mac> <id> <key>"
# are one value each (over-masking on purpose).
_QUOTED: Final = r"(?:\"(?:[^\"\\\r\n]|\\.)*\"|'(?:'\\''|[^'\r\n])*')"
_VALUE_RE: Final = re.compile(rf"{_QUOTED}(?:[ \t]+{_QUOTED})*(?![ \t]*[\"'])|[^\r\n]*")
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
# OpenSSH fingerprint: "SHA256:" + 43 base64 characters (no padding).
_FINGERPRINT_HEAD: Final = "SHA256:"
_FINGERPRINT_LEN: Final = 43
# Names, not tokens: paths and hostnames are words joined by "/", "-", "_".
# Each part is one word (lower, Capitalised or UPPER), at most one more
# CamelCase hump of 3+ letters ("OpenWrt"), digits only around it; random
# base64/base64url mixes case and digits inside a part, so it does not split
# into such parts. "+" and "=" never occur in names.
_NAME_PART_RE: Final = re.compile(
    r"[0-9]*(?:[A-Z]?[a-z]+|[A-Z]+)(?:[A-Z][a-z]{2,}|[A-Z]{3,})?[0-9]*|[0-9]+"
)
_NAME_SEP_RE: Final = re.compile(r"[/_-]+")


# A plain number (optionally quoted) that ends at a blank or a separator.
_NUMBER_VALUE_RE: Final = re.compile(
    r"([\"']?)-?[0-9]{1,20}(?:\.[0-9]{1,20})?\1(?=$|[\s,;})\]])"
)
# The value after an identifier head in free text: one (optionally quoted)
# token that ends the value, or is followed by "," / ";" or by the next
# "name=" / "name:" pair. Anything else (a phrase) is masked to the end.
_IDENTIFIER_TEXT_RE: Final = re.compile(
    rf"(?P<q>['\"]?)(?P<tok>[^\s'\",;]{{1,{IDENTIFIER_VALUE_MAX_LENGTH}}})(?P=q)"
    r"(?:[ \t]*\Z|[ \t]*[,;]|[ \t]+(?=[^\s=:'\"]+[ \t]*[=:]))"
)


def _identifier_text_value(raw: str) -> bool:
    """True if free text after an identifier head is one identifier value."""
    match = _IDENTIFIER_TEXT_RE.match(raw)
    return match is not None and is_identifier_value(match.group("tok"))


def _quoted_mask(value: str) -> str:
    """MASK, keeping surrounding quotes."""
    if value[:1] in ("'", '"') and len(value) >= 2 and value[-1] == value[0]:
        return f"{value[0]}{MASK}{value[0]}"
    return MASK


def _mask_after_heads(
    text: str, head_re: re.Pattern[str], value_re: re.Pattern[str]
) -> str:
    """Mask the value after every head whose name is secret.

    Names are judged by the broad :func:`is_secret_key`, which also checks
    the canonical spelling (URL escapes, zero-width, look-alikes).
    """
    out: list[str] = []
    pos = 0
    for match in head_re.finditer(text):
        if match.start() < pos:
            continue
        name = match.group("name")
        if not is_secret_key(name):
            continue
        value = value_re.match(text, match.end())
        end = value.end() if value else match.end()
        if end == match.end():
            continue
        raw = text[match.end() : end]
        if is_identifier_name(name):
            if _identifier_text_value(raw):
                continue  # "rule_key=wan_in": an identifier, the rest is scanned on
        elif is_counter_name(name) and _NUMBER_VALUE_RE.match(raw):
            continue  # a count, the rest is scanned on
        out.append(text[pos : match.end()])
        out.append(_quoted_mask(text[match.end() : end]))
        pos = end
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


_ESCAPED_SCALAR_RE: Final = re.compile(r"[^,}\]\s\\]*+")
_MAX_ESCAPE_DEPTH: Final = 64


@lru_cache(maxsize=16)
def _escaped_close_re(depth: int) -> re.Pattern[str]:
    """End of an escaped string value at ``depth`` backslashes, or a newline."""
    return re.compile(r"(?<!\\)" + r"\\" * depth + r'"|[\r\n]')


def _mask_escaped_json(text: str) -> str:
    """Mask \\"name\\": \\"value\\" pairs of escaped JSON (any depth).

    The value ends at the same escape depth's quote (a deeper escaped quote
    inside it does not end it) or at the end of the line. Every character
    is scanned at most once by the value search (linear).
    """
    out: list[str] = []
    pos = 0
    for match in _ESCAPED_HEAD_RE.finditer(text):
        if match.start() < pos or not is_secret_key(match.group("name")):
            continue
        quote = match.group("bs") + '"'
        start = match.end()
        if text.startswith(quote, start):
            depth = len(match.group("bs"))
            close = (
                _escaped_close_re(depth).search(text, start + len(quote))
                if depth <= _MAX_ESCAPE_DEPTH
                else None
            )
            if close is not None and close.group(0) not in ("\r", "\n"):
                end, masked = close.end(), f"{quote}{MASK}{quote}"
            elif close is not None:
                end, masked = close.start(), MASK
            else:
                eol = re.compile(r"[\r\n]").search(text, start)
                end, masked = (eol.start() if eol else len(text)), MASK
        else:
            value = _ESCAPED_SCALAR_RE.match(text, start)
            end, masked = (value.end() if value else start), MASK
        if end == start:
            continue
        out.append(text[pos:start])
        out.append(masked)
        pos = end
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def _mask_sshpass(text: str) -> str:
    """Mask the value of every ``-p`` on a line that runs sshpass."""
    if "sshpass" not in text:
        return text

    def _line(match: re.Match[str]) -> str:
        return _SSHPASS_P_RE.sub(
            lambda m: (
                f"{m.group('flag')}{m.group('sep')}{_quoted_mask(m.group('value'))}"
            ),
            match.group(0),
        )

    return _SSHPASS_LINE_RE.sub(_line, text)


def _is_name(token: str) -> bool:
    """True for a path or hostname made of words (not an opaque token)."""
    parts = [part for part in _NAME_SEP_RE.split(token) if part]
    return len(parts) >= 2 and all(_NAME_PART_RE.fullmatch(part) for part in parts)


def _is_id_path(token: str) -> bool:
    """True for a path whose parts are core ids, hex hashes or plain words.

    ``removed/rtr_<32 hex>`` (archive targets in audit data) stays readable;
    a part that is an opaque token (or a bare 32-hex session token) does not.
    """
    if "/" not in token:
        return False
    parts = token.split("/")
    return all(
        part
        and (
            _KEEP_TOKEN_RE.fullmatch(part)
            or _NAME_PART_RE.fullmatch(part)
            or _is_name(part)
        )
        for part in parts
    )


def _mask_long_token(match: re.Match[str]) -> str:
    """Mask an opaque run unless it is an id, a hex hash or a name.

    The 43 characters after ``SHA256:`` are an SSH host key fingerprint
    (public, needed to compare pins) and stay readable too.
    """
    token = match.group(0)
    if _KEEP_TOKEN_RE.fullmatch(token) or _is_name(token) or _is_id_path(token):
        return token
    start = match.start()
    if (
        len(token) == _FINGERPRINT_LEN
        and match.string[max(0, start - len(_FINGERPRINT_HEAD)) : start]
        == _FINGERPRINT_HEAD
    ):
        return token
    return MASK


# MACs in free text (1.49.4; the Security Center's pattern of 1.49.3, moved
# here so the Core, the configuration manager, network diagnostics and the
# Security Center share one). Colon, dash, Cisco dots and bare 12 hex (the
# forms of mac_utils.is_mac), also glued to "_" or a non-hex letter. The hex
# lookarounds keep longer hex runs (ids, pseudonyms, digests) intact. The
# bare and the dotted form need at least one hex letter a-f
# (``bytes=123456789012``, phone numbers, ``202611211530`` and
# ``2026.1121.1530`` are no MACs), and the space-separated form
# (``AA BB CC DD EE FF``, also with a letter) is masked when it is not part
# of a longer run of hex pairs (a hex dump). Lookaheads are bounded: linear.
_HEX: Final = "[0-9A-Fa-f]"
MAC_IN_TEXT_RE: Final = re.compile(
    r"(?<![0-9A-Fa-f:-])(?:"
    rf"{_HEX}{{2}}(?::{_HEX}{{2}}){{5}}"
    rf"|{_HEX}{{2}}(?:-{_HEX}{{2}}){{5}}"
    rf"|(?=[0-9.]{{0,13}}[A-Fa-f]){_HEX}{{4}}(?:\.{_HEX}{{4}}){{2}}"
    rf"|(?=[0-9]{{0,11}}[A-Fa-f]){_HEX}{{12}}"
    r")(?![0-9A-Fa-f:-])"
    rf"|(?<!{_HEX}{{2}} )(?<![0-9A-Fa-f:-])"
    rf"(?=[0-9 ]{{0,16}}[A-Fa-f]){_HEX}{{2}}(?: {_HEX}{{2}}){{5}}"
    rf"(?![0-9A-Fa-f:-])(?! {_HEX}{{2}}(?![0-9A-Za-z]))"
)
# ``usr_<12 hex>`` (user pseudonyms) and other ``<abc>_<12 hex>`` core ids
# look like a bare MAC glued to "_"; the core keeps them readable.
_ID_HEAD_RE: Final = re.compile(r"(?<![A-Za-z0-9])[a-z]{3}_\Z")


def _mask_mac(match: re.Match[str]) -> str:
    start = match.start()
    if len(match.group(0)) == 12 and _ID_HEAD_RE.search(
        match.string, max(0, start - 5), start
    ):
        return match.group(0)
    return MASK


def mask_macs(text: str) -> str:
    """``text`` with every MAC address (:data:`MAC_IN_TEXT_RE`) masked."""
    return MAC_IN_TEXT_RE.sub(_mask_mac, text)


def redact_text(text: object, *, macs: bool = True) -> str:
    """Remove secrets from free text (messages, stderr, log lines).

    Covers PEM blocks, URL credentials, Authorization schemes, UCI lines
    (``option key '…'``), ``uci show`` / ``name=value`` / ``name: value`` /
    JSON pairs (also escaped JSON inside a string), ``--flag value``,
    ``name<TAB>value`` and ``<name>value</name>`` with a secret name (value
    to the closing quote or the end of the line; names also judged
    URL-decoded, without zero-width characters, NFKC-folded and with
    look-alike letters mapped), ``sshpass -p …``, ``root/…`` login pairs,
    crypt hashes, base64 32-byte keys, 32-hex session tokens and other
    opaque runs of 32+ characters.
    ``<prefix>_<32 hex>`` ids, hex hashes and word-built names (archive
    paths, hostnames) are kept. MAC addresses (:data:`MAC_IN_TEXT_RE`) are
    masked too unless ``macs`` is False (1.49.4; :func:`mask_for_output`
    passes False for strings of structured data unless asked). Text longer
    than MAX_TEXT_LENGTH is cut and ends with TRUNCATED. Runtime is linear
    in the length.
    """
    if not isinstance(text, str):
        text = str(text)
    if not text:
        return text
    if len(text) <= MAX_TEXT_LENGTH:
        out = _redact(text)
        return mask_macs(out) if macs else out
    out = _redact(_cut(text))
    return (mask_macs(out) if macs else out) + TRUNCATED


def _cut(text: str) -> str:
    """First MAX_TEXT_LENGTH chars, back to the last whitespace."""
    head = text[:MAX_TEXT_LENGTH]
    if text[MAX_TEXT_LENGTH].isspace():
        return head
    last = max(head.rfind(blank) for blank in " \t\r\n")
    return head[: last + 1]  # no whitespace at all: nothing is kept


def _redact(text: str) -> str:
    """The rules of :func:`redact_text` on a bounded text."""
    text = _PEM_RE.sub(MASK, text)
    text = _URL_CRED_RE.sub(rf"\1:{MASK}@", text)
    text = _AUTH_SCHEME_RE.sub(rf"\1 {MASK}", text)
    text = _mask_after_heads(text, _UCI_HEAD_RE, _LINE_VALUE_RE)
    text = _mask_escaped_json(text)
    text = _mask_after_heads(text, _ASSIGN_HEAD_RE, _VALUE_RE)
    text = _mask_after_heads(text, _FLAG_HEAD_RE, _VALUE_RE)
    text = _mask_after_heads(text, _TAB_HEAD_RE, _LINE_VALUE_RE)
    text = _mask_after_heads(text, _XML_HEAD_RE, _XML_VALUE_RE)
    text = _mask_sshpass(text)
    text = _LOGIN_PAIR_RE.sub(rf"\g<user>\g<sep>{MASK}", text)
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
# Records that name their field in one of these keys ({"key": "password",
# "value": …}, {"name": "psk", "new": …}) mask their values like a secret
# option record (security review 2026-11-18).
_FIELD_NAME_KEYS: Final = ("key", "name", "field", "param", "parameter", "setting")
# Strings under id/hash keys stay readable only in these strict shapes;
# anything else under such a key is redacted as free text.
_STRICT_ID_RE: Final = re.compile(
    r"[a-z]{3}_[0-9a-f]{32}"  # core ids (rtr_, bkp_, evt_, apr_ …)
    r"|[0-9A-Fa-f]{8,128}"  # hex digests and hashes
    r"|[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}"  # UUID
    r"|[0-9A-HJKMNP-TV-Z]{26}"  # ULID (HA config entry ids)
    r"|SHA256:[A-Za-z0-9+/]{43}=?"  # ssh fingerprint
    r"|[0-9]{1,20}|-|"
)
_INLINE_KEY: Final = "-----BEGIN "
# Value types without attributes that could hold a secret; they stay as
# they are. Every other unknown object becomes an OBJECT marker.
_PLAIN_VALUE_TYPES: Final = (
    complex,
    date,
    time,
    timedelta,
    Decimal,
    UUID,
    PurePath,
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
    IPv4Interface,
    IPv6Interface,
)
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
    macs: bool = False


def _has_inline_key(mapping: Mapping[Any, Any]) -> bool:
    """True if a value of a change record holds a PEM-style key block.

    A readable option (openvpn ``tls_auth`` names a key file) must not show
    a key pasted inline in place of the path.
    """
    for key in _OPTION_VALUE_KEYS:
        value = mapping.get(key)
        items = value if isinstance(value, list | tuple) else (value,)
        if any(isinstance(item, str) and _INLINE_KEY in item for item in items):
            return True
    return False


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
        ) or _has_inline_key(mapping):
            masked |= _OPTION_VALUE_KEYS
    if not masked and any(key in mapping for key in _OPTION_VALUE_KEYS):
        # A record may name its field in several keys at once. Look at ALL of
        # them first: one secret name masks the values, whatever the others
        # say and in whatever order (review N1). Only when none is secret
        # does an allowed identifier name get the strict value rule.
        names = [
            named
            for named in (mapping.get(name_key) for name_key in _FIELD_NAME_KEYS)
            if isinstance(named, str)
        ]
        if any(is_secret_key(n) and not is_identifier_name(n) for n in names):
            masked |= _OPTION_VALUE_KEYS
        elif any(is_identifier_name(n) for n in names):
            # {"key": "rule_key", "value": …}: only strict identifier values
            # (or None) stay readable
            shown = all(
                mapping.get(k) is None or is_identifier_value(mapping.get(k))
                for k in _OPTION_VALUE_KEYS
            )
            if not shown:
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
        if not isinstance(key, str):  # bytes, tuple, number, object keys
            if is_secret_key(key, walk.extra):
                result[key] = mask_value(value)
                continue
        else:
            if (
                key.lower() not in masked_keys
                and is_identifier_name(key)
                and not _is_extra(key, walk)
            ):
                # only a strict identifier value is shown; dicts, lists,
                # numbers and phrases are masked, never walked into (M1)
                result[key] = value if is_identifier_value(value) else mask_value(value)
                continue
            if key.lower() in masked_keys or is_secret_key(key, walk.extra):
                if _readable_count(key, value, walk):
                    result[key] = value
                else:
                    result[key] = mask_value(value)
                continue
            if is_secret_path(key):
                result[key] = _path_value(value)
                continue
            if walk.redact_strings and isinstance(value, str):
                lowered = key.lower()
                if lowered in SAFE_KEYS or lowered.endswith(SAFE_SUFFIXES):
                    # ids and hashes stay readable in their strict shapes;
                    # anything else there is free text (review 2026-11-18)
                    result[key] = (
                        value
                        if _STRICT_ID_RE.fullmatch(value)
                        else redact_text(value, macs=walk.macs)
                    )
                    continue
        result[key] = _mask(value, walk, stack, depth + 1)
    return result


def _is_extra(key: str, walk: _Walk) -> bool:
    """True if the caller named ``key`` as secret (extra_keys)."""
    if not walk.extra:
        return False
    extra = {k.lower() for k in walk.extra}
    return key.lower() in extra or _normalise_name(key) in extra


def _readable_count(key: str, value: Any, walk: _Walk) -> bool:
    """A number under a counter name (not an extra key) stays readable."""
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and is_counter_name(key)
        and key.lower() not in {k.lower() for k in walk.extra}
    )


def _mask_sequence(obj: Any, walk: _Walk, stack: set[int], depth: int) -> Any:
    """Mask the items of a list, tuple, namedtuple or set."""
    if isinstance(obj, tuple) and hasattr(obj, "_fields"):  # namedtuple
        return type(obj)(
            *(
                mask_value(item)
                if is_secret_key(name, walk.extra)
                else _mask(item, walk, stack, depth + 1)
                for name, item in zip(obj._fields, obj, strict=False)
            )
        )
    items = [_mask(item, walk, stack, depth + 1) for item in obj]
    if isinstance(obj, list):
        return items
    if isinstance(obj, tuple):
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
        return redact_text(obj, macs=walk.macs) if walk.redact_strings else obj
    if isinstance(obj, bytes | bytearray | memoryview):
        return MASK
    if isinstance(obj, BaseException):
        return redact_text(str(obj))
    if isinstance(obj, _PLAIN_VALUE_TYPES):
        return obj
    is_dc = is_dataclass(obj) and not isinstance(obj, type)
    if not (is_dc or isinstance(obj, Mapping | list | tuple | set | frozenset)):
        # Unknown object: its attributes may hold a secret; show the type.
        return f"**OBJECT:{type(obj).__name__}**"
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


def mask_for_output(
    data: Any, *, extra_keys: Iterable[str] = (), macs: bool = False
) -> Any:
    """Like :func:`mask_secrets`, and every string goes through redact_text.

    The last barrier before HTTP responses, logs and events. Strings under
    id/hash keys (``*_id``, ``*_ids``, ``*_hash``, ``sha256``) stay only in
    a strict id/hash shape, otherwise they are redacted like any text; sets
    and namedtuples keep their type. MACs in strings are kept unless
    ``macs`` is True: structured output names network identifiers on
    purpose (a config diff names a ``dhcp`` host by its MAC); outputs
    without such content (network diagnostics, the diagnostics download)
    pass True. Exception texts always lose their MACs.
    """
    walk = _Walk(extra=frozenset(extra_keys), redact_strings=True, macs=macs)
    return _mask(data, walk, set(), 0)


# --- user pseudonyms ----------------------------------------------------------

# Home Assistant user ids never leave the core as they are: diagnostics and
# the bus event (recorder, logbook) carry ``usr_<12 hex>`` instead, an
# HMAC-SHA256 of the id with a caller-owned random salt (security review
# 2026-11-18 #11, review PR #55 finding 7). The audit store keeps the id.
ACTOR_PSEUDONYM_PREFIX: Final = "usr_"
ACTOR_PSEUDONYM_HEX_LENGTH: Final = 12
USER_ID_KEY: Final = "user_id"


def pseudonymise_user_id(user_id: str, salt: bytes) -> str:
    """``usr_<12 hex>`` for ``user_id``; same id and salt, same pseudonym."""
    digest = hmac.new(salt, user_id.encode("utf-8"), hashlib.sha256).hexdigest()
    return ACTOR_PSEUDONYM_PREFIX + digest[:ACTOR_PSEUDONYM_HEX_LENGTH]


def pseudonymise_user_ids(data: Any, salt: bytes) -> Any:
    """Copy of ``data`` with every string under a ``user_id`` key replaced.

    Walks mappings, lists and tuples (as lists) up to MAX_DEPTH; deeper
    values are returned unchanged, which is safe only because the result
    then goes through :func:`mask_for_output` (it truncates beyond the
    same depth). The input is never changed.
    """
    return _pseudonymise(data, salt, 0)


def _pseudonymise(data: Any, salt: bytes, depth: int) -> Any:
    if depth > MAX_DEPTH:
        return data
    if isinstance(data, Mapping):
        return {
            key: (
                pseudonymise_user_id(value, salt)
                if key == USER_ID_KEY and isinstance(value, str)
                else _pseudonymise(value, salt, depth + 1)
            )
            for key, value in data.items()
        }
    if isinstance(data, list | tuple):
        return [_pseudonymise(value, salt, depth + 1) for value in data]
    return data


# --- network identifier pseudonyms (follow-up B4) -------------------------------

# Core masking never hides MAC/IP/hostname/SSID/BSSID; a module that must
# (exports, reports) replaces them with ``<prefix><16 hex>``: HMAC-SHA256
# under the module's own key (api.async_get_module_key) over the kind and the
# normalised value. Same key + kind + value -> same pseudonym; the kind is
# part of the input, so one MAC as ``mac`` and as ``client`` cannot be linked.
IDENTIFIER_PSEUDONYM_PREFIXES: Final[Mapping[str, str]] = {
    "mac": "mac_",
    "ip": "ipa_",
    "hostname": "hst_",
    "ssid": "ssd_",
    "bssid": "bss_",
    "client": "cli_",
}
IDENTIFIER_PSEUDONYM_HEX_LENGTH: Final = 16
IDENTIFIER_INVALID: Final = "**INVALID_IDENTIFIER**"
_IDENTIFIER_INFO: Final = b"openwrt_router/identifier/v1"
_MAC_HEX_RE: Final = re.compile(r"[0-9a-f]{12}")
_MAC_SHAPE_RE: Final = re.compile(
    r"[0-9A-Fa-f]{2}(?:([:-])[0-9A-Fa-f]{2})(?:\1[0-9A-Fa-f]{2}){4}"
    r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}"
    r"|[0-9A-Fa-f]{12}"
)


def _normalise_mac(value: str) -> str:
    text = value.strip()
    if _MAC_SHAPE_RE.fullmatch(text) is None:
        raise ValueError("not a MAC address")
    digits = re.sub(r"[^0-9a-f]", "", text.lower())
    if _MAC_HEX_RE.fullmatch(digits) is None:
        raise ValueError("not a MAC address")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _normalise_identifier(kind: str, value: object) -> str:
    """Canonical form per kind; ValueError if ``value`` is not one."""
    if not isinstance(value, str):
        raise TypeError("identifier must be a string")
    if kind in ("mac", "bssid", "client"):
        return _normalise_mac(value)
    if kind == "ip":
        try:
            return ip_address(value.strip()).compressed
        except ValueError:
            raise ValueError("not an IP address") from None
    if kind == "hostname":
        name = value.strip().rstrip(".").lower()
        if not name or any(c.isspace() for c in name):
            raise ValueError("not a hostname")
        return name
    # ssid: case and spaces are significant; only an empty SSID is refused
    if not value or len(value.encode("utf-8")) > 32:
        raise ValueError("not an SSID (1-32 bytes)")
    return value


def pseudonymise_identifier(kind: str, value: str, key: bytes) -> str:
    """``<prefix><16 hex>`` for a network identifier (pure, deterministic).

    ``kind``: mac, ip, hostname, ssid, bssid, client (a client is named by
    its MAC). Normalisation: MAC/BSSID/client lower case with ``:``
    (``AA-BB-…``, ``aabb.ccdd.eeff`` and bare hex accepted); IPv4/IPv6 in
    the canonical compressed form; hostname lower case without a trailing
    dot; SSID unchanged (case sensitive). ValueError for an unknown kind, a
    value that is not of the kind, or a key shorter than 16 bytes;
    TypeError for a value that is not a string.
    """
    prefix = IDENTIFIER_PSEUDONYM_PREFIXES.get(kind) if isinstance(kind, str) else None
    if prefix is None:
        raise ValueError("unknown identifier kind")
    if not isinstance(key, bytes) or len(key) < SECRET_DIGEST_MIN_KEY_BYTES:
        raise ValueError(f"key must be at least {SECRET_DIGEST_MIN_KEY_BYTES} bytes")
    canonical = _normalise_identifier(kind, value)
    message = b"\x00".join((_IDENTIFIER_INFO, kind.encode(), canonical.encode()))
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()
    return prefix + digest[:IDENTIFIER_PSEUDONYM_HEX_LENGTH]


def pseudonymise_fields(data: Any, key: bytes, fields: Mapping[str, str]) -> Any:
    """Copy of ``data`` with the identifiers under the named fields replaced.

    ``fields`` maps a field name to its kind (``{"mac": "mac", "ip": "ip"}``).
    Walks mappings, lists and tuples (as lists) up to MAX_DEPTH (deeper
    values become TRUNCATED); a string, or each string in a list, under a
    named field becomes its pseudonym; one that is not of the kind becomes
    IDENTIFIER_INVALID (never the raw value). None stays None. The input is
    never changed.
    """
    for kind in fields.values():
        if kind not in IDENTIFIER_PSEUDONYM_PREFIXES:
            raise ValueError("unknown identifier kind")
    if not isinstance(key, bytes) or len(key) < SECRET_DIGEST_MIN_KEY_BYTES:
        raise ValueError(f"key must be at least {SECRET_DIGEST_MIN_KEY_BYTES} bytes")
    return _pseudo_fields(data, key, dict(fields), 0)


def _pseudo_one(kind: str, value: Any, key: bytes) -> Any:
    if value is None:
        return None
    if isinstance(value, list | tuple):
        return [_pseudo_one(kind, item, key) for item in value]
    try:
        return pseudonymise_identifier(kind, value, key)
    except (TypeError, ValueError):
        return IDENTIFIER_INVALID


def _pseudo_fields(data: Any, key: bytes, fields: dict[str, str], depth: int) -> Any:
    if depth > MAX_DEPTH:
        return TRUNCATED
    if isinstance(data, Mapping):
        out: dict[Any, Any] = {}
        for name, value in data.items():
            kind = fields.get(name) if isinstance(name, str) else None
            if kind is not None:
                out[name] = _pseudo_one(kind, value, key)
            else:
                out[name] = _pseudo_fields(value, key, fields, depth + 1)
        return out
    if isinstance(data, list | tuple):
        return [_pseudo_fields(value, key, fields, depth + 1) for value in data]
    return data
