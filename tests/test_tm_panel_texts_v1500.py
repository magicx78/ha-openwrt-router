"""1.50.0: every ``title_key`` the Time Machine can produce has a German text.

The "Zeitreise" tab shows ``TITLE_TEXT[mark.title_key]`` (``tmTexts.ts``).
A key without an entry falls back to the server's ``text`` (Security Center
only, already masked) and else to "Code <title_key>". This test collects the
keys from the backend itself, per source of ``tm_sources.py``:

* ``core_audit.<event type>``: the core types (``CoreEventType``) and the
  module types of every module that registers an event prefix (WiFi RF,
  network diagnostics, Configuration Manager, Traffic Analytics, Security
  Center: rule ids of its detectors, trust actions, status and settings).
* ``config_versions.<reason>.<status>``: ``BackupReason`` x ``VersionStatus``.
* ``ni_events.<kind>``: the log kinds of ``log_parser`` that the engine
  stores (``<category>.<kind>`` minus ``COUNT_ONLY_KINDS``), the ``*_KIND``
  constants and ``kind="..."`` literals of ``net_rules`` / ``net_engine`` and
  the RF findings of ``rf_incidents``.
* ``ni_incidents.<type>``: the rule types of ``net_rules.DEFAULT_SETTINGS``.
* ``security_timeline.<kind>[.<type>]``: the kinds the Security Center
  writes into its timeline (read from its source, so a new kind fails here)
  with the types each kind carries.
* ``<source>.unknown`` for a code that is no token.

Not enumerable (the fallback rule covers them, see ``NOT_COVERED``): module
types of a module that does not exist yet or of a newer stored version,
incident types of an older stored version, log kinds of a newer parser.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from custom_components.openwrt_router import (
    config_manager,
    diag_core,
    log_parser,
    net_engine,
    net_rules,
    rf_events,
    rf_incidents,
    security_center,
    security_model,
    security_rules,
    security_trust,
    tm_sources,
    traffic_collector,
    traffic_const,
)
from custom_components.openwrt_router.core_models import (
    BackupReason,
    CoreEventType,
    VersionStatus,
)

_PKG = Path(__file__).parents[1] / "custom_components/openwrt_router"
_TEXTS = _PKG / "frontend/topology/src/enterprise/timemachine/tmTexts.ts"

# What the table cannot list in advance; the tab shows the server text or
# "Code <title_key>" for these (documented in docs/time-machine.md).
NOT_COVERED = (
    "core_audit: module event types of modules added later or of a newer stored version",
    "ni_events: log kinds of a newer parser, kinds of events stored by an older version",
    "ni_incidents: incident types of an older stored version (rule removed since)",
    "security_timeline: kinds or types added to the Security Center later",
)


def _security_rule_ids() -> set[str]:
    return {
        cls.id
        for _name, cls in inspect.getmembers(security_rules, inspect.isclass)
        if isinstance(getattr(cls, "id", None), str) and cls.id
    }


def audit_types() -> set[str]:
    types = {t.value for t in CoreEventType}
    types |= set(rf_events.ALL_EVENT_TYPES) | set(diag_core.DIAG_EVENT_TYPES)
    types |= {
        config_manager.EVENT_BACKUP_BLOCKED,
        traffic_collector.EVENT_REJECTED,
        traffic_const.EVENT_ANOMALY_STARTED,
        traffic_const.EVENT_ANOMALY_ENDED,
        traffic_const.EVENT_INDICATOR,
        security_center.EVENT_INCIDENT_STATUS,
        security_center.EVENT_SETTINGS,
    }
    types |= set(security_model.AUDIT_MANDATORY_TYPES)
    types |= {security_model.event_type(rule) for rule in _security_rule_ids()}
    return types


_NI_LITERAL = r'"((?:system|wan|lan|dfs|wifi|dhcp|dns|rf|link|iface)\.[a-z_]+)"'


def ni_event_kinds() -> set[str]:
    lp = vars(log_parser)
    categories = {
        name.removeprefix("CATEGORY_"): value
        for name, value in lp.items()
        if name.startswith("CATEGORY_") and isinstance(value, str)
    }
    kinds: set[str] = set()
    for prefix, category in categories.items():
        for name, value in lp.items():
            if (
                name.startswith(f"{prefix}_")
                and not name.startswith("CATEGORY_")
                and isinstance(value, str)
            ):
                kinds.add(f"{category}.{value}")
    kinds -= {f"{c}.{k}" for c, k in log_parser.COUNT_ONLY_KINDS}
    for module in (net_rules, net_engine):
        kinds |= {
            value
            for name, value in vars(module).items()
            if name.endswith("_KIND") and isinstance(value, str) and "." in value
        }
        # every dotted kind literal (``kind="wan.down"``, ``_wan_reconnect("wan.up",
        # ...)``, kind tuples): a literal that is no stored kind only costs a text
        kinds |= set(re.findall(_NI_LITERAL, inspect.getsource(module)))
    kinds |= {
        net_rules.SERVICE_RESTART,
        net_rules.SERVICE_STOPPED,
        net_rules.CRASH_LOOP_KIND,
        net_rules.DECLINE_KIND,
    }
    kinds |= set(rf_incidents.RF_EVENT_KINDS)
    return kinds


def ni_incident_types() -> set[str]:
    rules = net_rules.DEFAULT_SETTINGS["thresholds"]
    return {k for k in rules if k not in ("auto_resolve", "ignored")}


# Types a Security Center timeline kind carries (``type_=`` of ``_timeline``).
def _security_types() -> dict[str, set[str]]:
    trust = {f"trust_{k.value}" for k in security_trust.TrustActionKind}
    return {
        security_center.KIND_TRAFFIC_NOTE: set(security_center.TRAFFIC_INDICATORS),
        "notice": {f"trust_{k.value}" for k in security_trust.NoticeKind},
        "reused": _security_rule_ids(),
        "action": trust,
    }


def security_timeline_codes() -> set[str]:
    source = inspect.getsource(security_center)
    kinds = set(re.findall(r'self\._timeline\(\s*[^,]+,\s*"([a-z_]+)"', source))
    kinds |= set(re.findall(r'self\._note_once\("([a-z_]+)"', source))
    kinds.add(security_center.KIND_TRAFFIC_NOTE)
    typed = _security_types()
    expected = {
        "drift",
        "status",
        "incident_opened",
        "incident_reopened",
        "incident_seen_again",
        "incident_resolved",
        "wifi_quota_reached",
        "cap_reached",
        "log_quota_reached",
        "other_quota_reached",
        *typed,
    }
    # a new timeline kind must be added here (and to the table)
    assert kinds == expected, sorted(kinds ^ expected)
    codes = set(kinds)  # a type that is no token leaves the bare kind
    for kind, types in typed.items():
        codes |= {f"{kind}.{t}" for t in types}
    return codes


def backend_title_keys() -> set[str]:
    codes = {
        tm_sources.SOURCE_CORE_AUDIT: audit_types(),
        tm_sources.SOURCE_CONFIG_VERSIONS: {
            f"{r.value}.{s.value}" for r in BackupReason for s in VersionStatus
        },
        tm_sources.SOURCE_NI_EVENTS: ni_event_kinds(),
        tm_sources.SOURCE_NI_INCIDENTS: ni_incident_types(),
        tm_sources.SOURCE_SECURITY_TIMELINE: security_timeline_codes(),
    }
    keys: set[str] = set()
    for source, values in codes.items():
        assert values, source
        for code in values:
            # make_mark: a code that is no token becomes "unknown"
            keys.add(f"{source}.{tm_sources.token(code) or 'unknown'}")
        keys.add(f"{source}.unknown")
    return keys


def _table(name: str) -> dict[str, str]:
    source = _TEXTS.read_text(encoding="utf-8")
    start = source.index(f"export const {name}: Record<string, string> = {{")
    body = source[start : source.index("\n};", start)]
    return dict(
        re.findall(r"^\s+'([a-z0-9_.]+)': '([^']+)',", body, flags=re.MULTILINE)
    )


def test_every_backend_title_key_has_a_german_text() -> None:
    keys = backend_title_keys()
    assert len(keys) > 200  # sanity: all five sources were collected
    table = _table("TITLE_TEXT")
    missing = sorted(keys - set(table))
    assert missing == [], f"title_key without a German text: {missing}"


def test_the_texts_are_plain_sentences_without_codes() -> None:
    for key, text in _table("TITLE_TEXT").items():
        assert text.strip() == text and text, key
        assert "_" not in text and not text.endswith("."), (key, text)


def test_states_reasons_groups_sources_and_severities_have_texts() -> None:
    assert set(_table("SOURCE_TEXT")) == set(tm_sources.SOURCE_IDS)
    assert set(_table("STATE_TEXT")) == {
        tm_sources.STATE_OK,
        tm_sources.STATE_EMPTY,
        tm_sources.STATE_OFF,
        tm_sources.STATE_UNREADABLE,
    }
    assert set(_table("REASON_TEXT")) == set(tm_sources.REASONS)
    assert set(_table("GROUP_TEXT")) == set(tm_sources.KIND_GROUP.values())
    assert set(_table("SEVERITY_TEXT")) == set(tm_sources.SEVERITIES)


def test_every_parameter_the_sources_hand_out_has_a_text() -> None:
    names = set(tm_sources._AUDIT_PARAMS) | set(tm_sources._NI_EVENT_PARAMS)
    names |= set(tm_sources._NI_INCIDENT_PARAMS) | {"repeat_count", "count"}
    assert names <= set(_table("PARAM_TEXT")), sorted(names - set(_table("PARAM_TEXT")))


def test_the_not_covered_list_is_honest() -> None:
    # each entry names one of the five sources
    assert {line.split(":", 1)[0] for line in NOT_COVERED} <= set(tm_sources.SOURCE_IDS)
