"""test_aggregator_skeleton.py — F5 (v1.18.0) aggregator-path skeleton.

The aggregator collapses the per-poll subprocess fan-out into one remote
shell invocation.  In v1.18.0 we ship only the skeleton — gated behind the
``use_aggregator`` feature flag (default off) — and these tests verify the
skeleton behaves correctly:

  * Feature flag default is OFF (no accidental enablement).
  * ``_call_aggregator`` raises NotImplementedError until the remote script
    is shipped (v1.19+).
  * ``_parse_aggregator_response`` validates the schema-version stamp.

Production data-flow tests will be added in v1.19 when /root/ha-collect.sh
is deployed.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from custom_components.openwrt_router.api import (  # noqa: E402
    OpenWrtAPI,
    OpenWrtResponseError,
)
from custom_components.openwrt_router.const import (  # noqa: E402
    AGGREGATOR_REMOTE_SCRIPT_PATH,
    AGGREGATOR_SCHEMA_VERSION,
    CONF_USE_AGGREGATOR,
    DEFAULT_USE_AGGREGATOR,
)


# ---------------------------------------------------------------------------
# Feature-flag defaults
# ---------------------------------------------------------------------------


def test_aggregator_flag_default_is_off():
    """Default must be False so v1.18.0 ships the helper but does NOT use it."""
    assert DEFAULT_USE_AGGREGATOR is False


def test_aggregator_flag_key_is_stable_string():
    """Other modules import this exact key — guard against typos."""
    assert CONF_USE_AGGREGATOR == "use_aggregator"


def test_aggregator_remote_script_path_under_root():
    """Path must be writable by SSH user (root) — same convention as other
    helper scripts (ha-system-metrics.sh, ha-wan-status.sh)."""
    assert AGGREGATOR_REMOTE_SCRIPT_PATH.startswith("/root/")
    assert AGGREGATOR_REMOTE_SCRIPT_PATH.endswith(".sh")


def test_aggregator_schema_version_format():
    """Version is dotted semver-ish for the rsplit(".",1) major.minor check."""
    parts = AGGREGATOR_SCHEMA_VERSION.split(".")
    assert len(parts) >= 2
    for p in parts:
        assert p.isdigit()


# ---------------------------------------------------------------------------
# _call_aggregator skeleton — must raise until v1.19
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_aggregator_raises_not_implemented():
    """Until /root/ha-collect.sh ships, the entry-point must fail loudly."""
    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="pw",
        session=MagicMock(),
        protocol="http",
    )
    with pytest.raises(NotImplementedError, match="skeleton-only"):
        await api._call_aggregator()


# ---------------------------------------------------------------------------
# _parse_aggregator_response — schema-version handling
# ---------------------------------------------------------------------------


def test_parse_aggregator_accepts_matching_schema_version():
    payload = '{"_v": "%s", "uptime": 12345}' % AGGREGATOR_SCHEMA_VERSION
    out = OpenWrtAPI._parse_aggregator_response(payload)
    assert out["_v"] == AGGREGATOR_SCHEMA_VERSION
    assert out["uptime"] == 12345


def test_parse_aggregator_accepts_patch_drift():
    """1.18.0 ↔ 1.18.5 is allowed (same major.minor)."""
    major_minor = AGGREGATOR_SCHEMA_VERSION.rsplit(".", 1)[0]
    payload = f'{{"_v": "{major_minor}.99", "load": [0,0,0]}}'
    out = OpenWrtAPI._parse_aggregator_response(payload)
    assert out["_v"].startswith(major_minor)


def test_parse_aggregator_rejects_major_minor_drift():
    """A 2.0.0 router script against a 1.18 integration must fail."""
    payload = '{"_v": "2.0.0", "uptime": 1}'
    with pytest.raises(OpenWrtResponseError, match="schema mismatch"):
        OpenWrtAPI._parse_aggregator_response(payload)


def test_parse_aggregator_rejects_invalid_json():
    with pytest.raises(OpenWrtResponseError, match="invalid JSON"):
        OpenWrtAPI._parse_aggregator_response("this is not json")


def test_parse_aggregator_rejects_missing_version_key():
    with pytest.raises(OpenWrtResponseError, match="missing schema-version"):
        OpenWrtAPI._parse_aggregator_response('{"uptime": 1}')


def test_parse_aggregator_rejects_non_dict_payload():
    with pytest.raises(OpenWrtResponseError, match="missing schema-version"):
        OpenWrtAPI._parse_aggregator_response('["a", "b"]')
