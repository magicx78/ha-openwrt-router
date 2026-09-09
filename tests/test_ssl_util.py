"""Tests for ssl_util — SSL context selection for the HA side.

The contexts must come from Home Assistant's process-wide caches
(homeassistant.util.ssl); building a fresh context per client would be a
blocking call in the event loop and waste memory.
"""

from __future__ import annotations

import ssl

from homeassistant.util.ssl import client_context, client_context_no_verify

from custom_components.openwrt_router.ssl_util import ssl_context_for_protocol


def test_http_returns_none():
    assert ssl_context_for_protocol("http") is None


def test_https_returns_cached_verified_context():
    ctx = ssl_context_for_protocol("https")
    assert ctx is client_context()
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_https_insecure_returns_cached_no_verify_context():
    ctx = ssl_context_for_protocol("https-insecure")
    assert ctx is client_context_no_verify()
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE
