"""Tests for helpers in custom_components.openwrt_router.const."""
from __future__ import annotations

from custom_components.openwrt_router.const import (
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_HTTPS_INSECURE,
    url_scheme_for,
)


class TestUrlSchemeFor:
    """Regression for v1.17.3.

    Internal `https-insecure` marker must collapse to `https` for any URL
    that HA's device_registry validates — otherwise async_get_or_create
    raises ValueError and all entities with configuration_url silently
    fail to register.
    """

    def test_https_insecure_collapses_to_https(self):
        assert url_scheme_for(PROTOCOL_HTTPS_INSECURE) == "https"

    def test_https_passes_through(self):
        assert url_scheme_for(PROTOCOL_HTTPS) == "https"

    def test_http_passes_through(self):
        assert url_scheme_for(PROTOCOL_HTTP) == "http"

    def test_empty_falls_back_to_http(self):
        assert url_scheme_for("") == "http"

    def test_unknown_value_passes_through(self):
        # Any custom marker we add later behaves like https/http (passes through),
        # so the helper does not silently rewrite future protocol options.
        assert url_scheme_for("custom") == "custom"
