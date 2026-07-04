"""Tests for OpenWrtAPI.get_lldp_neighbors / probe_lldp / client enrichment."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.api import (
    OpenWrtMethodNotFoundError,
    OpenWrtAPI,
)

_LLDP_JSON = json.dumps(
    {
        "lldp": {
            "interface": {
                "lan3": {
                    "chassis": {
                        "AP2": {
                            "id": {"type": "mac", "value": "aa:bb:cc:dd:ee:02"},
                            "mgmt-ip": ["10.10.10.2"],
                        }
                    },
                    "port": {"id": {"value": "wan"}, "descr": "wan"},
                }
            }
        }
    }
)


def _api():
    return OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="pw",
        session=MagicMock(),
        protocol="http",
    )


def _fake_conn(exit_status=0, stdout=b"", stderr=b""):
    conn = MagicMock()
    conn.run = AsyncMock(
        return_value=SimpleNamespace(
            exit_status=exit_status, stdout=stdout, stderr=stderr
        )
    )
    conn.close = MagicMock()
    conn.wait_closed = AsyncMock()
    return conn


def _patch_connect(conn=None, side_effect=None):
    mock = (
        AsyncMock(return_value=conn)
        if side_effect is None
        else AsyncMock(side_effect=side_effect)
    )
    return patch(
        "custom_components.openwrt_router.api.asyncssh.connect", mock
    ), mock


class TestGetLldpNeighborsSsh:
    @pytest.mark.asyncio
    async def test_ssh_returns_neighbors_ok(self):
        api = _api()
        api._lldp_ubus_unavailable = True  # skip ubus probe → SSH path
        ctx, _ = _patch_connect(_fake_conn(stdout=_LLDP_JSON.encode()))
        with ctx:
            neighbors, status = await api.get_lldp_neighbors()
        assert status == "ok"
        assert len(neighbors) == 1
        assert neighbors[0]["management_ip"] == "10.10.10.2"
        # LLDP must NOT flip the degraded/SSH-fallback state.
        assert api.uses_ssh_fallback is False

    @pytest.mark.asyncio
    async def test_ssh_empty_lldp_is_no_neighbors(self):
        api = _api()
        api._lldp_ubus_unavailable = True
        ctx, _ = _patch_connect(_fake_conn(stdout=b'{"lldp":{}}'))
        with ctx:
            _neighbors, status = await api.get_lldp_neighbors()
        assert status == "no_neighbors"

    @pytest.mark.asyncio
    async def test_missing_lldpcli_is_unavailable(self):
        """lldpcli absent: non-zero exit, empty stdout → _run_ssh None → unavailable."""
        api = _api()
        api._lldp_ubus_unavailable = True
        ctx, _ = _patch_connect(_fake_conn(exit_status=127, stdout=b"", stderr=b"not found"))
        with ctx:
            neighbors, status = await api.get_lldp_neighbors()
        assert neighbors == []
        assert status == "unavailable"

    @pytest.mark.asyncio
    async def test_unavailable_is_cached_no_second_ssh(self):
        """Once unavailable, a second call must NOT open another SSH connection."""
        api = _api()
        api._lldp_ubus_unavailable = True
        ctx, mock = _patch_connect(_fake_conn(exit_status=127, stdout=b""))
        with ctx:
            await api.get_lldp_neighbors()
            first_calls = mock.await_count
            _neighbors, status = await api.get_lldp_neighbors()
        assert status == "unavailable"
        # No new connect on the second call — the cache short-circuits it.
        assert mock.await_count == first_calls


class TestGetLldpNeighborsUbus:
    @pytest.mark.asyncio
    async def test_ubus_object_used_before_ssh(self):
        """A working lldp ubus object short-circuits before any SSH call."""
        api = _api()
        ubus_result = {
            "lldp": {
                "interface": {
                    "lan1": {
                        "chassis": {"n": {"id": {"value": "aa"}, "mgmt-ip": ["10.0.0.9"]}},
                        "port": {"id": {"value": "lan2"}},
                    }
                }
            }
        }
        api._call = AsyncMock(return_value=ubus_result)
        ctx, mock = _patch_connect(_fake_conn(stdout=_LLDP_JSON.encode()))
        with ctx:
            neighbors, status = await api.get_lldp_neighbors()
        assert status == "ok"
        assert neighbors[0]["management_ip"] == "10.0.0.9"
        mock.assert_not_awaited()  # SSH never used

    @pytest.mark.asyncio
    async def test_ubus_method_not_found_falls_back_to_ssh(self):
        api = _api()
        api._call = AsyncMock(side_effect=OpenWrtMethodNotFoundError("no such object"))
        ctx, mock = _patch_connect(_fake_conn(stdout=_LLDP_JSON.encode()))
        with ctx:
            neighbors, status = await api.get_lldp_neighbors()
        assert status == "ok"
        assert len(neighbors) == 1
        assert mock.await_count == 1  # SSH used as fallback
        assert api._lldp_ubus_unavailable is True  # cached


class TestProbeLldp:
    @pytest.mark.asyncio
    async def test_probe_returns_status_string(self):
        api = _api()
        api._lldp_ubus_unavailable = True
        ctx, _ = _patch_connect(_fake_conn(stdout=_LLDP_JSON.encode()))
        with ctx:
            assert await api.probe_lldp() == "ok"

    @pytest.mark.asyncio
    async def test_capability_included_and_optional(self):
        """check_capabilities exposes lldp_neighbors; a miss is not required."""
        api = _api()
        api._call = AsyncMock(return_value={})
        api.probe_lldp = AsyncMock(return_value="unavailable")
        caps = await api.check_capabilities()
        assert "lldp_neighbors" in caps
        assert caps["lldp_neighbors"] is False  # unavailable → optional miss


class TestClientEnrichment:
    def test_wireless_client_gets_vendor_and_type(self):
        api = _api()
        clients = [
            {"mac": "34:29:8F:11:22:33", "ip": "10.10.10.50", "radio": "phy0-ap0"},
        ]
        api._enrich_client_metadata(clients)
        c = clients[0]
        assert c["connection_type"] == "wireless"  # never 'wired'
        assert c["vendor"] == "Cudy"  # server-side OUI
        assert c["web_url"] == "http://10.10.10.50"
        assert c["source"] == "hostapd"
        assert c["confidence"] == "high"

    def test_iwinfo_only_client_medium_confidence(self):
        api = _api()
        clients = [{"mac": "00:11:22:33:44:55", "ip": "", "radio": ""}]
        api._enrich_client_metadata(clients)
        c = clients[0]
        assert c["connection_type"] == "wireless"
        assert c["source"] == "iwinfo"
        assert c["confidence"] == "medium"
        assert "web_url" not in c  # no IP → no link
