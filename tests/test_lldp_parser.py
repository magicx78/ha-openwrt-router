"""Tests for the LLDP neighbor parser (_parse_lldpcli_json) in api.py."""
from __future__ import annotations

import json

from custom_components.openwrt_router.api import _parse_lldpcli_json


def _iface(ifname: str, chassis: dict, port: dict) -> dict:
    return {ifname: {"chassis": chassis, "port": port}}


class TestParseLldpcliJson:
    def test_single_neighbor_full(self):
        """One neighbor with SysName, mgmt-ip, capabilities and a named port."""
        raw = json.dumps(
            {
                "lldp": {
                    "interface": {
                        "lan3": {
                            "chassis": {
                                "OpenWrt-AP2": {
                                    "id": {"type": "mac", "value": "aa:bb:cc:dd:ee:02"},
                                    "mgmt-ip": ["10.10.10.2"],
                                    "capability": [
                                        {"type": "Bridge", "enabled": True},
                                        {"type": "Router", "enabled": True},
                                        {"type": "Wlan", "enabled": False},
                                    ],
                                }
                            },
                            "port": {
                                "id": {"type": "ifname", "value": "wan"},
                                "descr": "wan",
                            },
                        }
                    }
                }
            }
        )
        neighbors = _parse_lldpcli_json(raw)
        assert len(neighbors) == 1
        n = neighbors[0]
        assert n["local_interface"] == "lan3"
        assert n["chassis_name"] == "OpenWrt-AP2"
        assert n["chassis_id"] == "aa:bb:cc:dd:ee:02"
        assert n["management_ip"] == "10.10.10.2"
        assert n["port_id"] == "wan"
        assert n["port_descr"] == "wan"
        # only enabled capabilities are kept
        assert n["capabilities"] == ["Bridge", "Router"]

    def test_multiple_neighbors_json0_list_shape(self):
        """json0 wraps children in arrays; chassis may be a list; mgmt-ip a str."""
        raw = json.dumps(
            {
                "lldp": {
                    "interface": [
                        {
                            "lan3": {
                                "chassis": [
                                    {"r2": {"id": {"value": "aa02"}, "mgmt-ip": "10.10.10.2"}}
                                ],
                                "port": {"id": {"value": "wan"}},
                            }
                        },
                        {
                            "lan4": {
                                "chassis": {"r4": {"id": {"value": "aa04"}}},
                                "port": {"id": {"value": "wan"}},
                            }
                        },
                    ]
                }
            }
        )
        neighbors = _parse_lldpcli_json(raw)
        assert len(neighbors) == 2
        by_iface = {n["local_interface"]: n for n in neighbors}
        assert by_iface["lan3"]["management_ip"] == "10.10.10.2"
        assert by_iface["lan3"]["chassis_name"] == "r2"
        assert by_iface["lan4"]["management_ip"] is None
        assert by_iface["lan4"]["chassis_id"] == "aa04"

    def test_neighbor_without_mgmt_ip(self):
        raw = json.dumps(
            {
                "lldp": {
                    "interface": {
                        "eth0": {
                            "chassis": {"nodeX": {"id": {"value": "bb01"}}},
                            "port": {"id": {"value": "lan1"}},
                        }
                    }
                }
            }
        )
        n = _parse_lldpcli_json(raw)[0]
        assert n["management_ip"] is None
        assert n["chassis_name"] == "nodeX"

    def test_chassis_without_sysname(self):
        """A direct chassis object (no SysName wrapper) → chassis_name is None."""
        raw = json.dumps(
            {
                "lldp": {
                    "interface": {
                        "eth0": {
                            "chassis": {
                                "id": {"value": "cc99"},
                                "mgmt-ip": ["1.2.3.4"],
                            },
                            "port": {"id": {"value": "lan2"}},
                        }
                    }
                }
            }
        )
        n = _parse_lldpcli_json(raw)[0]
        assert n["chassis_name"] is None
        assert n["chassis_id"] == "cc99"
        assert n["management_ip"] == "1.2.3.4"

    def test_empty_result(self):
        assert _parse_lldpcli_json(json.dumps({"lldp": {}})) == []
        assert _parse_lldpcli_json(json.dumps({"lldp": {"interface": {}}})) == []

    def test_invalid_json_returns_empty(self):
        assert _parse_lldpcli_json("{ this is not json") == []
        assert _parse_lldpcli_json("") == []

    def test_non_dict_json_returns_empty(self):
        assert _parse_lldpcli_json(json.dumps([1, 2, 3])) == []

    def test_missing_lldpcli_empty_output(self):
        """lldpcli absent → shell prints nothing usable; empty string parses to []."""
        assert _parse_lldpcli_json("") == []
