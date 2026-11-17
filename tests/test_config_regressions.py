"""Regression guards for the Configuration Manager (plan 2026-11-17, case 20).

The Configuration Manager must not change existing behaviour:

* its network code lives only in the two marked blocks of api.py (another
  session extends api.py in parallel; nothing outside the blocks may move);
* the detection rules keep their threshold keys and root tiers, so no
  incident type appears, disappears or changes its correlation order.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from custom_components.openwrt_router import api as api_module
from custom_components.openwrt_router.net_rules import DEFAULT_SETTINGS, ROOT_TIERS

API_PATH = Path(api_module.__file__)
BLOCK_START = "# --- Configuration Manager (config_*) ---"
BLOCK_END = "# --- end Configuration Manager ---"

# The four public fetch methods (plan section 2.4).
PUBLIC_METHODS = {
    "config_fetch_backup_cgi",
    "config_fetch_backup_ssh",
    "config_uci_get",
    "config_packagelist",
}
EXCEPTIONS = {
    "OpenWrtConfigFetchError",
    "OpenWrtConfigFetchPermissionError",
    "OpenWrtConfigFetchNotAvailableError",
    "OpenWrtConfigFetchTooLargeError",
    "OpenWrtConfigFetchIncompleteError",
}


def _blocks(lines: list[str]) -> list[tuple[int, int]]:
    """Return (start, end) line numbers (1-based) of the marked blocks."""
    starts = [i for i, line in enumerate(lines, 1) if line.strip() == BLOCK_START]
    ends = [i for i, line in enumerate(lines, 1) if line.strip() == BLOCK_END]
    assert len(starts) == 2, starts
    assert len(ends) == 2, ends
    pairs = list(zip(starts, ends, strict=True))
    for start, end in pairs:
        assert start < end
    assert pairs[0][1] < pairs[1][0]
    return pairs


def _inside(lineno: int, blocks: list[tuple[int, int]]) -> bool:
    return any(start < lineno < end for start, end in blocks)


def test_api_additions_only_in_marked_block() -> None:
    source = API_PATH.read_text(encoding="utf-8")
    lines = source.splitlines()
    blocks = _blocks(lines)
    tree = ast.parse(source)

    # Every config_* / _config_* definition and every OpenWrtConfig* class,
    # at module level or inside a class, lies within a marked block.
    found_methods: set[str] = set()
    found_classes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            if re.match(r"_?config_", node.name):
                assert _inside(node.lineno, blocks), (node.name, node.lineno)
                assert _inside(node.end_lineno or node.lineno, blocks), node.name
                found_methods.add(node.name)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("OpenWrtConfig"):
            assert _inside(node.lineno, blocks), (node.name, node.lineno)
            assert _inside(node.end_lineno or node.lineno, blocks), node.name
            found_classes.add(node.name)
        elif isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id.startswith("_CONFIG_"):
                    assert _inside(node.lineno, blocks), (target.id, node.lineno)

    assert PUBLIC_METHODS <= found_methods
    assert found_classes == EXCEPTIONS

    # The method block sits inside class OpenWrtAPI, at its end; the second
    # block is at module level, after the class.
    api_class = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "OpenWrtAPI"
    )
    class_methods = {
        n.name: n
        for n in api_class.body
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    assert PUBLIC_METHODS <= set(class_methods)
    (first_start, first_end), (second_start, _) = blocks
    class_end = api_class.end_lineno or 0
    assert api_class.lineno < first_start < class_end
    # only blank lines / comments between the last class statement and the
    # end marker, which is indented like a class member
    assert all(
        not line.strip() or line.lstrip().startswith("#")
        for line in lines[class_end : first_end - 1]
    )
    assert lines[first_end - 1].startswith("    #")
    assert second_start > class_end
    # nothing of the class follows the method block
    after = [n.name for n in class_methods.values() if n.lineno > first_end]
    assert after == []
    assert lines[first_start - 1].startswith("    #")
    assert lines[second_start - 1].startswith("#")


def test_net_rules_thresholds_unchanged() -> None:
    # Key set of DEFAULT_SETTINGS["thresholds"] as of v1.42.0 (0dc20cd).
    assert set(DEFAULT_SETTINGS["thresholds"]) == {
        "auto_resolve",
        "dhcp_conflict",
        "dhcp_pool_full",
        "ignored",
        "lan_lldp_change",
        "lan_port_errors",
        "lan_port_flap",
        "lan_port_load",
        "lan_port_speed_drop",
        "lan_unreachable",
        "lan_uplink_down",
        "router_unreachable",
        "system_clock_skew",
        "system_conntrack_jump",
        "system_cpu_high",
        "system_ram_high",
        "system_reboot",
        "system_service_restart",
        "wan_down",
        "wan_ip_changed",
        "wan_unstable",
        "wifi_auth_failures",
        "wifi_auth_wave",
        "wifi_band_flapping",
        "wifi_channel_busy",
        "wifi_dhcp_after_connect",
        "wifi_mass_disconnect",
        "wifi_no_ip",
        "wifi_radio_change",
        "wifi_reconnect_storm",
        "wifi_roam_flapping",
        "wifi_weak_clients",
    }


def test_root_tiers_unchanged() -> None:
    # net_rules.ROOT_TIERS decides which incidents become correlation roots
    # (AlarmMachine.correlate); a config incident type must never join them.
    assert ROOT_TIERS == {
        "lan_unreachable": 1,
        "router_unreachable": 2,
        "system_reboot": 2,
        "wan_down": 3,
        "wifi_radio_change": 4,
        "lan_uplink_down": 5,
        "lan_port_flap": 6,
        "wifi_mass_disconnect": 7,
    }
    assert not any(key.startswith("config") for key in ROOT_TIERS)
