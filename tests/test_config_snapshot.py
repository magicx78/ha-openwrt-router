"""Tests for normalized UCI snapshots (configuration manager, G3).

Plan: docs/plans/2026-11-17-config-manager.md, sections 3, 11.4, 14.1 and
16 (case 6). Pure logic: no router, no Home Assistant instance.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import random
import re
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from typing import Any

import pytest

from custom_components.openwrt_router.api import _parse_uci_show as api_parse_uci_show
from custom_components.openwrt_router.config_const import (
    SECRET_MARKER_KEY,
    UCI_CONFIGS,
)
from custom_components.openwrt_router.config_mask import secret_digest_factory
from custom_components.openwrt_router.config_snapshot import (
    UciSnapshot,
    build_snapshot,
    canonical_json,
    fingerprint_from_coordinator,
    normalize_uci,
    parse_uci_file,
    parse_uci_file_detailed,
    parse_uci_show,
    parse_uci_show_detailed,
)

DIGEST = secret_digest_factory(b"k" * 32)
OTHER_DIGEST = secret_digest_factory(b"z" * 32)

PLAINTEXT_SECRETS = ("WifiSecret#1", "GuestPass", "PppSecret!42")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")

# ---------------------------------------------------------------------------
# Fixtures: one router configuration in the three source forms
# (file text = /etc/config/* and archive, ubus `uci get`, `uci show`).
# ---------------------------------------------------------------------------

NETWORK_FILE = """\
config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1'
    option netmask '255.0.0.0'

config globals 'globals'
    option ula_prefix 'fd12:3456:789a::/48'
    option packet_steering '1'

config device
    option name 'br-lan'
    option type 'bridge'
    list ports 'lan1'
    list ports 'lan2'
    list ports 'lan3'

config bridge-vlan
    option device 'br-lan'
    option vlan '1'
    list ports 'lan1:u*'
    list ports 'lan2:u*'

config bridge-vlan
    option device 'br-lan'
    option vlan '10'
    list ports 'lan3:t'

config interface 'lan'
    option device 'br-lan.1'
    option proto 'static'
    option ipaddr '192.168.1.1'
    option netmask '255.255.255.0'
    list dns '1.1.1.1'

config interface 'wan'
    option device 'wan'
    option proto 'pppoe'
    option username 'user@isp'
    option password 'PppSecret!42'
"""

# Tabs, a comment line, a trailing comment, '#' inside quotes, the '\''
# escape and a double-quoted value, as found in real files.
WIRELESS_FILE = r"""# Wireless configuration
config wifi-device 'radio0'
    option type 'mac80211'
    option path 'platform/soc/18000000.wifi'
    option band '2g'
    option channel '1'
    option htmode 'HE20'
    option country 'DE'
    option cell_density '0'

config wifi-iface 'default_radio0'
    option device 'radio0'
    option network 'lan'
    option mode 'ap'
    option ssid 'Home'
    option encryption 'sae-mixed'
    option key 'WifiSecret#1'   # trailing comment

config wifi-iface
    option device 'radio0'
    option network 'guest'
    option mode 'ap'
    option ssid 'Guest It'\''s'
    option encryption 'psk2'
    option key "GuestPass"
    option isolate '1'
""".replace("    ", "\t")

FIREWALL_FILE = """\
config defaults
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'
    option synflood_protect '1'

config zone
    option name 'lan'
    list network 'lan'
    option input 'ACCEPT'
    option output 'ACCEPT'
    option forward 'ACCEPT'

config zone
    option name 'wan'
    list network 'wan'
    list network 'wan6'
    option input 'REJECT'
    option output 'ACCEPT'
    option forward 'REJECT'
    option masq '1'
    option mtu_fix '1'

config forwarding
    option src 'lan'
    option dest 'wan'

config rule
    option name 'Allow-DHCP-Renew'
    option src 'wan'
    option proto 'udp'
    option dest_port '68'
    option target 'ACCEPT'
    option family 'ipv4'

config rule
    option name 'Allow-Ping'
    option src 'wan'
    option proto 'icmp'
    option icmp_type 'echo-request'
    option family 'ipv4'
    option target 'ACCEPT'

config rule
    option src 'wan'
    option dest_port '22'
    option proto 'tcp'
    option target 'DROP'
"""

DHCP_FILE = """\
config dnsmasq
    option domainneeded '1'
    option localise_queries '1'
    option local '/lan/'
    option domain 'lan'
    list server '9.9.9.9'
    list server '149.112.112.112'

config dhcp 'lan'
    option interface 'lan'
    option start '100'
    option limit '150'
    option leasetime '12h'

config dhcp 'wan'
    option interface 'wan'
    option ignore '1'

config host
    option name 'nas'
    option mac '00:11:22:33:44:55'
    option ip '192.168.1.10'

config host
    option name 'printer'
    option mac 'AA:BB:CC:DD:EE:FF'
    option ip '192.168.1.20'
"""

SYSTEM_FILE = """\
package system

config system
    option hostname 'OpenWrt-GW'
    option timezone 'CET-1CEST,M3.5.0,M10.5.0/3'
    option zonename 'Europe/Berlin'
    option log_size '64'

config timeserver 'ntp'
    option enabled '1'
    option enable_server '0'
    list server '0.openwrt.pool.ntp.org'
    list server '1.openwrt.pool.ntp.org'
"""

DROPBEAR_FILE = """\
config dropbear
    option PasswordAuth 'on'
    option RootPasswordAuth 'on'
    option Port '22'
"""

FILES = {
    "network": NETWORK_FILE,
    "wireless": WIRELESS_FILE,
    "firewall": FIREWALL_FILE,
    "dhcp": DHCP_FILE,
    "system": SYSTEM_FILE,
    "dropbear": DROPBEAR_FILE,
}


def _named(stype: str, name: str, index: int, /, **opts: Any) -> dict[str, Any]:
    return {
        ".anonymous": False,
        ".type": stype,
        ".name": name,
        ".index": index,
        **opts,
    }


def _anon(stype: str, name: str, index: int, /, **opts: Any) -> dict[str, Any]:
    return {
        ".anonymous": True,
        ".type": stype,
        ".name": name,
        ".index": index,
        **opts,
    }


# What rpcd `uci get {"config": X}` returns under "values".
UBUS: dict[str, dict[str, dict[str, Any]]] = {
    "network": {
        "loopback": _named(
            "interface",
            "loopback",
            0,
            device="lo",
            proto="static",
            ipaddr="127.0.0.1",
            netmask="255.0.0.0",
        ),
        "globals": _named(
            "globals",
            "globals",
            1,
            ula_prefix="fd12:3456:789a::/48",
            packet_steering="1",
        ),
        "cfg030f15": _anon(
            "device",
            "cfg030f15",
            2,
            name="br-lan",
            type="bridge",
            ports=["lan1", "lan2", "lan3"],
        ),
        "cfg040f15": _anon(
            "bridge-vlan",
            "cfg040f15",
            3,
            device="br-lan",
            vlan="1",
            ports=["lan1:u*", "lan2:u*"],
        ),
        "cfg050f15": _anon(
            "bridge-vlan",
            "cfg050f15",
            4,
            device="br-lan",
            vlan="10",
            ports=["lan3:t"],
        ),
        "lan": _named(
            "interface",
            "lan",
            5,
            device="br-lan.1",
            proto="static",
            ipaddr="192.168.1.1",
            netmask="255.255.255.0",
            dns=["1.1.1.1"],
        ),
        "wan": _named(
            "interface",
            "wan",
            6,
            device="wan",
            proto="pppoe",
            username="user@isp",
            password="PppSecret!42",
        ),
    },
    "wireless": {
        "radio0": _named(
            "wifi-device",
            "radio0",
            0,
            type="mac80211",
            path="platform/soc/18000000.wifi",
            band="2g",
            channel="1",
            htmode="HE20",
            country="DE",
            cell_density="0",
        ),
        "default_radio0": _named(
            "wifi-iface",
            "default_radio0",
            1,
            device="radio0",
            network="lan",
            mode="ap",
            ssid="Home",
            encryption="sae-mixed",
            key="WifiSecret#1",
        ),
        "cfg033579": _anon(
            "wifi-iface",
            "cfg033579",
            2,
            device="radio0",
            network="guest",
            mode="ap",
            ssid="Guest It's",
            encryption="psk2",
            key="GuestPass",
            isolate="1",
        ),
    },
    "firewall": {
        "cfg01e63d": _anon(
            "defaults",
            "cfg01e63d",
            0,
            input="REJECT",
            output="ACCEPT",
            forward="REJECT",
            synflood_protect="1",
        ),
        "cfg02dc81": _anon(
            "zone",
            "cfg02dc81",
            1,
            name="lan",
            network=["lan"],
            input="ACCEPT",
            output="ACCEPT",
            forward="ACCEPT",
        ),
        "cfg03dc81": _anon(
            "zone",
            "cfg03dc81",
            2,
            name="wan",
            network=["wan", "wan6"],
            input="REJECT",
            output="ACCEPT",
            forward="REJECT",
            masq="1",
            mtu_fix="1",
        ),
        "cfg04ad58": _anon("forwarding", "cfg04ad58", 3, src="lan", dest="wan"),
        "cfg0592bd": _anon(
            "rule",
            "cfg0592bd",
            4,
            name="Allow-DHCP-Renew",
            src="wan",
            proto="udp",
            dest_port="68",
            target="ACCEPT",
            family="ipv4",
        ),
        "cfg0692bd": _anon(
            "rule",
            "cfg0692bd",
            5,
            name="Allow-Ping",
            src="wan",
            proto="icmp",
            icmp_type="echo-request",
            family="ipv4",
            target="ACCEPT",
        ),
        "cfg0792bd": _anon(
            "rule",
            "cfg0792bd",
            6,
            src="wan",
            dest_port="22",
            proto="tcp",
            target="DROP",
        ),
    },
    "dhcp": {
        "cfg01411c": _anon(
            "dnsmasq",
            "cfg01411c",
            0,
            domainneeded="1",
            localise_queries="1",
            local="/lan/",
            domain="lan",
            server=["9.9.9.9", "149.112.112.112"],
        ),
        "lan": _named(
            "dhcp",
            "lan",
            1,
            interface="lan",
            start="100",
            limit="150",
            leasetime="12h",
        ),
        "wan": _named("dhcp", "wan", 2, interface="wan", ignore="1"),
        "cfg03fe63": _anon(
            "host",
            "cfg03fe63",
            3,
            name="nas",
            mac="00:11:22:33:44:55",
            ip="192.168.1.10",
        ),
        "cfg04fe63": _anon(
            "host",
            "cfg04fe63",
            4,
            name="printer",
            mac="AA:BB:CC:DD:EE:FF",
            ip="192.168.1.20",
        ),
    },
    "system": {
        "cfg01e48a": _anon(
            "system",
            "cfg01e48a",
            0,
            hostname="OpenWrt-GW",
            timezone="CET-1CEST,M3.5.0,M10.5.0/3",
            zonename="Europe/Berlin",
            log_size="64",
        ),
        "ntp": _named(
            "timeserver",
            "ntp",
            1,
            enabled="1",
            enable_server="0",
            server=["0.openwrt.pool.ntp.org", "1.openwrt.pool.ntp.org"],
        ),
    },
    "dropbear": {
        "cfg014dd4": _anon(
            "dropbear",
            "cfg014dd4",
            0,
            PasswordAuth="on",
            RootPasswordAuth="on",
            Port="22",
        ),
    },
}

# `uci show <config>` output. Note: a one-element list prints exactly like an
# option (network.lan.dns, firewall.@zone[0].network).
SHOW = {
    "network": """\
network.loopback=interface
network.loopback.device='lo'
network.loopback.proto='static'
network.loopback.ipaddr='127.0.0.1'
network.loopback.netmask='255.0.0.0'
network.globals=globals
network.globals.ula_prefix='fd12:3456:789a::/48'
network.globals.packet_steering='1'
network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='lan1' 'lan2' 'lan3'
network.@bridge-vlan[0]=bridge-vlan
network.@bridge-vlan[0].device='br-lan'
network.@bridge-vlan[0].vlan='1'
network.@bridge-vlan[0].ports='lan1:u*' 'lan2:u*'
network.@bridge-vlan[1]=bridge-vlan
network.@bridge-vlan[1].device='br-lan'
network.@bridge-vlan[1].vlan='10'
network.@bridge-vlan[1].ports='lan3:t'
network.lan=interface
network.lan.device='br-lan.1'
network.lan.proto='static'
network.lan.ipaddr='192.168.1.1'
network.lan.netmask='255.255.255.0'
network.lan.dns='1.1.1.1'
network.wan=interface
network.wan.device='wan'
network.wan.proto='pppoe'
network.wan.username='user@isp'
network.wan.password='PppSecret!42'
""",
    "wireless": r"""wireless.radio0=wifi-device
wireless.radio0.type='mac80211'
wireless.radio0.path='platform/soc/18000000.wifi'
wireless.radio0.band='2g'
wireless.radio0.channel='1'
wireless.radio0.htmode='HE20'
wireless.radio0.country='DE'
wireless.radio0.cell_density='0'
wireless.default_radio0=wifi-iface
wireless.default_radio0.device='radio0'
wireless.default_radio0.network='lan'
wireless.default_radio0.mode='ap'
wireless.default_radio0.ssid='Home'
wireless.default_radio0.encryption='sae-mixed'
wireless.default_radio0.key='WifiSecret#1'
wireless.@wifi-iface[1]=wifi-iface
wireless.@wifi-iface[1].device='radio0'
wireless.@wifi-iface[1].network='guest'
wireless.@wifi-iface[1].mode='ap'
wireless.@wifi-iface[1].ssid='Guest It'\''s'
wireless.@wifi-iface[1].encryption='psk2'
wireless.@wifi-iface[1].key='GuestPass'
wireless.@wifi-iface[1].isolate='1'
""",
    "firewall": """\
firewall.@defaults[0]=defaults
firewall.@defaults[0].input='REJECT'
firewall.@defaults[0].output='ACCEPT'
firewall.@defaults[0].forward='REJECT'
firewall.@defaults[0].synflood_protect='1'
firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan'
firewall.@zone[0].input='ACCEPT'
firewall.@zone[0].output='ACCEPT'
firewall.@zone[0].forward='ACCEPT'
firewall.@zone[1]=zone
firewall.@zone[1].name='wan'
firewall.@zone[1].network='wan' 'wan6'
firewall.@zone[1].input='REJECT'
firewall.@zone[1].output='ACCEPT'
firewall.@zone[1].forward='REJECT'
firewall.@zone[1].masq='1'
firewall.@zone[1].mtu_fix='1'
firewall.@forwarding[0]=forwarding
firewall.@forwarding[0].src='lan'
firewall.@forwarding[0].dest='wan'
firewall.@rule[0]=rule
firewall.@rule[0].name='Allow-DHCP-Renew'
firewall.@rule[0].src='wan'
firewall.@rule[0].proto='udp'
firewall.@rule[0].dest_port='68'
firewall.@rule[0].target='ACCEPT'
firewall.@rule[0].family='ipv4'
firewall.@rule[1]=rule
firewall.@rule[1].name='Allow-Ping'
firewall.@rule[1].src='wan'
firewall.@rule[1].proto='icmp'
firewall.@rule[1].icmp_type='echo-request'
firewall.@rule[1].family='ipv4'
firewall.@rule[1].target='ACCEPT'
firewall.@rule[2]=rule
firewall.@rule[2].src='wan'
firewall.@rule[2].dest_port='22'
firewall.@rule[2].proto='tcp'
firewall.@rule[2].target='DROP'
""",
    "dhcp": """\
dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].domainneeded='1'
dhcp.@dnsmasq[0].localise_queries='1'
dhcp.@dnsmasq[0].local='/lan/'
dhcp.@dnsmasq[0].domain='lan'
dhcp.@dnsmasq[0].server='9.9.9.9' '149.112.112.112'
dhcp.lan=dhcp
dhcp.lan.interface='lan'
dhcp.lan.start='100'
dhcp.lan.limit='150'
dhcp.lan.leasetime='12h'
dhcp.wan=dhcp
dhcp.wan.interface='wan'
dhcp.wan.ignore='1'
dhcp.@host[0]=host
dhcp.@host[0].name='nas'
dhcp.@host[0].mac='00:11:22:33:44:55'
dhcp.@host[0].ip='192.168.1.10'
dhcp.@host[1]=host
dhcp.@host[1].name='printer'
dhcp.@host[1].mac='AA:BB:CC:DD:EE:FF'
dhcp.@host[1].ip='192.168.1.20'
""",
    "system": """\
system.@system[0]=system
system.@system[0].hostname='OpenWrt-GW'
system.@system[0].timezone='CET-1CEST,M3.5.0,M10.5.0/3'
system.@system[0].zonename='Europe/Berlin'
system.@system[0].log_size='64'
system.ntp=timeserver
system.ntp.enabled='1'
system.ntp.enable_server='0'
system.ntp.server='0.openwrt.pool.ntp.org' '1.openwrt.pool.ntp.org'
""",
    "dropbear": """\
dropbear.@dropbear[0]=dropbear
dropbear.@dropbear[0].PasswordAuth='on'
dropbear.@dropbear[0].RootPasswordAuth='on'
dropbear.@dropbear[0].Port='22'
""",
}


def _ubus() -> dict[str, dict[str, dict[str, Any]]]:
    return copy.deepcopy(UBUS)


def _snap_ubus(raw: dict[str, Any] | None = None) -> UciSnapshot:
    return build_snapshot(raw if raw is not None else _ubus(), DIGEST)


def _dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Plan 16 case 6: identical configs from all sources
# ---------------------------------------------------------------------------


def test_identical_configs_same_hash_across_sources() -> None:
    from_ubus = build_snapshot(_ubus(), DIGEST)
    from_show = build_snapshot(
        {name: parse_uci_show(text, name) for name, text in SHOW.items()}, DIGEST
    )
    from_file = build_snapshot(
        {name: parse_uci_file(text) for name, text in FILES.items()}, DIGEST
    )

    assert from_ubus.configs == from_show.configs
    assert from_ubus.configs == from_file.configs
    assert from_ubus.content_hash == from_show.content_hash
    assert from_ubus.content_hash == from_file.content_hash
    assert _HEX64.match(from_ubus.content_hash)
    assert from_ubus.missing == from_show.missing == from_file.missing


def test_existing_api_uci_show_parser_gives_same_hash() -> None:
    """The SSH fallback in api.py (_parse_uci_show) feeds the same shape."""
    from_api = build_snapshot(
        {name: api_parse_uci_show(text, name) for name, text in SHOW.items()},
        DIGEST,
    )
    assert from_api.content_hash == _snap_ubus().content_hash


def test_content_hash_is_sha256_of_canonical_json() -> None:
    snap = _snap_ubus()
    expected = hashlib.sha256(canonical_json(snap.configs).encode()).hexdigest()
    assert snap.content_hash == expected
    assert canonical_json({"b": 1, "a": [2, "ü"]}) == '{"a":[2,"ü"],"b":1}'


def test_hash_is_deterministic_and_independent_of_dict_order() -> None:
    raw = _ubus()
    shuffled = {
        name: dict(reversed(list(sections.items())))
        for name, sections in reversed(list(raw.items()))
    }
    assert _snap_ubus(shuffled).content_hash == _snap_ubus(raw).content_hash


# ---------------------------------------------------------------------------
# Shape of the normalized form
# ---------------------------------------------------------------------------


def test_normalized_shape_and_identity_keys() -> None:
    snap = _snap_ubus()
    net = snap.configs["network"]
    assert set(net) == {"sections", "order"}
    assert net["order"] == [
        "loopback",
        "globals",
        '@device{"name":"br-lan"}',
        '@bridge-vlan{"device":"br-lan","vlan":"1"}',
        '@bridge-vlan{"device":"br-lan","vlan":"10"}',
        "lan",
        "wan",
    ]
    # An option literally called "type" does not clash with the section type.
    assert net["sections"]['@device{"name":"br-lan"}'] == {
        "type": "device",
        "options": {
            "name": "br-lan",
            "type": "bridge",
            "ports": ["lan1", "lan2", "lan3"],
        },
    }
    assert set(snap.configs["firewall"]["sections"]) == {
        "@defaults[0]",
        '@zone{"name":"lan"}',
        '@zone{"name":"wan"}',
        '@forwarding{"dest":"wan","src":"lan"}',
        '@rule{"name":"Allow-DHCP-Renew"}',
        '@rule{"name":"Allow-Ping"}',
        "@rule[0]",
    }
    assert set(snap.configs["dhcp"]["sections"]) == {
        "@dnsmasq[0]",
        "lan",
        "wan",
        '@host{"mac":"00:11:22:33:44:55"}',
        '@host{"mac":"AA:BB:CC:DD:EE:FF"}',
    }
    assert set(snap.configs["wireless"]["sections"]) == {
        "radio0",
        "default_radio0",
        '@wifi-iface{"device":"radio0","mode":"ap","ssid":"Guest It\'s"}',
    }
    assert snap.configs["system"]["order"] == ["@system[0]", "ntp"]
    assert snap.configs["dropbear"]["order"] == ["@dropbear[0]"]


def test_meta_keys_dropped_and_no_cfg_names() -> None:
    dumped = _dump(_snap_ubus().configs)
    for meta in (".name", ".anonymous", ".index", ".type"):
        assert meta not in dumped
    assert not re.search(r"cfg[0-9a-f]{6}", dumped)


def test_values_are_not_converted() -> None:
    a = normalize_uci("system", {"x": _named("system", "x", 0, enabled="1")}, DIGEST)
    b = normalize_uci("system", {"x": _named("system", "x", 0, enabled="on")}, DIGEST)
    assert a["sections"]["x"]["options"]["enabled"] == "1"
    assert b["sections"]["x"]["options"]["enabled"] == "on"
    assert a != b


def test_lists_keep_order_and_list_order_matters() -> None:
    raw = _ubus()
    snap = _snap_ubus(raw)
    servers = snap.configs["dhcp"]["sections"]["@dnsmasq[0]"]["options"]["server"]
    assert servers == ["9.9.9.9", "149.112.112.112"]
    raw["dhcp"]["cfg01411c"]["server"] = ["149.112.112.112", "9.9.9.9"]
    assert _snap_ubus(raw).content_hash != snap.content_hash


def test_single_element_list_equals_option() -> None:
    """`uci show` cannot tell a one-element list from an option."""
    as_list = normalize_uci(
        "network", {"lan": _named("interface", "lan", 0, dns=["1.1.1.1"])}, DIGEST
    )
    as_option = normalize_uci(
        "network", {"lan": _named("interface", "lan", 0, dns="1.1.1.1")}, DIGEST
    )
    assert as_list == as_option
    assert as_list["sections"]["lan"]["options"]["dns"] == "1.1.1.1"


# ---------------------------------------------------------------------------
# Anonymous sections: reorder, rename, collisions, fallback
# ---------------------------------------------------------------------------


def test_reordered_anonymous_sections_same_content_other_order() -> None:
    raw = _ubus()
    rules = raw["firewall"]
    rules["cfg0592bd"][".index"], rules["cfg0692bd"][".index"] = 5, 4
    raw["firewall"] = dict(sorted(rules.items(), key=lambda kv: kv[1][".index"]))

    base = _snap_ubus()
    moved = _snap_ubus(raw)
    assert moved.configs["firewall"]["sections"] == base.configs["firewall"]["sections"]
    assert moved.configs["firewall"]["order"] != base.configs["firewall"]["order"]
    assert moved.configs["firewall"]["order"][4:6] == [
        '@rule{"name":"Allow-Ping"}',
        '@rule{"name":"Allow-DHCP-Renew"}',
    ]
    # Rule order is real configuration (first match wins), so the hash moves.
    assert moved.content_hash != base.content_hash
    for name in ("network", "wireless", "dhcp", "system", "dropbear"):
        assert moved.configs[name] == base.configs[name]


def test_renamed_anonymous_sections_same_hash() -> None:
    raw = _ubus()
    renamed: dict[str, dict[str, Any]] = {}
    for name, sections in raw.items():
        renamed[name] = {}
        for key, body in sections.items():
            if body[".anonymous"]:
                new = f"cfg{random.Random(key).randrange(16**6):06x}"
                body = {**body, ".name": new}
                key = new
            renamed[name][key] = body
    assert renamed != raw
    assert _snap_ubus(renamed).content_hash == _snap_ubus(raw).content_hash


def test_identity_collisions_resolved_by_content_not_position() -> None:
    def fw(order: list[tuple[str, str]]) -> dict[str, Any]:
        return {
            f"cfg{i:06x}": _anon(
                "rule", f"cfg{i:06x}", i, name="Dup", dest_port=port, target=target
            )
            for i, (port, target) in enumerate(order)
        }

    first = normalize_uci("firewall", fw([("80", "ACCEPT"), ("443", "DROP")]), DIGEST)
    second = normalize_uci("firewall", fw([("443", "DROP"), ("80", "ACCEPT")]), DIGEST)
    assert set(first["sections"]) == {'@rule{"name":"Dup"}', '@rule{"name":"Dup"}#2'}
    assert first["sections"] == second["sections"]
    assert first["order"] == list(reversed(second["order"]))


def test_fallback_position_counts_only_sections_without_identity() -> None:
    raw = _ubus()["firewall"]
    before = normalize_uci("firewall", raw, DIGEST)
    raw["cfg0892bd"] = _anon("rule", "cfg0892bd", -1, name="New-First", target="ACCEPT")
    raw["cfg0992bd"] = _anon("rule", "cfg0992bd", 7, src="lan", target="REJECT")
    after = normalize_uci("firewall", raw, DIGEST)
    # The unnamed DROP rule keeps its key although a rule was put in front.
    assert after["sections"]["@rule[0]"] == before["sections"]["@rule[0]"]
    assert after["sections"]["@rule[1]"]["options"]["src"] == "lan"
    assert after["order"][0] == '@rule{"name":"New-First"}'


def test_wifi_iface_identity_prefers_ifname_and_bridge_vlan_device_vlan() -> None:
    raw = {
        "cfg1": _anon(
            "wifi-iface", "cfg1", 0, device="radio1", ifname="phy1-ap0", ssid="X"
        ),
        "cfg2": _anon(
            "wifi-iface", "cfg2", 1, device="radio1", mesh_id="mesh", mode="mesh"
        ),
    }
    keys = list(normalize_uci("wireless", raw, DIGEST)["order"])
    assert keys == [
        '@wifi-iface{"device":"radio1","ifname":"phy1-ap0"}',
        '@wifi-iface{"device":"radio1","mesh_id":"mesh","mode":"mesh"}',
    ]
    # dhcp.host without mac falls back to name.
    host = normalize_uci(
        "dhcp", {"c": _anon("host", "c", 0, name="tv", ip="10.0.0.9")}, DIGEST
    )
    assert host["order"] == ['@host{"name":"tv"}']


def test_unknown_config_uses_type_and_position() -> None:
    raw = {
        "a": _anon("queue", "a", 0, interface="wan"),
        "b": _anon("other", "b", 1, x="1"),
        "c": _anon("other", "c", 2, x="2"),
    }
    assert normalize_uci("custom", raw, DIGEST)["order"] == [
        "@queue[0]",
        "@other[0]",
        "@other[1]",
    ]


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------


def test_secret_never_in_snapshot() -> None:
    for snap in (
        _snap_ubus(),
        build_snapshot({n: parse_uci_file(t) for n, t in FILES.items()}, DIGEST),
        build_snapshot({n: parse_uci_show(t, n) for n, t in SHOW.items()}, DIGEST),
    ):
        dumped = _dump(snap.configs) + repr(snap)
        for secret in PLAINTEXT_SECRETS:
            assert secret not in dumped
        key = snap.configs["wireless"]["sections"]["default_radio0"]["options"]["key"]
        assert set(key) == {SECRET_MARKER_KEY}
        assert _HEX16.match(key[SECRET_MARKER_KEY])
        password = snap.configs["network"]["sections"]["wan"]["options"]["password"]
        assert set(password) == {SECRET_MARKER_KEY}


def test_changed_secret_changes_hash_and_only_its_digest() -> None:
    raw = _ubus()
    base = _snap_ubus(raw)
    raw["wireless"]["default_radio0"]["key"] = "AnotherSecret"
    changed = _snap_ubus(raw)
    assert changed.content_hash != base.content_hash
    old_opts = base.configs["wireless"]["sections"]["default_radio0"]["options"]
    new_opts = changed.configs["wireless"]["sections"]["default_radio0"]["options"]
    assert old_opts["key"] != new_opts["key"]
    assert {k: v for k, v in old_opts.items() if k != "key"} == {
        k: v for k, v in new_opts.items() if k != "key"
    }
    assert "AnotherSecret" not in _dump(changed.configs)


def test_secret_list_masked_per_element_and_digest_input() -> None:
    calls: list[str] = []

    def recording(value: str) -> str:
        calls.append(value)
        return DIGEST(value)

    raw = {
        "default_radio0": _named(
            "wifi-iface",
            "default_radio0",
            0,
            ssid="Home",
            r0kh=[
                "ff:ff:ff:ff:ff:ff,*,KeyMaterialA",
                "aa:bb:cc:dd:ee:ff,*,KeyMaterialB",
            ],
        )
    }
    out = normalize_uci("wireless", raw, recording)
    r0kh = out["sections"]["default_radio0"]["options"]["r0kh"]
    assert isinstance(r0kh, list) and len(r0kh) == 2
    assert all(set(item) == {SECRET_MARKER_KEY} for item in r0kh)
    assert r0kh[0] != r0kh[1]
    assert "KeyMaterial" not in _dump(out)
    # Config, section type, option, value as a JSON array: no section key.
    assert calls == [
        '["wireless","wifi-iface","r0kh","ff:ff:ff:ff:ff:ff,*,KeyMaterialA"]',
        '["wireless","wifi-iface","r0kh","aa:bb:cc:dd:ee:ff,*,KeyMaterialB"]',
    ]


def _guest_iface(ssid: str, key: str, index: int = 0) -> dict[str, Any]:
    return _anon(
        "wifi-iface",
        f"cfg0{index}3579",
        index,
        device="radio0",
        mode="ap",
        ssid=ssid,
        encryption="psk2",
        key=key,
    )


def test_secret_digest_independent_of_section_key() -> None:
    """The SSID is part of the anonymous key; the key digest must not move."""
    before = normalize_uci("wireless", {"a": _guest_iface("Gast", "GuestPass")}, DIGEST)
    after = normalize_uci(
        "wireless", {"a": _guest_iface("Gast-2", "GuestPass")}, DIGEST
    )
    (old_key,) = before["sections"]
    (new_key,) = after["sections"]
    assert old_key != new_key
    assert "Gast" in old_key and "Gast-2" in new_key
    old_digest = before["sections"][old_key]["options"]["key"]
    new_digest = after["sections"][new_key]["options"]["key"]
    assert old_digest == new_digest
    # A changed key still changes the digest under the new section key.
    rekeyed = normalize_uci(
        "wireless", {"a": _guest_iface("Gast-2", "OtherPass")}, DIGEST
    )
    assert rekeyed["sections"][new_key]["options"]["key"] != new_digest
    # Named sections: renaming the section keeps the digest as well.
    named = {
        name: _named("wifi-iface", name, 0, device="radio0", key="WifiSecret#1")
        for name in ("default_radio0", "home_2g")
    }
    digests = {
        name: normalize_uci("wireless", {name: body}, DIGEST)["sections"][name][
            "options"
        ]["key"]
        for name, body in named.items()
    }
    assert digests["default_radio0"] == digests["home_2g"]


def test_secret_digest_input_is_unambiguous() -> None:
    """Config, type, option and value are encoded separately (JSON array)."""
    calls: list[str] = []

    def recording(value: str) -> str:
        calls.append(value)
        return DIGEST(value)

    tricky = 'a","b/c'
    normalize_uci(
        "network",
        {"wan": _named("interface", "wan", 0, proto="pppoe", password=tricky)},
        recording,
    )
    assert [json.loads(call) for call in calls] == [
        ["network", "interface", "password", tricky]
    ]
    # "ddns/a/password/password/b" for both under plain concatenation; the
    # array keeps them apart.
    a = normalize_uci(
        "ddns",
        {"s": _named("a", "s", 0, password="password/b")},
        DIGEST,
    )["sections"]["s"]["options"]["password"]
    b = normalize_uci(
        "ddns",
        {"s": _named("a/password", "s", 0, password="b")},
        DIGEST,
    )["sections"]["s"]["options"]["password"]
    assert a != b


def test_secret_digest_bound_to_config_type_and_option() -> None:
    def digest_of(config: str, stype: str, option: str) -> Any:
        raw = {"s": _named(stype, "s", 0, **{option: "SamePlaintext"})}
        return normalize_uci(config, raw, DIGEST)["sections"]["s"]["options"][option]

    base = digest_of("wireless", "wifi-iface", "key")
    assert set(base) == {SECRET_MARKER_KEY}
    assert digest_of("wireless", "wifi-iface", "sae_password") != base
    assert digest_of("wireless", "wifi-mesh", "key") != base
    assert digest_of("openvpn", "wifi-iface", "key") != base


def test_same_secret_in_two_sections_of_same_type_gives_same_digest() -> None:
    """Accepted consequence (see normalize_uci): equality is visible in HA."""
    raw = {
        "a": _guest_iface("Gast", "SharedPass", 0),
        "b": _guest_iface("Lab", "SharedPass", 1),
    }
    sections = normalize_uci("wireless", raw, DIGEST)["sections"]
    digests = [body["options"]["key"] for body in sections.values()]
    assert len(digests) == 2
    assert digests[0] == digests[1]
    assert "SharedPass" not in _dump(sections)


def test_installation_key_changes_digest_not_structure() -> None:
    a = build_snapshot(_ubus(), DIGEST)
    b = build_snapshot(_ubus(), OTHER_DIGEST)
    assert a.content_hash != b.content_hash
    assert a.configs["network"]["order"] == b.configs["network"]["order"]


def test_context_secret_detected_by_section_type() -> None:
    raw = {
        "svc": _named("service", "svc", 0, update_url="https://u:p@x/upd", domain="d")
    }
    opts = normalize_uci("ddns", raw, DIGEST)["sections"]["svc"]["options"]
    assert set(opts["update_url"]) == {SECRET_MARKER_KEY}
    assert opts["domain"] == "d"


def test_logs_contain_no_raw_values(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    text = "option key 'TopSecret1' \nconfig wifi-iface\n option key 'TopSecret2' extra\n option key 'TopSecret3"
    parse_uci_file_detailed(text)
    parse_uci_show_detailed("wireless.x.key='TopSecret4\n", "wireless")
    normalize_uci(
        "wireless",
        {"x": {".type": "wifi-iface", "key": "TopSecret5"}, "y": "TopSecret6"},
        DIGEST,
    )
    build_snapshot({"wireless": "TopSecret7"}, DIGEST)
    assert "TopSecret" not in caplog.text


# ---------------------------------------------------------------------------
# Missing configs and snapshot object
# ---------------------------------------------------------------------------


def test_missing_config_lands_in_missing() -> None:
    raw: dict[str, Any] = {
        "network": UBUS["network"],
        "wireless": None,
        "dhcp": "permission denied",
    }
    snap = build_snapshot(raw, DIGEST)
    assert set(snap.configs) == {"network"}
    assert snap.missing == frozenset(UCI_CONFIGS) - {"network"}
    assert "wireless" in snap.missing and "dhcp" in snap.missing


def test_empty_config_is_present_not_missing() -> None:
    snap = build_snapshot({"network": {}}, DIGEST)
    assert snap.configs["network"] == {"sections": {}, "order": []}
    assert "network" not in snap.missing


def test_configs_outside_list_ignored_unless_requested() -> None:
    raw = {
        "network": UBUS["network"],
        "luci": {"main": _named("core", "main", 0, lang="auto")},
    }
    assert "luci" not in build_snapshot(raw, DIGEST).configs
    all_given = build_snapshot(raw, DIGEST, configs=None)
    assert set(all_given.configs) == {"network", "luci"}
    assert all_given.missing == frozenset()
    only = build_snapshot(raw, DIGEST, configs=("network", "sqm"))
    assert set(only.configs) == {"network"} and only.missing == {"sqm"}


def test_snapshot_is_frozen() -> None:
    snap = _snap_ubus()
    with pytest.raises((FrozenInstanceError, AttributeError)):
        snap.content_hash = "x"  # type: ignore[misc]


def test_malformed_sections_are_skipped_without_crash() -> None:
    raw = {
        "ok": _named("interface", "ok", 0, proto="dhcp"),
        "bad": "not a section",
        "notype": {"proto": "static"},
        "nested": _named("interface", "nested", 1, weird={"a": 1}, num=5),
    }
    out = normalize_uci("network", raw, DIGEST)
    assert "bad" not in out["sections"]
    assert out["sections"]["notype"] == {"type": "", "options": {"proto": "static"}}
    assert out["sections"]["nested"]["options"]["num"] == 5
    json.dumps(out)


# ---------------------------------------------------------------------------
# parse_uci_file
# ---------------------------------------------------------------------------


def test_parse_file_ubus_shape() -> None:
    parsed = parse_uci_file(FIREWALL_FILE)
    assert list(parsed)[:2] == ["@defaults[0]", "@zone[0]"]
    zone = parsed["@zone[1]"]
    assert zone[".type"] == "zone"
    assert zone[".anonymous"] is True
    assert zone[".name"] == "@zone[1]"
    assert zone[".index"] == 2
    assert zone["network"] == ["wan", "wan6"]
    named = parse_uci_file(NETWORK_FILE)["lan"]
    assert named[".anonymous"] is False and named[".name"] == "lan"


def test_parse_file_quotes_escapes_comments() -> None:
    text = r"""
# full line comment

config wifi-iface 'w'   # comment after header
	option ssid 'Guest It'\''s'
	option key 'with#hash'
	option dq "say \"hi\" \\ ok"
	option bare plain\ word
	option mixed 'a'"b"c
	option empty_dq_list_ok 'x' # comment
"""
    w = parse_uci_file(text)["w"]
    assert w["ssid"] == "Guest It's"
    assert w["key"] == "with#hash"
    assert w["dq"] == 'say "hi" \\ ok'
    assert w["bare"] == "plain word"
    assert w["mixed"] == "abc"
    assert w["empty_dq_list_ok"] == "x"


def test_parse_file_continuation_multiline_crlf_semicolon() -> None:
    text = (
        "package dhcp\r\n"
        "config dnsmasq\r\n"
        "\tlist server \\\r\n"
        "\t\t'9.9.9.9'\r\n"
        '\toption dq "ab\\\r\ncd"\r\n'
        "\toption multi 'line1\r\nline2'\r\n"
        "config host 'h'; option mac 'aa'\r\n"
    )
    result = parse_uci_file_detailed(text)
    assert result.package == "dhcp"
    assert result.skipped == 0
    dns = result.sections["@dnsmasq[0]"]
    assert dns["server"] == ["9.9.9.9"]
    assert dns["dq"] == "abcd"
    assert dns["multi"] == "line1\nline2"
    assert result.sections["h"]["mac"] == "aa"


def test_parse_file_list_option_interplay_and_duplicate_sections() -> None:
    text = """
config interface 'lan'
    option dns 'a'
    list dns 'b'
    list ports 'x'
    option ports 'y'
config interface 'wan'
    option proto 'dhcp'
config interface 'lan'
    option proto 'static'
"""
    parsed = parse_uci_file(text)
    assert list(parsed) == ["lan", "wan"]
    assert parsed["lan"]["dns"] == ["a", "b"]
    assert parsed["lan"]["ports"] == "y"
    assert parsed["lan"]["proto"] == "static"
    assert parsed["lan"][".index"] == 0


def test_parse_file_anonymous_index_counts_named_sections() -> None:
    text = "config wifi-iface 'a'\nconfig wifi-iface\nconfig wifi-device\nconfig wifi-iface\n"
    assert list(parse_uci_file(text)) == [
        "a",
        "@wifi-iface[1]",
        "@wifi-device[0]",
        "@wifi-iface[2]",
    ]


@pytest.mark.parametrize(
    ("text", "skipped"),
    [
        ("option a '1'\nconfig x 'ok'\n", 1),  # option before any section
        ("config x 'ok'\nbogus line here\n", 1),  # unknown keyword
        ("config x 'ok'\noption a '1' '2'\n", 1),  # too many arguments
        ("config x 'ok'\noption a\n", 1),  # option without value
        ("config x 'ok'\noption a ''\n", 1),  # empty value is not stored
        ("config x 'ok'\noption bad-name '1'\n", 1),  # invalid option name
        (
            "config x 'bad name'\noption a '1'\nconfig x 'ok'\n",
            2,
        ),  # bad header + its option
        ("config\nconfig x 'ok'\n", 1),  # config without type
        ("config x 'ok'\noption a 'unterminated\n", 1),  # EOF inside quote
        ('config x "ok"\noption a "unterminated\n', 1),
        ("package\nconfig x 'ok'\n", 1),
    ],
)
def test_parse_file_broken_lines_skipped_and_counted(text: str, skipped: int) -> None:
    result = parse_uci_file_detailed(text)
    assert result.skipped == skipped
    assert result.sections["ok"][".type"] == "x"
    assert "a" not in result.sections["ok"]


def test_parse_file_empty_and_garbage() -> None:
    assert parse_uci_file("") == {}
    assert parse_uci_file("\n\n# only comments\n") == {}
    result = parse_uci_file_detailed("\x00\x01 garbage\n'''\n")
    assert result.sections == {}
    assert result.skipped >= 1


# ---------------------------------------------------------------------------
# parse_uci_show
# ---------------------------------------------------------------------------


def test_parse_show_shape_and_quoting() -> None:
    parsed = parse_uci_show(SHOW["wireless"], "wireless")
    iface = parsed["@wifi-iface[1]"]
    assert iface[".type"] == "wifi-iface"
    assert iface[".anonymous"] is True
    assert iface[".index"] == 2
    assert iface["ssid"] == "Guest It's"
    assert parsed["default_radio0"][".anonymous"] is False
    assert parse_uci_show(SHOW["firewall"], "firewall")["@zone[1]"]["network"] == [
        "wan",
        "wan6",
    ]


def test_parse_show_other_configs_garbage_and_multiline() -> None:
    text = (
        "network.lan=interface\n"
        "wireless.radio0=wifi-device\n"
        "Warning: something odd\n"
        "network.lan.description='first\n"
        "second'\n"
        "network.lan.proto='static'\n"
        "\n"
        "network.lan.broken='never closed\n"
        "network.lan.ipaddr='192.168.1.1'\n"
    )
    result = parse_uci_show_detailed(text, "network")
    lan = result.sections["lan"]
    assert list(result.sections) == ["lan"]
    assert lan["description"] == "first\nsecond"
    assert lan["proto"] == "static"
    assert lan["ipaddr"] == "192.168.1.1"
    assert "broken" not in lan
    assert result.skipped == 2  # the warning line and the unclosed value


# ---------------------------------------------------------------------------
# Fingerprint from coordinator data
# ---------------------------------------------------------------------------


def _coordinator_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "router_info": {
            "model": "GL.iNet GL-MT6000",
            "hostname": "OpenWrt-GW",
            "release": {
                "distribution": "OpenWrt",
                "version": "24.10.4",
                "revision": "r28959-29397011cc",
                "target": "mediatek/filogic",
            },
            "mac": "94:83:c4:00:00:01",
            "board_name": "glinet,gl-mt6000",
            "kernel": "6.6.110",
        },
        "uptime": 1000,
        "cpu_load": 3.5,
        "memory": {"total": 1_000_000, "free": 500_000},
        "wan_status": {
            "connected": True,
            "interface": "wan",
            "ipv4": "203.0.113.5",
            "uptime": 900,
            "proto": "pppoe",
            "rx_bytes": 123,
            "tx_bytes": 456,
        },
        "wan_connected": True,
        "wifi_radios": [
            {
                "name": "radio0",
                "ssid": "Home",
                "band": "2.4GHz",
                "enabled": True,
                "is_guest": False,
                "ifname": "phy0-ap0",
                "uci_section": "default_radio0",
                "channel": 1,
                "frequency": 2412,
                "txpower": 20,
                "bitrate": 286,
                "mode": "ap",
                "bssid": "94:83:c4:00:00:02",
            },
            {
                "name": "radio1",
                "ssid": "Home5",
                "band": "5GHz",
                "enabled": True,
                "uci_section": "default_radio1",
                "channel": 36,
                "mode": "ap",
            },
        ],
        "clients": [{"mac": "aa:bb:cc:00:00:01", "signal": -50}],
        "client_count": 1,
        "dhcp_leases": {"aa:bb:cc:00:00:01": {"ip": "192.168.1.50"}},
        "network_interfaces": [
            {
                "interface": "br-lan",
                "logical_name": "lan",
                "status": "up",
                "ipv4_addr": "192.168.1.1",
                "prefix_len": 24,
                "rx_bytes": 1,
                "tx_bytes": 2,
            },
            {
                "interface": "pppoe-wan",
                "logical_name": "wan",
                "status": "up",
                "ipv4_addr": "203.0.113.5",
                "prefix_len": 32,
                "rx_bytes": 3,
                "tx_bytes": 4,
            },
        ],
        "port_stats": [{"name": "lan1", "rx_bytes": 5}],
        "ap_interfaces": [
            {"ifname": "phy0-ap0", "ssid": "Home", "bitrate": 100, "channel": 1}
        ],
        "port_vlan_map": {"lan1": [1], "lan3": [10, 1]},
        "dhcp_pools": [
            {
                "name": "lan",
                "interface": "lan",
                "size": 150,
                "leases": 10,
                "usage_pct": 6.7,
            }
        ],
        "services": [
            {"name": "dnsmasq", "running": True, "enabled": True},
            {"name": "firewall", "running": True, "enabled": True},
            {"name": "sqm", "running": False, "enabled": None},
        ],
        "cpu_history": [{"ts": 1, "cpu": 2}],
        "events": [{"ts": 1}],
    }
    data.update(overrides)
    return data


def _volatile_variant() -> dict[str, Any]:
    data = _coordinator_data()
    data["uptime"] = 99_999
    data["cpu_load"] = 88.0
    data["memory"] = {"total": 1_000_000, "free": 10}
    data["wan_status"] = {
        **data["wan_status"],
        "ipv4": "198.51.100.9",
        "uptime": 5,
        "rx_bytes": 9,
        "connected": False,
    }
    data["wan_connected"] = False
    radios = copy.deepcopy(data["wifi_radios"])
    radios[0].update(
        channel=6,
        frequency=2437,
        txpower=17,
        bitrate=6,
        bssid="02:00:00:00:00:01",
        ifname="phy0-ap1",
    )
    data["wifi_radios"] = list(reversed(radios))
    data["clients"] = []
    data["client_count"] = 0
    data["dhcp_leases"] = {}
    ifaces = copy.deepcopy(data["network_interfaces"])
    ifaces[0].update(rx_bytes=999, tx_bytes=999, status="up")
    ifaces[1].update(ipv4_addr="198.51.100.9", status="down", rx_bytes=None)
    data["network_interfaces"] = list(reversed(ifaces))
    data["port_stats"] = []
    data["ap_interfaces"] = []
    data["port_vlan_map"] = {"lan3": [1, 10], "lan1": [1]}
    data["dhcp_pools"] = [
        {
            "name": "lan",
            "interface": "lan",
            "size": 150,
            "leases": 99,
            "usage_pct": 66.0,
        }
    ]
    data["services"] = [
        {"name": "firewall", "running": False, "enabled": True},
        {"name": "dnsmasq", "running": False, "enabled": True},
        {"name": "sqm", "running": True, "enabled": None},
    ]
    data["cpu_history"] = []
    data["events"] = [{"ts": 2}, {"ts": 3}]
    data["router_info"] = {**data["router_info"], "kernel": "6.6.110"}
    return data


def test_fingerprint_stable_across_volatile_fields() -> None:
    first = fingerprint_from_coordinator(_coordinator_data())
    assert _HEX64.match(first)
    assert fingerprint_from_coordinator(_volatile_variant()) == first
    # Many polls, same result.
    assert {fingerprint_from_coordinator(_coordinator_data()) for _ in range(20)} == {
        first
    }


def _with(path: tuple[Any, ...], value: Any) -> dict[str, Any]:
    data = _coordinator_data()
    target: Any = data
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value
    return data


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("wifi_radios", 0, "ssid"), "Home-New"),
        (("wifi_radios", 1, "enabled"), False),
        (("wifi_radios", 1, "name"), "radio2"),
        (("router_info", "release", "version"), "25.12.0"),
        (("router_info", "release", "revision"), "r30000-abc"),
        (("router_info", "hostname"), "Renamed"),
        (("port_vlan_map", "lan1"), [1, 20]),
        (("network_interfaces", 0, "ipv4_addr"), "192.168.2.1"),
        (("network_interfaces", 0, "prefix_len"), 16),
        (("wan_status", "proto"), "dhcp"),
        (("dhcp_pools", 0, "size"), 50),
        (("services", 1, "enabled"), False),
    ],
)
def test_fingerprint_sensitive_to_config_fields(
    path: tuple[Any, ...], value: Any
) -> None:
    assert fingerprint_from_coordinator(
        _with(path, value)
    ) != fingerprint_from_coordinator(_coordinator_data())


def test_fingerprint_defensive_against_missing_and_odd_values() -> None:
    empty = fingerprint_from_coordinator({})
    assert _HEX64.match(empty)
    odd = {
        "router_info": [1, 2],
        "wifi_radios": "x",
        "network_interfaces": [None, 5, {"logical_name": None}],
        "port_vlan_map": {"lan1": "notalist", 5: [object()]},
        "dhcp_pools": None,
        "services": [{"enabled": True}, "x"],
        "wan_status": None,
    }
    assert _HEX64.match(fingerprint_from_coordinator(odd))
    assert _HEX64.match(fingerprint_from_coordinator(None))  # type: ignore[arg-type]


def test_fingerprint_accepts_coordinator_data_object() -> None:
    data = _coordinator_data()
    obj = SimpleNamespace(**data)
    assert fingerprint_from_coordinator(obj) == fingerprint_from_coordinator(data)  # type: ignore[arg-type]
