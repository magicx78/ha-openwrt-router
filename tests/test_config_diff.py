"""Tests for the structured UCI diff and drift evaluation (configuration manager, G4).

Plan: docs/plans/2026-11-17-config-manager.md, sections 11.6, 14.1 and 16
(cases 7, 8, 9). Every snapshot is built with ``config_snapshot.build_snapshot``
from UCI file text as it lies in ``/etc/config`` on OpenWrt 24.10. Pure
logic: no router, no Home Assistant instance.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from custom_components.openwrt_router import config_diff as cd
from custom_components.openwrt_router.config_const import (
    AREAS,
    MASK_PLACEHOLDER,
    RISKS,
    SECRET_MARKER_KEY,
)
from custom_components.openwrt_router.config_diff import (
    Area,
    Change,
    DriftAck,
    DriftReport,
    Risk,
    classify,
    diff_snapshots,
    drift_id,
    evaluate_drift,
    not_comparable,
)
from custom_components.openwrt_router.config_mask import (
    mask_for_output,
    secret_digest_factory,
)
from custom_components.openwrt_router.config_snapshot import (
    UciSnapshot,
    build_snapshot,
    parse_uci_file,
)

DIGEST = secret_digest_factory(b"k" * 32)
MGMT = "192.168.1.1"

WLAN_KEY = "WlanSecret#2026"
GUEST_KEY = "GastSecret!7"
PLAINTEXT = (WLAN_KEY, GUEST_KEY, "NewWlanSecret#2027")

NETWORK = """\
config interface 'loopback'
\toption device 'lo'
\toption proto 'static'
\toption ipaddr '127.0.0.1'
\toption netmask '255.0.0.0'

config globals 'globals'
\toption ula_prefix 'fd12:3456:789a::/48'
\toption packet_steering '1'

config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'lan1'
\tlist ports 'lan2'
\tlist ports 'lan3'

config bridge-vlan
\toption device 'br-lan'
\toption vlan '1'
\tlist ports 'lan1'
\tlist ports 'lan2'

config bridge-vlan
\toption device 'br-lan'
\toption vlan '10'
\tlist ports 'lan3:t'

config interface 'lan'
\toption device 'br-lan.1'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
\toption netmask '255.255.255.0'
\toption ip6assign '60'

config interface 'iot'
\toption device 'br-lan.10'
\toption proto 'static'
\toption ipaddr '192.168.10.1'
\toption netmask '255.255.255.0'

config interface 'wan'
\toption device 'wan'
\toption proto 'dhcp'

config interface 'wan6'
\toption device 'wan'
\toption proto 'dhcpv6'
"""

NETWORK_SWCONFIG = """\
config interface 'loopback'
\toption device 'lo'
\toption proto 'static'
\toption ipaddr '127.0.0.1'
\toption netmask '255.0.0.0'

config switch
\toption name 'switch0'
\toption reset '1'
\toption enable_vlan '1'

config switch_vlan
\toption device 'switch0'
\toption vlan '1'
\toption ports '1 2 3 4 0t'

config switch_vlan
\toption device 'switch0'
\toption vlan '2'
\toption ports '5 0t'

config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'eth0.1'

config interface 'lan'
\toption device 'br-lan'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
\toption netmask '255.255.255.0'

config interface 'wan'
\toption device 'eth0.2'
\toption proto 'dhcp'
"""

WIRELESS = f"""\
config wifi-device 'radio0'
\toption type 'mac80211'
\toption path 'platform/soc/18000000.wifi'
\toption channel '6'
\toption band '2g'
\toption htmode 'HE20'
\toption country 'DE'

config wifi-device 'radio1'
\toption type 'mac80211'
\toption path 'platform/soc/18000000.wifi+1'
\toption channel '36'
\toption band '5g'
\toption htmode 'HE80'
\toption country 'DE'

config wifi-iface 'default_radio0'
\toption device 'radio0'
\toption network 'lan'
\toption mode 'ap'
\toption ssid 'HomeNet'
\toption encryption 'sae-mixed'
\toption key '{WLAN_KEY}'

config wifi-iface 'default_radio1'
\toption device 'radio1'
\toption network 'lan'
\toption mode 'ap'
\toption ssid 'HomeNet'
\toption encryption 'sae-mixed'
\toption key '{WLAN_KEY}'

config wifi-iface
\toption device 'radio0'
\toption network 'iot'
\toption mode 'ap'
\toption ssid 'Gast'
\toption encryption 'psk2'
\toption key '{GUEST_KEY}'
\toption isolate '1'
"""

FIREWALL = """\
config defaults
\toption input 'REJECT'
\toption output 'ACCEPT'
\toption forward 'REJECT'
\toption synflood_protect '1'

config zone
\toption name 'lan'
\tlist network 'lan'
\tlist network 'iot'
\toption input 'ACCEPT'
\toption output 'ACCEPT'
\toption forward 'ACCEPT'

config zone
\toption name 'wan'
\tlist network 'wan'
\tlist network 'wan6'
\toption input 'REJECT'
\toption output 'ACCEPT'
\toption forward 'REJECT'
\toption masq '1'
\toption mtu_fix '1'

config forwarding
\toption src 'lan'
\toption dest 'wan'

config rule
\toption name 'Allow-DHCP-Renew'
\toption src 'wan'
\toption proto 'udp'
\toption dest_port '68'
\toption target 'ACCEPT'
\toption family 'ipv4'

config rule
\toption name 'Allow-Ping'
\toption src 'wan'
\toption proto 'icmp'
\toption icmp_type 'echo-request'
\toption family 'ipv4'
\toption target 'ACCEPT'

config rule
\toption name 'Allow-IoT-HTTPS'
\toption src 'lan'
\toption dest 'wan'
\toption proto 'tcp'
\toption dest_port '443'
\toption target 'ACCEPT'
"""

DHCP = """\
config dnsmasq
\toption domainneeded '1'
\toption localise_queries '1'
\toption local '/lan/'
\toption domain 'lan'
\tlist server '1.1.1.1'
\tlist server '9.9.9.9'

config dhcp 'lan'
\toption interface 'lan'
\toption start '100'
\toption limit '150'
\toption leasetime '12h'

config dhcp 'wan'
\toption interface 'wan'
\toption ignore '1'

config host
\toption name 'nas'
\toption mac '00:11:22:33:44:55'
\toption ip '192.168.1.20'
"""

SYSTEM = """\
config system
\toption hostname 'OpenWrt'
\toption timezone 'CET-1CEST,M3.5.0,M10.5.0/3'
\toption zonename 'Europe/Berlin'
\toption log_size '128'
"""

DROPBEAR = """\
config dropbear
\toption PasswordAuth 'on'
\toption RootPasswordAuth 'on'
\toption Port '22'
"""

BASE = {
    "network": NETWORK,
    "wireless": WIRELESS,
    "firewall": FIREWALL,
    "dhcp": DHCP,
    "system": SYSTEM,
    "dropbear": DROPBEAR,
}
CONFIGS = tuple(BASE)


def sub(text: str, old: str, new: str, count: int = 1) -> str:
    """Replace exactly ``count`` occurrences, failing loudly on a typo."""
    assert text.count(old) >= count, old
    return text.replace(old, new, count)


def snap(**texts: str | None) -> UciSnapshot:
    """Snapshot of BASE with some configs replaced (None = not readable)."""
    merged: dict[str, str | None] = {**BASE, **texts}
    raw = {
        name: (parse_uci_file(text) if text is not None else None)
        for name, text in merged.items()
    }
    return build_snapshot(raw, DIGEST, configs=CONFIGS)


def only(changes: tuple[Change, ...]) -> Change:
    assert len(changes) == 1, changes
    return changes[0]


def dump(obj: Any) -> str:
    return json.dumps(obj, default=str, sort_keys=True)


# ---------------------------------------------------------------------------
# Enums and classification
# ---------------------------------------------------------------------------


def test_area_and_risk_enums_carry_const_values() -> None:
    assert [a.value for a in Area] == list(AREAS)
    assert [r.value for r in Risk] == list(RISKS)
    assert Area.MGMT_IP == "mgmt_ip"
    assert Risk.CRITICAL == "critical"


def test_classify_static_table() -> None:
    assert classify("system", "system", "hostname", mgmt_host=None) == (
        Area.SYSTEM,
        Risk.LOW,
    )
    assert classify("wireless", "wifi-device", "channel", mgmt_host=None) == (
        Area.WLAN,
        Risk.MEDIUM,
    )
    assert classify("dhcp", "host", None, mgmt_host=None) == (Area.DHCP, Risk.MEDIUM)
    assert classify("unknownpkg", "foo", "bar", mgmt_host=None) == (
        Area.OTHER,
        Risk.MEDIUM,
    )


def test_classify_value_dependent_upgrades() -> None:
    lan = {"device": "br-lan", "proto": "static", "ipaddr": "192.168.1.1/24"}
    assert classify(
        "network",
        "interface",
        "ipaddr",
        mgmt_host=MGMT,
        section_name="lan",
        section_options=(lan,),
    ) == (Area.MGMT_IP, Risk.CRITICAL)
    # Without the management host it could be the management interface
    # (review M3): critical, but not attributed to MGMT_IP.
    assert classify(
        "network",
        "interface",
        "ipaddr",
        mgmt_host=None,
        section_name="lan",
        section_options=(lan,),
    ) == (Area.INTERFACE, Risk.CRITICAL)
    # Management interface known elsewhere: a plain interface change.
    assert classify(
        "network",
        "interface",
        "ipaddr",
        mgmt_host=None,
        section_name="lan",
        section_options=(lan,),
        mgmt_known=True,
    ) == (Area.INTERFACE, Risk.HIGH)
    # Uplink by protocol on a custom name.
    assert classify(
        "network",
        "interface",
        "username",
        mgmt_host=None,
        section_name="dsl",
        section_options=({"proto": "pppoe"},),
    ) == (Area.INTERFACE, Risk.CRITICAL)
    # Firewall rule acting on input (no dest) vs. forward rule.
    assert classify(
        "firewall",
        "rule",
        "target",
        mgmt_host=None,
        section_options=({"src": "wan", "proto": "icmp"},),
    ) == (Area.FIREWALL, Risk.CRITICAL)
    assert classify(
        "firewall",
        "rule",
        "dest_port",
        mgmt_host=None,
        section_options=({"src": "lan", "dest": "wan", "dest_port": "443"},),
    ) == (Area.FIREWALL, Risk.HIGH)
    # SSH port in a forward rule range.
    assert classify(
        "firewall",
        "rule",
        "dest_port",
        mgmt_host=None,
        section_options=({"src": "lan", "dest": "wan", "dest_port": "20-25"},),
    ) == (Area.SSH, Risk.CRITICAL)


# ---------------------------------------------------------------------------
# Identity and nothing-changed
# ---------------------------------------------------------------------------


def test_identical_snapshots_give_no_diff_and_no_drift() -> None:
    old, new = snap(), snap()
    assert old.content_hash == new.content_hash
    assert diff_snapshots(old, new, mgmt_host=MGMT) == ()
    report = evaluate_drift(old, new, (), mgmt_host=MGMT)
    assert report.state == "none"
    assert report.drift_id is None
    assert report.changes == ()
    assert report.is_drift is False
    assert report.rebaseline is False
    assert report.highest_risk is None
    assert report.critical_count == 0


# ---------------------------------------------------------------------------
# Plan 16 case 7: WLAN
# ---------------------------------------------------------------------------


def test_channel_6_to_11_is_wlan_medium() -> None:
    new = snap(wireless=sub(WIRELESS, "option channel '6'", "option channel '11'"))
    change = only(diff_snapshots(snap(), new, mgmt_host=MGMT))
    assert (change.kind, change.config, change.section, change.option) == (
        "changed",
        "wireless",
        "radio0",
        "channel",
    )
    assert (change.old, change.new) == ("6", "11")
    assert (change.area, change.risk) == (Area.WLAN, Risk.MEDIUM)
    assert change.section_type == "wifi-device"


def test_wlan_ssid_change_is_wlan_high() -> None:
    new = snap(
        wireless=sub(
            WIRELESS,
            "option ssid 'HomeNet'\n\toption encryption 'sae-mixed'\n"
            f"\toption key '{WLAN_KEY}'\n\nconfig wifi-iface 'default_radio1'",
            "option ssid 'HomeNet-2G'\n\toption encryption 'sae-mixed'\n"
            f"\toption key '{WLAN_KEY}'\n\nconfig wifi-iface 'default_radio1'",
        )
    )
    change = only(diff_snapshots(snap(), new, mgmt_host=MGMT))
    assert (change.kind, change.section, change.option) == (
        "changed",
        "default_radio0",
        "ssid",
    )
    assert (change.old, change.new) == ("HomeNet", "HomeNet-2G")
    assert (change.area, change.risk) == (Area.WLAN, Risk.HIGH)


def test_wlan_ssid_change_on_anonymous_iface_is_paired_not_removed_added() -> None:
    """The SSID is part of the anonymous section key; still one section."""
    new = snap(wireless=sub(WIRELESS, "option ssid 'Gast'", "option ssid 'Gast-2'"))
    changes = diff_snapshots(snap(), new, mgmt_host=MGMT)
    assert {c.kind for c in changes} == {"changed"}
    ssid = next(c for c in changes if c.option == "ssid")
    assert (ssid.old, ssid.new) == ("Gast", "Gast-2")
    assert ssid.old_section is not None and "Gast" in ssid.old_section
    assert "Gast-2" in ssid.section
    # The key digest does not depend on the section key: same key, no change.
    assert [c.option for c in changes] == ["ssid"]


def test_wlan_ssid_and_key_change_on_anonymous_iface_reports_secret() -> None:
    new_text = sub(
        sub(WIRELESS, "option ssid 'Gast'", "option ssid 'Gast-2'"),
        f"option key '{GUEST_KEY}'",
        "option key 'NewWlanSecret#2027'",
    )
    changes = diff_snapshots(snap(), snap(wireless=new_text), mgmt_host=MGMT)
    assert sorted(c.option or "" for c in changes) == ["key", "ssid"]
    key = next(c for c in changes if c.option == "key")
    assert (key.kind, key.detail) == ("changed", cd.DETAIL_SECRET_CHANGED)
    assert key.old_section is not None and "Gast" in key.old_section
    assert "Gast-2" in key.section
    assert (key.area, key.risk) == (Area.WLAN, Risk.HIGH)
    assert set(key.old) == {SECRET_MARKER_KEY}
    assert set(key.new) == {SECRET_MARKER_KEY}
    assert key.old != key.new
    text = repr(changes) + dump([c.old for c in changes] + [c.new for c in changes])
    for secret in PLAINTEXT:
        assert secret not in text
    assert mask_for_output(key)["new"] == MASK_PLACEHOLDER


def test_secret_comparison_has_no_unverifiable_case() -> None:
    """Paired sections always share config and type, so digests compare."""
    assert not hasattr(cd, "DETAIL_SECRET_UNVERIFIABLE")
    assert "DETAIL_SECRET_UNVERIFIABLE" not in cd.__all__


def test_reordered_secret_list_in_rekeyed_section_is_reordered() -> None:
    base = sub(
        WIRELESS,
        "\toption isolate '1'\n",
        "\toption isolate '1'\n\tlist r0kh 'aa,*,KeyA'\n\tlist r0kh 'bb,*,KeyB'\n",
    )
    new_text = sub(
        sub(base, "option ssid 'Gast'", "option ssid 'Gast-2'"),
        "\tlist r0kh 'aa,*,KeyA'\n\tlist r0kh 'bb,*,KeyB'\n",
        "\tlist r0kh 'bb,*,KeyB'\n\tlist r0kh 'aa,*,KeyA'\n",
    )
    changes = diff_snapshots(
        snap(wireless=base), snap(wireless=new_text), mgmt_host=MGMT
    )
    by_option = {c.option: c for c in changes}
    assert set(by_option) == {"ssid", "r0kh"}
    assert by_option["r0kh"].kind == "reordered"
    assert by_option["r0kh"].detail is None
    assert "KeyA" not in repr(changes)


def test_wlan_key_change_detected_via_digest_without_plaintext() -> None:
    new_text = sub(
        WIRELESS, f"option key '{WLAN_KEY}'", "option key 'NewWlanSecret#2027'"
    )
    change = only(diff_snapshots(snap(), snap(wireless=new_text), mgmt_host=MGMT))
    assert (change.kind, change.section, change.option) == (
        "changed",
        "default_radio0",
        "key",
    )
    assert change.detail == cd.DETAIL_SECRET_CHANGED
    assert change.risk == Risk.HIGH and change.area == Area.WLAN
    # Only digest markers, never the plaintext.
    assert set(change.old) == {SECRET_MARKER_KEY}
    assert set(change.new) == {SECRET_MARKER_KEY}
    assert change.old != change.new
    text = repr(change) + dump(change.old) + dump(change.new)
    for secret in PLAINTEXT:
        assert secret not in text
    masked = mask_for_output(change)
    assert masked["old"] == MASK_PLACEHOLDER
    assert masked["new"] == MASK_PLACEHOLDER


# ---------------------------------------------------------------------------
# Plan 16 case 8: VLAN
# ---------------------------------------------------------------------------


def test_bridge_vlan_change_is_critical() -> None:
    new = snap(network=sub(NETWORK, "\tlist ports 'lan3:t'\n", "\tlist ports 'lan3'\n"))
    change = only(diff_snapshots(snap(), new, mgmt_host=MGMT))
    assert change.section == '@bridge-vlan{"device":"br-lan","vlan":"10"}'
    assert (change.option, change.old, change.new) == ("ports", "lan3:t", "lan3")
    assert (change.area, change.risk) == (Area.VLAN, Risk.CRITICAL)


def test_switch_vlan_change_is_critical() -> None:
    new_text = sub(
        NETWORK_SWCONFIG, "option ports '1 2 3 4 0t'", "option ports '1 2 3 0t'"
    )
    change = only(
        diff_snapshots(
            snap(network=NETWORK_SWCONFIG), snap(network=new_text), mgmt_host=MGMT
        )
    )
    assert change.section_type == "switch_vlan"
    assert (change.old, change.new) == ("1 2 3 4 0t", "1 2 3 0t")
    assert (change.area, change.risk) == (Area.VLAN, Risk.CRITICAL)


# ---------------------------------------------------------------------------
# Plan 16 case 9: firewall
# ---------------------------------------------------------------------------


def test_firewall_zone_input_policy_is_critical() -> None:
    new = snap(
        firewall=sub(
            FIREWALL,
            "list network 'wan6'\n\toption input 'REJECT'",
            "list network 'wan6'\n\toption input 'ACCEPT'",
        )
    )
    change = only(diff_snapshots(snap(), new, mgmt_host=MGMT))
    assert change.section == '@zone{"name":"wan"}'
    assert (change.option, change.old, change.new) == ("input", "REJECT", "ACCEPT")
    assert (change.area, change.risk) == (Area.FIREWALL, Risk.CRITICAL)


def _swap_rules(text: str) -> str:
    renew = text[text.index("config rule\n\toption name 'Allow-DHCP-Renew'") :]
    renew = renew[: renew.index("config rule\n\toption name 'Allow-Ping'")]
    ping = text[text.index("config rule\n\toption name 'Allow-Ping'") :]
    ping = ping[: ping.index("config rule\n\toption name 'Allow-IoT-HTTPS'")]
    return text.replace(renew + ping, ping + renew)


def test_reordered_rules_matched_by_name() -> None:
    swapped = _swap_rules(FIREWALL)
    assert swapped != FIREWALL
    changes = diff_snapshots(snap(), snap(firewall=swapped), mgmt_host=MGMT)
    assert changes, "a pure reordering must still be reported"
    assert {c.kind for c in changes} == {"reordered"}
    for change in changes:
        assert change.config == "firewall"
        assert change.option is None
        assert change.section in (
            '@rule{"name":"Allow-DHCP-Renew"}',
            '@rule{"name":"Allow-Ping"}',
        )
        # Rule order decides which rule matches: at least high.
        assert change.risk in (Risk.HIGH, Risk.CRITICAL)
        assert change.area == Area.FIREWALL


def test_reordering_where_order_has_no_effect_is_low() -> None:
    r0 = WIRELESS[: WIRELESS.index("config wifi-device 'radio1'")]
    r1 = WIRELESS[
        WIRELESS.index("config wifi-device 'radio1'") : WIRELESS.index(
            "config wifi-iface 'default_radio0'"
        )
    ]
    swapped = WIRELESS.replace(r0 + r1, r1 + r0)
    changes = diff_snapshots(snap(), snap(wireless=swapped), mgmt_host=MGMT)
    assert changes
    assert {(c.kind, c.risk, c.area) for c in changes} == {
        ("reordered", Risk.LOW, Area.WLAN)
    }


def test_list_value_reorder_is_reordered_low() -> None:
    new = snap(
        dhcp=sub(
            DHCP,
            "\tlist server '1.1.1.1'\n\tlist server '9.9.9.9'\n",
            "\tlist server '9.9.9.9'\n\tlist server '1.1.1.1'\n",
        )
    )
    change = only(diff_snapshots(snap(), new, mgmt_host=MGMT))
    assert (change.kind, change.option) == ("reordered", "server")
    assert change.risk == Risk.LOW
    assert change.old == ["1.1.1.1", "9.9.9.9"]
    assert change.new == ["9.9.9.9", "1.1.1.1"]


def test_ssh_port_rule_is_critical_and_forward_rule_is_high() -> None:
    ssh_rule = (
        "\nconfig rule\n\toption name 'Allow-SSH-WAN'\n\toption src 'wan'\n"
        "\toption proto 'tcp'\n\toption dest_port '22'\n\toption target 'ACCEPT'\n"
    )
    added = only(
        diff_snapshots(snap(), snap(firewall=FIREWALL + ssh_rule), mgmt_host=MGMT)
    )
    assert (added.kind, added.option) == ("added", None)
    assert (added.area, added.risk) == (Area.SSH, Risk.CRITICAL)
    assert added.new["options"]["dest_port"] == "22"

    fwd = only(
        diff_snapshots(
            snap(),
            snap(
                firewall=sub(
                    FIREWALL, "option dest_port '443'", "option dest_port '8443'"
                )
            ),
            mgmt_host=MGMT,
        )
    )
    assert (fwd.area, fwd.risk) == (Area.FIREWALL, Risk.HIGH)


# ---------------------------------------------------------------------------
# Management access
# ---------------------------------------------------------------------------


def test_mgmt_ip_change_is_critical() -> None:
    new = snap(
        network=sub(
            NETWORK, "option ipaddr '192.168.1.1'", "option ipaddr '192.168.2.1'"
        )
    )
    change = only(diff_snapshots(snap(), new, mgmt_host=MGMT))
    assert (change.section, change.option) == ("lan", "ipaddr")
    assert (change.area, change.risk) == (Area.MGMT_IP, Risk.CRITICAL)
    # Unknown management host: it could be this interface (review M3).
    plain = only(diff_snapshots(snap(), new, mgmt_host=None))
    assert (plain.area, plain.risk) == (Area.INTERFACE, Risk.CRITICAL)
    # A different interface than the one HA talks to stays high.
    iot = only(
        diff_snapshots(
            snap(),
            snap(network=sub(NETWORK, "'192.168.10.1'", "'192.168.11.1'")),
            mgmt_host=MGMT,
        )
    )
    assert (iot.section, iot.area, iot.risk) == ("iot", Area.INTERFACE, Risk.HIGH)


def test_mgmt_ip_in_cidr_list_is_recognised() -> None:
    old_net = sub(
        NETWORK,
        "\toption ipaddr '192.168.1.1'\n",
        "\tlist ipaddr '192.168.1.1/24'\n\tlist ipaddr '10.0.0.1/24'\n",
    )
    new_net = sub(old_net, "option ip6assign '60'", "option ip6assign '64'")
    change = only(
        diff_snapshots(snap(network=old_net), snap(network=new_net), mgmt_host=MGMT)
    )
    # ip6assign is not a management option: interface/high, not mgmt.
    assert (change.area, change.risk) == (Area.INTERFACE, Risk.HIGH)
    netmask = only(
        diff_snapshots(
            snap(network=old_net),
            snap(network=sub(old_net, "'10.0.0.1/24'", "'10.0.1.1/24'")),
            mgmt_host=MGMT,
        )
    )
    assert (netmask.area, netmask.risk) == (Area.MGMT_IP, Risk.CRITICAL)


def test_uplink_change_is_critical() -> None:
    new = snap(
        network=sub(
            NETWORK,
            "config interface 'wan'\n\toption device 'wan'\n\toption proto 'dhcp'",
            "config interface 'wan'\n\toption device 'wan'\n\toption proto 'pppoe'",
        )
    )
    change = only(diff_snapshots(snap(), new, mgmt_host=MGMT))
    assert (change.section, change.option) == ("wan", "proto")
    assert change.risk == Risk.CRITICAL


def test_dropbear_password_auth_off_is_visible_and_critical() -> None:
    new = snap(
        dropbear=sub(
            DROPBEAR,
            "PasswordAuth 'on'\n\toption Root",
            "PasswordAuth 'off'\n\toption Root",
        )
    )
    change = only(diff_snapshots(snap(), new, mgmt_host=MGMT))
    assert (change.option, change.old, change.new) == ("PasswordAuth", "on", "off")
    assert (change.area, change.risk) == (Area.SSH, Risk.CRITICAL)
    assert change.detail is None
    masked = mask_for_output(change)
    assert (masked["old"], masked["new"]) == ("on", "off")


# ---------------------------------------------------------------------------
# Sections added/removed, anonymous pairing
# ---------------------------------------------------------------------------


def test_section_added_and_removed() -> None:
    host = (
        "\nconfig host\n\toption name 'printer'\n"
        "\toption mac 'AA:BB:CC:DD:EE:FF'\n\toption ip '192.168.1.30'\n"
    )
    added = only(diff_snapshots(snap(), snap(dhcp=DHCP + host), mgmt_host=MGMT))
    assert (added.kind, added.option, added.old) == ("added", None, None)
    assert added.section == '@host{"mac":"AA:BB:CC:DD:EE:FF"}'
    assert (added.area, added.risk) == (Area.DHCP, Risk.MEDIUM)
    assert added.new == {
        "type": "host",
        "options": {
            "ip": "192.168.1.30",
            "mac": "AA:BB:CC:DD:EE:FF",
            "name": "printer",
        },
    }
    removed = only(diff_snapshots(snap(dhcp=DHCP + host), snap(), mgmt_host=MGMT))
    assert (removed.kind, removed.new) == ("removed", None)
    assert removed.old == added.new


_UNNAMED = """\
config rule
\toption src 'lan'
\toption dest 'wan'
\toption proto 'tcp'
\toption dest_port '25'
\toption target 'REJECT'

config rule
\toption src 'lan'
\toption dest 'wan'
\toption proto 'udp'
\toption dest_port '123'
\toption target 'ACCEPT'

config rule
\toption src 'lan'
\toption dest 'wan'
\toption proto 'tcp'
\toption dest_port '8080'
\toption target 'ACCEPT'
"""


def test_anonymous_sections_without_identity_paired_by_position() -> None:
    base = FIREWALL + "\n" + _UNNAMED
    # One option changed: one "changed", not "removed + added".
    changed = only(
        diff_snapshots(
            snap(firewall=base),
            snap(
                firewall=sub(base, "option dest_port '123'", "option dest_port '124'")
            ),
            mgmt_host=MGMT,
        )
    )
    assert (changed.kind, changed.section, changed.option) == (
        "changed",
        "@rule[1]",
        "dest_port",
    )
    # First unnamed rule deleted: one removal, the others are not "changed".
    first = _UNNAMED[: _UNNAMED.index("config rule", 5)]
    removed = only(
        diff_snapshots(
            snap(firewall=base),
            snap(firewall=base.replace(first, "")),
            mgmt_host=MGMT,
        )
    )
    assert removed.kind == "removed"
    assert removed.old["options"]["dest_port"] == "25"


def test_anonymous_section_gaining_a_name_is_paired() -> None:
    base = FIREWALL + "\n" + _UNNAMED
    named = sub(
        base,
        "config rule\n\toption src 'lan'\n\toption dest 'wan'\n\toption proto 'udp'",
        "config rule\n\toption name 'Allow-NTP'\n\toption src 'lan'\n"
        "\toption dest 'wan'\n\toption proto 'udp'",
    )
    change = only(
        diff_snapshots(snap(firewall=base), snap(firewall=named), mgmt_host=MGMT)
    )
    assert (change.kind, change.option, change.new) == ("added", "name", "Allow-NTP")
    assert change.section == '@rule{"name":"Allow-NTP"}'
    assert change.old_section == "@rule[1]"


# ---------------------------------------------------------------------------
# Not comparable configs
# ---------------------------------------------------------------------------


def test_missing_config_is_not_comparable_not_removed() -> None:
    old, new = snap(), snap(dropbear=None)
    assert "dropbear" in new.missing
    assert diff_snapshots(old, new, mgmt_host=MGMT) == ()
    assert not_comparable(old, new) == ("dropbear",)
    assert not_comparable(new, old) == ("dropbear",)
    report = evaluate_drift(old, new, (), mgmt_host=MGMT)
    # Review M2: a config that cannot be compared is never "no drift".
    assert report.state == "unknown"
    assert report.not_comparable == ("dropbear",)


def test_not_comparable_config_is_unknown_not_clean() -> None:
    """Review M2: unreadable configs make a visible state of their own."""
    old, new = snap(), snap(firewall=None)
    report = evaluate_drift(old, new, (), mgmt_host=MGMT)
    assert report.state == "unknown"
    assert report.degraded and report.is_drift and report.notify
    assert not report.rebaseline
    assert report.changes == ()
    assert report.drift_id == drift_id(
        (), new.content_hash, not_comparable=("firewall",)
    )
    # Acknowledging it is possible; "known" never rebuilds the baseline
    # from a view that misses configs.
    at = datetime(2026, 11, 17, tzinfo=UTC)
    did = report.drift_id
    assert did is not None
    seen = evaluate_drift(
        old, new, [DriftAck(did, "acknowledged", "a", at)], mgmt_host=MGMT
    )
    assert seen.state == "acknowledged" and not seen.notify
    known = evaluate_drift(old, new, [DriftAck(did, "known", "a", at)], mgmt_host=MGMT)
    assert known.state == "acknowledged" and not known.rebaseline


def test_changes_plus_unreadable_config_never_rebaseline() -> None:
    baseline, current = _drifted()
    current = snap(
        wireless=sub(WIRELESS, "option channel '6'", "option channel '11'"),
        firewall=None,
    )
    report = evaluate_drift(baseline, current, (), mgmt_host=MGMT)
    assert report.state == "new" and report.degraded
    did = report.drift_id
    assert did is not None
    ack = DriftAck(did, "known", "a", datetime(2026, 11, 17, tzinfo=UTC))
    known = evaluate_drift(baseline, current, [ack], mgmt_host=MGMT)
    assert known.state == "acknowledged" and not known.rebaseline


def test_drift_id_without_not_comparable_is_unchanged() -> None:
    baseline, current = _drifted()
    changes = diff_snapshots(baseline, current, mgmt_host=MGMT)
    plain = drift_id(changes, current.content_hash)
    assert plain == drift_id(changes, current.content_hash, not_comparable=())
    assert plain != drift_id(changes, current.content_hash, not_comparable=("sqm",))


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------


def _drifted() -> tuple[UciSnapshot, UciSnapshot]:
    return snap(), snap(
        wireless=sub(WIRELESS, "option channel '6'", "option channel '11'"),
        network=sub(
            NETWORK, "option ipaddr '192.168.1.1'", "option ipaddr '192.168.1.2'"
        ),
    )


def test_new_drift_is_reported() -> None:
    baseline, current = _drifted()
    report = evaluate_drift(baseline, current, (), mgmt_host=MGMT)
    assert report.state == "new"
    assert report.is_drift and report.notify and not report.rebaseline
    assert report.drift_id == drift_id(report.changes, current.content_hash)
    assert report.baseline_hash == baseline.content_hash
    assert report.current_hash == current.content_hash
    assert report.highest_risk == Risk.CRITICAL
    assert report.critical_count == 1
    assert report.ack is None


def test_known_ack_makes_drift_new_baseline() -> None:
    baseline, current = _drifted()
    did = evaluate_drift(baseline, current, (), mgmt_host=MGMT).drift_id
    assert did is not None
    ack = DriftAck(did, "known", "admin", datetime(2026, 11, 17, 9, 0, tzinfo=UTC))
    report = evaluate_drift(baseline, current, [ack], mgmt_host=MGMT)
    assert report.state == "known"
    assert report.rebaseline is True
    assert report.is_drift is False
    assert report.notify is False
    assert report.ack == ack
    # Nothing was reset: the changes are still listed.
    assert len(report.changes) == 2


def test_acknowledged_keeps_old_baseline() -> None:
    baseline, current = _drifted()
    did = evaluate_drift(baseline, current, (), mgmt_host=MGMT).drift_id
    assert did is not None
    ack = DriftAck(did, "acknowledged", "admin", datetime(2026, 11, 17, tzinfo=UTC))
    report = evaluate_drift(baseline, current, [ack], mgmt_host=MGMT)
    assert report.state == "acknowledged"
    assert report.is_drift is True
    assert report.notify is False
    assert report.rebaseline is False


def test_ack_for_other_drift_does_not_apply_and_latest_ack_wins() -> None:
    baseline, current = _drifted()
    did = evaluate_drift(baseline, current, (), mgmt_host=MGMT).drift_id
    assert did is not None
    other = DriftAck("0" * 32, "known", "admin", datetime(2026, 11, 17, tzinfo=UTC))
    assert evaluate_drift(baseline, current, [other], mgmt_host=MGMT).state == "new"
    early = DriftAck(did, "known", "a", datetime(2026, 11, 16, tzinfo=UTC))
    late = DriftAck(did, "acknowledged", "b", datetime(2026, 11, 17, tzinfo=UTC))
    report = evaluate_drift(baseline, current, [late, early], mgmt_host=MGMT)
    assert report.state == "acknowledged"
    assert report.ack == late


def test_drift_ack_rejects_unknown_state() -> None:
    with pytest.raises(ValueError):
        DriftAck("x", "ignored", "admin", datetime(2026, 11, 17, tzinfo=UTC))  # type: ignore[arg-type]


def test_drift_id_is_order_independent_and_bound_to_content() -> None:
    baseline, current = _drifted()
    changes = diff_snapshots(baseline, current, mgmt_host=MGMT)
    assert len(changes) == 2
    a = drift_id(changes, current.content_hash)
    assert a == drift_id(tuple(reversed(changes)), current.content_hash)
    assert a != drift_id(changes, baseline.content_hash)
    assert a != drift_id(changes[:1], current.content_hash)
    # Area/risk depend on mgmt_host and must not change the id.
    assert a == drift_id(
        diff_snapshots(baseline, current, mgmt_host=None), current.content_hash
    )
    # 64 hex: a 32-hex id would be masked by redact_text as a session token.
    assert len(a) == 64 and int(a, 16) >= 0


# ---------------------------------------------------------------------------
# Masking of the result objects
# ---------------------------------------------------------------------------


def test_mask_for_output_of_changes_and_report_has_no_plaintext() -> None:
    baseline = snap()
    current = snap(
        wireless=sub(
            sub(
                WIRELESS, f"option key '{WLAN_KEY}'", "option key 'NewWlanSecret#2027'"
            ),
            "option ssid 'Gast'",
            "option ssid 'Gast-2'",
        )
    )
    report = evaluate_drift(baseline, current, (), mgmt_host=MGMT)
    assert isinstance(report, DriftReport)
    digests = [
        c.new[SECRET_MARKER_KEY]
        for c in report.changes
        if isinstance(c.new, dict) and SECRET_MARKER_KEY in c.new
    ]
    assert digests
    for payload in (mask_for_output(report), mask_for_output(list(report.changes))):
        text = dump(payload)
        for secret in PLAINTEXT:
            assert secret not in text
        for digest in digests:
            assert digest not in text
        assert MASK_PLACEHOLDER in text
    # Nothing of the plaintext is in the unmasked objects either.
    raw = repr(report)
    for secret in PLAINTEXT:
        assert secret not in raw


def test_change_is_frozen() -> None:
    change = only(
        diff_snapshots(
            snap(),
            snap(wireless=sub(WIRELESS, "option channel '6'", "option channel '11'")),
            mgmt_host=MGMT,
        )
    )
    with pytest.raises(AttributeError):
        change.risk = Risk.LOW  # type: ignore[misc]


def test_diff_module_is_pure() -> None:
    tree = ast.parse(Path(cd.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(("." * node.level) + (node.module or ""))
    assert not any(name.startswith("homeassistant") for name in imported)
    assert ".api" not in imported
    assert not imported & {"aiohttp", "asyncssh", "socket", "subprocess", "os"}


# ---------------------------------------------------------------------------
# Security review M3: changes that can lock HA out are critical
# ---------------------------------------------------------------------------

LAN_ZONE = """\
config zone
\toption name 'lan'
\tlist network 'lan'
\tlist network 'iot'
\toption input 'ACCEPT'
\toption output 'ACCEPT'
\toption forward 'ACCEPT'

"""

BR_LAN = """\
config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'lan1'
\tlist ports 'lan2'
\tlist ports 'lan3'

"""

LAN_STATIC = """\
config interface 'lan'
\toption device 'br-lan.1'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
\toption netmask '255.255.255.0'
\toption ip6assign '60'
"""

LAN_DHCP = """\
config interface 'lan'
\toption device 'br-lan.1'
\toption proto 'dhcp'
"""

UHTTPD = """\
config uhttpd 'main'
\tlist listen_http '0.0.0.0:8080'
\tlist listen_https '0.0.0.0:8443'
\toption home '/www'
"""

RPCD = """\
config rpcd
\toption socket '/var/run/ubus/ubus.sock'
\toption timeout '30'

config login
\toption username 'root'
\toption password '$p$root'
\tlist read '*'
\tlist write '*'
"""


def snap_all(**texts: str | None) -> UciSnapshot:
    """Like ``snap``, plus uhttpd and rpcd."""
    merged: dict[str, str | None] = {
        **BASE,
        "uhttpd": UHTTPD,
        "rpcd": RPCD,
        **texts,
    }
    raw = {
        name: (parse_uci_file(text) if text is not None else None)
        for name, text in merged.items()
    }
    return build_snapshot(raw, DIGEST, configs=tuple(merged))


def risks(
    old: UciSnapshot, new: UciSnapshot, mgmt_host: str | None = MGMT
) -> dict[tuple[str, str, str | None], Risk]:
    return {
        (c.config, c.section, c.option): c.risk
        for c in diff_snapshots(old, new, mgmt_host=mgmt_host)
    }


def all_critical(found: dict[tuple[str, str, str | None], Risk]) -> None:
    assert found, "expected changes"
    assert set(found.values()) == {Risk.CRITICAL}, found


def test_removed_lan_zone_is_critical() -> None:
    all_critical(risks(snap(), snap(firewall=sub(FIREWALL, LAN_ZONE, ""))))


def test_removed_bridge_device_is_critical() -> None:
    all_critical(risks(snap(), snap(network=sub(NETWORK, BR_LAN, ""))))


def test_added_interface_is_critical() -> None:
    extra = "\nconfig interface 'mgmt'\n\toption device 'br-lan.20'\n"
    all_critical(risks(snap(), snap(network=NETWORK + extra)))


def test_new_zone_with_input_reject_on_lan_is_critical() -> None:
    zone = (
        "\nconfig zone\n\toption name 'lockdown'\n\tlist network 'lan'\n"
        "\toption input 'REJECT'\n"
    )
    all_critical(risks(snap(), snap(firewall=FIREWALL + zone)))


def test_mgmt_device_change_with_dhcp_lan_is_critical() -> None:
    old_net = sub(NETWORK, LAN_STATIC, LAN_DHCP)
    new_net = sub(old_net, "option device 'br-lan.1'", "option device 'br-lan.10'")
    found = risks(snap(network=old_net), snap(network=new_net), "192.168.1.50")
    all_critical(found)


def test_ipaddr_change_with_hostname_mgmt_is_critical() -> None:
    new_net = sub(NETWORK, "option ipaddr '192.168.1.1'", "option ipaddr '10.0.0.1'")
    all_critical(risks(snap(), snap(network=new_net), "router.lan"))


def test_proto_change_without_known_mgmt_is_critical() -> None:
    new_net = sub(NETWORK, "option ipaddr '192.168.10.1'", "option ipaddr '10.1.0.1'")
    # The management IP is on no interface: every address change counts.
    all_critical(risks(snap(), snap(network=new_net), "192.168.99.9"))
    # With the management interface known, other interfaces stay high.
    found = risks(snap(), snap(network=new_net), MGMT)
    assert found == {("network", "iot", "ipaddr"): Risk.HIGH}


def test_ip6addr_change_with_ipv6_mgmt_is_critical() -> None:
    with_v6 = sub(
        NETWORK,
        "option ip6assign '60'",
        "option ip6assign '60'\n\toption ip6addr 'fd12:3456:789a::1/64'",
    )
    new_net = sub(with_v6, "fd12:3456:789a::1/64", "fd12:3456:789a::2/64")
    all_critical(
        risks(snap(network=with_v6), snap(network=new_net), "fd12:3456:789a::1")
    )
    # Address from the delegated prefix only: ip6assign decides it.
    new_assign = sub(NETWORK, "option ip6assign '60'", "option ip6assign '64'")
    all_critical(risks(snap(), snap(network=new_assign), "fd12:3456:789a:1::1"))


@pytest.mark.parametrize("port", ["80", "443", "8080", "8443"])
def test_redirect_to_web_management_port_is_critical(port: str) -> None:
    redirect = (
        "\nconfig redirect\n\toption name 'Expose'\n\toption src 'wan'\n"
        f"\toption src_dport '{port}'\n\toption dest 'lan'\n"
        f"\toption dest_ip '192.168.1.1'\n\toption dest_port '{port}'\n"
        "\toption target 'DNAT'\n"
    )
    all_critical(risks(snap_all(), snap_all(firewall=FIREWALL + redirect)))


def test_forward_rule_on_443_stays_high() -> None:
    """Outbound HTTPS from a LAN zone is no management access."""
    new_fw = sub(FIREWALL, "option dest_port '443'", "option dest_port '443 8443'")
    found = risks(snap_all(), snap_all(firewall=new_fw))
    assert set(found.values()) == {Risk.HIGH}


def test_uhttpd_listen_change_is_critical() -> None:
    new = sub(UHTTPD, "0.0.0.0:8080", "127.0.0.1:8080")
    all_critical(risks(snap_all(), snap_all(uhttpd=new)))
    new = sub(UHTTPD, "0.0.0.0:8443", "0.0.0.0:9443")
    all_critical(risks(snap_all(), snap_all(uhttpd=new)))


def test_rpcd_login_change_is_critical() -> None:
    extra = "\nconfig login\n\toption username 'ha'\n\tlist read 'openwrt-ha'\n"
    all_critical(risks(snap_all(), snap_all(rpcd=RPCD + extra)))
    all_critical(risks(snap_all(), snap_all(rpcd=sub(RPCD, "list write '*'\n", ""))))


@pytest.mark.parametrize(
    ("option", "value"),
    [("Interface", "lan"), ("Port", "2222"), ("GatewayPorts", "on")],
)
def test_dropbear_access_options_are_critical(option: str, value: str) -> None:
    if option == "Port":
        new = sub(DROPBEAR, "option Port '22'", f"option Port '{value}'")
    else:
        new = DROPBEAR + f"\toption {option} '{value}'\n"
    all_critical(risks(snap(), snap(dropbear=new)))
