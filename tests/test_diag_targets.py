"""Tests for diag_targets.py: target allowlist, host validation, SSRF guard.

Pure logic: no network I/O, no Home Assistant instance. The autouse fixture
below makes any DNS lookup attempt fail loudly.
"""

from __future__ import annotations

import ast
import ipaddress
import logging
import socket
from pathlib import Path
from typing import Any

import pytest

from custom_components.openwrt_router.diag_targets import (
    MAX_RESOLVED_ADDRESSES,
    AddressClass,
    DiagTarget,
    Refusal,
    ScopePolicy,
    TargetKind,
    TargetRegistry,
    TargetScope,
    check_address,
    check_resolved,
    check_target,
    classify_ip,
    is_internal_name,
    make_target,
    may_query,
    normalize_host,
)

MODULE_PATH = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "openwrt_router"
    / "diag_targets.py"
)

EXT = TargetScope.EXTERNAL
INT = TargetScope.INTERNAL


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any resolver call during these tests is a bug."""

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("network I/O attempted")

    for name in (
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "create_connection",
    ):
        monkeypatch.setattr(socket, name, _boom)


def policy(**kw: Any) -> ScopePolicy:
    nets = kw.pop("networks", ["192.168.1.0/24", "10.0.0.0/8", "fd12:3456::/48"])
    return ScopePolicy.from_config(
        nets, local_domains=kw.pop("local_domains", ["corp.example.net"])
    )


def target(host: str, scope: TargetScope = EXT, **kw: Any) -> DiagTarget:
    made = make_target(
        kw.pop("target_id", "t1"),
        kw.pop("kind", TargetKind.ICMP),
        scope,
        host,
        port=kw.pop("port", None),
        confirmed=kw.pop("confirmed", True),
    )
    assert isinstance(made, DiagTarget), made
    return made


# --- named acceptance tests ---------------------------------------------------

INVALID_HOSTS: list[tuple[str, Refusal]] = [
    ("", Refusal.EMPTY_HOST),
    (
        "a" * 64 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63,
        Refusal.HOST_TOO_LONG,
    ),
    (" ", Refusal.BAD_CHARACTER),
    (" example.com", Refusal.BAD_CHARACTER),
    ("example.com ", Refusal.BAD_CHARACTER),
    ("host name", Refusal.BAD_CHARACTER),
    ("a\nb", Refusal.BAD_CHARACTER),
    ("a\tb", Refusal.BAD_CHARACTER),
    ("a\x00b", Refusal.BAD_CHARACTER),
    ("-oProxyCommand=x", Refusal.LEADING_DASH),
    ("-v", Refusal.LEADING_DASH),
    ("-1.2.3.4", Refusal.LEADING_DASH),
    ("a;b", Refusal.BAD_CHARACTER),
    ("a|b", Refusal.BAD_CHARACTER),
    ("a&b", Refusal.BAD_CHARACTER),
    ("$(id)", Refusal.BAD_CHARACTER),
    ("`id`", Refusal.BAD_CHARACTER),
    ("a>b", Refusal.BAD_CHARACTER),
    ("a'b", Refusal.BAD_CHARACTER),
    ('a"b', Refusal.BAD_CHARACTER),
    ("a*b", Refusal.BAD_CHARACTER),
    ("exa_mple.com", Refusal.BAD_CHARACTER),
    ("http://example.com", Refusal.URL_NOT_ALLOWED),
    ("https://example.com/x", Refusal.URL_NOT_ALLOWED),
    ("user@example.com", Refusal.URL_NOT_ALLOWED),
    ("user:pw@example.com", Refusal.URL_NOT_ALLOWED),
    ("example.com/path", Refusal.URL_NOT_ALLOWED),
    ("example.com?x=1", Refusal.URL_NOT_ALLOWED),
    ("example.com#x", Refusal.URL_NOT_ALLOWED),
    ("a\\b", Refusal.URL_NOT_ALLOWED),
    ("example.com:80", Refusal.PORT_IN_HOST),
    ("1.2.3.4:53", Refusal.PORT_IN_HOST),
    ("[::1]", Refusal.PORT_IN_HOST),
    ("[::1]:53", Refusal.PORT_IN_HOST),
    ("fe80::1%eth0", Refusal.BAD_CHARACTER),
    ("::ffff:zzzz", Refusal.BAD_CHARACTER),
    (":::1", Refusal.INVALID_IP),
    ("a..b", Refusal.EMPTY_LABEL),
    (".example.com", Refusal.EMPTY_LABEL),
    ("example.com.", Refusal.EMPTY_LABEL),
    ("a" * 64 + ".com", Refusal.LABEL_TOO_LONG),
    ("bad-.com", Refusal.BAD_LABEL),
    ("ab--cd.com", Refusal.BAD_LABEL),
    ("münchen.de", Refusal.NON_ASCII_HOST),
    ("ｅxample.com", Refusal.NON_ASCII_HOST),
    ("١٢٧.0.0.1", Refusal.NON_ASCII_HOST),
    ("xn--a.com", Refusal.BAD_PUNYCODE),
    ("xn--zz.com", Refusal.BAD_PUNYCODE),
    ("xn--abc-.com", Refusal.BAD_LABEL),  # would decode to plain ASCII "abc"
    ("xn--.com", Refusal.BAD_LABEL),
    ("0x7f.1", Refusal.NUMERIC_HOST),
    ("0x7f000001", Refusal.NUMERIC_HOST),
    ("127.1", Refusal.NUMERIC_HOST),
    ("2130706433", Refusal.NUMERIC_HOST),
    ("0177.0.0.1", Refusal.NUMERIC_HOST),
    ("127.0.0.01", Refusal.NUMERIC_HOST),
    ("1.2.3", Refusal.NUMERIC_HOST),
    ("1.2.3.4.5", Refusal.NUMERIC_HOST),
    ("256.1.1.1", Refusal.NUMERIC_HOST),
    ("foo.123", Refusal.NUMERIC_HOST),
    ("foo.0x10", Refusal.NUMERIC_HOST),
]


def test_case_22_invalid_test_targets() -> None:
    """Malformed hosts, ports, kinds and IDs are refused with a typed reason."""
    for raw, reason in INVALID_HOSTS:
        assert normalize_host(raw) is reason, raw
        made = make_target("t1", TargetKind.ICMP, EXT, raw, confirmed=True)
        assert made is reason, raw
    # Non-string host values
    for raw in (None, 1, b"example.com", ["example.com"]):
        assert normalize_host(raw) is Refusal.EMPTY_HOST
    # Port rules per kind
    assert make_target("t", TargetKind.TCP, EXT, "example.com") is Refusal.PORT_REQUIRED
    assert (
        make_target("t", TargetKind.ICMP, EXT, "example.com", port=7)
        is Refusal.INVALID_PORT
    )
    for port in (0, -1, 65536, True, 80.0, "80"):
        assert make_target("t", TargetKind.TCP, EXT, "example.com", port=port) is (
            Refusal.INVALID_PORT
        ), port
    # Unknown kind / scope / bad ids
    assert make_target("t", "smtp", EXT, "example.com") is Refusal.INVALID_KIND
    assert (
        make_target("t", TargetKind.ICMP, "dmz", "example.com") is Refusal.INVALID_SCOPE
    )
    for bad_id in ("", "T1", "../x", "a b", "8.8.8.8", "x" * 65, None, 5):
        assert (
            make_target(bad_id, TargetKind.ICMP, EXT, "example.com")
            is Refusal.INVALID_ID
        )
    # The dataclass itself never holds an unvalidated host or port
    with pytest.raises(ValueError) as err:
        DiagTarget("t1", TargetKind.ICMP, EXT, "8.8.8.8; rm -rf /")
    assert "rm -rf" not in str(err.value)
    with pytest.raises(ValueError):
        DiagTarget("t1", TargetKind.ICMP, EXT, "Example.COM")  # not normalised
    with pytest.raises(ValueError):
        DiagTarget("t1", TargetKind.TCP, EXT, "example.com")  # tcp needs a port


SSRF_EXTERNAL_HOSTS: list[tuple[str, Refusal]] = [
    ("127.0.0.1", Refusal.LOOPBACK),
    ("127.8.9.10", Refusal.LOOPBACK),
    ("::1", Refusal.LOOPBACK),
    ("::ffff:127.0.0.1", Refusal.LOOPBACK),
    ("::127.0.0.1", Refusal.LOOPBACK),
    ("10.0.0.1", Refusal.NOT_GLOBAL),
    ("172.16.5.4", Refusal.NOT_GLOBAL),
    ("192.168.1.1", Refusal.NOT_GLOBAL),
    ("fd12:3456::1", Refusal.NOT_GLOBAL),
    ("::ffff:10.0.0.1", Refusal.NOT_GLOBAL),
    ("64:ff9b::a00:1", Refusal.NOT_GLOBAL),
    ("2002:c0a8:101::1", Refusal.NOT_GLOBAL),
    (
        "2001:0:4136:e378:8000:63bf:3f57:fefe",
        Refusal.NOT_GLOBAL,
    ),  # Teredo client 192.168.1.1
    ("100.64.0.1", Refusal.NOT_GLOBAL),
    ("169.254.169.254", Refusal.METADATA),
    ("::ffff:169.254.169.254", Refusal.METADATA),
    ("fd00:ec2::254", Refusal.METADATA),
    ("100.100.100.200", Refusal.METADATA),
    ("169.254.1.1", Refusal.LINK_LOCAL),
    ("fe80::1", Refusal.LINK_LOCAL),
    ("224.0.0.1", Refusal.MULTICAST),
    ("ff02::1", Refusal.MULTICAST),
    ("255.255.255.255", Refusal.BROADCAST),
    ("0.0.0.0", Refusal.UNSPECIFIED),
    ("::", Refusal.UNSPECIFIED),
    ("0.1.2.3", Refusal.RESERVED),
    ("240.0.0.1", Refusal.RESERVED),
    ("198.18.0.1", Refusal.RESERVED),
    ("192.0.0.8", Refusal.RESERVED),
    ("192.0.2.1", Refusal.DOCUMENTATION),
    ("198.51.100.7", Refusal.DOCUMENTATION),
    ("203.0.113.9", Refusal.DOCUMENTATION),
    ("2001:db8::1", Refusal.DOCUMENTATION),
    ("3fff::1", Refusal.DOCUMENTATION),
    ("::ffff:8.8.8.8", Refusal.TRANSLATED),
    ("64:ff9b::808:808", Refusal.TRANSLATED),
    ("2002:808:808::1", Refusal.TRANSLATED),
    ("router.lan", Refusal.INTERNAL_NAME),
    ("nas.local", Refusal.INTERNAL_NAME),
    ("fritz.box", Refusal.INTERNAL_NAME),
    ("printer", Refusal.INTERNAL_NAME),
    ("x.home.arpa", Refusal.INTERNAL_NAME),
    ("db.internal", Refusal.INTERNAL_NAME),
    ("localhost", Refusal.INTERNAL_NAME),
    ("app.localdomain", Refusal.INTERNAL_NAME),
    ("wiki.corp.example.net", Refusal.INTERNAL_NAME),
    ("1.1.168.192.in-addr.arpa", Refusal.INTERNAL_NAME),
]


def test_case_23_ssrf_protection() -> None:
    """IDs only, allowlist only, scope rules, confirmation and rebinding guard."""
    pol = policy()
    # 1. Every forbidden external destination is refused when registered,
    #    even when the user "confirmed" it.
    for host, reason in SSRF_EXTERNAL_HOSTS:
        made = make_target("t1", TargetKind.ICMP, EXT, host, confirmed=True)
        assert isinstance(made, DiagTarget), host
        assert check_target(made, pol) is reason, host
        assert TargetRegistry(pol).with_target(made) is reason, host

    # 2. Unconfirmed external targets are stored but never handed out.
    reg, refused = TargetRegistry.build(
        pol,
        [
            target("8.8.8.8", target_id="dns_google", confirmed=False),
            target(
                "example.com", target_id="web", kind=TargetKind.HTTP, confirmed=False
            ),
            target("192.168.1.10", INT, target_id="nas", confirmed=False),
            target("127.0.0.1", target_id="evil", confirmed=True),
        ],
    )
    assert refused == [("evil", Refusal.LOOPBACK)]
    assert reg.ids == ("dns_google", "nas", "web")
    assert reg.resolve("dns_google") is Refusal.NOT_CONFIRMED
    assert reg.resolve("web") is Refusal.NOT_CONFIRMED
    # Internal targets need no confirmation
    nas = reg.resolve("nas")
    assert isinstance(nas, DiagTarget) and nas.host == "192.168.1.10"
    # No confirmed external target -> no external test is possible at all
    external = [t for t in reg.entries() if t.scope is EXT]
    assert len(external) == 2
    assert all(reg.resolve(t.target_id) is Refusal.NOT_CONFIRMED for t in external)

    # 3. The API path takes IDs only: free-form hosts, URLs and junk are refused
    #    without being looked up.
    for raw in (
        "8.8.8.8",
        "http://169.254.169.254/",
        "evil",
        "../nas",
        "",
        None,
        3,
        "NAS",
    ):
        assert reg.resolve(raw) in (Refusal.INVALID_ID, Refusal.UNKNOWN_TARGET), raw
    assert reg.resolve("8.8.8.8") is Refusal.INVALID_ID
    assert reg.resolve("evil") is Refusal.UNKNOWN_TARGET

    # 4. Confirmed external targets resolve.
    confirmed = reg.with_target(target("1.1.1.1", target_id="cf", confirmed=True))
    assert isinstance(confirmed, TargetRegistry)
    cf = confirmed.resolve("cf")
    assert isinstance(cf, DiagTarget) and cf.host == "1.1.1.1"
    assert reg.resolve("cf") is Refusal.UNKNOWN_TARGET  # original unchanged

    # 5. Internal scope: only configured networks, loopback never.
    for host, reason in [
        ("127.0.0.1", Refusal.LOOPBACK),
        ("::1", Refusal.LOOPBACK),
        ("169.254.169.254", Refusal.METADATA),
        ("169.254.1.1", Refusal.LINK_LOCAL),
        ("fe80::1", Refusal.LINK_LOCAL),
        ("192.168.2.1", Refusal.NOT_INTERNAL_NETWORK),
        ("8.8.8.8", Refusal.NOT_INTERNAL_NETWORK),
        ("::ffff:192.168.1.5", Refusal.NOT_INTERNAL_NETWORK),
        ("224.0.0.251", Refusal.MULTICAST),
        ("192.168.1.255", None),  # inside the configured /24: a host, not "broadcast"
        ("192.168.1.10", None),
        ("10.20.30.40", None),
        ("fd12:3456::10", None),
    ]:
        assert check_target(target(host, INT), pol) is reason, host
    with pytest.raises(ValueError):
        ScopePolicy.from_config(["127.0.0.0/8"])  # loopback can never be configured
    with pytest.raises(ValueError):
        ScopePolicy.from_config(["0.0.0.0/0"])  # far too broad to be "internal"
    with pytest.raises(ValueError):
        ScopePolicy.from_config(["::/0"])

    # 6. DNS rebinding guard: every resolved address must satisfy the scope.
    web = target("example.com", target_id="web", kind=TargetKind.HTTP)
    assert check_resolved(web, ["93.184.215.14"], pol) is None
    assert check_resolved(web, ["93.184.215.14", "127.0.0.1"], pol) is Refusal.LOOPBACK
    assert check_resolved(web, ["10.0.0.5"], pol) is Refusal.NOT_GLOBAL
    assert check_resolved(web, ["::ffff:169.254.169.254"], pol) is Refusal.METADATA
    assert check_resolved(web, [], pol) is Refusal.RESOLVED_EMPTY
    assert check_resolved(web, ["not-an-ip"], pol) is Refusal.RESOLVED_INVALID
    assert check_resolved(web, ["fe80::1%eth0"], pol) is Refusal.RESOLVED_INVALID
    many = ["93.184.215.14"] * (MAX_RESOLVED_ADDRESSES + 1)
    assert check_resolved(web, many, pol) is Refusal.TOO_MANY_ADDRESSES
    nas_name = target("nas.lan", INT, target_id="nasname")
    assert check_resolved(nas_name, ["192.168.1.20"], pol) is None
    assert check_resolved(nas_name, ["8.8.8.8"], pol) is Refusal.NOT_INTERNAL_NETWORK
    assert check_resolved(nas_name, ["127.0.0.1"], pol) is Refusal.LOOPBACK

    # 7. Internal names never go to an external resolver.
    assert may_query("example.com", EXT) is True
    for name in ("router.lan", "printer", "nas.local", "1.168.192.in-addr.arpa"):
        assert may_query(name, EXT) is False, name
        assert may_query(name, INT) is True, name
    assert (
        may_query("wiki.corp.example.net", EXT, local_domains=pol.local_domains)
        is False
    )


# --- host normalisation -------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.Com", "example.com"),
        ("router", "router"),
        ("a-b.c-d.org", "a-b.c-d.org"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
        ("8.8.8.8", "8.8.8.8"),
        ("0.0.0.0", "0.0.0.0"),
        ("2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888"),
        ("2001:DB8::1", "2001:db8::1"),
        ("::ffff:127.0.0.1", "::ffff:127.0.0.1"),  # dotted form since Python 3.13
        ("::127.0.0.1", "::7f00:1"),
        ("1e100.net", "1e100.net"),
        ("123abc.example", "123abc.example"),
        ("a" * 63 + ".com", "a" * 63 + ".com"),
    ],
)
def test_normalize_host_accepts(raw: str, expected: str) -> None:
    assert normalize_host(raw) == expected


@pytest.mark.parametrize(("raw", "reason"), INVALID_HOSTS)
def test_normalize_host_refuses(raw: str, reason: Refusal) -> None:
    assert normalize_host(raw) is reason


def test_normalized_host_is_one_safe_argv_element() -> None:
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-:")
    for raw in ("Example.COM", "2001:DB8::1", "10.0.0.1", "xn--mnchen-3ya.de"):
        host = normalize_host(raw)
        assert isinstance(host, str)
        assert set(host) <= allowed
        assert not host.startswith("-")
    for raw, _reason in INVALID_HOSTS:
        assert not isinstance(normalize_host(raw), str)


def test_module_offers_no_shell_string_builder() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "no intra-package imports"
            imported.add((node.module or "").split(".")[0])
    assert not imported & {
        "homeassistant",
        "socket",
        "subprocess",
        "aiohttp",
        "shlex",
        "os",
    }
    names = [n.name.lower() for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    assert not [n for n in names if "shell" in n or "cmd" in n or "command" in n]


# --- IP classification --------------------------------------------------------


@pytest.mark.parametrize(
    ("addr", "cls"),
    [
        ("8.8.8.8", AddressClass.GLOBAL),
        ("1.1.1.1", AddressClass.GLOBAL),
        ("2606:4700:4700::1111", AddressClass.GLOBAL),
        ("127.0.0.1", AddressClass.LOOPBACK),
        ("::1", AddressClass.LOOPBACK),
        ("10.1.2.3", AddressClass.PRIVATE),
        ("172.31.255.255", AddressClass.PRIVATE),
        ("172.32.0.1", AddressClass.GLOBAL),
        ("192.168.0.1", AddressClass.PRIVATE),
        ("fc00::1", AddressClass.PRIVATE),
        ("fd00::1", AddressClass.PRIVATE),
        ("100.64.0.1", AddressClass.CGNAT),
        ("100.127.255.254", AddressClass.CGNAT),
        ("100.128.0.1", AddressClass.GLOBAL),
        ("169.254.169.254", AddressClass.METADATA),
        ("169.254.0.1", AddressClass.LINK_LOCAL),
        ("fe80::abcd", AddressClass.LINK_LOCAL),
        ("fec0::1", AddressClass.RESERVED),
        ("224.0.0.251", AddressClass.MULTICAST),
        ("239.255.255.250", AddressClass.MULTICAST),
        ("ff05::2", AddressClass.MULTICAST),
        ("255.255.255.255", AddressClass.BROADCAST),
        ("0.0.0.0", AddressClass.UNSPECIFIED),
        ("::", AddressClass.UNSPECIFIED),
        ("0.0.0.1", AddressClass.RESERVED),
        ("240.1.2.3", AddressClass.RESERVED),
        ("198.19.255.255", AddressClass.RESERVED),
        ("192.88.99.1", AddressClass.RESERVED),
        ("100::1", AddressClass.RESERVED),
        ("2001:2::1", AddressClass.RESERVED),
        ("5f00::1", AddressClass.RESERVED),
        ("4000::1", AddressClass.RESERVED),
        ("192.0.2.1", AddressClass.DOCUMENTATION),
        ("2001:db8:1::1", AddressClass.DOCUMENTATION),
        ("::ffff:127.0.0.1", AddressClass.LOOPBACK),
        ("::ffff:192.168.1.1", AddressClass.PRIVATE),
        ("::ffff:8.8.8.8", AddressClass.TRANSLATED),
        ("::10.0.0.1", AddressClass.PRIVATE),
        ("64:ff9b::7f00:1", AddressClass.LOOPBACK),
        ("64:ff9b:1::a9fe:a9fe", AddressClass.METADATA),
        ("2002:7f00:1::", AddressClass.LOOPBACK),
        ("2002:a9fe:a9fe::", AddressClass.METADATA),
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", AddressClass.DOCUMENTATION),
        ("2001:0:808:808:8000:63bf:f7f7:f7f7", AddressClass.TRANSLATED),
    ],
)
def test_classify_ip(addr: str, cls: AddressClass) -> None:
    assert classify_ip(ipaddress.ip_address(addr)) is cls


def test_classification_does_not_depend_on_python_is_private() -> None:
    """Our tables, not ``is_private``/``is_global`` (changed in 3.12/3.13)."""
    source = MODULE_PATH.read_text(encoding="utf-8")
    for attr in (".is_private", ".is_global", ".is_reserved", ".is_link_local"):
        assert attr not in source


def test_check_address_rules() -> None:
    pol = policy()
    ip = ipaddress.ip_address
    assert check_address(ip("8.8.8.8"), EXT, pol) is None
    assert check_address(ip("8.8.8.8"), INT, pol) is Refusal.NOT_INTERNAL_NETWORK
    assert check_address(ip("10.9.9.9"), INT, pol) is None
    assert check_address(ip("10.9.9.9"), EXT, pol) is Refusal.NOT_GLOBAL


def test_link_local_and_metadata_need_the_exact_network() -> None:
    ip = ipaddress.ip_address
    broad = policy(networks=["10.0.0.0/8"])
    ll = policy(networks=["169.254.0.0/16"])
    md = policy(networks=["169.254.169.254/32"])
    v6ll = policy(networks=["fe80::/64"])
    assert check_address(ip("169.254.3.3"), INT, broad) is Refusal.LINK_LOCAL
    assert check_address(ip("169.254.3.3"), INT, ll) is None
    assert check_address(ip("169.254.169.254"), INT, ll) is Refusal.METADATA
    assert check_address(ip("169.254.169.254"), INT, md) is None
    assert check_address(ip("169.254.3.3"), INT, md) is Refusal.LINK_LOCAL
    assert check_address(ip("fe80::1"), INT, v6ll) is None
    assert check_address(ip("fe80::1"), INT, broad) is Refusal.LINK_LOCAL


def test_cgnat_and_global_v6_internal_when_configured() -> None:
    ip = ipaddress.ip_address
    pol = policy(networks=["100.64.0.0/10", "2a02:8070:1234::/48"])
    assert check_address(ip("100.100.1.1"), INT, pol) is None
    assert check_address(ip("2a02:8070:1234::5"), INT, pol) is None
    assert check_address(ip("100.100.100.200"), INT, pol) is Refusal.METADATA


def test_scope_policy_validation() -> None:
    pol = ScopePolicy.from_config(
        ["192.168.1.0/24", "fd00::/8"], local_domains=["Corp.Example.NET"]
    )
    assert pol.local_domains == ("corp.example.net",)
    for bad in (
        ["192.168.1.1/24"],
        ["nonsense"],
        ["::1/128"],
        ["10.0.0.0/7"],
        ["fd00::/7"],
    ):
        with pytest.raises(ValueError):
            ScopePolicy.from_config(bad)
    with pytest.raises(ValueError):
        ScopePolicy.from_config(["10.0.0.0/8"], local_domains=["bad domain"])
    with pytest.raises(ValueError):
        ScopePolicy.from_config(["10.0.0.0/8"] * 300)


# --- hostname classification ---------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "router",
        "router.lan",
        "NAS.LAN",
        "printer.local",
        "x.home.arpa",
        "home.arpa",
        "db.internal",
        "pc.localdomain",
        "fritz.box",
        "my.fritz.box",
        "localhost",
        "a.localhost",
        "x.test",
        "x.invalid",
        "x.onion",
        "1.1.168.192.in-addr.arpa",
        "168.192.in-addr.arpa",
        "10.in-addr.arpa",
        "1.0.0.127.in-addr.arpa",
        "254.169.in-addr.arpa",
        "in-addr.arpa",
        "x.1.168.192.in-addr.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        "d.f.ip6.arpa",
        "ip6.arpa",
        "10.0.0.1",
        "::1",
        "not valid!",
    ],
)
def test_internal_names(name: str) -> None:
    assert is_internal_name(name) is True
    assert may_query(name, EXT) is False


@pytest.mark.parametrize(
    "name",
    [
        "example.com",
        "www.google.de",
        "fritz.box.example.com",
        "lan.example.org",
        "8.8.8.8.in-addr.arpa",
        "8.in-addr.arpa",
        "8.8.8.8.8.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa",
        "xn--mnchen-3ya.de",
    ],
)
def test_external_names(name: str) -> None:
    assert is_internal_name(name) is False
    assert may_query(name, EXT) is True


def test_may_query_ip_literals_and_configured_domains() -> None:
    assert may_query("8.8.8.8", EXT) is False  # nothing to resolve
    assert may_query("8.8.8.8", INT) is False
    assert (
        may_query("svc.corp.example.net", EXT, local_domains=("corp.example.net",))
        is False
    )
    assert (
        may_query("corp.example.net", EXT, local_domains=("corp.example.net",)) is False
    )
    assert may_query("svc.corp.example.net", EXT) is True
    assert (
        may_query("svc.corp.example.net", INT, local_domains=("corp.example.net",))
        is True
    )
    assert may_query("bad host", INT) is False


# --- registry -----------------------------------------------------------------


def test_registry_is_bounded() -> None:
    pol = policy()
    reg = TargetRegistry(pol, max_targets=3)
    for i in range(3):
        nxt = reg.with_target(target(f"10.0.0.{i + 1}", INT, target_id=f"t{i}"))
        assert isinstance(nxt, TargetRegistry)
        reg = nxt
    assert len(reg) == 3
    assert (
        reg.with_target(target("10.0.0.9", INT, target_id="t9"))
        is Refusal.REGISTRY_FULL
    )
    assert (
        reg.with_target(target("10.0.0.9", INT, target_id="t0")) is Refusal.DUPLICATE_ID
    )
    smaller = reg.without_target("t0")
    assert len(smaller) == 2 and len(reg) == 3
    assert isinstance(
        smaller.with_target(target("10.0.0.9", INT, target_id="t9")), TargetRegistry
    )
    for bad in (0, -1, 10_000):
        with pytest.raises(ValueError):
            TargetRegistry(pol, max_targets=bad)


def test_registry_build_reports_overflow_and_duplicates() -> None:
    pol = policy()
    items = [target(f"10.0.0.{i + 1}", INT, target_id=f"t{i}") for i in range(4)]
    items.append(target("10.0.0.50", INT, target_id="t0"))
    reg, refused = TargetRegistry.build(pol, items, max_targets=3)
    assert reg.ids == ("t0", "t1", "t2")
    assert refused == [("t3", Refusal.REGISTRY_FULL), ("t0", Refusal.DUPLICATE_ID)]


def test_registry_rejects_non_targets() -> None:
    reg = TargetRegistry(policy())
    assert reg.with_target("8.8.8.8") is Refusal.INVALID_TARGET  # type: ignore[arg-type]
    assert reg.resolve("t1") is Refusal.UNKNOWN_TARGET


def test_registry_rechecks_on_resolve_with_a_new_policy() -> None:
    """A target stays bound to the policy of the registry that hands it out."""
    old = TargetRegistry(policy(networks=["192.168.5.0/24"]))
    reg = old.with_target(target("192.168.5.5", INT, target_id="cam"))
    assert isinstance(reg, TargetRegistry)
    assert isinstance(reg.resolve("cam"), DiagTarget)
    moved = reg.with_policy(policy(networks=["192.168.6.0/24"]))
    assert moved.resolve("cam") is Refusal.NOT_INTERNAL_NETWORK


def test_registry_rebinding_and_may_query_helpers() -> None:
    reg = TargetRegistry(policy())
    web = target("example.com", target_id="web", kind=TargetKind.HTTP, port=443)
    assert reg.check_resolved(web, [ipaddress.ip_address("93.184.215.14")]) is None
    assert reg.check_resolved(web, ["192.168.1.1"]) is Refusal.NOT_GLOBAL
    assert reg.may_query("wiki.corp.example.net", EXT) is False
    assert reg.may_query("example.com", EXT) is True


def test_refusals_do_not_echo_input_above_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(
        logging.DEBUG, logger="custom_components.openwrt_router.diag_targets"
    )
    reg = TargetRegistry(policy())
    secret = "198.51.100.77"
    reg.with_target(target(secret, target_id="leak"))
    reg.resolve("../" + secret)
    check_resolved(target("example.com"), [secret], policy())
    for record in caplog.records:
        if record.levelno > logging.DEBUG:
            assert secret not in record.getMessage()


def test_target_kinds_and_ports() -> None:
    assert target("example.com", kind=TargetKind.TCP, port=443).port == 443
    assert target("example.com", kind=TargetKind.HTTP).port is None
    assert target("example.com", kind=TargetKind.DNS, port=5353).port == 5353
    made = make_target("t", "icmp", "external", "Example.com")
    assert isinstance(made, DiagTarget)
    assert (
        made.kind is TargetKind.ICMP
        and made.scope is EXT
        and made.host == "example.com"
    )
    assert made.confirmed is False
    assert made.is_ip is False
    assert target("8.8.8.8").is_ip is True
