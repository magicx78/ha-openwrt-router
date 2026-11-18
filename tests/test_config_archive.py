"""Tests for the in-memory validation of router backup archives (G2).

Plan: docs/plans/2026-11-17-config-manager.md, sections 7, 11.3, 14.2 and
16 (cases 1, 4, 5, 6, 17). Every archive is built in memory with tarfile,
gzip and zlib; nothing touches the disk.
"""

from __future__ import annotations

import dataclasses
import functools
import gzip
import hashlib
import io
import logging
import struct
import tarfile
import zlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

import pytest

from custom_components.openwrt_router import config_archive as ca
from custom_components.openwrt_router.config_archive import (
    ArchiveError,
    ArchiveFinding,
    ArchiveReport,
    MemberInfo,
    UciTexts,
    content_hash,
    extract_uci_texts,
    validate_archive,
    verify_checksum,
    with_uci_cross_check,
)
from custom_components.openwrt_router.config_const import (
    DEFAULT_ARCHIVE_LIMITS,
    ERR_INCOMPLETE,
    ERR_INVALID,
    ERR_TOO_LARGE,
    WARN_CONFIG_MISSING_IN_ARCHIVE,
    ArchiveLimits,
)

MIB = 1024 * 1024
SECRET = "Sup3rS3cretWlanKey"

NETWORK = (
    b"config interface 'loopback'\n"
    b"\toption device 'lo'\n"
    b"\toption proto 'static'\n"
    b"\toption ipaddr '127.0.0.1'\n\n"
    b"config interface 'lan'\n"
    b"\toption device 'br-lan'\n"
    b"\toption proto 'static'\n"
    b"\toption ipaddr '192.168.1.1'\n"
)
SYSTEM = (
    b"config system\n"
    b"\toption hostname 'OpenWrt'\n"
    b"\toption timezone 'CET-1CEST,M3.5.0,M10.5.0/3'\n"
)
WIRELESS = (
    b"config wifi-iface 'default_radio0'\n"
    b"\toption ssid 'Home'\n"
    b"\toption encryption 'psk2'\n"
    b"\toption key '" + SECRET.encode() + b"'\n"
)
DHCP = b"config dnsmasq\n\toption domain 'lan'\n"
SHADOW = b"root:$5$" + SECRET.encode() + b":19000:0:99999:7:::\n"
HOST_KEY = bytes(range(256)) * 4


@dataclass(frozen=True)
class E:
    """One tar member for the test builders."""

    name: str
    data: bytes | None = b""
    type: bytes = tarfile.REGTYPE
    linkname: str = ""
    mode: int = 0o644
    mtime: int = 1_700_000_000
    uid: int = 0
    gid: int = 0
    uname: str = "root"
    gname: str = "root"
    pax: dict[str, str] = field(default_factory=dict)


def make_tar(entries: Sequence[E], *, fmt: int | None = None) -> tuple[bytes, int]:
    """Return (tar bytes, offset where the end-of-archive blocks start).

    GNU format by default (like busybox tar); pax format as soon as an entry
    carries pax headers, because the GNU writer drops them.
    """
    if fmt is None:
        fmt = (
            tarfile.PAX_FORMAT
            if any(entry.pax for entry in entries)
            else tarfile.GNU_FORMAT
        )
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for entry in entries:
            info = tarfile.TarInfo(entry.name)
            info.type = entry.type
            info.linkname = entry.linkname
            info.mode = entry.mode
            info.mtime = entry.mtime
            info.uid = entry.uid
            info.gid = entry.gid
            info.uname = entry.uname
            info.gname = entry.gname
            if entry.pax:
                info.pax_headers = dict(entry.pax)
            payload = None
            if entry.type in (tarfile.REGTYPE, tarfile.GNUTYPE_SPARSE, b"Z"):
                payload = io.BytesIO(entry.data or b"")
                info.size = len(entry.data or b"")
            tf.addfile(info, payload)
        end = tf.offset
    return buf.getvalue(), end


def gz(raw: bytes, *, mtime: int = 0, filename: str = "", level: int = 6) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(
        filename=filename, mode="wb", fileobj=buf, mtime=mtime, compresslevel=level
    ) as handle:
        handle.write(raw)
    return buf.getvalue()


def archive(entries: Sequence[E], **gz_kwargs: object) -> bytes:
    raw, _ = make_tar(entries)
    return gz(raw, **gz_kwargs)  # type: ignore[arg-type]


def base_entries() -> list[E]:
    return [
        E("etc/config/network", NETWORK),
        E("etc/config/system", SYSTEM),
    ]


def sysupgrade_entries(**overrides: object) -> list[E]:
    """Members shaped like `sysupgrade -b`: relative names, no directories."""
    kw = dict(overrides)
    return [
        E("etc/config/network", NETWORK, **kw),  # type: ignore[arg-type]
        E("etc/config/system", SYSTEM, **kw),  # type: ignore[arg-type]
        E("etc/config/wireless", WIRELESS, mode=0o600, **kw),  # type: ignore[arg-type]
        E("etc/config/dhcp", DHCP, **kw),  # type: ignore[arg-type]
        E("etc/passwd", b"root:x:0:0:root:/root:/bin/ash\n", **kw),  # type: ignore[arg-type]
        E("etc/shadow", SHADOW, mode=0o600, **kw),  # type: ignore[arg-type]
        E(
            "etc/dropbear/dropbear_ed25519_host_key",
            HOST_KEY,
            mode=0o600,
            **kw,  # type: ignore[arg-type]
        ),
        E(
            "etc/localtime",
            None,
            type=tarfile.SYMTYPE,
            linkname="/usr/share/zoneinfo/Europe/Berlin",
            mode=0o777,
            **kw,  # type: ignore[arg-type]
        ),
        E("etc/sysupgrade.conf", b"/root/.profile\n", **kw),  # type: ignore[arg-type]
        E("root/.profile", b"alias ll='ls -l'\n", **kw),  # type: ignore[arg-type]
    ]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def first_code(report: ArchiveReport) -> str:
    assert report.findings, report
    return report.findings[0].code


def assert_rejected(
    report: ArchiveReport, error: str, code: str, *, listing: bool = False
) -> None:
    """Check a failed report.

    ``listing`` is True for archives that are structurally sound but lack
    required configs; those keep their member list and content hash.
    """
    assert report.ok is False
    assert report.error == error
    assert first_code(report) == code
    if listing:
        assert report.content_hash == content_hash(report.members)
        return
    assert report.members == ()
    assert report.configs == frozenset()
    assert report.extra_paths == ()
    assert report.content_hash is None


# ---------------------------------------------------------------------------
# Case 1: a good backup
# ---------------------------------------------------------------------------


def test_validate_sysupgrade_shaped_archive() -> None:
    data = archive(sysupgrade_entries(), mtime=1_700_000_123, filename="backup.tar")

    report = validate_archive(data, DEFAULT_ARCHIVE_LIMITS)

    assert report.ok is True
    assert report.error is None
    assert report.findings == ()
    assert report.warnings == ()
    assert report.configs == frozenset({"network", "system", "wireless", "dhcp"})
    assert report.extra_paths == ("root/.profile",)
    assert report.archive_sha256 == sha(data)
    assert report.content_hash == content_hash(report.members)
    assert len(report.content_hash) == 64
    assert report.uncompressed_size == len(make_tar(sysupgrade_entries())[0])

    names = [m.name for m in report.members]
    assert names == sorted(names)
    by_name = {m.name: m for m in report.members}
    assert set(by_name) == {e.name for e in sysupgrade_entries()}

    wireless = by_name["etc/config/wireless"]
    assert wireless == MemberInfo(
        name="etc/config/wireless",
        type=ca.MEMBER_FILE,
        size=len(WIRELESS),
        mode=0o600,
        sha256=sha(WIRELESS),
        secret=True,
    )
    assert by_name["etc/config/system"].secret is False
    assert by_name["etc/shadow"].secret is True
    assert by_name["etc/dropbear/dropbear_ed25519_host_key"].secret is True
    assert by_name["etc/dropbear/dropbear_ed25519_host_key"].sha256 == sha(HOST_KEY)

    link = by_name["etc/localtime"]
    assert link.type == ca.MEMBER_SYMLINK
    assert link.size == 0
    assert link.sha256 == sha(b"/usr/share/zoneinfo/Europe/Berlin")


def test_report_and_member_carry_no_content() -> None:
    data = archive(sysupgrade_entries())
    report = validate_archive(data, DEFAULT_ARCHIVE_LIMITS)

    assert {f.name for f in dataclasses.fields(MemberInfo)} == {
        "name",
        "type",
        "size",
        "mode",
        "sha256",
        "secret",
    }
    assert {f.name for f in dataclasses.fields(ArchiveReport)} == {
        "ok",
        "error",
        "findings",
        "members",
        "configs",
        "extra_paths",
        "archive_sha256",
        "content_hash",
        "uncompressed_size",
        "warnings",
    }
    text = repr(report) + str(report)
    assert SECRET not in text
    assert "br-lan" not in text
    assert "hostname" not in text


def test_result_objects_are_frozen_and_slotted() -> None:
    report = validate_archive(archive(base_entries()), DEFAULT_ARCHIVE_LIMITS)
    cases = (
        (report, "ok"),
        (report.members[0], "name"),
        (ArchiveFinding("x"), "code"),
    )
    for obj, field_name in cases:
        assert not hasattr(obj, "__dict__")
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(obj, field_name, None)


def test_accepts_bytearray_and_memoryview() -> None:
    data = archive(base_entries())
    expected = validate_archive(data, DEFAULT_ARCHIVE_LIMITS)
    assert validate_archive(bytearray(data), DEFAULT_ARCHIVE_LIMITS) == expected
    assert validate_archive(memoryview(data), DEFAULT_ARCHIVE_LIMITS) == expected


def test_dot_slash_names_and_directories_are_normalised() -> None:
    entries = [
        E("./", None, type=tarfile.DIRTYPE, mode=0o755),
        E("./etc/", None, type=tarfile.DIRTYPE, mode=0o755),
        E("./etc/config/", None, type=tarfile.DIRTYPE, mode=0o755),
        E("./etc/config/network", NETWORK),
        E("./etc//config/./system", SYSTEM),
    ]
    report = validate_archive(archive(entries), DEFAULT_ARCHIVE_LIMITS)

    assert report.ok, report.findings
    assert [m.name for m in report.members] == [
        "etc",
        "etc/config",
        "etc/config/network",
        "etc/config/system",
    ]
    assert report.members[0].type == ca.MEMBER_DIR
    assert report.members[0].sha256 is None
    assert report.configs == frozenset({"network", "system"})


def test_multi_member_gzip_and_zero_padding_are_accepted() -> None:
    raw, _ = make_tar(base_entries())
    half = len(raw) // 2
    data = gz(raw[:half]) + gz(raw[half:]) + b"\x00" * 100
    report = validate_archive(data, DEFAULT_ARCHIVE_LIMITS)
    assert report.ok, report.findings
    assert (
        report.content_hash
        == validate_archive(gz(raw), DEFAULT_ARCHIVE_LIMITS).content_hash
    )


def test_too_many_gzip_members_is_invalid() -> None:
    data = archive(base_entries()) + gz(b"") * ca.MAX_GZIP_MEMBERS
    assert_rejected(
        validate_archive(data, DEFAULT_ARCHIVE_LIMITS),
        ERR_INVALID,
        ca.CODE_TOO_MANY_GZIP_MEMBERS,
    )
    ok = archive(base_entries()) + gz(b"") * (ca.MAX_GZIP_MEMBERS - 1)
    assert validate_archive(ok, DEFAULT_ARCHIVE_LIMITS).ok


def test_trailing_garbage_after_gzip_is_invalid() -> None:
    data = archive(base_entries()) + b"not gzip"
    assert_rejected(
        validate_archive(data, DEFAULT_ARCHIVE_LIMITS),
        ERR_INVALID,
        ca.CODE_TRAILING_GZIP_DATA,
    )


def test_data_after_end_of_tar_is_invalid() -> None:
    raw, end = make_tar(base_entries())
    tampered = raw[: end + 1024] + b"hidden" + raw[end + 1030 :]
    assert_rejected(
        validate_archive(gz(tampered), DEFAULT_ARCHIVE_LIMITS),
        ERR_INVALID,
        ca.CODE_TRAILING_TAR_DATA,
    )


def test_corrupt_second_header_is_not_silently_ignored() -> None:
    entries = [*base_entries(), E("etc/config/dhcp", DHCP)]
    raw, _ = make_tar(entries)
    # Third header starts after two (header + one data block) pairs.
    pos = 4 * 512
    assert raw[pos : pos + 15] == b"etc/config/dhcp"
    tampered = raw[:pos] + b"X" + raw[pos + 1 :]
    report = validate_archive(gz(tampered), DEFAULT_ARCHIVE_LIMITS)
    assert report.ok is False
    assert report.error == ERR_INVALID


# ---------------------------------------------------------------------------
# Case 4: incomplete backups
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cut", [1, 4, 8, 20, 200], ids=lambda c: f"cut{c}")
def test_truncated_gzip_is_incomplete(cut: int) -> None:
    data = archive(sysupgrade_entries())
    report = validate_archive(data[:-cut], DEFAULT_ARCHIVE_LIMITS)
    assert_rejected(report, ERR_INCOMPLETE, ca.CODE_TRUNCATED)
    assert report.archive_sha256 == sha(data[:-cut])


def test_truncated_to_gzip_header_only_is_incomplete() -> None:
    data = archive(base_entries())
    assert_rejected(
        validate_archive(data[:10], DEFAULT_ARCHIVE_LIMITS),
        ERR_INCOMPLETE,
        ca.CODE_TRUNCATED,
    )


def test_crc_mismatch_is_incomplete() -> None:
    data = bytearray(archive(base_entries()))
    data[-8] ^= 0xFF  # first CRC32 byte of the gzip trailer
    assert_rejected(
        validate_archive(bytes(data), DEFAULT_ARCHIVE_LIMITS),
        ERR_INCOMPLETE,
        ca.CODE_CORRUPT_GZIP,
    )


@pytest.mark.parametrize("missing", ["network", "system"])
def test_missing_network_config_is_incomplete(missing: str) -> None:
    entries = [e for e in sysupgrade_entries() if e.name != f"etc/config/{missing}"]
    report = validate_archive(archive(entries), DEFAULT_ARCHIVE_LIMITS)

    assert report.ok is False
    assert report.error == ERR_INCOMPLETE
    assert report.findings == (
        ArchiveFinding(ca.CODE_MISSING_REQUIRED_CONFIG, f"etc/config/{missing}"),
    )
    # The archive itself is sound, so its listing and hash stay available.
    assert missing not in report.configs
    assert len(report.members) == len(entries)
    assert report.content_hash == content_hash(report.members)


def test_tar_without_end_marker_is_incomplete() -> None:
    raw, end = make_tar(base_entries())
    assert_rejected(
        validate_archive(gz(raw[:end]), DEFAULT_ARCHIVE_LIMITS),
        ERR_INCOMPLETE,
        ca.CODE_MISSING_END_OF_ARCHIVE,
    )


def test_tar_cut_inside_header_is_incomplete() -> None:
    raw, _ = make_tar(base_entries())
    assert_rejected(
        validate_archive(gz(raw[: 2 * 512 + 100]), DEFAULT_ARCHIVE_LIMITS),
        ERR_INCOMPLETE,
        ca.CODE_MISSING_END_OF_ARCHIVE,
    )


def test_tar_cut_inside_member_data_is_incomplete() -> None:
    big = b"x" * 5000
    raw, _ = make_tar([*base_entries(), E("etc/config/firewall", big)])
    cut = 4 * 512 + 512 + 1000  # inside the firewall data
    assert_rejected(
        validate_archive(gz(raw[:cut]), DEFAULT_ARCHIVE_LIMITS),
        ERR_INCOMPLETE,
        ca.CODE_TRUNCATED_TAR,
    )


# ---------------------------------------------------------------------------
# Case 5: checksum
# ---------------------------------------------------------------------------


def test_verify_checksum_detects_mismatch() -> None:
    data = archive(base_entries())
    good = validate_archive(data, DEFAULT_ARCHIVE_LIMITS).archive_sha256

    assert verify_checksum(data, good) is True
    assert verify_checksum(data, good.upper()) is True
    tampered = bytearray(data)
    tampered[20] ^= 0x01
    assert verify_checksum(bytes(tampered), good) is False
    assert verify_checksum(data + b"\x00", good) is False
    assert verify_checksum(data, sha(b"other")) is False


@pytest.mark.parametrize("expected", ["", "abc", "z" * 64, " " + "0" * 63, "0" * 65])
def test_verify_checksum_rejects_malformed_expected(expected: str) -> None:
    assert verify_checksum(b"data", expected) is False


# ---------------------------------------------------------------------------
# Case 6: identical configs
# ---------------------------------------------------------------------------


def test_content_hash_ignores_mtime_owner_and_gzip_header() -> None:
    first = archive(
        sysupgrade_entries(mtime=1_700_000_000),
        mtime=1_700_000_000,
        filename="a.tar",
        level=9,
    )
    second = archive(
        sysupgrade_entries(
            mtime=1_800_000_000, uid=1000, gid=1000, uname="build", gname="users"
        ),
        mtime=1_800_000_555,
        filename="other-name.tar",
        level=1,
    )
    r1 = validate_archive(first, DEFAULT_ARCHIVE_LIMITS)
    r2 = validate_archive(second, DEFAULT_ARCHIVE_LIMITS)

    assert r1.ok and r2.ok
    assert first != second
    assert r1.archive_sha256 != r2.archive_sha256
    assert r1.content_hash == r2.content_hash


def test_content_hash_independent_of_member_order_and_tar_format() -> None:
    entries = sysupgrade_entries()
    raw_pax, _ = make_tar(list(reversed(entries)), fmt=tarfile.PAX_FORMAT)
    r1 = validate_archive(archive(entries), DEFAULT_ARCHIVE_LIMITS)
    r2 = validate_archive(gz(raw_pax), DEFAULT_ARCHIVE_LIMITS)
    assert r1.ok and r2.ok
    assert r1.content_hash == r2.content_hash


def _replace(entries: list[E], target: str, **changes: object) -> list[E]:
    return [
        dataclasses.replace(e, **changes) if e.name == target else e  # type: ignore[arg-type]
        for e in entries
    ]


@pytest.mark.parametrize(
    "change",
    [
        pytest.param(
            lambda es: _replace(es, "etc/config/wireless", data=WIRELESS + b"\n"),
            id="content",
        ),
        pytest.param(lambda es: _replace(es, "etc/config/dhcp", mode=0o600), id="mode"),
        pytest.param(
            lambda es: _replace(
                es, "etc/localtime", linkname="/usr/share/zoneinfo/UTC"
            ),
            id="link_target",
        ),
        pytest.param(
            lambda es: _replace(es, "root/.profile", name="root/.profile2"),
            id="name",
        ),
        pytest.param(lambda es: es[:-1], id="member_removed"),
        pytest.param(
            lambda es: [*es, E("etc/extra", None, type=tarfile.DIRTYPE)],
            id="directory_added",
        ),
    ],
)
def test_content_hash_changes_with_real_changes(
    change: Callable[[list[E]], list[E]],
) -> None:
    base = validate_archive(archive(sysupgrade_entries()), DEFAULT_ARCHIVE_LIMITS)
    changed = validate_archive(
        archive(change(sysupgrade_entries())), DEFAULT_ARCHIVE_LIMITS
    )
    assert base.ok and changed.ok
    assert base.content_hash != changed.content_hash


def test_content_hash_of_member_list_is_order_independent() -> None:
    members = validate_archive(
        archive(sysupgrade_entries()), DEFAULT_ARCHIVE_LIMITS
    ).members
    assert content_hash(members) == content_hash(reversed(members))
    assert content_hash(members) == content_hash(list(members))
    assert content_hash(()) != content_hash(members[:1])


# ---------------------------------------------------------------------------
# Case 17: manipulated archives
# ---------------------------------------------------------------------------


def _with(*extra: E) -> bytes:
    return archive([*base_entries(), *extra])


@functools.cache
def _zero_stream(header: bytes, zeros: int, trailer: bytes = b"") -> bytes:
    """Gzip(header + zeros + trailer) without holding the zeros in memory."""
    comp = zlib.compressobj(9, zlib.DEFLATED, 31)
    out = [comp.compress(header)]
    chunk = bytes(MIB)
    for _ in range(zeros // MIB):
        out.append(comp.compress(chunk))
    out.append(comp.compress(bytes(zeros % MIB)))
    out.append(comp.compress(trailer))
    out.append(comp.flush())
    return b"".join(out)


def _member_bomb() -> bytes:
    """A real member that inflates to 100 MiB of zeros."""
    head, end = make_tar(base_entries())
    info = tarfile.TarInfo("etc/config/firewall")
    info.size = 100 * MIB
    return _zero_stream(
        head[:end] + info.tobuf(tarfile.GNU_FORMAT), 100 * MIB, bytes(1024)
    )


def _header_bomb(kind: bytes) -> bytes:
    """A GNU long-name or pax header that tarfile reads whole into memory."""
    info = tarfile.TarInfo("././@LongLink")
    info.type = kind
    info.size = 100 * MIB
    return _zero_stream(info.tobuf(tarfile.GNU_FORMAT), 100 * MIB)


def _too_many_members() -> bytes:
    count = DEFAULT_ARCHIVE_LIMITS.max_members
    extra = [E(f"etc/f{i}") for i in range(count - 1)]
    return archive([*base_entries(), *extra])


def _plain_tar() -> bytes:
    return make_tar(base_entries())[0]


MALICIOUS = [
    pytest.param(
        lambda: _with(E("etc/../../evil", b"x")),
        ERR_INVALID,
        ca.CODE_PATH_TRAVERSAL,
        id="dotdot_inside",
    ),
    pytest.param(
        lambda: _with(E("../etc/passwd", b"x")),
        ERR_INVALID,
        ca.CODE_PATH_TRAVERSAL,
        id="dotdot_prefix",
    ),
    pytest.param(
        lambda: _with(E("/etc/passwd", b"x")),
        ERR_INVALID,
        ca.CODE_ABSOLUTE_PATH,
        id="absolute_path",
    ),
    pytest.param(
        lambda: _with(
            E(
                "etc/evil",
                None,
                type=tarfile.SYMTYPE,
                linkname="../../root/.ssh/authorized_keys",
            )
        ),
        ERR_INVALID,
        ca.CODE_SYMLINK_ESCAPE,
        id="symlink_relative_outside",
    ),
    pytest.param(
        lambda: _with(E("etc/evil", None, type=tarfile.SYMTYPE, linkname="/root/.ssh")),
        ERR_INVALID,
        ca.CODE_SYMLINK_ABSOLUTE,
        id="symlink_absolute_outside",
    ),
    pytest.param(
        lambda: _with(
            E("etc/hard", None, type=tarfile.LNKTYPE, linkname="etc/config/network")
        ),
        ERR_INVALID,
        ca.CODE_HARDLINK,
        id="hardlink",
    ),
    pytest.param(
        lambda: _with(E("etc/null", None, type=tarfile.CHRTYPE)),
        ERR_INVALID,
        ca.CODE_DEVICE_FILE,
        id="char_device",
    ),
    pytest.param(
        lambda: _with(E("etc/sda", None, type=tarfile.BLKTYPE)),
        ERR_INVALID,
        ca.CODE_DEVICE_FILE,
        id="block_device",
    ),
    pytest.param(
        lambda: _with(E("etc/pipe", None, type=tarfile.FIFOTYPE)),
        ERR_INVALID,
        ca.CODE_FIFO,
        id="fifo",
    ),
    pytest.param(
        lambda: archive(
            [*base_entries(), E("etc/x", b"x", pax={"path": "etc/con\x00fig/x"})]
        ),
        ERR_INVALID,
        ca.CODE_NUL_IN_NAME,
        id="nul_in_name",
    ),
    pytest.param(
        _member_bomb, ERR_INVALID, ca.CODE_MEMBER_TOO_LARGE, id="gzip_bomb_member"
    ),
    pytest.param(
        lambda: _header_bomb(tarfile.GNUTYPE_LONGNAME),
        ERR_INVALID,
        ca.CODE_RATIO_EXCEEDED,
        id="gzip_bomb_longname_header",
    ),
    pytest.param(
        lambda: _header_bomb(tarfile.XHDTYPE),
        ERR_INVALID,
        ca.CODE_RATIO_EXCEEDED,
        id="gzip_bomb_pax_header",
    ),
    pytest.param(
        _too_many_members, ERR_INVALID, ca.CODE_TOO_MANY_MEMBERS, id="too_many_members"
    ),
    pytest.param(_plain_tar, ERR_INVALID, ca.CODE_NOT_GZIP, id="not_gzip"),
    pytest.param(lambda: b"", ERR_INVALID, ca.CODE_NOT_GZIP, id="empty"),
    pytest.param(
        lambda: gz(b"this is not a tar archive at all" * 40),
        ERR_INVALID,
        ca.CODE_NOT_A_TAR,
        id="gzip_but_not_tar",
    ),
    pytest.param(
        lambda: archive([E("etc/passwd", b"x"), E("root/.profile", b"y")]),
        ERR_INCOMPLETE,
        ca.CODE_NO_ETC_CONFIG,
        id="tar_without_etc_config",
    ),
    pytest.param(
        lambda: _with(E("etc/sparse", b"abc", type=tarfile.GNUTYPE_SPARSE)),
        ERR_INVALID,
        ca.CODE_SPARSE_FILE,
        id="sparse_file",
    ),
    pytest.param(
        lambda: _with(E("etc/odd", b"abc", type=b"Z")),
        ERR_INVALID,
        ca.CODE_UNSUPPORTED_TYPE,
        id="unknown_type",
    ),
    pytest.param(
        lambda: _with(E("etc\\config\\x", b"x")),
        ERR_INVALID,
        ca.CODE_BACKSLASH_IN_NAME,
        id="backslash",
    ),
    pytest.param(
        lambda: _with(E("etc/a\nb", b"x")),
        ERR_INVALID,
        ca.CODE_CONTROL_CHAR_IN_NAME,
        id="newline_in_name",
    ),
    pytest.param(
        lambda: _with(E(".", b"x")), ERR_INVALID, ca.CODE_EMPTY_NAME, id="empty_name"
    ),
    pytest.param(
        lambda: _with(E("etc/config/network", b"other")),
        ERR_INVALID,
        ca.CODE_DUPLICATE_MEMBER,
        id="duplicate_file",
    ),
    pytest.param(
        lambda: _with(
            E("etc/lnk", None, type=tarfile.SYMTYPE, linkname="/usr/lib"),
            E("etc/lnk/evil", b"x"),
        ),
        ERR_INVALID,
        ca.CODE_PATH_THROUGH_SYMLINK,
        id="path_through_symlink",
    ),
    pytest.param(
        lambda: archive(
            [
                E("etc/lnk/evil", b"x"),
                *base_entries(),
                E("etc/lnk", None, type=tarfile.SYMTYPE, linkname="/usr/lib"),
            ]
        ),
        ERR_INVALID,
        ca.CODE_PATH_THROUGH_SYMLINK,
        id="path_through_later_symlink",
    ),
]


@pytest.mark.parametrize(("build", "error", "code"), MALICIOUS)
def test_rejects_malicious(
    build: Callable[[], bytes],
    error: str,
    code: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    data = build()
    with caplog.at_level(logging.DEBUG, logger=ca.__name__):
        report = validate_archive(data, DEFAULT_ARCHIVE_LIMITS)

    assert_rejected(report, error, code, listing=code == ca.CODE_NO_ETC_CONFIG)
    assert report.archive_sha256 == sha(data)
    with pytest.raises(ArchiveError) as exc:
        extract_uci_texts(data, DEFAULT_ARCHIVE_LIMITS)
    assert exc.value.error == error
    assert exc.value.findings == report.findings
    # Logs carry reason codes only, never member names or contents.
    assert "etc/" not in caplog.text
    assert "root" not in caplog.text


@pytest.mark.parametrize(
    "kind", [tarfile.GNUTYPE_LONGNAME, tarfile.XHDTYPE], ids=["longname", "pax"]
)
def test_bomb_decompression_stops_at_hard_cap(kind: bytes) -> None:
    data = _header_bomb(kind)
    limits = DEFAULT_ARCHIVE_LIMITS
    report = validate_archive(data, limits)

    cap = min(
        limits.max_uncompressed_total,
        max(ca.RATIO_CHECK_FLOOR_BYTES, limits.max_ratio * len(data)),
    )
    assert report.error == ERR_INVALID
    assert cap < 100 * MIB
    assert cap < report.uncompressed_size <= cap + ca.OUTPUT_CHUNK_BYTES


def test_bomb_hits_total_cap_when_ratio_is_generous() -> None:
    data = _header_bomb(tarfile.GNUTYPE_LONGNAME)
    limits = ArchiveLimits(max_ratio=1_000_000, max_uncompressed_total=8 * MIB)
    report = validate_archive(data, limits)
    assert_rejected(report, ERR_INVALID, ca.CODE_UNCOMPRESSED_TOO_LARGE)
    assert report.uncompressed_size <= 8 * MIB + ca.OUTPUT_CHUNK_BYTES


# ---------------------------------------------------------------------------
# Size limits, one per bound (exactly at the limit passes, one over fails)
# ---------------------------------------------------------------------------


def test_limit_max_compressed() -> None:
    data = archive(base_entries())
    ok = validate_archive(data, ArchiveLimits(max_compressed=len(data)))
    assert ok.ok, ok.findings
    over = validate_archive(data, ArchiveLimits(max_compressed=len(data) - 1))
    assert_rejected(over, ERR_TOO_LARGE, ca.CODE_COMPRESSED_TOO_LARGE)
    assert over.uncompressed_size == 0


def test_limit_max_uncompressed_total() -> None:
    raw, _ = make_tar(base_entries())
    data = gz(raw)
    ok = validate_archive(data, ArchiveLimits(max_uncompressed_total=len(raw)))
    assert ok.ok, ok.findings
    over = validate_archive(data, ArchiveLimits(max_uncompressed_total=len(raw) - 1))
    assert_rejected(over, ERR_INVALID, ca.CODE_UNCOMPRESSED_TOO_LARGE)


def test_limit_sum_of_member_sizes_checked_from_headers() -> None:
    data = _with(E("etc/a", b"a" * 3000), E("etc/b", b"b" * 3000))
    # The declared member sizes alone exceed the limit.
    limits = ArchiveLimits(max_uncompressed_total=len(NETWORK) + len(SYSTEM) + 5000)
    assert_rejected(
        validate_archive(data, limits), ERR_INVALID, ca.CODE_UNCOMPRESSED_TOO_LARGE
    )


def test_limit_max_member_size() -> None:
    data = _with(E("etc/blob", b"z" * 4096))
    ok = validate_archive(data, ArchiveLimits(max_member_size=4096))
    assert ok.ok, ok.findings
    over = validate_archive(data, ArchiveLimits(max_member_size=4095))
    assert_rejected(over, ERR_INVALID, ca.CODE_MEMBER_TOO_LARGE)


def test_limit_max_members() -> None:
    data = _with(E("etc/a"), E("etc/b"))
    ok = validate_archive(data, ArchiveLimits(max_members=4))
    assert ok.ok, ok.findings
    over = validate_archive(data, ArchiveLimits(max_members=3))
    assert_rejected(over, ERR_INVALID, ca.CODE_TOO_MANY_MEMBERS)


def test_limit_max_ratio() -> None:
    data = _with(E("etc/zeros", bytes(4 * MIB)))
    over = validate_archive(data, DEFAULT_ARCHIVE_LIMITS)
    assert_rejected(over, ERR_INVALID, ca.CODE_RATIO_EXCEEDED)
    ok = validate_archive(data, ArchiveLimits(max_ratio=100_000))
    assert ok.ok, ok.findings


def test_ratio_not_applied_below_floor() -> None:
    data = _with(E("etc/zeros", bytes(64 * 1024)))
    report = validate_archive(data, ArchiveLimits(max_ratio=1))
    assert report.ok, report.findings


def test_limit_max_name_length() -> None:
    name = "etc/" + "n" * 36  # 40 bytes
    data = _with(E(name, b"x"))
    ok = validate_archive(data, ArchiveLimits(max_name_length=40))
    assert ok.ok, ok.findings
    over = validate_archive(data, ArchiveLimits(max_name_length=39))
    assert_rejected(over, ERR_INVALID, ca.CODE_NAME_TOO_LONG)


def test_name_length_counts_utf8_bytes() -> None:
    name = "etc/" + "ä" * 10  # 4 + 20 bytes, 14 characters
    data = _with(E(name, b"x"))
    assert validate_archive(data, ArchiveLimits(max_name_length=24)).ok
    over = validate_archive(data, ArchiveLimits(max_name_length=23))
    assert_rejected(over, ERR_INVALID, ca.CODE_NAME_TOO_LONG)


# ---------------------------------------------------------------------------
# Symlink rule (plan section 7)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("etc/localtime", "/usr/share/zoneinfo/Europe/Berlin"),
        ("etc/x", "/etc/config/network"),
        ("etc/y", "/lib/functions.sh"),
        ("etc/config/alias", "network"),
        ("etc/config/up", "../passwd"),
        ("etc/deep/link", "../../root/.profile"),
        ("etc/dot", "./config/../config/system"),
        ("top", "etc/config/network"),
        ("etc/dangling", "../does/not/exist"),
    ],
)
def test_allowed_symlinks(name: str, target: str) -> None:
    data = _with(E(name, None, type=tarfile.SYMTYPE, linkname=target))
    report = validate_archive(data, DEFAULT_ARCHIVE_LIMITS)
    assert report.ok, report.findings


@pytest.mark.parametrize(
    ("name", "target", "code"),
    [
        ("etc/a", "/root/x", ca.CODE_SYMLINK_ABSOLUTE),
        ("etc/a", "/tmp/../root/.ssh", ca.CODE_SYMLINK_ABSOLUTE),
        ("etc/a", "/tmpx/y", ca.CODE_SYMLINK_ABSOLUTE),
        ("etc/a", "/tmp", ca.CODE_SYMLINK_ABSOLUTE),
        ("etc/a", "/etc/../root/.ssh", ca.CODE_SYMLINK_ABSOLUTE),
        ("etc/a", "/etcetera/x", ca.CODE_SYMLINK_ABSOLUTE),
        ("etc/a", "/etc", ca.CODE_SYMLINK_ABSOLUTE),
        ("etc/a", "/", ca.CODE_SYMLINK_ABSOLUTE),
        ("etc/a", "../..", ca.CODE_SYMLINK_ESCAPE),
        ("top", "../x", ca.CODE_SYMLINK_ESCAPE),
        ("etc/a", "config/../../../x", ca.CODE_SYMLINK_ESCAPE),
        ("etc/a", "", ca.CODE_SYMLINK_TARGET_INVALID),
        ("etc/a", "x\\..\\..\\y", ca.CODE_SYMLINK_TARGET_INVALID),
        ("etc/a", "x\ny", ca.CODE_SYMLINK_TARGET_INVALID),
    ],
)
def test_rejected_symlinks(name: str, target: str, code: str) -> None:
    data = _with(E(name, None, type=tarfile.SYMTYPE, linkname=target))
    assert_rejected(validate_archive(data, DEFAULT_ARCHIVE_LIMITS), ERR_INVALID, code)


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("etc/resolv.conf", "/tmp/resolv.conf"),
        ("etc/mtab", "/proc/mounts"),
        ("etc/ppp/resolv.conf", "/tmp/resolv.conf.ppp"),
        ("etc/lock", "/var/lock"),
    ],
)
def test_runtime_symlinks_of_full_etc_backup_are_allowed(
    name: str, target: str
) -> None:
    """A backup of all of /etc carries links into /tmp, /var and /proc.

    The archive is never extracted, so they are harmless and must not make
    the whole backup invalid.
    """
    data = archive(
        [
            *sysupgrade_entries(),
            E(name, None, type=tarfile.SYMTYPE, linkname=target, mode=0o777),
        ]
    )
    report = validate_archive(data, DEFAULT_ARCHIVE_LIMITS)
    assert report.ok, report.findings
    assert any(m.name == name and m.type == "symlink" for m in report.members)


def test_symlink_target_with_nul_is_rejected() -> None:
    data = _with(
        E(
            "etc/a",
            None,
            type=tarfile.SYMTYPE,
            linkname="x",
            pax={"linkpath": "/etc/x\x00/../../root"},
        )
    )
    assert_rejected(
        validate_archive(data, DEFAULT_ARCHIVE_LIMITS),
        ERR_INVALID,
        ca.CODE_SYMLINK_TARGET_INVALID,
    )


def test_duplicate_directories_are_allowed() -> None:
    data = _with(
        E("etc/d", None, type=tarfile.DIRTYPE),
        E("etc/d/", None, type=tarfile.DIRTYPE),
    )
    report = validate_archive(data, DEFAULT_ARCHIVE_LIMITS)
    assert report.ok, report.findings
    assert [m.name for m in report.members].count("etc/d") == 1


def test_directory_and_file_with_same_name_is_duplicate() -> None:
    data = _with(E("etc/d", None, type=tarfile.DIRTYPE), E("etc/d", b"x"))
    assert_rejected(
        validate_archive(data, DEFAULT_ARCHIVE_LIMITS),
        ERR_INVALID,
        ca.CODE_DUPLICATE_MEMBER,
    )


# ---------------------------------------------------------------------------
# extract_uci_texts
# ---------------------------------------------------------------------------


def test_extract_uci_texts_returns_only_etc_config() -> None:
    entries = [
        *sysupgrade_entries(),
        E("etc/config/sub/nested", b"config nested\n"),
        E("etc/config/linked", None, type=tarfile.SYMTYPE, linkname="network"),
        E("etc/configx", b"not a config\n"),
    ]
    texts = extract_uci_texts(archive(entries), DEFAULT_ARCHIVE_LIMITS)

    assert isinstance(texts, dict)
    assert isinstance(texts, UciTexts)
    assert texts == {
        "network": NETWORK.decode(),
        "system": SYSTEM.decode(),
        "wireless": WIRELESS.decode(),
        "dhcp": DHCP.decode(),
    }


def test_extract_uci_texts_repr_hides_content() -> None:
    texts = extract_uci_texts(archive(sysupgrade_entries()), DEFAULT_ARCHIVE_LIMITS)
    for rendered in (repr(texts), str(texts), f"{texts}", f"{texts!r}"):
        assert SECRET not in rendered
        assert "br-lan" not in rendered
        assert "wireless" in rendered


def test_extract_uci_texts_replaces_invalid_utf8() -> None:
    data = _with(E("etc/config/firewall", b"option name 'caf\xe9'\n"))
    texts = extract_uci_texts(data, DEFAULT_ARCHIVE_LIMITS)
    assert texts["firewall"] == "option name 'caf�'\n"


def test_extract_uci_texts_refuses_incomplete_archive() -> None:
    entries = [e for e in base_entries() if e.name != "etc/config/system"]
    with pytest.raises(ArchiveError) as exc:
        extract_uci_texts(archive(entries), DEFAULT_ARCHIVE_LIMITS)
    assert exc.value.error == ERR_INCOMPLETE
    assert SECRET not in str(exc.value)


def test_validate_and_extract_log_no_secrets(caplog: pytest.LogCaptureFixture) -> None:
    data = archive(sysupgrade_entries())
    with caplog.at_level(logging.DEBUG, logger=ca.__name__):
        validate_archive(data, DEFAULT_ARCHIVE_LIMITS)
        extract_uci_texts(data, DEFAULT_ARCHIVE_LIMITS)
    assert SECRET not in caplog.text
    assert "etc/shadow" not in caplog.text
    assert "dropbear" not in caplog.text


# ---------------------------------------------------------------------------
# Cross-check against the UCI snapshot (plan 7, point 4)
# ---------------------------------------------------------------------------


def test_with_uci_cross_check_warns_for_missing_config() -> None:
    report = validate_archive(archive(sysupgrade_entries()), DEFAULT_ARCHIVE_LIMITS)
    checked = with_uci_cross_check(
        report, ["network", "system", "wireless", "firewall", "dhcp", "sqm"]
    )

    assert checked.ok is True
    assert checked.warnings == (
        ArchiveFinding(WARN_CONFIG_MISSING_IN_ARCHIVE, "etc/config/firewall"),
        ArchiveFinding(WARN_CONFIG_MISSING_IN_ARCHIVE, "etc/config/sqm"),
    )
    assert checked.content_hash == report.content_hash
    assert with_uci_cross_check(report, report.configs) == report


def test_with_uci_cross_check_leaves_failed_report_alone() -> None:
    report = validate_archive(b"junk", DEFAULT_ARCHIVE_LIMITS)
    assert with_uci_cross_check(report, ["network"]) == report


# ---------------------------------------------------------------------------
# Parser differentials (review C1): what the check did not see as a member
# must not exist in the byte stream.
# ---------------------------------------------------------------------------

HIDDEN_RULE = (
    b"config rule\n\toption name 'EVIL'\n\toption src 'wan'\n"
    b"\toption dest_port '22'\n\toption target 'ACCEPT'\n"
)


def _pad(data: bytes) -> bytes:
    return data + bytes(-len(data) % 512)


def _ustar(
    name: str, size: int, *, kind: bytes = tarfile.REGTYPE, linkname: str = ""
) -> bytes:
    info = tarfile.TarInfo(name)
    info.size = size
    info.type = kind
    info.linkname = linkname
    info.mtime = 1_700_000_000
    return info.tobuf(tarfile.USTAR_FORMAT)


def _pax_records(fields: dict[str, str]) -> bytes:
    out = b""
    for key, value in fields.items():
        body = f"{key}={value}\n".encode()
        length = len(body) + 1
        while len(str(length)) + 1 + len(body) != length:
            length = len(str(length)) + 1 + len(body)
        out += str(length).encode() + b" " + body
    return out


def _pax(fields: dict[str, str], kind: bytes = tarfile.XHDTYPE) -> bytes:
    records = _pax_records(fields)
    return _ustar("PaxHeaders/x", len(records), kind=kind) + _pad(records)


def _rule_member(name: str = "etc/config/firewall") -> bytes:
    return _ustar(name, len(HIDDEN_RULE)) + _pad(HIDDEN_RULE)


def _patched(block: bytes, start: int, value: bytes, *, signed: bool = False) -> bytes:
    """Overwrite a header field and fix the checksum (unsigned or signed sum)."""
    buf = bytearray(block)
    buf[start : start + len(value)] = value
    fmt = "148b8x356b" if signed else "148B8x356B"
    checksum = 256 + sum(struct.unpack_from(fmt, bytes(buf)))
    buf[148:156] = b"%06o\x00 " % checksum
    return bytes(buf)


def _smuggled(*blocks: bytes) -> bytes:
    """network + system, then the raw blocks, then the end-of-archive blocks."""
    head, end = make_tar(base_entries(), fmt=tarfile.USTAR_FORMAT)
    return gz(head[:end] + b"".join(blocks) + bytes(1024))


def _rule_with_size_field(field: bytes, *, signed: bool = False) -> bytes:
    header = _patched(_ustar("etc/config/firewall", 0), 124, field, signed=signed)
    return header + _pad(HIDDEN_RULE)


HIDDEN = [
    pytest.param(
        lambda: _smuggled(_pax({"size": "-5"}), _rule_member()), id="pax_size_-5"
    ),
    pytest.param(
        lambda: _smuggled(_pax({"size": "-512"}), _rule_member()), id="pax_size_-512"
    ),
    pytest.param(
        lambda: _smuggled(_pax({"size": "0"}), _rule_member()),
        id="pax_size_0_with_data",
    ),
    pytest.param(
        lambda: _smuggled(_pax({"size": "+97"}), _rule_member()), id="pax_size_plus"
    ),
    pytest.param(
        lambda: _smuggled(_pax({"size": " 97"}), _rule_member()), id="pax_size_space"
    ),
    pytest.param(
        lambda: _smuggled(_pax({"size": "9_7"}), _rule_member()),
        id="pax_size_underscore",
    ),
    pytest.param(
        lambda: _smuggled(_pax({"size": "٩٧"}), _rule_member()),
        id="pax_size_arabic_digits",
    ),
    pytest.param(
        lambda: _smuggled(_pax({"size": "1" + "0" * 30}), _rule_member()),
        id="pax_size_huge",
    ),
    pytest.param(
        lambda: _smuggled(
            _pax({"path": "etc/config/firewall/"}), _rule_member("etc/x")
        ),
        id="pax_path_trailing_slash_on_file",
    ),
    pytest.param(
        lambda: _smuggled(
            _pax({"path": "etc/x", "GNU.sparse.name": "etc/config/firewall"}),
            _rule_member("etc/y"),
        ),
        id="pax_gnu_sparse_name",
    ),
    pytest.param(
        lambda: _smuggled(
            _pax({"path": "etc/config/firewall"}),
            _pax({"path": "etc/config/dhcp"}),
            _rule_member("etc/x"),
        ),
        id="two_pax_headers_in_a_row",
    ),
    pytest.param(
        lambda: _smuggled(
            _pax({"path": "etc/config/firewall"}, tarfile.XGLTYPE),
            _rule_member("etc/x"),
        ),
        id="global_pax_header",
    ),
    pytest.param(
        lambda: _smuggled(_pax({"size": "0"}, tarfile.XGLTYPE), _rule_member("etc/x")),
        id="global_pax_size",
    ),
    pytest.param(
        lambda: _smuggled(
            _rule_with_size_field(b"\x80" + len(HIDDEN_RULE).to_bytes(11, "big"))
        ),
        id="base256_size",
    ),
    pytest.param(
        lambda: _smuggled(_rule_with_size_field(b"\xff" * 12)),
        id="base256_negative_size",
    ),
    pytest.param(
        lambda: _smuggled(_rule_with_size_field(b"-0000000141\x00")),
        id="negative_octal_size",
    ),
    pytest.param(
        lambda: _smuggled(_rule_with_size_field(b"+0000000141\x00")),
        id="plus_octal_size",
    ),
    pytest.param(
        lambda: _smuggled(_rule_with_size_field(b"0000000141\x00x")),
        id="octal_size_with_garbage",
    ),
    pytest.param(
        lambda: _smuggled(
            _patched(
                _ustar("etc/config/firewall", len(HIDDEN_RULE)),
                99,
                b"\xe4",
                signed=True,
            )
            + _pad(HIDDEN_RULE)
        ),
        id="signed_checksum",
    ),
]


@pytest.mark.parametrize("build", HIDDEN)
def test_parser_differential_is_rejected(build: Callable[[], bytes]) -> None:
    report = validate_archive(build(), DEFAULT_ARCHIVE_LIMITS)
    assert report.ok is False, [m.name for m in report.members]
    assert report.error == ERR_INVALID
    assert first_code(report) in (ca.CODE_BAD_TAR_HEADER, ca.CODE_TRAILING_TAR_DATA)
    assert report.members == ()
    with pytest.raises(ArchiveError):
        extract_uci_texts(build(), DEFAULT_ARCHIVE_LIMITS)


def test_negative_pax_size_cannot_hide_a_member() -> None:
    """The review reproduction: firewall hidden behind a pax size of -5."""
    info = tarfile.TarInfo("etc/config/firewall")
    info.size = len(HIDDEN_RULE)
    info.pax_headers = {"size": "-5"}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for entry in base_entries():
            item = tarfile.TarInfo(entry.name)
            item.size = len(entry.data or b"")
            tf.addfile(item, io.BytesIO(entry.data or b""))
        tf.addfile(info, io.BytesIO(HIDDEN_RULE))
    assert b"EVIL" in buf.getvalue()

    report = validate_archive(gz(buf.getvalue()), DEFAULT_ARCHIVE_LIMITS)

    assert_rejected(report, ERR_INVALID, ca.CODE_BAD_TAR_HEADER)


@pytest.mark.parametrize(
    "entries",
    [
        pytest.param([E("etc/" + "l" * 150, b"long name")], id="gnu_longname"),
        pytest.param(
            [E("etc/ln", None, type=tarfile.SYMTYPE, linkname="config/" + "x" * 120)],
            id="gnu_longlink",
        ),
    ],
)
def test_gnu_long_names_stay_valid(entries: list[E]) -> None:
    report = validate_archive(archive([*base_entries(), *entries]))
    assert report.ok, report.findings


def test_pax_names_and_octal_variants_stay_valid() -> None:
    entries = [*base_entries(), E("etc/ünicode", b"x"), E("etc/" + "p" * 150, b"y")]
    raw, _ = make_tar(entries, fmt=tarfile.PAX_FORMAT)
    assert b"path=" in raw
    assert validate_archive(gz(raw)).ok

    # Space-terminated octal (old tar) and a full 12-digit field are legal.
    for size_field in (b"     141 \x00\x00\x00", b"000000000141"):
        report = validate_archive(_smuggled(_rule_with_size_field(size_field)))
        assert report.ok, (size_field, report.findings)
        assert "etc/config/firewall" in {m.name for m in report.members}
