"""Bounded conntrack fallback of ``api.get_active_connections`` (1.49.1).

Traffic Analytics plan 2026-11-20, question F2 / risk 3: the fallback over
``/proc/net/nf_conntrack`` read the whole table without a limit. It is now
bounded in time, bytes and lines, and a cut-off count says so
(``last_conntrack_count_complete``), so no caller takes it for the full
number. Mocks only: no router.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from custom_components.openwrt_router import api as api_module
from custom_components.openwrt_router.api import OpenWrtAPI, OpenWrtMethodNotFoundError
from custom_components.openwrt_router.const import (
    CONNTRACK_TABLE_MAX_BYTES,
    CONNTRACK_TABLE_MAX_LINES,
)
from custom_components.openwrt_router.net_engine import infra_snapshot
from custom_components.openwrt_router.sensor import SENSOR_DESCRIPTIONS

COUNT_FILE = "/proc/sys/net/netfilter/nf_conntrack_count"
TABLE = "/proc/net/nf_conntrack"
LINE = (
    "ipv4     2 tcp      6 7440 ESTABLISHED src=192.0.2.10 dst=198.51.100.7 "
    "sport=51000 dport=443 packets=10 bytes=1000 [ASSURED] mark=0 zone=0 use=2\n"
)


def make_api(table: str | BaseException, count: Any = None) -> OpenWrtAPI:
    api = OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username="root",
        password="test",
        session=MagicMock(),
        protocol="http",
    )

    async def call(obj: str, method: str, params: dict[str, Any], *a: Any) -> Any:
        if params["path"] == COUNT_FILE:
            if count is None:
                raise OpenWrtMethodNotFoundError("no count file")
            return {"data": count}
        if isinstance(table, BaseException):
            raise table
        return {"data": table}

    api._call = AsyncMock(side_effect=call)  # type: ignore[method-assign]
    return api


async def test_count_file_is_complete() -> None:
    api = make_api("", count="1234\n")
    assert await api.get_active_connections() == 1234
    assert api.last_conntrack_count_source == "count_file"
    assert api.last_conntrack_count_complete is True


async def test_a_small_full_table_is_complete() -> None:
    api = make_api(LINE * 3)
    assert await api.get_active_connections() == 3
    assert api.last_conntrack_count_source == "table_scan"
    assert api.last_conntrack_count_complete is True


async def test_a_read_of_rpcds_procfs_size_is_marked_cut_off() -> None:
    """rpcd returns at most 4 KiB of a procfs file: such a read is a lower bound."""
    table = (LINE * 40)[:4096]
    api = make_api(table)
    count = await api.get_active_connections()
    assert count == table.count("\n") + 1
    assert api.last_conntrack_count_complete is False


async def test_a_huge_table_is_bounded_in_bytes_and_lines() -> None:
    api = make_api(LINE * (CONNTRACK_TABLE_MAX_LINES * 4))
    count = await api.get_active_connections()
    assert count <= CONNTRACK_TABLE_MAX_LINES
    assert count * len(LINE) <= CONNTRACK_TABLE_MAX_BYTES + len(LINE)
    assert api.last_conntrack_count_complete is False
    assert api.last_conntrack_count_source == "table_scan"


async def test_a_slow_table_read_times_out_as_no_count(monkeypatch) -> None:
    monkeypatch.setattr(api_module, "CONNTRACK_TABLE_TIMEOUT_S", 0.01)
    api = make_api("")

    async def slow(obj: str, method: str, params: dict[str, Any], *a: Any) -> Any:
        if params["path"] == COUNT_FILE:
            raise OpenWrtMethodNotFoundError("no count file")
        await asyncio.sleep(1)
        return {"data": LINE}

    api._call = AsyncMock(side_effect=slow)  # type: ignore[method-assign]
    assert await api.get_active_connections() == 0
    assert api.last_conntrack_count_source is None
    assert api.last_conntrack_count_complete is None


async def test_no_source_is_no_count() -> None:
    api = make_api(OpenWrtMethodNotFoundError("blocked"))
    assert await api.get_active_connections() == 0
    assert api.last_conntrack_count_source is None
    assert api.last_conntrack_count_complete is None


def _sensor_value(data: Any) -> Any:
    (desc,) = [d for d in SENSOR_DESCRIPTIONS if d.key == "active_connections"]
    return desc.value_fn(data)


def test_a_cut_off_count_is_unknown_for_the_sensor_and_ni() -> None:
    cut = SimpleNamespace(active_connections=27, active_connections_complete=False)
    full = SimpleNamespace(active_connections=27, active_connections_complete=True)
    assert _sensor_value(cut) is None
    assert _sensor_value(full) == 27
    assert infra_snapshot(cut).conntrack is None
    assert infra_snapshot(full).conntrack == 27


# --- 1.49.3 review: F1 (truncation of rpcd's single read) and F2 (no count) -----


def _rpcd_read(table: str, size: int = 4096) -> str:
    """rpcd's one read() of procfs: the kernel hands out whole lines only."""
    out = ""
    for line in table.splitlines(keepends=True):
        if len(out) + len(line) > size:
            break
        out += line
    return out


async def test_f1_a_whole_line_read_below_4000_bytes_is_still_cut_off() -> None:
    """Before: ends on a newline and < 4000 bytes, so it counted as complete."""
    long_line = LINE.replace("use=2", "use=2 " + "x" * 160)  # about 300 bytes
    table = _rpcd_read(long_line * 100)
    assert table.endswith("\n") and len(table) < 4000
    api = make_api(table)
    await api.get_active_connections()
    assert api.last_conntrack_count_complete is False


async def test_f1_a_read_with_room_for_another_line_is_complete() -> None:
    table = LINE * 20  # about 3 KB: the next line would still have fitted
    assert len(table) < 4096 - 600
    api = make_api(table)
    assert await api.get_active_connections() == 20
    assert api.last_conntrack_count_complete is True

