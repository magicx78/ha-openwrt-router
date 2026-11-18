"""Version files: the ``.partial`` write never follows a planted link.

``_write_atomic`` opens ``<name>.partial`` with ``O_CREAT | O_EXCL`` (plus
``O_NOFOLLOW`` where the platform has it), mode 0o600. Something already at
that path is handled without following it:

* a symbolic link (dangling or not), a junction, a folder: refused with
  ``StorageError`` ``reason`` ``partial_not_regular``; the link target is
  never written; the store counts ``partial_refused``;
* a regular file of the same name (left by a crashed write of this very
  locator): removed and the write retried once with ``O_EXCL``.

Leftovers under other names never block a write (every version has a new
id) and the startup sweep deletes them.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest
from core_test_provider import start_env, stop_env
from core_testkit import ADMIN_ID, FakeDisks, user_actor

from custom_components.openwrt_router import version_store as vs
from custom_components.openwrt_router.core_errors import StorageError
from custom_components.openwrt_router.core_models import (
    PARTIAL_SUFFIX,
    BackupReason,
)

LOCATOR = "bkp_0123456789abcdef0123456789abcdef.uci"
ADMIN = user_actor(ADMIN_ID)


def _symlink_or_skip(target: str, link: str) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as err:  # Windows without privilege
        pytest.skip(f"cannot create a symbolic link here: {err}")


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


@pytest.fixture
def router_dir(tmp_path):
    path = tmp_path / "rtr"
    path.mkdir()
    return str(path)


def _partial(router_dir: str) -> str:
    return os.path.join(router_dir, LOCATOR) + PARTIAL_SUFFIX


@pytest.mark.parametrize("nofollow", [True, False], ids=["nofollow", "fallback"])
def test_symlink_partial_refused(router_dir, tmp_path, monkeypatch, nofollow):
    """A link at the .partial path is refused, its target never written.

    ``fallback`` = a platform without O_NOFOLLOW: O_EXCL alone refuses it.
    """
    if not nofollow:
        monkeypatch.setattr(vs, "_O_NOFOLLOW", 0)
    target = tmp_path / "victim.txt"
    target.write_bytes(b"keep")
    _symlink_or_skip(str(target), _partial(router_dir))

    with pytest.raises(StorageError) as err:
        vs._write_atomic(router_dir, LOCATOR, b"payload")
    assert err.value.details["reason"] == "partial_not_regular"
    assert target.read_bytes() == b"keep"
    assert not os.path.exists(os.path.join(router_dir, LOCATOR))
    assert os.path.islink(_partial(router_dir))  # left alone, not followed


def test_dangling_symlink_refused(router_dir, tmp_path):
    target = tmp_path / "created-through-link.txt"
    _symlink_or_skip(str(target), _partial(router_dir))
    with pytest.raises(StorageError) as err:
        vs._write_atomic(router_dir, LOCATOR, b"payload")
    assert err.value.details["reason"] == "partial_not_regular"
    assert not target.exists()  # O_CREAT never created the link target


def test_folder_partial_refused(router_dir):
    os.mkdir(_partial(router_dir))
    with pytest.raises(StorageError) as err:
        vs._write_atomic(router_dir, LOCATOR, b"payload")
    assert err.value.details["reason"] == "partial_not_regular"
    assert os.path.isdir(_partial(router_dir))


def test_same_name_leftover_replaced(router_dir):
    """A regular leftover of a crashed write of this locator does not block."""
    with open(_partial(router_dir), "wb") as handle:
        handle.write(b"half a file from a crash")
    path = vs._write_atomic(router_dir, LOCATOR, b"payload")
    assert _read(path) == b"payload"
    assert not os.path.exists(_partial(router_dir))


def test_write_is_exclusive_0600(router_dir):
    path = vs._write_atomic(router_dir, LOCATOR, b"payload")
    assert _read(path) == b"payload"
    assert not os.path.exists(_partial(router_dir))
    if sys.platform != "win32":  # Windows has no POSIX modes
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def test_put_link_refused(disks, tmp_path, monkeypatch):
    """Through the API: defined error, counted, the link target untouched."""
    env = await start_env(disks, tmp_path)
    backup_id = "bkp_" + "ab" * 16
    monkeypatch.setattr(
        vs, "new_id", lambda prefix: backup_id if prefix == "bkp_" else "x"
    )
    router_dir = os.path.join(env.versions._root, env.rid)
    os.makedirs(router_dir, exist_ok=True)
    target = tmp_path / "victim.txt"
    target.write_bytes(b"keep")
    link = os.path.join(router_dir, f"{backup_id}.archive{PARTIAL_SUFFIX}")
    _symlink_or_skip(str(target), link)

    with pytest.raises(StorageError) as err:
        await env.api.async_create_backup(
            env.rid, reason=BackupReason.MANUAL, actor=ADMIN
        )
    assert err.value.details["reason"] == "partial_not_regular"
    assert err.value.router_id == env.rid
    assert target.read_bytes() == b"keep"
    assert env.versions.stats["partial_refused"] == 1
    assert env.versions.records(env.rid) == ()
    await stop_env(env)
