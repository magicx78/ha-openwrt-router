"""test_subprocess_lifecycle.py — F4 (v1.18.0) leak-free subprocess helper.

Verifies that ``_safe_subprocess_exec`` cleans up the child process and its
file descriptors on every termination path:

  * success                 — exit 0, stdout/stderr returned
  * non-zero returncode     — pass-through, no kill
  * timeout                 — wait_for raises, helper terminates → kills the proc
  * spawn failure           — OSError before a Process exists
  * cancel mid-flight       — outer task is cancelled, proc still gets killed
  * binary output           — NUL-bytes survive the round trip
  * detached (nohup) helper — wrapping is correct, lifecycle still leak-free
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.api import (  # noqa: E402
    SUBPROCESS_RC_FAILED_TO_SPAWN,
    SUBPROCESS_RC_TIMEOUT,
    OpenWrtAPI,
    _safe_subprocess_exec,
)


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _make_proc(
    *,
    returncode: int | None = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
    communicate_raises: BaseException | None = None,
    wait_returns_after_terminate: bool = True,
) -> MagicMock:
    """Build a mock asyncio.subprocess.Process.

    The mock tracks .terminate() / .kill() / .wait() invocations so tests can
    assert the cleanup path was actually exercised.
    """
    proc = MagicMock()

    # mutable holder so .communicate() can flip returncode AFTER the await
    state = {"rc": returncode}

    async def _communicate() -> tuple[bytes, bytes]:
        if communicate_raises is not None:
            raise communicate_raises
        # successful communicate: process is now reaped
        proc.returncode = 0 if returncode is None else returncode
        return stdout, stderr

    async def _wait() -> int:
        # simulate proc dying after terminate()
        if wait_returns_after_terminate:
            proc.returncode = state["rc"] if state["rc"] is not None else 0
        return proc.returncode or 0

    proc.communicate = AsyncMock(side_effect=_communicate)
    proc.wait = AsyncMock(side_effect=_wait)
    proc.terminate = MagicMock()
    proc.kill = MagicMock()
    # Initially still running (None) — flip on communicate().
    proc.returncode = None
    return proc


# ---------------------------------------------------------------------------
# 1. success — straight-through
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safe_subprocess_exec_success_returns_stdout_str():
    proc = _make_proc(returncode=0, stdout=b"hello\n", stderr=b"")
    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc),
    ):
        rc, stdout, stderr = await _safe_subprocess_exec(
            ["true"], timeout=5.0, binary=False
        )

    assert rc == 0
    assert stdout == "hello\n"
    assert stderr == b""
    proc.terminate.assert_not_called()
    proc.kill.assert_not_called()


@pytest.mark.asyncio
async def test_safe_subprocess_exec_success_passthrough_nonzero_rc():
    """rc != 0 is returned verbatim — caller decides how to handle it."""
    proc = _make_proc(returncode=2, stdout=b"out", stderr=b"err")
    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc),
    ):
        rc, stdout, stderr = await _safe_subprocess_exec(
            ["false"], timeout=5.0, binary=False
        )

    assert rc == 2
    assert stdout == "out"
    assert stderr == b"err"
    # No cleanup needed — proc already exited cleanly.
    proc.terminate.assert_not_called()
    proc.kill.assert_not_called()


# ---------------------------------------------------------------------------
# 2. timeout — wait_for raises, helper terminates and kills
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safe_subprocess_exec_timeout_kills_and_reaps():
    """On wait_for timeout the helper must terminate, then wait, then kill —
    and return the SUBPROCESS_RC_TIMEOUT sentinel."""
    proc = _make_proc(
        returncode=None,  # still running
        communicate_raises=asyncio.TimeoutError(),
    )
    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc),
    ):
        rc, stdout, stderr = await _safe_subprocess_exec(
            ["sleep", "999"], timeout=0.01, binary=False
        )

    assert rc == SUBPROCESS_RC_TIMEOUT
    assert stdout == ""
    assert stderr == b"timeout"
    proc.terminate.assert_called_once()
    # If wait() returned cleanly after terminate, kill is NOT needed.
    proc.kill.assert_not_called()


@pytest.mark.asyncio
async def test_safe_subprocess_exec_timeout_escalates_to_kill():
    """If proc ignores SIGTERM (wait_for(wait()) also times out) → SIGKILL."""
    proc = _make_proc(returncode=None, communicate_raises=asyncio.TimeoutError())

    # Override .wait so the FIRST call times out, the SECOND succeeds.
    call_count = {"n": 0}

    async def _wait_two_phases() -> int:
        call_count["n"] += 1
        if call_count["n"] == 1:
            await asyncio.sleep(10)  # will be wait_for-timeouted
        proc.returncode = -9
        return -9

    proc.wait = AsyncMock(side_effect=_wait_two_phases)

    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc),
    ):
        rc, _stdout, _stderr = await _safe_subprocess_exec(
            ["sleep", "999"], timeout=0.01, binary=False
        )

    assert rc == SUBPROCESS_RC_TIMEOUT
    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()


# ---------------------------------------------------------------------------
# 3. spawn failure — never had a Process, return sentinel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safe_subprocess_exec_spawn_oserror_returns_failed_sentinel():
    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=FileNotFoundError("sshpass not installed")),
    ):
        rc, stdout, stderr = await _safe_subprocess_exec(
            ["sshpass", "-e", "ssh"], timeout=5.0, binary=False
        )

    assert rc == SUBPROCESS_RC_FAILED_TO_SPAWN
    assert stdout == ""
    assert b"sshpass not installed" in stderr


@pytest.mark.asyncio
async def test_safe_subprocess_exec_spawn_valueerror_returns_failed_sentinel():
    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=ValueError("argv invalid")),
    ):
        rc, _stdout, _stderr = await _safe_subprocess_exec(
            ["", "-bad"], timeout=5.0, binary=False
        )
    assert rc == SUBPROCESS_RC_FAILED_TO_SPAWN


# ---------------------------------------------------------------------------
# 4. CancelledError — cleanup must run even when caller is cancelled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safe_subprocess_exec_cancel_mid_flight_kills_proc():
    """When the caller's task is cancelled while we're blocked in
    wait_for(communicate()), the helper's finally-block must still kill the
    child process."""
    proc = _make_proc(returncode=None)

    cancel_event = asyncio.Event()

    async def _slow_communicate() -> tuple[bytes, bytes]:
        # block until cancelled — simulates a long remote command
        await cancel_event.wait()
        return b"", b""

    proc.communicate = AsyncMock(side_effect=_slow_communicate)

    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc),
    ):
        task = asyncio.create_task(
            _safe_subprocess_exec(["sleep", "999"], timeout=10.0)
        )
        # Yield once so the task reaches the wait_for(communicate()) await.
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    # Cleanup must have run: terminate (and probably wait()) called.
    proc.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_safe_subprocess_exec_cancel_during_cleanup_still_kills():
    """A cancel that arrives DURING the post-terminate wait must still let
    the helper escalate to SIGKILL + final wait — no leaked process.

    Regression for the v1.18.0 release-gate finding: the first wait_for in
    the finally-block was previously not shielded, so a second cancel would
    abort the cleanup before SIGKILL.
    """
    # proc.wait raises CancelledError on the first call (simulates cancel
    # arriving during the post-terminate wait), then returns -9 on the
    # final reap.  We expect the helper to call kill() in between.
    proc = _make_proc(returncode=None, communicate_raises=asyncio.TimeoutError())

    wait_calls = {"n": 0}

    async def _wait_with_cancel_then_reap() -> int:
        wait_calls["n"] += 1
        if wait_calls["n"] == 1:
            # First wait (after SIGTERM) — caller cancel arrives here
            raise asyncio.CancelledError()
        # Second wait (after SIGKILL) — proc reaped
        proc.returncode = -9
        return -9

    proc.wait = AsyncMock(side_effect=_wait_with_cancel_then_reap)

    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc),
    ):
        with pytest.raises(asyncio.CancelledError):
            await _safe_subprocess_exec(
                ["sleep", "999"], timeout=0.01, binary=False
            )

    # Even with a cancel mid-cleanup, the helper must have escalated past
    # terminate to SIGKILL and the final wait — proof that no zombie is left.
    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()
    assert wait_calls["n"] == 2  # both wait phases executed


# ---------------------------------------------------------------------------
# 5. binary output — NUL-bytes survive
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safe_subprocess_exec_binary_preserves_nul_bytes():
    """brforward output contains \\x00 — must not be UTF-8-decoded."""
    payload = bytes(range(256))  # all bytes 0..255 incl. NULs
    proc = _make_proc(returncode=0, stdout=payload, stderr=b"")
    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc),
    ):
        rc, stdout, _stderr = await _safe_subprocess_exec(
            ["cat", "/sys/class/net/br-lan/brforward"],
            timeout=5.0,
            binary=True,
        )

    assert rc == 0
    assert isinstance(stdout, bytes)
    assert stdout == payload  # exact round-trip, NUL bytes preserved


# ---------------------------------------------------------------------------
# 6. _run_ssh_detached — wrapping correctness + lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_ssh_detached_wraps_with_nohup_devnull():
    """Verify the detached helper wraps remote_cmd with nohup + </dev/null
    so the SSH connection can close while the remote process keeps running."""
    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="pw",
        session=MagicMock(),
        protocol="http",
    )
    proc = _make_proc(returncode=0, stdout=b"", stderr=b"")
    seen_cmd: list[str] = []

    async def _capture_spawn(*cmd, **kwargs):
        seen_cmd.extend(cmd)
        return proc

    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_capture_spawn),
    ):
        rc, _out, _err = await api._run_ssh_detached(
            "opkg update > /tmp/opkg.log 2>&1", timeout=10.0
        )

    assert rc == 0
    # The remote command (last argv element) must contain nohup + </dev/null
    # AND the caller's command verbatim.
    remote = seen_cmd[-1]
    assert remote.startswith("nohup sh -c '")
    assert "</dev/null" in remote
    assert remote.endswith(" &")
    assert "opkg update > /tmp/opkg.log 2>&1" in remote


@pytest.mark.asyncio
async def test_run_ssh_detached_timeout_cleans_up():
    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="pw",
        session=MagicMock(),
        protocol="http",
    )
    proc = _make_proc(returncode=None, communicate_raises=asyncio.TimeoutError())
    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc),
    ):
        rc, _out, _err = await api._run_ssh_detached("sleep 999", timeout=0.01)
    assert rc == SUBPROCESS_RC_TIMEOUT
    proc.terminate.assert_called_once()


@pytest.mark.asyncio
async def test_run_ssh_detached_handles_singlequotes_in_remote_cmd():
    """A remote_cmd that contains single quotes (e.g. opkg's grep filter)
    must be passed to the remote bash as ONE token to `sh -c`.

    Regression for the v1.18.0 release-gate finding: the previous wrapper
    naively concatenated f"nohup sh -c '{remote_cmd}' ..." which broke the
    surrounding quoting whenever remote_cmd contained ' itself.

    We verify by:
      1. parsing the wrapper string with shlex to confirm `sh -c` receives
         the original remote_cmd verbatim as a single argument,
      2. asserting the wrapper still contains the required nohup / detach
         decorations.
    """
    import shlex as _shlex

    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="pw",
        session=MagicMock(),
        protocol="http",
    )

    # The exact opkg "system update" filter that broke the old wrapper.
    nasty_remote_cmd = (
        "opkg update && opkg upgrade $(opkg list-upgradable | "
        "grep -v -E '^addon-|^luci-' | cut -d' ' -f1) "
        "> /tmp/opkg_update.log 2>&1"
    )

    proc = _make_proc(returncode=0, stdout=b"", stderr=b"")
    seen_cmd: list[str] = []

    async def _capture_spawn(*cmd, **kwargs):
        seen_cmd.extend(cmd)
        return proc

    with patch(
        "custom_components.openwrt_router.api.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_capture_spawn),
    ):
        rc, _out, _err = await api._run_ssh_detached(nasty_remote_cmd, timeout=10.0)

    assert rc == 0

    # Last argv element is what the remote bash will parse.
    remote = seen_cmd[-1]

    # Required decorations still in place
    assert remote.startswith("nohup sh -c ")
    assert "</dev/null" in remote
    assert ">/dev/null 2>&1" in remote
    assert remote.endswith(" &")

    # Now the critical bit: parse the wrapper as a posix shell would.
    # After splitting, the third token (sh, -c, <cmd>) must be exactly
    # nasty_remote_cmd.  If the old wrapper were used, shlex would either
    # raise ValueError (unterminated quote) or split the cmd into multiple
    # tokens — both would fail this assertion.
    tokens = _shlex.split(remote, posix=True)
    assert tokens[0] == "nohup"
    assert tokens[1] == "sh"
    assert tokens[2] == "-c"
    assert tokens[3] == nasty_remote_cmd, (
        f"sh -c argument was mangled by quoting.\n"
        f"  expected: {nasty_remote_cmd!r}\n"
        f"  got:      {tokens[3]!r}"
    )
    # Trailing tokens after the cmd: redirect tokens + &
    assert "</dev/null" in tokens
    assert "&" in tokens
