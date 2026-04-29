"""v1.17.9 Sicherheits-Regression: sshpass darf das Passwort nicht via CLI exponieren.

Background: Bis v1.17.8 wurden SSH-Fallback-Calls als
``sshpass -p <password> ssh ...`` ausgeführt. Das Passwort landete damit in
``/proc/<pid>/cmdline`` und war für jeden Prozess via ``ps aux`` lesbar.

v1.17.9 stellt auf ``sshpass -e`` um — das Passwort wird via SSHPASS-Env-Variable
übergeben, nicht auf der Kommandozeile.

Diese Tests stellen sicher dass:
  1. Kein ``-p <password>`` Pattern mehr im Quellcode existiert
  2. Die Helper-Methode ``_ssh_env()`` existiert und SSHPASS korrekt setzt
  3. ``_build_ssh_cmd()`` den ``-e``-Flag liefert (nicht ``-p``)
"""
from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest

from custom_components.openwrt_router.api import OpenWrtAPI


_API_PATH = Path(
    inspect.getfile(OpenWrtAPI)
).resolve()


def test_no_sshpass_minus_p_in_source():
    """No ``sshpass -p`` (or ``"-p", self._password``) anywhere in api.py."""
    src = _API_PATH.read_text(encoding="utf-8")
    # The literal `-p` flag right next to the sshpass binary is the danger
    # pattern. We accept the strings only as part of comments/docstrings.
    code_lines = [
        ln for ln in src.splitlines()
        if not ln.lstrip().startswith(("#", '"', "'"))
    ]
    code = "\n".join(code_lines)

    # Direct argv form
    assert '"-p", self._password' not in code, (
        "Found insecure 'sshpass -p <password>' inline pattern"
    )
    assert "'-p', self._password" not in code, (
        "Found insecure 'sshpass -p <password>' inline pattern (single-quoted)"
    )
    # Multi-line form
    assert '"sshpass",\n            "-p",' not in src, (
        "Found insecure multi-line sshpass -p pattern"
    )


def test_ssh_env_helper_exists():
    """OpenWrtAPI must expose _ssh_env() returning a dict with SSHPASS set."""
    assert hasattr(OpenWrtAPI, "_ssh_env"), "OpenWrtAPI._ssh_env() missing"
    api = OpenWrtAPI(
        host="10.10.10.1",
        port=80,
        username="root",
        password="hunter2",
        session=None,
    )
    env = api._ssh_env()
    assert isinstance(env, dict)
    assert env.get("SSHPASS") == "hunter2"
    # Returns a fresh dict each call — mutating one must not pollute another
    env["FOO"] = "bar"
    env2 = api._ssh_env()
    assert "FOO" not in env2
    # Inherits real environment so PATH etc. survive
    if "PATH" in os.environ:
        assert "PATH" in env


def test_build_ssh_cmd_uses_dash_e_flag():
    """_build_ssh_cmd must use 'sshpass -e' for password auth, not '-p <pw>'."""
    api = OpenWrtAPI(
        host="10.10.10.1",
        port=80,
        username="root",
        password="hunter2",
        session=None,
    )
    # Default state: password auth (not key auth)
    cmd = api._build_ssh_cmd("uptime")
    assert cmd[0] == "sshpass"
    assert cmd[1] == "-e", f"Expected -e flag, got {cmd[1]!r}"
    assert "hunter2" not in cmd, (
        f"Password leaked into argv: {cmd!r}"
    )
    assert "-p" not in cmd[:3], (
        f"Insecure -p flag still present: {cmd!r}"
    )


def test_build_ssh_cmd_key_auth_excludes_sshpass():
    """When key-auth is enabled, no sshpass wrapper should be used."""
    api = OpenWrtAPI(
        host="10.10.10.1",
        port=80,
        username="root",
        password="hunter2",
        session=None,
    )
    api._ssh_use_key = True
    cmd = api._build_ssh_cmd("uptime")
    assert cmd[0] == "ssh", f"Key-auth path should start with ssh, got {cmd!r}"
    assert "sshpass" not in cmd
    assert "hunter2" not in cmd


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
