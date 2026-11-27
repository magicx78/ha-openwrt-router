"""Self-Healing, package X (1.53.0): review nits e and f.

* e the session hook that fails a run for a stray ``MagicMock`` directory
  also says so where one looks: a section naming the directory and the
  final summary line (which read "N passed" before);
* f the option text says what the module does in plain words: it records
  and analyses incidents, shows recommendations and never changes a
  router (no "recommends (Observe mode)").

The first test runs pytest in a child process inside ``tmp_path``; the
stray directory is created there and removed with it.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

from custom_components.openwrt_router.const import OPTION_SELF_HEALING_ENABLED

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "custom_components" / "openwrt_router"


def test_a_stray_directory_is_named_in_the_summary(tmp_path: pathlib.Path) -> None:
    (tmp_path / "MagicMock").mkdir()
    (tmp_path / "test_ok.py").write_text("def test_ok():\n    assert True\n")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT / "tests"), str(ROOT), env.get("PYTHONPATH", "")]
    )
    env.pop("PYTEST_ADDOPTS", None)
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "conftest",
            "-p",
            "no:cacheprovider",
            "-q",
            "--rootdir",
            str(tmp_path),
            "test_ok.py",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    out = run.stdout + run.stderr
    assert run.returncode == 1, out
    stray = str(tmp_path / "MagicMock")
    assert stray in out
    final = [line for line in out.splitlines() if " in " in line and "passed" in line]
    assert final, out
    assert "stray" in final[-1].lower(), final[-1]
    assert "run failed" in out.lower()


def _option_texts() -> tuple[str, str, str]:
    texts = []
    for name in ("strings.json", "translations/en.json", "translations/de.json"):
        data = json.loads((COMPONENT / name).read_text(encoding="utf-8"))
        texts.append(
            data["options"]["step"]["init"]["data_description"][
                OPTION_SELF_HEALING_ENABLED
            ]
        )
    return texts[0], texts[1], texts[2]


def test_the_option_text_is_plain() -> None:
    en, en2, de = _option_texts()
    assert en == en2
    for gone in ("Observe mode", "recommends", "(Observe"):
        assert gone not in en, gone
    for gone in ("Modus Observe", "gibt nur Empfehlungen"):
        assert gone not in de, gone
    for needed in (
        "Records and analyses",
        "shows recommendations",
        "never changes a router",
        "API",
    ):
        assert needed in en, needed
    for needed in ("Zeichnet", "analysiert", "zeigt Empfehlungen", "ändert nie"):
        assert needed in de, needed
