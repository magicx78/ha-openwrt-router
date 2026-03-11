#!/usr/bin/env python3
"""Dev start script: syncs custom_components and launches Home Assistant."""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
SRC = ROOT / "custom_components" / "openwrt_router"
DST = ROOT / "ha_config" / "custom_components" / "openwrt_router"

print(f"Syncing {SRC} -> {DST}")
if DST.exists():
    shutil.rmtree(DST)
shutil.copytree(SRC, DST)
print("Sync done. Starting Home Assistant on http://localhost:8123 ...")

venv_hass = ROOT / "venv" / "Scripts" / "hass"
result = subprocess.run(
    [str(venv_hass), "--config", str(ROOT / "ha_config"), "-v"],
    cwd=str(ROOT),
)
sys.exit(result.returncode)
