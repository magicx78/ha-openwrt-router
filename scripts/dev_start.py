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

# Support both Linux (bin/) and Windows (Scripts/) venv layouts
venv_hass = ROOT / "venv" / "bin" / "hass"
if not venv_hass.exists():
    venv_hass = ROOT / "venv" / "Scripts" / "hass"

if not venv_hass.exists():
    print("ERROR: hass not found in venv. Run: venv/bin/pip install homeassistant")
    sys.exit(1)

result = subprocess.run(
    [str(venv_hass), "--config", str(ROOT / "ha_config"), "-v"],
    cwd=str(ROOT),
)
sys.exit(result.returncode)
