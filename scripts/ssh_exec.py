#!/usr/bin/env python3
"""SSH execution script for the ssh-exec skill.

Usage:
    python3 scripts/ssh_exec.py <alias> <command> [command2] [command3] ...

Output:
    JSON with validation results and step outputs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

PROFILES_PATH = Path.home() / ".config" / "ssh-profiles.json"
SSH_DIR = Path.home() / ".ssh"
COMMAND_TIMEOUT = 30  # seconds per command


def _load_profiles() -> dict[str, Any] | None:
    """Load SSH profiles from config file. Returns None if file missing."""
    if not PROFILES_PATH.exists():
        return None
    try:
        with PROFILES_PATH.open() as f:
            return json.load(f)
    except json.JSONDecodeError:
        return None


def _find_profile(profiles: list[dict], alias: str) -> dict | None:
    """Find a profile by alias (case-insensitive)."""
    for p in profiles:
        if p.get("alias", "").lower() == alias.lower():
            return p
    return None


def _check_octal(path: Path, expected: int) -> tuple[bool, str]:
    """Check file/dir permissions. Returns (ok, actual_str)."""
    try:
        mode = oct(path.stat().st_mode)[-3:]
        return mode == str(expected), mode
    except FileNotFoundError:
        return False, "missing"


def validate(alias: str) -> tuple[dict[str, Any], dict | None]:
    """Run all validation checks. Returns (validation_dict, profile_or_None)."""
    checks: list[dict[str, Any]] = []
    profile = None

    # 1. Profiles file exists
    if not PROFILES_PATH.exists():
        checks.append({
            "name": "Profiles file",
            "status": "error",
            "value": f"{PROFILES_PATH} not found",
        })
        return {
            "status": "error",
            "checks": checks,
            "tips": [
                "Use the ssh-pairing skill to create your SSH profile.",
                f"Or create {PROFILES_PATH} manually with the required fields.",
            ],
        }, None

    checks.append({"name": "Profiles file", "status": "ok"})

    # 2. Load profiles
    raw = _load_profiles()
    if raw is None:
        checks.append({"name": "Profiles parse", "status": "error", "value": "Invalid JSON"})
        return {"status": "error", "checks": checks, "tips": [f"Check {PROFILES_PATH} for syntax errors."]}, None

    profiles_list = raw if isinstance(raw, list) else raw.get("profiles", [])
    available = [p.get("alias", "?") for p in profiles_list]

    # 3. Alias exists
    profile = _find_profile(profiles_list, alias)
    if profile is None:
        checks.append({
            "name": "Profile exists",
            "status": "error",
            "value": f"'{alias}' not found. Available: {available}",
        })
        return {
            "status": "error",
            "checks": checks,
            "tips": [f"Available aliases: {available}"],
        }, None

    checks.append({"name": "Profile exists", "status": "ok", "value": alias})

    # 4. Required fields
    missing = [f for f in ("host", "user", "port", "keyfile") if not profile.get(f)]
    if missing:
        checks.append({
            "name": "Required fields",
            "status": "error",
            "value": f"Missing: {missing}",
        })
        return {"status": "error", "checks": checks, "tips": [f"Add {missing} to the profile."]}, None

    checks.append({"name": "Required fields", "status": "ok"})

    # 5. SSH key exists
    keyfile = Path(profile["keyfile"]).expanduser()
    if not keyfile.exists():
        checks.append({
            "name": "SSH key found",
            "status": "error",
            "value": f"{keyfile} not found",
        })
        return {
            "status": "error",
            "checks": checks,
            "tips": [
                f"Generate key: ssh-keygen -t ed25519 -f {keyfile} -N '' -q",
                f"Authorize: ssh-copy-id -i {keyfile}.pub {profile['user']}@{profile['host']}",
            ],
        }, None

    checks.append({"name": "SSH key found", "status": "ok"})

    # 6. Key permissions (warn if not 600)
    key_ok, key_mode = _check_octal(keyfile, 600)
    checks.append({
        "name": "Key permissions",
        "status": "ok" if key_ok else "warn",
        "value": key_mode,
    })
    if not key_ok:
        checks[-1]["tip"] = f"chmod 600 {keyfile}"

    # 7. ~/.ssh permissions (warn if not 700)
    ssh_ok, ssh_mode = _check_octal(SSH_DIR, 700)
    if SSH_DIR.exists():
        checks.append({
            "name": "SSH dir permissions",
            "status": "ok" if ssh_ok else "warn",
            "value": ssh_mode,
        })
        if not ssh_ok:
            checks[-1]["tip"] = f"chmod 700 {SSH_DIR}"

    overall = "ok" if all(c["status"] in ("ok", "warn") for c in checks) else "error"
    return {"status": overall, "checks": checks}, profile


def run_commands(profile: dict, commands: list[str]) -> list[dict[str, Any]]:
    """Run commands sequentially via SSH. Stops on first failure."""
    steps: list[dict[str, Any]] = []
    keyfile = str(Path(profile["keyfile"]).expanduser())
    host = profile["host"]
    user = profile["user"]
    port = str(profile["port"])

    for cmd in commands:
        ssh_cmd = [
            "ssh",
            "-i", keyfile,
            "-p", port,
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={COMMAND_TIMEOUT}",
            f"{user}@{host}",
            cmd,
        ]
        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT,
            )
            step = {
                "command": cmd,
                "stdout": result.stdout.rstrip("\n"),
                "stderr": result.stderr.rstrip("\n"),
                "exit_code": result.returncode,
            }
            steps.append(step)
            if result.returncode != 0:
                break  # fail-fast
        except subprocess.TimeoutExpired:
            steps.append({
                "command": cmd,
                "stdout": "",
                "stderr": f"Timeout after {COMMAND_TIMEOUT}s",
                "exit_code": -1,
            })
            break
        except Exception as exc:  # noqa: BLE001
            steps.append({
                "command": cmd,
                "stdout": "",
                "stderr": str(exc),
                "exit_code": -1,
            })
            break

    return steps


def main() -> None:
    if len(sys.argv) < 3:
        print(json.dumps({
            "error": "Usage: ssh_exec.py <alias> <command> [command2] ...",
            "success": False,
        }, indent=2))
        sys.exit(1)

    alias = sys.argv[1]
    commands = sys.argv[2:]

    validation, profile = validate(alias)

    if validation["status"] == "error":
        output = {
            "alias": alias,
            "validation": validation,
            "success": False,
        }
        print(json.dumps(output, indent=2))
        sys.exit(1)

    steps = run_commands(profile, commands)
    success = bool(steps) and all(s["exit_code"] == 0 for s in steps)

    output = {
        "alias": alias,
        "validation": validation,
        "steps": steps,
        "success": success,
    }
    print(json.dumps(output, indent=2))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
