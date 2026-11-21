"""MAC addresses inside free text, also glued to an underscore (1.49.1).

Every module that masks MACs in free text must catch them in all common
forms (colon, dash, Cisco dots, bare 12 hex), also when they hang directly
at an underscore (``sta_<mac>``, ``dev_<12 hex>``). Longer hex runs (ids,
pseudonyms, digests) stay. Only invented MACs from the locally administered
range are used.
"""

from __future__ import annotations

import pytest

from custom_components.openwrt_router.rf_privacy import mask_rf_output
from custom_components.openwrt_router.security_model import mask_identities

GLUED = [
    "sta_02:00:5e:00:53:01",
    "dev_02005e005301",
    "x_02-00-5e-00-53-01_y",
    "02:00:5e:00:53:01_ap",
    "id_0200.5e00.5301",
    "plain 02005e005301 text",
]
KEPT = [
    "sec_0123456789abcdef",  # 16 hex pseudonym part
    "sum 0123456789abcdef0123",  # 20 hex
    "rtr_" + "1" * 32,
]
PARTS = ("5e:00:53:01", "5e005301", "5e-00-53-01", "5e00.5301")


def leaked(text: str) -> bool:
    return any(p in text.lower() for p in PARTS)


@pytest.mark.parametrize("text", GLUED)
def test_wifi_rf_masks_glued_macs(text: str) -> None:
    for key in (bytes(32), None):
        assert not leaked(mask_rf_output({"note": text}, key=key)["note"])


@pytest.mark.parametrize("text", GLUED)
def test_security_center_masks_glued_macs(text: str) -> None:
    assert not leaked(mask_identities({"note": text})["note"])


@pytest.mark.parametrize("text", KEPT)
def test_longer_hex_runs_stay(text: str) -> None:
    assert mask_identities({"note": text})["note"] == text
    assert mask_rf_output({"note": text}, key=None)["note"] == text
