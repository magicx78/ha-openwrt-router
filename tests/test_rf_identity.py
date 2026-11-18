"""RF identity uses the Core router id (rf_identity.py, rf_conflicts adapter)."""

from __future__ import annotations

import pytest

from custom_components.openwrt_router.channel_plan import Radio
from custom_components.openwrt_router.core_models import (
    ROUTER_ID_PREFIX,
    default_router_id,
    new_id,
)
from custom_components.openwrt_router.rf_conflicts import (
    RadioRef,
    from_channel_plan_radio,
)
from custom_components.openwrt_router.rf_identity import radio_ref, require_router_id

R1 = default_router_id("e1")
# After an adoption the router keeps its OLD id: it is not derivable from
# the current entry id, so RF must take it from the registry.
ADOPTED = new_id(ROUTER_ID_PREFIX)


def _radio(entry_id="e1", phy="phy0"):
    return Radio(
        entry_id=entry_id,
        router="AP 1",
        phy=phy,
        band="2.4g",
        channel=6,
        width=20,
        center=6,
        backhaul=False,
    )


class TestRequireRouterId:
    def test_accepts_core_router_ids(self):
        assert require_router_id(R1) == R1
        assert require_router_id(ADOPTED) == ADOPTED

    @pytest.mark.parametrize(
        "value",
        ["e1", "", "rtr_", "rtr_XYZ", "rtr_" + "A" * 32, "evt_" + "a" * 32, None, 7],
    )
    def test_refuses_everything_else(self, value):
        with pytest.raises(ValueError):
            require_router_id(value)


class TestRadioRef:
    def test_builds_a_validated_ref(self):
        ref = radio_ref(R1, "radio0")
        assert ref == RadioRef(R1, "radio0")
        assert str(ref) == f"{R1}/radio0"

    @pytest.mark.parametrize("radio", ["", "  ", None, 3, "radio0/x"])
    def test_refuses_bad_radio_keys(self, radio):
        with pytest.raises(ValueError):
            radio_ref(R1, radio)

    def test_refuses_entry_ids_as_router(self):
        with pytest.raises(ValueError):
            radio_ref("e1", "radio0")


class TestChannelPlanAdapter:
    def test_router_key_is_the_given_core_id_not_the_entry_id(self):
        view = from_channel_plan_radio(_radio(), router_id=ADOPTED)
        assert view.router_key == ADOPTED
        assert view.router_key != default_router_id("e1")
        assert view.radio_key == "phy0"

    def test_router_id_is_required(self):
        with pytest.raises(TypeError):
            from_channel_plan_radio(_radio())  # type: ignore[call-arg]

    def test_entry_id_is_refused_as_router_id(self):
        with pytest.raises(ValueError):
            from_channel_plan_radio(_radio(), router_id="e1")
