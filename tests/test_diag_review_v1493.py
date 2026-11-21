"""Network diagnostics review findings of 1.49.3 (D1-D3). Mocks only."""

from __future__ import annotations

from custom_components.openwrt_router.diag_score import (
    COMP_WAN,
    MIN_SCORE_COVERAGE,
    Reading,
    ScoreInputs,
    compute_score,
    coverage_cap,
)

# --- D1: a score that rests on a sliver of the weight is unknown -------------------


def test_d1_access_point_without_wan_and_probes_is_unknown_not_100():
    """Before: only "0 restarts" -> 100.0 at 6.7 % coverage."""
    result = compute_score(
        ScoreInputs(
            router_restarts=Reading(0.0),
            observation_seconds=86_400,
            not_applicable=frozenset({COMP_WAN}),
        )
    )
    assert result.coverage < MIN_SCORE_COVERAGE
    assert result.score is None
    assert result.low_confidence is True


def test_d1_router_with_wan_only_is_capped_by_coverage():
    result = compute_score(
        ScoreInputs(
            wan_availability=Reading(100.0, 1.0),
            router_restarts=Reading(0.0),
            observation_seconds=86_400,
        )
    )
    assert result.coverage == 0.3
    assert result.score is not None
    assert result.score <= coverage_cap(result.coverage) < 100


def test_d1_full_coverage_can_reach_100():
    full = Reading(0.0, 1.0)
    result = compute_score(
        ScoreInputs(
            wan_availability=Reading(100.0),
            packet_loss=full,
            latency=Reading(10.0),
            jitter=Reading(1.0),
            dns_failure=full,
            dns_response=Reading(10.0),
            gateway_reachability=Reading(100.0),
            router_restarts=full,
            observation_seconds=86_400,
        )
    )
    assert result.coverage == 1.0
    assert result.score == 100.0
    assert coverage_cap(1.0) == 100
    assert coverage_cap(0.5) == 75
    assert coverage_cap(0.99) == 99


# --- D2: switching off disconnects the signal receiver -----------------------------


async def test_d2_off_disconnects_the_signal_receiver() -> None:
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch

    from core_testkit import make_hass

    from custom_components.openwrt_router import diag_entities as de

    hass = make_hass()
    diag = SimpleNamespace(loaded=True, enabled=True, entries_by_router=dict)
    unsub = MagicMock()
    with (
        patch.object(de, "_diag", lambda _h: diag),
        patch.object(de, "async_dispatcher_connect", MagicMock(return_value=unsub)),
        patch.object(de, "platforms_of", lambda _h: []),
        patch.object(de, "_remove_from_registry", lambda _h: None),
    ):
        await de.async_sync_diag_entities(hass)
        hosts = de._hosts(hass)
        assert hosts.unsub is unsub
        diag.enabled = False
        await de.async_sync_diag_entities(hass)
    unsub.assert_called_once_with()
    assert hosts.unsub is None
