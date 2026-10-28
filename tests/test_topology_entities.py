"""Tests for the topology diagnostic sensors (topology_entities.py).

Regression for audit finding C6: the snapshot used to be rebuilt on every
property access and the full snapshot (incl. ``generated_at``) was written as
state attributes, so every poll produced a ~80 KB state write + websocket push.
"""
from __future__ import annotations

import copy
from itertools import count
from typing import Any
from unittest.mock import patch

import pytest

from custom_components.openwrt_router import topology_entities
from custom_components.openwrt_router.topology_diagnostic import (
    build_topology_snapshot as _real_build,
)
from custom_components.openwrt_router.topology_entities import (
    OpenWrtTopologySnapshotSensor,
    OpenWrtTopologyStatusSensor,
    setup_topology_entities,
)

_RAW_KEYS = {"topology_snapshot", "interfaces", "clients", "nodes", "edges"}


def _setup(coordinator, entry) -> list[Any]:
    """Create the topology entities exactly like sensor.py does."""
    added: list[Any] = []
    setup_topology_entities(coordinator, entry, added.extend)
    return added


def _read_everything(entities: list[Any], rounds: int = 3) -> None:
    """Touch every state-relevant property several times."""
    for _ in range(rounds):
        for ent in entities:
            _ = ent.native_value
            _ = ent.extra_state_attributes


@pytest.fixture
def counting_builder():
    """Patch the snapshot builder with a counting, timestamp-unique wrapper."""
    calls = {"n": 0}
    stamp = count()

    def _build(data, *args, **kwargs):
        calls["n"] += 1
        snap = _real_build(data, *args, **kwargs)
        # Guarantee a different generated_at per build (real clock may tie).
        snap["generated_at"] = f"2026-01-01T00:00:{next(stamp):02d}+00:00"
        return snap

    with patch.object(topology_entities, "build_topology_snapshot", _build):
        yield calls


class TestSnapshotCache:
    def test_setup_creates_both_sensors(self, mock_coordinator, mock_config_entry):
        entities = _setup(mock_coordinator, mock_config_entry)
        assert {type(e) for e in entities} == {
            OpenWrtTopologySnapshotSensor,
            OpenWrtTopologyStatusSensor,
        }

    def test_built_once_per_update_across_entities(
        self, mock_coordinator, mock_config_entry, counting_builder
    ):
        entities = _setup(mock_coordinator, mock_config_entry)
        _read_everything(entities)
        assert counting_builder["n"] == 1

    def test_cache_invalidated_on_next_update(
        self, mock_coordinator, mock_config_entry, counting_builder
    ):
        entities = _setup(mock_coordinator, mock_config_entry)
        _read_everything(entities)
        # Next poll: the coordinator replaces self.data with a fresh object.
        mock_coordinator.data = copy.deepcopy(mock_coordinator.data)
        _read_everything(entities)
        assert counting_builder["n"] == 2

    def test_new_data_is_reflected(
        self, mock_coordinator, mock_config_entry, counting_builder
    ):
        entities = _setup(mock_coordinator, mock_config_entry)
        snap_sensor = next(
            e for e in entities if isinstance(e, OpenWrtTopologySnapshotSensor)
        )
        before = snap_sensor.extra_state_attributes["client_count"]
        new_data = copy.deepcopy(mock_coordinator.data)
        new_data.clients = []
        mock_coordinator.data = new_data
        assert snap_sensor.extra_state_attributes["client_count"] == 0
        assert before != 0

    def test_no_data_returns_empty(self, mock_coordinator, mock_config_entry):
        mock_coordinator.data = None
        for ent in _setup(mock_coordinator, mock_config_entry):
            assert ent.native_value is None
            assert ent.extra_state_attributes == {}

    def test_build_failure_is_cached_and_empty(
        self, mock_coordinator, mock_config_entry
    ):
        calls = {"n": 0}

        def _boom(*_a, **_k):
            calls["n"] += 1
            raise ValueError("bad data")

        with patch.object(topology_entities, "build_topology_snapshot", _boom):
            entities = _setup(mock_coordinator, mock_config_entry)
            _read_everything(entities)
            for ent in entities:
                assert ent.native_value is None
                assert ent.extra_state_attributes == {}
        assert calls["n"] == 1


class TestAttributes:
    def _attrs(self, mock_coordinator, mock_config_entry) -> list[dict[str, Any]]:
        return [
            e.extra_state_attributes
            for e in _setup(mock_coordinator, mock_config_entry)
        ]

    def test_no_generated_at_or_raw_lists(
        self, mock_coordinator, mock_config_entry, counting_builder
    ):
        for attrs in self._attrs(mock_coordinator, mock_config_entry):
            assert attrs
            assert not _RAW_KEYS & attrs.keys()
            assert "generated_at" not in repr(attrs)
            assert "topology_debug" not in attrs
            # Only flat scalars or short static string lists — no nested dicts.
            for value in attrs.values():
                assert not isinstance(value, dict)

    def test_snapshot_sensor_keeps_counts(
        self, mock_coordinator, mock_config_entry, counting_builder
    ):
        entities = _setup(mock_coordinator, mock_config_entry)
        sensor = next(
            e for e in entities if isinstance(e, OpenWrtTopologySnapshotSensor)
        )
        attrs = sensor.extra_state_attributes
        for key in (
            "node_count",
            "edge_count",
            "interface_count",
            "client_count",
            "inference_used",
            "schema_version",
        ):
            assert key in attrs
        assert sensor.native_value == attrs["node_count"]

    def test_status_sensor_keeps_counts(
        self, mock_coordinator, mock_config_entry, counting_builder
    ):
        entities = _setup(mock_coordinator, mock_config_entry)
        sensor = next(
            e for e in entities if isinstance(e, OpenWrtTopologyStatusSensor)
        )
        attrs = sensor.extra_state_attributes
        assert "active_interfaces" in attrs
        assert "clients_without_signal" in attrs
        assert sensor.native_value == attrs["active_interfaces"]

    def test_no_churn_across_identical_polls(
        self, mock_coordinator, mock_config_entry, counting_builder
    ):
        entities = _setup(mock_coordinator, mock_config_entry)
        first = [(e.native_value, e.extra_state_attributes) for e in entities]
        mock_coordinator.data = copy.deepcopy(mock_coordinator.data)
        second = [(e.native_value, e.extra_state_attributes) for e in entities]
        assert counting_builder["n"] == 2  # really rebuilt, just identical
        assert first == second
