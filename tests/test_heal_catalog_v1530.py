"""Self-Healing, package D (1.53.0): the closed catalog of typed actions.

Order tests (Phase 7 order §22) covered here: 4 (unauthorised action: an
unknown id, a disabled action, parameters outside the closed set). Further:

* every catalog entry validates and carries an honest rollback statement;
* nothing outside the catalog is ever accepted (property-style run over
  random ids and parameters, shell metacharacters included);
* the catalog cannot be changed at run time (no registration, read-only
  mapping, frozen entries);
* only the owner's catalog status: ``service.restart`` (dnsmasq, odhcpd) is
  the one action ready for the first write release; radio restart, reboot,
  restore and interface cycle are modelled but disabled; client, firewall,
  VLAN, management-IP, routing and firmware actions, ``network reload`` and a
  ``wpad`` restart are not in the catalog at all;
* 1.53.0 executes nothing that calls a router.

Pure: no Home Assistant instance, no router, no network.
"""

from __future__ import annotations

import dataclasses
import json
import random
import string
from typing import Any

import pytest

from custom_components.openwrt_router import heal_catalog as hc
from custom_components.openwrt_router import heal_model as hm

READY = hc.CatalogStatus.READY
DISABLED = hc.CatalogStatus.DISABLED

# The owner's catalog (binding): action -> (status, base risk).
OWNER_CATALOG = {
    "observe.evaluate": (READY, 0),
    "diag.refresh": (READY, 1),
    "diag.ha_probes": (READY, 1),
    "service.restart": (READY, 2),
    "wifi.radio_restart": (DISABLED, 2),
    "router.reboot": (DISABLED, 3),
    "config.restore": (DISABLED, 3),
    "interface.cycle": (DISABLED, 3),
}

SHELL_BITS = (
    ";",
    "&&",
    "||",
    "|",
    "`",
    "$(",
    "${",
    ">",
    "<",
    "\n",
    "\r",
    "\x00",
    " ",
    "'",
    '"',
    "\\",
    "*",
    "?",
    "~",
    "#",
    "!",
    "..",
    "/",
)

NEVER = (
    "client.deauth",
    "client.block",
    "client.roam",
    "client.kick",
    "firewall.reload",
    "firewall.rule_add",
    "vlan.change",
    "mgmt.ip_change",
    "management.ip_change",
    "routing.change",
    "route.add",
    "firmware.upgrade",
    "sysupgrade.run",
    "network.reload",
    "wpad.restart",
    "service.stop",
    "service.start",
    "service.disable",
    "uci.set",
    "shell.exec",
    "ssh.run",
)


# ---------------------------------------------------------------------------
# The catalog as data
# ---------------------------------------------------------------------------


def test_the_catalog_is_exactly_the_owners_list() -> None:
    got = {k: (e.status, int(e.base_risk)) for k, e in hc.CATALOG.items()}
    assert got == OWNER_CATALOG
    assert hc.CATALOG_VERSION >= 1


def test_every_entry_is_complete_and_consistent() -> None:
    for action_type, entry in hc.CATALOG.items():
        assert entry.action_type == action_type
        assert entry.version >= 1
        assert isinstance(entry.base_risk, hm.RiskClass)
        # an honest rollback statement on every entry, as a model code
        assert entry.rollback in hc.RollbackKind
        assert entry.rollback_statement
        assert hm.Rollback(statement=entry.rollback_statement).statement
        # status with its reason: a disabled action always says why
        if entry.status is DISABLED:
            assert entry.status_reason, action_type
        # facts and probes are codes, never free text
        for code in (*entry.needs_facts, *entry.verification_probes):
            assert hm.Factor(factor=code, value=0, reason=code)
        # a write names the router call it would map to (a name, no call)
        if entry.writes:
            assert entry.disruption is not hc.Disruption.NONE
            assert entry.rollback is not hc.RollbackKind.READ_ONLY
        else:
            assert entry.rollback is hc.RollbackKind.READ_ONLY
        # the target parameter is one of the parameters
        if entry.target_param is not None:
            assert entry.target_param in {p.name for p in entry.params}
            assert entry.target_kind is not None
        # every closed set is non-empty and plain
        for spec in entry.params:
            assert spec.choices or spec.id_prefix
            for choice in spec.choices:
                assert choice.isascii() and choice.replace("_", "").isalnum()


def test_rollback_statements_are_honest() -> None:
    """No action claims a rollback the platform does not have."""
    c = hc.CATALOG
    assert c["service.restart"].rollback is hc.RollbackKind.MANUAL_RECOVERY
    assert c["router.reboot"].rollback is hc.RollbackKind.MANUAL_RECOVERY
    assert c["config.restore"].rollback is hc.RollbackKind.MANUAL_RECOVERY
    assert c["wifi.radio_restart"].rollback is hc.RollbackKind.SECOND_CALL
    assert c["interface.cycle"].rollback is hc.RollbackKind.SECOND_CALL
    for key in ("observe.evaluate", "diag.refresh", "diag.ha_probes"):
        assert c[key].rollback is hc.RollbackKind.READ_ONLY
    # the model record of the statement: never a mechanism other than none
    for entry in c.values():
        rec = hc.rollback_record(entry)
        assert rec.mechanism is hm.RollbackMechanism.NONE
        assert rec.status is hm.RollbackStatus.NOT_AVAILABLE
        assert rec.statement == entry.rollback_statement


def test_service_restart_is_the_only_write_meant_for_the_first_write_release() -> None:
    ready_writes = [
        e.action_type for e in hc.CATALOG.values() if e.writes and e.status is READY
    ]
    assert ready_writes == ["service.restart"]
    spec = hc.CATALOG["service.restart"].params
    assert [(p.name, p.choices) for p in spec] == [("service", ("dnsmasq", "odhcpd"))]
    # Approval only: its base risk is above what Auto-Heal may ever hold
    assert hc.CATALOG["service.restart"].base_risk > hm.AUTO_HEAL_MAX_RISK


def test_release_1_53_0_executes_nothing_that_calls_a_router() -> None:
    for action_type in hc.EXECUTABLE_IN_RELEASE:
        entry = hc.CATALOG[action_type]
        assert entry.router_call is None
        assert entry.base_risk is hm.RiskClass.READ_ONLY
        assert not entry.writes


def test_the_catalog_cannot_be_changed_at_run_time() -> None:
    with pytest.raises(TypeError):
        hc.CATALOG["shell.exec"] = hc.CATALOG["observe.evaluate"]  # type: ignore[index]
    with pytest.raises(TypeError):
        del hc.CATALOG["observe.evaluate"]  # type: ignore[attr-defined]
    entry = hc.CATALOG["service.restart"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.base_risk = hm.RiskClass.READ_ONLY  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.params[0].choices = ("dnsmasq", "wpad")  # type: ignore[misc]
    # no function of the module adds an action
    assert not [n for n in dir(hc) if n.startswith(("register", "add_", "extend"))]


def test_catalog_table_is_plain_json() -> None:
    rows = hc.catalog_table()
    assert [r["action_type"] for r in rows] == list(hc.CATALOG)
    text = json.dumps(rows)
    assert "dnsmasq" in text
    assert json.loads(text) == rows


# ---------------------------------------------------------------------------
# Validation (order test 4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("service", ["dnsmasq", "odhcpd"])
def test_a_valid_service_restart(service: str) -> None:
    va = hc.validate("service.restart", {"service": service})
    assert va.entry is hc.CATALOG["service.restart"]
    assert dict(va.params) == {"service": service}
    assert va.components == (hm.Component(kind=hm.ComponentKind.SERVICE, name=service),)


def test_parameterless_actions_validate_with_empty_or_no_params() -> None:
    for key in ("observe.evaluate", "diag.refresh", "diag.ha_probes", "router.reboot"):
        assert hc.validate(key, {}).params == {}
        assert hc.validate(key, None).params == {}
        assert hc.validate(key, {}).components == ()


def test_disabled_actions_validate_but_stay_disabled() -> None:
    """Validation is about shape; the policy refuses them (Unsupported)."""
    va = hc.validate("wifi.radio_restart", {"radio": "radio0"})
    assert va.entry.status is DISABLED
    assert va.components == (hm.Component(kind=hm.ComponentKind.RADIO, name="radio0"),)
    va = hc.validate("config.restore", {"version_id": "bkp_" + "a" * 32})
    assert va.entry.status is DISABLED
    va = hc.validate("interface.cycle", {"interface": "lan"})
    assert va.components == (hm.Component(kind=hm.ComponentKind.INTERFACE, name="lan"),)


@pytest.mark.parametrize("action_type", NEVER)
def test_actions_that_are_never_in_the_catalog_are_refused(action_type: str) -> None:
    with pytest.raises(hc.CatalogError) as err:
        hc.validate(action_type, {})
    assert err.value.code.startswith(("never_", "unknown_action"))
    assert action_type not in str(err.value)


def test_never_families_have_their_own_reason() -> None:
    assert hc.refusal_reason("client.deauth") == "never_client_action"
    assert hc.refusal_reason("firewall.reload") == "never_firewall"
    assert hc.refusal_reason("vlan.change") == "never_vlan"
    assert hc.refusal_reason("routing.change") == "never_routing"
    assert hc.refusal_reason("firmware.upgrade") == "never_firmware"
    assert hc.refusal_reason("network.reload") == "never_network_reload"
    assert hc.refusal_reason("something.else") == "unknown_action"


@pytest.mark.parametrize(
    ("action_type", "params", "code"),
    [
        ("service.restart", {"service": "wpad"}, "param_value_invalid"),
        ("service.restart", {"service": "network"}, "param_value_invalid"),
        ("service.restart", {"service": "firewall"}, "param_value_invalid"),
        ("service.restart", {"service": "dropbear"}, "param_value_invalid"),
        ("service.restart", {"service": "uhttpd"}, "param_value_invalid"),
        ("service.restart", {"service": "rpcd"}, "param_value_invalid"),
        ("service.restart", {"service": "DNSMASQ"}, "param_value_invalid"),
        ("service.restart", {"service": " dnsmasq"}, "param_value_invalid"),
        ("service.restart", {"service": "dnsmasq;reboot"}, "param_value_invalid"),
        ("service.restart", {"service": "dnsmasq && reboot"}, "param_value_invalid"),
        ("service.restart", {"service": "$(reboot)"}, "param_value_invalid"),
        ("service.restart", {"service": "`reboot`"}, "param_value_invalid"),
        ("service.restart", {"service": "../dnsmasq"}, "param_value_invalid"),
        ("service.restart", {"service": "dnsmasq\n"}, "param_value_invalid"),
        ("service.restart", {"service": 1}, "param_value_invalid"),
        ("service.restart", {"service": True}, "param_value_invalid"),
        ("service.restart", {"service": None}, "param_value_invalid"),
        ("service.restart", {"service": ["dnsmasq"]}, "param_value_invalid"),
        ("service.restart", {}, "param_missing"),
        ("service.restart", None, "param_missing"),
        ("service.restart", {"service": "dnsmasq", "action": "stop"}, "param_unknown"),
        ("service.restart", {"name": "dnsmasq"}, "param_unknown"),
        ("service.restart", {1: "dnsmasq"}, "param_unknown"),
        ("service.restart", "dnsmasq", "params_invalid"),
        ("service.restart", [("service", "dnsmasq")], "params_invalid"),
        ("diag.refresh", {"cmd": "reboot"}, "param_unknown"),
        ("wifi.radio_restart", {"radio": "radio9"}, "param_value_invalid"),
        ("wifi.radio_restart", {"radio": "wlan0"}, "param_value_invalid"),
        ("interface.cycle", {"interface": "lan;reboot"}, "param_value_invalid"),
        ("interface.cycle", {"interface": "br-lan"}, "param_value_invalid"),
        ("config.restore", {"version_id": "bkp_" + "g" * 32}, "param_value_invalid"),
        ("config.restore", {"version_id": "bkp_" + "a" * 31}, "param_value_invalid"),
        ("config.restore", {"version_id": "evt_" + "a" * 32}, "param_value_invalid"),
        ("config.restore", {"version_id": "/etc/config"}, "param_value_invalid"),
    ],
)
def test_parameters_outside_the_closed_set_are_refused(
    action_type: str, params: Any, code: str
) -> None:
    with pytest.raises(hc.CatalogError) as err:
        hc.validate(action_type, params)
    assert err.value.code == code
    # the message never repeats the value
    for value in params.values() if isinstance(params, dict) else [params]:
        if isinstance(value, str) and value:
            assert value not in str(err.value)


class _SneakyStr(str):
    """A str subclass could lie in ``__eq__``; only plain str is taken."""

    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = str.__hash__


@pytest.mark.parametrize(
    "bad",
    [
        None,
        1,
        True,
        b"service.restart",
        "",
        "SERVICE.RESTART",
        "service.restart ",
        " service.restart",
        "service.restart\n",
        "service..restart",
        "service/restart",
        _SneakyStr("anything"),
    ],
)
def test_action_ids_must_be_exact_plain_strings(bad: Any) -> None:
    with pytest.raises(hc.CatalogError):
        hc.validate(bad, {"service": "dnsmasq"})


def test_a_sneaky_parameter_value_is_refused() -> None:
    with pytest.raises(hc.CatalogError) as err:
        hc.validate("service.restart", {"service": _SneakyStr("wpad")})
    assert err.value.code == "param_value_invalid"


def test_try_validate_returns_the_reason_instead_of_raising() -> None:
    va, reason = hc.try_validate("service.restart", {"service": "dnsmasq"})
    assert va is not None and reason is None
    va, reason = hc.try_validate("client.deauth", {})
    assert va is None and reason == "never_client_action"


# ---------------------------------------------------------------------------
# Property-style: nothing outside the catalog is ever accepted
# ---------------------------------------------------------------------------


def _random_text(rng: random.Random) -> str:
    pool = string.ascii_letters + string.digits + "._-" + "".join(SHELL_BITS)
    text = "".join(rng.choice(pool) for _ in range(rng.randint(0, 24)))
    if rng.random() < 0.5:
        text += rng.choice(SHELL_BITS)
    if rng.random() < 0.3:
        known = rng.choice(["dnsmasq", "odhcpd", "radio0", "lan", "service.restart"])
        text = rng.choice([known + text, text + known, known + rng.choice(SHELL_BITS)])
    return text


def _random_value(rng: random.Random) -> Any:
    kind = rng.random()
    if kind < 0.7:
        return _random_text(rng)
    return rng.choice([None, 0, 1, -1, 1.5, True, False, [], {}, ["dnsmasq"], b"x"])


@pytest.mark.parametrize("seed", range(5))
def test_random_ids_and_params_never_validate_outside_the_catalog(seed: int) -> None:
    rng = random.Random(seed)
    accepted = 0
    for _ in range(2000):
        if rng.random() < 0.5:
            action_type: Any = rng.choice(list(hc.CATALOG))
        else:
            action_type = _random_value(rng)
        params: Any
        if rng.random() < 0.15:
            params = _random_value(rng)
        else:
            params = {}
            for _k in range(rng.randint(0, 3)):
                key = rng.choice(
                    ["service", "radio", "interface", "version_id", _random_text(rng)]
                )
                params[key] = _random_value(rng)
        va, reason = hc.try_validate(action_type, params)
        if va is None:
            assert reason
            continue
        accepted += 1
        # accepted only if it is exactly an entry with values from its closed sets
        assert type(action_type) is str and action_type in hc.CATALOG
        entry = hc.CATALOG[action_type]
        assert set(va.params) == {p.name for p in entry.params}
        for spec in entry.params:
            value = va.params[spec.name]
            assert type(value) is str
            if spec.choices:
                assert value in spec.choices
            else:
                assert spec.id_prefix is not None
                assert value.startswith(spec.id_prefix)
            assert not any(bit in value for bit in SHELL_BITS)
    assert accepted > 0  # the run really hit valid requests too
