"""1.52.0: every reason, state and jump of the views "Zustand" and
"Vergleich" has a German text, and the panel's copy of the jump table is
the backend's.

The tab shows its texts from tables in ``tmTexts.ts``. This test reads them
(the parser of the 1.50.0 test) and compares them with the backend itself:

* ``GLOBAL_REASON_TEXT``: exactly the global reasons of ``tm_state`` (a
  ``known: false`` answer);
* ``STATE_REASON_TEXT``: every ``R_*`` reason of ``tm_state`` and every
  source reason of ``tm_sources`` (parts of the state say why they are off);
* ``PART_STATE_TEXT``: the ``PART_*`` states; ``ROLE_TEXT`` the roles and
  ``RADIO_STATE_TEXT`` the radio states ``tm_state`` writes;
  ``RADIO_BAND_TEXT`` the bands of ``channel_plan``;
* ``JUMP_REF_TAB`` / ``JUMP_KIND_TAB`` / ``JUMP_OBJECT`` against
  ``tm_sources.JUMP_TARGETS`` / ``KIND_TABS`` + ``KIND_NO_TAB`` /
  ``_OBJECT``, in both directions;
* ``JUMP_TAB_TEXT``: exactly the ``tm_sources.TAB_*`` ids, each one a tab
  the panel registers (``registerEnterpriseTab`` in a ``register.ts``) with
  the same title, and every registered tab a jump may name has a text.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from test_tm_panel_texts_v1500 import _table

from custom_components.openwrt_router import channel_plan, tm_sources, tm_state

_ENTERPRISE = (
    Path(__file__).parents[1]
    / "custom_components/openwrt_router/frontend/topology/src/enterprise"
)


def _consts(module: object, prefix: str) -> set[str]:
    return {
        v
        for k, v in vars(module).items()
        if k.startswith(prefix) and isinstance(v, str)
    }


def _const(text: str, name: str, where: Path) -> str:
    m = re.search(rf"export const {name} = '([^']+)';", text)
    assert m, (where, name)
    return m.group(1)


def registered_tabs() -> dict[str, str]:
    """Tab id -> title of every ``registerEnterpriseTab`` in the panel."""
    tabs: dict[str, str] = {}
    for reg in sorted(_ENTERPRISE.glob("*/register.ts")):
        src = reg.read_text(encoding="utf-8")
        block = src[src.index("registerEnterpriseTab({") :]
        ident = re.search(r"\bid: (?:'([a-z]+)'|(TAB_ID))", block)
        title = re.search(r"\btitle: (?:'([^']+)'|(TAB_TITLE))", block)
        assert ident and title, reg
        consts = "\n".join(
            p.read_text(encoding="utf-8") for p in reg.parent.glob("*Logic.ts")
        )
        tab = ident.group(1) or _const(consts, "TAB_ID", reg)
        tabs[tab] = title.group(1) or _const(consts, "TAB_TITLE", reg)
    return tabs


def test_global_reasons_are_the_backend_s_with_whole_sentences() -> None:
    table = _table("GLOBAL_REASON_TEXT")
    assert set(table) == set(tm_state._GLOBAL)
    for key, text in table.items():
        assert text[0].isupper() and text.endswith("."), (key, text)
        assert "_" not in text, key


def test_every_reason_of_a_value_or_part_has_a_text() -> None:
    reasons = _consts(tm_state, "R_") | set(tm_sources.ALL_REASONS)
    assert set(tm_state.UNKNOWN_REASONS) <= reasons
    assert len(reasons) >= 20  # sanity: both modules were read
    table = _table("STATE_REASON_TEXT")
    assert sorted(reasons - set(table)) == []
    # and no text for a reason that never comes
    assert sorted(set(table) - reasons) == []
    for key, text in table.items():
        assert "_" not in text and not text.endswith("."), (key, text)


def test_states_roles_radios_and_bands_have_texts() -> None:
    assert set(_table("PART_STATE_TEXT")) == _consts(tm_state, "PART_")
    src = inspect.getsource(tm_state)
    roles = set(
        re.findall(r'_value\(\s*"([a-z]+)" if role == "g" else "([a-z]+)"', src)[0]
    )
    assert roles == {"gateway", "node"}
    assert set(_table("ROLE_TEXT")) == roles
    # the radio states: the assignments ``state = "…"`` of the radio items
    radio_states = set(re.findall(r'\bstate = "([a-z]+)"', src))
    assert {"up", "down", "unknown"} <= radio_states
    assert set(_table("RADIO_STATE_TEXT")) == {"up", "down", "unknown"}
    assert set(_table("RADIO_BAND_TEXT")) == _consts(channel_plan, "BAND_")


def test_the_jump_table_is_the_backend_s_in_both_directions() -> None:
    by_kind = tm_sources._BY_KIND
    backend = {
        f"{module}.{kind}": (tab if tab is not None else "none")
        for (module, kind), tab in tm_sources.JUMP_TARGETS.items()
    }
    assert _table("JUMP_REF_TAB") == backend
    assert by_kind in backend.values()
    kinds = dict(tm_sources.KIND_TABS) | dict.fromkeys(tm_sources.KIND_NO_TAB, "none")
    assert _table("JUMP_KIND_TAB") == kinds
    objects = {
        f"{module}.{kind}": obj
        for (module, kind), obj in tm_sources._OBJECT.items()
        if obj is not None
    }
    assert _table("JUMP_OBJECT") == objects
    # every ref with an object is a ref of the jump table
    assert {f"{m}.{k}" for m, k in tm_sources._OBJECT} <= set(backend)


def test_every_jump_tab_is_a_registered_panel_tab_and_back() -> None:
    tabs = registered_tabs()
    assert len(tabs) == 6, tabs
    backend = _consts(tm_sources, "TAB_")
    texts = _table("JUMP_TAB_TEXT")
    assert set(texts) == backend
    # each tab a jump names is registered in the panel, under the same title
    for tab in backend:
        assert tab in tabs, tab
        assert texts[tab] == tabs[tab], tab
    # and each registered tab is one a jump can name
    assert set(tabs) == backend
    # every tab of the tables is a known tab (or by_kind / none)
    named = set(_table("JUMP_REF_TAB").values()) | set(_table("JUMP_KIND_TAB").values())
    assert named - {"by_kind", "none"} <= backend
