"""1.51.0: every title and number of the own index has a German text.

The "Zeitreise" tab shows ``TITLE_TEXT[mark.title_key]`` (``tmTexts.ts``);
for the sources of the own index (``tm_index``, ``tm_clients``) it first
looks up ``<title_key>.<code>``. This test collects from the backend itself:

* every kind the engine, the client recorder and the index write
  (``kind="..."`` literals of ``tm_engine``, ``tm_clients``, ``tm_marks``),
  which must be known kinds of ``tm_sources.KIND_GROUP``, and every kind of
  ``KIND_GROUP`` the index stores without a reference: each needs
  ``<tm_marks.source_of(kind)>.<kind>`` in the table (reference marks keep
  the audit's ``core_audit.<type>`` key, covered by the 1.50.0 test);
* every variant ``<source>.<kind>.<code>`` in the table must name a code
  the backend writes (a string literal in those modules), so no text stands
  for a code that never comes;
* every parameter of a ``params={...}`` literal there, plus the keys set or
  counted later (``params["…"] = …``, ``index.bump(…, "…")``), needs a text
  in ``PARAM_TEXT``.
"""

from __future__ import annotations

import inspect
import re

from test_tm_panel_texts_v1500 import _table

from custom_components.openwrt_router import tm_clients, tm_engine, tm_marks, tm_sources

_MODULES = (tm_engine, tm_clients, tm_marks)


def _sources() -> str:
    return "\n".join(inspect.getsource(m) for m in _MODULES)


def written_kinds() -> set[str]:
    return set(re.findall(r'\bkind="([a-z_]+)"', _sources()))


def index_title_keys() -> set[str]:
    kinds = written_kinds()
    unknown = kinds - set(tm_sources.KIND_GROUP)
    assert unknown == set(), f"kinds the index writes but KIND_GROUP lacks: {unknown}"
    stored = {k for k in tm_sources.KIND_GROUP if k not in tm_marks.REF_KINDS}
    stored = {k for k in stored if tm_marks.source_of(k) != tm_sources.SOURCE_TM_REFS}
    # the kinds of the own index are the ones written here (a kind of an
    # earlier source, e.g. ``config_drift``, is no index title)
    return {f"{tm_marks.source_of(k)}.{k}" for k in (kinds & stored)}


def written_params() -> set[str]:
    src = _sources()
    keys: set[str] = set()
    for m in re.finditer(r"params=\{(.*?)\}", src, re.DOTALL):
        keys |= set(re.findall(r'"([a-z_]+)":', m.group(1)))
    keys |= set(re.findall(r'params\[\s*"([a-z_]+)"\s*\]\s*=', src))
    keys |= set(re.findall(r'\.bump\([^,]+,\s*"([a-z_]+)"', src))
    return keys


def test_every_kind_of_the_own_index_has_a_german_title() -> None:
    keys = index_title_keys()
    assert len(keys) >= 20  # sanity: the engine and the recorder were read
    assert {k.split(".", 1)[0] for k in keys} == {
        tm_sources.SOURCE_TM_INDEX,
        tm_sources.SOURCE_TM_CLIENTS,
    }
    missing = sorted(keys - set(_table("TITLE_TEXT")))
    assert missing == [], f"title_key without a German text: {missing}"


def test_every_variant_title_names_a_code_the_backend_writes() -> None:
    src = _sources()
    table = _table("TITLE_TEXT")
    variants = {
        k: v for k, v in table.items() if k.startswith(("tm_index.", "tm_clients."))
    }
    variants = {k: v for k, v in variants.items() if k.count(".") == 2}
    assert len(variants) >= 10
    for key in variants:
        source, kind, code = key.split(".")
        assert f"{source}.{kind}" in table, key
        assert f'"{code}"' in src, f"{key}: the backend never writes the code {code}"


def test_every_number_of_the_own_index_has_a_text() -> None:
    names = written_params()
    for key in ("band", "roam", "resumed", "gaps", "blips", "suppressed", "cap"):
        assert key in names, key
    table = _table("PARAM_TEXT")
    missing = sorted(names - set(table))
    assert missing == [], f"parameter without a text: {missing}"


def test_the_fixture_titles_are_all_in_the_table() -> None:
    import json
    from pathlib import Path

    path = (
        Path(tm_sources.__file__).parent
        / "frontend/topology/src/enterprise/timemachine/tmFixtureClients.json"
    )
    fixture = json.loads(path.read_text(encoding="utf-8"))
    table = _table("TITLE_TEXT")
    keys = {
        m["title_key"]
        for answer in fixture.values()
        for m in answer["body"].get("marks", [])
    }
    assert keys and keys <= set(table), sorted(keys - set(table))
