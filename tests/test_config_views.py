"""HTTP routes R1-R20 of the configuration manager (plan 2026-11-18, section 7).

A real aiohttp application with HA's own view plumbing
(``HomeAssistantView.register``: 401 without login), a fake login middleware
(header ``X-Test-User``), the enterprise core on FakeDisks and the in-memory
FakeConfigProvider. No Home Assistant instance, no router: the coordinators'
api objects must stay untouched.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from config_manager_kit import ON, attach_entry, cm_env, drain, restart, stop
from core_test_provider import (
    FakeConfigProvider,
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import ADMIN_ID, OTHER_ADMIN_ID, USER_ID, FakeDisks, user_actor
from homeassistant.components.http import KEY_HASS_USER
from homeassistant.helpers.http import KEY_AUTHENTICATED, KEY_HASS
from test_acl_tiers import V8_TEXT
from test_acl_tiers import _api as acl_api
from test_ssh_hostkey_pinning import KEY_A, FakeRouter, _patched
from test_ssh_hostkey_pinning import _api as ssh_api
from yarl import URL

from custom_components.openwrt_router import config_manager as cm
from custom_components.openwrt_router import config_views as cv
from custom_components.openwrt_router.acl_provisioning import (
    RPCD_ACL_CONTENT,
    AclEnsureOutcome,
    observe_deployed_acl,
)
from custom_components.openwrt_router.api import OpenWrtHostKeyError
from custom_components.openwrt_router.const import (
    CONFIG_MANAGER_EVENT_PREFIX,
    CONFIG_MANAGER_MODULE,
    CONFIG_ROUTE_PSEUDONYM_PURPOSE,
    DATA_CONFIG_MANAGER,
    DEFAULT_CONFIG_BACKUP_TIME,
)
from custom_components.openwrt_router.core_errors import (
    ApprovalInvalidError,
    ApprovalRequiredError,
    AuthorizationError,
    BackupIncompleteError,
    BackupIntegrityError,
    BackupMetadataError,
    BackupNotFoundError,
    CapabilityUnavailableError,
    ConfigApiError,
    ErrorClass,
    OperationInProgressError,
    OperationTimeoutError,
    ProviderConflictError,
    ProviderError,
    RestoreIncompatibleError,
    RouterAuthError,
    RouterIdentityError,
    RouterNotFoundError,
    RouterPermissionError,
    RouterUnavailableError,
    StorageFullError,
    VersionProtectedError,
)
from custom_components.openwrt_router.core_models import (
    ChangeKind,
    CompatibilityCheck,
    CompatibilityIssue,
    ConfigChange,
    ConfigDiff,
    ConfigRef,
    GuardedAction,
    derive_module_key,
    utcnow,
)
from custom_components.openwrt_router.topology_panel import _PANEL_VIEW_DISABLED_KEY

SECRET = "S3cr3t-pa55"
ADMIN = user_actor(ADMIN_ID)
RID0 = "rtr_" + "0" * 32
BID0 = "bkp_" + "0" * 32
AID0 = "apr_" + "0" * 32


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------


@dataclass
class Resp:
    status: int
    headers: Any
    body: bytes

    @property
    def data(self) -> Any:
        return json.loads(self.body)


class Http:
    """The test client; remembers every response body (secret checks)."""

    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.bodies: list[bytes] = []

    async def call(
        self,
        method: str,
        path: str | URL,
        *,
        user: str | None = ADMIN_ID,
        body: Any = None,
        raw: Any = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        record: bool = True,
    ) -> Resp:
        sent = dict(headers or {})
        if user is not None:
            sent["X-Test-User"] = user
        kwargs: dict[str, Any] = {}
        if body is not None:
            kwargs["json"] = body
        if raw is not None:
            kwargs["data"] = raw
        resp = await self.client.request(
            method.upper(), path, headers=sent, params=params, **kwargs
        )
        data = await resp.read()
        if record:
            self.bodies.append(data)
            self.bodies.append(json.dumps(dict(resp.headers)).encode())
        return Resp(resp.status, resp.headers, data)

    async def get(self, path: str, **kw: Any) -> Resp:
        return await self.call("get", cv.BASE_URL + path, **kw)

    async def post(self, path: str, **kw: Any) -> Resp:
        return await self.call("post", cv.BASE_URL + path, **kw)

    def assert_no_secret(self, *needles: str) -> None:
        for needle in (SECRET, *needles):
            for body in self.bodies:
                assert needle.encode() not in body, (needle, body[:300])


def _auth_middleware(hass: Any) -> Any:
    @web.middleware
    async def middleware(request: web.Request, handler: Any) -> Any:
        user_id = request.headers.get("X-Test-User")
        if user_id:
            request[KEY_AUTHENTICATED] = True
            request[KEY_HASS_USER] = hass.users.get(user_id)
        return await handler(request)

    return middleware


@asynccontextmanager
async def http(hass: Any) -> AsyncIterator[Http]:
    app = web.Application(middlewares=[_auth_middleware(hass)])
    app[KEY_HASS] = hass
    for view_class in cv.CONFIG_VIEWS:
        view_class().register(hass, app, app.router)
    async with TestClient(TestServer(app)) as client:
        yield Http(client)


def method_of(view_class: type) -> str:
    return "post" if issubclass(view_class, cv._PostView) else "get"


def sample_path(
    view_class: type,
    *,
    router_id: str = RID0,
    backup_id: str = BID0,
    approval_id: str = AID0,
    drift_id: str = "drift_0",
    op: str = "confirm",
) -> str:
    return view_class.url.format(
        router_id=router_id,
        backup_id=backup_id,
        approval_id=approval_id,
        drift_id=drift_id,
        op=op,
    )


def route_id(view_class: type) -> str:
    return view_class.name.rsplit(":", 1)[-1]


def no_min_gap(monkeypatch: Any) -> None:
    """Switch the manual minimum gaps off (tests that call routes back to back)."""
    monkeypatch.setattr(cm, "MANUAL_BACKUP_MIN_GAP_S", 0)
    monkeypatch.setattr(cm, "MANUAL_LIVE_CHECK_MIN_GAP_S", 0)


async def backup(h: Http, rid: str, **body: Any) -> dict[str, Any]:
    resp = await h.post(f"/routers/{rid}/backup", body=body or None)
    assert resp.status == 200, resp.body
    return resp.data


def change_live(env: Any, rid: str, config: str = "system") -> None:
    live = env.provider.live(rid)
    live[config] = {**live.get(config, {}), "changed": {"x": str(uuid.uuid4())}}


def fake_approval(action: str, router_id: str, **extra: Any) -> Any:
    aid = "apr_" + uuid.uuid4().hex
    data = {
        "approval_id": aid,
        "action": action,
        "router_id": router_id,
        "subject_id": router_id,
        "checksum": "c" * 64,
        "requested_by": {"kind": "user", "user_id": ADMIN_ID},
        "requested_at": utcnow().isoformat(),
        "expires_at": utcnow().isoformat(),
        "status": "pending",
        "decided_by": None,
        "decided_at": None,
        "reason": None,
        "correlation_id": "corr",
        **extra,
    }
    return SimpleNamespace(
        approval_id=aid, action=action, router_id=router_id, to_dict=lambda: data
    )


def patch_api(monkeypatch: Any, api: Any, name: str, fn: Any) -> None:
    """Replace a facade method (the facade has __slots__: on the class).

    Every call is first bound against the real method's signature, so a
    route that calls the facade with a missing or unknown argument fails
    here exactly like it would against the real core (contract #111: the
    actor of ``async_validate_backup``).
    """
    real = inspect.signature(getattr(type(api), name))

    def replacement(self: Any, *a: Any, **k: Any) -> Any:
        real.bind(self, *a, **k)
        return fn(*a, **k)

    monkeypatch.setattr(type(api), name, replacement)


def acl_capable(env: Any, router_id: str | None = None) -> Any:
    """Give a router an api the core's ACL flow can read and write.

    The kit's coordinator api is a plain MagicMock; the core reads the
    current ACL through ``await api._call("file", "read", ...)`` before it
    builds an offer.  Same helper as ``_acl_env`` in the enterprise tests.
    """
    rid = router_id or env.rid
    api = acl_api(V8_TEXT)
    api.login = AsyncMock(return_value=True)
    api.reset_acl_blocked = MagicMock()
    api.uses_ssh_fallback = False
    env.coords[rid].api = api
    env.core.security.grace_s = 0
    env.core.security.login_retry_s = 0
    env.core.registry.note_deployed_acl(
        env.entry_of(rid).entry_id,
        observe_deployed_acl(
            AclEnsureOutcome(False, "current", True, RPCD_ACL_CONTENT)
        ),
    )
    return api


def test_patch_api_binds_against_the_real_signature(monkeypatch):
    """A patched facade method still refuses a call the core would refuse."""
    from custom_components.openwrt_router.config_api import ConfigurationApi

    actor = inspect.signature(ConfigurationApi.async_validate_backup).parameters[
        "actor"
    ]
    assert actor.kind is inspect.Parameter.KEYWORD_ONLY
    assert actor.default is inspect.Parameter.empty  # contract #111

    class Facade:
        __slots__ = ()

        async def async_validate_backup(self, backup_id: str, *, actor: Any) -> Any:
            raise AssertionError("replaced")

    api = Facade()
    patch_api(monkeypatch, api, "async_validate_backup", lambda *a, **k: "ok")
    with pytest.raises(TypeError):
        api.async_validate_backup("bkp_x")
    assert api.async_validate_backup("bkp_x", actor=ADMIN) == "ok"


def with_fake_approvals(monkeypatch: Any, api: Any, *fakes: Any) -> None:
    by_id = {f.approval_id: f for f in fakes}
    original = api.get_approval

    def get_approval(approval_id: str) -> Any:
        return by_id[approval_id] if approval_id in by_id else original(approval_id)

    patch_api(monkeypatch, api, "get_approval", get_approval)


# ---------------------------------------------------------------------------
# route list and access (every route, parametrised over CONFIG_VIEWS)
# ---------------------------------------------------------------------------

ALL = [pytest.param(v, id=route_id(v)) for v in cv.CONFIG_VIEWS]


def test_route_list_is_complete_and_unique():
    module_views = {
        obj
        for obj in vars(cv).values()
        if inspect.isclass(obj)
        and issubclass(obj, cv._ConfigView)
        and obj not in (cv._ConfigView, cv._GetView, cv._PostView)
    }
    assert module_views == set(cv.CONFIG_VIEWS)
    assert len(cv.CONFIG_VIEWS) == 20
    assert len({v.name for v in cv.CONFIG_VIEWS}) == 20
    assert len({(v.url, method_of(v)) for v in cv.CONFIG_VIEWS}) == 20
    for view in cv.CONFIG_VIEWS:
        assert view.requires_auth is True
        assert view.url.startswith(cv.BASE_URL + "/")
        assert view.name.startswith("api:openwrt_topology:config:")
        # exactly one method per route
        assert hasattr(view, "get") != hasattr(view, "post")


def test_no_route_deletes_or_executes_a_restore():
    for view in cv.CONFIG_VIEWS:
        assert "delete" not in view.url and not hasattr(view, "delete")
        assert "restore" not in view.url or view.url.endswith("/restore-check")
    source = inspect.getsource(cv)
    assert "async_execute_restore" not in source
    assert "async_delete_backups" not in source
    assert "async_request_restore" not in source
    assert "async_request_deletion" not in source


@pytest.mark.parametrize("view", ALL)
async def test_every_route_needs_a_login(disks, tmp_path, view):
    env = await cm_env(disks, tmp_path)
    calls = list(env.provider.calls)
    async with http(env.hass) as h:
        path = sample_path(view, router_id=env.rid)
        resp = await h.call(method_of(view), path, user=None)
        assert resp.status == 401
    assert env.provider.calls == calls
    await stop(env)


@pytest.mark.parametrize("view", ALL)
async def test_every_route_is_admin_only(disks, tmp_path, view):
    env = await cm_env(disks, tmp_path)
    calls = list(env.provider.calls)
    async with http(env.hass) as h:
        resp = await h.call(
            method_of(view), sample_path(view, router_id=env.rid), user=USER_ID
        )
        assert resp.status == 403
        assert resp.data["code"] == "authorization_denied"
        assert resp.headers["Cache-Control"] == "no-store"
        # also before any id or body check: a malformed id is still 403
        bad = sample_path(
            view, router_id="x", backup_id="x", approval_id="x", drift_id="x", op="x"
        )
        resp = await h.call(
            method_of(view), bad, user=USER_ID, raw=b"x" * (cv.BODY_MAX_BYTES + 10)
        )
        assert resp.status == 403
    assert env.provider.calls == calls
    assert env.router_calls() == []
    await stop(env)


async def test_unknown_user_is_forbidden(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        resp = await h.get("/overview", user="nobody")
        assert resp.status == 403
    await stop(env)


async def test_disabled_panel_answers_410(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    env.hass.data[_PANEL_VIEW_DISABLED_KEY] = True
    async with http(env.hass) as h:
        resp = await h.get("/overview")
        assert resp.status == 410
        assert resp.data["code"] == "integration_not_loaded"
        assert resp.headers["Cache-Control"] == "no-store"
        # non-admins still get 403 first
        assert (await h.get("/overview", user=USER_ID)).status == 403
    await stop(env)


async def test_no_runtime_answers_503(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    runtime = env.hass.data.pop(DATA_CONFIG_MANAGER)
    async with http(env.hass) as h:
        resp = await h.get("/overview")
        assert resp.status == 503
        assert resp.data == {
            "message": "The configuration manager is not running",
            "code": "core_not_running",
            "error_class": "not_available",
            "retryable": True,
            "details": {},
        }
    env.hass.data[DATA_CONFIG_MANAGER] = runtime
    await stop(env)


async def test_provider_conflict_refuses_every_post(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    env.runtime.provider_conflict = True
    calls = list(env.provider.calls)
    async with http(env.hass) as h:
        for view in cv.CONFIG_VIEWS:
            resp = await h.call(method_of(view), sample_path(view, router_id=env.rid))
            if method_of(view) == "post":
                assert resp.status == 409, view.name
                assert resp.data["code"] == "provider_conflict"
        overview = await h.get("/overview")
        assert overview.status == 200
        assert overview.data["provider_conflict"] is True
    assert env.provider.calls == calls
    env.runtime.provider_conflict = False
    await stop(env)


def test_views_are_bound_once():
    hass = SimpleNamespace(data={}, http=SimpleNamespace(register_view=None))
    registered: list[Any] = []
    hass.http.register_view = registered.append
    assert cv.async_register_config_views(hass) == 20
    assert cv.async_register_config_views(hass) == 0
    assert len(registered) == 20
    # a retry after a partial failure binds only what is missing
    hass.data[cv.DATA_CONFIG_VIEWS_BOUND].discard(cv.OverviewView.name)
    assert cv.async_register_config_views(hass) == 1
    assert isinstance(registered[-1], cv.OverviewView)
    assert cv.async_register_config_views(SimpleNamespace(data={})) == 0


async def test_setup_registers_the_views(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    bound = env.hass.data[cv.DATA_CONFIG_VIEWS_BOUND]
    assert bound == {v.name for v in cv.CONFIG_VIEWS}
    assert env.hass.http.register_view.call_count == 20  # not per entry
    await stop(env)


# ---------------------------------------------------------------------------
# inputs: ids, bodies, query
# ---------------------------------------------------------------------------

BAD_IDS = [
    "rtr_" + "A" * 32,  # upper case
    "rtr_" + "0" * 33,  # too long
    "rtr_" + "0" * 31,
    "rtr_" + "0" * 300,  # overlong
    "rtr_" + "g" * 32,
    "RTR_" + "0" * 32,
    "bkp_" + "0" * 32,  # wrong prefix
    "rtr_..%2f" + "0" * 26,
]


@pytest.mark.parametrize("bad", BAD_IDS)
async def test_malformed_router_ids_are_400(disks, tmp_path, bad):
    env = await cm_env(disks, tmp_path)
    calls = list(env.provider.calls)
    async with http(env.hass) as h:
        for view in (cv.RouterView, cv.VersionsView, cv.BackupView, cv.DriftView):
            path = sample_path(view, router_id=bad)
            resp = await h.call(method_of(view), URL(path, encoded=True))
            assert resp.status == 400, (view.name, resp.body)
            assert resp.data["code"] == "invalid_request"
            assert resp.data["details"]["field"] == "router_id"
    assert env.provider.calls == calls
    await stop(env)


TRAVERSAL = ["..", "%2e%2e", "%2E%2E%2Fetc", "..%2f..%2fetc%2fpasswd", "%00", "%20"]


@pytest.mark.parametrize("bad", TRAVERSAL)
async def test_path_traversal_ids_never_reach_the_core(disks, tmp_path, bad):
    env = await cm_env(disks, tmp_path)
    calls = list(env.provider.calls)
    async with http(env.hass) as h:
        for view in (cv.VersionView, cv.ValidateView, cv.ApproveView, cv.RouterView):
            path = sample_path(view, router_id=bad, backup_id=bad, approval_id=bad)
            resp = await h.call(method_of(view), URL(path, encoded=True))
            assert resp.status in (400, 404), (view.name, resp.status)
            assert resp.status != 200
    assert env.provider.calls == calls
    await stop(env)


async def test_empty_and_odd_ids_rejected_by_the_handlers(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    ctx = cv.RequestContext(
        hass=env.hass,
        runtime=env.runtime,
        api=env.api,
        actor=ADMIN,
        user_id=ADMIN_ID,
        salt=await env.runtime.async_route_salt(),
    )
    for bad in ("", "../x", "rtr_/../../x", None, 5, "rtr_" + "0" * 32 + "\n"):
        with pytest.raises(cv.RequestError) as err:
            ctx.router(bad)
        assert err.value.status == 400
        with pytest.raises(cv.RequestError):
            await ctx.backup(bad)
        with pytest.raises(cv.RequestError):
            ctx.approval(bad)
    with pytest.raises(RouterNotFoundError):
        ctx.router(RID0)  # well formed but not ours
    async with http(env.hass) as h:
        resp = await h.get(f"/routers/{RID0}")
        assert resp.status == 404
        assert resp.data["code"] == "router_not_found"
        resp = await h.get(f"/versions/{BID0}")
        assert resp.status == 404
        assert resp.data["code"] == "backup_not_found"
        # drift ids: strict pattern
        for bad in ("a" * 129, "x%2e", "x.y", "%2e%2e"):
            path = sample_path(cv.DriftAckView, router_id=env.rid, drift_id=bad)
            resp = await h.call(
                "post", URL(path, encoded=True), body={"state": "known"}
            )
            assert resp.status == 400
            assert resp.data["details"]["field"] == "drift_id"
    await stop(env)


async def test_body_is_limited_to_4_kb(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    calls = len(env.provider.calls)
    async with http(env.hass) as h:
        big = json.dumps({"note": "x" * cv.BODY_MAX_BYTES}).encode()
        resp = await h.post(f"/routers/{env.rid}/backup", raw=big)
        assert resp.status == 413
        assert resp.data["code"] == "body_too_large"

        async def chunks() -> AsyncIterator[bytes]:
            for _ in range(5):
                yield b" " * 1000

        resp = await h.post(f"/routers/{env.rid}/backup", raw=chunks())
        assert resp.status == 413
    assert len(env.provider.calls) == calls
    await stop(env)


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b'{"note": "a", "extra": 1}', "unknown_key"),
        (b'{"protected": true}', "unknown_key"),
        (b"[1, 2]", "not_an_object"),
        (b'"note"', "not_an_object"),
        (b"{not json", "not_json"),
        (b"\xff\xfe", "not_json"),
    ],
)
async def test_bad_bodies_are_400(disks, tmp_path, raw, reason):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        resp = await h.post(f"/routers/{env.rid}/backup", raw=raw)
        assert resp.status == 400
        assert resp.data["details"] == {"field": "body", "reason": reason}
    assert env.provider.ops("collect") == []
    await stop(env)


@pytest.mark.parametrize(
    ("note", "ok"),
    [
        (("planned change of the guest wifi " * 7)[:200], True),
        ("  padded  ", True),
        ("", True),
        (None, True),
        ("x" * 201, False),
        ("line\nbreak", False),
        ("bell\x07", False),
        ("zero\u200bwidth", False),
        (5, False),
        (["a"], False),
    ],
)
async def test_note_limits(disks, tmp_path, note, ok):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        resp = await h.post(f"/routers/{env.rid}/backup", body={"note": note})
        if ok:
            assert resp.status == 200, resp.body
            expected = None if not note else note.strip()
            assert resp.data["version"]["note"] == expected
        else:
            assert resp.status == 400
            assert resp.data["details"]["field"] == "note"
            assert env.provider.ops("collect") == []
    await stop(env)


@pytest.mark.parametrize(
    ("limit", "status"),
    [
        (None, 200),
        ("1", 200),
        ("200", 200),
        ("0", 400),
        ("201", 400),
        ("-1", 400),
        ("abc", 400),
        ("1e2", 400),
        ("99999999", 400),
    ],
)
async def test_versions_limit_bounds(disks, tmp_path, limit, status):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        params = None if limit is None else {"limit": limit}
        resp = await h.get(f"/routers/{env.rid}/versions", params=params)
        assert resp.status == status
        if status == 400:
            assert resp.data["details"]["field"] == "limit"
    await stop(env)


async def test_versions_limit_default_and_since(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        first = await backup(h, env.rid)
        env.clock.advance(minutes=10)
        change_live(env, env.rid)
        await backup(h, env.rid)
        resp = await h.get(f"/routers/{env.rid}/versions")
        assert resp.data["count"] == 2
        newest = resp.data["versions"][0]["backup_id"]
        resp = await h.get(f"/routers/{env.rid}/versions", params={"limit": "1"})
        assert [v["backup_id"] for v in resp.data["versions"]] == [newest]
        resp = await h.get(
            f"/routers/{env.rid}/versions", params={"since": "not-a-date"}
        )
        assert resp.status == 400
        resp = await h.get(
            f"/routers/{env.rid}/versions",
            params={"since": first["version"]["created_at"]},
        )
        assert resp.status == 200
        resp = await h.get(
            f"/routers/{env.rid}/versions", params={"since": first["backup_id"]}
        )
        assert resp.status == 200
        resp = await h.get(f"/routers/{env.rid}/versions", params={"since": BID0})
        assert resp.status == 404
    await stop(env)


# ---------------------------------------------------------------------------
# error mapping (codes, never router text)
# ---------------------------------------------------------------------------

ERRORS = [
    (RouterNotFoundError(SECRET), 404),
    (BackupNotFoundError(SECRET), 404),
    (AuthorizationError(SECRET), 403),
    (ApprovalRequiredError(SECRET), 409),
    (ApprovalInvalidError(SECRET), 409),
    (OperationInProgressError(SECRET), 409),
    (VersionProtectedError(SECRET), 409),
    (ProviderConflictError(SECRET), 409),
    (CapabilityUnavailableError(SECRET, capability="config.backup", reason="x"), 409),
    (BackupIntegrityError(SECRET), 422),
    (BackupIncompleteError(SECRET), 422),
    (RestoreIncompatibleError(SECRET), 422),
    (RouterUnavailableError(SECRET), 503),
    (OperationTimeoutError(SECRET), 504),
    (RouterAuthError(SECRET), 502),
    (RouterPermissionError(SECRET), 502),
    (ProviderError(SECRET), 502),
    (StorageFullError(SECRET), 507),
    # not in the table: by error class
    (RouterIdentityError(SECRET), 409),
    (BackupMetadataError(SECRET), 422),
    (ConfigApiError(SECRET, error_class=ErrorClass.CONFLICT), 409),
    (ConfigApiError(SECRET), 500),
]


@pytest.mark.parametrize(
    ("err", "status"), [pytest.param(e, s, id=e.code + str(s)) for e, s in ERRORS]
)
def test_error_mapping(err, status):
    err.details["reason"] = "no_pending_pin"
    err.details["raw"] = SECRET
    resp = cv.api_error_response(err)
    assert resp.status == status
    body = json.loads(resp.body)
    assert set(body) == {"message", "code", "error_class", "retryable", "details"}
    assert body["code"] == err.code
    assert body["error_class"] == err.error_class.value
    assert body["retryable"] is err.retryable
    assert SECRET not in resp.body.decode()
    assert "raw" not in body["details"]
    assert body["details"]["reason"] == "no_pending_pin"
    assert resp.headers["Cache-Control"] == "no-store"
    assert ("Retry-After" in resp.headers) is (err.code == "operation_in_progress")
    if err.code == "operation_in_progress":
        assert resp.headers["Retry-After"] == "30"


def test_error_details_only_tokens():
    err = ProviderError(details={"reason": "has space 192.168.1.1", "field": "ok_1"})
    body = json.loads(cv.api_error_response(err).body)
    assert body["details"] == {"field": "ok_1"}


async def test_internal_errors_carry_no_text(disks, tmp_path, monkeypatch, caplog):
    env = await cm_env(disks, tmp_path)

    async def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError(f"{SECRET} at 192.168.1.1")

    patch_api(monkeypatch, env.api, "async_list_backups", boom)
    caplog.set_level("DEBUG")
    async with http(env.hass) as h:
        resp = await h.get(f"/routers/{env.rid}/versions")
        assert resp.status == 500
        assert resp.data["code"] == "internal"
        h.assert_no_secret("192.168.1.1")
    assert SECRET not in caplog.text
    assert "RuntimeError" in caplog.text
    await stop(env)


# ---------------------------------------------------------------------------
# R1-R4, R6, R7: overview, router, versions
# ---------------------------------------------------------------------------


async def test_overview_lists_every_router(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    async with http(env.hass) as h:
        await backup(h, env.rids[0])
        resp = await h.get("/overview")
        assert resp.status == 200
        assert resp.headers["Cache-Control"] == "no-store"
        data = resp.data
        assert data["provider"] == "test_provider"
        assert data["provider_registered"] is True
        assert data["pending_approvals"] == 0
        routers = {r["router_id"]: r for r in data["routers"]}
        assert set(routers) == set(env.rids)
        first = routers[env.rids[0]]
        assert first["enabled"] is True
        assert first["status"] == first["state"] == "ok"
        assert first["versions"] == first["version_count"] == 1
        assert first["last_backup_at"] == first["last_success_at"] is not None
        assert first["schedule"]["mode"] == "daily"
        assert first["schedule"]["time"] == DEFAULT_CONFIG_BACKUP_TIME[:5]
        assert first["capability"]["state"] == "available"
        assert first["openwrt_version"] in (None, "24.10.2") or isinstance(
            first["openwrt_version"], str
        )
        assert routers[env.rids[1]]["status"] == "never"
        assert routers[env.rids[1]]["drift"] is None
    assert env.router_calls() == []
    await stop(env)


async def test_router_view_lists_capabilities_pin_and_acl(disks, tmp_path, monkeypatch):
    env = await cm_env(disks, tmp_path)
    patch_api(
        monkeypatch,
        env.api,
        "ssh_pin_status",
        lambda rid: {
            "state": "pending",
            "policy": "confirm",
            "fingerprint": None,
            "algorithm": "ssh-ed25519",
            "pinned_at": None,
            "pending_fingerprint": "SHA256:abcdef",
            "pending_since": None,
            "confirmed_at": None,
            "confirmed_by": ADMIN_ID,
        },
    )
    async with http(env.hass) as h:
        resp = await h.get(f"/routers/{env.rid}")
        data = resp.data
        assert resp.status == 200
        assert "config.backup" in data["capabilities"]
        assert data["ssh_pin"]["state"] == "pending"
        assert data["ssh_pin"]["fingerprint"] == "SHA256:abcdef"
        assert "confirmed_by" not in data["ssh_pin"]
        assert data["acl"] == {
            "offerable": ["config_backup_read"],
            "deployed_version": None,
        }
        h.assert_no_secret(ADMIN_ID)
    await stop(env)


async def test_version_view_has_no_storage_locators(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        made = await backup(h, env.rid, note="first")
        resp = await h.get(f"/versions/{made['backup_id']}")
        data = resp.data
        assert data["backup_id"] == made["backup_id"]
        assert data["note"] == "first"
        assert data["created_by"] == {"kind": "user", "mine": True}
        kinds = {a["kind"] for a in data["artifacts"]}
        assert "uci" in kinds
        text = resp.body.decode()
        for hidden in ("storage", "content_hash", "uci_hash", "installation_key"):
            assert hidden not in text
        # another admin sees "mine": False
        other = await h.get(f"/versions/{made['backup_id']}", user="user-admin-2")
        assert other.data["created_by"] == {"kind": "user", "mine": False}
        h.assert_no_secret(ADMIN_ID, "user-admin-2")
    await stop(env)


async def test_validate_and_protect(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        resp = await h.post(f"/versions/{bid}/validate")
        assert resp.status == 200
        assert resp.data["validation"]["state"] == "valid"
        resp = await h.post(f"/versions/{bid}/protect", body={"protected": True})
        assert resp.data["protected"] is True
        resp = await h.post(f"/versions/{bid}/protect", body={"protected": "yes"})
        assert resp.status == 400
        resp = await h.post(f"/versions/{bid}/protect", body={})
        assert resp.data["details"] == {"field": "protected", "reason": "missing"}
        resp = await h.post(f"/versions/{bid}/protect", body={"protected": False})
        assert resp.data["protected"] is False
    await stop(env)


# ---------------------------------------------------------------------------
# R5: backup
# ---------------------------------------------------------------------------


async def test_backup_route_manual_always_creates(disks, tmp_path):
    """Manual versions always create (core rule: no note is lost); the
    content dedup of scheduled and drift runs is covered in
    test_config_manager.test_identical_scheduled_run_is_deduplicated."""
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        first = await backup(h, env.rid)
        assert first["created"] is True and first["status"] == "ok"
        assert first["version"]["reason"] == "manual"
        env.clock.advance(seconds=61)  # the minimum gap of manual backups
        again = await backup(h, env.rid, note="second")
        assert again["created"] is True
        assert again["backup_id"] != first["backup_id"]
        resp = await h.get(f"/routers/{env.rid}/versions")
        assert resp.data["count"] == 2
        assert resp.data["versions"][0]["note"] == "second"
    await stop(env)


async def test_backup_route_while_running_is_409_with_retry_after(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    gate = asyncio.Event()
    env.provider.gates["collect"] = gate
    async with http(env.hass) as h:
        running = asyncio.ensure_future(backup(h, env.rids[0]))
        await env.provider.entered.setdefault("collect", asyncio.Event()).wait()
        # concurrency 1: the second router waits for the first one
        resp = await h.post(f"/routers/{env.rids[1]}/backup")
        assert resp.status == 409
        assert resp.data["code"] == "operation_in_progress"
        assert resp.data["retryable"] is True
        assert resp.headers["Retry-After"] == "30"
        assert env.provider.max_active == 1
        gate.set()
        assert (await running)["created"] is True
        assert (await backup(h, env.rids[1]))["created"] is True
    await stop(env)


async def test_manual_backup_min_gap_is_429_with_retry_after(disks, tmp_path):
    """H3: one manual backup per router and minute (R5); others unaffected."""
    env = await cm_env(disks, tmp_path, routers=2)
    async with http(env.hass) as h:
        await backup(h, env.rids[0])
        env.clock.advance(seconds=20)
        resp = await h.post(f"/routers/{env.rids[0]}/backup")
        assert resp.status == 429
        assert resp.data["code"] == "rate_limited"
        assert resp.data["error_class"] == "rate_limited"
        assert resp.data["retryable"] is True
        assert resp.data["details"] == {"reason": "min_gap_backup"}
        assert resp.headers["Retry-After"] == "40"
        assert (await backup(h, env.rids[1]))["created"] is True  # other router
        env.clock.advance(seconds=41)
        assert (await backup(h, env.rids[0]))["created"] is True
    assert len(env.provider.ops("collect")) == 3
    await stop(env)


async def test_manual_live_checks_share_one_min_gap(disks, tmp_path):
    """H3: R10, R8 live and R12 share the live-check gap; R8 without live not."""
    env = await cm_env(disks, tmp_path)
    rid = env.rid
    async with http(env.hass) as h:
        bid = (await backup(h, rid))["backup_id"]
        assert (await h.post(f"/routers/{rid}/drift/check")).status == 200
        env.clock.advance(seconds=10)
        for method, path, params in (
            ("get", f"/routers/{rid}/diff", {"from": bid}),
            ("post", f"/versions/{bid}/restore-check", None),
            ("post", f"/routers/{rid}/drift/check", None),
        ):
            if params is None:
                resp = await h.call(method, cv.BASE_URL + path)
            else:
                resp = await h.get(path, params=params)
            assert resp.status == 429, path
            assert resp.data["details"] == {"reason": "min_gap_live_check"}
            assert resp.headers["Retry-After"] == "50"
        resp = await h.get(f"/routers/{rid}/diff", params={"from": bid, "to": bid})
        assert resp.status == 200  # two stored versions: no router access
        env.clock.advance(seconds=51)
        resp = await h.get(f"/routers/{rid}/diff", params={"from": bid})
        assert resp.status == 200
    await stop(env)


async def test_live_check_while_the_router_is_busy_is_409(disks, tmp_path):
    """H3: a live check never waits behind a run of the same router."""
    env = await cm_env(disks, tmp_path)
    rid = env.rid
    gate = asyncio.Event()
    env.provider.gates["collect"] = gate
    async with http(env.hass) as h:
        running = asyncio.ensure_future(backup(h, rid))
        await env.provider.entered.setdefault("collect", asyncio.Event()).wait()
        assert env.runtime.router_busy(rid)
        resp = await h.post(f"/routers/{rid}/drift/check")
        assert resp.status == 409
        assert resp.data["code"] == "operation_in_progress"
        assert resp.data["details"] == {"reason": "router_busy"}
        assert resp.headers["Retry-After"] == "30"
        assert env.provider.ops("detect_drift") == []
        gate.set()
        await running
        assert not env.runtime.router_busy(rid)
        # the refused check did not count for the gap
        assert (await h.post(f"/routers/{rid}/drift/check")).status == 200
    await stop(env)


async def test_service_waits_for_the_router_lock_and_runs_serially(disks, tmp_path):
    """H3: the service waits its turn (no 409); one router run at a time."""
    env = await cm_env(disks, tmp_path, routers=2)
    gate = asyncio.Event()
    env.provider.gates["collect"] = gate
    runtime = env.runtime
    first = asyncio.ensure_future(runtime.async_backup_now(env.rids[0], actor=ADMIN))
    await env.provider.entered.setdefault("collect", asyncio.Event()).wait()
    second = asyncio.ensure_future(
        runtime.async_backup_now(env.rids[1], actor=ADMIN, wait=True)
    )
    await asyncio.sleep(0)
    assert not second.done()
    gate.set()
    await first
    await second
    assert env.provider.max_active == 1
    assert [rid for _op, rid in env.provider.ops("collect")] == env.rids
    await stop(env)


async def test_unknown_router_backup_is_404(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        resp = await h.post(f"/routers/{RID0}/backup")
        assert resp.status == 404
    assert env.provider.ops("collect") == []
    await stop(env)


# ---------------------------------------------------------------------------
# option off: disabled, no router contact
# ---------------------------------------------------------------------------


async def test_option_off_routes_answer_disabled_without_router_calls(
    disks, tmp_path, monkeypatch
):
    env = await cm_env(disks, tmp_path, options={})
    acl = []
    patch_api(
        monkeypatch, env.api, "async_request_acl_deploy", lambda *a, **k: acl.append(a)
    )
    async with http(env.hass) as h:
        resp = await h.get("/overview")
        router = resp.data["routers"][0]
        assert router["enabled"] is False
        assert router["status"] == "disabled"
        assert router["schedule"]["mode"] == "off"
        assert router["schedule"]["next_run_at"] is None
        assert router["capability"]["state"] == "unavailable"
        assert router["capability"]["reason"] == "disabled"
        detail = await h.get(f"/routers/{env.rid}")
        assert detail.data["acl"]["offerable"] == []
        for path, body in (
            (f"/routers/{env.rid}/backup", None),
            (f"/routers/{env.rid}/drift/check", None),
            (f"/routers/{env.rid}/acl-offer", None),
            (f"/routers/{env.rid}/drift/drift_1/ack", {"state": "known"}),
        ):
            resp = await h.post(path, body=body)
            assert resp.status == 409, path
            assert resp.data["code"] == "capability_unavailable"
            assert resp.data["details"]["reason"] == "disabled"
            assert resp.data["details"]["state"] == "disabled"
        resp = await h.get(
            f"/routers/{env.rid}/diff", params={"from": BID0, "to": "live"}
        )
        assert resp.status == 404  # unknown version before any live read
        resp = await h.get(f"/routers/{env.rid}/versions")
        assert resp.data == {"versions": [], "count": 0}
        resp = await h.get(f"/routers/{env.rid}/drift")
        assert resp.data["state"] == "unknown"
    assert acl == []
    assert env.provider.calls == []
    assert env.router_calls() == []
    await stop(env)


# ---------------------------------------------------------------------------
# R8: diff
# ---------------------------------------------------------------------------


async def test_diff_route(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rids[0]))["backup_id"]
        change_live(env, env.rids[0], "firewall")
        resp = await h.get(f"/routers/{env.rids[0]}/diff", params={"from": bid})
        assert resp.status == 200
        data = resp.data
        assert data["from"] == bid and data["to"] == "live"
        assert data["complete"] is True
        assert data["changes"] == [
            {
                "area": None,
                "risk": "critical",
                "config": "firewall",
                "section": "*",
                "section_type": None,
                "option": None,
                "op": "changed",
                "old": None,
                "new": None,
                "secret": False,
            }
        ]
        for params, status in (
            ({}, 400),
            ({"from": "live"}, 400),  # live against live
            ({"from": "live", "to": "live"}, 400),
            ({"from": "bkp_x"}, 400),
            ({"from": BID0}, 404),
        ):
            resp = await h.get(f"/routers/{env.rids[0]}/diff", params=params)
            assert resp.status == status, params
        # a version of another router is not found here
        resp = await h.get(f"/routers/{env.rids[1]}/diff", params={"from": bid})
        assert resp.status == 404
    await stop(env)


async def test_diff_masks_secret_values(disks, tmp_path, monkeypatch):
    env = await cm_env(disks, tmp_path)

    async def compare(base: Any, other: Any, ctx: Any, **_: Any) -> ConfigDiff:
        return ConfigDiff(
            base=ConfigRef.live(env.rid),
            other=ConfigRef.live(env.rid),
            compared_at=utcnow(),
            changes=(
                ConfigChange(
                    kind=ChangeKind.MODIFIED,
                    config="wireless",
                    section="default_radio0",
                    option="key",
                    before=SECRET,
                    after=SECRET + "2",
                ),
                ConfigChange(
                    kind=ChangeKind.ADDED,
                    config="network",
                    section="wan",
                    option="password",
                    after=SECRET,
                ),
            ),
        )

    monkeypatch.setattr(env.provider, "async_compare", compare)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        resp = await h.get(f"/routers/{env.rid}/diff", params={"from": bid})
        assert resp.status == 200
        changes = resp.data["changes"]
        assert [c["secret"] for c in changes] == [True, True]
        assert changes[1]["op"] == "added"
        h.assert_no_secret()
    await stop(env)


# ---------------------------------------------------------------------------
# R9-R11: drift
# ---------------------------------------------------------------------------


async def test_drift_check_and_acknowledge(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        await backup(h, env.rid)
        resp = await h.post(f"/routers/{env.rid}/drift/check")
        assert resp.status == 200
        assert resp.data["state"] == "clean" and resp.data["open"] is False
        change_live(env, env.rid, "dropbear")
        env.clock.advance(seconds=61)  # the minimum gap of manual live checks
        resp = await h.post(f"/routers/{env.rid}/drift/check")
        report = resp.data["report"]
        assert resp.data["state"] == "open" and resp.data["open"] is True
        assert report["critical_count"] == 1
        drift_id = report["drift_id"]
        resp = await h.post(
            f"/routers/{env.rid}/drift/{drift_id}/ack",
            body={"state": "acknowledged", "note": "planned"},
        )
        assert resp.status == 200, resp.body
        assert resp.data["state"] == "acknowledged"
        assert resp.data["open"] is False
        ack = resp.data["acks"][0]
        assert ack["drift_id"] == drift_id and ack["note"] == "planned"
        assert ack["by"] == {"kind": "user", "mine": True}
        resp = await h.get(f"/routers/{env.rid}/drift")
        assert resp.data["acks"][0]["state"] == "acknowledged"
        for body in ({"state": "open"}, {}, {"state": "known", "x": 1}):
            resp = await h.post(f"/routers/{env.rid}/drift/{drift_id}/ack", body=body)
            assert resp.status == 400, body
        h.assert_no_secret(ADMIN_ID)
    assert env.router_calls() == []
    await stop(env)


async def test_connection_loss_after_restore_gives_checklist_only(disks, tmp_path):
    """Phase 1: the restore is manual; the panel gets instructions and a
    checklist. A router that is gone afterwards answers with codes only."""
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        resp = await h.post(f"/versions/{bid}/restore-check")
        plan = resp.data
        assert plan["manual"] is True and plan["executable"] is False
        assert "restore_verify_after_reboot" in plan["instructions"]
        assert "restore_not_reversible" in plan["instructions"]
        # the router is gone (after the manual restore it does not come back)
        env.provider.fail["detect_drift"] = RouterUnavailableError(
            f"{SECRET} lost 192.168.1.1"
        )
        env.provider.fail["collect"] = RouterUnavailableError(f"{SECRET} lost")
        env.clock.advance(seconds=61)  # the minimum gap of manual runs
        resp = await h.post(f"/routers/{env.rid}/drift/check")
        assert resp.status == 503
        assert resp.data["code"] == "router_unavailable"
        assert resp.data["retryable"] is True
        resp = await h.post(f"/routers/{env.rid}/backup")
        assert resp.status == 503
        # reading still works: overview, versions, the checklist again
        assert (await h.get("/overview")).status == 200
        assert (await h.get(f"/routers/{env.rid}/versions")).data["count"] == 1
        env.provider.fail.pop("detect_drift")
        env.clock.advance(seconds=61)
        resp = await h.post(f"/versions/{bid}/restore-check")
        assert resp.status == 200
        h.assert_no_secret("192.168.1.1")
    assert env.provider.ops("execute_restore") == []
    assert env.router_calls() == []
    await stop(env)


# ---------------------------------------------------------------------------
# R12: restore check (dry run only)
# ---------------------------------------------------------------------------


async def test_restore_check_lists_lockout_step(disks, tmp_path, monkeypatch):
    env = await cm_env(disks, tmp_path)
    original = env.provider.async_prepare_restore

    async def prepare(*args: Any) -> Any:
        plan = await original(*args)
        return replace(
            plan,
            compatibility=CompatibilityCheck(
                compatible=True,
                issues=(
                    CompatibilityIssue(
                        code="lockout_risk", message=f"{SECRET}", blocking=False
                    ),
                    CompatibilityIssue(code="has space", message="x", blocking=False),
                ),
            ),
            warnings=("access_files_overwritten", f"free text {SECRET}"),
            instructions=("restore_luci_upload", f"run {SECRET}"),
        )

    monkeypatch.setattr(env.provider, "async_prepare_restore", prepare)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        resp = await h.post(f"/versions/{bid}/restore-check")
        assert resp.status == 200, resp.body
        data = resp.data
        assert data["lockout_risk"] is True
        assert data["findings"] == [
            {"code": "lockout_risk", "blocking": False, "level": "warning"}
        ]
        assert data["warnings"] == ["access_files_overwritten"]
        assert data["instructions"] == [
            "restore_luci_upload",
            "restore_prepare_console_failsafe",
            "restore_not_reversible",
            "restore_verify_after_reboot",
        ]
        assert data["compatible"] is True
        assert data["manual"] is True and data["executable"] is False
        assert data["expires_at"] is not None
        assert all(set(s) == {"order", "action", "instructions"} for s in data["steps"])
        h.assert_no_secret()
    assert env.provider.ops("execute_restore") == []
    await stop(env)


async def test_restore_check_incompatible_is_blocked(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        env.provider.incompatible = True
        resp = await h.post(f"/versions/{bid}/restore-check")
        if resp.status == 200:
            data = resp.data
            assert data["compatible"] is False
            assert data["findings"][0]["code"] == "board_mismatch"
            assert data["findings"][0]["blocking"] is True
            assert data["instructions"][0] == "restore_blocked"
        else:  # the core may refuse an incompatible plan outright
            assert resp.status == 422
            assert resp.data["code"] == "restore_incompatible"
    await stop(env)


def test_restore_view_detects_access_changes():
    def change(config: str, option: str | None) -> dict[str, Any]:
        return {"config": config, "option": option}

    assert cv._touches_access([change("dropbear", "Port")])
    assert cv._touches_access([change("network", "ipaddr")])
    assert cv._touches_access([change("firewall", "input")])
    assert cv._touches_access([change("firewall", None)])
    assert not cv._touches_access([change("network", "mtu")])
    assert not cv._touches_access([change("system", "hostname")])


async def test_no_route_executes_restore(disks, tmp_path):
    env = await cm_env(disks, tmp_path, provider=FakeConfigProvider(restore=True))
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        plan = await env.api.async_prepare_restore(bid, env.rid, actor=ADMIN)
        request = await env.api.async_request_restore(plan, actor=ADMIN)
        aid = request.approval_id
        listed = await h.get("/approvals")
        assert aid not in listed.body.decode()
        for route in ("approve", "reject", "download", "execute"):
            resp = await h.post(f"/approvals/{aid}/{route}")
            assert resp.status == 409, route
            assert resp.data["details"]["reason"] == "action_not_supported"
        assert env.api.get_approval(aid).status.value == "pending"
    assert env.provider.ops("execute_restore") == []
    await stop(env)


# ---------------------------------------------------------------------------
# R13-R17: export with approval, single download
# ---------------------------------------------------------------------------


async def _export(h: Http, bid: str, artifact: str | None = None) -> str:
    body = None if artifact is None else {"artifact": artifact}
    resp = await h.post(f"/versions/{bid}/export", body=body)
    assert resp.status == 200, resp.body
    assert resp.data["action"] == "export"
    assert resp.data["status"] == "pending"
    assert resp.data["requested_by"] == {"kind": "user", "mine": True}
    assert "checksum" not in resp.data and "correlation_id" not in resp.data
    return resp.data["approval_id"]


async def test_export_needs_approval_and_downloads_once(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        aid = await _export(h, bid, "uci")
        listed = await h.get("/approvals", params={"router_id": env.rid})
        assert [a["approval_id"] for a in listed.data["approvals"]] == [aid]
        assert (await h.get("/overview")).data["pending_approvals"] == 1
        resp = await h.post(f"/approvals/{aid}/download")
        assert resp.status == 409
        assert resp.data["code"] == "approval_required"
        resp = await h.post(f"/approvals/{aid}/approve")
        assert resp.status == 200 and resp.data["status"] == "approved"
        executor_calls = env.hass.async_add_executor_job.call_count
        resp = await h.post(f"/approvals/{aid}/download", record=False)
        assert resp.status == 200
        headers = resp.headers
        assert headers["Content-Type"] == "application/json"
        disposition = headers["Content-Disposition"]
        assert disposition.startswith('attachment; filename="')
        filename = disposition.split('filename="', 1)[1].rstrip('"')
        assert filename and all(c.isalnum() or c in "._-" for c in filename)
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
        assert int(headers["Content-Length"]) == len(resp.body)
        assert SECRET.encode() in resp.body  # the plaintext export itself
        assert env.hass.async_add_executor_job.call_count > executor_calls
        assert any(
            c.args and c.args[0] is cv._sha256
            for c in env.hass.async_add_executor_job.call_args_list
        )
        again = await h.post(f"/approvals/{aid}/download")
        assert again.status == 409
        assert again.data["code"] == "approval_invalid"
        h.assert_no_secret(ADMIN_ID)
    await stop(env)


async def test_archive_export_is_gzip(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        made = await backup(h, env.rid)
        kinds = {a["kind"] for a in made["version"]["artifacts"]}
        if "archive" not in kinds:
            pytest.skip("manual backups of this provider carry no archive")
        aid = await _export(h, made["backup_id"])
        await h.post(f"/approvals/{aid}/approve")
        resp = await h.post(f"/approvals/{aid}/download", record=False)
        assert resp.status == 200
        assert resp.headers["Content-Type"] == "application/gzip"
    await stop(env)


async def test_export_checksum_mismatch_sends_no_bytes(disks, tmp_path, monkeypatch):
    env = await cm_env(disks, tmp_path)
    original = env.api.async_export_backup

    async def tampered(*args: Any, **kwargs: Any) -> Any:
        return replace(await original(*args, **kwargs), sha256="0" * 64)

    patch_api(monkeypatch, env.api, "async_export_backup", tampered)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        aid = await _export(h, bid, "uci")
        await h.post(f"/approvals/{aid}/approve")
        resp = await h.post(f"/approvals/{aid}/download")
        assert resp.status == 422
        assert resp.data["code"] == "backup_integrity_failed"
        assert resp.headers["Content-Type"].startswith("application/json")
        assert "Content-Disposition" not in resp.headers
        h.assert_no_secret()
    await stop(env)


async def test_reject_route_and_unknown_approval(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        aid = await _export(h, bid)
        resp = await h.post(f"/approvals/{aid}/reject", body={"reason": "x" * 201})
        assert resp.status == 400
        resp = await h.post(f"/approvals/{aid}/reject", body={"reason": "no"})
        assert resp.status == 200
        assert resp.data["status"] == "rejected"
        assert resp.data["decided_by"] == {"kind": "user", "mine": True}
        resp = await h.post(f"/approvals/{aid}/approve")
        assert resp.status == 409
        resp = await h.post(f"/approvals/{AID0}/approve")
        assert resp.status == 409
        assert resp.data["code"] == "approval_invalid"
        resp = await h.post(f"/versions/{bid}/export", body={"artifact": "../x"})
        assert resp.status == 400
        assert (await h.get("/approvals", params={"router_id": "x"})).status == 400
        h.assert_no_secret(ADMIN_ID)
    await stop(env)


async def test_execute_refuses_exports(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        aid = await _export(h, bid)
        await h.post(f"/approvals/{aid}/approve")
        resp = await h.post(f"/approvals/{aid}/execute")
        assert resp.status == 409
        assert resp.data["details"]["reason"] == "use_download"
    await stop(env)


# ---------------------------------------------------------------------------
# R18-R20: ACL offer, SSH pin, execute (core flows replaced by fakes)
# ---------------------------------------------------------------------------


async def test_acl_offer_and_execute(disks, tmp_path, monkeypatch):
    env = await cm_env(disks, tmp_path)
    approval = fake_approval(GuardedAction.ACL_DEPLOY, env.rid)
    requested: list[Any] = []
    deployed: list[Any] = []

    async def request(rid: str, tiers: Any, *, actor: Any) -> Any:
        requested.append((rid, list(tiers), actor.user_id))
        return approval

    offer = SimpleNamespace(
        to_dict=lambda: {
            "tiers": ["config_backup_read"],
            "acl_checksum": "c" * 64,
            "acl_version": 9,
            "current_kind": "tiered",
            "added": ["ubus uci get"],
            "removed": [],
            "unchanged": 3,
            "risks": [{"tier_id": "config_backup_read", "risk": "reads_secrets"}],
        }
    )

    async def deploy(aid: str, *, actor: Any) -> dict[str, Any]:
        deployed.append(aid)
        return {"changed": True, "transport": "ubus", "password": SECRET}

    patch_api(monkeypatch, env.api, "async_request_acl_deploy", request)
    patch_api(monkeypatch, env.api, "acl_offer", lambda aid: offer)
    patch_api(monkeypatch, env.api, "async_deploy_acl_offer", deploy)
    with_fake_approvals(monkeypatch, env.api, approval)
    async with http(env.hass) as h:
        resp = await h.post(f"/routers/{env.rid}/acl-offer")
        assert resp.status == 200, resp.body
        assert requested == [(env.rid, ["config_backup_read"], ADMIN_ID)]
        assert resp.data["offer"]["risks"] == ["reads_secrets"]
        assert resp.data["offer"]["added"] == ["ubus uci get"]
        assert resp.data["approval"]["approval_id"] == approval.approval_id
        assert "acl_checksum" not in resp.body.decode()
        assert deployed == []  # nothing is written before the explicit execute
        resp = await h.post(f"/approvals/{approval.approval_id}/execute")
        assert resp.status == 200
        assert resp.data["done"] is True
        assert resp.data["action"] == "acl_deploy"
        assert deployed == [approval.approval_id]
        h.assert_no_secret(ADMIN_ID)
    await stop(env)


async def test_ssh_pin_routes(disks, tmp_path, monkeypatch):
    env = await cm_env(disks, tmp_path)
    confirm = fake_approval(GuardedAction.SSH_PIN_CONFIRM, env.rid)
    reset = fake_approval(GuardedAction.SSH_PIN_RESET, env.rid)
    done: list[str] = []

    async def req_confirm(rid: str, *, actor: Any) -> Any:
        return confirm

    async def req_reset(rid: str, *, actor: Any) -> Any:
        return reset

    async def do_confirm(aid: str, *, actor: Any) -> dict[str, Any]:
        done.append("confirm")
        return {"state": "pinned", "confirmed_by": ADMIN_ID}

    async def do_reset(aid: str, *, actor: Any) -> dict[str, Any]:
        done.append("reset")
        return {"state": "none"}

    patch_api(monkeypatch, env.api, "async_request_ssh_pin_confirm", req_confirm)
    patch_api(monkeypatch, env.api, "async_request_ssh_pin_reset", req_reset)
    patch_api(monkeypatch, env.api, "async_confirm_ssh_pin", do_confirm)
    patch_api(monkeypatch, env.api, "async_reset_ssh_pin", do_reset)
    with_fake_approvals(monkeypatch, env.api, confirm, reset)
    async with http(env.hass) as h:
        resp = await h.post(f"/routers/{env.rid}/ssh-pin/confirm")
        assert resp.data["approval_id"] == confirm.approval_id
        resp = await h.post(f"/routers/{env.rid}/ssh-pin/reset")
        assert resp.data["approval_id"] == reset.approval_id
        resp = await h.post(f"/routers/{env.rid}/ssh-pin/drop")
        assert resp.status == 400
        assert (await h.post(f"/approvals/{confirm.approval_id}/execute")).status == 200
        assert (await h.post(f"/approvals/{reset.approval_id}/execute")).status == 200
        assert done == ["confirm", "reset"]
        h.assert_no_secret(ADMIN_ID)
    await stop(env)


# ---------------------------------------------------------------------------
# secrets, user ids, logs
# ---------------------------------------------------------------------------


async def test_secret_never_in_any_response(disks, tmp_path, caplog, monkeypatch):
    no_min_gap(monkeypatch)  # every route is called back to back
    env = await cm_env(disks, tmp_path, routers=2, options=ON)
    router_api = acl_capable(env)  # the acl-offer route reads the live ACL
    caplog.set_level("DEBUG")
    async with http(env.hass) as h:
        bid = (await backup(h, env.rid))["backup_id"]
        change_live(env, env.rid, "wireless")
        await h.post(f"/routers/{env.rid}/drift/check")
        for view in cv.CONFIG_VIEWS:
            if view is cv.DownloadView:
                continue  # the plaintext export, tested above
            path = sample_path(
                view,
                router_id=env.rid,
                backup_id=bid,
                drift_id="drift_0",
            )
            resp = await h.call(method_of(view), path)
            # no route may crash on the current core (a 500 is a bug here)
            assert resp.status < 500, (route_id(view), resp.body[:300])
        await h.get(f"/routers/{env.rid}/diff", params={"from": bid})
        env.provider.fail["validate"] = ProviderError(f"{SECRET} broke")
        resp = await h.post(f"/versions/{bid}/validate")
        assert resp.status == 502
        env.provider.fail["compare"] = RuntimeError(f"{SECRET} broke")
        resp = await h.get(f"/routers/{env.rid}/diff", params={"from": bid})
        assert resp.status >= 500
        h.assert_no_secret(ADMIN_ID, "user-plain", router_api._password)
    assert SECRET not in caplog.text
    await stop(env)


# What the panel reads (frontend/topology/src/enterprise/config/configLogic.ts
# parsers, configTypes.ts); top-level keys per route answer.
FRONTEND_KEYS: dict[str, set[str]] = {
    "overview": {"provider", "pending_approvals", "routers"},
    "router_summary": {
        "router_id",
        "name",
        "enabled",
        "status",
        "error_class",
        "running",
        "last_backup_at",
        "versions",
        "capability",
        "schedule",
        "drift",
        "openwrt_version",
    },
    "router": {"router_id", "enabled", "capabilities", "ssh_pin", "acl"},
    "version": {
        "backup_id",
        "router_id",
        "created_at",
        "last_seen_at",
        "reason",
        "backup_type",
        "status",
        "error_class",
        "protected",
        "created_by",
        "openwrt_version",
        "validation",
        "warnings",
        "note",
        "artifacts",
        "size_bytes",
        "sha256",
    },
    "diff": {"from", "to", "complete", "truncated", "changes"},
    "drift": {"state", "report", "acks"},
    "restore": {
        "backup_id",
        "compatible",
        "findings",
        "steps",
        "warnings",
        "instructions",
        "requires_reboot",
        "expires_at",
    },
    "approval": {
        "approval_id",
        "action",
        "router_id",
        "subject_id",
        "status",
        "requested_by",
        "expires_at",
    },
    "acl_offer": {"approval", "offer"},
    "backup": {"backup_id", "created", "status"},
    "execute": {"done"},
}
# The only places a mask may appear: the old/new value of a secret change.
_DIFF_VALUE_KEYS = {"old", "new", "before", "after"}


def masked_paths(data: Any, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """Every path whose value (or key) is the core's mask."""
    from custom_components.openwrt_router.core_masking import MASK

    found: list[tuple[Any, ...]] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if MASK in str(key):
                found.append((*path, key))
            found.extend(masked_paths(value, (*path, key)))
    elif isinstance(data, list):
        for i, value in enumerate(data):
            found.extend(masked_paths(value, (*path, i)))
    elif isinstance(data, str) and MASK in data:
        found.append(path)
    return found


def _allowed_mask(body: Any, path: tuple[Any, ...]) -> bool:
    """A mask under changes[i].<old|new|before|after> of a secret change."""
    if len(path) != 3 or path[0] != "changes" or path[2] not in _DIFF_VALUE_KEYS:
        return False
    return body["changes"][path[1]].get("secret") is True


async def test_every_route_succeeds_with_readable_frontend_fields(
    disks, tmp_path, monkeypatch
):
    no_min_gap(monkeypatch)  # every route is called back to back
    """Real core, every route R1-R20 reaches 200 (contract changes #100-#114).

    Every JSON answer carries the fields the panel reads, none of them is
    masked (only the old/new value of a secret diff change is), and no
    plaintext secret (config value, router password, user id) goes out.
    """
    env = await cm_env(disks, tmp_path, routers=2, options=ON)
    acl_router = acl_capable(env)
    pin_rid = env.rids[1]
    pin_router = ssh_api()
    env.coords[pin_rid].api = pin_router

    async def compare(base: Any, other: Any, ctx: Any, **_: Any) -> ConfigDiff:
        return ConfigDiff(
            base=base,
            other=other,
            compared_at=utcnow(),
            changes=(
                ConfigChange(
                    kind=ChangeKind.MODIFIED,
                    config="wireless",
                    section="default_radio0",
                    option="key",
                    before=SECRET,
                    after=SECRET + "2",
                ),
                ConfigChange(
                    kind=ChangeKind.MODIFIED,
                    config="system",
                    section="cfg01",
                    option="hostname",
                    before="gw-a",
                    after="gw-b",
                ),
            ),
        )

    monkeypatch.setattr(env.provider, "async_compare", compare)
    ok: set[str] = set()
    bodies: list[tuple[str, Any]] = []

    async def call(route: str, method: str, path: str, **kw: Any) -> Any:
        resp = await h.call(method, cv.BASE_URL + path, **kw)
        assert resp.status == 200, (route, resp.status, resp.body[:300])
        assert resp.headers.get("Cache-Control") == "no-store", route
        ok.add(route)
        if resp.headers.get("Content-Type", "").startswith("application/json"):
            bodies.append((route, resp.data))
            return resp.data
        return resp

    def has(keys: str, data: Any) -> None:
        missing = FRONTEND_KEYS[keys] - set(data)
        assert not missing, (keys, missing)

    rid = env.rid
    async with http(env.hass) as h:
        created = await call("backup", "post", f"/routers/{rid}/backup")
        has("backup", created)
        bid = created["backup_id"]
        overview = await call("overview", "get", "/overview")
        has("overview", overview)
        for summary in overview["routers"]:
            has("router_summary", summary)
        has("router", await call("router", "get", f"/routers/{rid}"))
        versions = await call("versions", "get", f"/routers/{rid}/versions")
        assert versions["versions"], versions
        has("version", versions["versions"][0])
        has("version", await call("version", "get", f"/versions/{bid}"))
        has("version", await call("validate", "post", f"/versions/{bid}/validate"))
        has(
            "version",
            await call(
                "protect", "post", f"/versions/{bid}/protect", body={"protected": True}
            ),
        )
        diff = await call("diff", "get", f"/routers/{rid}/diff?from={bid}")
        has("diff", diff)
        assert [c["secret"] for c in diff["changes"]] == [True, False]
        assert diff["changes"][1]["new"] == "gw-b"  # a plain value stays readable
        change_live(env, rid, "dropbear")
        drift = await call("drift_check", "post", f"/routers/{rid}/drift/check")
        has("drift", drift)
        drift_id = drift["report"]["drift_id"]
        has("drift", await call("drift", "get", f"/routers/{rid}/drift"))
        has(
            "drift",
            await call(
                "drift_ack",
                "post",
                f"/routers/{rid}/drift/{drift_id}/ack",
                body={"state": "acknowledged", "note": "planned"},
            ),
        )
        has(
            "restore",
            await call("restore_check", "post", f"/versions/{bid}/restore-check"),
        )
        # export: request, approve (second admin), download once
        export = await call("export", "post", f"/versions/{bid}/export")
        has("approval", export)
        approvals = await call("approvals", "get", "/approvals")
        assert approvals["approvals"]
        has("approval", approvals["approvals"][0])
        has(
            "approval",
            await call(
                "approve",
                "post",
                f"/approvals/{export['approval_id']}/approve",
                user=OTHER_ADMIN_ID,
            ),
        )
        await call(
            "download",
            "post",
            f"/approvals/{export['approval_id']}/download",
            record=False,  # the plaintext export, tested above
        )
        # a second export, rejected
        other = await call("export", "post", f"/versions/{bid}/export")
        has(
            "approval",
            await call(
                "reject",
                "post",
                f"/approvals/{other['approval_id']}/reject",
                body={"reason": "not now"},
            ),
        )
        # ACL offer -> approve -> execute (real core, deploy over ubus)
        offer = await call("acl_offer", "post", f"/routers/{rid}/acl-offer")
        has("acl_offer", offer)
        assert {"added", "removed", "risks"} <= set(offer["offer"])
        aid = offer["approval"]["approval_id"]
        await call("approve", "post", f"/approvals/{aid}/approve", user=OTHER_ADMIN_ID)
        done = await call("execute", "post", f"/approvals/{aid}/execute")
        has("execute", done)
        await drain(env.hass)
        # SSH pin: first contact leaves a pending key; confirm, then reset
        with _patched(FakeRouter(KEY_A)), pytest.raises(OpenWrtHostKeyError):
            await env.core.manager._context().async_ssh_run_pinned(
                pin_rid, "uci show", timeout=5
            )
        for op in ("confirm", "reset"):
            req = await call("ssh_pin", "post", f"/routers/{pin_rid}/ssh-pin/{op}")
            has("approval", req)
            await call(
                "approve",
                "post",
                f"/approvals/{req['approval_id']}/approve",
                user=OTHER_ADMIN_ID,
            )
            done = await call(
                "execute", "post", f"/approvals/{req['approval_id']}/execute"
            )
            has("execute", done)
        assert env.api.ssh_pin_status(pin_rid)["state"] == "none"
        h.assert_no_secret(
            ADMIN_ID, OTHER_ADMIN_ID, acl_router._password, pin_router._password
        )
    assert ok == {route_id(v) for v in cv.CONFIG_VIEWS}
    for route, body in bodies:
        bad = [p for p in masked_paths(body) if not _allowed_mask(body, p)]
        assert not bad, (route, bad)
    await stop(env)


def test_acl_offer_restores_only_the_registry_risk_texts():
    """The fixed tier warning comes back; anything else stays masked."""
    from custom_components.openwrt_router.acl_provisioning import (
        DEFAULT_TIER_REGISTRY,
        TIER_CONFIG_BACKUP_READ,
    )
    from custom_components.openwrt_router.core_masking import MASK

    risk = DEFAULT_TIER_REGISTRY.get(TIER_CONFIG_BACKUP_READ).risk
    forged = f"psk: {SECRET}"
    details = [
        {"tier_id": TIER_CONFIG_BACKUP_READ, "risk": risk},
        {"tier_id": TIER_CONFIG_BACKUP_READ, "risk": risk + " extra: " + SECRET},
        {"tier_id": "no_such_tier", "risk": forged},
        {"tier_id": TIER_CONFIG_BACKUP_READ, "risk": forged},
    ]
    raw = {"offer": {"risks": [d["risk"] for d in details], "risk_details": details}}
    body = cv.output(raw, b"0" * 16, ADMIN_ID)
    assert MASK in body["offer"]["risks"][0]  # the core over-masks the sentence
    cv.AclOfferView().restore_constants(raw, body)
    risks = body["offer"]["risks"]
    assert risks[0] == risk
    assert [d["risk"] for d in body["offer"]["risk_details"]] == risks
    assert all(MASK in r for r in risks[1:])
    assert SECRET not in json.dumps(body)


def test_output_replaces_actors_and_pseudonymises():
    salt = b"0" * 16
    data = {
        "created_by": {"kind": "user", "user_id": ADMIN_ID},
        "list": [{"by": {"kind": "system", "module": "x"}}],
        "nested": {"user_id": ADMIN_ID},
        "key": SECRET,
    }
    out = cv.output(data, salt, ADMIN_ID)
    assert out["created_by"] == {"kind": "user", "mine": True}
    assert out["list"][0]["by"] == {"kind": "system", "mine": False}
    assert ADMIN_ID not in json.dumps(out)
    assert SECRET not in json.dumps(out)
    assert cv.output(data, salt, "other")["created_by"]["mine"] is False
    assert cv.output(data, salt, None)["created_by"]["mine"] is False


def _salts_of_routes(monkeypatch: Any) -> list[bytes]:
    """Every salt a route passes to ``output`` (the module key, contract #100)."""
    seen: list[bytes] = []
    real = cv.output

    def spy(data: Any, salt: bytes, user_id: str | None) -> Any:
        seen.append(salt)
        return real(data, salt, user_id)

    monkeypatch.setattr(cv, "output", spy)
    return seen


async def test_route_salt_is_the_module_key(disks, tmp_path, monkeypatch, caplog):
    """With a key the pseudonym salt is the module key, stable over restarts."""
    env = await cm_env(disks, tmp_path)
    key = await env.api.async_get_installation_key()  # creates it on first use
    assert env.api.installation_key_state == "ok"
    assert CONFIG_MANAGER_MODULE in env.core.audit.registered_modules()
    want = derive_module_key(key, CONFIG_MANAGER_MODULE, CONFIG_ROUTE_PSEUDONYM_PURPOSE)
    seen = _salts_of_routes(monkeypatch)
    caplog.set_level("DEBUG")
    async with http(env.hass) as h:
        assert (await h.get("/overview")).status == 200
        assert (await h.get(f"/routers/{env.rid}/versions")).status == 200
    assert seen and set(seen) == {want}
    assert env.runtime.route_salt_stable is True
    assert env.runtime.stats["route_salt_ephemeral"] == 0
    assert want.hex() not in caplog.text and key.hex() not in caplog.text
    ctx = cv.RequestContext(env.hass, env.runtime, env.api, ADMIN, ADMIN_ID, want)
    assert "salt" not in repr(ctx) and want.hex() not in repr(ctx)
    # same installation key after a restart -> same salt -> same pseudonyms
    env = await restart(env)
    assert await env.runtime.async_route_salt() == want
    # the last release removes our prefix (and only ours)
    audit = env.core.audit
    for entry in env.entries:
        cm.async_release_config_manager(env.hass, entry.entry_id)
    assert CONFIG_MANAGER_MODULE not in audit.registered_modules()
    await stop(env)


async def test_route_salt_without_a_key_is_random_and_creates_none(
    disks, tmp_path, caplog
):
    """First start: random for this run, counted, logged once, no key made."""
    env = await cm_env(disks, tmp_path)
    assert env.api.installation_key_state == "uninitialised"
    caplog.set_level("INFO")
    runtime = env.runtime
    salt = await runtime.async_route_salt()
    assert len(salt) == 16
    assert await runtime.async_route_salt() is salt  # decided once per run
    assert runtime.route_salt_stable is False
    assert runtime.stats["route_salt_ephemeral"] == 1
    assert env.api.installation_key_state == "uninitialised"  # nothing created
    assert caplog.text.count("random for this run") == 1
    assert salt.hex() not in caplog.text
    await stop(env)


async def test_route_salt_when_the_prefix_is_taken(disks, tmp_path):
    """Another module holds the prefix: no module key, a random salt."""
    env = await cm_env(disks, tmp_path, attach=False)
    env.api.register_event_prefix(CONFIG_MANAGER_EVENT_PREFIX, module="other")
    await env.api.async_get_installation_key()
    for entry in env.entries:
        await attach_entry(env, entry)
    salt = await env.runtime.async_route_salt()
    assert env.runtime.route_salt_stable is False
    assert env.runtime.stats["route_salt_ephemeral"] == 1
    assert len(salt) == 16
    audit = env.core.audit
    for entry in env.entries:
        cm.async_release_config_manager(env.hass, entry.entry_id)
    assert "other" in audit.registered_modules()  # never removed by us
    await stop(env)


@pytest.mark.parametrize(
    ("name", "safe"),
    [
        ("backup.tar.gz", "backup.tar.gz"),
        ('a"b.tgz', "a_b.tgz"),
        ("../../etc/passwd", "_.._etc_passwd"),
        ("..", "config-backup.bin"),
        ("", "config-backup.bin"),
        (None, "config-backup.bin"),
        ("ä\r\nx", "___x"),
        ("x" * 300, "x" * 100),
    ],
)
def test_safe_filename(name, safe):
    assert cv.safe_filename(name) == safe


async def test_runtime_routes_add_no_router_polling(disks, tmp_path):
    """Reading routes never start a probe or a router call."""
    env = await cm_env(disks, tmp_path)
    calls = list(env.provider.calls)
    async with http(env.hass) as h:
        for path in (
            "/overview",
            f"/routers/{env.rid}",
            f"/routers/{env.rid}/versions",
            f"/routers/{env.rid}/drift",
            "/approvals",
        ):
            assert (await h.get(path)).status == 200, path
    await drain(env.hass)
    assert env.provider.calls == calls
    assert env.router_calls() == []
    await stop(env)
