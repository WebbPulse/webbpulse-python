"""Tests for the configurable error envelope and the `webbpulse.dynamodb` error handlers.

The exact-body cases are adapted from CarModPicker's own error handler tests, because the
point of the `"detailed"` shape is that a consumer can drop its local handlers without
changing a single byte any caller already reads.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from typing import Any, ClassVar

import pytest
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel

from webbpulse.dynamodb import ConditionFailed, DynamoError, ItemNotFound, TransactionCanceled
from webbpulse.http import (
    DYNAMODB_ERROR_MESSAGES,
    DynamoDBErrorHandlerOptions,
    ErrorContext,
    ErrorResponse,
    create_app,
    detailed_error_body,
    install_dynamodb_error_handlers,
    register_error_handlers,
    resolve_error_envelope,
)

BASE_KEYS = {"success", "status", "message", "request_id"}


class _Payload(BaseModel):
    """A request body used to provoke a validation error."""

    name: str
    count: int


def _router() -> APIRouter:
    """One route per error condition the envelope has to render."""
    router = APIRouter()

    @router.get("/boom-4xx")
    async def boom_4xx() -> None:
        """Raise a client error carrying a plain message."""
        raise HTTPException(status_code=403, detail="You may not do that")

    @router.get("/boom-5xx")
    async def boom_5xx() -> None:
        """Raise a server error carrying a detail that must not escape."""
        raise HTTPException(status_code=500, detail="secret internal detail")

    @router.get("/boom-structured")
    async def boom_structured() -> None:
        """Raise a conflict carrying a message, an error code and structured details."""
        raise HTTPException(
            status_code=409,
            detail={
                "message": "You already have one of those.",
                "error_code": "PART_ALREADY_EXISTS",
                "details": {"existing_part_id": "abc123"},
            },
        )

    @router.get("/boom-unhandled")
    async def boom_unhandled() -> None:
        """Raise an unhandled exception."""
        raise RuntimeError("a leaked stack trace would be bad")

    @router.get("/missing")
    async def missing() -> None:
        """Raise the package's item not found error."""
        raise ItemNotFound("test-users", {"id": "abc"})

    @router.get("/duplicate")
    async def duplicate() -> None:
        """Raise the package's condition failed error."""
        raise ConditionFailed("test-users", "attribute_not_exists(id)", {"id": "abc"})

    @router.get("/canceled-conditional")
    async def canceled_conditional() -> None:
        """Raise a transaction cancelled by a failed condition."""
        raise TransactionCanceled([{"Code": "None"}, {"Code": "ConditionalCheckFailed"}])

    @router.get("/canceled-other")
    async def canceled_other() -> None:
        """Raise a transaction cancelled for a reason that is not a conflict."""
        raise TransactionCanceled([{"Code": "TransactionConflict"}])

    @router.post("/validate")
    async def validate(payload: _Payload) -> dict[str, str]:
        """Echo a validated payload, so an invalid one produces a validation error."""
        return {"name": payload.name}

    return router


def _app(**kwargs: Any) -> TestClient:
    """Build a client for an app carrying the routes and the options under test."""
    app = create_app([_router()], dynamodb_error_handlers=True, **kwargs)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def detailed() -> TestClient:
    """A client for an app using the `"detailed"` envelope."""
    return _app(error_envelope="detailed")


@pytest.fixture
def default() -> TestClient:
    """A client for an app using the default envelope."""
    return _app()


def assert_exact(body: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    """The whole envelope, with a real request id and nothing else besides."""
    assert body.keys() == expected.keys() | {"request_id"}
    assert {key: body[key] for key in expected} == expected
    assert isinstance(body["request_id"], str) and body["request_id"] != "-"
    assert "detail" not in body


class TestDetailedShape:
    """The `"detailed"` envelope, pinned field by field against what CarModPicker emits."""

    def test_4xx_keeps_its_message_and_code(self, detailed: TestClient) -> None:
        """A client error keeps its message and carries the per status code."""
        response = detailed.get("/boom-4xx")
        assert response.status_code == 403
        assert_exact(
            response.json(),
            {
                "success": False,
                "status": 403,
                "message": "You may not do that",
                "error_code": "FORBIDDEN",
            },
        )

    def test_5xx_is_sanitised(self, detailed: TestClient) -> None:
        """A server error's detail is replaced with a generic message."""
        response = detailed.get("/boom-5xx")
        assert response.status_code == 500
        assert "secret internal detail" not in response.text
        assert_exact(
            response.json(),
            {
                "success": False,
                "status": 500,
                "message": "Internal server error.",
                "error_code": "INTERNAL_ERROR",
            },
        )

    def test_unhandled_exception_leaks_nothing(self, detailed: TestClient) -> None:
        """An unhandled exception leaks neither message nor traceback."""
        response = detailed.get("/boom-unhandled")
        assert response.status_code == 500
        assert "a leaked stack trace would be bad" not in response.text
        assert response.json()["error_code"] == "INTERNAL_ERROR"

    def test_structured_detail_carries_route_code_and_details(self, detailed: TestClient) -> None:
        """A route's own `error_code` and `details` survive into the envelope."""
        response = detailed.get("/boom-structured")
        assert response.status_code == 409
        assert_exact(
            response.json(),
            {
                "success": False,
                "status": 409,
                "message": "You already have one of those.",
                "error_code": "PART_ALREADY_EXISTS",
                "details": {"existing_part_id": "abc123"},
            },
        )

    def test_validation_error_has_flat_field_details_and_no_errors_key(self, detailed: TestClient) -> None:
        """A 422 reports fields in a flat `details` list and drops the legacy `errors` key."""
        response = detailed.post("/validate", json={})
        assert response.status_code == 422
        body = response.json()
        assert body.keys() == BASE_KEYS | {"error_code", "details"}
        assert "errors" not in body
        assert body["error_code"] == "VALIDATION_ERROR"
        assert {entry["field"] for entry in body["details"]} == {"name", "count"}
        for entry in body["details"]:
            assert set(entry) == {"field", "message", "type"}

    def test_validation_error_never_echoes_the_input(self, detailed: TestClient) -> None:
        """A rejected value could be a password, so it must not come back."""
        response = detailed.post("/validate", json={"name": "n", "count": "hunter2"})
        assert response.status_code == 422
        assert "hunter2" not in response.text

    def test_unknown_path_returns_the_envelope(self, detailed: TestClient) -> None:
        """An unmatched route returns the envelope, never the raw Starlette detail body."""
        response = detailed.get("/no/such/route")
        assert response.status_code == 404
        body = response.json()
        assert body != {"detail": "Not Found"}
        assert_exact(
            body,
            {
                "success": False,
                "status": 404,
                "message": "The requested resource was not found.",
                "error_code": "NOT_FOUND",
            },
        )

    def test_wrong_method_returns_the_envelope(self, detailed: TestClient) -> None:
        """A wrong method returns the envelope with the method not allowed code."""
        response = detailed.delete("/boom-4xx")
        assert response.status_code == 405
        assert response.json()["error_code"] == "METHOD_NOT_ALLOWED"

    def test_the_detailed_shape_implies_both_legacy_options(self) -> None:
        """`"detailed"` turns on codes and field details without the consumer naming them."""
        client = _app(error_envelope="detailed", error_codes=False, validation_details=False)
        body = client.post("/validate", json={}).json()
        assert body["error_code"] == "VALIDATION_ERROR"
        assert body["details"]


class TestDefaultShapeUnchanged:
    """The default envelope, which this release must not move."""

    def test_the_base_body_has_exactly_the_four_fields(self, default: TestClient) -> None:
        """No `error_code` and no `details` unless the consumer asks."""
        response = default.get("/boom-4xx")
        assert response.status_code == 403
        assert response.json().keys() == BASE_KEYS

    def test_the_validation_body_keeps_the_errors_key(self, default: TestClient) -> None:
        """The default 422 still carries the `errors` list callers have always read."""
        body = default.post("/validate", json={}).json()
        assert body["errors"]
        assert "details" not in body
        assert "error_code" not in body

    def test_the_explicit_default_name_matches_the_omitted_one(self) -> None:
        """Passing `"default"` is the same as passing nothing."""
        explicit = _app(error_envelope="default").get("/boom-4xx").json()
        assert explicit.keys() == _app().get("/boom-4xx").json().keys()


class TestDynamoDbErrorHandlers:
    """`webbpulse.dynamodb`'s own exception types, rendered by the opt-in handlers."""

    NOT_FOUND: ClassVar[dict[str, Any]] = {
        "success": False,
        "status": 404,
        "message": "The requested resource was not found.",
        "error_code": "NOT_FOUND",
    }
    CONFLICT: ClassVar[dict[str, Any]] = {
        "success": False,
        "status": 409,
        "message": "The resource was modified by another request. Try again.",
        "error_code": "CONFLICT",
    }
    INTERNAL: ClassVar[dict[str, Any]] = {
        "success": False,
        "status": 500,
        "message": "Internal server error.",
        "error_code": "INTERNAL_ERROR",
    }

    def test_item_not_found_is_404(self, detailed: TestClient) -> None:
        """Item not found renders as a 404 naming neither the table nor the key."""
        response = detailed.get("/missing")
        assert response.status_code == 404
        assert_exact(response.json(), self.NOT_FOUND)
        assert "test-users" not in response.text

    def test_condition_failed_is_409(self, detailed: TestClient) -> None:
        """A failed condition renders as a 409 and never echoes the condition."""
        response = detailed.get("/duplicate")
        assert response.status_code == 409
        assert_exact(response.json(), self.CONFLICT)
        assert "attribute_not_exists" not in response.text

    def test_transaction_cancelled_by_condition_is_409(self, detailed: TestClient) -> None:
        """A cancellation caused by a failed condition reads as an ordinary lost race."""
        response = detailed.get("/canceled-conditional")
        assert response.status_code == 409
        assert_exact(response.json(), self.CONFLICT)

    def test_transaction_cancelled_for_another_reason_is_500(self, detailed: TestClient) -> None:
        """Anything else is a real fault, and its reason codes stay in the log."""
        response = detailed.get("/canceled-other")
        assert response.status_code == 500
        assert_exact(response.json(), self.INTERNAL)
        assert "TransactionConflict" not in response.text

    def test_the_handlers_render_the_default_shape_too(self, default: TestClient) -> None:
        """The same three conditions under the default envelope, with no `error_code`."""
        assert default.get("/missing").json().keys() == BASE_KEYS
        assert default.get("/duplicate").status_code == 409
        assert default.get("/canceled-other").status_code == 500

    def test_the_messages_are_overridable(self) -> None:
        """A consumer can keep its own wording without writing a handler."""
        app = FastAPI()
        register_error_handlers(app, error_envelope="detailed")
        install_dynamodb_error_handlers(
            app,
            error_envelope="detailed",
            not_found_message="Resource not found",
            conflict_message="Resource already exists or was modified concurrently",
        )

        @app.get("/missing")
        async def missing() -> None:
            """Raise the package's item not found error."""
            raise ItemNotFound("t")

        @app.get("/duplicate")
        async def duplicate() -> None:
            """Raise the package's condition failed error."""
            raise ConditionFailed("t")

        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/missing").json()["message"] == "Resource not found"
        assert client.get("/duplicate").json()["message"] == "Resource already exists or was modified concurrently"

    def test_a_subclass_uses_its_base_handler(self) -> None:
        """Starlette walks the MRO, so a service's own subclass needs no entry of its own."""

        class PostNotFound(ItemNotFound):
            """A service's own narrowing of the package's type."""

        app = FastAPI()
        register_error_handlers(app, error_envelope="detailed", dynamodb_errors=True)

        @app.get("/work")
        async def work() -> None:
            """Raise the subclass."""
            raise PostNotFound("posts")

        assert TestClient(app, raise_server_exceptions=False).get("/work").status_code == 404

    def test_the_handlers_are_opt_in(self) -> None:
        """Without the flag a repository exception is an unhandled 500."""
        client = TestClient(create_app([_router()]), raise_server_exceptions=False)
        response = client.get("/missing")
        assert response.status_code == 500
        assert response.json()["status"] == 500

    def test_the_internal_message_is_overridable(self) -> None:
        """A consumer can pin the non-conditional cancellation wording too."""
        app = FastAPI()
        register_error_handlers(app, error_envelope="detailed")
        install_dynamodb_error_handlers(
            app,
            error_envelope="detailed",
            internal_error_message="Internal server error",
        )

        @app.get("/canceled-other")
        async def canceled_other() -> None:
            """Raise a transaction cancelled for a reason that is not a conflict."""
            raise TransactionCanceled([{"Code": "TransactionConflict"}])

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/canceled-other")
        assert response.status_code == 500
        assert response.json()["message"] == "Internal server error"

    def test_an_overridden_message_leaves_the_others_alone(self) -> None:
        """Pinning one message keeps the package default for the other two."""
        app = FastAPI()
        register_error_handlers(app, error_envelope="detailed")
        install_dynamodb_error_handlers(app, error_envelope="detailed", not_found_message="Gone")
        app.include_router(_router())

        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/missing").json()["message"] == "Gone"
        assert client.get("/duplicate").json()["message"] == DYNAMODB_ERROR_MESSAGES["conflict"]
        assert client.get("/canceled-other").json()["message"] == DYNAMODB_ERROR_MESSAGES["internal"]


class TestDynamoDbOptionsForwarding:
    """`DynamoDBErrorHandlerOptions` reaching the handlers through either flag."""

    OPTIONS: ClassVar[DynamoDBErrorHandlerOptions] = DynamoDBErrorHandlerOptions(
        not_found_message="Resource not found",
        conflict_message="Resource already exists or was modified concurrently",
        internal_error_message="Internal server error",
    )

    def _assert_pinned(self, client: TestClient) -> None:
        """Every one of the three messages is the consumer's, not the package's."""
        assert client.get("/missing").json()["message"] == "Resource not found"
        assert client.get("/duplicate").json()["message"] == "Resource already exists or was modified concurrently"
        assert client.get("/canceled-other").json()["message"] == "Internal server error"

    def test_register_error_handlers_forwards_the_options(self) -> None:
        """`dynamodb_errors` takes the options in place of `True` and forwards every field."""
        app = FastAPI()
        register_error_handlers(app, error_envelope="detailed", dynamodb_errors=self.OPTIONS)
        app.include_router(_router())
        self._assert_pinned(TestClient(app, raise_server_exceptions=False))

    def test_create_app_forwards_the_options(self) -> None:
        """`dynamodb_error_handlers` does the same, so a consumer needs no second call."""
        app = create_app(
            [_router()],
            error_envelope="detailed",
            dynamodb_error_handlers=self.OPTIONS,
        )
        self._assert_pinned(TestClient(app, raise_server_exceptions=False))

    def test_the_options_work_under_the_default_envelope(self) -> None:
        """Forwarding is independent of the shape, so the default envelope pins them too."""
        app = create_app([_router()], dynamodb_error_handlers=self.OPTIONS)
        client = TestClient(app, raise_server_exceptions=False)
        self._assert_pinned(client)
        assert client.get("/missing").json().keys() == BASE_KEYS

    def test_empty_options_are_the_package_defaults(self) -> None:
        """Passing options that pin nothing is exactly `True`."""
        app = create_app(
            [_router()],
            error_envelope="detailed",
            dynamodb_error_handlers=DynamoDBErrorHandlerOptions(),
        )
        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/missing").json()["message"] == DYNAMODB_ERROR_MESSAGES["not_found"]
        assert client.get("/duplicate").json()["message"] == DYNAMODB_ERROR_MESSAGES["conflict"]
        assert client.get("/canceled-other").json()["message"] == DYNAMODB_ERROR_MESSAGES["internal"]

    def test_the_options_are_frozen(self) -> None:
        """The options carry no mutable state a consumer could change after installation."""
        with pytest.raises((AttributeError, FrozenInstanceError)):
            self.OPTIONS.not_found_message = "changed"  # type: ignore[misc]


class TestDefaultDynamoDbMessagesUnchanged:
    """A regression guard: `True` renders byte identically to 0.23.0."""

    EXPECTED: ClassVar[Mapping[str, str]] = {
        "/missing": "The requested resource was not found.",
        "/duplicate": "The resource was modified by another request. Try again.",
        "/canceled-conditional": "The resource was modified by another request. Try again.",
        "/canceled-other": "Internal server error.",
    }

    @pytest.mark.parametrize("envelope", [None, "detailed"])
    def test_the_flag_still_renders_the_0_23_0_wording(self, envelope: str | None) -> None:
        """The literals are pinned here, not read from the package, so a drift fails."""
        app = create_app([_router()], error_envelope=envelope, dynamodb_error_handlers=True)
        client = TestClient(app, raise_server_exceptions=False)
        for path, message in self.EXPECTED.items():
            assert client.get(path).json()["message"] == message, path

    def test_the_message_table_still_carries_the_0_23_0_entries(self) -> None:
        """`DYNAMODB_ERROR_MESSAGES` gained a key and changed none of the two it had."""
        assert DYNAMODB_ERROR_MESSAGES["not_found"] == "The requested resource was not found."
        assert DYNAMODB_ERROR_MESSAGES["conflict"] == "The resource was modified by another request. Try again."
        assert DYNAMODB_ERROR_MESSAGES["internal"] == "Internal server error."


class TestDynamoDbExceptionTypes:
    """The exception types themselves, which consumers raise."""

    def test_every_type_shares_one_base(self) -> None:
        """One `except DynamoError` or one map entry covers the whole hierarchy."""
        for exc_type in (ItemNotFound, ConditionFailed, TransactionCanceled):
            assert issubclass(exc_type, DynamoError)

    def test_item_not_found_records_the_table_and_key(self) -> None:
        """The table and key are kept as attributes, for the log."""
        exc = ItemNotFound("users", {"id": "abc"})
        assert (exc.table, exc.key) == ("users", {"id": "abc"})
        assert "users" in str(exc)

    def test_condition_failed_records_its_condition(self) -> None:
        """The condition expression is kept as an attribute, for the log."""
        exc = ConditionFailed("users", "attribute_not_exists(pk)", {"pk": "1"})
        assert (exc.table, exc.condition, exc.key) == (
            "users",
            "attribute_not_exists(pk)",
            {"pk": "1"},
        )

    @pytest.mark.parametrize(
        ("reasons", "expected"),
        [
            ([{"Code": "ConditionalCheckFailed"}], True),
            ([{"Code": "None"}, {"Code": "ConditionalCheckFailed"}], True),
            ([{"Code": "TransactionConflict"}], False),
            ([], False),
            (None, False),
        ],
    )
    def test_conditional_check_failed_inspects_every_reason(
        self, reasons: list[dict[str, str]] | None, expected: bool
    ) -> None:
        """The conflict decision is read from the reasons, never assumed."""
        assert TransactionCanceled(reasons).conditional_check_failed is expected

    def test_the_key_is_copied_rather_than_aliased(self) -> None:
        """A caller mutating the dict it passed cannot change what gets logged."""
        key = {"id": "abc"}
        exc = ItemNotFound("users", key)
        key["id"] = "changed"
        assert exc.key == {"id": "abc"}


class TestCallableRenderer:
    """A consumer supplying its own renderer."""

    @staticmethod
    def _renderer(context: ErrorContext) -> dict[str, Any]:
        """Render a flat shape of the consumer's own design."""
        from webbpulse.http import request_id

        body: dict[str, Any] = {
            "ok": False,
            "code": context.error_code,
            "reason": context.message,
            "request_id": request_id(context.request),
            "http_status": context.status,
        }
        if context.validation_errors is not None:
            body["fields"] = [list(error["loc"]) for error in context.validation_errors]
        return body

    def test_a_callable_renders_every_handler(self) -> None:
        """One callable covers HTTP errors, routing errors, faults and the DynamoDB types."""
        client = _app(error_envelope=self._renderer)

        for path, status_code in (
            ("/boom-4xx", 403),
            ("/boom-unhandled", 500),
            ("/no/such/route", 404),
            ("/missing", 404),
            ("/canceled-conditional", 409),
        ):
            body = client.get(path).json()
            assert body["ok"] is False, path
            assert body["http_status"] == status_code, path
            assert body["request_id"] != "-", path
            assert "success" not in body, path

    def test_a_callable_always_receives_the_error_code(self) -> None:
        """A custom renderer decides whether to emit a code, so it is always handed one."""
        client = _app(error_envelope=self._renderer)
        assert client.get("/boom-4xx").json()["code"] == "FORBIDDEN"
        assert client.get("/missing").json()["code"] == "NOT_FOUND"

    def test_a_callable_receives_the_validation_errors(self) -> None:
        """`validation_errors` reaches the renderer so it can build its own field shape."""
        body = _app(error_envelope=self._renderer).post("/validate", json={}).json()
        assert sorted(body["fields"]) == [["body", "count"], ["body", "name"]]

    def test_a_callable_receives_the_raised_exception(self) -> None:
        """`exception` lets a renderer branch on the type it was given."""
        seen: list[type[BaseException]] = []

        def renderer(context: ErrorContext) -> dict[str, Any]:
            """Record the exception type and render the detailed shape."""
            if context.exception is not None:
                seen.append(type(context.exception))
            return dict(detailed_error_body(context.status, context.message, context.request))

        _app(error_envelope=renderer).get("/missing")
        assert seen == [ItemNotFound]


class TestEnvelopeResolution:
    """`resolve_error_envelope`, which validates the argument at app build time."""

    def test_none_and_default_resolve_to_the_same_renderer(self) -> None:
        """Omitting the option and naming the default are the same thing."""
        assert resolve_error_envelope(None) is resolve_error_envelope("default")

    def test_detailed_resolves_to_its_own_renderer(self) -> None:
        """The two built-in shapes are distinct renderers."""
        assert resolve_error_envelope("detailed") is not resolve_error_envelope("default")

    def test_a_callable_passes_through(self) -> None:
        """A callable is returned unchanged, so a consumer keeps its own identity."""

        def renderer(context: ErrorContext) -> dict[str, Any]:
            """Render nothing in particular."""
            return {}

        assert resolve_error_envelope(renderer) is renderer

    def test_an_unknown_name_raises_at_build_time(self) -> None:
        """A typo belongs at import, not in a 500 under load."""
        with pytest.raises(ValueError, match="error_envelope must be one of"):
            resolve_error_envelope("verbose")

    def test_an_unknown_name_raises_from_create_app(self) -> None:
        """The same refusal reaches a consumer through `create_app`."""
        with pytest.raises(ValueError, match="error_envelope must be one of"):
            create_app(error_envelope="verbose")


class TestDetailedErrorBody:
    """`detailed_error_body`, usable directly by a consumer's own handler."""

    def test_it_fills_the_code_from_the_status(self) -> None:
        """An omitted code falls back to the stable one for the status."""
        body = detailed_error_body(409, "conflict", _FakeRequest())  # type: ignore[arg-type]
        assert body == {
            "success": False,
            "status": 409,
            "message": "conflict",
            "request_id": "-",
            "error_code": "CONFLICT",
        }

    def test_an_unlisted_status_falls_back_to_a_generic_code(self) -> None:
        """A status with no code of its own still gets one."""
        assert detailed_error_body(418, "teapot", _FakeRequest())["error_code"] == "HTTP_ERROR"  # type: ignore[arg-type]
        assert detailed_error_body(599, "gone", _FakeRequest())["error_code"] == "INTERNAL_ERROR"  # type: ignore[arg-type]

    def test_extra_keys_are_carried_through(self) -> None:
        """A consumer can add its own keys, as with `error_body`."""
        body = detailed_error_body(400, "bad", _FakeRequest(), retry_in=5)  # type: ignore[arg-type]
        assert body["retry_in"] == 5


class _FakeRequest:
    """A request stand-in with no state, so `request_id` returns its fallback."""

    class state:
        """Empty request state."""


def test_dynamodb_handlers_and_error_handlers_coexist() -> None:
    """A service can install both the botocore handlers and the package's own types."""
    client = _app(error_envelope="detailed", dynamodb_handlers=True)
    assert client.get("/missing").status_code == 404
    assert client.get("/duplicate").status_code == 409


class _Rejected(Exception):
    """A consumer's own exception, mapped through `exception_map`."""


def _mapped_client(status: int) -> TestClient:
    """A client for an app mapping `_Rejected` to the given status."""
    router = APIRouter()

    @router.get("/work")
    async def work() -> None:
        """Raise the mapped exception."""
        raise _Rejected("an internal detail")

    app = create_app([router], error_envelope="detailed", exception_map={_Rejected: status})
    return TestClient(app, raise_server_exceptions=False)


def test_mapped_exceptions_render_through_the_chosen_envelope() -> None:
    """`exception_map` entries use the same renderer as every other error."""
    response = _mapped_client(409).get("/work")

    assert response.status_code == 409
    assert_exact(
        response.json(),
        {
            "success": False,
            "status": 409,
            "message": "The resource was modified by another request. Try again.",
            "error_code": "CONFLICT",
        },
    )


def test_a_mapped_server_fault_is_still_sanitised_in_the_detailed_shape() -> None:
    """Choosing a shape does not relax the rule that a mapped 5xx never echoes its message."""
    response = _mapped_client(503).get("/work")

    assert response.status_code == 503
    assert "an internal detail" not in response.text
    assert_exact(
        response.json(),
        {
            "success": False,
            "status": 503,
            "message": "Internal server error.",
            "error_code": "SERVICE_UNAVAILABLE",
        },
    )


def _openapi_app() -> FastAPI:
    """An app whose routes validate a body and a path param, so 422s are reachable."""
    router = APIRouter()

    @router.post("/things")
    async def create_thing(payload: _Payload) -> dict[str, str]:
        """Accept a body pydantic has to validate."""
        return {"ok": "yes"}

    @router.get("/things/{thing_id}")
    async def read_thing(thing_id: int) -> dict[str, str]:
        """Accept a path param pydantic has to coerce."""
        return {"ok": "yes"}

    return create_app([router], error_envelope="detailed", instrument=False)


def test_the_detailed_openapi_advertises_the_envelope_and_not_httpvalidationerror() -> None:
    """The generated schema documents what the handlers render, so a contract file matches."""
    spec = _openapi_app().openapi()
    schemas = spec["components"]["schemas"]

    assert "ErrorResponse" in schemas
    assert "ValidationErrorDetail" in schemas
    assert "HTTPValidationError" not in schemas
    assert "ValidationError" not in schemas
    assert "HTTPValidationError" not in json.dumps(spec)


@pytest.mark.parametrize(
    ("path", "method"),
    [("/things", "post"), ("/things/{thing_id}", "get")],
)
def test_every_operation_points_its_422_at_the_envelope(path: str, method: str) -> None:
    """Both a validated body and a validated path param document the envelope."""
    spec = _openapi_app().openapi()
    schema = spec["paths"][path][method]["responses"]["422"]["content"]["application/json"]["schema"]

    assert schema == {"$ref": "#/components/schemas/ErrorResponse"}


def test_the_envelope_schema_carries_every_field_the_handlers_render() -> None:
    """The advertised properties are the ones `detailed_error_body` actually emits."""
    schemas = _openapi_app().openapi()["components"]["schemas"]
    properties = schemas["ErrorResponse"]["properties"]

    assert set(properties) == {"success", "status", "message", "request_id", "error_code", "details"}
    assert set(schemas["ValidationErrorDetail"]["properties"]) == {"field", "message", "type"}


def test_the_advertised_schema_validates_a_real_422_body() -> None:
    """A live validation error parses as the model OpenAPI advertises for it."""
    response = TestClient(_openapi_app()).post("/things", json={"name": "only a name"})

    assert response.status_code == 422
    parsed = ErrorResponse.model_validate(response.json())
    assert parsed.error_code == "VALIDATION_ERROR"
    assert parsed.details is not None
    assert [detail.field for detail in parsed.details] == ["count"]


def test_the_advertised_schema_validates_a_non_validation_error_body() -> None:
    """The same model covers the unmatched route 404, where `details` is absent."""
    response = TestClient(_openapi_app()).get("/no-such-route")

    assert response.status_code == 404
    parsed = ErrorResponse.model_validate(response.json())
    assert parsed.error_code == "NOT_FOUND"
    assert parsed.details is None


def test_the_default_envelope_leaves_the_openapi_schema_untouched() -> None:
    """Opting out keeps FastAPI's own 422 shape, so an existing consumer is unaffected."""
    router = APIRouter()

    @router.post("/things")
    async def create_thing(payload: _Payload) -> dict[str, str]:
        """Accept a body pydantic has to validate."""
        return {"ok": "yes"}

    schemas = create_app([router], instrument=False).openapi()["components"]["schemas"]

    assert "HTTPValidationError" in schemas
    assert "ErrorResponse" not in schemas


def test_an_explicit_responses_argument_still_wins() -> None:
    """A consumer passing its own `responses` is not overridden by the envelope default."""
    router = APIRouter()

    @router.post("/things")
    async def create_thing(payload: _Payload) -> dict[str, str]:
        """Accept a body pydantic has to validate."""
        return {"ok": "yes"}

    app = create_app(
        [router],
        error_envelope="detailed",
        instrument=False,
        responses={422: {"description": "Mine", "model": _Payload}},
    )
    documented = app.openapi()["paths"]["/things"]["post"]["responses"]["422"]

    assert documented["description"] == "Mine"
    assert documented["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/_Payload"}
