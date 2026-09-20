"""Tests for the ephemeral user helpers and the xdist grouping.

Two things carry the risk here. The fallback: a deployment that does not offer the route
must send the suite back to the durable user rather than failing the run, while a route that
exists and is erroring must fail loudly rather than quietly mutating the shared account. And
the secret: the generated password must not reach a repr, a message or an exception.
"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from webbpulse.e2e.ephemeral import (
    BODY_EXCERPT_LIMIT,
    CREATE_PATH,
    RESERVED_EMAIL_DOMAIN,
    Credentials,
    EphemeralUser,
    create_ephemeral_user,
    delete_ephemeral_user,
    describe_delete_failure,
    describe_error_body,
    email_validation_hint,
    ephemeral_email,
    generate_password,
    item_path,
)
from webbpulse.e2e.xdist import (
    SHARED_STATE_GROUP,
    apply_groups,
    group_for,
    worker_id,
)

RUN_ID = "run-1234"
ADMIN_TOKEN = "minted-admin-token"


VALIDATION_ENVELOPE: Any = {
    "success": False,
    "status": 422,
    "error_code": "VALIDATION_ERROR",
    "message": "Request validation failed.",
    "request_id": "req-abc123",
    "details": [{"field": "request", "message": "Field required", "type": "missing"}],
}


class FakeResponse:
    """One scripted HTTP answer."""

    def __init__(self, status_code: int, payload: Any = None, text: str = "") -> None:
        """Hold the status, the body this answer carries and its raw text."""
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self) -> Any:
        """The body, raising the way httpx does when it is not JSON."""
        if isinstance(self._payload, ValueError):
            raise self._payload
        return self._payload


class FakeClient:
    """An `E2EClient` stand-in recording what it was asked and answering a script."""

    def __init__(self, responses: list[Any] | None = None, raises: Exception | None = None) -> None:
        """Hold the answers to give in order and the calls made."""
        self._responses = list(responses or [])
        self._raises = raises
        self.calls: list[dict[str, Any]] = []
        self.tokens: list[str | None] = []

    def with_token(self, token: str | None) -> FakeClient:
        """Record the token and keep answering from the same script."""
        self.tokens.append(token)
        return self

    def post(self, path: str, *, json: Any = None) -> Any:
        """Record a POST and answer the next scripted response."""
        return self.request("POST", path, json=json)

    def request(self, method: str, path: str, *, json: Any = None) -> Any:
        """Record one call and answer the next scripted response."""
        self.calls.append({"method": method, "path": path, "json": json})
        if self._raises is not None:
            raise self._raises
        return self._responses.pop(0)


class TestGeneratePassword:
    """The generated password, which every product's policy has to accept."""

    def test_it_is_the_requested_length(self) -> None:
        """A caller asking for a length gets it."""
        assert len(generate_password(24)) == 24

    def test_it_carries_every_character_class(self) -> None:
        """A policy demanding each class must not reject a run at random."""
        for _ in range(50):
            password = generate_password()
            assert any(char.isupper() for char in password)
            assert any(char.islower() for char in password)
            assert any(char.isdigit() for char in password)
            assert any(not char.isalnum() for char in password)

    def test_two_passwords_differ(self) -> None:
        """Generated from `secrets`, so two runs never share one."""
        assert generate_password() != generate_password()

    def test_it_refuses_a_length_no_policy_would_accept(self) -> None:
        """A password too short to hold the forced classes is a caller error."""
        with pytest.raises(ValueError):
            generate_password(4)


class TestEphemeralEmail:
    """The address, which must be undeliverable and traceable."""

    def test_it_carries_the_run_id(self) -> None:
        """A leaked account can be traced back to the run that made it."""
        assert RUN_ID in ephemeral_email(RUN_ID)

    def test_it_uses_a_reserved_undeliverable_domain(self) -> None:
        """RFC 2606 reserves `.invalid`, so no mail can ever reach a real inbox."""
        assert ephemeral_email(RUN_ID).endswith("@e2e.invalid")

    def test_it_strips_characters_an_address_cannot_hold(self) -> None:
        """A run id from a branch name must not produce an invalid address."""
        assert ephemeral_email("Feature/Thing_42") == "e2e-featurething42@e2e.invalid"

    def test_it_refuses_an_empty_run_id(self) -> None:
        """An address with no run id would collide with every other run."""
        with pytest.raises(ValueError):
            ephemeral_email("   ")


EMAIL_VALIDATION_ENVELOPE: Any = {
    "success": False,
    "status": 500,
    "error_code": "INTERNAL_ERROR",
    "message": "value is not a valid email address: The part after the @-sign is a special-use or reserved name.",
    "request_id": "req-email-1",
}


class TestEmailValidationHint:
    """The hint that names the reserved domain as the reason a product answered 500."""

    def test_a_500_on_the_reserved_domain_earns_the_hint_with_an_opaque_body(self) -> None:
        """A production envelope hides the cause, and the domain is the only reason a record model rejects it."""
        hint = email_validation_hint(500, "body=Internal Server Error", f"e2e-run@{RESERVED_EMAIL_DOMAIN}")
        assert "EmailStr" in hint
        assert RESERVED_EMAIL_DOMAIN in hint

    def test_a_gateway_failure_on_the_reserved_domain_gets_no_hint(self) -> None:
        """Every ephemeral address is on the reserved domain, so the status must carry the decision."""
        for status in (429, 502, 503, 504):
            assert email_validation_hint(status, "body=Bad Gateway", f"e2e-run@{RESERVED_EMAIL_DOMAIN}") == ""

    def test_a_500_mentioning_email_validation_earns_the_hint(self) -> None:
        """A product may report the validation error without echoing the address."""
        hint = email_validation_hint(500, "message=value is not a valid email address", "someone@example.com")
        assert "EmailStr" in hint

    def test_an_unrelated_failure_gets_no_hint(self) -> None:
        """A misleading explanation on an unrelated failure would send a reader the wrong way."""
        assert email_validation_hint(502, "body=Bad Gateway", "someone@example.com") == ""

    def test_a_non_500_email_mention_off_the_reserved_domain_gets_no_hint(self) -> None:
        """A 422 naming the email field is the product validating input, not the domain trap."""
        assert email_validation_hint(422, "details=[email: Field required]", "someone@example.com") == ""


class TestCreateEphemeralUserEmailHint:
    """What the raised message carries when the reserved domain is the likely cause."""

    def test_the_message_carries_the_status_body_and_hint(self) -> None:
        """A reader needs the status, what the route said and why the address is the suspect."""
        client = FakeClient([FakeResponse(500, EMAIL_VALIDATION_ENVELOPE)])
        with pytest.raises(RuntimeError) as caught:
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)
        message = str(caught.value)
        assert "500" in message
        assert "req-email-1" in message
        assert "EmailStr" in message
        assert RESERVED_EMAIL_DOMAIN in message

    def test_the_body_stays_bounded(self) -> None:
        """A hint appended to an unbounded body would flood the CI log."""
        client = FakeClient([FakeResponse(500, ValueError("not json"), text="x" * 5000)])
        with pytest.raises(RuntimeError) as caught:
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)
        message = str(caught.value)
        assert "x" * BODY_EXCERPT_LIMIT in message
        assert "x" * (BODY_EXCERPT_LIMIT + 1) not in message

    def test_no_secret_reaches_a_message_carrying_the_hint(self) -> None:
        """The hint must not change what the message is allowed to hold."""
        client = FakeClient([FakeResponse(500, EMAIL_VALIDATION_ENVELOPE)])
        with pytest.raises(RuntimeError) as caught:
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN, password="the-generated-password")
        assert "the-generated-password" not in str(caught.value)
        assert ADMIN_TOKEN not in str(caught.value)

    def test_a_successful_creation_is_untouched(self) -> None:
        """The hint is a failure path concern and must not alter a 201."""
        client = FakeClient([FakeResponse(201, {"user_id": "user-1", "email": f"e2e-run@{RESERVED_EMAIL_DOMAIN}"})])
        user = create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)
        assert user is not None
        assert user.user_id == "user-1"


class TestCredentials:
    """The credentials object the fixtures hand around."""

    def test_the_password_is_kept_out_of_the_repr(self) -> None:
        """A fixture dump or an assertion rewrite must never render the secret."""
        credentials = Credentials(email="e2e@e2e.invalid", password="super-secret-value")
        assert "super-secret-value" not in repr(credentials)

    def test_the_email_stays_visible(self) -> None:
        """The address is not a secret and naming it makes a failure readable."""
        assert "e2e@e2e.invalid" in repr(Credentials(email="e2e@e2e.invalid", password="x"))


class TestCreateEphemeralUser:
    """Creating this run's user, and deciding when not having one is acceptable."""

    def test_it_returns_the_created_user(self) -> None:
        """A 201 yields credentials the suite can sign in with."""
        client = FakeClient([FakeResponse(201, {"user_id": "user-1", "email": "e2e-run-1234@e2e.invalid"})])
        user = create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)
        assert user is not None
        assert user.user_id == "user-1"
        assert user.credentials.ephemeral is True
        assert user.credentials.password

    def test_it_sends_the_admin_token(self) -> None:
        """The route is admin gated, so the minted admin token has to be presented."""
        client = FakeClient([FakeResponse(201, {"user_id": "user-1"})])
        create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)
        assert client.tokens == [ADMIN_TOKEN]

    def test_it_posts_to_the_create_path(self) -> None:
        """The suite and the router have to agree on where the route lives."""
        client = FakeClient([FakeResponse(201, {"user_id": "user-1"})])
        create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)
        assert client.calls[0]["path"] == CREATE_PATH

    @pytest.mark.parametrize("status", [403, 404, 405])
    def test_a_deployment_without_the_route_falls_back(self, status: int) -> None:
        """None sends the caller to the durable user, which is the supported fallback.

        This is the answer for a product that has not adopted the flag and for production,
        which refuses to mount the route at all.
        """
        client = FakeClient([FakeResponse(status)])
        assert create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN) is None

    @pytest.mark.parametrize("status", [400, 409, 422, 500, 502])
    def test_a_route_that_exists_and_errors_is_a_failure(self, status: int) -> None:
        """A mounted route erroring is a finding, not a reason to mutate the shared account."""
        client = FakeClient([FakeResponse(status)])
        with pytest.raises(RuntimeError):
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)

    def test_a_created_user_with_no_id_is_a_failure(self) -> None:
        """Without an id the user could never be deleted, so the run would leak an account."""
        client = FakeClient([FakeResponse(201, {"email": "e2e@e2e.invalid"})])
        with pytest.raises(RuntimeError):
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)

    def test_a_non_json_success_body_is_a_failure(self) -> None:
        """A 201 that is not JSON cannot name a user id."""
        client = FakeClient([FakeResponse(201, ValueError("not json"))])
        with pytest.raises(RuntimeError):
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)

    def test_no_secret_reaches_the_raised_message(self) -> None:
        """The failure message is read by a person and lands in CI logs."""
        client = FakeClient([FakeResponse(500)])
        with pytest.raises(RuntimeError) as caught:
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN, password="the-generated-password")
        assert "the-generated-password" not in str(caught.value)
        assert ADMIN_TOKEN not in str(caught.value)

    def test_no_secret_reaches_a_message_carrying_an_envelope(self) -> None:
        """The password is in the request body, and the response rendering must not echo it."""
        client = FakeClient([FakeResponse(422, VALIDATION_ENVELOPE)])
        with pytest.raises(RuntimeError) as caught:
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN, password="the-generated-password")
        message = str(caught.value)
        assert "the-generated-password" not in message
        assert ADMIN_TOKEN not in message

    def test_no_secret_reaches_a_message_carrying_a_non_json_body(self) -> None:
        """The excerpt path reads the response alone, so the posted password cannot reach it."""
        client = FakeClient([FakeResponse(400, ValueError("not json"), text="Bad Request")])
        with pytest.raises(RuntimeError) as caught:
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN, password="the-generated-password")
        message = str(caught.value)
        assert "the-generated-password" not in message
        assert ADMIN_TOKEN not in message
        assert "body=Bad Request" in message

    def test_the_envelope_reaches_the_raised_message(self) -> None:
        """Today's staging 422 said nothing about why until the envelope was rendered."""
        client = FakeClient([FakeResponse(422, VALIDATION_ENVELOPE)])
        with pytest.raises(RuntimeError) as caught:
            create_ephemeral_user(client, run_id=RUN_ID, admin_token=ADMIN_TOKEN)
        message = str(caught.value)
        assert "VALIDATION_ERROR" in message
        assert "Request validation failed." in message
        assert "req-abc123" in message
        assert "request: Field required (missing)" in message


class TestDescribeErrorBody:
    """What a failing response is rendered as, which is the whole point of the change."""

    def test_it_renders_the_shared_envelope_with_details(self) -> None:
        """The shape CarModPicker's 422 carries, whose cause was invisible before."""
        rendered = describe_error_body(FakeResponse(422, VALIDATION_ENVELOPE))
        assert "error_code=VALIDATION_ERROR" in rendered
        assert "message=Request validation failed." in rendered
        assert "request_id=req-abc123" in rendered
        assert "details=[request: Field required (missing)]" in rendered

    def test_it_renders_an_envelope_without_details(self) -> None:
        """Only a 422 carries details, so every other status renders the three scalar fields."""
        rendered = describe_error_body(
            FakeResponse(500, {"error_code": "INTERNAL_ERROR", "message": "Boom.", "request_id": "req-xyz"})
        )
        assert rendered == "error_code=INTERNAL_ERROR message=Boom. request_id=req-xyz"
        assert "details" not in rendered

    def test_it_renders_every_detail_entry(self) -> None:
        """A validation failure naming several fields must name all of them."""
        rendered = describe_error_body(
            FakeResponse(
                422,
                {
                    "error_code": "VALIDATION_ERROR",
                    "details": [
                        {"field": "email", "message": "Field required", "type": "missing"},
                        {"field": "password", "message": "Too short", "type": "string_too_short"},
                    ],
                },
            )
        )
        assert "email: Field required (missing)" in rendered
        assert "password: Too short (string_too_short)" in rendered

    def test_it_reads_a_pydantic_shaped_detail(self) -> None:
        """A product answering raw FastAPI errors names the field under `loc` and `msg`."""
        rendered = describe_error_body(
            FakeResponse(
                422,
                {
                    "error_code": "VALIDATION_ERROR",
                    "details": [{"loc": ["body", "email"], "msg": "Field required", "type": "missing"}],
                },
            )
        )
        assert "body.email: Field required (missing)" in rendered

    def test_a_non_json_body_is_excerpted(self) -> None:
        """A gateway or proxy answers HTML, and a whole page in a message is unreadable."""
        html = "<html>" + "x" * 1000 + "</html>"
        rendered = describe_error_body(FakeResponse(502, ValueError("not json"), text=html))
        assert rendered.startswith("body=<html>")
        assert rendered.endswith("...")
        assert len(rendered) <= BODY_EXCERPT_LIMIT + len("body=") + len("...")

    def test_a_short_non_json_body_is_rendered_whole(self) -> None:
        """Nothing is lost when the body already fits."""
        rendered = describe_error_body(FakeResponse(502, ValueError("not json"), text="Bad Gateway"))
        assert rendered == "body=Bad Gateway"

    def test_an_empty_body_says_so(self) -> None:
        """A bare status with no body is itself the finding, and must not render as nothing."""
        assert describe_error_body(FakeResponse(500, ValueError("not json"), text="")) == "the body was empty"

    def test_a_json_body_that_is_not_an_object_is_excerpted(self) -> None:
        """A bare list or string is not the envelope, so it falls through to the excerpt."""
        assert describe_error_body(FakeResponse(500, ["nope"], text='["nope"]')) == 'body=["nope"]'


class TestDeleteEphemeralUser:
    """Teardown, which must never replace a finished run's results with an error."""

    @staticmethod
    def user() -> EphemeralUser:
        """One created user to delete."""
        return EphemeralUser(
            credentials=Credentials(email="e2e@e2e.invalid", password="x", user_id="user-1", ephemeral=True),
            user_id="user-1",
        )

    def test_it_deletes_at_the_item_path(self) -> None:
        """The delete path is the create path plus the id."""
        client = FakeClient([FakeResponse(200)])
        delete_ephemeral_user(client, self.user(), admin_token=ADMIN_TOKEN)
        assert client.calls[0] == {"method": "DELETE", "path": item_path("user-1"), "json": None}

    def test_a_200_reports_success(self) -> None:
        """The ordinary teardown."""
        client = FakeClient([FakeResponse(200)])
        assert delete_ephemeral_user(client, self.user(), admin_token=ADMIN_TOKEN) is True

    def test_a_failure_status_reports_failure_without_raising(self) -> None:
        """The caller turns this into a warning rather than a teardown error."""
        client = FakeClient([FakeResponse(500)])
        assert delete_ephemeral_user(client, self.user(), admin_token=ADMIN_TOKEN) is False

    def test_a_transport_failure_never_raises(self) -> None:
        """A raise at session teardown would replace a completed run's results."""
        client = FakeClient(raises=RuntimeError("connection reset"))
        assert delete_ephemeral_user(client, self.user(), admin_token=ADMIN_TOKEN) is False

    def test_a_success_describes_no_failure(self) -> None:
        """The empty string is what the caller reads as "nothing to warn about"."""
        client = FakeClient([FakeResponse(200)])
        assert describe_delete_failure(client, self.user(), admin_token=ADMIN_TOKEN) == ""

    def test_a_failure_status_carries_the_envelope(self) -> None:
        """The teardown warning is the only place a cleanup failure is ever seen."""
        client = FakeClient([FakeResponse(422, VALIDATION_ENVELOPE)])
        failure = describe_delete_failure(client, self.user(), admin_token=ADMIN_TOKEN)
        assert "answered 422" in failure
        assert "VALIDATION_ERROR" in failure
        assert "request: Field required (missing)" in failure

    def test_a_transport_failure_names_the_exception(self) -> None:
        """A reset connection and a refused delete must not read alike."""
        client = FakeClient(raises=RuntimeError("connection reset"))
        failure = describe_delete_failure(client, self.user(), admin_token=ADMIN_TOKEN)
        assert "RuntimeError" in failure
        assert "connection reset" in failure

    def test_no_admin_token_reaches_a_described_failure(self) -> None:
        """The delete call is admin gated, and its message lands in CI logs."""
        client = FakeClient([FakeResponse(500, ValueError("not json"), text="nope")])
        assert ADMIN_TOKEN not in describe_delete_failure(client, self.user(), admin_token=ADMIN_TOKEN)


class FakeItem:
    """A pytest item stand-in carrying a node id and markers."""

    def __init__(self, nodeid: str, markers: tuple[str, ...] = ()) -> None:
        """Hold the node id, the markers present and the ones added."""
        self.nodeid = nodeid
        self._markers = markers
        self.added: list[Any] = []

    def get_closest_marker(self, name: str) -> Any:
        """Return a truthy stand-in when this item carries the marker."""
        return object() if name in self._markers else None

    def add_marker(self, marker: Any) -> None:
        """Record a marker the grouping applied."""
        self.added.append(marker)


class TestGrouping:
    """Which cases have to share a worker under `--dist loadgroup`."""

    @pytest.mark.parametrize("cls", ["TestIdentity", "TestBrowser", "TestHygiene"])
    def test_shared_state_classes_are_grouped(self, cls: str) -> None:
        """Everything that signs in as the session user or drives the one page stays together."""
        assert group_for(FakeItem(f"tests/test_e2e.py::{cls}::test_thing")) == SHARED_STATE_GROUP

    @pytest.mark.parametrize("cls", ["TestRouteCut", "TestReachability", "TestCoverage", "TestFrontend"])
    def test_independent_probes_are_left_schedulable(self, cls: str) -> None:
        """The hundreds of read-only probes are what parallelising is for."""
        assert group_for(FakeItem(f"tests/test_e2e.py::{cls}::test_thing")) == ""

    def test_a_product_case_that_writes_is_grouped(self) -> None:
        """A product marks a mutating case and gets it held with the rest, naming no group."""
        item = FakeItem("tests/test_product.py::TestOwnThing::test_it", markers=("e2e_writes",))
        assert group_for(item) == SHARED_STATE_GROUP

    def test_a_module_level_function_is_not_grouped(self) -> None:
        """A node id with no class is read without falling over."""
        assert group_for(FakeItem("tests/test_e2e.py::test_loose")) == ""

    def test_apply_groups_marks_only_the_shared_ones(self) -> None:
        """The grouping pass counts and marks exactly the shared state cases."""
        items = [
            FakeItem("tests/test_e2e.py::TestIdentity::test_a"),
            FakeItem("tests/test_e2e.py::TestRouteCut::test_b"),
            FakeItem("tests/test_e2e.py::TestBrowser::test_c"),
        ]
        assert apply_groups(items) == 2
        assert [len(item.added) for item in items] == [1, 0, 1]


class TestWorkerId:
    """The id that keeps one worker's created user from colliding with another's."""

    def test_a_serial_run_is_master(self) -> None:
        """The same string xdist uses, so serial and one-worker runs name resources alike."""

        class Config:
            """A config with no xdist worker input."""

        assert worker_id(Config()) == "master"

    def test_a_distributed_run_carries_its_worker_id(self) -> None:
        """Each worker derives its own user from this."""

        class Config:
            """A config as xdist sets it up on a worker."""

            workerinput: ClassVar[dict[str, str]] = {"workerid": "gw3"}

        assert worker_id(Config()) == "gw3"
