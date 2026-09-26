"""`webbpulse.integrations.github`: the App JWT, the token cache, request shapes and errors."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from webbpulse.integrations.github import (
    APP_JWT_BACKDATE_SECONDS,
    APP_JWT_TTL_SECONDS,
    AppInstallation,
    CheckRunOutput,
    GitHubAppClient,
    GitHubAppSettings,
    GitHubError,
    GitHubForbidden,
    GitHubNotConfigured,
    GitHubNotFound,
    GitHubRateLimited,
    GitHubUnauthorized,
    GitHubUnavailable,
    GitHubUnprocessable,
    convert_manifest_code,
    load_github_app_settings,
)

NOW = 1_800_000_000.0

INSTALLATION = 42

REPO = "WebbPulse/example"

SHA = "a" * 40


def _pem_pair() -> tuple[str, str]:
    """A fresh RSA private key PEM and its public key PEM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private, public


PRIVATE_PEM, PUBLIC_PEM = _pem_pair()


def _iso(epoch: float) -> str:
    """An epoch second as GitHub's `expires_at` renders it."""
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Clock:
    """A settable clock standing in for `time.time`."""

    now: float = NOW

    def __call__(self) -> float:
        """The current fake time."""
        return self.now


@dataclass
class GitHub:
    """A scripted GitHub behind an `httpx.MockTransport`, recording every request."""

    clock: Clock
    token_lifetime: float = 3600.0
    routes: dict[tuple[str, str], Callable[[httpx.Request], httpx.Response]] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)
    minted: int = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        """Answer one request from the routes, minting installation tokens itself."""
        self.requests.append(request)
        if request.method == "POST" and request.url.path.endswith("/access_tokens"):
            self.minted += 1
            return httpx.Response(
                201,
                json={"token": f"ghs_token{self.minted}", "expires_at": _iso(self.clock.now + self.token_lifetime)},
            )
        route = self.routes.get((request.method, request.url.path))
        if route is None:
            return httpx.Response(404, json={"message": "Not Found"})
        return route(request)

    def on(self, method: str, path: str, status: int = 200, body: Any = None, **headers: str) -> None:
        """Answer `method path` with a fixed status, JSON body and headers."""

        def answer(_: httpx.Request) -> httpx.Response:
            return httpx.Response(status, json=body, headers=headers)

        self.routes[(method, path)] = answer

    def api_requests(self) -> list[httpx.Request]:
        """Every request except the token exchanges."""
        return [r for r in self.requests if not r.url.path.endswith("/access_tokens")]


@pytest.fixture
def clock() -> Clock:
    """A fake clock at a fixed instant."""
    return Clock()


@pytest.fixture
def github(clock: Clock) -> GitHub:
    """A scripted GitHub on the fake clock."""
    return GitHub(clock=clock)


@pytest.fixture
def client(github: GitHub, clock: Clock) -> GitHubAppClient:
    """A client over the scripted GitHub."""
    http = httpx.Client(transport=httpx.MockTransport(github.handler))
    return GitHubAppClient(app_id=12345, private_key=PRIVATE_PEM, client=http, clock=clock)


def _body(request: httpx.Request) -> Any:
    """The JSON body a request carried."""
    return json.loads(request.content)


def test_app_jwt_claims_and_signature(client: GitHubAppClient) -> None:
    """The JWT is RS256, issued by the App id, backdated, and expires inside ten minutes."""
    token = client.app_jwt()
    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    claims = jwt.decode(token, PUBLIC_PEM, algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False})
    assert claims == {
        "iss": "12345",
        "iat": int(NOW) - APP_JWT_BACKDATE_SECONDS,
        "exp": int(NOW) + APP_JWT_TTL_SECONDS,
    }
    assert claims["exp"] - int(NOW) < 600
    assert claims["exp"] - claims["iat"] <= 600


def test_bad_private_key_raises_without_the_key() -> None:
    """A key that cannot sign raises `GitHubError` whose message and chain hold no key material."""
    broken = GitHubAppClient(app_id=1, private_key="-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----")
    with pytest.raises(GitHubError) as caught:
        broken.app_jwt()
    assert "nope" not in str(caught.value)
    assert caught.value.__cause__ is None
    broken.close()


@pytest.mark.parametrize(("app_id", "key"), [("", PRIVATE_PEM), (1, "  ")], ids=["no-app-id", "blank-key"])
def test_missing_credentials_refused(app_id: int | str, key: str) -> None:
    """An empty App id or private key is refused at construction."""
    with pytest.raises(ValueError):
        GitHubAppClient(app_id=app_id, private_key=key)


def test_repr_holds_no_secret(client: GitHubAppClient) -> None:
    """The repr names the App and never the key or a cached token."""
    token = client.installation_token(INSTALLATION)
    text = repr(client)
    assert "12345" in text
    assert "PRIVATE" not in text
    assert token not in text
    assert token not in repr(client._tokens)


def test_token_exchange_request_shape(client: GitHubAppClient, github: GitHub) -> None:
    """The exchange posts to the installation with the App JWT and GitHub's headers."""
    assert client.installation_token(INSTALLATION) == "ghs_token1"
    (request,) = github.requests
    assert request.method == "POST"
    assert str(request.url) == f"https://api.github.com/app/installations/{INSTALLATION}/access_tokens"
    assert request.headers["accept"] == "application/vnd.github+json"
    assert request.headers["x-github-api-version"] == "2022-11-28"
    bearer = request.headers["authorization"].removeprefix("Bearer ")
    claims = jwt.decode(bearer, PUBLIC_PEM, algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False})
    assert claims["iss"] == "12345"


def test_token_cached_until_near_expiry(client: GitHubAppClient, github: GitHub, clock: Clock) -> None:
    """The same token is reused until five minutes before expiry, then replaced."""
    first = client.installation_token(INSTALLATION)
    clock.now += 3600 - 301
    assert client.installation_token(INSTALLATION) == first
    assert github.minted == 1
    clock.now += 1
    second = client.installation_token(INSTALLATION)
    assert second != first
    assert github.minted == 2


def test_token_cache_is_per_installation(client: GitHubAppClient, github: GitHub) -> None:
    """Each installation gets and keeps its own token."""
    one = client.installation_token(1)
    two = client.installation_token(2)
    assert one != two
    assert client.installation_token("1") == one
    assert github.minted == 2


def test_unparseable_expiry_is_not_cached(client: GitHubAppClient, github: GitHub) -> None:
    """A token whose expiry cannot be read is used once and never cached."""
    github.token_lifetime = 0
    original = github.handler

    def no_expiry(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/access_tokens"):
            github.minted += 1
            return httpx.Response(201, json={"token": f"t{github.minted}"})
        return original(request)

    github.handler = no_expiry  # type: ignore[method-assign]
    http = httpx.Client(transport=httpx.MockTransport(github.handler))
    uncached = GitHubAppClient(app_id=1, private_key=PRIVATE_PEM, client=http, clock=github.clock)
    assert uncached.installation_token(1) == "t1"
    assert uncached.installation_token(1) == "t2"


def test_exchange_without_token_raises(clock: Clock) -> None:
    """An exchange answering no token raises rather than returning an empty credential."""
    http = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(201, json={})))
    empty = GitHubAppClient(app_id=1, private_key=PRIVATE_PEM, client=http, clock=clock)
    with pytest.raises(GitHubError, match="no token"):
        empty.installation_token(1)


def test_unauthorized_drops_the_cached_token(client: GitHubAppClient, github: GitHub) -> None:
    """A 401 on an installation call evicts its token so the next call mints a new one."""
    github.on("POST", f"/repos/{REPO}/issues/7/comments", 401, {"message": "Bad credentials"})
    with pytest.raises(GitHubUnauthorized):
        client.create_issue_comment(REPO, 7, "hi", installation_id=INSTALLATION)
    github.on("POST", f"/repos/{REPO}/issues/7/comments", 201, {"id": 9, "html_url": "u"})
    client.create_issue_comment(REPO, 7, "hi", installation_id=INSTALLATION)
    assert github.minted == 2
    assert github.api_requests()[-1].headers["authorization"] == "Bearer ghs_token2"


def test_get_app_installation_is_typed_and_uses_the_app_jwt(client: GitHubAppClient, github: GitHub) -> None:
    """The installation read authenticates as the App and answers a typed record."""
    github.on(
        "GET",
        f"/app/installations/{INSTALLATION}",
        200,
        {
            "id": INSTALLATION,
            "app_id": 12345,
            "account": {"login": "acme", "type": "Organization", "avatar_url": "https://a/acme"},
            "repository_selection": "selected",
            "html_url": "https://github.com/organizations/acme/settings/installations/42",
            "permissions": {"checks": "write", "metadata": "read"},
            "suspended_at": "2026-09-01T12:00:00Z",
        },
    )
    installation = client.get_app_installation(INSTALLATION)
    assert installation == AppInstallation(
        id=INSTALLATION,
        app_id=12345,
        account_login="acme",
        account_type="Organization",
        account_avatar_url="https://a/acme",
        repository_selection="selected",
        html_url="https://github.com/organizations/acme/settings/installations/42",
        permissions={"checks": "write", "metadata": "read"},
        suspended_at=datetime(2026, 9, 1, 12, 0, tzinfo=UTC),
    )
    (request,) = github.requests
    assert request.headers["authorization"].startswith("Bearer ey")
    assert github.minted == 0


def test_get_app_installation_active_has_no_suspension(client: GitHubAppClient, github: GitHub) -> None:
    """An installation GitHub reports no suspension for answers None."""
    github.on("GET", "/app/installations/7", 200, {"id": 7, "app_id": 1, "suspended_at": None})
    assert client.get_app_installation(7).suspended_at is None


def test_get_app_installation_not_found(client: GitHubAppClient, github: GitHub) -> None:
    """An id naming no installation of this App raises a clear `GitHubNotFound`."""
    with pytest.raises(GitHubNotFound, match="not an installation of this App") as caught:
        client.get_app_installation(99)
    assert caught.value.status_code == 404
    assert caught.value.path == "/app/installations/99"


def test_list_installation_repositories_pages_to_the_end(client: GitHubAppClient, github: GitHub) -> None:
    """Full pages are followed until a short one, with the installation token."""

    def answer(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        count = 100 if page < 3 else 5
        repos = [{"id": page * 1000 + i, "full_name": f"o/r{page}-{i}"} for i in range(count)]
        return httpx.Response(200, json={"total_count": 205, "repositories": repos})

    github.routes[("GET", "/installation/repositories")] = answer
    repos = client.list_installation_repositories(INSTALLATION)
    assert len(repos) == 205
    pages = [r.url.params["page"] for r in github.api_requests()]
    assert pages == ["1", "2", "3"]
    assert all(r.url.params["per_page"] == "100" for r in github.api_requests())
    assert all(r.headers["authorization"] == "Bearer ghs_token1" for r in github.api_requests())


def test_create_check_run_request_shape(client: GitHubAppClient, github: GitHub) -> None:
    """A check run posts its name, sha, status, conclusion and output."""
    github.on(
        "POST",
        f"/repos/{REPO}/check-runs",
        201,
        {"id": 77, "status": "completed", "conclusion": "success", "html_url": "https://x/77"},
    )
    run = client.create_check_run(
        REPO,
        name="Plan",
        head_sha=SHA,
        conclusion="success",
        output=CheckRunOutput(title="t", summary="s"),
        details_url="https://example.com/run",
        external_id="run-1",
        installation_id=INSTALLATION,
    )
    assert (run.id, run.status, run.conclusion, run.html_url) == (77, "completed", "success", "https://x/77")
    (request,) = github.api_requests()
    assert request.headers["authorization"] == "Bearer ghs_token1"
    assert _body(request) == {
        "name": "Plan",
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "success",
        "output": {"title": "t", "summary": "s"},
        "details_url": "https://example.com/run",
        "external_id": "run-1",
    }


def test_create_check_run_in_progress_omits_conclusion(client: GitHubAppClient, github: GitHub) -> None:
    """An in-progress run sends no conclusion and answers a None one."""
    github.on("POST", f"/repos/{REPO}/check-runs", 201, {"id": 1, "status": "in_progress", "conclusion": None})
    run = client.create_check_run(REPO, name="Plan", head_sha=SHA, status="in_progress", installation_id=INSTALLATION)
    assert run.conclusion is None
    assert _body(github.api_requests()[0]) == {"name": "Plan", "head_sha": SHA, "status": "in_progress"}


def test_completed_check_run_needs_a_conclusion(client: GitHubAppClient) -> None:
    """A completed run with no conclusion is refused before any request."""
    with pytest.raises(ValueError, match="conclusion"):
        client.create_check_run(REPO, name="Plan", head_sha=SHA, installation_id=INSTALLATION)


def test_update_check_run_sends_only_given_fields(client: GitHubAppClient, github: GitHub) -> None:
    """An update patches the run by id with just the fields supplied."""
    github.on("PATCH", f"/repos/{REPO}/check-runs/77", 200, {"id": 77, "status": "completed", "conclusion": "failure"})
    run = client.update_check_run(
        REPO,
        "77",
        installation_id=INSTALLATION,
        status="completed",
        conclusion="failure",
        output=CheckRunOutput(title="t", summary="s", text="detail"),
    )
    assert run.conclusion == "failure"
    assert _body(github.api_requests()[0]) == {
        "status": "completed",
        "conclusion": "failure",
        "output": {"title": "t", "summary": "s", "text": "detail"},
    }


def test_create_commit_status_request_shape(client: GitHubAppClient, github: GitHub) -> None:
    """A status posts its state, context, description and target URL to the sha."""
    github.on("POST", f"/repos/{REPO}/statuses/{SHA}", 201, {"id": 5, "state": "pending", "context": "tf/plan"})
    status = client.create_commit_status(
        REPO,
        SHA,
        installation_id=INSTALLATION,
        state="pending",
        context="tf/plan",
        description="Planning",
        target_url="https://example.com/run",
    )
    assert (status.id, status.state, status.context) == (5, "pending", "tf/plan")
    assert _body(github.api_requests()[0]) == {
        "state": "pending",
        "context": "tf/plan",
        "description": "Planning",
        "target_url": "https://example.com/run",
    }


def test_create_commit_status_minimal_body(client: GitHubAppClient, github: GitHub) -> None:
    """Absent optional fields are not sent."""
    github.on("POST", f"/repos/{REPO}/statuses/{SHA}", 201, {"id": 5, "state": "success", "context": "c"})
    client.create_commit_status(REPO, SHA, state="success", context="c", installation_id=INSTALLATION)
    assert _body(github.api_requests()[0]) == {"state": "success", "context": "c"}


def test_issue_comment_create_and_update(client: GitHubAppClient, github: GitHub) -> None:
    """A comment posts to the issue and patches by comment id."""
    github.on("POST", f"/repos/{REPO}/issues/12/comments", 201, {"id": 900, "html_url": "https://c/900"})
    github.on("PATCH", f"/repos/{REPO}/issues/comments/900", 200, {"id": 900, "html_url": "https://c/900"})
    created = client.create_issue_comment(REPO, 12, "first", installation_id=INSTALLATION)
    updated = client.update_issue_comment(REPO, str(created.id), "second", installation_id=INSTALLATION)
    assert created.id == updated.id == 900
    post, patch = github.api_requests()
    assert (post.method, _body(post)) == ("POST", {"body": "first"})
    assert (patch.method, _body(patch)) == ("PATCH", {"body": "second"})


@pytest.mark.parametrize(
    ("call", "error"),
    [
        (lambda c: c.create_issue_comment("../x", 1, "b", installation_id=1), "repository"),
        (lambda c: c.create_issue_comment("o/r/extra", 1, "b", installation_id=1), "repository"),
        (lambda c: c.create_issue_comment(REPO, 0, "b", installation_id=1), "issue_number"),
        (lambda c: c.update_issue_comment(REPO, "x", "b", installation_id=1), "invalid literal"),
        (lambda c: c.create_commit_status(REPO, "main/../x", state="success", context="c", installation_id=1), "sha"),
        (lambda c: c.installation_token(-1), "installation_id"),
    ],
)
def test_path_inputs_are_validated(
    client: GitHubAppClient, github: GitHub, call: Callable[[GitHubAppClient], Any], error: str
) -> None:
    """Ids, repositories and shas that could escape their path segment are refused."""
    with pytest.raises(ValueError, match=error):
        call(client)
    assert github.api_requests() == []


@pytest.mark.parametrize(
    ("status", "headers", "error"),
    [
        (401, {}, GitHubUnauthorized),
        (403, {}, GitHubForbidden),
        (404, {}, GitHubNotFound),
        (422, {}, GitHubUnprocessable),
        (500, {}, GitHubUnavailable),
        (502, {}, GitHubUnavailable),
        (429, {"retry-after": "30"}, GitHubRateLimited),
        (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(NOW) + 90)}, GitHubRateLimited),
        (403, {"retry-after": "60"}, GitHubRateLimited),
        (409, {}, GitHubError),
    ],
)
def test_error_mapping(
    client: GitHubAppClient, github: GitHub, status: int, headers: dict[str, str], error: type[GitHubError]
) -> None:
    """Each failing status maps to its own exception, carrying the call and GitHub's message."""
    github.on("POST", f"/repos/{REPO}/issues/1/comments", status, {"message": "nope"}, **headers)
    with pytest.raises(error) as caught:
        client.create_issue_comment(REPO, 1, "b", installation_id=INSTALLATION)
    assert type(caught.value) is error
    assert caught.value.status_code == status
    assert caught.value.method == "POST"
    assert caught.value.path == f"/repos/{REPO}/issues/1/comments"
    assert caught.value.github_message == "nope"


@pytest.mark.parametrize(
    ("headers", "retry_after"),
    [({"retry-after": "30"}, 30.0), ({"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(int(NOW) + 90)}, 90.0)],
)
def test_rate_limit_carries_retry_after(
    client: GitHubAppClient, github: GitHub, headers: dict[str, str], retry_after: float
) -> None:
    """A rate limit reports how long GitHub asked the caller to wait."""
    github.on("POST", f"/repos/{REPO}/issues/1/comments", 429 if "retry-after" in headers else 403, {}, **headers)
    with pytest.raises(GitHubRateLimited) as caught:
        client.create_issue_comment(REPO, 1, "b", installation_id=INSTALLATION)
    assert caught.value.retry_after == retry_after


def test_transport_failure_is_unavailable(clock: Clock) -> None:
    """A request that never got an answer raises `GitHubUnavailable` with status 0."""

    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    http = httpx.Client(transport=httpx.MockTransport(fail))
    down = GitHubAppClient(app_id=1, private_key=PRIVATE_PEM, client=http, clock=clock)
    with pytest.raises(GitHubUnavailable) as caught:
        down.installation_token(1)
    assert caught.value.status_code == 0


def test_failure_log_holds_no_token(client: GitHubAppClient, github: GitHub, caplog: pytest.LogCaptureFixture) -> None:
    """The failure log line names the call and status, never a credential."""
    github.on("POST", f"/repos/{REPO}/issues/1/comments", 404, {"message": "Not Found"})
    with caplog.at_level(logging.WARNING, logger="webbpulse.integrations.github"), pytest.raises(GitHubNotFound):
        client.create_issue_comment(REPO, 1, "b", installation_id=INSTALLATION)
    (record,) = caplog.records
    assert record.__dict__["status"] == 404
    rendered = record.getMessage() + repr(record.__dict__)
    assert "ghs_token" not in rendered
    assert "Bearer" not in rendered


def test_api_url_override_and_owned_client_closed(clock: Clock) -> None:
    """A GitHub Enterprise root is honoured and an owned client closes on exit."""
    with GitHubAppClient(app_id=1, private_key=PRIVATE_PEM, api_url="https://ghe.example.com/api/v3/") as owned:
        assert repr(owned) == (
            "GitHubAppClient(app_id='1', installation_id=None, api_url='https://ghe.example.com/api/v3')"
        )
        inner = owned._client
    assert inner.is_closed


def test_supplied_client_left_open(client: GitHubAppClient) -> None:
    """Closing never closes an `httpx.Client` the caller handed in."""
    client.close()
    assert not client._client.is_closed


def _pkcs1_pem() -> str:
    """A fresh RSA private key in the traditional PKCS#1 `RSA PRIVATE KEY` form."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


class FakeSecrets:
    """A Secrets Manager stand-in answering one JSON secret."""

    def __init__(self, payload: dict[str, Any]) -> None:
        """Hold the secret's JSON object."""
        self.payload = payload
        self.reads = 0

    def get_secret_value(self, SecretId: str) -> dict[str, Any]:
        """Answer the payload as a secret string."""
        self.reads += 1
        return {"SecretString": json.dumps(self.payload)}


def _standupless_secret() -> dict[str, Any]:
    """An `app` secret keyed exactly as Standupless staging stores it."""
    return {
        "SECRET_KEY": "unrelated",
        "GITHUB_APP_ID": "12345",
        "GITHUB_CLIENT_ID": "Iv1.abc",
        "GITHUB_CLIENT_SECRET": "client-secret-value",
        "GITHUB_PRIVATE_KEY": PRIVATE_PEM,
        "GITHUB_WEBHOOK_SECRET": "webhook-secret-value",
    }


def test_settings_load_from_the_app_secret() -> None:
    """The Standupless secret shape loads with no migration and no pinned installation."""
    settings = load_github_app_settings("arn:secret", environ={}, client=FakeSecrets(_standupless_secret()))
    assert settings.app_id == "12345"
    assert settings.private_key.get_secret_value() == PRIVATE_PEM
    assert settings.installation_id is None
    assert settings.client_id == "Iv1.abc"
    assert settings.client_secret is not None
    assert settings.client_secret.get_secret_value() == "client-secret-value"
    assert settings.webhook_secret is not None
    assert settings.webhook_secret.get_secret_value() == "webhook-secret-value"


def test_settings_repr_masks_every_secret() -> None:
    """No secret value appears in the settings repr or str."""
    settings = load_github_app_settings("arn:secret", environ={}, client=FakeSecrets(_standupless_secret()))
    rendered = repr(settings) + str(settings)
    for value in ("client-secret-value", "webhook-secret-value", "PRIVATE KEY"):
        assert value not in rendered
    assert "12345" in rendered


def test_settings_environment_wins_per_key() -> None:
    """An environment value overrides the secret for its key alone, in any case."""
    secret = FakeSecrets(_standupless_secret())
    environ = {"GITHUB_APP_INSTALLATION_ID": "77", "github_client_id": "Iv1.local", "GITHUB_WEBHOOK_SECRET": ""}
    settings = load_github_app_settings("arn:secret", environ=environ, client=secret)
    assert settings.installation_id == 77
    assert settings.client_id == "Iv1.local"
    assert settings.webhook_secret is not None
    assert settings.webhook_secret.get_secret_value() == "webhook-secret-value"
    assert settings.app_id == "12345"


def test_settings_without_an_arn_read_only_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no ARN the environment alone configures the App."""
    monkeypatch.delenv("APP_SECRETS_ARN", raising=False)
    settings = load_github_app_settings(environ={"GITHUB_APP_ID": "9", "GITHUB_PRIVATE_KEY": PRIVATE_PEM})
    assert settings.app_id == "9"


def test_settings_accept_a_pkcs1_key_and_the_client_signs_with_it() -> None:
    """A PKCS#1 key is accepted as readily as PKCS#8, and signs."""
    pem = _pkcs1_pem()
    assert "BEGIN RSA PRIVATE KEY" in pem
    settings = load_github_app_settings(environ={"GITHUB_APP_ID": "9", "GITHUB_PRIVATE_KEY": pem}, secret_arn="")
    with GitHubAppClient.from_settings(settings) as app:
        assert jwt.get_unverified_header(app.app_jwt())["alg"] == "RS256"


@pytest.mark.parametrize("missing", ["GITHUB_APP_ID", "GITHUB_PRIVATE_KEY"])
def test_settings_missing_required_key(missing: str) -> None:
    """A missing required key raises `GitHubNotConfigured` naming it."""
    payload = _standupless_secret()
    del payload[missing]
    with pytest.raises(GitHubNotConfigured, match=missing):
        load_github_app_settings("arn:secret", environ={}, client=FakeSecrets(payload))


def test_settings_invalid_values_name_the_key_not_the_value() -> None:
    """A malformed key or installation id is refused without echoing the value."""
    environ = {"GITHUB_APP_ID": "1", "GITHUB_PRIVATE_KEY": "not-a-pem-secret", "GITHUB_APP_INSTALLATION_ID": "abc"}
    with pytest.raises(GitHubNotConfigured) as caught:
        load_github_app_settings(environ=environ, secret_arn="")
    message = str(caught.value)
    assert "GITHUB_PRIVATE_KEY" in message
    assert "GITHUB_APP_INSTALLATION_ID" in message
    assert "not-a-pem-secret" not in message
    assert caught.value.__cause__ is None


def test_from_settings_pins_the_installation(github: GitHub, clock: Clock) -> None:
    """A pinned installation serves repository calls with no lookup."""
    settings = GitHubAppSettings.model_validate(
        {"GITHUB_APP_ID": "1", "GITHUB_PRIVATE_KEY": PRIVATE_PEM, "GITHUB_APP_INSTALLATION_ID": "55"}
    )
    http = httpx.Client(transport=httpx.MockTransport(github.handler))
    pinned = GitHubAppClient.from_settings(settings, client=http, clock=clock)
    github.on("POST", f"/repos/{REPO}/issues/3/comments", 201, {"id": 1})
    pinned.create_issue_comment(REPO, 3, "b")
    assert [r.url.path for r in github.requests] == [
        "/app/installations/55/access_tokens",
        f"/repos/{REPO}/issues/3/comments",
    ]
    assert "55" in repr(pinned)


def test_repository_installation_lookup_is_cached(client: GitHubAppClient, github: GitHub) -> None:
    """Without a pin the installation is looked up once per repository with the App JWT."""
    github.on("GET", f"/repos/{REPO}/installation", 200, {"id": 314})
    github.on("POST", f"/repos/{REPO}/statuses/{SHA}", 201, {"id": 1, "state": "success", "context": "c"})
    github.on("POST", f"/repos/{REPO.upper()}/statuses/{SHA}", 201, {"id": 2, "state": "success", "context": "c"})
    client.create_commit_status(REPO, SHA, state="success", context="c")
    client.create_commit_status(REPO.upper(), SHA, state="success", context="c")
    paths = [r.url.path for r in github.requests]
    assert paths.count(f"/repos/{REPO}/installation") == 1
    assert paths.count("/app/installations/314/access_tokens") == 1
    lookup = next(r for r in github.requests if r.url.path.endswith("/installation"))
    assert lookup.method == "GET"
    assert lookup.headers["authorization"].startswith("Bearer ey")


def test_repository_installation_not_found(client: GitHubAppClient, github: GitHub) -> None:
    """A repository the App is not installed on raises `GitHubNotFound` before any write."""
    with pytest.raises(GitHubNotFound):
        client.create_issue_comment(REPO, 1, "b")
    assert [r.url.path for r in github.requests] == [f"/repos/{REPO}/installation"]


def test_stale_lookup_is_forgotten_when_its_installation_is_gone(client: GitHubAppClient, github: GitHub) -> None:
    """A looked-up installation whose token exchange 404s is looked up again next time."""
    github.on("GET", f"/repos/{REPO}/installation", 200, {"id": 314})
    original = github.handler

    def gone(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/314/access_tokens":
            github.requests.append(request)
            return httpx.Response(404, json={"message": "Not Found"})
        return original(request)

    client._client = httpx.Client(transport=httpx.MockTransport(gone))
    with pytest.raises(GitHubNotFound):
        client.create_issue_comment(REPO, 1, "b")
    github.on("GET", f"/repos/{REPO}/installation", 200, {"id": 315})
    github.on("POST", f"/repos/{REPO}/issues/1/comments", 201, {"id": 2})
    client.create_issue_comment(REPO, 1, "b")
    assert [r.url.path for r in github.requests].count(f"/repos/{REPO}/installation") == 2
    assert github.requests[-2].url.path == "/app/installations/315/access_tokens"


def _conversion_body() -> dict[str, Any]:
    """GitHub's answer to a manifest conversion, trimmed to the fields read."""
    return {
        "id": 1001,
        "slug": "standupless-staging",
        "name": "Standupless (staging)",
        "html_url": "https://github.com/apps/standupless-staging",
        "owner": {"login": "WebbPulse", "type": "Organization"},
        "client_id": "Iv1.new",
        "client_secret": "fresh-client-secret",
        "webhook_secret": "fresh-webhook-secret",
        "pem": PRIVATE_PEM,
    }


def test_convert_manifest_code_is_unauthenticated_and_typed() -> None:
    """The conversion posts with no Authorization header and answers the new App."""
    seen: list[httpx.Request] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json=_conversion_body())

    http = httpx.Client(transport=httpx.MockTransport(answer))
    app = convert_manifest_code("abc123-_X", client=http)
    (request,) = seen
    assert request.method == "POST"
    assert str(request.url) == "https://api.github.com/app-manifests/abc123-_X/conversions"
    assert "authorization" not in request.headers
    assert request.headers["accept"] == "application/vnd.github+json"
    assert (app.id, app.slug, app.name, app.owner_login, app.client_id) == (
        1001,
        "standupless-staging",
        "Standupless (staging)",
        "WebbPulse",
        "Iv1.new",
    )
    assert app.html_url == "https://github.com/apps/standupless-staging"
    assert app.pem.get_secret_value() == PRIVATE_PEM
    assert app.client_secret.get_secret_value() == "fresh-client-secret"
    assert app.webhook_secret is not None
    assert app.webhook_secret.get_secret_value() == "fresh-webhook-secret"
    rendered = repr(app)
    for secret in ("fresh-client-secret", "fresh-webhook-secret", "PRIVATE KEY"):
        assert secret not in rendered
    assert not http.is_closed


def test_convert_manifest_code_errors() -> None:
    """A spent code maps to its error, a malformed one is refused, and no App is an error."""
    spent = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(404, json={"message": "Not Found"})))
    with pytest.raises(GitHubNotFound):
        convert_manifest_code("used", client=spent)
    with pytest.raises(ValueError, match="code"):
        convert_manifest_code("../app/installations")
    empty = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(201, json={"id": 1})))
    with pytest.raises(GitHubError, match="no App"):
        convert_manifest_code("abc", client=empty)
