"""A small, synchronous GitHub App client: the App JWT, installation tokens, and write-backs.

`GitHubAppSettings` is the one configuration shape every product reads from its `app`
secret, and `load_github_app_settings` resolves it from the environment and that secret.
`GitHubAppClient` signs the App JWT, exchanges it for an installation access token cached
per installation until shortly before it expires, and makes the handful of calls a product
reports through: check runs, commit statuses and issue comments. It also reads an
installation's own record, the repositories it covers, and the installation a repository
belongs to. `convert_manifest_code` finishes the App manifest flow, before any App
configuration exists. Nothing here routes webhooks or knows any product's naming.

Every failure is a `GitHubError` subclass chosen by status, so a caller can tell a missing
repository from a rate limit without reading status codes. The App private key and every
token stay out of reprs, exception messages and log lines.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import TracebackType
from typing import Any, Final, Literal, Self

import httpx
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, field_validator

__all__ = [
    "ACCEPT",
    "API_ROOT",
    "API_VERSION",
    "APP_JWT_BACKDATE_SECONDS",
    "APP_JWT_TTL_SECONDS",
    "DEFAULT_TIMEOUT_SECONDS",
    "SETTINGS_KEYS",
    "TOKEN_REFRESH_MARGIN_SECONDS",
    "AppInstallation",
    "AppManifestConversion",
    "CheckRun",
    "CheckRunConclusion",
    "CheckRunOutput",
    "CheckRunStatus",
    "CommitState",
    "CommitStatus",
    "GitHubAppClient",
    "GitHubAppSettings",
    "GitHubError",
    "GitHubForbidden",
    "GitHubNotConfigured",
    "GitHubNotFound",
    "GitHubRateLimited",
    "GitHubUnauthorized",
    "GitHubUnavailable",
    "GitHubUnprocessable",
    "IssueComment",
    "convert_manifest_code",
    "load_github_app_settings",
]

_log = logging.getLogger(__name__)

API_ROOT: Final = "https://api.github.com"

ACCEPT: Final = "application/vnd.github+json"

API_VERSION: Final = "2022-11-28"

APP_JWT_TTL_SECONDS: Final = 540
"""Nine minutes from now. GitHub refuses an App JWT whose `exp` is more than ten ahead."""

APP_JWT_BACKDATE_SECONDS: Final = 60
"""How far `iat` is backdated, so a clock slightly ahead of GitHub's is not refused."""

TOKEN_REFRESH_MARGIN_SECONDS: Final = 300
"""A cached installation token is replaced once it has less than this left to live."""

DEFAULT_TIMEOUT_SECONDS: Final = 10.0

SETTINGS_KEYS: Final = (
    "GITHUB_APP_ID",
    "GITHUB_PRIVATE_KEY",
    "GITHUB_APP_INSTALLATION_ID",
    "GITHUB_CLIENT_ID",
    "GITHUB_CLIENT_SECRET",
    "GITHUB_WEBHOOK_SECRET",
)
"""Every key `GitHubAppSettings` reads, as it is spelled in the `app` secret."""

_REQUIRED_KEYS: Final = ("GITHUB_APP_ID", "GITHUB_PRIVATE_KEY")

_REPOSITORY_PATTERN: Final = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

_SHA_PATTERN: Final = re.compile(r"^[0-9a-fA-F]{7,64}$")

_MANIFEST_CODE_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]+$")


_REPOSITORIES_PAGE_SIZE: Final = 100

_MESSAGE_LIMIT: Final = 200

CheckRunStatus = Literal["queued", "in_progress", "completed"]

CheckRunConclusion = Literal[
    "action_required", "cancelled", "failure", "neutral", "success", "skipped", "stale", "timed_out"
]

CommitState = Literal["error", "failure", "pending", "success"]


class GitHubError(Exception):
    """GitHub did not answer, or answered with a status the call cannot succeed on.

    `status_code` is 0 when nothing came back. `github_message` is the `message` field of
    GitHub's error body, truncated, and never carries a credential.
    """

    def __init__(
        self,
        message: str,
        *,
        method: str = "",
        path: str = "",
        status_code: int = 0,
        github_message: str = "",
    ) -> None:
        """Record the call that failed alongside the human-readable message."""
        super().__init__(message)
        self.method = method
        self.path = path
        self.status_code = status_code
        self.github_message = github_message


class GitHubNotConfigured(GitHubError):
    """The environment and the `app` secret lack a usable GitHub App configuration."""


class GitHubUnavailable(GitHubError):
    """A transport failure or a 5xx: worth retrying later."""


class GitHubUnauthorized(GitHubError):
    """A 401: the App JWT or the installation token was refused."""


class GitHubForbidden(GitHubError):
    """A 403 that is not a rate limit: the App lacks a permission the call needs."""


class GitHubNotFound(GitHubError):
    """A 404: the resource is missing, or the App or installation cannot see it."""


class GitHubUnprocessable(GitHubError):
    """A 422: GitHub rejected the request body."""


class GitHubRateLimited(GitHubError):
    """A 429, or a 403 carrying GitHub's rate limit headers.

    `retry_after` is the number of seconds GitHub asked the caller to wait, when it said.
    """

    def __init__(self, message: str, *, retry_after: float | None = None, **kwargs: Any) -> None:
        """Record how long to wait alongside the failed call."""
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class GitHubAppSettings(BaseModel):
    """The standard GitHub App configuration, keyed as the `app` secret spells it.

    The App id and private key are required. `installation_id` pins every repository call to
    one installation; without it the client looks the installation up per repository. The
    OAuth client pair and the webhook secret are carried for the product and unused by the
    client. Secret values are `SecretStr`, so they print masked, and validation errors never
    echo an input.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True, hide_input_in_errors=True, extra="ignore")

    app_id: str = Field(alias="GITHUB_APP_ID", min_length=1)
    private_key: SecretStr = Field(alias="GITHUB_PRIVATE_KEY")
    installation_id: int | None = Field(default=None, alias="GITHUB_APP_INSTALLATION_ID", gt=0)
    client_id: str | None = Field(default=None, alias="GITHUB_CLIENT_ID")
    client_secret: SecretStr | None = Field(default=None, alias="GITHUB_CLIENT_SECRET")
    webhook_secret: SecretStr | None = Field(default=None, alias="GITHUB_WEBHOOK_SECRET")

    @field_validator("app_id", mode="before")
    @classmethod
    def _strip_app_id(cls, value: object) -> object:
        """Accept a numeric App id and trim whitespace around a string one."""
        return str(value).strip() if isinstance(value, int | str) else value

    @field_validator("private_key")
    @classmethod
    def _parse_private_key(cls, value: SecretStr) -> SecretStr:
        """Refuse anything that is not an unencrypted PKCS#1 or PKCS#8 PEM private key."""
        try:
            load_pem_private_key(value.get_secret_value().encode(), password=None)
        except (ValueError, TypeError):
            raise ValueError("GITHUB_PRIVATE_KEY is not an unencrypted PEM private key") from None
        return value


def _present(values: Mapping[str, Any]) -> dict[str, str]:
    """The standard keys that carry a non-empty value, matched without regard to case."""
    by_upper = {str(name).upper(): value for name, value in values.items()}
    found: dict[str, str] = {}
    for key in SETTINGS_KEYS:
        value = by_upper.get(key)
        if value is not None and str(value).strip():
            found[key] = str(value)
    return found


def load_github_app_settings(
    secret_arn: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    client: Any = None,
    region_name: str | None = None,
) -> GitHubAppSettings:
    """Resolve `GitHubAppSettings` from the environment, then the `app` secret.

    Each key resolves on its own: a non-empty environment variable wins over the secret key
    of the same name, so a local run can override a deployed value. The secret is read
    through `webbpulse.security.app_secrets`, defaulting to `APP_SECRETS_ARN`; with no ARN
    only the environment is read. Raises `GitHubNotConfigured` naming the missing or invalid
    keys, never their values.
    """
    from webbpulse.security import app_secrets

    merged = _present(app_secrets(secret_arn, client=client, region_name=region_name))
    merged.update(_present(os.environ if environ is None else environ))
    missing = [key for key in _REQUIRED_KEYS if key not in merged]
    if missing:
        raise GitHubNotConfigured(f"the GitHub App configuration is missing {', '.join(missing)}")
    try:
        return GitHubAppSettings.model_validate(merged)
    except ValidationError as exc:
        names = sorted({str(error["loc"][0]) for error in exc.errors() if error["loc"]})
        raise GitHubNotConfigured(f"the GitHub App configuration has invalid {', '.join(names)}") from None


@dataclass(frozen=True, slots=True)
class CheckRunOutput:
    """The `output` object of a check run: a title, a Markdown summary and optional detail."""

    title: str
    summary: str
    text: str | None = None

    def as_json(self) -> dict[str, str]:
        """The object as GitHub takes it, leaving out an absent `text`."""
        body = {"title": self.title, "summary": self.summary}
        if self.text is not None:
            body["text"] = self.text
        return body


@dataclass(frozen=True, slots=True)
class CheckRun:
    """A check run as GitHub answered it."""

    id: int
    status: str
    conclusion: str | None
    html_url: str


@dataclass(frozen=True, slots=True)
class CommitStatus:
    """A commit status as GitHub answered it."""

    id: int
    state: str
    context: str


@dataclass(frozen=True, slots=True)
class IssueComment:
    """An issue or pull request comment as GitHub answered it."""

    id: int
    html_url: str


@dataclass(frozen=True, slots=True)
class AppInstallation:
    """An installation of this App as GitHub reports it to the App.

    `permissions` maps each permission to `read` or `write`. `suspended_at` is set while an
    account admin has suspended the App on this installation.
    """

    id: int
    app_id: int
    account_login: str
    account_type: str
    account_avatar_url: str
    repository_selection: str
    html_url: str
    permissions: Mapping[str, str]
    suspended_at: datetime | None


@dataclass(frozen=True, slots=True)
class AppManifestConversion:
    """The App GitHub created from a manifest, with the credentials it hands back only once.

    `pem`, `client_secret` and `webhook_secret` are `SecretStr`, so they print masked. Store
    them in the `app` secret as `GITHUB_PRIVATE_KEY`, `GITHUB_CLIENT_SECRET` and
    `GITHUB_WEBHOOK_SECRET`, with `id` as `GITHUB_APP_ID` and `client_id` as `GITHUB_CLIENT_ID`.
    """

    id: int
    slug: str
    name: str
    html_url: str
    owner_login: str
    client_id: str
    client_secret: SecretStr
    webhook_secret: SecretStr | None
    pem: SecretStr


@dataclass(slots=True)
class _CachedToken:
    """An installation token and the epoch second it expires at."""

    token: str = field(repr=False)
    expires_at: float


def _identifier(value: int | str, what: str) -> str:
    """A positive integer id rendered for a URL path, refusing anything else."""
    number = int(value)
    if number <= 0:
        raise ValueError(f"{what} must be a positive integer")
    return str(number)


def _repository(value: str) -> str:
    """An `owner/name` repository, refusing anything that could escape its path segment."""
    if not _REPOSITORY_PATTERN.fullmatch(value) or ".." in value:
        raise ValueError("repository must be 'owner/name'")
    return value


def _sha(value: str) -> str:
    """A hex commit sha, refusing anything else."""
    if not _SHA_PATTERN.fullmatch(value):
        raise ValueError("sha must be a hex commit sha")
    return value


def _expiry(value: Any) -> float | None:
    """The epoch second an ISO 8601 `expires_at` names, or None when it does not parse."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _timestamp(value: Any) -> datetime | None:
    """An ISO 8601 timestamp, or None when it is absent or does not parse."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _github_message(response: httpx.Response) -> str:
    """The `message` field of an error body, truncated, or empty when there is none."""
    try:
        body = response.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        return str(body.get("message", ""))[:_MESSAGE_LIMIT]
    return ""


def _retry_after(response: httpx.Response, now: float) -> float | None:
    """Seconds to wait from `Retry-After`, else from `X-RateLimit-Reset`, else None."""
    header = response.headers.get("retry-after")
    if header is not None:
        try:
            return max(float(header), 0.0)
        except ValueError:
            return None
    reset = response.headers.get("x-ratelimit-reset")
    if reset is not None:
        try:
            return max(float(reset) - now, 0.0)
        except ValueError:
            return None
    return None


def _is_rate_limited(response: httpx.Response) -> bool:
    """Whether a 403 or 429 is GitHub's primary or secondary rate limit."""
    if response.status_code == 429:
        return True
    return response.status_code == 403 and (
        response.headers.get("x-ratelimit-remaining") == "0" or "retry-after" in response.headers
    )


def _error_for(response: httpx.Response, method: str, path: str, now: float) -> GitHubError:
    """The `GitHubError` subclass a failed response maps to."""
    status = response.status_code
    context: dict[str, Any] = {
        "method": method,
        "path": path,
        "status_code": status,
        "github_message": _github_message(response),
    }
    message = f"{method} {path} answered {status}"
    if _is_rate_limited(response):
        return GitHubRateLimited(message, retry_after=_retry_after(response, now), **context)
    if status >= 500:
        return GitHubUnavailable(message, **context)
    kinds: dict[int, type[GitHubError]] = {
        401: GitHubUnauthorized,
        403: GitHubForbidden,
        404: GitHubNotFound,
        422: GitHubUnprocessable,
    }
    return kinds.get(status, GitHubError)(message, **context)


class GitHubAppClient:
    """One GitHub App's client, holding its credentials and its token and installation caches.

    Build one per process and reuse it: installation tokens are cached on the instance, so a
    warm Lambda makes one token exchange per installation an hour rather than one per call.
    A caller that wants no token outliving its unit of work builds one per unit instead.

    A repository call runs as the installation named by its `installation_id` argument, else
    the pinned `installation_id` the client was built with, else the installation GitHub
    reports for that repository, looked up once and cached. Closing the client closes the
    `httpx.Client` it built, never one it was handed.
    """

    def __init__(
        self,
        *,
        app_id: int | str,
        private_key: str,
        installation_id: int | str | None = None,
        api_url: str = API_ROOT,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
        refresh_margin_seconds: float = TOKEN_REFRESH_MARGIN_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Hold the App id, the private key PEM and an optional pinned installation."""
        if not str(app_id).strip():
            raise ValueError("app_id is required")
        if not private_key.strip():
            raise ValueError("private_key is required")
        self._app_id = str(app_id).strip()
        self._private_key = private_key
        self._installation_id = None if installation_id is None else _identifier(installation_id, "installation_id")
        self._api_url = api_url.rstrip("/")
        self._owns_client = client is None
        self._client = client if client is not None else httpx.Client(timeout=timeout, follow_redirects=False)
        self._refresh_margin = refresh_margin_seconds
        self._clock = clock
        self._tokens: dict[str, _CachedToken] = {}
        self._installations: dict[str, str] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_settings(cls, settings: GitHubAppSettings, **kwargs: Any) -> Self:
        """Build a client from the standard settings, passing any other option through."""
        return cls(
            app_id=settings.app_id,
            private_key=settings.private_key.get_secret_value(),
            installation_id=settings.installation_id,
            **kwargs,
        )

    def __repr__(self) -> str:
        """Name the App, the pinned installation and the API root, and nothing secret."""
        return (
            f"GitHubAppClient(app_id={self._app_id!r}, installation_id={self._installation_id!r}, "
            f"api_url={self._api_url!r})"
        )

    def __enter__(self) -> Self:
        """Use the client as a context manager that closes it on exit."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the client on leaving the block."""
        self.close()

    def close(self) -> None:
        """Close the underlying `httpx.Client` when this instance built it."""
        if self._owns_client:
            self._client.close()

    def app_jwt(self) -> str:
        """A fresh RS256 App JWT, `iat` backdated a minute and `exp` nine minutes out."""
        now = int(self._clock())
        claims = {
            "iat": now - APP_JWT_BACKDATE_SECONDS,
            "exp": now + APP_JWT_TTL_SECONDS,
            "iss": self._app_id,
        }
        try:
            return jwt.encode(claims, self._private_key, algorithm="RS256")
        except (ValueError, TypeError, jwt.PyJWTError):
            raise GitHubError("the App private key could not sign the App JWT") from None

    def installation_token(self, installation_id: int | str) -> str:
        """An installation access token, from the cache while it has time left, else minted."""
        key = _identifier(installation_id, "installation_id")
        with self._lock:
            cached = self._tokens.get(key)
            if cached is not None and cached.expires_at - self._refresh_margin > self._clock():
                return cached.token
            body = self._call("POST", f"/app/installations/{key}/access_tokens", token=self.app_jwt())
            token = str(body.get("token", "")) if isinstance(body, dict) else ""
            if not token:
                raise GitHubError("the installation token exchange answered no token")
            expires_at = _expiry(body.get("expires_at"))
            if expires_at is None:
                self._tokens.pop(key, None)
            else:
                self._tokens[key] = _CachedToken(token=token, expires_at=expires_at)
            return token

    def repository_installation(self, repository: str) -> int:
        """The id of the installation covering `repository`, read with the App JWT and cached."""
        name = _repository(repository)
        cache_key = name.lower()
        with self._lock:
            cached = self._installations.get(cache_key)
        if cached is not None:
            return int(cached)
        body = self._call("GET", f"/repos/{name}/installation", token=self.app_jwt())
        found = body.get("id") if isinstance(body, dict) else None
        if not isinstance(found, int) or found <= 0:
            raise GitHubError("the repository installation read answered no id")
        with self._lock:
            self._installations[cache_key] = str(found)
        return found

    def get_app_installation(self, installation_id: int | str) -> AppInstallation:
        """One of this App's installations, read with the App JWT.

        Raises `GitHubNotFound` when the id names no installation of this App, which is what
        makes an installation id from an unauthenticated redirect trustworthy once read.
        """
        key = _identifier(installation_id, "installation_id")
        path = f"/app/installations/{key}"
        try:
            body = self._call("GET", path, token=self.app_jwt())
        except GitHubNotFound as exc:
            raise GitHubNotFound(
                f"installation {key} is not an installation of this App",
                method=exc.method,
                path=exc.path,
                status_code=exc.status_code,
                github_message=exc.github_message,
            ) from None
        if not isinstance(body, dict):
            raise GitHubError("the installation read answered no object", method="GET", path=path)
        account = body.get("account")
        account = account if isinstance(account, dict) else {}
        permissions = body.get("permissions")
        return AppInstallation(
            id=int(body.get("id", key)),
            app_id=int(body.get("app_id", 0)),
            account_login=str(account.get("login", "")),
            account_type=str(account.get("type", "")),
            account_avatar_url=str(account.get("avatar_url", "")),
            repository_selection=str(body.get("repository_selection", "")),
            html_url=str(body.get("html_url", "")),
            permissions={str(k): str(v) for k, v in permissions.items()} if isinstance(permissions, dict) else {},
            suspended_at=_timestamp(body.get("suspended_at")),
        )

    def list_installation_repositories(self, installation_id: int | str) -> list[dict[str, Any]]:
        """Every repository an installation covers, paged to the end."""
        key = _identifier(installation_id, "installation_id")
        repositories: list[dict[str, Any]] = []
        page = 1
        while True:
            body = self._as_installation(
                key,
                None,
                "GET",
                "/installation/repositories",
                params={"per_page": _REPOSITORIES_PAGE_SIZE, "page": page},
            )
            batch = body.get("repositories", []) if isinstance(body, dict) else []
            repositories.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < _REPOSITORIES_PAGE_SIZE:
                return repositories
            page += 1

    def create_check_run(
        self,
        repository: str,
        *,
        name: str,
        head_sha: str,
        status: CheckRunStatus = "completed",
        conclusion: CheckRunConclusion | None = None,
        output: CheckRunOutput | None = None,
        details_url: str | None = None,
        external_id: str | None = None,
        installation_id: int | str | None = None,
    ) -> CheckRun:
        """Create a check run on `head_sha`. A completed one needs a conclusion."""
        if status == "completed" and conclusion is None:
            raise ValueError("a completed check run needs a conclusion")
        payload: dict[str, Any] = {"name": name, "head_sha": head_sha, "status": status}
        payload.update(_check_run_fields(conclusion, output, details_url, external_id))
        body = self._repository_call(repository, installation_id, "POST", "/check-runs", json=payload)
        return _check_run(body)

    def update_check_run(
        self,
        repository: str,
        check_run_id: int | str,
        *,
        status: CheckRunStatus | None = None,
        conclusion: CheckRunConclusion | None = None,
        output: CheckRunOutput | None = None,
        details_url: str | None = None,
        external_id: str | None = None,
        installation_id: int | str | None = None,
    ) -> CheckRun:
        """Update an existing check run, sending only the fields given."""
        payload: dict[str, Any] = {} if status is None else {"status": status}
        payload.update(_check_run_fields(conclusion, output, details_url, external_id))
        run = _identifier(check_run_id, "check_run_id")
        body = self._repository_call(repository, installation_id, "PATCH", f"/check-runs/{run}", json=payload)
        return _check_run(body)

    def create_commit_status(
        self,
        repository: str,
        sha: str,
        *,
        state: CommitState,
        context: str,
        description: str | None = None,
        target_url: str | None = None,
        installation_id: int | str | None = None,
    ) -> CommitStatus:
        """Set the commit status named `context` on `sha`."""
        payload: dict[str, Any] = {"state": state, "context": context}
        if description is not None:
            payload["description"] = description
        if target_url is not None:
            payload["target_url"] = target_url
        body = self._repository_call(repository, installation_id, "POST", f"/statuses/{_sha(sha)}", json=payload)
        mapping = body if isinstance(body, dict) else {}
        return CommitStatus(
            id=int(mapping.get("id", 0)),
            state=str(mapping.get("state", state)),
            context=str(mapping.get("context", context)),
        )

    def create_issue_comment(
        self,
        repository: str,
        issue_number: int | str,
        body: str,
        *,
        installation_id: int | str | None = None,
    ) -> IssueComment:
        """Post a comment on an issue or pull request."""
        number = _identifier(issue_number, "issue_number")
        answer = self._repository_call(
            repository, installation_id, "POST", f"/issues/{number}/comments", json={"body": body}
        )
        return _issue_comment(answer)

    def update_issue_comment(
        self,
        repository: str,
        comment_id: int | str,
        body: str,
        *,
        installation_id: int | str | None = None,
    ) -> IssueComment:
        """Replace the body of a comment the App already posted."""
        comment = _identifier(comment_id, "comment_id")
        answer = self._repository_call(
            repository, installation_id, "PATCH", f"/issues/comments/{comment}", json={"body": body}
        )
        return _issue_comment(answer)

    def _repository_call(
        self,
        repository: str,
        installation_id: int | str | None,
        method: str,
        suffix: str,
        *,
        json: Mapping[str, Any],
    ) -> Any:
        """One call under `/repos/{repository}`, as the installation that resolves for it."""
        name = _repository(repository)
        if installation_id is not None:
            key, looked_up = _identifier(installation_id, "installation_id"), None
        elif self._installation_id is not None:
            key, looked_up = self._installation_id, None
        else:
            key, looked_up = str(self.repository_installation(name)), name.lower()
        return self._as_installation(key, looked_up, method, f"/repos/{name}{suffix}", json=json)

    def _as_installation(
        self,
        key: str,
        looked_up: str | None,
        method: str,
        path: str,
        *,
        json: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """One call as installation `key`, forgetting whatever cached state GitHub refused.

        A 401 drops the cached token. A 404 on the token exchange for an installation that was
        looked up for `looked_up` drops that lookup, since the App was reinstalled or removed.
        """
        try:
            token = self.installation_token(key)
        except GitHubNotFound:
            if looked_up is not None:
                with self._lock:
                    self._installations.pop(looked_up, None)
            raise
        try:
            return self._call(method, path, token=token, json=json, params=params)
        except GitHubUnauthorized:
            with self._lock:
                cached = self._tokens.get(key)
                if cached is not None and cached.token == token:
                    del self._tokens[key]
            raise

    def _call(
        self,
        method: str,
        path: str,
        *,
        token: str,
        json: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """One GitHub call with `token`, answering the parsed body or raising `GitHubError`."""
        return _send(self._client, self._api_url, method, path, token=token, json=json, params=params, now=self._clock)


def _send(
    http: httpx.Client,
    api_url: str,
    method: str,
    path: str,
    *,
    token: str | None,
    json: Mapping[str, Any] | None = None,
    params: Mapping[str, Any] | None = None,
    now: Callable[[], float] = time.time,
) -> Any:
    """One GitHub call, answering the parsed body or raising the mapped `GitHubError`.

    `token` is sent as a bearer when given; the manifest conversion is the one call without.
    A failure logs the method, the path and the status, and never a header.
    """
    headers = {"Accept": ACCEPT, "X-GitHub-Api-Version": API_VERSION}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = http.request(
            method,
            f"{api_url}{path}",
            headers=headers,
            json=dict(json) if json is not None else None,
            params=dict(params) if params is not None else None,
        )
    except httpx.HTTPError as exc:
        _log.warning(
            "GitHub did not answer.",
            extra={"event": "integrations.github.unavailable", "method": method, "path": path},
        )
        raise GitHubUnavailable(f"{method} {path} did not answer", method=method, path=path) from exc
    if response.status_code >= 400:
        error = _error_for(response, method, path, now())
        _log.warning(
            "GitHub refused a call.",
            extra={
                "event": "integrations.github.error",
                "method": method,
                "path": path,
                "status": response.status_code,
            },
        )
        raise error
    if not response.content:
        return None
    return response.json()


def convert_manifest_code(
    code: str,
    *,
    api_url: str = API_ROOT,
    client: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> AppManifestConversion:
    """Exchange the manifest flow's one-time `code` for the new App and its credentials.

    Unauthenticated by GitHub's design, so it needs no App configuration: this is the call
    that creates one. The code expires an hour after GitHub issues it and works once.
    """
    if not _MANIFEST_CODE_PATTERN.fullmatch(code):
        raise ValueError("code must be the manifest flow's code")
    http = client if client is not None else httpx.Client(timeout=timeout, follow_redirects=False)
    path = f"/app-manifests/{code}/conversions"
    try:
        body = _send(http, api_url.rstrip("/"), "POST", path, token=None)
    finally:
        if client is None:
            http.close()
    mapping = body if isinstance(body, dict) else {}
    app_id = mapping.get("id")
    pem = mapping.get("pem")
    if not isinstance(app_id, int) or not isinstance(pem, str) or not pem:
        raise GitHubError(
            "the manifest conversion answered no App", method="POST", path="/app-manifests/.../conversions"
        )
    owner = mapping.get("owner")
    webhook_secret = mapping.get("webhook_secret")
    return AppManifestConversion(
        id=app_id,
        slug=str(mapping.get("slug", "")),
        name=str(mapping.get("name", "")),
        html_url=str(mapping.get("html_url", "")),
        owner_login=str(owner.get("login", "")) if isinstance(owner, dict) else "",
        client_id=str(mapping.get("client_id", "")),
        client_secret=SecretStr(str(mapping.get("client_secret", ""))),
        webhook_secret=SecretStr(webhook_secret) if isinstance(webhook_secret, str) and webhook_secret else None,
        pem=SecretStr(pem),
    )


def _check_run_fields(
    conclusion: CheckRunConclusion | None,
    output: CheckRunOutput | None,
    details_url: str | None,
    external_id: str | None,
) -> dict[str, Any]:
    """The optional check run fields that were given, as GitHub takes them."""
    fields: dict[str, Any] = {}
    if conclusion is not None:
        fields["conclusion"] = conclusion
    if output is not None:
        fields["output"] = output.as_json()
    if details_url is not None:
        fields["details_url"] = details_url
    if external_id is not None:
        fields["external_id"] = external_id
    return fields


def _check_run(body: Any) -> CheckRun:
    """Read a check run answer into `CheckRun`."""
    mapping = body if isinstance(body, dict) else {}
    conclusion = mapping.get("conclusion")
    return CheckRun(
        id=int(mapping.get("id", 0)),
        status=str(mapping.get("status", "")),
        conclusion=None if conclusion is None else str(conclusion),
        html_url=str(mapping.get("html_url", "")),
    )


def _issue_comment(body: Any) -> IssueComment:
    """Read a comment answer into `IssueComment`."""
    mapping = body if isinstance(body, dict) else {}
    return IssueComment(id=int(mapping.get("id", 0)), html_url=str(mapping.get("html_url", "")))
