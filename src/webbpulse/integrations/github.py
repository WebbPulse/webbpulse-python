"""A small, synchronous GitHub App client: the App JWT, installation tokens, and write-backs.

`GitHubAppSettings` is the one configuration shape every product reads from its `app`
secret, and `load_github_app_settings` resolves it from the environment and that secret.
`GitHubAppClient` signs the App JWT, exchanges it for an installation access token cached
per installation until shortly before it expires, and makes the handful of calls a product
reports through: check runs, commit statuses and issue comments. It also reads an
installation's own record, the repositories it covers, and the installation a repository
belongs to. Through an installation it reads commits, comparisons, pull requests with their
commits and files, check runs, issue comments, tags and releases, and downloads repository
archives and release assets. Reads retry a transport failure, a 5xx or a refused token with
backoff, and listings page to a bounded number of pages. `convert_manifest_code` finishes
the App manifest flow, before any App configuration exists. Nothing here routes webhooks or
knows any product's naming.

Every failure is a `GitHubError` subclass chosen by status, so a caller can tell a missing
repository from a rate limit without reading status codes. Only a 2xx is success: redirects
are never followed, and a 3xx raises `GitHubRedirected`. The App private key and every
token stay out of reprs, exception messages and log lines.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Literal, Self
from urllib.parse import quote, urlsplit

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
    "ASSET_HOSTS",
    "DEFAULT_MAX_PAGES",
    "DEFAULT_TIMEOUT_SECONDS",
    "READ_ATTEMPTS",
    "READ_BACKOFF_SECONDS",
    "SETTINGS_KEYS",
    "TARBALL_HOSTS",
    "TOKEN_REFRESH_MARGIN_SECONDS",
    "AppInstallation",
    "AppManifestConversion",
    "CheckRun",
    "CheckRunConclusion",
    "CheckRunOutput",
    "CheckRunStatus",
    "Commit",
    "CommitComparison",
    "CommitState",
    "CommitStatus",
    "Download",
    "GitHubAppClient",
    "GitHubAppSettings",
    "GitHubDownloadTooLarge",
    "GitHubError",
    "GitHubForbidden",
    "GitHubNotConfigured",
    "GitHubNotFound",
    "GitHubRateLimited",
    "GitHubRedirected",
    "GitHubUnauthorized",
    "GitHubUnavailable",
    "GitHubUnprocessable",
    "IssueComment",
    "PullRequest",
    "PullRequestFile",
    "Release",
    "ReleaseAsset",
    "Tag",
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

DEFAULT_MAX_PAGES: Final = 10
"""How many pages of 100 a listing reads unless the caller names another bound."""

READ_ATTEMPTS: Final = 3
"""How many times a read or a download is tried before its last failure is raised."""

READ_BACKOFF_SECONDS: Final = 0.5
"""The wait before the second attempt of a read, doubling for each attempt after it."""

TARBALL_HOSTS: Final = frozenset({"codeload.github.com"})
"""Where a repository archive redirect may point. Anything else is refused."""

ASSET_HOSTS: Final = frozenset(
    {"objects.githubusercontent.com", "release-assets.githubusercontent.com", "github-releases.githubusercontent.com"}
)
"""Where a release asset redirect may point. Anything else is refused."""

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


_PAGE_SIZE: Final = 100

_REF_REFUSED: Final = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]|\.\.|//|^/|/$|^-")

_REDIRECTS: Final = frozenset({301, 302, 303, 307, 308})

_DOWNLOAD_CHUNK_BYTES: Final = 1024 * 1024

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


class GitHubRedirected(GitHubError):
    """A 3xx: GitHub pointed the call elsewhere, most often because the repository was renamed or moved.

    The client this module builds never follows a redirect, for any method; one a caller
    hands in keeps its own setting, and only its final answer is judged. A followed 307 or 308 would replay a write
    with the bearer token against a URL the caller never chose, and a followed 301 on a
    write turns into a GET whose answer looks like success, so a caller would record a post
    that never happened. Raising keeps success meaning the call did what was asked;
    `location` is where GitHub pointed, so a caller can refresh its stored owner and name,
    or address the repository by id, and call again.
    """

    def __init__(self, message: str, *, location: str = "", **kwargs: Any) -> None:
        """Record where GitHub pointed alongside the failed call."""
        super().__init__(message, **kwargs)
        self.location = location


class GitHubDownloadTooLarge(GitHubError):
    """A download outgrew the byte limit the caller set, so it was abandoned part way."""


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
    """A check run as GitHub answered it.

    `app_id` is the App that created it, which a listing needs to tell this App's runs apart.
    """

    id: int
    status: str
    conclusion: str | None
    html_url: str
    name: str = ""
    head_sha: str = ""
    external_id: str | None = None
    app_id: int | None = None


@dataclass(frozen=True, slots=True)
class CommitStatus:
    """A commit status as GitHub answered it."""

    id: int
    state: str
    context: str


@dataclass(frozen=True, slots=True)
class IssueComment:
    """An issue or pull request comment as GitHub answered it.

    `user_type` is `Bot` for a comment an App posted, `User` for a person's.
    """

    id: int
    html_url: str
    body: str = ""
    user_login: str = ""
    user_type: str = ""


@dataclass(frozen=True, slots=True)
class Commit:
    """A commit as GitHub answered it, its parents' shas in order."""

    sha: str
    message: str
    parents: tuple[str, ...]
    html_url: str


@dataclass(frozen=True, slots=True)
class CommitComparison:
    """How `head` relates to `base`: `status` is `identical`, `ahead`, `behind` or `diverged`."""

    status: str
    ahead_by: int
    behind_by: int
    total_commits: int


@dataclass(frozen=True, slots=True)
class PullRequest:
    """A pull request as GitHub answered it.

    `mergeable` is None while GitHub is still computing the merge, and `merge_commit_sha`
    names the test merge commit of an open pull request or the merge of a merged one.
    """

    number: int
    state: str
    html_url: str
    head_sha: str
    head_ref: str
    base_ref: str
    merge_commit_sha: str | None
    mergeable: bool | None
    merged_at: datetime | None
    draft: bool


@dataclass(frozen=True, slots=True)
class PullRequestFile:
    """One file a pull request changes, with the path it had before a rename."""

    filename: str
    status: str
    previous_filename: str | None


@dataclass(frozen=True, slots=True)
class Tag:
    """A tag and the commit it names, dereferenced even for an annotated tag."""

    name: str
    sha: str


@dataclass(frozen=True, slots=True)
class ReleaseAsset:
    """A file attached to a release."""

    id: int
    name: str
    size: int
    content_type: str


@dataclass(frozen=True, slots=True)
class Release:
    """A release as GitHub answered it, a draft included when the App can see drafts."""

    id: int
    tag_name: str
    name: str
    draft: bool
    prerelease: bool
    html_url: str
    assets: tuple[ReleaseAsset, ...]


@dataclass(frozen=True, slots=True)
class Download:
    """What a download wrote: its size in bytes and its hex SHA-256."""

    size: int
    sha256: str


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

    def app_secret_values(self) -> dict[str, str]:
        """Return the credentials keyed by their `app` secret names, ready for `SecretStore.set_many`."""
        values = {
            "GITHUB_APP_ID": str(self.id),
            "GITHUB_PRIVATE_KEY": self.pem.get_secret_value(),
            "GITHUB_CLIENT_ID": self.client_id,
            "GITHUB_CLIENT_SECRET": self.client_secret.get_secret_value(),
        }
        if self.webhook_secret is not None:
            values["GITHUB_WEBHOOK_SECRET"] = self.webhook_secret.get_secret_value()
        return values


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


def _ref(value: str) -> str:
    """A branch, tag or sha, refusing what git forbids in a ref or could escape its path."""
    if not value or _REF_REFUSED.search(value):
        raise ValueError("ref must be a branch, tag or commit sha")
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
    if 300 <= status < 400:
        return GitHubRedirected(f"{message}, a redirect", location=response.headers.get("location", ""), **context)
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

    Reads and downloads are tried `read_attempts` times, waiting `read_backoff_seconds` and
    then twice as long each time, when GitHub does not answer, answers a 5xx, or refuses the
    installation token (which is then minted afresh). Writes are never retried, since a
    write GitHub applied but did not confirm would be applied twice.
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
        read_attempts: int = READ_ATTEMPTS,
        read_backoff_seconds: float = READ_BACKOFF_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Hold the App id, the private key PEM and an optional pinned installation."""
        if not str(app_id).strip():
            raise ValueError("app_id is required")
        if not private_key.strip():
            raise ValueError("private_key is required")
        if read_attempts < 1:
            raise ValueError("read_attempts must be at least 1")
        self._app_id = str(app_id).strip()
        self._private_key = private_key
        self._installation_id = None if installation_id is None else _identifier(installation_id, "installation_id")
        self._api_url = api_url.rstrip("/")
        self._owns_client = client is None
        self._client = client if client is not None else httpx.Client(timeout=timeout, follow_redirects=False)
        self._refresh_margin = refresh_margin_seconds
        self._clock = clock
        self._read_attempts = read_attempts
        self._read_backoff = read_backoff_seconds
        self._sleep = sleep
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
                params={"per_page": _PAGE_SIZE, "page": page},
            )
            batch = body.get("repositories", []) if isinstance(body, dict) else []
            repositories.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < _PAGE_SIZE:
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

    def get_commit(self, repository: str, ref: str, *, installation_id: int | str | None = None) -> Commit:
        """The commit `ref` names, a sha, branch or tag."""
        body = self._read(repository, installation_id, f"/commits/{quote(_ref(ref), safe='/')}")
        return _commit(body)

    def compare_commits(
        self, repository: str, base: str, head: str, *, installation_id: int | str | None = None
    ) -> CommitComparison:
        """How `head` relates to `base`, each a sha, branch or tag."""
        spec = f"{quote(_ref(base), safe='/')}...{quote(_ref(head), safe='/')}"
        body = self._read(repository, installation_id, f"/compare/{spec}", params={"per_page": 1})
        mapping = _object(body)
        return CommitComparison(
            status=str(mapping.get("status", "")),
            ahead_by=_int(mapping.get("ahead_by")),
            behind_by=_int(mapping.get("behind_by")),
            total_commits=_int(mapping.get("total_commits")),
        )

    def get_pull_request(
        self, repository: str, number: int | str, *, installation_id: int | str | None = None
    ) -> PullRequest:
        """One pull request by number."""
        body = self._read(repository, installation_id, f"/pulls/{_identifier(number, 'number')}")
        return _pull_request(body)

    def list_pull_request_commits(
        self,
        repository: str,
        number: int | str,
        *,
        max_pages: int = DEFAULT_MAX_PAGES,
        installation_id: int | str | None = None,
    ) -> list[Commit]:
        """The commits of a pull request, oldest first. GitHub lists at most 250."""
        suffix = f"/pulls/{_identifier(number, 'number')}/commits"
        return [_commit(item) for item in self._read_pages(repository, installation_id, suffix, max_pages=max_pages)]

    def list_pull_request_files(
        self,
        repository: str,
        number: int | str,
        *,
        max_pages: int = DEFAULT_MAX_PAGES,
        installation_id: int | str | None = None,
    ) -> list[PullRequestFile]:
        """The files a pull request changes. GitHub lists at most 3000."""
        suffix = f"/pulls/{_identifier(number, 'number')}/files"
        return [
            PullRequestFile(
                filename=str(item.get("filename", "")),
                status=str(item.get("status", "")),
                previous_filename=_optional_str(item.get("previous_filename")),
            )
            for item in self._read_pages(repository, installation_id, suffix, max_pages=max_pages)
        ]

    def list_commit_pull_requests(
        self,
        repository: str,
        sha: str,
        *,
        max_pages: int = DEFAULT_MAX_PAGES,
        installation_id: int | str | None = None,
    ) -> list[PullRequest]:
        """The pull requests `sha` belongs to, merged ones included."""
        suffix = f"/commits/{_sha(sha)}/pulls"
        listed = self._read_pages(repository, installation_id, suffix, max_pages=max_pages)
        return [_pull_request(item) for item in listed]

    def list_check_runs(
        self,
        repository: str,
        ref: str,
        *,
        check_name: str | None = None,
        app_id: int | str | None = None,
        latest: bool = True,
        max_pages: int = DEFAULT_MAX_PAGES,
        installation_id: int | str | None = None,
    ) -> list[CheckRun]:
        """The check runs on `ref`, narrowed by name and creating App when given.

        `latest` keeps GitHub's default of the newest run per name; False lists every run.
        """
        params: dict[str, Any] = {"filter": "latest" if latest else "all"}
        if check_name is not None:
            params["check_name"] = check_name
        if app_id is not None:
            params["app_id"] = _identifier(app_id, "app_id")
        suffix = f"/commits/{quote(_ref(ref), safe='/')}/check-runs"
        listed = self._read_pages(
            repository, installation_id, suffix, params=params, key="check_runs", max_pages=max_pages
        )
        return [_check_run(item) for item in listed]

    def list_issue_comments(
        self,
        repository: str,
        issue_number: int | str,
        *,
        max_pages: int = DEFAULT_MAX_PAGES,
        installation_id: int | str | None = None,
    ) -> list[IssueComment]:
        """The comments on an issue or pull request, oldest first."""
        suffix = f"/issues/{_identifier(issue_number, 'issue_number')}/comments"
        listed = self._read_pages(repository, installation_id, suffix, max_pages=max_pages)
        return [_issue_comment(item) for item in listed]

    def list_tags(
        self, repository: str, *, max_pages: int = DEFAULT_MAX_PAGES, installation_id: int | str | None = None
    ) -> list[Tag]:
        """The repository's tags, each with the commit it names."""
        found: list[Tag] = []
        for item in self._read_pages(repository, installation_id, "/tags", max_pages=max_pages):
            name = str(item.get("name") or "")
            sha = str(_object(item.get("commit")).get("sha") or "")
            if name and sha:
                found.append(Tag(name=name, sha=sha))
        return found

    def list_releases(
        self, repository: str, *, max_pages: int = DEFAULT_MAX_PAGES, installation_id: int | str | None = None
    ) -> list[Release]:
        """The repository's releases, newest first."""
        listed = self._read_pages(repository, installation_id, "/releases", max_pages=max_pages)
        return [_release(item) for item in listed]

    def get_release_by_tag(self, repository: str, tag: str, *, installation_id: int | str | None = None) -> Release:
        """The published release at `tag`. Raises `GitHubNotFound` when there is none."""
        body = self._read(repository, installation_id, f"/releases/tags/{quote(_ref(tag), safe='')}")
        return _release(body)

    def download_tarball(
        self,
        repository: str,
        ref: str,
        target: Path,
        *,
        max_bytes: int,
        installation_id: int | str | None = None,
    ) -> Download:
        """Write the gzipped archive of `repository` at `ref` to `target`.

        GitHub redirects to a signed `codeload.github.com` URL, which is fetched without the
        installation token; a redirect anywhere else is refused. Raises
        `GitHubDownloadTooLarge` past `max_bytes`, leaving a partial `target` behind.
        """
        suffix = f"/tarball/{quote(_ref(ref), safe='/')}"
        return self._download(repository, installation_id, suffix, target, ACCEPT, TARBALL_HOSTS, max_bytes)

    def download_release_asset(
        self,
        repository: str,
        asset_id: int | str,
        target: Path,
        *,
        max_bytes: int,
        installation_id: int | str | None = None,
    ) -> Download:
        """Write one release asset to `target`.

        GitHub either answers the bytes or redirects to a signed asset host, which is fetched
        without the installation token; a redirect anywhere else is refused. Raises
        `GitHubDownloadTooLarge` past `max_bytes`, leaving a partial `target` behind.
        """
        suffix = f"/releases/assets/{_identifier(asset_id, 'asset_id')}"
        return self._download(
            repository, installation_id, suffix, target, "application/octet-stream", ASSET_HOSTS, max_bytes
        )

    def _retrying[T](self, attempt: Callable[[], T]) -> T:
        """Run `attempt`, trying again with backoff on an unavailable GitHub or a refused token."""
        for number in range(1, self._read_attempts):
            try:
                return attempt()
            except (GitHubUnavailable, GitHubUnauthorized):
                self._sleep(self._read_backoff * 2 ** (number - 1))
        return attempt()

    def _read(
        self,
        repository: str,
        installation_id: int | str | None,
        suffix: str,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """One GET under `/repos/{repository}`, retried."""
        name = _repository(repository)
        return self._retrying(lambda: self._repository_call(name, installation_id, "GET", suffix, params=params))

    def _read_pages(
        self,
        repository: str,
        installation_id: int | str | None,
        suffix: str,
        *,
        max_pages: int,
        params: Mapping[str, Any] | None = None,
        key: str | None = None,
    ) -> list[dict[str, Any]]:
        """Every object a paged listing answers, stopping at a short page or after `max_pages`.

        `key` names the list inside an object answer, such as `check_runs`.
        """
        if max_pages < 1:
            raise ValueError("max_pages must be at least 1")
        items: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            query = {**(params or {}), "per_page": _PAGE_SIZE, "page": page}
            body = self._read(repository, installation_id, suffix, params=query)
            batch = body.get(key) if key is not None and isinstance(body, dict) else body
            batch = batch if isinstance(batch, list) else []
            items.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < _PAGE_SIZE:
                break
        return items

    def _download(
        self,
        repository: str,
        installation_id: int | str | None,
        suffix: str,
        target: Path,
        accept: str,
        hosts: Collection[str],
        max_bytes: int,
    ) -> Download:
        """Fetch `/repos/{repository}{suffix}` into `target`, following one redirect to `hosts`, retried."""
        if max_bytes < 1:
            raise ValueError("max_bytes must be at least 1")
        name = _repository(repository)
        path = f"/repos/{name}{suffix}"

        def attempt() -> Download:
            """One try: resolve the installation, then fetch with its token."""
            key, looked_up = self._installation_for(name, installation_id)
            return self._with_installation(
                key, looked_up, lambda token: self._fetch(path, token, target, accept, hosts, max_bytes)
            )

        return self._retrying(attempt)

    def _fetch(
        self, path: str, token: str, target: Path, accept: str, hosts: Collection[str], max_bytes: int
    ) -> Download:
        """One download: the API call with the token, then any redirect without it."""
        headers = {"Accept": accept, "X-GitHub-Api-Version": API_VERSION, "Authorization": f"Bearer {token}"}
        try:
            with self._client.stream(
                "GET", f"{self._api_url}{path}", headers=headers, follow_redirects=False
            ) as response:
                if response.status_code == 200:
                    return _save(response, target, max_bytes, path)
                if response.status_code not in _REDIRECTS:
                    response.read()
                    raise _refused(response, "GET", path, self._clock())
                location = response.headers.get("location", "")
        except httpx.HTTPError as exc:
            raise GitHubUnavailable(f"GET {path} did not answer", method="GET", path=path) from exc
        parts = urlsplit(location)
        if parts.scheme != "https" or parts.hostname not in hosts:
            raise GitHubError(f"GET {path} redirected to an unexpected host", method="GET", path=path)
        try:
            with self._client.stream("GET", location, follow_redirects=False) as download:
                if download.status_code != 200:
                    download.read()
                    raise _refused(download, "GET", path, self._clock())
                return _save(download, target, max_bytes, path)
        except httpx.HTTPError as exc:
            raise GitHubUnavailable(f"GET {path} download did not answer", method="GET", path=path) from exc

    def _installation_for(self, name: str, installation_id: int | str | None) -> tuple[str, str | None]:
        """The installation a call on `name` runs as, and the lookup key when it was looked up."""
        if installation_id is not None:
            return _identifier(installation_id, "installation_id"), None
        if self._installation_id is not None:
            return self._installation_id, None
        return str(self.repository_installation(name)), name.lower()

    def _repository_call(
        self,
        repository: str,
        installation_id: int | str | None,
        method: str,
        suffix: str,
        *,
        json: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """One call under `/repos/{repository}`, as the installation that resolves for it."""
        name = _repository(repository)
        key, looked_up = self._installation_for(name, installation_id)
        return self._as_installation(key, looked_up, method, f"/repos/{name}{suffix}", json=json, params=params)

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
        """One call as installation `key`, forgetting whatever cached state GitHub refused."""
        return self._with_installation(
            key, looked_up, lambda token: self._call(method, path, token=token, json=json, params=params)
        )

    def _with_installation[T](self, key: str, looked_up: str | None, send: Callable[[str], T]) -> T:
        """Run `send` with installation `key`'s token, forgetting whatever cached state GitHub refused.

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
            return send(token)
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
    Anything but a 2xx raises, a 3xx included, since redirects are never followed (see
    `GitHubRedirected`). A failure logs the method, the path and the status, and never a header.
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
    if not 200 <= response.status_code < 300:
        raise _refused(response, method, path, now())
    if not response.content:
        return None
    return response.json()


def _refused(response: httpx.Response, method: str, path: str, now: float) -> GitHubError:
    """Log a refused call by method, path and status, and answer the error it maps to."""
    _log.warning(
        "GitHub refused a call.",
        extra={
            "event": "integrations.github.error",
            "method": method,
            "path": path,
            "status": response.status_code,
        },
    )
    return _error_for(response, method, path, now)


def _save(response: httpx.Response, target: Path, max_bytes: int, path: str) -> Download:
    """Stream a download's body into `target`, hashing it and refusing it past `max_bytes`."""
    digest = hashlib.sha256()
    size = 0
    with target.open("wb") as handle:
        for chunk in response.iter_bytes(_DOWNLOAD_CHUNK_BYTES):
            size += len(chunk)
            if size > max_bytes:
                raise GitHubDownloadTooLarge(
                    f"GET {path} is larger than {max_bytes} bytes", method="GET", path=path, status_code=200
                )
            digest.update(chunk)
            handle.write(chunk)
    return Download(size=size, sha256=digest.hexdigest())


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


def _int(value: Any) -> int:
    """An integer field, or 0 when it is absent or not a number."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _optional_str(value: Any) -> str | None:
    """A non-empty string field, or None."""
    return value if isinstance(value, str) and value else None


def _object(value: Any) -> dict[str, Any]:
    """A nested object field, or an empty one."""
    return value if isinstance(value, dict) else {}


def _check_run(body: Any) -> CheckRun:
    """Read a check run answer into `CheckRun`."""
    mapping = _object(body)
    conclusion = mapping.get("conclusion")
    app_id = _int(_object(mapping.get("app")).get("id"))
    return CheckRun(
        id=int(mapping.get("id", 0)),
        status=str(mapping.get("status", "")),
        conclusion=None if conclusion is None else str(conclusion),
        html_url=str(mapping.get("html_url", "")),
        name=str(mapping.get("name", "")),
        head_sha=str(mapping.get("head_sha", "")),
        external_id=_optional_str(mapping.get("external_id")),
        app_id=app_id or None,
    )


def _issue_comment(body: Any) -> IssueComment:
    """Read a comment answer into `IssueComment`."""
    mapping = _object(body)
    user = _object(mapping.get("user"))
    return IssueComment(
        id=int(mapping.get("id", 0)),
        html_url=str(mapping.get("html_url", "")),
        body=str(mapping.get("body") or ""),
        user_login=str(user.get("login", "")),
        user_type=str(user.get("type", "")),
    )


def _commit(body: Any) -> Commit:
    """Read a commit answer into `Commit`."""
    mapping = _object(body)
    parents = mapping.get("parents")
    return Commit(
        sha=str(mapping.get("sha", "")),
        message=str(_object(mapping.get("commit")).get("message") or ""),
        parents=tuple(
            str(parent.get("sha", ""))
            for parent in (parents if isinstance(parents, list) else [])
            if isinstance(parent, dict)
        ),
        html_url=str(mapping.get("html_url", "")),
    )


def _pull_request(body: Any) -> PullRequest:
    """Read a pull request answer into `PullRequest`."""
    mapping = _object(body)
    head = _object(mapping.get("head"))
    base = _object(mapping.get("base"))
    mergeable = mapping.get("mergeable")
    return PullRequest(
        number=_int(mapping.get("number")),
        state=str(mapping.get("state", "")),
        html_url=str(mapping.get("html_url", "")),
        head_sha=str(head.get("sha", "")),
        head_ref=str(head.get("ref", "")),
        base_ref=str(base.get("ref", "")),
        merge_commit_sha=_optional_str(mapping.get("merge_commit_sha")),
        mergeable=mergeable if isinstance(mergeable, bool) else None,
        merged_at=_timestamp(mapping.get("merged_at")),
        draft=mapping.get("draft") is True,
    )


def _release(body: Any) -> Release:
    """Read a release answer into `Release`."""
    mapping = _object(body)
    assets = mapping.get("assets")
    return Release(
        id=_int(mapping.get("id")),
        tag_name=str(mapping.get("tag_name") or ""),
        name=str(mapping.get("name") or ""),
        draft=mapping.get("draft") is True,
        prerelease=mapping.get("prerelease") is True,
        html_url=str(mapping.get("html_url", "")),
        assets=tuple(
            ReleaseAsset(
                id=_int(item.get("id")),
                name=str(item.get("name") or ""),
                size=_int(item.get("size")),
                content_type=str(item.get("content_type") or ""),
            )
            for item in (assets if isinstance(assets, list) else [])
            if isinstance(item, dict)
        ),
    )
