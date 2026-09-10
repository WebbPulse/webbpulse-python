"""OAuth sign-in and account linking: providers, the state store, and the link service.

M6 of `docs/identity-standard.md`. Section 2.6 names Google and GitHub as the two providers
in the mandatory baseline, section 3.4's sequence diagram fixes the shape of the flow, and
section 4.2 gives the two tables. This module is the whole of that, minus the routes, which
live in `oauth_routes.py` for the reason given there.

Everything here is synchronous and imports no FastAPI, matching the `services/` rule in
section 2.1: a flow must be callable from a test, a CLI or a queue consumer without a
request object. The provider HTTP calls go through `httpx` behind a small `HttpClient`
protocol, so a test substitutes a transport rather than monkeypatching a module.

## The authorization code flow, with PKCE where it exists

Both providers get `state`; only Google gets PKCE and a nonce.

**PKCE** (RFC 7636) is offered by Google and not by GitHub. GitHub's web application flow
documents no `code_challenge` parameter and ignores one sent, so sending it would be
security theatre: a verifier the provider never checks proves nothing on the exchange. The
provider table records this per provider rather than sending it unconditionally, so a reader
can see which providers are actually protected by it and which rest on `state` and the
client secret alone. When GitHub adds PKCE the change is one flag.

PKCE matters here even with a confidential client because the redirect URI is a public
endpoint: an attacker who intercepts an authorization code cannot exchange it without the
verifier, which never left this service.

**`state`** is stored server-side with a ten minute TTL and spent exactly once, by a
conditional delete. A cookie-based double submit would be the other option and is weaker in
the way that matters: the callback arrives as a top-level cross-site navigation from the
provider, so a `SameSite=Lax` cookie is sent but a `SameSite=Strict` one is not, and the
state cookie therefore has to be readable on exactly the request an attacker would forge.
A server-side row has no such trade-off, and it is the only place a PKCE verifier can live
anyway.

**`nonce`** is Google's, because Google returns an ID token and an ID token replayed from
another session is the attack `nonce` exists to stop. It is generated with the state, stored
on the state row, and compared against the `nonce` claim after signature verification.
GitHub returns no ID token, so it has no nonce.

## How the provider's answer is verified

Google's ID token is a JWT signed by Google, and it is verified properly: the signature
against Google's published JWKS, then `iss`, `aud`, `exp` and `nonce`. Verifying an ID token
by decoding it without checking the signature is the classic OAuth mistake, and it turns the
whole flow into "anybody who can reach the callback is anybody they say they are".

GitHub has no ID token. Its access token is opaque, so identity comes from two authenticated
calls: `GET /user` for the account, and `GET /user/emails` for the addresses, because the
`email` on `/user` is the public profile email, which may be absent, may be unverified, and
is chosen by the user. `/user/emails` is the only source that says `verified` and `primary`,
and the verified-email branch below depends on that distinction being real.

## Auto-link, and the one rule the whole design rests on

Section 3.4 calls the email-match branch the dangerous one, and section 10's threat table
lists "account takeover via OAuth" against exactly it. The locked decision for this
milestone is the strict reading:

> Auto-link an OAuth identity to an existing account **only** when both the provider email
> and the account email are verified. Otherwise, refuse and require the account password:
> the user signs in locally and links from their settings page.

Both halves are load-bearing and they fail in different directions:

- **Provider email unverified**: the provider is asserting an address the user typed and
  nobody checked. Linking on it means registering a GitHub account with somebody else's
  address takes over their account.
- **Local account email unverified**: the local record's address was never proved either, so
  matching a provider-verified address against it proves the provider owns the address and
  says nothing about who owns the account. An attacker who registered locally with a
  victim's address, unverified, would have that account handed the victim's real Google
  identity, which is takeover in the other direction.

When either side is unverified the callback answers `OAUTH_EMAIL_UNVERIFIED` (section 7.3
lists that code) and nothing is written. There is no partial state to clean up: the state row
is already spent, and the user starts again after signing in locally.

**A provider identity with no matching local account is a registration**, which is the
`create_user` hook, exactly as password registration is. `email_verified` is passed through
from the provider, so a Google user who verified with Google does not then have to verify
with the product.

## Unlink refuses to leave an account with no way in

Removing the last sign-in method locks a user out of their own account permanently, and the
account is then unreachable by any support path this design has. So `unlink` counts what
would remain: other OAuth links, a password credential, and passkeys. Only if something
remains does it delete.

The password is a `CredentialStore` lookup, which this module already has. Passkeys are M5's
and are not knowable here, so they arrive through a hook: `has_other_sign_in_method`, added
to `IdentityHooks` with a **default of `False`**, so every existing hooks class keeps
type-checking and keeps working. `False` is the safe default in the one direction that
matters: a product that has not implemented it can only ever be told "no extra methods",
which makes `unlink` refuse more often than strictly necessary, never less. A default of
`True` would let a product that forgot the hook delete its users' last credential.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol
from urllib.parse import urlencode, urlsplit

from webbpulse.dynamodb import now_iso, ttl_in
from webbpulse.identity.storage import constant_time_equals, is_expired

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Mapping

    from webbpulse.dynamodb import Repository
    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.storage import CredentialStore

__all__ = [
    "GITHUB_PROVIDER",
    "GOOGLE_PROVIDER",
    "OAUTH_LINKS_TABLE",
    "OAUTH_LINK_USER_INDEX",
    "OAUTH_STATES_TABLE",
    "OAUTH_STATE_TTL_SECONDS",
    "PROVIDERS",
    "DynamoOAuthLinkStore",
    "DynamoOAuthStateStore",
    "HttpClient",
    "HttpResponse",
    "HttpxClient",
    "InMemoryOAuthLinkStore",
    "InMemoryOAuthStateStore",
    "OAuthAuthorization",
    "OAuthIdentity",
    "OAuthLinkRecord",
    "OAuthLinkStore",
    "OAuthMode",
    "OAuthProviderConfig",
    "OAuthRejected",
    "OAuthService",
    "OAuthStateRecord",
    "OAuthStateStore",
    "provider_account_key",
]

_log = logging.getLogger(__name__)

#: Logical table names, as `webbpulse.dynamodb.table_name` expects them. Hyphenated to match
#: the estate's naming, the same convention `storage.py` follows for its six.
OAUTH_STATES_TABLE: Final = "oauth-states"
OAUTH_LINKS_TABLE: Final = "oauth-links"

#: The GSI on `oauth-links` that answers "every link for this user", which `list` and the
#: last-method count in `unlink` both need.
#:
#: A GSI rather than a second store keyed on `user_id`, and the choice is worth recording.
#: A second table would need both rows written and deleted in step, and DynamoDB gives no
#: transaction across two tables without `TransactWriteItems`, which the `Repository` in this
#: estate does not expose. Two rows that can disagree is exactly the state where a user has
#: an orphaned link that `unlink` cannot find and `list` still shows. The GSI cannot
#: disagree with its base table: DynamoDB maintains it. The price is that it is eventually
#: consistent, which is why every read that must be exact goes to the base table by primary
#: key and the index is used only where a slightly stale list is acceptable. The one place
#: that is **not** acceptable is the last-method count in `unlink`, and that path re-reads
#: the base table for each candidate before counting it. See `OAuthService.unlink`.
OAUTH_LINK_USER_INDEX: Final = "user_id-index"

#: Section 4.3: ten minutes. Long enough for a user to work through a provider's consent
#: screen and an interstitial account chooser, short enough that an abandoned state is not
#: sitting around to be guessed.
OAUTH_STATE_TTL_SECONDS: Final = 600

#: Provider names, matching `IdentitySettings.oauth_providers`.
GOOGLE_PROVIDER: Final = "google"
GITHUB_PROVIDER: Final = "github"

#: What the state row records about why the flow was started. A callback cannot be replayed
#: into the other meaning, which is section 3.4's reason for the field: a `link` callback
#: carries an authenticated user id and a `login` one must never acquire it.
type OAuthMode = Literal["login", "link"]

#: The `amr` value for a login that came from a provider rather than from a password. Not an
#: RFC 8176 registered value, for the same reason `AMR_RECOVERY` is not: RFC 8176 has no
#: value for "federated through a specific provider", and reusing `pwd` would make a policy
#: that asserts on `amr` unable to tell a password login from a Google one.
AMR_OAUTH: Final = "oauth"


class OAuthRejected(Exception):
    """An OAuth start, callback, link or unlink was refused.

    Same shape as `LoginRejected` and `MfaRejected`, so the router renders all three
    identically: a `message` the caller may show and an `error_code` the frontend branches
    on. Section 7.3 lists `OAUTH_EMAIL_UNVERIFIED` as one the frontend must handle by name.
    """

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "OAUTH_FAILED",
        status_code: int = 400,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code


# ---------------------------------------------------------------------------
# The HTTP seam
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """Just enough of a response for this module: the status and the parsed JSON body.

    A structural minimum rather than a wrapper around `httpx.Response`, so a test can build
    one directly and so nothing here depends on a client library's response type.
    """

    status_code: int
    json_body: Any

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class HttpClient(Protocol):
    """The two calls this module makes against a provider.

    A Protocol rather than a class, so `HttpxClient` and a test double satisfy it without
    inheritance, matching how `IdentityHooks` is defined.
    """

    def post_form(
        self, url: str, *, data: Mapping[str, str], headers: Mapping[str, str]
    ) -> HttpResponse:
        """Post an `application/x-www-form-urlencoded` body. The token exchange."""
        ...

    def get_json(self, url: str, *, headers: Mapping[str, str]) -> HttpResponse:
        """Fetch a JSON document. Userinfo, the GitHub emails list, and a JWKS."""
        ...


class HttpxClient:
    """`HttpClient` over `httpx`, built once and reused.

    `httpx` rather than `urllib.request`, which is what `tests/test_identity_contract.py`
    deliberately uses: that file is a read-only probe with no dependencies, and this is a
    request path where connection reuse across a warm Lambda and a real timeout on every
    call are both worth a dependency. The `oauth` extra declares it.

    **A timeout on every call is the point.** `httpx`'s default is five seconds, and this
    sets it explicitly anyway, because a provider that hangs would otherwise hold a Lambda
    execution environment open until the function's own timeout and turn a provider incident
    into an availability incident here.

    Constructed lazily, so importing this module needs no `httpx` and a product that mounts
    no OAuth routes does not install the extra.
    """

    def __init__(self, *, timeout: float = 10.0, client: Any = None) -> None:
        self._timeout = timeout
        self._client = client

    def _require(self) -> Any:
        if self._client is None:
            import httpx

            self._client = httpx.Client(timeout=self._timeout, follow_redirects=False)
        return self._client

    def post_form(
        self, url: str, *, data: Mapping[str, str], headers: Mapping[str, str]
    ) -> HttpResponse:
        response = self._require().post(url, data=dict(data), headers=dict(headers))
        return _response_from(response)

    def get_json(self, url: str, *, headers: Mapping[str, str]) -> HttpResponse:
        response = self._require().get(url, headers=dict(headers))
        return _response_from(response)


def _response_from(response: Any) -> HttpResponse:
    """Read a client library's response into this module's own shape.

    A body that is not JSON becomes `None` rather than raising: a provider answering an
    error page instead of a JSON error is a real condition, and the caller turns a missing
    field into an `OAuthRejected` with a message that does not quote the provider's HTML.
    """
    try:
        body = response.json()
    except Exception:
        body = None
    return HttpResponse(status_code=int(response.status_code), json_body=body)


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OAuthProviderConfig:
    """Everything that differs between one provider and the next, in one place.

    A table rather than an `if provider == "google"` at each step. The flow is genuinely the
    same for both; what differs is four URLs, a scope string and three booleans, and keeping
    them here means adding a third provider is a new entry rather than a new branch in five
    functions.
    """

    name: str
    authorize_url: str
    token_url: str
    #: Where a `sub` and an email come from when there is no ID token. Empty for a provider
    #: whose ID token carries both.
    userinfo_url: str = ""
    #: GitHub's separate verified-addresses endpoint. Empty for a provider without one.
    emails_url: str = ""
    #: The JWKS an ID token's signature is checked against. Empty for a provider that
    #: returns no ID token.
    jwks_url: str = ""
    #: The `iss` an ID token must carry. Google publishes two spellings and accepts either.
    id_token_issuers: tuple[str, ...] = ()
    scope: str = ""
    #: Whether the provider honours PKCE. See the module docstring: sending a challenge to a
    #: provider that ignores it proves nothing on the exchange.
    supports_pkce: bool = False
    #: Whether the provider returns an OIDC ID token, and therefore takes a `nonce`.
    returns_id_token: bool = False
    #: Extra fixed parameters on the authorization URL.
    extra_authorize_params: Mapping[str, str] = field(default_factory=dict)


#: Google's endpoints are the ones its discovery document publishes. They are hardcoded
#: rather than fetched from `https://accounts.google.com/.well-known/openid-configuration`
#: at request time, deliberately: a discovery fetch on the login path adds a round trip to
#: every sign-in and a third party outage to a flow that would otherwise still work from
#: cache, and these four URLs have been stable for a decade. A rotation of Google's *keys* is
#: handled, because the JWKS itself is fetched per verification.
PROVIDERS: Final[Mapping[str, OAuthProviderConfig]] = {
    GOOGLE_PROVIDER: OAuthProviderConfig(
        name=GOOGLE_PROVIDER,
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        jwks_url="https://www.googleapis.com/oauth2/v3/certs",
        id_token_issuers=("https://accounts.google.com", "accounts.google.com"),
        scope="openid email profile",
        supports_pkce=True,
        returns_id_token=True,
        # `select_account` so a shared machine does not silently sign in whoever the browser
        # last authenticated, which is a real account-mixing hazard rather than a nicety.
        extra_authorize_params={"prompt": "select_account"},
    ),
    GITHUB_PROVIDER: OAuthProviderConfig(
        name=GITHUB_PROVIDER,
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        userinfo_url="https://api.github.com/user",
        emails_url="https://api.github.com/user/emails",
        # `user:email` rather than `user`: the flow needs the addresses and nothing else, and
        # the broader scope would grant profile write access this design never uses.
        scope="read:user user:email",
        supports_pkce=False,
        returns_id_token=False,
    ),
}


def provider_account_key(provider: str, subject: str) -> str:
    """The `oauth-links` partition key: `"<provider>#<subject>"`.

    Section 4.2 fixes this spelling, and CarModPicker's existing `oauth_accounts` rows carry
    the same one, so a migration is a copy rather than a transform.

    The provider is part of the key because a subject is only unique within its provider:
    Google and GitHub both hand out small numeric ids, and a bare subject would let a GitHub
    account collide with a Google one and inherit its user.
    """
    return f"{provider}#{subject}"


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class OAuthStateRecord:
    """One in-flight authorization, written before the redirect and spent by the callback.

    Holds the PKCE verifier, which is the one value that must never reach the browser, and
    the `nonce` the ID token is checked against. `mode` and `user_id` together are what stop
    a login callback being replayed as a link: a `login` row carries no user id, so there is
    no account for a replay to attach to.

    `return_to` is where the frontend is sent afterwards. It is validated against the
    redirect allow-list **when it is stored**, not when it is used, so a rejected value never
    reaches the table and a stored row is safe to redirect to without re-checking.
    """

    state: str
    provider: str
    mode: OAuthMode
    created_at: str
    expires_at: int
    pkce_verifier: str = ""
    nonce: str = ""
    return_to: str = ""
    #: The authenticated subject that started a `link`. Empty for a `login`.
    user_id: str = ""
    #: The exact `redirect_uri` sent to the provider. Stored because the token exchange must
    #: send back a byte-identical value or the provider refuses it, and because a service
    #: behind more than one host would otherwise recompute a different one on the callback.
    redirect_uri: str = ""


@dataclass(frozen=True, slots=True)
class OAuthLinkRecord:
    """One provider identity attached to one local user.

    The field names match CarModPicker's `oauth_accounts` rows so that migrating is a copy
    with a renamed key attribute rather than a transform, and section 4.2's `oauth_links`
    adds `provider_email`, `provider_email_verified` and `linked_at` to that shape.

    **No provider tokens are stored.** Neither the access token nor the refresh token from
    the provider is written down: this design consumes a provider as an identity source, and
    it never calls a provider API on the user's behalf afterwards. Storing a token nobody
    spends is a stored credential with no use, which is all cost.
    """

    provider_subject: str
    provider: str
    subject: str
    user_id: str
    linked_at: str
    provider_email: str = ""
    provider_email_verified: bool = False
    last_login_at: str = ""


@dataclass(frozen=True, slots=True)
class OAuthIdentity:
    """What a provider said about the person who just authenticated.

    Normalised across the two providers, so the linking rules read the same for both.
    `email_verified` is the field the whole auto-link decision turns on, and it is `False`
    unless the provider positively asserted otherwise.
    """

    provider: str
    subject: str
    email: str
    email_verified: bool
    name: str = ""

    @property
    def account_key(self) -> str:
        return provider_account_key(self.provider, self.subject)


@dataclass(frozen=True, slots=True)
class OAuthAuthorization:
    """The redirect a `start` produces: where to send the browser, and the state it spent."""

    authorization_url: str
    state: str


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


class OAuthStateStore(ABC):
    """The `oauth-states` table: hash `state`, TTL `expires_at`, ten minutes.

    Single use is enforced by `consume`, which must be one conditional operation. A `get`
    followed by a `delete` would let two callbacks carrying the same state both pass the
    read before either deleted, which is precisely the replay the state exists to stop.
    """

    @abstractmethod
    def put(self, record: OAuthStateRecord) -> None:
        """Write a fresh state. Called once, immediately before the redirect."""

    @abstractmethod
    def consume(self, state: str) -> OAuthStateRecord | None:
        """Atomically spend a state and return it, or `None` if unknown or expired.

        Expiry is checked here as well as by the table's TTL, for the reason every store in
        this package checks it: DynamoDB deletes on its own schedule and an expired row is
        readable for days. TTL is storage reclamation and never an access control.
        """


class OAuthLinkStore(ABC):
    """The `oauth-links` table: hash `provider_subject`, GSI `user_id-index`, no TTL ever.

    Never a TTL. A link is a sign-in method, and a sign-in method that expires on a schedule
    locks a user out of an account they can still see, which is the same rule the M4 tables
    follow and for the sharper version of the same reason.
    """

    @abstractmethod
    def get(self, provider_subject: str) -> OAuthLinkRecord | None:
        """The link for a `"<provider>#<subject>"` key, or `None`.

        On the login path this must be a strongly consistent read of the base table: a user
        who just linked and immediately signs in must not be told their identity is unknown.
        """

    @abstractmethod
    def put(self, record: OAuthLinkRecord) -> None:
        """Write or replace a link."""

    @abstractmethod
    def list_for_user(self, user_id: str) -> list[OAuthLinkRecord]:
        """Every link for a user. Backed by the GSI, so it may be slightly stale."""

    @abstractmethod
    def delete(self, provider_subject: str) -> None:
        """Remove a link. Idempotent: removing an absent one is not an error."""

    @abstractmethod
    def claim(self, record: OAuthLinkRecord) -> bool:
        """Write a link only if that provider identity is not already attached to somebody.

        Conditional, and the condition is the security control rather than a nicety. Two
        concurrent callbacks for the same provider identity must not both succeed, and only
        the database can settle that; a read-then-write would let the second overwrite the
        first and silently move a provider identity from one local account to another.

        Returns `False` when the key already exists, which the caller reads as "already
        linked" and answers without saying whose account it is attached to.
        """


class InMemoryOAuthStateStore(OAuthStateStore):
    """Dict-backed `OAuthStateStore`, with the same single-use and expiry semantics."""

    def __init__(self) -> None:
        self._items: dict[str, OAuthStateRecord] = {}

    def put(self, record: OAuthStateRecord) -> None:
        self._items[record.state] = record

    def consume(self, state: str) -> OAuthStateRecord | None:
        record = self._items.pop(state, None)
        if record is None or is_expired(record.expires_at):
            return None
        return record


class InMemoryOAuthLinkStore(OAuthLinkStore):
    """Dict-backed `OAuthLinkStore`, keyed as the table is."""

    def __init__(self) -> None:
        self._items: dict[str, OAuthLinkRecord] = {}

    def get(self, provider_subject: str) -> OAuthLinkRecord | None:
        return self._items.get(provider_subject)

    def put(self, record: OAuthLinkRecord) -> None:
        self._items[record.provider_subject] = record

    def list_for_user(self, user_id: str) -> list[OAuthLinkRecord]:
        return [record for record in self._items.values() if record.user_id == user_id]

    def delete(self, provider_subject: str) -> None:
        self._items.pop(provider_subject, None)

    def claim(self, record: OAuthLinkRecord) -> bool:
        if record.provider_subject in self._items:
            return False
        self._items[record.provider_subject] = record
        return True


class DynamoOAuthStateStore(OAuthStateStore):
    """`OAuthStateStore` over a `webbpulse.dynamodb.Repository`.

    Takes the repository rather than building one, exactly as every other Dynamo store in
    this package does, so the caller owns the table name, the prefix and the region.
    """

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def put(self, record: OAuthStateRecord) -> None:
        self._repo.put(
            {
                "state": record.state,
                "provider": record.provider,
                "mode": record.mode,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
                "pkce_verifier": record.pkce_verifier,
                "nonce": record.nonce,
                "return_to": record.return_to,
                "user_id": record.user_id,
                "redirect_uri": record.redirect_uri,
            }
        )

    def consume(self, state: str) -> OAuthStateRecord | None:
        """Spend the row with a conditional delete that returns what it deleted.

        `ReturnValues=ALL_OLD` on a `DeleteItem` is what makes this one operation rather
        than two: the row is gone and its contents are in the response, so a second callback
        carrying the same state finds nothing. Doing it as `get` then `delete` would let two
        concurrent callbacks both read the verifier before either delete landed.
        """
        from botocore.exceptions import ClientError

        try:
            response = self._repo.table.delete_item(
                Key={"state": state},
                ConditionExpression="attribute_exists(#s)",
                ExpressionAttributeNames={"#s": "state"},
                ReturnValues="ALL_OLD",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return None
            raise
        item = response.get("Attributes")
        if not item:
            return None
        record = _state_from_item(item)
        # Expired rows are deleted above and then refused here. Deleting an expired state is
        # correct either way: it was single use and it is now spent.
        return None if is_expired(record.expires_at) else record


class DynamoOAuthLinkStore(OAuthLinkStore):
    """`OAuthLinkStore` over a `webbpulse.dynamodb.Repository`, with the `user_id-index` GSI."""

    def __init__(self, repository: Repository) -> None:
        self._repo = repository

    def get(self, provider_subject: str) -> OAuthLinkRecord | None:
        # Consistent, because this read decides whether a sign-in succeeds and an eventually
        # consistent miss reads as "we do not know you" to somebody who linked a moment ago.
        item = self._repo.get({"provider_subject": provider_subject}, consistent=True)
        return _link_from_item(item) if item is not None else None

    def put(self, record: OAuthLinkRecord) -> None:
        self._repo.put(_link_to_item(record))

    def list_for_user(self, user_id: str) -> list[OAuthLinkRecord]:
        from boto3.dynamodb.conditions import Key as KeyCondition

        # No `consistent=True`: a GSI cannot be read consistently at all, which is the one
        # real cost of choosing an index over a second table. Callers that need an exact
        # answer re-read the base table per key. See `OAuthService.unlink`.
        return [
            _link_from_item(item)
            for item in self._repo.iter_query(
                KeyCondition("user_id").eq(user_id), index_name=OAUTH_LINK_USER_INDEX
            )
        ]

    def delete(self, provider_subject: str) -> None:
        self._repo.delete({"provider_subject": provider_subject})

    def claim(self, record: OAuthLinkRecord) -> bool:
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        try:
            self._repo.put(
                _link_to_item(record),
                condition=Attr("provider_subject").not_exists(),
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise
        return True


def _link_to_item(record: OAuthLinkRecord) -> dict[str, Any]:
    return {
        "provider_subject": record.provider_subject,
        "provider": record.provider,
        "subject": record.subject,
        "user_id": record.user_id,
        "linked_at": record.linked_at,
        "provider_email": record.provider_email,
        "provider_email_verified": record.provider_email_verified,
        "last_login_at": record.last_login_at,
    }


def _state_from_item(item: Mapping[str, Any]) -> OAuthStateRecord:
    """Read a state row defensively, as every mapper in this package does.

    A row written by an older version of this module during a rolling deploy is a normal
    condition rather than a corrupt one, and a `KeyError` on a field added last release would
    turn that into a 500 on the callback path.
    """
    mode = str(item.get("mode", "login"))
    return OAuthStateRecord(
        state=str(item["state"]),
        provider=str(item.get("provider", "")),
        mode="link" if mode == "link" else "login",
        created_at=str(item.get("created_at", "")),
        expires_at=int(item.get("expires_at", 0)),
        pkce_verifier=str(item.get("pkce_verifier", "")),
        nonce=str(item.get("nonce", "")),
        return_to=str(item.get("return_to", "")),
        user_id=str(item.get("user_id", "")),
        redirect_uri=str(item.get("redirect_uri", "")),
    )


def _link_from_item(item: Mapping[str, Any]) -> OAuthLinkRecord:
    return OAuthLinkRecord(
        provider_subject=str(item["provider_subject"]),
        provider=str(item.get("provider", "")),
        subject=str(item.get("subject", "")),
        user_id=str(item.get("user_id", "")),
        linked_at=str(item.get("linked_at", "")),
        provider_email=str(item.get("provider_email", "")),
        provider_email_verified=bool(item.get("provider_email_verified", False)),
        last_login_at=str(item.get("last_login_at", "")),
    )


# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    """base64url with no padding, which is what RFC 7636 and JWS both want."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def new_pkce_verifier() -> str:
    """A fresh RFC 7636 code verifier: 43 to 128 characters from the unreserved set.

    32 bytes base64url-encoded is 43 characters, which is the RFC's minimum length and
    carries 256 bits. Longer buys nothing: the verifier is compared for equality, not
    searched, so entropy beyond the point of unguessability is only bytes on the wire.
    """
    return _b64url(secrets.token_bytes(32))


def pkce_challenge(verifier: str) -> str:
    """The `S256` challenge for a verifier: base64url of its SHA-256.

    `S256` and never `plain`. RFC 7636 permits `plain`, where the challenge *is* the
    verifier, which protects against nothing at all if the authorization request can be
    observed, and observing it is the threat the whole mechanism exists for.
    """
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------


class OAuthService:
    """Provider start, callback, link, list and unlink, with no FastAPI in sight.

    Built once per execution environment from settings, hooks and the two stores, and holds
    no request state. `oauth_routes.register_oauth_routes` is the only caller in this
    package; a product may call it directly.

    `client_secrets` is a mapping from provider name to that provider's client secret,
    supplied by the composition root from `webbpulse.config.load_json_secret` under the keys
    section 5.8 names, `google_client_secret` and `github_client_secret`. It is **not** a
    settings field, for the reason `IdentitySettings` gives in its own docstring: a secret
    that is a settings field is a secret that ends up in a `repr`, a validation error and a
    log line. Nothing in this module logs the value, and every code path that fails with a
    wrong secret reports the provider's status code rather than what was sent.
    """

    def __init__(
        self,
        settings: IdentitySettings,
        hooks: IdentityHooks,
        *,
        states: OAuthStateStore,
        links: OAuthLinkStore,
        credentials: CredentialStore | None = None,
        client_secrets: Mapping[str, str] | None = None,
        http_client: HttpClient | None = None,
    ) -> None:
        self._settings = settings
        self._hooks = hooks
        self._states = states
        self._links = links
        self._credentials = credentials
        self._secrets = dict(client_secrets or {})
        self._http = http_client if http_client is not None else HttpxClient()

    # ---- provider and configuration -------------------------------------------------

    def enabled_providers(self) -> list[str]:
        """The providers this product has both switched on and given a client id.

        Both halves matter. A provider listed in `oauth_providers` with an empty client id
        is a misconfiguration whose symptom is a redirect to a provider error page, and it
        is better for the route not to exist than for it to hand the user to Google with no
        `client_id`.
        """
        return [name for name in self._settings.oauth_providers if self._client_id(name)]

    def _provider(self, provider: str) -> OAuthProviderConfig:
        config = PROVIDERS.get(provider)
        if config is None or provider not in self.enabled_providers():
            raise OAuthRejected(
                "That sign-in provider is not available.",
                error_code="OAUTH_PROVIDER_UNKNOWN",
                status_code=404,
            )
        return config

    def _client_id(self, provider: str) -> str:
        if provider == GOOGLE_PROVIDER:
            return self._settings.google_client_id
        if provider == GITHUB_PROVIDER:
            return self._settings.github_client_id
        return ""

    def _client_secret(self, provider: str) -> str:
        secret = self._secrets.get(provider, "")
        if not secret:
            # Deliberately not "the google_client_secret key is missing from the app secret",
            # which is a true sentence that also tells an anonymous caller how this service
            # is configured. The operator gets the detail in the log line below.
            _log.error(
                "No OAuth client secret configured.",
                extra={"event": "oauth.misconfigured", "provider": provider},
            )
            raise OAuthRejected(
                "That sign-in provider is not available.",
                error_code="OAUTH_PROVIDER_UNAVAILABLE",
                status_code=503,
            )
        return secret

    # ---- start ----------------------------------------------------------------------

    def start(
        self,
        provider: str,
        *,
        mode: OAuthMode = "login",
        user_id: str = "",
        return_to: str = "",
        redirect_uri: str = "",
    ) -> OAuthAuthorization:
        """Mint a state, write it, and build the URL the browser is redirected to.

        The row is written **before** the URL is returned, for the reason
        `MfaService.issue_challenge` writes its row first: a state the table does not know
        cannot be spent, so a failed write is a sign-in the user retries rather than a
        callback that arrives with nothing to check it against.

        `redirect_uri` is checked against the allow-list here. An unvalidated redirect URI is
        the open-redirect half of an OAuth flow, and checking it at the point it enters the
        table means the callback can use the stored value without re-deriving trust.
        """
        config = self._provider(provider)
        if mode == "link" and not user_id:
            raise OAuthRejected("Sign in first.", error_code="NOT_AUTHENTICATED", status_code=401)

        resolved_redirect = self._resolve_redirect_uri(redirect_uri)
        resolved_return = self._resolve_return_to(return_to)

        state = _b64url(secrets.token_bytes(32))
        verifier = new_pkce_verifier() if config.supports_pkce else ""
        nonce = _b64url(secrets.token_bytes(16)) if config.returns_id_token else ""

        self._states.put(
            OAuthStateRecord(
                state=state,
                provider=provider,
                mode=mode,
                created_at=now_iso(),
                expires_at=ttl_in(OAUTH_STATE_TTL_SECONDS),
                pkce_verifier=verifier,
                nonce=nonce,
                return_to=resolved_return,
                user_id=user_id if mode == "link" else "",
                redirect_uri=resolved_redirect,
            )
        )

        params: dict[str, str] = {
            "client_id": self._client_id(provider),
            "redirect_uri": resolved_redirect,
            "response_type": "code",
            "scope": config.scope,
            "state": state,
            **dict(config.extra_authorize_params),
        }
        if verifier:
            params["code_challenge"] = pkce_challenge(verifier)
            params["code_challenge_method"] = "S256"
        if nonce:
            params["nonce"] = nonce

        _log.info(
            "OAuth authorization started.",
            extra={"event": "oauth.start", "provider": provider, "mode": mode},
        )
        return OAuthAuthorization(
            authorization_url=f"{config.authorize_url}?{urlencode(params)}",
            state=state,
        )

    def _resolve_redirect_uri(self, requested: str) -> str:
        """The redirect URI to send, checked against the allow-list.

        Empty means "the default", which is the issuer plus the callback path, and that is
        the ordinary case: a product with one host never configures a list at all. A
        non-empty value must appear in `oauth_redirect_uris` **exactly**, string equality and
        not a prefix match, because a prefix match on `https://app.example.com` also admits
        `https://app.example.com.attacker.test`.
        """
        default = f"{self._settings.issuer}/oauth/callback"
        allowed = list(self._settings.oauth_redirect_uris)
        if not requested:
            return allowed[0] if allowed else default
        if requested in allowed or (not allowed and requested == default):
            return requested
        raise OAuthRejected(
            "That redirect URI is not allowed.",
            error_code="OAUTH_REDIRECT_NOT_ALLOWED",
            status_code=400,
        )

    def _resolve_return_to(self, requested: str) -> str:
        """Where the frontend is sent after the callback, constrained to the frontend.

        A `return_to` echoed back into a `Location` header with no check is an open redirect
        that a phishing page reaches through this product's own domain, which is worth more
        to an attacker than a domain they own. Two forms are accepted: a path, which is
        resolved against `frontend_base_url`, and an absolute URL that is exactly under
        `frontend_base_url`'s origin. Anything else falls back to the frontend root rather
        than raising, because a bad `return_to` is a broken link and not an attack the user
        should be shown an error for.
        """
        base = self._settings.frontend_base_url
        if not requested:
            return base
        if requested.startswith("/") and not requested.startswith("//"):
            # `//host` is a scheme-relative URL and is a redirect off-site, so it is refused
            # here alongside anything absolute that is not ours.
            return f"{base}{requested}"
        if base:
            base_parts = urlsplit(base)
            parts = urlsplit(requested)
            if (parts.scheme, parts.netloc) == (base_parts.scheme, base_parts.netloc):
                return requested
        return base

    # ---- callback -------------------------------------------------------------------

    def consume_state(self, state: str, *, provider: str = "") -> OAuthStateRecord:
        """Spend a state exactly once, and return what it recorded.

        The row is the authority on which provider the flow belongs to, which is why
        `provider` is optional. The single shared callback route has no provider in its path
        to pass, and that is the safer arrangement rather than a gap: the provider then comes
        from a server-side, single-use row instead of from a path segment the caller writes.

        A caller that *does* know the provider, such as a per-provider callback a product
        mounts itself, passes it and gets the equality check. It is a constant-time
        comparison for consistency with every other comparison in this package, though the
        entropy here is in the state itself, which the store has already spent.

        Every failure answers identically. Whether a state was unknown, expired, already
        spent or belonged to a different provider is information about somebody else's
        sign-in attempt, and distinguishing them would confirm to anyone guessing values that
        a guess had found a real row.
        """
        if not state:
            raise OAuthRejected(
                "That sign-in attempt is no longer valid. Start again.",
                error_code="OAUTH_STATE_INVALID",
            )
        record = self._states.consume(state)
        if record is None:
            raise OAuthRejected(
                "That sign-in attempt is no longer valid. Start again.",
                error_code="OAUTH_STATE_INVALID",
            )
        if provider and not constant_time_equals(record.provider, provider):
            raise OAuthRejected(
                "That sign-in attempt is no longer valid. Start again.",
                error_code="OAUTH_STATE_INVALID",
            )
        return record

    def identity_from_callback(
        self, provider: str, *, code: str, state_record: OAuthStateRecord
    ) -> OAuthIdentity:
        """Exchange the code and turn the provider's answer into an `OAuthIdentity`.

        One method rather than two because the two providers diverge at exactly this point
        and a caller should not have to know which branch it is on: Google's identity comes
        out of a verified ID token in the token response, and GitHub's comes from two
        authenticated calls made with the access token.
        """
        config = self._provider(provider)
        token_body = self._token_body(provider, code=code, state_record=state_record)

        if config.returns_id_token:
            id_token = _require_str(token_body, "id_token", provider)
            return self._identity_from_id_token(config, id_token, nonce=state_record.nonce)

        access_token = _require_str(token_body, "access_token", provider)
        return self._identity_from_userinfo(config, access_token)

    def _token_body(
        self, provider: str, *, code: str, state_record: OAuthStateRecord
    ) -> Mapping[str, Any]:
        """Trade the authorization code for the provider's token response.

        Returns the whole body rather than just the access token, because Google's
        `id_token` arrives in the same response and splitting the two would mean either two
        return values or a second round trip for something already in hand.
        """
        config = self._provider(provider)
        if not code:
            raise OAuthRejected(
                "The sign-in provider returned no authorization code.",
                error_code="OAUTH_CODE_MISSING",
            )
        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self._client_id(provider),
            "client_secret": self._client_secret(provider),
            "redirect_uri": state_record.redirect_uri,
        }
        if state_record.pkce_verifier:
            data["code_verifier"] = state_record.pkce_verifier

        response = self._http.post_form(
            config.token_url, data=data, headers={"Accept": "application/json"}
        )
        body = response.json_body if isinstance(response.json_body, dict) else {}
        if not response.ok or body.get("error"):
            _log.warning(
                "OAuth token exchange failed.",
                extra={
                    "event": "oauth.exchange_failed",
                    "provider": provider,
                    "status": response.status_code,
                    "error": str(body.get("error", ""))[:64],
                },
            )
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_EXCHANGE_FAILED",
            )
        return body

    def _signing_key_for(self, config: OAuthProviderConfig, id_token: str) -> Any:
        """Find the provider's public key for this token, fetching the JWKS ourselves.

        `PyJWKClient` would do this in one line, but it fetches with `urllib.request` and no
        timeout, which is the one thing `HttpxClient` exists to prevent: a provider that
        accepts the connection and never answers would hold a Lambda execution environment
        open until the function times out. Going through `self._http` puts the JWKS fetch
        under the same timeout as the token exchange and the userinfo call, and puts it on
        the same seam a test can mock.

        The set is fetched per verification rather than cached. A cache would need an
        invalidation path for the key rotation it exists to survive, and one extra HTTPS
        call on a flow that already makes two is not where this endpoint's latency is.
        """
        import jwt

        header = jwt.get_unverified_header(id_token)
        kid = str(header.get("kid", ""))

        response = self._http.get_json(config.jwks_url, headers={"accept": "application/json"})
        if not response.ok or not isinstance(response.json_body, dict):
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_ID_TOKEN_INVALID",
            )

        keys = response.json_body.get("keys")
        if not isinstance(keys, list):
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_ID_TOKEN_INVALID",
            )

        for entry in keys:
            if isinstance(entry, dict) and str(entry.get("kid", "")) == kid:
                return jwt.PyJWK.from_dict(dict(entry)).key

        # No matching `kid`. Refusing rather than trying every key: a token whose header
        # names a key the provider does not publish is not a token the provider signed.
        raise OAuthRejected(
            "That sign-in could not be completed. Try again.",
            error_code="OAUTH_ID_TOKEN_INVALID",
        )

    def _identity_from_id_token(
        self, config: OAuthProviderConfig, id_token: str, *, nonce: str
    ) -> OAuthIdentity:
        """Verify an OIDC ID token properly, then read the identity out of its claims.

        Properly means: the signature against the provider's published JWKS, then `iss`
        against the provider's own issuers, `aud` against this product's client id, `exp`
        against the clock, and `nonce` against the one this flow generated. Skipping any of
        them turns the ID token into an unauthenticated assertion, and skipping the
        signature turns it into one an attacker writes.
        """
        import jwt

        audience = self._client_id(config.name)
        try:
            signing_key = self._signing_key_for(config, id_token)
            claims = jwt.decode(
                id_token,
                signing_key,
                algorithms=["RS256"],
                audience=audience,
                issuer=list(config.id_token_issuers),
                leeway=self._settings.clock_skew_leeway,
                options={"require": ["exp", "iat", "sub", "aud", "iss"]},
            )
        except Exception as exc:
            _log.warning(
                "OAuth ID token verification failed.",
                extra={
                    "event": "oauth.id_token_invalid",
                    "provider": config.name,
                    "reason": type(exc).__name__,
                },
            )
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_ID_TOKEN_INVALID",
            ) from exc

        # The nonce is checked after the signature, never before: comparing a claim from an
        # unverified token is comparing whatever the caller wrote.
        presented = str(claims.get("nonce", ""))
        if nonce and not constant_time_equals(presented, nonce):
            _log.warning(
                "OAuth ID token nonce mismatch.",
                extra={"event": "oauth.nonce_mismatch", "provider": config.name},
            )
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_NONCE_MISMATCH",
            )

        return OAuthIdentity(
            provider=config.name,
            subject=str(claims.get("sub", "")),
            email=str(claims.get("email", "")).strip().lower(),
            # Google spells it as a real boolean in the ID token, and a string in some older
            # responses. `is True` would refuse the string form and `bool()` would accept the
            # string "false", so both spellings are handled explicitly.
            email_verified=_as_bool(claims.get("email_verified")),
            name=str(claims.get("name", "")),
        )

    def _identity_from_userinfo(
        self, config: OAuthProviderConfig, access_token: str
    ) -> OAuthIdentity:
        """GitHub's identity: the account from `/user`, the verified address from `/user/emails`.

        The two calls are both needed. `/user` gives the immutable numeric `id`, which is the
        subject, and its `email` field is the **public profile** address: user-chosen, often
        absent, and never marked verified. `/user/emails` is the only endpoint that says
        which address GitHub has confirmed, and the auto-link rule depends on that being a
        real assertion rather than a field a user typed.
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        profile = self._http.get_json(config.userinfo_url, headers=headers)
        if not profile.ok or not isinstance(profile.json_body, dict):
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_USERINFO_FAILED",
            )
        body = profile.json_body
        subject = str(body.get("id", ""))
        if not subject:
            raise OAuthRejected(
                "That sign-in could not be completed. Try again.",
                error_code="OAUTH_USERINFO_FAILED",
            )

        email, verified = self._github_primary_email(config, headers)
        return OAuthIdentity(
            provider=config.name,
            subject=subject,
            email=email,
            email_verified=verified,
            name=str(body.get("name", "") or body.get("login", "")),
        )

    def _github_primary_email(
        self, config: OAuthProviderConfig, headers: Mapping[str, str]
    ) -> tuple[str, bool]:
        """The verified primary address, or the best available with `verified` false.

        Preference order: the verified primary, then any verified address, then the primary
        whatever its state. The last case returns `verified=False`, which the linking rules
        then refuse to auto-link on, so an unverified address is still usable for a fresh
        registration and never for attaching to an existing account.

        A failed call is not fatal. A GitHub account with no usable address is a registration
        this product refuses, not a 500, and it is refused by the caller finding no email.
        """
        response = self._http.get_json(config.emails_url, headers=headers)
        entries = response.json_body if response.ok else None
        if not isinstance(entries, list):
            return "", False

        primary_unverified = ""
        first_verified = ""
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            address = str(entry.get("email", "")).strip().lower()
            if not address:
                continue
            verified = _as_bool(entry.get("verified"))
            primary = _as_bool(entry.get("primary"))
            if verified and primary:
                return address, True
            if verified and not first_verified:
                first_verified = address
            if primary and not primary_unverified:
                primary_unverified = address
        if first_verified:
            return first_verified, True
        return primary_unverified, False

    # ---- linking rules --------------------------------------------------------------

    def resolve_login(self, identity: OAuthIdentity) -> tuple[Mapping[str, Any], str]:
        """Turn a provider identity into a local user, per section 3.4's three branches.

        Returns the user and how it was reached: `"linked"` for an existing link,
        `"auto_linked"` for the verified-email attach, `"registered"` for a new account.

        The branches, in the order they are tried:

        1. **A link already exists.** The ordinary case. The link's `user_id` is the account,
           and nothing about the email is consulted at all: the provider identity was
           attached deliberately at some earlier point and an address changing at the
           provider does not move an account.
        2. **No link, and the email matches a local account.** This is the dangerous branch.
           It attaches only when **both** the provider email and the local account's email
           are verified, per the locked decision in the module docstring. Otherwise it
           refuses with `OAUTH_EMAIL_UNVERIFIED` and the user is told to sign in and link.
        3. **No link and no match.** A registration through `create_user`, with
           `email_verified` carried across from the provider.
        """
        existing = self._links.get(identity.account_key)
        if existing is not None:
            user = self._hooks.load_user_by_id(existing.user_id)
            if user is None:
                # The link outlived the user, which a deletion that missed this table
                # produces. Refusing and cleaning up is right: signing somebody in to an
                # account that no longer exists is worse than asking them to start again.
                self._links.delete(identity.account_key)
                raise OAuthRejected(
                    "That account is no longer available.",
                    error_code="OAUTH_ACCOUNT_MISSING",
                    status_code=401,
                )
            self._touch(existing, identity)
            return user, "linked"

        if not identity.email:
            raise OAuthRejected(
                "That sign-in provider did not share an email address. Add one to your "
                "provider account, or sign in with a password.",
                error_code="OAUTH_EMAIL_MISSING",
            )

        matched = self._hooks.load_user_by_email(identity.email)
        if matched is not None:
            self._require_auto_link_allowed(identity, matched)
            record = self._new_link(identity, _user_id(matched))
            if not self._links.claim(record):
                # Another callback attached this identity between the `get` above and here.
                # Refusing is correct: the winner may have attached it to a different
                # account, and overwriting would silently move a provider identity.
                raise OAuthRejected(
                    "That provider account is already linked.",
                    error_code="OAUTH_ALREADY_LINKED",
                    status_code=409,
                )
            _log.info(
                "OAuth identity auto-linked on a verified email.",
                extra={
                    "event": "oauth.linked",
                    "provider": identity.provider,
                    "user_id": _user_id(matched),
                    "auto": True,
                },
            )
            return matched, "auto_linked"

        return self._register(identity), "registered"

    def _require_auto_link_allowed(self, identity: OAuthIdentity, user: Mapping[str, Any]) -> None:
        """Both sides verified, or nothing is attached. See the module docstring.

        The two failures deliberately answer with the same code and the same message. Telling
        a caller *which* side was unverified tells them whether an account exists for that
        address and whether it has confirmed its email, which is exactly the enumeration
        section 5.4 closes on every other route.
        """
        local_verified = bool(user.get("email_verified", False))
        if identity.email_verified and local_verified:
            return
        _log.warning(
            "OAuth auto-link refused: an unverified email on one side.",
            extra={
                "event": "oauth.autolink_refused",
                "provider": identity.provider,
                "provider_verified": identity.email_verified,
                "local_verified": local_verified,
            },
        )
        raise OAuthRejected(
            "An account already exists for that email address. Sign in with your password "
            "first, then link this provider from your account settings.",
            error_code="OAUTH_EMAIL_UNVERIFIED",
            status_code=409,
        )

    def _register(self, identity: OAuthIdentity) -> Mapping[str, Any]:
        """Create a local account for a provider identity nobody has seen before.

        `create_user` is the same hook password registration uses, so a product's own
        username rules, required columns and defaults apply identically however an account
        came to exist. `email_verified` is passed through from the provider rather than being
        forced true: a GitHub user whose address is unverified gets an unverified local
        account and the ordinary verification flow, which is the same position a password
        registration starts from.
        """
        if not self._settings.registration_enabled:
            raise OAuthRejected(
                "This service is not accepting new accounts.",
                error_code="REGISTRATION_DISABLED",
                status_code=403,
            )
        user = self._hooks.create_user(
            email=identity.email,
            attributes={
                "email_verified": identity.email_verified,
                "name": identity.name,
            },
        )
        user_id = _user_id(user)
        record = self._new_link(identity, user_id)
        if not self._links.claim(record):
            raise OAuthRejected(
                "That provider account is already linked.",
                error_code="OAUTH_ALREADY_LINKED",
                status_code=409,
            )
        self._hooks.on_user_created(user, identity.provider)
        _log.info(
            "OAuth registration created an account.",
            extra={
                "event": "oauth.linked",
                "provider": identity.provider,
                "user_id": user_id,
                "registered": True,
            },
        )
        return user

    def link(self, identity: OAuthIdentity, *, user_id: str) -> OAuthLinkRecord:
        """Attach a provider identity to the authenticated account that asked for it.

        This is the path the refused auto-link sends people to, and it needs no email check
        at all: the user proved they hold this account by presenting a token for it, and they
        proved they hold the provider account by completing the provider's own flow. The
        email is recorded, not consulted.

        Refuses when the identity is already attached, to this account or another, and says
        the same thing either way. "You have already linked this" and "somebody else has"
        are the same sentence on purpose: the second would confirm that a given provider
        account has a local account here.
        """
        existing = self._links.get(identity.account_key)
        if existing is not None:
            raise OAuthRejected(
                "That provider account is already linked.",
                error_code="OAUTH_ALREADY_LINKED",
                status_code=409,
            )
        record = self._new_link(identity, user_id)
        if not self._links.claim(record):
            raise OAuthRejected(
                "That provider account is already linked.",
                error_code="OAUTH_ALREADY_LINKED",
                status_code=409,
            )
        _log.info(
            "OAuth identity linked.",
            extra={
                "event": "oauth.linked",
                "provider": identity.provider,
                "user_id": user_id,
                "auto": False,
            },
        )
        return record

    def list_links(self, user_id: str) -> list[OAuthLinkRecord]:
        """Every provider linked to this account, for the settings page."""
        return sorted(self._links.list_for_user(user_id), key=lambda record: record.provider)

    def unlink(self, *, user_id: str, provider: str) -> None:
        """Detach a provider, unless doing so would leave the account with no way in.

        The count is the whole point of the method. Removing the last sign-in method is
        permanent lockout: nobody can log in, so nobody can add a method back, and the
        account is unreachable by any path this design has. So what would remain is counted
        first, and only a non-empty answer permits the delete.

        What counts as remaining:

        - **Another OAuth link.** Read from the GSI and then **re-read from the base table**,
          because the GSI is eventually consistent and a stale entry for a link that was just
          removed would be counted as a remaining method. Over-counting here is the one
          direction that loses the account, so it is the one the extra read buys out.
        - **A password**, from the credential store this service was given. A product that
          did not supply one gets `False`, which errs toward refusing.
        - **A passkey or anything else**, through the `has_other_sign_in_method` hook, which
          defaults to `False` so a hooks class written before M6 keeps working and can only
          make this stricter.
        """
        target = provider_account_key(provider, "")
        links = [
            record
            for record in self._links.list_for_user(user_id)
            if record.provider == provider or record.provider_subject.startswith(target)
        ]
        if not links:
            raise OAuthRejected(
                "That provider is not linked to this account.",
                error_code="OAUTH_NOT_LINKED",
                status_code=404,
            )

        removing = {record.provider_subject for record in links}
        remaining = self._other_sign_in_methods(user_id, removing=removing)
        if not remaining:
            raise OAuthRejected(
                "That is the only way to sign in to this account. Set a password or add "
                "another sign-in method first.",
                error_code="OAUTH_LAST_SIGN_IN_METHOD",
                status_code=409,
            )

        for record in links:
            self._links.delete(record.provider_subject)
        _log.info(
            "OAuth identity unlinked.",
            extra={"event": "oauth.unlinked", "provider": provider, "user_id": user_id},
        )

    def _other_sign_in_methods(self, user_id: str, *, removing: set[str]) -> bool:
        """Whether anything would still sign this user in after `removing` goes away."""
        for record in self._links.list_for_user(user_id):
            if record.provider_subject in removing:
                continue
            # The GSI is eventually consistent, so a link it still lists may already be gone.
            # Confirm against the base table before counting it as a way in.
            confirmed = self._links.get(record.provider_subject)
            if confirmed is not None and confirmed.user_id == user_id:
                return True

        if self._credentials is not None:
            from webbpulse.identity.flows import PASSWORD_CREDENTIAL_TYPE

            password = self._credentials.get(user_id, PASSWORD_CREDENTIAL_TYPE)
            if password is not None and password.secret:
                return True

        return bool(self._hooks.has_other_sign_in_method(user_id))

    # ---- helpers --------------------------------------------------------------------

    def _new_link(self, identity: OAuthIdentity, user_id: str) -> OAuthLinkRecord:
        moment = now_iso()
        return OAuthLinkRecord(
            provider_subject=identity.account_key,
            provider=identity.provider,
            subject=identity.subject,
            user_id=user_id,
            linked_at=moment,
            provider_email=identity.email,
            provider_email_verified=identity.email_verified,
            last_login_at=moment,
        )

    def _touch(self, record: OAuthLinkRecord, identity: OAuthIdentity) -> None:
        """Record this login on the link, and refresh what the provider now says.

        Best effort on purpose: a write failure here must not fail a sign-in that has already
        succeeded in every way that matters. The value is an audit trail and a settings page
        that shows the current address, neither of which is worth refusing a login for.
        """
        try:
            self._links.put(
                OAuthLinkRecord(
                    provider_subject=record.provider_subject,
                    provider=record.provider,
                    subject=record.subject,
                    user_id=record.user_id,
                    linked_at=record.linked_at,
                    provider_email=identity.email or record.provider_email,
                    provider_email_verified=identity.email_verified,
                    last_login_at=now_iso(),
                )
            )
        except Exception:
            _log.warning(
                "Could not record an OAuth login on its link.",
                extra={"event": "oauth.touch_failed", "provider": record.provider},
            )


def _as_bool(value: object) -> bool:
    """Read a provider's boolean, which may be a real one or the string spelling of one.

    Google has returned `email_verified` as both `true` and `"true"` over the years and
    GitHub's `verified` is a real boolean. `bool("false")` is `True`, which is why this is a
    function rather than a `bool()` call at each site.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _require_str(body: Mapping[str, Any], key: str, provider: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        _log.warning(
            "OAuth token response was missing a required field.",
            extra={"event": "oauth.token_incomplete", "provider": provider, "field": key},
        )
        raise OAuthRejected(
            "That sign-in could not be completed. Try again.",
            error_code="OAUTH_EXCHANGE_FAILED",
        )
    return value


def _user_id(user: Mapping[str, Any]) -> str:
    """The immutable id from a product's user mapping, as `flows._user_id` reads it."""
    value = user.get("id") or user.get("user_id") or ""
    if not value:
        raise OAuthRejected(
            "The product's user record has no id, so no token can be minted for it.",
            error_code="USER_ID_MISSING",
            status_code=500,
        )
    return str(value)
