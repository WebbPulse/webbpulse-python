"""Contract tests: does a **deployed** identity service satisfy API Gateway's JWT authorizer?

Skipped unless `WEBBPULSE_IDENTITY_CONTRACT_BASE_URL` is set. **The default test run makes no
network request at all**, so `pytest` in CI and `pytest` on a laptop behave the same and
neither depends on staging being up.

## Why this exists as a separate suite

Every other test in this repository asserts what the package produces. This one asserts what
a running deployment serves, which is a different question with a different failure mode:
the two `.well-known` documents can be perfect in `build_discovery_document` and still be
unreachable in production because a gateway route was not created, an access gate sits in
front of them, a CDN rewrote the `Cache-Control` header, or the issuer in the deployed
settings has a trailing slash the local settings did not.

Section 3.4 records that API Gateway fetches both documents **at `CreateAuthorizer` time**,
so every one of those failures presents as a Terraform apply that fails with
`BadRequestException` and quotes only the discovery URL back. That error names nothing about
which of the six requirements below was violated. This suite names it.

## Running it

Against staging, from the repository root::

    WEBBPULSE_IDENTITY_CONTRACT_BASE_URL=https://api.staging.webbpulse.com/api/auth \\
        pytest tests/test_identity_contract.py -v

The base URL is the **issuer**, path included. `https://api.staging.webbpulse.com` and
`https://api.staging.webbpulse.com/api/auth` are different contracts and the second is what
section 6.1 specifies, so passing the origin when the issuer has a path is itself the bug
this suite is looking for and it will be reported as a 404 on discovery.

CarModPicker staging is `https://api.staging.carmodpicker.com/api/auth`, and the production
hosts are the same URLs without `staging.`. Run it against production after a rotation as
well as after a deploy: section 3.5's three-hour wait is about a `kid` that is advertised
but not yet trusted, and this is what confirms the advertisement half.

## What is deliberately not asserted

No token is minted and no signature is verified. Doing either needs a real credential
against a real product, which turns a read-only probe anybody can run into something that
needs secrets. The token path is covered by the unit suites against a local key.

`Cache-Control` is asserted as **present and sane** rather than byte-equal to the package's
constants. A CDN in front of the API is entitled to shorten a max-age, and a test that
failed on that would be reporting an infrastructure choice as a defect.

## The HTTP client is `urllib.request`

Deliberately, rather than `httpx` or `requests`. Neither is a dependency of this package or
of any of its extras, and a contract suite that skipped itself with "could not import httpx"
would look exactly like the intended skip while actually being broken. The stdlib cannot go
missing, and the four requests this file makes need nothing a client library adds.

Redirects are **not** followed, which needs saying because `urlopen` follows them by
default and this file turns that off. A redirect on either document is itself a finding:
API Gateway's validator is not documented to follow one, and a discovery URL that 301s to a
trailing-slash variant is a classic way for an authorizer create call to fail.
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

import pytest

BASE_URL_ENV = "WEBBPULSE_IDENTITY_CONTRACT_BASE_URL"
TIMEOUT_ENV = "WEBBPULSE_IDENTITY_CONTRACT_TIMEOUT"

DISCOVERY_SUFFIX = "/.well-known/openid-configuration"

#: The five members OIDC Discovery requires, per section 3.4.
REQUIRED_DISCOVERY_MEMBERS = (
    "issuer",
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
)

#: The JWK members API Gateway needs to verify an RS256 signature.
REQUIRED_JWK_MEMBERS = ("kty", "use", "alg", "kid", "n", "e")

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


base_url = os.environ.get(BASE_URL_ENV, "").rstrip("/")

pytestmark = pytest.mark.skipif(
    not base_url,
    reason=(
        f"Set {BASE_URL_ENV} to the issuer of a deployed identity service to run the "
        "contract tests, for example "
        "https://api.staging.webbpulse.com/api/auth. They make live HTTP requests and are "
        "skipped by default so that the ordinary test run needs no network."
    ),
)


@dataclass(frozen=True, slots=True)
class Fetched:
    """One response, reduced to the three things this suite asserts about."""

    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Turn a redirect into a response rather than following it. See the module docstring."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def fetch(url: str) -> Fetched:
    """GET one URL anonymously: no cookie, no bearer token, no origin-verify header.

    Anonymously is the point rather than an accident of the implementation. API Gateway's
    validator carries none of those, so a document that answers only to an authenticated
    caller fails `CreateAuthorizer` while looking healthy in a browser that is signed in.
    """
    timeout = float(os.environ.get(TIMEOUT_ENV, "10"))
    opener = urllib.request.build_opener(_NoRedirects)
    # The URL is operator-supplied through the environment variable, never attacker-supplied.
    request = urllib.request.Request(url, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return Fetched(
                status=response.status,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=response.read(),
            )
    except urllib.error.HTTPError as exc:
        # A 4xx or 5xx is a result to assert on, not an error to raise through. A 401 on
        # discovery is exactly the finding this suite exists to report.
        return Fetched(
            status=exc.code,
            headers={key.lower(): value for key, value in exc.headers.items()},
            body=exc.read(),
        )


@pytest.fixture(scope="module")
def discovery_response() -> Fetched:
    return fetch(f"{base_url}{DISCOVERY_SUFFIX}")


@pytest.fixture(scope="module")
def discovery(discovery_response: Fetched) -> dict[str, Any]:
    assert discovery_response.status == 200, (
        f"{base_url}{DISCOVERY_SUFFIX} answered {discovery_response.status}. API Gateway "
        "fetches this URL during CreateAuthorizer, so anything but a 200 makes the "
        "authorizer impossible to create. Check that the route exists, that it is "
        f"anonymous, and that the issuer really is {base_url} rather than its origin."
    )
    body: dict[str, Any] = discovery_response.json()
    return body


@pytest.fixture(scope="module")
def jwks_response(discovery: dict[str, Any]) -> Fetched:
    """The JWKS fetched from the advertised `jwks_uri`, not from a guessed path.

    Following the advertisement is the whole point: section 3.4's access log shows API
    Gateway reading `jwks_uri` out of the document it just fetched, so a JWKS that is
    reachable at the conventional path but not at the advertised one still fails.
    """
    return fetch(discovery["jwks_uri"])


@pytest.fixture(scope="module")
def jwks(jwks_response: Fetched, discovery: dict[str, Any]) -> dict[str, Any]:
    assert jwks_response.status == 200, (
        f"The advertised jwks_uri {discovery['jwks_uri']} answered {jwks_response.status}. "
        "Section 3.4: this URL is fetched anonymously at CreateAuthorizer time as well, so "
        "a JWKS behind an access gate fails the apply and the error names only the "
        "discovery URL."
    )
    body: dict[str, Any] = jwks_response.json()
    return body


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discovery_answers_anonymously(discovery_response: Fetched) -> None:
    """No cookie, no bearer token, no origin-verify header. As the validator would ask.

    A 3xx fails here too, because redirects are not followed: the validator is not
    documented to follow one either.
    """
    assert discovery_response.status == 200
    assert discovery_response.header("content-type").startswith("application/json")


def test_discovery_carries_the_five_required_members(discovery: dict[str, Any]) -> None:
    missing = [member for member in REQUIRED_DISCOVERY_MEMBERS if member not in discovery]
    assert not missing, f"Discovery document is missing {missing}."


def test_the_issuer_matches_the_base_url_byte_for_byte(discovery: dict[str, Any]) -> None:
    """The classic failure, and the one with the least useful error message.

    A trailing slash on one side and not the other presents as every request being denied,
    with nothing in the gateway's response saying why. Compared exactly rather than
    normalised, because the authorizer compares it exactly.
    """
    assert discovery["issuer"] == base_url, (
        f"The document advertises issuer {discovery['issuer']!r} but was fetched from "
        f"{base_url!r}. These must be byte-identical to the `iss` claim and to the "
        "authorizer's configured issuer."
    )


def test_the_jwks_uri_sits_under_the_issuer(discovery: dict[str, Any]) -> None:
    """Section 3.4: both documents are served under the issuer's path, not at the origin."""
    assert discovery["jwks_uri"].startswith(f"{base_url}/"), (
        f"jwks_uri {discovery['jwks_uri']!r} is not under the issuer {base_url!r}. A JWKS at "
        "the origin is correct only for a path-less issuer."
    )
    # Scheme compared against the issuer's rather than hard-coded to https, so this file
    # can be pointed at a locally served app to check the assertions themselves. Against
    # any real deployment the issuer is https, so this still catches a downgrade.
    scheme = base_url.split("://", 1)[0]
    assert discovery["jwks_uri"].startswith(f"{scheme}://"), (
        f"jwks_uri {discovery['jwks_uri']!r} does not use the issuer's own scheme. A key "
        "fetched over plain HTTP can be substituted in transit by anyone on the path."
    )


def test_rs256_is_advertised(discovery: dict[str, Any]) -> None:
    """Asymmetric only. A symmetric alg here would mean the gateway could not verify at all."""
    algorithms = discovery["id_token_signing_alg_values_supported"]
    assert "RS256" in algorithms
    assert not any(str(alg).startswith("HS") for alg in algorithms), (
        f"{algorithms} advertises a symmetric algorithm. Section 3.1: the signing key is "
        "asymmetric so that the gateway verifies with a public key it can fetch."
    )


def test_discovery_is_cacheable(discovery_response: Fetched) -> None:
    """Present and sane rather than byte-equal to the package constant.

    A CDN is entitled to shorten a max-age, and failing on that would report an
    infrastructure choice as a defect. What matters is that the document is not marked
    `no-store`, because it sits on the hot path: section 3.4's access log shows it fetched
    again on every authorizer host that has not seen it.
    """
    header = discovery_response.header("cache-control")
    assert header, "No Cache-Control on the discovery document."
    assert "no-store" not in header
    assert "max-age" in header


# ---------------------------------------------------------------------------
# JWKS
# ---------------------------------------------------------------------------


def test_the_jwks_has_at_least_one_key(jwks: dict[str, Any]) -> None:
    assert isinstance(jwks.get("keys"), list)
    assert jwks["keys"], "The JWKS advertises no keys, so no token can ever be verified."


def test_every_key_carries_the_members_the_authorizer_needs(jwks: dict[str, Any]) -> None:
    for index, key in enumerate(jwks["keys"]):
        missing = [member for member in REQUIRED_JWK_MEMBERS if member not in key]
        assert not missing, f"keys[{index}] is missing {missing}."
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert key["kid"], f"keys[{index}] has an empty kid."


def test_every_modulus_and_exponent_is_unpadded_base64url(jwks: dict[str, Any]) -> None:
    """RFC 7517 base64url, no padding. A `+`, `/` or `=` here is a real interoperability bug.

    Decoded as well as pattern-matched, because a value can match the character class and
    still be an invalid length. `e` is `AQAB` for every key AWS KMS produces, which is
    65537, and a different exponent is worth noticing rather than asserting against.
    """
    for index, key in enumerate(jwks["keys"]):
        for member in ("n", "e"):
            value = key[member]
            assert _BASE64URL.match(value), f"keys[{index}].{member} is not base64url."
            assert "=" not in value, f"keys[{index}].{member} is padded."
            padding = "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode(value + padding)
            assert decoded, f"keys[{index}].{member} decodes to nothing."
        # A 2048-bit modulus is 256 bytes. Section 3.1 fixes RSA_2048 as the key spec.
        modulus = base64.urlsafe_b64decode(key["n"] + "=" * (-len(key["n"]) % 4))
        assert len(modulus) >= 256, (
            f"keys[{index}].n decodes to {len(modulus)} bytes, which is smaller than the "
            "256 an RSA_2048 modulus takes."
        )


def test_every_kid_is_distinct(jwks: dict[str, Any]) -> None:
    """Two keys sharing a `kid` makes the header ambiguous during exactly the window a
    rotation exists to survive."""
    kids = [key["kid"] for key in jwks["keys"]]
    assert len(kids) == len(set(kids)), f"Duplicate kid in the JWKS: {kids}."


def test_the_jwks_is_cacheable_but_shorter_lived_than_discovery(
    jwks_response: Fetched, discovery_response: Fetched
) -> None:
    """Shorter, because a rotation has to propagate inside one deploy window.

    Asserted as an inequality between the two documents rather than against a constant, so a
    CDN that shortens both proportionally still passes while one that caches keys longer
    than the discovery document that names them does not.
    """
    jwks_header = jwks_response.header("cache-control")
    discovery_header = discovery_response.header("cache-control")
    assert jwks_header, "No Cache-Control on the JWKS."
    assert "no-store" not in jwks_header

    jwks_age = _max_age(jwks_header)
    discovery_age = _max_age(discovery_header)
    assert jwks_age is not None, f"No max-age in the JWKS Cache-Control: {jwks_header!r}."
    if discovery_age is not None:
        assert jwks_age <= discovery_age, (
            f"The JWKS is cached for {jwks_age}s and the discovery document that names it "
            f"for {discovery_age}s. A rotation cannot propagate faster than the longer of "
            "the two."
        )


def test_the_jwks_route_is_anonymous(jwks_response: Fetched) -> None:
    """Section 3.4's stronger form: the advertised JWKS must answer anonymously too.

    A discovery document pointing at a JWKS behind the staging access gate fails
    `CreateAuthorizer` exactly as a missing discovery route does, and the error names only
    the discovery URL.
    """
    assert jwks_response.status == 200
    assert jwks_response.header("content-type").startswith("application/json")


def _max_age(header: str) -> int | None:
    match = re.search(r"max-age=(\d+)", header)
    return int(match.group(1)) if match else None
