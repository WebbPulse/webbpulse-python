"""Contract tests against a deployed identity service.

Skipped unless `WEBBPULSE_IDENTITY_CONTRACT_BASE_URL` is set to the issuer URL, so
the ordinary test run makes no network request.
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

REQUIRED_DISCOVERY_MEMBERS = (
    "issuer",
    "jwks_uri",
    "response_types_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
)

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
        """Parse the body as JSON."""
        return json.loads(self.body)

    def header(self, name: str) -> str:
        """Return a response header by case-insensitive name, or an empty string."""
        return self.headers.get(name.lower(), "")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Turn a redirect into a response rather than following it."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        """Refuse to build a follow-up request, so the redirect surfaces as a response."""
        return None


def fetch(url: str) -> Fetched:
    """GET one URL anonymously, without following redirects, as the validator would."""
    timeout = float(os.environ.get(TIMEOUT_ENV, "10"))
    opener = urllib.request.build_opener(_NoRedirects)
    request = urllib.request.Request(url, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return Fetched(
                status=response.status,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=response.read(),
            )
    except urllib.error.HTTPError as exc:
        return Fetched(
            status=exc.code,
            headers={key.lower(): value for key, value in exc.headers.items()},
            body=exc.read(),
        )


@pytest.fixture(scope="module")
def discovery_response() -> Fetched:
    """Fetch the discovery document from the configured issuer, once per module."""
    return fetch(f"{base_url}{DISCOVERY_SUFFIX}")


@pytest.fixture(scope="module")
def discovery(discovery_response: Fetched) -> dict[str, Any]:
    """Return the parsed discovery document, failing loudly if it did not answer 200."""
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
    """Fetch the JWKS from the advertised `jwks_uri`, not from a guessed path."""
    return fetch(discovery["jwks_uri"])


@pytest.fixture(scope="module")
def jwks(jwks_response: Fetched, discovery: dict[str, Any]) -> dict[str, Any]:
    """Return the parsed JWKS, failing loudly if the advertised URI did not answer 200."""
    assert jwks_response.status == 200, (
        f"The advertised jwks_uri {discovery['jwks_uri']} answered {jwks_response.status}. "
        "Section 3.4: this URL is fetched anonymously at CreateAuthorizer time as well, so "
        "a JWKS behind an access gate fails the apply and the error names only the "
        "discovery URL."
    )
    body: dict[str, Any] = jwks_response.json()
    return body


def test_discovery_answers_anonymously(discovery_response: Fetched) -> None:
    """Discovery answers 200 with JSON to an anonymous, non-redirected request."""
    assert discovery_response.status == 200
    assert discovery_response.header("content-type").startswith("application/json")


def test_discovery_carries_the_five_required_members(discovery: dict[str, Any]) -> None:
    """The served discovery document carries every member OIDC Discovery requires."""
    missing = [member for member in REQUIRED_DISCOVERY_MEMBERS if member not in discovery]
    assert not missing, f"Discovery document is missing {missing}."


def test_the_issuer_matches_the_base_url_byte_for_byte(discovery: dict[str, Any]) -> None:
    """The advertised `issuer` is byte-identical to the URL the document was fetched from."""
    assert discovery["issuer"] == base_url, (
        f"The document advertises issuer {discovery['issuer']!r} but was fetched from "
        f"{base_url!r}. These must be byte-identical to the `iss` claim and to the "
        "authorizer's configured issuer."
    )


def test_the_jwks_uri_sits_under_the_issuer(discovery: dict[str, Any]) -> None:
    """The advertised `jwks_uri` sits under the issuer path and uses the issuer's scheme."""
    assert discovery["jwks_uri"].startswith(f"{base_url}/"), (
        f"jwks_uri {discovery['jwks_uri']!r} is not under the issuer {base_url!r}. A JWKS at "
        "the origin is correct only for a path-less issuer."
    )
    scheme = base_url.split("://", 1)[0]
    assert discovery["jwks_uri"].startswith(f"{scheme}://"), (
        f"jwks_uri {discovery['jwks_uri']!r} does not use the issuer's own scheme. A key "
        "fetched over plain HTTP can be substituted in transit by anyone on the path."
    )


def test_rs256_is_advertised(discovery: dict[str, Any]) -> None:
    """RS256 is advertised and no symmetric algorithm is."""
    algorithms = discovery["id_token_signing_alg_values_supported"]
    assert "RS256" in algorithms
    assert not any(str(alg).startswith("HS") for alg in algorithms), (
        f"{algorithms} advertises a symmetric algorithm. Section 3.1: the signing key is "
        "asymmetric so that the gateway verifies with a public key it can fetch."
    )


def test_discovery_is_cacheable(discovery_response: Fetched) -> None:
    """Discovery carries a `Cache-Control` with a max-age and is not marked `no-store`."""
    header = discovery_response.header("cache-control")
    assert header, "No Cache-Control on the discovery document."
    assert "no-store" not in header
    assert "max-age" in header


def test_the_jwks_has_at_least_one_key(jwks: dict[str, Any]) -> None:
    """The served JWKS has a `keys` list holding at least one key."""
    assert isinstance(jwks.get("keys"), list)
    assert jwks["keys"], "The JWKS advertises no keys, so no token can ever be verified."


def test_every_key_carries_the_members_the_authorizer_needs(jwks: dict[str, Any]) -> None:
    """Every served key carries the required members and is a signing RS256 RSA key."""
    for index, key in enumerate(jwks["keys"]):
        missing = [member for member in REQUIRED_JWK_MEMBERS if member not in key]
        assert not missing, f"keys[{index}] is missing {missing}."
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert key["kid"], f"keys[{index}] has an empty kid."


def test_every_modulus_and_exponent_is_unpadded_base64url(jwks: dict[str, Any]) -> None:
    """Every `n` and `e` is unpadded base64url that decodes, with a modulus of 256 bytes or more."""
    for index, key in enumerate(jwks["keys"]):
        for member in ("n", "e"):
            value = key[member]
            assert _BASE64URL.match(value), f"keys[{index}].{member} is not base64url."
            assert "=" not in value, f"keys[{index}].{member} is padded."
            padding = "=" * (-len(value) % 4)
            decoded = base64.urlsafe_b64decode(value + padding)
            assert decoded, f"keys[{index}].{member} decodes to nothing."
        modulus = base64.urlsafe_b64decode(key["n"] + "=" * (-len(key["n"]) % 4))
        assert len(modulus) >= 256, (
            f"keys[{index}].n decodes to {len(modulus)} bytes, which is smaller than the "
            "256 an RSA_2048 modulus takes."
        )


def test_every_kid_is_distinct(jwks: dict[str, Any]) -> None:
    """No two keys in the served JWKS share a `kid`."""
    kids = [key["kid"] for key in jwks["keys"]]
    assert len(kids) == len(set(kids)), f"Duplicate kid in the JWKS: {kids}."


def test_the_jwks_is_cacheable_but_shorter_lived_than_discovery(
    jwks_response: Fetched, discovery_response: Fetched
) -> None:
    """The JWKS is cacheable and its max-age is no longer than the discovery document's."""
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
    """The advertised JWKS answers 200 with JSON to an anonymous request."""
    assert jwks_response.status == 200
    assert jwks_response.header("content-type").startswith("application/json")


def _max_age(header: str) -> int | None:
    """Return the `max-age` seconds from a `Cache-Control` header, or None."""
    match = re.search(r"max-age=(\d+)", header)
    return int(match.group(1)) if match else None
