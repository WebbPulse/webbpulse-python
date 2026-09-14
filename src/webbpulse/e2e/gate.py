"""Signed CloudFront session cookies for the staging web gate.

Both staging sites sit behind a CloudFront viewer-request function that admits a non-API
request only when `CloudFront-Policy`, `CloudFront-Signature` and `CloudFront-Key-Pair-Id`
are present and the policy's `AWS:EpochTime` is more than thirty seconds in the future;
without them it redirects to the Cognito hosted UI, and a request under the site's `/api/`
prefix is answered 401. The API host's authorizer admits either the `x-origin-verify`
header or these same cookies, which is how a browser-driven suite reaches the API.

The policy this module signs must be byte identical to the one the gate's login Lambda
issues, because the CloudFront function regex-matches the decoded policy text: no spaces
in the JSON, and the keys in the order `Statement`, `Resource`, `Condition`,
`DateLessThan`, `AWS:EpochTime`. The base64 uses CloudFront's own safe alphabet, where
`+` becomes `-`, `=` becomes `_` and `/` becomes `~`.

Nothing here prints, logs or puts a PEM or a cookie value into an error message.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest

__all__ = [
    "COOKIE_NAMES",
    "DEFAULT_SESSION_SECONDS",
    "GateCookies",
    "cloudfront_safe_base64",
    "gate_policy",
    "mint_gate_cookies",
    "sign_gate_policy",
]

COOKIE_NAMES = ("CloudFront-Policy", "CloudFront-Signature", "CloudFront-Key-Pair-Id")
DEFAULT_SESSION_SECONDS = 3600


def cloudfront_safe_base64(payload: bytes) -> str:
    """Encode bytes in CloudFront's URL-safe base64 alphabet.

    Standard base64 with `+` replaced by `-`, `=` by `_` and `/` by `~`, which is what the
    gate function decodes and what CloudFront itself verifies against.
    """
    return base64.b64encode(payload).decode("ascii").replace("+", "-").replace("=", "_").replace("/", "~")


def gate_policy(domain: str, expires: float) -> str:
    """Build the custom policy JSON for a cookie domain and an expiry.

    Serialised with no whitespace and in a fixed key order, because the CloudFront viewer
    function reads the expiry back out with a regular expression over the decoded text
    rather than by parsing it.
    """
    document = {
        "Statement": [
            {
                "Resource": f"https://*{domain}/*",
                "Condition": {"DateLessThan": {"AWS:EpochTime": int(expires)}},
            }
        ]
    }
    return json.dumps(document, separators=(",", ":"))


def sign_gate_policy(private_key_pem: str, domain: str, expires: int) -> tuple[str, str]:
    """Sign the gate policy with an RSA private key, returning the encoded pair.

    The signature is RSA PKCS1 v1.5 over SHA1 of the policy bytes, which is the only
    scheme CloudFront signed cookies accept. Returns the safe-base64 policy and the
    safe-base64 signature, in that order. The PEM never appears in a return value or a
    raised message.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("the gate signing key is not an RSA private key, which CloudFront signed cookies require")
    policy = gate_policy(domain, expires).encode("utf-8")
    signature = key.sign(policy, padding.PKCS1v15(), hashes.SHA1())
    return cloudfront_safe_base64(policy), cloudfront_safe_base64(signature)


@dataclass(frozen=True)
class GateCookies:
    """One minted staging session, in the shape each client wants it.

    `policy` and `signature` are already safe-base64 encoded. Both are excluded from the
    repr, since a dataclass repr reaches a pytest failure report.
    """

    policy: str = field(repr=False)
    signature: str = field(repr=False)
    key_pair_id: str
    domain: str
    expires: int

    @property
    def values(self) -> Mapping[str, str]:
        """The three cookie names mapped to their values, in the gate's own order."""
        return {
            "CloudFront-Policy": self.policy,
            "CloudFront-Signature": self.signature,
            "CloudFront-Key-Pair-Id": self.key_pair_id,
        }

    def as_httpx_cookies(self) -> Mapping[str, str]:
        """The cookies as the name to value mapping httpx's `cookies=` takes."""
        return dict(self.values)

    def as_playwright_cookies(self) -> list[dict[str, Any]]:
        """The cookies as the dicts `BrowserContext.add_cookies` takes.

        Scoped to the cookie domain with a leading dot so every host under the staging
        apex sends them, which is what the login Lambda's `Domain=` attribute produces.
        """
        domain = self.domain if self.domain.startswith(".") else f".{self.domain}"
        return [
            {
                "name": name,
                "value": value,
                "domain": domain,
                "path": "/",
                "expires": float(self.expires),
                "httpOnly": True,
                "secure": True,
                "sameSite": "Lax",
            }
            for name, value in self.values.items()
        ]


def mint_gate_cookies(
    *,
    ssm_client: Any,
    parameter_name: str,
    key_pair_id: str,
    domain: str,
    environment: str,
    session_seconds: int = DEFAULT_SESSION_SECONDS,
    now: int | None = None,
) -> GateCookies:
    """Read the signing PEM from SSM and mint one staging session.

    Refuses production outright, the way `mint_test_token` does: production has no web
    gate, so a signing key there would be a key that should not exist. The parameter is
    read with decryption through the caller's own credentials and its value is never
    returned, logged or interpolated into a message.
    """
    if environment.strip().lower() == "production":
        raise RuntimeError(
            "mint_gate_cookies refuses production. Production has no web gate, so there is "
            "no session to mint and no signing key that should be readable there."
        )
    response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
    pem = str(response["Parameter"]["Value"])
    expires = int(time.time() if now is None else now) + int(session_seconds)
    policy, signature = sign_gate_policy(pem, domain, expires)
    return GateCookies(
        policy=policy,
        signature=signature,
        key_pair_id=key_pair_id,
        domain=domain,
        expires=expires,
    )


@pytest.fixture(scope="session")
def gate_cookies(e2e_env: Any, request: Any) -> Iterator[GateCookies | None]:
    """The minted staging session cookies, or None where no web gate is configured.

    The three `E2E_GATE_*` web gate variables are all set or all empty; the environment
    parse refuses a mix, so by here an empty parameter name means production, a local
    stack, or a deliberately gate-less stage. `boto3_session` is requested only after that
    check, so a run with no gate constructs no AWS client.
    """
    if not e2e_env.gate_signing_key_ssm_parameter:
        yield None
        return
    boto3_session = request.getfixturevalue("boto3_session")
    yield mint_gate_cookies(
        ssm_client=boto3_session.client("ssm"),
        parameter_name=e2e_env.gate_signing_key_ssm_parameter,
        key_pair_id=e2e_env.gate_key_pair_id,
        domain=e2e_env.gate_cookie_domain,
        environment=e2e_env.environment,
    )
