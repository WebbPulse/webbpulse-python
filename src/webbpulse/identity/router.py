"""`build_identity_router`: the router a product mounts into its identity Lambda.

In 0.9.0 this mounts exactly three routes:

    GET /.well-known/openid-configuration
    GET /.well-known/jwks.json
    GET /health

and nothing else. The flows (login, refresh, MFA, passkeys, OAuth) are M2 and later, per
section 9.1 of `docs/identity-standard.md`. The router takes `settings`, `hooks` and
`stores` now anyway, so that a product's composition root is written once and the later
milestones add routes rather than arguments.

## Why these routes must be anonymous

API Gateway fetches both `.well-known` documents **itself**, from outside any browser
session, holding no cookies and presenting no token. Any authorizer or access gate in front
of either one means the JWT authorizer cannot retrieve the signing key, and then every
authorized route in the product fails closed. Section 2.5 names this as the single most
likely way to get the deployment wrong, and it is worth repeating at the place where the
routes are actually declared: **do not put these behind the staging access gate.**

## Caching

Both documents get an explicit `Cache-Control`. The gateway refetches the JWKS on its own
interval and the discovery document at authorizer creation, and both are on the anonymous
hot path, so an unclaimed cache policy means every fetch is a Lambda invocation.

The two get different lifetimes, and the asymmetry is the point:

- **Discovery is `max-age=3600`.** It is a pure function of the issuer and changes only when
  the issuer does, which is never in the life of a deployment.
- **JWKS is `max-age=300`.** Short, because this is the document rotation moves through. A
  long cache here is what turns rotation step 3 into an outage: a verifier holding a
  ten-hour-old JWKS has not seen the new key and rejects every token signed with it. Five
  minutes bounds that window while still absorbing the fetch volume.

Neither carries `no-store`. Neither contains a secret: a JWKS is public key material by
definition, and treating it as sensitive would be cargo cult.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from webbpulse.identity.storage import IdentityStores
from webbpulse.identity.tokens import DISCOVERY_PATH, JWKS_PATH

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi import APIRouter

    from webbpulse.identity.hooks import IdentityHooks
    from webbpulse.identity.service import TokenService
    from webbpulse.identity.settings import IdentitySettings
    from webbpulse.identity.tokens import KmsClient

__all__ = [
    "DISCOVERY_CACHE_CONTROL",
    "HEALTH_PATH",
    "JWKS_CACHE_CONTROL",
    "build_identity_router",
]

#: One hour. The discovery document changes only when the issuer changes.
DISCOVERY_CACHE_CONTROL = "public, max-age=3600"

#: Five minutes. Short enough that a rotation propagates inside one step's deploy window.
JWKS_CACHE_CONTROL = "public, max-age=300"

#: Matches `webbpulse.http.health_router`, so an identity Lambda answers the same probe
#: path as every other service in the estate.
HEALTH_PATH = "/health"


def build_identity_router(
    settings: IdentitySettings,
    hooks: IdentityHooks | None = None,
    stores: IdentityStores | None = None,
    *,
    tokens: TokenService | None = None,
    kms_client: KmsClient | None = None,
    service: str = "identity",
    version: str = "",
) -> APIRouter:
    """The identity router for a product, mounted with no prefix.

    `settings` is an `IdentitySettings`. `hooks` and `stores` are accepted and held but
    unused in 0.9.0, because no route here calls a hook or touches a store yet; they are in
    the signature so that M2 adds routes without changing how a product constructs this.

    `tokens` is a `TokenService`. Pass one to share a single instance, and its JWK cache,
    with the rest of the service. Omit it and one is built from `settings` and `kms_client`,
    which is the ordinary case.

    `service` and `version` are what `/health` reports, matching the arguments
    `webbpulse.http.health_router` takes for the same purpose.

    The paths are absolute, so mount this with no prefix even in a service whose other
    routers sit under `/api/v1`. RFC 8615 defines `.well-known` paths relative to an origin,
    and one moved under a prefix is not discoverable.

    Every route here is anonymous, deliberately. See the module docstring.
    """
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse

    if tokens is None:
        if kms_client is None:
            raise ValueError(
                "build_identity_router needs either a TokenService as `tokens` or a KMS "
                "client as `kms_client` to build one from."
            )
        from webbpulse.identity.service import TokenService as _TokenService

        tokens = _TokenService(settings, kms_client)

    # Held for M2, which adds the flows that use them. Bound here so a product's composition
    # root is written once rather than gaining an argument at each milestone.
    _ = (hooks, stores if stores is not None else IdentityStores())

    router = APIRouter(tags=["identity"])

    # Each returns an explicit `JSONResponse` rather than taking a `response: Response`
    # parameter and mutating its headers. Under `from __future__ import annotations` that
    # parameter's annotation is the *string* "Response", and FastAPI, unable to resolve it
    # to the class from this function's local import, treats it as a required query
    # parameter and answers 422 to every request. Returning the response sidesteps the
    # resolution problem entirely.

    @router.get(DISCOVERY_PATH, include_in_schema=False)
    async def discovery_document() -> JSONResponse:
        return JSONResponse(tokens.discovery(), headers={"Cache-Control": DISCOVERY_CACHE_CONTROL})

    @router.get(JWKS_PATH, include_in_schema=False)
    async def jwks_document() -> JSONResponse:
        return JSONResponse(tokens.jwks(), headers={"Cache-Control": JWKS_CACHE_CONTROL})

    @router.get(HEALTH_PATH, include_in_schema=False)
    async def health() -> dict[str, Any]:
        # Shape matches `webbpulse.http.health_router` so one probe configuration works
        # across every service. Deliberately does not call KMS: a health check that depends
        # on a downstream turns a KMS blip into an unhealthy target and a restart loop,
        # and the JWKS route already fails loudly if KMS is genuinely unreachable.
        return {
            "status": "healthy",
            "service": service,
            "version": version,
        }

    return router
