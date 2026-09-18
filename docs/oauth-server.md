# Identity: the OAuth 2.1 authorization server

An authorization server a product turns on so it can host a remote MCP server that Claude,
editors and other MCP clients connect to. The rest of the identity package is in
[identity.md](identity.md); the sign-in side, where this package is an OAuth *client*
against Google and GitHub, is in [identity-oauth.md](identity-oauth.md). Back to the
[README](../README.md).

Implements the MCP authorization spec (2025-06-18) over RFC 8414, 9728, 7591, 7636, 8707
and 7009.

## Turning it on

Off by default, because a product with no MCP server should not expose one.

```python
from webbpulse.identity import (
    IdentitySettings,
    OAuthServerStores,
    TokenService,
    build_identity_router,
    signing_client,
)

settings = IdentitySettings()  # IDENTITY_MCP_OAUTH_ENABLED=true, IDENTITY_MCP_RESOURCE_URL=...
app.include_router(
    build_identity_router(
        settings,
        hooks,
        stores,
        tokens=TokenService(settings, signing_client(settings)),
        oauth_server_stores=OAuthServerStores(clients=..., codes=..., consents=...),
        tenant_resolver=lambda user_id: [TenantChoice(id=w.id, name=w.name) for w in workspaces_for(user_id)],
    )
)
```

**The flag without `oauth_server_stores` raises at startup rather than mounting.** The
discovery documents advertise these endpoints the moment the flag is on, and endpoints that
are advertised and then answer 404 are worse than a service that refuses to boot: the
failure moves from the deploy, where it is one traceback, to every client that reads the
metadata and tries to use it.

Provision `OAUTH_SERVER_TABLES` alongside `TABLES`. They are a separate tuple, so a product
that never turns the flag on provisions nothing extra.

| Setting | What it does |
| --- | --- |
| `mcp_oauth_enabled` | Mounts the routes and extends the OIDC document. Default `False` |
| `mcp_resource_url` | The MCP resource these tokens are bound to. Required when enabled |
| `mcp_scopes_supported` | The scopes a client may ask for. Default `mcp:read`, `mcp:write` |
| `mcp_registration_enabled` | Whether `/register-client` is open. Default `True` |
| `mcp_clients` | Pre-registered first-party clients, which carry no TTL |
| `mcp_authorization_code_ttl` | Default 60s, capped at 10 minutes |
| `mcp_client_ttl` | How long an unused dynamic registration survives. Default 90 days |
| `mcp_tenant_claim` | The claim the consented tenant is written to. Default `tenant_id` |

**`mcp_tenant_claim` may not name a registered claim.** `mint_access_token` drops
registered claims from product claims rather than letting them be overridden, so naming one
here would not fail loudly: the tenant would silently vanish from every token the server
issues, and a resource server reading it would see `None` where it expected a workspace.
Settings validation refuses the name instead.

## The endpoints

All of them mount under the issuer's path, like every other identity route.

| Path | What it is |
| --- | --- |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `/.well-known/oauth-protected-resource` | RFC 9728 metadata, naming this issuer for `mcp_resource_url` |
| `/authorize` | The authorization request, and the consent screen |
| `/authorize/consent` | Where the consent form posts |
| `/token` | The code grant and refresh rotation |
| `/register-client` | RFC 7591 dynamic registration |
| `/revoke` | RFC 7009 revocation |

**Registration is at `/register-client`, not `/register`.** `/register` is already the
identity package's user-registration route. `registration_endpoint` in both metadata
documents advertises the real path, so a client that reads discovery, as RFC 7591 requires,
finds it without knowing this.

Turning the flag on also adds `authorization_endpoint`, `token_endpoint`,
`registration_endpoint`, `code_challenge_methods_supported`, `scopes_supported` and
`response_types_supported` to the existing OIDC discovery document. The document is copied
rather than mutated, so the `TokenService` precomputed one is untouched.

## What the server refuses, and why

**PKCE S256 is required; `plain` is refused.** `plain` sends the verifier and the challenge
as the same string, so an attacker who intercepted the authorization request holds
everything needed to redeem the code. OAuth 2.1 forbids it.

**There is no implicit grant.** `response_type=token` is refused rather than quietly served
as a code request. The implicit grant puts an access token in a URL fragment, where it
reaches browser history, `Referer` headers and logs.

**`resource` is required, at both `/authorize` and `/token`.** RFC 8707's indicator becomes
the token's `aud`, so every token this server issues names exactly one resource and a token
minted for one MCP server is not accepted by another. A `resource` at the token endpoint
that differs from the one the code was issued for is refused rather than ignored.

**A redirect URI must match exactly, and must be https or loopback.** Exact string
equality, never a prefix or a subdomain match, because every relaxation of that rule is a
way to redirect a code somewhere else. Plaintext `http` is accepted only on `127.0.0.1`,
`::1` or `localhost`, which is what a native client's loopback listener needs and is not
reachable across a network. A fragment is refused outright.

**A code is single use, and a failed exchange still burns it.** The code is deleted before
PKCE or the redirect URI is compared, so a client that gets the verifier wrong does not get
a second attempt at the same code. The delete is conditional with `ReturnValues=ALL_OLD`, so
two concurrent exchanges cannot both win.

**Only the code's hash is stored.** As with refresh and verification tokens, a read of the
table yields nothing exchangeable.

**An unsupported scope is refused, not narrowed.** Silently issuing a token with fewer
scopes than asked for leaves a client believing it holds a permission it does not, and it
discovers this later as an unexplained failure against the resource server.

**Registration is open, but only to public clients.** `token_endpoint_auth_method` must be
`none`; asking for a client secret is refused rather than downgraded. There is a per-address
rate limit, ten per hour, and a dynamic registration carries a TTL so one nothing ever used
is reclaimed. First-party clients from `mcp_clients` are marked as such and never expire.

**Revocation answers 200 for a token it has never seen.** RFC 7009 requires it: answering
differently would make the endpoint an oracle for guessing tokens.

## Consent

`/authorize` requires a signed-in user and renders a consent screen. **Consent binds the
token to exactly one tenant**, chosen by the user from what `tenant_resolver` returns, and
the tenant is re-checked against that resolver when the form posts rather than trusted from
the form. It is written into the code record, not accepted again at `/token`, where the
client could change it.

The form carries the authorization parameters through the user's browser, so they are
covered by an HMAC. A scope or redirect URI edited in the browser, or a form posted from
somewhere else, fails the check and is refused.

`consent_renderer` replaces the built-in screen wholesale, taking a `ConsentContext` and
returning any Starlette response. A replacement must post `form_fields` back unchanged;
everything else about the page is the product's. The default screen exists so a product has
a working authorization screen on day one, not so it ships that one. Every value on it is
HTML-escaped, because a client name arrives from an unauthenticated endpoint.

## The tokens

The same RS256 access tokens the package already mints, so an existing API Gateway JWT
authorizer and `coerce_claims` handle them with no change at all. On top of the usual
claims they carry `scope` as a space-separated string, which `coerce_claims` already splits
into `scopes`, plus `client_id` and the tenant claim. `aud` is the resource, not the
product's own audience.

Refresh tokens rotate through the existing `SessionService` family model, so reuse
detection is the same one the browser sessions get: presenting a rotated token kills the
family.
