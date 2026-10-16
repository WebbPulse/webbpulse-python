# Single sign-on

Per-tenant OIDC and SAML 2.0 single sign-on and DNS TXT domain verification for
`webbpulse.identity`.
Install the `sso` extra (`httpx`, `dnspython`, `PyJWT[crypto]`). A product that never passes
`sso=` to `build_identity_router` mounts nothing new and imports none of these.

The nouns are generic: a **tenant** is whatever the product sells to (a workspace, an
organisation), and a **connection** is one tenant's identity provider, with
`protocol="oidc"` or `protocol="saml"`. Both share the state table, the link table and the
session issuance.

## Wiring

```python
from webbpulse.identity import (
    OidcConnectionConfig, PublicUrlGuard, SsoConnection, SsoHooks, SsoService,
    build_identity_router, seal_oidc_client_secret,
)

class Connections(SsoHooks):
    def load_connection(self, connection_id): ...
    def find_connection(self, *, email="", tenant_hint=""): ...
    def on_sso_login(self, user, connection, identity, *, outcome): ...

sso = SsoService(
    settings, hooks, Connections(),
    states=stores.require_oauth_states(),
    links=stores.require_oauth_links(),
    cipher=cipher,
)
router = build_identity_router(settings, hooks, stores, kms_client=kms, sso=sso)
```

`cipher` is the package's sealing cipher (`SecretMasterKeyCipher` or `EnvelopeCipher`).
Seal a tenant's client secret with `seal_oidc_client_secret(cipher, connection_id=...,
client_secret=...)` and store only the sealed value; it is bound to its connection id and
opened only for the token exchange. It is never logged.

## Routes

| Route | Answers |
| --- | --- |
| `POST <prefix>/sso/start` | Body `email`, `tenant` or `connection_id`, plus `return_to`. JSON `{authorization_url, connection_id}` and a binding cookie. 404 `SSO_CONNECTION_NOT_FOUND` means "use the password form" |
| `GET <prefix>/sso/oidc/{connection_id}/callback` | Always a 303 to the frontend: `sso=1` with the refresh cookie, `sso_error=<code>` on failure, or `#mfa_ticket=` when MFA is enrolled |

Register `<issuer>/sso/oidc/<connection_id>/callback` as the redirect URI at the provider.

## SAML

Install the `saml` extra as well (`signxml`, `lxml`, `httpx`; manylinux wheels on x86_64 and
arm64, no `xmlsec`). Pass `saml_replay=` to `SsoService`, any store with
`claim(key, ttl_seconds) -> bool` such as `webbpulse.dynamodb.IdempotencyStore`, and two
more routes mount:

| Route | Answers |
| --- | --- |
| `GET <prefix>/sso/saml/{connection_id}/metadata` | The SP metadata to import at the IdP. The SP entity id defaults to this URL |
| `POST <prefix>/sso/saml/{connection_id}/acs` | The HTTP-POST assertion consumer. Always a 303, as the OIDC callback |

`POST /sso/start` answers the HTTP-Redirect URL carrying an unsigned AuthnRequest, with the
state as `RelayState`. The binding cookie is `SameSite=None` for a SAML start, since the
response arrives as a cross-site POST.

Build `SamlConnectionConfig` by hand or from the IdP's metadata with
`parse_saml_idp_metadata(xml)` or `fetch_saml_idp_metadata(url)` (through `PublicUrlGuard`,
no redirects, 1 MiB cap), then `.connection_config()`. Several `idp_certificates` allow
rotation. A transient NameID needs `subject_attribute`.

Checks: the assertion signature is required (a response signature is checked when present),
only the element the signature covers is read, and exactly one unencrypted assertion is
allowed, so wrapping attacks fail. `Destination`, `Recipient` and `InResponseTo` must match
the ACS and the spent state's AuthnRequest id, the audience must be the SP entity id, and
`NotBefore`, `NotOnOrAfter` and `SessionNotOnOrAfter` are checked with the settings' clock
skew leeway. A DOCTYPE is refused before parsing. Each assertion id is claimed in the replay
store until it expires. A SAML session's `amr` is `["sso", "saml"]`. Encrypted assertions
and signed AuthnRequests are not supported.

## Sessions

`IdentityFlows.issue_for_sso` mirrors `issue_for_oauth`: `may_authenticate` and MFA still
apply. The access token's `amr` is `["sso", "oidc"]` and it carries
`sso_connection=<connection_id>`; both survive refresh. A product enforcing SSO for a tenant
checks those two claims and answers 403 `SSO_REQUIRED` itself. The connection is stored on
the session as an `sso_conn:` amr marker that never reaches a token, and a hook cannot forge
the `sso_connection` claim.

## Account resolution

1. The durable link is `(connection, subject)` in the OAuth links table, never the email.
2. A first sign-in needs an email on one of the connection's `verified_domains`
   (`SSO_DOMAIN_NOT_VERIFIED` otherwise).
3. An existing local account with that email is linked only when its own address was
   verified (`SSO_EMAIL_UNVERIFIED` otherwise), outcome `auto_linked`.
4. Otherwise, with `jit_provisioning`, a verified account is created, outcome `provisioned`.
5. `on_sso_login` runs last for membership and role mapping, and may raise `SsoRejected`.

## Provider checks

Discovery `issuer` must match exactly. ID tokens must be RS, PS or ES signed by a JWKS key,
with `iss`, `aud`, `azp`, `exp` and the nonce checked. The RFC 9207 `iss` callback parameter
is required when the provider advertises it. The token endpoint uses `client_secret_basic`
unless the connection says `client_secret_post`.

`PublicUrlGuard` refuses provider URLs that are not HTTPS, carry credentials, or resolve to
any non-public address, so a tenant cannot point discovery at the metadata service. It
resolves before the request, so DNS rebinding between the check and the connect is not
covered; run the API without a route to private networks it should not reach. Pass
`trusted_hosts` only for a local test provider.

## Domain verification

```python
challenge = domain_verification_challenge(domain, token, prefix="example")
# TXT at challenge.record_name: challenge.record_value == "example-verification=<token>"
is_domain_verified(domain, token, prefix="example")
```

`new_domain_verification_token()` mints the token. `is_domain_verified` raises
`DomainVerificationUnavailable` when DNS cannot answer, so a timeout never revokes a domain.
Keeping a verified domain unique across tenants is the product's job.

## Testing

`tests/test_identity_sso.py` runs against a fake provider. The `sso-keycloak` CI job starts
Keycloak in dev mode and runs `tests/test_identity_sso_keycloak.py`, which skips unless
`KEYCLOAK_URL` is set. Free Okta and Entra developer tenants are checked by hand.
