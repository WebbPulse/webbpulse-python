"""Tests for the OAuth 2.1 authorization server: discovery, the code grant and its refusals."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from webbpulse.identity import (
    AUTHORIZATION_SERVER_METADATA_PATH,
    AUTHORIZE_PATH,
    PROTECTED_RESOURCE_METADATA_PATH,
    REGISTER_CLIENT_PATH,
    REVOKE_PATH,
    TOKEN_PATH,
    BaseIdentityHooks,
    IdentitySettings,
    IdentityStores,
    InMemoryAuthorizationCodeStore,
    InMemoryConsentStore,
    InMemoryCredentialStore,
    InMemoryOAuthClientStore,
    InMemoryRefreshTokenStore,
    OAuthClientRecord,
    OAuthServerError,
    OAuthServerService,
    OAuthServerStores,
    TenantChoice,
    TokenService,
    build_identity_router,
    identity_prefix,
    new_pkce_verifier,
    pkce_challenge,
    validate_redirect_uri,
)
from webbpulse.identity.oauth_server import CONSENT_PATH
from webbpulse.identity.tokens import DISCOVERY_PATH

if TYPE_CHECKING:
    from collections.abc import Sequence

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
ISSUER = "https://api.staging.example.com/api/auth"
AUDIENCE = "webbpulse-staging"
RESOURCE = "https://api.staging.example.com/mcp"
REDIRECT = "http://127.0.0.1:33418/callback"
TENANT = "workspace-1"
USER = "user-abc"


class Hooks(BaseIdentityHooks):
    """The smallest hooks class the router will mount its flows behind."""

    def load_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        """Every user id resolves, since these tests never branch on the user record."""
        return {"id": user_id, "email": "person@example.com", "email_verified": True}

    def claims_for(self, user: Any) -> dict[str, Any]:
        """No product claims, so the token carries only what the server puts there."""
        return {}


def build_settings(**overrides: Any) -> IdentitySettings:
    """An `IdentitySettings` with the authorization server turned on."""
    values: dict[str, Any] = {
        "environment": "test",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "signing_key_arns": [KEY_A],
        "mcp_oauth_enabled": True,
        "mcp_resource_url": RESOURCE,
        "mcp_clients": [{"client_id": "first-party", "redirect_uris": [REDIRECT]}],
    }
    values.update(overrides)
    return IdentitySettings(**values)


def build_stores() -> OAuthServerStores:
    """Fresh in-memory authorization server stores."""
    return OAuthServerStores(
        clients=InMemoryOAuthClientStore(),
        codes=InMemoryAuthorizationCodeStore(),
        consents=InMemoryConsentStore(),
    )


def tenants_for(user_id: str) -> Sequence[TenantChoice]:
    """One workspace for every user, which is all the consent step needs to bind to."""
    return [TenantChoice(id=TENANT, name="Workspace One")]


@pytest.fixture
def service(fake_kms: Any) -> OAuthServerService:
    """An `OAuthServerService` over in-memory stores and a locally signing KMS stand-in."""
    settings = build_settings()
    return OAuthServerService(settings, build_stores(), TokenService(settings, fake_kms))


@pytest.fixture
def client(fake_kms: Any) -> TestClient:
    """A `TestClient` over an app mounting the identity router with the server enabled."""
    settings = build_settings()
    app = FastAPI()
    app.include_router(
        build_identity_router(
            settings,
            Hooks(),
            IdentityStores(
                credentials=InMemoryCredentialStore(),
                refresh_tokens=InMemoryRefreshTokenStore(),
            ),
            tokens=TokenService(settings, fake_kms),
            oauth_server_stores=build_stores(),
            tenant_resolver=tenants_for,
            limiter_enabled=False,
        )
    )
    return TestClient(app)


def signed_in(client: TestClient, fake_kms: Any) -> dict[str, str]:
    """An `Authorization` header for `USER`, as a signed-in browser would carry."""
    settings = build_settings()
    token = TokenService(settings, fake_kms).mint_access_token(USER)
    return {"Authorization": f"Bearer {token}"}


def authorize_params(verifier: str, **overrides: Any) -> dict[str, str]:
    """A complete, valid `/authorize` query, before any single field is broken."""
    params = {
        "response_type": "code",
        "client_id": "first-party",
        "redirect_uri": REDIRECT,
        "code_challenge": pkce_challenge(verifier),
        "code_challenge_method": "S256",
        "resource": RESOURCE,
        "scope": "mcp:read",
        "state": "opaque-state",
    }
    params.update(overrides)
    return params


class TestDiscovery:
    """The three documents a client reads before it can start a flow."""

    def test_authorization_server_metadata_shape(self, client: TestClient) -> None:
        """RFC 8414 metadata advertises only what this server honours."""
        prefix = identity_prefix(build_settings())
        body = client.get(f"{prefix}{AUTHORIZATION_SERVER_METADATA_PATH}").json()
        assert body["issuer"] == ISSUER
        assert body["authorization_endpoint"] == f"{ISSUER}{AUTHORIZE_PATH}"
        assert body["token_endpoint"] == f"{ISSUER}{TOKEN_PATH}"
        assert body["registration_endpoint"] == f"{ISSUER}{REGISTER_CLIENT_PATH}"
        assert body["code_challenge_methods_supported"] == ["S256"]
        assert body["response_types_supported"] == ["code"]
        assert body["token_endpoint_auth_methods_supported"] == ["none"]
        assert "token" not in body["response_types_supported"]

    def test_protected_resource_metadata_names_the_resource(self, client: TestClient) -> None:
        """RFC 9728 metadata points a client at this issuer for this resource."""
        prefix = identity_prefix(build_settings())
        body = client.get(f"{prefix}{PROTECTED_RESOURCE_METADATA_PATH}").json()
        assert body["resource"] == RESOURCE
        assert body["authorization_servers"] == [ISSUER]
        assert body["bearer_methods_supported"] == ["header"]

    def test_oidc_discovery_carries_the_endpoints_when_enabled(self, client: TestClient) -> None:
        """The existing OIDC document gains the authorization server's endpoints."""
        prefix = identity_prefix(build_settings())
        body = client.get(f"{prefix}{DISCOVERY_PATH}").json()
        assert body["authorization_endpoint"] == f"{ISSUER}{AUTHORIZE_PATH}"
        assert body["code_challenge_methods_supported"] == ["S256"]
        assert body["scopes_supported"] == ["mcp:read", "mcp:write"]
        assert body["issuer"] == ISSUER

    def test_oidc_discovery_is_untouched_when_disabled(self, fake_kms: Any) -> None:
        """A product that never turns the flag on serves exactly the document it always did."""
        settings = build_settings(mcp_oauth_enabled=False, mcp_resource_url="")
        app = FastAPI()
        app.include_router(build_identity_router(settings, tokens=TokenService(settings, fake_kms)))
        body = TestClient(app).get(f"{identity_prefix(settings)}{DISCOVERY_PATH}").json()
        assert "authorization_endpoint" not in body
        assert "registration_endpoint" not in body


class TestHappyPath:
    """One complete authorization code grant, from consent to a usable access token."""

    def test_code_exchanges_for_a_token_bound_to_the_resource(self, client: TestClient, fake_kms: Any) -> None:
        """The token carries the resource as `aud`, plus scope, client and tenant."""
        prefix = identity_prefix(build_settings())
        verifier = new_pkce_verifier()
        page = client.get(
            f"{prefix}{AUTHORIZE_PATH}",
            params=authorize_params(verifier),
            headers=signed_in(client, fake_kms),
        )
        assert page.status_code == 200
        assert "Allow" in page.text

        fields = _form_fields(page.text)
        fields["decision"] = "allow"
        fields["tenant_id"] = TENANT
        redirect = client.post(
            f"{prefix}{CONSENT_PATH}",
            data=fields,
            headers=signed_in(client, fake_kms),
            follow_redirects=False,
        )
        assert redirect.status_code == 303
        code, state = _code_from(redirect.headers["location"])
        assert state == "opaque-state"

        token = client.post(
            f"{prefix}{TOKEN_PATH}",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": "first-party",
                "redirect_uri": REDIRECT,
                "code_verifier": verifier,
                "resource": RESOURCE,
            },
        )
        assert token.status_code == 200
        body = token.json()
        assert body["token_type"] == "Bearer"
        assert body["scope"] == "mcp:read"

        settings = build_settings()
        claims = TokenService(settings, fake_kms).verify_access_token(body["access_token"], audience=RESOURCE)
        assert claims["aud"] == RESOURCE
        assert claims["sub"] == USER
        assert claims["scope"] == "mcp:read"
        assert claims["client_id"] == "first-party"
        assert claims[settings.mcp_tenant_claim] == TENANT

    def test_coerce_claims_reads_the_scope_unchanged(self, client: TestClient, fake_kms: Any) -> None:
        """The existing claim coercion splits this server's `scope` with no change to it."""
        from webbpulse.identity import coerce_claims

        settings = build_settings()
        claims = coerce_claims({"scope": "mcp:read mcp:write", "exp": "1700000000"})
        assert claims["scopes"] == ["mcp:read", "mcp:write"]
        assert claims["exp"] == 1700000000
        assert settings.mcp_tenant_claim == "tenant_id"

    def test_authorize_requires_a_signed_in_user(self, client: TestClient) -> None:
        """An anonymous authorization request is refused rather than shown a consent screen."""
        prefix = identity_prefix(build_settings())
        response = client.get(f"{prefix}{AUTHORIZE_PATH}", params=authorize_params(new_pkce_verifier()))
        assert response.status_code == 401
        assert response.json()["error"] == "login_required"


class TestRefusals:
    """Each way the grant is refused, driven through the service directly."""

    def test_pkce_mismatch_is_refused(self, service: OAuthServerService) -> None:
        """A verifier that does not hash to the stored challenge cannot redeem the code."""
        request = service.parse_authorization_request(authorize_params(new_pkce_verifier()))
        code = service.issue_code(request, user_id=USER, tenant_id=TENANT)
        with pytest.raises(OAuthServerError) as exc:
            service.exchange_code(
                {
                    "code": code,
                    "client_id": "first-party",
                    "redirect_uri": REDIRECT,
                    "code_verifier": new_pkce_verifier(),
                }
            )
        assert exc.value.error == "invalid_grant"

    def test_redirect_mismatch_is_refused(self, service: OAuthServerService) -> None:
        """A redirect URI differing from the one the code was issued for is refused."""
        verifier = new_pkce_verifier()
        request = service.parse_authorization_request(authorize_params(verifier))
        code = service.issue_code(request, user_id=USER, tenant_id=TENANT)
        with pytest.raises(OAuthServerError) as exc:
            service.exchange_code(
                {
                    "code": code,
                    "client_id": "first-party",
                    "redirect_uri": "http://127.0.0.1:33418/other",
                    "code_verifier": verifier,
                }
            )
        assert exc.value.error == "invalid_grant"

    def test_a_code_is_single_use(self, service: OAuthServerService) -> None:
        """The second exchange of the same code is refused, whatever it carries."""
        verifier = new_pkce_verifier()
        request = service.parse_authorization_request(authorize_params(verifier))
        code = service.issue_code(request, user_id=USER, tenant_id=TENANT)
        params = {
            "code": code,
            "client_id": "first-party",
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
        }
        assert service.exchange_code(params)["access_token"]
        with pytest.raises(OAuthServerError) as exc:
            service.exchange_code(params)
        assert exc.value.error == "invalid_grant"

    def test_a_failed_exchange_still_burns_the_code(self, service: OAuthServerService) -> None:
        """A wrong verifier spends the code, so an attacker gets no second guess at it."""
        verifier = new_pkce_verifier()
        request = service.parse_authorization_request(authorize_params(verifier))
        code = service.issue_code(request, user_id=USER, tenant_id=TENANT)
        with pytest.raises(OAuthServerError):
            service.exchange_code(
                {
                    "code": code,
                    "client_id": "first-party",
                    "redirect_uri": REDIRECT,
                    "code_verifier": new_pkce_verifier(),
                }
            )
        with pytest.raises(OAuthServerError) as exc:
            service.exchange_code(
                {
                    "code": code,
                    "client_id": "first-party",
                    "redirect_uri": REDIRECT,
                    "code_verifier": verifier,
                }
            )
        assert exc.value.error == "invalid_grant"

    def test_an_expired_code_is_refused(self, service: OAuthServerService) -> None:
        """A code past its TTL is refused even though the row is still readable."""
        verifier = new_pkce_verifier()
        request = service.parse_authorization_request(authorize_params(verifier))
        past = int(time.time()) - 3600
        code = service.issue_code(request, user_id=USER, tenant_id=TENANT, now=past)
        with pytest.raises(OAuthServerError) as exc:
            service.exchange_code(
                {
                    "code": code,
                    "client_id": "first-party",
                    "redirect_uri": REDIRECT,
                    "code_verifier": verifier,
                }
            )
        assert exc.value.error == "invalid_grant"

    def test_resource_mismatch_is_refused_at_authorize(self, service: OAuthServerService) -> None:
        """A `resource` naming something this server does not protect never gets a code."""
        with pytest.raises(OAuthServerError) as exc:
            service.parse_authorization_request(
                authorize_params(new_pkce_verifier(), resource="https://other.example.com/mcp")
            )
        assert exc.value.error == "invalid_target"

    def test_a_missing_resource_is_refused(self, service: OAuthServerService) -> None:
        """RFC 8707's `resource` is required, so every token has exactly one audience."""
        params = authorize_params(new_pkce_verifier())
        del params["resource"]
        with pytest.raises(OAuthServerError) as exc:
            service.parse_authorization_request(params)
        assert exc.value.error == "invalid_target"

    def test_resource_mismatch_is_refused_at_token(self, service: OAuthServerService) -> None:
        """A resource swapped between authorization and exchange is caught at the exchange."""
        verifier = new_pkce_verifier()
        request = service.parse_authorization_request(authorize_params(verifier))
        code = service.issue_code(request, user_id=USER, tenant_id=TENANT)
        with pytest.raises(OAuthServerError) as exc:
            service.exchange_code(
                {
                    "code": code,
                    "client_id": "first-party",
                    "redirect_uri": REDIRECT,
                    "code_verifier": verifier,
                    "resource": "https://other.example.com/mcp",
                }
            )
        assert exc.value.error == "invalid_target"

    def test_an_unregistered_client_is_refused(self, service: OAuthServerService) -> None:
        """A client id nothing registered cannot start a flow."""
        with pytest.raises(OAuthServerError) as exc:
            service.parse_authorization_request(authorize_params(new_pkce_verifier(), client_id="never-registered"))
        assert exc.value.error == "invalid_client"

    def test_plain_pkce_is_refused(self, service: OAuthServerService) -> None:
        """`plain` is not a proof of possession, so only `S256` is accepted."""
        with pytest.raises(OAuthServerError) as exc:
            service.parse_authorization_request(authorize_params(new_pkce_verifier(), code_challenge_method="plain"))
        assert exc.value.error == "invalid_request"

    def test_a_missing_challenge_is_refused(self, service: OAuthServerService) -> None:
        """PKCE is required, so an authorization request without a challenge is refused."""
        params = authorize_params(new_pkce_verifier())
        del params["code_challenge"]
        with pytest.raises(OAuthServerError) as exc:
            service.parse_authorization_request(params)
        assert exc.value.error == "invalid_request"

    def test_the_implicit_grant_is_not_offered(self, service: OAuthServerService) -> None:
        """`response_type=token` is refused rather than quietly treated as a code request."""
        with pytest.raises(OAuthServerError) as exc:
            service.parse_authorization_request(authorize_params(new_pkce_verifier(), response_type="token"))
        assert exc.value.error == "unsupported_response_type"

    def test_an_unsupported_scope_is_refused_not_narrowed(self, service: OAuthServerService) -> None:
        """An unknown scope is a refusal, so a client never believes it holds one it does not."""
        with pytest.raises(OAuthServerError) as exc:
            service.parse_authorization_request(authorize_params(new_pkce_verifier(), scope="mcp:read admin:all"))
        assert exc.value.error == "invalid_scope"

    def test_a_redirect_uri_outside_the_allow_list_is_refused(self, service: OAuthServerService) -> None:
        """Only an exactly registered redirect URI is accepted, never a lookalike."""
        with pytest.raises(OAuthServerError) as exc:
            service.parse_authorization_request(
                authorize_params(new_pkce_verifier(), redirect_uri="https://attacker.test/callback")
            )
        assert exc.value.error == "invalid_request"


class TestRegistration:
    """Dynamic client registration, and the shapes it will not accept."""

    def test_a_public_client_registers(self, client: TestClient) -> None:
        """A public PKCE client gets a client id and no secret at all."""
        prefix = identity_prefix(build_settings())
        response = client.post(
            f"{prefix}{REGISTER_CLIENT_PATH}",
            json={"redirect_uris": [REDIRECT], "client_name": "Some Editor"},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["client_id"].startswith("mcp_")
        assert body["token_endpoint_auth_method"] == "none"
        assert "client_secret" not in body

    def test_a_confidential_client_is_refused(self, client: TestClient) -> None:
        """Asking for a client secret is refused rather than silently downgraded."""
        prefix = identity_prefix(build_settings())
        response = client.post(
            f"{prefix}{REGISTER_CLIENT_PATH}",
            json={"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "client_secret_basic"},
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_client_metadata"

    def test_a_registered_client_can_then_authorize(self, client: TestClient, fake_kms: Any) -> None:
        """A registration is immediately usable, which a non-consistent read would break."""
        prefix = identity_prefix(build_settings())
        client_id = client.post(f"{prefix}{REGISTER_CLIENT_PATH}", json={"redirect_uris": [REDIRECT]}).json()[
            "client_id"
        ]
        page = client.get(
            f"{prefix}{AUTHORIZE_PATH}",
            params=authorize_params(new_pkce_verifier(), client_id=client_id),
            headers=signed_in(client, fake_kms),
        )
        assert page.status_code == 200

    def test_registration_can_be_closed(self, fake_kms: Any) -> None:
        """A deployment that pre-registers everything can shut the open endpoint."""
        settings = build_settings(mcp_registration_enabled=False)
        app = FastAPI()
        app.include_router(
            build_identity_router(
                settings,
                tokens=TokenService(settings, fake_kms),
                oauth_server_stores=build_stores(),
                limiter_enabled=False,
            )
        )
        response = TestClient(app).post(
            f"{identity_prefix(settings)}{REGISTER_CLIENT_PATH}",
            json={"redirect_uris": [REDIRECT]},
        )
        assert response.status_code == 403

    @pytest.mark.parametrize(
        "uri",
        [
            "https://app.example.com/callback",
            "http://127.0.0.1:1234/cb",
            "http://localhost:9999/cb",
            "http://[::1]:8080/cb",
        ],
    )
    def test_allowed_redirect_uris(self, uri: str) -> None:
        """https anywhere, and plaintext http only on a loopback address."""
        assert validate_redirect_uri(uri) == uri

    @pytest.mark.parametrize(
        "uri",
        [
            "http://app.example.com/callback",
            "https://app.example.com/cb#fragment",
            "ftp://example.com/cb",
            "not-a-uri",
        ],
    )
    def test_refused_redirect_uris(self, uri: str) -> None:
        """Plaintext http off loopback, a fragment, and anything not an absolute http(s) URI."""
        with pytest.raises(OAuthServerError):
            validate_redirect_uri(uri)


class TestConsent:
    """The consent step, and what it binds the resulting token to."""

    def test_the_form_is_bound_to_the_request_it_approves(self, client: TestClient, fake_kms: Any) -> None:
        """A scope edited in the browser invalidates the signature and is refused."""
        prefix = identity_prefix(build_settings())
        verifier = new_pkce_verifier()
        page = client.get(
            f"{prefix}{AUTHORIZE_PATH}",
            params=authorize_params(verifier),
            headers=signed_in(client, fake_kms),
        )
        fields = _form_fields(page.text)
        fields["scope"] = "mcp:read mcp:write"
        fields["decision"] = "allow"
        fields["tenant_id"] = TENANT
        response = client.post(
            f"{prefix}{CONSENT_PATH}",
            data=fields,
            headers=signed_in(client, fake_kms),
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    def test_a_denial_redirects_with_access_denied(self, client: TestClient, fake_kms: Any) -> None:
        """Declining sends the client the RFC 6749 error rather than a code."""
        prefix = identity_prefix(build_settings())
        page = client.get(
            f"{prefix}{AUTHORIZE_PATH}",
            params=authorize_params(new_pkce_verifier()),
            headers=signed_in(client, fake_kms),
        )
        fields = _form_fields(page.text)
        fields["decision"] = "deny"
        fields["tenant_id"] = TENANT
        response = client.post(
            f"{prefix}{CONSENT_PATH}",
            data=fields,
            headers=signed_in(client, fake_kms),
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "error=access_denied" in response.headers["location"]
        assert "code=" not in response.headers["location"]

    def test_a_tenant_the_user_does_not_hold_is_refused(self, client: TestClient, fake_kms: Any) -> None:
        """The tenant is checked against the resolver, not taken from the posted form."""
        prefix = identity_prefix(build_settings())
        page = client.get(
            f"{prefix}{AUTHORIZE_PATH}",
            params=authorize_params(new_pkce_verifier()),
            headers=signed_in(client, fake_kms),
        )
        fields = _form_fields(page.text)
        fields["decision"] = "allow"
        fields["tenant_id"] = "someone-elses-workspace"
        response = client.post(
            f"{prefix}{CONSENT_PATH}",
            data=fields,
            headers=signed_in(client, fake_kms),
            follow_redirects=False,
        )
        assert response.status_code == 400

    def test_a_custom_renderer_replaces_the_screen(self, fake_kms: Any) -> None:
        """A product restyles consent without reimplementing the binding it carries."""
        from fastapi.responses import HTMLResponse

        from webbpulse.identity.oauth_server import ConsentContext

        seen: list[ConsentContext] = []

        def render(context: ConsentContext) -> HTMLResponse:
            """Record the context and answer with the product's own markup."""
            seen.append(context)
            return HTMLResponse("<p>product consent</p>")

        settings = build_settings()
        app = FastAPI()
        app.include_router(
            build_identity_router(
                settings,
                Hooks(),
                IdentityStores(credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()),
                tokens=TokenService(settings, fake_kms),
                oauth_server_stores=build_stores(),
                consent_renderer=render,
                tenant_resolver=tenants_for,
                limiter_enabled=False,
            )
        )
        test_client = TestClient(app)
        response = test_client.get(
            f"{identity_prefix(settings)}{AUTHORIZE_PATH}",
            params=authorize_params(new_pkce_verifier()),
            headers=signed_in(test_client, fake_kms),
        )
        assert response.text == "<p>product consent</p>"
        assert seen[0].tenants == (TenantChoice(id=TENANT, name="Workspace One"),)
        assert seen[0].user_id == USER

    def test_the_consent_screen_escapes_a_client_name(self, client: TestClient, fake_kms: Any) -> None:
        """A client name comes from an open endpoint, so it is escaped before rendering."""
        prefix = identity_prefix(build_settings())
        client_id = client.post(
            f"{prefix}{REGISTER_CLIENT_PATH}",
            json={"redirect_uris": [REDIRECT], "client_name": "<script>alert(1)</script>"},
        ).json()["client_id"]
        page = client.get(
            f"{prefix}{AUTHORIZE_PATH}",
            params=authorize_params(new_pkce_verifier(), client_id=client_id),
            headers=signed_in(client, fake_kms),
        )
        assert "<script>alert(1)</script>" not in page.text
        assert "&lt;script&gt;" in page.text


class TestTokenEndpoint:
    """What the token endpoint does beyond the code grant."""

    def test_an_unknown_grant_type_is_refused(self, client: TestClient) -> None:
        """Only the two advertised grant types are accepted."""
        prefix = identity_prefix(build_settings())
        response = client.post(f"{prefix}{TOKEN_PATH}", data={"grant_type": "password"})
        assert response.status_code == 400
        assert response.json()["error"] == "unsupported_grant_type"

    def test_the_token_response_is_never_cached(self, client: TestClient, fake_kms: Any) -> None:
        """A cached token response would leak a bearer token to the next reader of the cache."""
        prefix = identity_prefix(build_settings())
        response = client.post(f"{prefix}{TOKEN_PATH}", data={"grant_type": "password"})
        assert response.headers["cache-control"] == "no-store"

    def test_revocation_accepts_an_unknown_token(self, client: TestClient) -> None:
        """RFC 7009 requires a 200 either way, so the endpoint is not a token oracle."""
        prefix = identity_prefix(build_settings())
        response = client.post(f"{prefix}{REVOKE_PATH}", data={"token": "never-issued"})
        assert response.status_code == 200


class TestSettings:
    """The settings the flag brings with it, and what they refuse."""

    def test_the_flag_needs_a_resource_url(self) -> None:
        """An authorization server with no resource could not bind an audience."""
        with pytest.raises(ValueError, match="mcp_resource_url"):
            build_settings(mcp_resource_url="")

    def test_a_plaintext_resource_is_refused_outside_local(self) -> None:
        """A bearer token bound to an http resource is readable on the path to it."""
        with pytest.raises(ValueError, match="plaintext http"):
            build_settings(environment="production", mcp_resource_url="http://api.example.com/mcp")

    def test_a_registered_claim_cannot_hold_the_tenant(self) -> None:
        """`mint_access_token` drops registered claims, so the tenant would vanish."""
        with pytest.raises(ValueError, match="registered JWT claim"):
            build_settings(mcp_tenant_claim="sub")

    def test_a_long_code_ttl_is_refused(self) -> None:
        """A code is redeemed within seconds, so a long life is only an interception window."""
        with pytest.raises(ValueError, match="exceeds the"):
            build_settings(mcp_authorization_code_ttl="PT30M")

    def test_the_flag_needs_its_stores(self, fake_kms: Any) -> None:
        """Advertising endpoints that then answer 404 is worse than failing at startup."""
        settings = build_settings()
        with pytest.raises(ValueError, match="oauth_server_stores"):
            build_identity_router(settings, tokens=TokenService(settings, fake_kms))


class TestClientStore:
    """The client store's TTL behaviour, which is what keeps an open endpoint bounded."""

    def test_an_expired_dynamic_client_is_gone(self) -> None:
        """A registration nothing ever used is reclaimed."""
        store = InMemoryOAuthClientStore()
        store.put(
            OAuthClientRecord(
                client_id="stale",
                redirect_uris=(REDIRECT,),
                expires_at=int(time.time()) - 60,
            )
        )
        assert store.get("stale") is None

    def test_a_first_party_client_never_expires(self) -> None:
        """A settings-declared client carries no TTL and is not touched by one."""
        store = InMemoryOAuthClientStore()
        store.put(OAuthClientRecord(client_id="first-party", redirect_uris=(REDIRECT,), first_party=True))
        store.touch("first-party", expires_at=int(time.time()) - 60)
        record = store.get("first-party")
        assert record is not None
        assert record.expires_at == 0


def _form_fields(html: str) -> dict[str, str]:
    """Pull the hidden inputs out of the rendered consent form."""
    import re

    fields: dict[str, str] = {}
    for match in re.finditer(r'<input type="hidden" name="([^"]*)" value="([^"]*)">', html):
        import html as html_module

        fields[match.group(1)] = html_module.unescape(match.group(2))
    return fields


def _code_from(location: str) -> tuple[str, str]:
    """Read the `code` and `state` back off a redirect to the client."""
    from urllib.parse import parse_qs, urlsplit

    query = parse_qs(urlsplit(location).query)
    return query["code"][0], query.get("state", [""])[0]
