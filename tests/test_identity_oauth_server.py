"""Tests for the OAuth 2.1 authorization server: discovery, the code grant and its refusals."""

from __future__ import annotations

import time
from dataclasses import replace
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
    ConsentPalette,
    ConsentRecord,
    ConsentTheme,
    FontFace,
    IdentityFlows,
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
    ScopeLabel,
    TenantChoice,
    TokenService,
    build_consent_renderer,
    build_identity_router,
    describe_scopes,
    identity_prefix,
    new_pkce_verifier,
    pkce_challenge,
    validate_redirect_uri,
)
from webbpulse.identity.consent_page import DARK_PALETTE, consent_security_policy, render_consent_page
from webbpulse.identity.oauth_server import CONSENT_PATH, AuthorizationRequest, ConsentContext
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


def _service_with_refresh(fake_kms: Any) -> tuple[OAuthServerService, OAuthServerStores, InMemoryRefreshTokenStore]:
    """An `OAuthServerService` with flows, so a granted code also starts a refresh family."""
    settings = build_settings()
    tokens = TokenService(settings, fake_kms)
    refresh_tokens = InMemoryRefreshTokenStore()
    flows = IdentityFlows(
        settings,
        Hooks(),
        IdentityStores(credentials=InMemoryCredentialStore(), refresh_tokens=refresh_tokens),
        tokens,
    )
    stores = build_stores()
    return OAuthServerService(settings, stores, tokens, flows=flows), stores, refresh_tokens


def _grant(service: OAuthServerService, *, tenant_id: str = TENANT) -> dict[str, Any]:
    """Consent, issue and exchange one code for `USER`, returning the token response."""
    verifier = new_pkce_verifier()
    request = service.parse_authorization_request(authorize_params(verifier))
    service.record_consent(request, user_id=USER, tenant_id=tenant_id)
    code = service.issue_code(request, user_id=USER, tenant_id=tenant_id)
    return service.exchange_code(
        {"code": code, "client_id": "first-party", "redirect_uri": REDIRECT, "code_verifier": verifier}
    )


def _refresh(service: OAuthServerService, token: str) -> dict[str, Any]:
    """Rotate a refresh token for the first-party client."""
    return service.refresh({"refresh_token": token, "client_id": "first-party", "scope": "mcp:read"})


class TestAuthorizationRevocation:
    """Withdrawing a grant ends the client's refresh, so it must authorize again."""

    def test_a_refresh_stamps_the_consent_as_used(self, fake_kms: Any) -> None:
        """A refresh continues the grant and records when it last did."""
        service, stores, _ = _service_with_refresh(fake_kms)
        body = _grant(service)
        stores.consents.put(_replace_last_used(_only_consent(stores), ""))

        refreshed = _refresh(service, body["refresh_token"])

        assert refreshed["refresh_token"]
        assert _only_consent(stores).last_used_at

    def test_revoking_deletes_the_consent_and_ends_refresh(self, fake_kms: Any) -> None:
        """After revocation the refresh token is refused and its family is revoked."""
        service, stores, refresh_tokens = _service_with_refresh(fake_kms)
        body = _grant(service)

        result = service.revoke_authorization(USER, "first-party")

        assert len(result.consents) == 1
        assert result.refresh_records_revoked == 1
        assert stores.consents.list_for_user(USER) == []
        assert all(record.revoked for record in refresh_tokens._items.values())
        with pytest.raises(OAuthServerError) as exc:
            _refresh(service, body["refresh_token"])
        assert exc.value.error == "invalid_grant"

    def test_a_refresh_with_no_consent_is_refused_and_its_family_revoked(self, fake_kms: Any) -> None:
        """A consent deleted out of band still ends the grant at the next refresh."""
        service, stores, refresh_tokens = _service_with_refresh(fake_kms)
        body = _grant(service)
        stores.consents.delete(_only_consent(stores).consent_id)

        with pytest.raises(OAuthServerError) as exc:
            _refresh(service, body["refresh_token"])

        assert exc.value.error == "invalid_grant"
        assert all(record.revoked for record in refresh_tokens._items.values())

    def test_a_tenant_scoped_revocation_ends_only_that_tenants_family(self, fake_kms: Any) -> None:
        """Revoking one tenant's grant ends its family and leaves the other tenant's live."""
        service, stores, _ = _service_with_refresh(fake_kms)
        other = _grant(service, tenant_id="workspace-2")
        body = _grant(service)

        result = service.revoke_authorization(USER, "first-party", tenant_id=TENANT)

        assert [record.tenant_id for record in result.consents] == [TENANT]
        assert result.refresh_records_revoked == 1
        assert [record.tenant_id for record in stores.consents.list_for_user(USER)] == ["workspace-2"]
        with pytest.raises(OAuthServerError):
            _refresh(service, body["refresh_token"])
        refreshed = _refresh(service, other["refresh_token"])
        assert _tenant_claim(fake_kms, refreshed) == "workspace-2"

    def test_a_family_never_moves_to_another_tenant(self, fake_kms: Any) -> None:
        """With its own tenant's consent gone, a family is refused even though another grant exists."""
        service, stores, refresh_tokens = _service_with_refresh(fake_kms)
        _grant(service, tenant_id="workspace-2")
        body = _grant(service)
        tenant_grant = next(record for record in stores.consents.list_for_user(USER) if record.tenant_id == TENANT)
        stores.consents.delete(tenant_grant.consent_id)

        with pytest.raises(OAuthServerError) as exc:
            _refresh(service, body["refresh_token"])

        assert exc.value.error == "invalid_grant"
        assert all(
            record.revoked for record in refresh_tokens._items.values() if record.device == f"mcp:first-party:{TENANT}"
        )

    def test_a_family_started_before_tenant_binding_falls_back_to_any_grant(self, fake_kms: Any) -> None:
        """A family labelled with the client alone keeps refreshing under the grant the user holds."""
        service, stores, _ = _service_with_refresh(fake_kms)
        _grant(service, tenant_id="workspace-2")
        legacy = _legacy_family(service)

        refreshed = _refresh(service, legacy)

        assert _tenant_claim(fake_kms, refreshed) == "workspace-2"
        assert _only_consent(stores).last_used_at

    def test_revoking_every_tenant_ends_tenant_bound_and_legacy_families(self, fake_kms: Any) -> None:
        """An unscoped revocation reaches each tenant's family and the pre-binding one."""
        service, _, refresh_tokens = _service_with_refresh(fake_kms)
        first = _grant(service)
        second = _grant(service, tenant_id="workspace-2")
        legacy = _legacy_family(service)

        result = service.revoke_authorization(USER, "first-party")

        assert result.refresh_records_revoked == 3
        assert all(record.revoked for record in refresh_tokens._items.values())
        for token in (first["refresh_token"], second["refresh_token"], legacy):
            with pytest.raises(OAuthServerError):
                _refresh(service, token)

    def test_a_family_started_for_another_client_is_refused(self, fake_kms: Any) -> None:
        """A refresh token from a browser session or another client continues no grant."""
        service, _, _ = _service_with_refresh(fake_kms)
        _grant(service)
        assert service._flows is not None
        stray = service._flows.sessions.start_family(USER, device="firefox").token

        with pytest.raises(OAuthServerError) as exc:
            _refresh(service, stray)

        assert exc.value.error == "invalid_grant"

    def test_a_revocation_racing_the_stamp_is_not_undone(self, fake_kms: Any) -> None:
        """A consent deleted between the refresh's read and its stamp stays deleted."""
        service, stores, _ = _service_with_refresh(fake_kms)
        body = _grant(service)
        consents = stores.consents
        read = consents.list_for_client

        def read_then_revoke(user_id: str, client_id: str) -> list[ConsentRecord]:
            """Return the grants, then delete them before the caller stamps one."""
            grants = read(user_id, client_id)
            for grant in grants:
                consents.delete(grant.consent_id)
            return grants

        consents.list_for_client = read_then_revoke  # type: ignore[method-assign]

        with pytest.raises(OAuthServerError) as exc:
            _refresh(service, body["refresh_token"])

        assert exc.value.error == "invalid_grant"
        assert consents.list_for_user(USER) == []

    def test_revoking_an_unknown_client_is_a_no_op(self, fake_kms: Any) -> None:
        """Nothing granted means nothing deleted and nothing revoked."""
        service, _, _ = _service_with_refresh(fake_kms)

        result = service.revoke_authorization(USER, "never-authorized")

        assert result.consents == ()
        assert result.refresh_records_revoked == 0

    def test_re_authorizing_replaces_the_grant_rather_than_adding_one(self, fake_kms: Any) -> None:
        """A second consent in the same tenant keeps one row and its first grant time."""
        service, stores, _ = _service_with_refresh(fake_kms)
        request = service.parse_authorization_request(authorize_params(new_pkce_verifier()))
        first = service.record_consent(request, user_id=USER, tenant_id=TENANT, now=1_700_000_000)
        second = service.record_consent(request, user_id=USER, tenant_id=TENANT, now=1_700_000_100)

        assert second.consent_id == first.consent_id
        assert second.granted_at == first.granted_at
        assert second.updated_at != first.updated_at
        assert len(stores.consents.list_for_user(USER)) == 1


class TestConsentStoreHelpers:
    """The concrete helpers every `ConsentStore` inherits from the abstract four."""

    def _seed(self) -> InMemoryConsentStore:
        """Three grants: two clients in one tenant, and one client in a second tenant."""
        store = InMemoryConsentStore()
        for consent_id, client_id, tenant_id in (
            ("c1", "client-a", "t1"),
            ("c2", "client-b", "t1"),
            ("c3", "client-a", "t2"),
        ):
            store.put(
                ConsentRecord(
                    consent_id=consent_id,
                    user_id=USER,
                    client_id=client_id,
                    tenant_id=tenant_id,
                    resource=RESOURCE,
                    scopes=("mcp:read",),
                    granted_at="2026-09-26T00:00:00Z",
                )
            )
        return store

    def test_list_for_client(self) -> None:
        """Grants to one client across tenants."""
        store = self._seed()
        assert sorted(record.consent_id for record in store.list_for_client(USER, "client-a")) == ["c1", "c3"]

    def test_delete_for_client_in_one_tenant(self) -> None:
        """A tenant filter narrows the delete to that tenant's grant."""
        store = self._seed()
        deleted = store.delete_for_client(USER, "client-a", tenant_id="t1")
        assert [record.consent_id for record in deleted] == ["c1"]
        assert store.get("c3") is not None

    def test_mark_used_touches_only_a_present_row(self) -> None:
        """A present consent is stamped, and an absent one is reported and not written back."""
        store = self._seed()
        assert store.mark_used("c1", "2026-09-26T01:00:00Z")
        assert store.get("c1") is not None
        assert store.get("c1").last_used_at == "2026-09-26T01:00:00Z"  # type: ignore[union-attr]
        store.delete("c1")
        assert not store.mark_used("c1", "2026-09-26T02:00:00Z")
        assert store.get("c1") is None

    def test_delete_for_tenant(self) -> None:
        """Every client's grant in one tenant goes, and the other tenant's stays."""
        store = self._seed()
        deleted = store.delete_for_tenant(USER, "t1")
        assert sorted(record.consent_id for record in deleted) == ["c1", "c2"]
        assert [record.consent_id for record in store.list_for_user(USER)] == ["c3"]


def _legacy_family(service: OAuthServerService) -> str:
    """Start a family labelled the way families were before they carried their tenant."""
    assert service._flows is not None
    return service._flows.sessions.start_family(USER, device="mcp:first-party").token


def _tenant_claim(fake_kms: Any, body: dict[str, Any]) -> str:
    """The tenant claim on the access token in a token response."""
    claims = TokenService(build_settings(), fake_kms).verify_access_token(body["access_token"], audience=RESOURCE)
    return str(claims["tenant_id"])


def _only_consent(stores: OAuthServerStores) -> ConsentRecord:
    """The single consent `USER` holds."""
    grants = stores.consents.list_for_user(USER)
    assert len(grants) == 1
    return grants[0]


def _replace_last_used(record: ConsentRecord, value: str) -> ConsentRecord:
    """A copy of `record` with `last_used_at` set to `value`."""
    import dataclasses

    return dataclasses.replace(record, last_used_at=value)


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


LOGIN_URL = "https://app.staging.example.com/login"


class CookieHooks(Hooks):
    """Hooks for the cookie path, which also consults `may_authenticate`."""

    def __init__(self, refused: frozenset[str] = frozenset(), missing: frozenset[str] = frozenset()) -> None:
        """Record which user ids are refused and which no longer exist."""
        self.refused = refused
        self.missing = missing

    def load_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        """Every user resolves unless it is listed as missing."""
        return None if user_id in self.missing else super().load_user_by_id(user_id)

    def may_authenticate(self, user: Any) -> None:
        """Refuse the listed users, as a product would a disabled account."""
        from webbpulse.identity import AuthenticationRefused

        if user["id"] in self.refused:
            raise AuthenticationRefused("disabled")


class Browser:
    """A test client whose only credential is the refresh cookie, as a browser tab has."""

    def __init__(self, fake_kms: Any, *, hooks: CookieHooks | None = None, **overrides: Any) -> None:
        """Mount the identity router over in-memory stores built from `overrides`."""
        from webbpulse.identity import SessionService

        self.settings = build_settings(**overrides)
        self.store = InMemoryRefreshTokenStore()
        self.sessions = SessionService(self.settings, self.store)
        self.oauth_stores = build_stores()
        self.prefix = identity_prefix(self.settings)
        app = FastAPI()
        app.include_router(
            build_identity_router(
                self.settings,
                hooks or CookieHooks(),
                IdentityStores(credentials=InMemoryCredentialStore(), refresh_tokens=self.store),
                tokens=TokenService(self.settings, fake_kms),
                oauth_server_stores=self.oauth_stores,
                tenant_resolver=tenants_for,
                limiter_enabled=False,
            )
        )
        self.client = TestClient(app, base_url="https://api.staging.example.com")

    def sign_in(self, user_id: str = USER, *, auth_time: int | None = None) -> str:
        """Start a refresh family and hold its token as the cookie; return the token."""
        issued = self.sessions.start_family(user_id, device="browser", auth_time=auth_time)
        self.client.cookies.set(self.settings.cookie_name, issued.token)
        return issued.token

    def snapshot(self) -> dict[str, Any]:
        """Every stored refresh record, to prove a request wrote nothing."""
        return dict(self.store._items)

    def authorize(self, verifier: str = "", **overrides: Any) -> Any:
        """GET `/authorize` with a valid request, without following redirects."""
        return self.client.get(
            f"{self.prefix}{AUTHORIZE_PATH}",
            params=authorize_params(verifier or new_pkce_verifier(), **overrides),
            follow_redirects=False,
        )

    def consent(self, fields: dict[str, str], headers: dict[str, str] | None = None) -> Any:
        """POST the consent form, without following redirects."""
        return self.client.post(
            f"{self.prefix}{CONSENT_PATH}", data=fields, headers=headers or {}, follow_redirects=False
        )


class TestCookieSignIn:
    """A browser opened by an MCP client carries only the refresh cookie, never a bearer."""

    def test_the_cookie_alone_renders_consent(self, fake_kms: Any) -> None:
        """A live refresh family is enough to show the consent screen."""
        browser = Browser(fake_kms)
        browser.sign_in()
        response = browser.authorize()
        assert response.status_code == 200
        assert "signature" in _form_fields(response.text)

    def test_the_cookie_completes_a_grant(self, fake_kms: Any) -> None:
        """Consent posted with the cookie issues a code the client can exchange."""
        browser = Browser(fake_kms)
        browser.sign_in()
        verifier = new_pkce_verifier()
        fields = _form_fields(browser.authorize(verifier).text)
        fields.update(decision="allow", tenant_id=TENANT)
        response = browser.consent(fields, headers={"Sec-Fetch-Site": "same-origin"})
        assert response.status_code == 303
        code, state = _code_from(response.headers["location"])
        assert state == "opaque-state"
        token = browser.client.post(
            f"{browser.prefix}{TOKEN_PATH}",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "client_id": "first-party",
                "redirect_uri": REDIRECT,
                "resource": RESOURCE,
            },
        )
        assert token.status_code == 200
        assert token.json()["access_token"]

    def test_authorize_and_consent_write_nothing_to_the_refresh_store(self, fake_kms: Any) -> None:
        """The cookie is read, never rotated, touched or consumed."""
        browser = Browser(fake_kms)
        presented = browser.sign_in()
        before = browser.snapshot()
        fields = _form_fields(browser.authorize().text)
        fields.update(decision="allow", tenant_id=TENANT)
        assert browser.consent(fields).status_code == 303
        assert browser.snapshot() == before
        assert browser.sessions.rotate(presented).ok

    def test_a_revoked_family_is_refused_and_left_alone(self, fake_kms: Any) -> None:
        """A signed-out family cannot authorize, and reading it changes nothing."""
        browser = Browser(fake_kms)
        presented = browser.sign_in()
        browser.sessions.revoke_family(browser.sessions.family_of(presented))
        before = browser.snapshot()
        response = browser.authorize()
        assert response.status_code == 401
        assert response.json()["error"] == "login_required"
        assert browser.snapshot() == before

    def test_a_rotated_out_token_is_refused_without_reuse_detection(self, fake_kms: Any) -> None:
        """An old generation is refused, and presenting it does not revoke the family."""
        browser = Browser(fake_kms)
        old = browser.sign_in()
        successor = browser.sessions.rotate(old)
        assert successor.issued is not None
        before = browser.snapshot()
        assert browser.authorize().status_code == 401
        assert browser.snapshot() == before
        browser.client.cookies.set(browser.settings.cookie_name, successor.issued.token)
        assert browser.authorize().status_code == 200

    def test_an_unknown_cookie_is_refused(self, fake_kms: Any) -> None:
        """A cookie that names no stored record is the same as none."""
        browser = Browser(fake_kms)
        browser.client.cookies.set(browser.settings.cookie_name, "not-a-real-token")
        assert browser.authorize().status_code == 401

    def test_a_refused_user_cannot_authorize_by_cookie(self, fake_kms: Any) -> None:
        """`may_authenticate` is consulted, as a refresh would, and its refusal holds."""
        browser = Browser(fake_kms, hooks=CookieHooks(refused=frozenset({USER})))
        browser.sign_in()
        assert browser.authorize().status_code == 401

    def test_a_deleted_user_cannot_authorize_by_cookie(self, fake_kms: Any) -> None:
        """A family outliving its user resolves to nobody."""
        browser = Browser(fake_kms, hooks=CookieHooks(missing=frozenset({USER})))
        browser.sign_in()
        assert browser.authorize().status_code == 401

    def test_the_bearer_wins_over_the_cookie(self, fake_kms: Any) -> None:
        """A request carrying both is the bearer's user, as every other route treats it."""
        browser = Browser(fake_kms)
        browser.sign_in("someone-else")
        response = browser.client.get(
            f"{browser.prefix}{AUTHORIZE_PATH}",
            params=authorize_params(new_pkce_verifier()),
            headers=signed_in(browser.client, fake_kms),
        )
        assert response.status_code == 200
        fields = _form_fields(response.text)
        fields.update(decision="allow", tenant_id=TENANT)
        assert browser.consent(fields).status_code == 400


class TestConsentBinding:
    """The consent form is bound to the user it was shown to, and to this origin."""

    def test_a_form_signed_for_another_user_is_refused(self, fake_kms: Any) -> None:
        """A form minted in one account's session cannot be posted into another's."""
        browser = Browser(fake_kms)
        browser.sign_in("attacker")
        fields = _form_fields(browser.authorize().text)
        fields.update(decision="allow", tenant_id=TENANT)
        browser.sign_in(USER)
        response = browser.consent(fields)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
        assert not list(browser.oauth_stores.consents.list_for_user(USER))

    def test_a_cross_site_post_is_refused(self, fake_kms: Any) -> None:
        """A browser that reports a cross-site form post is refused before anything is read."""
        browser = Browser(fake_kms)
        browser.sign_in()
        fields = _form_fields(browser.authorize().text)
        fields.update(decision="allow", tenant_id=TENANT)
        response = browser.consent(fields, headers={"Sec-Fetch-Site": "cross-site"})
        assert response.status_code == 403


class TestLoginRedirect:
    """An unauthenticated browser is sent to the product's sign-in page and back."""

    def test_no_login_url_keeps_the_401(self, fake_kms: Any) -> None:
        """Without the setting the refusal is unchanged."""
        response = Browser(fake_kms).authorize()
        assert response.status_code == 401
        assert response.json()["error"] == "login_required"

    def test_the_login_url_receives_the_authorize_url(self, fake_kms: Any) -> None:
        """The return parameter carries the full authorize request on the issuer."""
        from urllib.parse import parse_qs, urlsplit

        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL)
        verifier = new_pkce_verifier()
        response = browser.authorize(verifier)
        assert response.status_code == 302
        assert response.headers["cache-control"] == "no-store"
        location = urlsplit(response.headers["location"])
        assert f"{location.scheme}://{location.netloc}{location.path}" == LOGIN_URL
        query = parse_qs(location.query)
        assert "prompt" not in query
        back = urlsplit(query["returnTo"][0])
        assert f"{back.scheme}://{back.netloc}{back.path}" == f"{ISSUER}{AUTHORIZE_PATH}"
        assert {key: value[0] for key, value in parse_qs(back.query).items()} == authorize_params(verifier)

    def test_the_return_url_ignores_the_request_host(self, fake_kms: Any) -> None:
        """The return URL is built from the issuer, so a spoofed Host cannot steer it."""
        from urllib.parse import parse_qs, urlsplit

        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL)
        response = browser.client.get(
            f"{browser.prefix}{AUTHORIZE_PATH}",
            params=authorize_params(new_pkce_verifier()),
            headers={"Host": "evil.example.net"},
            follow_redirects=False,
        )
        back = parse_qs(urlsplit(response.headers["location"]).query)["returnTo"][0]
        assert back.startswith(f"{ISSUER}{AUTHORIZE_PATH}?")

    def test_the_return_param_is_configurable(self, fake_kms: Any) -> None:
        """A product whose login page reads another parameter names it."""
        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL, mcp_login_return_param="next")
        assert "next=" in browser.authorize().headers["location"]

    def test_an_invalid_request_is_never_redirected(self, fake_kms: Any) -> None:
        """A request that fails validation is answered as JSON, never bounced to login."""
        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL)
        response = browser.authorize(redirect_uri="https://evil.example.net/cb")
        assert response.status_code in {400, 401}
        assert "location" not in response.headers

    def test_consent_without_a_session_redirects_to_login(self, fake_kms: Any) -> None:
        """A consent post whose session lapsed goes back through sign-in, not a dead end."""
        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL)
        browser.sign_in()
        fields = _form_fields(browser.authorize().text)
        browser.client.cookies.clear()
        fields.update(decision="allow", tenant_id=TENANT)
        response = browser.consent(fields)
        assert response.status_code == 303
        assert response.headers["location"].startswith(f"{LOGIN_URL}?returnTo=")
        assert "signature" not in response.headers["location"]


class TestRecentAuth:
    """`mcp_consent_max_age` sends a stale session back through sign-in."""

    def test_a_fresh_session_is_shown_consent(self, fake_kms: Any) -> None:
        """A login inside the window passes straight through."""
        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL, mcp_consent_max_age="PT1H")
        browser.sign_in()
        assert browser.authorize().status_code == 200

    def test_a_stale_session_is_sent_to_login_with_prompt(self, fake_kms: Any) -> None:
        """An old `auth_time` redirects with `prompt=login`, so the page asks again."""
        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL, mcp_consent_max_age="PT1H")
        browser.sign_in(auth_time=int(time.time()) - 7200)
        response = browser.authorize()
        assert response.status_code == 302
        assert "prompt=login" in response.headers["location"]

    def test_a_stale_consent_post_is_sent_to_login(self, fake_kms: Any) -> None:
        """The check repeats on the post, so a form left open past the window is refused."""
        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL, mcp_consent_max_age="PT1H")
        browser.sign_in()
        fields = _form_fields(browser.authorize().text)
        browser.sign_in(auth_time=int(time.time()) - 7200)
        fields.update(decision="allow", tenant_id=TENANT)
        response = browser.consent(fields)
        assert response.status_code == 303
        assert "prompt=login" in response.headers["location"]

    def test_a_stale_session_without_a_login_url_is_refused(self, fake_kms: Any) -> None:
        """With nowhere to send the user the refusal is the 401 it always was."""
        browser = Browser(fake_kms, mcp_consent_max_age="PT1H")
        browser.sign_in(auth_time=int(time.time()) - 7200)
        assert browser.authorize().status_code == 401

    def test_a_bearer_without_auth_time_is_stale(self, fake_kms: Any) -> None:
        """A token that cannot say when its user authenticated is never counted as recent."""
        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL, mcp_consent_max_age="PT1H")
        response = browser.client.get(
            f"{browser.prefix}{AUTHORIZE_PATH}",
            params=authorize_params(new_pkce_verifier()),
            headers=signed_in(browser.client, fake_kms),
            follow_redirects=False,
        )
        assert response.status_code == 302


class TestPeek:
    """`SessionService.peek` answers who holds a token without changing anything."""

    def test_a_live_token_names_its_user_family_and_auth_time(self) -> None:
        """The family's `auth_time` comes back as the login set it."""
        from webbpulse.identity import SessionService

        settings = build_settings()
        store = InMemoryRefreshTokenStore()
        sessions = SessionService(settings, store)
        issued = sessions.start_family(USER, auth_time=1_700_000_000)
        found = sessions.peek(issued.token)
        assert found is not None
        assert (found.user_id, found.family_id, found.auth_time) == (USER, issued.family_id, 1_700_000_000)

    def test_expired_and_capped_tokens_are_refused(self) -> None:
        """Past the token's own expiry, or the family's absolute cap, there is no session."""
        from datetime import UTC, datetime

        from webbpulse.identity import SessionService

        settings = build_settings()
        store = InMemoryRefreshTokenStore()
        sessions = SessionService(settings, store)
        issued = sessions.start_family(USER)
        before = dict(store._items)
        now = datetime.now(UTC)
        assert sessions.peek(issued.token, now=now + settings.refresh_token_ttl + settings.refresh_token_ttl) is None
        assert sessions.peek(issued.token, now=now + settings.refresh_absolute_ttl) is None
        assert sessions.peek("") is None
        assert dict(store._items) == before


class TestLoginSettings:
    """What the sign-in redirect settings refuse."""

    def test_a_plaintext_login_url_is_refused_outside_local(self) -> None:
        """The page collects credentials, so http is only for local and test."""
        with pytest.raises(ValueError, match="plaintext http"):
            build_settings(environment="production", mcp_login_url="http://app.example.com/login")

    def test_a_plaintext_login_url_is_allowed_in_test(self) -> None:
        """Local and test run over http."""
        assert build_settings(mcp_login_url="http://localhost:5173/login").mcp_login_url

    @pytest.mark.parametrize(
        "value",
        ["/login", "javascript:alert(1)", "https:///login", "https://app.example.com/login#frag"],
    )
    def test_a_malformed_login_url_is_refused(self, value: str) -> None:
        """Only an absolute http(s) URL on a real host, with no fragment, is accepted."""
        with pytest.raises(ValueError, match="mcp_login_url"):
            build_settings(mcp_login_url=value)

    def test_a_login_url_already_carrying_the_return_param_is_refused(self) -> None:
        """The redirect writes that parameter itself, so a second copy would be ambiguous."""
        with pytest.raises(ValueError, match="already carries"):
            build_settings(mcp_login_url="https://app.example.com/login?returnTo=/")

    def test_a_blank_return_param_is_refused(self) -> None:
        """The login page must be told where to come back to."""
        with pytest.raises(ValueError, match="mcp_login_return_param"):
            build_settings(mcp_login_return_param=" ")

    def test_a_negative_consent_max_age_is_refused(self) -> None:
        """Zero turns the check off; below zero is a mistake."""
        with pytest.raises(ValueError, match="mcp_consent_max_age"):
            build_settings(mcp_consent_max_age="-PT1H")


CONSENT_PNG = "data:image/png;base64,iVBORw0KGgo="


def consent_context(**overrides: Any) -> ConsentContext:
    """A consent context for a named client asking for two scopes."""
    request = AuthorizationRequest(
        client=OAuthClientRecord(client_id="c1", redirect_uris=(REDIRECT,), client_name="Claude Code"),
        redirect_uri=REDIRECT,
        resource=RESOURCE,
        scopes=("mcp:read", "mcp:write"),
        code_challenge="x" * 43,
        state="s",
    )
    values: dict[str, Any] = {
        "request": request,
        "user_id": "u1",
        "tenants": (TenantChoice(id=TENANT, name="Workspace One"),),
        "form_action": "/api/auth/authorize/consent",
        "form_fields": {"client_id": "c1", "signature": "sig"},
        "tenant_required": True,
        "product_name": "Acme",
        "account_email": "person@example.com",
        "account_name": "Pat Person",
        "switch_account_url": f"{LOGIN_URL}?prompt=login",
    }
    values.update(overrides)
    return ConsentContext(**values)


def csp_of(response: Any) -> dict[str, str]:
    """The response's CSP as a directive to value map."""
    policy = response.headers["content-security-policy"]
    return {name: rest for name, _, rest in (part.strip().partition(" ") for part in policy.split(";"))}


class TestDescribeScopes:
    """Scopes are grouped and worded for people, with the product's labels winning."""

    def test_builtin_scopes_are_worded(self) -> None:
        """The package's own scopes read as sentences under the right heading."""
        groups = describe_scopes(["mcp:read", "mcp:write"])
        assert [(group.access, group.title) for group in groups] == [("read", "Read access"), ("write", "Write access")]
        assert groups[0].rows[0].label == "Read your data"
        assert groups[1].rows[0].label == "Make changes on your behalf"

    def test_resource_action_scopes_are_inferred(self) -> None:
        """A `resource:action` scope reads as a verb and its resource."""
        groups = describe_scopes(["issues:read", "comments:write"])
        assert [(row.scope, row.label) for group in groups for row in group.rows] == [
            ("issues:read", "Read issues"),
            ("comments:write", "Create and update comments"),
        ]

    def test_product_labels_win(self) -> None:
        """A label the product supplies replaces the inferred one, detail included."""
        labels = {"issues:read": ScopeLabel("Read issues and projects", "Includes archived work.", access="read")}
        row = describe_scopes(["issues:read"], labels)[0].rows[0]
        assert (row.label, row.detail) == ("Read issues and projects", "Includes archived work.")

    def test_unknown_scopes_are_verbatim_writes(self) -> None:
        """A scope with no known shape is shown as is, on the write side."""
        groups = describe_scopes(["weird"])
        assert groups[0].access == "write"
        assert groups[0].rows[0].label == "weird"

    def test_duplicates_are_dropped(self) -> None:
        """A repeated scope is listed once."""
        assert len(describe_scopes(["mcp:read", "mcp:read"])[0].rows) == 1


class TestThemeValidation:
    """A theme can carry nothing into the page but colours, names and approved sources."""

    def test_a_palette_refuses_css_injection(self) -> None:
        """A token that is not a plain colour is refused."""
        with pytest.raises(ValueError, match="accent"):
            replace(DARK_PALETTE, accent="red;}body{display:none")

    def test_a_palette_accepts_colour_functions(self) -> None:
        """Hex, rgb, hsl and oklch values are all accepted."""
        replace(DARK_PALETTE, accent="oklch(0.7 0.1 40)", line="rgb(1 2 3 / 50%)", text="hsl(10 20% 30%)")

    @pytest.mark.parametrize(
        "logo",
        [
            "http://cdn.example.com/logo.svg",
            "javascript:alert(1)",
            "data:text/html;base64,PGI+",
            "https://a@b.example/",
        ],
    )
    def test_a_logo_must_be_https_or_an_image_data_uri(self, logo: str) -> None:
        """Plain http, scripts, non-image data and credentialed URLs are refused."""
        with pytest.raises(ValueError):
            ConsentTheme(logo_url=logo)

    def test_a_font_family_refuses_markup(self) -> None:
        """The family string may not close the rule it sits in."""
        with pytest.raises(ValueError):
            ConsentTheme(font_family="Inter;}</style><script>")

    def test_a_font_face_must_be_a_font(self) -> None:
        """A font source that is not a font data URI or https is refused."""
        with pytest.raises(ValueError):
            FontFace(weight=400, src="data:image/png;base64,AAAA")
        assert FontFace.woff2(500, b"wOF2").src.startswith("data:font/woff2;base64,")

    def test_an_unknown_scheme_is_refused(self) -> None:
        """Only light, dark and system are schemes."""
        with pytest.raises(ValueError):
            ConsentTheme(color_scheme="sepia")  # type: ignore[arg-type]


class TestRender:
    """The rendered page and the headers that keep it from being abused."""

    def test_the_security_headers(self) -> None:
        """Framing is refused, nothing is cached and no referrer leaks."""
        response = render_consent_page(consent_context(), ConsentTheme())
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_the_policy_allows_only_what_the_page_needs(self) -> None:
        """No script source, a nonce for the one style block, and form targets by origin."""
        theme = ConsentTheme(logo_url=CONSENT_PNG, font_faces=(FontFace.woff2(400, b"wOF2"),))
        response = render_consent_page(consent_context(), theme)
        policy = csp_of(response)
        assert policy["default-src"] == "'none'"
        assert "script-src" not in policy
        nonce = policy["style-src"].removeprefix("'nonce-").removesuffix("'")
        assert f'<style nonce="{nonce}">' in response.body.decode()
        assert policy["img-src"] == "data:"
        assert policy["font-src"] == "data:"
        assert policy["form-action"] == "'self' http://127.0.0.1:33418 https://app.staging.example.com"
        assert policy["frame-ancestors"] == "'none'"
        assert policy["base-uri"] == "'none'"

    def test_each_response_has_a_fresh_nonce(self) -> None:
        """The nonce is never reused between two renders."""
        first = csp_of(render_consent_page(consent_context(), ConsentTheme()))["style-src"]
        second = csp_of(render_consent_page(consent_context(), ConsentTheme()))["style-src"]
        assert first != second

    def test_a_native_redirect_is_a_scheme_source(self) -> None:
        """A custom-scheme redirect is admitted by its scheme alone."""
        request = replace(consent_context().request, redirect_uri="cursor://anysphere.cursor-mcp/oauth/callback")
        policy = consent_security_policy(consent_context(request=request), ConsentTheme(), "n")
        assert "form-action 'self' cursor: https://app.staging.example.com" in policy

    def test_https_assets_are_admitted_by_origin(self) -> None:
        """An https logo admits its origin and nothing wider."""
        theme = ConsentTheme(logo_url="https://CDN.example.com/a/logo.svg")
        assert "img-src https://cdn.example.com;" in consent_security_policy(consent_context(), theme, "n")

    def test_the_page_shows_the_account_and_switch_link(self) -> None:
        """The signed-in account is named and the switch link goes to sign-in."""
        page = render_consent_page(consent_context(), ConsentTheme()).body.decode()
        assert "Signed in as Pat Person" in page
        assert "person@example.com" in page
        assert f'href="{LOGIN_URL}?prompt=login">Switch account</a>' in page
        assert "Connect Claude Code to Acme" in page

    def test_the_page_escapes_what_the_client_named_itself(self) -> None:
        """A dynamically registered client's name is text, never markup."""
        request = replace(
            consent_context().request,
            client=OAuthClientRecord(client_id="c1", redirect_uris=(REDIRECT,), client_name="<img src=x>"),
        )
        page = render_consent_page(consent_context(request=request), ConsentTheme()).body.decode()
        assert "<img src=x>" not in page
        assert "&lt;img src=x&gt;" in page

    def test_scope_labels_and_revoke_note_render(self) -> None:
        """The product's wording and its revoke note reach the page."""
        theme = ConsentTheme(
            scope_labels={"mcp:write": ScopeLabel("Post comments as you")},
            revoke_note="Disconnect it any time in Settings.",
        )
        page = render_consent_page(consent_context(), theme).body.decode()
        assert "Post comments as you" in page
        assert "Disconnect it any time in Settings." in page

    def test_the_workspace_picker_checks_the_first(self) -> None:
        """Each workspace is a required radio and the first is preselected."""
        tenants = (TenantChoice(id="w1", name="One"), TenantChoice(id="w2", name="Two"))
        page = render_consent_page(consent_context(tenants=tenants), ConsentTheme()).body.decode()
        assert 'name="tenant_id" value="w1" required checked' in page
        assert 'name="tenant_id" value="w2" required>' in page

    def test_no_workspace_disables_allow(self) -> None:
        """With a resolver mounted and nothing to grant, Allow is disabled and the reason shown."""
        page = render_consent_page(consent_context(tenants=()), ConsentTheme()).body.decode()
        assert 'value="allow" disabled>' in page
        assert "not in a workspace" in page

    def test_no_resolver_needs_no_workspace(self) -> None:
        """A product with no tenants gets no picker and an enabled Allow."""
        page = render_consent_page(consent_context(tenants=(), tenant_required=False), ConsentTheme()).body.decode()
        assert 'name="tenant_id"' not in page
        assert 'value="allow">' in page

    def test_the_scheme_and_palettes_reach_the_page(self) -> None:
        """A pinned scheme is written on the root and both palettes are in the stylesheet."""
        light = replace(ConsentTheme().light, accent="#b8451a")
        page = render_consent_page(consent_context(), ConsentTheme(light=light, color_scheme="dark")).body.decode()
        assert 'data-scheme="dark"' in page
        assert "--accent:#b8451a" in page
        assert f"--accent:{DARK_PALETTE.accent}" in page

    def test_only_one_logo_shows_per_scheme(self) -> None:
        """The dark logo is hidden by a rule at least as specific as the one sizing tile images."""
        page = render_consent_page(consent_context(), ConsentTheme(logo_url=CONSENT_PNG, logo_dark_url=CONSENT_PNG))
        body = page.body.decode()
        assert '<span class="tile has-dark">' in body
        assert ".tile .logo-dark {\n  display: none;" in body


class TestRouterWiring:
    """The theme is threaded through `build_identity_router` to the live endpoint."""

    def test_a_themed_router_serves_the_theme(self, fake_kms: Any) -> None:
        """The authorize page carries the product's wording and the account's email."""
        settings = build_settings(product_name="Acme")
        app = FastAPI()
        app.include_router(
            build_identity_router(
                settings,
                Hooks(),
                IdentityStores(credentials=InMemoryCredentialStore(), refresh_tokens=InMemoryRefreshTokenStore()),
                tokens=TokenService(settings, fake_kms),
                oauth_server_stores=build_stores(),
                tenant_resolver=tenants_for,
                consent_theme=ConsentTheme(scope_labels={"mcp:read": ScopeLabel("Read your widgets", access="read")}),
                limiter_enabled=False,
            )
        )
        client = TestClient(app)
        response = client.get(
            f"{identity_prefix(settings)}{AUTHORIZE_PATH}",
            params=authorize_params(new_pkce_verifier()),
            headers=signed_in(client, fake_kms),
        )
        assert response.status_code == 200
        assert "Read your widgets" in response.text
        assert "person@example.com" in response.text
        assert "Workspace One" in response.text
        assert csp_of(response)["frame-ancestors"] == "'none'"

    def test_switch_account_forces_a_fresh_sign_in_on_the_issuer(self, fake_kms: Any) -> None:
        """The switch link goes to sign-in with prompt=login and returns to the issuer's authorize."""
        import html
        import re
        from urllib.parse import parse_qs, urlsplit

        browser = Browser(fake_kms, mcp_login_url=LOGIN_URL)
        browser.sign_in()
        page = browser.authorize().text
        href = html.unescape(re.search(r'href="([^"]+)">Switch account', page).group(1))  # type: ignore[union-attr]
        location = urlsplit(href)
        assert f"{location.scheme}://{location.netloc}{location.path}" == LOGIN_URL
        query = parse_qs(location.query)
        assert query["prompt"] == ["login"]
        assert query["returnTo"][0].startswith(f"{build_settings().issuer}{AUTHORIZE_PATH}?")


def test_the_default_renderer_is_themed() -> None:
    """`build_consent_renderer` with no theme paints the neutral default."""
    response = build_consent_renderer()(consent_context())
    assert response.status_code == 200
    assert "Allow access" in response.body.decode()


def test_palette_is_exported() -> None:
    """The palette type is part of the public surface."""
    assert ConsentPalette is type(DARK_PALETTE)
