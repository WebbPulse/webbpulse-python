"""Tests for pinning SSO provider fetches to the addresses `PublicUrlGuard` approved."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable

import httpx
import pytest

from webbpulse.identity import (
    OidcConnectionConfig,
    PublicUrlGuard,
    SecretMasterKeyCipher,
    SsoRejected,
    seal_oidc_client_secret,
)
from webbpulse.identity.oauth import HttpxClient
from webbpulse.identity.pinned_transport import PinnedAddressTransport
from webbpulse.identity.sso_oidc import OidcSsoClient
from webbpulse.identity.sso_saml import fetch_saml_idp_metadata

PUBLIC_ADDRESS = "93.184.216.34"
SECOND_PUBLIC_ADDRESS = "93.184.216.35"
PUBLIC_V6 = "2606:4700::1111"
IDP_HOST = "idp.example.test"
IDP_ISSUER = f"https://{IDP_HOST}/realms/acme"

type Handler = Callable[[httpx.Request], httpx.Response]


class ScriptedResolver:
    """A resolver that gives each lookup the next scripted answer and counts the lookups."""

    def __init__(self, *answers: list[str]) -> None:
        """Hold the answers in the order lookups should receive them."""
        self._answers = list(answers)
        self.lookups: list[str] = []

    def __call__(self, host: str) -> Iterable[str]:
        """The next answer, repeating the last one once the script runs out."""
        self.lookups.append(host)
        if len(self._answers) > 1:
            return self._answers.pop(0)
        return self._answers[0]


class Recorder:
    """An `httpx.MockTransport` per host that records every request it is sent."""

    def __init__(self, handler: Handler) -> None:
        """Hold the handler every recorded request is answered by."""
        self._handler = handler
        self.requests: list[httpx.Request] = []
        self.hosts: list[str] = []

    def transport_for_host(self, host: str) -> httpx.BaseTransport:
        """A mock transport for one host, recording what reaches it."""
        self.hosts.append(host)

        def handle(request: httpx.Request) -> httpx.Response:
            """Record the request, then answer it."""
            self.requests.append(request)
            return self._handler(request)

        return httpx.MockTransport(handle)


def ok(request: httpx.Request) -> httpx.Response:
    """A plain 200 answer."""
    return httpx.Response(200, json={"ok": True})


def pinned_client(guard: PublicUrlGuard, recorder: Recorder, *, follow_redirects: bool = False) -> httpx.Client:
    """An `httpx` client whose transport pins through `guard` onto the recorder's mocks."""
    transport = PinnedAddressTransport(guard.addresses, transport_for_host=recorder.transport_for_host)
    return httpx.Client(transport=transport, follow_redirects=follow_redirects)


def test_the_request_goes_to_the_vetted_address_with_the_original_host_and_server_name() -> None:
    """The connection target is the IP literal, while `Host` and SNI keep the name for TLS."""
    recorder = Recorder(ok)
    guard = PublicUrlGuard(resolver=lambda host: [PUBLIC_ADDRESS])
    with pinned_client(guard, recorder) as client:
        response = client.get(f"{IDP_ISSUER}/.well-known/openid-configuration?x=1")
    assert response.status_code == 200
    [sent] = recorder.requests
    assert sent.url.host == PUBLIC_ADDRESS
    assert sent.url.path == "/realms/acme/.well-known/openid-configuration"
    assert sent.url.query == b"x=1"
    assert sent.headers["host"] == IDP_HOST
    assert sent.extensions["sni_hostname"] == IDP_HOST
    assert recorder.hosts == [IDP_HOST]


def test_an_ipv6_address_is_bracketed_in_the_pinned_url() -> None:
    """A vetted IPv6 address becomes a valid URL host."""
    recorder = Recorder(ok)
    guard = PublicUrlGuard(resolver=lambda host: [PUBLIC_V6])
    with pinned_client(guard, recorder) as client:
        client.get(f"{IDP_ISSUER}/x")
    [sent] = recorder.requests
    assert sent.url.host == PUBLIC_V6
    assert f"[{PUBLIC_V6}]" in str(sent.url)
    assert sent.headers["host"] == IDP_HOST


def test_a_second_resolution_to_a_private_address_is_refused() -> None:
    """DNS rebinding: public on the up-front check, private when connecting, and nothing is sent."""
    recorder = Recorder(ok)
    resolver = ScriptedResolver([PUBLIC_ADDRESS], ["169.254.169.254"])
    guard = PublicUrlGuard(resolver=resolver)
    guard(f"{IDP_ISSUER}/x")
    with pinned_client(guard, recorder) as client, pytest.raises(SsoRejected) as excinfo:
        client.get(f"{IDP_ISSUER}/x")
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"
    assert resolver.lookups == [IDP_HOST, IDP_HOST]
    assert recorder.requests == []


def test_a_redirect_to_a_private_host_is_checked_again_and_refused() -> None:
    """Each redirect hop goes back through the guard before anything connects."""

    def redirect(request: httpx.Request) -> httpx.Response:
        """Send the caller on to an internal host."""
        return httpx.Response(302, headers={"location": "https://internal.example.test/latest/meta-data"})

    recorder = Recorder(redirect)
    answers = {IDP_HOST: [PUBLIC_ADDRESS], "internal.example.test": ["10.0.0.7"]}
    guard = PublicUrlGuard(resolver=lambda host: answers[host])
    with pinned_client(guard, recorder, follow_redirects=True) as client, pytest.raises(SsoRejected) as excinfo:
        client.get(f"{IDP_ISSUER}/x")
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"
    assert [request.url.host for request in recorder.requests] == [PUBLIC_ADDRESS]


def test_a_redirect_to_a_public_host_is_pinned_under_its_own_name() -> None:
    """A followed redirect gets its own vetted address, Host header and connection pool."""

    def handler(request: httpx.Request) -> httpx.Response:
        """Redirect from the first address, answer on the second."""
        if request.url.host == PUBLIC_ADDRESS:
            return httpx.Response(302, headers={"location": "https://cdn.example.test/doc"})
        return httpx.Response(200, json={})

    recorder = Recorder(handler)
    answers = {IDP_HOST: [PUBLIC_ADDRESS], "cdn.example.test": [SECOND_PUBLIC_ADDRESS]}
    guard = PublicUrlGuard(resolver=lambda host: answers[host])
    with pinned_client(guard, recorder, follow_redirects=True) as client:
        response = client.get(f"{IDP_ISSUER}/x")
    assert response.status_code == 200
    assert [request.url.host for request in recorder.requests] == [PUBLIC_ADDRESS, SECOND_PUBLIC_ADDRESS]
    assert [request.headers["host"] for request in recorder.requests] == [IDP_HOST, "cdn.example.test"]
    assert recorder.hosts == [IDP_HOST, "cdn.example.test"]


def test_the_next_vetted_address_is_tried_when_one_does_not_connect() -> None:
    """A dead address falls through to the next approved one, never to a fresh lookup."""

    def handler(request: httpx.Request) -> httpx.Response:
        """Refuse the first address, answer on the second."""
        if request.url.host == PUBLIC_ADDRESS:
            raise httpx.ConnectError("refused", request=request)
        return httpx.Response(200, json={})

    recorder = Recorder(handler)
    resolver = ScriptedResolver([PUBLIC_ADDRESS, SECOND_PUBLIC_ADDRESS])
    guard = PublicUrlGuard(resolver=resolver)
    with pinned_client(guard, recorder) as client:
        assert client.get(f"{IDP_ISSUER}/x").status_code == 200
    assert [request.url.host for request in recorder.requests] == [PUBLIC_ADDRESS, SECOND_PUBLIC_ADDRESS]
    assert resolver.lookups == [IDP_HOST]


def test_a_trusted_host_is_reached_without_pinning() -> None:
    """`trusted_hosts` is for a local test provider, so its URL goes through unchanged."""
    recorder = Recorder(ok)
    guard = PublicUrlGuard(trusted_hosts={"localhost"}, resolver=lambda host: ["127.0.0.1"])
    with pinned_client(guard, recorder) as client:
        client.get("http://localhost:8080/x")
    [sent] = recorder.requests
    assert sent.url.host == "localhost"
    assert "sni_hostname" not in sent.extensions


@pytest.mark.parametrize(
    "address",
    ["::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "2002:a00:1::1"],
)
def test_ipv6_forms_that_embed_a_private_ipv4_address_are_refused(address: str) -> None:
    """Mapped, NAT64 and 6to4 addresses are judged by the IPv4 address inside them."""
    guard = PublicUrlGuard(resolver=lambda host: [address])
    with pytest.raises(SsoRejected) as excinfo:
        guard.addresses(f"{IDP_ISSUER}/x")
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"


def test_the_guard_returns_each_vetted_address_once() -> None:
    """Duplicate answers collapse, zone ids are dropped, and a trusted host yields none."""
    answer = [PUBLIC_ADDRESS, PUBLIC_ADDRESS, f"{PUBLIC_V6}%eth0"]
    guard = PublicUrlGuard(trusted_hosts={"localhost"}, resolver=lambda host: answer)
    assert guard.addresses(f"{IDP_ISSUER}/x") == (PUBLIC_ADDRESS, PUBLIC_V6)
    assert guard.addresses("http://localhost:8080/x") == ()


def test_an_oidc_discovery_that_rebinds_to_a_private_address_is_refused() -> None:
    """End to end: the client's up-front check passes, the pinned connect refuses the rebind."""
    recorder = Recorder(ok)
    resolver = ScriptedResolver([PUBLIC_ADDRESS], ["10.0.0.5"])
    guard = PublicUrlGuard(resolver=resolver)
    http = HttpxClient(client=pinned_client(guard, recorder))
    cipher = SecretMasterKeyCipher(os.urandom(32))
    client = OidcSsoClient(cipher=cipher, http_client=http, url_guard=guard)
    sealed = seal_oidc_client_secret(cipher, connection_id="conn_acme", client_secret="acme-client-secret")
    config = OidcConnectionConfig(issuer=IDP_ISSUER, client_id="example-app", sealed_client_secret=sealed)
    with pytest.raises(SsoRejected) as excinfo:
        client.metadata(config)
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"
    assert recorder.requests == []


def test_the_default_oidc_client_pins_through_a_public_url_guard() -> None:
    """With no client supplied, the built `httpx` client uses the guard's pinned transport."""
    guard = PublicUrlGuard(resolver=lambda host: [PUBLIC_ADDRESS])
    client = OidcSsoClient(cipher=SecretMasterKeyCipher(os.urandom(32)), url_guard=guard)
    http = client._http
    assert isinstance(http, HttpxClient)
    built = http._require()
    assert isinstance(built._transport, PinnedAddressTransport)
    built.close()


def test_saml_metadata_fetched_by_default_is_refused_when_it_rebinds(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default metadata client pins too, so a second answer that is private is refused."""
    recorder = Recorder(ok)
    resolver = ScriptedResolver([PUBLIC_ADDRESS], ["127.0.0.1"])
    guard = PublicUrlGuard(resolver=resolver)

    def transport() -> httpx.BaseTransport:
        """The guard's pinned transport over the recorder's mocks."""
        return PinnedAddressTransport(guard.addresses, transport_for_host=recorder.transport_for_host)

    monkeypatch.setattr(guard, "transport", transport)
    with pytest.raises(SsoRejected) as excinfo:
        fetch_saml_idp_metadata(f"https://{IDP_HOST}/metadata", url_guard=guard)
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"
    assert resolver.lookups == [IDP_HOST, IDP_HOST]
    assert recorder.requests == []
