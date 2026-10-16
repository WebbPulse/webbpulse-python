"""Tests for per-tenant SAML 2.0 single sign-on: the AuthnRequest, SP metadata and response checks."""

from __future__ import annotations

import base64
import datetime
import os
import secrets
import subprocess
import sys
import time
import zlib
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from lxml import etree
from signxml.algorithms import CanonicalizationMethod
from signxml.signer import XMLSigner

from webbpulse.identity import (
    AMR_SSO,
    SSO_CONNECTION_CLAIM,
    BaseIdentityHooks,
    IdentitySettings,
    IdentityStores,
    InMemoryCredentialStore,
    InMemoryOAuthLinkStore,
    InMemoryOAuthStateStore,
    InMemoryRefreshTokenStore,
    PublicUrlGuard,
    SamlConnectionConfig,
    SecretMasterKeyCipher,
    SsoConnection,
    SsoHooks,
    SsoIdentity,
    SsoLoginOutcome,
    SsoRejected,
    SsoService,
    TokenService,
    build_identity_router,
    identity_prefix,
)
from webbpulse.identity.oauth import OAUTH_LINK_BINDING_COOKIE, OAuthStateRecord
from webbpulse.identity.sso_saml import (
    SAML_BINDING_HTTP_POST,
    SAML_BINDING_HTTP_REDIRECT,
    SamlSsoClient,
    fetch_saml_idp_metadata,
    parse_saml_idp_metadata,
)
from webbpulse.testing import FakeIdempotencyStore

KEY_A = "arn:aws:kms:us-west-2:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa"
ISSUER = "https://api.example.test/api/auth"
AUDIENCE = "example-test"
FRONTEND = "https://app.example.test"

CONNECTION_ID = "conn_saml"
TENANT_ID = "tenant-acme"
DOMAIN = "acme.example"
EMAIL = f"pat@{DOMAIN}"
SUBJECT = "pat-0001"
IDP_ENTITY = "https://idp.example.test/saml/metadata"
IDP_SSO_URL = "https://idp.example.test/saml/sso"
SP_ENTITY = f"{ISSUER}/sso/saml/{CONNECTION_ID}/metadata"
ACS = f"{ISSUER}/sso/saml/{CONNECTION_ID}/acs"
PUBLIC_ADDRESS = "93.184.216.34"

P_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
A_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
PLACEHOLDER = f'<ds:Signature xmlns:ds="{DS_NS}" Id="placeholder"/>'


def iso(moment: float) -> str:
    """A SAML instant for epoch seconds."""
    return datetime.datetime.fromtimestamp(moment, tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_key_and_cert(common_name: str = "idp") -> tuple[rsa.RSAPrivateKey, str]:
    """A signing key and a self-signed certificate for it, valid around now."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return key, cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def bare_base64(pem: str) -> str:
    """A PEM certificate's base64 body, as metadata carries it."""
    return "".join(line for line in pem.splitlines() if line and not line.startswith("-----"))


class Idp:
    """A SAML identity provider that signs real responses with its own key."""

    def __init__(self, key: rsa.RSAPrivateKey, cert: str) -> None:
        """Hold the signing key and certificate."""
        self.key = key
        self.cert = cert

    def _sign(self, element: Any, element_id: str, key: rsa.RSAPrivateKey | None, cert: str | None) -> Any:
        """Sign an element in place of its placeholder, with exclusive canonicalisation."""
        signer = XMLSigner(c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0)
        return signer.sign(element, key=key or self.key, cert=cert or self.cert, reference_uri=element_id)

    def assertion(
        self,
        request_id: str,
        *,
        sign: bool = True,
        key: rsa.RSAPrivateKey | None = None,
        cert: str | None = None,
        **fields: Any,
    ) -> str:
        """One assertion, signed unless told otherwise, with any field overridden."""
        now = time.time()
        values: dict[str, Any] = {
            "assertion_id": f"_a{secrets.token_hex(8)}",
            "issuer": IDP_ENTITY,
            "name_id": SUBJECT,
            "name_id_format": PERSISTENT,
            "recipient": ACS,
            "sc_in_response_to": request_id,
            "sc_not_on_or_after": iso(now + 300),
            "not_before": iso(now - 30),
            "not_on_or_after": iso(now + 300),
            "audience": SP_ENTITY,
            "session_not_on_or_after": iso(now + 3600),
            "attributes": {"email": [EMAIL], "displayName": ["Pat Example"], "groups": ["engineering", "admins"]},
        }
        values.update(fields)
        attributes = "".join(
            f'<saml:Attribute Name="{name}">'
            + "".join(f"<saml:AttributeValue>{value}</saml:AttributeValue>" for value in items)
            + "</saml:Attribute>"
            for name, items in values["attributes"].items()
        )
        document = (
            f'<saml:Assertion xmlns:saml="{A_NS}" ID="{values["assertion_id"]}" Version="2.0"'
            f' IssueInstant="{iso(now)}">'
            f"<saml:Issuer>{values['issuer']}</saml:Issuer>"
            f"{PLACEHOLDER if sign else ''}"
            "<saml:Subject>"
            f'<saml:NameID Format="{values["name_id_format"]}">{values["name_id"]}</saml:NameID>'
            f'<saml:SubjectConfirmation Method="{BEARER}">'
            f'<saml:SubjectConfirmationData NotOnOrAfter="{values["sc_not_on_or_after"]}"'
            f' Recipient="{values["recipient"]}" InResponseTo="{values["sc_in_response_to"]}"/>'
            "</saml:SubjectConfirmation>"
            "</saml:Subject>"
            f'<saml:Conditions NotBefore="{values["not_before"]}" NotOnOrAfter="{values["not_on_or_after"]}">'
            f"<saml:AudienceRestriction><saml:Audience>{values['audience']}</saml:Audience></saml:AudienceRestriction>"
            "</saml:Conditions>"
            f'<saml:AuthnStatement AuthnInstant="{iso(now)}" SessionIndex="_s1"'
            f' SessionNotOnOrAfter="{values["session_not_on_or_after"]}">'
            "<saml:AuthnContext><saml:AuthnContextClassRef>"
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            "</saml:AuthnContextClassRef></saml:AuthnContext>"
            "</saml:AuthnStatement>"
            f"<saml:AttributeStatement>{attributes}</saml:AttributeStatement>"
            "</saml:Assertion>"
        )
        if not sign:
            return document
        signed = self._sign(etree.fromstring(document), values["assertion_id"], key, cert)
        return str(etree.tostring(signed).decode("utf-8"))

    def response(
        self,
        request_id: str,
        *,
        assertion: str | None = None,
        sign_response: bool = False,
        **fields: Any,
    ) -> str:
        """A response carrying one assertion, with the response itself optionally signed."""
        values: dict[str, Any] = {
            "response_id": f"_r{secrets.token_hex(8)}",
            "destination": ACS,
            "in_response_to": request_id,
            "response_issuer": IDP_ENTITY,
            "status": SUCCESS,
        }
        response_fields = {name: fields.pop(name) for name in list(fields) if name in values}
        values.update(response_fields)
        body = assertion if assertion is not None else self.assertion(request_id, **fields)
        document = (
            f'<samlp:Response xmlns:samlp="{P_NS}" xmlns:saml="{A_NS}" ID="{values["response_id"]}"'
            f' Version="2.0" IssueInstant="{iso(time.time())}" Destination="{values["destination"]}"'
            f' InResponseTo="{values["in_response_to"]}">'
            f"<saml:Issuer>{values['response_issuer']}</saml:Issuer>"
            f"{PLACEHOLDER if sign_response else ''}"
            f'<samlp:Status><samlp:StatusCode Value="{values["status"]}"/></samlp:Status>'
            f"{body}"
            "</samlp:Response>"
        )
        if not sign_response:
            return document
        return str(etree.tostring(self._sign(etree.fromstring(document), values["response_id"], None, None)).decode())


def encode(document: str | bytes) -> str:
    """The base64 `SAMLResponse` form value for a document."""
    raw = document.encode("utf-8") if isinstance(document, str) else document
    return base64.b64encode(raw).decode("ascii")


class FakeKms:
    """Signs with a local private key, so `TokenService` mints verifiable tokens."""

    def __init__(self, key: rsa.RSAPrivateKey) -> None:
        """Hold the RSA key this fake signs with."""
        self._key = key

    def get_public_key(self, *, KeyId: str) -> dict[str, Any]:
        """Return the DER public key, as KMS does."""
        der = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {
            "KeyId": KeyId,
            "PublicKey": der,
            "KeySpec": "RSA_2048",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["RSASSA_PKCS1_V1_5_SHA_256"],
        }

    def sign(self, *, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> dict[str, Any]:
        """Sign a prehashed message with the local key."""
        signature = self._key.sign(Message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return {"KeyId": KeyId, "Signature": signature, "SigningAlgorithm": SigningAlgorithm}


class FakeHooks(BaseIdentityHooks):
    """A product's identity policy, in memory."""

    def __init__(self) -> None:
        """Start with no users."""
        self.users: dict[str, dict[str, Any]] = {}

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """Return the user with this id, or None."""
        return self.users.get(user_id)

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """Return the user with this email, or None."""
        return next((user for user in self.users.values() if user["email"].lower() == email.lower()), None)

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Let every user in."""
        return None

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create and store a user."""
        user = {"id": f"user-{len(self.users) + 1:04d}", "email": email, **dict(attributes)}
        self.users[user["id"]] = user
        return user


class FakeSsoHooks(SsoHooks):
    """A product's connection table, in memory."""

    def __init__(self, connections: Sequence[SsoConnection]) -> None:
        """Hold the connections and record every login outcome."""
        self.connections = {connection.connection_id: connection for connection in connections}
        self.logins: list[tuple[str, SsoLoginOutcome, SsoIdentity]] = []

    def load_connection(self, connection_id: str) -> SsoConnection | None:
        """The connection with this id, or None."""
        return self.connections.get(connection_id)

    def on_sso_login(
        self,
        user: Mapping[str, Any],
        connection: SsoConnection,
        identity: SsoIdentity,
        *,
        outcome: SsoLoginOutcome,
    ) -> None:
        """Record the outcome and the identity."""
        self.logins.append((str(user["id"]), outcome, identity))


@pytest.fixture(autouse=True)
def cheap_bcrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin bcrypt to its minimum cost for the whole module."""
    import webbpulse.security as security

    real_hash = security.hash_password

    def cheap(password: str, *, rounds: int = 4) -> str:
        """Hash a password at the minimum bcrypt cost."""
        return real_hash(password, rounds=rounds)

    monkeypatch.setattr(security, "hash_password", cheap)


@pytest.fixture(scope="module")
def idp_material() -> tuple[rsa.RSAPrivateKey, str]:
    """The identity provider's key and certificate."""
    return make_key_and_cert()


@pytest.fixture
def idp(idp_material: tuple[rsa.RSAPrivateKey, str]) -> Idp:
    """The identity provider."""
    return Idp(*idp_material)


@pytest.fixture(scope="module")
def module_key() -> rsa.RSAPrivateKey:
    """The key this module's own access tokens are signed with."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_settings() -> IdentitySettings:
    """Identity settings for this module."""
    return IdentitySettings(
        environment="test",
        issuer=ISSUER,
        audience=AUDIENCE,
        signing_key_arns=[KEY_A],
        email_verification_required=False,
        frontend_base_url=FRONTEND,
        product_name="Example",
        support_email="support@example.com",
    )


def make_connection(idp: Idp, **overrides: Any) -> SsoConnection:
    """A SAML connection trusting the identity provider's certificate."""
    config: dict[str, Any] = {
        "idp_entity_id": IDP_ENTITY,
        "idp_sso_url": IDP_SSO_URL,
        "idp_certificates": (idp.cert,),
    }
    config.update(overrides)
    return SsoConnection(
        connection_id=CONNECTION_ID,
        tenant_id=TENANT_ID,
        protocol="saml",
        verified_domains=(DOMAIN,),
        display_name="Acme",
        saml=SamlConnectionConfig(**config),
    )


class Harness:
    """The service, its stores and its hooks for one test."""

    def __init__(self, idp: Idp, connection: SsoConnection | None = None, *, leeway: float = 30.0) -> None:
        """Build the stores and an `SsoService` with SAML enabled."""
        self.idp = idp
        self.hooks = FakeHooks()
        self.sso_hooks = FakeSsoHooks([connection or make_connection(idp)])
        self.stores = IdentityStores(
            credentials=InMemoryCredentialStore(),
            refresh_tokens=InMemoryRefreshTokenStore(),
            oauth_states=InMemoryOAuthStateStore(),
            oauth_links=InMemoryOAuthLinkStore(),
        )
        self.replay = FakeIdempotencyStore()
        self.service = SsoService(
            make_settings(),
            self.hooks,
            self.sso_hooks,
            states=self.stores.require_oauth_states(),
            links=self.stores.require_oauth_links(),
            cipher=SecretMasterKeyCipher(os.urandom(32)),
            saml_client=SamlSsoClient(replay=self.replay, leeway=leeway),
        )

    def begin(self) -> OAuthStateRecord:
        """Start a sign-in and spend its state, as the assertion consumer does."""
        authorization = self.service.start(connection_id=CONNECTION_ID, binding="digest")
        return self.service.consume_state(authorization.state, connection_id=CONNECTION_ID)

    def verify(self, document: str | bytes, record: OAuthStateRecord) -> SsoIdentity:
        """Verify a response document against a spent state."""
        return self.service.identity_from_saml_response(
            self.service.connection(CONNECTION_ID), saml_response=encode(document), state_record=record
        )


@pytest.fixture
def harness(idp: Idp) -> Harness:
    """A fresh service with one SAML connection."""
    return Harness(idp)


def refused_code(harness: Harness, document: str | bytes, record: OAuthStateRecord) -> str:
    """The error code a response is refused with."""
    with pytest.raises(SsoRejected) as excinfo:
        harness.verify(document, record)
    return excinfo.value.error_code


def query_of(url: str) -> dict[str, str]:
    """The query parameters of a URL, one value each."""
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


def test_start_sends_a_deflated_authn_request_over_http_redirect(harness: Harness) -> None:
    """The request names this SP, the POST ACS, and an id the state remembers."""
    authorization = harness.service.start(connection_id=CONNECTION_ID, binding="digest")
    assert authorization.protocol == "saml"
    assert authorization.authorization_url.startswith(f"{IDP_SSO_URL}?")
    params = query_of(authorization.authorization_url)
    assert params["RelayState"] == authorization.state
    request = etree.fromstring(zlib.decompress(base64.b64decode(params["SAMLRequest"]), wbits=-15))
    assert request.tag == f"{{{P_NS}}}AuthnRequest"
    assert request.get("AssertionConsumerServiceURL") == ACS
    assert request.get("ProtocolBinding") == SAML_BINDING_HTTP_POST
    assert request.get("Destination") == IDP_SSO_URL
    assert request.findtext(f"{{{A_NS}}}Issuer") == SP_ENTITY

    record = harness.service.consume_state(authorization.state, connection_id=CONNECTION_ID)
    assert record.nonce == request.get("ID")
    assert record.nonce.startswith("_")
    assert record.redirect_uri == ACS
    assert record.binding == "digest"


@pytest.mark.parametrize("url", ["javascript:alert(1)", "http://idp.example.test/sso", "https://user:pw@idp.example.test/"])
def test_start_refuses_an_unsafe_identity_provider_url(idp: Idp, url: str) -> None:
    """The browser is never sent to a script URL, plain HTTP or embedded credentials."""
    harness = Harness(idp, make_connection(idp, idp_sso_url=url))
    with pytest.raises(SsoRejected) as excinfo:
        harness.service.start(connection_id=CONNECTION_ID)
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"


def test_sp_metadata_declares_the_entity_and_the_post_acs(harness: Harness) -> None:
    """Signed assertions wanted, unsigned requests, one default POST ACS."""
    document = harness.service.saml_metadata(harness.service.connection(CONNECTION_ID))
    root = etree.fromstring(document.encode("utf-8"))
    assert root.get("entityID") == SP_ENTITY
    descriptor = root.find(f"{{{MD_NS}}}SPSSODescriptor")
    assert descriptor.get("WantAssertionsSigned") == "true"
    assert descriptor.get("AuthnRequestsSigned") == "false"
    acs = descriptor.find(f"{{{MD_NS}}}AssertionConsumerService")
    assert acs.get("Location") == ACS
    assert acs.get("Binding") == SAML_BINDING_HTTP_POST


def test_a_signed_response_yields_the_asserted_identity(harness: Harness, idp: Idp) -> None:
    """Subject from the NameID, email and name from attributes, every attribute kept."""
    record = harness.begin()
    identity = harness.verify(idp.response(record.nonce), record)
    assert identity.protocol == "saml"
    assert identity.connection_id == CONNECTION_ID
    assert identity.subject == SUBJECT
    assert identity.email == EMAIL
    assert identity.email_verified is False
    assert identity.name == "Pat Example"
    assert identity.attributes["groups"] == ["engineering", "admins"]
    assert identity.attributes["name_id_format"] == PERSISTENT


def test_a_signed_response_and_assertion_are_both_accepted(harness: Harness, idp: Idp) -> None:
    """A provider that signs both, as Keycloak can, still verifies."""
    record = harness.begin()
    assert harness.verify(idp.response(record.nonce, sign_response=True), record).subject == SUBJECT


def test_a_rotated_certificate_is_accepted_beside_the_old_one(idp: Idp) -> None:
    """Each configured certificate is tried, so a tenant can publish the next one early."""
    _, other = make_key_and_cert("old")
    harness = Harness(idp, make_connection(idp, idp_certificates=(other, bare_base64(idp.cert))))
    record = harness.begin()
    assert harness.verify(idp.response(record.nonce), record).subject == SUBJECT


def test_a_response_signed_by_another_key_is_refused(harness: Harness, idp: Idp) -> None:
    """A signature that verifies under its own embedded certificate proves nothing."""
    record = harness.begin()
    key, cert = make_key_and_cert("attacker")
    assertion = idp.assertion(record.nonce, key=key, cert=cert)
    assert refused_code(harness, idp.response(record.nonce, assertion=assertion), record) == "SSO_SAML_INVALID"


def test_a_tampered_name_id_is_refused(harness: Harness, idp: Idp) -> None:
    """Any change to the signed assertion breaks its digest."""
    record = harness.begin()
    document = idp.response(record.nonce).replace(f">{SUBJECT}<", ">admin<")
    assert ">admin<" in document
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"


def test_an_unsigned_assertion_is_refused(harness: Harness, idp: Idp) -> None:
    """Signed assertions are required."""
    record = harness.begin()
    document = idp.response(record.nonce, assertion=idp.assertion(record.nonce, sign=False))
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"


def test_a_signed_response_around_an_unsigned_assertion_is_refused(harness: Harness, idp: Idp) -> None:
    """A response signature alone does not stand in for the assertion's own."""
    record = harness.begin()
    document = idp.response(record.nonce, assertion=idp.assertion(record.nonce, sign=False), sign_response=True)
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"


def _wrap(document: str, mutate: Callable[[Any, Any, Any], None]) -> bytes:
    """Rearrange a response's tree: `mutate(root, signed_assertion, evil_assertion)`."""
    root = etree.fromstring(document.encode("utf-8"))
    signed = root.find(f"{{{A_NS}}}Assertion")
    evil = etree.fromstring(etree.tostring(signed))
    evil.set("ID", "_evil")
    evil.find(f"{{{A_NS}}}Subject/{{{A_NS}}}NameID").text = "admin"
    signature = evil.find(f"{{{DS_NS}}}Signature")
    evil.remove(signature)
    mutate(root, signed, evil)
    return bytes(etree.tostring(root))


def _sibling(root: Any, signed: Any, evil: Any) -> None:
    """The evil assertion sits beside the signed one."""
    root.insert(list(root).index(signed), evil)


def _in_extensions(root: Any, signed: Any, evil: Any) -> None:
    """The signed assertion moves into `Extensions`; the evil one takes its place."""
    extensions = etree.SubElement(root, f"{{{P_NS}}}Extensions")
    root.replace(signed, evil)
    extensions.append(signed)


def _nested(root: Any, signed: Any, evil: Any) -> None:
    """The signed assertion hides inside the evil one's `Advice`."""
    root.replace(signed, evil)
    advice = etree.SubElement(evil, f"{{{A_NS}}}Advice")
    advice.append(signed)


def _same_id(root: Any, signed: Any, evil: Any) -> None:
    """The evil assertion copies the signed one's id, so a reference could match either."""
    evil.set("ID", signed.get("ID"))
    root.insert(list(root).index(signed), evil)


@pytest.mark.parametrize("mutate", [_sibling, _in_extensions, _nested, _same_id])
def test_signature_wrapping_is_refused(
    harness: Harness, idp: Idp, mutate: Callable[[Any, Any, Any], None]
) -> None:
    """Only one assertion may exist, as a direct child, and it must be the element signed."""
    record = harness.begin()
    document = _wrap(idp.response(record.nonce), mutate)
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"
    assert harness.replay.claims == []


def test_a_wrapped_response_with_a_valid_response_signature_is_refused(harness: Harness, idp: Idp) -> None:
    """Moving the signed response into an unsigned outer one breaks the location check."""
    record = harness.begin()
    signed = etree.fromstring(idp.response(record.nonce, sign_response=True).encode("utf-8"))
    outer = etree.fromstring(idp.response(record.nonce, assertion=idp.assertion(record.nonce, sign=False)).encode())
    etree.SubElement(outer, f"{{{P_NS}}}Extensions").append(signed)
    assert refused_code(harness, etree.tostring(outer), record) == "SSO_SAML_INVALID"


def test_comments_inside_a_name_id_cannot_truncate_it(harness: Harness, idp: Idp) -> None:
    """The whole signed text is read, so a comment never cuts a subject short."""
    record = harness.begin()
    document = idp.response(record.nonce, name_id=f"{EMAIL}.evil")
    injected = document.replace(f">{EMAIL}.evil<", f">{EMAIL}<!---->.evil<")
    assert injected != document
    assert harness.verify(injected, record).subject == f"{EMAIL}.evil"


def test_an_expired_assertion_is_refused(harness: Harness, idp: Idp) -> None:
    """Past `NotOnOrAfter` plus the leeway, both on the conditions and the confirmation."""
    record = harness.begin()
    past = iso(time.time() - 120)
    document = idp.response(record.nonce, not_on_or_after=past, sc_not_on_or_after=past)
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"


def test_an_expired_subject_confirmation_is_refused(harness: Harness, idp: Idp) -> None:
    """The bearer confirmation's own window is checked too."""
    record = harness.begin()
    document = idp.response(record.nonce, sc_not_on_or_after=iso(time.time() - 120))
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"


def test_a_not_yet_valid_assertion_is_refused(harness: Harness, idp: Idp) -> None:
    """`NotBefore` further ahead than the leeway is refused."""
    record = harness.begin()
    document = idp.response(record.nonce, not_before=iso(time.time() + 300))
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"


def test_an_expired_session_is_refused(harness: Harness, idp: Idp) -> None:
    """`SessionNotOnOrAfter` in the past ends the sign-in."""
    record = harness.begin()
    document = idp.response(record.nonce, session_not_on_or_after=iso(time.time() - 120))
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"


def test_small_clock_skew_is_tolerated(harness: Harness, idp: Idp) -> None:
    """Ten seconds past expiry or before validity is within the default leeway."""
    record = harness.begin()
    now = time.time()
    document = idp.response(
        record.nonce,
        not_before=iso(now + 10),
        not_on_or_after=iso(now - 10),
        sc_not_on_or_after=iso(now - 10),
    )
    assert harness.verify(document, record).subject == SUBJECT


def test_a_replayed_assertion_is_refused(harness: Harness, idp: Idp) -> None:
    """The assertion id is claimed, so the same response cannot sign in twice."""
    record = harness.begin()
    document = idp.response(record.nonce)
    harness.verify(document, record)
    assert refused_code(harness, document, record) == "SSO_SAML_REPLAYED"
    assert len(harness.replay.claims) == 2
    assert harness.replay.claims[0].startswith(f"saml-assertion:{CONNECTION_ID}#_a")


@pytest.mark.parametrize(
    "field",
    [
        {"audience": "https://other.example.test/sp"},
        {"recipient": "https://other.example.test/acs"},
        {"destination": "https://other.example.test/acs"},
        {"in_response_to": "_someone-else"},
        {"sc_in_response_to": "_someone-else"},
        {"issuer": "https://evil.example.test"},
        {"response_issuer": "https://evil.example.test"},
    ],
)
def test_a_response_meant_for_someone_else_is_refused(harness: Harness, idp: Idp, field: dict[str, Any]) -> None:
    """Audience, recipient, destination, request id and issuer must all match."""
    record = harness.begin()
    assert refused_code(harness, idp.response(record.nonce, **field), record) == "SSO_SAML_INVALID"


def test_a_response_for_another_request_is_refused(harness: Harness, idp: Idp) -> None:
    """A response answering one AuthnRequest cannot finish another."""
    first = harness.begin()
    second = harness.begin()
    assert refused_code(harness, idp.response(first.nonce), second) == "SSO_SAML_INVALID"


def test_a_doctype_is_refused_before_any_entity_is_expanded(harness: Harness, idp: Idp, tmp_path: Any) -> None:
    """No DTD is loaded and no external entity is resolved."""
    secret = tmp_path / "secret.txt"
    secret.write_text("top-secret")
    record = harness.begin()
    document = idp.response(record.nonce).replace(f">{SUBJECT}<", ">&xxe;<", 1)
    document = f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file://{secret}">]>{document}'
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"


def test_an_encrypted_assertion_is_refused(harness: Harness, idp: Idp) -> None:
    """Encrypted assertions are not supported, so they are never half-read."""
    record = harness.begin()
    document = idp.response(record.nonce).replace(
        "</samlp:Response>", f'<saml:EncryptedAssertion xmlns:saml="{A_NS}"/></samlp:Response>'
    )
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"


def test_a_failed_status_is_reported_as_an_identity_provider_refusal(harness: Harness, idp: Idp) -> None:
    """A non-success status reads as the provider saying no."""
    record = harness.begin()
    document = idp.response(record.nonce, status="urn:oasis:names:tc:SAML:2.0:status:Responder")
    assert refused_code(harness, document, record) == "SSO_IDP_REFUSED"


@pytest.mark.parametrize("value", ["", "not base64 !!", "PHg+"])
def test_malformed_input_is_refused(harness: Harness, value: str) -> None:
    """Empty, non-base64 and non-SAML input are all one refusal."""
    record = harness.begin()
    with pytest.raises(SsoRejected) as excinfo:
        harness.service.identity_from_saml_response(
            harness.service.connection(CONNECTION_ID), saml_response=value, state_record=record
        )
    assert excinfo.value.error_code == "SSO_SAML_INVALID"


def test_a_transient_name_id_needs_a_subject_attribute(idp: Idp) -> None:
    """A transient NameID changes every sign-in, so it cannot be the durable subject."""
    harness = Harness(idp)
    record = harness.begin()
    document = idp.response(record.nonce, name_id_format=TRANSIENT, name_id="_t1")
    assert refused_code(harness, document, record) == "SSO_SAML_INVALID"

    harness = Harness(idp, make_connection(idp, subject_attribute="uid"))
    record = harness.begin()
    attributes = {"uid": ["pat-uid"], "mail": [EMAIL], "givenName": ["Pat"], "sn": ["Example"]}
    document = idp.response(record.nonce, name_id_format=TRANSIENT, name_id="_t1", attributes=attributes)
    identity = harness.verify(document, record)
    assert identity.subject == "pat-uid"
    assert identity.email == EMAIL
    assert identity.name == "Pat Example"


def test_a_missing_extra_answers_501(harness: Harness, idp: Idp, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without `signxml` installed, a SAML response is refused as unsupported."""
    record = harness.begin()
    document = idp.response(record.nonce)
    monkeypatch.setitem(sys.modules, "signxml", None)
    with pytest.raises(SsoRejected) as excinfo:
        harness.verify(document, record)
    assert excinfo.value.error_code == "SSO_PROTOCOL_UNSUPPORTED"
    assert excinfo.value.status_code == 501


def test_a_plain_identity_import_loads_no_saml_dependency() -> None:
    """`webbpulse.identity` and the SSO routes import neither `lxml`, `signxml` nor `sso_saml`."""
    code = (
        "import sys\n"
        "import webbpulse.identity\n"
        "import webbpulse.identity.sso_routes\n"
        "import webbpulse.identity.router\n"
        "print(','.join(m for m in ('lxml', 'signxml', 'webbpulse.identity.sso_saml') if m in sys.modules))\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == ""


def test_a_service_without_saml_still_refuses_a_saml_connection(idp: Idp) -> None:
    """With no replay store or client, a SAML connection answers 501 and no routes mount."""
    stores = IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        oauth_states=InMemoryOAuthStateStore(),
        oauth_links=InMemoryOAuthLinkStore(),
    )
    service = SsoService(
        make_settings(),
        FakeHooks(),
        FakeSsoHooks([make_connection(idp)]),
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        cipher=SecretMasterKeyCipher(os.urandom(32)),
    )
    assert service.saml_enabled is False
    with pytest.raises(SsoRejected) as excinfo:
        service.start(connection_id=CONNECTION_ID)
    assert excinfo.value.status_code == 501


def test_a_replay_store_alone_enables_saml(idp: Idp) -> None:
    """`saml_replay` builds the default client with the settings' leeway."""
    stores = IdentityStores(
        credentials=InMemoryCredentialStore(),
        refresh_tokens=InMemoryRefreshTokenStore(),
        oauth_states=InMemoryOAuthStateStore(),
        oauth_links=InMemoryOAuthLinkStore(),
    )
    service = SsoService(
        make_settings(),
        FakeHooks(),
        FakeSsoHooks([make_connection(idp)]),
        states=stores.require_oauth_states(),
        links=stores.require_oauth_links(),
        cipher=SecretMasterKeyCipher(os.urandom(32)),
        saml_replay=FakeIdempotencyStore(),
    )
    assert service.saml_enabled is True
    assert service.start(connection_id=CONNECTION_ID).protocol == "saml"


def build_client(harness: Harness, module_key: rsa.RSAPrivateKey) -> tuple[TestClient, FastAPI]:
    """An HTTPS `TestClient` over a router with the SSO routes mounted."""
    app = FastAPI()
    app.include_router(
        build_identity_router(
            make_settings(),
            harness.hooks,
            harness.stores,
            kms_client=FakeKms(module_key),
            limiter_enabled=False,
            sso=harness.service,
        )
    )
    return TestClient(app, base_url="https://testserver", follow_redirects=False), app


PREFIX = identity_prefix(make_settings())


def start_through_the_route(client: TestClient) -> dict[str, str]:
    """POST the start route for the SAML connection; returns the redirect URL's params."""
    response = client.post(f"{PREFIX}/sso/start", json={"connection_id": CONNECTION_ID, "return_to": "/home"})
    assert response.status_code == 200, response.text
    return query_of(response.json()["authorization_url"])


def request_id_of(params: Mapping[str, str]) -> str:
    """The AuthnRequest id inside a redirect's `SAMLRequest`."""
    request = etree.fromstring(zlib.decompress(base64.b64decode(params["SAMLRequest"]), wbits=-15))
    return str(request.get("ID"))


def test_the_routes_sign_a_user_in_end_to_end(harness: Harness, idp: Idp, module_key: rsa.RSAPrivateKey) -> None:
    """Start, post the response to the ACS, leave with a refresh cookie, and refresh as SAML."""
    client, _ = build_client(harness, module_key)
    started = client.post(f"{PREFIX}/sso/start", json={"connection_id": CONNECTION_ID, "return_to": "/home"})
    assert started.status_code == 200, started.text
    binding = next(c for c in started.headers.get_list("set-cookie") if c.startswith(OAUTH_LINK_BINDING_COOKIE))
    assert "samesite=none" in binding.lower()
    assert "secure" in binding.lower()
    params = query_of(started.json()["authorization_url"])

    form = {"SAMLResponse": encode(idp.response(request_id_of(params))), "RelayState": params["RelayState"]}
    response = client.post(f"{PREFIX}/sso/saml/{CONNECTION_ID}/acs", data=form)
    assert response.status_code == 303
    assert response.headers["location"] == f"{FRONTEND}/home?sso=1"
    settings = make_settings()
    assert any(c.startswith(f"{settings.cookie_name}=") for c in response.headers.get_list("set-cookie"))
    assert len(harness.hooks.users) == 1
    assert harness.sso_hooks.logins[-1][1] == "provisioned"

    refreshed = client.post(f"{PREFIX}/refresh")
    assert refreshed.status_code == 200, refreshed.text
    claims = TokenService(settings, FakeKms(module_key)).verify_access_token(refreshed.json()["access_token"])
    assert claims["amr"] == [AMR_SSO, "saml"]
    assert claims[SSO_CONNECTION_CLAIM] == CONNECTION_ID

    replayed = client.post(f"{PREFIX}/sso/saml/{CONNECTION_ID}/acs", data=form)
    assert replayed.status_code == 303
    assert "sso_error=SSO_STATE_INVALID" in replayed.headers["location"]


def test_the_acs_refuses_a_browser_that_did_not_start_the_sign_in(
    harness: Harness, idp: Idp, module_key: rsa.RSAPrivateKey
) -> None:
    """A login CSRF with a genuine response lands nowhere."""
    client, _ = build_client(harness, module_key)
    params = start_through_the_route(client)
    client.cookies.clear()
    form = {"SAMLResponse": encode(idp.response(request_id_of(params))), "RelayState": params["RelayState"]}
    response = client.post(f"{PREFIX}/sso/saml/{CONNECTION_ID}/acs", data=form)
    assert response.status_code == 303
    assert "sso_error=SSO_STATE_INVALID" in response.headers["location"]
    assert harness.hooks.users == {}


def test_the_acs_refuses_a_state_from_another_connection(
    harness: Harness, idp: Idp, module_key: rsa.RSAPrivateKey
) -> None:
    """The path's connection id must be the one the state was minted for."""
    client, _ = build_client(harness, module_key)
    params = start_through_the_route(client)
    form = {"SAMLResponse": encode(idp.response(request_id_of(params))), "RelayState": params["RelayState"]}
    response = client.post(f"{PREFIX}/sso/saml/conn_other/acs", data=form)
    assert response.status_code == 303
    assert response.headers["location"] == f"{FRONTEND}?sso_error=SSO_STATE_INVALID"


def test_the_acs_redirects_a_refused_response_with_its_code(
    harness: Harness, idp: Idp, module_key: rsa.RSAPrivateKey
) -> None:
    """A tampered response comes back as `SSO_SAML_INVALID`, and no session is set."""
    client, _ = build_client(harness, module_key)
    params = start_through_the_route(client)
    document = idp.response(request_id_of(params)).replace(f">{SUBJECT}<", ">admin<")
    response = client.post(
        f"{PREFIX}/sso/saml/{CONNECTION_ID}/acs",
        data={"SAMLResponse": encode(document), "RelayState": params["RelayState"]},
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"{FRONTEND}/home?sso_error=SSO_SAML_INVALID"
    assert harness.hooks.users == {}


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (b'{"SAMLResponse": "x", "RelayState": "y"}', "application/json"),
        (b"SAMLResponse=x", "application/x-www-form-urlencoded"),
        (b"SAMLResponse=x&SAMLResponse=y&RelayState=z", "application/x-www-form-urlencoded"),
        (b"RelayState=" + b"a" * (600 * 1024), "application/x-www-form-urlencoded"),
    ],
)
def test_the_acs_refuses_a_post_that_is_not_one_saml_form(
    harness: Harness, module_key: rsa.RSAPrivateKey, content: bytes, content_type: str
) -> None:
    """JSON, a missing field, a repeated field and an oversize body are all refused."""
    client, _ = build_client(harness, module_key)
    response = client.post(
        f"{PREFIX}/sso/saml/{CONNECTION_ID}/acs", content=content, headers={"content-type": content_type}
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"{FRONTEND}?sso_error=SSO_SAML_INVALID"


def test_the_metadata_route_serves_saml_metadata(harness: Harness, module_key: rsa.RSAPrivateKey) -> None:
    """Served as `application/samlmetadata+xml`; an unknown connection answers 404 JSON."""
    client, _ = build_client(harness, module_key)
    response = client.get(f"{PREFIX}/sso/saml/{CONNECTION_ID}/metadata")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/samlmetadata+xml")
    assert etree.fromstring(response.content).get("entityID") == SP_ENTITY

    missing = client.get(f"{PREFIX}/sso/saml/conn_missing/metadata")
    assert missing.status_code == 404
    assert missing.json()["error_code"] == "SSO_CONNECTION_NOT_FOUND"


def test_the_saml_routes_appear_in_the_openapi_document(harness: Harness, module_key: rsa.RSAPrivateKey) -> None:
    """The schema builds and declares the assertion consumer's redirect."""
    _, app = build_client(harness, module_key)
    paths = app.openapi()["paths"]
    acs = paths[f"{PREFIX}/sso/saml/{{connection_id}}/acs"]["post"]
    assert "303" in acs["responses"]
    assert f"{PREFIX}/sso/saml/{{connection_id}}/metadata" in paths


def test_no_saml_routes_mount_without_saml(idp: Idp, module_key: rsa.RSAPrivateKey) -> None:
    """A service with SAML off adds nothing to the router."""
    harness = Harness(idp)
    harness.service = SsoService(
        make_settings(),
        harness.hooks,
        harness.sso_hooks,
        states=harness.stores.require_oauth_states(),
        links=harness.stores.require_oauth_links(),
        cipher=SecretMasterKeyCipher(os.urandom(32)),
    )
    _, app = build_client(harness, module_key)
    assert not any("/sso/saml/" in path for path in app.openapi()["paths"])


def idp_metadata(idp: Idp, *, entity_id: str = IDP_ENTITY, cert: str | None = None) -> str:
    """An identity provider's metadata with a signing key and both bindings."""
    body = bare_base64(idp.cert) if cert is None else cert
    return (
        f'<md:EntityDescriptor xmlns:md="{MD_NS}" xmlns:ds="{DS_NS}" entityID="{entity_id}">'
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{P_NS}" WantAuthnRequestsSigned="false">'
        '<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>'
        f"<ds:X509Certificate>\n{body}\n</ds:X509Certificate>"
        "</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        '<md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data>'
        "<ds:X509Certificate>ignored</ds:X509Certificate>"
        "</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"
        f'<md:SingleSignOnService Binding="{SAML_BINDING_HTTP_POST}" Location="{IDP_SSO_URL}/post"/>'
        f'<md:SingleSignOnService Binding="{SAML_BINDING_HTTP_REDIRECT}" Location="{IDP_SSO_URL}"/>'
        "</md:IDPSSODescriptor>"
        "</md:EntityDescriptor>"
    )


def test_idp_metadata_imports_into_a_working_connection(idp: Idp) -> None:
    """Entity id, the HTTP-Redirect URL and the signing certificate, never the encryption one."""
    metadata = parse_saml_idp_metadata(idp_metadata(idp))
    assert metadata.entity_id == IDP_ENTITY
    assert metadata.sso_url == IDP_SSO_URL
    assert len(metadata.certificates) == 1
    assert metadata.want_authn_requests_signed is False

    harness = Harness(idp, make_connection(idp, **_config_fields(metadata.connection_config())))
    record = harness.begin()
    assert harness.verify(idp.response(record.nonce), record).subject == SUBJECT


def _config_fields(config: SamlConnectionConfig) -> dict[str, Any]:
    """The fields of a config, for `make_connection`."""
    return {
        "idp_entity_id": config.idp_entity_id,
        "idp_sso_url": config.idp_sso_url,
        "idp_certificates": config.idp_certificates,
    }


def test_an_entities_descriptor_needs_an_entity_id_to_choose(idp: Idp) -> None:
    """With several providers, `entity_id` picks one; without it the import is refused."""
    first = idp_metadata(idp)
    second = idp_metadata(idp, entity_id="https://other.example.test/idp")
    document = f'<md:EntitiesDescriptor xmlns:md="{MD_NS}">{first}{second}</md:EntitiesDescriptor>'
    with pytest.raises(SsoRejected) as excinfo:
        parse_saml_idp_metadata(document)
    assert excinfo.value.error_code == "SSO_SAML_METADATA_INVALID"
    assert parse_saml_idp_metadata(document, entity_id=IDP_ENTITY).entity_id == IDP_ENTITY


@pytest.mark.parametrize(
    "document",
    [
        "<not-metadata/>",
        '<!DOCTYPE x [<!ENTITY e "boom">]><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>',
    ],
)
def test_unusable_idp_metadata_is_refused(document: str) -> None:
    """A wrong root or a DOCTYPE is refused."""
    with pytest.raises(SsoRejected) as excinfo:
        parse_saml_idp_metadata(document)
    assert excinfo.value.error_code == "SSO_SAML_METADATA_INVALID"


def test_idp_metadata_with_a_broken_certificate_is_refused(idp: Idp) -> None:
    """A signing certificate that does not parse fails the import."""
    with pytest.raises(SsoRejected) as excinfo:
        parse_saml_idp_metadata(idp_metadata(idp, cert="bm90IGEgY2VydA=="))
    assert excinfo.value.error_code == "SSO_SAML_METADATA_INVALID"


def public_guard() -> PublicUrlGuard:
    """The real guard, with a resolver that answers one public address for every host."""
    return PublicUrlGuard(resolver=lambda host: [PUBLIC_ADDRESS])


def test_idp_metadata_is_fetched_by_url(idp: Idp) -> None:
    """Fetched through the guard without following redirects."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        """Serve the metadata document."""
        seen.append(request)
        return httpx.Response(200, content=idp_metadata(idp).encode("utf-8"))

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        metadata = fetch_saml_idp_metadata(f"{IDP_ENTITY}", url_guard=public_guard(), client=http)
    assert metadata.entity_id == IDP_ENTITY
    assert str(seen[0].url) == IDP_ENTITY


def test_idp_metadata_fetch_refuses_an_unsafe_url() -> None:
    """Plain HTTP and private addresses are refused before any request."""
    with pytest.raises(SsoRejected) as excinfo:
        fetch_saml_idp_metadata("http://idp.example.test/metadata", url_guard=public_guard())
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"
    with pytest.raises(SsoRejected) as excinfo:
        fetch_saml_idp_metadata(
            "https://idp.example.test/metadata", url_guard=PublicUrlGuard(resolver=lambda host: ["10.0.0.5"])
        )
    assert excinfo.value.error_code == "SSO_PROVIDER_URL_REFUSED"


@pytest.mark.parametrize("status", [302, 404, 500])
def test_idp_metadata_fetch_failure_is_a_502(status: int) -> None:
    """A redirect or an error status is not followed or parsed."""

    def handler(request: httpx.Request) -> httpx.Response:
        """Answer with the status under test."""
        return httpx.Response(status, headers={"location": "https://elsewhere.example.test/"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http, pytest.raises(SsoRejected) as excinfo:
        fetch_saml_idp_metadata(IDP_ENTITY, url_guard=public_guard(), client=http)
    assert excinfo.value.error_code == "SSO_SAML_METADATA_UNREACHABLE"
    assert excinfo.value.status_code == 502
