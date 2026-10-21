"""The SAML 2.0 leg of single sign-on: the AuthnRequest, SP metadata, and response verification.

A service provider for the Web Browser SSO profile: the AuthnRequest goes out over
HTTP-Redirect and the response comes back over HTTP-POST to the assertion consumer service.
Signatures are checked with `signxml` (pure Python, no `xmlsec`) on a hardened `lxml`
parser, both from the `saml` extra and imported only when a response or metadata document
is parsed.
Encrypted assertions and signed AuthnRequests are not supported.
"""

from __future__ import annotations

import base64
import binascii
import logging
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlencode, urlsplit
from xml.sax.saxutils import escape, quoteattr

from webbpulse.identity.sso import (
    SAML_DEFAULT_EMAIL_ATTRIBUTES,
    SAML_DEFAULT_NAME_ATTRIBUTES,
    SSO_PROTOCOL_SAML,
    SamlConnectionConfig,
    SsoIdentity,
    SsoRejected,
)
from webbpulse.identity.storage import constant_time_equals

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterable

    import httpx

    from webbpulse.identity.sso import AssertionReplayStore, SsoConnection
    from webbpulse.identity.sso_oidc import UrlGuard

__all__ = [
    "SAML_ASSERTION_NS",
    "SAML_BINDING_HTTP_POST",
    "SAML_BINDING_HTTP_REDIRECT",
    "SAML_METADATA_MAX_BYTES",
    "SAML_METADATA_NS",
    "SAML_PROTOCOL_NS",
    "SAML_REPLAY_KEY_PREFIX",
    "SAML_RESPONSE_MAX_BYTES",
    "SamlIdpMetadata",
    "SamlSsoClient",
    "fetch_saml_idp_metadata",
    "parse_saml_idp_metadata",
]

_log = logging.getLogger(__name__)

SAML_PROTOCOL_NS: Final = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_ASSERTION_NS: Final = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML_METADATA_NS: Final = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS_NS: Final = "http://www.w3.org/2000/09/xmldsig#"
_XENC_NS: Final = "http://www.w3.org/2001/04/xmlenc#"

SAML_BINDING_HTTP_POST: Final = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
SAML_BINDING_HTTP_REDIRECT: Final = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

_STATUS_SUCCESS: Final = "urn:oasis:names:tc:SAML:2.0:status:Success"
_NAMEID_TRANSIENT: Final = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
_NAMEID_EMAIL: Final = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
_NAMEID_ENTITY: Final = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
_CM_BEARER: Final = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
_EMAIL_CLAIM: Final = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"

SAML_RESPONSE_MAX_BYTES: Final = 256 * 1024
"""The largest base64 `SAMLResponse` accepted, before it is decoded."""

SAML_METADATA_MAX_BYTES: Final = 1024 * 1024
"""The largest identity provider metadata document parsed or fetched."""

SAML_REPLAY_KEY_PREFIX: Final = "saml-assertion:"
"""The replay store key prefix: `saml-assertion:<connection_id>#<assertion id>`."""

_REPLAY_TTL_FLOOR_SECONDS: Final = 60.0
_REPLAY_TTL_CEILING_SECONDS: Final = 86400.0
_MAX_SUBJECT_LENGTH: Final = 512

_GIVEN_NAME_ATTRIBUTES: Final = (
    "givenName",
    "firstName",
    "urn:oid:2.5.4.42",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
)
_SURNAME_ATTRIBUTES: Final = (
    "sn",
    "surname",
    "lastName",
    "urn:oid:2.5.4.4",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
)


def _p(tag: str) -> str:
    """A tag in the SAML protocol namespace, in lxml's Clark notation."""
    return f"{{{SAML_PROTOCOL_NS}}}{tag}"


def _a(tag: str) -> str:
    """A tag in the SAML assertion namespace."""
    return f"{{{SAML_ASSERTION_NS}}}{tag}"


def _md(tag: str) -> str:
    """A tag in the SAML metadata namespace."""
    return f"{{{SAML_METADATA_NS}}}{tag}"


def _ds(tag: str) -> str:
    """A tag in the XML signature namespace."""
    return f"{{{_DS_NS}}}{tag}"


def _not_installed() -> SsoRejected:
    """The refusal when the `saml` extra is missing from this deployment."""
    return SsoRejected(
        "That single sign-on connection is not available.",
        error_code="SSO_PROTOCOL_UNSUPPORTED",
        status_code=501,
    )


def _etree() -> Any:
    """`lxml.etree`, imported on first use so a plain `identity` install never loads it."""
    try:
        from lxml import etree
    except ImportError as exc:
        raise _not_installed() from exc
    return etree


def _signxml() -> Any:
    """`signxml`, imported on first use."""
    try:
        import signxml
    except ImportError as exc:
        raise _not_installed() from exc
    return signxml


def _parse_xml(document: bytes) -> Any:
    """Parse untrusted XML with entities, DTDs, network access and huge trees all off.

    A document declaring a DOCTYPE is refused before parsing, so no entity is ever expanded.
    """
    head = document[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in document.lower():
        raise ValueError("doctype")
    etree = _etree()
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        remove_comments=True,
        remove_pis=True,
    )
    root = etree.fromstring(document, parser=parser)
    if root.getroottree().docinfo.doctype:
        raise ValueError("doctype")
    return root


def _text(element: Any) -> str:
    """Every text node under an element, joined and stripped, so a split value reads whole."""
    if element is None:
        return ""
    return "".join(str(part) for part in element.itertext()).strip()


def _attr(element: Any, name: str) -> str:
    """An attribute's value, or an empty string."""
    value = element.get(name)
    return str(value).strip() if value is not None else ""


def _instant(value: str) -> float:
    """A SAML `xs:dateTime` as epoch seconds; a value without an offset is UTC."""
    moment = datetime.fromisoformat(value.strip())
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.timestamp()


def _pem(certificate: str) -> str:
    """A certificate as PEM, accepting PEM or bare base64 DER with any whitespace."""
    body = certificate.strip()
    if body.startswith("-----BEGIN"):
        lines = [line.strip() for line in body.splitlines()]
        body = "".join(line for line in lines if line and not line.startswith("-----"))
    body = "".join(body.split())
    wrapped = "\n".join(body[index : index + 64] for index in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"


def _check_certificate(certificate: str) -> str:
    """The certificate as PEM after checking it parses, or `ValueError`."""
    from cryptography import x509

    pem = _pem(certificate)
    x509.load_pem_x509_certificate(pem.encode("ascii"))
    return pem


def _as_seconds(leeway: timedelta | float) -> float:
    """A leeway in seconds, from a `timedelta` or a number."""
    if isinstance(leeway, timedelta):
        return leeway.total_seconds()
    return float(leeway)


class SamlSsoClient:
    """The AuthnRequest, SP metadata, and response verification for SAML connections.

    `replay` remembers every accepted assertion id until it expires, so a captured response
    cannot be posted twice. `leeway` is the clock skew allowed on every time check.
    `trusted_hosts` lets a named host serve the identity provider over plain HTTP, for a
    local test provider only.
    """

    def __init__(
        self,
        *,
        replay: AssertionReplayStore,
        leeway: timedelta | float = 30.0,
        clock: Callable[[], float] = time.time,
        trusted_hosts: Iterable[str] = (),
    ) -> None:
        """Hold the replay store, the skew leeway, the clock and the trusted host names."""
        self._replay = replay
        self._leeway = _as_seconds(leeway)
        self._clock = clock
        self._trusted = frozenset(host.lower() for host in trusted_hosts)

    def _config(self, connection: SsoConnection) -> SamlConnectionConfig:
        """The connection's SAML settings, refusing a connection that has none."""
        if connection.protocol != SSO_PROTOCOL_SAML or connection.saml is None:
            raise SsoRejected(
                "That single sign-on connection is not available.",
                error_code="SSO_PROTOCOL_UNSUPPORTED",
                status_code=501,
            )
        return connection.saml

    def _require_sso_url(self, url: str) -> None:
        """Refuse an identity provider sign-in URL that is not HTTPS, unless its host is trusted.

        The browser follows this URL, so the check stops a `javascript:` or plain HTTP value
        from a tenant's configuration reaching it.
        """
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        allowed = parts.scheme == "https" or (parts.scheme == "http" and host in self._trusted)
        if not allowed or not host or parts.username or parts.password:
            _log.warning(
                "SSO provider URL refused.",
                extra={"event": "sso.url_refused", "host": host, "reason": "scheme"},
            )
            raise SsoRejected(
                "That single sign-on connection is not available.",
                error_code="SSO_PROVIDER_URL_REFUSED",
                status_code=502,
            )

    def authn_request_url(
        self,
        connection: SsoConnection,
        *,
        request_id: str,
        acs_url: str,
        sp_entity_id: str,
        relay_state: str,
    ) -> str:
        """The identity provider URL carrying a deflated AuthnRequest and the `RelayState`.

        The request is unsigned, which the SP metadata declares with `AuthnRequestsSigned`.
        """
        config = self._config(connection)
        self._require_sso_url(config.idp_sso_url)
        issued = datetime.fromtimestamp(self._clock(), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        policy = (
            f'<samlp:NameIDPolicy Format={quoteattr(config.name_id_format)} AllowCreate="true"/>'
            if config.name_id_format
            else '<samlp:NameIDPolicy AllowCreate="true"/>'
        )
        request = (
            f'<samlp:AuthnRequest xmlns:samlp="{SAML_PROTOCOL_NS}" xmlns:saml="{SAML_ASSERTION_NS}"'
            f' ID={quoteattr(request_id)} Version="2.0" IssueInstant="{issued}"'
            f" Destination={quoteattr(config.idp_sso_url)}"
            f" AssertionConsumerServiceURL={quoteattr(acs_url)}"
            f' ProtocolBinding="{SAML_BINDING_HTTP_POST}">'
            f"<saml:Issuer>{escape(sp_entity_id)}</saml:Issuer>"
            f"{policy}"
            "</samlp:AuthnRequest>"
        )
        deflated = zlib.compress(request.encode("utf-8"), wbits=-15)
        query = urlencode({"SAMLRequest": base64.b64encode(deflated).decode("ascii"), "RelayState": relay_state})
        separator = "&" if "?" in config.idp_sso_url else "?"
        return f"{config.idp_sso_url}{separator}{query}"

    def sp_metadata(self, connection: SsoConnection, *, sp_entity_id: str, acs_url: str) -> str:
        """The service provider metadata document to give the identity provider."""
        config = self._config(connection)
        name_id = f"<md:NameIDFormat>{escape(config.name_id_format)}</md:NameIDFormat>" if config.name_id_format else ""
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<md:EntityDescriptor xmlns:md="{SAML_METADATA_NS}" entityID={quoteattr(sp_entity_id)}>'
            '<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"'
            f' protocolSupportEnumeration="{SAML_PROTOCOL_NS}">'
            f"{name_id}"
            f'<md:AssertionConsumerService Binding="{SAML_BINDING_HTTP_POST}"'
            f' Location={quoteattr(acs_url)} index="0" isDefault="true"/>'
            "</md:SPSSODescriptor>"
            "</md:EntityDescriptor>\n"
        )

    def identity_from_response(
        self,
        connection: SsoConnection,
        *,
        saml_response: str,
        request_id: str,
        acs_url: str,
        sp_entity_id: str,
    ) -> SsoIdentity:
        """Verify a posted `SAMLResponse` and return the identity its one signed assertion carries.

        The assertion must be signed itself, or sit inside a signed Response, as Entra can be
        set to do; with both, both must verify. Only elements a verified signature covers are
        read, so a wrapped or moved assertion is refused. `request_id` is the AuthnRequest id
        from the spent state, which rules out unsolicited responses. The assertion id is
        claimed last, so a refused response never burns it.
        """
        config = self._config(connection)
        if not request_id:
            raise _invalid(connection, "request_id")
        root = self._decode(connection, saml_response)

        if root.tag != _p("Response") or _attr(root, "Version") != "2.0":
            raise _invalid(connection, "not_a_response")
        status = root.find(f"{_p('Status')}/{_p('StatusCode')}")
        if status is None or _attr(status, "Value") != _STATUS_SUCCESS:
            _log.warning(
                "SSO identity provider refused the sign-in.",
                extra={
                    "event": "sso.idp_refused",
                    "connection_id": connection.connection_id,
                    "status": _attr(status, "Value") if status is not None else "",
                },
            )
            raise SsoRejected(
                "Your identity provider did not sign you in. Try again.",
                error_code="SSO_IDP_REFUSED",
            )
        if any(True for _ in root.iter(_a("EncryptedAssertion"), _a("EncryptedID"), f"{{{_XENC_NS}}}EncryptedData")):
            raise _invalid(connection, "encrypted")

        assertions = list(root.iter(_a("Assertion")))
        if len(assertions) != 1 or assertions[0].getparent() is not root:
            raise _invalid(connection, "assertion_count")
        assertion_id = _attr(assertions[0], "ID")
        if not assertion_id:
            raise _invalid(connection, "assertion_id")

        response_signed = root.find(_ds("Signature")) is not None
        assertion_signed = assertions[0].find(_ds("Signature")) is not None
        if not response_signed and not assertion_signed:
            raise _invalid(connection, "unsigned")
        response = root
        assertion: Any = None
        if response_signed:
            response = self._verified(
                connection,
                config,
                root,
                location="./",
                tag=_p("Response"),
                element_id=_attr(root, "ID"),
            )
            assertion = _only_assertion(connection, response, assertion_id)
        if assertion_signed:
            assertion = self._verified(
                connection,
                config,
                root,
                location=f"./{_a('Assertion')}/",
                tag=_a("Assertion"),
                element_id=assertion_id,
            )
        if assertion is None:
            raise _invalid(connection, "signature")

        now = self._clock()
        self._check_response(connection, config, response, request_id=request_id, acs_url=acs_url)
        expiries = self._check_assertion(
            connection,
            config,
            assertion,
            request_id=request_id,
            acs_url=acs_url,
            sp_entity_id=sp_entity_id,
            now=now,
        )
        identity = self._identity(connection, config, assertion)

        latest = max(expiries) if expiries else now
        ttl = min(max(latest + self._leeway - now, _REPLAY_TTL_FLOOR_SECONDS), _REPLAY_TTL_CEILING_SECONDS)
        if not self._replay.claim(f"{SAML_REPLAY_KEY_PREFIX}{connection.connection_id}#{assertion_id}", ttl):
            _log.warning(
                "SSO SAML assertion replayed.",
                extra={"event": "sso.saml_replayed", "connection_id": connection.connection_id},
            )
            raise SsoRejected(
                "That sign-in was already used. Start again.",
                error_code="SSO_SAML_REPLAYED",
            )
        return identity

    def _decode(self, connection: SsoConnection, saml_response: str) -> Any:
        """Base64-decode and parse a posted response, refusing oversize or malformed input."""
        compact = "".join(saml_response.split())
        if not compact or len(compact) > SAML_RESPONSE_MAX_BYTES:
            raise _invalid(connection, "size")
        try:
            document = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise _invalid(connection, "base64") from exc
        try:
            return _parse_xml(document)
        except SsoRejected:
            raise
        except Exception as exc:
            raise _invalid(connection, "xml") from exc

    def _verified(
        self,
        connection: SsoConnection,
        config: SamlConnectionConfig,
        root: Any,
        *,
        location: str,
        tag: str,
        element_id: str,
    ) -> Any:
        """The element one enveloped signature covers, checked to be the element expected.

        Each configured certificate is tried in turn, so a tenant can publish its next one
        before the provider switches. The signature must sit at `location`, carry exactly one
        reference, and that reference must be `#<element_id>` naming an element of `tag`.
        """
        signxml = _signxml()
        if not element_id or not config.idp_certificates:
            raise _invalid(connection, "signature")
        expect = signxml.SignatureConfiguration(location=location, expect_references=1)
        for certificate in config.idp_certificates:
            try:
                result = signxml.XMLVerifier().verify(
                    root,
                    x509_cert=_pem(certificate),
                    id_attribute="ID",
                    expect_config=expect,
                )
            except Exception:
                continue
            signed = result.signed_xml
            reference = result.signature_xml.find(f"{_ds('SignedInfo')}/{_ds('Reference')}")
            if (
                signed is None
                or reference is None
                or signed.tag != tag
                or _attr(signed, "ID") != element_id
                or _attr(reference, "URI") != f"#{element_id}"
            ):
                raise _invalid(connection, "signature_reference")
            return signed
        raise _invalid(connection, "signature")

    def _check_response(
        self,
        connection: SsoConnection,
        config: SamlConnectionConfig,
        response: Any,
        *,
        request_id: str,
        acs_url: str,
    ) -> None:
        """The response must be addressed to this ACS, answer this request and come from this IdP."""
        if _attr(response, "Destination") != acs_url:
            raise _invalid(connection, "destination")
        if not constant_time_equals(_attr(response, "InResponseTo"), request_id):
            raise _invalid(connection, "in_response_to")
        issuer = response.find(_a("Issuer"))
        if issuer is not None and not self._issuer_matches(issuer, config):
            raise _invalid(connection, "issuer")

    def _issuer_matches(self, issuer: Any, config: SamlConnectionConfig) -> bool:
        """Whether an `Issuer` names the configured identity provider."""
        name_format = _attr(issuer, "Format")
        return _text(issuer) == config.idp_entity_id and name_format in ("", _NAMEID_ENTITY)

    def _check_assertion(
        self,
        connection: SsoConnection,
        config: SamlConnectionConfig,
        assertion: Any,
        *,
        request_id: str,
        acs_url: str,
        sp_entity_id: str,
        now: float,
    ) -> list[float]:
        """Check the assertion's issuer, bearer confirmation, conditions and authn statement.

        Returns every expiry instant seen, which bounds how long the replay claim must last.
        """
        skew = self._leeway
        if _attr(assertion, "Version") != "2.0":
            raise _invalid(connection, "assertion_version")
        issuer = assertion.find(_a("Issuer"))
        if issuer is None or not self._issuer_matches(issuer, config):
            raise _invalid(connection, "issuer")

        expiries: list[float] = []
        try:
            confirmed = False
            for confirmation in assertion.findall(f"{_a('Subject')}/{_a('SubjectConfirmation')}"):
                if _attr(confirmation, "Method") != _CM_BEARER:
                    continue
                data = confirmation.find(_a("SubjectConfirmationData"))
                if data is None:
                    continue
                not_on_or_after = _attr(data, "NotOnOrAfter")
                not_before = _attr(data, "NotBefore")
                if (
                    _attr(data, "Recipient") != acs_url
                    or not constant_time_equals(_attr(data, "InResponseTo"), request_id)
                    or not not_on_or_after
                    or now >= _instant(not_on_or_after) + skew
                    or (not_before and now + skew < _instant(not_before))
                ):
                    continue
                expiries.append(_instant(not_on_or_after))
                confirmed = True
            if not confirmed:
                raise _invalid(connection, "subject_confirmation")

            conditions = assertion.find(_a("Conditions"))
            if conditions is None:
                raise _invalid(connection, "conditions")
            not_before = _attr(conditions, "NotBefore")
            not_on_or_after = _attr(conditions, "NotOnOrAfter")
            if not_before and now + skew < _instant(not_before):
                raise _invalid(connection, "not_yet_valid")
            if not_on_or_after:
                if now >= _instant(not_on_or_after) + skew:
                    raise _invalid(connection, "expired")
                expiries.append(_instant(not_on_or_after))
            restrictions = conditions.findall(_a("AudienceRestriction"))
            if not restrictions:
                raise _invalid(connection, "audience")
            for restriction in restrictions:
                if sp_entity_id not in {_text(audience) for audience in restriction.findall(_a("Audience"))}:
                    raise _invalid(connection, "audience")

            statements = assertion.findall(_a("AuthnStatement"))
            if not statements:
                raise _invalid(connection, "authn_statement")
            for statement in statements:
                session_end = _attr(statement, "SessionNotOnOrAfter")
                if session_end and now >= _instant(session_end) + skew:
                    raise _invalid(connection, "session_expired")
        except ValueError as exc:
            raise _invalid(connection, "instant") from exc
        return expiries

    def _identity(self, connection: SsoConnection, config: SamlConnectionConfig, assertion: Any) -> SsoIdentity:
        """The subject, email, name and attributes the verified assertion carries.

        The email comes from the configured attributes, then the WS-Federation emailaddress
        claim, then an emailAddress-format NameID, which covers Okta and Entra defaults.
        """
        attributes: dict[str, list[str]] = {}
        friendly: dict[str, list[str]] = {}
        for attribute in assertion.iter(_a("Attribute")):
            values = [_text(value) for value in attribute.findall(_a("AttributeValue"))]
            name = _attr(attribute, "Name")
            if name:
                attributes.setdefault(name, []).extend(values)
            friendly_name = _attr(attribute, "FriendlyName")
            if friendly_name:
                friendly.setdefault(friendly_name, []).extend(values)

        def first(names: Iterable[str]) -> str:
            """The first non-empty value of the first of these attributes that has one."""
            for name in names:
                for value in attributes.get(name, friendly.get(name, [])):
                    if value:
                        return value
            return ""

        name_id = assertion.find(f"{_a('Subject')}/{_a('NameID')}")
        name_id_value = _text(name_id)
        name_id_format = _attr(name_id, "Format") if name_id is not None else ""
        if config.subject_attribute:
            subject = first((config.subject_attribute,))
        elif name_id_format == _NAMEID_TRANSIENT:
            raise _invalid(connection, "transient_name_id")
        else:
            subject = name_id_value
        if not subject or len(subject) > _MAX_SUBJECT_LENGTH:
            raise _invalid(connection, "subject")

        email = first(config.email_attributes or SAML_DEFAULT_EMAIL_ATTRIBUTES) or first((_EMAIL_CLAIM,))
        if not email and name_id_format == _NAMEID_EMAIL:
            email = name_id_value
        name = first(config.name_attributes or SAML_DEFAULT_NAME_ATTRIBUTES)
        if not name:
            name = " ".join(part for part in (first(_GIVEN_NAME_ATTRIBUTES), first(_SURNAME_ATTRIBUTES)) if part)

        return SsoIdentity(
            connection_id=connection.connection_id,
            protocol=SSO_PROTOCOL_SAML,
            subject=subject,
            email=email.strip(),
            email_verified=False,
            name=name,
            attributes={**attributes, "name_id": name_id_value, "name_id_format": name_id_format},
        )


def _only_assertion(connection: SsoConnection, response: Any, assertion_id: str) -> Any:
    """The one assertion a verified Response holds, as a direct child with the expected id."""
    found = list(response.iter(_a("Assertion")))
    if len(found) != 1 or found[0].getparent() is not response or _attr(found[0], "ID") != assertion_id:
        raise _invalid(connection, "assertion_count")
    return found[0]


def _invalid(connection: SsoConnection, reason: str) -> SsoRejected:
    """The generic refusal for a response that did not verify, with the reason logged only."""
    _log.warning(
        "SSO SAML response verification failed.",
        extra={"event": "sso.saml_invalid", "connection_id": connection.connection_id, "reason": reason},
    )
    return SsoRejected("That sign-in could not be completed. Try again.", error_code="SSO_SAML_INVALID")


@dataclass(frozen=True, slots=True)
class SamlIdpMetadata:
    """The parts of an identity provider's metadata a connection needs.

    `want_authn_requests_signed` is recorded only: this service provider never signs its
    requests, so a provider that insists will refuse them.
    """

    entity_id: str
    sso_url: str
    certificates: tuple[str, ...]
    name_id_formats: tuple[str, ...] = ()
    want_authn_requests_signed: bool = False

    def connection_config(
        self,
        *,
        sp_entity_id: str = "",
        name_id_format: str = "",
        subject_attribute: str = "",
        email_attributes: tuple[str, ...] = SAML_DEFAULT_EMAIL_ATTRIBUTES,
        name_attributes: tuple[str, ...] = SAML_DEFAULT_NAME_ATTRIBUTES,
    ) -> SamlConnectionConfig:
        """A connection config trusting this provider's entity id, sign-in URL and certificates."""
        return SamlConnectionConfig(
            idp_entity_id=self.entity_id,
            idp_sso_url=self.sso_url,
            idp_certificates=self.certificates,
            sp_entity_id=sp_entity_id,
            name_id_format=name_id_format,
            subject_attribute=subject_attribute,
            email_attributes=email_attributes,
            name_attributes=name_attributes,
        )


def _metadata_invalid(reason: str) -> SsoRejected:
    """The refusal for identity provider metadata that cannot be used."""
    _log.warning("SSO SAML metadata refused.", extra={"event": "sso.saml_metadata_invalid", "reason": reason})
    return SsoRejected(
        "That identity provider metadata could not be used.",
        error_code="SSO_SAML_METADATA_INVALID",
    )


def parse_saml_idp_metadata(document: str | bytes, *, entity_id: str = "") -> SamlIdpMetadata:
    """Read the entity id, HTTP-Redirect sign-in URL and signing certificates from IdP metadata.

    Takes an `EntityDescriptor` or an `EntitiesDescriptor`; with several providers in it,
    `entity_id` picks one. The metadata's own signature is not checked, so take it from the
    provider over HTTPS or from an administrator who downloaded it.
    """
    raw = document.encode("utf-8") if isinstance(document, str) else document
    if len(raw) > SAML_METADATA_MAX_BYTES:
        raise _metadata_invalid("size")
    try:
        root = _parse_xml(raw)
    except SsoRejected:
        raise
    except Exception as exc:
        raise _metadata_invalid("xml") from exc

    if root.tag == _md("EntityDescriptor"):
        candidates = [root]
    elif root.tag == _md("EntitiesDescriptor"):
        candidates = list(root.iter(_md("EntityDescriptor")))
    else:
        raise _metadata_invalid("root")
    providers = [item for item in candidates if item.find(_md("IDPSSODescriptor")) is not None]
    if entity_id:
        providers = [item for item in providers if _attr(item, "entityID") == entity_id]
    if len(providers) != 1:
        raise _metadata_invalid("entity")
    entity = providers[0]
    descriptor = entity.find(_md("IDPSSODescriptor"))

    sso_url = ""
    for service in descriptor.findall(_md("SingleSignOnService")):
        if _attr(service, "Binding") == SAML_BINDING_HTTP_REDIRECT:
            sso_url = _attr(service, "Location")
            break
    if not sso_url:
        raise _metadata_invalid("redirect_binding")

    certificates: list[str] = []
    for key in descriptor.findall(_md("KeyDescriptor")):
        if _attr(key, "use") not in ("", "signing"):
            continue
        for cert in key.iter(_ds("X509Certificate")):
            try:
                pem = _check_certificate(_text(cert))
            except Exception as exc:
                raise _metadata_invalid("certificate") from exc
            if pem not in certificates:
                certificates.append(pem)
    if not certificates:
        raise _metadata_invalid("certificate")

    return SamlIdpMetadata(
        entity_id=_attr(entity, "entityID"),
        sso_url=sso_url,
        certificates=tuple(certificates),
        name_id_formats=tuple(_text(item) for item in descriptor.findall(_md("NameIDFormat")) if _text(item)),
        want_authn_requests_signed=_attr(descriptor, "WantAuthnRequestsSigned").lower() in ("true", "1"),
    )


def fetch_saml_idp_metadata(
    url: str,
    *,
    entity_id: str = "",
    url_guard: UrlGuard | None = None,
    client: httpx.Client | None = None,
    timeout: float = 10.0,
) -> SamlIdpMetadata:
    """Fetch identity provider metadata by URL and parse it, through the URL guard.

    The default guard refuses anything but HTTPS to a public address, and with a
    `PublicUrlGuard` the default client connects only to the addresses it approved. Redirects
    are not followed, and a body over `SAML_METADATA_MAX_BYTES` is refused.
    """
    from webbpulse.identity.sso_oidc import PublicUrlGuard

    guard = url_guard or PublicUrlGuard()
    guard(url)
    try:
        import httpx
    except ImportError as exc:
        raise _not_installed() from exc

    owned = client is None
    if client is not None:
        session = client
    else:
        transport = guard.transport() if isinstance(guard, PublicUrlGuard) else None
        session = httpx.Client(timeout=timeout, follow_redirects=False, transport=transport)
    try:
        with session.stream("GET", url, headers={"Accept": "application/samlmetadata+xml, application/xml"}) as reply:
            if reply.status_code != 200:
                raise _metadata_unreachable("status")
            body = bytearray()
            for chunk in reply.iter_bytes():
                body.extend(chunk)
                if len(body) > SAML_METADATA_MAX_BYTES:
                    raise _metadata_invalid("size")
    except httpx.HTTPError as exc:
        raise _metadata_unreachable("transport") from exc
    finally:
        if owned:
            session.close()
    return parse_saml_idp_metadata(bytes(body), entity_id=entity_id)


def _metadata_unreachable(reason: str) -> SsoRejected:
    """The refusal when identity provider metadata could not be fetched."""
    _log.warning("SSO SAML metadata fetch failed.", extra={"event": "sso.saml_metadata_unreachable", "reason": reason})
    return SsoRejected(
        "The identity provider metadata could not be fetched.",
        error_code="SSO_SAML_METADATA_UNREACHABLE",
        status_code=502,
    )
