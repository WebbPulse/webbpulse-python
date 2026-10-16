"""DNS TXT domain verification: prove a tenant controls a domain before trusting its addresses.

The tenant publishes `<prefix>-verification=<token>` as a TXT record on the domain, and the
product checks for it. Uniqueness of a verified domain across tenants is the product's to
enforce, in its own table. The default resolver needs `dnspython` from the `sso` extra.
"""

from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol

from webbpulse.identity.storage import constant_time_equals

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Sequence

__all__ = [
    "DOMAIN_VERIFICATION_TOKEN_BYTES",
    "DnsPythonTxtResolver",
    "DomainVerificationChallenge",
    "DomainVerificationUnavailable",
    "TxtResolver",
    "domain_of_email",
    "domain_verification_challenge",
    "is_domain_verified",
    "new_domain_verification_token",
    "normalise_domain",
]

_log = logging.getLogger(__name__)

DOMAIN_VERIFICATION_TOKEN_BYTES: Final = 24

_LABEL_PATTERN: Final = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_PREFIX_PATTERN: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")


class DomainVerificationUnavailable(Exception):
    """DNS could not answer, so the domain's state is unknown rather than unverified."""


def normalise_domain(domain: str) -> str:
    """A domain lower-cased, IDNA encoded and stripped of a trailing dot, or `ValueError`.

    Refuses anything that is not a plausible registrable name: a single label, an IP
    address, a wildcard, or a label that breaks the hostname rules.
    """
    candidate = domain.strip().rstrip(".").lower()
    try:
        encoded = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("That is not a valid domain name.") from exc
    labels = encoded.split(".")
    if (
        len(encoded) > 253
        or len(labels) < 2
        or not all(_LABEL_PATTERN.fullmatch(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise ValueError("That is not a valid domain name.")
    return encoded


def domain_of_email(email: str) -> str:
    """The normalised domain of an email address, or `ValueError` when it has none."""
    _, at, domain = email.strip().rpartition("@")
    if not at:
        raise ValueError("That is not a valid email address.")
    return normalise_domain(domain)


def new_domain_verification_token() -> str:
    """A fresh unguessable token for a TXT record, URL and DNS safe."""
    return secrets.token_urlsafe(DOMAIN_VERIFICATION_TOKEN_BYTES)


@dataclass(frozen=True, slots=True)
class DomainVerificationChallenge:
    """The TXT record a tenant must publish: where it goes and exactly what it says."""

    domain: str
    record_name: str
    record_type: str
    record_value: str


def domain_verification_challenge(domain: str, token: str, *, prefix: str) -> DomainVerificationChallenge:
    """The record proving control of `domain`: TXT `<prefix>-verification=<token>` at its apex.

    `prefix` names the product, such as `example` for `example-verification=`, so two
    products verifying the same domain never read each other's records.
    """
    if not _PREFIX_PATTERN.fullmatch(prefix):
        raise ValueError("A verification prefix is lower-case letters, digits and hyphens.")
    if not token:
        raise ValueError("A verification token is required.")
    normalised = normalise_domain(domain)
    return DomainVerificationChallenge(
        domain=normalised,
        record_name=normalised,
        record_type="TXT",
        record_value=f"{prefix}-verification={token}",
    )


class TxtResolver(Protocol):
    """Looks up the TXT strings published at a name.

    A Protocol, so `DnsPythonTxtResolver` and a test double satisfy it without inheritance.
    """

    def txt_records(self, name: str) -> Sequence[str]:
        """Every TXT record at `name`, each with its strings joined, or empty for none.

        Raises `DomainVerificationUnavailable` when DNS cannot answer.
        """
        ...


class DnsPythonTxtResolver:
    """`TxtResolver` over `dnspython`, imported on first use so the extra stays optional."""

    def __init__(self, *, lifetime: float = 5.0, nameservers: Sequence[str] = ()) -> None:
        """Hold the total lookup time budget and, optionally, the nameservers to ask."""
        self._lifetime = lifetime
        self._nameservers = list(nameservers)

    def txt_records(self, name: str) -> list[str]:
        """Every TXT record at `name`; no such name or no TXT answers as empty."""
        import dns.exception
        import dns.resolver

        resolver = dns.resolver.Resolver()
        if self._nameservers:
            resolver.nameservers = self._nameservers
        try:
            answer = resolver.resolve(name, "TXT", lifetime=self._lifetime)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except dns.exception.DNSException as exc:
            raise DomainVerificationUnavailable(type(exc).__name__) from exc
        records: list[str] = []
        for rdata in answer:
            strings = getattr(rdata, "strings", ())
            records.append(b"".join(strings).decode("utf-8", errors="replace"))
        return records


def is_domain_verified(
    domain: str,
    token: str,
    *,
    prefix: str,
    resolver: TxtResolver | None = None,
) -> bool:
    """Whether the domain publishes this token's record right now.

    Compares in constant time and tolerates surrounding whitespace. Raises
    `DomainVerificationUnavailable` when DNS cannot answer, so a timeout never reads as a
    revoked verification.
    """
    challenge = domain_verification_challenge(domain, token, prefix=prefix)
    lookup = resolver if resolver is not None else DnsPythonTxtResolver()
    found = any(
        constant_time_equals(record.strip(), challenge.record_value) for record in lookup.txt_records(challenge.record_name)
    )
    _log.info(
        "Domain verification checked.",
        extra={"event": "sso.domain_checked", "domain": challenge.domain, "verified": found},
    )
    return found
