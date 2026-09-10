"""`IdentityHooks`: the seam where a product's own policy lives.

Section 6.3 of `docs/identity-standard.md` draws the boundary this module implements: **the
product decides who may sign in and what they may do, and the package decides how signing
in works.** A hook cannot change a ceremony, a lifetime, or a verification rule. It answers
questions about users, and it is deliberately small enough to read in one screen.

That split is what keeps the 0.5.0 reasoning intact while reversing its conclusion for the
flows. A WebAuthn ceremony does not differ per product; a refresh rotation does not; a TOTP
window does not. But CarModPicker has ordinary users with `disabled` and `email_verified`
while Portfolio has exactly one administrator, and no amount of shared code makes those the
same question.

## A Protocol and a base class, both

`IdentityHooks` is a `Protocol`, so a product's own class satisfies it structurally with no
import-time coupling and no inheritance. `BaseIdentityHooks` is a concrete class
implementing the same surface, where every hook raises `HookNotImplemented` naming itself.

Both exist because they fail differently and both failures are worth having available. A
product that subclasses the base gets a clear error at the first call of a hook it forgot,
naming the hook and the class. A product that implements the protocol gets the error from
mypy instead, before anything runs, which is better when it is available. Neither is the
right answer for everyone, so neither is imposed.

The two hooks with a safe default are `claims_for` and `on_user_created`. `claims_for`
returns no extra claims, which is correct for a product with no roles, and
`on_user_created` does nothing, which is correct for a product with no side effects to run.
Every other hook raises, because there is no defensible default for "may this user sign in"
and a hook that silently answers yes is the worst possible shape for that question.

`mark_email_verified` deliberately has **no** default, even though "do nothing" looks
harmless. A product that mounted the verification flow and forgot the hook would confirm
addresses that never became verified, and `may_authenticate` would go on refusing the login
it just told the user was now possible. Raising names the missing hook the first time
somebody clicks a link, which is loud and early; silently succeeding produces a flow that
appears to work and never does.

## `may_authenticate` raises rather than returning a bool

A predicate returning `False` says nothing about why, so the caller has to invent a reason
and every product invents a different one. Raising carries the reason, and
`AuthenticationRefused` carries a `message` the flow may show the user and an `error_code`
the frontend can branch on, so "your email is not verified" and "this account is disabled"
stay distinguishable without the package knowing either concept.

It is also the shape that fails safe. A hook that forgets to return anything returns `None`,
and `if not hooks.may_authenticate(user)` on a `None` refuses the login, but
`if hooks.may_authenticate(user)` admits it. A hook that raises has no such pair of
readings: not raising is the only way to permit, and every mistake in writing one lands on
the refusing side.

## `user_repository` and the ownership convention

Section 4.2 records that the user record is owned by the `users` domain and that `identity`
is a writer of the authentication columns only. That is a convention rather than an
enforcement, and this is where it is expressed: `user_repository` hands back the product's
own `webbpulse.dynamodb.Repository` for its own users table, and the identity flows read
freely and write only through the narrow update paths M2 adds.

Typed as `object` rather than as `Repository`, so this module imports nothing from the
`dynamodb` extra. A product that serves a JWKS and nothing else should not be made to
install boto3, which is the same argument the `identity` extra already makes for KMS.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "AuthenticationRefused",
    "BaseIdentityHooks",
    "HookNotImplemented",
    "IdentityHooks",
]


class HookNotImplemented(NotImplementedError):
    """A hook the flow needed is not implemented by the product's hooks class.

    Raised by `BaseIdentityHooks` rather than by an abstract method, so the failure names
    the hook and the class at the moment it is needed instead of refusing to instantiate
    the class at all. A product mounting only the discovery routes in M1 has no reason to
    implement `load_user_by_email` yet, and an ABC would demand it anyway.
    """


class AuthenticationRefused(Exception):
    """The product's policy refuses this login.

    Raised by `may_authenticate`. Carries the message a flow may show the user and a
    machine-readable code the frontend branches on, so the package can render a refusal it
    does not itself understand.

    `message` reaches the caller, so it must not distinguish an existing account from a
    missing one. Section 5.4 requires login to answer identically either way, and a hook
    that raises "this account is disabled" for a real user and lets the generic path answer
    "invalid email or password" for a missing one has reintroduced enumeration through the
    hook.
    """

    def __init__(self, message: str, *, error_code: str = "AUTHENTICATION_REFUSED") -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code


@runtime_checkable
class IdentityHooks(Protocol):
    """The product's own identity policy, supplied to `build_identity_router`.

    Structural: a product's class satisfies this by having the methods, with no import of
    this module and no inheritance. `BaseIdentityHooks` is the concrete alternative.

    Every method may be `def` or `async def`. The flows in M2 and later await whatever comes
    back, so a product whose repository is synchronous writes plain methods and one talking
    to something async writes coroutines, and neither is privileged.

    None of these is called in M1: 0.9.0 mounts only the discovery routes, and the hooks are
    here so that a product's composition root is written once rather than gaining a required
    argument at every milestone.
    """

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """The user with this id, or `None`.

        `user_id` is the `sub` claim, which section 3.3 fixes as the user's immutable id and
        never the username or the email.
        """
        ...

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """The user with this email address, or `None`.

        `email` arrives already lowercased and stripped, matching the `email_lower-index`
        GSI both products key on, so a hook must not lowercase it again against a
        case-sensitive store.

        Returning `None` must be indistinguishable in cost from returning a user, or it is a
        timing oracle for whether an address has an account. The login flow equalises the
        password verification against a dummy hash; it cannot equalise a lookup that is
        slower when it finds something.
        """
        ...

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Raise `AuthenticationRefused` to refuse this login, or return `None` to permit.

        CarModPicker checks `disabled` and `email_verified`; Portfolio checks `is_admin` and
        `is_active`. The package knows neither concept.
        """
        ...

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """The product's own claims for this user: roles, scopes, tenant.

        Never the registered claims. `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `sid`
        and `typ` belong to the token service, and a hook returning any of them has those
        entries dropped rather than honoured: a product that could rewrite `iss` or `exp`
        through this seam could mint a token for another issuer or one that never expires.
        """
        ...

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Product-side side effects for a new account: default rows, a welcome email.

        `via` names how the account came to exist: `"password"`, `"google"`, `"github"`.
        Raising here fails the registration, so a hook that does non-essential work should
        catch its own errors.
        """
        ...

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create the user row for a registration and return it.

        Section 4.2 gives the `users` table to the product's own domain, so the package
        cannot write that row itself: it does not know the product's schema, its username
        rules, or which columns are required. Registration therefore hands the product an
        email and the authentication attributes it computed, and the product decides what a
        user record is.

        The returned mapping must carry the immutable user id under `id`, because that is
        what becomes the `sub` claim and the partition key of every credential.

        Called before `on_user_created`, which is for side effects rather than for the row
        itself. Raising fails the registration.
        """
        ...

    def mark_email_verified(self, user_id: str) -> None:
        """Record that this user's email address is now confirmed.

        The `email_verified` column lives on the product's `users` table, which section 4.2
        gives to the `users` domain rather than to `identity`, so the package cannot write
        it. This is the same seam `create_user` is, for the same reason: the package owns
        the token that proves the address, the product owns the row that records it.

        Called only after a verification link has been consumed, so an implementation does
        not re-check anything. It sets the column and returns.

        Raising fails the confirmation, and the link is already consumed by then, so a
        product whose write can fail transiently should retry inside the hook rather than
        let the user's one link be spent on a failure.
        """
        ...

    def user_repository(self) -> object:
        """The product's own users table, as a `webbpulse.dynamodb.Repository`.

        Typed `object` so this module needs no `dynamodb` extra. The identity flows read
        users freely and write only the authentication attributes section 4.2 lists.
        """
        ...

    def has_other_sign_in_method(self, user_id: str) -> bool:
        """Whether this user holds a sign-in method the identity package cannot see.

        Added in M6 and **defaulted to `False`**, so every `IdentityHooks` implementation
        written before it keeps satisfying this Protocol and keeps working unchanged.

        It exists for exactly one caller: `OAuthService.unlink`, which refuses to remove the
        last way into an account. That check can see two of the three answers itself, the
        remaining OAuth links and the password credential, and cannot see the third. Passkeys
        live in M5's `webauthn-credentials` table, and anything else a product invented, such
        as an SSO assertion or a magic link, is not in this package's tables at all. So the
        product is asked.

        **`False` is the safe default, and the direction matters.** A product that has not
        implemented this can only ever be told "no additional methods", which makes `unlink`
        refuse in cases where it might have allowed. The cost is a user who must set a
        password before unlinking a provider they could safely have unlinked. A default of
        `True` would invert that: a product that forgot the hook would let its users delete
        their last credential, and a locked-out account has no recovery path this design can
        offer. Refusing too often is a support ticket; allowing too often is a lost account.

        Do **not** count OAuth links or the password here. `unlink` already counts both, and
        counting them twice cannot make the answer wrong, but a product that counted only
        those and forgot passkeys would be reporting the very thing this hook was added to
        ask about.
        """
        ...


class BaseIdentityHooks:
    """A concrete `IdentityHooks` whose unimplemented hooks raise a clear error.

    Subclass it and override what the product needs::

        class CarModPickerHooks(BaseIdentityHooks):
            def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
                return users.find_by_unique("email_lower", email)

            def may_authenticate(self, user: Mapping[str, Any]) -> None:
                if user.get("disabled"):
                    raise AuthenticationRefused("Invalid email or password.")

    Not an ABC on purpose. An abstract method refuses to instantiate the class at all, which
    would demand `load_user_by_email` from a product that in M1 mounts nothing but the two
    discovery routes. Raising at the call keeps the error just as loud and just as specific
    while letting a partial implementation exist during the milestones where it is correct.
    """

    def _not_implemented(self, hook: str) -> HookNotImplemented:
        return HookNotImplemented(
            f"{type(self).__name__} does not implement the {hook!r} hook, and an identity "
            "flow needed it. See section 6.3 of the identity standard for what each hook "
            "owns."
        )

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        raise self._not_implemented("load_user_by_id")

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        raise self._not_implemented("load_user_by_email")

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        raise self._not_implemented("may_authenticate")

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """No product claims. Correct for a product with no roles, so it is the default."""
        return {}

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Nothing. Correct for a product with no side effects, so it is the default."""
        return None

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        raise self._not_implemented("create_user")

    def mark_email_verified(self, user_id: str) -> None:
        raise self._not_implemented("mark_email_verified")

    def user_repository(self) -> object:
        raise self._not_implemented("user_repository")

    def has_other_sign_in_method(self, user_id: str) -> bool:
        """No methods this package cannot see. The conservative default: see the Protocol.

        Unlike the other unimplemented hooks this returns rather than raising, because
        `unlink` calls it on a path that must keep working for every product written before
        M6 existed. Raising `HookNotImplemented` here would turn an optional refinement into
        a required hook and break those products on upgrade.
        """
        return False
