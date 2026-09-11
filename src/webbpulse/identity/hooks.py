"""`IdentityHooks`: the seam where a product's own policy lives.

The product decides who may sign in and what they may do; the package decides how
signing in works. Offered both as a Protocol and as a concrete base class.
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

    Raised at the call rather than at instantiation, so the error names the hook and the
    class while still allowing a partial implementation.
    """


class AuthenticationRefused(Exception):
    """The product's policy refuses this login.

    Raised by `may_authenticate`, carrying a user-facing message and a machine-readable
    code. The message reaches the caller, so it must not distinguish an existing account
    from a missing one.
    """

    def __init__(self, message: str, *, error_code: str = "AUTHENTICATION_REFUSED") -> None:
        """Record the user-facing message and the machine-readable refusal code."""
        super().__init__(message)
        self.message = message
        self.error_code = error_code


@runtime_checkable
class IdentityHooks(Protocol):
    """The product's own identity policy, supplied to `build_identity_router`.

    Structural, so a product's class satisfies it without inheritance. Every method may be
    `def` or `async def`; the flows await whatever comes back.
    """

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """The user with this id, or `None`.

        `user_id` is the `sub` claim: the user's immutable id, never a username or email.
        """
        ...

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """The user with this email address, or `None`.

        `email` arrives already lowercased and stripped. Returning `None` must cost the
        same as returning a user, or the lookup becomes an account enumeration oracle.
        """
        ...

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Raise `AuthenticationRefused` to refuse this login, or return `None` to permit.

        The product owns the policy, since the package knows none of its account flags.
        """
        ...

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """The product's own claims for this user: roles, scopes, tenant.

        Never the registered claims: any of those returned here are dropped rather than
        honoured, since rewriting `iss` or `exp` through this seam would be forgeable.
        """
        ...

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Product-side side effects for a new account: default rows, a welcome email.

        `via` names how the account came to exist. Raising here fails the registration.
        """
        ...

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create the user row for a registration and return it.

        The product owns the `users` table and its schema, so it decides what a user record
        is. The returned mapping must carry the immutable user id under `id`.
        """
        ...

    def mark_email_verified(self, user_id: str) -> None:
        """Record that this user's email address is now confirmed.

        Called only after a verification link has been consumed, so it re-checks nothing.
        Raising fails the confirmation after the link is already spent.
        """
        ...

    def user_repository(self) -> object:
        """The product's own users table, as a `webbpulse.dynamodb.Repository`.

        Typed `object` so this module needs no `dynamodb` extra.
        """
        ...

    def has_other_sign_in_method(self, user_id: str) -> bool:
        """Whether this user holds a sign-in method the identity package cannot see.

        Asked by `OAuthService.unlink`, which refuses to remove the last way into an
        account. Do not count OAuth links or the password here: `unlink` counts those.
        """
        ...


class BaseIdentityHooks:
    """A concrete `IdentityHooks` whose unimplemented hooks raise a clear error.

    Subclass it and override what the product needs. Not an ABC on purpose, so a partial
    implementation can exist and fails only at the first call of a missing hook.
    """

    def _not_implemented(self, hook: str) -> HookNotImplemented:
        """Build the error raised for a hook this class does not implement."""
        return HookNotImplemented(
            f"{type(self).__name__} does not implement the {hook!r} hook, and an identity "
            "flow needed it. See section 6.3 of the identity standard for what each hook "
            "owns."
        )

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """Refuse: the product must implement this hook."""
        raise self._not_implemented("load_user_by_id")

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """Refuse: the product must implement this hook."""
        raise self._not_implemented("load_user_by_email")

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Refuse: the product must implement this hook."""
        raise self._not_implemented("may_authenticate")

    def claims_for(self, user: Mapping[str, Any]) -> Mapping[str, Any]:
        """No product claims. Correct for a product with no roles, so it is the default."""
        return {}

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Nothing. Correct for a product with no side effects, so it is the default."""
        return None

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Refuse: the product must implement this hook."""
        raise self._not_implemented("create_user")

    def mark_email_verified(self, user_id: str) -> None:
        """Refuse: the product must implement this hook."""
        raise self._not_implemented("mark_email_verified")

    def user_repository(self) -> object:
        """Refuse: the product must implement this hook."""
        raise self._not_implemented("user_repository")

    def has_other_sign_in_method(self, user_id: str) -> bool:
        """No methods this package cannot see, the conservative default.

        Returns rather than raising, so products written before this hook existed keep
        working on upgrade.
        """
        return False
