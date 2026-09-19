"""`DynamoUsersHooks`: the `IdentityHooks` a product gets for free over `users`.

Every hook but `claims_for` reduces to a read or a write of the shared `users` row, so
three products were writing the same 135 lines. This implements all of them and leaves
`claims_for` to the subclass, which is the one hook that is genuinely a product's own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

from webbpulse.identity.hooks import AuthenticationRefused, BaseIdentityHooks
from webbpulse.identity.users import DynamoUsersRepository, User

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping

__all__ = [
    "ACCOUNT_DISABLED",
    "EMAIL_NOT_VERIFIED",
    "REFUSAL_MESSAGE",
    "DynamoUsersHooks",
]

REFUSAL_MESSAGE: Final = "This account may not sign in."
"""One message for every refusal, so a caller cannot tell a disabled account from an
unverified one and use the difference to enumerate addresses."""

ACCOUNT_DISABLED: Final = "ACCOUNT_DISABLED"
"""The refusal code for an account an operator switched off."""

EMAIL_NOT_VERIFIED: Final = "EMAIL_NOT_VERIFIED"
"""The refusal code for an account whose address is not yet confirmed."""


class DynamoUsersHooks[UserT: User](BaseIdentityHooks):
    """`IdentityHooks` over a `DynamoUsersRepository`, with `claims_for` left to the product.

    Stateless apart from one repository, so a single instance is shared per process.
    Constructing it makes no AWS call and caches no boto3 object. `claims_for` inherits
    `BaseIdentityHooks`'s empty mapping, which is correct for a product with no roles;
    anything else overrides it and nothing else.
    """

    def __init__(
        self,
        users: DynamoUsersRepository[UserT] | None = None,
        *,
        model: type[UserT] | None = None,
        prefix: str | None = None,
        table_name: str | None = None,
        region_name: str | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        """Take an injected users repository, or build one from a prefix or a table name.

        The keyword arguments are `DynamoUsersRepository`'s own and are ignored when
        `users` is given, so a test passes the repository and a product passes the prefix.
        """
        self._users: DynamoUsersRepository[UserT] = (
            users
            if users is not None
            else DynamoUsersRepository(
                model=model,
                prefix=prefix,
                table_name=table_name,
                region_name=region_name,
                endpoint_url=endpoint_url,
            )
        )

    @property
    def users(self) -> DynamoUsersRepository[UserT]:
        """The users repository these hooks read and write, for a subclass that needs it."""
        return self._users

    def load_user_by_id(self, user_id: str) -> Mapping[str, Any] | None:
        """The user whose id is this `sub`, or `None`."""
        user = self._users.get(user_id)
        return self.as_mapping(user) if user is not None else None

    def load_user_by_email(self, email: str) -> Mapping[str, Any] | None:
        """The user holding this address, or `None`.

        The address arrives lowercased and stripped, and the repository queries the
        lowercased index, so a miss costs the same single query a hit does.
        """
        user = self._users.get_by_email(email)
        return self.as_mapping(user) if user is not None else None

    def may_authenticate(self, user: Mapping[str, Any]) -> None:
        """Permit an enabled, verified account and refuse everything else.

        Returns `None` to permit and raises to refuse, which is the protocol's shape and the
        one where forgetting to return lands on the refusing side. A product with further
        flags overrides this, calls `super()` first, and adds its own refusals.
        """
        if user.get("disabled"):
            raise AuthenticationRefused(REFUSAL_MESSAGE, error_code=ACCOUNT_DISABLED)
        if not user.get("email_verified"):
            raise AuthenticationRefused(REFUSAL_MESSAGE, error_code=EMAIL_NOT_VERIFIED)

    def create_user(self, *, email: str, attributes: Mapping[str, Any]) -> Mapping[str, Any]:
        """Create a users row for a package registration and return it.

        The display name falls back to the address's local part when none is given. `id` and
        `hashed_password` are dropped: the id is the model's to mint, and the password lives
        in the package's `credentials` table rather than on this row.
        """
        record = dict(attributes)
        record.pop("id", None)
        record.pop("hashed_password", None)
        record["email"] = email
        record["display_name"] = str(record.get("display_name") or display_name_from(email))
        return self.as_mapping(self._users.create(self.build_user(record)))

    def mark_email_verified(self, user_id: str) -> None:
        """Record that this user's address is confirmed, on the `users` row.

        Raises:
            ValueError: When no row has this id. The link is already spent, so a failure has
                to be visible rather than passing silently.
        """
        if self._users.get(user_id) is None:
            raise ValueError(
                f"mark_email_verified found no user with id {user_id!r}. The link was consumed, "
                "so the address is not verified and the user needs a new one."
            )
        self._users.update(user_id, email_verified=True)

    def delete_user(self, user_id: str) -> bool:
        """Hard-delete this product's users row, returning whether one was there.

        Only the users row. The identity rows are the users-table stream purge's to remove,
        so an ephemeral e2e user's teardown exercises the same deletion path a real account
        does.
        """
        return self._users.delete(user_id)

    def on_user_created(self, user: Mapping[str, Any], via: str) -> None:
        """Nothing.

        The verification email is the package's own register flow's to send, and a new
        account owns no default rows. A product that seeds one overrides this.
        """
        del user, via

    def has_other_sign_in_method(self, user_id: str) -> bool:
        """Whether this user holds a sign-in method the identity package cannot see.

        `False`, because a product on this base keeps every credential, passkey and OAuth
        link in the package's own tables, which `unlink` counts for itself. A product with
        a legacy table of its own overrides this.
        """
        del user_id
        return False

    def user_repository(self) -> object:
        """This product's users repository, as the protocol's `object`.

        The underlying `webbpulse.dynamodb.Repository`, which is what the purge and the
        ephemeral user routes reach for.
        """
        return self._users.repository

    def build_user(self, record: Mapping[str, Any]) -> UserT:
        """The model instance `create_user` stores, from the attributes it assembled.

        Overridable for a product whose model needs a field derived rather than passed.
        """
        return self._users.model(**dict(record))

    def as_mapping(self, user: UserT) -> Mapping[str, Any]:
        """A user row as the plain mapping the hooks protocol returns.

        `mode="json"` so the id reaches the package as the string it becomes in the `sub`
        claim rather than as a richer type.
        """
        return user.model_dump(mode="json")


def display_name_from(email: str) -> str:
    """A display name derived from the address's local part, or `"user"` when it is empty."""
    return email.partition("@")[0].strip() or "user"
