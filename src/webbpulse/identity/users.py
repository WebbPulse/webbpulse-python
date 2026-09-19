"""The `users` table: the account row the identity hooks read and write.

Credentials, passkeys, OAuth links and second factors are not here. They belong to this
package's own tables, which `webbpulse.identity.storage` describes. This table holds only
what a product needs to know about a person, and three products were keeping byte-identical
copies of it before it moved here.

A product that needs more fields subclasses `User`; one whose account row looks nothing like
this keeps its own repository and adopts only the router glue.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, cast

from pydantic import BaseModel, Field

from webbpulse.identity.storage import USERS_TABLE

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Mapping, Sequence

    from webbpulse.dynamodb import Repository

__all__ = [
    "EMAIL_INDEX",
    "USERS_TABLE_SPEC",
    "DynamoUsersRepository",
    "User",
    "new_user_id",
    "users_repository",
]

EMAIL_INDEX: Final = "email_lower-index"
"""The GSI resolving a lowercased address to its user, which is how sign-in looks one up."""


def new_user_id() -> str:
    """A fresh user id, which becomes the `sub` claim of every token minted for them."""
    return str(uuid.uuid4())


def _utc_now() -> datetime:
    """The current UTC time, as a timezone-aware datetime."""
    return datetime.now(UTC)


class User(BaseModel):
    """One person's account, in the shape the identity hooks read.

    Subclass it to add a product's own fields; `DynamoUsersRepository` is generic over the
    model, so the subclass round-trips without a second repository.
    """

    id: str = Field(default_factory=new_user_id)
    email: str
    """The address as the person typed it. Validated by the identity flows before it reaches
    this row, and stored as typed so a profile shows the casing they chose."""

    display_name: str = ""
    email_verified: bool = False
    disabled: bool = False
    is_admin: bool = False
    created_at: datetime = Field(default_factory=_utc_now)

    @property
    def email_lower(self) -> str:
        """The address lowercased, which is what the lookup index stores."""
        return str(self.email).strip().lower()


class DynamoUsersRepository[UserT: User]:
    """Reads and writes `users` rows through the shared package repository.

    Constructing it makes no AWS call: the package repository builds its client on first
    use. The model defaults to `User` and is overridable, so a product with extra fields
    passes its own subclass rather than reimplementing every method.
    """

    def __init__(
        self,
        repository: Repository | None = None,
        *,
        model: type[UserT] | None = None,
        prefix: str | None = None,
        table_name: str | None = None,
        region_name: str | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        """Take an injected repository, or build one from a prefix or a whole table name.

        `table_name` is the physical name when the stack chose it outright, and `prefix` is
        the estate's `<prefix>-users` rule; passing both is a `ValueError`, since the two
        would disagree. `logical_name` is restored either way, so a caller reading it off
        the repository sees `users` rather than the physical name.
        """
        self._model: type[UserT] = model if model is not None else cast("type[UserT]", User)
        if repository is not None:
            self._repository = repository
            return
        if table_name is not None and prefix is not None:
            raise ValueError(
                "A DynamoUsersRepository takes either `prefix` or `table_name`, not both: "
                "the stack names the table whole or names it by prefix, never both at once."
            )
        self._repository = users_repository(
            prefix=prefix,
            table_name=table_name,
            region_name=region_name,
            endpoint_url=endpoint_url,
        )

    @property
    def repository(self) -> Repository:
        """The underlying package repository, which `user_repository` hands the purge."""
        return self._repository

    @property
    def model(self) -> type[UserT]:
        """The model this repository validates rows into, which `create_user` instantiates."""
        return self._model

    def get(self, user_id: str) -> UserT | None:
        """The user with this id, or `None`."""
        if not user_id:
            return None
        item = self._repository.get({"id": user_id})
        return self._as_user(item) if item is not None else None

    def get_by_email(self, email: str) -> UserT | None:
        """The user holding this address, or `None`.

        Queries `email_lower-index`, so casing and surrounding space never matter.
        """
        from boto3.dynamodb.conditions import Key

        normalized = email.strip().lower()
        if not normalized:
            return None
        page = self._repository.query(Key("email_lower").eq(normalized), index_name=EMAIL_INDEX, limit=1)
        if not page.items:
            return None
        return self._as_user(page.items[0])

    def get_many(self, user_ids: Sequence[str]) -> dict[str, UserT]:
        """The named users keyed by id, skipping any that are gone.

        One `BatchGetItem` behind a member list, so rendering a workspace's people costs one
        call rather than one per membership.
        """
        items = self._repository.get_many(list(user_ids))
        return {user_id: self._as_user(item) for user_id, item in items.items()}

    def create(self, user: UserT) -> UserT:
        """Write a new user row, keyed by id and indexed by lowercased address."""
        self._repository.put(self._as_item(user))
        return user

    def update(self, user_id: str, **attributes: Any) -> UserT:
        """Apply `attributes` to one user row and return the stored result.

        Every attribute name is aliased, because DynamoDB reserves ordinary words such as
        `name` and `status` and rejects an expression using them directly. Setting `email`
        rewrites the indexed `email_lower` alongside it, so the lookup index can never
        disagree with the address on the row.

        Raises:
            KeyError: When no row has this id, rather than creating one: an update naming a
                user who is not there is a bug in the caller. The check is a read rather
                than a condition expression, because DynamoDB refuses a condition on a key
                attribute in `UpdateItem`.
        """
        stored = self.get(user_id)
        if stored is None:
            raise KeyError(user_id)

        values = dict(attributes)
        if "email" in values:
            values["email_lower"] = str(values["email"]).strip().lower()
        if not values:
            return stored

        names = {f"#n{index}": key for index, key in enumerate(values)}
        expression_values = {f":v{index}": value for index, value in enumerate(values.values())}
        assignments = ", ".join(f"#n{index} = :v{index}" for index in range(len(values)))

        item = self._repository.update(
            {"id": user_id},
            update_expression=f"SET {assignments}",
            expression_values=expression_values,
            expression_names=names,
            return_values="ALL_NEW",
        )
        if item is None:
            raise KeyError(user_id)
        return self._as_user(item)

    def delete(self, user_id: str) -> bool:
        """Hard-delete this user row, returning whether one was there.

        Idempotent: a second call answers `False` rather than raising, which is what a
        teardown running twice needs.
        """
        if not user_id or self.get(user_id) is None:
            return False
        self._repository.delete({"id": user_id})
        return True

    def _as_item(self, user: UserT) -> dict[str, Any]:
        """A user as the stored item, carrying the index's lowercased address."""
        item = user.model_dump(mode="json")
        item["email_lower"] = user.email_lower
        return item

    def _as_user(self, item: Mapping[str, Any]) -> UserT:
        """One stored item as the repository's model."""
        return self._model.model_validate(dict(item))


def users_repository(
    *,
    prefix: str | None = None,
    table_name: str | None = None,
    region_name: str | None = None,
    endpoint_url: str | None = None,
) -> Repository:
    """The package repository for the `users` table in this environment.

    `table_name` wins when the stack named the table whole: the physical name is passed as
    the logical one under an empty prefix, and `logical_name` is put back to `users` so a
    caller reading it sees the logical name. Otherwise the estate's `<prefix>-users` rule
    applies.
    """
    from webbpulse.dynamodb import Repository

    if table_name:
        repository = Repository(
            table_name,
            prefix="",
            region_name=region_name,
            endpoint_url=endpoint_url,
        )
        repository.logical_name = USERS_TABLE
        return repository
    return Repository(
        USERS_TABLE,
        prefix=prefix,
        region_name=region_name,
        endpoint_url=endpoint_url,
    )


def _users_table_spec() -> Any:
    """The `TableSpec` for the users table, built lazily to keep the import graph one way."""
    from webbpulse.identity.storage import TableAttribute, TableIndex, TableSpec

    return TableSpec(
        logical_name=USERS_TABLE,
        attributes=(TableAttribute("id", "S"), TableAttribute("email_lower", "S")),
        hash_key="id",
        global_secondary_indexes=(TableIndex(name=EMAIL_INDEX, hash_key="email_lower"),),
    )


def __getattr__(name: str) -> Any:
    """Resolve `USERS_TABLE_SPEC` on first access, so the storage import stays lazy."""
    if name == "USERS_TABLE_SPEC":
        spec = _users_table_spec()
        globals()["USERS_TABLE_SPEC"] = spec
        return spec
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if TYPE_CHECKING:  # pragma: no cover
    from webbpulse.identity.storage import TableSpec

    USERS_TABLE_SPEC: TableSpec
