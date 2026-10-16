"""The SCIM error, rendered as the RFC 7644 section 3.12 error response."""

from __future__ import annotations

from typing import Any, Final

__all__ = [
    "SCIM_ERROR_SCHEMA",
    "ScimError",
]

SCIM_ERROR_SCHEMA: Final = "urn:ietf:params:scim:api:messages:2.0:Error"


class ScimError(Exception):
    """A SCIM request was refused, with the HTTP status and the optional `scimType` keyword.

    A product's `ScimHooks` raise it too, for example `ScimError.uniqueness()` when a
    `userName` is taken. `detail` reaches the identity provider, so it never names a secret.
    """

    def __init__(self, status: int, detail: str, *, scim_type: str = "") -> None:
        """Record the status, the human-readable detail and the `scimType` keyword."""
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type

    def as_body(self) -> dict[str, Any]:
        """The error response body. `status` is a string, as RFC 7644 shows it."""
        body: dict[str, Any] = {"schemas": [SCIM_ERROR_SCHEMA], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            body["scimType"] = self.scim_type
        return body

    @classmethod
    def invalid_filter(cls, detail: str = "The filter syntax is invalid.") -> ScimError:
        """A 400 `invalidFilter`."""
        return cls(400, detail, scim_type="invalidFilter")

    @classmethod
    def invalid_syntax(cls, detail: str = "The request body could not be parsed.") -> ScimError:
        """A 400 `invalidSyntax`."""
        return cls(400, detail, scim_type="invalidSyntax")

    @classmethod
    def invalid_value(cls, detail: str) -> ScimError:
        """A 400 `invalidValue`."""
        return cls(400, detail, scim_type="invalidValue")

    @classmethod
    def invalid_path(cls, detail: str = "The PATCH path is invalid.") -> ScimError:
        """A 400 `invalidPath`."""
        return cls(400, detail, scim_type="invalidPath")

    @classmethod
    def no_target(cls, detail: str = "The PATCH path matched nothing.") -> ScimError:
        """A 400 `noTarget`."""
        return cls(400, detail, scim_type="noTarget")

    @classmethod
    def mutability(cls, detail: str) -> ScimError:
        """A 400 `mutability`, for a write to a read-only attribute."""
        return cls(400, detail, scim_type="mutability")

    @classmethod
    def uniqueness(cls, detail: str = "A resource with that unique attribute already exists.") -> ScimError:
        """A 409 `uniqueness`."""
        return cls(409, detail, scim_type="uniqueness")

    @classmethod
    def not_found(cls, detail: str = "Resource not found.") -> ScimError:
        """A 404."""
        return cls(404, detail)

    @classmethod
    def unauthorized(cls, detail: str = "A valid SCIM bearer token is required.") -> ScimError:
        """A 401."""
        return cls(401, detail)

    @classmethod
    def forbidden(cls, detail: str = "This token may not provision this directory.") -> ScimError:
        """A 403."""
        return cls(403, detail)

    @classmethod
    def precondition_failed(cls, detail: str = "The resource has changed since that version.") -> ScimError:
        """A 412, for an `If-Match` that no longer matches."""
        return cls(412, detail)
