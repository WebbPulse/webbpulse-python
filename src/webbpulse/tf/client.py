"""The control plane's HTTP API, as much of it as `wp-tf` uses."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import httpx

GATE_HEADER = "x-origin-verify"
"""The staging access gate's origin header; production has no gate."""

WORKSPACE_ID = re.compile(r"^ws-[0-9A-HJKMNP-TV-Z]{26}$")

DISCOVERY_PATH = "/.well-known/terraform.json"

DEFAULT_TIMEOUT = 30.0

TERMINAL_STATUSES = frozenset({"applied", "planned_and_finished", "errored", "cancelled", "discarded"})
"""The run statuses after which nothing more happens."""

SUCCESS_STATUSES = frozenset({"planned_and_finished", "planned", "awaiting_confirmation", "applied"})
"""The statuses of a run whose plan succeeded."""


class ApiError(Exception):
    """A refused or failed API call, carrying the status and the envelope's message and code."""

    def __init__(self, status: int, message: str, error_code: str = "") -> None:
        """Keep the HTTP status, a readable message and the stable error code when there is one."""
        super().__init__(message)
        self.status = status
        self.message = message
        self.error_code = error_code

    def __str__(self) -> str:
        """The status, the code when present and the message on one line."""
        code = f" {self.error_code}" if self.error_code else ""
        return f"{self.status}{code}: {self.message}"


def _error_from(response: httpx.Response) -> ApiError:
    """The `ApiError` for a non-2xx response, read from the error envelope when it has one."""
    message = response.reason_phrase or "request failed"
    code = ""
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, dict):
            message = str(detail.get("message") or message)
            code = str(detail.get("error_code") or "")
        elif isinstance(detail, str):
            message = detail
        if body.get("message"):
            message = str(body["message"])
        if body.get("error_code"):
            code = str(body["error_code"])
    if response.status_code == 403 and not code:
        message = f"{message} (the key may lack the scope this needs, or the host needs its access gate)"
    return ApiError(response.status_code, message, code)


LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
"""Hosts a plain-http API origin is accepted for, so a local stack can be driven."""


def trusted_origin(host: str, url: str) -> bool:
    """Whether `url` is an https origin on `host` or a subdomain of it, where a login key may go."""
    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower()
    host = host.lower()
    on_host = hostname == host or hostname.endswith(f".{host}")
    return parts.scheme == "https" and on_host and parts.port is None and not parts.username


def check_api_url(url: str) -> str:
    """`url` as an API origin, refusing anything but https outside a local stack.

    Raises:
        ApiError: The origin is not https, or http on a host other than a local one.
    """
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname and not parts.username:
        return url.rstrip("/")
    if parts.scheme == "http" and (parts.hostname or "") in LOCAL_HOSTS:
        return url.rstrip("/")
    raise ApiError(0, f"refusing API URL {url!r}: the key is only sent over https", "INSECURE_API_URL")


def discover_api_url(host: str, client: httpx.Client) -> str:
    """The API origin for `host`, read off the service discovery document `terraform login` uses.

    The control plane serves its registry and API from one origin, so the `modules.v1`
    URL's origin is the API's. A relative entry means the API is on `host` itself. The
    origin must be https on `host` or a subdomain of it, since the login key is sent there.

    Raises:
        ApiError: The document is missing, names no service, or points the key elsewhere.
    """
    response = client.get(f"https://{host}{DISCOVERY_PATH}")
    if response.status_code != 200:
        raise _error_from(response)
    try:
        document = response.json()
    except ValueError as exc:
        raise ApiError(response.status_code, f"{host}{DISCOVERY_PATH} is not JSON") from exc
    service = document.get("modules.v1") or document.get("providers.v1") if isinstance(document, dict) else None
    if not isinstance(service, str) or not service:
        raise ApiError(response.status_code, f"{host}{DISCOVERY_PATH} names no modules.v1 or providers.v1 service")
    parts = urlsplit(service)
    if not parts.scheme and not parts.netloc:
        return f"https://{host}"
    origin = f"{parts.scheme}://{parts.netloc}"
    if not trusted_origin(host, origin):
        raise ApiError(
            response.status_code,
            f"{host}{DISCOVERY_PATH} points the API at {origin}, which is not https on {host} or a subdomain",
            "UNTRUSTED_API_ORIGIN",
        )
    return origin


class ControlPlane:
    """An authenticated client for the control plane API.

    The token is sent only to the API origin and to nothing else; the presigned upload
    goes out on a separate client with no authorization header.
    """

    def __init__(
        self,
        api_url: str,
        token: str,
        *,
        gate: str = "",
        transport: httpx.BaseTransport | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """Bind the API origin, the bearer key and the optional staging gate value."""
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if gate:
            headers[GATE_HEADER] = gate
        self._api = httpx.Client(
            base_url=api_url.rstrip("/") + "/api/v1",
            headers=headers,
            transport=transport,
            timeout=timeout,
        )
        self._uploads = httpx.Client(transport=transport, timeout=max(timeout, 120.0))

    def close(self) -> None:
        """Close both HTTP clients."""
        self._api.close()
        self._uploads.close()

    def __enter__(self) -> ControlPlane:
        """Use the client as a context manager."""
        return self

    def __exit__(self, *exc: object) -> None:
        """Close on the way out."""
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Send one API call and return its JSON body, raising `ApiError` on a non-2xx answer."""
        response = self._api.request(method, path, **kwargs)
        if response.status_code >= 400:
            raise _error_from(response)
        if not response.content:
            return None
        return response.json()

    def list_workspaces(self) -> list[dict[str, Any]]:
        """Every workspace the key can read, following `next_cursor` when the API pages."""
        workspaces: list[dict[str, Any]] = []
        params: dict[str, str] = {}
        while True:
            body = self._request("GET", "/workspaces", params=params)
            items = body.get("items", []) if isinstance(body, dict) else body
            workspaces.extend(dict(item) for item in items or [])
            cursor = body.get("next_cursor") if isinstance(body, dict) else None
            if not cursor or cursor == params.get("cursor"):
                return workspaces
            params = {"cursor": str(cursor)}

    def get_workspace(self, workspace_id: str) -> dict[str, Any]:
        """One workspace by id."""
        return dict(self._request("GET", f"/workspaces/{workspace_id}"))

    def resolve_workspace(self, reference: str) -> dict[str, Any]:
        """A workspace by `ws-` id or by exact name.

        Raises:
            ApiError: No workspace has that id or name.
        """
        if WORKSPACE_ID.match(reference):
            return self.get_workspace(reference)
        for item in self.list_workspaces():
            if item.get("name") == reference:
                return item
        raise ApiError(404, f"no workspace named '{reference}'", "WORKSPACE_NOT_FOUND")

    def upload_config(self, workspace_id: str, tarball: bytes) -> str:
        """Create a config version, PUT the tarball to its presigned URL and return its id.

        The presigned request signs every header it hands back, `Content-Length` included,
        so the declared size is the tarball's exact length and the headers go back as given.
        """
        created = self._request(
            "POST",
            f"/workspaces/{workspace_id}/config-versions",
            json={"size_bytes": len(tarball)},
        )
        response = self._uploads.put(str(created["upload_url"]), content=tarball, headers=dict(created["headers"]))
        if response.status_code not in (200, 204):
            raise ApiError(response.status_code, "the configuration upload was refused")
        return str(created["config_version"]["config_version_id"])

    def create_plan_run(
        self,
        workspace_id: str,
        config_version_id: str,
        *,
        message: str,
        is_destroy: bool = False,
    ) -> dict[str, Any]:
        """Start a plan-only run, a destroy plan when `is_destroy`. Never an applying run."""
        return dict(
            self._request(
                "POST",
                "/runs",
                json={
                    "workspace_id": workspace_id,
                    "config_version_id": config_version_id,
                    "plan_only": True,
                    "is_destroy": is_destroy,
                    "message": message,
                },
            )
        )

    def get_run(self, run_id: str) -> dict[str, Any]:
        """One run by id."""
        return dict(self._request("GET", f"/runs/{run_id}"))

    def list_runs(self, workspace_id: str) -> list[dict[str, Any]]:
        """A workspace's runs, newest first."""
        body = self._request("GET", "/runs", params={"workspace_id": workspace_id})
        return [dict(item) for item in body.get("items", [])]

    def cancel_run(self, run_id: str) -> dict[str, Any]:
        """Cancel a run that has not finished."""
        return dict(self._request("POST", f"/runs/{run_id}/cancel"))

    def logs(self, run_id: str, phase: str, after: str | None) -> tuple[list[str], str | None]:
        """One page of a phase's log lines and the token that continues after them."""
        params = {"phase": phase}
        if after:
            params["after"] = after
        body = self._request("GET", f"/runs/{run_id}/logs", params=params)
        lines = [str(event.get("message", "")).rstrip("\n") for event in body.get("events", [])]
        next_after = body.get("next_after")
        return lines, str(next_after) if next_after else after


__all__ = [
    "GATE_HEADER",
    "SUCCESS_STATUSES",
    "TERMINAL_STATUSES",
    "ApiError",
    "ControlPlane",
    "check_api_url",
    "discover_api_url",
    "trusted_origin",
]
