"""The per-domain entrypoint: run uvicorn under the Lambda Web Adapter.

There is no Lambda handler and no Mangum: the adapter turns each invoke into an HTTP
request against the local uvicorn, so the same image runs on Lambda or in any container.
The adapter is one pinned `COPY` in the image::

    COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:1.0.1 /lambda-adapter /opt/extensions/lambda-adapter
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import FastAPI

__all__ = [
    "ADAPTER_IMAGE",
    "AWS_LWA_PORT_ENV",
    "DEFAULT_PORT",
    "is_lambda",
    "resolve_port",
    "run_uvicorn",
]

_log = logging.getLogger(__name__)

ADAPTER_IMAGE: Final = "public.ecr.aws/awsguru/aws-lambda-adapter:1.0.1"

AWS_LWA_PORT_ENV: Final = "AWS_LWA_PORT"
DEFAULT_PORT: Final = 8080


def is_lambda() -> bool:
    """Whether this process is running inside Lambda."""
    return bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


def resolve_port(default: int = DEFAULT_PORT) -> int:
    """The port to bind, from `AWS_LWA_PORT`, then `PORT`, then the default.

    That precedence is the adapter's own, and binding any other port leaves its readiness
    check failing forever.
    """
    for name in (AWS_LWA_PORT_ENV, "PORT"):
        raw = os.environ.get(name, "").strip()
        if not raw:
            continue
        try:
            return int(raw)
        except ValueError:
            _log.warning("%s is set to %r, which is not an integer; ignoring it.", name, raw)
    return default


def run_uvicorn(
    app: FastAPI | str,
    *,
    port: int | None = None,
    host: str = "0.0.0.0",
    log_config: dict[str, Any] | None = None,
    **uvicorn_kwargs: Any,
) -> None:
    """Serve `app` with uvicorn on the port the Web Adapter expects.

    Blocks until the server stops, so it is the last call in an entrypoint. `log_config`
    stays `None` so uvicorn leaves the JSON logging configuration alone.
    """
    import uvicorn

    resolved_port = port if port is not None else resolve_port()
    _log.info(
        "Starting uvicorn.",
        extra={"port": resolved_port, "host": host, "on_lambda": is_lambda()},
    )
    uvicorn.run(
        app,
        host=host,
        port=resolved_port,
        log_config=log_config,
        access_log=uvicorn_kwargs.pop("access_log", False),
        **uvicorn_kwargs,
    )
