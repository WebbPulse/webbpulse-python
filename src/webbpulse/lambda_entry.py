"""The per-domain entrypoint: run uvicorn under the Lambda Web Adapter.

There is no Lambda handler here and no Mangum. The Web Adapter is a Lambda external
extension that starts before the application, translates each invoke into an ordinary HTTP
request against `127.0.0.1:$AWS_LWA_PORT`, and translates the response back. The application
is a normal ASGI server process, so the identical image runs on Lambda, in a local
container, and anywhere else that can run a container.

## The entrypoint

Each domain gets a small module of its own::

    # posts/entrypoint.py
    from webbpulse.lambda_entry import run_uvicorn
    from webbpulse.logging import configure_logging
    from webbpulse.otel import configure_tracing
    from myapp.posts import build_app

    def main() -> None:
        configure_logging(level="INFO", service="posts", environment="staging")
        configure_tracing("webbpulse-staging-posts", environment="staging")
        run_uvicorn(build_app())

    if __name__ == "__main__":
        main()

## The Dockerfile

The adapter is one `COPY` from a public image, pinned to an exact version. Version 1.0.1 is
current. The image is multi-arch, so the same line works for arm64 and x86_64::

    # syntax=docker/dockerfile:1.7
    FROM public.ecr.aws/docker/library/python:3.13-slim AS build
    WORKDIR /build
    COPY requirements.txt .
    RUN --mount=type=secret,id=codeartifact_token \\
        PIP_INDEX_URL="https://aws:$(cat /run/secrets/codeartifact_token)@webbpulse-432410731887.d.codeartifact.us-west-2.amazonaws.com/pypi/python/simple/" \\
        pip install --no-cache-dir --target /deps -r requirements.txt

    FROM public.ecr.aws/docker/library/python:3.13-slim
    COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:1.0.1 /lambda-adapter /opt/extensions/lambda-adapter
    COPY --from=build /deps /var/task
    COPY app /var/task/app
    ENV PYTHONPATH=/var/task \\
        PYTHONUNBUFFERED=1 \\
        AWS_LWA_PORT=8080 \\
        AWS_LWA_READINESS_CHECK_PATH=/health \\
        AWS_LWA_ASYNC_INIT=true
    WORKDIR /var/task
    CMD ["python", "-m", "app.posts.entrypoint"]

Notes on that file, each of which is a real failure mode:

- **`/opt/extensions/lambda-adapter` is the required destination.** Lambda only starts
  binaries it finds in `/opt/extensions`. Copied anywhere else, the adapter never runs, the
  function has no handler, and every invoke times out.
- **The CodeArtifact token is a BuildKit secret mount, never a build arg or an `ENV`.** Both
  of those persist into the image, visible in `docker history`, so the token leaks to
  anyone who can pull the image.
- **`PYTHONUNBUFFERED=1` matters.** Python buffers stdout when it is not a terminal, so
  without it log lines can sit in the buffer while the execution environment is frozen
  between invokes and arrive attributed to a later request.
- **`AWS_LWA_ASYNC_INIT=true`** lets a slow import finish inside Lambda's 10 second init
  window rather than counting against the first invoke.
- **`AWS_LWA_READINESS_CHECK_PATH=/health`** must point at a route that does no I/O; the
  default is `/`. See `webbpulse.http.health_router`.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:  # pragma: no cover - typing only
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

#: The pinned Web Adapter image for the Dockerfile `COPY --from=`.
ADAPTER_IMAGE: Final = "public.ecr.aws/awsguru/aws-lambda-adapter:1.0.1"

AWS_LWA_PORT_ENV: Final = "AWS_LWA_PORT"
DEFAULT_PORT: Final = 8080


def is_lambda() -> bool:
    """Whether this process is running inside Lambda."""
    return bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


def resolve_port(default: int = DEFAULT_PORT) -> int:
    """The port to bind, from `AWS_LWA_PORT`, then `PORT`, then the default.

    That precedence is the adapter's own: it reads `AWS_LWA_PORT` and falls back to `PORT`,
    with a default of 8080. Binding a different port than the adapter polls is the single
    most common Web Adapter misconfiguration, and it presents as the readiness check never
    passing and the function timing out with no application logs at all.
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
    # Binding all interfaces is required inside a container; the adapter reaches the
    # process over the container network, not over the loopback of the host.
    host: str = "0.0.0.0",
    log_config: dict[str, Any] | None = None,
    **uvicorn_kwargs: Any,
) -> None:
    """Serve `app` with uvicorn on the port the Web Adapter expects.

    Blocks until the server stops, so it is the last call in an entrypoint.

    `log_config=None` is passed to uvicorn deliberately: uvicorn's default config installs
    its own handlers and sets `propagate = False` on its loggers, which would bypass the
    JSON formatter from `webbpulse.logging` and put plain-text access lines in the same log
    group as the structured ones. Passing `None` leaves the logging configuration alone.

    A single worker is correct here and is not a throughput limitation. Lambda gives each
    execution environment one concurrent request, so a second worker would idle while
    doubling memory. Scaling is Lambda's job, not uvicorn's.
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
        # Uvicorn's access log duplicates what API Gateway already records and what the
        # request id middleware makes traceable, at real CloudWatch ingestion cost.
        access_log=uvicorn_kwargs.pop("access_log", False),
        **uvicorn_kwargs,
    )
