# Packaging: the Lambda entrypoint and the container image

How a domain Lambda is packaged and started under the AWS Lambda Web Adapter, and the test
fixtures. Back to the [README](../README.md).

## `webbpulse.lambda_entry`

There is no Lambda handler and no Mangum. The AWS Lambda Web Adapter is an external
extension that starts before the application, turns each invoke into an ordinary HTTP
request against `127.0.0.1:$AWS_LWA_PORT`, and turns the response back. The application is a
normal ASGI server, so the identical image runs on Lambda, in a local container, and
anywhere else.

```python
# app/posts/entrypoint.py
from webbpulse.lambda_entry import run_uvicorn
from webbpulse.logging import configure_logging
from webbpulse.otel import configure_tracing
from app.posts import build_app


def main() -> None:
    configure_logging(level="INFO", service="posts", environment="staging")
    configure_tracing("webbpulse-staging-posts", environment="staging")
    run_uvicorn(build_app())


if __name__ == "__main__":
    main()
```

`run_uvicorn` binds `AWS_LWA_PORT`, falling back to `PORT` and then 8080, which is the
adapter's own precedence. Binding a port the adapter is not polling is the most common Web
Adapter misconfiguration and it presents as the readiness check never passing and the
function timing out with no application logs at all.

The Dockerfile is one `COPY` from a pinned public image. Version 1.0.1 is current, and the
image is multi-arch, so the same line serves arm64 and x86_64:

```dockerfile
# syntax=docker/dockerfile:1.7
FROM public.ecr.aws/docker/library/python:3.13-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN --mount=type=secret,id=codeartifact_token \
    PIP_INDEX_URL="https://aws:$(cat /run/secrets/codeartifact_token)@webbpulse-432410731887.d.codeartifact.us-west-2.amazonaws.com/pypi/python/simple/" \
    pip install --no-cache-dir --target /deps -r requirements.txt

FROM public.ecr.aws/docker/library/python:3.13-slim
COPY --from=public.ecr.aws/awsguru/aws-lambda-adapter:1.0.1 /lambda-adapter /opt/extensions/lambda-adapter
COPY --from=build /deps /var/task
COPY app /var/task/app
ENV PYTHONPATH=/var/task \
    PYTHONUNBUFFERED=1 \
    AWS_LWA_PORT=8080 \
    AWS_LWA_READINESS_CHECK_PATH=/health \
    AWS_LWA_ASYNC_INIT=true
WORKDIR /var/task
CMD ["python", "-m", "app.posts.entrypoint"]
```

Each line there is a real failure mode:

- **`/opt/extensions/lambda-adapter` is the required destination.** Lambda only starts
  binaries it finds in `/opt/extensions`. Copied anywhere else the adapter never runs, the
  function has no handler, and every invoke times out.
- **The CodeArtifact token is a BuildKit secret mount, never a build arg or `ENV`.** Both of
  those persist into the image and are visible in `docker history`.
- **`PYTHONUNBUFFERED=1`** keeps log lines from sitting in a buffer while the execution
  environment is frozen between invokes and arriving attributed to a later request.
- **`AWS_LWA_ASYNC_INIT=true`** lets a slow import finish inside Lambda's 10 second init
  window instead of counting against the first invoke.
- **`AWS_LWA_READINESS_CHECK_PATH=/health`** must point at a route that does no I/O. The
  adapter's default is `/`.

## `webbpulse.testing`

Pytest fixtures for a moto-backed table and a `TestClient`. Enable them from a service's
`conftest.py`:

```python
pytest_plugins = ["webbpulse.testing"]
```

| Fixture or helper | What it gives you |
| --- | --- |
| `aws_credentials` | Placeholder credentials and region, so a mis-scoped mock cannot reach a real account |
| `dynamodb_resource` | A moto-mocked DynamoDB resource, with the package's cached resource cleared on both sides |
| `create_table(...)` | One on-demand table with an optional range key and TTL |
| `rate_limit_table` | The `rate-limits` table shaped exactly as Terraform creates it |
| `test_client(app, source_ip=...)` | A `TestClient` whose requests carry a realistic API Gateway request context |
| `make_request_context_headers(...)` | That header on its own, in either payload shape |

`test_client` is the one worth knowing about. Without the injected context header a
`TestClient` request has no API Gateway context at all, so `client_ip` falls back to the
peer address and a service's rate limit tests pass while never covering the branch that
actually runs in production.
