"""Shared infrastructure code for WebbPulse FastAPI services on AWS Lambda.

Every module here is importable on its own and none of them run AWS calls at import time.
Install only what a service needs through the extras: `fastapi`, `dynamodb`, `otel`,
`testing`. See the README for the module map and the per-app migration notes.
"""

from webbpulse._version import __version__

__all__ = ["__version__"]
