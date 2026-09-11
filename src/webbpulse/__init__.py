"""Shared infrastructure code for WebbPulse FastAPI services on AWS Lambda.

No module runs AWS calls at import time. Install only what a service needs through the
extras: `fastapi`, `dynamodb`, `otel`, `security`, `testing`.
"""

from webbpulse._version import __version__

__all__ = ["__version__"]
