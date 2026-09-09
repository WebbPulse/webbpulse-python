"""Shared infrastructure code for WebbPulse FastAPI services on AWS Lambda.

None of these modules run AWS calls at import time. Install only what a service needs
through the extras: `fastapi`, `dynamodb`, `otel`, `security`, `testing`.

`config`, `logging`, `dynamodb`, `ratelimit`, `otel`, `security` and `lambda_entry` import
on the base install and degrade at call time when their extra is absent. `http` requires
the `fastapi` extra and `testing` requires the `testing` extra to import at all. See the
README for the module map and the per-app migration notes.
"""

from webbpulse._version import __version__

__all__ = ["__version__"]
