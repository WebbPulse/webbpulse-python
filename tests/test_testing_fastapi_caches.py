"""Tests for `clear_fastapi_caches` and the autouse fixture built on it.

FastAPI memoises callable classification with `functools.lru_cache`, which pins every
dependency override lambda for the life of a pytest-xdist worker unless something clears it.
"""

from __future__ import annotations

import gc
import subprocess
import sys
import weakref
from collections.abc import Callable
from typing import Any

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from webbpulse.testing import clear_fastapi_caches


def _dependency() -> str:
    """Stand in for a real dependency such as a repository bundle."""
    return "real"


def _serve_with_override() -> tuple[weakref.ref[Callable[[], Any]], FastAPI]:
    """Serve one request through an override lambda, then drop the override and every local reference."""
    app = FastAPI()

    @app.get("/")
    def read(value: str = Depends(_dependency)) -> dict[str, str]:
        """Echo the resolved dependency."""
        return {"value": value}

    bundle = {"payload": "x" * 1024}
    override: Callable[[], Any] = lambda: str(len(bundle["payload"]))  # noqa: E731
    app.dependency_overrides[_dependency] = override
    with TestClient(app) as client:
        assert client.get("/").json() == {"value": "1024"}
    app.dependency_overrides.clear()
    ref = weakref.ref(override)
    del override
    return ref, app


def _fastapi_pins_callables() -> bool:
    """Report whether this FastAPI version keeps overrides alive in an `lru_cache`."""
    import fastapi.dependencies.models as models

    return any(
        hasattr(getattr(models, name, None), "cache_info")
        for name in ("_is_coroutine_callable_cached", "_is_gen_callable_cached", "_is_async_gen_callable_cached")
    )


def test_clearing_releases_an_overridden_dependency() -> None:
    """After the clear, nothing but the weakref points at the override lambda."""
    clear_fastapi_caches()
    ref, _app = _serve_with_override()
    gc.collect()
    if _fastapi_pins_callables():
        assert ref() is not None
    assert clear_fastapi_caches() > 0
    gc.collect()
    assert ref() is None


def test_clearing_is_idempotent() -> None:
    """A second clear finds the same caches and raises nothing."""
    first = clear_fastapi_caches()
    assert clear_fastapi_caches() == first


def test_clearing_never_imports_fastapi() -> None:
    """Without FastAPI loaded the helper is a no-op and leaves it unimported."""
    script = (
        "import sys\n"
        "import webbpulse.testing as t\n"
        "for name in [n for n in sys.modules if n == 'fastapi' or n.startswith('fastapi.')]:\n"
        "    del sys.modules[name]\n"
        "assert t.clear_fastapi_caches() == 0\n"
        "assert 'fastapi' not in sys.modules\n"
    )
    subprocess.run([sys.executable, "-c", script], check=True)
