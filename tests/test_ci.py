"""Tests for the per-domain pytest matrix discovery in `webbpulse.ci`.

The reusable `python-ci.yml` workflow parses this command's stdout with `fromJson`, so
stdout shape is asserted directly rather than only through the return values.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from webbpulse.ci import SHARED_DOMAIN, CiConfig, load_config, main, pytest_args_for


def write_pyproject(directory: Path, body: str) -> Path:
    """Write a `pyproject.toml` carrying `body` and return the directory."""
    (directory / "pyproject.toml").write_text(textwrap.dedent(body), encoding="utf-8")
    return directory


class TestLoadConfig:
    """Tests for `load_config`."""

    def test_reads_domains_and_test_root(self, tmp_path: Path) -> None:
        """`load_config` reads the test root and each domain's paths from pyproject."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci]
            test-root = "backend/tests"

            [tool.webbpulse.ci.domains]
            identity = ["backend/tests/auth"]
            catalog = ["backend/tests/api/test_parts.py", "backend/tests/api/test_cats.py"]
            """,
        )

        config = load_config(tmp_path)

        assert config.test_root == "backend/tests"
        assert config.domains["identity"] == ("backend/tests/auth",)
        assert config.domains["catalog"] == (
            "backend/tests/api/test_parts.py",
            "backend/tests/api/test_cats.py",
        )

    def test_domain_names_are_sorted(self, tmp_path: Path) -> None:
        """A matrix whose order moved between runs would renumber jobs in the UI."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            zulu = ["tests/z"]
            alpha = ["tests/a"]
            mike = ["tests/m"]
            """,
        )

        assert load_config(tmp_path).domain_names == ("alpha", "mike", "zulu")

    def test_missing_pyproject_is_an_empty_config(self, tmp_path: Path) -> None:
        """A repository that has not adopted the convention still calls the command."""
        config = load_config(tmp_path)

        assert config.domains == {}
        assert config.test_root == "tests"

    def test_missing_table_is_an_empty_config(self, tmp_path: Path) -> None:
        """A pyproject without the ci table yields no domains."""
        write_pyproject(tmp_path, '[project]\nname = "thing"\n')

        assert load_config(tmp_path).domains == {}

    def test_shared_is_rejected_as_a_domain_name(self, tmp_path: Path) -> None:
        """`shared` and a domain called `shared` would be one colliding matrix job."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            shared = ["tests/shared"]
            """,
        )

        with pytest.raises(ValueError, match="reserved"):
            load_config(tmp_path)

    def test_a_domain_claiming_nothing_is_rejected(self, tmp_path: Path) -> None:
        """An empty list would create a job that runs pytest with no paths, collecting all."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            identity = []
            """,
        )

        with pytest.raises(ValueError, match="claims no paths"):
            load_config(tmp_path)

    def test_a_non_list_domain_is_rejected(self, tmp_path: Path) -> None:
        """A domain mapped to a bare string is rejected as not a list of paths."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            identity = "tests/auth"
            """,
        )

        with pytest.raises(ValueError, match="list of path strings"):
            load_config(tmp_path)


class TestPytestArgs:
    """Tests for `pytest_args_for`."""

    def test_a_domain_gets_its_own_paths(self) -> None:
        """A named domain runs exactly the paths it claims."""
        config = CiConfig(test_root="tests", domains={"identity": ("tests/auth",)})

        assert pytest_args_for(config, "identity") == ("tests/auth",)

    def test_shared_sweeps_the_root_and_ignores_every_claimed_path(self) -> None:
        """The two kinds of job together must run each test exactly once."""
        config = CiConfig(
            test_root="tests",
            domains={"identity": ("tests/auth",), "catalog": ("tests/api/test_parts.py",)},
        )

        assert pytest_args_for(config, SHARED_DOMAIN) == (
            "tests",
            "--ignore=tests/api/test_parts.py",
            "--ignore=tests/auth",
        )

    def test_shared_with_no_domains_is_just_the_root(self) -> None:
        """With no domains configured, the shared job runs the test root alone."""
        config = CiConfig(test_root="tests", domains={})

        assert pytest_args_for(config, SHARED_DOMAIN) == ("tests",)

    def test_a_path_claimed_twice_is_ignored_once(self) -> None:
        """Two domains may legitimately share a fixture directory; --ignore must not repeat."""
        config = CiConfig(
            test_root="tests",
            domains={"a": ("tests/shared_bits",), "b": ("tests/shared_bits",)},
        )

        assert pytest_args_for(config, SHARED_DOMAIN) == (
            "tests",
            "--ignore=tests/shared_bits",
        )

    def test_an_unknown_domain_names_the_ones_that_exist(self) -> None:
        """An unknown domain raises KeyError mentioning the configured domains."""
        config = CiConfig(test_root="tests", domains={"identity": ("tests/auth",)})

        with pytest.raises(KeyError, match="identity"):
            pytest_args_for(config, "nope")


class TestCommandLine:
    """Tests for the `main` command line entrypoint."""

    def test_domains_prints_a_json_array(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """`fromJson` in the workflow parses exactly this, so it must be a bare array."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            identity = ["tests/auth"]
            catalog = ["tests/catalog"]
            """,
        )

        assert main(["--project-dir", str(tmp_path), "domains"]) == 0

        assert json.loads(capsys.readouterr().out) == ["catalog", "identity"]

    def test_domains_can_append_shared(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """`--include-shared` appends the shared job to the matrix."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            identity = ["tests/auth"]
            """,
        )

        assert main(["--project-dir", str(tmp_path), "domains", "--include-shared"]) == 0

        assert json.loads(capsys.readouterr().out) == ["identity", SHARED_DOMAIN]

    def test_empty_config_prints_an_empty_array(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """An empty matrix must still be valid JSON or the workflow fails to expand it."""
        assert main(["--project-dir", str(tmp_path), "domains"]) == 0

        assert json.loads(capsys.readouterr().out) == []

    def test_pytest_args_prints_shell_quoted_paths(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """`pytest-args` prints the domain's paths shell quoted, so spaces survive."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            identity = ["tests/auth", "tests/dir with space"]
            """,
        )

        code = main(["--project-dir", str(tmp_path), "pytest-args", "--domain", "identity"])

        assert code == 0
        assert capsys.readouterr().out.strip() == "'tests/auth' 'tests/dir with space'"

    def test_pytest_args_for_shared(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """`pytest-args --domain shared` prints the root plus an --ignore per claimed path."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci]
            test-root = "tests"

            [tool.webbpulse.ci.domains]
            identity = ["tests/auth"]
            """,
        )

        code = main(["--project-dir", str(tmp_path), "pytest-args", "--domain", "shared"])

        assert code == 0
        assert capsys.readouterr().out.strip() == "'tests' '--ignore=tests/auth'"

    def test_an_unknown_domain_exits_two(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        """An unknown domain exits 2 and names the problem on stderr."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            identity = ["tests/auth"]
            """,
        )

        code = main(["--project-dir", str(tmp_path), "pytest-args", "--domain", "ghost"])

        assert code == 2
        assert "unknown domain" in capsys.readouterr().err

    def test_a_malformed_table_exits_two_rather_than_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A typo in a service's config should read as an error, not as a crash."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            identity = []
            """,
        )

        assert main(["--project-dir", str(tmp_path), "domains"]) == 2
        assert "claims no paths" in capsys.readouterr().err


class TestRunsAsAModule:
    """The workflow invokes this as `python -m webbpulse.ci`, before test deps are installed."""

    def test_python_dash_m_prints_the_matrix(self, tmp_path: Path) -> None:
        """`python -m webbpulse.ci domains` prints the matrix as JSON."""
        write_pyproject(
            tmp_path,
            """
            [tool.webbpulse.ci.domains]
            identity = ["tests/auth"]
            """,
        )

        result = subprocess.run(
            [sys.executable, "-m", "webbpulse.ci", "--project-dir", str(tmp_path), "domains"],
            capture_output=True,
            text=True,
            check=True,
        )

        assert json.loads(result.stdout) == ["identity"]

    def test_imports_only_the_standard_library(self) -> None:
        """CI runs this in a bare interpreter, so importing it must not need any extra."""
        result = subprocess.run(
            [sys.executable, "-c", "import webbpulse.ci; print('ok')"],
            capture_output=True,
            text=True,
            check=True,
        )

        assert result.stdout.strip() == "ok"
