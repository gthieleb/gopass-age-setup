"""pytest-Einstiegspunkt für die Testsuite von gopass_age_setup.py.

Wiederverwendet die im Skript integrierten unittest-Cases und ergänzt
pytest-native CLI-Tests (Exit-Codes, --help). Coverage via pytest-cov:

    pytest --cov=gopass_age_setup --cov-report=term-missing
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import gopass_age_setup as mod

# Die integrierten unittest-Suiten werden von pytest automatisch eingesammelt,
# sobald sie in diesem Modul importiert sind.
from gopass_age_setup import (  # noqa: F401
    BackupAndInitTests,
    FetchSshKeyTests,
    IntegrationTests,
    PrivateKeyMatchTests,
    VerificationFlowTests,
    VerifyEnvironmentTests,
)

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "gopass_age_setup.py"


def test_module_exposes_core_api() -> None:
    """Smoke-Test: öffentliche API des Setup-Moduls vorhanden."""
    for attr in (
        "GopassAgeSetup",
        "GopassSetupError",
        "CommandError",
        "CommandRunner",
        "run_unittest_suite",
        "main",
    ):
        assert hasattr(mod, attr), f"Attribut fehlt: {attr}"


def test_cli_help_exit_zero() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "gopass" in result.stdout


def test_cli_fails_cleanly_without_ssh_auth_sock() -> None:
    env = {key: value for key, value in os.environ.items() if key != "SSH_AUTH_SOCK"}
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--dry-run"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 1
    assert "SSH_AUTH_SOCK" in result.stdout


def test_cli_run_tests_exit_zero() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--run-tests"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert "OK" in combined


def test_command_error_carries_context() -> None:
    error = mod.CommandError(["gopass", "init"], 42, stdout="out", stderr="err")
    assert error.returncode == 42
    assert error.cmd == ["gopass", "init"]
    assert "42" in str(error)
    assert "gopass init" in str(error)


def test_runner_dry_run_does_not_execute(tmp_path: Path) -> None:
    marker = tmp_path / "marker.txt"
    runner = mod.CommandRunner(dry_run=True)
    result = runner.run(
        [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"],
        mutating=True,
    )
    assert result.returncode == 0
    assert not marker.exists()


def test_runner_missing_binary_raises_setup_error(tmp_path: Path) -> None:
    runner = mod.CommandRunner()
    with pytest.raises(mod.GopassSetupError, match="nicht gefunden"):
        runner.run(["definitely-not-a-real-binary-xyz", "--version"])


def test_runner_timeout_raises_command_error() -> None:
    runner = mod.CommandRunner(timeout=1)
    with pytest.raises(mod.CommandError, match="Timeout"):
        runner.run([sys.executable, "-c", "import time; time.sleep(5)"])


def test_parse_ssh_public_key_rejects_malformed_line() -> None:
    with pytest.raises(mod.GopassSetupError):
        mod.parse_ssh_public_key("only-one-field")
    key_type, body = mod.parse_ssh_public_key("ssh-ed25519 AAAABODY comment here")
    assert key_type == "ssh-ed25519"
    assert body == "AAAABODY"


def test_secret_file_path_rejects_empty_name() -> None:
    setup = mod.GopassAgeSetup(store_path=Path("/tmp/unused-store"))
    with pytest.raises(mod.GopassSetupError):
        setup.secret_file_path("///")
