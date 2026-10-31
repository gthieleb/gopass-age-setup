#!/usr/bin/env python3
"""
gopass_age_setup.py — Robustes Setup für einen gopass-Tresor mit
``fs``-Storage-Backend und ``age``-Krypto, dessen Recipient ein SSH-Public-Key
ist, der über SSH-Agent-Forwarding (z. B. via Tailscale) bezogen wird.

Verifizierte Fakten (gopass-Quellcode v1.15.18 / v1.17.4, age v1.3.1):

1. gopass kennt KEIN ``jsonfs``-Storage-Backend. Verfügbare Backends:
   ``fs`` (ohne RCS), ``gitfs``, ``fossilfs``, ``jjfs``.
   → Dieses Skript nutzt ``--storage fs``.

2. age unterstützt KEINE Entschlüsselung über ssh-agent:
   „keys … accessed via ssh-agent(1) are not supported." (age-Manpage).
   gopass verlangt die SSH-*Private-Key-Datei* neben dem ``.pub``
   (Standard: ``~/.ssh``, alternativ ``GOPASS_SSH_DIR`` oder
   ``gopass config age.ssh-key-path``).
   → Der weitergeleitete Agent-Key wird nur als *Recipient* (Verschlüsseln)
     verwendet; zum Entschlüsseln muss die passende Key-Datei auf dem
     Ziel-Host vorhanden sein. Das prüft dieses Skript und bricht sonst ab.

3. Secret-Namen liegen bei ``fs``/``gitfs`` als Klartext-Dateinamen ab
   (``<secret-name>.age``); verschlüsselt sind nur die Inhalte sowie die
   Recipients-Datei (``.age-recipients`` → physisch ``.age-recipients.age``).
   → Die Test-Suite prüft daher: verschlüsselte Secret-Datei existiert,
     das Klartext-Passwort taucht in KEINER Datei im Store auf,
     ``.age-recipients`` existiert ausschließlich verschlüsselt,
     und der Read-back über ``gopass show -o`` liefert das Original.

Verwendung:

    # Via Tailscale mit Agent-Forwarding einloggen:
    #   ssh -A user@tailscale-host
    python3 gopass_age_setup.py                     # Setup + Verifikation
    python3 gopass_age_setup.py --dry-run           # nur zeigen, was passiert
    python3 gopass_age_setup.py --run-tests         # gemockte Unit-Tests
    python3 gopass_age_setup.py --run-all-tests     # Unit- + Integrationstests
    python3 gopass_age_setup.py --store-path ~/.password-store \\
        --test-secret-path tests/setup-verification/setup-proof \\
        --skip-private-key-check --log-file setup.log -v

Exit-Codes: 0 = Erfolg, 1 = Setup-Fehler, 2 = Testfehler, 130 = Abbruch (Ctrl-C).
"""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from collections.abc import Sequence
from pathlib import Path

LOG = logging.getLogger("gopass-setup")

DEFAULT_STORE_PATH = Path.home() / ".password-store"
DEFAULT_TEST_SECRET_PATH = "tests/setup-verification/setup-proof"
DEFAULT_TIMEOUT_SECONDS = 60

# Von gopass/age als Recipient unterstützte SSH-Key-Typen (authorized_keys-Format).
SUPPORTED_AGE_SSH_KEY_TYPES = ("ssh-ed25519", "ssh-rsa")
# Konventionelle Dateinamen der privaten Schlüssel (Fallback-Suche).
PRIVATE_KEY_CANDIDATES: dict[str, tuple[str, ...]] = {
    "ssh-ed25519": ("id_ed25519",),
    "ssh-rsa": ("id_rsa",),
}
# Dateien in ~/.ssh, die definitiv keine Private-Keys sind.
SSH_NON_KEY_FILES = ("authorized_keys", "known_hosts", "config", "environment")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class GopassSetupError(Exception):
    """Basis-Exception für alle absehbaren Fehler im Setup."""


class CommandError(GopassSetupError):
    """Fehler eines fehlgeschlagenen Subprocess-Aufrufs, mit vollem Kontext."""

    def __init__(
        self,
        cmd: list[str],
        returncode: int,
        stdout: str = "",
        stderr: str = "",
        message: str | None = None,
    ) -> None:
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        if message is None:
            detail = (stderr or stdout).strip() or "(keine Ausgabe)"
            message = f"Befehl fehlgeschlagen (Exit-Code {returncode}): " f"{' '.join(cmd)}\n  → {detail}"
        super().__init__(message)


# ---------------------------------------------------------------------------
# Subprocess-Runner mit Logging, Timeout und Dry-Run-Unterstützung
# ---------------------------------------------------------------------------


class CommandRunner:
    """Führt Befehle aus, loggt sie und wandelt Fehler in CommandError um."""

    def __init__(self, dry_run: bool = False, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> None:
        self.dry_run = dry_run
        self.timeout = timeout

    def run(
        self,
        cmd: list[str],
        *,
        cwd: Path | None = None,
        input: str | None = None,
        env: dict[str, str] | None = None,
        check: bool = True,
        timeout: int | None = None,
        mutating: bool = False,
    ) -> subprocess.CompletedProcess:
        argv = [str(part) for part in cmd]
        dry = self.dry_run and mutating
        LOG.debug(
            "Befehl%s: %s (cwd=%s)",
            " [DRY-RUN]" if dry else "",
            " ".join(argv),
            cwd or os.getcwd(),
        )
        if dry:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        use_env = dict(os.environ if env is None else env)
        try:
            result = subprocess.run(
                argv,
                cwd=str(cwd) if cwd else None,
                input=input,
                env=use_env,
                text=True,
                capture_output=True,
                timeout=timeout or self.timeout,
            )
        except FileNotFoundError as exc:
            raise GopassSetupError(
                f"Programm nicht gefunden: '{argv[0]}' ist nicht installiert " f"oder nicht im PATH ({exc})"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandError(
                argv,
                -1,
                stdout=(exc.stdout or b"").decode(errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or ""),
                stderr=(exc.stderr or b"").decode(errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or ""),
                message=f"Timeout nach {timeout or self.timeout}s: {' '.join(argv)}",
            ) from exc

        if result.stdout:
            LOG.debug("stdout: %s", result.stdout.strip())
        if result.stderr:
            LOG.debug("stderr: %s", result.stderr.strip())
        if check and result.returncode != 0:
            raise CommandError(argv, result.returncode, result.stdout, result.stderr)
        return result


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------


def parse_ssh_public_key(line: str) -> tuple[str, str]:
    """Zerlegt eine authorized_keys-Zeile in (key_type, base64_body).

    Raises:
        GopassSetupError: Bei malformeden Zeilen.
    """
    parts = line.strip().split()
    if len(parts) < 2:
        raise GopassSetupError(f"Ungültige SSH-Public-Key-Zeile: '{line[:80]}'")
    return parts[0], parts[1]


class GopassAgeSetup:
    """Kapselt den kompletten Setup- und Verifikationsablauf."""

    def __init__(
        self,
        store_path: Path = DEFAULT_STORE_PATH,
        *,
        dry_run: bool = False,
        skip_private_key_check: bool = False,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        env_override: dict[str, str] | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.store_path = Path(store_path).expanduser()
        self.dry_run = dry_run
        self.skip_private_key_check = skip_private_key_check
        self.env_override = dict(env_override or {})
        self.runner = runner or CommandRunner(dry_run=dry_run, timeout=timeout)
        self.ssh_pub_key: str | None = None
        self.ssh_key_type: str | None = None

    # -- Umgebung -----------------------------------------------------------

    def _gopass_env(self) -> dict[str, str]:
        """Umgebung für gopass-Aufrufe (inkl. Overrides für Tests/Isolation)."""
        env = dict(os.environ)
        env.update(self.env_override)
        return env

    def verify_environment(self) -> None:
        """Prüft SSH-Agent-Forwarding und installierte Werkzeuge."""
        LOG.info("[1/5] Verifiziere Systemumgebung ...")

        sock = os.environ.get("SSH_AUTH_SOCK")
        if not sock:
            raise GopassSetupError(
                "SSH_AUTH_SOCK ist nicht gesetzt. Bitte via Tailscale mit "
                "Agent-Forwarding einloggen: 'ssh -A user@<tailscale-host>'."
            )
        if not os.path.exists(sock):
            LOG.warning(
                "SSH_AUTH_SOCK zeigt auf '%s', das Socket existiert aber (noch) "
                "nicht. Fahre fort — ssh-add zeigt es verlässlich an.",
                sock,
            )
        else:
            LOG.info("SSH-Agent-Socket gefunden: %s", sock)

        for binary in ("gopass", "ssh-add"):
            if not shutil.which(binary):
                raise GopassSetupError(f"Benötigtes Tool '{binary}' ist nicht installiert oder " "nicht im PATH.")
        if not shutil.which("age"):
            LOG.info(
                "Hinweis: Das 'age'-CLI ist nicht installiert — das ist unkritisch, "
                "denn gopass nutzt die age-Bibliothek intern (kein externes Binary nötig)."
            )

        version = self.runner.run(["gopass", "version"], check=False)
        first_line = (version.stdout or "").strip().splitlines()
        LOG.info("gopass-Version: %s", first_line[0] if first_line else "unbekannt")
        LOG.info("Umgebung erfolgreich verifiziert.")

    # -- SSH-Key ------------------------------------------------------------

    def fetch_ssh_key(self) -> None:
        """Extrahiert den ersten age-kompatiblen Public Key aus dem Agenten."""
        LOG.info("[2/5] Lese SSH-Agent aus (ssh-add -L) ...")
        result = self.runner.run(["ssh-add", "-L"])
        keys = [line for line in (result.stdout or "").splitlines() if line.strip()]
        if not keys:
            raise GopassSetupError(
                "Der SSH-Agent läuft, enthält aber keine Schlüssel. "
                "Auf dem lokalen Rechner z. B. 'ssh-add ~/.ssh/id_ed25519' ausführen."
            )

        skipped: list[str] = []
        for line in keys:
            try:
                key_type, body = parse_ssh_public_key(line)
            except GopassSetupError as exc:
                LOG.warning("Überspringe unlesbare Zeile: %s", exc)
                continue
            if key_type in SUPPORTED_AGE_SSH_KEY_TYPES:
                self.ssh_pub_key = line.strip()
                self.ssh_key_type = key_type
                LOG.info(
                    "age-kompatibler SSH-Key ausgewählt: Typ=%s, Body=%s… (erste "
                    "unter %d gelieferten Keys; übersprungen: %d)",
                    key_type,
                    body[:16],
                    len(keys),
                    len(skipped),
                )
                for skipped_line in skipped:
                    LOG.info("  übersprungen: %s", skipped_line)
                return
            skipped.append(f"{key_type} (von age nicht als Recipient unterstützt)")

        raise GopassSetupError(
            "Kein age-kompatibler SSH-Key im Agenten gefunden. age unterstützt "
            f"nur {', '.join(SUPPORTED_AGE_SSH_KEY_TYPES)} als Recipient; "
            f"vorhandene Typen: {', '.join(k.split()[0] for k in keys) or 'unbekannt'}."
        )

    def find_matching_private_key(self) -> Path | None:
        """Sucht die Private-Key-Datei, die zum ausgewählten Public Key passt.

        gopass/age benötigen zum Entschlüsseln die Key-Datei auf der Maschine
        (~/.ssh, GOPASS_SSH_DIR oder age.ssh-key-path). Der Abgleich erfolgt
        über den Base64-Body des jeweiligen .pub-Files.
        """
        if not self.ssh_pub_key:
            raise GopassSetupError("Interner Fehler: fetch_ssh_key() wurde nicht ausgeführt.")
        _, expected_body = parse_ssh_public_key(self.ssh_pub_key)

        search_dirs: list[Path] = []
        env_dir = os.environ.get("GOPASS_SSH_DIR")
        if env_dir:
            search_dirs.append(Path(env_dir).expanduser())
        search_dirs.append(Path.home() / ".ssh")

        for directory in search_dirs:
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if (
                    not path.is_file()
                    or path.name.endswith(".pub")
                    or path.name in SSH_NON_KEY_FILES
                    or path.name.startswith("known_hosts")
                ):
                    continue
                pub_file = path.with_name(path.name + ".pub")
                if not pub_file.is_file():
                    continue
                try:
                    _, pub_body = parse_ssh_public_key(pub_file.read_text(encoding="utf-8").splitlines()[0])
                except (GopassSetupError, IndexError, OSError):
                    continue
                if pub_body == expected_body:
                    return path

        # Fallback: konventionelle Namen ohne .pub-Abgleich
        if self.ssh_key_type:
            for directory in search_dirs:
                for name in PRIVATE_KEY_CANDIDATES.get(self.ssh_key_type, ()):
                    candidate = directory / name
                    if candidate.is_file():
                        return candidate
        return None

    def check_private_key_availability(self) -> None:
        """Stellt sicher, dass gopass den Key später auch entschlüsseln kann."""
        LOG.info("[3/5] Prüfe Verfügbarkeit der privaten SSH-Key-Datei ...")
        if self.skip_private_key_check:
            LOG.warning(
                "Prüfung der Private-Key-Datei übersprungen (--skip-private-key-check). "
                "Ohne Key-Datei (~/.ssh, GOPASS_SSH_DIR oder age.ssh-key-path) schlägt "
                "die Entschlüsselung fehl — age unterstützt kein ssh-agent-Decrypt."
            )
            return
        private_key = self.find_matching_private_key()
        if private_key is None:
            raise GopassSetupError(
                "Keine zur Agent-Identity passende Private-Key-Datei gefunden. "
                "age kann NICHT über ssh-agent entschlüsseln — der Ziel-Host "
                "braucht die Key-Datei. Optionen: (a) Private-Key (geschützt, "
                "0600) auf den Host kopieren, (b) GOPASS_SSH_DIR auf das "
                "Verzeichnis mit dem Key-Paar setzen, oder (c) diesen Check mit "
                "--skip-private-key-check überspringen (auf eigenes Risiko)."
            )
        LOG.info("Passende Private-Key-Datei gefunden: %s", private_key)
        mode = private_key.stat().st_mode & 0o777
        if mode & 0o077:
            LOG.warning(
                "Rechte von %s sind %o — restriktiver empfohlen: chmod 600 %s",
                private_key,
                mode,
                private_key,
            )

    # -- Store-Initialisierung ----------------------------------------------

    def backup_existing_store(self) -> Path | None:
        """Sichert einen bereits existierenden Store unter Zeitstempel-Backup."""
        if not self.store_path.exists():
            return None
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        backup_path = self.store_path.with_name(f"{self.store_path.name}.bak-{timestamp}")
        while backup_path.exists():
            backup_path = backup_path.with_name(backup_path.name + ".1")
        LOG.warning(
            "Store-Pfad %s existiert bereits. Verschiebe nach %s ...",
            self.store_path,
            backup_path,
        )
        if not self.dry_run:
            self.store_path.rename(backup_path)
        else:
            LOG.info("[DRY-RUN] Würde %s nach %s verschieben.", self.store_path, backup_path)
        return backup_path

    def initialize_gopass(self) -> None:
        """Initialisiert den Tresor: --crypto age --storage fs, SSH-Key als Recipient."""
        LOG.info("[4/5] Initialisiere gopass-Tresor in %s (fs + age) ...", self.store_path)
        self.backup_existing_store()

        if self.ssh_pub_key is None:  # defensive; fetch_ssh_key setzt dies immer
            raise GopassSetupError("Kein SSH-Public-Key gesetzt — Initialisierung abgebrochen.")

        cmd = [
            "gopass",
            "init",
            "--crypto",
            "age",
            "--storage",
            "fs",
            "--path",
            str(self.store_path),
            self.ssh_pub_key,
        ]
        if self.dry_run:
            LOG.info("[DRY-RUN] Würde ausführen: %s", " ".join(cmd))
            return

        self.store_path.mkdir(parents=True, exist_ok=True)
        self.runner.run(cmd, env=self._gopass_env(), mutating=True, timeout=180)
        LOG.info("gopass erfolgreich mit fs-Storage + age-Krypto initialisiert.")

        recipients_encrypted = self.store_path / ".age-recipients.age"
        if recipients_encrypted.is_file():
            LOG.info("Recipients-Datei verschlüsselt vorhanden: %s", recipients_encrypted)
        else:
            LOG.warning(
                "Erwartete (verschlüsselte) Recipients-Datei %s nicht gefunden — " "bitte Store manuell prüfen.",
                recipients_encrypted,
            )

    # -- Secret-Operationen ---------------------------------------------------

    def write_secret(self, name: str, value: str) -> None:
        """Schreibt ein Secret nicht-interaktiv (stdin, -f = overwrite)."""
        self.runner.run(
            ["gopass", "insert", "-f", name],
            input=value + "\n",
            env=self._gopass_env(),
            mutating=True,
        )

    def read_secret(self, name: str) -> str:
        """Liest ein Secret (nur Passwort/erste Zeile)."""
        result = self.runner.run(["gopass", "show", "-o", name], env=self._gopass_env())
        return result.stdout.strip()

    def delete_secret(self, name: str) -> None:
        """Löscht ein Secret erzwungen (-f); Fehler werden geloggt, nicht geworfen."""
        try:
            self.runner.run(["gopass", "rm", "-f", name], env=self._gopass_env(), mutating=True)
            LOG.info("Test-Secret '%s' entfernt.", name)
        except GopassSetupError as exc:
            LOG.warning("Konnte Test-Secret '%s' nicht entfernen: %s", name, exc)

    # -- Verifikation / Test-Suite --------------------------------------------

    def secret_file_path(self, name: str) -> Path:
        """Physischer Pfad eines Secrets im fs-Store: <store>/<pfad>/<name>.age."""
        parts = [segment for segment in name.strip("/").split("/") if segment]
        if not parts:
            raise GopassSetupError(f"Ungültiger Secret-Pfad: '{name}'")
        return self.store_path.joinpath(*parts[:-1], parts[-1] + ".age")

    def run_verification(self, test_secret_path: str = DEFAULT_TEST_SECRET_PATH) -> None:
        """Führt die Verifikationstests nach dem Setup aus (siehe check_*-Methoden)."""
        LOG.info("[5/5] Starte Verifikationstests ...")
        password = secrets.token_urlsafe(24)
        self.check_write_and_file_exists(test_secret_path, password)
        try:
            self.check_no_plaintext_leaks(password)
            self.check_read_back(test_secret_path, password)
        finally:
            self.delete_secret(test_secret_path)
        LOG.info("✅ ALLE VERIFIKATIONSTESTS ERFOLGREICH.")

    def check_write_and_file_exists(self, test_secret_path: str, password: str) -> None:
        """Test 1: Secret schreiben; die verschlüsselte <name>.age-Datei muss existieren."""
        LOG.info("Test 1: Schreibe Secret '%s' ...", test_secret_path)
        self.write_secret(test_secret_path, password)

        encrypted_file = self.secret_file_path(test_secret_path)
        if not encrypted_file.is_file():
            raise GopassSetupError(f"Verschlüsselte Secret-Datei wurde nicht angelegt: {encrypted_file}")
        LOG.info("  ✓ Verschlüsselte Datei existiert: %s (%d Bytes)", encrypted_file, encrypted_file.stat().st_size)

    def check_no_plaintext_leaks(self, password: str) -> None:
        """Test 2: Kein Klartext-Passwort in irgendeiner Store-Datei; Recipients-Datei nur verschlüsselt.

        Bekannt und akzeptiert: Secret-NAHMEN sind Klartext-Dateinamen —
        verschlüsselt sind Inhalte (und die Recipients-Liste).
        """
        LOG.info("Test 2: Scanne Store auf Klartext-Leaks ...")
        needle = password.encode("utf-8")
        hits: list[Path] = []
        for file_path in sorted(self.store_path.rglob("*")):
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_bytes()
            except OSError as exc:
                LOG.warning("  Datei nicht lesbar, überspringe: %s (%s)", file_path, exc)
                continue
            if needle in content:
                hits.append(file_path)
        if hits:
            raise GopassSetupError(
                "KLARTEXT-LECK: Das Passwort steht unverschlüsselt in: " + ", ".join(str(p) for p in hits)
            )
        LOG.info(
            "  ✓ Kein Klartext-Passwort in %s Dateien im Store.",
            sum(1 for _ in self.store_path.rglob("*") if _.is_file()),
        )

        plaintext_recipients = self.store_path / ".age-recipients"
        if plaintext_recipients.is_file():
            raise GopassSetupError(f"META-LECK: Unverschlüsselte Recipients-Datei gefunden: {plaintext_recipients}")
        recipients_encrypted = self.store_path / ".age-recipients.age"
        if recipients_encrypted.is_file():
            LOG.info("  ✓ Recipients-Datei nur verschlüsselt vorhanden: %s", recipients_encrypted)
        else:
            LOG.warning("  ! Recipients-Datei (%s) nicht gefunden.", recipients_encrypted)

    def check_read_back(self, test_secret_path: str, password: str) -> None:
        """Test 3: Entschlüsseltes Secret muss exakt dem Original entsprechen."""
        LOG.info("Test 3: Lese Secret '%s' zurück (gopass show -o) ...", test_secret_path)
        read_back = self.read_secret(test_secret_path)
        if read_back != password:
            raise GopassSetupError(
                "Entschlüsseltes Secret stimmt nicht mit dem Original überein "
                f"(erwartet {len(password)} Zeichen, erhalten {len(read_back)} Zeichen). "
                "Häufigste Ursache: fehlende/passphrase-geschützte Private-Key-Datei."
            )
        LOG.info("  ✓ Read-back identisch (%d Zeichen).", len(password))


# ---------------------------------------------------------------------------
# Integrierte Test-Suite (unittest)
# ---------------------------------------------------------------------------


class StubRunner:
    """Test-Double für CommandRunner: zeichnet Aufrufe auf, liefert Skript-Antworten."""

    def __init__(self, script: list[object] | None = None) -> None:
        self.calls: list[dict[str, object]] = []
        self.script: list[object] = list(script or [])

    def run(self, cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        argv = [str(part) for part in cmd]
        self.calls.append({"cmd": argv, **kwargs})
        if not self.script:
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item  # type: ignore[return-value]

    def calls_with(self, needle: str) -> list[dict[str, object]]:
        return [c for c in self.calls if needle in " ".join(str(x) for x in c["cmd"])]  # type: ignore[operator]


def make_test_setup(store_path: Path, **kwargs: object) -> GopassAgeSetup:
    """GopassAgeSetup mit übergebenem Store-Pfad für Unit-Tests."""
    return GopassAgeSetup(store_path=Path(store_path), **kwargs)  # type: ignore[arg-type]


def simulate_encrypted_secret(setup: GopassAgeSetup, test_path: str) -> Path:
    """Legt im Test-Store die verschlüsselte <name>.age-Datei an (Stub-Insert)."""
    parts = test_path.split("/")
    enc_dir = setup.store_path.joinpath(*parts[:-1])
    enc_dir.mkdir(parents=True, exist_ok=True)
    encrypted_file = enc_dir / (parts[-1] + ".age")
    encrypted_file.write_bytes(b"AGE-ENCRYPTED-BINARY-SIMULATION")
    return encrypted_file


class VerifyEnvironmentTests(unittest.TestCase):
    def _setup(self, tmp: Path) -> GopassAgeSetup:
        return make_test_setup(tmp / ".password-store", runner=StubRunner())

    def test_missing_ssh_auth_sock_raises(self) -> None:
        import unittest.mock as mock

        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SSH_AUTH_SOCK", None)
            with tempfile.TemporaryDirectory() as raw_tmp:
                with self.assertRaises(GopassSetupError) as ctx:
                    self._setup(Path(raw_tmp)).verify_environment()
        self.assertIn("SSH_AUTH_SOCK", str(ctx.exception))

    def test_missing_binary_raises(self) -> None:
        import unittest.mock as mock

        with tempfile.TemporaryDirectory() as raw_tmp:
            env = dict(os.environ)
            env["SSH_AUTH_SOCK"] = "/tmp/agent.sock"
            with mock.patch.dict(os.environ, env, clear=True), mock.patch("shutil.which", return_value=None):
                with self.assertRaises(GopassSetupError) as ctx:
                    self._setup(Path(raw_tmp)).verify_environment()
        self.assertIn("nicht installiert", str(ctx.exception))


class FetchSshKeyTests(unittest.TestCase):
    def _setup(self, tmp: Path, script: list[object]) -> tuple[GopassAgeSetup, StubRunner]:
        runner = StubRunner(script=script)
        return make_test_setup(tmp / ".password-store", runner=runner), runner

    def test_picks_first_supported_key(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            setup, _ = self._setup(
                Path(raw_tmp),
                script=[
                    subprocess.CompletedProcess(
                        [],
                        0,
                        stdout="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host\n",
                        stderr="",
                    )
                ],
            )
            setup.fetch_ssh_key()
            self.assertEqual(setup.ssh_key_type, "ssh-ed25519")
            self.assertTrue(setup.ssh_pub_key.startswith("ssh-ed25519 AAAA"))

    def test_skips_unsupported_and_takes_next(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            out = (
                "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY user@host\n"
                "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB user@host\n"
            )
            setup, _ = self._setup(Path(raw_tmp), script=[subprocess.CompletedProcess([], 0, stdout=out, stderr="")])
            setup.fetch_ssh_key()
            self.assertEqual(setup.ssh_key_type, "ssh-rsa")

    def test_empty_agent_raises(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            setup, _ = self._setup(Path(raw_tmp), script=[subprocess.CompletedProcess([], 0, stdout="", stderr="")])
            with self.assertRaises(GopassSetupError):
                setup.fetch_ssh_key()

    def test_ssh_add_failure_raises(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            failure = CommandError(["ssh-add", "-L"], 2, stderr="Could not open a connection")
            setup, _ = self._setup(Path(raw_tmp), script=[failure])
            with self.assertRaises(GopassSetupError):
                setup.fetch_ssh_key()

    def test_no_supported_type_raises(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            out = "ecdsa-sha2-nistp256 AAAAE2VjZHNh user@host\n"
            setup, _ = self._setup(Path(raw_tmp), script=[subprocess.CompletedProcess([], 0, stdout=out, stderr="")])
            with self.assertRaises(GopassSetupError):
                setup.fetch_ssh_key()


class PrivateKeyMatchTests(unittest.TestCase):
    def test_matches_by_base64_body(self) -> None:
        pub_line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host"
        with tempfile.TemporaryDirectory() as raw_tmp:
            ssh_dir = Path(raw_tmp)
            key_file = ssh_dir / "id_ed25519"
            key_file.write_text("fake unencrypted private key bytes for testing\n")
            (ssh_dir / "id_ed25519.pub").write_text(pub_line + "\n")
            (ssh_dir / "other.pub").write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAOTHER other@host\n")
            (ssh_dir / "other").write_text("not-matching")

            setup = make_test_setup(ssh_dir / "store")
            setup.ssh_pub_key = pub_line
            setup.ssh_key_type = "ssh-ed25519"
            with unittest.mock.patch.dict(os.environ, {"GOPASS_SSH_DIR": str(ssh_dir)}, clear=False):
                found = setup.find_matching_private_key()
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found, key_file)

    def test_returns_none_without_match(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            setup = make_test_setup(Path(raw_tmp) / "store")
            setup.ssh_pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host"
            setup.ssh_key_type = "ssh-ed25519"
            with unittest.mock.patch.dict(os.environ, {"GOPASS_SSH_DIR": raw_tmp}, clear=False):
                found = setup.find_matching_private_key()
        self.assertIsNone(found)


class BackupAndInitTests(unittest.TestCase):
    def test_backup_moves_existing_store(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            store = tmp / ".password-store"
            store.mkdir()
            (store / "old-secret.age").write_bytes(b"ciphertext")
            setup = make_test_setup(store)
            backup = setup.backup_existing_store()
            self.assertIsNotNone(backup)
            assert backup is not None
            self.assertTrue(backup.is_dir())
            self.assertTrue((backup / "old-secret.age").is_file())
            self.assertFalse(store.exists())

    def test_backup_noop_without_store(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            setup = make_test_setup(Path(raw_tmp) / ".password-store")
            self.assertIsNone(setup.backup_existing_store())

    def test_dry_run_touches_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            store = tmp / ".password-store"
            store.mkdir()
            (store / "keep.age").write_bytes(b"x")
            setup = make_test_setup(store, dry_run=True)
            setup.ssh_pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host"
            setup.initialize_gopass()
            self.assertTrue((store / "keep.age").is_file())
            self.assertFalse((store / ".age-recipients.age").exists())

    def test_init_builds_correct_command(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            runner = StubRunner()
            setup = make_test_setup(tmp / ".password-store", runner=runner)
            setup.ssh_pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host"
            setup.initialize_gopass()
            init_calls = runner.calls_with("gopass init")
            self.assertEqual(len(init_calls), 1)
            argv = [str(x) for x in init_calls[0]["cmd"]]  # type: ignore[index]
            self.assertIn("--crypto", argv)
            self.assertIn("age", argv)
            self.assertIn("--storage", argv)
            self.assertIn("fs", argv)
            self.assertIn("--path", argv)
            self.assertIn("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA user@host", argv)
            self.assertTrue(setup.store_path.is_dir())


class VerificationFlowTests(unittest.TestCase):
    """Verifikations-Logik mit gemocktem gopass (ohne echte Binary)."""

    def _prepared_setup(self, tmp: Path) -> tuple[GopassAgeSetup, StubRunner, str, str]:
        runner = StubRunner()
        setup = make_test_setup(tmp / ".password-store", runner=runner)
        test_path = "tests/setup-verification/setup-proof"
        password = "S3cr3t-Unit-Test-Pw!"
        # insert + show + rm simulieren
        runner.script = [
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),  # insert
            subprocess.CompletedProcess([], 0, stdout=password + "\n", stderr=""),  # show -o
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),  # rm
        ]
        return setup, runner, test_path, password

    def test_verification_detects_plaintext_leak(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            setup, _, test_path, password = self._prepared_setup(tmp)
            setup.store_path.mkdir(parents=True)
            # Datei mit Klartext-Passwort simulieren (z. B. unverschlüsselter Store)
            leaked = setup.store_path / "leaked.age"
            leaked.write_text(f"encrypted-header\n{password}\n")

            simulate_encrypted_secret(setup, test_path)
            setup.check_write_and_file_exists(test_path, password)
            with self.assertRaises(GopassSetupError) as ctx:
                setup.check_no_plaintext_leaks(password)
            self.assertIn("KLARTEXT-LECK", str(ctx.exception))

    def test_verification_detects_plaintext_recipients_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            setup, _, test_path, password = self._prepared_setup(tmp)
            setup.store_path.mkdir(parents=True)
            (setup.store_path / ".age-recipients").write_text("ssh-ed25519 AAAA user@host\n")

            simulate_encrypted_secret(setup, test_path)
            setup.check_write_and_file_exists(test_path, password)
            with self.assertRaises(GopassSetupError) as ctx:
                setup.check_no_plaintext_leaks(password)
            self.assertIn("META-LECK", str(ctx.exception))

    def test_verification_happy_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            setup, _, test_path, password = self._prepared_setup(tmp)
            setup.store_path.mkdir(parents=True)
            # Verschlüsselte Dateien simulieren (Inhalt ohne Klartext-Passwort)
            simulate_encrypted_secret(setup, test_path)
            (setup.store_path / ".age-recipients.age").write_bytes(b"AGE-RECIPIENTS-CIPHER")

            setup.check_write_and_file_exists(test_path, password)
            setup.check_no_plaintext_leaks(password)
            setup.check_read_back(test_path, password)

    def test_verification_detects_readback_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            runner = StubRunner(script=[subprocess.CompletedProcess([], 0, stdout="wrong-password\n", stderr="")])
            setup = make_test_setup(tmp, runner=runner)
            with self.assertRaises(GopassSetupError) as ctx:
                setup.check_read_back("some/secret", "expected-password")
            self.assertIn("nicht mit dem Original", str(ctx.exception))

    def test_secret_file_path_layout(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            tmp = Path(raw_tmp)
            setup = make_test_setup(tmp / ".password-store")
            expected = tmp / ".password-store" / "a" / "b" / "c.age"
            self.assertEqual(setup.secret_file_path("a/b/c"), expected)


class IntegrationTests(unittest.TestCase):
    """Echte End-to-End-Tests gegen ein installiertes gopass (isoliert in tmp).

    Läuft nur, wenn gopass + ssh-keygen installiert sind; sonst skip.
    Erzeugt ein eigenes ed25519-Schlüsselpaar und einen isolierten Store.
    """

    @unittest.skipUnless(
        shutil.which("gopass") and shutil.which("ssh-keygen"),
        "gopass/ssh-keygen nicht installiert",
    )
    def test_full_lifecycle_with_real_gopass(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gopass-itest-") as raw_tmp:
            tmp = Path(raw_tmp)
            key_file = tmp / "id_ed25519"
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "gopass-test", "-f", str(key_file)],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            # gopass-Quirk: GOPASS_SSH_DIR erwartet <dir>/.ssh und scannt <dir> selbst.
            (tmp / ".ssh").mkdir()
            config_file = tmp / "gopass-config"
            config_file.write_text("")

            store = tmp / "store"
            setup = GopassAgeSetup(
                store_path=store,
                skip_private_key_check=True,
                env_override={"GOPASS_SSH_DIR": str(tmp), "GOPASS_CONFIG": str(config_file)},
            )
            setup.ssh_pub_key = (tmp / "id_ed25519.pub").read_text(encoding="utf-8").strip()
            setup.ssh_key_type = "ssh-ed25519"
            setup.initialize_gopass()
            self.assertTrue(store.is_dir())

            test_path = "tests/setup-verification/setup-proof"
            password = secrets.token_urlsafe(24)
            setup.check_write_and_file_exists(test_path, password)
            setup.check_no_plaintext_leaks(password)
            setup.check_read_back(test_path, password)
            setup.delete_secret(test_path)


def run_unittest_suite(include_integration: bool) -> bool:
    """Baut die Suite und führt sie aus; gibt Erfolg zurück."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for case in (
        VerifyEnvironmentTests,
        FetchSshKeyTests,
        PrivateKeyMatchTests,
        BackupAndInitTests,
        VerificationFlowTests,
    ):
        suite.addTests(loader.loadTestsFromTestCase(case))
    if include_integration:
        suite.addTests(loader.loadTestsFromTestCase(IntegrationTests))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result.wasSuccessful()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def configure_logging(verbose: bool, log_file: str | None) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gopass_age_setup.py",
        description=(
            "Richtet einen gopass-Tresor ein (fs-Storage + age-Krypto) und "
            "verwendet den ersten age-kompatiblen SSH-Key aus dem "
            "weitergeleiteten SSH-Agenten (SSH_AUTH_SOCK) als Recipient."
        ),
    )
    parser.add_argument(
        "--store-path", default=str(DEFAULT_STORE_PATH), help=f"Pfad des Tresors (Standard: {DEFAULT_STORE_PATH})"
    )
    parser.add_argument(
        "--test-secret-path",
        default=DEFAULT_TEST_SECRET_PATH,
        help=f"Pfad des Test-Secrets (Standard: {DEFAULT_TEST_SECRET_PATH})",
    )
    parser.add_argument("--dry-run", action="store_true", help="Nur zeigen, was ausgeführt würde — nichts verändern.")
    parser.add_argument(
        "--skip-private-key-check",
        action="store_true",
        help="Prüfung auf Private-Key-Datei überspringen (Entschlüsselung schlägt sonst fehl).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Timeout pro Befehl in Sekunden (Standard: {DEFAULT_TIMEOUT_SECONDS})",
    )
    parser.add_argument("--run-tests", action="store_true", help="Nur die gemockten Unit-Tests ausführen und beenden.")
    parser.add_argument(
        "--run-all-tests",
        action="store_true",
        help="Unit-Tests + echte Integrationstests (benötigt gopass + ssh-keygen).",
    )
    parser.add_argument("--log-file", default=None, help="Zusätzliche Logdatei.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug-Ausgaben aktivieren.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    configure_logging(args.verbose, args.log_file)

    if args.run_tests or args.run_all_tests:
        ok = run_unittest_suite(include_integration=args.run_all_tests)
        return 0 if ok else 2

    setup = GopassAgeSetup(
        store_path=Path(args.store_path),
        dry_run=args.dry_run,
        skip_private_key_check=args.skip_private_key_check,
        timeout=args.timeout,
    )
    try:
        setup.verify_environment()
        setup.fetch_ssh_key()
        setup.check_private_key_availability()
        setup.initialize_gopass()
        setup.run_verification(test_secret_path=args.test_secret_path)
    except GopassSetupError as exc:
        LOG.error("Setup abgebrochen: %s", exc)
        return 1
    except KeyboardInterrupt:
        LOG.error("Durch Benutzer abgebrochen (Ctrl-C).")
        return 130
    except Exception:  # noqa: BLE001 — letztes Netz: unerwartete Fehler sauber loggen
        LOG.exception("Unerwarteter Fehler — Setup abgebrochen:")
        return 1

    print("\n🎉 SETUP UND VALIDIERUNG VOLLSTÄNDIG ERFOLGREICH!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
