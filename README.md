# gopass-age-setup

[![CI](https://github.com/gthieleb/gopass-age-setup/actions/workflows/ci.yml/badge.svg)](https://github.com/gthieleb/gopass-age-setup/actions/workflows/ci.yml)

A robust, single-file Python bootstrap for a [gopass](https://www.gopass.pw/) password
store using the **`fs` storage backend** with **`age` cryptography**, where the age
recipient is an **SSH public key taken from the forwarded SSH agent**
(`SSH_AUTH_SOCK`) — e.g. when logging into a server over [Tailscale](https://tailscale.com/)
with `ssh -A`.

```
ssh -A user@tailscale-host
python3 gopass_age_setup.py
```

## Why these backends (and not `jsonfs` / ssh-agent decryption)?

Verified against the gopass source (v1.15.18 / v1.17.4) and the age man page:

| Assumption | Reality |
|---|---|
| `--storage jsonfs` | **Does not exist.** 1.x storage backends are `fs`, `gitfs`, `fossilfs`, `jjfs`. This script uses `fs` (no RCS). |
| Decrypt via ssh-agent | **Not possible.** age: *"keys … accessed via ssh-agent(1) are not supported."* gopass needs the matching SSH **private key file** on the host (`~/.ssh`, `GOPASS_SSH_DIR`, or `gopass config age.ssh-key-path`). The forwarded agent key is only used to derive the **recipient** (encryption). |
| "No plaintext metadata at all" | Secret **names** are stored as cleartext file names (`<secret>.age`); the **content** and the recipients list (`.age-recipients` → encrypted `.age-recipients.age`) are encrypted. The test suite verifies content encryption instead. |

## What the script does

1. **Verify environment** — `SSH_AUTH_SOCK` present, `gopass` + `ssh-add` in `PATH`
   (missing `age` binary is fine — gopass embeds the age library).
2. **Fetch SSH key** — runs `ssh-add -L`, picks the **first age-compatible key**
   (`ssh-ed25519`/`ssh-rsa`); unsupported types are logged and skipped.
3. **Private key check** — makes sure gopass will be able to *decrypt* later
   (hard fail with instructions, or `--skip-private-key-check`).
4. **Initialize the store** — backs up an existing store to
   `<store>.bak-<timestamp>` first, then runs
   `gopass init --crypto age --storage fs --path <store> "<recipient>"`.
5. **Verification suite** — writes a random test secret and validates:
   - the encrypted `<secret>.age` file exists,
   - the plaintext secret appears in **no** file inside the store (byte scan),
   - `.age-recipients` exists **only** in encrypted form,
   - `gopass show -o` returns the original password,
   - the test secret is removed afterwards.

## Usage

```bash
python3 gopass_age_setup.py                 # full setup + verification
python3 gopass_age_setup.py --dry-run       # show what would happen, change nothing
python3 gopass_age_setup.py --run-tests     # mocked unit tests only
python3 gopass_age_setup.py --run-all-tests # unit tests + real integration tests
```

| Flag | Purpose |
|---|---|
| `--store-path PATH` | Store location (default `~/.password-store`) |
| `--test-secret-path PATH` | Path of the verification secret (default `tests/setup-verification/setup-proof`) |
| `--dry-run` | Log mutating commands instead of running them |
| `--skip-private-key-check` | Skip the private-key availability check (decryption will fail without it) |
| `--timeout SECONDS` | Per-command timeout (default 60) |
| `--run-tests` / `--run-all-tests` | Run the built-in test suite and exit |
| `--log-file FILE` / `-v` | Extra log file / debug output |

Exit codes: `0` success · `1` setup error · `2` test failure · `130` interrupted.

**Make decryption work:** the SSH private key matching the agent identity must be
readable on the target host (permissions `0600`). Either place it in `~/.ssh`,
point `GOPASS_SSH_DIR` at a directory containing the key pair (note: gopass
expects `<dir>/.ssh` to exist and scans `<dir>` itself), or set
`gopass config age.ssh-key-path`. Passphrase-protected keys can supply their
passphrase non-interactively via `GOPASS_AGE_PASSWORD`.

## Testing & coverage

The script ships its own integrated `unittest` suite (`--run-tests` /
`--run-all-tests`); this repository runs the same cases — plus CLI tests —
through **pytest with coverage**:

```bash
python -m pip install -r requirements-dev.txt
pytest --cov=gopass_age_setup --cov-report=term-missing
```

CI (GitHub Actions, Python 3.10–3.14 matrix) installs a pinned gopass release
and runs the full suite including the real end-to-end integration test, then
uploads `coverage.xml` and writes a coverage summary to the job summary.

## Development

This repo uses [pre-commit](https://pre-commit.com/) (gitleaks, ruff, ruff-format,
yamllint, hygiene hooks):

```bash
pre-commit install
pre-commit run -a
```

## License

[MIT](LICENSE) © 2026 gthieleb
