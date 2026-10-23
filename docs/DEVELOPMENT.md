# Development

[README](../README.md) · [Architecture](ARCHITECTURE.md)

## Environment and checks

Use `uv` to reproduce the locked development environment:

```sh
uv sync --frozen --extra all --extra dev
. .venv/bin/activate
python -m playwright install chromium
ruff check src benchmarks hexstrike_mcp.py hexstrike_server.py
python -m pytest
python -m build
```

Browser tests need a working Chromium installation and OS libraries. Tests use temporary state and loopback fixtures. The security regression suite retains coverage for authentication, shell argument handling, path confinement, caller ownership and process lifecycle behavior. Do not replace behavioral tests with static completion labels.

After intentional dependency changes, update `uv.lock` and export the runtime lock:

```sh
uv lock
uv export --frozen --extra all --no-dev --no-emit-project --format requirements-txt --output-file requirements.lock
```

The installer uses the hashed runtime lock. Keep external command-line tools in their own environments when their dependencies conflict with the application.

The CI workflow runs Linux/macOS checks, installed-wheel acceptance. A configured CI matrix is not evidence that every platform passed; inspect the actual run results before a release.

## Opt-in integration tests

SSH worker tests require an operator-configured destination with Python and Nmap:

```sh
HEXSTRIKE_RUN_REMOTE_TESTS=1 HEXSTRIKE_TEST_SSH_TARGET=operator@worker \
  python -m pytest tests/integration/test_remote_worker.py
```

Container tests require a working engine and a locally available image:

```sh
HEXSTRIKE_TEST_SANDBOX=docker HEXSTRIKE_TEST_IMAGE=docker.io/library/python:3.12-slim \
  python -m pytest tests/integration/test_sandbox_sessions.py
```

Use `podman` for that backend. Missing optional environments are reported as skips; do not count them as passing tests.

## Installed-distribution acceptance

Build a wheel, install it into a separate disposable environment and run:

```sh
/path/to/disposable/bin/python tests/installation/acceptance.py /absolute/path/to/package.whl
```

The script requires a virtual environment and uninstalls its own HexStrike package at the end. It checks the ten-tool MCP interface, actual execution, reconnect, UI, upgrade and retained state. Do not run it against your working server installation.

Test both `./install.sh` and the standalone HTTPS-download path in temporary install/state directories. Verify guided setup from a terminal, paths containing spaces, noninteractive installation, existing command preservation and failed-install cleanup. Test a real initialization/tool call in each supported MCP client before claiming client compatibility.

`python tests/installation/installer_acceptance.py dist/*.tar.gz` exercises the curl-to-shell path against a private HTTPS fixture, including a working directory belonging to an unrelated Python project. It downloads runtime dependencies, verifies the real browser, and retains its temporary logs for diagnosis. The fixture certificate is trusted only by that test's child processes.

## Benchmarks

```sh
python benchmarks/run_benchmarks.py
```

The runner measures fresh-process MCP initialization, manifest size, local HTTP/JWT fixture detection and redirect boundaries. It writes `benchmarks/latest_benchmark_results.json`, which is ignored by Git. Token estimates use UTF-8 bytes divided by four; they are not tokenizer measurements. Precision/recall describe the limited fixture set, not arbitrary pentest quality. Preserve misses and false positives in the results.

## Repository contents

Commit source, tests, the benchmark runner, documentation, installer, packaging/CI definitions, the project logo. Keep private state, tokens, certificates, local client settings, virtual environments, caches, build outputs and test-run receipts outside version control.

The wheel contains the importable package and distribution metadata. The source archive also includes docs, tests, installer, benchmark source. Review both archives before release. Do not add a file solely to claim a feature is finished; retain executable checks and user-facing documentation instead.

Before publishing, inspect `git status --short`, run `git diff --check`, check ignored/untracked files and review the staged diff. Ignore rules do not remove already-tracked sensitive files. No local audit, benchmark or successful install substitutes for reviewing the actual release contents.
