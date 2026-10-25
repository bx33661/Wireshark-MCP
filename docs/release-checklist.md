# Release Checklist

Use this checklist before publishing a release from the active `4.x` line.

## Version Sync

Update these files together:

- `pyproject.toml`
- `src/wireshark_mcp/__init__.py`
- `server.json`
- `.well-known/mcp/server.json`
- `changelog/<version>.md` and the root `CHANGELOG.md` index
- `SECURITY.md` if the supported major line changes
- `Dockerfile` (`WIRESHARK_MCP_VERSION`) and the image tags in `docs/deployment-scenarios*.md`
- `.claude-plugin/plugin.json` and `.codex-plugin/plugin.json`

Also confirm that compatibility notes still match reality:

- legacy CLI flags are still documented correctly
- deprecated tools retained for compatibility are still explicitly marked as deprecated

## Validation Commands

Run the full local validation set in an environment with the `index` extra installed (`uv sync --group dev --extra index`), so the capture-index and tshark-equivalence tests run instead of skipping:

```sh
uv run python -m ruff check src/ tests/
uv run python -m mypy --package wireshark_mcp --ignore-missing-imports --no-namespace-packages
uv run python -m pytest
uv export --frozen --no-dev --no-emit-project --format requirements-txt | uvx pip-audit -r /dev/stdin --disable-pip
uvx bandit -q -r src
uvx zizmor --pedantic --min-severity low .
uv build
uv run wireshark-mcp --help
uv run wireshark-mcp doctor
uv run wireshark-mcp doctor --format json
uv run wireshark-mcp clients
uv run wireshark-mcp clients --format json
uv run wireshark-mcp config
```

Build only after the final source change. Compare packaged Python files with `src/wireshark_mcp`, then install that exact wheel into a fresh environment. The installed wheel must pass `--version`, `python -m wireshark_mcp --version`, JSON doctor output, and the `2026-07-28` stateless `server/discover` → `tools/list` → `tools/call` sequence without an MCP session ID.

If Codex support matters for the release, also run:

```sh
uv run wireshark-mcp config --format codex-toml
```

## Documentation Checks

Before release, confirm:

- `README.md` and `README_zh.md` describe the current install path
- `docs/README.md` and `docs/README_zh.md` contain no broken local links
- every documented CLI option appears in `wireshark-mcp <command> --help`
- every documented `wireshark_*` name exists in the selected public tool profile
- `docs/aggregation.md` and `docs/aggregation_zh.md` match the current limits and result fields
- platform validation docs still match the CLI behavior
- the numbered changelog explains user-visible changes from `changelog/unreleased.md`
- `ROADMAP.md` and `ROADMAP_zh.md` reflect any completed or rescheduled work

## Skill Gates

Validate source, discoverability, packaged resources and behavior separately:

```sh
python scripts/sync_skills.py
python scripts/sync_skills.py --check --require-installed
python skills/tshark-cli-analysis/scripts/tshark_inventory.py --output new-inventory.json --check
python scripts/check_skill_package.py dist/wireshark_mcp-<version>-py3-none-any.whl
python scripts/check_skill_installation.py --python /absolute/path/to/clean/venv/python --require-engine --output installed-skills.json
```

Review every newly discovered option/report/tap against the installed/official
manual before updating the capability catalog. The wheel must contain both skill
entrypoints, every referenced guide, UI metadata and executable helper source;
bytecode caches are not distributed. Run actual offline format/statistic/export
smokes and budget recovery tests. Live/remote capture, hardware-specific and
key-dependent features need appropriate separate environments, not fabricated
sign-off from an offline fixture. Independent Agent traces are required before
publishing behavior/cost improvements. Require a complete repeated matrix with
`scripts/check_agent_matrix.py` before interpreting a full comparison; prepared
blind tasks are not executed results. See [Agent evaluation](agent-evaluation.md).

## Cross-Platform Sign-Off

Use [platform-validation.md](platform-validation.md) to confirm at least one manual validation pass on:

- macOS
- Linux
- Windows

## Publish

1. Merge the release PR and set the date in `changelog/<version>.md` and `CHANGELOG.md`.
2. Tag the release commit `v<version>` and publish a GitHub Release whose body is `changelog/<version>.md`.
3. Publishing the Release triggers `publish.yml` (PyPI, trusted publishing) and `publish-container.yml` (GHCR multi-platform image).
4. The container build installs the version from PyPI. If it ran before the package appeared there, re-run it: `gh workflow run publish-container.yml -f version=<version>`. `publish.yml` can be re-run the same way with `-f tag=v<version>`.
5. Confirm the published package version matches both registry metadata files.

The `Container smoke` check on a release PR installs the new version from PyPI, so it fails until that version is published. That failure is expected on the release PR only.

## Post-Publish Checks

After publication, confirm:

- PyPI shows the expected version
- the packaged wheel contains the bundled skill files
- `wireshark-mcp --version` matches the tagged release
- `server.json` and `.well-known/mcp/server.json` match the release version
- a clean installation can call `wireshark_open_file`, `wireshark_aggregate`, and one packet-level verification tool
- with `pip install 'wireshark-mcp[index]'`, `wireshark_index` builds an index and the next `wireshark_aggregate` reports `coverage.source: "index"`
- `ghcr.io/bx33661/wireshark-mcp:<version>` and `:latest` exist and `docker run … --version` prints the release version
- the Homebrew tap (`bx33661/homebrew-wireshark-mcp`) received the formula bump; `publish.yml` only dispatches it when the `HOMEBREW_TAP_TOKEN` secret is set

## Client plugin distribution

Keep both plugin manifest versions aligned with the Python package. Validate
`scripts/check_plugin_package.py`, build a clean source ZIP, and cold-start both
launchers with `scripts/smoke_plugin_runtime.py`. Test native client
marketplace/install/list/remove in isolated configuration directories. Check
that fresh uv environments contain no dev dependencies, stdio is clean, and
skills/resources resolve without a developer checkout or venv.

Commit/publish the repo manifests before advertising the GitHub marketplace
commands as available. Repository marketplaces, release ZIPs and universal public
directory approval are distinct deliverables. Never infer GUI-session success
from manifest parsing alone.
