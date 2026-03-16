# Release Checklist

Use this checklist before publishing any `1.x` release, especially `1.0.0`.

## Version Sync

Update these files together:

- `pyproject.toml`
- `src/wireshark_mcp/__init__.py`
- `server.json`
- `CHANGELOG.md`
- `SECURITY.md` if the supported major line changes

For `1.x`, also confirm that compatibility notes still match reality:

- legacy CLI flags are still documented correctly
- deprecated tools retained for compatibility are still explicitly marked as deprecated

## Validation Commands

Run the full local validation set:

```sh
uv run python -m ruff check src/ tests/
uv run python -m mypy --package wireshark_mcp --ignore-missing-imports --no-namespace-packages
uv run python -m pytest
uv build
uv run wireshark-mcp --help
uv run wireshark-mcp doctor
uv run wireshark-mcp doctor --format json
uv run wireshark-mcp clients
uv run wireshark-mcp clients --format json
uv run wireshark-mcp config
```

If Codex support matters for the release, also run:

```sh
uv run wireshark-mcp config --format codex-toml
```

## Documentation Checks

Before release, confirm:

- `README.md` and `README_zh.md` describe the current install path
- `README.md` and `README_zh.md` describe the current compatibility policy
- platform validation docs still match the CLI behavior
- `CHANGELOG.md` explains the user-visible release changes

## Cross-Platform Sign-Off

Use [platform-validation.md](platform-validation.md) to confirm at least one manual validation pass on:

- macOS
- Linux
- Windows

## Publish

1. Push the release commit.
2. Tag the release.
3. Let GitHub Actions build and publish the package.
4. Confirm the published package version matches `server.json`.

## Post-Publish Checks

After publication, confirm:

- PyPI shows the expected version
- the packaged wheel contains the bundled skill files
- `wireshark-mcp --version` matches the tagged release
- `server.json` registry metadata matches the release version
