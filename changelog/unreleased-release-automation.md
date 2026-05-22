# [Unreleased] - Release automation hardening

Date: 2026-04-28

## Changed

- Hardened the PyPI release workflow so Homebrew tap dispatch HTTP failures now fail the release step instead of being silently ignored.
- Added explicit read permissions for checkout in the PyPI release workflow.
- Fixed the Homebrew bottle workflow by relying on `Homebrew/actions/setup-homebrew`'s local tap setup instead of re-tapping the checkout during the job.
- Updated the Homebrew bottle workflow to mark bot bottle-block commits with `[skip bottles]` and skip bottle builds when that marker is present.
- Updated the Homebrew formula template and generated formula to satisfy current `brew style` checks.
- Ignored generated Claude worktrees so machine-local worktree checkouts are not added to patches.

## Files touched

- `.github/workflows/publish.yml`
- `homebrew/.github/workflows/build-bottles.yml`
- `homebrew/.github/scripts/generate_formula.py`
- `homebrew/Formula/wireshark-mcp.rb`
- `.gitignore`

## Why

These changes prevent missed Homebrew formula bumps from appearing as successful releases, avoid redundant bottle builds triggered by the workflow's own commits, and keep generated local worktrees out of version control.

## Usage

No user-facing usage changes. Release and bottle workflows continue to run from the existing GitHub Actions triggers.
