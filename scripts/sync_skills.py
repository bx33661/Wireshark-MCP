#!/usr/bin/env python3
"""Sync canonical project skills into app-specific discovery locations."""

from __future__ import annotations

import argparse
import filecmp
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
GITHUB_SKILLS_DIR = ROOT / ".github" / "skills"
CLAUDE_SKILLS_DIR = ROOT / ".claude" / "skills"
MANIFEST_PATH = SKILLS_DIR / "manifest.json"


# Unreleased prototype skills are not distributed to client mirrors until 3.1
UNRELEASED_SKILLS = {"tshark-cli-analysis"}


def list_skill_dirs() -> list[Path]:
    return sorted(
        path
        for path in SKILLS_DIR.iterdir()
        if path.is_dir() and (path / "SKILL.md").exists() and path.name not in UNRELEASED_SKILLS
    )


def sync_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


def check_tree_matches(source: Path, destination: Path) -> bool:
    if not destination.exists():
        print(f"Destination does not exist: {destination}", file=sys.stderr)
        return False
    comparison = filecmp.dircmp(source, destination)
    if comparison.left_only or comparison.right_only or comparison.diff_files or comparison.funny_files:
        print(f"Differences found between {source} and {destination}:", file=sys.stderr)
        if comparison.left_only:
            print(f"  Missing in destination: {comparison.left_only}", file=sys.stderr)
        if comparison.right_only:
            print(f"  Extra in destination: {comparison.right_only}", file=sys.stderr)
        if comparison.diff_files:
            print(f"  Modified files: {comparison.diff_files}", file=sys.stderr)
        return False
    for common_dir in comparison.common_dirs:
        if not check_tree_matches(source / common_dir, destination / common_dir):
            return False
    return True


def build_manifest(skill_dirs: list[Path]) -> dict[str, object]:
    skills: list[dict[str, object]] = []
    for skill_dir in skill_dirs:
        skill_name = skill_dir.name
        skills.append(
            {
                "name": skill_name,
                "canonical_path": f"skills/{skill_name}",
                "project_locations": [
                    f".github/skills/{skill_name}",
                    f".claude/skills/{skill_name}",
                ],
                "root_instruction_files": [
                    "CLAUDE.md",
                ],
                "copilot": {
                    "instructions_file": ".github/copilot-instructions.md",
                    "prompt_file": f".github/prompts/{skill_name}.prompt.md",
                },
                "packaged_path": f"wireshark_mcp/skills/{skill_name}",
            }
        )
    return {
        "schema_version": 1,
        "generated_by": "scripts/sync_skills.py",
        "skills": skills,
    }


def run_check(skill_dirs: list[Path]) -> int:
    if not MANIFEST_PATH.exists():
        print(f"Manifest missing: {MANIFEST_PATH}", file=sys.stderr)
        return 1
    expected_manifest = build_manifest(skill_dirs)
    try:
        current_manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Failed to read/parse manifest: {exc}", file=sys.stderr)
        return 1
    if current_manifest != expected_manifest:
        print("Manifest does not match generated manifest.", file=sys.stderr)
        return 1

    for skill_dir in skill_dirs:
        github_dest = GITHUB_SKILLS_DIR / skill_dir.name
        claude_dest = CLAUDE_SKILLS_DIR / skill_dir.name
        if not check_tree_matches(skill_dir, github_dest):
            return 1
        if not check_tree_matches(skill_dir, claude_dest):
            return 1

    print("All skills and manifests are in sync.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync or check skill distribution.")
    parser.add_argument("--check", action="store_true", help="Check skill sync without modifying files.")
    args = parser.parse_args()

    skill_dirs = list_skill_dirs()

    if args.check:
        sys.exit(run_check(skill_dirs))

    GITHUB_SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    CLAUDE_SKILLS_DIR.mkdir(parents=True, exist_ok=True)

    for skill_dir in skill_dirs:
        sync_tree(skill_dir, GITHUB_SKILLS_DIR / skill_dir.name)
        sync_tree(skill_dir, CLAUDE_SKILLS_DIR / skill_dir.name)

    MANIFEST_PATH.write_text(
        json.dumps(build_manifest(skill_dirs), indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
