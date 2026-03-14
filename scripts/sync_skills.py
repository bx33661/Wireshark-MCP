#!/usr/bin/env python3
"""Sync canonical project skills into app-specific discovery locations."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
GITHUB_SKILLS_DIR = ROOT / ".github" / "skills"
CLAUDE_SKILLS_DIR = ROOT / ".claude" / "skills"
MANIFEST_PATH = SKILLS_DIR / "manifest.json"


def list_skill_dirs() -> list[Path]:
    return sorted(
        path
        for path in SKILLS_DIR.iterdir()
        if path.is_dir() and (path / "SKILL.md").exists()
    )


def sync_tree(source: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)


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
                    "AGENTS.md",
                    "CLAUDE.md",
                    "GEMINI.md",
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


def main() -> None:
    skill_dirs = list_skill_dirs()
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
