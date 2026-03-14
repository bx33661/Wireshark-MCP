from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_DIR = ROOT / "skills" / "wireshark-traffic-analysis"
GITHUB_DIR = ROOT / ".github" / "skills" / "wireshark-traffic-analysis"
CLAUDE_DIR = ROOT / ".claude" / "skills" / "wireshark-traffic-analysis"
MANIFEST_PATH = ROOT / "skills" / "manifest.json"


def _relative_file_map(base: Path) -> dict[str, str]:
    return {
        str(path.relative_to(base)): path.read_text(encoding="utf-8")
        for path in sorted(base.rglob("*"))
        if path.is_file()
    }


def test_skill_mirrors_match_canonical() -> None:
    canonical_files = _relative_file_map(CANONICAL_DIR)

    assert canonical_files
    assert canonical_files == _relative_file_map(GITHUB_DIR)
    assert canonical_files == _relative_file_map(CLAUDE_DIR)


def test_skill_manifest_lists_supported_locations() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 1
    skills = manifest["skills"]
    assert isinstance(skills, list)
    assert skills

    skill = next(item for item in skills if item["name"] == "wireshark-traffic-analysis")
    assert skill["canonical_path"] == "skills/wireshark-traffic-analysis"
    assert ".github/skills/wireshark-traffic-analysis" in skill["project_locations"]
    assert ".claude/skills/wireshark-traffic-analysis" in skill["project_locations"]
    assert "AGENTS.md" in skill["root_instruction_files"]
    assert skill["copilot"]["instructions_file"] == ".github/copilot-instructions.md"
    assert skill["copilot"]["prompt_file"] == ".github/prompts/wireshark-traffic-analysis.prompt.md"
