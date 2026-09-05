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
    if GITHUB_DIR.exists():
        assert canonical_files == _relative_file_map(GITHUB_DIR)
    if CLAUDE_DIR.exists():
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
    assert skill["copilot"]["instructions_file"] == ".github/copilot-instructions.md"
    assert skill["copilot"]["prompt_file"] == ".github/prompts/wireshark-traffic-analysis.prompt.md"


def test_sync_skills_cli_check_returns_zero_when_in_sync() -> None:
    import subprocess
    import sys

    res = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sync_skills.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "All skills and manifests are in sync." in res.stdout


def test_sync_skills_check_detects_discrepancy(tmp_path: Path, monkeypatch) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("sync_skills", ROOT / "scripts" / "sync_skills.py")
    assert spec and spec.loader
    ss = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ss)

    fake_empty = tmp_path / "empty_dir"
    fake_empty.mkdir()
    monkeypatch.setattr(ss, "GITHUB_SKILLS_DIR", fake_empty)
    skill_dirs = ss.list_skill_dirs()
    assert ss.run_check(skill_dirs) == 1
