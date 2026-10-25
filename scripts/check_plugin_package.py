#!/usr/bin/env python3
"""Validate client plugin wiring and optionally build a clean source plugin ZIP."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = (".codex-plugin", ".claude-plugin", ".agents/plugins", "src", "skills", "docs", "changelog", "scripts")
FILES = (
    "pyproject.toml",
    "uv.lock",
    ".python-version",
    "README.md",
    "README_zh.md",
    "LICENSE",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "ROADMAP.md",
    "ROADMAP_zh.md",
)


def load(root: Path, path: str) -> dict:
    return json.loads((root / path).read_text(encoding="utf-8"))


def local_path(root: Path, value: str) -> Path:
    if not isinstance(value, str) or not value.startswith("./"):
        raise ValueError(f"plugin component must use a ./ path: {value}")
    target = (root / value).resolve()
    if not target.is_relative_to(root.resolve()) or not target.exists():
        raise ValueError(f"plugin component missing or outside root: {value}")
    return target


def check(root: Path) -> dict:
    source = ast.parse((root / "src/wireshark_mcp/__init__.py").read_text(encoding="utf-8"))
    version = next(
        ast.literal_eval(node.value)
        for node in source.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
    )
    skills = {item["name"] for item in load(root, "skills/manifest.json")["skills"]}
    native = load(root, ".codex-plugin/plugin.json")
    claude = load(root, ".claude-plugin/plugin.json")
    for manifest in (native, claude):
        if manifest["name"] != "wireshark-mcp" or manifest["version"] != version:
            raise ValueError("plugin identity/version differs from the package")
        directory = local_path(root, manifest["skills"])
        actual = {p.name for p in directory.iterdir() if p.is_dir() and (p / "SKILL.md").is_file()}
        if actual != skills:
            raise ValueError("plugin does not expose every canonical skill")
    codex_mcp = json.loads(local_path(root, native["mcpServers"]).read_text(encoding="utf-8"))["mcpServers"][
        "wireshark-mcp"
    ]
    claude_mcp = claude["mcpServers"]["wireshark-mcp"]
    for entry in (codex_mcp, claude_mcp):
        if entry["command"] != "uv" or not {
            "run",
            "--locked",
            "--no-dev",
            "--extra",
            "index",
            "wireshark-mcp",
            "stdio",
        } <= set(entry["args"]):
            raise ValueError(
                "launcher must resolve the locked runtime via uv with the index extra and without dev dependencies"
            )
    if codex_mcp.get("cwd") != ".":
        raise ValueError("Codex launcher must start at plugin root")
    args = claude_mcp["args"]
    if "--project" not in args or args[args.index("--project") + 1] != "${CLAUDE_PLUGIN_ROOT}":
        raise ValueError("Claude launcher must select its own plugin project")
    for file in (".agents/plugins/marketplace.json", ".claude-plugin/marketplace.json"):
        marketplace = load(root, file)
        if marketplace["name"] != "wireshark-mcp" or len(marketplace["plugins"]) != 1:
            raise ValueError("marketplace identity differs from documented install selector")
        plugin = marketplace["plugins"][0]
        path = plugin["source"]["path"] if isinstance(plugin["source"], dict) else plugin["source"]
        if plugin["name"] != native["name"] or local_path(root, path) != root.resolve():
            raise ValueError("marketplace does not resolve to this complete source project")
    for file in FILES:
        if not (root / file).is_file():
            raise ValueError(f"missing runtime project resource: {file}")
    return {
        "name": native["name"],
        "version": version,
        "skills": sorted(skills),
        "codex_launcher": codex_mcp,
        "claude_launcher": claude_mcp,
    }


def build(root: Path, destination: Path) -> int:
    check(root)
    paths = [root / name for name in FILES]
    paths.extend(
        path
        for directory in DIRECTORIES
        for path in (root / directory).rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
        and "superpowers" not in path.parts
        and "presentation" not in path.parts
    )
    # Exclusive creation prevents silently replacing a previously validated release.
    with destination.open("xb") as output, ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for path in sorted(set(paths)):
            archive.write(path, path.relative_to(root).as_posix())
    return len(set(paths))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--build", type=Path, help="new ZIP output path; no caches, venv or user configuration")
    args = parser.parse_args(argv)
    report = check(args.root)
    print(
        f"Plugin wiring valid: {report['name']} {report['version']}; {len(report['skills'])} skills; 2 client launchers"
    )
    if args.build:
        count = build(args.root, args.build)
        print(f"Built clean source plugin: {args.build.resolve()} ({count} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
