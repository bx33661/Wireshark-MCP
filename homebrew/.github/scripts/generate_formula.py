#!/usr/bin/env python3
"""
Generate a Homebrew Formula for wireshark-mcp at a given version.

Usage:
    python3 generate_formula.py 1.2.0 > Formula/wireshark-mcp.rb
"""
import json
import os
import sys
import subprocess
import tempfile
import urllib.request
import venv

TEMPLATE_HEADER = """\
class WiresharkMcp < Formula
  include Language::Python::Virtualenv

  desc "MCP server that turns tshark into a structured packet-analysis interface"
  homepage "https://github.com/bx33661/Wireshark-MCP"
  url "{sdist_url}"
  sha256 "{sdist_sha256}"
  license "MIT"

  head "https://github.com/bx33661/Wireshark-MCP.git", branch: "main"

  depends_on "openssl@3"
  depends_on "python@3.12"
  depends_on "rust" => :build
  depends_on "wireshark"

"""

TEMPLATE_FOOTER = """\

  def install
    virtualenv_install_with_resources
  end

  test do
    output = shell_output("#{bin}/wireshark-mcp --version 2>&1")
    assert_match version.to_s, output
    assert_path_exists Formula["wireshark"].opt_bin/"tshark"
  end
end
"""

SKIP_PACKAGES = {"pip", "setuptools", "wheel", "wireshark-mcp"}
# Packages that only ship as sdist (native extensions)
NATIVE_PACKAGES = {"cffi", "cryptography", "pydantic_core", "pydantic-core", "rpds_py", "rpds-py"}


def pypi_info(name: str, version: str) -> dict:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url) as r:
        return json.load(r)


def best_url(urls: list[dict]) -> dict:
    """Pick py3-none-any wheel, then any-none-any, then sdist."""
    for u in urls:
        if u["filename"].endswith("py3-none-any.whl"):
            return u
    for u in urls:
        if u["filename"].endswith("none-any.whl"):
            return u
    for u in urls:
        if u["packagetype"] == "sdist":
            return u
    return urls[0]


def resource_name(pkg_name: str) -> str:
    return pkg_name.lower().replace("-", "_").replace(".", "_")


def main(version: str) -> None:
    # 1. Get wireshark-mcp sdist info
    data = pypi_info("wireshark-mcp", version)
    sdist = next(u for u in data["urls"] if u["packagetype"] == "sdist")

    # 2. Install into a temp venv to capture full dep tree
    tmpdir = tempfile.mkdtemp()
    venv_dir = os.path.join(tmpdir, "venv")
    venv.create(venv_dir, with_pip=True)
    pip = os.path.join(venv_dir, "bin", "pip")

    subprocess.run(
        [pip, "install", "--quiet", f"wireshark-mcp=={version}"],
        check=True,
    )
    result = subprocess.run(
        [pip, "list", "--format=json"],
        capture_output=True, text=True, check=True,
    )
    installed = json.loads(result.stdout)

    # 3. Build resource blocks
    resource_blocks = []
    for pkg in installed:
        name, ver = pkg["name"], pkg["version"]
        if name.lower() in SKIP_PACKAGES:
            continue
        info = pypi_info(name, ver)
        chosen = best_url(info["urls"])
        rname = resource_name(name)
        block = (
            f'  resource "{rname}" do\n'
            f'    url "{chosen["url"]}"\n'
            f'    sha256 "{chosen["digests"]["sha256"]}"\n'
            f'  end'
        )
        resource_blocks.append(block)

    # 4. Emit formula
    print(TEMPLATE_HEADER.format(
        sdist_url=sdist["url"],
        sdist_sha256=sdist["digests"]["sha256"],
    ), end="")
    print("\n\n".join(resource_blocks))
    print(TEMPLATE_FOOTER, end="")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <version>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
