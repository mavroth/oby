"""The public agent skill stays installable and pinned to the package version."""

from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "oby" / "SKILL.md"


def _frontmatter() -> str:
    text = SKILL.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    front, _body = text.split("---", 2)[1:]
    return front


def test_skill_matches_the_release_people_install():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    front = _frontmatter()
    assert "\nname: oby\n" in f"\n{front}"
    assert f'version: "{version}"' in front
    description = front.split("description:", 1)[1].split("license:", 1)[0].strip()
    assert 0 < len(description) <= 1024
    assert "HAR" in description
    assert "oby browse" in description
    assert "oby mcp" in description
    pin = f"npx skills add mavroth/oby@v{version} --skill oby"
    skill = SKILL.read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert pin in skill
    assert pin in readme
    assert "session.har" in skill
    assert "scripts.json" in skill
    settings = (ROOT / ".claude" / "settings.json").read_text(encoding="utf-8")
    assert "mcp__oby" in settings
