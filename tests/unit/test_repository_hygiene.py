"""Guard high-impact repository reporting and release-process invariants."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ISSUE_TEMPLATES = ROOT / ".github" / "ISSUE_TEMPLATE"


def test_security_vulnerabilities_are_routed_privately() -> None:
    config = yaml.safe_load((ISSUE_TEMPLATES / "config.yml").read_text(encoding="utf-8"))
    links = config["contact_links"]
    security_link = next(link for link in links if "security vulnerability" in link["name"].lower())

    assert security_link["url"].endswith("/security/advisories/new")
    assert config["blank_issues_enabled"] is False
    assert not (ISSUE_TEMPLATES / "vulnerability_report.md").exists()
    assert not (ISSUE_TEMPLATES / "signature_submission.md").exists()
    assert "security@example.org" not in (ROOT / "SECURITY.md").read_text(encoding="utf-8")


def test_release_jobs_wait_for_tag_version_and_test_gate() -> None:
    workflow = (ROOT / ".github" / "workflows" / "release.yaml").read_text(encoding="utf-8")

    assert "tag matches package version" in workflow
    assert "pytest -q tests" in workflow
    assert "  release:\n    needs: verify" in workflow
    assert "  pypi:\n    needs: verify" in workflow
    assert "  ghcr:\n    needs: verify" in workflow
