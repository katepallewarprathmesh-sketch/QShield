from pathlib import Path

from scripts.build_static_site import _render_index


def test_index_can_reference_a_content_hashed_bootstrap():
    html = _render_index("bootstrap.012345abcdef.js")
    assert '<script src="./bootstrap.012345abcdef.js"></script>' in html


def test_static_policies_api_reports_fixture_availability():
    bootstrap = Path(__file__).resolve().parents[2] / "scripts" / "site" / "bootstrap.js"
    source = bootstrap.read_text(encoding="utf-8")

    assert "if (path === '/api/policies')" in source
    assert '"corpus_available": __srv._fixture_corpus_available()' in source
