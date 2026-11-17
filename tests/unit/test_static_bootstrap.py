from pathlib import Path


def test_static_policies_api_reports_fixture_availability():
    bootstrap = Path(__file__).resolve().parents[2] / "scripts" / "site" / "bootstrap.js"
    source = bootstrap.read_text(encoding="utf-8")

    assert "if (path === '/api/policies')" in source
    assert '"corpus_available": __srv._fixture_corpus_available()' in source
