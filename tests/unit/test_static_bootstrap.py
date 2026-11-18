import runpy
from pathlib import Path

_site_builder = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts" / "build_static_site.py"))
_render_workbench = _site_builder["_render_workbench"]
_render_home = _site_builder["_render_home"]


def test_workbench_can_reference_a_content_hashed_bootstrap():
    html = _render_workbench("bootstrap.012345abcdef.js")
    assert '<script src="./bootstrap.012345abcdef.js"></script>' in html
    assert '<script src="./assets/workbench.js" defer></script>' in html
    assert 'src="/assets/workbench.js"' not in html
    assert "IN-BROWSER ANALYSIS" in html
    assert "SERVER-SIDE ANALYSIS" not in html


def test_home_page_links_to_workbench_and_has_current_version():
    html = _render_home("1.4.0")
    assert 'href="workbench.html"' in html
    assert "v1.4.0" in html
    assert "Flexible integration" in html
    assert "Likely budget owner" not in html
    assert "no paid enterprise plan" not in html
    assert "Trust &amp; transparency" in html
    assert "Trust &amp; limits" not in html
    assert "__QSHIELD_VERSION__" not in html


def test_about_tab_label_is_synced_in_source_and_runtime_bundle():
    repo = Path(__file__).resolve().parents[2]
    sources = [
        repo / "frontend" / "src" / "workbench.ts",
        repo / "src" / "qshield" / "ui" / "static" / "workbench.js",
    ]
    for source in sources:
        text = source.read_text(encoding="utf-8")
        assert '"about", "About"' in text
        assert "About & limits" not in text


def test_static_policies_api_reports_fixture_availability():
    bootstrap = Path(__file__).resolve().parents[2] / "scripts" / "site" / "bootstrap.js"
    source = bootstrap.read_text(encoding="utf-8")

    assert "if (path === '/api/policies')" in source
    assert "capabilities: [" in source
    assert "limits: [" not in source
    assert '"corpus_available": __srv._fixture_corpus_available()' in source
