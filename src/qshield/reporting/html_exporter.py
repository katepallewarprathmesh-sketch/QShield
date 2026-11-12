"""HTML export via Jinja2 (self-contained, inline CSS)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


def render_html(
    findings: list,
    summary: dict[str, Any],
    report: dict[str, Any],
    version: str = "0.1.0",
) -> str:
    template_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "jinja2"]),
    )
    env.filters["tojson"] = lambda v, **kw: json.dumps(v, default=str, **{"indent": 2, **kw})
    template = env.get_template("report.html.jinja2")
    return template.render(findings=findings, summary=summary, report=report, version=version)
