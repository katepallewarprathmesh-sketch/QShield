#!/usr/bin/env python3
"""Build the static Workbench demo site (GitHub Pages) from the real UI.

Outputs /tmp/qshield-site/index.html — a fully browser-only page whose
analysis responses are *precomputed outputs of the real QSHIELD engine* on the
bundled fixtures (captured via the live backend into scripts/static_demo_canned/).

Usage: python3 scripts/build_static_site.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CANNED = REPO / "scripts" / "static_demo_canned"
OUT = Path("/tmp/qshield-site")

sys.path.insert(0, str(REPO / "src"))
from qshield.ui.page import WORKBENCH_HTML  # noqa: E402


def js(obj) -> str:
    return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")


canned = {
    "overview": json.loads((CANNED / "overview.json").read_text()),
    "policies": json.loads((CANNED / "policies.json").read_text()),
    "scan_ancilla": json.loads((CANNED / "scan_ancilla.json").read_text()),
    "scan_bell": json.loads((CANNED / "scan_bell.json").read_text()),
    "compare_eq": json.loads((CANNED / "compare_eq.json").read_text()),
    "compare_diff": json.loads((CANNED / "compare_diff.json").read_text()),
    "robustness_ancilla": json.loads((CANNED / "robustness_ancilla.json").read_text()),
    "robustness_bell": json.loads((CANNED / "robustness_bell.json").read_text()),
    "policy_full": json.loads((CANNED / "policy_full.json").read_text()),
    "policy_60": json.loads((CANNED / "policy_60.json").read_text()),
    "example": (CANNED / "ancilla_leakage.qasm").read_text(),
}

banner_css = """
.demo-banner { background:#131f10; border-bottom:1px solid #2c4a1e; color:#b8e986; font-size:12px; padding:9px 18px; display:flex; gap:12px; align-items:center; justify-content:center; flex-wrap:wrap; text-align:center; }
.demo-banner code { background:#0b141f; padding:2px 7px; border-radius:6px; font-size:11px; color:#8ff0c8; }
.demo-banner button { margin-left:6px; background:none; border:1px solid #2c4a1e; color:#b8e986; border-radius:6px; cursor:pointer; padding:1px 9px; }
"""

banner = """
<div class="demo-banner" id="demo-banner"><span><b>STATIC DEMO</b> — runs entirely in your browser on <b>precomputed output of the real QSHIELD engine</b> over the bundled fixtures. For your own circuits: <code>git clone https://github.com/katepallewarprathmesh-sketch/QShield &amp;&amp; pip install -e . &amp;&amp; qshield ui</code></span><button onclick="document.getElementById('demo-banner').remove()" aria-label="dismiss">×</button></div>
"""

shim = """
<script>
// ---- Static-demo shim: replaces the live API with precomputed engine output ----
const __D = %s;
function __norm(s) {
  return (s || '').replace(/\\/\\*[^]*?\\*\\//g, '').replace(/\\/\\/[^\\n]*/g, '').replace(/\\s+/g, ' ').trim();
}
const __BELL = __norm('OPENQASM 2.0; include "qelib1.inc"; qreg q[2]; creg c[2]; h q[0]; cx q[0],q[1]; measure q -> c;');
const __XBELL = __norm('OPENQASM 2.0; include "qelib1.inc"; qreg q[2]; creg c[2]; x q[0]; h q[0]; cx q[0],q[1]; measure q -> c;');
const __ANC = __norm('OPENQASM 2.0; include "qelib1.inc"; qreg q[3]; creg c[3]; cx q[0], q[2]; h q[0]; cx q[0], q[1]; measure q -> c;');
function __kind(src) {
  const n = __norm(src);
  if (n === __ANC) return 'ancilla';
  if (n === __BELL) return 'bell';
  if (n === __XBELL) return 'xbell';
  return null;
}
const __clone = (o) => JSON.parse(JSON.stringify(o));
function __limitation(what) {
  return new Error('Static demo: ' + what + ' is only available for the bundled examples here. Full analysis runs locally — git clone https://github.com/katepallewarprathmesh-sketch/QShield && pip install -e . && qshield ui');
}
async function api(path) {
  const p = String(path).split('?')[0];
  if (p === '/api/overview') return __clone(__D.overview);
  if (p === '/api/policies') return __clone(__D.policies);
  if (p === '/api/example') return { qasm: __D.example };
  throw __limitation('this endpoint');
}
async function apiPost(path, body) {
  if (path === '/api/scan') {
    const k = __kind(body.qasm);
    if (k === 'ancilla') return __clone(__D.scan_ancilla);
    if (k === 'bell') return __clone(__D.scan_bell);
    throw __limitation('scanning arbitrary circuits');
  }
  if (path === '/api/compare') {
    const ka = __kind(body.a), kb = __kind(body.b);
    if (ka && kb) {
      if (ka === kb) return __clone(__D.compare_eq);
      return __clone(__D.compare_diff);
    }
    throw __limitation('comparing arbitrary circuit pairs');
  }
  if (path === '/api/robustness') {
    const k = __kind(body.qasm);
    if (k === 'ancilla') return __clone(__D.robustness_ancilla);
    if (k === 'bell') return __clone(__D.robustness_bell);
    throw __limitation('probing arbitrary circuits');
  }
  if (path === '/api/policy-eval') {
    const src = body.sample ? __D.policy_60 : __D.policy_full;
    const sel = new Set(body.ids || []);
    const per_policy = src.per_policy.filter((r) => sel.has(r.id));
    return { per_policy, any_policy: src.any_policy, corpus: src.corpus,
      note: (src.note || 'Fixture-corpus rates — not field rates.') + ' (static demo: precomputed for the full builtin pack)' };
  }
  throw __limitation('this endpoint');
}
</script>
""" % js(canned)

html = WORKBENCH_HTML
assert html.count("</style>") == 1 and html.count("<body>") == 1 and html.count("</body>") == 1
html = html.replace("</style>", banner_css + "</style>", 1)
html = html.replace("<body>", "<body>\n" + banner, 1)
html = html.replace("</body>", shim + "</body>", 1)
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "index.html").write_text(html)
print(f"built {OUT/'index.html'} ({len(html)} bytes)")
