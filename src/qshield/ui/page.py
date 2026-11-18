"""Embedded single-page Workbench UI — served offline, no CDN, no external assets."""

WORKBENCH_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="color-scheme" content="dark" />
<title>QSHIELD · Quantum Supply-Chain Security Workbench</title>
<style>
:root {
  --bg: #0b0f16; --side: #0d1320; --panel: #121a28; --panel2: #151f31; --panel3: #1a2438;
  --line: #21304a; --line2: #2b3d5c; --text: #dfe7f2; --dim: #8b9bb4; --faint: #5b6b84;
  --acc: #2dd4bf; --acc2: #7cc4ff; --acc-soft: rgba(45,212,191,.12);
  --amber: #ffab4a; --red: #ff5c5c; --green: #38d39f; --blue: #4da3ff; --yellow: #ffd84d;
}
* { box-sizing: border-box; }
body {
  margin: 0; background:
    radial-gradient(1100px 500px at 75% -10%, #14203a 0%, transparent 60%),
    radial-gradient(900px 500px at -20% 110%, #101d30 0%, transparent 55%),
    var(--bg);
  color: var(--text); font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  -webkit-font-smoothing: antialiased; font-feature-settings: "tnum" 1;
}
.app { display: grid; grid-template-columns: 236px 1fr; min-height: 100vh; }

/* ===== Sidebar ===== */
.side {
  position: sticky; top: 0; height: 100vh; display: flex; flex-direction: column;
  background: var(--side); border-right: 1px solid var(--line);
  padding: 18px 14px 14px; gap: 4px;
}
.brand { display: flex; align-items: center; gap: 12px; padding: 4px 8px 16px; border-bottom: 1px solid var(--line); margin-bottom: 14px; }
.brand svg { width: 36px; height: 36px; flex: none; }
.brand b { font-size: 17px; letter-spacing: .16em; display: block; }
.brand small { display: block; color: var(--dim); font-size: 9px; letter-spacing: .14em; text-transform: uppercase; line-height: 1.5; }
.sidenav { display: flex; flex-direction: column; gap: 3px; }
.nav-label { color: var(--faint); font-size: 10px; letter-spacing: .16em; text-transform: uppercase; padding: 6px 10px 4px; }
.sidenav button {
  cursor: pointer; display: flex; align-items: center; gap: 11px; width: 100%;
  background: transparent; border: 0; border-left: 3px solid transparent; border-radius: 8px;
  color: var(--dim); font: 600 13px system-ui; letter-spacing: .02em; text-align: left;
  padding: 9px 10px; transition: .15s;
}
.sidenav button svg { width: 17px; height: 17px; stroke: currentColor; fill: none; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; flex: none; opacity: .9; }
.sidenav button:hover { color: var(--text); background: var(--panel2); }
.sidenav button.active {
  color: var(--acc); border-left-color: var(--acc);
  background: linear-gradient(90deg, var(--acc-soft), transparent 75%);
}
.side-spacer { flex: 1; }
.side-foot { border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; background: linear-gradient(180deg, var(--panel2), var(--panel)); }
.side-foot .v { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.side-foot b { font: 700 12px ui-monospace, Menlo, monospace; color: var(--acc); letter-spacing: .06em; }
.side-foot .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); box-shadow: 0 0 8px rgba(56,211,159,.8); display: inline-block; margin-right: 6px; }
.side-foot small { display: block; color: var(--dim); font-size: 10.5px; margin-top: 6px; line-height: 1.5; }

/* ===== Main / topbar ===== */
.main { min-width: 0; display: flex; flex-direction: column; }
.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 14px;
  padding: 13px 26px; border-bottom: 1px solid var(--line);
  background: rgba(13,19,32,.72); backdrop-filter: blur(8px);
  position: sticky; top: 0; z-index: 20;
}
.crumb { color: var(--faint); font-size: 12px; letter-spacing: .06em; }
.crumb b { color: var(--text); margin-left: 8px; font-weight: 600; }
.status-pill { font: 600 10.5px/1 ui-monospace, Menlo, monospace; letter-spacing: .1em; color: var(--acc);
  border: 1px solid rgba(45,212,191,.35); background: var(--acc-soft); border-radius: 999px; padding: 7px 13px; white-space: nowrap; }
.content { padding: 22px 26px 8px; max-width: 1180px; width: 100%; margin: 0 auto; }

section.tab { display: none; }
section.tab.active { display: block; animation: fade .25s ease; }
@keyframes fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }

/* ===== Cards & grids ===== */
.grid { display: grid; gap: 14px; }
.cols-4 { grid-template-columns: repeat(4, 1fr); }
.cols-2 { grid-template-columns: 1fr 1fr; }
@media (max-width: 1080px) { .cols-4 { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 900px) { .cols-2 { grid-template-columns: 1fr; } }
.card { background: linear-gradient(180deg, var(--panel2) 0%, var(--panel) 100%); border: 1px solid var(--line);
        border-radius: 12px; padding: 16px 18px; box-shadow: 0 12px 32px rgba(0,0,0,.28); }
.card h3 { margin: 0 0 10px; font-size: 11px; letter-spacing: .12em; text-transform: uppercase; color: var(--faint); }

/* KPI cards with top accent */
.kpi { position: relative; overflow: hidden; }
.kpi::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, var(--acc), transparent 70%); }
.kpi b { font-size: 27px; color: #fff; display: block; letter-spacing: -.02em; }
.kpi span { color: var(--dim); font-size: 12px; }

/* ===== Forms ===== */
textarea, select {
  width: 100%; background: #0b121d; color: var(--text); border: 1px solid var(--line); border-radius: 10px;
  font: 12.5px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; padding: 10px 12px; resize: vertical;
}
input[type="search"] { width:100%; min-width:180px; background:#0b121d; color:var(--text); border:1px solid var(--line); border-radius:9px; font:12px ui-monospace,Menlo,monospace; padding:9px 11px; }
textarea { min-height: 170px; }
textarea:focus, select:focus, input[type="search"]:focus { outline: none; border-color: var(--acc); box-shadow: 0 0 0 3px rgba(45,212,191,.14); }
label.small { font-size: 10.5px; color: var(--faint); letter-spacing: .1em; text-transform: uppercase; margin: 8px 0 6px; display:block; }
.btn { cursor: pointer; border: 0; border-radius: 9px; padding: 11px 18px; font: 700 13px system-ui; letter-spacing: .03em;
       color: #062a24; background: var(--acc); transition: .15s; }
.btn:hover { transform: translateY(-1px); box-shadow: 0 6px 22px rgba(45,212,191,.35); }
.btn.secondary { background: transparent; color: var(--acc2); border: 1px solid var(--line2); }
.btn.secondary:hover { border-color: var(--acc2); box-shadow: none; }
.btn:disabled { cursor: not-allowed; opacity: .58; transform: none; box-shadow: none; }
.row { display: flex; gap: 10px; align-items: center; margin-top: 12px; flex-wrap: wrap; }
.hero { display:flex; align-items:flex-start; justify-content:space-between; gap:18px; margin:4px 0 18px; }
.hero h1 { margin:0; color:#fff; font-size:clamp(23px,3vw,32px); line-height:1.15; letter-spacing:-.03em; }
.hero p { margin:7px 0 0; color:var(--dim); max-width:680px; font-size:13px; }
.eyebrow { color:var(--acc)!important; font:700 10px/1.4 ui-monospace,Menlo,monospace!important; letter-spacing:.14em; text-transform:uppercase; }
.status-dot { width:7px; height:7px; border-radius:50%; background:var(--green); display:inline-block; margin-right:6px; }

/* ===== Pills ===== */
.pill { display: inline-block; padding: 3px 10px; border-radius: 999px; font: 700 9.5px/1.7 ui-monospace; letter-spacing: .09em; text-transform: uppercase; border: 1px solid transparent; }
.pill.critical { background: rgba(255,92,92,.13); color: #ff8f8f; border-color: rgba(255,92,92,.4); }
.pill.high { background: rgba(255,171,74,.12); color: #ffc98a; border-color: rgba(255,171,74,.38); }
.pill.medium { background: rgba(255,216,77,.1); color: #ffe27a; border-color: rgba(255,216,77,.35); }
.pill.low { background: rgba(77,163,255,.12); color: #8fc2ff; border-color: rgba(77,163,255,.35); }
.pill.info { background: rgba(148,163,184,.1); color: #a9b8c9; border-color: rgba(148,163,184,.3); }
.pill.robust { background: rgba(56,211,159,.12); color: #5ff0bd; border-color: rgba(56,211,159,.38); }
.pill.fragile { background: rgba(255,216,77,.1); color: #ffe27a; border-color: rgba(255,216,77,.35); }
.pill.evaded { background: rgba(255,92,92,.13); color: #ff8f8f; border-color: rgba(255,92,92,.4); }

/* ===== Findings (cards) ===== */
.find { border: 1px solid var(--line); border-left: 3px solid var(--amber); background: var(--panel2); border-radius: 10px; padding: 10px 14px; margin: 10px 0; }
.find.critical { border-left-color: var(--red); } .find.high { border-left-color: var(--amber); } .find.medium,.find.low,.find.info { border-left-color: var(--blue); }
.find h4 { margin: 0 0 4px; font-size: 13px; display: flex; gap: 10px; align-items: center; font-weight: 650; }
.find p { margin: 4px 0 0; color: var(--dim); font-size: 12.5px; }

/* ===== Findings table (Semgrep-style) ===== */
.scan-meta { display: flex; gap: 16px; align-items: center; flex-wrap: wrap; color: var(--dim);
  font-size: 12px; margin: 2px 0 10px; font-family: ui-monospace, Menlo, monospace; }
.scan-meta b { color: var(--text); }
.finding-tools { display:grid; grid-template-columns:minmax(180px,1fr) minmax(150px,.35fr); gap:9px; align-items:center; margin:0 0 8px; }
.finding-count { margin:0 0 8px; color:var(--dim); font-size:11.5px; }
.sevbar { display: flex; height: 8px; border-radius: 99px; overflow: hidden; background: var(--panel3); margin: 0 0 14px; border: 1px solid var(--line); }
.sevbar i { display: block; height: 100%; }
.sevbar .s-critical { background: var(--red); } .sevbar .s-high { background: var(--amber); }
.sevbar .s-medium { background: var(--yellow); } .sevbar .s-low { background: var(--blue); } .sevbar .s-info { background: #64748b; }
.tablewrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--faint); font-size: 10px; letter-spacing: .13em; text-transform: uppercase; background: var(--panel); position: sticky; top: 0; }
tbody tr:nth-child(even) { background: rgba(255,255,255,.015); }
tbody tr:hover { background: var(--acc-soft); }
tbody tr:last-child td { border-bottom: 0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.conf { font-family: ui-monospace, Menlo, monospace; font-size: 12px; color: var(--text); }
.conf small { display: block; color: var(--faint); font-size: 10px; }
.fix { color: var(--dim); font-size: 11.5px; margin-top: 4px; }
.fix b { color: var(--acc2); font-weight: 600; }

/* ===== Compare verdict ===== */
.verdict { font-size: 30px; font-weight: 800; letter-spacing: .02em; padding: 14px 18px; border-radius: 12px; text-align: center; margin: 14px 0 6px; }
.verdict.ok { background: rgba(56,211,159,.1); color: var(--green); border: 1px solid rgba(56,211,159,.35); }
.verdict.bad { background: rgba(255,92,92,.1); color: var(--red); border: 1px solid rgba(255,92,92,.35); }
.verdict.unknown { background: rgba(255,216,77,.08); color: var(--yellow); border: 1px solid rgba(255,216,77,.32); }

/* ===== Policy scorecard bars ===== */
.bar { height: 10px; border-radius: 99px; background: var(--panel3); overflow: hidden; min-width: 120px; border: 1px solid var(--line); }
.bar > i { display: block; height: 100%; background: linear-gradient(90deg, #0e6e5c, var(--acc)); }
.bar.fpr > i { background: linear-gradient(90deg, #6e2020, var(--red)); }

/* ===== Severity legend ===== */
.legend { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
.legend .cell { border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; background: var(--panel); }
.legend .cell small { display: block; color: var(--dim); font-size: 10.5px; margin-top: 6px; }
@media (max-width: 1080px) { .legend { grid-template-columns: repeat(2, 1fr); } }

.ai-reply { white-space: pre-wrap; font-size: 13px; line-height: 1.62; color: #dbe7f5; max-height: 560px; overflow-y: auto; }
.muted { color: var(--dim); font-size: 12px; }
.limit li { margin: 4px 0; color: #b9c8d8; font-size: 13px; }
.err { color: #ff9d9d; background: #241014; border: 1px solid #57201f; border-radius: 10px; padding: 10px 12px; font-size: 13px; white-space: pre-wrap; }
footer { border-top: 1px solid var(--line); margin: 30px 26px 18px; padding: 14px 0 4px; color: var(--faint); font-size: 11px; text-align: center; }
.spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid #2c405e; border-top-color: var(--acc); border-radius: 50%; animation: spin .7s linear infinite; vertical-align: -2px; }
@keyframes spin { to { transform: rotate(360deg); } }
:focus-visible { outline: 2px solid var(--acc); outline-offset: 2px; }

/* ===== Responsive: sidebar -> top strip ===== */
@media (max-width: 900px) {
  .app { grid-template-columns: 1fr; }
  .side { position: static; height: auto; flex-direction: row; align-items: center; gap: 10px; padding: 10px 14px; border-right: 0; border-bottom: 1px solid var(--line); overflow-x: auto; }
  .brand { border: 0; margin: 0; padding: 2px 6px; }
  .brand small, .side-spacer, .side-foot, .nav-label { display: none; }
  .sidenav { flex-direction: row; }
  .sidenav button { border-left: 0; border-bottom: 3px solid transparent; white-space: nowrap; }
  .sidenav button.active { border-bottom-color: var(--acc); background: transparent; }
  .content { padding: 16px 14px 8px; }
  .topbar { padding: 10px 14px; }
  .hero { flex-direction:column; }
}
</style>
</head>
<body>
<div class="app">

<aside class="side">
  <div class="brand">
    <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <path d="M24 2 L44 10 V22 C44 36 36 45 24 46 C12 45 4 36 4 22 V10 Z" fill="#0f2b23" stroke="#2dd4bf" stroke-width="2.4" stroke-linejoin="round"/>
      <path d="M15 24.5 L21.5 31 L34 17.5" stroke="#2dd4bf" stroke-width="3.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div><b>QSHIELD</b><small>Quantum Supply-Chain<br/>Security Workbench</small></div>
  </div>

  <div class="nav-label">Workbench</div>
  <div class="sidenav" id="sidenav" role="tablist" aria-label="Workbench sections"></div>
  <div class="side-spacer"></div>

  <div class="side-foot">
    <div class="v"><b><span class="dot"></span>v1.4.0</b><span class="pill robust">local-first</span></div>
    <small>Local-first quantum software security review.</small>
  </div>
</aside>

<main class="main">
  <div class="topbar">
    <div class="crumb">QSHIELD<b id="crumb-current">Overview</b></div>
    <span class="status-pill"><span class="status-dot"></span>SERVER-SIDE ANALYSIS</span>
  </div>

  <div class="content">

  <section class="tab active" id="tab-overview" role="tabpanel" tabindex="0" aria-labelledby="tab-button-overview" aria-hidden="false">
    <div class="hero">
      <div><p class="eyebrow">QSHIELD SECURITY WORKBENCH</p><h1>Review circuits with evidence.</h1><p>Bring static analysis, equivalence checks, and policy evaluation together for a clear, reviewable view of quantum software.</p></div>
      <div class="status-row"><span class="pill robust">Software-only analysis</span></div>
    </div>
    <div class="grid cols-4">
      <div class="card kpi"><h3>Fixture corpus</h3><b>417</b><span>202 clean · 215 malicious QASM</span></div>
      <div class="card kpi"><h3>Detection (twin-cal.)</h3><b>0.958</b><span>TPR @ δ≥0.1 rigging · FPR 0.008</span></div>
      <div class="card kpi"><h3>Runtime proxy p95</h3><b>1.5 ms</b><span>measured intercept overhead</span></div>
      <div class="card kpi"><h3>Static scale</h3><b>~2 s</b><span>1000-qubit scan · ~75 MB peak</span></div>
    </div>

    <div class="card" style="margin-top:14px">
      <h3>Severity scale &amp; CI action</h3>
      <div class="legend">
        <div class="cell"><span class="pill critical">critical</span><small>Block the build. Human audit before merge/release.</small></div>
        <div class="cell"><span class="pill high">high</span><small>Block in CI. Review and remediate; re-scan to clear.</small></div>
        <div class="cell"><span class="pill medium">medium</span><small>Warn &amp; review. Track to zero across milestones.</small></div>
        <div class="cell"><span class="pill low">low</span><small>Routine hygiene improvement.</small></div>
        <div class="cell"><span class="pill info">info</span><small>Context only. Useful in diffs and audits.</small></div>
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:14px">
      <div class="card">
        <h3>What this is</h3>
        <p style="margin:0 0 8px">A local-first workspace for quantum circuit and supply-chain review, bringing together static analysis, ZX-calculus equivalence, sandboxed execution, policy-as-code, and robustness testing.</p>
        <ul class="limit" style="margin:0; padding-left: 18px">
          <li>Explore circuit structure, compare implementations, and review evidence in one place.</li>
          <li>Use reproducible benchmarks and detailed findings to guide engineering decisions.</li>
        </ul>
      </div>
      <div class="card">
        <h3>Reading a finding</h3>
        <div class="find high"><h4><span class="pill high">high</span> T2.1 · Ancilla carries information about the computation</h4><p>Partial-trace analysis shows ancilla qubit(s) [1, 2] are NOT independent of the data qubits (ancilla reduced states differ by up to 1.00e+00 trace distance across 2 probe inputs). Information is leaking out of the computation. Confidence 0.85.</p></div>
        <p class="muted">Findings provide gate-location and confidence context with suggested remediation to support an informed human review.</p>
      </div>
    </div>
  </section>

  <section class="tab" id="tab-scan" role="tabpanel" tabindex="0" aria-labelledby="tab-button-scan" aria-hidden="true">
    <div class="cols-2 grid">
      <div class="card">
        <h3>Target circuit</h3>
        <label class="small" for="scan-qasm">OpenQASM 2.0 / 3.0 source</label>
        <textarea id="scan-qasm" spellcheck="false" placeholder="OPENQASM 2.0;&#10;include &quot;qelib1.inc&quot;;&#10;qreg q[3];&#10;creg c[3];&#10;h q[0]; cx q[0],q[1]; measure q -> c;"></textarea>
        <div class="row">
          <button class="btn" data-action="scan">Scan circuit</button>
          <button class="btn secondary" data-action="load-example">Load ancilla-leakage example</button>
        </div>
      </div>
      <div class="card">
        <h3>Findings</h3>
        <div id="scan-out" class="muted">Results will appear here. Scanning is static + builtin signatures; dynamic execution is CLI-only (<span class="mono">qshield scan --full</span>).</div>
      </div>
    </div>
  </section>

  <section class="tab" id="tab-compare" role="tabpanel" tabindex="0" aria-labelledby="tab-button-compare" aria-hidden="true">
    <div class="cols-2 grid">
      <div class="card">
        <h3>Pair under audit</h3>
        <label class="small" for="cmp-a">Original (trusted)</label>
        <textarea id="cmp-a" spellcheck="false">OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q -> c;</textarea>
        <label class="small" for="cmp-b">Suspicious (under audit)</label>
        <textarea id="cmp-b" spellcheck="false">OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q -> c;</textarea>
        <label class="small" for="cmp-engine">Verdict engine</label>
        <select id="cmp-engine"><option value="unitary">Dense unitary distance (≤12 qubits)</option><option value="zx">ZX-calculus (proof when supported)</option></select>
        <div class="row"><button class="btn" data-action="compare">Compare</button></div>
      </div>
      <div class="card"><h3>Equivalence report</h3><div id="cmp-out" class="muted">Structural diff, then exact verification.</div></div>
    </div>
  </section>

  <section class="tab" id="tab-robustness" role="tabpanel" tabindex="0" aria-labelledby="tab-button-robustness" aria-hidden="true">
    <div class="card" style="margin-bottom:14px">
      <h3>Novel · Robustness Probe</h3>
      <p style="margin:0 0 6px" class="muted">Applies the five semantics-preserving attack classes from the evasion suite (camouflage, synonyms, rotation_split, dead_code, qubit_relabel) to <i>your</i> circuit, re-scans each variant, and tells you whether each finding survives. This is the question an auditor asks after a flag: <i>“and if the attacker camouflaged it?”</i></p>
      <label class="small" for="rb-qasm">Flagged circuit (.qasm)</label>
      <textarea id="rb-qasm" spellcheck="false" placeholder="Paste the circuit that already triggered a finding…"></textarea>
      <div class="row"><button class="btn" data-action="robustness">Probe finding robustness</button></div>
    </div>
    <div class="card"><h3>Probe results</h3><div id="rb-out" class="muted">One card per base finding with per-attack survival.</div></div>
  </section>

  <section class="tab" id="tab-policy" role="tabpanel" tabindex="0" aria-labelledby="tab-button-policy" aria-hidden="true">
    <div class="cols-2 grid">
      <div class="card">
        <h3>Novel · Policy Studio</h3>
        <p class="muted" style="margin-top:0">Your own lint-style security policies as reviewable code. Toggle the builtin pack, then score it on the fixture corpus when available — see what each policy catches and what it costs in false positives. Heuristic hygiene rules, not threat detectors.</p>
        <label class="small">Builtin pack (FOR YOUR ORG)</label>
        <div id="pl-list">loading…</div>
        <p id="pl-corpus-status" class="muted" role="status" aria-live="polite"></p>
        <label class="small" for="pl-sample">Corpus size</label>
        <select id="pl-sample" disabled><option value="60">Sample 60+60 (fast)</option><option value="0">Full corpus 202+215</option></select>
        <div class="row"><button id="pl-run" class="btn" data-action="policy-eval" disabled>Score on corpus</button></div>
      </div>
      <div class="card"><h3>Corpus scorecard</h3><div id="pl-out" class="muted">TPR = fraction of malicious fixtures flagged · FPR = fraction of clean fixtures flagged. Fixture-corpus rates — not field rates.</div></div>
    </div>
  </section>

  <section class="tab" id="tab-ai" role="tabpanel" tabindex="0" aria-labelledby="tab-button-ai" aria-hidden="true">
    <div class="cols-2 grid" style="margin-top:14px">
      <div class="card">
        <h3>AI Triage <span class="pill medium" style="vertical-align:2px">cloud · advisory</span></h3>
        <div id="ai-status" class="muted" style="margin-bottom:8px">checking AI configuration…</div>
        <label class="small" for="ai-qasm">Circuit under review</label>
        <textarea id="ai-qasm" spellcheck="false" placeholder="OPENQASM 2.0;&#10;include &quot;qelib1.inc&quot;;&#10;qreg q[3];&#10;cx q[0],q[2]; …"></textarea>
        <div class="row">
          <button class="btn" data-action="ai-triage">Explain with AI</button>
          <button class="btn secondary" data-action="load-ai-example">Load ancilla-leakage example</button>
        </div>
        <p class="muted" style="margin-top:10px">Model: sarvam-105b-conversations.</p>
      </div>
      <div class="card"><h3>AI reply</h3><div id="ai-out" class="muted">The triage reply will appear here — plain English, per-finding disposition, and an overall BLOCK / REVIEW / TRACK recommendation. Advisory only.</div></div>
    </div>

    <div class="cols-2 grid" style="margin-top:14px">
      <div class="card">
        <h3>Speak <span class="pill medium" style="vertical-align:2px">Bulbul · cloud</span></h3>
        <label class="small" for="tts-text">Text to speak</label>
        <textarea id="tts-text" spellcheck="false" style="min-height:110px" placeholder="Type what QSHIELD should say, or use “Speak this reply” after a triage…"></textarea>
        <label class="small" for="tts-lang">Language</label>
        <select id="tts-lang"><option value="hi-IN">Hindi (hi-IN)</option><option value="en-IN">English - India (en-IN)</option><option value="mr-IN">Marathi (mr-IN)</option><option value="ta-IN">Tamil (ta-IN)</option><option value="te-IN">Telugu (te-IN)</option><option value="bn-IN">Bengali (bn-IN)</option><option value="gu-IN">Gujarati (gu-IN)</option><option value="kn-IN">Kannada (kn-IN)</option><option value="ml-IN">Malayalam (ml-IN)</option></select>
        <div class="row">
          <button class="btn" data-action="speak">Synthesize</button>
          <label class="muted" style="font-size:11.5px; display:flex; gap:6px; align-items:center"><input type="checkbox" id="tts-auto" checked /> auto-play</label>
        </div>
        <audio id="tts-audio" controls style="width:100%; margin-top:10px; display:none"></audio>
        <div id="tts-out" class="muted" style="margin-top:8px"></div>
      </div>
      <div class="card">
        <h3>Listen <span class="pill medium" style="vertical-align:2px">Saaras · cloud</span></h3>
        <p class="muted" style="margin-top:0">Record with your microphone, then request a transcript.</p>
        <div class="row">
          <button class="btn" id="rec-btn" data-action="record-start">● Record</button>
          <button class="btn secondary" id="rec-stop" data-action="record-stop" disabled>■ Stop</button>
          <button class="btn secondary" id="rec-send" data-action="transcribe" disabled>Transcribe</button>
        </div>
        <div id="rec-status" class="muted" style="margin:10px 0 4px">idle</div>
        <label class="small" for="rec-out">Transcript</label>
        <textarea id="rec-out" style="min-height:110px" placeholder="Transcript appears here…" readonly></textarea>
      </div>
    </div>

      <div class="card" style="margin-top:14px">
        <h3>Audit report in your language <span class="pill medium" style="vertical-align:2px">Sarvam-Translate · cloud</span></h3>
        <p class="muted" style="margin-top:0">A short factual report of the scan (counts, findings, remediation) — machine-translated with Sarvam-Translate (formal mode). Translations can err; the English original is shown alongside for review.</p>
        <label class="small" for="rep-lang">Target language</label>
        <select id="rep-lang"><option value="hi-IN">Hindi (hi-IN)</option><option value="mr-IN">Marathi (mr-IN)</option><option value="ta-IN">Tamil (ta-IN)</option><option value="te-IN">Telugu (te-IN)</option><option value="bn-IN">Bengali (bn-IN)</option><option value="gu-IN">Gujarati (gu-IN)</option><option value="kn-IN">Kannada (kn-IN)</option><option value="ml-IN">Malayalam (ml-IN)</option><option value="en-IN">English - India (en-IN)</option></select>
        <div class="row"><button class="btn" data-action="localized-report">Render report (uses the circuit above)</button><button class="btn secondary" data-action="copy-report">Copy translated</button></div>
        <p id="rep-copy-status" class="muted" role="status" aria-live="polite"></p>
        <div class="grid cols-2" style="margin-top:12px; gap:12px">
          <div><label class="small">English (source)</label><div id="rep-en" class="ai-reply" style="max-height:260px">Render to see the source report.</div></div>
          <div><label class="small">Translated</label><div id="rep-out" class="ai-reply" style="max-height:260px">अनुवाद यहाँ दिखाई देगा।</div></div>
        </div>
      </div>
  </section>

  <section class="tab" id="tab-about" role="tabpanel" tabindex="0" aria-labelledby="tab-button-about" aria-hidden="true">
    <div class="card">
      <h3>About QSHIELD</h3>
      <p>QSHIELD is a local-first workbench for reviewing quantum circuits and the software supply chains around them.</p>
      <div class="grid cols-2" style="margin-top:14px">
        <div class="card"><h4>Analyze</h4><p>Explore circuit structure, threat signatures, information flow, and dependency hygiene.</p></div>
        <div class="card"><h4>Compare</h4><p>Review circuit changes with equivalence and robustness analysis.</p></div>
        <div class="card"><h4>Integrate</h4><p>Bring policy checks and structured reports into engineering workflows.</p></div>
        <div class="card"><h4>Review</h4><p>Use clear findings, benchmark results, and remediation context to support decisions.</p></div>
      </div>
      <p class="muted">QSHIELD Workbench · Apache-2.0</p>
    </div>
  </section>

  </div><!-- /content -->
  <footer>QSHIELD Workbench — local-first quantum software security review, with benchmark metrics measured on the bundled fixture corpus.</footer>
</main>
</div><!-- /app -->

<script nonce="__CSP_NONCE__" src="/assets/workbench.js" defer></script>
</body>
</html>
"""
