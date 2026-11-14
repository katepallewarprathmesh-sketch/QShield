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
textarea { min-height: 170px; }
textarea:focus, select:focus { outline: none; border-color: var(--acc); box-shadow: 0 0 0 3px rgba(45,212,191,.14); }
label.small { font-size: 10.5px; color: var(--faint); letter-spacing: .1em; text-transform: uppercase; margin: 8px 0 6px; display:block; }
.btn { cursor: pointer; border: 0; border-radius: 9px; padding: 11px 18px; font: 700 13px system-ui; letter-spacing: .03em;
       color: #062a24; background: var(--acc); transition: .15s; }
.btn:hover { transform: translateY(-1px); box-shadow: 0 6px 22px rgba(45,212,191,.35); }
.btn.secondary { background: transparent; color: var(--acc2); border: 1px solid var(--line2); }
.btn.secondary:hover { border-color: var(--acc2); box-shadow: none; }
.row { display: flex; gap: 10px; align-items: center; margin-top: 12px; flex-wrap: wrap; }

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

  <div class="sidenav" id="sidenav" role="navigation" aria-label="Workbench sections"></div>
  <div class="side-spacer"></div>

  <div class="side-foot">
    <div class="v"><b><span class="dot"></span>v1.1.1</b><span class="pill robust">offline</span></div>
    <small>Zero network calls. Zero hardware. Numbers measured on the bundled fixture corpus — evidence, not proofs.</small>
  </div>
</aside>

<main class="main">
  <div class="topbar">
    <div class="crumb">QSHIELD<b id="crumb-current">Overview</b></div>
    <span class="status-pill">OFFLINE · NO NETWORK</span>
  </div>

  <div class="content">

  <section class="tab active" id="tab-overview">
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
        <div class="cell"><span class="pill low">low</span><small>Track silently. Hygiene debt, not an incident.</small></div>
        <div class="cell"><span class="pill info">info</span><small>Context only. Useful in diffs and audits.</small></div>
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:14px">
      <div class="card">
        <h3>What this is</h3>
        <p style="margin:0 0 8px">An offline workbench for auditing quantum circuits and their supply chains: static threat analysis, ZX-calculus equivalence, sandboxed-execution verdicts, policy-as-code hygiene rules, and an adversarial robustness probe — with every number measured and every limit printed.</p>
        <ul class="limit" style="margin:0; padding-left: 18px">
          <li><b>No QPU, no device SDK, no cloud account, no network</b> — nothing in this workbench ever talks to hardware. Detection runs on files and fixtures, here.</li>
          <li>Detection evidence, never proofs of honesty; measured on fixture corpora, not in the field.</li>
        </ul>
      </div>
      <div class="card">
        <h3>Reading a finding</h3>
        <div class="find high"><h4><span class="pill high">high</span> T2.1 · Ancilla carries information about the computation</h4><p>Partial-trace analysis shows ancilla qubit(s) [1, 2] are NOT independent of the data qubits (ancilla reduced states differ by up to 1.00e+00 trace distance across 2 probe inputs). Information is leaking out of the computation. Confidence 0.85.</p></div>
        <p class="muted">Every finding links the gate indices that triggered it, a false-positive probability, and a concrete remediation. Treat each as a lead for a human auditor, not a verdict.</p>
      </div>
    </div>
  </section>

  <section class="tab" id="tab-scan">
    <div class="cols-2 grid">
      <div class="card">
        <h3>Target circuit</h3>
        <label class="small" for="scan-qasm">OpenQASM 2.0 / 3.0 source</label>
        <textarea id="scan-qasm" spellcheck="false" placeholder="OPENQASM 2.0;&#10;include &quot;qelib1.inc&quot;;&#10;qreg q[3];&#10;creg c[3];&#10;h q[0]; cx q[0],q[1]; measure q -> c;"></textarea>
        <div class="row">
          <button class="btn" onclick="runScan()">Scan circuit</button>
          <button class="btn secondary" onclick="loadExample()">Load ancilla-leakage example</button>
        </div>
      </div>
      <div class="card">
        <h3>Findings</h3>
        <div id="scan-out" class="muted">Results will appear here. Scanning is static + builtin signatures; dynamic execution is CLI-only (<span class="mono">qshield scan --full</span>).</div>
      </div>
    </div>
  </section>

  <section class="tab" id="tab-compare">
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
        <select id="cmp-engine"><option value="unitary">Exact unitary (≤12 qubits, proof)</option><option value="zx">ZX-calculus (decidable fragments, proof)</option></select>
        <div class="row"><button class="btn" onclick="runCompare()">Compare</button></div>
      </div>
      <div class="card"><h3>Equivalence report</h3><div id="cmp-out" class="muted">Structural diff, then exact verification.</div></div>
    </div>
  </section>

  <section class="tab" id="tab-robustness">
    <div class="card" style="margin-bottom:14px">
      <h3>Novel · Robustness Probe</h3>
      <p style="margin:0 0 6px" class="muted">Applies the five semantics-preserving attack classes from the evasion suite (camouflage, synonyms, rotation_split, dead_code, qubit_relabel) to <i>your</i> circuit, re-scans each variant, and tells you whether each finding survives. This is the question an auditor asks after a flag: <i>“and if the attacker camouflaged it?”</i></p>
      <label class="small" for="rb-qasm">Flagged circuit (.qasm)</label>
      <textarea id="rb-qasm" spellcheck="false" placeholder="Paste the circuit that already triggered a finding…"></textarea>
      <div class="row"><button class="btn" onclick="runRobustness()">Probe finding robustness</button></div>
    </div>
    <div class="card"><h3>Probe results</h3><div id="rb-out" class="muted">One card per base finding with per-attack survival.</div></div>
  </section>

  <section class="tab" id="tab-policy">
    <div class="cols-2 grid">
      <div class="card">
        <h3>Novel · Policy Studio</h3>
        <p class="muted" style="margin-top:0">Your own lint-style security policies as reviewable code. Toggle the builtin pack, then score it on the bundled 417-circuit fixture corpus — see what each policy catches and what it costs in false positives. Heuristic hygiene rules, not threat detectors.</p>
        <label class="small">Builtin pack (FOR YOUR ORG)</label>
        <div id="pl-list">loading…</div>
        <label class="small" for="pl-sample">Corpus size</label>
        <select id="pl-sample"><option value="60">Sample 60+60 (fast)</option><option value="0">Full corpus 202+215</option></select>
        <div class="row"><button class="btn" onclick="runPolicyEval()">Score on corpus</button></div>
      </div>
      <div class="card"><h3>Corpus scorecard</h3><div id="pl-out" class="muted">TPR = fraction of malicious fixtures flagged · FPR = fraction of clean fixtures flagged. Fixture-corpus rates — not field rates.</div></div>
    </div>
  </section>

  <section class="tab" id="tab-ai">
    <div class="card" style="border-color:rgba(255,216,77,.4); background:linear-gradient(180deg, rgba(255,216,77,.06), var(--panel))">
      <h3 style="color:#ffe27a">⚠ Opt-in cloud feature — read before use</h3>
      <p class="muted" style="margin:0">AI Triage sends a <b>summary of findings</b> (never the raw circuit source) to <b>Sarvam AI</b> (api.sarvam.ai) for explanation and prioritization. Output is <b>advisory — never a verdict</b> and can be wrong; a human auditor decides. Static analysis, comparison, Policy Studio and the rest of this page remain fully offline. Requires <span class="mono">SARVAM_API_KEY</span> on the machine running the Workbench server.</p>
    </div>
    <div class="cols-2 grid" style="margin-top:14px">
      <div class="card">
        <h3>AI Triage <span class="pill medium" style="vertical-align:2px">cloud · advisory</span></h3>
        <div id="ai-status" class="muted" style="margin-bottom:8px">checking AI configuration…</div>
        <label class="small" for="ai-qasm">Circuit under review</label>
        <textarea id="ai-qasm" spellcheck="false" placeholder="OPENQASM 2.0;&#10;include &quot;qelib1.inc&quot;;&#10;qreg q[3];&#10;cx q[0],q[2]; …"></textarea>
        <div class="row">
          <button class="btn" onclick="runAiTriage()">Explain with AI</button>
          <button class="btn secondary" onclick="loadAiExample()">Load ancilla-leakage example</button>
        </div>
        <p class="muted" style="margin-top:10px">Findings summary is sent; your circuit text stays here. Model: sarvam-105b-conversations.</p>
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
          <button class="btn" onclick="runTts()">Synthesize</button>
          <label class="muted" style="font-size:11.5px; display:flex; gap:6px; align-items:center"><input type="checkbox" id="tts-auto" checked /> auto-play</label>
        </div>
        <audio id="tts-audio" controls style="width:100%; margin-top:10px; display:none"></audio>
        <div id="tts-out" class="muted" style="margin-top:8px"></div>
      </div>
      <div class="card">
        <h3>Listen <span class="pill medium" style="vertical-align:2px">Saaras · cloud</span></h3>
        <p class="muted" style="margin-top:0">Record with your microphone, then transcribe. Audio leaves this machine only when you click <b>Transcribe</b> — it is sent to Sarvam AI and never stored by the Workbench.</p>
        <div class="row">
          <button class="btn" id="rec-btn" onclick="toggleRecord()">● Record</button>
          <button class="btn secondary" id="rec-stop" onclick="stopRecord()" disabled>■ Stop</button>
          <button class="btn secondary" id="rec-send" onclick="sendRecording()" disabled>Transcribe</button>
        </div>
        <div id="rec-status" class="muted" style="margin:10px 0 4px">idle — microphone permission is requested only when you press Record</div>
        <label class="small" for="rec-out">Transcript</label>
        <textarea id="rec-out" style="min-height:110px" placeholder="Transcript appears here…" readonly></textarea>
      </div>
    </div>

      <div class="card" style="margin-top:14px">
        <h3>Audit report in your language <span class="pill medium" style="vertical-align:2px">Sarvam-Translate · cloud</span></h3>
        <p class="muted" style="margin-top:0">A short factual report of the scan (counts, findings, remediation) — machine-translated with Sarvam-Translate (formal mode). Translations can err; the English original is shown alongside for review.</p>
        <label class="small" for="rep-lang">Target language</label>
        <select id="rep-lang"><option value="hi-IN">Hindi (hi-IN)</option><option value="mr-IN">Marathi (mr-IN)</option><option value="ta-IN">Tamil (ta-IN)</option><option value="te-IN">Telugu (te-IN)</option><option value="bn-IN">Bengali (bn-IN)</option><option value="gu-IN">Gujarati (gu-IN)</option><option value="kn-IN">Kannada (kn-IN)</option><option value="ml-IN">Malayalam (ml-IN)</option><option value="en-IN">English - India (en-IN)</option></select>
        <div class="row"><button class="btn" onclick="runLocalizedReport()">Render report (uses the circuit above)</button><button class="btn secondary" onclick="copyReport()">Copy translated</button></div>
        <div class="grid cols-2" style="margin-top:12px; gap:12px">
          <div><label class="small">English (source)</label><div id="rep-en" class="ai-reply" style="max-height:260px">Render to see the source report.</div></div>
          <div><label class="small">Translated</label><div id="rep-out" class="ai-reply" style="max-height:260px">अनुवाद यहाँ दिखाई देगा।</div></div>
        </div>
      </div>
  </section>

  <section class="tab" id="tab-about">
    <div class="card">
      <h3>About &amp; honest limits</h3>
      <ul class="limit" style="padding-left:18px; margin-top:4px">
        <li><b>Hardware:</b> none. Ever. Detection, verification and scoring all run offline on files. There is no QPU path in this workbench and no hardware in any acceptance criterion — by design, not by accident.</li>
        <li><b>Papers / publishing:</b> out of scope. This is a software product, measured and documented, not a publication vehicle.</li>
        <li><b>What it is:</b> evidence of known tampering classes and supply-chain hygiene — not a proof that a circuit or device is honest, and not runtime-blocking by default.</li>
        <li><b>Metrics:</b> fixture-corpus numbers (202 clean / 215 malicious). Field rates unknown. Twin-calibrated dynamic results are simulator-measured.</li>
        <li><b>Formal verdicts:</b> Equivalent/NotEquivalent only on decidable ZX fragments; otherwise honest <span class="mono">Unknown</span>.</li>
        <li><b>Community signatures:</b> ships empty by design — no invented threats, no silent updates.</li>
        <li><b>Network:</b> this page makes zero direct requests to the internet. Only the opt-in <b>AI</b> tab calls out — from the local Workbench server to api.sarvam.ai, on your click: AI Triage sends finding summaries, Speak/Listen send your text/audio respectively. Delete it and nothing else broke.</li>
      </ul>
      <p class="muted">QSHIELD Workbench · Apache-2.0</p>
    </div>
  </section>

  </div><!-- /content -->
  <footer>QSHIELD Workbench — offline quantum supply-chain security audit. Evidence, not proofs. Numbers measured on bundled fixtures.</footer>
</main>
</div><!-- /app -->

<script>
"use strict";
const TABS = [
  ["overview", "Overview", '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7.5" height="7.5" rx="1.5"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5"/></svg>'],
  ["scan", "Scan", '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.3" y2="16.3"/><line x1="8.2" y1="11" x2="13.8" y2="11"/></svg>'],
  ["compare", "Compare", '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="7" height="16" rx="1.5"/><rect x="14" y="4" width="7" height="16" rx="1.5"/><line x1="7" y1="9" x2="10" y2="9"/><line x1="17" y1="15" x2="20" y2="15"/></svg>'],
  ["robustness", "Robustness Probe", '<svg viewBox="0 0 24 24"><path d="M12 2 L20 6 V12 C20 17.5 16.5 21 12 22 C7.5 21 4 17.5 4 12 V6 Z"/><path d="M9.5 12.5 L11.5 14.5 L15 10.5"/></svg>'],
  ["policy", "Policy Studio", '<svg viewBox="0 0 24 24"><path d="M9 4 h6 a1 1 0 0 1 1 1 v2 h3 v14 a1 1 0 0 1 -1 1 h-12 a1 1 0 0 1 -1 -1 v-14 h3 v-2 a1 1 0 0 1 1 -1 Z"/><line x1="9.5" y1="12" x2="14.5" y2="12"/><line x1="9.5" y1="16" x2="14.5" y2="16"/></svg>'],
  ["ai", "AI Triage", '<svg viewBox="0 0 24 24"><path d="M12 3v3"/><path d="M12 18v3"/><path d="M3 12h3"/><path d="M18 12h3"/><path d="M5.6 5.6l2.1 2.1"/><path d="M16.3 16.3l2.1 2.1"/><path d="M5.6 18.4l2.1-2.1"/><path d="M16.3 7.7l2.1-2.1"/><circle cx="12" cy="12" r="4"/></svg>'],
  ["about", "About & limits", '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><line x1="12" y1="11" x2="12" y2="16"/><line x1="12" y1="7.5" x2="12.01" y2="7.5"/></svg>'],
];
const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const spin = (el) => { el.innerHTML = '<span class="spinner"></span> working…'; };
async function api(path, opts) {
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({ error: 'invalid server response' }));
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}
async function apiPost(path, body) {
  return api(path, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) });
}
function activate(id, label) {
  $$('.sidenav button').forEach(x => x.classList.toggle('active', x.dataset.tab === id));
  $$('section.tab').forEach(s => s.classList.toggle('active', s.id === 'tab-' + id));
  $('#crumb-current').textContent = label;
}
function buildTabs() {
  const nav = $('#sidenav');
  const lbl = document.createElement('div'); lbl.className = 'nav-label'; lbl.textContent = 'Workbench'; nav.appendChild(lbl);
  TABS.forEach(([id, label, icon], i) => {
    const b = document.createElement('button');
    b.innerHTML = icon + '<span>' + esc(label) + '</span>';
    b.dataset.tab = id; b.setAttribute('aria-label', label);
    if (i === 0) b.classList.add('active');
    b.onclick = () => activate(id, label);
    nav.appendChild(b);
  });
}
const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
function severitySummary(fs) {
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  fs.forEach(f => { const s = (f.severity || 'info'); if (counts[s] !== undefined) counts[s]++; });
  const total = fs.length || 1;
  const segs = Object.keys(sevOrder)
    .filter(k => counts[k] > 0)
    .map(k => `<i class="s-${k}" style="width:${(counts[k]/total*100).toFixed(2)}%" title="${counts[k]} ${k}"></i>`).join('');
  const chips = Object.keys(sevOrder)
    .filter(k => counts[k] > 0)
    .map(k => `<span class="pill ${k}">${counts[k]} ${k}</span>`).join(' ');
  return `<div class="sevbar" role="img" aria-label="Findings by severity">${segs}</div><div style="margin-bottom:12px">${chips}</div>`;
}
function findingRow(f) {
  const cls = esc(f.severity || 'info');
  const gates = (f.location && f.location.gate_indices && f.location.gate_indices.length)
    ? `<span class="mono">gates:[${f.location.gate_indices.slice(0, 10).join(',')}${f.location.gate_indices.length > 10 ? '…' : ''}]</span>`
    : ((f.location && f.location.qubit_indices && f.location.qubit_indices.length)
        ? `<span class="mono">qubits:[${f.location.qubit_indices.join(',')}]</span>` : '<span class="muted">—</span>');
  const conf = (typeof f.confidence === 'number')
    ? `<span class="conf">${f.confidence.toFixed(2)}${typeof f.false_positive_probability === 'number' ? `<small>FPP ${f.false_positive_probability.toFixed(2)}</small>` : ''}</span>`
    : '<span class="muted">—</span>';
  const fix = f.remediation ? `<div class="fix"><b>Remediate:</b> ${esc(f.remediation)}</div>` : '';
  return `<tr>
    <td><span class="pill ${cls}">${cls}</span></td>
    <td class="mono" style="white-space:nowrap">${esc(f.finding_id || '—')}</td>
    <td class="mono">${esc(f.threat_type || 'policy')}</td>
    <td><div style="font-weight:600">${esc(f.title || f.policy_name || 'finding')}</div>
        <div class="muted" style="margin-top:2px">${esc(f.description || f.message || '')}</div>${fix}</td>
    <td>${gates}</td>
    <td>${conf}</td>
  </tr>`;
}
async function loadExample() {
  const out = $('#scan-qasm');
  try { const d = await api('/api/example?name=ancilla_leakage'); out.value = d.qasm; }
  catch (e) { out.value = 'OPENQASM 2.0;\ninclude "qelib1.inc";\nqreg q[2];\ncreg c[2];\nh q[0];\nmeasure q -> c;'; }
}
async function runScan() {
  const out = $('#scan-out'); spin(out);
  try {
    const d = await apiPost('/api/scan', { qasm: $('#scan-qasm').value });
    const fs = (d.findings || []).slice().sort((a,b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
    const meta = `<div class="scan-meta"><span><b>${d.stats.gates}</b> gates</span><span><b>${d.stats.depth}</b> depth</span><span><b>${d.stats.qubits}</b> qubits</span><span><b>${fs.length}</b> finding(s)</span></div>`;
    if (!fs.length) {
      out.innerHTML = meta + '<div class="find info"><h4><span class="pill info">info</span>No findings</h4><p>Static + signature analysis found nothing in this circuit. Absence of evidence — not proof of cleanliness.</p></div>';
      return;
    }
    out.innerHTML = meta + severitySummary(fs) +
      '<div class="tablewrap"><table><thead><tr><th>Severity</th><th>ID</th><th>Threat</th><th>Finding</th><th>Gates</th><th>Conf</th></tr></thead><tbody>' +
      fs.map(findingRow).join('') + '</tbody></table></div>';
  } catch (e) { out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
async function runCompare() {
  const out = $('#cmp-out'); spin(out);
  try {
    const d = await apiPost('/api/compare', { a: $('#cmp-a').value, b: $('#cmp-b').value, engine: $('#cmp-engine').value });
    const rows = d.rows.map(r => `<tr><td>${esc(r.label)}</td><td class="mono">${esc(r.a)}</td><td class="mono">${esc(r.b)}</td><td>${r.match ? '✓' : '✗'}</td></tr>`).join('');
    const v = d.verdict === 'EQUIVALENT' ? 'ok' : d.verdict === 'DIFFERENT' ? 'bad' : 'unknown';
    out.innerHTML = `<div class="tablewrap"><table><thead><tr><th>Metric</th><th>Original</th><th>Suspicious</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      <div class="verdict ${v}">${esc(d.verdict)}</div>
      <p class="muted">${esc(d.detail || '')}</p>`;
  } catch (e) { out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
async function runRobustness() {
  const out = $('#rb-out'); spin(out);
  try {
    const d = await apiPost('/api/robustness', { qasm: $('#rb-qasm').value });
    if (!d.probes.length) { out.innerHTML = '<div class="find info"><h4><span class="pill info">info</span>Nothing to probe</h4><p>No base findings — run a scan first on the Scan tab.</p></div>'; return; }
    out.innerHTML = `<p class="muted">${d.base_findings} base finding(s) · ${d.variants_per_attack} variants per attack class · ${d.attacks.join(', ')}</p>` +
      d.probes.map(p => {
        const chips = Object.entries(p.per_attack).map(([name, v]) =>
          `<span class="pill ${v.survived === v.variants ? 'robust' : v.survived === 0 ? 'evaded' : 'fragile'}" title="${esc(name)}: ${v.survived}/${v.variants} variants preserved the finding">${esc(name)} ${v.survived}/${v.variants}</span>`).join(' ');
        return `<div class="find ${esc(p.robustness === 'evaded' ? 'high' : p.robustness === 'fragile' ? 'medium' : 'info')}"><h4><span class="pill ${esc(p.robustness)}">${esc(p.robustness)}</span>${esc(p.threat_type)} · ${esc(p.title)}</h4><p>survived ${p.survived}/${p.total} camouflaged variants</p><p>${chips}</p></div>`;
      }).join('') +
      `<ul class="limit" style="padding-left:18px">${d.limitations.map(l => `<li class="muted">${esc(l)}</li>`).join('')}</ul>`;
  } catch (e) { out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
async function loadPolicies() {
  try {
    const d = await api('/api/policies');
    $('#pl-list').innerHTML = d.policies.map(p => `
      <label style="display:flex; gap:10px; align-items:flex-start; padding:8px 10px; border:1px solid var(--line); border-radius:10px; margin:6px 0; cursor:pointer; background:var(--panel)">
        <input type="checkbox" class="pl-check" value="${esc(p.id)}" checked />
        <span><b class="mono" style="color:#fff">${esc(p.id)}</b> <span class="pill ${esc(p.severity)}">${esc(p.severity)}</span><br/>
        <span style="font-size:12.5px">${esc(p.name)}</span><br/>
        <span class="muted" style="font-size:11.5px">${esc(p.description)}</span></span>
      </label>`).join('');
  } catch (e) { $('#pl-list').innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
async function runPolicyEval() {
  const out = $('#pl-out'); spin(out);
  const ids = $$('.pl-check').filter(c => c.checked).map(c => c.value);
  const sample = Number($('#pl-sample').value) || null;
  try {
    const d = await apiPost('/api/policy-eval', { ids, sample: sample || undefined });
    const bar = (v, cls='') => `<div class="bar ${cls}"><i style="width:${Math.round(v*100)}%"></i></div>`;
    const rows = d.per_policy.map(r => `<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.name)}<br/><span class="pill ${esc(r.severity)}">${esc(r.severity)}</span></td><td>${r.tpr.toFixed(2)}</td><td>${bar(r.tpr)}</td><td>${r.fpr.toFixed(2)}</td><td>${bar(r.fpr, 'fpr')}</td></tr>`).join('');
    out.innerHTML = `<div class="tablewrap"><table><thead><tr><th>ID</th><th>Policy</th><th>TPR</th><th></th><th>FPR</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      <p style="margin:12px 0 2px"><b>Any-policy</b> (≥1 policy fires): TPR <b>${d.any_policy.tpr.toFixed(3)}</b> · FPR <b>${d.any_policy.fpr.toFixed(3)}</b></p>
      <p class="muted">Corpus: ${d.corpus.clean} clean + ${d.corpus.malicious} malicious (${d.corpus.skipped_unparseable} skipped unparseable). ${esc(d.note)}</p>`;
  } catch (e) { out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
async function aiStatus() {
  const el = $('#ai-status');
  try {
    const d = await api('/api/ai/status');
    el.innerHTML = d.configured
      ? '<span class="pill robust">AI configured</span> <span class="muted">Sarvam AI reachable on demand · finding summaries only</span>'
      : '<span class="pill fragile">AI not configured</span> <span class="muted">set SARVAM_API_KEY on the Workbench server (.env) — everything else works offline</span>';
  } catch (e) { el.textContent = 'AI status unavailable'; }
}
async function loadAiExample() {
  try { const d = await api('/api/example?name=ancilla_leakage'); $('#ai-qasm').value = d.qasm; } catch (e) { /* keep placeholder */ }
}
async function runAiTriage() {
  const out = $('#ai-out'); spin(out);
  try {
    const d = await apiPost('/api/ai/triage', { qasm: $('#ai-qasm').value });
    lastAiReply = d.reply;
    out.innerHTML = '<div class="ai-reply">' + esc(d.reply) + '</div>' +
      '<p class="muted" style="margin-top:10px; border-top:1px solid var(--line); padding-top:10px">' + esc(d.findings_sent) + ' finding(s) summary sent · ' + esc(d.disclaimer) + '</p>' +
      '<button class="btn secondary" onclick="speakLastReply()">🔊 Speak this reply</button>';
  } catch (e) { out.innerHTML = '<div class="err">' + esc(e.message) + '</div>'; }
}
let lastAiReply = '';
let recMedia = null, recChunks = [], recBlob = null;
async function speakText(text) {
  const outEl = $('#tts-out'); outEl.textContent = 'synthesizing…';
  try {
    const res = await fetch('/api/ai/speak', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: String(text).slice(0, 1500), language_code: $('#tts-lang').value }) });
    if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || ('HTTP ' + res.status)); }
    const url = URL.createObjectURL(await res.blob());
    const a = $('#tts-audio'); a.src = url; a.style.display = 'block';
    if ($('#tts-auto').checked) await a.play().catch(() => {});
    outEl.textContent = 'done — audio stays in your browser';
  } catch (e) { outEl.innerHTML = '<div class="err">' + esc(e.message) + '</div>'; }
}
function runTts() { const t = $('#tts-text').value.trim(); if (t) speakText(t); }
function speakLastReply() { if (!lastAiReply) return; $('#tts-text').value = lastAiReply.slice(0, 1500); speakText(lastAiReply); }
async function toggleRecord() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    recChunks = []; recBlob = null;
    recMedia = new MediaRecorder(stream);
    recMedia.ondataavailable = e => { if (e.data && e.data.size) recChunks.push(e.data); };
    recMedia.onstop = () => {
      recBlob = new Blob(recChunks, { type: recMedia.mimeType || 'audio/webm' });
      stream.getTracks().forEach(t => t.stop());
      $('#rec-stop').disabled = true; $('#rec-btn').disabled = false; $('#rec-send').disabled = false;
      $('#rec-status').textContent = 'recorded ' + Math.round(recBlob.size / 1024) + ' KB — click Transcribe to send to Sarvam AI';
    };
    recMedia.start();
    $('#rec-btn').disabled = true; $('#rec-stop').disabled = false; $('#rec-send').disabled = true;
    $('#rec-status').textContent = '● recording…';
  } catch (e) { $('#rec-status').innerHTML = '<span class="err">microphone unavailable: ' + esc(e.message) + '</span>'; }
}
function stopRecord() { if (recMedia && recMedia.state !== 'inactive') recMedia.stop(); }
function blobToB64(blob) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(String(r.result).split(',')[1]);
    r.onerror = rej;
    r.readAsDataURL(blob);
  });
}
async function sendRecording() {
  if (!recBlob) return;
  $('#rec-status').textContent = 'transcribing via Saaras…';
  try {
    const b64 = await blobToB64(recBlob);
    const d = await apiPost('/api/ai/listen', { audio_b64: b64, mode: 'transcribe' });
    $('#rec-out').value = d.transcript;
    $('#rec-status').textContent = 'done — audio was sent to Sarvam AI for transcription only';
  } catch (e) { $('#rec-status').innerHTML = '<div class="err">' + esc(e.message) + '</div>'; }
}
async function runLocalizedReport() {
  const en = $('#rep-en'), out = $('#rep-out');
  en.innerHTML = '<span class="spinner"></span> generating…';
  out.innerHTML = '<span class="spinner"></span> translating…';
  try {
    const d = await apiPost('/api/ai/report', { qasm: $('#ai-qasm').value, to: $('#rep-lang').value });
    en.textContent = d.english;
    out.textContent = d.translated;
  } catch (e) { en.innerHTML = '<div class="err">' + esc(e.message) + '</div>'; out.textContent = ''; }
}
async function copyReport() {
  const out = $('#rep-out').textContent || '';
  try { await navigator.clipboard.writeText(out); $('#rep-out').style.outline = '2px solid var(--acc)'; setTimeout(() => { $('#rep-out').style.outline = 'none'; }, 800); } catch (e) { /* clipboard unavailable */ }
}
buildTabs(); loadPolicies(); aiStatus();
</script>
</body>
</html>
"""
