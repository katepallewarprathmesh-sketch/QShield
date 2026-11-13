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
  --bg: #0a111c; --bg2: #0e1724; --panel: #111c2c; --panel2: #16233a;
  --line: #1f2f47; --text: #dbe7f5; --dim: #7d93ad; --acc: #39e6c0; --acc2: #7cc4ff;
  --amber: #ffc857; --red: #ff6b6b; --green: #38d39f; --blue: #5aa9ff;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: radial-gradient(1200px 600px at 15% -10%, #12203a 0%, var(--bg) 55%) no-repeat, var(--bg);
  color: var(--text); font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 22px 60px; }
header.top {
  border-bottom: 1px solid var(--line); backdrop-filter: blur(6px);
  background: linear-gradient(180deg, rgba(14,23,36,.92), rgba(14,23,36,.75));
  position: sticky; top: 0; z-index: 20;
}
.top-inner { max-width: 1180px; margin: 0 auto; padding: 12px 22px; display: flex; align-items: center; gap: 14px; }
.logo { display: flex; align-items: center; gap: 12px; }
.logo svg { width: 34px; height: 34px; }
.logo b { font-size: 17px; letter-spacing: .14em; }
.logo small { display: block; color: var(--dim); font-size: 10.5px; letter-spacing: .18em; text-transform: uppercase; }
.tag { margin-left: auto; font: 600 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--acc);
       border: 1px solid rgba(57,230,192,.35); background: rgba(57,230,192,.08); border-radius: 999px; padding: 7px 12px; letter-spacing: .08em; }
nav.tabs { display: flex; gap: 6px; flex-wrap: wrap; margin: 18px 0 22px; }
nav.tabs button {
  cursor: pointer; border: 1px solid var(--line); background: var(--panel); color: var(--dim);
  font: 600 12.5px system-ui; letter-spacing: .03em; padding: 9px 14px; border-radius: 10px; transition: .15s;
}
nav.tabs button:hover { color: var(--text); border-color: #2c405e; transform: translateY(-1px); }
nav.tabs button.active { color: #06231c; background: var(--acc); border-color: var(--acc); box-shadow: 0 4px 18px rgba(57,230,192,.25); }
section.tab { display: none; }
section.tab.active { display: block; animation: fade .25s ease; }
@keyframes fade { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
.grid { display: grid; gap: 14px; }
.cols-4 { grid-template-columns: repeat(4, 1fr); }
.cols-2 { grid-template-columns: 1fr 1fr; }
@media (max-width: 900px) { .cols-4 { grid-template-columns: repeat(2, 1fr); } .cols-2 { grid-template-columns: 1fr; } }
.card { background: linear-gradient(180deg, var(--panel2) 0%, var(--panel) 100%); border: 1px solid var(--line);
        border-radius: 14px; padding: 16px 18px; box-shadow: 0 10px 30px rgba(0,0,0,.25); }
.card h3 { margin: 0 0 10px; font-size: 13px; letter-spacing: .1em; text-transform: uppercase; color: var(--dim); }
.kpi b { font-size: 26px; color: #fff; display: block; letter-spacing: -.02em; }
.kpi span { color: var(--dim); font-size: 12px; }
textarea, select {
  width: 100%; background: #0b141f; color: var(--text); border: 1px solid var(--line); border-radius: 10px;
  font: 12.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; padding: 10px 12px; resize: vertical;
}
textarea { min-height: 170px; }
textarea:focus, select:focus { outline: none; border-color: var(--acc); box-shadow: 0 0 0 3px rgba(57,230,192,.12); }
label.small { font-size: 11px; color: var(--dim); letter-spacing: .08em; text-transform: uppercase; margin: 8px 0 6px; display:block; }
.btn { cursor: pointer; border: 0; border-radius: 10px; padding: 11px 18px; font: 700 13px system-ui; letter-spacing: .04em;
       color: #06231c; background: var(--acc); transition: .15s; }
.btn:hover { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(57,230,192,.35); }
.btn.secondary { background: transparent; color: var(--acc2); border: 1px solid #274162; }
.btn.secondary:hover { border-color: var(--acc2); box-shadow: none; }
.row { display: flex; gap: 10px; align-items: center; margin-top: 12px; flex-wrap: wrap; }
.pill { display: inline-block; padding: 3px 10px; border-radius: 999px; font: 700 10px/1.6 ui-monospace; letter-spacing: .08em; text-transform: uppercase; }
.pill.critical { background: #3b1215; color: #ff8f8f; border: 1px solid #6b2027; }
.pill.high { background: #3a2310; color: #ffbf7a; border: 1px solid #6b4a1c; }
.pill.medium { background: #36300f; color: #ffe27a; border: 1px solid #6b621f; }
.pill.low { background: #12233b; color: #8fc2ff; border: 1px solid #1f406b; }
.pill.info { background: #1b2430; color: #a9b8c9; border: 1px solid #2b3848; }
.pill.robust { background: #0f2e24; color: #5ff0bd; border: 1px solid #1e5c44; }
.pill.fragile { background: #36300f; color: #ffe27a; border: 1px solid #6b621f; }
.pill.evaded { background: #3b1215; color: #ff8f8f; border: 1px solid #6b2027; }
.find { border: 1px solid var(--line); border-left: 3px solid var(--amber); background: #101a29; border-radius: 10px; padding: 10px 14px; margin: 10px 0; }
.find.critical { border-left-color: var(--red); } .find.high { border-left-color: var(--amber); } .find.medium,.find.low,.find.info { border-left-color: var(--blue); }
.find h4 { margin: 0 0 4px; font-size: 13px; display: flex; gap: 10px; align-items: center; }
.find p { margin: 4px 0 0; color: var(--dim); font-size: 12.5px; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.verdict { font-size: 30px; font-weight: 800; letter-spacing: .02em; padding: 14px 18px; border-radius: 12px; text-align: center; margin: 14px 0 6px; }
.verdict.ok { background: rgba(56,211,159,.1); color: var(--green); border: 1px solid rgba(56,211,159,.35); }
.verdict.bad { background: rgba(255,107,107,.1); color: var(--red); border: 1px solid rgba(255,107,107,.35); }
.verdict.unknown { background: rgba(255,200,87,.1); color: var(--amber); border: 1px solid rgba(255,200,87,.35); }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); }
th { color: var(--dim); font-size: 11px; letter-spacing: .1em; text-transform: uppercase; }
.bar { height: 8px; border-radius: 99px; background: #1c2a3f; overflow: hidden; min-width: 110px; }
.bar > i { display: block; height: 100%; background: linear-gradient(90deg, #1f8a70, var(--acc)); }
.bar.fpr > i { background: linear-gradient(90deg, #8a2a2a, var(--red)); }
.muted { color: var(--dim); font-size: 12px; }
.limit li { margin: 4px 0; color: #b9c8d8; font-size: 13px; }
.err { color: #ff9d9d; background: #2a1214; border: 1px solid #57201f; border-radius: 10px; padding: 10px 12px; font-size: 13px; white-space: pre-wrap; }
footer { border-top: 1px solid var(--line); margin-top: 34px; padding: 16px 0; color: var(--dim); font-size: 11.5px; text-align: center; }
.spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid #2c405e; border-top-color: var(--acc); border-radius: 50%; animation: spin .7s linear infinite; vertical-align: -2px; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<header class="top"><div class="top-inner">
  <div class="logo">
    <svg viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <path d="M24 2 L44 10 V22 C44 36 36 45 24 46 C12 45 4 36 4 22 V10 Z" fill="#0f2b23" stroke="#39e6c0" stroke-width="2.4" stroke-linejoin="round"/>
      <path d="M15 24.5 L21.5 31 L34 17.5" stroke="#39e6c0" stroke-width="3.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div><b>QSHIELD</b><small>Quantum Supply-Chain Security Workbench</small></div>
  </div>
  <span class="tag">SOFTWARE-ONLY · OFFLINE · NO HARDWARE</span>
</div></header>

<div class="wrap">
  <nav class="tabs" id="tabs"></nav>

  <section class="tab" id="tab-overview">
    <div class="grid cols-4">
      <div class="card kpi"><h3>Fixture corpus</h3><b>417</b><span>202 clean · 215 malicious QASM</span></div>
      <div class="card kpi"><h3>Detection (twin-cal.)</h3><b>0.958</b><span>TPR @ δ≥0.1 rigging · FPR 0.008</span></div>
      <div class="card kpi"><h3>Runtime proxy p95</h3><b>1.5 ms</b><span>measured intercept overhead</span></div>
      <div class="card kpi"><h3>Static scale</h3><b>~2 s</b><span>1000-qubit scan · ~75 MB peak</span></div>
    </div>
    <div class="card" style="margin-top:14px">
      <h3>What this is</h3>
      <p style="margin:0 0 8px">An offline workbench for auditing quantum circuits and their supply chains: static threat analysis, ZX-calculus equivalence, sandboxed-execution verdicts, policy-as-code hygiene rules, and an adversarial robustness probe — with every number measured and every limit printed.</p>
      <ul class="limit" style="margin:0; padding-left: 18px">
        <li><b>No QPU, no device SDK, no cloud account, no network</b> — nothing in this workbench ever talks to hardware. Detection runs on files and fixtures, here.</li>
        <li>Detection evidence, never proofs of honesty; measured on fixture corpora, not in the field.</li>
      </ul>
    </div>
    <div class="card" style="margin-top:14px">
      <h3>Reading a finding</h3>
      <div class="find high"><h4><span class="pill high">high</span> T2.1 · Ancilla entangled with output</h4><p>An ancilla qubit ends the circuit correlated with a primary output qubit. Typical exfiltration-staging shape. Confidence 0.85. Measured on the fixture corpus — evidence, not proof.</p></div>
      <p class="muted">Severity → critical/high: block in CI · medium: review · low/info: track. Every finding links the gate indices that triggered it.</p>
    </div>
  </section>

  <section class="tab" id="tab-scan">
    <div class="cols-2 grid">
      <div class="card">
        <label class="small" for="scan-qasm">OpenQASM 2.0 / 3.0 source</label>
        <textarea id="scan-qasm" spellcheck="false" placeholder="OPENQASM 2.0;&#10;include \"qelib1.inc\";&#10;qreg q[3];&#10;creg c[3];&#10;h q[0]; cx q[0],q[1]; measure q -> c;"></textarea>
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

  <section class="tab" id="tab-about">
    <div class="card">
      <h3>About & honest limits</h3>
      <ul class="limit" style="padding-left:18px; margin-top:4px">
        <li><b>Hardware:</b> none. Ever. Detection, verification and scoring all run offline on files. There is no QPU path in this workbench and no hardware in any acceptance criterion — by design, not by accident.</li>
        <li><b>Papers / publishing:</b> out of scope. This is a software product, measured and documented, not a publication vehicle.</li>
        <li><b>What it is:</b> evidence of known tampering classes and supply-chain hygiene — not a proof that a circuit or device is honest, and not runtime-blocking by default.</li>
        <li><b>Metrics:</b> fixture-corpus numbers (202 clean / 215 malicious). Field rates unknown. Twin-calibrated dynamic results are simulator-measured.</li>
        <li><b>Formal verdicts:</b> Equivalent/NotEquivalent only on decidable ZX fragments; otherwise honest <span class="mono">Unknown</span>.</li>
        <li><b>Community signatures:</b> ships empty by design — no invented threats, no silent updates.</li>
        <li><b>Network:</b> this page makes zero requests to the internet. Delete the file and nothing else broke.</li>
      </ul>
      <p class="muted">QSHIELD Workbench · Apache-2.0 · spec docs/spec/QSHIELD.md (v2.0 software-only scope) · limits: docs/limitations.md</p>
    </div>
  </section>

  <footer>QSHIELD Workbench — offline quantum supply-chain security audit. Evidence, not proofs. Numbers measured on bundled fixtures.</footer>
</div>

<script>
"use strict";
const TABS = [["overview","Overview"],["scan","Scan"],["compare","Compare"],["robustness","Robustness Probe"],["policy","Policy Studio"],["about","About & limits"]];
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
function buildTabs() {
  const nav = $('#tabs');
  TABS.forEach(([id, label], i) => {
    const b = document.createElement('button');
    b.textContent = label; b.dataset.tab = id;
    if (i === 0) b.classList.add('active');
    b.onclick = () => {
      $$('.tabs button').forEach(x => x.classList.toggle('active', x === b));
      $$('section.tab').forEach(s => s.classList.toggle('active', s.id === 'tab-' + id));
    };
    nav.appendChild(b);
  });
}
const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
function findingCard(f) {
  const cls = esc(f.severity || 'info');
  const loc = (f.location && f.location.gate_indices && f.location.gate_indices.length)
    ? `<p class="mono muted">gates: [${f.location.gate_indices.slice(0, 12).join(', ')}${f.location.gate_indices.length > 12 ? '…' : ''}]</p>` : '';
  return `<div class="find ${cls}"><h4><span class="pill ${cls}">${cls}</span>${esc(f.threat_type || 'policy')} · ${esc(f.title || f.policy_name || 'finding')}</h4><p>${esc(f.description || f.message || '')}</p>${loc}</div>`;
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
    out.innerHTML = `<p class="muted mono">${d.stats.gates} gates · depth ${d.stats.depth} · ${d.stats.qubits} qubits · ${fs.length} finding(s)</p>` +
      (fs.length ? fs.map(findingCard).join('') : '<div class="find info"><h4><span class="pill info">info</span>No findings</h4><p>Static + signature analysis found nothing in this circuit. Absence of evidence — not proof of cleanliness.</p></div>');
  } catch (e) { out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
async function runCompare() {
  const out = $('#cmp-out'); spin(out);
  try {
    const d = await apiPost('/api/compare', { a: $('#cmp-a').value, b: $('#cmp-b').value, engine: $('#cmp-engine').value });
    const rows = d.rows.map(r => `<tr><td>${esc(r.label)}</td><td class="mono">${esc(r.a)}</td><td class="mono">${esc(r.b)}</td><td>${r.match ? '✓' : '✗'}</td></tr>`).join('');
    const v = d.verdict === 'EQUIVALENT' ? 'ok' : d.verdict === 'DIFFERENT' ? 'bad' : 'unknown';
    out.innerHTML = `<table><thead><tr><th>Metric</th><th>Original</th><th>Suspicious</th><th></th></tr></thead><tbody>${rows}</tbody></table>
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
      <label style="display:flex; gap:10px; align-items:flex-start; padding:8px 10px; border:1px solid var(--line); border-radius:10px; margin:6px 0; cursor:pointer">
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
    out.innerHTML = `<table><thead><tr><th>ID</th><th>Policy</th><th>TPR</th><th></th><th>FPR</th><th></th></tr></thead><tbody>${rows}</tbody></table>
      <p style="margin:12px 0 2px"><b>Any-policy</b> (≥1 policy fires): TPR <b>${d.any_policy.tpr.toFixed(3)}</b> · FPR <b>${d.any_policy.fpr.toFixed(3)}</b></p>
      <p class="muted">Corpus: ${d.corpus.clean} clean + ${d.corpus.malicious} malicious (${d.corpus.skipped_unparseable} skipped unparseable). ${esc(d.note)}</p>`;
  } catch (e) { out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
buildTabs(); loadPolicies();
</script>
</body>
</html>
"""
