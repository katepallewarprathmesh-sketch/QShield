/* QSHIELD Workbench browser behavior (TypeScript source). */
"use strict";
const TABS = [
    ["overview", "Overview", '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7.5" height="7.5" rx="1.5"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5"/></svg>'],
    ["scan", "Scan", '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.3" y2="16.3"/><line x1="8.2" y1="11" x2="13.8" y2="11"/></svg>'],
    ["compare", "Compare", '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="7" height="16" rx="1.5"/><rect x="14" y="4" width="7" height="16" rx="1.5"/><line x1="7" y1="9" x2="10" y2="9"/><line x1="17" y1="15" x2="20" y2="15"/></svg>'],
    ["robustness", "Robustness Probe", '<svg viewBox="0 0 24 24"><path d="M12 2 L20 6 V12 C20 17.5 16.5 21 12 22 C7.5 21 4 17.5 4 12 V6 Z"/><path d="M9.5 12.5 L11.5 14.5 L15 10.5"/></svg>'],
    ["policy", "Policy Studio", '<svg viewBox="0 0 24 24"><path d="M9 4 h6 a1 1 0 0 1 1 1 v2 h3 v14 a1 1 0 0 1 -1 1 h-12 a1 1 0 0 1 -1 -1 v-14 h3 v-2 a1 1 0 0 1 1 -1 Z"/><line x1="9.5" y1="12" x2="14.5" y2="12"/><line x1="9.5" y1="16" x2="14.5" y2="16"/></svg>'],
    ["ai", "AI Triage", '<svg viewBox="0 0 24 24"><path d="M12 3v3"/><path d="M12 18v3"/><path d="M3 12h3"/><path d="M18 12h3"/><path d="M5.6 5.6l2.1 2.1"/><path d="M16.3 16.3l2.1 2.1"/><path d="M5.6 18.4l2.1-2.1"/><path d="M16.3 7.7l2.1-2.1"/><circle cx="12" cy="12" r="4"/></svg>'],
    ["about", "About", '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><line x1="12" y1="11" x2="12" y2="16"/><line x1="12" y1="7.5" x2="12.01" y2="7.5"/></svg>'],
];
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const spin = (el) => { el.innerHTML = '<span class="spinner"></span> working…'; };
async function api(path, opts = {}) {
    const res = await fetch(path, opts);
    const data = await res.json().catch(() => ({ error: 'invalid server response' }));
    if (!res.ok)
        throw new Error(data.error || ('HTTP ' + res.status));
    return data;
}
async function apiPost(path, body) {
    return api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}
function activate(id, label) {
    $$('.sidenav button').forEach(x => {
        const active = x.dataset.tab === id;
        x.classList.toggle('active', active);
        x.setAttribute('aria-selected', String(active));
        x.tabIndex = active ? 0 : -1;
    });
    $$('section.tab').forEach(s => {
        const active = s.id === 'tab-' + id;
        s.classList.toggle('active', active);
        s.setAttribute('aria-hidden', String(!active));
    });
    $('#crumb-current').textContent = label;
    autoProbeOnOpen(id);
}
/* The Robustness tab runs against the circuit already scanned, without asking the
   user to paste it again. It only fires when a circuit is available and the user
   has not already produced a result for that exact circuit. */
let probedSignature = '';
let probeInFlight = false;
function circuitSignature(qasm) {
    let hash = 5381;
    for (let i = 0; i < qasm.length; i++)
        hash = ((hash << 5) + hash + qasm.charCodeAt(i)) | 0;
    return `${qasm.length}:${hash}`;
}
function autoProbeOnOpen(id) {
    if (id !== 'robustness')
        return;
    const source = circuitFor('robustness');
    if (!source)
        return;
    const signature = circuitSignature(source);
    if (probeInFlight || signature === probedSignature)
        return;
    probeInFlight = true;
    probedSignature = signature;
    runRobustness().finally(() => { probeInFlight = false; });
}
function buildTabs() {
    const nav = $('#sidenav');
    TABS.forEach(([id, label, icon], i) => {
        const b = document.createElement('button');
        b.innerHTML = icon + '<span>' + esc(label) + '</span>';
        b.id = 'tab-button-' + id;
        b.dataset.tab = id;
        b.setAttribute('role', 'tab');
        b.setAttribute('aria-label', label);
        b.setAttribute('aria-controls', 'tab-' + id);
        b.setAttribute('aria-selected', String(i === 0));
        b.tabIndex = i === 0 ? 0 : -1;
        if (i === 0)
            b.classList.add('active');
        b.addEventListener('click', () => activate(id, label));
        b.addEventListener('keydown', event => {
            const current = TABS.findIndex(([tab]) => tab === id);
            const next = event.key === 'ArrowRight' ? (current + 1) % TABS.length
                : event.key === 'ArrowLeft' ? (current + TABS.length - 1) % TABS.length
                    : event.key === 'Home' ? 0 : event.key === 'End' ? TABS.length - 1 : -1;
            if (next < 0)
                return;
            event.preventDefault();
            const [nextId, nextLabel] = TABS[next];
            activate(nextId, nextLabel);
            $('#tab-button-' + nextId).focus();
        });
        nav.appendChild(b);
    });
}
/* The circuit last successfully scanned. The Robustness and AI tabs read this
   so a user who already loaded and scanned a file does not paste it twice. */
let lastLoadedName = '';
let lastScannedQasm = '';
let lastScannedName = '';
const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
function severitySummary(fs) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    fs.forEach(f => { const s = (f.severity || 'info'); if (counts[s] !== undefined)
        counts[s]++; });
    const total = fs.length || 1;
    const segs = Object.keys(sevOrder)
        .filter(k => counts[k] > 0)
        .map(k => `<i class="s-${k}" style="width:${(counts[k] / total * 100).toFixed(2)}%" title="${counts[k]} ${k}"></i>`).join('');
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
    try {
        const d = await api('/api/example?name=ancilla_leakage');
        out.value = d.qasm;
    }
    catch (e) {
        out.value = 'OPENQASM 2.0;\ninclude "qelib1.inc";\nqreg q[2];\ncreg c[2];\nh q[0];\nmeasure q -> c;';
    }
}
const MAX_LOCAL_QASM_BYTES = 1024 * 1024;
async function loadCircuitFile(file) {
    const status = $('#scan-file-status');
    try {
        const extension = file.name.toLowerCase().split('.').pop();
        if (!['qasm', 'qasm2', 'qasm3'].includes(extension)) {
            throw new Error('Choose an OpenQASM file (.qasm, .qasm2, or .qasm3).');
        }
        if (file.size > MAX_LOCAL_QASM_BYTES) {
            throw new Error('File exceeds the 1 MiB local-import limit.');
        }
        let source;
        try {
            const bytes = await file.arrayBuffer();
            source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        }
        catch {
            throw new Error('File must contain valid UTF-8 text.');
        }
        if (!source.trim())
            throw new Error('The selected file is empty.');
        $('#scan-qasm').value = source;
        lastLoadedName = file.name;
        status.textContent = `${file.name} loaded (${file.size.toLocaleString()} bytes). It stays in this browser until you run Scan.`;
    }
    catch (e) {
        status.textContent = `Could not load file: ${e.message || e}`;
    }
}
function currentCircuit() {
    /* A tab the user edited by hand wins for that tab; otherwise use the last scan. */
    const rb = $('#rb-qasm')?.value?.trim() || '';
    const ai = $('#ai-qasm')?.value?.trim() || '';
    const scan = $('#scan-qasm')?.value?.trim() || '';
    const rbEdited = rb && rb !== (autoFilled['rb-qasm'] || '').trim();
    const aiEdited = ai && ai !== (autoFilled['ai-qasm'] || '').trim();
    if (rbEdited)
        return rb;
    if (aiEdited)
        return ai;
    if (scan)
        return scan;
    return rb || ai;
}
function circuitFor(tab) {
    /* Per-tab resolution: an edited box wins, else the last scanned circuit. */
    const id = tab === 'robustness' ? 'rb-qasm' : 'ai-qasm';
    const own = $('#' + id)?.value?.trim() || '';
    const auto = (autoFilled[id] || '').trim();
    if (own && own !== auto)
        return own;
    return lastScannedQasm || own;
}
/* Tabs that hold their own copy of the circuit. A tab keeps user-edited text and
   only accepts the scanned circuit while it still holds the previous auto-fill. */
const autoFilled = {};
function setAutoFill(id, qasm) {
    const el = $('#' + id);
    if (!el)
        return;
    const current = el.value.trim();
    const previousAuto = autoFilled[id] || '';
    if (current && current !== previousAuto.trim())
        return; // user typed here: leave it
    el.value = qasm;
    autoFilled[id] = qasm;
}
/* Push the scanned circuit into the other tabs that operate on it. */
function shareCircuit(qasm, name) {
    lastScannedQasm = qasm;
    lastScannedName = name;
    setAutoFill('rb-qasm', qasm);
    setAutoFill('ai-qasm', qasm);
    const rbNote = $('#rb-source');
    if (rbNote)
        rbNote.textContent = name
            ? `Using the circuit from your last scan (${name}).`
            : 'Using the circuit from your last scan.';
    const aiNote = $('#ai-source');
    if (aiNote)
        aiNote.textContent = name
            ? `Using the circuit from your last scan (${name}).`
            : 'Using the circuit from your last scan.';
}
async function runScan() {
    const out = $('#scan-out');
    spin(out);
    try {
        const source = $('#scan-qasm').value;
        const d = await apiPost('/api/scan', { qasm: source });
        const fs = (d.findings || []).slice().sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
        const meta = `<div class="scan-meta"><span><b>${d.stats.gates}</b> gates</span><span><b>${d.stats.depth}</b> depth</span><span><b>${d.stats.qubits}</b> qubits</span><span><b>${fs.length}</b> finding(s)</span></div>`;
        const warnings = (d.warnings || []).map(w => `<div class="find medium"><h4><span class="pill medium">review</span>Analysis warning</h4><p>${esc(w)}</p></div>`).join('');
        const warningPanel = warnings ? `<div class="analysis-warnings"><h4>Review before interpreting results</h4>${warnings}</div>` : '';
        if (!fs.length) {
            out.innerHTML = meta + warningPanel + '<div class="find info"><h4><span class="pill info">info</span>No findings</h4><p>Static + signature analysis found nothing in this circuit. Absence of evidence — not proof of cleanliness.</p></div>';
            shareCircuit(source, lastLoadedName);
            return;
        }
        out.innerHTML = meta + warningPanel + severitySummary(fs) +
            '<div class="finding-tools"><input id="scan-search" type="search" aria-label="Search findings" placeholder="Search title, ID, threat, or remediation"><select id="scan-severity" aria-label="Filter findings by severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select></div>' +
            '<p id="scan-match-count" class="finding-count" role="status" aria-live="polite"></p><div id="scan-table"></div>';
        const renderFiltered = () => {
            const query = $('#scan-search').value.trim().toLowerCase();
            const severity = $('#scan-severity').value;
            const visible = fs.filter(f => {
                if (severity && f.severity !== severity)
                    return false;
                const searchable = [f.finding_id, f.threat_type, f.title, f.policy_name, f.description, f.message, f.remediation]
                    .filter(Boolean).join(' ').toLowerCase();
                return !query || searchable.includes(query);
            });
            $('#scan-match-count').textContent = `Showing ${visible.length} of ${fs.length} finding(s).`;
            $('#scan-table').innerHTML = visible.length
                ? '<div class="tablewrap"><table><thead><tr><th>Severity</th><th>ID</th><th>Threat</th><th>Finding</th><th>Gates</th><th>Conf</th></tr></thead><tbody>' +
                    visible.map(findingRow).join('') + '</tbody></table></div>'
                : '<div class="find info"><h4><span class="pill info">info</span>No matching findings</h4><p>Adjust or clear the search and severity filters.</p></div>';
        };
        $('#scan-search').addEventListener('input', renderFiltered);
        $('#scan-severity').addEventListener('change', renderFiltered);
        renderFiltered();
        shareCircuit(source, lastLoadedName);
    }
    catch (e) {
        out.innerHTML = `<div class="err">${esc(e.message)}</div>`;
    }
}
async function runCompare() {
    const out = $('#cmp-out');
    spin(out);
    try {
        const d = await apiPost('/api/compare', { a: $('#cmp-a').value, b: $('#cmp-b').value, engine: $('#cmp-engine').value });
        const rows = d.rows.map(r => `<tr><td>${esc(r.label)}</td><td class="mono">${esc(r.a)}</td><td class="mono">${esc(r.b)}</td><td>${r.match ? '✓' : '✗'}</td></tr>`).join('');
        const v = d.verdict === 'EQUIVALENT' ? 'ok' : d.verdict === 'DIFFERENT' ? 'bad' : 'unknown';
        out.innerHTML = `<div class="tablewrap"><table><thead><tr><th>Metric</th><th>Original</th><th>Suspicious</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      <div class="verdict ${v}">${esc(d.verdict)}</div>
      <p class="muted">${esc(d.detail || '')}</p>`;
    }
    catch (e) {
        out.innerHTML = `<div class="err">${esc(e.message)}</div>`;
    }
}
async function runRobustness() {
    const out = $('#rb-out');
    spin(out);
    try {
        const source = currentCircuit();
        if (!source) {
            out.innerHTML = '<div class="find info"><h4><span class="pill info">info</span>Nothing to probe yet</h4><p>Load or paste a circuit on the Scan tab, then run a scan. This tab picks it up automatically.</p></div>';
            return;
        }
        const d = await apiPost('/api/robustness', { qasm: source });
        if (!d.probes.length) {
            out.innerHTML = '<div class="find info"><h4><span class="pill info">info</span>Nothing to probe</h4><p>This circuit produced no base findings to probe for robustness.</p></div>';
            return;
        }
        out.innerHTML = `<p class="muted">${d.base_findings} base finding(s) · ${d.variants_per_attack} variants per attack class · ${d.attacks.join(', ')}</p>` +
            d.probes.map(p => {
                const chips = Object.entries(p.per_attack).map(([name, v]) => `<span class="pill ${v.survived === v.variants ? 'robust' : v.survived === 0 ? 'evaded' : 'fragile'}" title="${esc(name)}: ${v.survived}/${v.variants} variants preserved the finding">${esc(name)} ${v.survived}/${v.variants}</span>`).join(' ');
                return `<div class="find ${esc(p.robustness === 'evaded' ? 'high' : p.robustness === 'fragile' ? 'medium' : 'info')}"><h4><span class="pill ${esc(p.robustness)}">${esc(p.robustness)}</span>${esc(p.threat_type)} · ${esc(p.title)}</h4><p>survived ${p.survived}/${p.total} camouflaged variants</p><p>${chips}</p></div>`;
            }).join('') +
            `<ul class="limit" style="padding-left:18px">${d.limitations.map(l => `<li class="muted">${esc(l)}</li>`).join('')}</ul>`;
    }
    catch (e) {
        out.innerHTML = `<div class="err">${esc(e.message)}</div>`;
    }
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
        if (d.corpus_available) {
            $('#pl-corpus-status').textContent = 'Bundled fixture corpus available: 202 clean + 215 malicious circuits.';
            $('#pl-sample').disabled = false;
            $('#pl-run').disabled = false;
        }
        else {
            $('#pl-corpus-status').innerHTML = 'Scoring unavailable: the fixture corpus could not be found in this installation. Reinstall QSHIELD or set <code>QSHIELD_FIXTURES_DIR</code> to a directory containing <code>clean_circuits/</code> and <code>malicious_circuits/</code>.';
        }
    }
    catch (e) {
        $('#pl-list').innerHTML = `<div class="err">${esc(e.message)}</div>`;
    }
}
async function runPolicyEval() {
    const out = $('#pl-out');
    spin(out);
    const ids = $$('.pl-check').filter(c => c.checked).map(c => c.value);
    const sample = Number($('#pl-sample').value) || null;
    try {
        const d = await apiPost('/api/policy-eval', { ids, sample: sample || undefined });
        const bar = (v, cls = '') => `<div class="bar ${cls}"><i style="width:${Math.round(v * 100)}%"></i></div>`;
        const rows = d.per_policy.map(r => `<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.name)}<br/><span class="pill ${esc(r.severity)}">${esc(r.severity)}</span></td><td>${r.tpr.toFixed(2)}</td><td>${bar(r.tpr)}</td><td>${r.fpr.toFixed(2)}</td><td>${bar(r.fpr, 'fpr')}</td></tr>`).join('');
        out.innerHTML = `<div class="tablewrap"><table><thead><tr><th>ID</th><th>Policy</th><th>TPR</th><th></th><th>FPR</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      <p style="margin:12px 0 2px"><b>Any-policy</b> (≥1 policy fires): TPR <b>${d.any_policy.tpr.toFixed(3)}</b> · FPR <b>${d.any_policy.fpr.toFixed(3)}</b></p>
      <p class="muted">Corpus: ${d.corpus.clean} clean + ${d.corpus.malicious} malicious (${d.corpus.skipped_unparseable} skipped unparseable). ${esc(d.note)}</p>`;
    }
    catch (e) {
        out.innerHTML = `<div class="err">${esc(e.message)}</div>`;
    }
}
async function aiStatus() {
    const el = $('#ai-status');
    if (!el)
        return;
    try {
        const d = await api('/api/ai/status');
        if (d.configured) {
            el.innerHTML = '<span class="pill robust">AI ready</span> <span class="muted">Sarvam AI is configured on this Workbench server. Triage, translation, and voice actions run live.</span>';
        }
        else if (d.key_present === false) {
            el.innerHTML = '<span class="pill fragile">AI key missing</span> <span class="muted">'
                + esc(d.reason || 'SARVAM_API_KEY is not set on the Workbench server.')
                + ' ' + esc(d.hint || '') + '</span>';
        }
        else if (d.key_present && d.sdk_installed === false) {
            el.innerHTML = '<span class="pill fragile">AI SDK missing</span> <span class="muted">'
                + esc(d.reason || "The 'sarvamai' package is not installed.")
                + ' ' + esc(d.hint || '') + '</span>';
        }
        else {
            el.innerHTML = '<span class="pill fragile">AI unavailable</span> <span class="muted">'
                + esc(d.reason || 'AI actions are unavailable on this deployment.') + '</span>';
        }
    }
    catch (e) {
        el.innerHTML = '<span class="pill fragile">AI status unavailable</span> <span class="muted">The Workbench server did not answer the status check.</span>';
    }
}
async function loadAiExample() {
    try {
        const d = await api('/api/example?name=ancilla_leakage');
        $('#ai-qasm').value = d.qasm;
    }
    catch (e) { /* keep placeholder */ }
}
async function runAiTriage() {
    const out = $('#ai-out');
    spin(out);
    try {
        const source = circuitFor('ai') || $('#ai-qasm').value;
        if (!source.trim()) {
            out.innerHTML = '<div class="find info"><h4><span class="pill info">info</span>No circuit yet</h4><p>Load or paste a circuit on the Scan tab, then run a scan. This tab picks it up automatically.</p></div>';
            return;
        }
        const d = await apiPost('/api/ai/triage', { qasm: source });
        lastAiReply = d.reply;
        out.innerHTML = '<div class="ai-reply">' + esc(d.reply) + '</div>' +
            '<p class="muted" style="margin-top:10px; border-top:1px solid var(--line); padding-top:10px">' + esc(d.disclaimer) + '</p>' +
            '<button class="btn secondary" data-action="speak-reply">🔊 Speak this reply</button>';
    }
    catch (e) {
        out.innerHTML = '<div class="err">' + esc(e.message) + '</div>';
    }
}
let lastAiReply = '';
let recMedia = null, recChunks = [], recBlob = null;
async function speakText(text) {
    const outEl = $('#tts-out');
    outEl.textContent = 'synthesizing…';
    try {
        const res = await fetch('/api/ai/speak', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: String(text).slice(0, 1500), language_code: $('#tts-lang').value }) });
        if (!res.ok) {
            const d = await res.json().catch(() => ({}));
            throw new Error(d.error || ('HTTP ' + res.status));
        }
        const url = URL.createObjectURL(await res.blob());
        const a = $('#tts-audio');
        a.src = url;
        a.style.display = 'block';
        if ($('#tts-auto').checked)
            await a.play().catch(() => { });
        outEl.textContent = 'done — audio stays in your browser';
    }
    catch (e) {
        outEl.innerHTML = '<div class="err">' + esc(e.message) + '</div>';
    }
}
async function runTts() { const t = $('#tts-text').value.trim(); if (t)
    await speakText(t); }
function speakLastReply() { if (!lastAiReply)
    return; $('#tts-text').value = lastAiReply.slice(0, 1500); speakText(lastAiReply); }
async function toggleRecord() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        recChunks = [];
        recBlob = null;
        recMedia = new MediaRecorder(stream);
        recMedia.ondataavailable = e => { if (e.data && e.data.size)
            recChunks.push(e.data); };
        recMedia.onstop = () => {
            recBlob = new Blob(recChunks, { type: recMedia.mimeType || 'audio/webm' });
            stream.getTracks().forEach(t => t.stop());
            $('#rec-stop').disabled = true;
            $('#rec-btn').disabled = false;
            $('#rec-send').disabled = false;
            $('#rec-status').textContent = 'recorded ' + Math.round(recBlob.size / 1024) + ' KB — click Transcribe to send to Sarvam AI';
        };
        recMedia.start();
        $('#rec-btn').disabled = true;
        $('#rec-stop').disabled = false;
        $('#rec-send').disabled = true;
        $('#rec-status').textContent = '● recording…';
    }
    catch (e) {
        $('#rec-status').innerHTML = '<span class="err">microphone unavailable: ' + esc(e.message) + '</span>';
    }
}
function stopRecord() { if (recMedia && recMedia.state !== 'inactive')
    recMedia.stop(); }
function blobToB64(blob) {
    return new Promise((res, rej) => {
        const r = new FileReader();
        r.onload = () => res(String(r.result).split(',')[1]);
        r.onerror = rej;
        r.readAsDataURL(blob);
    });
}
async function sendRecording() {
    if (!recBlob)
        return;
    $('#rec-status').textContent = 'transcribing via Saaras…';
    try {
        const b64 = await blobToB64(recBlob);
        const d = await apiPost('/api/ai/listen', { audio_b64: b64, mode: 'transcribe' });
        $('#rec-out').value = d.transcript;
        $('#rec-status').textContent = 'transcription complete';
    }
    catch (e) {
        $('#rec-status').innerHTML = '<div class="err">' + esc(e.message) + '</div>';
    }
}
async function runLocalizedReport() {
    const en = $('#rep-en'), out = $('#rep-out');
    en.innerHTML = '<span class="spinner"></span> generating…';
    out.innerHTML = '<span class="spinner"></span> translating…';
    try {
        const d = await apiPost('/api/ai/report', { qasm: $('#ai-qasm').value, to: $('#rep-lang').value });
        en.textContent = d.english;
        out.textContent = d.translated;
    }
    catch (e) {
        en.innerHTML = '<div class="err">' + esc(e.message) + '</div>';
        out.textContent = '';
    }
}
async function copyReport() {
    const out = $('#rep-out').textContent || '';
    const status = $('#rep-copy-status');
    try {
        await navigator.clipboard.writeText(out);
        status.textContent = 'Translated report copied to clipboard.';
        $('#rep-out').style.outline = '2px solid var(--acc)';
        setTimeout(() => { $('#rep-out').style.outline = 'none'; }, 800);
    }
    catch (e) {
        status.textContent = 'Could not copy report: ' + e.message;
    }
}
const UI_ACTIONS = {
    scan: runScan,
    'load-example': loadExample,
    compare: runCompare,
    robustness: runRobustness,
    'policy-eval': runPolicyEval,
    'ai-triage': runAiTriage,
    'load-ai-example': loadAiExample,
    speak: runTts,
    'record-start': toggleRecord,
    'record-stop': stopRecord,
    transcribe: sendRecording,
    'localized-report': runLocalizedReport,
    'copy-report': copyReport,
    'speak-reply': speakLastReply,
};
document.addEventListener('click', async (event) => {
    const target = event.target;
    if (!(target instanceof Element))
        return;
    const button = target.closest('button[data-action]');
    if (!button || button.disabled)
        return;
    const actionName = button.dataset.action;
    if (!actionName)
        return;
    const action = UI_ACTIONS[actionName];
    if (!action)
        return;
    if (actionName === 'record-start' || actionName === 'record-stop') {
        action();
        return;
    }
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    try {
        await action();
    }
    finally {
        button.disabled = false;
        button.removeAttribute('aria-busy');
    }
});
const scanFileInput = $('#scan-file');
scanFileInput?.addEventListener('change', () => {
    const file = scanFileInput.files?.[0];
    if (file)
        void loadCircuitFile(file);
    scanFileInput.value = '';
});
buildTabs();
loadPolicies();
aiStatus();
