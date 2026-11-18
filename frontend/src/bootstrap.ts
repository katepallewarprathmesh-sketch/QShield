/* QSHIELD static site — real engine in the browser.
 *
 * Loads a pinned, self-hosted Pyodide (CPython 3.12) runtime plus the wheel
 * built from this same repository, then backs every /api/* call the page
 * makes with the real QSHIELD engine running locally in this tab.
 *
 *   - nothing you paste leaves this machine (no network calls after load)
 *   - no third-party requests at page view: runtime, wheels, fixtures are
 *     all served from this same origin (GitHub Pages artifact)
 *
 * AI Triage stays honest: a static page cannot hold a Sarvam API key, so
 * the AI endpoints return precomputed outputs of the real engine + Sarvam AI
 * on the bundled ancilla fixture — always labeled as such in the UI — or a
 * clear error for anything else.
 */
interface Window {
  __QSHIELD_AI_CANNED__?: Record<string, any>;
}

type EngineHandle = { pyodide: any; version: string };
type HttpError = Error & { __httpStatus?: number };

(function () {
  "use strict";

  let READY!: Promise<EngineHandle>;
  let LOAD_ERROR: unknown = null;

  function banner() { return document.getElementById('demo-banner'); }
  function setBanner(html, isError) {
    var b = banner();
    if (!b) return;
    b.innerHTML = html;
    if (isError) b.style.cssText += ';background:#2a1214;border-color:#5a2228;color:#ffb4b4';
  }
  function bannerNote(text) {
    var b = banner();
    if (b) b.querySelector('.banner-note').textContent = text;
  }

  function pythonPath() { return './vendor/pyodide/'; }

  function loadEngine() {
    return (async function () {
      var mod = await import(pythonPath() + 'pyodide.mjs');
      var pyodide = await mod.loadPyodide({ indexURL: pythonPath() });
      pyodide.setStdout({ batched: function () {} });           // keep the console clean
      await pyodide.loadPackage(['numpy', 'jinja2', 'pyyaml']);  // sha256-verified by build

      async function fetchBytes(url) {
        var res = await origFetch(url);
        if (!res.ok) throw new Error('failed to fetch ' + url + ' (' + res.status + ')');
        return new Uint8Array(await res.arrayBuffer());
      }
      pyodide.FS.writeFile('/qshield.whl', await fetchBytes('./vendor/qshield.whl'));
      pyodide.FS.writeFile('/fixtures.zip', await fetchBytes('./vendor/fixtures.zip'));
      pyodide.runPython(
        'import zipfile, os, sys\n' +
        'zipfile.ZipFile("/qshield.whl").extractall("/site-packages")\n' +
        'os.makedirs("/fixtures", exist_ok=True)\n' +
        'zipfile.ZipFile("/fixtures.zip").extractall("/fixtures")\n' +
        'sys.path.insert(0, "/site-packages")\n' +
        'os.environ["QSHIELD_FIXTURES_DIR"] = "/fixtures"\n'
      );
      var version = pyodide.runPython('import qshield; qshield.__version__');
      return { pyodide: pyodide, version: version };
    })();
  }

  // Engine calls pass arguments through globals (never string-interpolated
  // into Python source — no code-injection surface from page input).
  function callPython(code, args) {
    return READY.then(function (engine) {
      var py = engine.pyodide;
      Object.keys(args || {}).forEach(function (k) { py.globals.set(k, args[k]); });
      try {
        var out = py.runPython(code + '\n__out');
        return JSON.parse(out);
      } catch (err) {
        var msg = String((err && err.message) || err);
        var lines = msg.split('\n').filter(function (l) { return l.trim(); });
        throw new Error(lines.length ? lines[lines.length - 1].replace(/^(PythonError:|qshield\.\w+Error:?)\s*/, '') : 'engine error');
      } finally {
        Object.keys(args || {}).forEach(function (k) { try { py.globals.delete(k); } catch (e) { /* noop */ } });
      }
    });
  }

  function pyJson(fnCall, args) {
    return callPython(
      'import json as __json\n' +
      'from qshield.ui import server as __srv\n' +
      'from qshield.core.parsers.qasm_parser import parse_qasm as __parse\n' +
      'from qshield.redteam import probe_finding_robustness as __probe\n' +
      'from qshield.policy import builtin_policies as __policies\n' +
      '__out = __json.dumps(' + fnCall + ', default=str)',
      args
    );
  }

  function httpError(status: number, message: string): HttpError {
    var e = new Error(message) as HttpError;
    e.__httpStatus = status;
    return e;
  }
  function errorStatus(err: any): number {
    if (err && err.__httpStatus) return err.__httpStatus;
    var m = String((err && err.message) || err);
    if (/PolicyError|QASMParseError|parse/i.test(m)) return 400;
    if (/SARVAM|Sarvam|upstream/i.test(m)) return 503;
    return 500;
  }
  function jsonResponse(status, obj) {
    return new Response(JSON.stringify(obj), {
      status: status,
      headers: { 'content-type': 'application/json' },
    });
  }

  /* ---------------------------------------------------------------- AI
   * Precomputed real outputs (ancilla fixture), always labeled.            */
  var AI = window.__QSHIELD_AI_CANNED__ || {};
  var CANNED_NOTE = 'precomputed real output (real engine + Sarvam AI on the bundled ancilla fixture) — the static page cannot call the cloud; run locally with SARVAM_API_KEY for live AI';
  function norm(s) {
    return String(s || '')
      .replace(/\/\*[^]*?\*\//g, '')
      .replace(/\/\/[^\n]*/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }
  function ancillaQasmOnce() {
    return READY.then(function (engine) {
      return engine.pyodide.FS.readFile('/fixtures/malicious_circuits/ancilla_leakage.qasm', { encoding: 'utf8' });
    });
  }
  function isAncilla(qasm) {
    return ancillaQasmOnce().then(function (fixture) {
      return norm(qasm) === norm(fixture);
    });
  }
  function requireAncilla(qasm) {
    return isAncilla(qasm).then(function (ok) {
      if (!ok) {
        throw httpError(400, 'The static page only carries the precomputed AI output for the bundled ancilla-leakage fixture. Run locally (pip install -e . && SARVAM_API_KEY=... qshield ui) for live AI on your own circuits.');
      }
    });
  }

  /* ------------------------------------------------------ API handler */
  function handleApi(url: string, opts: RequestInit = {}): Promise<any> {
    var parsed = new URL(url, window.location.origin);
    var path = parsed.pathname;
    var method = (opts && opts.method ? opts.method : 'GET').toUpperCase();
    var body: Record<string, any> = {};
    if (opts && typeof opts.body === 'string' && opts.body.trim()) {
      try { body = JSON.parse(opts.body); } catch (e) { return Promise.reject(httpError(400, 'invalid JSON body')); }
    }

    if (method === 'GET') {
      if (path === '/api/overview') {
        return READY.then(function (engine) {
          return {
            name: 'QSHIELD Workbench',
            version: engine.version,
            corpus: { clean: 202, malicious: 215 },
            metrics: { tpr: 0.958, fpr: 0.008, runtime_p95_ms: 1.5, static_1000q_s: 2 },
            capabilities: [
              'Local-first circuit analysis in the browser',
              'Evidence-led scans, comparison, robustness, and policy review',
              'Reproducible benchmarks on the bundled fixture corpus',
              'Optional AI assistance operates separately from core scan results',
            ],
          };
        });
      }
      if (path === '/api/ai/status') {
        return Promise.resolve({
          configured: false,
          disclaimer: 'AI-advisory (Sarvam AI, cloud). A static page cannot hold a Sarvam key — live AI is unavailable here; the AI tab shows precomputed real outputs. Run locally with SARVAM_API_KEY for live AI. LLM output is not a verdict.',
        });
      }
      if (path === '/api/policies') {
        return pyJson(
          '{"policies": [p.to_dict() for p in __policies()], "corpus_available": __srv._fixture_corpus_available()}',
          {}
        );
      }
      if (path === '/api/example') {
        var name = parsed.searchParams.get('name') || 'ancilla_leakage';
        if (!/^[A-Za-z0-9_.-]+$/.test(name)) return Promise.reject(httpError(400, 'bad example name'));
        return READY.then(function (engine) {
          try {
            return { qasm: engine.pyodide.FS.readFile('/fixtures/malicious_circuits/' + name.replace(/\.qasm$/, '') + '.qasm', { encoding: 'utf8' }) };
          } catch (e) {
            throw httpError(404, "example '" + name + "' not found in the bundled corpus");
          }
        });
      }
      return Promise.reject(httpError(404, 'not found'));
    }

    if (method === 'POST') {
      if (path === '/api/scan') {
        var qasm = String(body.qasm || '').trim();
        if (!qasm) return Promise.reject(httpError(400, "provide 'qasm' source text"));
        return pyJson('__srv._scan_qasm(__qasm)', { __qasm: qasm });
      }
      if (path === '/api/compare') {
        var a = String(body.a || '').trim(), b = String(body.b || '').trim();
        if (!a || !b) return Promise.reject(httpError(400, "provide both 'a' and 'b' circuit sources"));
        var engineName = String(body.engine || 'unitary');
        if (engineName !== 'unitary' && engineName !== 'zx') return Promise.reject(httpError(400, "engine must be 'unitary' or 'zx'"));
        return pyJson('__srv._compare(__a, __b, __engine)', { __a: a, __b: b, __engine: engineName });
      }
      if (path === '/api/robustness') {
        var rqasm = String(body.qasm || '').trim();
        if (!rqasm) return Promise.reject(httpError(400, "provide 'qasm' source text"));
        return pyJson('__probe(__parse(__qasm, name="probe"), variants_per_attack=2)', { __qasm: rqasm });
      }
      if (path === '/api/policy-eval') {
        var ids = body.ids;
        if (!Array.isArray(ids) || !ids.length || !ids.every(function (i) { return typeof i === 'string'; })) {
          return Promise.reject(httpError(400, "provide non-empty 'ids': list of builtin policy ids"));
        }
        var sample = body.sample;
        if (sample !== undefined && sample !== null && (!Number.isInteger(sample) || sample < 1)) {
          return Promise.reject(httpError(400, "'sample' must be a positive integer (or omitted for full corpus)"));
        }
        return pyJson('__srv._policy_eval(__ids, __sample)', {
          __ids: ids,
          __sample: (sample === undefined || sample === null) ? null : sample,
        });
      }

      /* ---- AI endpoints: canned real outputs, honestly labeled ---- */
      if (path === '/api/ai/triage') {
        var tqasm = String(body.qasm || '').trim();
        if (!tqasm) return Promise.reject(httpError(400, "provide 'qasm' source text"));
        return requireAncilla(tqasm).then(function () {
          return Object.assign({}, AI.triage, { note: CANNED_NOTE });
        });
      }
      if (path === '/api/ai/report') {
        var pqasm = String(body.qasm || '').trim();
        var to = String(body.to || 'hi-IN').trim();
        if (!pqasm) return Promise.reject(httpError(400, "provide 'qasm' source text"));
        if (!/^[a-z]{2}-IN$/.test(to)) return Promise.reject(httpError(400, "'to' must be an Indian language code like hi-IN, mr-IN, ta-IN"));
        return requireAncilla(pqasm).then(function () {
          var pack = to === 'hi-IN' ? AI.report_hi : to === 'mr-IN' ? AI.report_mr : null;
          if (!pack) return Promise.reject(httpError(400, 'The static page only carries the precomputed ' + to + ' report for the ancilla fixture (hi-IN, mr-IN). Run locally for other languages.'));
          return Object.assign({}, pack, { note: CANNED_NOTE });
        });
      }
      if (path === '/api/ai/speak' || path === '/api/ai/listen') {
        return Promise.reject(httpError(503, 'Cloud voice features are unavailable on the static page — run locally with SARVAM_API_KEY (qshield ui).'));
      }
      return Promise.reject(httpError(404, 'not found'));
    }

    return Promise.reject(httpError(405, 'method not allowed'));
  }


  /* --------------------------------------------- window.fetch override */
  var origFetch = window.fetch.bind(window);

  READY = loadEngine().then(function (engine) {
    bannerNote('engine ready — scans, compare, robustness, policy scoring and overview all run locally in this tab');
    return engine;
  }, function (err) {
    LOAD_ERROR = err;
    setBanner(
      '<span><b>ENGINE FAILED TO LOAD</b> — ' + String((err && err.message) || err).replace(/[<>&]/g, '') +
      '. Check your connection (first load fetches ~18 MB) and reload. The full local Workbench: ' +
      '<code>pip install -e . &amp;&amp; qshield ui</code></span>',
      true
    );
    throw err;
  });

  window.fetch = function (input: RequestInfo | URL, opts?: RequestInit): Promise<Response> {
    var url = typeof input === 'string' ? input : input instanceof Request ? input.url : input.toString();
    var path = '';
    try { path = new URL(url, window.location.origin).pathname; } catch (e) { path = url; }
    if (path.indexOf('/api/') !== 0) return origFetch(input, opts);
    if (LOAD_ERROR) {
      return Promise.resolve(jsonResponse(503, { error: 'In-browser engine failed to load — reload the page, or run the local Workbench (pip install -e . && qshield ui).' }));
    }
    return handleApi(url, opts || {}).then(
      function (data) { return jsonResponse(200, data); },
      function (err) { return jsonResponse(errorStatus(err), { error: String((err && err.message) || err) }); }
    );
  };
})();
