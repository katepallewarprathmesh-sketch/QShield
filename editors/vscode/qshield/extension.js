// QSHIELD VS Code extension — inline diagnostics from `qshield scan --format json`.
// No runtime dependencies; shells out to the QSHIELD CLI.
const vscode = require('vscode');
const { execFile } = require('child_process');

const SEVERITY_MAP = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const CIRCUIT_RE = /\.(qasm|qasm3|qir)$/i;

let diagnostics;
let warnedMissingCli = false;
let warnedParse = false;
const pending = new Map();

function config() {
  return vscode.workspace.getConfiguration('qshield');
}

function minSeverityRank() {
  return RANK[String(config().get('minSeverity', 'low')).toLowerCase()] ?? 1;
}

function diagnosticFor(document, finding) {
  const loc = finding.location || {};
  let line = 0;
  if (Number.isInteger(loc.source_line)) {
    line = Math.max(0, loc.source_line);
  } else if (Array.isArray(loc.gate_indices) && loc.gate_indices.length) {
    line = Math.max(0, Number(loc.gate_indices[0]));
  }
  line = Math.min(line, Math.max(0, document.lineCount - 1));
  const range = new vscode.Range(line, 0, line, document.lineAt(line).text.length);
  const diag = new vscode.Diagnostic(
    range,
    `[${finding.threat_type}] ${finding.title}`,
    SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Information,
  );
  diag.source = 'qshield';
  diag.code = finding.signature_id || finding.finding_id;
  return diag;
}

function runScan(document) {
  const cfg = config();
  const exe = cfg.get('executable', 'qshield');
  const filePath = document.uri.fsPath;
  execFile(
    exe,
    ['scan', filePath, '--format', 'json', '--fail-on', 'never'],
    { maxBuffer: 16 * 1024 * 1024, timeout: 120_000 },
    (error, stdout) => {
      if (error && error.code === 'ENOENT') {
        if (!warnedMissingCli) {
          warnedMissingCli = true;
          vscode.window.showWarningMessage(
            `QSHIELD: '${exe}' not found. Install it (pip install qshield) or set qshield.executable.`,
          );
        }
        return;
      }
      let payload;
      try {
        payload = JSON.parse(String(stdout));
      } catch (parseError) {
        if (!warnedParse) {
          warnedParse = true;
          const detail = error ? ` (${error.message})` : '';
          vscode.window.showWarningMessage(`QSHIELD: could not parse scanner output${detail}.`);
        }
        return;
      }
      const minRank = minSeverityRank();
      const diagnosticsForDoc = (payload.findings || [])
        .filter((f) => (RANK[f.severity] ?? 0) >= minRank)
        .map((f) => diagnosticFor(document, f));
      diagnostics.set(document.uri, diagnosticsForDoc);
    },
  );
}

function scheduleScan(document) {
  const key = document.uri.toString();
  clearTimeout(pending.get(key));
  pending.set(key, setTimeout(() => {
    pending.delete(key);
    runScan(document);
  }, 300));
}

function maybeScan(document) {
  if (document && CIRCUIT_RE.test(document.fileName)) {
    scheduleScan(document);
  }
}

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection('qshield');
  context.subscriptions.push(diagnostics);

  context.subscriptions.push(
    vscode.commands.registerCommand('qshield.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scheduleScan(editor.document);
      }
    }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (config().get('scanOnSave', true)) {
        maybeScan(document);
      }
    }),
    vscode.workspace.onDidOpenTextDocument(maybeScan),
    vscode.workspace.onDidCloseTextDocument((document) => {
      diagnostics.delete(document.uri);
    }),
  );

  for (const document of vscode.workspace.textDocuments) {
    maybeScan(document);
  }
}

function deactivate() {
  if (diagnostics) {
    diagnostics.clear();
    diagnostics.dispose();
  }
}

module.exports = { activate, deactivate };
