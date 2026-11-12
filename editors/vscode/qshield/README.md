# QSHIELD for VS Code (source build)

Inline security diagnostics for quantum circuits, powered by the local
`qshield` CLI. **Not published on the VS Code Marketplace** — install from
source until the project is listed:

```bash
pip install qshield          # or pip install -e . from the QSHIELD repo
cd editors/vscode/qshield
npm install -g @vscode/vsce
vsce package                 # produces qshield-vscode-0.1.0.vsix
code --install-extension qshield-vscode-0.1.0.vsix
```

## What it does

- Scans `.qasm`, `.qasm3` and `.qir` files on open and on save (300 ms
  debounce), publishing one diagnostic per QSHIELD finding.
- Maps severities: critical/high → Error, medium → Warning, low →
  Information, info → Hint.
- Command palette: **QSHIELD: Scan current circuit**.

## Configuration

| Setting | Default | Description |
|---|---|---|
| `qshield.executable` | `qshield` | Path to the QSHIELD CLI |
| `qshield.minSeverity` | `low` | Minimum severity shown inline |
| `qshield.scanOnSave` | `true` | Re-scan on save |

## Honest limitations

- Inline positions are approximations: findings anchored to a gate index
  (not a source line) are squiggled at the corresponding line number, else
  at line 1. Use `qshield scan <file> --format json` for exact evidence.
- Diagnostics appear only after the CLI finishes (async); the Problems
  panel is the source of truth.
- Marketplace listing requires a publisher account and is not automated.
