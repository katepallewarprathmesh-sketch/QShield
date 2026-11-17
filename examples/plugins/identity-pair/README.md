# QSHIELD WASI detector plugin example

This Rust example reads the QSHIELD plugin API v1 JSON input from stdin and reports adjacent `x` gates on the same qubit as an **informational review hint**. It does not claim that a circuit is malicious. The plugin receives a reduced CircuitIR view, not source code or arbitrary metadata.

## Build

Install Rust and the WASI target, then build the module:

```bash
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1
mkdir -p dist/example.identity-pair
cp target/wasm32-wasip1/release/qshield_identity_pair_example.wasm dist/example.identity-pair/module.wasm
```

Create `dist/example.identity-pair/qshield-plugin.json` with the module hash:

```bash
python - <<'PY'
import hashlib, json
from pathlib import Path
plugin = Path("dist/example.identity-pair")
manifest = {
    "manifest_version": 1,
    "plugin_id": "example.identity-pair",
    "version": "0.1.0",
    "api_version": "1",
    "module": "module.wasm",
    "sha256": hashlib.sha256((plugin / "module.wasm").read_bytes()).hexdigest(),
}
(plugin / "qshield-plugin.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
```

## Run (explicit opt-in)

```bash
pip install 'qshield[plugins]'
```

```python
from qshield.core.parsers import parse_file
from qshield.plugins import WasmPluginRunner

circuit = parse_file("circuit.qasm")
result = WasmPluginRunner().run("dist/example.identity-pair", circuit)
for finding in result.findings:
    print(finding.plugin_id, finding.plugin_version, finding.severity, finding.message)
```

The host verifies the manifest and SHA-256 before execution, accepts only WASI Preview 1 imports, provides no preopened directories or environment variables, and enforces memory, instruction-fuel, output-size, and wall-time limits. Plugin results are returned separately; they are not silently merged into core findings or gate decisions. The manifest hash detects accidental/tampered module changes relative to that manifest; it is **not publisher authentication or a digital signature**.
