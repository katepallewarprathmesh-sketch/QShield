"""Launch detector plugins in an isolated worker process."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from qshield.core.circuit_ir import CircuitIR
from qshield.plugins.api import (
    PluginExecutionError,
    PluginLimitError,
    PluginLimits,
    PluginRunResult,
    decode_output,
    encode_input,
)


class WasmPluginRunner:
    """Execute an explicitly selected WebAssembly plugin in a worker process.

    The worker exposes only WASI Preview 1, with no preopened directories,
    environment variables, or network-capable imports. Guest memory, tables,
    fuel, wall time, stdin, stdout, and stderr are bounded.
    """

    def __init__(self, limits: PluginLimits | None = None):
        self.limits = limits or PluginLimits()

    def run(self, plugin_dir: str | Path, circuit: CircuitIR) -> PluginRunResult:
        start_time = time.monotonic()
        from qshield.plugins.api import PluginManifest

        manifest, _module_path = PluginManifest.load(plugin_dir)
        input_bytes = encode_input(circuit, max_bytes=self.limits.input_bytes)
        request = {
            "plugin_dir": str(Path(plugin_dir).resolve()),
            "expected_manifest": asdict(manifest),
            "input_b64": base64.b64encode(input_bytes).decode("ascii"),
            "limits": asdict(self.limits),
        }
        request_bytes = json.dumps(request, separators=(",", ":")).encode("utf-8")
        env = {
            "PATH": os.defpath,
            "PYTHONNOUSERSITE": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        with tempfile.TemporaryDirectory(prefix="qshield-plugin-worker-") as cwd:
            try:
                completed = subprocess.run(
                    [sys.executable, "-I", "-m", "qshield.plugins.worker"],
                    input=request_bytes,
                    capture_output=True,
                    cwd=cwd,
                    env=env,
                    timeout=self.limits.timeout_seconds + 3.0,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise PluginLimitError("plugin worker exceeded its wall-time limit") from exc
            except OSError as exc:
                raise PluginExecutionError(f"could not start isolated plugin worker: {exc}") from exc

        if completed.returncode:
            error = completed.stderr.decode("utf-8", errors="replace")[:4_000].strip()
            if completed.returncode == 20 or error.startswith("QSHIELD_PLUGIN_LIMIT:"):
                raise PluginLimitError(error.removeprefix("QSHIELD_PLUGIN_LIMIT:").strip())
            raise PluginExecutionError(error or f"plugin worker exited with status {completed.returncode}")
        if len(completed.stdout) > self.limits.output_bytes:
            raise PluginLimitError(f"plugin output exceeded {self.limits.output_bytes} bytes")

        valid_gate_ids = {gate.gate_id for gate in circuit.gates}
        findings = decode_output(completed.stdout, manifest, valid_gate_ids=valid_gate_ids)
        return PluginRunResult(
            plugin_id=manifest.plugin_id,
            plugin_version=manifest.version,
            api_version=manifest.api_version,
            findings=findings,
            elapsed_seconds=time.monotonic() - start_time,
        )
