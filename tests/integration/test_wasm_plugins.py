from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from qshield.core.parsers import parse_qasm
from qshield.plugins import PluginExecutionError, PluginLimitError, PluginLimits, WasmPluginRunner

wasmtime = pytest.importorskip("wasmtime")


def _install_plugin(tmp_path: Path, wat: str, *, plugin_id: str = "test.wasm-plugin") -> Path:
    plugin_dir = tmp_path / plugin_id
    plugin_dir.mkdir(parents=True)
    module_bytes = wasmtime.wat2wasm(wat)
    module = plugin_dir / "module.wasm"
    module.write_bytes(module_bytes)
    manifest = {
        "manifest_version": 1,
        "plugin_id": plugin_id,
        "version": "1.0.0",
        "api_version": "1",
        "module": module.name,
        "sha256": hashlib.sha256(module_bytes).hexdigest(),
    }
    (plugin_dir / "qshield-plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
    return plugin_dir


def _writer_module(response: dict) -> str:
    output = (json.dumps(response, separators=(",", ":")) + "\n").encode()
    data = "".join(f"\\{byte:02x}" for byte in output)
    return f'''(module
      (import "wasi_snapshot_preview1" "fd_write"
        (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (data (i32.const 0) "{data}")
      (func (export "_start")
        (i32.store (i32.const 2048) (i32.const 0))
        (i32.store (i32.const 2052) (i32.const {len(output)}))
        (i32.store (i32.const 2056) (i32.const 0))
        (drop (call $fd_write (i32.const 1) (i32.const 2048) (i32.const 1) (i32.const 2056))))
    )'''


def test_wasi_plugin_runs_and_host_tags_result(tmp_path: Path):
    circuit = parse_qasm("OPENQASM 2.0; qreg q[1]; x q[0];")
    response = {
        "api_version": "1",
        "findings": [{
            "code": "EXAMPLE-X",
            "severity": "info",
            "message": "Review this gate",
            "gate_ids": [circuit.gates[0].gate_id],
        }],
    }
    plugin = _install_plugin(tmp_path, _writer_module(response))
    result = WasmPluginRunner().run(plugin, circuit)
    assert result.plugin_id == "test.wasm-plugin"
    assert result.plugin_version == "1.0.0"
    assert result.api_version == "1"
    assert result.findings[0].gate_ids == (circuit.gates[0].gate_id,)
    assert result.findings[0].plugin_id == "test.wasm-plugin"


def test_rejects_non_wasi_host_imports(tmp_path: Path):
    plugin = _install_plugin(
        tmp_path,
        '''(module
          (import "qshield_host" "network" (func $network))
          (func (export "_start")))''',
    )
    circuit = parse_qasm("OPENQASM 2.0; qreg q[1];")
    with pytest.raises(PluginExecutionError, match="unsupported host modules"):
        WasmPluginRunner().run(plugin, circuit)


def test_rejects_network_capable_wasi_imports(tmp_path: Path):
    plugin = _install_plugin(
        tmp_path,
        '''(module
          (import "wasi_snapshot_preview1" "sock_connect" (func $connect (param i32 i32) (result i32)))
          (func (export "_start")))''',
    )
    circuit = parse_qasm("OPENQASM 2.0; qreg q[1];")
    with pytest.raises(PluginExecutionError, match="network-capable"):
        WasmPluginRunner().run(plugin, circuit)


def test_fuel_limit_stops_infinite_guest_loop(tmp_path: Path):
    plugin = _install_plugin(tmp_path, """(module (func (export "_start") (loop $again (br $again))) )""")
    circuit = parse_qasm("OPENQASM 2.0; qreg q[1];")
    with pytest.raises(PluginLimitError, match="fuel/time"):
        WasmPluginRunner(PluginLimits(fuel=100)).run(plugin, circuit)


def test_memory_limit_rejects_oversized_guest_memory(tmp_path: Path):
    plugin = _install_plugin(
        tmp_path,
        """(module (memory (export "memory") 20 20) (func (export "_start")))""",
    )
    circuit = parse_qasm("OPENQASM 2.0; qreg q[1];")
    with pytest.raises(PluginLimitError):
        WasmPluginRunner(PluginLimits(memory_bytes=64 * 1024)).run(plugin, circuit)


def test_wall_time_limit_interrupts_guest_loop(tmp_path: Path):
    plugin = _install_plugin(tmp_path, """(module (func (export "_start") (loop $again (br $again))) )""")
    circuit = parse_qasm("OPENQASM 2.0; qreg q[1];")
    with pytest.raises(PluginLimitError, match="fuel/time"):
        WasmPluginRunner(PluginLimits(fuel=10**12, timeout_seconds=0.03)).run(plugin, circuit)


def test_output_limit_is_enforced(tmp_path: Path):
    response = {"api_version": "1", "findings": []}
    plugin = _install_plugin(tmp_path, _writer_module(response))
    circuit = parse_qasm("OPENQASM 2.0; qreg q[1];")
    with pytest.raises(PluginLimitError, match="output exceeded"):
        WasmPluginRunner(PluginLimits(output_bytes=8)).run(plugin, circuit)
