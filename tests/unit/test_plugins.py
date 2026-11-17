from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from qshield.core.parsers import parse_qasm
from qshield.plugins import (
    PLUGIN_API_VERSION,
    PluginExecutionError,
    PluginLimits,
    PluginManifest,
)
from qshield.plugins.api import MANIFEST_FILENAME, decode_output, encode_input

REPO_ROOT = Path(__file__).resolve().parents[2]


def make_manifest(tmp_path: Path, *, module_bytes: bytes = b"\x00asmtest", **changes) -> Path:
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "module.wasm").write_bytes(module_bytes)
    data = {
        "manifest_version": 1,
        "plugin_id": "example.test-plugin",
        "version": "1.2.3",
        "api_version": PLUGIN_API_VERSION,
        "module": "module.wasm",
        "sha256": hashlib.sha256(module_bytes).hexdigest(),
    }
    data.update(changes)
    (plugin_dir / MANIFEST_FILENAME).write_text(json.dumps(data), encoding="utf-8")
    return plugin_dir


def test_versioned_plugin_schemas_match_manifest_contract():
    schema_root = REPO_ROOT / "src" / "qshield" / "plugins"
    manifest_schema = json.loads((schema_root / "plugin-manifest.schema.json").read_text(encoding="utf-8"))
    input_schema = json.loads((schema_root / "plugin-input.schema.json").read_text(encoding="utf-8"))
    response_schema = json.loads((schema_root / "plugin-response.schema.json").read_text(encoding="utf-8"))
    assert manifest_schema["properties"]["api_version"]["const"] == PLUGIN_API_VERSION
    assert input_schema["properties"]["api_version"]["const"] == PLUGIN_API_VERSION
    assert response_schema["properties"]["api_version"]["const"] == PLUGIN_API_VERSION
    module_pattern = manifest_schema["properties"]["module"]["pattern"]
    assert re.fullmatch(module_pattern, "module.wasm")
    assert not re.fullmatch(module_pattern, "../module.wasm")


def test_manifest_load_verifies_hash_and_versions(tmp_path: Path):
    plugin = make_manifest(tmp_path)
    manifest, module = PluginManifest.load(plugin)
    assert manifest.plugin_id == "example.test-plugin"
    assert module.name == "module.wasm"


def test_manifest_rejects_module_tampering(tmp_path: Path):
    plugin = make_manifest(tmp_path)
    (plugin / "module.wasm").write_bytes(b"\x00asmchanged")
    with pytest.raises(PluginExecutionError, match="SHA-256"):
        PluginManifest.load(plugin)


@pytest.mark.parametrize("module_name", ["../escape.wasm", "/outside/escape.wasm", "sub/module.wasm"])
def test_manifest_rejects_module_path_traversal(tmp_path: Path, module_name: str):
    plugin = make_manifest(tmp_path, module=module_name)
    with pytest.raises(PluginExecutionError, match="filename inside"):
        PluginManifest.load(plugin)


def test_manifest_rejects_missing_plugin_directory(tmp_path: Path):
    with pytest.raises(PluginExecutionError, match="invalid plugin directory"):
        PluginManifest.load(tmp_path / "missing")


def test_manifest_rejects_unsupported_api(tmp_path: Path):
    plugin = make_manifest(tmp_path, api_version="2")
    with pytest.raises(PluginExecutionError, match="unsupported"):
        PluginManifest.load(plugin)


def test_input_is_versioned_and_does_not_include_arbitrary_metadata():
    ir = parse_qasm("OPENQASM 2.0; qreg q[1]; x q[0];")
    ir.metadata["private_note"] = "do not send plugin metadata"
    payload = json.loads(encode_input(ir, max_bytes=1024 * 1024))
    assert payload["api_version"] == PLUGIN_API_VERSION
    assert "metadata" not in payload["circuit"]
    assert payload["circuit"]["gates"][0]["gate_name"] == "x"


def test_input_size_limit_is_enforced():
    ir = parse_qasm("OPENQASM 2.0; qreg q[1]; x q[0];")
    with pytest.raises(PluginExecutionError, match="exceeds"):
        encode_input(ir, max_bytes=1)


def test_plugin_output_is_tagged_by_verified_manifest(tmp_path: Path):
    ir = parse_qasm("OPENQASM 2.0; qreg q[1]; x q[0];")
    plugin = make_manifest(tmp_path)
    manifest, _ = PluginManifest.load(plugin)
    raw = json.dumps({
        "api_version": "1",
        "findings": [{
            "code": "EXAMPLE-1",
            "severity": "info",
            "message": "review this gate",
            "gate_ids": [ir.gates[0].gate_id],
        }],
    }).encode()
    result = decode_output(raw, manifest, valid_gate_ids={gate.gate_id for gate in ir.gates})
    assert result[0].plugin_id == manifest.plugin_id
    assert result[0].plugin_version == manifest.version
    assert result[0].gate_ids == (ir.gates[0].gate_id,)


def test_plugin_output_rejects_unknown_gate_ids(tmp_path: Path):
    ir = parse_qasm("OPENQASM 2.0; qreg q[1]; x q[0];")
    plugin = make_manifest(tmp_path)
    manifest, _ = PluginManifest.load(plugin)
    raw = b'{"api_version":"1","findings":[{"code":"X","severity":"high","message":"bad ref","gate_ids":["not-a-gate"]}]}'
    with pytest.raises(PluginExecutionError, match="unknown gate"):
        decode_output(raw, manifest, valid_gate_ids={gate.gate_id for gate in ir.gates})


def test_plugin_output_rejects_unknown_fields(tmp_path: Path):
    plugin = make_manifest(tmp_path)
    manifest, _ = PluginManifest.load(plugin)
    with pytest.raises(PluginExecutionError, match="exactly"):
        decode_output(b'{"api_version":"1","findings":[],"decision":"allow"}', manifest, valid_gate_ids=set())


def test_limits_reject_nonpositive_values():
    with pytest.raises(ValueError, match="fuel"):
        PluginLimits(fuel=0)
