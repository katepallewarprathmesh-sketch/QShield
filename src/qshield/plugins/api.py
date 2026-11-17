"""Versioned data contract and validation for detector plugins.

Plugins receive a JSON-only CircuitIR view over WASI stdin and return findings
as JSON on stdout. Host identity is taken from the verified manifest, never
from plugin output.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qshield.core.circuit_ir import CircuitIR

PLUGIN_API_VERSION = "1"
MANIFEST_FILENAME = "qshield-plugin.json"
_MANIFEST_KEYS = {"manifest_version", "plugin_id", "version", "api_version", "module", "sha256"}
_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class PluginExecutionError(RuntimeError):
    """A plugin could not be safely loaded or returned a valid response."""


class PluginLimitError(PluginExecutionError):
    """A plugin exceeded a configured execution resource limit."""


@dataclass(frozen=True)
class PluginManifest:
    manifest_version: int
    plugin_id: str
    version: str
    api_version: str
    module: str
    sha256: str

    @classmethod
    def load(cls, plugin_dir: str | Path) -> tuple[PluginManifest, Path]:
        try:
            root = Path(plugin_dir).resolve(strict=True)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise PluginExecutionError(f"invalid plugin directory: {exc}") from exc
        if not root.is_dir():
            raise PluginExecutionError("plugin path must be a directory")
        manifest_path = root / MANIFEST_FILENAME
        try:
            if manifest_path.resolve(strict=True).parent != root:
                raise PluginExecutionError("plugin manifest must be a regular file in its plugin directory")
            raw = manifest_path.read_bytes()
        except OSError as exc:
            raise PluginExecutionError(f"could not read {MANIFEST_FILENAME}: {exc}") from exc
        if len(raw) > 64 * 1024:
            raise PluginExecutionError("plugin manifest exceeds the 64 KiB limit")
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PluginExecutionError(f"invalid plugin manifest JSON: {exc}") from exc
        if not isinstance(data, dict) or set(data) != _MANIFEST_KEYS:
            raise PluginExecutionError(f"manifest must contain exactly: {', '.join(sorted(_MANIFEST_KEYS))}")
        manifest = cls(**data)
        manifest.validate()

        module_name = Path(manifest.module)
        if module_name.suffix != ".wasm":
            raise PluginExecutionError("manifest module must have a .wasm extension")
        if module_name.is_absolute() or len(module_name.parts) != 1 or module_name.name in {".", ".."}:
            raise PluginExecutionError("manifest module must be a filename inside the plugin directory")
        try:
            module_path = (root / module_name).resolve(strict=True)
            if module_path.parent != root or not module_path.is_file():
                raise PluginExecutionError("plugin module must be a regular file inside the plugin directory")
            if module_path.stat().st_size > 16 * 1024 * 1024:
                raise PluginLimitError("plugin module exceeds the 16 MiB size limit")
            module_bytes = module_path.read_bytes()
            if len(module_bytes) > 16 * 1024 * 1024:
                raise PluginLimitError("plugin module exceeds the 16 MiB size limit")
        except OSError as exc:
            raise PluginExecutionError(f"could not read plugin module: {exc}") from exc
        digest = hashlib.sha256(module_bytes).hexdigest()
        if digest != manifest.sha256:
            raise PluginExecutionError("plugin module SHA-256 does not match the manifest")
        if not module_bytes.startswith(b"\x00asm"):
            raise PluginExecutionError("plugin module is not a WebAssembly binary")
        return manifest, module_path

    def validate(self) -> None:
        if type(self.manifest_version) is not int or self.manifest_version != 1:
            raise PluginExecutionError("unsupported plugin manifest version")
        if not isinstance(self.plugin_id, str) or not _ID_RE.fullmatch(self.plugin_id):
            raise PluginExecutionError("plugin_id must be a lowercase identifier (letters, digits, dot, underscore, hyphen)")
        if not isinstance(self.version, str) or not _VERSION_RE.fullmatch(self.version):
            raise PluginExecutionError("plugin version must use MAJOR.MINOR.PATCH form")
        if self.api_version != PLUGIN_API_VERSION:
            raise PluginExecutionError(f"plugin API {self.api_version!r} is unsupported; expected {PLUGIN_API_VERSION!r}")
        if not isinstance(self.module, str) or not self.module or "\x00" in self.module:
            raise PluginExecutionError("manifest module must be a non-empty filename")
        if not isinstance(self.sha256, str) or not _SHA256_RE.fullmatch(self.sha256):
            raise PluginExecutionError("manifest sha256 must be 64 lowercase hexadecimal characters")


@dataclass(frozen=True)
class PluginLimits:
    """Hard limits for a WASI plugin instance."""

    memory_bytes: int = 16 * 1024 * 1024
    fuel: int = 20_000_000
    timeout_seconds: float = 2.0
    input_bytes: int = 2 * 1024 * 1024
    output_bytes: int = 256 * 1024

    def __post_init__(self) -> None:
        if type(self.memory_bytes) is not int or not 64 * 1024 <= self.memory_bytes <= 1024 * 1024 * 1024:
            raise ValueError("plugin memory limit must be an integer between 64 KiB and 1 GiB")
        if type(self.fuel) is not int or not 1 <= self.fuel <= 10**12:
            raise ValueError("plugin fuel must be an integer between 1 and 10^12 instructions")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise TypeError("plugin timeout must be a finite number greater than 0 and at most 300 seconds")
        if not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 300:
            raise ValueError("plugin timeout must be a finite number greater than 0 and at most 300 seconds")
        if type(self.input_bytes) is not int or not 1 <= self.input_bytes <= 16 * 1024 * 1024:
            raise ValueError("plugin input limit must be an integer between 1 byte and 16 MiB")
        if type(self.output_bytes) is not int or not 1 <= self.output_bytes <= 16 * 1024 * 1024:
            raise ValueError("plugin output limit must be an integer between 1 byte and 16 MiB")


def circuit_payload(circuit: CircuitIR) -> dict[str, Any]:
    """Return the versioned, source-free view exposed to a plugin."""
    gates = []
    for gate in circuit.gates:
        parameters = [float(value) if math.isfinite(float(value)) else None for value in gate.parameters]
        gates.append({
            "gate_id": gate.gate_id,
            "gate_name": gate.gate_name,
            "gate_type": gate.gate_type.value,
            "qubits": list(gate.qubits),
            "parameters": parameters,
            "source_location": gate.source_location,
        })
    return {
        "api_version": PLUGIN_API_VERSION,
        "circuit": {
            "circuit_id": circuit.circuit_id,
            "name": circuit.name,
            "num_qubits": circuit.num_qubits,
            "num_classical_bits": circuit.num_classical_bits,
            "gates": gates,
            "measurements": [list(item) for item in circuit.measurements],
            "ancilla_qubits": list(circuit.ancilla_qubits),
            "source_framework": circuit.source_framework,
            "source_hash": circuit.source_hash,
        },
    }


def encode_input(circuit: CircuitIR, *, max_bytes: int) -> bytes:
    try:
        encoded = json.dumps(circuit_payload(circuit), ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise PluginExecutionError(f"could not serialize circuit for plugin API: {exc}") from exc
    if len(encoded) > max_bytes:
        raise PluginLimitError(f"plugin input exceeds {max_bytes} bytes")
    return encoded


@dataclass(frozen=True)
class PluginFinding:
    plugin_id: str
    plugin_version: str
    code: str
    severity: str
    message: str
    gate_ids: tuple[str, ...]


@dataclass(frozen=True)
class PluginRunResult:
    plugin_id: str
    plugin_version: str
    api_version: str
    findings: tuple[PluginFinding, ...]
    elapsed_seconds: float


def decode_output(
    raw: bytes,
    manifest: PluginManifest,
    *,
    valid_gate_ids: set[str],
    max_findings: int = 1_000,
) -> tuple[PluginFinding, ...]:
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PluginExecutionError(f"plugin stdout is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or set(data) != {"api_version", "findings"}:
        raise PluginExecutionError("plugin response must contain exactly api_version and findings")
    if data["api_version"] != PLUGIN_API_VERSION:
        raise PluginExecutionError("plugin response API version does not match the host")
    records = data["findings"]
    if not isinstance(records, list) or len(records) > max_findings:
        raise PluginExecutionError(f"plugin findings must be a list of at most {max_findings} items")

    findings: list[PluginFinding] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) - {"code", "severity", "message", "gate_ids"}:
            raise PluginExecutionError(f"plugin finding {index} contains invalid fields")
        code, severity, message = record.get("code"), record.get("severity"), record.get("message")
        gate_ids = record.get("gate_ids", [])
        if not isinstance(code, str) or not code or len(code) > 64:
            raise PluginExecutionError(f"plugin finding {index} has an invalid code")
        if not isinstance(severity, str) or severity not in _SEVERITIES:
            raise PluginExecutionError(f"plugin finding {index} has an invalid severity")
        if not isinstance(message, str) or not message.strip() or len(message) > 1_000:
            raise PluginExecutionError(f"plugin finding {index} has an invalid message")
        if not isinstance(gate_ids, list) or len(gate_ids) > 1_000 or any(not isinstance(item, str) for item in gate_ids):
            raise PluginExecutionError(f"plugin finding {index} has invalid gate_ids")
        if not set(gate_ids) <= valid_gate_ids:
            raise PluginExecutionError(f"plugin finding {index} references an unknown gate id")
        findings.append(PluginFinding(
            plugin_id=manifest.plugin_id,
            plugin_version=manifest.version,
            code=code,
            severity=severity,
            message=message.strip(),
            gate_ids=tuple(gate_ids),
        ))
    return tuple(findings)
