"""Configuration management for QSHIELD.

Profiles: ``default``, ``strict``, ``permissive``.  A path to a YAML file
with the same schema as ``.qshield.yaml`` (see the specification, section 10)
is also accepted.  Missing keys fall back to the profile defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_STATIC = {
    "check_dead_qubits": True,
    "check_gate_cancellation": True,
    "check_entanglement_anomaly": True,
    "check_parameter_anomaly": True,
    "check_gate_count_heuristic": True,
    "check_measurement_basis": True,
    "unitary_verification": True,
    "unitary_max_qubits": 12,
    "unitary_tolerance": 1e-6,
    "scan_dependencies": True,
    "check_typosquatting": True,
    "verify_hashes": False,
}

_DEFAULT_THRESHOLDS = {
    "max_parameter_precision": 10,
    "min_qubit_activity": 2,
    "gate_count_multiplier": 2.0,
    "js_divergence_threshold": 0.05,
    "min_confidence": 0.5,
    "cancellation_tolerance": 1e-6,
    "micro_rotation_threshold": 0.01,
    "micro_rotation_min_occurrences": 6,
}

_PROFILES: dict[str, dict[str, Any]] = {
    "default": {},
    "strict": {
        "thresholds": {
            "max_parameter_precision": 6,
            "min_qubit_activity": 3,
            "gate_count_multiplier": 1.5,
            "js_divergence_threshold": 0.01,
            "min_confidence": 0.3,
        },
        "analysis": {"dynamic": True, "formal": False},
    },
    "permissive": {
        "thresholds": {
            "max_parameter_precision": 15,
            "min_qubit_activity": 1,
            "gate_count_multiplier": 3.0,
            "js_divergence_threshold": 0.1,
            "min_confidence": 0.8,
        },
        "analysis": {"dynamic": False, "formal": False},
    },
}


@dataclass
class QShieldConfig:
    """Resolved QSHIELD configuration."""

    profile: str = "default"
    static: dict[str, Any] = field(default_factory=lambda: dict(_DEFAULT_STATIC))
    dynamic_enabled: bool = False
    formal_enabled: bool = False
    dynamic_backends: list[str] = field(default_factory=lambda: ["qshield_numpy_statevector"])
    num_shots: int = 10_000
    num_random_inputs: int = 8
    significance_level: float = 0.01
    thresholds: dict[str, Any] = field(default_factory=lambda: dict(_DEFAULT_THRESHOLDS))
    reporting_format: str = "json"
    fail_on: str = "high"
    signatures_builtin: bool = True
    signatures_community: bool = False  # spec default config (.qshield.yaml): use_community: false
    signature_paths: list[str] = field(default_factory=list)
    unitary_max_qubits: int = 12
    unitary_tolerance: float = 1e-6
    license_policy: dict[str, Any] = field(
        default_factory=lambda: {"allowed_licenses": [
            "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause",
            "ISC", "Zlib", "Python-2.0", "Unlicense", "MPL-2.0",
        ]}
    )

    # -- convenience accessors -------------------------------------------
    def threshold(self, key: str) -> float:
        return self.thresholds.get(key, _DEFAULT_THRESHOLDS.get(key, 0.0))

    def static_check(self, key: str) -> bool:
        return bool(self.static.get(key, _DEFAULT_STATIC.get(key, False)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "static": dict(self.static),
            "dynamic_enabled": self.dynamic_enabled,
            "formal_enabled": self.formal_enabled,
            "dynamic_backends": list(self.dynamic_backends),
            "num_shots": self.num_shots,
            "num_random_inputs": self.num_random_inputs,
            "significance_level": self.significance_level,
            "thresholds": dict(self.thresholds),
            "reporting_format": self.reporting_format,
            "fail_on": self.fail_on,
            "signatures_builtin": self.signatures_builtin,
            "signatures_community": self.signatures_community,
            "signature_paths": list(self.signature_paths),
            "license_policy": dict(self.license_policy),
        }


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(source: str | None = None) -> QShieldConfig:
    """Load configuration from a profile name or a YAML file path."""
    if source is None or source == "default":
        base: dict[str, Any] = {}
        profile = "default"
    elif source in _PROFILES:
        base = _PROFILES[source]
        profile = source
    else:
        path = Path(source).expanduser()
        if not path.exists():
            raise FileNotFoundError(
                f"Unknown config profile or missing file: {source!r}. "
                f"Built-in profiles: {', '.join(sorted(_PROFILES))}"
            )
        base = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        profile = f"file:{path}"

    static = _merge(_DEFAULT_STATIC, base.get("analysis", {}).get("static", {}) if isinstance(base.get("analysis"), dict) else {})
    # YAML shape: analysis.static can be either bool-map directly under analysis.static
    analysis = base.get("analysis", {}) or {}
    if isinstance(analysis.get("static"), dict):
        static = _merge(static, analysis["static"])

    thresholds = _merge(_DEFAULT_THRESHOLDS, base.get("thresholds", {}) or {})

    dynamic = bool(analysis.get("dynamic", False))
    formal = bool(analysis.get("formal", False))

    dynamic_cfg = analysis.get("dynamic", {}) if isinstance(analysis.get("dynamic"), dict) else {}
    backends = dynamic_cfg.get("backends", ["qshield_numpy_statevector"])
    if isinstance(dynamic, bool):
        pass
    else:
        dynamic = True  # a dynamic: map means enabled

    signatures = base.get("signatures", {}) or {}
    reporting = base.get("reporting", {}) or {}
    ci = base.get("ci", {}) or {}
    license_policy = {"allowed_licenses": [
        "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause",
        "ISC", "Zlib", "Python-2.0", "Unlicense", "MPL-2.0",
    ]}
    if isinstance(base.get("license_policy"), dict):
        license_policy = _merge(license_policy, base["license_policy"])

    unitary_max = int(static.get("unitary_max_qubits", _DEFAULT_STATIC["unitary_max_qubits"]))
    unitary_tol = float(static.get("unitary_tolerance", _DEFAULT_STATIC["unitary_tolerance"]))

    return QShieldConfig(
        profile=profile,
        static=static,
        dynamic_enabled=dynamic,
        formal_enabled=formal,
        dynamic_backends=list(backends),
        num_shots=int(dynamic_cfg.get("num_shots", 10_000)),
        num_random_inputs=int(dynamic_cfg.get("num_random_inputs", 8)),
        significance_level=float(dynamic_cfg.get("significance_level", 0.01)),
        thresholds=thresholds,
        reporting_format=str(reporting.get("format", "json")),
        fail_on=str(ci.get("fail_on", "high")),
        signatures_builtin=bool(signatures.get("use_builtin", True)),
        signatures_community=bool(signatures.get("use_community", False)),
        signature_paths=list(signatures.get("custom_paths", [])),
        unitary_max_qubits=unitary_max,
        unitary_tolerance=unitary_tol,
        license_policy=license_policy,
    )
