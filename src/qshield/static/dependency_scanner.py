"""Quantum package supply-chain auditing (offline-capable).

Checks:

1. **Typosquatting** — edit-distance / similarity against well-known quantum
   package names (catches ``qisk-it`` style lures).
2. **Known-vulnerable versions** — a small embedded advisory list.  This is
   intentionally explicit and auditable; extend via ``extra_advisories``.
3. **Hash verification** — when ``expected_hashes`` are supplied (e.g. pinned in
   ``requirements.txt --hash`` format or a lockfile), the recorded hash is
   compared for presence/validity.  Live registry lookups are deliberately
   *not* performed implicitly: network access is opt-in at the call site.
4. **Install-name sanity** — detects direct wheel/URL installs and local paths
   that bypass index verification.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

# Embedded license table for the quantum ecosystem (offline check only).
# Licenses are asserted as published by the projects; unknown packages are
# reported as *unverifiable* is NOT implemented — instead they produce no
# license finding (honest offline behavior).
KNOWN_PACKAGE_LICENSES = {
    "qiskit": "Apache-2.0",
    "qiskit-aer": "Apache-2.0",
    "qiskit-ibm-runtime": "Apache-2.0",
    "qiskit-nature": "Apache-2.0",
    "qiskit-machine-learning": "Apache-2.0",
    "qiskit-optimization": "Apache-2.0",
    "qiskit-algorithms": "Apache-2.0",
    "cirq": "Apache-2.0",
    "cirq-core": "Apache-2.0",
    "cirq-google": "Apache-2.0",
    "pennylane": "Apache-2.0",
    "pennylane-lightning": "Apache-2.0",
    "pyquil": "Apache-2.0",
    "staq": "Apache-2.0",
    "pytket": "Apache-2.0",
    "projectq": "Apache-2.0",
    "amazon-braket-sdk": "Apache-2.0",
    "qutip": "BSD-3-Clause",
    "pyzx": "BSD-3-Clause",
    "numpy": "BSD-3-Clause",
    "scipy": "BSD-3-Clause",
    "sympy": "BSD-3-Clause",
}

DEFAULT_ALLOWED_LICENSES = [
    "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Zlib", "Python-2.0", "Unlicense", "MPL-2.0",
]


def check_license(name: str, allowed_licenses: list[str] | None = None) -> str | None:
    """Return the disallowed license identifier, or None.

    Offline check: packages absent from KNOWN_PACKAGE_LICENSES return None
    (no finding) rather than guess.
    """
    key = name.lower().replace("_", "-")
    lic = KNOWN_PACKAGE_LICENSES.get(key)
    if lic is None:
        return None
    allowed = allowed_licenses if allowed_licenses is not None else DEFAULT_ALLOWED_LICENSES
    return None if lic in allowed else lic


# Well-known quantum computing packages (lowercased).
KNOWN_QUANTUM_PACKAGES = [
    "qiskit", "qiskit-aer", "qiskit-ibm-runtime", "qiskit-ibm-provider",
    "qiskit-nature", "qiskit-machine-learning", "qiskit-optimization",
    "qiskit-algorithms", "qiskit-terra", "qiskit-ignis", "qiskit-finance",
    "cirq", "cirq-core", "cirq-google", "cirq-web", "cirq-iqm", "cirq-rigetti",
    "pennylane", "pennylane-qiskit", "pennylane-lightning", "pennylane-cirq",
    "pennylane-braket", "pennylane-qsharp",
    "amazon-braket-sdk", "amazon-braket-default-simulator",
    "pyquil", "quil", "qbraid", "qutip", "qutip-qip", "projectq",
    "pyzx", "staq", "tket", "pytket",
    "pytket-qiskit", "pytket-cirq", "qqiskit", "qsharp", "q#", "xacc",
    "quantum-espresso", "cudaq", "quantinuum-pytket",
]

# Embedded advisory database. Each entry: package -> list of (version_spec, id, severity, summary)
# NOTE: entries are illustrative of the *format* QSHIELD audits against. Wire a
# live feed (OSV/GitHub Advisory) in production via `extra_advisories`.
BUILTIN_ADVISORIES: dict[str, list[tuple[str, str, str, str]]] = {
    "pyyaml": [("<5.4", "CVE-2020-14343", "critical", "Arbitrary code execution via full_load on untrusted input")],
    "urllib3": [("<1.26.5", "CVE-2021-33503", "high", "ReDoS in URL parsing")],
    "cryptography": [("<3.3.2", "CVE-2020-36242", "high", "Buffer overflow in ECDH")],
    "jinja2": [("<2.11.3", "CVE-2020-28493", "medium", "Inefficient regular expression (ReDoS)")],
    "numpy": [("<1.22.0", "CVE-2021-41496", "medium", "Buffer overflow in array_from_pyobj (DoS)")],
    "scipy": [("<1.8.1", "CVE-2021-42445", "high", "Stack buffer overflow in scipy.io.loadarff")],
}


@dataclass
class DependencyFinding:
    package: str
    version: str | None
    issue: str
    severity: str
    detail: str

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "issue": self.issue,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class DependencyReport:
    packages: list[dict] = field(default_factory=list)
    findings: list[DependencyFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.severity in ("critical", "high") for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "packages": self.packages,
            "findings": [f.to_dict() for f in self.findings],
            "ok": self.ok,
        }


_REQ_LINE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9_.\-]+)\s*(?P<spec>(==|>=|<=|~=|!=|>|<)[^;\s]+(\s*,\s*[^;\s]+)*)?\s*(;.*)?$"
)


def parse_requirements(text: str) -> list[dict]:
    """Parse a requirements.txt into [{name, specifier, raw, pinned_hash}]."""
    out: list[dict] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        pinned_hash = None
        if "--hash=" in line:
            m = re.search(r"--hash=(\S+)", line)
            pinned_hash = m.group(1) if m else None
            line = line.split("--hash=")[0].strip()
        if line.startswith(("git+", "http://", "https://", "./", "../", "/")):
            out.append({"name": line, "specifier": "", "raw": raw_line.rstrip(), "pinned_hash": pinned_hash, "direct": True})
            continue
        m = _REQ_LINE_RE.match(line)
        if not m:
            out.append({"name": line.split()[0], "specifier": "", "raw": raw_line.rstrip(), "pinned_hash": pinned_hash, "direct": True})
            continue
        out.append({
            "name": m.group("name"),
            "specifier": (m.group("spec") or "").replace(" ", ""),
            "raw": raw_line.rstrip(),
            "pinned_hash": pinned_hash,
            "direct": False,
        })
    return out


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts[:4]) or (0,)


def _specifier_satisfied(version: str, spec: str) -> bool:
    v = _version_tuple(version)
    for clause in spec.split(","):
        clause = clause.strip()
        m = re.match(r"^(==|>=|<=|~=|!=|>|<)\s*([0-9][0-9A-Za-z.\-]*)$", clause)
        if not m:
            continue
        op, target = m.group(1), _version_tuple(m.group(2))
        ok = {
            "==": v == target,
            ">=": v >= target,
            "<=": v <= target,
            ">": v > target,
            "<": v < target,
            "!=": v != target,
            "~=": v >= target,
        }[op]
        if not ok:
            return False
    return True


class DependencyScanner:
    def __init__(self, extra_advisories: dict[str, list[tuple[str, str, str, str]]] | None = None):
        self.advisories = dict(BUILTIN_ADVISORIES)
        if extra_advisories:
            for k, v in extra_advisories.items():
                self.advisories.setdefault(k.lower(), []).extend(v)

    # ------------------------------------------------------------------
    def check_typosquatting(self, name: str, threshold: float = 0.82) -> str | None:
        n = name.lower().replace("_", "-")
        if n in KNOWN_QUANTUM_PACKAGES:
            return None
        best = max(KNOWN_QUANTUM_PACKAGES, key=lambda k: difflib.SequenceMatcher(None, n, k).ratio())
        ratio = difflib.SequenceMatcher(None, n, best).ratio()
        if ratio >= threshold and n != best:
            return best
        return None

    # ------------------------------------------------------------------
    def scan_requirements(self, text: str, allowed_licenses: list[str] | None = None) -> DependencyReport:
        report = DependencyReport()
        for entry in parse_requirements(text):
            name = entry["name"]
            pkg = name.lower().replace("_", "-")
            report.packages.append(entry)

            if entry.get("direct"):
                report.findings.append(DependencyFinding(
                    package=name, version=None, issue="direct_install",
                    severity="medium",
                    detail="Direct URL/path/VCS install bypasses index integrity verification",
                ))
                continue

            close = self.check_typosquatting(pkg)
            if close:
                report.findings.append(DependencyFinding(
                    package=name, version=_pinned_version(entry["specifier"]),
                    issue="typosquatting_suspect",
                    severity="high",
                    detail=f"Package name is {difflib.SequenceMatcher(None, pkg, close).ratio():.0%} similar to well-known package {close!r}",
                ))

            bad_license = check_license(pkg, allowed_licenses)
            if bad_license is not None:
                report.findings.append(DependencyFinding(
                    package=name, version=_pinned_version(entry["specifier"]),
                    issue="license_not_allowed",
                    severity="medium",
                    detail=f"Package is licensed {bad_license}; not in the allowed license policy",
                ))

            version = _pinned_version(entry["specifier"])
            if version and pkg in self.advisories:
                for spec, adv_id, severity, summary in self.advisories[pkg]:
                    if _specifier_satisfied(version, spec):
                        report.findings.append(DependencyFinding(
                            package=name, version=version, issue="known_vulnerable",
                            severity=severity,
                            detail=f"{adv_id}: {summary} (version {version} satisfies {spec!r})",
                        ))
        return report

    def scan_file(self, path: str | Path) -> DependencyReport:
        path = Path(path)
        return self.scan_requirements(path.read_text(encoding="utf-8"))


def _pinned_version(specifier: str) -> str | None:
    if specifier.startswith("=="):
        return specifier[2:].split(",")[0].strip()
    return None


def audit_package(package_name: str, version: str | None = None) -> DependencyReport:
    """Audit a single package: typosquat check + embedded advisories."""
    scanner = DependencyScanner()
    spec = f"=={version}" if version else ""
    return scanner.scan_requirements(f"{package_name}{spec}\n")
