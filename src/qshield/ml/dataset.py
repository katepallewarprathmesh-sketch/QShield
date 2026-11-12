"""Labeled circuit dataset loader (spec M3.2 training pipeline).

Loads QASM fixtures from ``tests/fixtures/clean_circuits`` (label 0) and
``tests/fixtures/malicious_circuits`` (label 1).  Fixtures that fail to
parse are skipped and counted — never silently relabeled.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from qshield.core.circuit_ir import CircuitIR
from qshield.core.parsers import parse_any

ROOT = Path(__file__).resolve().parents[3]
CLEAN_DIR = ROOT / "tests" / "fixtures" / "clean_circuits"
MALICIOUS_DIR = ROOT / "tests" / "fixtures" / "malicious_circuits"

LABEL_CLEAN = 0
LABEL_MALICIOUS = 1


@dataclass
class LabeledCircuit:
    ir: CircuitIR
    label: int          # LABEL_CLEAN | LABEL_MALICIOUS
    name: str

    @property
    def is_malicious(self) -> bool:
        return self.label == LABEL_MALICIOUS


@dataclass
class DatasetStats:
    total: int
    clean: int
    malicious: int
    skipped: list[tuple[str, str]]  # (filename, error)


def load_fixture_dataset(
    clean_dir: Path | None = None,
    malicious_dir: Path | None = None,
) -> tuple[list[LabeledCircuit], DatasetStats]:
    clean_dir = clean_dir or CLEAN_DIR
    malicious_dir = malicious_dir or MALICIOUS_DIR
    items: list[LabeledCircuit] = []
    skipped: list[tuple[str, str]] = []
    n_clean = n_mal = 0
    for directory, label in ((clean_dir, LABEL_CLEAN), (malicious_dir, LABEL_MALICIOUS)):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.qasm")):
            try:
                ir = parse_any(str(path))
            except Exception as exc:
                skipped.append((path.name, str(exc)))
                continue
            items.append(LabeledCircuit(ir=ir, label=label, name=path.stem))
            if label == LABEL_CLEAN:
                n_clean += 1
            else:
                n_mal += 1
    return items, DatasetStats(total=len(items), clean=n_clean,
                               malicious=n_mal, skipped=skipped)
