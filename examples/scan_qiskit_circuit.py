"""QSHIELD with Qiskit objects (requires: pip install 'qshield[qiskit]')."""

import qshield

try:
    from qiskit import QuantumCircuit
except ImportError as exc:
    raise SystemExit("qiskit not installed; pip install 'qshield[qiskit]'") from exc

qc = QuantumCircuit(2)
qc.h(0)
qc.cx(0, 1)
qc.measure_all()

if __name__ == "__main__":
    scanner = qshield.Scanner(config="strict")
    scanner.add_circuit(qc, name="bell_from_qiskit")
    results = scanner.run()
    print(results.to_json())
