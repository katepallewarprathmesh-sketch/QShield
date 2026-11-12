"""QSHIELD with Cirq objects (requires: pip install 'qshield[cirq]')."""

import qshield

try:
    import cirq
except ImportError as exc:
    raise SystemExit("cirq not installed; pip install 'qshield[cirq]'") from exc

q0, q1 = cirq.LineQubit.range(2)
circuit = cirq.Circuit(cirq.H(q0), cirq.CNOT(q0, q1), cirq.measure(q0, q1))

if __name__ == "__main__":
    scanner = qshield.Scanner()
    scanner.add_circuit(circuit, name="bell_from_cirq")
    results = scanner.run()
    print(results.to_json())
