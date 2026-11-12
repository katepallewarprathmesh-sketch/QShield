"""QSHIELD quickstart: scan an OpenQASM circuit."""

import qshield

BELL = """
OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
measure q -> c;
"""

if __name__ == "__main__":
    results = qshield.scan(BELL, name="bell")
    print(results.to_json()[:800])
    print("clean:", results.is_clean)
