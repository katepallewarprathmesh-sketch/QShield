OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T2.1): q[2] receives a deterministic copy of raw input q[0]
// BEFORE any mixing gate — classic ancilla exfiltration pattern.
qreg q[3];
creg c[3];
cx q[0], q[2];
h q[0];
cx q[0], q[1];
measure q -> c;
