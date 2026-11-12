OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T2.1): ancilla receives a copy of raw input, then is measured and discarded
qreg q[3];
creg c[3];
h q[0];
cx q[0], q[2];
cx q[0], q[1];
h q[1];
measure q -> c;
