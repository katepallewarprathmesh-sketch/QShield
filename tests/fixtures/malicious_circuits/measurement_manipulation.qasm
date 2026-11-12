OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T2.3): basis rotation forced immediately before every measurement
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
h q[0];
h q[1];
measure q -> c;
