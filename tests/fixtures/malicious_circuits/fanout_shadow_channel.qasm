OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T2.1 / ADV-002 style): control fans out to four targets (shadow correlations)
qreg q[5];
creg c[5];
h q[0];
cx q[0], q[1];
cx q[0], q[2];
cx q[0], q[3];
cx q[0], q[4];
cx q[0], q[1];
cx q[0], q[2];
measure q -> c;
