OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T1.3): z pair cancels, salted with unrelated gates between them
qreg q[3];
creg c[3];
h q[0];
cx q[0], q[1];
z q[0];
cx q[1], q[2];
h q[2];
z q[0];
measure q -> c;
