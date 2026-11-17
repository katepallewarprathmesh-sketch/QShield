OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T1.3): CX pair separated by gates on an unrelated qubit
qreg q[3];
creg c[3];
h q[2];
cx q[0], q[1];
s q[2];
cx q[0], q[1];
measure q -> c;
