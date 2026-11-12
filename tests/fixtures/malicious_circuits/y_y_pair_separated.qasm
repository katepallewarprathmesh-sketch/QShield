OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T1.3): Y-Y identity pair separated by unrelated-qubit gates
qreg q[3];
creg c[3];
y q[0];
h q[2];
s q[2];
cx q[1], q[2];
y q[0];
measure q -> c;
