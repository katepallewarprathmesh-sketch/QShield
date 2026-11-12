OPENQASM 2.0;
include "qelib1.inc";
// Clean: Deutsch algorithm on one qubit (balanced function)
qreg q[1];
creg c[1];
x q[0];
h q[0];
z q[0];
h q[0];
measure q[0] -> c[0];
