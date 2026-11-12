OPENQASM 2.0;
include "qelib1.inc";
qreg q[3];
creg c[3];
cx q[0], q[1];
h q[2];
s q[2];
cx q[0], q[1];
measure q -> c;
