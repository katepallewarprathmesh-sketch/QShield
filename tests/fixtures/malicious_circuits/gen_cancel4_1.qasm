OPENQASM 2.0;
include "qelib1.inc";
qreg q[3];
creg c[3];
tdg q[0];
h q[2];
s q[2];
t q[0];
measure q -> c;
