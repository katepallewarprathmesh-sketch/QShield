OPENQASM 2.0;
include "qelib1.inc";
// Clean: magic state preparation (H then T)
qreg q[2];
creg c[2];
h q[0];
t q[0];
h q[1];
t q[1];
cx q[0], q[1];
measure q -> c;
