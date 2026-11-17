OPENQASM 2.0;
include "qelib1.inc";
// Clean: ZZ interaction via cx-rz-cx (Ising evolution fragment)
qreg q[3];
creg c[3];
h q[0];
h q[1];
h q[2];
cx q[0], q[1];
rz(0.7) q[1];
cx q[0], q[1];
cx q[1], q[2];
rz(0.7) q[2];
cx q[1], q[2];
measure q -> c;
