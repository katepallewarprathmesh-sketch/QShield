OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T1.1 / ADV-001): perturbation smeared across 8 micro-rotations
qreg q[2];
creg c[2];
h q[0];
rz(0.001) q[0];
cx q[0], q[1];
rz(0.001) q[0];
rz(0.001) q[1];
rz(0.001) q[0];
rz(0.001) q[1];
rz(0.001) q[0];
rz(0.001) q[1];
rz(0.001) q[0];
rz(0.001) q[1];
measure q -> c;
