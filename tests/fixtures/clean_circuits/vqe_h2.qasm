OPENQASM 2.0;
include "qelib1.inc";
// Minimal 2-parameter VQE ansatz (UCCSD-inspired) for H2
qreg q[4];
creg c[4];
x q[0];
x q[1];
h q[0];
h q[1];
cx q[0], q[2];
cx q[1], q[3];
ry(0.3927) q[2];
cx q[2], q[3];
ry(0.3927) q[2];
cx q[2], q[3];
cx q[0], q[2];
cx q[1], q[3];
measure q -> c;
