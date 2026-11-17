OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T1.1 / ADV-001): eight micro-rotations, none above 0.01 rad
qreg q[2];
creg c[2];
h q[0];
rz(0.002) q[0];
cx q[0], q[1];
rz(0.003) q[1];
rx(0.004) q[0];
rz(0.0025) q[0];
cx q[0], q[1];
rz(0.0035) q[1];
rx(0.0015) q[0];
rz(0.0022) q[1];
measure q -> c;
