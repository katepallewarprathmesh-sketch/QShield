OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T1.1 / ADV-001): six micro-rotations accumulate on one qubit
qreg q[2];
creg c[2];
h q[0];
rx(0.005) q[0];
rx(0.006) q[0];
cx q[0], q[1];
rx(0.004) q[0];
rz(0.003) q[0];
rx(0.007) q[0];
rx(0.002) q[0];
measure q -> c;
