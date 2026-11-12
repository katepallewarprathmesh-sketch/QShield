OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T2.1): swap dumps raw input into an ancilla that is then measured
qreg q[3];
creg c[3];
h q[0];
cx q[0], q[1];
swap q[0], q[2];
measure q -> c;
