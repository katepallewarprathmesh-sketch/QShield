OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T1.3): s ... sdg pair cancels; intervening gates touch other qubits only
qreg q[3];
creg c[3];
h q[1];
cx q[1], q[2];
s q[0];
h q[2];
cx q[1], q[2];
h q[1];
sdg q[0];
measure q -> c;
