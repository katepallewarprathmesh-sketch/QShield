OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T1.3): adjacent H-H pair (identity obfuscation)
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
h q[0];
h q[0];
measure q -> c;
