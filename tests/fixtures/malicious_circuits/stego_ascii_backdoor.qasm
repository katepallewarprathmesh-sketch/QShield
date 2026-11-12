OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T2.2): rotation angles encode ASCII payload 'BACKDOOR' on a pi/4096 grid
qreg q[4];
creg c[4];
h q[0];
rz(0.05062136600022616) q[0];
rz(0.049854375606283335) q[1];
rz(0.05138835639416898) q[2];
rz(0.05752427954571154) q[3];
rz(0.0521553467881118) q[0];
rz(0.06059224112148283) q[1];
rz(0.06059224112148283) q[2];
rz(0.06289321230331128) q[3];
cx q[0], q[1];
measure q -> c;
