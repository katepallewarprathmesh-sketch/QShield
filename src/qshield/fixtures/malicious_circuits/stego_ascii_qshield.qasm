OPENQASM 2.0;
include "qelib1.inc";
// TROJAN (T2.2): rotation angles encode ASCII payload 'QSHIELD' on a pi/4096 grid
qreg q[4];
creg c[4];
h q[0];
rz(0.062126221909368465) q[0];
rz(0.06366020269725411) q[1];
rz(0.05522330836388308) q[2];
rz(0.0559902987578259) q[3];
rz(0.05292233718205462) q[0];
rz(0.05829126993965436) q[1];
rz(0.0521553467881118) q[2];
cx q[0], q[1];
measure q -> c;
