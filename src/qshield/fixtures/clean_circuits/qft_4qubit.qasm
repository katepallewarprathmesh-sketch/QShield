OPENQASM 2.0;
include "qelib1.inc";
// Clean: 4-qubit quantum Fourier transform
qreg q[4];
creg c[4];
h q[0];
crz(1.5707963267948966) q[1], q[0];
crz(0.7853981633974483) q[2], q[0];
crz(0.39269908169872414) q[3], q[0];
h q[1];
crz(1.5707963267948966) q[2], q[1];
crz(0.7853981633974483) q[3], q[1];
h q[2];
crz(1.5707963267948966) q[3], q[2];
h q[3];
swap q[0], q[3];
swap q[1], q[2];
measure q -> c;
