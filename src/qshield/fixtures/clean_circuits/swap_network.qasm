OPENQASM 2.0;
include "qelib1.inc";
// Clean: ring swap network used for qubit reordering between rounds
qreg q[3];
creg c[3];
swap q[0], q[1];
swap q[1], q[2];
swap q[0], q[1];
swap q[1], q[2];
measure q -> c;
