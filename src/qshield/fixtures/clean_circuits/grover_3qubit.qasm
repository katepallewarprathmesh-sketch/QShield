OPENQASM 2.0;
include "qelib1.inc";
// 3-qubit Grover search for |101> (one iteration, textbook construction)
qreg q[3];
creg c[3];
h q[0];
h q[1];
h q[2];
// oracle for 101: X on q[1], CCZ via ccx with q[1] flipped
x q[1];
ccx q[0], q[1], q[2];
cz q[0], q[2];
ccx q[0], q[1], q[2];
x q[1];
// diffusion
h q[0];
h q[1];
h q[2];
x q[0];
x q[1];
x q[2];
ccx q[0], q[1], q[2];
h q[2];
ccx q[0], q[1], q[2];
h q[2];
x q[0];
x q[1];
x q[2];
h q[0];
h q[1];
h q[2];
measure q -> c;
