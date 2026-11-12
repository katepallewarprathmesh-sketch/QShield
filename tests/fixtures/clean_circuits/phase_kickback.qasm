OPENQASM 2.0;
include "qelib1.inc";
// Clean: phase kickback — interference without basis change at the end
qreg q[2];
creg c[2];
h q[0];
x q[1];
cz q[0], q[1];
measure q -> c;
