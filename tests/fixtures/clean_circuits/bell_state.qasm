OPENQASM 2.0;
include "qelib1.inc";
// Clean 2-qubit Bell state
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
measure q -> c;
