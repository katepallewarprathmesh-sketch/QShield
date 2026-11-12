"""Audit a requirements.txt for quantum supply-chain risk."""

from qshield.static.dependency_scanner import DependencyScanner

REQUIREMENTS = """
qiskit==0.45.0
qiskit-aer==0.12.0
pynnylane>=0.33
urllib3==1.26.4
"""

if __name__ == "__main__":
    report = DependencyScanner().scan_requirements(REQUIREMENTS)
    print(report.to_dict())
    print("ok:", report.ok)
