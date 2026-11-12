def test_minimal_sig(tmp_path):
    import qshield
    sig = tmp_path / "s.yaml"
    sig.write_text("id: \"QSig-2026-9991\"\nname: \"Test sig\"\n")
    scanner = qshield.Scanner()
    scanner.add_package("qiskit", version="1.2.0")
    scanner.add_requirements("qiskit==1.2.0\nurllib3==1.26.4\n")
    scanner.add_signatures(str(sig))
    results = scanner.run()
    print("MINIMAL-SIG FINDINGS:", [f.title for f in results.findings])

def test_body_of_Twin(tmp_path):
    import qshield
    sig = tmp_path / "s.yaml"
    sig.write_text("""id: "QSig-2026-9991"
name: "Test sig"
version: "1.0"
author: "test"
date: "2026-11-12"
severity: "low"
threat_type: "T1.3"
description: "test"
detection:
  method: "structural"
  structural_pattern:
    type: "leaf_ancilla"
    max_ancilla_uses: 1
""")
    scanner = qshield.Scanner()
    scanner.add_package("qiskit", version="1.2.0")
    scanner.add_requirements("qiskit==1.2.0\nurllib3==1.26.4\n")
    scanner.add_signatures(str(sig))
    results = scanner.run()
    print("FULL-SIG FINDINGS:", [f.title for f in results.findings])
