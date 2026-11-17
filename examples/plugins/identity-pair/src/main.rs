use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read, Write};

#[derive(Deserialize)]
struct Input {
    api_version: String,
    circuit: Circuit,
}

#[derive(Deserialize)]
struct Circuit {
    gates: Vec<Gate>,
}

#[derive(Deserialize)]
struct Gate {
    gate_id: String,
    gate_name: String,
    qubits: Vec<usize>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input_bytes = Vec::new();
    io::stdin().read_to_end(&mut input_bytes)?;
    let input: Input = serde_json::from_slice(&input_bytes)?;
    if input.api_version != "1" {
        return Err("unsupported QSHIELD plugin API version".into());
    }

    let mut findings = Vec::new();
    for pair in input.circuit.gates.windows(2) {
        if pair[0].gate_name == "x" && pair[1].gate_name == "x" && pair[0].qubits == pair[1].qubits {
            findings.push(json!({
                "code": "EXAMPLE-ADJACENT-X-PAIR",
                "severity": "info",
                "message": "Adjacent X gates on the same qubit cancel; review whether this pair is intentional.",
                "gate_ids": [pair[0].gate_id, pair[1].gate_id]
            }));
        }
    }

    let response: Value = json!({"api_version": "1", "findings": findings});
    serde_json::to_writer(io::stdout().lock(), &response)?;
    io::stdout().write_all(b"\n")?;
    Ok(())
}
