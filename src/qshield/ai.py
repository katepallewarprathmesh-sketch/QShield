"""Optional AI assistance via Sarvam AI (cloud) — ADVISORY ONLY.

NOT part of the offline core: nothing in this module runs unless you invoke
`qshield ai ...` explicitly. Findings (not the raw circuit source) are sent to
Sarvam AI's cloud API. LLM output is a lead for a human auditor — never a
verdict, never proof that a circuit is honest.

Requires: pip install sarvamai  and  SARVAM_API_KEY in the environment or a
gitignored .env file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

CHAT_MODEL = "sarvam-105b-conversations"
STT_MODEL = "saaras:v4"
TTS_MODEL = "bulbul:v4-flash"
TRANSLATE_MODEL = "sarvam-translate:v1"
DEFAULT_SPEAKER = "simran_en_customer"

_DISCLAIMER = "AI-advisory (Sarvam AI, cloud) — verify against the evidence. LLM output is not a verdict."


class SarvamUnavailable(RuntimeError):
    pass


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _client():
    repo_root = Path(__file__).resolve().parents[2]
    _load_dotenv(Path.cwd() / ".env")
    _load_dotenv(repo_root / ".env")
    key = os.environ.get("SARVAM_API_KEY")
    if not key:
        raise SarvamUnavailable(
            "SARVAM_API_KEY is not set. Add it to .env (gitignored) or export it. "
            "Get a key at https://indus.sarvam.ai/key-management"
        )
    try:
        from sarvamai import SarvamAI
    except ImportError as exc:
        raise SarvamUnavailable("The 'sarvamai' package is required: pip install sarvamai") from exc
    return SarvamAI(api_subscription_key=key)


def _payload(results, circuit_name: str) -> dict:
    findings = []
    for f in results.findings:
        findings.append(
            {
                "id": f.finding_id,
                "severity": f.severity,
                "threat_type": f.threat_type,
                "title": f.title,
                "description": f.description,
                "confidence": round(f.confidence, 3),
                "false_positive_probability": round(f.false_positive_probability, 3),
                "gate_indices": list(f.location.gate_indices),
                "qubit_indices": list(f.location.qubit_indices),
                "remediation": f.remediation,
            }
        )
    s = results.summary
    return {
        "circuit": circuit_name,
        "summary": {
            "total": s.total,
            "critical": s.critical,
            "high": s.high,
            "medium": s.medium,
            "low": s.low,
            "info": s.info,
        },
        "findings": findings,
    }


def scan_findings(path: Path) -> dict:
    """Run the local static + supply-chain analyzer and return a compact payload."""
    from qshield.scanner import Scanner

    sc = Scanner(config="default")
    sc.add_circuit(str(path), name=path.stem)
    results = sc.run(analyses=["static", "supply_chain"])
    return _payload(results, path.name)


def scan_findings_ir(ir, name: str = "workbench") -> dict:
    """Same payload, from an already-parsed CircuitIR (e.g. in-memory Workbench uploads)."""
    from qshield.scanner import Scanner

    sc = Scanner(config="default", parallel=False)
    sc.add_circuit(ir)
    results = sc.run(analyses=["static"])
    return _payload(results, name)


def configured() -> bool:
    """True if a SARVAM_API_KEY is discoverable (env or gitignored .env). Never reveals it."""
    repo_root = Path(__file__).resolve().parents[2]
    _load_dotenv(Path.cwd() / ".env")
    _load_dotenv(repo_root / ".env")
    return bool(os.environ.get("SARVAM_API_KEY"))


def disclaimer() -> str:
    return _DISCLAIMER


def triage(payload: dict) -> str:
    client = _client()
    system = (
        "You are an auditor's assistant for quantum-circuit supply-chain security. "
        "You receive structured static-analysis findings (not the raw circuit). "
        "For each finding give: (1) what it means in plain English, "
        "(2) whether it is likely a true positive or deserves a second look — and why, "
        "(3) priority order for remediation. Then give one overall disposition: "
        "BLOCK / REVIEW / TRACK. Be explicit about uncertainty. Never claim the circuit "
        "is 'safe' or 'secure'; your output is advisory leads, not a verdict."
    )
    response = client.chat.completions(
        model=CHAT_MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(payload, indent=2)},
        ],
    )
    return response.choices[0].message.content


def tts_bytes(text: str, language_code: str = "hi-IN", speaker: str = DEFAULT_SPEAKER) -> bytes:
    """Synthesize speech in memory; returns audio bytes."""
    import base64

    client = _client()
    audio = client.text_to_speech.convert(
        text=text, language_code=language_code, model=TTS_MODEL, speaker=speaker
    )
    data = getattr(audio, "audios", None)
    if not data:
        raise SarvamUnavailable("Sarvam TTS returned no audio payload")
    return base64.b64decode("".join(data))


def stt_bytes(data: bytes, mode: str = "transcribe") -> str:
    """Transcribe audio bytes; no temp files."""
    import io

    client = _client()
    response = client.speech_to_text.transcribe(file=io.BytesIO(data), model=STT_MODEL, mode=mode)
    return response.transcript


def speak(text: str, out: Path, language_code: str = "hi-IN", speaker: str = DEFAULT_SPEAKER) -> Path:
    out.write_bytes(tts_bytes(text, language_code=language_code, speaker=speaker))
    return out


def listen(path: Path, mode: str = "transcribe") -> str:
    return stt_bytes(path.read_bytes(), mode=mode)


def translate(text: str, target_language_code: str, source_language_code: str = "en-IN") -> str:
    client = _client()
    response = client.text.translate(
        input=text,
        source_language_code=source_language_code,
        target_language_code=target_language_code,
        model=TRANSLATE_MODEL,
        mode="formal",
    )
    return getattr(response, "translated_text", None) or getattr(response, "translation", None) or str(response)


def english_report(payload: dict) -> str:
    s = payload["summary"]
    lines = [
        f"QSHIELD audit report for {payload['circuit']}.",
        f"Findings: {s['total']} total — {s['critical']} critical, {s['high']} high, "
        f"{s['medium']} medium, {s['low']} low, {s['info']} info.",
    ]
    for f in payload["findings"][:10]:
        lines.append(
            f"[{f['severity'].upper()}] {f['threat_type']} — {f['title']} (confidence {f['confidence']:.2f}). "
            f"Remediation: {f['remediation']}"
        )
    lines.append("Evidence from static analysis — not a proof of honesty. Human review recommended.")
    return "\n".join(lines)
