#!/usr/bin/env python3
"""Minimal Sarvam AI sanity check: one chat completion.

Reads SARVAM_API_KEY from the environment or from a local .env file
(gitignored). Never hardcodes or prints the key.
"""
import os
import sys
from pathlib import Path

from sarvamai import SarvamAI


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_dotenv(Path(__file__).resolve().parents[1] / ".env")

key = os.environ.get("SARVAM_API_KEY")
if not key:
    sys.exit("SARVAM_API_KEY is not set — add it to .env (see .gitignore) or export it.")

client = SarvamAI(api_subscription_key=key)

response = client.chat.completions(
    model="sarvam-105b-conversations",
    messages=[
        {"role": "user", "content": "Reply with exactly one short sentence: confirm you are reachable."}
    ],
)
print(response.choices[0].message.content)
