"""Contract tests for AI readiness reporting."""
from __future__ import annotations

from qshield import ai


def test_readiness_reports_configured_when_key_and_sdk_present(monkeypatch) -> None:
    monkeypatch.setattr(ai, "_has_key", lambda: True)
    monkeypatch.setattr(ai, "_has_sdk", lambda: True)
    state = ai.readiness()
    assert state["configured"] is True
    assert state["reason"] == ""
    assert ai.configured() is True


def test_readiness_distinguishes_missing_key_from_missing_sdk(monkeypatch) -> None:
    monkeypatch.setattr(ai, "_has_key", lambda: False)
    monkeypatch.setattr(ai, "_has_sdk", lambda: True)
    missing_key = ai.readiness()
    assert missing_key["configured"] is False
    assert missing_key["key_present"] is False
    assert "SARVAM_API_KEY" in missing_key["reason"]

    monkeypatch.setattr(ai, "_has_key", lambda: True)
    monkeypatch.setattr(ai, "_has_sdk", lambda: False)
    missing_sdk = ai.readiness()
    assert missing_sdk["configured"] is False
    assert missing_sdk["key_present"] is True
    assert missing_sdk["sdk_installed"] is False
    assert "sarvamai" in missing_sdk["reason"]


def test_configured_requires_the_sdk_not_just_the_key(monkeypatch) -> None:
    """A key alone is not enough: the run path imports sarvamai and would fail."""
    monkeypatch.setattr(ai, "_has_key", lambda: True)
    monkeypatch.setattr(ai, "_has_sdk", lambda: False)
    assert ai.configured() is False


def test_readiness_never_returns_the_key(monkeypatch) -> None:
    monkeypatch.setenv("SARVAM_API_KEY", "sk_secret_value_do_not_leak")
    monkeypatch.setattr(ai, "_has_key", lambda: True)
    monkeypatch.setattr(ai, "_has_sdk", lambda: True)
    dumped = repr(ai.readiness())
    assert "sk_secret_value_do_not_leak" not in dumped
