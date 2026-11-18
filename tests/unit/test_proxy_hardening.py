"""Configuration and audit guarantees for the runtime gate hardening."""

import pytest

from qshield.runtime.alerting import Alert, AlertRouter
from qshield.runtime.proxy import ProxyConfig


def test_failure_mode_defaults_are_explicit_by_policy_mode():
    assert ProxyConfig().failure_mode == "open"
    assert ProxyConfig(policy="enforce").failure_mode == "closed"
    assert ProxyConfig(policy="enforce", failure_mode="open").failure_mode == "open"


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"failure_mode": "maybe"}, "failure_mode"),
        ({"policy_version": ""}, "policy_version"),
        ({"max_workers": 0}, "max_workers"),
        ({"request_queue_size": 0}, "request_queue_size"),
        ({"upstream_timeout": float("nan")}, "finite"),
        ({"upstream": "//relative/path"}, "absolute http"),
        ({"upstream": "https://user:password@example.test"}, "credentials"),
        ({"extra_headers": {"X-QShield-Decision": "allow"}}, "reserved"),
        ({"extra_headers": {"X-Example": "ok\r\nInjected: yes"}}, "single-line"),
    ],
)
def test_proxy_rejects_unsafe_configuration(kwargs, message):
    with pytest.raises(ValueError, match=message):
        ProxyConfig(**kwargs)


def test_audit_events_bypass_alert_severity_threshold():
    class Sink:
        def __init__(self):
            self.events = []

        def emit(self, event):
            self.events.append(event)

    sink = Sink()
    router = AlertRouter(sinks=[sink], min_severity="critical")
    router.emit(Alert(severity="info", category="gate.decision", message="filtered normally"))
    assert sink.events == []
    router.emit_audit(Alert(severity="info", category="gate.decision", message="always logged"))
    assert [event.message for event in sink.events] == ["always logged"]
