"""Configuration and audit guarantees for the runtime gate hardening."""

import json
import os

import pytest

from qshield.runtime.alerting import Alert, AlertRouter
from qshield.runtime.proxy import ProxyConfig, QShieldProxy, load_bearer_tokens


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


def test_bearer_token_config_is_scoped_and_redacted_from_repr():
    secret = "s" * 48
    config = ProxyConfig(auth_tokens={secret: ["proxy:read", "proxy:submit"]})
    assert config.auth_tokens[secret] == ("proxy:read", "proxy:submit")
    assert secret not in repr(config)
    with pytest.raises(ValueError, match="32 to 8192"):
        ProxyConfig(auth_tokens={"short": ["proxy:read"]})
    with pytest.raises(ValueError, match="scopes"):
        ProxyConfig(auth_tokens={secret: ["root"]})
    with pytest.raises(ValueError, match="bearer-token alphabet"):
        ProxyConfig(auth_tokens={"é" * 32: ["proxy:read"]})


def test_token_file_requires_restrictive_permissions_and_loads_scopes(tmp_path):
    secret = "t" * 48
    token_file = tmp_path / "tokens.json"
    token_file.write_text(json.dumps({"tokens": [{"token": secret, "scopes": ["proxy:read"]}]}))
    token_file.chmod(0o600)
    assert load_bearer_tokens(token_file) == {secret: ("proxy:read",)}
    if os.name == "posix":
        token_file.chmod(0o644)
        with pytest.raises(ValueError, match="permissions"):
            load_bearer_tokens(token_file)


def test_remote_bind_requires_tls_auth_or_trusted_front_proxy():
    with pytest.raises(ValueError, match="non-loopback binds require TLS"):
        QShieldProxy(ProxyConfig(), host="0.0.0.0")  # noqa: S104 - verifies remote-bind protection
    with pytest.raises(ValueError, match="certificate and private key"):
        QShieldProxy(ProxyConfig(), host="127.0.0.1", tls_certfile="cert.pem")
    with pytest.raises(ValueError, match="client certificate authentication requires TLS"):
        QShieldProxy(ProxyConfig(), client_ca_file="ca.pem")


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
