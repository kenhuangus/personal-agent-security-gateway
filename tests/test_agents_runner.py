"""Pillar 2 §1.3: ``python -m agents.runner`` fail-closed startup.

The runner is the agents-side scheduler loop. It must refuse to start
when the master switch is off (``GATEWAY_AGENTS_ENABLED != 1``,
default-off), and when the gateway itself is unreachable — never
dispatching red-team runs into a void.
"""

from __future__ import annotations

import pytest

from agents import runner


def test_runner_refuses_when_agents_disabled(monkeypatch, capsys):
    monkeypatch.delenv("GATEWAY_AGENTS_ENABLED", raising=False)
    assert runner.main() == 2
    err = capsys.readouterr().err
    assert "GATEWAY_AGENTS_ENABLED != 1" in err


def test_runner_refuses_when_gateway_unreachable(monkeypatch, capsys):
    # Enabled, but no gateway on the loopback port → fail closed
    # instead of scheduling runs against nothing.
    monkeypatch.setenv("GATEWAY_AGENTS_ENABLED", "1")
    monkeypatch.setenv("GATEWAY_PORT", "1")  # nothing listens here
    monkeypatch.setenv("GATEWAY_HMAC_KEY", "test-hmac-key-material-32bytes!")
    # Point the health check at the unroutable port; it must fail
    # closed instead of scheduling runs against nothing.
    assert runner.main() == 2
    err = capsys.readouterr().err
    assert "refusing to start" in err
