"""Tests for OpaClient external mode (GATEWAY_OPA_URL).

Covers the docker-compose deployment path: no sidecar subprocess is
launched, decisions go to the given URL, and the fail-closed contract
is identical (any failure -> OpaUnavailable -> the policy engine
denies). Uses a tiny in-process fake OPA server; no binary needed.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from gateway.opa_client import OpaClient, OpaUnavailable, bundle_fingerprint

GOOD_DECISION = {"result": {"effect": "allow", "rule": "r1"}}

#: The pinned bundle's fingerprint, served by the fake OPA's bundle-info
#: endpoint (GH #17: external mode verifies it at startup).
GOOD_BUNDLE_INFO = {"result": {"fingerprint": bundle_fingerprint()}}


def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


class _GoodHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/v1/data/gateway/bundle/info":
            body = json.dumps(GOOD_BUNDLE_INFO).encode()
        else:
            assert self.path == "/health"
            body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        assert self.path == "/v1/data/gateway/authz/decision"
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)  # consume
        body = json.dumps(GOOD_DECISION).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


class _BadDecisionHandler(_GoodHandler):
    def do_POST(self):  # noqa: N802
        body = json.dumps({"result": {"effect": "maybe", "rule": "r1"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _FlakyHealthHandler(_GoodHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(503)
        self.end_headers()


def _url(srv):
    return f"http://127.0.0.1:{srv.server_address[1]}"


class TestExternalMode:
    def test_decide_through_external_url(self):
        srv = _serve(_GoodHandler)
        try:
            c = OpaClient(external_url=_url(srv))
            assert c._external
            assert c.binary is None  # no binary resolution in this mode
            assert c.transport == "tcp"
            c.start()
            assert c.running
            d = c.decide({"input": "doc"})
            assert d == {"effect": "allow", "rule": "r1"}
            c.stop()
            assert not c.running
        finally:
            srv.shutdown()

    def test_env_var_selects_external_mode(self, monkeypatch):
        srv = _serve(_GoodHandler)
        try:
            # A bogus GATEWAY_OPA_BIN must NOT matter in external mode:
            # the binary is never resolved.
            monkeypatch.setenv("GATEWAY_OPA_URL", _url(srv))
            monkeypatch.setenv("GATEWAY_OPA_BIN", "/nonexistent/opa")
            c = OpaClient()
            assert c._external
            assert c.decide({})["effect"] == "allow"
            c.stop()
        finally:
            srv.shutdown()

    def test_malformed_decision_fails_closed(self):
        srv = _serve(_BadDecisionHandler)
        try:
            c = OpaClient(external_url=_url(srv), startup_timeout=5)
            c.start()
            with pytest.raises(OpaUnavailable):
                c.decide({})
            c.stop()
        finally:
            srv.shutdown()

    def test_unreachable_server_fails_closed(self):
        c = OpaClient(external_url="http://127.0.0.1:1", startup_timeout=2)
        with pytest.raises(OpaUnavailable):
            c.start()
        assert not c.running

    def test_unhealthy_server_fails_closed(self):
        srv = _serve(_FlakyHealthHandler)
        try:
            c = OpaClient(external_url=_url(srv), startup_timeout=2)
            with pytest.raises(OpaUnavailable):
                c.start()
        finally:
            srv.shutdown()

    def test_bad_url_scheme_rejected(self):
        c = OpaClient(external_url="ftp://opa:8181", startup_timeout=2)
        with pytest.raises(OpaUnavailable):
            c.start()

    def test_trailing_slash_stripped(self):
        c = OpaClient(external_url="http://opa:8181/")
        assert c.external_url == "http://opa:8181"
