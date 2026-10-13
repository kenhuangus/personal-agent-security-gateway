"""Latency instrumentation tests (workstream 2).

- Ring buffer: span recording with correct stage labels, bounded size,
  thread safety.
- Statistics: p50 / p95 / max / count computed correctly.
- Wiring: the judge cascade records its own latency_ms (no second
  timer); the pipeline execute loop records the inspection stage.
- Console: /latency renders real numbers from synthetic buffer data
  (no server needed), with an honest empty state.
"""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from gateway import latency
from gateway.config import Settings
from gateway.console import create_console_app
from gateway.db import Databases
from gateway.errors import make_error
from gateway.judge.cascade import JudgeCascade
from gateway.judge.client import Answer, DecisionResult
from gateway.latency import LatencyRecorder
from gateway.pipeline import CallContext, Pipeline
from gateway.policy import _policy_effect_label
from gateway.vault.kms import generate_kms_key

HMAC_KEY = "test-hmac-key-material-32bytes!"


@pytest.fixture(autouse=True)
def _clean_recorder():
    latency.recorder.clear()
    yield
    latency.recorder.clear()


@pytest.fixture()
def rec():
    return LatencyRecorder(maxlen=1000)


# ---------------------------------------------------------------------
# Ring buffer
# ---------------------------------------------------------------------


class TestRecorder:
    def test_record_stores_stage_label_latency(self, rec):
        span = rec.record("policy", 12.5, label="allow")
        assert span.stage == "policy"
        assert span.latency_ms == 12.5
        assert span.label == "allow"
        assert span.timestamp > 0
        assert rec.count("policy") == 1
        assert rec.count("inspection") == 0

    def test_labels_histogram(self, rec):
        rec.record("policy", 1.0, label="allow")
        rec.record("policy", 2.0, label="deny")
        rec.record("policy", 3.0, label="allow")
        assert rec.labels("policy") == {"allow": 2, "deny": 1}

    def test_ring_buffer_is_bounded(self):
        small = LatencyRecorder(maxlen=10)
        for i in range(50):
            small.record("judge", float(i), label="kev")
        assert small.count("judge") == 10
        # The oldest samples fell off: max of the last 10 is 49.
        assert small.stats("judge")["max"] == 49.0

    def test_thread_safe_recording(self, rec):
        def _work(n):
            for i in range(n):
                rec.record("inspection", float(i), label="ok")

        threads = [threading.Thread(target=_work, args=(100,)) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert rec.count("inspection") == 800
        assert rec.stats("inspection")["count"] == 800

    def test_stats_empty_is_none(self, rec):
        assert rec.stats("policy") is None
        assert rec.stats_all() == {}


# ---------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------


class TestStats:
    def test_p50_p95_max_count(self, rec):
        for v in range(1, 101):  # 1..100, n=100
            rec.record("policy", float(v), label="allow")
        s = rec.stats("policy")
        # Nearest-rank: rank = ceil(p/100 * n).
        assert s["p50"] == 50.0
        assert s["p95"] == 95.0
        assert s["max"] == 100.0
        assert s["count"] == 100

    def test_single_sample(self, rec):
        rec.record("judge", 321.5, label="kev")
        s = rec.stats("judge")
        assert (s["p50"], s["p95"], s["max"], s["count"]) == (321.5, 321.5, 321.5, 1)

    def test_percentiles_are_real_not_placeholders(self, rec):
        # Two distinct populations: p50 must sit in the fast one, p95 in
        # the slow one — a hard-coded value could not do this.
        for _ in range(90):
            rec.record("inspection", 2.0, label="ok")
        for _ in range(10):
            rec.record("inspection", 400.0, label="ok")
        s = rec.stats("inspection")
        assert s["p50"] == 2.0
        assert s["p95"] == 400.0  # nearest-rank: ceil(0.95*100)=95 -> 400.0
        assert s["max"] == 400.0


# ---------------------------------------------------------------------
# Wiring: policy effect labels, judge cascade reuse, pipeline inspection
# ---------------------------------------------------------------------


class TestPolicyEffectLabel:
    def test_ask_maps_to_require_approval(self):
        assert _policy_effect_label({"effect": "ask"}) == "require_approval"

    def test_allow_and_deny_pass_through(self):
        assert _policy_effect_label({"effect": "allow"}) == "allow"
        assert _policy_effect_label({"effect": "deny"}) == "deny"

    def test_malformed_decision_is_honest(self):
        assert _policy_effect_label({}) == "unknown"


class _ScriptedBackend:
    """Minimal DecisionBackend: one scripted confidence per question."""

    def __init__(self, name, confidence=0.9):
        self.name = name
        self.confidence = confidence

    def decide(self, state, questions, timeout_s):
        answers = {}
        for q in questions:
            answers[q.name] = Answer(
                name=q.name, kind=q.kind,
                probabilities={"yes": self.confidence, "no": 1.0 - self.confidence},
                top="", confidence=0.0,
            )
        return DecisionResult(
            answers=answers, latency_ms=123.456, backend=self.name, model="test",
        )


class TestJudgeCascadeRecording:
    def test_decide_records_its_own_latency_ms(self):
        from gateway.judge.client import Question

        cascade = JudgeCascade(_ScriptedBackend("kev-test"), threshold=0.75)
        result = cascade.decide(
            "state", [Question(name="q", kind="noul", prompt="p")]
        )
        stats = latency.recorder.stats("judge")
        assert stats is not None and stats["count"] == 1
        # The recorded span IS the cascade's measured latency_ms — no
        # second timer was added around decide().
        assert stats["max"] == pytest.approx(result.latency_ms)
        assert latency.recorder.labels("judge") == {"kev-test": 1}

    def test_failed_cascade_records_nothing(self):
        from gateway.judge.client import DisabledBackend, Question

        cascade = JudgeCascade(DisabledBackend(), threshold=0.75)
        with pytest.raises(Exception):
            cascade.decide("state", [Question(name="q", kind="noul", prompt="p")])
        assert latency.recorder.stats("judge") is None


class _FakeStage:
    def __init__(self, name, error=None):
        self.name = name
        self._error = error

    def run(self, ctx: CallContext):
        return self._error


class _AuditStub:
    name = "audit"

    def run(self, ctx: CallContext):
        return None


class TestPipelineInspectionRecording:
    def test_inspect_output_stage_is_recorded_with_ok_label(self):
        pipe = Pipeline(
            stages=[_FakeStage("validate_inputs"), _FakeStage("inspect_output")],
            audit_stage=_AuditStub(),
        )
        outcome = pipe.execute("agent1", "email.search", {"query": "x"})
        assert outcome.ok
        stats = latency.recorder.stats("inspection")
        assert stats is not None and stats["count"] == 1
        assert latency.recorder.labels("inspection") == {"ok": 1}
        # Other stages are NOT recorded by the pipeline loop.
        assert latency.recorder.stats("policy") is None

    def test_halted_inspection_records_error_code(self):
        err = make_error(
            "injected_output_blocked", "email.send: blocked",
            "req_test", {"tool": "email.send"},
        )
        pipe = Pipeline(
            stages=[_FakeStage("inspect_output", error=err)],
            audit_stage=_AuditStub(),
        )
        outcome = pipe.execute("agent1", "email.send", {})
        assert not outcome.ok
        assert latency.recorder.labels("inspection") == {"injected_output_blocked": 1}


# ---------------------------------------------------------------------
# Console page: real numbers from synthetic buffer data
# ---------------------------------------------------------------------


@pytest.fixture()
def csettings(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_KMS_KEY", generate_kms_key())
    return Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        vault_db_path=str(tmp_path / "vault.db"),
        hmac_key=HMAC_KEY,
    )


@pytest.fixture()
def cdbs(csettings):
    d = Databases(csettings.config_db_path, csettings.audit_db_path)
    d.create_all()
    return d


def _client(cdbs, csettings):
    app = create_console_app(
        cdbs.config.session, cdbs.audit.session, csettings,
        connectors=[], dev_no_auth=True,
    )
    return TestClient(app)


class TestLatencyPage:
    def test_empty_buffer_shows_honest_no_data_state(self, cdbs, csettings):
        client = _client(cdbs, csettings)
        r = client.get("/latency")
        assert r.status_code == 200
        assert "No data yet" in r.text
        assert "100 ms" in r.text  # the AC-11 budget line is present

    def test_page_renders_real_measured_numbers(self, cdbs, csettings):
        # Synthetic buffer data (injected directly, no server needed).
        for _ in range(90):
            latency.record("policy", 2.0, label="allow")
        for _ in range(10):
            latency.record("policy", 400.0, label="deny")
        latency.record("inspection", 5.0, label="ok")
        latency.record("judge", 300.0, label="kev")

        client = _client(cdbs, csettings)
        r = client.get("/latency")
        assert r.status_code == 200
        # Policy p95 of the injected population (nearest-rank 95/100 -> 400.0).
        assert "400.00" in r.text
        # p50 of the same population.
        assert "2.00" in r.text
        # Judge sample over the 100 ms budget -> highlighted red.
        assert "300.00" in r.text
        assert "badge denied" in r.text
        # Labels and sample counts are real.
        assert "kev" in r.text
        assert ">100<" in r.text or ">100</td>" in r.text
        # Judge backend line comes from settings (default: none/disabled).
        assert "<code>none</code>" in r.text
        assert "GATEWAY_JUDGE_ENABLED" in r.text

    def test_judge_backend_line_reflects_settings(self, cdbs, tmp_path, monkeypatch):
        monkeypatch.setenv("GATEWAY_KMS_KEY", generate_kms_key())
        s = Settings(
            config_db_path=str(tmp_path / "config2.db"),
            audit_db_path=str(tmp_path / "audit2.db"),
            vault_db_path=str(tmp_path / "vault2.db"),
            hmac_key=HMAC_KEY,
            judge_backend="kev",
            judge_enabled=True,
        )
        d = Databases(s.config_db_path, s.audit_db_path)
        d.create_all()
        client = _client(d, s)
        latency.record("judge", 42.0, label="kev")
        r = client.get("/latency")
        assert r.status_code == 200
        assert "<code>kev</code>" in r.text
        assert "42.00" in r.text
