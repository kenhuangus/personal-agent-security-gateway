"""M3 approval-workflow tests — Personal Agent Security Gateway.

Covers (per the M3 task):
- the FULL loop: sensitive call → approval_required → poll pending →
  console approve → poll approved → re-invoke → executes, with 3
  linked audit rows sharing one approval_request_id
- validate-first: invalid args on a sensitive tool → invalid_input,
  NO apr_ created (MF-4)
- caller binding on gateway.approval_status (MF-5)
- pending dedupe → existing apr_ id
- already_executed terminal (no new request, no re-execution)
- refusal cooldown + denial-streak escalation (FR-PAA09-003)
- per-agent queue cap → approval_queue_full (FR-028, MF-9)
- one-time grant TTL expiry (30 min)
- atomic grant consumption under concurrency (first wins)
- mandate withdrawal kills grants (BLOCKER-1, FR-PAA01-004)
- policy supersession: material change → policy_superseded;
  non-material preserves grants (FR-PAA04-003)
- CSRF rejection on state-changing console routes (FR-042, MF-8)
- notifier: fixed field allowlist + bounce → in-console fallback +
  90-day secret age (02 §2.8 step 5, T13)
- execute-on-approval fallback: single execution, grant consumed at
  approval time, result_summary mirror (MF-11)
- evidence subset shape (HMAC tag, redacted args, code-secret
  redaction in the preview)
- inert card rendering (MF-6)
- counterparty: new-payee escalation, changed-details delta,
  console correction (FR-PAA05-001/002/003)
- unknown-outcome retry gate (FR-PAA06-003)
"""

from __future__ import annotations

import datetime as dt
import functools
import json
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from gateway.approval_card import build_card, build_evidence_subset, render_inert_html
from gateway.approvals import (
    DESTRUCTIVE_TOOLS,
    ApprovalService,
    GrantCheckResult,
    UnknownOutcomeService,
    make_approval_status_tool,
    redact_full_args,
)
from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.console import create_console_app
from gateway.console.approvals import ApprovalConsoleDeps
from gateway.console.csrf import CsrfProtector
from gateway.counterparty import CounterpartyService
from gateway.db import Databases
from gateway.errors import ToolHalt
from gateway.hmac_util import HmacKeyRing
from gateway.identity import IdentityService
from gateway.mandates import MandateService
from gateway.models import (
    ApprovalRequest,
    CounterpartyRecord,
    Grant,
    RefusalCooldown,
    UnknownOutcomeBlock,
    as_utc,
)
from gateway.notifier import MockNotifierTransport, Notifier, build_notifier
from gateway.pipeline import (
    ConnectorRegistry,
    StubTokenMinter,
    build_pipeline,
    execute_approved_call,
)
from gateway.policy import PolicyEngine
from gateway.connectors.calendar import CalendarConnector
from gateway.connectors.codehost import CodeHostConnector
from gateway.connectors.email import EmailConnector
from gateway.connectors.mock_upstream import MockCalendar, MockGitHub, MockGmail

HMAC_KEY = "test-hmac-key-material-32bytes!"

ALL_TOOLS = [
    "email.search", "email.read", "email.send", "email.draft",
    "email.settings.read", "email.settings.write",
    "calendar.list", "calendar.create", "calendar.update", "calendar.delete",
    "code.file.read", "code.pr.open",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def settings(tmp_path):
    return Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        hmac_key=HMAC_KEY,
    )


@pytest.fixture()
def dbs(settings):
    d = Databases(settings.config_db_path, settings.audit_db_path)
    d.create_all()
    return d


@pytest.fixture()
def config_db(dbs):
    with dbs.config.session() as s:
        yield s


@pytest.fixture()
def audit_db(dbs):
    with dbs.audit.session() as s:
        yield s


@pytest.fixture()
def ring(settings):
    return HmacKeyRing.from_env_string(settings.hmac_key_id, settings.hmac_key)


@pytest.fixture()
def connectors():
    return {
        "email": EmailConnector(MockGmail()),
        "calendar": CalendarConnector(MockCalendar()),
        "code": CodeHostConnector(MockGitHub()),
    }


@pytest.fixture()
def registry(dbs, settings, ring, connectors):
    reg = ConnectorRegistry()
    for name, conn in connectors.items():
        conn.register(reg)
    # The agent-visible meta tool (02 §2.5), registered like any other
    # tool so it flows through the pipeline (auth → validate → mandate
    # → policy → execute). Its own rate budget is enforced by the
    # pipeline's validate-stage rate limiter.
    reg.register(
        "gateway",
        [make_approval_status_tool(
            config_session_factory=dbs.config.session,
            audit_session_factory=dbs.audit.session,
            settings=settings, hmac_ring=ring,
        )],
    )
    return reg


@pytest.fixture()
def agent(dbs):
    with dbs.config.session() as cdb:
        ident = IdentityService(cdb)
        agent, _cid, secret = ident.register_agent("ag_muse", "muse", "Muse", "ken")
        MandateService(cdb).create_mandate(
            agent.id, "test mandate", ALL_TOOLS + ["gateway.*"], purpose_key="work"
        )
        return {"agent_id": agent.id, "secret": secret}


@pytest.fixture()
def agent2(dbs):
    with dbs.config.session() as cdb:
        ident = IdentityService(cdb)
        agent, _cid, secret = ident.register_agent("ag_grok", "grok", "Grok", "ken")
        MandateService(cdb).create_mandate(
            agent.id, "test mandate", ALL_TOOLS + ["gateway.*"], purpose_key="work"
        )
        return {"agent_id": agent.id, "secret": secret}


@pytest.fixture()
def transport():
    return MockNotifierTransport()


@pytest.fixture()
def csrf():
    return CsrfProtector()


def make_service(config_db, audit_db, settings, ring, transport=None, csrf=None, notifier=None):
    """ApprovalService wired like the pipeline/console would wire it."""
    audit = AuditLog(audit_db)
    if notifier is None:
        notifier = build_notifier(settings, audit, transport=transport or MockNotifierTransport())
    return ApprovalService(
        config_db, audit, settings, ring, MandateService(config_db),
        notifier=notifier, confirmations=csrf.confirmations if csrf else None,
    )


def _require_approval_rule(cdb, tool="email.send"):
    return PolicyEngine(cdb).save_version(
        [{"name": f"approve {tool}", "effect": "require_approval", "tool": tool}],
        change_note="test",
    )


def _allow_rule(cdb, tool="email.send"):
    return PolicyEngine(cdb).save_version(
        [{"name": f"allow {tool}", "effect": "allow", "tool": tool}],
        change_note="test",
    )


def _run(dbs, settings, ring, registry, agent, tool, args, transport=None, csrf=None):
    """One pipeline call with the M3 approval flow wired.

    Returns (outcome, service): the service shares the call's
    sessions, so tests can decide()/inspect on it afterwards.
    """
    with dbs.config.session() as cdb, dbs.audit.session() as adb:
        service = make_service(cdb, adb, settings, ring, transport=transport, csrf=csrf)
        service.executor = functools.partial(
            execute_approved_call,
            config_session_factory=dbs.config.session,
            audit_session_factory=dbs.audit.session,
            settings=settings,
            hmac_ring=ring,
            registry=registry,
            minter=StubTokenMinter(),
        )
        pipeline, _, auth_stage = build_pipeline(
            cdb, adb, settings, hmac_ring=ring, registry=registry,
            approval_service=service,
        )
        auth_stage.presented[agent["agent_id"]] = agent["secret"]
        return pipeline.execute(agent["agent_id"], tool, args), service


SEND_ARGS = {
    "to": ["alice@example.com"],
    "subject": "Hello",
    "body": "This is a test message with no secrets.",
}


def _approval_required_body(outcome):
    assert outcome.error is not None
    assert outcome.error.code == "approval_required", outcome.error.to_text()
    return outcome.error.details


def _audit_rows(audit_db, **filters):
    return AuditLog(audit_db).search(**filters)

# ---------------------------------------------------------------------------
# The full loop (extended AC-04, as far as verifiable without live agents)
# ---------------------------------------------------------------------------

class TestFullLoop:
    def test_full_loop_three_linked_rows(
        self, dbs, settings, ring, registry, agent, transport, csrf, connectors, audit_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS),
            transport=transport, csrf=csrf,
        )
        details = _approval_required_body(outcome)
        apr_id = details["approval_request_id"]
        assert apr_id.startswith("apr_")

        # 1. paused-call audit row, linked.
        rows = _audit_rows(audit_db, approval_request_id=apr_id)
        assert [r.decision for r in rows] == ["approval_required"]

        # 2. poll pending via gateway.approval_status (through the pipeline).
        poll_outcome, _ = _run(
            dbs, settings, ring, registry, agent,
            "gateway.approval_status", {"approval_request_id": apr_id},
        )
        assert poll_outcome.ok, poll_outcome.error.to_text() if poll_outcome.error else ""
        assert poll_outcome.context.result["status"] == "pending"
        assert "result_summary" not in poll_outcome.context.result
        # Routine polls leave no audit row (02 §2.5 carve-out).
        assert _audit_rows(audit_db, approval_request_id=apr_id,
                           decision="allowed") == []

        # 3. console approve (one-time scope).
        decision = service.decide(apr_id, decision="approve", admin_id="admin")
        assert decision["status"] == "approved"
        assert decision["already_decided"] is False

        # 4. poll approved.
        poll2, _ = _run(
            dbs, settings, ring, registry, agent,
            "gateway.approval_status", {"approval_request_id": apr_id},
        )
        assert poll2.context.result["status"] == "approved"

        # 5. re-invoke the original call → executes via the consumed grant.
        exec_outcome, _ = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS)
        )
        assert exec_outcome.ok, exec_outcome.error.to_text() if exec_outcome.error else ""
        assert exec_outcome.context.decision == "allowed_via_approval"
        assert exec_outcome.context.approval_request_id == apr_id
        assert connectors["email"].upstream._sent_log, "mock Gmail should have sent"

        # 3 linked rows, one approval_request_id.
        rows = sorted(
            _audit_rows(audit_db, approval_request_id=apr_id),
            key=lambda r: r.id,
        )
        assert [r.decision for r in rows] == [
            "approval_required", "approved", "allowed_via_approval",
        ]

    def test_poll_approved_has_no_result_summary_in_normal_path(
        self, dbs, settings, ring, registry, agent, csrf
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        service.decide(apr_id, decision="approve")
        poll, _ = _run(
            dbs, settings, ring, registry, agent,
            "gateway.approval_status", {"approval_request_id": apr_id},
        )
        assert "result_summary" not in poll.context.result

    def test_reinvoke_with_different_args_is_a_fresh_call(
        self, dbs, settings, ring, registry, agent, csrf
    ):
        """FR-PAA06-002: the grant binds the exact argument hash."""
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        service.decide(apr_id, decision="approve")
        other = dict(SEND_ARGS, subject="Different subject")
        fresh, _ = _run(dbs, settings, ring, registry, agent, "email.send", other)
        assert fresh.error is not None and fresh.error.code == "approval_required"
        assert fresh.error.details["approval_request_id"] != apr_id


# ---------------------------------------------------------------------------
# Validate-first (MF-4)
# ---------------------------------------------------------------------------

class TestValidateFirst:
    def test_invalid_args_never_create_approval(
        self, dbs, settings, ring, registry, agent, config_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, _ = _run(
            dbs, settings, ring, registry, agent,
            "email.send", {"subject": "no recipients", "body": "x"},
        )
        assert outcome.error is not None
        assert outcome.error.code == "invalid_input"
        assert outcome.error.details["field"] == "to"
        # No apr_ was created (validate-first, MF-4).
        with dbs.config.session() as cdb:
            assert cdb.execute(select(ApprovalRequest)).scalars().all() == []


# ---------------------------------------------------------------------------
# Caller binding (MF-5)
# ---------------------------------------------------------------------------

class TestCallerBinding:
    def test_other_agents_id_is_not_found(
        self, dbs, settings, ring, registry, agent, agent2, csrf, audit_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, _ = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]

        poll, _ = _run(
            dbs, settings, ring, registry, agent2,
            "gateway.approval_status", {"approval_request_id": apr_id},
        )
        assert poll.ok
        # Not-found — never "denied" (MF-5).
        assert poll.context.result["status"] == "not_found"
        # ...but the not-found poll IS audit-logged (02 §2.5).
        rows = _audit_rows(audit_db, agent_id=agent2["agent_id"], decision="error")
        assert any(r.reason == "approval_not_found" for r in rows)

    def test_malformed_id_is_invalid_input(
        self, dbs, settings, ring, registry, agent
    ):
        poll, _ = _run(
            dbs, settings, ring, registry, agent,
            "gateway.approval_status", {"approval_request_id": "bogus"},
        )
        assert poll.error is not None and poll.error.code == "invalid_input"


# ---------------------------------------------------------------------------
# Step-3 lookup chain
# ---------------------------------------------------------------------------

class TestLookupChain:
    def test_pending_dedupe_returns_existing_id(
        self, dbs, settings, ring, registry, agent, csrf, config_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        o1, _ = _run(dbs, settings, ring, registry, agent, "email.send",
                     dict(SEND_ARGS), csrf=csrf)
        o2, _ = _run(dbs, settings, ring, registry, agent, "email.send",
                     dict(SEND_ARGS), csrf=csrf)
        id1 = _approval_required_body(o1)["approval_request_id"]
        id2 = _approval_required_body(o2)["approval_request_id"]
        assert id1 == id2
        with dbs.config.session() as cdb:
            assert len(cdb.execute(select(ApprovalRequest)).scalars().all()) == 1

    def test_already_executed_is_terminal(
        self, dbs, settings, ring, registry, agent, csrf, connectors, config_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        service.decide(apr_id, decision="approve")
        ok, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert ok.ok
        sent_before = len(connectors["email"].upstream._sent_log)
        # Replay after consumption: terminal, no new apr_, no re-execution.
        again, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert again.error is not None and again.error.code == "already_executed"
        assert again.error.retryable is False
        with dbs.config.session() as cdb:
            assert len(cdb.execute(select(ApprovalRequest)).scalars().all()) == 1
        assert len(connectors["email"].upstream._sent_log) == sent_before

    def test_refusal_cooldown_blocks_identical_reinvoke(
        self, dbs, settings, ring, registry, agent, csrf, transport, config_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS),
            transport=transport, csrf=csrf,
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        sent_before = len(transport.sent)
        service.decide(apr_id, decision="deny", note="nope")
        # Identical re-invoke inside the refusal cooldown → cooldown_active.
        again, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert again.error is not None and again.error.code == "cooldown_active"
        # No new approval request, no notification.
        with dbs.config.session() as cdb:
            assert len(cdb.execute(select(ApprovalRequest)).scalars().all()) == 1
            assert cdb.execute(select(RefusalCooldown)).scalars().all() != []
        assert len(transport.sent) == sent_before

    def test_denial_streak_escalation_covers_mutated_args(
        self, dbs, settings, ring, registry, agent, csrf, config_db
    ):
        """FR-PAA09-003: 3 denials for (agent, tool)/24h → pair-level
        cooldown regardless of arguments."""
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        for i in range(3):
            args = dict(SEND_ARGS, subject=f"attempt {i}")
            outcome, service = _run(
                dbs, settings, ring, registry, agent, "email.send", args, csrf=csrf
            )
            apr_id = _approval_required_body(outcome)["approval_request_id"]
            service.decide(apr_id, decision="deny")
        # A fourth call with entirely new args hits the pair-level cooldown.
        fresh = dict(SEND_ARGS, to=["bob@example.com"], subject="brand new")
        outcome, _ = _run(dbs, settings, ring, registry, agent, "email.send", fresh)
        assert outcome.error is not None
        assert outcome.error.code == "cooldown_active"
        with dbs.config.session() as cdb:
            # No fourth approval request was created.
            assert len(cdb.execute(select(ApprovalRequest)).scalars().all()) == 3

    def test_queue_cap_returns_approval_queue_full(
        self, dbs, settings, ring, registry, agent, csrf, config_db, audit_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        for i in range(settings.approval_queue_cap):
            args = dict(SEND_ARGS, subject=f"cap {i}")
            outcome, _ = _run(
                dbs, settings, ring, registry, agent, "email.send", args, csrf=csrf
            )
            _approval_required_body(outcome)
        overflow = dict(SEND_ARGS, subject="over the cap")
        outcome, _ = _run(dbs, settings, ring, registry, agent, "email.send", overflow)
        assert outcome.error is not None
        assert outcome.error.code == "approval_queue_full"
        # The event is audit-logged (FR-028).
        rows = _audit_rows(audit_db, decision="denied")
        assert any(r.reason == "approval_queue_full" for r in rows)

    def test_dedupe_wins_over_cap(
        self, dbs, settings, ring, registry, agent, csrf, config_db
    ):
        """Step-3 order: an at-cap agent re-submitting an identical
        pending request gets the existing apr_ id, not approval_queue_full."""
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        first_args = dict(SEND_ARGS, subject="first")
        o1, _ = _run(dbs, settings, ring, registry, agent, "email.send", first_args, csrf=csrf)
        id1 = _approval_required_body(o1)["approval_request_id"]
        for i in range(settings.approval_queue_cap - 1):
            args = dict(SEND_ARGS, subject=f"filler {i}")
            _run(dbs, settings, ring, registry, agent, "email.send", args, csrf=csrf)
        # At cap now; re-submit the identical first call → dedupe wins.
        o2, _ = _run(dbs, settings, ring, registry, agent, "email.send", first_args)
        assert _approval_required_body(o2)["approval_request_id"] == id1

# ---------------------------------------------------------------------------
# Grant semantics: TTL, supersession, mandate liveness, atomicity
# ---------------------------------------------------------------------------

class TestGrants:
    def test_grant_ttl_expiry_forces_fresh_approval(
        self, dbs, settings, ring, registry, agent, csrf, config_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            make_service(cdb, adb, settings, ring, csrf=csrf).decide(
                apr_id, decision="approve"
            )
        # Expire the grant (30-min TTL lapsed).
        with dbs.config.session() as cdb:
            grant = cdb.execute(select(Grant)).scalars().one()
            grant.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)
            cdb.commit()
        # Re-invoke: no matching grant → a FRESH approval request.
        again, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert again.error is not None and again.error.code == "approval_required"
        assert again.error.details["approval_request_id"] != apr_id

    def test_atomic_consume_under_concurrency(
        self, dbs, settings, ring, registry, agent, connectors
    ):
        """Two concurrent re-invokes: exactly one executes, the other
        gets already_executed (atomic compare-and-consume)."""
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            make_service(cdb, adb, settings, ring).decide(apr_id, decision="approve")

        sent_before = len(connectors["email"].upstream._sent_log)
        barrier = threading.Barrier(2)
        results = {}

        def thread_session_factory(which):
            path = settings.config_db_path if which == "config" else settings.audit_db_path
            eng = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
            with eng.connect() as conn:
                conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
            return sessionmaker(bind=eng, expire_on_commit=False)

        def worker(i):
            cfg_factory = thread_session_factory("config")
            aud_factory = thread_session_factory("audit")
            with cfg_factory() as cdb, aud_factory() as adb:
                pipeline, _, auth_stage = build_pipeline(
                    cdb, adb, settings, hmac_ring=ring, registry=registry, approvals=True
                )
                auth_stage.presented[agent["agent_id"]] = agent["secret"]
                barrier.wait(timeout=10)
                results[i] = pipeline.execute(agent["agent_id"], "email.send", dict(SEND_ARGS))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert all(not t.is_alive() for t in threads)
        codes = sorted(
            "ok" if r.ok else r.error.code for r in results.values()
        )
        assert codes == ["already_executed", "ok"], codes
        assert len(connectors["email"].upstream._sent_log) == sent_before + 1

    def test_mandate_withdrawal_kills_grant(
        self, dbs, settings, ring, registry, agent, csrf, config_db, audit_db
    ):
        """BLOCKER-1: the grant's mandate died → mandate_withdrawn,
        remaining grants invalidated, audit event recorded."""
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
            ms = MandateService(cdb)
            m_extra = ms.create_mandate(agent["agent_id"], "extra", ["email.send"])
        outcome, _ = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with dbs.config.session() as cdb:
            grant = cdb.execute(select(Grant).where(
                Grant.approval_request_id == apr_id)).scalars().first()
        # Withdraw whichever mandate the grant bound (the other stays live
        # so the pipeline's mandate stage passes and the grant-time
        # re-check is what fires).
        grant_mandate_id = None
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            svc = make_service(cdb, adb, settings, ring, csrf=csrf)
            svc.decide(apr_id, decision="approve")
            grant = cdb.execute(select(Grant).where(
                Grant.approval_request_id == apr_id)).scalars().one()
            grant_mandate_id = grant.mandate_id
            MandateService(cdb).withdraw(grant_mandate_id)
        outcome, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert outcome.error is not None
        assert outcome.error.code == "policy_denied"
        assert outcome.error.details["reason"] == "mandate_withdrawn"
        # Remaining unconsumed grants under the dead mandate invalidated.
        with dbs.config.session() as cdb:
            grant = cdb.execute(select(Grant).where(
                Grant.approval_request_id == apr_id)).scalars().one()
            assert grant.invalidated is True
        # Audit event recorded.
        rows = [r for r in _audit_rows(audit_db, approval_request_id=apr_id)
                if r.reason == "mandate_withdrawn"]
        assert rows != []

    def test_mandate_pause_and_expiry_reasons(
        self, dbs, settings, ring, registry, agent, csrf
    ):
        from gateway.models import Mandate

        for action, expected in [("pause", "mandate_paused"), ("expire", "mandate_expired")]:
            with dbs.config.session() as cdb:
                _require_approval_rule(cdb)
                # A second live mandate: the pipeline's mandate stage
                # must pass so the GRANT-consumption re-check is what
                # fires (BLOCKER-1).
                MandateService(cdb).create_mandate(agent["agent_id"], "extra", ["email.send"])
            outcome, _ = _run(
                dbs, settings, ring, registry, agent,
                "email.send", dict(SEND_ARGS, subject=f"reason {action}"), csrf=csrf,
            )
            apr_id = _approval_required_body(outcome)["approval_request_id"]
            with dbs.config.session() as cdb, dbs.audit.session() as adb:
                svc = make_service(cdb, adb, settings, ring, csrf=csrf)
                svc.decide(apr_id, decision="approve")
                grant = cdb.execute(select(Grant).where(
                    Grant.approval_request_id == apr_id)).scalars().one()
                ms = MandateService(cdb)
                if action == "pause":
                    ms.pause(grant.mandate_id)
                else:
                    m = cdb.get(Mandate, grant.mandate_id)
                    m.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
                    cdb.commit()
            again, _ = _run(
                dbs, settings, ring, registry, agent,
                "email.send", dict(SEND_ARGS, subject=f"reason {action}"),
            )
            assert again.error is not None, action
            assert again.error.details.get("reason") == expected, (
                action, again.error.to_text())

    def test_material_policy_change_supersedes_grant(
        self, dbs, settings, ring, registry, agent, csrf
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, _ = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            make_service(cdb, adb, settings, ring, csrf=csrf).decide(
                apr_id, decision="approve")
        # MATERIAL policy change since issuance.
        with dbs.config.session() as cdb:
            PolicyEngine(cdb).save_version(
                [{"name": "approve send", "effect": "require_approval", "tool": "email.send"}],
                change_note="material widening", material_change=True,
            )
        again, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert again.error is not None
        assert again.error.code == "policy_denied"
        assert again.error.details["reason"] == "policy_superseded"

    def test_non_material_change_preserves_grant(
        self, dbs, settings, ring, registry, agent, csrf, connectors
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, _ = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            make_service(cdb, adb, settings, ring, csrf=csrf).decide(
                apr_id, decision="approve")
        with dbs.config.session() as cdb:
            PolicyEngine(cdb).save_version(
                [{"name": "approve send (renamed)", "effect": "require_approval",
                  "tool": "email.send"}],
                change_note="rename only", material_change=False,
            )
        again, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert again.ok, again.error.to_text() if again.error else ""
        assert connectors["email"].upstream._sent_log

    def test_revocation_kills_grants(
        self, dbs, settings, ring, registry, agent, csrf, config_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, _ = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            svc = make_service(cdb, adb, settings, ring, csrf=csrf)
            svc.decide(apr_id, decision="approve")
            IdentityService(cdb).revoke(agent["agent_id"])
            assert svc.kill_agent_grants(agent["agent_id"]) == 1
            grant = cdb.execute(select(Grant)).scalars().one()
            assert grant.invalidated is True


# ---------------------------------------------------------------------------
# Evidence subset (02 §2.8 step 4)
# ---------------------------------------------------------------------------

class TestEvidenceSubset:
    def test_evidence_shape_and_hmac(self, dbs, settings, ring, registry, agent, config_db):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        args = dict(SEND_ARGS, body="Call me back. My verification code is 482916.")
        outcome, _ = _run(dbs, settings, ring, registry, agent, "email.send", args)
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with dbs.config.session() as cdb:
            apr = cdb.get(ApprovalRequest, apr_id)
            ev = apr.evidence_subset
            # Approver-visible fields stay cleartext…
            assert ev["audience"]["to"] == ["alice@example.com"]
            assert ev["subject"] == "Hello"
            # …but code-like secrets are redacted even in the preview.
            assert "482916" not in ev["body_preview"]
            assert "[redacted:code]" in ev["body_preview"]
            # HMAC-SHA256 tag (never plain SHA-256).
            assert apr.argument_hash.startswith("k1:")
            assert len(apr.argument_hash) == 3 + 64
            assert ring.matches(args, apr.argument_hash)
            # Full args stored redacted only.
            assert "482916" not in json.dumps(apr.redacted_args)

    def test_redact_full_args_minimal(self):
        redacted = redact_full_args({"body": "code 123456", "to": ["a@b.c"]})
        assert "123456" not in json.dumps(redacted)
        assert redacted["to"] == ["a@b.c"]


# ---------------------------------------------------------------------------
# content_hash binds the bytes that execute (issue #3)
# ---------------------------------------------------------------------------


class TestContentHashBindsReplayArgs:
    def test_email_send_hash_covers_exact_replay_args(self, ring):
        body = "Invoice 20261013 for order 482916 is due."
        ev = build_evidence_subset(
            "email.send",
            {"to": ["a@b.c"], "subject": "s", "body": body},
            ring,
        )
        # Single source of truth: the hash binds replay_args exactly,
        # so it can be recomputed at replay time.
        from gateway.approval_card import _content_hash

        assert ev["content_hash"] == _content_hash(ev["replay_args"], ring)
        # What executes is the RAW body — digits intact, never mangled
        # by the display redactor.
        assert ev["replay_args"]["body"] == body
        assert "20261013" in ev["replay_args"]["body"]
        assert "482916" in ev["replay_args"]["body"]
        # Redaction stays in the display preview only.
        assert "482916" not in ev["body_preview"]
        assert "[redacted:code]" in ev["body_preview"]

    def test_code_pr_open_hash_covers_exact_replay_args(self, ring):
        body = "Fixes ticket 12345678."
        ev = build_evidence_subset(
            "code.pr.open",
            {"repo": "o/r", "title": "t", "head": "h", "base": "b",
             "body": body},
            ring,
        )
        from gateway.approval_card import _content_hash

        assert ev["content_hash"] == _content_hash(ev["replay_args"], ring)
        assert ev["replay_args"]["body"] == body
        assert "12345678" not in ev["body_preview"]

    def test_calendar_create_hash_covers_full_replay_args(self, ring):
        args = {"title": "t", "start": "s", "end": "e",
                "attendees": ["a@b.c"], "description": "d",
                "location": "l"}
        ev = build_evidence_subset("calendar.create", args, ring)
        from gateway.approval_card import _content_hash

        assert ev["content_hash"] == _content_hash(ev["replay_args"], ring)
        assert ev["replay_args"]["location"] == "l"


# ---------------------------------------------------------------------------
# Inert card rendering (MF-6)
# ---------------------------------------------------------------------------

class TestInertRendering:
    def test_card_html_is_inert(self, dbs, settings, ring, registry, agent, config_db):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        args = dict(SEND_ARGS, body='<script>alert(1)</script> see https://evil.example/x')
        outcome, _ = _run(dbs, settings, ring, registry, agent, "email.send", args)
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with dbs.config.session() as cdb:
            apr = cdb.get(ApprovalRequest, apr_id)
            card = build_card(
                apr, agent_display_name="Muse", mandate=None,
                cap_used=1, cap_total=5, recorded_criteria=None,
                destructive=False, now=dt.datetime.now(dt.timezone.utc),
            )
            html_out = render_inert_html(card)
        assert "<a" not in html_out  # no clickable links, ever
        assert "untrusted content" in html_out
        assert "&lt;script&gt;" in html_out  # escaped, not executed
        assert "https://evil.example/x" in html_out  # visible as plain text
        # Consequence summary exists (before free text).
        assert card["consequence"]
        # Cap state on the card (FR-028).
        assert card["cap"]["label"] == "1 of 5 pending approvals used"

# ---------------------------------------------------------------------------
# Notifier: exempt path, fixed allowlist, failure fallback (02 §2.8 step 5)
# ---------------------------------------------------------------------------

class TestNotifier:
    def _notifier_settings(self, tmp_path, **kw):
        return Settings(
            config_db_path=str(tmp_path / "config.db"),
            audit_db_path=str(tmp_path / "audit.db"),
            hmac_key=HMAC_KEY,
            notifier_recipient="ken@example.com",
            notifier_secret="test-bootstrap-secret",
            **kw,
        )

    def _settings_for(self, settings, **kw):
        return Settings(
            config_db_path=settings.config_db_path,
            audit_db_path=settings.audit_db_path,
            hmac_key=HMAC_KEY,
            **kw,
        )

    def test_allowlist_only_no_arg_passthrough(
        self, dbs, settings, ring, registry, agent, transport, csrf
    ):
        settings = self._settings_for(
            settings, notifier_recipient="ken@example.com",
            notifier_secret="test-bootstrap-secret",
        )
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        secret_body = "This body contains the phrase walrus-banana-42."
        outcome, _ = _run(
            dbs, settings, ring, registry, agent,
            "email.send", dict(SEND_ARGS, body=secret_body),
            transport=transport, csrf=csrf,
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        assert len(transport.sent) == 1
        msg = transport.sent[0]
        # Fixed allowlist: agent name, tool name, timestamp, console link.
        assert "email.send" in msg["subject"]
        assert apr_id in msg["body"]
        # NO tool-argument passthrough — not even redacted.
        assert "walrus-banana-42" not in msg["body"]
        assert "alice@example.com" not in msg["body"]

    def test_bounce_falls_back_to_console(
        self, dbs, settings, ring, registry, agent, transport, csrf, audit_db
    ):
        transport.fail = True
        settings = self._settings_for(
            settings, notifier_recipient="ken@example.com",
            notifier_secret="test-bootstrap-secret",
        )
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, _ = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS),
            transport=transport, csrf=csrf,
        )
        # The approval request is still created (in-console queue is
        # the delivery path); the failure is audit-logged.
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        assert apr_id.startswith("apr_")
        assert transport.sent == []
        rows = _audit_rows(audit_db, tool="notifier.send", decision="error")
        assert any(r.redacted_args.get("outcome") == "fallback" for r in rows)

    def test_secret_older_than_90_days_refuses(
        self, dbs, tmp_path, ring, transport, audit_db
    ):
        settings = self._notifier_settings(
            tmp_path,
            notifier_secret_issued_at=(
                dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=91)
            ).isoformat(),
        )
        with dbs.audit.session() as adb:
            notifier = build_notifier(settings, AuditLog(adb), transport=transport)
            result = notifier.notify_new_request(
                agent_id="ag_x", agent_name="X", tool_name="email.send",
                approval_id="apr_" + "0" * 32,
                created_at=dt.datetime.now(dt.timezone.utc),
            )
        assert result.outcome == "secret_expired"
        assert result.delivered is False
        assert transport.sent == []

    def test_per_agent_notification_cooldown(self, dbs, tmp_path, ring, transport, audit_db):
        settings = self._notifier_settings(tmp_path)
        with dbs.audit.session() as adb:
            notifier = build_notifier(settings, AuditLog(adb), transport=transport)
            now = dt.datetime.now(dt.timezone.utc)
            first = notifier.notify_new_request(
                agent_id="ag_x", agent_name="X", tool_name="email.send",
                approval_id="apr_" + "1" * 32, created_at=now)
            second = notifier.notify_new_request(
                agent_id="ag_x", agent_name="X", tool_name="email.send",
                approval_id="apr_" + "2" * 32, created_at=now)
        assert first.outcome == "sent"
        assert second.outcome == "cooldown"
        assert len(transport.sent) == 1


# ---------------------------------------------------------------------------
# Execute-on-approval fallback (MF-11)
# ---------------------------------------------------------------------------

class TestExecuteOnApproval:
    def test_single_execution_with_result_summary(
        self, dbs, settings, ring, registry, agent, csrf, connectors
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        sent_before = len(connectors["email"].upstream._sent_log)
        decision = service.decide(apr_id, decision="approve", execute_on_approval=True)
        assert decision["status"] == "approved"
        assert decision["executed"] is True
        # Grant consumed AT APPROVAL TIME.
        with dbs.config.session() as cdb:
            grant = cdb.execute(select(Grant)).scalars().one()
            assert grant.consumed is True
        # Exactly one server-side execution.
        assert len(connectors["email"].upstream._sent_log) == sent_before + 1
        # result_summary mirrored on approval_status (execute-on-approval only).
        poll, _ = _run(
            dbs, settings, ring, registry, agent,
            "gateway.approval_status", {"approval_request_id": apr_id},
        )
        assert poll.context.result["status"] == "approved"
        assert poll.context.result["result_summary"]["ok"] is True
        # The agent re-invoking afterwards → already_executed (no double execution).
        again, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert again.error is not None and again.error.code == "already_executed"
        assert len(connectors["email"].upstream._sent_log) == sent_before + 1


# ---------------------------------------------------------------------------
# Destructive scopes: per-decision confirmation token (FR-042)
# ---------------------------------------------------------------------------

class TestDestructiveScopes:
    def _delete_args(self):
        return {"event_id": "evt_123"}

    def test_destructive_window_is_5_minutes(
        self, dbs, settings, ring, registry, agent, csrf, config_db
    ):
        assert "calendar.delete" in DESTRUCTIVE_TOOLS
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb, tool="calendar.delete")
        outcome, _ = _run(
            dbs, settings, ring, registry, agent, "calendar.delete",
            self._delete_args(), csrf=csrf,
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with dbs.config.session() as cdb:
            apr = cdb.get(ApprovalRequest, apr_id)
            window = (as_utc(apr.expires_at) - as_utc(apr.created_at)).total_seconds()
            assert 290 <= window <= 310

    def test_destructive_approve_needs_confirmation_token(
        self, dbs, settings, ring, registry, agent, csrf
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb, tool="calendar.delete")
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "calendar.delete",
            self._delete_args(), csrf=csrf,
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with pytest.raises(ValueError, match="confirmation token"):
            service.decide(apr_id, decision="approve")
        # Mint from the card render, single-use, bound to this apr_.
        token = csrf.confirmations.mint(apr_id)
        decision = service.decide(
            apr_id, decision="approve", confirmation_token=token)
        assert decision["status"] == "approved"
        # The token was single-use: redeeming again fails.
        assert csrf.confirmations.redeem(token, apr_id) is False
        # And the decision itself is idempotent.
        assert service.decide(apr_id, decision="approve")["already_decided"] is True

    def test_confirmation_token_bound_to_apr_id(
        self, dbs, settings, ring, registry, agent, csrf
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb, tool="calendar.delete")
        o1, service = _run(
            dbs, settings, ring, registry, agent, "calendar.delete",
            self._delete_args(), csrf=csrf)
        o2, _ = _run(
            dbs, settings, ring, registry, agent, "calendar.delete",
            {"event_id": "evt_999"}, csrf=csrf)
        id1 = _approval_required_body(o1)["approval_request_id"]
        id2 = _approval_required_body(o2)["approval_request_id"]
        token_for_2 = csrf.confirmations.mint(id2)
        with pytest.raises(ValueError, match="confirmation token"):
            service.decide(id1, decision="approve", confirmation_token=token_for_2)


# ---------------------------------------------------------------------------
# Decision idempotency (02 §2.6)
# ---------------------------------------------------------------------------

class TestDecisionIdempotency:
    def test_retry_returns_existing_decision_no_second_grant(
        self, dbs, settings, ring, registry, agent, csrf, config_db
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        first = service.decide(apr_id, decision="approve")
        second = service.decide(apr_id, decision="deny")
        assert first["already_decided"] is False
        assert second["already_decided"] is True
        assert second["status"] == "approved"
        with dbs.config.session() as cdb:
            assert len(cdb.execute(select(Grant)).scalars().all()) == 1

    def test_scope_other_than_one_time_rejected(
        self, dbs, settings, ring, registry, agent, csrf
    ):
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, service = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        with pytest.raises(ValueError, match="one_time"):
            service.decide(apr_id, decision="approve", scope="windowed")

# ---------------------------------------------------------------------------
# Counterparty records (FR-PAA05-001/002/003)
# ---------------------------------------------------------------------------

class TestCounterparty:
    def test_new_payee_escalates_to_approval(
        self, dbs, settings, ring, registry, agent, csrf, config_db
    ):
        """FR-PAA05-002: a recipient with no prior audited history is
        auto-sensitive for commitment-adjacent actions."""
        with dbs.config.session() as cdb:
            _allow_rule(cdb)  # policy would allow…
        outcome, _ = _run(
            dbs, settings, ring, registry, agent,
            "email.send", dict(SEND_ARGS, to=["new@example.com"]), csrf=csrf,
        )
        # …but the new payee escalates to approval.
        assert outcome.error is not None
        assert outcome.error.code == "approval_required"
        assert outcome.context.escalation_reason == "new_payee"

    def test_known_payee_proceeds_and_changed_details_escalate(
        self, dbs, settings, ring, registry, agent, csrf, connectors, config_db
    ):
        with dbs.config.session() as cdb:
            _allow_rule(cdb)
        # First send to alice → escalated (new), approve, execute.
        o1, _ = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr1 = _approval_required_body(o1)["approval_request_id"]
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            make_service(cdb, adb, settings, ring, csrf=csrf).decide(apr1, decision="approve")
        ok, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert ok.ok
        # Record now exists.
        with dbs.config.session() as cdb:
            rec = cdb.execute(
                select(CounterpartyRecord).where(
                    CounterpartyRecord.key == "alice@example.com")
            ).scalars().one()
            assert rec.call_count == 1
        # Same payee, same details → allowed, no approval.
        ok2, _ = _run(dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS))
        assert ok2.ok
        # Same payee, CHANGED details (new cc) → escalate with delta.
        changed = dict(SEND_ARGS, cc=["intruder@example.com"])
        o3, _ = _run(dbs, settings, ring, registry, agent, "email.send", changed, csrf=csrf)
        assert o3.error is not None and o3.error.code == "approval_required"
        assert o3.context.escalation_reason == "changed_details"
        apr3 = o3.error.details["approval_request_id"]
        with dbs.config.session() as cdb:
            apr = cdb.get(ApprovalRequest, apr3)
            delta = apr.evidence_subset["counterparty"]["delta"]
            assert delta["cc"]["added"] == ["intruder@example.com"]

    def test_counterparty_correct_is_audit_logged(
        self, dbs, settings, ring, config_db, audit_db
    ):
        with dbs.config.session() as cdb:
            svc = CounterpartyService(cdb)
            svc.record_from_call("ag_muse", "email.send", dict(SEND_ARGS))
            with dbs.audit.session() as adb:
                svc.correct(
                    "alice@example.com", notes="Ken corrected",
                    details={"to": ["alice@example.com"], "cc": [], "bcc": []},
                    admin_id="admin", audit=AuditLog(adb),
                )
        with dbs.config.session() as cdb:
            rec = cdb.execute(
                select(CounterpartyRecord).where(
                    CounterpartyRecord.key == "alice@example.com")
            ).scalars().one()
            assert rec.notes == "Ken corrected"
        rows = _audit_rows(audit_db, tool="counterparty.correct")
        assert len(rows) == 1
        assert rows[0].redacted_args["before"]["notes"] == ""


# ---------------------------------------------------------------------------
# Unknown-outcome retry gate (FR-PAA06-003)
# ---------------------------------------------------------------------------

class TestUnknownOutcome:
    @pytest.fixture()
    def flaky_registry(self, registry):
        from gateway.pipeline import ToolDescriptor

        state = {"fail": True}

        def _flaky(ctx, args):
            if state["fail"]:
                raise TimeoutError("upstream hung")
            return {"ok": True}

        registry.register(
            "test",
            [ToolDescriptor(
                name="test.flaky", description="flaky",
                input_schema={"type": "object"}, sensitivity="routine",
                handler=_flaky,
            )],
        )
        return registry, state

    def test_timeout_blocks_retry_until_resolved(
        self, dbs, settings, ring, agent, flaky_registry, audit_db
    ):
        registry, state = flaky_registry
        with dbs.config.session() as cdb:
            _allow_rule(cdb, tool="test.flaky")
            MandateService(cdb).create_mandate(agent["agent_id"], "test", ["test.*"])
        outcome, _ = _run(dbs, settings, ring, registry, agent, "test.flaky", {})
        assert outcome.error is not None
        assert outcome.error.code == "upstream_failure"
        assert outcome.error.details.get("unknown_outcome") is True
        # Identical retry is blocked.
        again, _ = _run(dbs, settings, ring, registry, agent, "test.flaky", {})
        assert again.error is not None
        assert again.error.code == "upstream_failure"
        assert again.error.details.get("retry_blocked") is True
        # Console resolves after a status check (MockGmail.transaction_status
        # is the connector capability; here Ken confirms manually).
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            svc = UnknownOutcomeService(cdb)
            blocks = svc.list_unresolved()
            assert len(blocks) == 1
            svc.resolve(blocks[0].id, "status check confirmed non-execution",
                        AuditLog(adb))
        state["fail"] = False
        fixed, _ = _run(dbs, settings, ring, registry, agent, "test.flaky", {})
        assert fixed.ok


# ---------------------------------------------------------------------------
# Expiry sweep (step 10: timeout)
# ---------------------------------------------------------------------------

class TestExpiry:
    def test_timeout_marks_expired_and_cools_down(
        self, dbs, tmp_path, ring, registry, agent, csrf
    ):
        settings = Settings(
            config_db_path=str(tmp_path / "config.db"),
            audit_db_path=str(tmp_path / "audit.db"),
            hmac_key=HMAC_KEY,
            approval_window_minutes=0,  # expires immediately
        )
        d = Databases(settings.config_db_path, settings.audit_db_path)
        d.create_all()
        with d.config.session() as cdb:
            ident = IdentityService(cdb)
            ag, _cid, secret = ident.register_agent("ag_t", "muse", "T", "ken")
            MandateService(cdb).create_mandate(ag.id, "t", ALL_TOOLS + ["gateway.*"])
            PolicyEngine(cdb).save_version(
                [{"name": "r", "effect": "require_approval", "tool": "email.send"}],
                change_note="t",
            )
            agent_ref = {"agent_id": ag.id, "secret": secret}
        outcome, service = _run(
            d, settings, ring, registry, agent_ref, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        # Poll → the lazy sweep marks it expired.
        poll, _ = _run(
            d, settings, ring, registry, agent_ref,
            "gateway.approval_status", {"approval_request_id": apr_id},
        )
        assert poll.context.result["status"] == "expired"
        # The expired poll IS audit-logged (02 §2.5).
        with d.audit.session() as adb:
            rows = _audit_rows(adb, decision="expired")
        assert any(r.approval_request_id == apr_id for r in rows)
        # Timeout records the refusal cooldown like a deny (M3 step 10).
        again, _ = _run(d, settings, ring, registry, agent_ref, "email.send", dict(SEND_ARGS))
        assert again.error is not None and again.error.code == "cooldown_active"


# ---------------------------------------------------------------------------
# approval_status rate budget (02 §2.5)
# ---------------------------------------------------------------------------

class TestPollBudget:
    def test_own_budget_and_no_audit_rows(
        self, dbs, tmp_path, ring, registry, agent, csrf
    ):
        settings = Settings(
            config_db_path=str(tmp_path / "config.db"),
            audit_db_path=str(tmp_path / "audit.db"),
            hmac_key=HMAC_KEY,
            approval_status_polls_per_minute=2,
        )
        d = Databases(settings.config_db_path, settings.audit_db_path)
        d.create_all()
        with d.config.session() as cdb:
            ident = IdentityService(cdb)
            ag, _cid, secret = ident.register_agent("ag_p", "muse", "P", "ken")
            MandateService(cdb).create_mandate(ag.id, "p", ALL_TOOLS + ["gateway.*"])
            PolicyEngine(cdb).save_version(
                [{"name": "r", "effect": "require_approval", "tool": "email.send"}],
                change_note="p",
            )
            agent_ref = {"agent_id": ag.id, "secret": secret}
        # Rebuild the registry (the own-budget limiter reads the
        # setting at validate time).
        reg = ConnectorRegistry()
        for name, conn in {
            "email": EmailConnector(MockGmail()),
        }.items():
            conn.register(reg)
        reg.register("gateway", [make_approval_status_tool(
            config_session_factory=d.config.session,
            audit_session_factory=d.audit.session,
            settings=settings, hmac_ring=ring,
        )])
        outcome, _ = _run(
            d, settings, ring, reg, agent_ref, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        for _ in range(2):
            poll, _ = _run(
                d, settings, ring, reg, agent_ref,
                "gateway.approval_status", {"approval_request_id": apr_id},
            )
            assert poll.ok and poll.context.result["status"] == "pending"
        # Third poll inside the minute → rate_limited (the validate
        # stage enforces the own budget)…
        limited, _ = _run(
            d, settings, ring, reg, agent_ref,
            "gateway.approval_status", {"approval_request_id": apr_id},
        )
        assert limited.error is not None and limited.error.code == "rate_limited"
        # …and the two routine polls left no audit rows (carve-out);
        # the rate-limited poll is a denied outcome, so it IS logged
        # (02 §2.5: EXCEPT denied/expired/not-found).
        with d.audit.session() as adb:
            rows = _audit_rows(adb, tool="gateway.approval_status")
        assert len(rows) == 1
        assert rows[0].decision == "denied" and rows[0].reason == "rate_limited"


# ---------------------------------------------------------------------------
# Console: Approvals page + API + CSRF
# ---------------------------------------------------------------------------

@pytest.fixture()
def console_client(dbs, settings, ring, registry, csrf):
    deps = ApprovalConsoleDeps(
        settings=settings, csrf=csrf, registry=registry,
        minter=StubTokenMinter(), hmac_ring=ring,
        notifier_transport=MockNotifierTransport(),
    )
    app = create_console_app(
        dbs.config.session, dbs.audit.session, settings, approval_deps=deps,
        dev_no_auth=True,  # TEST ONLY — M6 auth is covered in test_console.py
    )
    return TestClient(app), deps


def _csrf_headers(client):
    r = client.get("/api/csrf-token")
    assert r.status_code == 200
    return {"X-CSRF-Token": r.json()["csrf_token"]}


class TestConsoleApprovals:
    def test_page_queue_card_and_decision(
        self, dbs, settings, ring, registry, agent, csrf, console_client
    ):
        client, deps = console_client
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb)
        outcome, _ = _run(
            dbs, settings, ring, registry, agent, "email.send", dict(SEND_ARGS), csrf=csrf
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]

        r = client.get("/approvals")
        assert r.status_code == 200 and apr_id in r.text

        r = client.get("/api/approvals/pending")
        assert any(q["approval_request_id"] == apr_id for q in r.json())

        r = client.get(f"/api/approvals/{apr_id}")
        assert r.status_code == 200
        body = r.json()
        assert "untrusted content" in body["card_html"]
        assert "<a " not in body["card_html"] and "<a>" not in body["card_html"]
        assert body["card"]["cap"]["label"].startswith("1 of")

        # CSRF: no token → 403.
        r = client.post(f"/api/approvals/{apr_id}/decision",
                        json={"decision": "approve", "scope": "one_time"})
        assert r.status_code == 403
        # With token → approved.
        r = client.post(f"/api/approvals/{apr_id}/decision",
                        json={"decision": "approve", "scope": "one_time"},
                        headers=_csrf_headers(client))
        assert r.status_code == 200
        assert r.json()["status"] == "approved"

    def test_destructive_decision_via_api(
        self, dbs, settings, ring, registry, agent, csrf, console_client
    ):
        client, deps = console_client
        with dbs.config.session() as cdb:
            _require_approval_rule(cdb, tool="calendar.delete")
        outcome, _ = _run(
            dbs, settings, ring, registry, agent,
            "calendar.delete", {"event_id": "evt_1"}, csrf=csrf,
        )
        apr_id = _approval_required_body(outcome)["approval_request_id"]
        headers = _csrf_headers(client)
        # No confirmation token → 400.
        r = client.post(f"/api/approvals/{apr_id}/decision",
                        json={"decision": "approve", "scope": "one_time"},
                        headers=headers)
        assert r.status_code == 400
        # Card carries the per-decision confirmation token…
        card = client.get(f"/api/approvals/{apr_id}").json()
        assert card["confirmation_token"]
        # …which authorizes the destructive decision.
        r = client.post(f"/api/approvals/{apr_id}/decision",
                        json={"decision": "approve", "scope": "one_time",
                              "confirmation_token": card["confirmation_token"]},
                        headers=headers)
        assert r.status_code == 200 and r.json()["status"] == "approved"

    def test_counterparty_correct_via_api(
        self, dbs, settings, ring, registry, agent, console_client
    ):
        client, deps = console_client
        with dbs.config.session() as cdb:
            _allow_rule(cdb)
        _run(dbs, settings, ring, registry, agent, "email.send",
             dict(SEND_ARGS, to=["new@example.com"]))
        # new payee → escalated; approve via direct service to execute
        with dbs.config.session() as cdb, dbs.audit.session() as adb:
            svc = make_service(cdb, adb, settings, ring)
            apr = cdb.execute(select(ApprovalRequest)).scalars().one()
            svc.decide(apr.id, decision="approve")
        _run(dbs, settings, ring, registry, agent, "email.send",
             dict(SEND_ARGS, to=["new@example.com"]))
        headers = _csrf_headers(client)
        r = client.get("/api/counterparties")
        assert any(c["key"] == "new@example.com" for c in r.json())
        r = client.post("/api/counterparties/new@example.com/correct",
                        json={"notes": "verified vendor",
                              "details": {"to": ["new@example.com"], "cc": [], "bcc": []}},
                        headers=headers)
        assert r.status_code == 200 and r.json()["notes"] == "verified vendor"

    def test_m2_form_routes_require_csrf(self, console_client):
        client, _deps = console_client
        # No token → 403 (FR-042 on all state-changing console routes).
        r = client.post("/agents", data={"agent_id": "x", "platform": "muse",
                                         "display_name": "X", "household_role": "ken"})
        assert r.status_code == 403
        # With token → works.
        token = client.get("/api/csrf-token").json()["csrf_token"]
        r = client.post("/agents", data={"agent_id": "x", "platform": "muse",
                                         "display_name": "X", "household_role": "ken",
                                         "csrf_token": token})
        assert r.status_code == 200 and "shown ONCE" in r.text
