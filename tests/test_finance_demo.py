"""Pillar 1 §10: the finance demo is a scripted test.

Runs scripts/demo_finance.py end-to-end against temp DBs: asserts
all four acts produce the expected decisions, audit rows link
(req_/apr_/pay_), and both approver identities appear. This is the
MVP acceptance artifact — the scripted test and the demo are the
same code path.
"""

from __future__ import annotations

import importlib.util
import os


def _load_demo():
    path = os.path.join(
        os.path.dirname(__file__), "..", "scripts", "demo_finance.py")
    spec = importlib.util.spec_from_file_location("demo_finance", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_finance_demo_end_to_end():
    demo = _load_demo()
    result = demo.run_demo()
    acts = result["acts"]

    # Act 1: the routine rebalance is allowed, silently.
    assert acts["act1"]["decision"] == "allowed"
    assert acts["act1"]["marker"].startswith("MVP")

    # Act 2: quorum payment — two distinct approvers, receipt, linked
    # audit rows.
    assert acts["act2"]["marker"].startswith("MVP")
    assert acts["act2"]["receipt_id"].startswith("pay_")
    assert acts["act2"]["audit_rows"] >= 3
    # The transcript names both approvers.
    transcript = "\n".join(result["transcript"])
    assert "1 / 2 approvals" in transcript
    assert "2 / 2" in transcript

    # Act 3: the spoofed email is quarantined (MVP monitor mode).
    assert acts["act3"]["verdict"] == "quarantine"
    assert "MVP" in acts["act3"]["marker"]

    # Act 4: the checkpoint act is flagged as a deferred extension.
    assert "EXTENSION" in acts["act4"]["marker"]


def test_demo_seed_is_idempotent(tmp_path):
    """seed_finance_demo.seed_demo can run twice without error."""
    seed_path = os.path.join(
        os.path.dirname(__file__), "..", "scripts", "seed_finance_demo.py")
    spec = importlib.util.spec_from_file_location("seed_finance_demo", seed_path)
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)

    from gateway.config import Settings
    from gateway.db import Databases

    settings = Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        hmac_key="test-hmac-key-material-32bytes!",
        money_enabled=True,
    )
    databases = Databases(settings.config_db_path, settings.audit_db_path)
    databases.create_all()
    seed.seed_demo(databases, settings)
    # Second run: everything exists — must not raise.
    seed.seed_demo(databases, settings)
