"""M4 vault tests — Personal Agent Security Gateway.

Covers (per the M4 task):
- KMS provider: env loading, key validation, --generate CLI
- ciphertext-at-rest (no plaintext in the DB file), round-trip
- rotation: old + new both valid during grace, old invalid after;
  rotation audit-logged as an admin action (FR-041)
- every vault read audit-logged (FR-024), value never in the row
- derived token TTL enforcement + (agent, tool, action) bookkeeping
- AC-05 (amended): full pipeline call — no vault secret in
  agent-visible outputs, error payloads, or audit rows
- AC-08 re-verified with credential-backed calls (agent revoke +
  credential revoke → subsequent calls denied)
- notifier-secret separation: not storable in the vault; read from
  the platform secret store with audited reads (FR-024)

Conventions: test keys/secrets are generated at test time only
(secrets.token_hex); nothing real, nothing hardcoded.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys

import pytest

from gateway.audit import AuditLog
from gateway.config import Settings
from gateway.db import Databases
from gateway.errors import GatewayError
from gateway.identity import IdentityService
from gateway.mandates import MandateService
from gateway.mock_oauth import MockOAuthProvider
from gateway.pipeline import (
    ApprovalStage,
    AuditStage,
    AuthenticateStage,
    CallContext,
    ExecuteStage,
    InspectOutputStage,
    MandateStage,
    Pipeline,
    Stage,
    TokenMintStage,
    ToolDescriptor,
    ValidateInputsStage,
    build_m1_pipeline,
)
from gateway.vault import (
    EnvKmsProvider,
    MockOAuthIssuer,
    NotifierSecretProvider,
    VaultError,
    VaultStore,
    generate_kms_key,
)
from gateway.vault.minter import VaultTokenMinter
from gateway.vault.store import RESERVED_CONNECTORS


HMAC_KEY = "test-hmac-key-material-32bytes!"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEWAY_KMS_KEY", generate_kms_key())
    return Settings(
        config_db_path=str(tmp_path / "config.db"),
        audit_db_path=str(tmp_path / "audit.db"),
        vault_db_path=str(tmp_path / "vault.db"),
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
def audit(audit_db):
    return AuditLog(audit_db)


@pytest.fixture()
def agent_bundle(config_db):
    ident = IdentityService(config_db)
    agent, client_id, client_secret = ident.register_agent(
        "ag_vault_01", "muse", "Vault Test Agent", "ken"
    )
    mandates = MandateService(config_db)
    mandate = mandates.create_default_mandate(agent)
    # Transact tools need a NEW mandate (FR-PAA01-008): the default is
    # read-only and never silently authorizes communicate/transact.
    transact_mandate = mandates.create_mandate(
        agent_id=agent.id,
        purpose="Test transact mandate for vault-backed tools",
        allowed_classes=["email.send", "calendar.write", "codehost.repo_read"],
        created_by="admin",
    )
    return {
        "agent": agent,
        "agent_id": "ag_vault_01",
        "client_id": client_id,
        "client_secret": client_secret,
        "mandate": mandate,
        "transact_mandate": transact_mandate,
        "identity": ident,
    }


@pytest.fixture()
def vault_store(settings, audit):
    store = VaultStore(settings.vault_db_path, EnvKmsProvider(), audit)
    yield store
    store.close()


@pytest.fixture()
def issuer():
    return MockOAuthIssuer(MockOAuthProvider())


@pytest.fixture()
def minter(vault_store, issuer, settings, audit, credential_bundle):
    # credential_bundle first: minting needs stored connector credentials.
    return VaultTokenMinter(vault_store, issuer, settings, audit)


@pytest.fixture()
def credential_bundle(vault_store):
    """One stored mock upstream credential per MVP connector."""
    secrets_map = {
        "email": "mock-refresh-" + secrets.token_hex(16),
        "calendar": "mock-refresh-" + secrets.token_hex(16),
        "codehost": "mock-apikey-" + secrets.token_hex(16),
    }
    entries = {}
    for connector, secret in secrets_map.items():
        entries[connector] = vault_store.store(
            connector, f"Test {connector} credential", secret
        )
    return {"entries": entries, "secrets": secrets_map}


class MockUpstream:
    """Fake upstream API: accepts only a currently-valid derived token."""

    def __init__(self, issuer):
        self.issuer = issuer

    def call(self, presented_token: str, tool: str, args: dict):
        if not self.issuer.validate(presented_token):
            raise PermissionError("upstream rejected the derived token")
        return {"tool": tool, "ok": True, "arg_keys": sorted(args)}


def make_mock_handler(minter, upstream):
    def handler(ctx: CallContext, args: dict):
        tok = ctx.derived_token
        if tok is None or not minter.validate_token(
            tok, expected_agent_id=ctx.agent_id, expected_tool=ctx.tool
        ):
            raise PermissionError("no valid derived token on the call context")
        return upstream.call(tok.raw(), ctx.tool, args)

    return handler


class AllowPolicyStage:
    """TEST DOUBLE ONLY — stands in for M2's rule evaluator so M4 can
    exercise the credential-backed execute path."""

    name = "policy"

    def run(self, ctx: CallContext):
        return None


@pytest.fixture()
def vault_pipeline_bundle(
    config_db, audit_db, audit, settings, agent_bundle, minter, issuer,
    credential_bundle,
):
    """Full pipeline: real auth + mandate + vault minter + mock connectors.

    Tools: email.send, calendar.write, codehost.repo_read — each backed
    by a vault-stored mock credential via the derived-token flow.
    """
    registry = None
    from gateway.pipeline import ConnectorRegistry

    registry = ConnectorRegistry()
    upstream = MockUpstream(issuer)
    tools = ["email.send", "calendar.write", "codehost.repo_read"]
    for tool_name in tools:
        connector = tool_name.split(".")[0]
        registry.register(
            connector,
            [
                ToolDescriptor(
                    name=tool_name,
                    description=f"mock {tool_name}",
                    input_schema={},
                    sensitivity="routine",
                    handler=make_mock_handler(minter, upstream),
                )
            ],
        )
    identity = IdentityService(config_db)
    mandates = MandateService(config_db)
    auth_stage = AuthenticateStage(identity)
    auth_stage.presented[agent_bundle["agent_id"]] = agent_bundle["client_secret"]
    stages: list[Stage] = [
        auth_stage,
        ValidateInputsStage(registry),
        MandateStage(mandates),
        AllowPolicyStage(),
        ApprovalStage(),
        TokenMintStage(minter),
        ExecuteStage(registry),
        InspectOutputStage(),
    ]
    pipeline = Pipeline(stages, AuditStage(audit), settings)
    return {
        "pipeline": pipeline,
        "registry": registry,
        "minter": minter,
        "issuer": issuer,
        "agent_id": agent_bundle["agent_id"],
        "identity": agent_bundle["identity"],
        "secrets": credential_bundle["secrets"],
        "entries": credential_bundle["entries"],
        "vault_store": minter.store,
        "audit": audit,
        "settings": settings,
    }


# ---------------------------------------------------------------------------
# KMS provider
# ---------------------------------------------------------------------------

class TestKmsProvider:
    def test_env_loads_key_and_id(self, monkeypatch):
        key = generate_kms_key()
        monkeypatch.setenv("GATEWAY_KMS_KEY", key)
        monkeypatch.setenv("GATEWAY_KMS_KEY_ID", "test-k1")
        p = EnvKmsProvider()
        assert p.key_id == "test-k1"
        assert len(p.get_data_key()) == 32

    def test_missing_env_is_a_clear_error(self, monkeypatch):
        monkeypatch.delenv("GATEWAY_KMS_KEY", raising=False)
        with pytest.raises(VaultError, match="GATEWAY_KMS_KEY"):
            EnvKmsProvider()

    def test_malformed_base64_rejected(self, monkeypatch):
        monkeypatch.setenv("GATEWAY_KMS_KEY", "not-valid-base64!!!")
        with pytest.raises(VaultError, match="base64"):
            EnvKmsProvider()

    def test_wrong_length_rejected(self, monkeypatch):
        import base64

        monkeypatch.setenv(
            "GATEWAY_KMS_KEY", base64.b64encode(b"too-short").decode()
        )
        with pytest.raises(VaultError, match="32 bytes"):
            EnvKmsProvider()

    def test_generate_cli_produces_loadable_key(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = os.path.join(os.getcwd(), "src")
        proc = subprocess.run(
            [sys.executable, "-m", "gateway.vault.kms", "--generate"],
            capture_output=True,
            text=True,
            env=env,
            cwd=os.getcwd(),
            timeout=60,
        )
        assert proc.returncode == 0, proc.stderr
        first = proc.stdout.splitlines()[0]
        assert first.startswith("GATEWAY_KMS_KEY=")
        value = first.split("=", 1)[1]
        p = EnvKmsProvider({"GATEWAY_KMS_KEY": value})
        assert len(p.get_data_key()) == 32

    def test_repr_never_shows_key(self, monkeypatch):
        key = generate_kms_key()
        monkeypatch.setenv("GATEWAY_KMS_KEY", key)
        assert key not in repr(EnvKmsProvider())


# ---------------------------------------------------------------------------
# Vault store: encryption at rest, CRUD, rotation, audit
# ---------------------------------------------------------------------------

class TestVaultStore:
    def test_roundtrip(self, vault_store):
        secret = "refresh-" + secrets.token_hex(16)
        entry = vault_store.store("email", "label", secret)
        cred_id, out = vault_store.read("email", actor="ag_vault_01")
        assert cred_id == entry.id
        assert out == secret

    def test_ciphertext_at_rest(self, vault_store, settings):
        secret = "super-secret-" + secrets.token_hex(16)
        vault_store.store("email", "label", secret)
        vault_store.close()  # flush WAL so the file holds everything
        with open(settings.vault_db_path, "rb") as fh:
            blob = fh.read()
        assert secret.encode("utf-8") not in blob
        # The DEK-wrapped form must also not contain the plaintext; the
        # only plaintext-adjacent bytes allowed are the label.
        assert b"label" in blob  # sanity: we read the right file

    def test_duplicate_store_rejected_use_rotate(self, vault_store):
        vault_store.store("email", "label", "s1")
        with pytest.raises(VaultError, match="rotate"):
            vault_store.store("email", "label", "s2")

    def test_empty_secret_refused(self, vault_store):
        with pytest.raises(VaultError, match="empty"):
            vault_store.store("email", "label", "")

    def test_reserved_connectors_refused(self, vault_store):
        for reserved in sorted(RESERVED_CONNECTORS):
            with pytest.raises(VaultError, match="reserved"):
                vault_store.store(reserved, "label", "s3cr3t")

    def test_every_read_is_audit_logged_without_value(self, vault_store, audit):
        secret = "read-audit-" + secrets.token_hex(16)
        entry = vault_store.store("email", "label", secret)
        vault_store.read("email", actor="ag_vault_01")
        rows = audit.search(tool="vault.read")
        assert len(rows) == 1
        row = rows[0]
        assert row.agent_id == "ag_vault_01"
        assert row.redacted_args["credential_id"] == entry.id
        assert row.redacted_args["connector"] == "email"
        assert row.timestamp is not None
        dumped = json.dumps(audit._row(row))
        assert secret not in dumped

    def test_rotation_grace_and_supersede(self, vault_store, audit):
        old_secret = "old-" + secrets.token_hex(16)
        new_secret = "new-" + secrets.token_hex(16)
        old_entry = vault_store.store("email", "label", old_secret)
        new_entry = vault_store.rotate("email", new_secret)
        assert new_entry.id != old_entry.id
        # New reads get the new credential.
        cred_id, out = vault_store.read("email", actor="ag_vault_01")
        assert cred_id == new_entry.id
        assert out == new_secret
        # Old entry is superseded, still encrypted at rest.
        metas = {m["credential_id"]: m for m in vault_store.list_entries()}
        assert metas[old_entry.id]["status"] == "superseded"
        assert metas[new_entry.id]["status"] == "active"
        # Rotation is audit-logged as an admin action (FR-041).
        rows = audit.search(tool="vault.rotate")
        assert len(rows) == 1
        assert rows[0].redacted_args["old_credential_id"] == old_entry.id
        assert rows[0].redacted_args["new_credential_id"] == new_entry.id
        assert old_secret not in json.dumps(audit._row(rows[0]))
        assert new_secret not in json.dumps(audit._row(rows[0]))

    def test_revoke_blocks_reads(self, vault_store, audit):
        vault_store.store("email", "label", "s1")
        vault_store.revoke("email")
        with pytest.raises(VaultError, match="no active"):
            vault_store.read("email", actor="ag_vault_01")
        assert audit.search(tool="vault.revoke")

    def test_list_entries_is_console_safe(self, vault_store, settings):
        secret = "list-safe-" + secrets.token_hex(16)
        vault_store.store("email", "label", secret)
        metas = vault_store.list_entries()
        assert len(metas) == 1
        dumped = json.dumps(metas)
        assert secret not in dumped
        assert "ciphertext" not in dumped

    def test_rekey_rewraps_deks(self, vault_store, monkeypatch):
        secret = "rekey-" + secrets.token_hex(16)
        vault_store.store("email", "label", secret)
        new_key = generate_kms_key()
        new_kms = EnvKmsProvider(
            {"GATEWAY_KMS_KEY": new_key, "GATEWAY_KMS_KEY_ID": "test-k2"}
        )
        count = vault_store.rekey(new_kms)
        assert count == 1
        cred_id, out = vault_store.read("email", actor="ag_vault_01")
        assert out == secret
        metas = vault_store.list_entries()
        assert metas[0]["key_id"] == "test-k2"


# ---------------------------------------------------------------------------
# Minter: derived tokens, TTL, scope bookkeeping
# ---------------------------------------------------------------------------

class TestVaultTokenMinter:
    def _ctx(self, agent_id="ag_vault_01", tool="email.send"):
        return CallContext(agent_id=agent_id, tool=tool, args={})

    def test_mint_binds_scope_and_ttl(self, minter, settings):
        ctx = self._ctx()
        tok = minter.mint(ctx)
        assert tok.agent_id == "ag_vault_01"
        assert tok.tool == "email.send"
        assert tok.action == "send"
        # 5-minute TTL (00 §7 param 2), within a small tolerance.
        import time

        remaining = tok.expires_at_epoch - time.time()
        assert 4 * 60 < remaining <= 5 * 60
        assert minter.validate_token(tok)

    def test_derived_material_is_not_the_stored_credential(
        self, minter, credential_bundle
    ):
        tok = minter.mint(self._ctx())
        assert tok.raw() != credential_bundle["secrets"]["email"]
        # repr never leaks the material (FR-022)
        assert tok.raw() not in repr(tok)

    def test_unknown_connector_fails_closed(self, minter):
        with pytest.raises(VaultError, match="no active vault credential"):
            minter.mint(self._ctx(tool="notes.write"))

    def test_mint_is_audit_logged_with_scope(self, minter, audit, credential_bundle):
        entry = credential_bundle["entries"]["email"]
        minter.mint(self._ctx())
        rows = audit.search(tool="email.send")
        mint_rows = [r for r in rows if r.action == "token-mint"]
        assert len(mint_rows) == 1
        row = mint_rows[0]
        assert row.redacted_args["credential_id"] == entry.id
        assert row.redacted_args["bound_scope"] == {
            "agent": "ag_vault_01",
            "tool": "email.send",
            "action": "send",
        }
        dumped = json.dumps(audit._row(row))
        assert credential_bundle["secrets"]["email"] not in dumped
        assert "<derived>" not in dumped  # the value is never in the row at all

    def test_ttl_enforcement(self, minter, issuer):
        # GH #22: the LEDGER is the authority on expiry — not the
        # token's self-asserted expires_at_epoch and (for opaque upstream
        # tokens) not issuer introspection.
        import time

        from gateway.vault.minter import _ledger_key

        tok = minter.mint(self._ctx())
        assert minter.validate_token(tok)
        minter._ledger[_ledger_key(tok.raw())].expires_at_epoch = (
            time.time() - 1
        )
        assert not minter.validate_token(tok)

    def test_scope_bookkeeping_agent_and_tool(self, minter):
        tok = minter.mint(self._ctx())
        assert minter.validate_token(
            tok, expected_agent_id="ag_vault_01", expected_tool="email.send"
        )
        assert not minter.validate_token(tok, expected_agent_id="ag_other")
        assert not minter.validate_token(tok, expected_tool="calendar.write")

    def test_rotation_grace_old_and_new_valid(self, minter, issuer, vault_store):
        t1 = minter.mint(self._ctx())
        vault_store.rotate("email", "rotated-" + secrets.token_hex(16))
        t2 = minter.mint(self._ctx())
        # Grace: the pre-rotation token lives out its ≤5-min TTL (FR-023).
        assert minter.validate_token(t1)
        assert minter.validate_token(t2)
        # After the old token's TTL lapses, it is invalid; the new one holds.
        issuer.expire(t1.raw())
        assert not minter.validate_token(t1)
        assert minter.validate_token(t2)


# ---------------------------------------------------------------------------
# AC-05 (amended): no vault secret is retrievable agent-side
# ---------------------------------------------------------------------------

class TestAC05:
    def _agent_visible_surfaces(self, bundle):
        pipeline = bundle["pipeline"]
        agent_id = bundle["agent_id"]
        surfaces = []
        ok = pipeline.execute(agent_id, "email.send", {"to": "a@example.com"})
        assert ok.ok, ok.error
        surfaces.append(json.dumps(ok.context.result, default=str))
        # Error path: a tool whose connector has no vault credential.
        from gateway.pipeline import ConnectorRegistry, ToolDescriptor

        pipeline2_registry = bundle["registry"]  # shared registry
        # Register a tool on a connector with no stored credential.
        if "notes.write" not in pipeline2_registry.tool_names():
            pipeline2_registry.register(
                "notes",
                [
                    ToolDescriptor(
                        name="notes.write",
                        description="mock",
                        input_schema={},
                        sensitivity="routine",
                        handler=lambda ctx, args: {"never": "reached"},
                    )
                ],
            )
        err_outcome = pipeline.execute(agent_id, "notes.write", {"x": 1})
        assert err_outcome.error is not None
        surfaces.append(err_outcome.error.to_text())
        surfaces.append(json.dumps(bundle["audit"].export_json()))
        return surfaces

    def test_no_vault_secret_in_agent_visible_surfaces(self, vault_pipeline_bundle):
        bundle = vault_pipeline_bundle
        stored = list(bundle["secrets"].values())
        surfaces = self._agent_visible_surfaces(bundle)
        for secret in stored:
            for surface in surfaces:
                assert secret not in surface, "vault secret leaked agent-side (AC-05)"
        # Derived token values are equally agent-invisible.
        for surface in surfaces:
            assert "mockat_" not in surface

    def test_vault_db_file_has_no_plaintext(self, vault_pipeline_bundle):
        bundle = vault_pipeline_bundle
        path = bundle["settings"].vault_db_path
        bundle["vault_store"].close()
        with open(path, "rb") as fh:
            blob = fh.read()
        for secret in bundle["secrets"].values():
            assert secret.encode("utf-8") not in blob


# ---------------------------------------------------------------------------
# AC-08 re-verified with credential-backed calls
# ---------------------------------------------------------------------------

class TestAC08CredentialBacked:
    def test_call_succeeds_then_agent_revoke_denies(self, vault_pipeline_bundle):
        bundle = vault_pipeline_bundle
        pipeline = bundle["pipeline"]
        agent_id = bundle["agent_id"]
        ok = pipeline.execute(agent_id, "calendar.write", {"title": "x"})
        assert ok.ok, ok.error
        bundle["identity"].revoke(agent_id)
        denied = pipeline.execute(agent_id, "calendar.write", {"title": "x"})
        assert denied.error is not None
        assert denied.error.code == "agent_revoked"

    def test_credential_revoke_denies_subsequent_calls(self, vault_pipeline_bundle):
        bundle = vault_pipeline_bundle
        pipeline = bundle["pipeline"]
        agent_id = bundle["agent_id"]
        ok = pipeline.execute(agent_id, "codehost.repo_read", {"repo": "r"})
        assert ok.ok, ok.error
        bundle["vault_store"].revoke("codehost")
        denied = pipeline.execute(agent_id, "codehost.repo_read", {"repo": "r"})
        assert denied.error is not None
        # Fail closed: mint cannot proceed (03 §7); no secret in the envelope.
        assert denied.error.code == "upstream_failure"
        envelope = denied.error.to_text()
        for secret in bundle["secrets"].values():
            assert secret not in envelope

    def test_expired_derived_token_rejected_by_adapter(self, vault_pipeline_bundle):
        bundle = vault_pipeline_bundle
        minter = bundle["minter"]
        issuer = bundle["issuer"]
        ctx = CallContext(agent_id=bundle["agent_id"], tool="email.send", args={})
        tok = minter.mint(ctx)
        issuer.expire(tok.raw())
        assert not minter.validate_token(tok)


# ---------------------------------------------------------------------------
# Notifier-secret separation (NFR-SEC-002 scope note; 02 §2.8 step 5)
# ---------------------------------------------------------------------------

class TestNotifierSeparation:
    @pytest.fixture()
    def notifier_env(self, monkeypatch):
        secret = "notifier-bootstrap-" + secrets.token_hex(16)
        monkeypatch.setenv("GATEWAY_NOTIFIER_SECRET", secret)
        return secret

    def test_notifier_secret_not_storable_in_vault(self, vault_store, notifier_env):
        with pytest.raises(VaultError, match="reserved"):
            vault_store.store("notifier", "email-to-Ken bootstrap", notifier_env)
        with pytest.raises(VaultError, match="reserved"):
            vault_store.store("system", "email-to-Ken bootstrap", notifier_env)

    def test_notifier_read_from_platform_store_with_audit(
        self, notifier_env, settings, audit, tmp_path, vault_store
    ):
        provider = NotifierSecretProvider(settings, audit)
        assert provider.read(purpose="approval-notify") == notifier_env
        rows = audit.search(tool="notifier.read")
        assert len(rows) == 1
        assert rows[0].agent_id == "system"
        assert rows[0].redacted_args["purpose"] == "approval-notify"
        assert notifier_env not in json.dumps(audit._row(rows[0]))
        # The vault file never holds it either.
        vault_store.close()
        with open(settings.vault_db_path, "rb") as fh:
            assert notifier_env.encode("utf-8") not in fh.read()

    def test_missing_notifier_secret_is_a_clear_error(self, settings, audit, monkeypatch):
        monkeypatch.delenv("GATEWAY_NOTIFIER_SECRET", raising=False)
        fresh = Settings(
            config_db_path=settings.config_db_path,
            audit_db_path=settings.audit_db_path,
            vault_db_path=settings.vault_db_path,
            hmac_key=HMAC_KEY,
        )
        provider = NotifierSecretProvider(fresh, audit)
        with pytest.raises(VaultError, match="GATEWAY_NOTIFIER_SECRET"):
            provider.read(purpose="approval-notify")

    def test_notifier_repr_hides_value(self, settings, audit, notifier_env):
        provider = NotifierSecretProvider(settings, audit)
        assert notifier_env not in repr(provider)


# ---------------------------------------------------------------------------
# Wiring: vault minter plugs into build_m1_pipeline via the minter param
# ---------------------------------------------------------------------------

class TestPipelineWiring:
    def test_minter_param_replaces_stub(
        self, config_db, audit_db, settings, minter, agent_bundle, credential_bundle
    ):
        pipeline, registry, auth_stage = build_m1_pipeline(
            config_db, audit_db, settings, minter=minter
        )
        mint_stage = next(
            s for s in pipeline.stages if isinstance(s, TokenMintStage)
        )
        assert mint_stage.minter is minter

    def test_stub_still_default(self, config_db, audit_db, settings):
        from gateway.pipeline import StubTokenMinter

        pipeline, _, _ = build_m1_pipeline(config_db, audit_db, settings)
        mint_stage = next(
            s for s in pipeline.stages if isinstance(s, TokenMintStage)
        )
        assert isinstance(mint_stage.minter, StubTokenMinter)
