"""Decision snapshots: immutable, content-addressed records of the
ontology slice used at a decision (PAA04 traceability).

At decision time the engine captures: the calling principal (id, kind,
display name) + its relationships, the declared context dimensions, the
applicable dimension groups, the matched preference group(s), and the
rule reference. The payload is canonicalized and hashed with
HMAC-SHA256 under the gateway key (same convention as ``hmac_util``);
the tagged digest (``key_id:hexdigest``) is BOTH the content address and
the stored row id. Decision/audit rows carry the ref in
``ontology_snapshot_ref``.

Snapshots are write-once: there is no update or delete API. Two
identical slices produce the same ref (idempotent store).
``verify_snapshot`` re-hashes the stored payload and compares with the
key ring — tampering or key mismatch fails the check.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..hmac_util import HmacKeyRing
from .models import (
    OntologyDimensionGroup,
    OntologyPreferenceGroup,
    OntologyPrincipal,
    OntologyRelationship,
    OntologySnapshot,
)


@dataclass
class SnapshotInput:
    """The ontology slice that shaped a decision."""

    principal_id: Optional[str]
    dimensions: dict[str, str]
    dimension_group_ids: list[str]
    preference_group_ids: list[str]
    matched_rule_id: Optional[int]
    policy_version: Optional[int]


def build_payload(
    db: Session,
    snap: SnapshotInput,
) -> dict[str, Any]:
    """Assemble the canonical snapshot payload from the DB slice."""
    principal = None
    relationships: list[dict[str, str]] = []
    if snap.principal_id is not None:
        row = db.get(OntologyPrincipal, snap.principal_id)
        if row is not None:
            principal = {
                "id": row.id,
                "kind": row.kind,
                "display_name": row.display_name,
            }
        rels = db.execute(
            select(OntologyRelationship).where(
                (OntologyRelationship.source_principal_id == snap.principal_id)
                | (OntologyRelationship.target_principal_id == snap.principal_id)
            )
        ).scalars().all()
        relationships = [
            {
                "source": r.source_principal_id,
                "type": r.relation_type,
                "target": r.target_principal_id,
            }
            for r in rels
        ]
        relationships.sort(key=lambda d: (d["source"], d["type"], d["target"]))

    dimension_groups: list[dict[str, Any]] = []
    for gid in sorted(set(snap.dimension_group_ids)):
        g = db.get(OntologyDimensionGroup, gid)
        if g is not None:
            dimension_groups.append(
                {"id": g.id, "name": g.name, "dimensions": g.dimensions or {}}
            )

    preference_groups: list[dict[str, Any]] = []
    for pid in sorted(set(snap.preference_group_ids)):
        p = db.get(OntologyPreferenceGroup, pid)
        if p is not None:
            preference_groups.append(
                {
                    "id": p.id,
                    "name": p.name,
                    "dimension_group_id": p.dimension_group_id,
                    "constraints": p.constraints or {},
                }
            )

    return {
        # NOTE: no timestamp inside the hashed payload — the address must
        # be a pure function of the slice (idempotent store: identical
        # slices → identical refs). OntologySnapshot.created_at records
        # when the row was written.
        "schema": "ontology-snapshot/v1",
        "principal": principal,
        "relationships": relationships,
        "dimensions": dict(sorted(snap.dimensions.items())),
        "dimension_groups": dimension_groups,
        "preference_groups": preference_groups,
        "matched_rule_id": snap.matched_rule_id,
        "policy_version": snap.policy_version,
    }


def capture_snapshot(
    db: Session,
    ring: HmacKeyRing,
    snap: SnapshotInput,
) -> str:
    """Build, hash, and idempotently store a snapshot. Returns the ref
    (``key_id:hexdigest``) for the decision/audit record."""
    payload = build_payload(db, snap)
    ref = ring.digest(payload)
    existing = db.get(OntologySnapshot, ref)
    if existing is not None:
        return ref
    db.add(OntologySnapshot(id=ref, payload=payload))
    try:
        db.commit()
    except IntegrityError:
        # Lost a race with an identical slice — same content address.
        db.rollback()
    return ref


def get_snapshot(db: Session, ref: str) -> Optional[OntologySnapshot]:
    return db.get(OntologySnapshot, ref)


def verify_snapshot(db: Session, ring: HmacKeyRing, ref: str) -> bool:
    """True iff the stored payload still hashes to the ref under the
    ring (tamper-evident; key rotation keeps old refs verifiable while
    the retired key is registered)."""
    row = db.get(OntologySnapshot, ref)
    if row is None:
        return False
    return ring.matches(row.payload, ref)
