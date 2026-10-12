"""CRUD for the personal ontology (config SQLite).

Every mutation validates references (no dangling principals, dimension
values inside their allowed sets) and is audit-logged as an admin
action via the existing audit API (``tool="ontology.admin"``,
``action="<entity>.<op>"``). Reads are not logged — the ontology is
configuration, not sensitive data.

Validation failures raise ``OntologyError`` (a ValueError) before
anything is written.
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import AuditLog
from .models import (
    CANDIDATE_KINDS,
    CANDIDATE_STATUSES,
    FEEDBACK_KINDS,
    LABEL_CLASSES,
    PREFERENCE_CONSTRAINT_KEYS,
    PRINCIPAL_KINDS,
    RELATIONSHIP_TYPES,
    REVIEW_STATUSES,
    OntologyAction,
    OntologyAgentBinding,
    OntologyCandidate,
    OntologyDimension,
    OntologyDimensionGroup,
    OntologyFeedbackEvent,
    OntologyPreferenceGroup,
    OntologyPrincipal,
    OntologyRelationship,
    OntologyResource,
    OntologyReviewItem,
    new_ontology_id,
)


class OntologyError(ValueError):
    """Invalid ontology data or reference (raised before any write)."""


ADMIN_TOOL = "ontology.admin"


class OntologyStore:
    """CRUD + validation + admin-action audit logging for the ontology."""

    def __init__(
        self,
        db: Session,
        audit: Optional[AuditLog] = None,
        admin_id: str = "admin",
    ) -> None:
        self.db = db
        self.audit = audit
        self.admin_id = admin_id

    # -- internals ----------------------------------------------------

    def _log(self, action: str, redacted_args: dict[str, Any]) -> None:
        if self.audit is not None:
            self.audit.append(
                agent_id=self.admin_id,
                tool=ADMIN_TOOL,
                action=action,
                decision="allowed",
                redacted_args=redacted_args,
            )

    def _get_principal(self, principal_id: str) -> OntologyPrincipal:
        row = self.db.get(OntologyPrincipal, principal_id)
        if row is None:
            raise OntologyError(f"unknown principal {principal_id!r}")
        return row

    def _check_dimensions_valid(
        self, dimensions: dict[str, str], *, what: str
    ) -> None:
        """Every dimension must exist and every value must be allowed."""
        if not isinstance(dimensions, dict):
            raise OntologyError(f"{what}: dimensions must be an object")
        for name, value in dimensions.items():
            dim = self.db.get(OntologyDimension, name)
            if dim is None:
                raise OntologyError(f"{what}: unknown dimension {name!r}")
            if value not in (dim.allowed_values or []):
                raise OntologyError(
                    f"{what}: value {value!r} not allowed for dimension "
                    f"{name!r} (allowed: {dim.allowed_values})"
                )

    # -- principals ---------------------------------------------------

    def create_principal(
        self,
        kind: str,
        display_name: str,
        provenance: str = "explicit:manual",
    ) -> OntologyPrincipal:
        if kind not in PRINCIPAL_KINDS:
            raise OntologyError(
                f"unknown principal kind {kind!r}; want one of {PRINCIPAL_KINDS}"
            )
        if not display_name or not display_name.strip():
            raise OntologyError("display_name must be non-empty")
        row = OntologyPrincipal(
            id=new_ontology_id(),
            kind=kind,
            display_name=display_name.strip(),
            provenance=provenance,
        )
        self.db.add(row)
        self.db.commit()
        self._log(
            "principal.create",
            {"principal_id": row.id, "kind": kind, "provenance": provenance},
        )
        return row

    def get_principal(self, principal_id: str) -> Optional[OntologyPrincipal]:
        return self.db.get(OntologyPrincipal, principal_id)

    def list_principals(self, kind: Optional[str] = None) -> list[OntologyPrincipal]:
        stmt = select(OntologyPrincipal).order_by(OntologyPrincipal.display_name)
        if kind is not None:
            if kind not in PRINCIPAL_KINDS:
                raise OntologyError(f"unknown principal kind {kind!r}")
            stmt = stmt.where(OntologyPrincipal.kind == kind)
        return list(self.db.execute(stmt).scalars().all())

    def update_principal(
        self, principal_id: str, display_name: Optional[str] = None
    ) -> OntologyPrincipal:
        row = self._get_principal(principal_id)
        if display_name is not None:
            if not display_name.strip():
                raise OntologyError("display_name must be non-empty")
            row.display_name = display_name.strip()
        self.db.commit()
        self._log("principal.update", {"principal_id": principal_id})
        return row

    def delete_principal(self, principal_id: str) -> None:
        row = self._get_principal(principal_id)
        # Refuse while referenced (no dangling relationships / resources).
        rel = self.db.execute(
            select(OntologyRelationship).where(
                (OntologyRelationship.source_principal_id == principal_id)
                | (OntologyRelationship.target_principal_id == principal_id)
            ).limit(1)
        ).scalar_one_or_none()
        if rel is not None:
            raise OntologyError(
                f"principal {principal_id!r} is still referenced by a relationship"
            )
        res = self.db.execute(
            select(OntologyResource)
            .where(OntologyResource.owner_principal_id == principal_id)
            .limit(1)
        ).scalar_one_or_none()
        if res is not None:
            raise OntologyError(
                f"principal {principal_id!r} still owns a resource"
            )
        self.db.delete(row)
        self.db.commit()
        self._log("principal.delete", {"principal_id": principal_id})

    # -- relationships ------------------------------------------------

    def add_relationship(
        self,
        source_principal_id: str,
        relation_type: str,
        target_principal_id: str,
        provenance: str = "explicit:manual",
    ) -> OntologyRelationship:
        if relation_type not in RELATIONSHIP_TYPES:
            raise OntologyError(
                f"unknown relation type {relation_type!r}; "
                f"want one of {RELATIONSHIP_TYPES}"
            )
        self._get_principal(source_principal_id)  # no dangling references
        self._get_principal(target_principal_id)
        row = OntologyRelationship(
            source_principal_id=source_principal_id,
            relation_type=relation_type,
            target_principal_id=target_principal_id,
            provenance=provenance,
        )
        self.db.add(row)
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise OntologyError("relationship already exists")
        self._log(
            "relationship.add",
            {
                "source": source_principal_id,
                "type": relation_type,
                "target": target_principal_id,
            },
        )
        return row

    def remove_relationship(
        self, source_principal_id: str, relation_type: str, target_principal_id: str
    ) -> bool:
        row = self.db.execute(
            select(OntologyRelationship).where(
                OntologyRelationship.source_principal_id == source_principal_id,
                OntologyRelationship.relation_type == relation_type,
                OntologyRelationship.target_principal_id == target_principal_id,
            )
        ).scalar_one_or_none()
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        self._log(
            "relationship.remove",
            {
                "source": source_principal_id,
                "type": relation_type,
                "target": target_principal_id,
            },
        )
        return True

    def relationships_of(
        self,
        principal_id: str,
        direction: str = "out",
        relation_type: Optional[str] = None,
    ) -> list[OntologyRelationship]:
        """Relationships touching a principal ("out": source, "in": target,
        "both")."""
        from sqlalchemy import or_

        self._get_principal(principal_id)
        if direction not in ("out", "in", "both"):
            raise OntologyError("direction must be 'out', 'in', or 'both'")
        conds = []
        if direction in ("out", "both"):
            conds.append(OntologyRelationship.source_principal_id == principal_id)
        if direction in ("in", "both"):
            conds.append(OntologyRelationship.target_principal_id == principal_id)
        stmt = select(OntologyRelationship).where(or_(*conds))
        if relation_type is not None:
            if relation_type not in RELATIONSHIP_TYPES:
                raise OntologyError(f"unknown relation type {relation_type!r}")
            stmt = stmt.where(OntologyRelationship.relation_type == relation_type)
        return list(self.db.execute(stmt).scalars().all())

    def has_relationship(
        self, source_principal_id: str, relation_type: str, target_principal_id: str
    ) -> bool:
        row = self.db.execute(
            select(OntologyRelationship).where(
                OntologyRelationship.source_principal_id == source_principal_id,
                OntologyRelationship.relation_type == relation_type,
                OntologyRelationship.target_principal_id == target_principal_id,
            ).limit(1)
        ).scalar_one_or_none()
        return row is not None

    def related_principals(
        self, target_principal_id: str, relation_type: str
    ) -> list[OntologyPrincipal]:
        """Sources related to a target (e.g. household members of an owner)."""
        if relation_type not in RELATIONSHIP_TYPES:
            raise OntologyError(f"unknown relation type {relation_type!r}")
        stmt = (
            select(OntologyPrincipal)
            .join(
                OntologyRelationship,
                OntologyRelationship.source_principal_id == OntologyPrincipal.id,
            )
            .where(
                OntologyRelationship.target_principal_id == target_principal_id,
                OntologyRelationship.relation_type == relation_type,
            )
            .order_by(OntologyPrincipal.display_name)
        )
        return list(self.db.execute(stmt).scalars().all())

    # -- agent bindings ------------------------------------------------

    def bind_agent(self, agent_id: str, principal_id: str) -> OntologyAgentBinding:
        self._get_principal(principal_id)
        row = self.db.get(OntologyAgentBinding, agent_id)
        if row is None:
            row = OntologyAgentBinding(agent_id=agent_id, principal_id=principal_id)
            self.db.add(row)
        else:
            row.principal_id = principal_id
        self.db.commit()
        self._log(
            "agent.bind", {"agent_id": agent_id, "principal_id": principal_id}
        )
        return row

    def unbind_agent(self, agent_id: str) -> bool:
        row = self.db.get(OntologyAgentBinding, agent_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        self._log("agent.unbind", {"agent_id": agent_id})
        return True

    def principal_for_agent(self, agent_id: str) -> Optional[str]:
        row = self.db.get(OntologyAgentBinding, agent_id)
        return row.principal_id if row else None

    # -- resources -----------------------------------------------------

    def create_resource(
        self,
        kind: str,
        display_name: str,
        label_class: str,
        owner_principal_id: str,
        provenance: str = "explicit:manual",
    ) -> OntologyResource:
        if label_class not in LABEL_CLASSES:
            raise OntologyError(
                f"unknown label class {label_class!r}; want one of {LABEL_CLASSES}"
            )
        self._get_principal(owner_principal_id)
        if not kind or not display_name.strip():
            raise OntologyError("kind and display_name must be non-empty")
        row = OntologyResource(
            id=new_ontology_id(),
            kind=kind,
            display_name=display_name.strip(),
            label_class=label_class,
            owner_principal_id=owner_principal_id,
            provenance=provenance,
        )
        self.db.add(row)
        self.db.commit()
        self._log("resource.create", {"resource_id": row.id, "label": label_class})
        return row

    def get_resource(self, resource_id: str) -> Optional[OntologyResource]:
        return self.db.get(OntologyResource, resource_id)

    def list_resources(
        self,
        owner_principal_id: Optional[str] = None,
        label_class: Optional[str] = None,
    ) -> list[OntologyResource]:
        stmt = select(OntologyResource).order_by(OntologyResource.display_name)
        if owner_principal_id is not None:
            stmt = stmt.where(
                OntologyResource.owner_principal_id == owner_principal_id
            )
        if label_class is not None:
            if label_class not in LABEL_CLASSES:
                raise OntologyError(f"unknown label class {label_class!r}")
            stmt = stmt.where(OntologyResource.label_class == label_class)
        return list(self.db.execute(stmt).scalars().all())

    def delete_resource(self, resource_id: str) -> bool:
        row = self.db.get(OntologyResource, resource_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        self._log("resource.delete", {"resource_id": resource_id})
        return True

    # -- actions -------------------------------------------------------

    def create_action(
        self,
        name: str,
        default_sensitivity: str = "standard",
        provenance: str = "explicit:manual",
    ) -> OntologyAction:
        if default_sensitivity not in ("standard", "sensitive"):
            raise OntologyError(
                "default_sensitivity must be 'standard' or 'sensitive'"
            )
        if not name or not name.strip():
            raise OntologyError("name must be non-empty")
        row = OntologyAction(
            id=new_ontology_id(),
            name=name.strip(),
            default_sensitivity=default_sensitivity,
            provenance=provenance,
        )
        self.db.add(row)
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise OntologyError(f"action {name!r} already exists")
        self._log("action.create", {"action_id": row.id, "name": name})
        return row

    def list_actions(self) -> list[OntologyAction]:
        return list(
            self.db.execute(
                select(OntologyAction).order_by(OntologyAction.name)
            ).scalars().all()
        )

    def delete_action(self, action_id: str) -> bool:
        row = self.db.get(OntologyAction, action_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        self._log("action.delete", {"action_id": action_id})
        return True

    # -- dimensions ----------------------------------------------------

    def upsert_dimension(
        self,
        name: str,
        allowed_values: list[str],
        provenance: str = "explicit:manual",
    ) -> OntologyDimension:
        if not name or not name.strip():
            raise OntologyError("dimension name must be non-empty")
        values = [str(v) for v in (allowed_values or [])]
        if not values or any(not v for v in values):
            raise OntologyError("allowed_values must be a non-empty list of strings")
        if len(set(values)) != len(values):
            raise OntologyError("allowed_values must not contain duplicates")
        name = name.strip()
        row = self.db.get(OntologyDimension, name)
        if row is None:
            row = OntologyDimension(
                name=name, allowed_values=values, provenance=provenance
            )
            self.db.add(row)
        else:
            row.allowed_values = values
            row.provenance = provenance
        self.db.commit()
        self._log(
            "dimension.upsert",
            {"name": name, "values": values, "provenance": provenance},
        )
        return row

    def get_dimension(self, name: str) -> Optional[OntologyDimension]:
        return self.db.get(OntologyDimension, name)

    def list_dimensions(self) -> list[OntologyDimension]:
        return list(
            self.db.execute(
                select(OntologyDimension).order_by(OntologyDimension.name)
            ).scalars().all()
        )

    def delete_dimension(self, name: str) -> bool:
        # Refuse while a dimension group references it (no dangling refs).
        for group in self.list_dimension_groups():
            if name in (group.dimensions or {}):
                raise OntologyError(
                    f"dimension {name!r} is referenced by dimension group "
                    f"{group.name!r}"
                )
        row = self.db.get(OntologyDimension, name)
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        self._log("dimension.delete", {"name": name})
        return True

    # -- dimension groups ("scenario slices") --------------------------

    def create_dimension_group(
        self,
        name: str,
        dimensions: dict[str, str],
        provenance: str = "explicit:manual",
    ) -> OntologyDimensionGroup:
        if not name or not name.strip():
            raise OntologyError("dimension group name must be non-empty")
        self._check_dimensions_valid(dimensions, what="dimension group")
        row = OntologyDimensionGroup(
            id=new_ontology_id(),
            name=name.strip(),
            dimensions=dict(dimensions),
            provenance=provenance,
        )
        self.db.add(row)
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise OntologyError(f"dimension group {name!r} already exists")
        self._log("dimension_group.create", {"name": name})
        return row

    def get_dimension_group(self, group_id: str) -> Optional[OntologyDimensionGroup]:
        return self.db.get(OntologyDimensionGroup, group_id)

    def get_dimension_group_by_name(
        self, name: str
    ) -> Optional[OntologyDimensionGroup]:
        return self.db.execute(
            select(OntologyDimensionGroup).where(OntologyDimensionGroup.name == name)
        ).scalar_one_or_none()

    def list_dimension_groups(self) -> list[OntologyDimensionGroup]:
        return list(
            self.db.execute(
                select(OntologyDimensionGroup).order_by(OntologyDimensionGroup.name)
            ).scalars().all()
        )

    def delete_dimension_group(self, group_id: str) -> bool:
        for pref in self.list_preference_groups():
            if pref.dimension_group_id == group_id:
                raise OntologyError(
                    "dimension group is referenced by a preference group"
                )
        row = self.db.get(OntologyDimensionGroup, group_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        self._log("dimension_group.delete", {"group_id": group_id})
        return True

    # -- preference groups ---------------------------------------------

    def create_preference_group(
        self,
        name: str,
        dimension_group_id: str,
        constraints: dict[str, list[str]],
        provenance: str = "explicit:manual",
    ) -> OntologyPreferenceGroup:
        if not name or not name.strip():
            raise OntologyError("preference group name must be non-empty")
        group = self.db.get(OntologyDimensionGroup, dimension_group_id)
        if group is None:
            raise OntologyError(
                f"unknown dimension group {dimension_group_id!r}"
            )
        constraints = constraints or {}
        if not isinstance(constraints, dict):
            raise OntologyError("constraints must be an object")
        for key, selectors in constraints.items():
            if key not in PREFERENCE_CONSTRAINT_KEYS:
                raise OntologyError(
                    f"unknown constraint key {key!r}; "
                    f"want one of {PREFERENCE_CONSTRAINT_KEYS}"
                )
            if not isinstance(selectors, list) or not all(
                isinstance(s, str) and s for s in selectors
            ):
                raise OntologyError(
                    f"constraint {key!r} must be a list of tool selectors"
                )
        row = OntologyPreferenceGroup(
            id=new_ontology_id(),
            name=name.strip(),
            dimension_group_id=dimension_group_id,
            constraints={k: list(v) for k, v in constraints.items()},
            provenance=provenance,
        )
        self.db.add(row)
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise OntologyError(f"preference group {name!r} already exists")
        self._log("preference_group.create", {"name": name})
        return row

    def list_preference_groups(self) -> list[OntologyPreferenceGroup]:
        return list(
            self.db.execute(
                select(OntologyPreferenceGroup).order_by(OntologyPreferenceGroup.name)
            ).scalars().all()
        )

    def delete_preference_group(self, group_id: str) -> bool:
        row = self.db.get(OntologyPreferenceGroup, group_id)
        if row is None:
            return False
        self.db.delete(row)
        self.db.commit()
        self._log("preference_group.delete", {"group_id": group_id})
        return True

    # -- household seeding (PAA08) --------------------------------------

    def seed_household(
        self,
        owner_display_name: str,
        member_display_names: list[str],
        provenance: str = "explicit:seed",
    ) -> dict[str, OntologyPrincipal]:
        """Seed household roles: one owner person principal + one person
        principal per member, each linked ``household_member_of`` the
        owner (feeds PAA08 household-role scoping).

        Idempotent per display name: existing person principals with the
        same display name are reused.
        """
        def _ensure_person(display_name: str) -> OntologyPrincipal:
            existing = self.db.execute(
                select(OntologyPrincipal).where(
                    OntologyPrincipal.kind == "person",
                    OntologyPrincipal.display_name == display_name,
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing
            return self.create_principal(
                "person", display_name, provenance=provenance
            )

        owner = _ensure_person(owner_display_name)
        out = {"owner": owner}
        for member_name in member_display_names or []:
            member = _ensure_person(member_name)
            if not self.has_relationship(
                member.id, "household_member_of", owner.id
            ):
                self.add_relationship(
                    member.id, "household_member_of", owner.id,
                    provenance=provenance,
                )
            out[member_name] = member
        return out

    # -- discovery candidates ------------------------------------------

    def propose_candidates(
        self, candidates: list[dict[str, Any]]
    ) -> list[OntologyCandidate]:
        """Stage discovery-proposed entries for confirmation.

        Each item: ``{"kind", "payload", "provenance", "confidence"}``.
        ``provenance`` MUST start with ``"inferred:"`` (FR-PAA04-001);
        ``confidence`` is a 0..1 float. Items identical (by
        kind+payload) to an already-pending candidate are skipped —
        discovery sweeps are idempotent. Returns the created rows.

        Candidates are NOT authority: the policy engine never consults
        them. Only ``confirm_candidate`` promotes one into a real
        entity.
        """
        import hashlib
        import json as _json

        created: list[OntologyCandidate] = []
        for item in candidates or []:
            kind = item.get("kind")
            if kind not in CANDIDATE_KINDS:
                raise OntologyError(
                    f"unknown candidate kind {kind!r}; "
                    f"want one of {CANDIDATE_KINDS}"
                )
            provenance = item.get("provenance") or ""
            if not provenance.startswith("inferred:"):
                raise OntologyError(
                    "candidate provenance must start with 'inferred:' "
                    f"(got {provenance!r})"
                )
            confidence = item.get("confidence", 0.5)
            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                raise OntologyError(
                    f"candidate confidence must be a number (got {confidence!r})"
                )
            if not 0.0 <= confidence <= 1.0:
                raise OntologyError("candidate confidence must be within 0..1")
            payload = item.get("payload") or {}
            if not isinstance(payload, dict):
                raise OntologyError("candidate payload must be an object")
            dedupe_key = hashlib.sha256(
                _json.dumps(
                    {"kind": kind, "payload": payload}, sort_keys=True
                ).encode("utf-8")
            ).hexdigest()
            existing = self.db.execute(
                select(OntologyCandidate).where(
                    OntologyCandidate.dedupe_key == dedupe_key,
                    OntologyCandidate.status == "pending_confirmation",
                )
            ).scalar_one_or_none()
            if existing is not None:
                continue  # already proposed and awaiting review
            row = OntologyCandidate(
                id=new_ontology_id(),
                kind=kind,
                payload=dict(payload),
                provenance=provenance,
                confidence=confidence,
                status="pending_confirmation",
                dedupe_key=dedupe_key,
            )
            self.db.add(row)
            created.append(row)
        if created:
            self.db.commit()
            self._log(
                "candidate.propose",
                {"count": len(created)},
            )
        return created

    def get_candidate(self, candidate_id: str) -> Optional[OntologyCandidate]:
        return self.db.get(OntologyCandidate, candidate_id)

    def list_candidates(
        self, status: Optional[str] = None
    ) -> list[OntologyCandidate]:
        if status is not None and status not in CANDIDATE_STATUSES:
            raise OntologyError(
                f"unknown candidate status {status!r}; "
                f"want one of {CANDIDATE_STATUSES}"
            )
        stmt = select(OntologyCandidate).order_by(
            OntologyCandidate.created_at.desc()
        )
        if status is not None:
            stmt = stmt.where(OntologyCandidate.status == status)
        return list(self.db.execute(stmt).scalars().all())

    def confirm_candidate(
        self, candidate_id: str, corrections: Optional[dict[str, Any]] = None
    ) -> Any:
        """Promote a pending candidate into a real ontology entity.

        ``corrections`` is merged over the candidate payload before
        creation (the reviewer's explicit edits — recorded in the
        provenance chain). The created entity's provenance becomes
        ``"<inferred provenance> -> explicit:confirmed"``. The
        candidate row is marked confirmed with the full chain.

        Nothing else is mutated: confirmation is the ONLY path by
        which an inferred entry becomes authority (FR-PAA04-002).
        """
        from ..models import utcnow

        cand = self.db.get(OntologyCandidate, candidate_id)
        if cand is None:
            raise OntologyError(f"unknown candidate {candidate_id!r}")
        if cand.status != "pending_confirmation":
            raise OntologyError(
                f"candidate {candidate_id!r} is already {cand.status}"
            )
        payload = dict(cand.payload or {})
        if corrections:
            if not isinstance(corrections, dict):
                raise OntologyError("corrections must be an object")
            payload.update(corrections)
        chain = f"{cand.provenance} -> explicit:confirmed"
        if corrections:
            chain += f" (corrections: {sorted(corrections)})"
        provenance = chain
        entity = self._materialize_candidate(cand.kind, payload, provenance)
        cand.status = "confirmed"
        cand.provenance_chain = chain
        cand.decided_at = utcnow()
        self.db.commit()
        self._log(
            "candidate.confirm",
            {"candidate_id": candidate_id, "kind": cand.kind},
        )
        return entity

    def _materialize_candidate(
        self, kind: str, payload: dict[str, Any], provenance: str
    ) -> Any:
        """Create the real entity for a confirmed candidate."""
        if kind == "principal":
            return self.create_principal(
                payload["kind"],
                payload["display_name"],
                provenance=provenance,
            )
        if kind == "relationship":
            source_id = self._resolve_principal_ref(payload, "source")
            target_id = self._resolve_principal_ref(payload, "target")
            return self.add_relationship(
                source_id,
                payload["relation_type"],
                target_id,
                provenance=provenance,
            )
        if kind == "resource":
            owner_id = self._resolve_principal_ref(payload, "owner")
            return self.create_resource(
                payload["kind"],
                payload["display_name"],
                payload["label_class"],
                owner_id,
                provenance=provenance,
            )
        if kind == "action":
            return self.create_action(
                payload["name"],
                payload.get("default_sensitivity", "standard"),
                provenance=provenance,
            )
        if kind == "dimension":
            name = payload["name"]
            existing = self.db.get(OntologyDimension, name)
            if existing is None:
                return self.upsert_dimension(
                    name, payload["allowed_values"], provenance=provenance
                )
            # Dimension exists: extend the value set (idempotent union).
            merged = list(dict.fromkeys(
                list(existing.allowed_values or [])
                + [str(v) for v in payload.get("allowed_values", [])]
            ))
            return self.upsert_dimension(name, merged, provenance=provenance)
        if kind == "dimension_group":
            return self.create_dimension_group(
                payload["name"], payload["dimensions"], provenance=provenance
            )
        if kind == "preference_group":
            group_id = payload.get("dimension_group_id")
            if group_id is None:
                group = self.get_dimension_group_by_name(
                    payload["dimension_group_name"]
                )
                if group is None:
                    raise OntologyError(
                        "preference_group candidate needs dimension_group_id "
                        "or a known dimension_group_name"
                    )
                group_id = group.id
            return self.create_preference_group(
                payload["name"],
                group_id,
                payload.get("constraints", {}),
                provenance=provenance,
            )
        raise OntologyError(f"unknown candidate kind {kind!r}")

    def _resolve_principal_ref(
        self, payload: dict[str, Any], key: str
    ) -> str:
        """Resolve a candidate's principal reference: ``<key>_id`` wins,
        else ``<key>_display_name`` is looked up among person principals
        (created on demand would be authority-by-side-effect, so an
        unknown name is an error — the reviewer confirms the principal
        candidate first)."""
        pid = payload.get(f"{key}_id")
        if pid:
            self._get_principal(pid)
            return pid
        name = payload.get(f"{key}_display_name")
        if not name:
            raise OntologyError(
                f"candidate payload needs {key}_id or {key}_display_name"
            )
        row = self.db.execute(
            select(OntologyPrincipal).where(
                OntologyPrincipal.kind == "person",
                OntologyPrincipal.display_name == name,
            )
        ).scalar_one_or_none()
        if row is None:
            raise OntologyError(
                f"candidate references unknown person {name!r}; confirm the "
                "principal candidate first"
            )
        return row.id

    def reject_candidate(self, candidate_id: str) -> OntologyCandidate:
        """Drop a pending candidate. The row is kept (status=rejected)
        for auditability — rejected inferences stay visible."""
        from ..models import utcnow

        cand = self.db.get(OntologyCandidate, candidate_id)
        if cand is None:
            raise OntologyError(f"unknown candidate {candidate_id!r}")
        if cand.status != "pending_confirmation":
            raise OntologyError(
                f"candidate {candidate_id!r} is already {cand.status}"
            )
        cand.status = "rejected"
        cand.provenance_chain = f"{cand.provenance} -> explicit:rejected"
        cand.decided_at = utcnow()
        self.db.commit()
        self._log("candidate.reject", {"candidate_id": candidate_id})
        return cand

    # -- review queue (PAA04: flag, never auto-mutate) ------------------

    def flag_for_review(
        self,
        entry_kind: str,
        entry_id: str,
        reason: str,
        provenance: str,
        context: Optional[dict[str, Any]] = None,
    ) -> OntologyReviewItem:
        """Flag an entry for human review. Open dedupe: an already-open
        item for the same (entry_kind, entry_id, reason) is returned
        instead of duplicated."""
        existing = self.db.execute(
            select(OntologyReviewItem).where(
                OntologyReviewItem.entry_kind == entry_kind,
                OntologyReviewItem.entry_id == entry_id,
                OntologyReviewItem.reason == reason,
                OntologyReviewItem.status == "open",
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing
        row = OntologyReviewItem(
            id=new_ontology_id(),
            entry_kind=entry_kind,
            entry_id=entry_id,
            reason=reason,
            provenance=provenance,
            context=dict(context or {}),
        )
        self.db.add(row)
        self.db.commit()
        self._log(
            "review.flag",
            {"entry_kind": entry_kind, "entry_id": entry_id},
        )
        return row

    def list_review_items(
        self, status: Optional[str] = None
    ) -> list[OntologyReviewItem]:
        if status is not None and status not in REVIEW_STATUSES:
            raise OntologyError(
                f"unknown review status {status!r}; "
                f"want one of {REVIEW_STATUSES}"
            )
        stmt = select(OntologyReviewItem).order_by(
            OntologyReviewItem.detected_at.desc()
        )
        if status is not None:
            stmt = stmt.where(OntologyReviewItem.status == status)
        return list(self.db.execute(stmt).scalars().all())

    def resolve_review_item(
        self, item_id: str, resolution: str = ""
    ) -> OntologyReviewItem:
        return self._set_review_status(item_id, "resolved", resolution)

    def dismiss_review_item(
        self, item_id: str, resolution: str = ""
    ) -> OntologyReviewItem:
        return self._set_review_status(item_id, "dismissed", resolution)

    def _set_review_status(
        self, item_id: str, status: str, resolution: str
    ) -> OntologyReviewItem:
        row = self.db.get(OntologyReviewItem, item_id)
        if row is None:
            raise OntologyError(f"unknown review item {item_id!r}")
        if row.status != "open":
            raise OntologyError(f"review item {item_id!r} is already {row.status}")
        row.status = status
        if resolution:
            context = dict(row.context or {})
            context["resolution"] = resolution
            row.context = context
        self.db.commit()
        self._log(
            "review.resolve",
            {"item_id": item_id, "status": status},
        )
        return row

    # -- feedback events (immutable input to the living-ontology loop) --

    def record_feedback_event(
        self,
        kind: str,
        summary: dict[str, Any],
        provenance: str,
    ) -> OntologyFeedbackEvent:
        if kind not in FEEDBACK_KINDS:
            raise OntologyError(
                f"unknown feedback kind {kind!r}; want one of {FEEDBACK_KINDS}"
            )
        if not isinstance(summary, dict):
            raise OntologyError("feedback summary must be an object")
        row = OntologyFeedbackEvent(
            id=new_ontology_id(),
            kind=kind,
            summary=dict(summary),
            provenance=provenance,
        )
        self.db.add(row)
        self.db.commit()
        self._log("feedback.record", {"kind": kind})
        return row

    def list_feedback_events(
        self, kind: Optional[str] = None, limit: int = 200
    ) -> list[OntologyFeedbackEvent]:
        stmt = select(OntologyFeedbackEvent).order_by(
            OntologyFeedbackEvent.created_at.desc()
        ).limit(limit)
        if kind is not None:
            if kind not in FEEDBACK_KINDS:
                raise OntologyError(f"unknown feedback kind {kind!r}")
            stmt = stmt.where(OntologyFeedbackEvent.kind == kind)
        return list(self.db.execute(stmt).scalars().all())
