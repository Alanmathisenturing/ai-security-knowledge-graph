from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Status(StrEnum):
    ACTIVE = "active"
    DRAFT = "draft"
    DEPRECATED = "deprecated"
    EXPERIMENTAL = "experimental"


class EntityType(StrEnum):
    ACTOR = "actor"
    ASSET = "asset"
    SYSTEM = "system"
    COMPONENT = "component"
    CAPABILITY = "capability"
    VULNERABILITY = "vulnerability"
    ATTACK = "attack"
    TECHNIQUE = "technique"
    PRIMITIVE = "primitive"
    EVENT = "event"
    OBSERVABLE = "observable"
    TRUST_BOUNDARY = "trust_boundary"
    CONTROL = "control"
    DETECTION = "detection"
    RESPONSE = "response"
    POLICY = "policy"
    IMPACT = "impact"
    EVIDENCE = "evidence"
    PROTOCOL = "protocol"
    MODEL = "model"
    LIFECYCLE_STAGE = "lifecycle_stage"


class RelationshipType(StrEnum):
    TARGETS = "targets"
    AFFECTS = "affects"
    EXPLOITS = "exploits"
    REQUIRES = "requires"
    ENABLES = "enables"
    CAUSES = "causes"
    CONTRIBUTES_TO = "contributes_to"
    PRECEDES = "precedes"
    CROSSES = "crosses"
    ABUSES = "abuses"
    GRANTS = "grants"
    ESCALATES = "escalates"
    DETECTS = "detects"
    PREVENTS = "prevents"
    MITIGATES = "mitigates"
    CONTAINS = "contains"
    DEPENDS_ON = "depends_on"
    DERIVED_FROM = "derived_from"
    SUPPORTED_BY = "supported_by"
    MAPPED_TO = "mapped_to"
    IMPLEMENTS = "implements"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class EvidenceType(StrEnum):
    PAPER = "paper"
    ADVISORY = "security_advisory"
    EXPERIMENT = "experiment"
    BENCHMARK = "benchmark"
    INCIDENT = "incident"
    SPECIFICATION = "specification"
    STANDARD = "standard"
    RED_TEAM_REPORT = "red_team_report"
    OBSERVED_BEHAVIOR = "observed_behavior"
    THEORETICAL_ANALYSIS = "theoretical_analysis"


class AiskgModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, use_enum_values=True)


class BaseKnowledgeObject(AiskgModel):
    id: str = Field(pattern=r"^ASKG-[A-Z][A-Z0-9_-]*-[0-9]{4,}$")
    name: str = Field(min_length=1)
    type: EntityType
    description: str = Field(min_length=1)
    version: str = "0.1.0"
    status: Status = Status.ACTIVE
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class RiskVector(AiskgModel):
    likelihood: RiskLevel = RiskLevel.UNKNOWN
    impact: RiskLevel = RiskLevel.UNKNOWN
    exploitability: RiskLevel = RiskLevel.UNKNOWN
    exposure: RiskLevel = RiskLevel.UNKNOWN
    detectability: RiskLevel = RiskLevel.UNKNOWN
    persistence: RiskLevel = RiskLevel.UNKNOWN
    reversibility: RiskLevel = RiskLevel.UNKNOWN
    blast_radius: RiskLevel = RiskLevel.UNKNOWN
    uncertainty: RiskLevel = RiskLevel.UNKNOWN
    confidence: RiskLevel = RiskLevel.UNKNOWN


class Relationship(AiskgModel):
    source: str
    target: str
    type: RelationshipType
    provenance: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Attack(BaseKnowledgeObject):
    type: EntityType = EntityType.ATTACK
    entry_points: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    capabilities_abused: list[str] = Field(default_factory=list)
    impacts: dict[str, RiskLevel] = Field(default_factory=dict)
    detection: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    risk: RiskVector = Field(default_factory=RiskVector)


class Vulnerability(BaseKnowledgeObject):
    type: EntityType = EntityType.VULNERABILITY
    affected_assets: list[str] = Field(default_factory=list)
    root_cause: str = "unknown"
    severity: RiskLevel = RiskLevel.UNKNOWN


class Capability(BaseKnowledgeObject):
    type: EntityType = EntityType.CAPABILITY
    risk: RiskLevel = RiskLevel.UNKNOWN
    required_auth: str = "none"
    required_scope: str = "none"
    allowed_principals: list[str] = Field(default_factory=list)
    trust_level: RiskLevel = RiskLevel.UNKNOWN
    side_effects: list[str] = Field(default_factory=list)
    reversibility: RiskLevel = RiskLevel.UNKNOWN
    controls: list[str] = Field(default_factory=list)


class Control(BaseKnowledgeObject):
    type: EntityType = EntityType.CONTROL
    control_class: str = "preventive"
    mitigates: list[str] = Field(default_factory=list)
    detects: list[str] = Field(default_factory=list)
    coverage: RiskLevel = RiskLevel.UNKNOWN


class Detection(BaseKnowledgeObject):
    type: EntityType = EntityType.DETECTION
    detection_type: str = "rule_based"
    signals: list[str] = Field(default_factory=list)
    observables: list[str] = Field(default_factory=list)


class Evidence(BaseKnowledgeObject):
    type: EntityType = EntityType.EVIDENCE
    evidence_type: EvidenceType = EvidenceType.THEORETICAL_ANALYSIS
    source: str = "unknown"
    citation: str | None = None
    publication_date: datetime | None = None
    observed_date: datetime | None = None
    confidence: RiskLevel = RiskLevel.UNKNOWN
    methodology: str = "unknown"
    reproducibility: str = "unknown"
    notes: str = ""


class TrustBoundary(BaseKnowledgeObject):
    type: EntityType = EntityType.TRUST_BOUNDARY
    source: str
    target: str
    trust_level: RiskLevel = RiskLevel.UNKNOWN
    authentication: str = "unknown"
    authorization: str = "unknown"
    data_flow: str = "unknown"
    capability_flow: str = "unknown"
    risk: RiskLevel = RiskLevel.UNKNOWN
    controls: list[str] = Field(default_factory=list)


class Impact(BaseKnowledgeObject):
    type: EntityType = EntityType.IMPACT
    confidentiality: RiskLevel = RiskLevel.UNKNOWN
    integrity: RiskLevel = RiskLevel.UNKNOWN
    availability: RiskLevel = RiskLevel.UNKNOWN
    privacy: RiskLevel = RiskLevel.UNKNOWN
    financial: RiskLevel = RiskLevel.UNKNOWN
    safety: RiskLevel = RiskLevel.UNKNOWN


class EntityEnvelope(AiskgModel):
    entity: BaseKnowledgeObject
    relationships: list[Relationship] = Field(default_factory=list)

    @field_validator("relationships")
    @classmethod
    def relationships_are_non_self_referential(cls, value: list[Relationship]) -> list[Relationship]:
        if any(item.source == item.target for item in value):
            raise ValueError("self-referential relationships are not allowed")
        return value
