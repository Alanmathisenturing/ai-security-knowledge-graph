from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Status(StrEnum):
    DRAFT = "draft"
    EXPERIMENTAL = "experimental"
    STABLE = "stable"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


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
    FOLLOWS = "follows"
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


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class EvidenceType(StrEnum):
    PAPER = "paper"
    ADVISORY = "advisory"
    EXPERIMENT = "experiment"
    BENCHMARK = "benchmark"
    INCIDENT = "incident"
    SPECIFICATION = "specification"
    STANDARD = "standard"
    RED_TEAM_REPORT = "red_team_report"
    VENDOR_REPORT = "vendor_report"
    OBSERVED_BEHAVIOR = "observed_behavior"
    THEORETICAL_ANALYSIS = "theoretical_analysis"


class AiskgModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, use_enum_values=True)


class Entity(AiskgModel):
    id: str = Field(pattern=r"^ASKG-[A-Z][A-Z0-9_]*-[0-9]{4,}$")
    type: EntityType
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    version: str = "0.1.0"
    status: Status = Status.DRAFT
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    id_prefix: ClassVar[dict[EntityType, str]] = {
        EntityType.ATTACK: "ATTACK", EntityType.VULNERABILITY: "VULN",
        EntityType.TECHNIQUE: "TECH", EntityType.CAPABILITY: "CAP",
        EntityType.CONTROL: "CONTROL", EntityType.DETECTION: "DETECTION",
        EntityType.EVIDENCE: "EVIDENCE", EntityType.ACTOR: "ACTOR",
        EntityType.ASSET: "ASSET", EntityType.IMPACT: "IMPACT",
    }

    @model_validator(mode="after")
    def validate_category_prefix(self) -> Entity:
        expected = self.id_prefix.get(self.type)
        if expected and not self.id.startswith(f"ASKG-{expected}-"):
            raise ValueError(f"{self.type.value} IDs must use ASKG-{expected}- prefix")
        return self


class RiskVector(AiskgModel):
    likelihood: Severity = Severity.UNKNOWN
    impact: Severity = Severity.UNKNOWN
    exploitability: Severity = Severity.UNKNOWN
    exposure: Severity = Severity.UNKNOWN
    detectability: Severity = Severity.UNKNOWN
    persistence: Severity = Severity.UNKNOWN
    reversibility: Severity = Severity.UNKNOWN
    blast_radius: Severity = Severity.UNKNOWN
    uncertainty: Severity = Severity.UNKNOWN
    confidence: Severity = Severity.UNKNOWN


class Reference(AiskgModel):
    uri: str
    title: str | None = None
    source_type: str = "documentation"
    accessed_at: datetime | None = None
    note: str | None = None


class Relationship(AiskgModel):
    source: str
    target: str
    relation: RelationshipType
    confidence: Severity = Severity.UNKNOWN
    evidence: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def no_self_reference(self) -> Relationship:
        if self.source == self.target:
            raise ValueError("self-referential relationships are not allowed")
        return self


class Actor(Entity):
    type: EntityType = EntityType.ACTOR
    capability: Severity = Severity.UNKNOWN
    motivation: str | None = None
    resources: Severity = Severity.UNKNOWN
    access_level: str = "unknown"
    technical_skill: Severity = Severity.UNKNOWN
    persistence: Severity = Severity.UNKNOWN
    automation_level: Severity = Severity.UNKNOWN


class Asset(Entity):
    type: EntityType = EntityType.ASSET
    asset_type: str
    criticality: Severity = Severity.UNKNOWN
    owner: str | None = None


class Capability(Entity):
    type: EntityType = EntityType.CAPABILITY
    risk: Severity = Severity.UNKNOWN
    required_auth: str = "none"
    required_scope: str = "none"
    allowed_principals: list[str] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    reversibility: Severity = Severity.UNKNOWN
    controls: list[str] = Field(default_factory=list)


class Attack(Entity):
    type: EntityType = EntityType.ATTACK
    attack_type: str = "unknown"
    entry_points: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)
    capabilities_abused: list[str] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    impacts: list[str] = Field(default_factory=list)
    observables: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    detections: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: Severity = Severity.UNKNOWN
    risk: RiskVector = Field(default_factory=RiskVector)


class Vulnerability(Entity):
    type: EntityType = EntityType.VULNERABILITY
    affected_components: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    exposure: Severity = Severity.UNKNOWN
    exploitability: Severity = Severity.UNKNOWN
    impact: Severity = Severity.UNKNOWN
    controls: list[str] = Field(default_factory=list)
    detections: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: Severity = Severity.UNKNOWN


class Technique(Entity):
    type: EntityType = EntityType.TECHNIQUE
    category: str = "unknown"
    primitives: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    capabilities_abused: list[str] = Field(default_factory=list)
    observables: list[str] = Field(default_factory=list)
    detections: list[str] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class Impact(Entity):
    type: EntityType = EntityType.IMPACT
    confidentiality: Severity = Severity.UNKNOWN
    integrity: Severity = Severity.UNKNOWN
    availability: Severity = Severity.UNKNOWN
    privacy: Severity = Severity.UNKNOWN
    safety: Severity = Severity.UNKNOWN
    financial: Severity = Severity.UNKNOWN
    legal: Severity = Severity.UNKNOWN
    physical: Severity = Severity.UNKNOWN
    reputational: Severity = Severity.UNKNOWN


class Control(Entity):
    type: EntityType = EntityType.CONTROL
    control_class: str = "preventive"
    mitigates: list[str] = Field(default_factory=list)
    detects: list[str] = Field(default_factory=list)
    applies_to: list[str] = Field(default_factory=list)


class Detection(Entity):
    type: EntityType = EntityType.DETECTION
    detection_type: str = "behavior"
    observables: list[str] = Field(default_factory=list)
    detects: list[str] = Field(default_factory=list)
    confidence: Severity = Severity.UNKNOWN
    false_positive_risk: Severity = Severity.UNKNOWN
    latency: str = "unknown"
    requirements: list[str] = Field(default_factory=list)


class Evidence(Entity):
    type: EntityType = EntityType.EVIDENCE
    evidence_type: EvidenceType = EvidenceType.THEORETICAL_ANALYSIS
    source: str = "unknown"
    citation: str | None = None
    publication_date: datetime | None = None
    observed_date: datetime | None = None
    methodology: str = "unknown"
    confidence: Severity = Severity.UNKNOWN
    reproducibility: str = "unknown"
    evidence_status: str = "available"
    notes: str = ""


class TrustBoundary(Entity):
    type: EntityType = EntityType.TRUST_BOUNDARY
    source: str
    target: str
    trust_level: Severity = Severity.UNKNOWN
    authentication: str = "unknown"
    authorization: str = "unknown"
    data_flow: str = "unknown"
    capability_flow: str = "unknown"
    controls: list[str] = Field(default_factory=list)


class Policy(Entity):
    type: EntityType = EntityType.POLICY
    subject: str
    action: str
    resource: str
    conditions: list[str] = Field(default_factory=list)
    effect: str = "deny"
    priority: int = 0


class Event(Entity):
    type: EntityType = EntityType.EVENT
    event_type: str
    timestamp: datetime = Field(default_factory=utc_now)
    actor: str | None = None
    subject: str | None = None
    action: str | None = None
    resource: str | None = None
    source: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Observable(Entity):
    type: EntityType = EntityType.OBSERVABLE
    observable_type: str
    value: str
    source: str | None = None
    confidence: Severity = Severity.UNKNOWN
    timestamp: datetime | None = None


class Protocol(Entity):
    type: EntityType = EntityType.PROTOCOL
    protocol_name: str
    version_label: str | None = None


class AIModel(Entity):
    type: EntityType = EntityType.MODEL
    architecture: str | None = None
    parameter_scale: str | None = None
    modality: list[str] = Field(default_factory=list)
    tokenizer: str | None = None
    training_stage: str | None = None
    alignment_method: str | None = None
    serving_stack: str | None = None
    provenance: list[str] = Field(default_factory=list)
    integrity: list[str] = Field(default_factory=list)


class LifecycleStage(Entity):
    type: EntityType = EntityType.LIFECYCLE_STAGE
    stage: str
