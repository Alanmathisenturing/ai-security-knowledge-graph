# Domain Model

## Phase 1 scope

The domain kernel is the stable semantic foundation for later ontology, graph, evidence, control, and detection subsystems. It intentionally does not implement graph projections or framework mappings.

## Semantic distinctions

AI-SKG keeps these concepts separate:

- `Attack`: an adversarial action or campaign
- `Vulnerability`: a weakness or enabling condition
- `Technique`: a reusable attack method
- `Capability`: what a system or principal can cause
- `Event`: something that occurred
- `Observable`: evidence available to a detector
- `Impact`: a consequence
- `Control`: a preventive, corrective, governance, or assurance measure
- `Detection`: a mechanism that identifies activity
- `Evidence`: provenance supporting a claim

For example, prompt injection can be represented as an attack or technique depending on the assertion being made; missing instruction isolation is a vulnerability; sensitive-data exposure is an impact; and instruction-boundary enforcement is a control.

## Stable identifiers

Entity IDs use the form:

```text
ASKG-<CATEGORY>-<NUMBER>
```

Examples:

```text
ASKG-ATTACK-0001
ASKG-VULN-0001
ASKG-CAP-0001
ASKG-EVIDENCE-0001
```

The numeric component does not need to be sequential. IDs are references, not list positions.

## Core modules

The current compatibility module is `src/aiskg/models.py`. The next refactor may split it into a `src/aiskg/models/` package, but public imports should remain stable during the transition.

Core types include:

- `Entity`, `Actor`, `Asset`, `Attack`, `Vulnerability`, `Technique`
- `Capability`, `Control`, `Detection`, `Evidence`
- `TrustBoundary`, `Impact`, `Policy`, `Event`, `Observable`
- `Protocol`, `AIModel`, `LifecycleStage`
- `Relationship` and `RelationshipType`

All models use Pydantic v2 with forbidden extra fields, assignment validation, controlled enums, and serializable values.

## Relationship foundation

Relationships use stable IDs and carry confidence, evidence, and metadata. The vocabulary includes `targets`, `affects`, `exploits`, `requires`, `enables`, `causes`, `crosses`, `escalates`, `detects`, `prevents`, `mitigates`, `supported_by`, and `mapped_to`.

Graph construction and relationship legality validation are intentionally deferred to later phases.
