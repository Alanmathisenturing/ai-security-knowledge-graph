# Implementation Status

Updated during the Phase 1 domain-kernel transition on 2026-09-22.

## Evidence-based status

| Area | Status | Evidence |
|---|---|---|
| Project metadata | IMPLEMENTED | `pyproject.toml` defines the package, runtime dependencies, and development tools. |
| Package entry point | PARTIAL | `src/aiskg/__init__.py` exports the initial public API; compatibility has not been verified by an executed test run. |
| Domain kernel | PARTIAL | `src/aiskg/models.py` contains typed enums, entity models, stable-ID validation, risk vectors, references, and relationship primitives. Execution and full semantic test coverage remain pending. |
| Semantic distinctions | PARTIAL | Attack, vulnerability, technique, capability, impact, control, detection, evidence, event, observable, policy, and trust-boundary classes exist; relationship legality is not yet implemented. |
| Stable identifiers | PARTIAL | Entity IDs have an ASKG/category/numeric pattern and category-prefix validation for core types; repository-wide uniqueness is not yet enforced. |
| Graph engine | PARTIAL | `src/aiskg/graph.py` provides a NetworkX-based engine and analysis methods; integration with the typed domain kernel is not yet verified. |
| YAML loader | PARTIAL | `src/aiskg/loader.py` supports recursive YAML loading for initial attack/evidence types; all domain types and cross-reference validation are pending. |
| Validation | PARTIAL | Basic ID/reference helpers exist; schema, ontology, mapping, evidence, and graph validators are pending. |
| CLI | PARTIAL | `pyproject.toml` declares the `aiskg` entry point; command behavior and exit codes are not yet verified by execution. |
| Knowledge dataset | PARTIAL | Initial attack and evidence YAML entries exist; the canonical dataset is intentionally incomplete. |
| JSON Schema | MISSING | No verified `schemas/json-schema/` implementation is present. |
| Ontology directories | MISSING | No verified layered `ontology/` implementation is present. |
| Framework mappings | MISSING | OWASP, MITRE ATLAS, NIST AI RMF, and ISO/IEC 42001 mappings are not implemented. |
| Examples | MISSING | Executable scenario examples are not implemented. |
| Documentation | PARTIAL | Baseline, implementation-status, and domain-model documents exist; documentation still needs synchronization with executable behavior. |
| CI | PARTIAL | Project metadata contains test/lint configuration; a complete verified CI gate is not present. |
| Test suite | PARTIAL | Test files exist in the repository; no execution result is available in this environment. |
| Coverage | UNTESTED | No coverage command result is available. |
| Ruff | UNTESTED | No Ruff execution result is available. |
| MyPy | UNTESTED | No MyPy execution result is available. |

## Phase tracker

1. Audit and baseline — documented; execution measurements unavailable.
2. Domain model and Pydantic validation — in progress; implementation exists but is not execution-verified.
3. Schema and ontology — pending.
4. Loader and validation engine — pending expansion.
5. Graph and attack/capability/trust analysis — pending integration verification.
6. Dataset and scenarios — pending.
7. Mappings and evidence — pending expansion.
8. CLI and exports — pending verification and completion.
9. Tests and coverage — pending execution and expansion.
10. CI and security automation — pending.
11. Documentation synchronization — pending.
12. Release gate — blocked until all phase checks produce actual results.

## Current gate

The repository is **active development** and is not production-ready. The next implementation gate is to execute and repair Phase 1:

```bash
python -m pip install -e '.[dev]'
pytest --cov=aiskg --cov-report=term-missing
ruff check .
ruff format --check .
mypy src
```

No test, coverage, lint, type-check, schema-validation, ontology-validation, or production-readiness claim may be reported without an actual command result.
