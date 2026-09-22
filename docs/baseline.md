# Baseline

Generated during Phase 0 repository audit on 2026-09-22.

## Environment

| Check | Result |
|---|---|
| Python version | NOT EXECUTED: no shell execution result available in this session |
| pytest | NOT EXECUTED |
| pytest-cov | NOT EXECUTED |
| Ruff | NOT EXECUTED |
| Ruff format check | NOT EXECUTED |
| MyPy | NOT EXECUTED |
| `aiskg validate` | NOT EXECUTED |

## Interpretation

This document intentionally records unavailable measurements rather than estimating them. No test, coverage, lint, type-check, schema-validation, ontology-validation, or graph-validation result may be reported as passing until it is produced by an actual execution environment.

## Required local baseline commands

```bash
python --version
python -m pip install -e '.[dev]'
pytest --cov=aiskg --cov-report=term-missing
ruff check .
ruff format --check .
mypy src
python -m aiskg.cli validate
```

The output of these commands should replace the `NOT EXECUTED` entries after running them in CI or a local checkout.
