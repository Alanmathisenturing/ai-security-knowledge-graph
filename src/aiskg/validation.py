from __future__ import annotations

from collections.abc import Iterable

from .loader import KnowledgeBase


def validate_unique_ids(items: Iterable[object]) -> list[str]:
    seen: set[str] = set()
    errors: list[str] = []
    for item in items:
        item_id = getattr(item, "id", None)
        if not isinstance(item_id, str):
            errors.append("object is missing a string id")
        elif item_id in seen:
            errors.append(f"duplicate ID: {item_id}")
        else:
            seen.add(item_id)
    return errors


def validate_references(base: KnowledgeBase) -> list[str]:
    errors: list[str] = []
    known = set(base.entries)
    for item in base.entries.values():
        for field in ("evidence", "references", "controls", "detection", "techniques", "targets"):
            for reference in getattr(item, field, []):
                if reference.startswith("ASKG-") and reference not in known:
                    errors.append(f"{item.id}: unresolved {field} reference {reference}")
    return errors


def validate(base: KnowledgeBase) -> list[str]:
    return [*validate_unique_ids(base.entries.values()), *validate_references(base)]
