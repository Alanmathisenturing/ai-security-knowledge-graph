from __future__ import annotations

from pathlib import Path
from typing import Any, Type

import yaml

from .models import Attack, BaseKnowledgeObject, Evidence, EntityType

MODEL_BY_TYPE: dict[str, Type[BaseKnowledgeObject]] = {
    EntityType.ATTACK.value: Attack,
    EntityType.EVIDENCE.value: Evidence,
}


class KnowledgeLoadError(ValueError):
    pass


class KnowledgeBase:
    def __init__(self) -> None:
        self.entries: dict[str, BaseKnowledgeObject] = {}

    def load_file(self, path: str | Path) -> BaseKnowledgeObject:
        file_path = Path(path)
        try:
            raw: Any = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise KnowledgeLoadError(f"invalid YAML in {file_path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise KnowledgeLoadError(f"{file_path} must contain a mapping")
        type_name = str(raw.get("type", ""))
        model_type = MODEL_BY_TYPE.get(type_name)
        if model_type is None:
            raise KnowledgeLoadError(f"unknown entity type {type_name!r} in {file_path}")
        try:
            item = model_type.model_validate(raw)
        except Exception as exc:
            raise KnowledgeLoadError(f"invalid entity in {file_path}: {exc}") from exc
        if item.id in self.entries:
            raise KnowledgeLoadError(f"duplicate ID {item.id!r}: {file_path}")
        self.entries[item.id] = item
        return item

    def load_directory(self, root: str | Path) -> None:
        for path in sorted(Path(root).rglob("*.y*ml")):
            self.load_file(path)

    def get(self, item_id: str) -> BaseKnowledgeObject | None:
        return self.entries.get(item_id)

    def search(self, query: str) -> list[BaseKnowledgeObject]:
        needle = query.casefold()
        return sorted(
            (item for item in self.entries.values() if needle in f"{item.name} {item.description}".casefold()),
            key=lambda item: item.id,
        )

    def __len__(self) -> int:
        return len(self.entries)
