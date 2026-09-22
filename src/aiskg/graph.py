from __future__ import annotations

from typing import Any, Iterable

import networkx as nx

from .models import Relationship


class KnowledgeGraph:
    """Deterministic local graph engine preserving node and edge metadata."""

    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()

    def add_node(self, node_id: str, **metadata: Any) -> None:
        self.graph.add_node(node_id, **metadata)

    def add_edge(self, relationship: Relationship | None = None, *, source: str = "", target: str = "", **metadata: Any) -> None:
        if relationship is not None:
            source, target = relationship.source, relationship.target
            metadata = {"type": relationship.type.value, "provenance": relationship.provenance, **relationship.metadata}
        if not source or not target:
            raise ValueError("source and target are required")
        self.graph.add_edge(source, target, **metadata)

    def remove_node(self, node_id: str) -> None:
        self.graph.remove_node(node_id)

    def remove_edge(self, source: str, target: str, key: int | str | None = None) -> None:
        if key is None:
            self.graph.remove_edges_from(list(self.graph.edges(source, target)))
        else:
            self.graph.remove_edge(source, target, key=key)

    def find_paths(self, source: str, target: str, cutoff: int = 12) -> list[list[str]]:
        if source not in self.graph or target not in self.graph:
            return []
        return [list(path) for path in nx.all_simple_paths(self.graph, source, target, cutoff=cutoff)]

    def shortest_path(self, source: str, target: str) -> list[str]:
        try:
            return list(nx.shortest_path(self.graph, source, target))
        except (nx.NodeNotFound, nx.NetworkXNoPath):
            return []

    def reachable_nodes(self, source: str) -> list[str]:
        if source not in self.graph:
            return []
        return sorted(nx.descendants(self.graph, source))

    def attack_surface(self, source: str) -> list[str]:
        return self.reachable_nodes(source)

    def blast_radius(self, source: str) -> list[str]:
        return self.reachable_nodes(source)

    def trust_boundary_crossings(self, path: Iterable[str]) -> list[dict[str, Any]]:
        nodes = list(path)
        result: list[dict[str, Any]] = []
        for source, target in zip(nodes, nodes[1:]):
            for data in self.graph.get_edge_data(source, target, default={}).values():
                if data.get("type") == "crosses" or data.get("trust_boundary"):
                    result.append({"source": source, "target": target, **data})
        return result

    def capability_escalation_paths(self, source: str, target: str) -> list[list[str]]:
        return [path for path in self.find_paths(source, target) if any("capab" in str(node).lower() for node in path)]

    def control_coverage(self, path: Iterable[str]) -> set[str]:
        nodes = list(path)
        controls: set[str] = set()
        for source, target in zip(nodes, nodes[1:]):
            for data in self.graph.get_edge_data(source, target, default={}).values():
                controls.update(data.get("controls", []))
        return controls

    def detection_coverage(self, path: Iterable[str]) -> set[str]:
        nodes = list(path)
        detections: set[str] = set()
        for source, target in zip(nodes, nodes[1:]):
            for data in self.graph.get_edge_data(source, target, default={}).values():
                detections.update(data.get("detections", []))
        return detections

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [{"id": node, **data} for node, data in self.graph.nodes(data=True)],
            "edges": [{"source": s, "target": t, **data} for s, t, data in self.graph.edges(data=True)],
        }
