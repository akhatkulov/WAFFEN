"""Attack graph — nodes are (endpoint, auth_state) pairs, edges are HTTP
requests that transition between states.  Dijkstra finds the cheapest path
to a goal; DFS enumerates all paths within a depth limit."""
from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Sequence


@dataclass(frozen=True)
class AttackNode:
    endpoint: str = ""
    auth_state: str = "anonymous"
    injection_point: str = ""
    waf_protection: str = "UNKNOWN"

    @property
    def key(self) -> str:
        return f"{self.endpoint}|{self.auth_state}|{self.injection_point}|{self.waf_protection}"


@dataclass
class AttackEdge:
    source: AttackNode
    target: AttackNode
    action: str = ""
    method: str = "GET"
    path: str = "/"
    requires: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    cost: float = 1.0
    bypass_needed: bool = False
    description: str = ""

    def __repr__(self) -> str:
        arrow = " ⚡" if self.bypass_needed else ""
        return (f"Edge({self.source.auth_state} → {self.target.auth_state} "
                f"via {self.method} {self.path}{arrow})")


class AttackGraph:
    """Directed weighted graph of attack states and transitions."""

    def __init__(self):
        self.nodes: list[AttackNode] = []
        self.edges: list[AttackEdge] = []
        self._adjacency: dict[str, list[AttackEdge]] = {}

    def add_node(self, node: AttackNode) -> AttackNode:
        if node.key not in {n.key for n in self.nodes}:
            self.nodes.append(node)
            self._adjacency.setdefault(node.key, [])
        return node

    def add_edge(self, edge: AttackEdge) -> AttackEdge:
        self.add_node(edge.source)
        self.add_node(edge.target)
        self.edges.append(edge)
        self._adjacency.setdefault(edge.source.key, []).append(edge)
        return edge

    def neighbors(self, node: AttackNode) -> list[AttackEdge]:
        return list(self._adjacency.get(node.key, []))

    def _node_by_key(self, key: str) -> AttackNode | None:
        for n in self.nodes:
            if n.key == key:
                return n
        return None

    # ------------------------------------------------------------------
    # Dijkstra: cheapest path from *start* to any node whose *provides*
    # (accumulated along the path) contain the *goal* capability.
    # ------------------------------------------------------------------

    def shortest_path(self, start: AttackNode, goal: str) -> list[AttackEdge]:
        self.add_node(start)

        dist: dict[str, float] = {start.key: 0.0}
        prev: dict[str, AttackEdge | None] = {start.key: None}
        caps: dict[str, set[str]] = {start.key: set()}
        pq: list[tuple[float, int, str]] = [(0.0, 0, start.key)]
        seq = 1
        goal_key: str | None = None

        while pq:
            d, _, ukey = heapq.heappop(pq)
            if d > dist.get(ukey, float("inf")):
                continue
            if goal in caps.get(ukey, set()):
                goal_key = ukey
                break
            for edge in self._adjacency.get(ukey, []):
                nd = d + edge.cost
                vkey = edge.target.key
                if nd < dist.get(vkey, float("inf")):
                    dist[vkey] = nd
                    prev[vkey] = edge
                    new_caps = set(caps.get(ukey, set()))
                    new_caps.update(edge.provides)
                    caps[vkey] = new_caps
                    heapq.heappush(pq, (nd, seq, vkey))
                    seq += 1

        if goal_key is None:
            return []

        path: list[AttackEdge] = []
        cur = goal_key
        while prev.get(cur) is not None:
            edge = prev[cur]
            path.append(edge)
            cur = edge.source.key
        path.reverse()
        return path

    # ------------------------------------------------------------------
    # DFS: all simple paths up to *max_depth* edges whose accumulated
    # *provides* contain *goal*.
    # ------------------------------------------------------------------

    def all_paths(self, start: AttackNode, goal: str,
                  max_depth: int = 5) -> list[list[AttackEdge]]:
        self.add_node(start)
        results: list[list[AttackEdge]] = []

        def _dfs(node_key: str, path: list[AttackEdge],
                 visited: set[str], caps: set[str]):
            if goal in caps:
                results.append(list(path))
                return
            if len(path) >= max_depth:
                return
            for edge in self._adjacency.get(node_key, []):
                tkey = edge.target.key
                if tkey in visited:
                    continue
                new_caps = caps | set(edge.provides)
                visited.add(tkey)
                path.append(edge)
                _dfs(tkey, path, visited, new_caps)
                path.pop()
                visited.discard(tkey)

        _dfs(start.key, [], {start.key}, set())
        return results

    def as_dict(self) -> dict:
        return {
            "nodes": [{"endpoint": n.endpoint, "auth_state": n.auth_state,
                        "injection_point": n.injection_point,
                        "waf_protection": n.waf_protection} for n in self.nodes],
            "edges": [{"source": e.source.key, "target": e.target.key,
                        "action": e.action, "cost": e.cost,
                        "bypass_needed": e.bypass_needed,
                        "provides": e.provides, "requires": e.requires}
                       for e in self.edges],
        }
