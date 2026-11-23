"""Attack planner — discovers an attack graph from a live target and plans
multi-step attacks toward pre-defined goals."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Sequence

from .graph import AttackGraph, AttackNode, AttackEdge
from .goals import GOALS, Goal


# -- common endpoint templates used to seed the graph discovery ------------

_COMMON_ENDPOINTS: list[dict] = [
    {"path": "/rest/user/login", "method": "POST", "role": "login",
     "provides": ["user_token"], "auth": "anonymous"},
    {"path": "/api/Users/", "method": "POST", "role": "register",
     "provides": ["user_account"], "auth": "anonymous"},
    {"path": "/rest/products/search", "method": "GET", "role": "search",
     "provides": ["sqli_sink"], "auth": "anonymous", "param": "q"},
    {"path": "/api/Users/", "method": "GET", "role": "user_list",
     "provides": ["user_data"], "auth": "user"},
    {"path": "/api/Users/1", "method": "GET", "role": "user_detail",
     "provides": ["user_data"], "auth": "user"},
    {"path": "/rest/basket/1", "method": "GET", "role": "basket",
     "provides": ["idor_target"], "auth": "user"},
    {"path": "/api/Feedbacks/", "method": "POST", "role": "feedback",
     "provides": ["xss_sink", "write_access"], "auth": "user"},
    {"path": "/profile/image/file", "method": "POST", "role": "upload",
     "provides": ["upload_sink"], "auth": "user"},
    {"path": "/rest/admin/application-version", "method": "GET",
     "role": "admin_info", "provides": ["admin_data"], "auth": "admin"},
    {"path": "/ftp/", "method": "GET", "role": "ftp",
     "provides": ["file_content"], "auth": "anonymous"},
]


# -- result types -----------------------------------------------------------

@dataclass
class StepResult:
    edge: AttackEdge
    success: bool = False
    response_code: str = ""
    data: str = ""


@dataclass
class AttackResult:
    goal: str
    success: bool = False
    steps: list[StepResult] = field(default_factory=list)
    data_extracted: str = ""


@dataclass
class AttackPlan:
    goal: str
    goal_obj: Goal | None = None
    best_path: list[AttackEdge] = field(default_factory=list)
    alternative_paths: list[list[AttackEdge]] = field(default_factory=list)
    bypasses_needed: list[AttackEdge] = field(default_factory=list)
    total_cost: float = 0.0
    estimated_requests: int = 0

    def summary(self) -> str:
        lines = [f"Goal: {self.goal}"]
        if not self.best_path:
            lines.append("  No path found.")
            return "\n".join(lines)
        lines.append(f"  Best path ({len(self.best_path)} steps, cost {self.total_cost:.1f}):")
        for i, edge in enumerate(self.best_path, 1):
            bypass = " ⚡ WAF bypass needed" if edge.bypass_needed else ""
            provides = ", ".join(edge.provides) if edge.provides else ""
            lines.append(
                f"    {i}. [{edge.source.auth_state}] "
                f"{edge.method} {edge.path} → [{edge.target.auth_state}] "
                f"({provides}){bypass}"
            )
        lines.append(f"  Bypasses needed: {len(self.bypasses_needed)}")
        if self.alternative_paths:
            lines.append(f"  Alternative paths: {len(self.alternative_paths)}")
        return "\n".join(lines)

    def as_dict(self) -> dict:
        return {
            "goal": self.goal,
            "total_cost": self.total_cost,
            "steps": len(self.best_path),
            "bypasses_needed": len(self.bypasses_needed),
            "alternatives": len(self.alternative_paths),
            "best_path": [
                {"from": e.source.auth_state, "to": e.target.auth_state,
                 "method": e.method, "path": e.path,
                 "bypass": e.bypass_needed, "provides": e.provides}
                for e in self.best_path
            ],
        }


# -- planner ----------------------------------------------------------------

class AttackPlanner:
    """Build an attack graph and plan multi-step attacks."""

    def __init__(self, target=None, *, oracle=None, sender=None,
                 endpoints: Sequence[dict] | None = None):
        self.target = target
        self._oracle = oracle
        self._sender = sender
        self.graph = AttackGraph()
        self._endpoints = list(endpoints) if endpoints else list(_COMMON_ENDPOINTS)

    # -- graph construction -------------------------------------------------

    def build_graph(self, waf_probes: dict[str, str] | None = None) -> AttackGraph:
        """Build the attack graph from endpoint templates + optional WAF probe
        results (path → 'BLOCKED'|'THROUGH')."""
        waf = waf_probes or {}

        anon = self.graph.add_node(AttackNode("", "anonymous"))
        user_node = self.graph.add_node(
            AttackNode("", "user"))
        admin_node = self.graph.add_node(
            AttackNode("", "admin"))

        for ep in self._endpoints:
            path = ep["path"]
            method = ep.get("method", "GET")
            auth = ep.get("auth", "anonymous")
            provides = list(ep.get("provides", []))
            role = ep.get("role", "")

            prot = waf.get(path, "UNKNOWN")
            ep_node = self.graph.add_node(
                AttackNode(path, auth, ep.get("param", ""), prot))

            source = anon if auth == "anonymous" else (
                admin_node if auth == "admin" else user_node)

            bypass = prot == "BLOCKED"
            cost = 5.0 if bypass else 1.0
            if auth == "admin":
                cost += 3.0

            edge = AttackEdge(
                source=source, target=ep_node,
                action=f"{method} {path}", method=method, path=path,
                requires=[f"{auth}_token"] if auth != "anonymous" else [],
                provides=provides, cost=cost,
                bypass_needed=bypass,
                description=role,
            )
            self.graph.add_edge(edge)

            if role == "login":
                self.graph.add_edge(AttackEdge(
                    source=ep_node, target=user_node,
                    action="authenticate", method="POST", path=path,
                    provides=["user_token"], cost=1.0,
                    description="login → user session",
                ))
            elif role == "register":
                self.graph.add_edge(AttackEdge(
                    source=ep_node, target=user_node,
                    action="register account", method="POST", path=path,
                    provides=["user_account", "user_token"], cost=1.0,
                    description="register → user account",
                ))

            if "sqli_sink" in provides:
                self.graph.add_edge(AttackEdge(
                    source=ep_node,
                    target=self.graph.add_node(
                        AttackNode(path, auth, ep.get("param", ""), "exploit")),
                    action="SQLi exploit", method=method, path=path,
                    provides=["data_extracted", "admin_token"],
                    cost=3.0 if bypass else 2.0,
                    bypass_needed=bypass,
                    description="exploit SQLi → extract data",
                ))

            if "xss_sink" in provides:
                self.graph.add_edge(AttackEdge(
                    source=ep_node,
                    target=self.graph.add_node(
                        AttackNode(path, auth, "", "xss")),
                    action="store XSS", method=method, path=path,
                    provides=["payload_stored", "victim_session"],
                    cost=3.0 if bypass else 2.0,
                    bypass_needed=bypass,
                    description="store XSS payload",
                ))

            if "upload_sink" in provides:
                self.graph.add_edge(AttackEdge(
                    source=ep_node,
                    target=self.graph.add_node(
                        AttackNode(path, auth, "", "rce")),
                    action="upload webshell", method="POST", path=path,
                    provides=["command_output"],
                    cost=4.0 if bypass else 3.0,
                    bypass_needed=bypass,
                    description="upload → RCE",
                ))

            if "file_content" in provides:
                self.graph.add_edge(AttackEdge(
                    source=ep_node,
                    target=self.graph.add_node(
                        AttackNode(path, auth, "", "lfi")),
                    action="read file", method=method, path=path,
                    provides=["file_content"],
                    cost=2.0 if bypass else 1.0,
                    bypass_needed=bypass,
                    description="directory traversal / LFI",
                ))

        return self.graph

    def discover(self) -> AttackGraph:
        """Probe the live target to discover WAF protection per endpoint and
        build the graph. Requires a working oracle."""
        waf: dict[str, str] = {}
        if self._oracle or self._sender:
            oracle = self._oracle
            if oracle is None:
                from ..core.oracle import Oracle
                oracle = Oracle(self.target, sender=self._sender)
            test_payload = "' OR 1=1--"
            for ep in self._endpoints:
                try:
                    resp = oracle.send(test_payload)
                    waf[ep["path"]] = resp.verdict
                except Exception:
                    waf[ep["path"]] = "UNKNOWN"
        return self.build_graph(waf)

    # -- planning -----------------------------------------------------------

    def plan_attack(self, goal_name: str) -> AttackPlan:
        goal_obj = GOALS.get(goal_name)
        if goal_obj is None:
            return AttackPlan(goal=goal_name)

        capability = goal_obj.capability
        start = AttackNode("", "anonymous")

        best = self.graph.shortest_path(start, capability)
        all_p = self.graph.all_paths(start, capability, max_depth=6)

        scored = []
        for p in all_p:
            c = sum(e.cost for e in p)
            scored.append((c, p))
        scored.sort(key=lambda x: x[0])

        best_path = scored[0][1] if scored else best
        alternatives = [p for _, p in scored[1:5]]
        bypasses = [e for e in best_path if e.bypass_needed]
        total_cost = sum(e.cost for e in best_path) if best_path else 0.0
        est_requests = len(best_path) * 200

        return AttackPlan(
            goal=goal_name, goal_obj=goal_obj,
            best_path=best_path,
            alternative_paths=alternatives,
            bypasses_needed=bypasses,
            total_cost=total_cost,
            estimated_requests=est_requests,
        )

    # -- execution (mock-safe) ----------------------------------------------

    def execute_plan(self, plan: AttackPlan,
                     executor=None) -> AttackResult:
        """Execute the plan step by step.  *executor* is an optional callback
        ``(edge) -> StepResult``; without it every step succeeds (dry-run)."""
        result = AttackResult(goal=plan.goal)
        for edge in plan.best_path:
            if executor:
                sr = executor(edge)
            else:
                sr = StepResult(edge=edge, success=True,
                                response_code="200", data="(dry-run)")
            result.steps.append(sr)
            if not sr.success:
                break
        result.success = all(s.success for s in result.steps)
        return result


def write_plan_json(plan: AttackPlan, path: str):
    with open(path, "w") as f:
        json.dump(plan.as_dict(), f, indent=2, ensure_ascii=False)
