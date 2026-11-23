"""Tests for the multi-step attack graph planner."""
from waffen.plan.graph import AttackGraph, AttackNode, AttackEdge
from waffen.plan.planner import AttackPlanner, AttackPlan, AttackResult, StepResult, write_plan_json
from waffen.plan.goals import GOALS, Goal, list_goals, get_goal


# ---- AttackNode ------------------------------------------------------------

class TestAttackNode:
    def test_key(self):
        n = AttackNode("/api", "user", "q", "BLOCKED")
        assert n.key == "/api|user|q|BLOCKED"

    def test_default(self):
        n = AttackNode()
        assert n.auth_state == "anonymous"
        assert n.waf_protection == "UNKNOWN"

    def test_frozen(self):
        n = AttackNode("/x", "admin")
        assert hash(n)  # hashable


# ---- AttackEdge ------------------------------------------------------------

class TestAttackEdge:
    def test_repr_bypass(self):
        e = AttackEdge(
            source=AttackNode("", "anonymous"),
            target=AttackNode("/search", "user"),
            method="GET", path="/search", bypass_needed=True,
        )
        assert "⚡" in repr(e)

    def test_repr_no_bypass(self):
        e = AttackEdge(
            source=AttackNode("", "anonymous"),
            target=AttackNode("/login", "user"),
            method="POST", path="/login",
        )
        assert "⚡" not in repr(e)


# ---- AttackGraph -----------------------------------------------------------

class TestAttackGraph:
    def _simple_graph(self):
        g = AttackGraph()
        a = AttackNode("", "anonymous")
        b = AttackNode("/login", "user")
        c = AttackNode("/search", "user", "q")
        d = AttackNode("/data", "user", "q", "exploit")

        g.add_edge(AttackEdge(a, b, "login", "POST", "/login",
                               provides=["user_token"], cost=1.0))
        g.add_edge(AttackEdge(b, c, "search", "GET", "/search",
                               provides=["sqli_sink"], cost=2.0))
        g.add_edge(AttackEdge(c, d, "exploit", "GET", "/search",
                               provides=["data_extracted"], cost=3.0,
                               bypass_needed=True))
        return g, a, d

    def test_add_node_dedup(self):
        g = AttackGraph()
        n = AttackNode("/x", "user")
        g.add_node(n)
        g.add_node(n)
        assert len(g.nodes) == 1

    def test_add_edge_adds_nodes(self):
        g = AttackGraph()
        a = AttackNode("", "anonymous")
        b = AttackNode("/login", "user")
        g.add_edge(AttackEdge(a, b, "go"))
        assert len(g.nodes) == 2
        assert len(g.edges) == 1

    def test_neighbors(self):
        g, a, _ = self._simple_graph()
        nbrs = g.neighbors(a)
        assert len(nbrs) == 1
        assert nbrs[0].path == "/login"

    def test_shortest_path(self):
        g, a, _ = self._simple_graph()
        path = g.shortest_path(a, "data_extracted")
        assert len(path) == 3
        assert path[0].path == "/login"
        assert path[-1].provides == ["data_extracted"]

    def test_shortest_path_no_goal(self):
        g, a, _ = self._simple_graph()
        path = g.shortest_path(a, "nonexistent_capability")
        assert path == []

    def test_all_paths(self):
        g, a, _ = self._simple_graph()
        paths = g.all_paths(a, "data_extracted")
        assert len(paths) >= 1
        assert all(isinstance(p, list) for p in paths)

    def test_all_paths_max_depth(self):
        g, a, _ = self._simple_graph()
        paths = g.all_paths(a, "data_extracted", max_depth=1)
        assert paths == []

    def test_as_dict(self):
        g, _, _ = self._simple_graph()
        d = g.as_dict()
        assert "nodes" in d
        assert "edges" in d
        assert len(d["edges"]) == 3

    def test_shortest_path_prefers_cheap(self):
        g = AttackGraph()
        a = AttackNode("", "anonymous")
        b = AttackNode("/cheap", "user")
        c = AttackNode("/expensive", "user")
        d = AttackNode("/goal", "user")
        g.add_edge(AttackEdge(a, b, cost=1.0, provides=[]))
        g.add_edge(AttackEdge(b, d, cost=1.0, provides=["goal_cap"]))
        g.add_edge(AttackEdge(a, c, cost=10.0, provides=[]))
        g.add_edge(AttackEdge(c, d, cost=1.0, provides=["goal_cap"]))
        path = g.shortest_path(a, "goal_cap")
        total = sum(e.cost for e in path)
        assert total == 2.0


# ---- Goals -----------------------------------------------------------------

class TestGoals:
    def test_goals_not_empty(self):
        assert len(GOALS) >= 5

    def test_all_have_capability(self):
        for name, goal in GOALS.items():
            assert goal.capability, f"{name} missing capability"

    def test_list_goals(self):
        names = list_goals()
        assert "dump_database" in names
        assert "admin_access" in names

    def test_get_goal(self):
        g = get_goal("dump_database")
        assert g is not None
        assert g.capability == "data_extracted"

    def test_get_goal_missing(self):
        assert get_goal("nonexistent") is None


# ---- AttackPlanner ---------------------------------------------------------

class TestAttackPlanner:
    def test_build_graph(self):
        planner = AttackPlanner()
        g = planner.build_graph()
        assert len(g.nodes) > 0
        assert len(g.edges) > 0

    def test_build_graph_with_waf(self):
        planner = AttackPlanner()
        waf = {"/rest/products/search": "BLOCKED", "/ftp/": "THROUGH"}
        g = planner.build_graph(waf)
        blocked_edges = [e for e in g.edges if e.bypass_needed]
        assert len(blocked_edges) > 0

    def test_plan_dump_database(self):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("dump_database")
        assert plan.goal == "dump_database"
        assert len(plan.best_path) > 0

    def test_plan_admin_access(self):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("admin_access")
        assert plan.goal == "admin_access"

    def test_plan_nonexistent_goal(self):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("fly_to_moon")
        assert plan.best_path == []

    def test_plan_summary(self):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("dump_database")
        s = plan.summary()
        assert "dump_database" in s

    def test_plan_as_dict(self):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("dump_database")
        d = plan.as_dict()
        assert "goal" in d
        assert "best_path" in d

    def test_plan_read_file(self):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("read_file")
        assert plan.goal == "read_file"
        assert len(plan.best_path) > 0

    def test_plan_xss_stored(self):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("xss_stored")
        assert plan.goal == "xss_stored"


# ---- AttackResult / execute ------------------------------------------------

class TestExecutePlan:
    def test_dry_run(self):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("dump_database")
        result = planner.execute_plan(plan)
        assert result.success
        assert len(result.steps) == len(plan.best_path)
        assert all(s.success for s in result.steps)

    def test_custom_executor(self):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("dump_database")

        def fail_on_bypass(edge):
            if edge.bypass_needed:
                return StepResult(edge=edge, success=False, response_code="403")
            return StepResult(edge=edge, success=True, response_code="200")

        result = planner.execute_plan(plan, executor=fail_on_bypass)
        if any(e.bypass_needed for e in plan.best_path):
            assert not result.success


# ---- write_plan_json -------------------------------------------------------

class TestWritePlan:
    def test_write(self, tmp_path):
        planner = AttackPlanner()
        planner.build_graph()
        plan = planner.plan_attack("dump_database")
        out = str(tmp_path / "plan.json")
        write_plan_json(plan, out)
        import json
        with open(out) as f:
            d = json.load(f)
        assert d["goal"] == "dump_database"


# ---- CLI -------------------------------------------------------------------

class TestCLI:
    def test_parser_has_plan(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["plan", "--target", "https://test.com", "--goal", "dump_database"])
        assert hasattr(args, "func")
        assert args.goal == "dump_database"

    def test_list_goals_flag(self):
        from waffen.cli import build_parser
        p = build_parser()
        args = p.parse_args(["plan", "--list-goals"])
        assert args.list_goals is True
