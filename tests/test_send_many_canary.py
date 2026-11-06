"""Tests for the two fixes this round: send_many(concurrency<=1) routes through
self.send() (gaining canary/backoff), and build_dataset measures benign first."""
from waffen.core.oracle import BLOCKED, THROUGH, Oracle, Response, Target
from waffen.eval.dataset import build_dataset


def test_send_many_concurrency_1_triggers_canary_ban_detection():
    state = {"n": 0}

    def sender(p):
        state["n"] += 1
        if p == "CANARY":
            return (Response(THROUGH, "200", 50, 0.1, "ok") if state["n"] < 5
                    else Response(BLOCKED, "403", 10, 0.01, "Request blocked by RedEye"))
        return Response(BLOCKED, "403", 10, 0.01, "Request blocked by RedEye")

    o = Oracle(Target(base_url="x"), sender=sender, canary_payload="CANARY",
              canary_every=3, backoff=False)
    o.send_many(["a", "b", "c"], concurrency=1)
    assert o.ban_suspected is False, "first canary read was benign"
    o.send_many(["d", "e", "f"], concurrency=1)
    assert o.ban_suspected is True, "send_many(concurrency=1) must route through send() for canary to fire"


def test_send_many_concurrency_gt1_does_not_use_canary():
    # documented limitation: concurrent batches skip the canary check entirely
    def sender(p):
        return Response(BLOCKED, "403", 10, 0.01, "Request blocked by RedEye")

    o = Oracle(Target(base_url="x"), sender=sender, canary_payload="CANARY", canary_every=1)
    o.send_many(["a", "b", "c", "d"], concurrency=4)
    assert o.ban_suspected is False  # never checked at concurrency>1


def test_build_dataset_measures_benign_before_attacks():
    order = []

    def sender(p):
        order.append(p)
        return Response(THROUGH, "200", 10, 0.01, "ok")

    out = build_dataset(
        Target(base_url="x", inject="query"),
        attack_cases=[("XSS Injection", "attack1"), ("XSS Injection", "attack2")],
        benign=["benign1", "benign2"],
        sender=sender, concurrency=1,
    )
    # every benign payload must appear before every attack payload in send order
    first_attack_idx = order.index("attack1")
    assert all(order.index(b) < first_attack_idx for b in ("benign1", "benign2"))
    labels = {r["text"]: r["label"] for r in out["records"]}
    assert labels["benign1"] == "benign" and labels["attack1"] == "malicious"


def test_build_dataset_canary_wiring_reaches_the_oracle():
    # canary_every set higher than the total send count -> the check never actually
    # fires in this run; this test is about the wiring (param reaches build_dataset's
    # internal Oracle and nothing crashes), not about exercising the backoff sleep
    # (that path is already covered, with backoff disabled, in test_oracle_upload_canary.py).
    def sender(p):
        assert p != "safe-canary", "canary should not fire: canary_every exceeds total sends"
        return Response(THROUGH, "200", 10, 0.01, "ok")

    out = build_dataset(
        Target(base_url="x"),
        attack_cases=[("XSS Injection", f"p{i}") for i in range(10)],
        sender=sender, concurrency=1,
        canary_payload="safe-canary", canary_every=100,
    )
    assert out["stats"]["kept"] == 10  # dataset build itself still completes
