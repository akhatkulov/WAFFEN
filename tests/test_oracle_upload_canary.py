"""Tests for the upload-filename inject mode and the canary ban-detector (oracle.py)."""
import os

from waffen.core.oracle import BLOCKED, THROUGH, Oracle, Response, Target


def test_upload_build_bare_extension_gets_probe_stem():
    t = Target(base_url="https://x.example", path="/file-upload", param="file",
              method="POST", inject="upload")
    o = Oracle(t, sender=lambda p: Response(THROUGH, "200", 10, 0.01, "ok"))
    argv = o._build("phtml")
    assert "-F" in argv
    f_arg = argv[argv.index("-F") + 1]
    assert f_arg.startswith("file=@") and 'filename="waffen_probe.phtml"' in f_arg
    assert "POST" in argv and "https://x.example/file-upload" in argv


def test_upload_build_dotted_payload_used_verbatim():
    t = Target(base_url="https://x.example", path="/file-upload", param="file",
              method="POST", inject="upload")
    o = Oracle(t, sender=lambda p: Response(THROUGH, "200", 10, 0.01, "ok"))
    argv = o._build("shell.php;.jpg")
    f_arg = argv[argv.index("-F") + 1]
    assert 'filename="shell.php;.jpg"' in f_arg


def test_upload_temp_file_created_then_cleaned_after_curl_send(monkeypatch):
    t = Target(base_url="https://x.example", path="/file-upload", param="file",
              method="POST", inject="upload")
    o = Oracle(t)  # default sender = _curl_send (real curl path)
    seen_path = {}

    class FakeCompleted:
        stdout = "ok\n200 2 0.01"

    def fake_run(cmd, **kwargs):
        # capture the temp file path from the -F arg and confirm it exists NOW
        f_arg = cmd[cmd.index("-F") + 1]
        path = f_arg.split("=@", 1)[1].split(";", 1)[0]
        seen_path["path"] = path
        assert os.path.exists(path), "probe file must exist while curl runs"
        return FakeCompleted()

    monkeypatch.setattr("subprocess.run", fake_run)
    o._curl_send("phtml")
    assert seen_path, "fake curl was never invoked"
    assert not os.path.exists(seen_path["path"]), "probe file must be cleaned up after the send"


def test_upload_not_the_default_inject_mode():
    assert Target(base_url="x").inject == "query"


# --- canary ban detector -----------------------------------------------------
def test_canary_disabled_by_default_no_extra_sends():
    calls = []

    def sender(p):
        calls.append(p)
        return Response(BLOCKED, "403", 10, 0.01, "Request blocked by RedEye")

    o = Oracle(Target(base_url="x"), sender=sender)
    o.send("attack-payload")
    assert calls == ["attack-payload"]  # no canary re-probe
    assert o.ban_suspected is False


def test_canary_fires_every_n_and_detects_ban():
    state = {"n": 0}

    def sender(p):
        state["n"] += 1
        if p == "CANARY":
            # canary stays benign for the first probe, then starts looking blocked
            # (simulating the real-world failure: a ban makes even benign look blocked)
            return (Response(THROUGH, "200", 50, 0.1, "ok") if state["n"] < 5
                    else Response(BLOCKED, "403", 10, 0.01, "Request blocked by RedEye"))
        return Response(BLOCKED, "403", 10, 0.01, "Request blocked by RedEye")

    o = Oracle(Target(base_url="x"), sender=sender, canary_payload="CANARY", canary_every=3, backoff=False)
    for _ in range(3):
        o.send("x")
    assert o.ban_suspected is False, "first canary read was benign"
    for _ in range(3):
        o.send("x")
    assert o.ban_suspected is True, "second canary read came back blocked -> ban suspected"


def test_canary_recovers_when_a_later_read_is_clean_again():
    reads = iter([THROUGH, BLOCKED, THROUGH])  # not sticky: flips back

    def sender(p):
        if p == "CANARY":
            v = next(reads)
            return Response(v, "200" if v == THROUGH else "403", 10, 0.01,
                            "" if v == THROUGH else "Request blocked by RedEye")
        return Response(BLOCKED, "403", 10, 0.01, "Request blocked by RedEye")

    o = Oracle(Target(base_url="x"), sender=sender, canary_payload="CANARY", canary_every=1, backoff=False)
    o.send("x")
    assert o.ban_suspected is False
    o.send("x")
    assert o.ban_suspected is True
    o.send("x")
    assert o.ban_suspected is False, "a later clean canary read should clear the suspicion"


def test_ban_suspected_triggers_aggressive_backoff(monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

    def sender(p):
        return Response(BLOCKED, "403", 10, 0.01, "Request blocked by RedEye")

    o = Oracle(Target(base_url="x"), sender=sender, canary_payload="x", canary_every=1, backoff=True)
    o.send("attack")  # canary check fires immediately (every=1), canary itself is "BLOCKED" -> ban_suspected
    assert o.ban_suspected is True
    assert sleeps, "expected a backoff sleep once ban is suspected"
    assert sleeps[-1] >= 1.0, "ban-suspected backoff should be much larger than the plain DOWN backoff"
