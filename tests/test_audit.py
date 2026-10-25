import json
import sys

from secure_ai.audit import AuditLog, SecurityMonitor


def test_chain_valid_and_detects_tampering(clock):
    a = AuditLog(clock=clock)
    for i in range(5):
        a.log("evt", n=i)
    assert a.verify_chain()
    a.records[2]["fields"]["n"] = 999                    # attacker edits history
    assert not a.verify_chain()


def test_deleting_a_record_breaks_chain(clock):
    a = AuditLog(clock=clock)
    for i in range(4):
        a.log("evt", n=i)
    del a.records[1]
    assert not a.verify_chain()


def test_logs_never_contain_pii_or_secrets():
    a = AuditLog()
    rec = a.log("req", preview="my key sk-ant-abcdefghijklmnopqrstuvwx1234 mail a@b.com", nested={"card": "4111 1111 1111 1111"})
    s = json.dumps(rec)
    assert "sk-ant" not in s and "a@b.com" not in s and "4111" not in s


def test_file_persistence_permissions(tmp_path):
    p = tmp_path / "audit.jsonl"
    a = AuditLog(path=str(p))
    a.log("x", v=1); a.log("y", v=2)
    lines = p.read_text().splitlines()
    assert len(lines) == 2 and json.loads(lines[1])["prev"] == json.loads(lines[0])["hash"]
    if sys.platform != "win32":                           # POSIX permission bits only
        assert oct(p.stat().st_mode)[-3:] == "600"


def test_retention_purge_keeps_chain_verifiable(clock):
    a = AuditLog(clock=clock)
    a.log("old"); clock.advance(1000); a.log("new1"); a.log("new2")
    assert a.purge_older_than(500) == 1
    assert [r["event"] for r in a.records] == ["new1", "new2"] and a.verify_chain()


def test_monitor_suspends_after_threshold(clock):
    m = SecurityMonitor(3, 60, clock)
    assert not m.record("u", "x") and not m.record("u", "x")
    assert m.record("u", "x") and m.is_suspended("u")
    m.reinstate("u")
    assert not m.is_suspended("u")


def test_monitor_window_expires(clock):
    m = SecurityMonitor(3, 60, clock)
    m.record("u", "x"); m.record("u", "x")
    clock.advance(61)
    assert not m.record("u", "x")                        # old violations aged out
