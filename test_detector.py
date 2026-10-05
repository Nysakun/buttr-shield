# tests/test_detector.py
# Automatic checks: normal users must be left alone, every attack must be caught.

import pytest

from app import config, responder, storage


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Each test gets its own empty database, so the real one is never touched."""
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "test.db"))
    storage.init_db()


def send(event_type, user, ip, ts, device=None):
    return responder.handle_event(event_type, user_id=user, ip=ip, device=device, ts=ts)


def incident_types():
    return {i["attack_type"] for i in storage.list_incidents()}


# ---------- Normal users must not be punished ----------

def test_normal_login_typos_are_allowed():
    for i in range(3):
        assert send("login_failed", "alice", "1.1.1.1", 1000 + i)["status"] == "allowed"
    assert send("login_success", "alice", "1.1.1.1", 1005, "phone")["status"] == "allowed"
    assert storage.list_incidents() == []


def test_busy_but_legitimate_sender_is_not_flagged():
    base = 10000
    statuses = []
    for i in range(36):                      # about 6 emails per minute, every day
        statuses.append(send("email_sent", "busy", "5.5.5.5", base - 400 + i * 9)["status"])
    for i in range(18):                      # a small burst, still normal for them
        statuses.append(send("email_sent", "busy", "5.5.5.5", base + i)["status"])
    assert set(statuses) == {"allowed"}
    assert storage.list_incidents() == []


def test_known_user_on_new_device_is_flagged_not_blocked():
    for i in range(6):
        send("login_success", "alice", "1.1.1.1", 1000 + i * 300, "laptop")
    result = send("login_success", "alice", "7.7.7.7", 3000, "phone")
    assert result["status"] == "flagged"
    assert incident_types() == {"new_device"}


def test_block_on_attacker_does_not_affect_other_users():
    for i in range(12):
        send("login_failed", f"user{i}", "9.9.9.9", 3000 + i)
    result = send("login_success", "normal1", "198.51.100.5", 3020, "laptop")
    assert result["status"] == "allowed"


def test_brute_force_victim_can_still_log_in_from_own_ip():
    for i in range(8):
        send("login_failed", "bob", "2.2.2.2", 2000 + i)
    result = send("login_success", "bob", "5.5.5.5", 2100)
    assert result["status"] == "allowed"


# ---------- Attacks must be caught ----------

def test_brute_force_is_rate_limited():
    for i in range(8):
        result = send("login_failed", "bob", "2.2.2.2", 2000 + i)
    assert result["status"] == "rate_limited"
    assert incident_types() == {"brute_force"}


def test_persistent_brute_force_escalates_to_block():
    for i in range(12):
        result = send("login_failed", "bob", "2.2.2.2", 2000 + i)
    assert result["status"] == "blocked"


def test_credential_stuffing_is_blocked():
    for i in range(12):
        result = send("login_failed", f"user{i}", "9.9.9.9", 3000 + i)
    assert result["status"] == "blocked"
    assert incident_types() == {"credential_stuffing"}


def test_email_spam_account_is_restricted():
    for i in range(40):
        result = send("email_sent", "dave", "4.4.4.4", 4100 + i)
    assert result["status"] == "restricted"
    assert "email_spam" in incident_types()


def test_sudden_spike_far_above_own_normal_is_caught():
    base = 10000
    for i in range(6):                       # about 1 email per minute
        send("email_sent", "erin", "6.6.6.6", base - 400 + i * 60)
    for i in range(60):                      # sudden flood
        result = send("email_sent", "erin", "6.6.6.6", base + i)
    assert result["status"] == "restricted"
    assert {"behavior_change", "email_spam"} <= incident_types()


def test_api_abuse_is_rate_limited():
    for i in range(150):
        result = send("api_request", None, "8.8.8.8", 6000 + i * 0.1)
    assert result["status"] == "rate_limited"
    assert incident_types() == {"api_abuse"}


# ---------- Recording, recovery and review ----------

def test_block_lifts_automatically_after_it_expires():
    for i in range(12):
        send("login_failed", f"user{i}", "9.9.9.9", 3000 + i)
    assert send("login_failed", "user0", "9.9.9.9", 3012)["status"] == "blocked"
    later = 3012 + config.BLOCK_SECONDS + 100
    assert send("login_failed", "user0", "9.9.9.9", later)["status"] == "allowed"
    assert storage.list_incidents()[0]["recovered_at"] is not None


def test_incident_records_reason_and_evidence():
    for i in range(12):
        send("login_failed", f"user{i}", "9.9.9.9", 3000 + i)
    incident = storage.get_incident(1)
    assert "9.9.9.9" in incident["reason"]
    assert incident["severity"] in ("low", "medium", "high", "critical")
    assert len(incident["events"]) >= 10
    assert incident["review_status"] == "open"


def test_admin_can_review_an_incident():
    for i in range(12):
        send("login_failed", f"user{i}", "9.9.9.9", 3000 + i)
    storage.review_incident(1, "false_alarm", "checked, it was our load test")
    incident = storage.get_incident(1)
    assert incident["review_status"] == "reviewed"
    assert incident["review_verdict"] == "false_alarm" 