# app/detector.py
# Looks at each new event and decides whether it is suspicious.
# It only detects and explains. Choosing the action is the responder's job.

from app import config, storage

RECENT_WINDOW = 60          # seconds used for "per minute" counts
BASELINE_LOOKBACK = 3600    # how far back we look to learn a user's normal
BEHAVIOR_MIN_RECENT = 10    # ignore tiny bursts when checking behavior change


# ---------- Helpers ----------

def _scale(value, low, high, low_score, high_score):
    """Map value in [low, high] to a score in [low_score, high_score]."""
    if high <= low:
        return high_score
    ratio = (value - low) / (high - low)
    ratio = max(0.0, min(1.0, ratio))
    return int(round(low_score + ratio * (high_score - low_score)))


def severity_from_score(score):
    if score >= 85:
        return config.SEVERITY_CRITICAL
    if score >= 65:
        return config.SEVERITY_HIGH
    if score >= 40:
        return config.SEVERITY_MEDIUM
    return config.SEVERITY_LOW


def _finding(attack_type, subject_type, subject, score, reason, events):
    return {
        "attack_type": attack_type,
        "subject_type": subject_type,
        "subject": subject,
        "risk_score": score,
        "severity": severity_from_score(score),
        "reason": reason,
        "evidence_ids": [e["id"] for e in events][-50:],
    }


def _baseline_per_minute(user_id, event_type, now):
    """A user's normal rate (events per minute) from history BEFORE the recent window.
    Returns None when there is not enough history to know what is normal."""
    cutoff = now - RECENT_WINDOW
    history = storage.get_events(
        since_ts=now - BASELINE_LOOKBACK, until_ts=cutoff,
        event_type=event_type, user_id=user_id,
    )
    if len(history) < config.BASELINE_MIN_EVENTS:
        return None
    span_minutes = max((cutoff - history[0]["ts"]) / 60.0, 1.0)
    return len(history) / span_minutes


# ---------- Rules ----------

def _check_brute_force(ev, now):
    """One IP failing again and again on the same account."""
    if ev["event_type"] != "login_failed" or not ev["user_id"] or not ev["ip"]:
        return None
    events = storage.get_events(
        now - config.BRUTE_FORCE_WINDOW, now, "login_failed",
        ip=ev["ip"], user_id=ev["user_id"],
    )
    fails = len(events)
    if fails < config.BRUTE_FORCE_MAX_FAILS:
        return None
    score = _scale(fails, config.BRUTE_FORCE_MAX_FAILS,
                   config.BRUTE_FORCE_CRITICAL_FAILS, 45, 95)
    reason = (
        f"IP {ev['ip']} failed to log in to account '{ev['user_id']}' {fails} times "
        f"in {config.BRUTE_FORCE_WINDOW} seconds. A normal user rarely fails more than "
        f"{config.BRUTE_FORCE_MAX_FAILS - 1} times."
    )
    return _finding("brute_force", "ip", ev["ip"], score, reason, events)


def _check_credential_stuffing(ev, now):
    """One IP trying many different accounts."""
    if ev["event_type"] != "login_failed" or not ev["ip"]:
        return None
    events = storage.get_events(
        now - config.STUFFING_WINDOW, now, "login_failed", ip=ev["ip"]
    )
    accounts = {e["user_id"] for e in events if e["user_id"]}
    count = len(accounts)
    if count < config.STUFFING_MIN_ACCOUNTS:
        return None
    score = _scale(count, config.STUFFING_MIN_ACCOUNTS,
                   config.STUFFING_MIN_ACCOUNTS * 5, 70, 100)
    reason = (
        f"IP {ev['ip']} tried {count} different accounts in "
        f"{config.STUFFING_WINDOW} seconds. A real person uses one or two accounts; "
        f"this looks like a bot testing stolen passwords."
    )
    return _finding("credential_stuffing", "ip", ev["ip"], score, reason, events)


def _check_email_spam(ev, now):
    """An account sending far more email than it normally does."""
    if ev["event_type"] != "email_sent" or not ev["user_id"]:
        return None
    events = storage.get_events(
        now - RECENT_WINDOW, now, "email_sent", user_id=ev["user_id"]
    )
    count = len(events)
    if count < config.EMAIL_MAX_PER_MINUTE:
        return None
    baseline = _baseline_per_minute(ev["user_id"], "email_sent", now)
    # A heavy sender who always sends a lot is not spam. Only flag a real jump.
    if baseline is not None and count < baseline * config.EMAIL_SPIKE_MULTIPLIER:
        return None
    score = _scale(count, config.EMAIL_MAX_PER_MINUTE,
                   config.EMAIL_MAX_PER_MINUTE * 10, 70, 100)
    if baseline is None:
        normal = "the account has no history of sending this much"
    else:
        normal = f"this account normally sends about {baseline:.1f} per minute"
    reason = (
        f"Account '{ev['user_id']}' sent {count} emails in the last minute, "
        f"but {normal}."
    )
    return _finding("email_spam", "account", ev["user_id"], score, reason, events)


def _check_api_abuse(ev, now):
    """One IP sending too many requests."""
    if ev["event_type"] != "api_request" or not ev["ip"]:
        return None
    events = storage.get_events(
        now - RECENT_WINDOW, now, "api_request", ip=ev["ip"]
    )
    count = len(events)
    if count < config.API_MAX_PER_MINUTE:
        return None
    score = _scale(count, config.API_MAX_PER_MINUTE,
                   config.API_MAX_PER_MINUTE * 5, 45, 90)
    reason = (
        f"IP {ev['ip']} made {count} API requests in the last minute. "
        f"The allowed limit is {config.API_MAX_PER_MINUTE}."
    )
    return _finding("api_abuse", "ip", ev["ip"], score, reason, events)


def _check_behavior_change(ev, now):
    """An account suddenly acting far above its own normal."""
    if ev["event_type"] not in ("email_sent", "api_request") or not ev["user_id"]:
        return None
    events = storage.get_events(
        now - RECENT_WINDOW, now, ev["event_type"], user_id=ev["user_id"]
    )
    count = len(events)
    if count < BEHAVIOR_MIN_RECENT:
        return None
    baseline = _baseline_per_minute(ev["user_id"], ev["event_type"], now)
    if baseline is None:
        return None
    ratio = count / max(baseline, 1.0)
    if ratio < config.BEHAVIOR_CHANGE_MULTIPLIER:
        return None
    score = _scale(ratio, config.BEHAVIOR_CHANGE_MULTIPLIER,
                   config.BEHAVIOR_CHANGE_MULTIPLIER * 5, 40, 75)
    reason = (
        f"Account '{ev['user_id']}' did {count} '{ev['event_type']}' actions in the "
        f"last minute, about {ratio:.0f}x its normal rate "
        f"({baseline:.1f} per minute)."
    )
    return _finding("behavior_change", "account", ev["user_id"], score, reason, events)


def _check_new_device(ev, now):
    """A login from a device this account has never used before."""
    if ev["event_type"] != "login_success" or not ev["user_id"] or not ev["device"]:
        return None
    history = storage.get_events(
        0, now, "login_success", user_id=ev["user_id"]
    )
    prior = [e for e in history if e["id"] != ev["id"]]
    if len(prior) < config.BASELINE_MIN_EVENTS:
        return None
    known_devices = {e["device"] for e in prior if e["device"]}
    if ev["device"] in known_devices:
        return None
    reason = (
        f"Account '{ev['user_id']}' logged in from a new device '{ev['device']}'. "
        f"It has used {len(known_devices)} other device(s) in {len(prior)} earlier logins."
    )
    return _finding("new_device", "account", ev["user_id"], 35, reason, [ev])


# ---------- Main entry point ----------

def analyze(event, now=None):
    """Check one stored event against every rule. Returns a list of findings."""
    now = now if now is not None else event["ts"]
    findings = []
    for check in (_check_brute_force, _check_credential_stuffing,
                  _check_email_spam, _check_api_abuse, _check_new_device):
        finding = check(event, now)
        if finding:
            findings.append(finding)
    # Email spam already explains a sudden email jump, so skip the duplicate.
    if not any(f["attack_type"] == "email_spam" for f in findings):
        finding = _check_behavior_change(event, now)
        if finding:
            findings.append(finding)
    return findings 
