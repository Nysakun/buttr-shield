# app/responder.py
# Decides what to do about suspicious activity and records every incident.
# Single entry point: handle_event().

import time

from app import config, detector, storage

ACTION_RANK = {"flag": 0, "rate_limit": 1, "restrict": 2, "block": 3}
STATUS_RANK = {"allowed": 0, "flagged": 1, "rate_limited": 2,
               "restricted": 3, "blocked": 4}

# A restricted account may not send email or call the API.
RESTRICTED_EVENTS = ("email_sent", "api_request")
FLAG_SECONDS = 300  # how long a "flag only" incident stays open (avoids duplicates)


def choose_action(attack_type, severity):
    """Pick a protective action that matches the attack and how serious it is."""
    high = (config.SEVERITY_HIGH, config.SEVERITY_CRITICAL)
    if attack_type == "credential_stuffing":
        return "block"
    if attack_type == "brute_force":
        return "block" if severity in high else "rate_limit"
    if attack_type == "email_spam":
        return "restrict"
    if attack_type == "api_abuse":
        return "block" if severity == config.SEVERITY_CRITICAL else "rate_limit"
    if attack_type == "behavior_change":
        return "restrict" if severity in high else "rate_limit"
    return "flag"


def _duration(action):
    return {
        "rate_limit": config.RATE_LIMIT_SECONDS,
        "restrict": config.RESTRICT_SECONDS,
        "block": config.BLOCK_SECONDS,
        "flag": FLAG_SECONDS,
    }[action]


def _status_from(event, protections):
    """Strongest status that active protections impose on this event."""
    status, strongest = "allowed", None
    for p in protections:
        if p["action"] == "block":
            candidate = "blocked"
        elif p["action"] == "restrict":
            candidate = "restricted" if event["event_type"] in RESTRICTED_EVENTS else "allowed"
        elif p["action"] == "rate_limit":
            candidate = "rate_limited"
        else:
            continue
        if STATUS_RANK[candidate] > STATUS_RANK[status]:
            status, strongest = candidate, p
    return status, strongest


def _record_finding(finding, ts):
    """Create a new incident, or update the ongoing one for the same subject."""
    action = choose_action(finding["attack_type"], finding["severity"])
    expires_at = ts + _duration(action)
    existing = storage.find_active_incident(
        finding["attack_type"], finding["subject_type"], finding["subject"], now=ts
    )

    if existing:
        merged = sorted(set(existing["evidence"]) | set(finding["evidence_ids"]))[-50:]
        changes = {"evidence": merged}
        escalated = False
        if finding["risk_score"] > existing["risk_score"]:
            changes.update(severity=finding["severity"],
                           risk_score=finding["risk_score"],
                           reason=finding["reason"])
            if ACTION_RANK[action] > ACTION_RANK[existing["action"]]:
                escalated = True
                changes.update(action=action, expires_at=expires_at)
                if action != "flag":
                    storage.add_protection(finding["subject_type"], finding["subject"],
                                           action, expires_at,
                                           incident_id=existing["id"], ts=ts)
        storage.update_incident(existing["id"], **changes)
        return {
            "id": existing["id"],
            "attack_type": finding["attack_type"],
            "severity": changes.get("severity", existing["severity"]),
            "action": changes.get("action", existing["action"]),
            "reason": changes.get("reason", existing["reason"]),
            "new": False,
            "escalated": escalated,
        }

    incident_id = storage.create_incident(
        attack_type=finding["attack_type"],
        severity=finding["severity"],
        risk_score=finding["risk_score"],
        subject_type=finding["subject_type"],
        subject=finding["subject"],
        reason=finding["reason"],
        action=action,
        expires_at=expires_at,
        evidence_ids=finding["evidence_ids"],
        ts=ts,
    )
    if action != "flag":
        storage.add_protection(finding["subject_type"], finding["subject"],
                               action, expires_at, incident_id=incident_id, ts=ts)
    return {
        "id": incident_id,
        "attack_type": finding["attack_type"],
        "severity": finding["severity"],
        "action": action,
        "reason": finding["reason"],
        "new": True,
        "escalated": False,
    }


def handle_event(event_type, user_id=None, ip=None, device=None,
                 ts=None, label="normal", meta=None):
    """Process one event and return the decision.

    status is one of: allowed, flagged, rate_limited, restricted, blocked.
    """
    ts = ts if ts is not None else time.time()

    # 1. Automatic recovery: lift protections that have run out.
    storage.expire_protections(ts)

    # 2. Always record what happened.
    event_id = storage.add_event(event_type, user_id=user_id, ip=ip, device=device,
                                 ts=ts, label=label, meta=meta)
    event = {"id": event_id, "ts": ts, "event_type": event_type,
             "user_id": user_id, "ip": ip, "device": device}

    # 3. Is this event already covered by an active protection?
    protections = storage.get_active_protections(ip=ip, user_id=user_id, now=ts)
    status, protection = _status_from(event, protections)
    if status in ("blocked", "restricted"):
        return {
            "event_id": event_id,
            "status": status,
            "incidents": [],
            "incident_id": protection["incident_id"],
            "reason": f"Request refused: active {protection['action']} on "
                      f"{protection['subject_type']} '{protection['subject']}'.",
        }

    # 4. Look for new suspicious behavior.
    incidents = [_record_finding(f, ts) for f in detector.analyze(event, now=ts)]
    if incidents:
        protections = storage.get_active_protections(ip=ip, user_id=user_id, now=ts)
        status, protection = _status_from(event, protections)
        if status == "allowed":
            status = "flagged"

    return {
        "event_id": event_id,
        "status": status,
        "incidents": incidents,
        "incident_id": incidents[0]["id"] if incidents else None,
        "reason": incidents[0]["reason"] if incidents else "",
    }   