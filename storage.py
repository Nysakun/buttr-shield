# app/storage.py
# SQLite storage for events, incidents and active protections.

import json
import os
import sqlite3
import time
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT, "buttr_shield.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    event_type TEXT NOT NULL,
    user_id TEXT,
    ip TEXT,
    device TEXT,
    label TEXT DEFAULT 'normal',
    meta TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    attack_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    subject_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    reason TEXT NOT NULL,
    action TEXT NOT NULL,
    expires_at REAL,
    recovered_at REAL,
    evidence TEXT,
    review_status TEXT DEFAULT 'open',
    review_verdict TEXT,
    review_note TEXT,
    reviewed_at REAL
);

CREATE TABLE IF NOT EXISTS protections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    incident_id INTEGER,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    active INTEGER DEFAULT 1
);
"""


@contextmanager
def db():
    """Open a connection, commit on success, always close."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript(SCHEMA)


def reset_db():
    """Wipe everything and start fresh (used by the simulator and tests)."""
    with db() as conn:
        conn.executescript(
            "DROP TABLE IF EXISTS events;"
            "DROP TABLE IF EXISTS incidents;"
            "DROP TABLE IF EXISTS protections;"
        )
    init_db()


def _to_dict(row):
    data = dict(row)
    if "evidence" in data:
        data["evidence"] = json.loads(data["evidence"] or "[]")
    return data


# ---------- Events ----------

def add_event(event_type, user_id=None, ip=None, device=None,
              ts=None, label="normal", meta=None):
    """Save one event. `label` is only used by the simulator for accuracy reports."""
    ts = ts if ts is not None else time.time()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO events (ts, event_type, user_id, ip, device, label, meta) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, event_type, user_id, ip, device, label, json.dumps(meta or {})),
        )
        return cur.lastrowid


def get_events(since_ts=0, until_ts=None, event_type=None, ip=None, user_id=None):
    """Fetch events in a time range, optionally filtered."""
    query = "SELECT * FROM events WHERE ts >= ?"
    params = [since_ts]
    if until_ts is not None:
        query += " AND ts <= ?"
        params.append(until_ts)
    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if ip:
        query += " AND ip = ?"
        params.append(ip)
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    query += " ORDER BY ts"
    with db() as conn:
        return [dict(r) for r in conn.execute(query, params).fetchall()]


# ---------- Incidents ----------

def create_incident(attack_type, severity, risk_score, subject_type, subject,
                    reason, action, expires_at=None, evidence_ids=None, ts=None):
    ts = ts if ts is not None else time.time()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO incidents (created_at, attack_type, severity, risk_score, "
            "subject_type, subject, reason, action, expires_at, evidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, attack_type, severity, risk_score, subject_type, subject,
             reason, action, expires_at, json.dumps(evidence_ids or [])),
        )
        return cur.lastrowid


def find_active_incident(attack_type, subject_type, subject, now=None):
    """Return the ongoing incident for this subject, if any (avoids duplicates)."""
    now = now if now is not None else time.time()
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE attack_type = ? AND subject_type = ? "
            "AND subject = ? AND recovered_at IS NULL "
            "AND (expires_at IS NULL OR expires_at > ?) ORDER BY id DESC LIMIT 1",
            (attack_type, subject_type, subject, now),
        ).fetchone()
    return _to_dict(row) if row else None


def update_incident(incident_id, **fields):
    """Update selected columns, e.g. when an attack escalates."""
    allowed = {"severity", "risk_score", "reason", "action",
               "expires_at", "recovered_at", "evidence"}
    sets, params = [], []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "evidence":
            value = json.dumps(value)
        sets.append(f"{key} = ?")
        params.append(value)
    if not sets:
        return
    params.append(incident_id)
    with db() as conn:
        conn.execute(f"UPDATE incidents SET {', '.join(sets)} WHERE id = ?", params)


def list_incidents(limit=100, review_status=None):
    query = "SELECT * FROM incidents"
    params = []
    if review_status:
        query += " WHERE review_status = ?"
        params.append(review_status)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with db() as conn:
        return [_to_dict(r) for r in conn.execute(query, params).fetchall()]


def get_incident(incident_id):
    """Return one incident together with the events that triggered it."""
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if not row:
            return None
        incident = _to_dict(row)
        ids = incident["evidence"]
        events = []
        if ids:
            marks = ",".join("?" * len(ids))
            events = [dict(r) for r in conn.execute(
                f"SELECT * FROM events WHERE id IN ({marks}) ORDER BY ts", ids
            ).fetchall()]
        incident["events"] = events
        return incident


def review_incident(incident_id, verdict, note=""):
    """Admin review. verdict: 'real_attack' or 'false_alarm'."""
    with db() as conn:
        conn.execute(
            "UPDATE incidents SET review_status = 'reviewed', review_verdict = ?, "
            "review_note = ?, reviewed_at = ? WHERE id = ?",
            (verdict, note, time.time(), incident_id),
        )


# ---------- Protections (temporary blocks) ----------

def add_protection(subject_type, subject, action, expires_at,
                   incident_id=None, ts=None):
    ts = ts if ts is not None else time.time()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO protections (subject_type, subject, action, incident_id, "
            "created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (subject_type, subject, action, incident_id, ts, expires_at),
        )
        return cur.lastrowid


def get_active_protections(ip=None, user_id=None, now=None):
    """Return active protections that apply to this IP or account."""
    now = now if now is not None else time.time()
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM protections WHERE active = 1 AND expires_at > ? AND "
            "((subject_type = 'ip' AND subject = ?) OR "
            "(subject_type = 'account' AND subject = ?))",
            (now, ip or "", user_id or ""),
        ).fetchall()
    return [dict(r) for r in rows]


def list_active_protections(now=None):
    now = now if now is not None else time.time()
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM protections WHERE active = 1 AND expires_at > ? "
            "ORDER BY id DESC", (now,)
        ).fetchall()
    return [dict(r) for r in rows]


def expire_protections(now=None):
    """Automatic recovery: switch off expired protections.
    An incident is marked recovered only when none of its protections are still active."""
    now = now if now is not None else time.time()
    with db() as conn:
        rows = conn.execute(
            "SELECT id, incident_id FROM protections WHERE active = 1 AND expires_at <= ?",
            (now,),
        ).fetchall()
        for row in rows:
            conn.execute("UPDATE protections SET active = 0 WHERE id = ?", (row["id"],))
        for incident_id in {r["incident_id"] for r in rows if r["incident_id"]}:
            still_active = conn.execute(
                "SELECT 1 FROM protections WHERE incident_id = ? AND active = 1 LIMIT 1",
                (incident_id,),
            ).fetchone()
            if not still_active:
                conn.execute(
                    "UPDATE incidents SET recovered_at = ? WHERE id = ?",
                    (now, incident_id),
                )
        return len(rows) 