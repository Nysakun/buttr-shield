# app/server.py
# Flask API: receives events, returns decisions, serves incident data for the dashboard.

import time

from flask import Flask, jsonify, render_template, request

from app import responder, storage

STATUS_CODES = {
    "allowed": 200,
    "flagged": 200,
    "rate_limited": 429,
    "restricted": 403,
    "blocked": 403,
}
VALID_EVENTS = ("login_failed", "login_success", "email_sent", "api_request")


def create_app():
    app = Flask(__name__)
    storage.init_db()

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html")

    @app.post("/api/event")
    def post_event():
        data = request.get_json(silent=True) or {}
        event_type = data.get("event_type")
        if event_type not in VALID_EVENTS:
            return jsonify(error=f"event_type must be one of {VALID_EVENTS}"), 400
        decision = responder.handle_event(
            event_type,
            user_id=data.get("user_id"),
            ip=data.get("ip") or request.remote_addr,
            device=data.get("device"),
            ts=data.get("ts"),
            label=data.get("label", "normal"),
            meta=data.get("meta"),
        )
        return jsonify(decision), STATUS_CODES.get(decision["status"], 200)

    @app.get("/api/incidents")
    def incidents():
        storage.expire_protections()
        limit = request.args.get("limit", 100, type=int)
        status = request.args.get("review_status")
        return jsonify(storage.list_incidents(limit=limit, review_status=status))

    @app.get("/api/incidents/<int:incident_id>")
    def incident_detail(incident_id):
        incident = storage.get_incident(incident_id)
        if not incident:
            return jsonify(error="incident not found"), 404
        return jsonify(incident)

    @app.post("/api/incidents/<int:incident_id>/review")
    def review(incident_id):
        data = request.get_json(silent=True) or {}
        verdict = data.get("verdict")
        if verdict not in ("real_attack", "false_alarm"):
            return jsonify(error="verdict must be 'real_attack' or 'false_alarm'"), 400
        if not storage.get_incident(incident_id):
            return jsonify(error="incident not found"), 404
        storage.review_incident(incident_id, verdict, data.get("note", ""))
        return jsonify(storage.get_incident(incident_id))

    @app.get("/api/protections")
    def protections():
        storage.expire_protections()
        return jsonify(storage.list_active_protections())

    @app.get("/api/stats")
    def stats():
        storage.expire_protections()
        all_incidents = storage.list_incidents(limit=10000)
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for inc in all_incidents:
            by_severity[inc["severity"]] = by_severity.get(inc["severity"], 0) + 1
        return jsonify(
            total_events=len(storage.get_events()),
            total_incidents=len(all_incidents),
            open_incidents=sum(1 for i in all_incidents if i["review_status"] == "open"),
            active_protections=len(storage.list_active_protections()),
            by_severity=by_severity,
            server_time=time.time(),
        )

    @app.post("/api/reset")
    def reset():
        storage.reset_db()
        return jsonify(ok=True)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False) 
    