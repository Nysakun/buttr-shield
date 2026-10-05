# simulator/simulator.py
# Generates normal users and different attacks, sends them to the running
# server, and records what the system decided for every event.
#
# Usage (the server must be running):
#   python simulator\simulator.py all
#   python simulator\simulator.py credential_stuffing

import argparse
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

BASE_URL = "http://127.0.0.1:5000"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_PATH = os.path.join(ROOT, "reports", "last_run.json")

STATUS_ORDER = ["allowed", "flagged", "rate_limited", "restricted", "blocked"]
ICONS = {
    "allowed": "🟢 Allowed",
    "flagged": "🟡 Flagged",
    "rate_limited": "🟠 Rate limited",
    "restricted": "🔴 Restricted",
    "blocked": "🔴 Blocked",
}


class Client:
    """Sends events to the server and remembers every decision."""

    def __init__(self, delay):
        self.delay = delay
        self.records = []
        self.scenario = ""
        self.label = "normal"
        self.count = 0
        self.last_status = "allowed"

    def begin(self, scenario, label):
        self.scenario = scenario
        self.label = label
        self.count = 0
        self.last_status = "allowed"

    def _post(self, path, payload=None):
        data = json.dumps(payload or {}).encode()
        request = urllib.request.Request(
            BASE_URL + path, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as err:
            # 403 and 429 are normal answers ("blocked", "slow down"), not failures.
            return json.load(err)

    def reset(self):
        self._post("/api/reset")

    def send(self, event_type, user_id, ip, device=None, ts=None, history=False):
        """Send one event. history=True means old background activity:
        it is sent silently and always labelled normal."""
        label = "normal" if history else self.label
        payload = {"event_type": event_type, "user_id": user_id, "ip": ip,
                   "device": device, "label": label}
        if ts is not None:
            payload["ts"] = ts
        decision = self._post("/api/event", payload)
        if "error" in decision:
            raise RuntimeError(decision["error"])

        status = decision["status"]
        self.records.append({
            "scenario": self.scenario, "label": label, "history": history,
            "event_type": event_type, "user_id": user_id, "ip": ip,
            "status": status, "incident_id": decision.get("incident_id"),
        })
        if not history:
            self.count += 1
            if status != self.last_status:
                reason = decision.get("reason", "")[:100]
                line = f"   event #{self.count}: {ICONS[status]}"
                print(f"{line} - {reason}" if reason else line)
                self.last_status = status
            time.sleep(self.delay)
        return decision


def fake_ip():
    return f"203.0.113.{random.randint(1, 254)}"


def run_id():
    return random.randint(100, 999)


# ---------- Scenarios ----------

def normal_traffic(c):
    office_ip = "198.51.100.5"          # 6 people share one office IP
    for i in range(1, 13):
        user = f"normal{i}"
        ip = office_ip if i <= 6 else f"198.51.100.{20 + i}"
        device = f"laptop-{i}"
        for _ in range(random.randint(0, 2)):        # password typos
            c.send("login_failed", user, ip, device)
        c.send("login_success", user, ip, device)
        for _ in range(random.randint(1, 5)):
            c.send("email_sent", user, ip, device)
        for _ in range(random.randint(3, 8)):
            c.send("api_request", user, ip, device)

    base = time.time()

    # A busy but legitimate sender: about 6 emails/min, then a small burst.
    for i in range(36):
        c.send("email_sent", "busy-sender", "198.51.100.60", "laptop-busy",
               ts=base - 400 + i * 9, history=True)
    for _ in range(18):
        c.send("email_sent", "busy-sender", "198.51.100.60", "laptop-busy")

    # A known user logging in from a new phone (flagged, but never blocked).
    for i in range(6):
        c.send("login_success", "traveler", "198.51.100.70", "laptop",
               ts=base - 3000 + i * 300, history=True)
    c.send("login_success", "traveler", "198.51.100.71", "phone")


def brute_force(c):
    ip, victim = fake_ip(), f"victim{run_id()}"
    for _ in range(8):
        c.send("login_failed", victim, ip, "unknown-device")


def credential_stuffing(c):
    ip, rid = fake_ip(), run_id()
    for i in range(40):
        c.send("login_failed", f"stolen{rid}-{i}", ip, "bot")


def email_spam(c):
    user, ip = f"spammer{run_id()}", fake_ip()
    base = time.time()
    for i in range(6):                                # about 1 email per minute
        c.send("email_sent", user, ip, "web", ts=base - 400 + i * 60, history=True)
    for _ in range(60):                               # sudden flood
        c.send("email_sent", user, ip, "web")


def api_abuse(c):
    ip = fake_ip()
    for _ in range(150):
        c.send("api_request", None, ip, "scraper")


def behavior_change(c):
    user, ip = f"service{run_id()}", fake_ip()
    base = time.time()
    for i in range(30):                               # about 5 requests per minute
        c.send("api_request", user, ip, "server", ts=base - 400 + i * 11, history=True)
    for _ in range(60):                               # sudden jump
        c.send("api_request", user, ip, "server")


# key, title, label, expected strongest status, function
SCENARIOS = [
    ("normal", "🟢 Normal users", "normal", None, normal_traffic),
    ("brute_force", "🟠 Brute force (one account, many passwords)",
     "brute_force", "rate_limited", brute_force),
    ("credential_stuffing", "🔴 Credential stuffing (one IP, many accounts)",
     "credential_stuffing", "blocked", credential_stuffing),
    ("email_spam", "🔴 Email spam (sudden flood from one account)",
     "email_spam", "restricted", email_spam),
    ("api_abuse", "🟠 API abuse (too many requests from one IP)",
     "api_abuse", "rate_limited", api_abuse),
    ("behavior_change", "🟠 Behavior change (account far above its own normal)",
     "behavior_change", "rate_limited", behavior_change),
]


def run_scenario(client, key, title, label, expected, func):
    print(f"\n=== {title} ===")
    client.begin(key, label)
    func(client)

    events = [r for r in client.records if r["scenario"] == key and not r["history"]]
    counts = Counter(r["status"] for r in events)
    strongest = max(counts, key=STATUS_ORDER.index)
    summary = ", ".join(f"{ICONS[s]} {counts[s]}" for s in STATUS_ORDER if s in counts)
    print(f"   {len(events)} events: {summary}")

    if label == "normal":
        passed = STATUS_ORDER.index(strongest) <= STATUS_ORDER.index("flagged")
        print("   Expected: nobody limited, restricted or blocked -> "
              + ("PASS ✅" if passed else "FAIL ❌ (normal users were punished)"))
    else:
        passed = strongest == expected
        print(f"   Expected: {ICONS[expected]} -> "
              + ("PASS ✅" if passed else f"FAIL ❌ (got {ICONS[strongest]})"))
    return passed


def main():
    parser = argparse.ArgumentParser(description="Buttr Shield traffic simulator")
    parser.add_argument("scenario", choices=["all"] + [s[0] for s in SCENARIOS])
    parser.add_argument("--delay", type=float, default=0.03,
                        help="seconds between events (default 0.03)")
    parser.add_argument("--reset", action="store_true",
                        help="clear old data first ('all' always does this)")
    args = parser.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    client = Client(args.delay)
    chosen = SCENARIOS if args.scenario == "all" else [
        s for s in SCENARIOS if s[0] == args.scenario]

    try:
        if args.scenario == "all" or args.reset:
            client.reset()
            print("Old data cleared.")
        results = []
        for key, title, label, expected, func in chosen:
            results.append(run_scenario(client, key, title, label, expected, func))
            time.sleep(1)
    except urllib.error.URLError:
        print("\nCannot reach the server. Start it first in another terminal:")
        print("   python -m app.server")
        return
    except ValueError:
        print("\nThe server sent an unexpected answer. Check the server terminal for the error.")
        return

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump({"generated_at": time.time(), "records": client.records}, f)

    print(f"\nScenarios passed: {sum(results)}/{len(results)}")
    print(f"Results saved to reports\\last_run.json. Dashboard: {BASE_URL}")


if __name__ == "__main__":
    main() 