# 🛡️ Buttr Shield

Abuse and attack protection prototype for Buttr. It watches activity, detects
suspicious behavior, explains why, protects the service temporarily, and keeps
a full record for admin review.

## What it detects

| Attack | How it is recognised | Response |
|---|---|---|
| Brute force | One IP fails many times on one account | Rate limit, then block |
| Credential stuffing | One IP tries many different accounts | Block IP |
| Email spam | Account sends far more email than usual | Restrict email |
| API abuse | One IP sends too many requests | Rate limit |
| Behavior change | Account far above its own normal | Rate limit or restrict |
| New device | Known account logs in from a new device | Flag only |

Every incident stores a severity, a risk score (0-100), the reason in plain
English, the evidence events, and the action taken. Protections are temporary
and lift automatically.

## Demo

| Traffic | Result |
|---|---|
| Normal users | 🟢 Allowed |
| Repeated login failures | 🟠 Detected, rate limited |
| Credential stuffing | 🔴 Detected, blocked |
| Abnormal email activity | 🔴 Detected, restricted |

## Results on simulated traffic

| Metric | Result |
|---|---|
| Attack types caught | 5/5 |
| False positives | 0 of 144 normal events |
| Precision | 100% |
| Soft alerts (flagged only) | 1 |

These numbers come from the built-in simulator, not from real traffic. Real
traffic is messier, so thresholds in `app/config.py` will need tuning on real
data. The system waits for a little evidence before acting, so the first few
events of each attack are allowed on purpose. That is the trade-off between
catching attacks early and not punishing normal users.

## Setup

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Run

| Goal | Command |
|---|---|
| Full demo (server, dashboard, attacks, report) | `python run_demo.py` |
| Server only | `python -m app.server` (dashboard at http://127.0.0.1:5000) |
| One scenario | `python simulator\simulator.py credential_stuffing --reset` |
| Accuracy report | `python report.py` |
| Tests | `python -m pytest -v` |

Scenarios: `normal`, `brute_force`, `credential_stuffing`, `email_spam`,
`api_abuse`, `behavior_change`, or `all`.

## Project structure

```
app/config.py       thresholds and protection durations
app/storage.py      SQLite: events, incidents, protections
app/detector.py     detection rules and risk scoring
app/responder.py    chooses and applies the protective action
app/server.py       Flask API and dashboard
simulator/          normal users and attack traffic
report.py           detection rate and false positive report
tests/              automatic tests
```

## API

| Endpoint | Purpose |
|---|---|
| `POST /api/event` | Send an event, get a decision (200 allowed, 429 rate limited, 403 blocked or restricted) |
| `GET /api/incidents` | Incident history |
| `GET /api/incidents/<id>` | One incident with its evidence |
| `POST /api/incidents/<id>/review` | Admin verdict: `real_attack` or `false_alarm` |
| `GET /api/protections` | Active protections |
| `GET /api/stats` | Dashboard numbers |

## Design decisions

- Blocks target the attacking IP, not the victim account, so an attacker
  cannot lock real users out.
- Detection compares an account to its own history, so a legitimately busy
  sender is not treated as spam.
- The system waits for a little evidence before acting, so one typo is never
  an attack.
- Detectors use event timestamps instead of the clock, so hours of traffic
  can be simulated in seconds.
- The dashboard escapes all text it displays, so a hostile username cannot
  run code in the admin's browser.

## Limitations and next steps

- Rules and thresholds only (no machine learning). Thresholds are in `app/config.py`.
- SQLite and the Flask development server are for a prototype. A real
  deployment needs a production server, a faster store such as Redis for
  counters, and authentication on the admin dashboard and API.
- Real traffic may sit behind proxies, so client IPs need to be read carefully.
- Next steps: IP reputation lists, CAPTCHA as an extra response, email or
  Slack alerts for critical incidents, and learning thresholds from real data. 