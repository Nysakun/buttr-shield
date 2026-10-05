# report.py
# Reads the results saved by the simulator and measures how well the system
# detected attacks and how often it wrongly punished normal users.
#
# Usage:
#   python simulator\simulator.py all
#   python report.py

import html
import json
import os
import sys
import time
from collections import defaultdict

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS_PATH = os.path.join(ROOT, "reports", "last_run.json")
HTML_PATH = os.path.join(ROOT, "reports", "report.html")

# Statuses that actually restrict someone. "flagged" is only a soft alert.
PROTECTIVE = ("rate_limited", "restricted", "blocked")


def pct(part, whole):
    return 100.0 * part / whole if whole else 0.0


def load_records():
    if not os.path.exists(RESULTS_PATH):
        print("No results found. Run the simulator first:")
        print("   python simulator\\simulator.py all")
        sys.exit(1)
    with open(RESULTS_PATH, encoding="utf-8") as f:
        data = json.load(f)
    # Background history events are not part of the test.
    return [r for r in data["records"] if not r["history"]]


def analyze(records):
    normal = [r for r in records if r["label"] == "normal"]
    attacks = [r for r in records if r["label"] != "normal"]

    false_positives = [r for r in normal if r["status"] in PROTECTIVE]
    soft_alerts = [r for r in normal if r["status"] == "flagged"]
    stopped = [r for r in attacks if r["status"] in PROTECTIVE]

    grouped = defaultdict(list)
    for r in attacks:
        grouped[r["label"]].append(r)

    scenarios = []
    for name, events in grouped.items():
        first = next((i + 1 for i, r in enumerate(events)
                      if r["status"] in PROTECTIVE), None)
        scenarios.append({
            "name": name,
            "total": len(events),
            "detected": first is not None,
            "first": first,
            "stopped": sum(1 for r in events if r["status"] in PROTECTIVE),
        })

    caught = sum(1 for s in scenarios if s["detected"])
    return {
        "normal_total": len(normal),
        "attack_total": len(attacks),
        "false_positives": len(false_positives),
        "fp_users": sorted({r["user_id"] or r["ip"] for r in false_positives}),
        "soft_alerts": len(soft_alerts),
        "stopped": len(stopped),
        "scenarios": scenarios,
        "attacks_caught": caught,
        "attacks_total": len(scenarios),
        "detection_rate": pct(caught, len(scenarios)),
        "fp_rate": pct(len(false_positives), len(normal)),
        "precision": pct(len(stopped), len(stopped) + len(false_positives)),
        "stopped_rate": pct(len(stopped), len(attacks)),
    }


def print_report(m):
    print("\n" + "=" * 62)
    print(" BUTTR SHIELD - ACCURACY REPORT")
    print("=" * 62)
    print(f"\n Attacks caught        : {m['attacks_caught']}/{m['attacks_total']}"
          f"  ({m['detection_rate']:.0f}%)")
    print(f" False positive rate   : {m['false_positives']}/{m['normal_total']}"
          f" normal events punished  ({m['fp_rate']:.1f}%)")
    print(f" Precision             : {m['precision']:.1f}%"
          "  (of all actions taken, how many were real attacks)")
    print(f" Soft alerts (flagged) : {m['soft_alerts']}  (logged, nobody was restricted)")
    print(f" Attack events stopped : {m['stopped']}/{m['attack_total']}"
          f"  ({m['stopped_rate']:.0f}%)")

    print("\n Per attack type:")
    print(f"   {'attack':<22}{'result':<12}{'caught after':<16}{'events stopped'}")
    for s in m["scenarios"]:
        result = "caught" if s["detected"] else "MISSED"
        after = f"event #{s['first']}" if s["first"] else "-"
        print(f"   {s['name']:<22}{result:<12}{after:<16}{s['stopped']}/{s['total']}")

    if m["fp_users"]:
        print("\n Normal users wrongly punished: " + ", ".join(m["fp_users"]))
    missed = [s["name"] for s in m["scenarios"] if not s["detected"]]
    if missed:
        print("\n Missed attacks: " + ", ".join(missed))
    print("\n Note: the first few events of every attack are allowed on purpose."
          "\n The system needs a little evidence before it acts, so one"
          "\n typo or one busy minute is never treated as an attack.\n")


def write_html(m):
    def esc(value):
        return html.escape(str(value))

    rows = "".join(
        f"<tr><td>{esc(s['name'])}</td>"
        f"<td class='{'ok' if s['detected'] else 'bad'}'>"
        f"{'caught' if s['detected'] else 'MISSED'}</td>"
        f"<td>{'event #' + str(s['first']) if s['first'] else '-'}</td>"
        f"<td>{s['stopped']}/{s['total']}</td></tr>"
        for s in m["scenarios"]
    )
    fp_line = (", ".join(esc(u) for u in m["fp_users"])
               if m["fp_users"] else "none")
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Buttr Shield report</title>
<style>
 body {{ font-family: system-ui, sans-serif; max-width: 820px; margin: 30px auto; padding: 0 16px; color: #1f2933; }}
 .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }}
 .card {{ border: 1px solid #d0d7de; border-radius: 10px; padding: 14px; }}
 .card b {{ display: block; font-size: 28px; margin-top: 4px; }}
 table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
 th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #e5e9ee; }}
 .ok {{ color: #1a7f37; font-weight: 600; }} .bad {{ color: #cf222e; font-weight: 600; }}
 small {{ color: #6b7785; }}
</style></head><body>
<h1>Buttr Shield - accuracy report</h1>
<small>Generated {esc(time.strftime('%Y-%m-%d %H:%M:%S'))}</small>
<div class="cards">
 <div class="card">Attacks caught<b>{m['attacks_caught']}/{m['attacks_total']}</b>{m['detection_rate']:.0f}%</div>
 <div class="card">False positive rate<b>{m['fp_rate']:.1f}%</b>{m['false_positives']} of {m['normal_total']} normal events</div>
 <div class="card">Precision<b>{m['precision']:.1f}%</b>actions that were real attacks</div>
 <div class="card">Soft alerts<b>{m['soft_alerts']}</b>flagged, not restricted</div>
</div>
<h2>Per attack type</h2>
<table><tr><th>Attack</th><th>Result</th><th>Caught after</th><th>Events stopped</th></tr>{rows}</table>
<p>Normal users wrongly punished: {fp_line}</p>
<p><small>The first few events of each attack are allowed on purpose: the system
needs some evidence before it acts, so a typo or a busy minute is not punished.</small></p>
</body></html>"""
    with open(HTML_PATH, "w", encoding="utf-8") as f:
        f.write(page)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    metrics = analyze(load_records())
    print_report(metrics)
    write_html(metrics)
    print(f" HTML report saved: {HTML_PATH}")


if __name__ == "__main__":
    main() 