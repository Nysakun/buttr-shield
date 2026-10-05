# run_demo.py
# One command for the whole demo: starts the server, opens the dashboard,
# runs normal users plus every attack, and prints the accuracy report.
#
#   python run_demo.py            (slower, so you can watch the dashboard)
#   python run_demo.py --fast

import argparse
import os
import subprocess
import sys
import time
import urllib.request
import webbrowser

ROOT = os.path.dirname(os.path.abspath(__file__))
URL = "http://127.0.0.1:5000"


def server_is_up():
    try:
        urllib.request.urlopen(URL + "/api/stats", timeout=1)
        return True
    except Exception:
        return False


def wait_for_server(seconds=15):
    for _ in range(seconds * 4):
        if server_is_up():
            return True
        time.sleep(0.25)
    return False


def run(*args):
    return subprocess.run([sys.executable, *args], cwd=ROOT).returncode


def main():
    parser = argparse.ArgumentParser(description="Buttr Shield full demo")
    parser.add_argument("--fast", action="store_true", help="no delay between events")
    parser.add_argument("--no-browser", action="store_true", help="do not open the dashboard")
    args = parser.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    server = None
    if server_is_up():
        print("Server is already running, using it.")
    else:
        print("Starting server...")
        server = subprocess.Popen(
            [sys.executable, "-m", "app.server"], cwd=ROOT,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if not wait_for_server():
            print("The server did not start. Run 'python -m app.server' to see the error.")
            server.terminate()
            return

    print(f"Dashboard: {URL}")
    if not args.no_browser:
        webbrowser.open(URL)
    time.sleep(2)

    try:
        delay = "0" if args.fast else "0.08"
        run(os.path.join("simulator", "simulator.py"), "all", "--delay", delay)
        run("report.py")
        print("\nDemo finished. The dashboard still shows every incident.")
        if server:
            input("Press Enter to stop the server...")
    except KeyboardInterrupt:
        pass
    finally:
        if server:
            server.terminate()


if __name__ == "__main__":
    main() 