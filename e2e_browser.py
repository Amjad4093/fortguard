"""End-to-end check in a real browser (needs `pip install playwright` and a Chromium).

    python e2e_browser.py [--shots DIR]

Starts the server in dev mode, drives /phone like a person would (CDP touch swipes, typing with
human-like timing, device motion events), checks the decisions, opens /portal and takes screenshots.
"""

import argparse
import math
import os
import pathlib
import random
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

PORT = 8791
BASE = f"http://localhost:{PORT}"
ACCOUNT = "PK36EXMP00992201029381"


def start_server():
    env = dict(os.environ, PORT=str(PORT))
    proc = subprocess.Popen([sys.executable, "-m", "fortguard.app", "--dev", "--port", str(PORT)],
                            cwd=pathlib.Path(__file__).parent, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            import urllib.request
            urllib.request.urlopen(BASE + "/healthz", timeout=1)
            return proc
        except Exception:
            time.sleep(0.2)
    proc.kill()
    raise SystemExit("server did not start")


def swipe(cdp, x0, y0, x1, y1, bow):
    steps = 12
    def point(i):
        f = i / steps
        return {"x": x0 + (x1 - x0) * f + math.sin(f * math.pi) * bow + random.gauss(0, 1.2),
                "y": y0 + (y1 - y0) * f, "radiusX": 6, "radiusY": 6, "force": 0.4 + 0.3 * random.random()}
    cdp.send("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [point(0)]})
    for i in range(1, steps):
        time.sleep(0.016 + random.random() * 0.012)
        cdp.send("Input.dispatchTouchEvent", {"type": "touchMove", "touchPoints": [point(i)]})
    cdp.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})


def shake(page, seconds=2.0):
    """Feed devicemotion events like a phone held in a hand (about 8 Hz tremor on top of gravity)."""
    t0 = time.time()
    while time.time() - t0 < seconds:
        t = time.time() - t0
        page.evaluate(
            """([t]) => window.dispatchEvent(new DeviceMotionEvent('devicemotion', {
              accelerationIncludingGravity: {x: 0.1 + 0.05*Math.sin(t*50), y: 9.81 + 0.06*Math.sin(t*50.3), z: 0.2 + 0.04*Math.cos(t*47)},
              rotationRate: {alpha: 0.8*Math.sin(t*9), beta: 0.6*Math.cos(t*11), gamma: 0.5*Math.sin(t*13)}, interval: 16}))""",
            [t])
        time.sleep(0.03)


def human_type(page, selector, text):
    page.click(selector)
    for ch in text:
        page.keyboard.type(ch, delay=random.uniform(40, 110))
        time.sleep(random.uniform(0.07, 0.22))


def decision(page):
    page.wait_for_selector("#result:not(.hidden)", timeout=15000)
    return int(page.inner_text("#r-score")), page.inner_text("#r-level").replace(" ", "_"), page.inner_text("#r-reasons")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", default="e2e_shots")
    shots = pathlib.Path(ap.parse_args().shots)
    shots.mkdir(exist_ok=True)
    random.seed(7)
    server = start_server()
    ok = True
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context(**p.devices["Pixel 7"])
            # Simulate the person tapping "Allow" on the motion-sensor prompt (headless Chromium denies it).
            ctx.add_init_script("if (window.DeviceMotionEvent) DeviceMotionEvent.requestPermission = async () => 'granted';")
            page = ctx.new_page()
            logs = []
            page.on("console", lambda m: logs.append(m.text))
            page.on("pageerror", lambda e: logs.append("PAGEERROR " + str(e)))
            cdp = ctx.new_cdp_session(page)
            page.goto(BASE + "/phone")
            page.click("#b-motion")  # newer Chromium and iOS Safari both ask for a tap before sensors start

            # 1. A person on a calm phone sending money to a new payee.
            for _ in range(3):
                swipe(cdp, 200, 520, 220, 380, random.uniform(10, 24)); time.sleep(0.5)
            shake(page, 1.5)
            human_type(page, "#acct", ACCOUNT)
            human_type(page, "#amount", "250000")
            for _ in range(3):
                swipe(cdp, 260, 520, 180, 400, random.uniform(10, 24)); time.sleep(0.4)
            shake(page, 1.0)
            page.click("#b-check")
            score, level, reasons = decision(page)
            print(f"calm person      -> {score:4d} {level:8s} {' '.join(r for r in reasons.split() if r.startswith('REASON_'))}")
            page.screenshot(path=str(shots / "phone_calm.png"), full_page=True)
            batch = page.inner_text("#last-batch")
            typed_leak = ACCOUNT in batch or "250000" in batch
            print("typed characters in the last batch:", "YES (BUG)" if typed_leak else "none")
            ok &= not typed_leak and level == "ALLOW"

            # 2. Coached scam look: on a call, pasted account, remote tool, long pauses.
            page.click("#b-newsession")
            page.check("#f-active_call"); page.check("#f-active_remote_software")
            page.click("#acct")
            page.evaluate("document.getElementById('acct').dispatchEvent(new Event('paste', {bubbles: true}))")
            page.fill("#acct", ACCOUNT)
            time.sleep(3.2)
            page.click("#amount"); time.sleep(3.2); page.fill("#amount", "250000"); time.sleep(3.2)
            for _ in range(3):
                swipe(cdp, 200, 520, 220, 380, 12); time.sleep(0.3)
            shake(page, 1.0)
            page.click("#b-check")
            page.wait_for_timeout(600)
            score2, level2, reasons2 = decision(page)
            print(f"call + remote    -> {score2:4d} {level2:8s} {' '.join(r for r in reasons2.split() if r.startswith('REASON_'))}")
            page.screenshot(path=str(shots / "phone_scam.png"), full_page=True)
            ok &= level2 in ("STEP_UP", "BLOCK")

            # 3. The portal shows both, with reasons.
            portal = ctx.new_page()
            portal.set_viewport_size({"width": 1280, "height": 800})
            portal.goto(BASE + "/portal")
            portal.wait_for_selector("#rows tr")
            rows = portal.locator("#rows tr").count()
            portal.locator("#rows tr").first.click()
            portal.wait_for_selector("#detail:not(.hidden)")
            portal.screenshot(path=str(shots / "portal.png"))
            print("portal rows:", rows, "| device rows:", portal.locator("#drows tr").count())
            ok &= rows >= 2

            errors = [l for l in logs if "PAGEERROR" in l or "Failed to load" in l]
            print("page errors:", errors or "none")
            ok &= not errors
            browser.close()
    finally:
        server.terminate()
    print("E2E", "PASSED" if ok else "FAILED")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
