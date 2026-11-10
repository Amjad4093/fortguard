"""Set up (or update) the FortGuard test server on a free PythonAnywhere account.

Run it in a PythonAnywhere Bash console, from the folder that holds the unzipped project:

    python3.12 fortguard/deploy/pythonanywhere_setup.py

Use the same Python version you chose for the web app (3.12 in the guide). It is safe to run again
after uploading a new version of the code.

What it does
    1. Installs Flask, NumPy and cryptography for your user (no admin rights needed).
    2. Creates ~/.fortguard-secrets with a random API key and admin password, once, private to you.
    3. Creates the data folder ~/fortguard-data (SQLite database).
    4. Writes the web app's WSGI file so PythonAnywhere runs FortGuard.
    5. Starts FortGuard once in test mode and checks that it answers.
Then press Reload on the Web tab.
"""

import glob
import os
import secrets
import subprocess
import sys

HOME = os.path.expanduser("~")
PROJECT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SECRETS = os.path.join(HOME, ".fortguard-secrets")
DATA = os.path.join(HOME, "fortguard-data")
WSGI_DIR = os.environ.get("FORTGUARD_WSGI_DIR", "/var/www")  # overridable for testing

WSGI_TEMPLATE = '''# FortGuard test server: written by fortguard/deploy/pythonanywhere_setup.py
# DEV MODE: simulated device attestation and the /phone test page. Synthetic data only; never real customers.
import os
import sys

PROJECT = {project!r}
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

with open({secrets!r}) as fh:
    for line in fh:
        if "=" in line:
            key, value = line.strip().split("=", 1)
            os.environ.setdefault(key, value)

os.environ.setdefault("FORTGUARD_DEV_MODE", "1")
os.environ.setdefault("FORTGUARD_TRUST_PROXY", "1")
os.environ.setdefault("FORTGUARD_DATA_DIR", {data!r})

from fortguard.app import create_app  # noqa: E402

application = create_app()
'''


def say(msg):
    print(msg, flush=True)


def install_packages():
    say("1/5 Installing Flask, NumPy and cryptography for your user ...")
    cmd = [sys.executable, "-m", "pip", "install", "--user", "--quiet", "flask>=3.0", "numpy>=1.26", "cryptography>=46.0"]
    if os.environ.get("FORTGUARD_SKIP_PIP") == "1":
        say("    skipped (FORTGUARD_SKIP_PIP=1)")
        return
    result = subprocess.run(cmd)
    if result.returncode != 0:
        sys.exit("pip install failed. Check the messages above; disk space (512 MB) is the usual cause.")


def ensure_secrets():
    say("2/5 Secrets ...")
    if not os.path.exists(SECRETS):
        values = {
            "FORTGUARD_API_KEY": secrets.token_urlsafe(24),
            "FORTGUARD_ADMIN_PASSWORD": secrets.token_urlsafe(12),
        }
        fd = os.open(SECRETS, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            for k, v in values.items():
                fh.write(f"{k}={v}\n")
        say(f"    created {SECRETS} (only you can read it)")
    else:
        say(f"    kept existing {SECRETS}")
    out = {}
    with open(SECRETS) as fh:
        for line in fh:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                out[k] = v
    return out


def find_wsgi():
    files = sorted(glob.glob(os.path.join(WSGI_DIR, "*_wsgi.py")))
    if not files:
        sys.exit("\nNo web app found. On the Web tab choose 'Add a new web app' -> 'Manual configuration' -> "
                 "Python 3.12, then run this script again.")
    if len(files) > 1:
        say(f"    several WSGI files found, using {files[0]}")
    return files[0]


def write_wsgi(path):
    say(f"4/5 Writing {path} ...")
    with open(path, "w") as fh:
        fh.write(WSGI_TEMPLATE.format(project=PROJECT, secrets=SECRETS, data=DATA))


def self_test(values):
    say("5/5 Self-test ...")
    sys.path.insert(0, PROJECT)
    os.environ.update({"FORTGUARD_DEV_MODE": "1", "FORTGUARD_API_KEY": values["FORTGUARD_API_KEY"]})
    from fortguard.app import create_app

    app = create_app(db_path=":memory:", admin_password=values["FORTGUARD_ADMIN_PASSWORD"])
    c = app.test_client()
    checks = {
        "health": c.get("/healthz").status_code == 200,
        "portal page": c.get("/portal").status_code == 200,
        "phone page": c.get("/phone").status_code == 200,
        "admin sign-in": c.post("/v1/auth/login", json={"username": "admin", "password": values["FORTGUARD_ADMIN_PASSWORD"]}).status_code == 200,
        "device challenge": c.post("/v1/devices/challenge", json={}).status_code == 201,
    }
    for name, ok in checks.items():
        say(f"    {'ok  ' if ok else 'FAIL'} {name}")
    if not all(checks.values()):
        sys.exit("Self-test failed: send the lines above to Claude.")


def main():
    say(f"FortGuard setup (Python {sys.version.split()[0]}, project {PROJECT})")
    if sys.version_info < (3, 10):
        sys.exit("Python 3.10 or newer is needed: run with python3.12")
    install_packages()
    values = ensure_secrets()
    say("3/5 Data folder ...")
    os.makedirs(DATA, exist_ok=True)
    write_wsgi(find_wsgi())
    self_test(values)
    user = os.environ.get("USER") or os.path.basename(HOME)
    say("")
    say("Done. Now open the Web tab and press the green Reload button.")
    say("")
    say(f"  Back office : https://{user}.pythonanywhere.com/portal")
    say("                user admin, password below")
    say(f"  Phone page  : https://{user}.pythonanywhere.com/phone")
    say(f"  Demo apps   : server https://{user}.pythonanywhere.com and the API key below")
    say("")
    say(f"  Admin password : {values['FORTGUARD_ADMIN_PASSWORD']}")
    say(f"  API key        : {values['FORTGUARD_API_KEY']}")
    say("")
    say(f"Keep these private. They are stored in {SECRETS}; run 'cat ~/.fortguard-secrets' to see them again.")
    say("(If your account is on the EU site, the address is <you>.eu.pythonanywhere.com.)")


if __name__ == "__main__":
    main()
