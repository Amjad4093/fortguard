# FortGuard: start here

This repository holds the whole FortGuard test system:

| Part | Folder | What you get |
|---|---|---|
| Risk engine (server) | `fortguard/` | Scores sessions and returns ALLOW / STEP_UP / BLOCK with reasons |
| Back office | `fortguard/web/portal.html` (served at `/portal`) | Sign in, dashboard, case queue, case notes and status, devices, rule settings, users, audit log |
| Android SDK + demo app | `android/` | The APK you install on an Android phone |
| iOS SDK + demo app | `ios/` | The iPhone app, built and run on a simulated iPhone in the cloud |
| Browser test page | served at `/phone` | Try FortGuard from any phone's browser, no install |

Everything is for **testing only**: device attestation is simulated, data is synthetic, and the rules are
first guesses to be tuned. See "What is not production-ready" at the end.

## 1. Builds happen on GitHub

Every time code is pushed, GitHub's own machines (the **Actions** tab of the repository) run three jobs:

| Job | What it does | Where the result is |
|---|---|---|
| **server** | Runs the 200+ server tests | Green tick in Actions |
| **android** | Runs the SDK tests against a live server, builds the APK | **Releases → "FortGuard Demo APK (test build)" → FortGuardDemo.apk** |
| **ios** | Runs the SDK tests against a live server, builds the app, runs it on a simulated iPhone, takes a screenshot | Actions → latest **ios** run → **Artifacts → ios-results** (contains `ios-simulator.png`) |

You do not need Android Studio or Xcode.

## 2. Put the test server online (Render, free)

1. Sign in at https://render.com with **GitHub**.
2. **New → Blueprint**, pick the `fortguard` repository, then **Apply**. Render reads `render.yaml` and builds
   the server (about 5 minutes the first time).
3. Open the new **fortguard-test** service. Its address looks like `https://fortguard-test-xxxx.onrender.com`.
4. Under **Environment** you will find two generated values:
   - `FORTGUARD_ADMIN_PASSWORD`: the back-office password for user **admin**
   - `FORTGUARD_API_KEY`: the key the demo apps use in their "API key" field

The free plan sleeps after 15 minutes without use; the first request after that takes about a minute.
It also forgets enrolled devices and cases when it restarts. The demo apps re-enroll on their own.

## 3. Test

**Back office:** open `https://<your-render-address>/portal`, sign in as `admin`, then press
**Run sample scenarios** on the Dashboard to fill it with example cases. Add analysts under **Users**.

**Android phone:**
1. On the phone, open the repository's **Releases** page (signed in to GitHub) and download **FortGuardDemo.apk**.
2. Open it and allow "install unknown apps" when asked.
3. In the app, enter the Render address in **Server** (with `https://`), paste the API key, tap **Connect**.
   The status should show "enrolled".
4. Make a transfer. Then try one **during a real phone or WhatsApp call**: the SDK detects the call itself.
5. Watch each decision appear as a case in the back office.

**iPhone:** without an Apple Developer membership Apple does not allow installing test apps on an iPhone.
The cloud build proves the iOS app compiles and runs on a simulated iPhone against a real server; the
screenshot is in the **ios-results** artifact. To test on real iPhones later you need an Apple Developer
membership (US$99/year), after which the same app can go out through TestFlight.

**Any phone, no install:** open `https://<your-render-address>/phone` in the phone's browser.

## 4. Things to try

| Try | Expected |
|---|---|
| Normal transfer, typed by hand | ALLOW |
| Paste the account number | "account was pasted" |
| Transfer during a phone call, to a new payee | STEP_UP with the coached-scam pattern |
| Screen recording on (Android 15+, or iPhone) | "screen is being shared or recorded" |
| AnyDesk / TeamViewer QuickSupport with its accessibility service on (Android) | "remote-access tool", BLOCK |
| App in an emulator or simulator | "emulator" |
| In the back office: open a case, **Assign to me**, add a note, set **Confirmed fraud** | history and audit log record each step |
| **Rules**: raise "Payment to a new beneficiary" to 650, then a plain new-payee transfer | now STEP_UP |
| **Devices → Revoke** a phone | that phone's next upload is refused |

## 5. Running things on a computer instead (optional)

```bash
pip install -r requirements.txt
python -m fortguard.app --dev --host 0.0.0.0     # portal at http://<computer>:8080/portal, login admin / fortguard-admin-dev
python -m pytest -q                              # all server tests
```

## What is not production-ready

- **Attestation is simulated.** Real Google Play Integrity and Apple App Attest need the bank's Google Cloud
  project, the app in Play Console, and an Apple Developer account.
- **Machine-learning models are not trained.** Scoring is rules only until real, consented pilot data exists.
- **One server, memory and SQLite.** The scale-out design in the PRD (shared store, many servers, regions) is not built.
- **No single sign-on** for the back office, no case exports, no alerting.
- **iOS on real iPhones** needs Apple Developer membership.
- **Legal:** consent wording, lawful basis for behavioral data and Pakistan data residency need the bank's sign-off.
