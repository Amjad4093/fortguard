# FortGuard sprint 1 slice

A device enrolls with its own key, signs its telemetry, and the API returns a score, a level, an action
and reason codes. Rules only, no machine learning, synthetic data only. This covers backlog items E1-09
(payload signing, device-key and attestation parts), E3-01, E4-01 and E6-06 in thin form, so the
contract can be argued about with something running.

## Run it

```bash
pip install -r requirements.txt
python -m pytest -q                 # 322 tests
python demo.py                      # every synthetic scenario through the full flow, as a table
python -m fortguard.app --dev       # serve on 127.0.0.1:8080 with the portal and phone test page
python demo.py --url http://127.0.0.1:8080
python export_samples.py            # rewrite samples/ (reproducible)
python loadtest.py                  # single-instance load test over real HTTP
python e2e_browser.py               # drives /phone and /portal in headless Chromium (needs playwright)
```

Python 3.12 or later. Flask, numpy, requests, cryptography and pytest are the only dependencies.

## The flow

```
device                                        server
  |  POST /v1/devices/challenge  ------------>  one-time challenge (5 min, single use)
  |  generate key in hardware; ask Google/Apple to attest it, bound to challenge + key
  |  POST /v1/devices/enroll  --------------->  verify attestation, store public key + integrity level
  |  POST /v1/telemetry/stream (ES256-signed) ->  verify with the stored public key, store events
bank backend
  |  POST /v1/risk/evaluate (X-API-Key)  ---->  score, level, action, reason codes
  |  POST /v1/devices/<id>/revoke (X-API-Key) ->  stop trusting a device
```

**New here? Read START_HERE.md first.** Progress against the 80-item backlog is in `docs/FortGuard_Backlog.xlsx` (Progress sheet). It explains the builds, the cloud test server and what to test.

## Back office

`/portal` is the back office: sign in, dashboard, case queue (step-up and block decisions open cases
automatically), case detail with reasons, notes, status, assignee and history, devices with revoke, rule
weights and decision bands editable live, a deny list (customers, devices, payee accounts and IP addresses
the bank blocks outright), users with roles (viewer, analyst, admin) and an audit log of every change. Data is kept in SQLite (`FORTGUARD_DATA_DIR`). The first user is `admin`; its password comes from
`FORTGUARD_ADMIN_PASSWORD`, or is `fortguard-admin-dev` in dev mode, or is printed at start.

## iOS SDK and demo app

`ios/FortGuardSDK` is a Swift package (Secure Enclave signing, touch, motion, call, screen-capture and jailbreak
checks); `ios/DemoApp` is the SwiftUI demo, generated into an Xcode project by XcodeGen. Both are built and
tested on GitHub's Mac machines by `.github/workflows/ios.yml`.

## Android SDK and demo APK

The `android/` folder holds the Android SDK (`fortguard-sdk`) and a demo app (`demo-app`) that builds into an
APK. See **android/BUILD_AND_TEST.md** for building in Android Studio, installing on a phone and what to test.
The SDK's core was compiled and tested against this server; the Android-specific parts still need their first
real build.

**Sessions.** Call `FortGuard.newSession()` when the customer signs in and after each decision, as the demo
does. The server learns one row per session and keeps at most 50,000 touch, typing and motion events for one,
so an app that never starts a new session stops being measured after a few minutes and its customer's
profile never becomes ready. The response's `identity` block answers "is this the account holder?":
`LEARNING` for the first 10 allowed sessions, then `OWNER_LIKELY` or `NOT_OWNER_LIKELY`.

## Try it: analyst portal and phone test page

```bash
python -m fortguard.app --dev                 # this computer only
python -m fortguard.app --dev --https --host 0.0.0.0   # so a phone on the same Wi-Fi can reach it
```

| Page | What it is |
|---|---|
| `/portal` | Analyst portal. Decisions with filters, a case detail that explains every point in plain language, the device list, and a revoke button. The API key is `dev-only-api-key` unless `FORTGUARD_API_KEY` is set. **Run sample scenarios** fills it with synthetic cases. |
| `/phone` | Browser test client (dev mode only). Records real touch, typing timing and motion in the phone's browser, signs each batch with a key that never leaves the browser, enrolls through the real endpoints, and shows the decision. Tick boxes to simulate a call, screen sharing, a remote tool, and so on. "What leaves this device" shows the exact last batch. |

On a phone: open `https://<computer address>:8080/phone`, accept the certificate warning (it is a throwaway
certificate), then tap **Enable motion sensors**. Phones only allow signing and sensors on HTTPS pages,
which is why `--https` exists. The phone and computer clocks must agree to within 5 minutes.

This is a web stand-in for the mobile SDK. It is **not** an APK and it does not use the real Android or iOS
sensors, attestation or key store. The first real Android and iOS builds need the SDK projects (backlog E1-01).

## Load test (one instance, measured)

`python loadtest.py`: one uvicorn process, 8 concurrent clients on the same 2-core machine, 200 sessions
(enroll, two signed batches of about 1,600 sensor samples each, evaluate). Both versions measured on the
same machine at the same moment:

| | Before the incremental engine | With it |
|---|---|---|
| Scoring inside the server, p50 / p99 | 14.2 ms / 68.6 ms | **0.8 ms** / 59.9 ms |
| Evaluate end to end, p50 / p99 | 82 ms / 186 ms | **47 ms** / 153 ms |
| Telemetry end to end, p50 | 85 ms | 99 ms (now does the feature work) |
| Throughput | 93 requests/s | 96 requests/s, while also writing cases, baselines and audit records |

Features are now updated as telemetry arrives (`fortguard/incremental.py`), so scoring no longer re-reads
the whole session. The remaining tail is CPU contention: one Python process, with the load generator
sharing the same two cores. The PRD's 50 ms p99 is **not** demonstrated here; that needs the production
shape (several processes and instances behind a shared session store) and a load test from separate
machines. Treat these as relative numbers, not capacity.

## Endpoints

| Method and path | Purpose | Auth |
|---|---|---|
| `POST /v1/devices/challenge` | One-time enrollment challenge. `201`. | none |
| `POST /v1/devices/enroll` | Public key plus attestation in; device registered. `201`. | attestation |
| `POST /v1/devices/<id>/revoke` | Stop trusting a device. `200`. | `X-API-Key` |
| `POST /v1/telemetry/stream` | One signed SDK batch. `202` with counts of what was kept. | device-key signature |
| `POST /v1/risk/evaluate` | Decision for a session and transaction. `200`. | `X-API-Key` |
| `POST /v1/feedback` | Bank-confirmed outcome for a session: `FRAUD` or `GENUINE`. Confirms or closes cases, opens one for missed fraud, cleans the user's baseline. `201`. | `X-API-Key` |
| `GET /metrics` | Prometheus metrics: requests, latency histograms, decisions by level, rate-limited requests, devices and sessions. | `X-API-Key` or bearer |
| `GET /v1/admin/decisions` | Recent decisions with counts, for the portal. Keeps only the last 4 digits of the beneficiary account. | `X-API-Key` |
| `GET /v1/admin/devices` | Enrolled devices. | `X-API-Key` |
| `GET /portal`, `GET /healthz` | Portal page; liveness and model version. | none (portal data needs the key) |
| `GET /phone`, `POST /v1/dev/attest`, `GET /v1/dev/scenarios`, `POST /v1/dev/simulate` | Test harness. **Dev mode only**, `404` otherwise. | dev mode (+ `X-API-Key` for simulate) |

Errors are always `{"error": {"code": "...", "message": "..."}}`.

| Status | Code | Meaning |
|---|---|---|
| 400 | `invalid_json`, `invalid_request`, `unknown_field`, `stale_timestamp`, `invalid_challenge`, `invalid_public_key` | bad body; timestamp more than 5 minutes from server time; challenge unknown, expired or used; key is not P-256 |
| 401 | `bad_signature`, `unknown_device`, `device_revoked`, `unauthorized` | signature wrong or missing; device not enrolled or revoked; API key wrong |
| 403 | `attestation_failed`, `app_not_allowed`, `app_mismatch`, `device_revoked` | attestation does not verify or does not match the request; app not on the allow list; revoked device tried to enroll |
| 404 | `unknown_session`, `unknown_device` | evaluate for a session with no telemetry; revoke of an unknown device |
| 409 | `replay_detected`, `device_mismatch`, `session_user_mismatch` | nonce reused; session owned by another device or user |
| 413 | `body_too_large`, `batch_too_large` | over 1 MB, or over the per-batch event limits |
| 422 | `forbidden_field` | a key or UI event carried anything beyond type, timestamp and a field name from the fixed list |
| 501 | `attestation_not_configured` | a real Play Integrity or App Attest verifier is selected but not implemented |
| 503 | `busy` | too many open challenges |

`request_id` on evaluate makes the call idempotent: the same id returns the same answer.

`allow_degraded: true` on evaluate turns on degraded mode (PRD fail policy): with no telemetry for the
session, or if scoring fails, FortGuard answers from the transaction alone, marked `degraded: true`.
A new payee or an amount of 100,000 PKR or more steps up; everything else is allowed. It never blocks.

Each response carries `baseline`: the user's behavioral baseline status (`NONE`, `LEARNING` below 10
allowed sessions, `MATURE`), and once mature the biometric match score (0 to 1) that also appears as
`threat_details.user_biometric_match_score`. A mature match below 0.35 adds `REASON_BEHAVIORAL_ANOMALY_HIGH`.

Each response also carries `ml`: the per-customer machine-learning anomaly model (`fortguard/mlmodel.py`).
It is `LEARNING` below 10 allowed sessions and `ACTIVE` after that, when `scoring_mode` becomes
`RULES_AND_ML`. A session unlike the customer's own past sessions adds `REASON_ML_BEHAVIOR_ANOMALY`.
On a payment, new payee or profile change, either model's doubt also adds `REASON_NOT_ACCOUNT_HOLDER`,
which forces at least a step-up.
What the model is, the evidence for it and its limits are in [docs/ML.md](docs/ML.md).

Every response has an `X-Request-ID` and security headers. Rate limits per minute: sign-in 20 and device
challenges 30 per client IP, telemetry 240 per device, evaluate 6000 per API key (`config.RATE_LIMITS`).

Samples are in `samples/`: an enrollment request, a signed telemetry payload, an evaluate request and
the response, for a genuine session and a coached-scam session. They are reproducible and checked in CI.

### Contextual risk model

A third model, shared by all customers, learns from confirmed fraud and genuine outcomes: gradient-boosted
trees with a champion and a challenger, a second-admin approval and a model card. It exists only after
an admin trains it on at least 20 confirmed frauds. See [docs/MODELS.md](docs/MODELS.md).

## Device trust

- **Signing.** ES256 (ECDSA, P-256, SHA-256), DER signatures, over a domain-separated canonical JSON of
  the batch. The server keeps only the public key. Tests show that altering any value, a wrong key, a
  missing or garbage signature, a replay and a stale timestamp are all refused.
- **Attestation is bound.** The token commits to the one-time challenge, the SHA-256 of the public key,
  the device ID, the app ID and the platform, and must be fresh. A valid token cannot be reused for
  another key, challenge, device or app. This is the same idea as Play Integrity's `requestHash` and
  App Attest's `clientDataHash`. Tests cover each of these.
- **The level comes from the attestor, not the app.** `STRONG`, `DEVICE` or `BASIC` is stored on the
  device record. A `BASIC`-only device adds `REASON_DEVICE_INTEGRITY_WEAK`. The SDK cannot send or alter
  its own level (unknown fields are refused). The `is_rooted` and `is_emulator` flags in telemetry are
  still self-reported, so a compromised app can lie about them. Attestation is the independent signal.
- **Revocation and re-enrollment.** Revoked devices cannot send telemetry or enroll again. A device that
  re-enrolls with a new key (reinstall) gets a higher `key_version`, and the old key stops working.
- **Challenges** are single use, expire after 5 minutes, and are burned even when enrollment fails.

## How the score works

`fortguard/config.py` holds every weight and threshold. Each rule that fires adds points and a reason
code; the score is capped at 1000. Bands are the PRD starting values: ALLOW 0 to 599, STEP_UP 600 to
899, BLOCK 900 to 1000. A rooted or jailbroken device, an emulator, a hooking framework or remote-access
software lifts the score to at least 600, as in the BRD example, and so does a debugger attached to the app.
A match on the bank's deny list scores 1000 and blocks. A SIM change alone adds a little; with a payment to a
new payee it is the SIM-swap pattern and steps up. The response lists `score_breakdown` so every point can be
traced to a rule.

Hesitation is measured inside one payment entry only: from its first payment input to pressing send, counting
each pause beyond 3 seconds for at most 5 seconds. Signing in, browsing and earlier payments never count.
`docs/COMPARISON.md` compares the signals here with the platform team's FortGuard and lists what was added.

Behavior rules use five features from BRD FR-ING-002 (swipe curvature, keystroke hold and flight time,
device angle stability, paste frequency, hesitation index). Typing rhythm is measured within one field
only, because the pause between fields is looking at the screen, not rhythm.

## Privacy rules enforced in code

- Key and UI events may carry only an event type, a timestamp and a field name from a fixed list. Anything
  else is refused with `forbidden_field`, so typed characters cannot be sent even by mistake.
- If `consent.behavioral` is false, the server drops all behavioral data whatever the SDK sent, and
  scores on environment signals alone.
- No account number or typed value is stored from telemetry. Tests check this.

## What this is not

Read this before quoting any result.

- **Attestation is simulated.** `fortguard/attestation.py` contains a simulated authority that plays
  Google or Apple. Anyone with this repository can mint its tokens, so it is **not a security control**.
  `PlayIntegrityVerifier` and `AppAttestVerifier` are placeholders that list what a real check must do
  and answer `501` until they are built. Building them needs a Google Cloud project, Apple team and
  bundle IDs, and the real pilot app. This is the main thing left before the trust chain is real.
- **Keys are simulated.** The simulated device derives its key from a seed and signs deterministically so
  that samples reproduce. Real devices create the key in the Secure Enclave or Android KeyStore, where it
  cannot be exported, and sign with randomized ECDSA. The server code is the same for both.
- **Android SDK is a first version and iOS is not started.** The Android code still needs its first build in
  Android Studio, and attestation on the device is simulated until Play Integrity is wired in.
- **Dev mode is unsafe on purpose.** `--dev` mints attestation tokens for anyone who asks. Never run it where
  real users or real money are involved.
- **The decision log is not an audit log.** It keeps the last 500 decisions in memory and is for the portal only.
- **Canonical JSON, not Protobuf.** The production wire format (backlog E1-09) is not built.
- **No rate limiting.** The challenge endpoint is unauthenticated by design and needs rate limits and
  abuse controls at the gateway before it faces the internet.
- **Synthetic data.** The generator invents sessions from simple models. Passing the scenario tests proves
  the rules work as written. It says nothing about fraud capture or false positives on real customers.
  Do not quote these results as expected performance.
- **Weights and thresholds are first guesses.** None is calibrated. They are set to be tuned in shadow
  mode on real traffic (PRD section 6).
- **Dev credentials.** `dev-only-api-key` in `fortguard/app.py` is for local use. Set `FORTGUARD_API_KEY`
  anywhere else. The allowed app list in `config.py` (`com.example.mobilebank`) is a placeholder.
- **One process, in memory.** Sessions, devices and challenges vanish on restart and cannot be shared
  across instances. The sharded store, streams and cells in PRD section 11 are not built. Flask's dev
  server is not a production server.
- **No biometric match.** `user_biometric_match_score` is `null` until baselines and models exist
  (backlog E3-02 onward).
- **No gateway fallback or degraded mode.** `degraded` is always `false`. The fail policy in PRD section 6
  lives in the bank's gateway and is not simulated here.
- **No audit log or case management.** Enrollment and revocation events are not logged yet.
- **Latency** in the response is scoring time inside the process, not the 50 ms end-to-end target.

## Layout

```
fortguard/config.py       weights, bands, thresholds, limits, allowed apps
fortguard/schema.py       strict validation and the privacy rule
fortguard/signing.py      ES256 signing and verification, key helpers
fortguard/attestation.py  verifier interface, simulated authority, real-verifier placeholders
fortguard/devices.py      device registry, enrollment challenges, revocation
fortguard/store.py        in-memory sessions, replay protection, consent handling
fortguard/features.py     behavioral features
fortguard/scoring.py      rules, score, level, reason codes
fortguard/app.py          Flask API
fortguard/admin.py        portal data, decision log, dev-mode harness endpoints
fortguard/web/            portal.html, phone.html, fgcore.js (shared signing code)
fortguard/generator.py    labeled synthetic sessions
fortguard/simdevice.py    simulated phone: own key, attestation request, signing
fortguard/client.py       stand-in SDK uplink (HTTP or in-process)
tests/                    contract, security, device, admin, scenario, feature and browser-signing tests
loadtest.py               single-instance load test
e2e_browser.py            real-browser end-to-end check
android/                  Android SDK library and demo app (see android/BUILD_AND_TEST.md)
```

## Suggested next steps

1. Build the real Play Integrity and App Attest verifiers against the pilot app (needs credentials).
2. Compute features as telemetry arrives (see the load test), then move sessions, devices and challenges to a
   shared store behind several instances, add rate limits, and load-test again against the PRD targets.
3. Capture real, consented pilot sessions to replace synthetic data for tuning.
4. Add the baseline and the first model behind the same response contract.
