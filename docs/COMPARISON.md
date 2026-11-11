# This project and the platform team's FortGuard, compared

Written 2026-11-11 from a ZIP of `faisalfort/fortguard` (main branch). I read its README, the telemetry
and decision contracts, `contracts/rules.md`, the Android SDK collectors, the ML package layout, the
pilot evaluation and the gap list. I did not build or run it, so "captures" below means "the contract and
the Android collector code say so", not "seen working".

## The short version

- The two projects aim at the same product and overlap on most signals.
- They are built very differently. The platform project is a multi-service design (.NET services, Kafka,
  Redis, Postgres, ClickHouse, ONNX models, Helm). This one is a single Python server with SQLite that
  runs on PythonAnywhere, with a working Android demo app.
- The platform SDK sends **summaries only** (averages, counts, flags). This SDK sends **raw touch points
  and sensor samples** and the server computes the features. That is a privacy and compliance difference
  a bank will ask about, and the two teams should pick one approach.
- Sixteen signals and three controls from the platform catalogue were missing here and are now added
  (listed below). A longer list is not added yet, with the reason for each.

## Signals: who captures what

"Now" means added to this project on 2026-11-11 as a result of this comparison.

| Area | Signal | Platform project | This project |
| --- | --- | --- | --- |
| Touch | Pressure, contact size, swipe speed, swipe curvature, time between taps | Yes | Yes |
| Touch | How long a tap is held, long presses, double taps | Yes | **Now** (server-side, from raw touches) |
| Touch | Where on the screen touches land | 9-zone histogram | 8 × 14 heat grid |
| Touch | Distance of a tap from the centre of the button | Yes | No |
| Touch | Left-hand probability, correction taps | In the contract, not computed | No |
| Typing | Time between keystrokes, typing speed, deletions, paste | Yes | Yes |
| Typing | Key hold time | Hardware keyboards only | No (soft keyboards do not report it) |
| Typing | Keyboard app changed | Yes | **Now** |
| Typing | Autofill used, time spent in each field | Yes | No |
| Typing | Long pauses while entering a payment | No | Yes |
| Motion | Movement variance, hand tremor | Yes | Yes |
| Motion | Tilt (front-back, side-side), lying flat on a surface | Yes | **Now** |
| Motion | Walking cadence, activity (still, walking, vehicle) | Yes | No |
| Motion | Magnetometer, gravity, rotation, light, proximity, air pressure | No | Yes (stored, not scored) |
| Device | Rooted, emulator, hooking, screen recording, model, OS | Yes | Yes |
| Device | Debugger attached | Yes | **Now** (scored: forces a step-up) |
| Device | Developer options, security patch level | Yes | **Now** (recorded only) |
| Device | Remote-access app installed (separate from "in control") | Yes | **Now** (recorded only) |
| Device | Unrecognised accessibility service | Yes | **Now** (recorded only) |
| Device | Battery, charging, free storage, screen size | No | Yes |
| Device | App tampered, reinstall count, clock skew | In the contract; fixed values or not sent on Android | No |
| Network | Wi-Fi or mobile data, VPN | Yes | Yes |
| Network | Mobile network code, roaming | Yes | **Now** (recorded only) |
| Network | SIM changed | Yes | **Now** (scored, see below) |
| Network | Hotspot | Yes | No |
| Network | Client IP address and IP changes in a session | Hashed IP for sign-up counting | Yes |
| Call | Phone call in progress | Yes | Yes (plus internet calls by audio mode) |
| Call | Call direction and how long it has lasted | Duration yes, direction "unknown" | **Now** (both) |
| Location | Coordinates with consent, mock location | Yes | Yes (rounded to about 1 km) |
| Location | Impossible travel | Against the customer's known places | Between fixes in one session |
| Location | Country, speed, known places | Yes | No |
| Usage | Screen reader on, text size, clock offset | Yes | **Now** (recorded only) |
| Usage | Times sent to the background, screens opened | Yes | **Now** (recorded only) |
| Usage | Time on each screen, arrived by deep link | Yes | No |
| Identity | Owner confirmed by fingerprint or face | Passkeys through FortAuth | Yes (device biometric proof) |

## What was added here, and how it behaves

1. **Sixteen facts in the telemetry schema**, sent by the Android SDK and shown on the device card in the
   back office: debugger attached, developer options, screen reader, unrecognised accessibility service,
   remote-access app installed, roaming, SIM changed, keyboard changed, security patch, mobile network
   code, call direction, call seconds, text size, background switches, screens opened, clock offset.
   An older app that does not send one shows nothing for it, never a false "No".
2. **Debugger rule.** A debugger attached to the banking app adds 400 points and forces at least a step-up.
3. **SIM-change rules**, following the platform project's reasoning. A SIM change alone adds 150 points
   and stays in ALLOW. A SIM change with a payment to a new payee adds a further 300 and lands in
   STEP-UP. The SDK reports the change for 72 hours after it first sees it.
4. **Installed is not active**, the platform project's ADR 0003. A remote-access app that is only
   installed is a recorded fact and never a reason. Only a tool in control of the screen is scored.
5. **Deny list**: customers, devices, payee accounts and IP addresses the bank blocks outright. A match
   scores 1000 and blocks, also when scoring falls back to degraded mode. Payee accounts are stored as a
   one-way fingerprint and shown by their last four characters. Entries can expire, and every add and
   remove is in the audit log. There is a Deny list page in the back office.
6. **Tap and tilt measurements** on the case page: tap hold time, long presses, double taps, tilt, and
   whether the phone was lying still on a flat surface.

All weights and thresholds for these are judgement calls, not measured on real customers.

## Not added yet, and why

| From the platform project | Why it is not here yet |
| --- | --- |
| Velocity features: payments and new payees in 24 hours, distinct payees in 7 days, customers per device | The most useful missing piece. Needs a transaction history table and counters. A day or two of work here. |
| Rule expression language, shadow rules, backtest, maker-checker approval | This project has fixed rules with editable points. A rule language is a larger change and should be designed once, by both teams. |
| Mule-account and allow lists | The deny list here is one list of four kinds. Mule and allow lists are a small extension. |
| Journeys (payment, add payee, sign-up, device enrolment) with different actions per journey | This project scores LOGIN and payment events only. |
| Step-up verification matrix and passkeys (FortAuth) | Depends on the bank's authentication stack. |
| Consent wording per feature group and language, with versions | This project has one behavioural consent switch and one location switch. |
| Signed remote configuration with per-signal kill switches | Not needed for the demo. Needed before a bank rollout. |
| Tap offset from button centre, walking cadence, hotspot, autofill, time in field | Each needs new on-device code and a phone to test on. |
| Kafka, Redis, ClickHouse, multi-tenant services, Helm | A different architecture. It cannot run on PythonAnywhere and is not a feature to copy. |

## What this project has that I did not find there

- A demo app and a hosted server a client can try today.
- A machine-learning model per customer that is active in decisions, and a per-customer baseline.
  The platform project trains an Isolation Forest and a transaction model on synthetic sessions and
  exports them to ONNX.
- Bot rules from raw events: scripted typing, perfectly straight swipes, touches with no phone movement.
- The "long pauses during a payment" signal and the coached-scam pattern built on it.

## One decision for the two of you

Two repositories now carry the same product name and different wire formats. Before more is built on
either, agree which is the product and which is the demo, or agree one telemetry format both use. The
biggest single choice is raw events (this project) or on-device summaries (the platform project).
