# FortGuard Android SDK and demo app: build and test

This folder holds two Android modules:

| Module | What it is |
|---|---|
| `fortguard-sdk` | The SDK library a bank app includes. Captures touch, typing rhythm, motion sensors and device checks; signs every batch with a hardware-backed key; enrolls and uploads. Never reads typed text. |
| `demo-app` | A one-screen test app (package `com.example.mobilebank`) that uses the SDK like a bank app would, with extra test controls. Building it gives you the APK. |

## What was verified, and what was not

- **Verified:** the platform-neutral core (`fortguard-sdk/src/main/java/com/fortguard/sdk/core/`) was compiled with
  Kotlin 2.0.21 and run against the real FortGuard server. Canonical JSON matches the server byte for byte, the
  server verifies the Kotlin signatures, and tampered or replayed batches are refused. 14 unit tests and 2
  live-server tests pass.
- **Not yet verified:** the Android-specific files (key store, touch, sensors, device checks, the demo screen)
  have been reviewed but never built, because the Android SDK was not available where they were written. Expect
  the first build to need small fixes. If it fails, send the error text back.

## 1. Build the APK

Needs Android Studio (Ladybug 2024.2 or newer) on Windows, macOS or Linux. It brings its own Java and
downloads everything else on the first sync, so the computer needs internet access.

1. Unzip the project. In Android Studio choose **File > Open** and pick this `android` folder (the one with
   `settings.gradle.kts`).
2. Wait for **Gradle sync** to finish (a few minutes the first time). If Android Studio offers to upgrade the
   Android Gradle Plugin, accepting is fine.
3. **Build > Build App Bundle(s) / APK(s) > Build APK(s)**.
4. The APK is at `demo-app/build/outputs/apk/debug/demo-app-debug.apk`.

From a terminal instead: `./gradlew :demo-app:assembleDebug` (Windows: `gradlew.bat :demo-app:assembleDebug`).

Unit tests: `./gradlew :fortguard-sdk:test`.

## 2. Install it on a phone

Android 8.0 or newer. Either:

- **USB:** turn on Developer options and USB debugging on the phone, plug it in, press **Run** in Android
  Studio, or run `adb install -r demo-app-debug.apk`.
- **File:** send the APK to the phone (email, Drive, WhatsApp), open it, and allow "install unknown apps"
  when asked.

It is a debug build signed with the developer's debug key, for testing only.

## 3. Start the server so the phone can reach it

On a computer on the **same Wi-Fi** as the phone, in the server folder (`fortguard-sprint1`):

```bash
pip install -r requirements.txt
python -m fortguard.app --dev --host 0.0.0.0
```

Plain HTTP on port 8080 is fine for the APK (the browser test page needs `--https`; the app does not).

Find the computer's address: Windows `ipconfig` (IPv4 Address), macOS `ipconfig getifaddr en0`, Linux
`hostname -I`. If the phone cannot connect, allow port 8080 through the computer's firewall.

## 4. Test

1. Open **FortGuard Demo**. Under **Server**, enter `http://<computer address>:8080` and tap **Connect**.
   **Status** should show "enrolled, attestation STRONG (simulated)" within a few seconds.
2. Open the analyst portal on the computer: `http://localhost:8080/portal` (API key `dev-only-api-key`).
3. Try these and watch the decision on the phone and in the portal:

| Try | Expect |
|---|---|
| Type an account and amount normally, swipe a little, **Check risk** | ALLOW, with "new beneficiary" if that box is ticked |
| Paste the account number instead of typing it | "account was pasted" reason |
| **Make a real phone or WhatsApp call**, then do a transfer during the call | "call active during the payment", detected by the SDK itself, plus the coached-scam pattern with a new payee |
| Android 15: start screen recording, then transfer | "screen is being shared or recorded", detected by the SDK |
| Install AnyDesk or TeamViewer QuickSupport and enable its accessibility service | "remote-access tool is active", detected by the SDK |
| Run the APK in the Android Studio emulator | "emulator" reason, detected by the SDK |
| Set attestation level to **BASIC**, tap **Re-enroll** | "basic integrity only" adds 200 points |
| Tick boxes under **Force conditions** | the matching reasons, to test the server rules without the real situation |
| Untick consent | the server scores on device checks only |
| **Last batch** | the exact JSON sent: key events hold only type, time and field, never characters |
| **Revoke** the device in the portal's Devices tab | the app's next upload is refused (tap **Reset device** to start over) |

## Phone checklist for the latest build

Each line is something the code is meant to do but nobody has yet seen on a real phone. Tick it or note what
happened instead; a screenshot of the result card or the portal page is the most useful report.

1. **Same device after reinstall.** Note the Device and Customer ids on the Signals screen, uninstall,
   install the same APK again. Both ids should match, and the portal's Devices page should say "Enrolled 2 times".
2. **No false "long pauses".** Sign in, browse for half a minute, then type a payment at a normal pace and
   check it. "Long pauses" should not be among the reasons.
3. **Fingerprint on a step-up.** Get a STEP-UP (tick "New beneficiary" and stay on a call), tap "Confirm with
   fingerprint or face". On success the whole card turns green and says "Identity confirmed".
4. **Every sensor arrives.** After a check, open the decision in the portal. "Signals captured" should show
   samples for each sensor the phone has, and "Readings from the other sensors" should show light and the rest.
5. **A long session keeps its sensors.** Leave the app open on one screen for 10 minutes, then check a payment.
   The sensors should still show samples (the SDK starts a new session before the old one fills up).
6. **Who is using the app.** Do 10 allowed payment checks as yourself. The card should count "1 of 10" up to
   "10 of 10", then say "looks like the account holder". Hand the phone to someone else for the 11th: the
   answer should change, though a few sessions are not proof either way.
7. **Calls.** Allow call detection in Settings, make a normal call, check a payment during it. "Call in
   progress" should be a reason and the portal should show the direction and duration.

## Troubleshooting

| Message | Fix |
|---|---|
| `failed to connect` / timeout | Same Wi-Fi? Server started with `--host 0.0.0.0`? Firewall open for 8080? |
| `dev attestation failed ... 404` | The server is not in dev mode: add `--dev`. |
| `app_not_allowed` | The app's package must be `com.example.mobilebank`, or add yours to `ALLOWED_APP_IDS` in `fortguard/config.py`. |
| `stale_timestamp` / clock message | Phone and computer clocks differ by more than 5 minutes: turn on automatic time on both. |
| `device_revoked` | You revoked it in the portal. Tap **Reset device**. |
| Motion sensors "no accelerometer" | Some emulators have none; use a real phone. |

## Using the SDK in a bank app

```kotlin
// once, e.g. Application.onCreate
FortGuard.init(context, FortGuard.Config(baseUrl = "https://risk.bank.example", appId = BuildConfig.APPLICATION_ID,
                                         devAttestation = false, attestationProvider = playIntegrityProvider))

// each protected screen
override fun onResume() { super.onResume(); FortGuard.attach(this) }
override fun onPause()  { FortGuard.detach(this); super.onPause() }
FortGuard.watch(beneficiaryField, Field.BENEFICIARY_ACCOUNT)
FortGuard.watch(amountField, Field.AMOUNT)

// on "Confirm": send what is buffered, then the bank's server asks FortGuard for the decision
FortGuard.submit { bankApi.confirmTransfer(fortguardSession = FortGuard.sessionId) }
```

The app never calls `/v1/risk/evaluate` itself and never holds the API key. The demo does only because it
also plays the bank's server.

## Known gaps before production

- **Attestation is simulated.** Play Integrity on the device (`core/Attestation.kt` describes the steps) and
  the matching server verifier are not built. They need a Google Cloud project and the app in Play Console.
- **Root and hook checks are basic** and can be hidden by tools like Magisk with Shamiko. Play Integrity is
  the real answer; these checks only raise suspicion.
- **Remote-access list is short** (AnyDesk, TeamViewer, AirDroid, RustDesk). It needs maintaining.
- **Mock location is not collected** (would need location permission).
- **Paste is judged by size** (6 or more characters in one edit), because Android does not say whether text
  came from the clipboard. Use no-suggestion or number inputs for account and amount fields.
- **Batches that fail to upload are dropped**, not retried.
- **No certificate pinning.** The demo even allows plain HTTP for office testing. Production must use HTTPS
  with pinning.
- **iOS SDK not started.**
