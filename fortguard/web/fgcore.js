/* FortGuard browser test client: canonical JSON and ES256 signing.
 *
 * Must produce byte-for-byte the same canonical text as fortguard/signing.py
 * (json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)).
 * Numbers are rounded to 3 decimals before they reach here, so JS and Python print them identically
 * (no exponent forms, no "1.0"). tests/test_web_signing.py checks this against the Python verifier.
 */
(function (root) {
  "use strict";

  var CONTEXT = "fortguard.telemetry.v1\n";

  function round3(n) {
    var r = Math.round(n * 1000) / 1000;
    return r === 0 ? 0 : r; // turns -0 into 0
  }

  function canonical(value) {
    if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
    if (typeof value === "number") {
      if (!isFinite(value)) throw new Error("non-finite number");
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
    var keys = Object.keys(value).filter(function (k) { return value[k] !== undefined; }).sort();
    return "{" + keys.map(function (k) { return JSON.stringify(k) + ":" + canonical(value[k]); }).join(",") + "}";
  }

  function b64url(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // WebCrypto returns ECDSA signatures as raw r||s (64 bytes). The server expects DER.
  function rawToDer(raw) {
    function integer(bytes) {
      var i = 0;
      while (i < bytes.length - 1 && bytes[i] === 0) i++;
      bytes = Array.prototype.slice.call(bytes, i);
      if (bytes[0] & 0x80) bytes.unshift(0);
      return [0x02, bytes.length].concat(bytes);
    }
    var r = integer(raw.slice(0, 32)), s = integer(raw.slice(32, 64));
    var body = r.concat(s);
    return new Uint8Array([0x30, body.length].concat(body));
  }

  function signingBytes(payload) {
    var body = {};
    Object.keys(payload).forEach(function (k) { if (k !== "signature") body[k] = payload[k]; });
    return new TextEncoder().encode(CONTEXT + canonical(body));
  }

  async function sign(payload, privateKey, subtle) {
    var raw = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, signingBytes(payload)));
    var out = {};
    Object.keys(payload).forEach(function (k) { out[k] = payload[k]; });
    out.signature = b64url(rawToDer(raw));
    return out;
  }

  var REASONS = {
    REASON_DEVICE_ROOTED_OR_JAILBROKEN: "The app reports the device is rooted or jailbroken.",
    REASON_EMULATOR_DETECTED: "Running in an emulator, not a real phone.",
    REASON_HOOKING_FRAMEWORK_DETECTED: "A hooking framework (such as Frida) is present.",
    REASON_REMOTE_ACCESS_TOOL_ACTIVE: "Remote-access software is running.",
    REASON_SCREEN_SHARING_ACTIVE: "Screen sharing is on during a sensitive action.",
    REASON_LOCATION_SPOOFING_SUSPECTED: "Mock or spoofed location is switched on.",
    REASON_VPN_OR_PROXY: "A VPN or proxy is active.",
    REASON_ACTIVE_CALL_DURING_PAYMENT: "A phone call is active during a payment.",
    REASON_PASTE_ACTIVITY_IN_BENEFICIARY_FIELD: "The beneficiary account was pasted, not typed.",
    REASON_COGNITIVE_HESITATION_DETECTED: "Long pauses between inputs, as when someone is being coached.",
    REASON_NEW_BENEFICIARY: "Payment to a new beneficiary.",
    REASON_COACHED_SCAM_PATTERN: "A call together with a new payee or hesitation: a pattern seen in coached scams.",
    REASON_SCRIPTED_INPUT: "Typing rhythm is too regular for a person.",
    REASON_PERFECT_LINEAR_SWIPES: "Swipes are perfectly straight, as a script would draw them.",
    REASON_NO_PHYSICAL_MOTION: "Touches arrive but the phone shows no motion at all.",
    REASON_NO_SENSOR_DATA: "Touches arrive but no motion-sensor data was sent.",
    REASON_NO_TELEMETRY: "No behavioral data was received for this session.",
    REASON_DEVICE_INTEGRITY_WEAK: "Attestation shows basic integrity only.",
    RULE_FORCE_STEP_UP: "Raised to the step-up band by a hard rule.",
    REASON_BEHAVIORAL_ANOMALY_HIGH: "Behavior is far from this customer's own usual pattern.",
    REASON_DEGRADED_NO_TELEMETRY: "Degraded mode: no behavioral data, decided from the transaction alone.",
    REASON_DEGRADED_SCORING_ERROR: "Degraded mode: scoring failed, decided from the transaction alone."
  };
  var ACTIONS = {
    PROCEED: "Let it through",
    CHALLENGE_FIDO2_OR_OTP: "Ask for a second factor (FIDO2 or OTP)",
    TERMINATE_SESSION_AND_OPEN_CASE: "End the session and open a case"
  };

  var api = { REASONS: REASONS, ACTIONS: ACTIONS, canonical: canonical, round3: round3, b64url: b64url, rawToDer: rawToDer, sign: sign, CONTEXT: CONTEXT };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.FGCore = api;
})(typeof self !== "undefined" ? self : this);
