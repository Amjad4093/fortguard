"""Two things the bank controls from the back office and the apps pick up: the consent wording, and
what the SDK may collect.

Consent wording
    One text per group and language, with a version that goes up each time the text is published.
    The app shows the customer the current text and reports which version they accepted. The server
    keeps a record each time a customer's answer changes, so the bank can show what was agreed to, when,
    and in which words.

Remote configuration
    A small document saying which kinds of data the SDK may collect, signed with a key that only this
    server holds (ES256). The SDK checks the signature against a key it was built with, or the first key
    it saw, before obeying. That makes each switch a kill switch nobody between the server and the phone
    can flip. The server enforces the same switches on what arrives, so an old or tampered app cannot
    keep sending a kind of data the bank has turned off.

The signing key is kept in the back-office database. That is fine for a pilot on one machine; a bank
rollout should hold it in a key-management service or HSM.
"""

import json
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import signing
from .schema import ValidationFailure

CONFIG_CONTEXT = b"fortguard.config.v1\n"   # a config signature is never valid as anything else
COLLECT_KINDS = ("touch", "keys", "motion", "sensors", "location")
COLLECT_TEXT = {
    "touch": "Touches and swipes",
    "keys": "Typing rhythm, paste and field focus",
    "motion": "Accelerometer and gyroscope",
    "sensors": "Other sensors (magnetometer, light, proximity, pressure and the rest)",
    "location": "Approximate location, when the customer has agreed",
}
FLUSH_MS = (1000, 60_000)
DEFAULT_CONFIG = {"collect": {k: True for k in COLLECT_KINDS}, "flush_interval_ms": 5000}

CONSENT_GROUPS = ("behavioural", "location")
LANG_RE = re.compile(r"^[a-z]{2,3}(-[A-Z]{2})?$")
DEFAULT_TEXTS = {
    "behavioural": "To protect your account from fraud, this app measures how the phone is used while you bank: "
                   "the rhythm of your typing, how you touch and swipe, and how the phone moves. It never records "
                   "what you type. You can switch this off at any time in Settings.",
    "location": "To spot a payment made from somewhere impossible for you, this app can share its approximate "
                "location, rounded to about one kilometre, while you bank. You can switch this off at any time in Settings.",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS consent_texts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, grp TEXT NOT NULL, lang TEXT NOT NULL, version INTEGER NOT NULL,
    text TEXT NOT NULL, published_by TEXT NOT NULL, published_ms INTEGER NOT NULL, UNIQUE(grp, lang, version));
CREATE TABLE IF NOT EXISTS consent_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, grp TEXT NOT NULL, granted INTEGER NOT NULL,
    lang TEXT, version INTEGER, device_guid TEXT, time_ms INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS consent_records_user ON consent_records(user_id, grp, id);
"""


class Remote:
    def __init__(self, bo):
        self.bo = bo
        with bo.lock:
            bo.db.executescript(SCHEMA)
            bo.db.commit()
        if not bo.q("SELECT 1 FROM consent_texts LIMIT 1"):
            for group, text in DEFAULT_TEXTS.items():
                self.publish_text(group, "en", text, "system")
        self._key = self._load_key()
        self._config = self._load_config()
        self._last = {}     # (user_id, group) -> (granted, lang, version), so a record is written only on a change

    # --- consent wording ---------------------------------------------------------------------------------
    def publish_text(self, group, lang, text, actor):
        if group not in CONSENT_GROUPS:
            raise ValidationFailure(400, "invalid_request", f"group must be one of {list(CONSENT_GROUPS)}")
        if not isinstance(lang, str) or not LANG_RE.match(lang):
            raise ValidationFailure(400, "invalid_request", "lang must be a language code such as en, ur or en-GB")
        if not isinstance(text, str) or not 20 <= len(text.strip()) <= 2000 or any(ord(c) < 32 and c != "\n" for c in text):
            raise ValidationFailure(400, "invalid_request", "the wording must be 20 to 2000 characters")
        last = self.bo.q("SELECT MAX(version) AS v FROM consent_texts WHERE grp=? AND lang=?", (group, lang))[0]["v"] or 0
        current = self.bo.q("SELECT text FROM consent_texts WHERE grp=? AND lang=? AND version=?", (group, lang, last))
        if current and current[0]["text"] == text.strip():
            raise ValidationFailure(409, "unchanged", "that is already the published wording")
        self.bo.x("INSERT INTO consent_texts (grp, lang, version, text, published_by, published_ms) VALUES (?,?,?,?,?,?)",
                  (group, lang, last + 1, text.strip(), actor, self.bo.now_ms()))
        return {"group": group, "lang": lang, "version": last + 1}

    def current_texts(self, lang="en"):
        """The wording to show a customer: the asked-for language where it exists, English otherwise."""
        lang = lang if isinstance(lang, str) and LANG_RE.match(lang) else "en"
        out = {}
        for group in CONSENT_GROUPS:
            for candidate in (lang, lang.split("-")[0], "en"):
                rows = self.bo.q("SELECT lang, version, text FROM consent_texts WHERE grp=? AND lang=? ORDER BY version DESC LIMIT 1",
                                 (group, candidate))
                if rows:
                    out[group] = {"lang": rows[0]["lang"], "version": rows[0]["version"], "text": rows[0]["text"]}
                    break
        return out

    def all_texts(self):
        rows = self.bo.q("SELECT * FROM consent_texts ORDER BY grp, lang, version DESC")
        latest = {}
        for r in rows:
            latest.setdefault((r["grp"], r["lang"]), []).append(
                {"version": r["version"], "text": r["text"], "published_by": r["published_by"], "published_ms": r["published_ms"]})
        return [{"group": g, "lang": l, "current": versions[0], "earlier": versions[1:]} for (g, l), versions in latest.items()]

    def note_consent(self, user_id, device_guid, consent):
        """Record a customer's answers when they differ from the last ones seen for that customer."""
        if not user_id:
            return
        texts = consent.get("texts") or {}
        answers = {"behavioural": consent.get("behavioral"), "location": consent.get("location")}
        for group, granted in answers.items():
            if granted is None:
                continue
            accepted = texts.get(group) or {}
            state = (bool(granted), accepted.get("lang"), accepted.get("version"))
            key = (user_id, group)
            if key not in self._last:
                rows = self.bo.q("SELECT granted, lang, version FROM consent_records WHERE user_id=? AND grp=? ORDER BY id DESC LIMIT 1",
                                 (user_id, group))
                self._last[key] = (bool(rows[0]["granted"]), rows[0]["lang"], rows[0]["version"]) if rows else None
            if self._last[key] == state:
                continue
            self.bo.x("INSERT INTO consent_records (user_id, grp, granted, lang, version, device_guid, time_ms) VALUES (?,?,?,?,?,?,?)",
                      (user_id, group, 1 if state[0] else 0, state[1], state[2], device_guid, self.bo.now_ms()))
            self._last[key] = state

    def consent_history(self, user_id):
        return [{"group": r["grp"], "granted": bool(r["granted"]), "lang": r["lang"], "version": r["version"],
                 "device_guid": r["device_guid"], "time_ms": r["time_ms"]}
                for r in self.bo.q("SELECT * FROM consent_records WHERE user_id=? ORDER BY id DESC", (user_id,))]

    def erase(self, user_id):
        self._last = {k: v for k, v in self._last.items() if k[0] != user_id}
        return self.bo.x("DELETE FROM consent_records WHERE user_id=?", (user_id,)).rowcount

    # --- signed configuration ------------------------------------------------------------------------------
    def _load_key(self):
        rows = self.bo.q("SELECT value FROM settings WHERE key='config_signing_key'")
        if rows:
            return serialization.load_pem_private_key(rows[0]["value"].encode(), password=None)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        self.bo.x("INSERT INTO settings VALUES ('config_signing_key', ?)", (pem.decode(),))
        return key

    def _load_config(self):
        rows = self.bo.q("SELECT value FROM settings WHERE key='remote_config'")
        if rows:
            return json.loads(rows[0]["value"])
        return {"version": 1, "issued_ms": self.bo.now_ms(), **json.loads(json.dumps(DEFAULT_CONFIG))}

    @property
    def config(self):
        return json.loads(json.dumps(self._config))

    def public_key(self):
        pub = self._key.public_key()
        return {"public_key": signing.public_key_to_b64(pub), "key_sha256": signing.key_sha256(pub), "algorithm": "ES256",
                "signs": "fortguard.config.v1 + canonical JSON of the config"}

    def signed(self):
        """What the SDK fetches: the config and a signature over its canonical bytes."""
        body = CONFIG_CONTEXT + signing.canonical_bytes(self._config)
        return {"config": self.config, "signature": signing.b64e(self._key.sign(body, ec.ECDSA(signing.hashes.SHA256()))),
                "key_sha256": signing.key_sha256(self._key.public_key())}

    def update_config(self, data):
        if not isinstance(data, dict) or set(data) - {"collect", "flush_interval_ms"}:
            raise ValidationFailure(400, "unknown_field", "send collect and, optionally, flush_interval_ms")
        new = self.config
        collect = data.get("collect", {})
        if not isinstance(collect, dict) or set(collect) - set(COLLECT_KINDS) or any(not isinstance(v, bool) for v in collect.values()):
            raise ValidationFailure(400, "invalid_request", f"collect holds true or false for {list(COLLECT_KINDS)}")
        new["collect"].update(collect)
        if "flush_interval_ms" in data:
            ms = data["flush_interval_ms"]
            if isinstance(ms, bool) or not isinstance(ms, int) or not FLUSH_MS[0] <= ms <= FLUSH_MS[1]:
                raise ValidationFailure(400, "invalid_request", f"flush_interval_ms must be a whole number from {FLUSH_MS[0]} to {FLUSH_MS[1]}")
            new["flush_interval_ms"] = ms
        before = self.config
        if {k: new[k] for k in ("collect", "flush_interval_ms")} == {k: before[k] for k in ("collect", "flush_interval_ms")}:
            return before, before
        new["version"] = before["version"] + 1
        new["issued_ms"] = self.bo.now_ms()
        self.bo.x("INSERT OR REPLACE INTO settings VALUES ('remote_config', ?)", (json.dumps(new),))
        self._config = new
        return before, self.config

    def enforce(self, payload):
        """Drop from a batch every kind of data that is switched off. Returns the names of what was dropped."""
        collect = self._config["collect"]
        dropped = []
        if not collect["touch"] and payload.get("touch_events"):
            payload["touch_events"] = []
            dropped.append("touch")
        if not collect["keys"] and (payload.get("key_events") or payload.get("ui_events")):
            payload["key_events"], payload["ui_events"] = [], []
            dropped.append("keys")
        sensors = payload.get("sensor_data")
        if isinstance(sensors, dict):
            if not collect["motion"] and (sensors.get("accelerometer") or sensors.get("gyroscope")):
                sensors["accelerometer"], sensors["gyroscope"] = [], []
                dropped.append("motion")
            extra = [name for name in sensors if name not in ("accelerometer", "gyroscope")]
            if not collect["sensors"] and any(sensors[name] for name in extra):
                for name in extra:
                    sensors[name] = []
                dropped.append("sensors")
        if not collect["location"] and "location" in (payload.get("environment") or {}):
            del payload["environment"]["location"]
            dropped.append("location")
        return dropped
