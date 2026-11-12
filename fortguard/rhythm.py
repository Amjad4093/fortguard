"""Typing rhythm of a fixed sentence: the "Is it me?" check.

Two people who type at the same average speed still differ in the gaps between particular keys. When a
customer types the same sentence each time, the i-th gap can be compared with the customer's own earlier
i-th gaps. Only the times of the edits are used. Which characters were typed is never sent.

A sample is usable only if the sentence was typed one character at a time with no corrections, so that
gap i means the same thing every time. The limit is set from the customer's own samples: how far each of
them lies from the others. Nothing here has been measured on real customers; the response carries the
distance and the limit so that real results can be used to tune it.
"""

import json
import statistics

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS rhythm_samples (
    user_id TEXT NOT NULL, session_id TEXT NOT NULL, time_ms INTEGER NOT NULL, gaps TEXT NOT NULL,
    PRIMARY KEY (user_id, session_id));
"""

RETRY_TEXT = ("Type the sentence in one go, one key at a time, without corrections. Then its rhythm can be "
              "compared with the account holder's.")


def gaps_of(keys, field="other"):
    """The gaps between keystrokes in the sentence field, in ms, or None when the sample cannot be compared."""
    edits = sorted((k for k in keys if k["event_type"] == "DOWN" and k.get("field") == field), key=lambda k: k["ts"])
    if len(edits) < config.RHYTHM_MIN_KEYS:
        return None
    if any(k.get("deleted", 0) or k.get("inserted", 0) != 1 for k in edits):
        return None      # a correction, or several characters at once: gap i no longer means the same thing
    return [min(b["ts"] - a["ts"], config.RHYTHM_GAP_CAP_MS) for a, b in zip(edits, edits[1:])]


def distance(gaps, rows):
    """How far a sample is from a set of samples: the average gap difference, in units of the usual spread."""
    total = 0.0
    for i, x in enumerate(gaps):
        column = [r[i] for r in rows]
        mean = statistics.fmean(column)
        spread = statistics.fmean(abs(v - mean) for v in column)
        total += abs(x - mean) / max(spread, config.RHYTHM_REL_FLOOR * mean, config.RHYTHM_ABS_FLOOR_MS)
    return total / len(gaps)


def limit(rows):
    """The furthest a sample may be: the customer's own leave-one-out distances, mean plus two deviations."""
    own = [distance(rows[i], rows[:i] + rows[i + 1:]) for i in range(len(rows))]
    return statistics.fmean(own) + config.RHYTHM_LIMIT_SDS * statistics.pstdev(own)


class Rhythms:
    def __init__(self, bo):
        self.bo = bo
        with bo.lock:
            bo.db.executescript(SCHEMA)
            bo.db.commit()

    def rows(self, user_id, length):
        found = self.bo.q("SELECT gaps FROM rhythm_samples WHERE user_id=? ORDER BY time_ms DESC LIMIT ?",
                          (user_id, config.RHYTHM_WINDOW))
        rows = [json.loads(r["gaps"]) for r in found]
        return [r for r in rows if len(r) == length]   # a different sentence is a different rhythm

    def count(self, user_id):
        return self.bo.q("SELECT COUNT(*) AS n FROM rhythm_samples WHERE user_id=?", (user_id,))[0]["n"]

    def learn(self, user_id, session_id, gaps, time_ms):
        self.bo.x("INSERT OR REPLACE INTO rhythm_samples VALUES (?,?,?,?)", (user_id, session_id, time_ms, json.dumps(gaps)))
        self.bo.x("DELETE FROM rhythm_samples WHERE user_id=? AND session_id NOT IN "
                  "(SELECT session_id FROM rhythm_samples WHERE user_id=? ORDER BY time_ms DESC LIMIT ?)",
                  (user_id, user_id, config.RHYTHM_WINDOW))

    def forget(self, session_id):
        return self.bo.x("DELETE FROM rhythm_samples WHERE session_id=?", (session_id,)).rowcount

    def forget_user(self, user_id):
        return self.bo.x("DELETE FROM rhythm_samples WHERE user_id=?", (user_id,)).rowcount

    def judge(self, user_id, session_id, keys, time_ms, owner_proved=False):
        """The identity block for a sentence check, or None when the session has no sentence typing at all.

        Learns the sample when it is usable and either the profile is still learning, the sample was
        accepted, or the owner proved themselves with a fingerprint or face check.
        """
        if not any(k.get("field") == "other" for k in keys):
            return None
        required = config.RHYTHM_MIN_SAMPLES
        gaps = gaps_of(keys)
        if gaps is None:
            return {"verdict": "UNKNOWN", "sessions": min(self.count(user_id), required), "required": required,
                    "match_score": None, "text": RETRY_TEXT, "method": "TYPING_RHYTHM"}
        rows = self.rows(user_id, len(gaps))
        if len(rows) < required:
            self.learn(user_id, session_id, gaps, time_ms)
            n = len(rows) + 1
            left = required - n
            text = (f"Still learning how you type this sentence: {n} of {required}. "
                    + (f"{left} more and FortGuard can tell you from someone else." if left
                       else "The next check is compared with these."))
            return {"verdict": "LEARNING", "sessions": n, "required": required, "match_score": None,
                    "text": text, "method": "TYPING_RHYTHM"}
        d, lim = distance(gaps, rows), limit(rows)
        block = {"sessions": len(rows), "required": required, "match_score": None, "method": "TYPING_RHYTHM",
                 "rhythm_distance": round(d, 2), "rhythm_limit": round(lim, 2)}
        if d > lim and not owner_proved:
            return dict(block, verdict="NOT_OWNER_LIKELY",
                        text=f"The rhythm of this typing is unlike the account holder's (distance {d:.2f}, limit {lim:.2f}).")
        self.learn(user_id, session_id, gaps, time_ms)
        return dict(block, verdict="OWNER_LIKELY",
                    text=f"The rhythm of this typing matches the account holder's (distance {d:.2f}, limit {lim:.2f}).")
