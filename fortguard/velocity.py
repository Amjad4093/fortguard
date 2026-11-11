"""Velocity: how much has this customer, device or payee account been doing lately?

One row is kept per evaluated request: who, on which device, which journey, how much, and a one-way
fingerprint of the payee account. The counters below are read from those rows at decision time and
include the request being decided. Rows older than HISTORY_DAYS are deleted by the retention purge.

Nothing here is calibrated on real traffic. The thresholds live in config.py and are judgement calls.
"""

import hashlib
import re

from . import config

DAY_MS = 86_400_000
HISTORY_DAYS = 30

SCHEMA = """
CREATE TABLE IF NOT EXISTS tx_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT, time_ms INTEGER NOT NULL, user_id TEXT NOT NULL,
    device_guid TEXT, event_type TEXT NOT NULL, amount REAL, account_hash TEXT, is_new INTEGER NOT NULL DEFAULT 0,
    session_id TEXT);
CREATE INDEX IF NOT EXISTS tx_history_user ON tx_history(user_id, time_ms);
CREATE INDEX IF NOT EXISTS tx_history_device ON tx_history(device_guid, time_ms);
CREATE INDEX IF NOT EXISTS tx_history_account ON tx_history(account_hash, time_ms);
"""

EMPTY = {"payments_24h": 0, "amount_24h": 0.0, "new_payees_24h": 0, "distinct_payees_7d": 0,
         "device_customers_7d": 0, "payee_customers_7d": 0}


def account_hash(account):
    """Spaces and letter case never matter. The account itself is not stored."""
    if not isinstance(account, str):
        return None
    compact = re.sub(r"\s+", "", account).upper()
    return hashlib.sha256(f"payee:{compact}".encode()).hexdigest() if compact else None


class Velocity:
    def __init__(self, bo):
        self.bo = bo
        with bo.lock:
            bo.db.executescript(SCHEMA)
            bo.db.commit()

    def snapshot(self, user_id, device_guid, event_type, tx, now_ms):
        """The counters for this request, counting the request itself."""
        tx = tx or {}
        payee = account_hash(tx.get("beneficiary_account"))
        is_new = bool(tx.get("is_new_beneficiary"))
        day, week = now_ms - DAY_MS, now_ms - 7 * DAY_MS
        q = self.bo.q

        paid = q("SELECT COUNT(*) AS n, COALESCE(SUM(amount), 0) AS total FROM tx_history "
                 "WHERE user_id=? AND time_ms>? AND event_type='FUNDS_TRANSFER'", (user_id, day))[0]
        payments, amount = paid["n"], float(paid["total"])
        if event_type == "FUNDS_TRANSFER":
            payments += 1
            amount += float(tx.get("amount") or 0)

        new_today = {r["account_hash"] for r in q(
            "SELECT DISTINCT account_hash FROM tx_history WHERE user_id=? AND time_ms>? AND is_new=1 AND account_hash IS NOT NULL",
            (user_id, day))}
        if is_new and payee:
            new_today.add(payee)

        payees_week = {r["account_hash"] for r in q(
            "SELECT DISTINCT account_hash FROM tx_history WHERE user_id=? AND time_ms>? AND account_hash IS NOT NULL",
            (user_id, week))}
        if payee:
            payees_week.add(payee)

        on_device = set()
        if device_guid:
            on_device = {r["user_id"] for r in q(
                "SELECT DISTINCT user_id FROM tx_history WHERE device_guid=? AND time_ms>?", (device_guid, week))}
            on_device.add(user_id)

        paying_payee = set()
        if payee:
            # Customers for whom this account was a new payee. A biller that thousands pay every month is
            # not what this looks for; an account that several customers add within a week is.
            paying_payee = {r["user_id"] for r in q(
                "SELECT DISTINCT user_id FROM tx_history WHERE account_hash=? AND time_ms>? AND is_new=1", (payee, week))}
            if is_new:
                paying_payee.add(user_id)

        return {"payments_24h": payments, "amount_24h": round(amount, 2), "new_payees_24h": len(new_today),
                "distinct_payees_7d": len(payees_week), "device_customers_7d": len(on_device),
                "payee_customers_7d": len(paying_payee)}

    def record(self, user_id, device_guid, event_type, tx, session_id, now_ms):
        tx = tx or {}
        amount = tx.get("amount") if event_type == "FUNDS_TRANSFER" else None
        self.bo.x("INSERT INTO tx_history (time_ms, user_id, device_guid, event_type, amount, account_hash, is_new, session_id) "
                  "VALUES (?,?,?,?,?,?,?,?)",
                  (now_ms, user_id, device_guid, event_type, amount, account_hash(tx.get("beneficiary_account")),
                   1 if tx.get("is_new_beneficiary") else 0, session_id))

    def purge(self, now_ms):
        return self.bo.x("DELETE FROM tx_history WHERE time_ms<?", (now_ms - HISTORY_DAYS * DAY_MS,)).rowcount

    def erase(self, user_id):
        return self.bo.x("DELETE FROM tx_history WHERE user_id=?", (user_id,)).rowcount


def reasons(v, sensitive, new_payee):
    """Reason codes the counters raise. new_payee is False when the payee is on the bank's allow list."""
    found = []
    if v["payments_24h"] >= config.VELOCITY_PAYMENTS_24H:
        found.append("REASON_VELOCITY_MANY_PAYMENTS")
    if sensitive and new_payee and v["new_payees_24h"] >= config.VELOCITY_NEW_PAYEES_24H:
        found.append("REASON_VELOCITY_MANY_NEW_PAYEES")
    if v["device_customers_7d"] >= config.VELOCITY_DEVICE_CUSTOMERS_7D:
        found.append("REASON_DEVICE_USED_BY_MANY_CUSTOMERS")
    if sensitive and new_payee and v["payee_customers_7d"] >= config.VELOCITY_PAYEE_CUSTOMERS_7D:
        found.append("REASON_PAYEE_PAID_BY_MANY_CUSTOMERS")
    return found
