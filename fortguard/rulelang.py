"""A small, safe expression language for the bank's own rules.

    tx.amount >= 500000 and tx.is_new_payee and env.in_call
    vel.new_payees_24h >= 3 or (list.mule_account and not session.owner_confirmed)
    journey in ("FUNDS_TRANSFER", "ADD_PAYEE") and beh.hesitation > 0.5

Only the names in VARIABLES exist. There are no function calls, no attribute access and no loops, so an
expression can read the decision's facts and nothing else. It is parsed once into a tree and the tree is
walked: nothing is ever passed to eval().

A name with no value for this decision (behaviour when the customer gave no consent, a fact an older
app does not send) makes every comparison it is part of false. A rule can therefore never fire on
missing data.
"""

import re

MAX_LENGTH = 600
MAX_DEPTH = 24

NUMBER, BOOL, TEXT = "number", "true/false", "text"

# name -> (type, plain description). The back office shows this list next to the rule editor.
VARIABLES = {
    "journey": (TEXT, "What the customer is doing: LOGIN, ADD_PAYEE, FUNDS_TRANSFER, PROFILE_CHANGE, SIGN_UP or DEVICE_ENROLLMENT"),
    "score": (NUMBER, "The risk score from the built-in rules, before any custom rule"),
    "tx.amount": (NUMBER, "Payment amount"),
    "tx.currency": (TEXT, "Three-letter currency code"),
    "tx.is_new_payee": (BOOL, "The bank says this payee is new for the customer"),
    "list.mule_account": (BOOL, "The payee account is on the suspected-mule list"),
    "list.allow_account": (BOOL, "The payee account is on the trusted list"),
    "vel.payments_24h": (NUMBER, "Payments by this customer in the last 24 hours, counting this one"),
    "vel.amount_24h": (NUMBER, "Total paid by this customer in the last 24 hours, counting this one"),
    "vel.new_payees_24h": (NUMBER, "New payees this customer used in the last 24 hours"),
    "vel.distinct_payees_7d": (NUMBER, "Different payees this customer used in the last 7 days"),
    "vel.device_customers_7d": (NUMBER, "Different customers seen on this phone in the last 7 days"),
    "vel.payee_customers_7d": (NUMBER, "Different customers who added this payee account as new in the last 7 days"),
    "env.rooted": (BOOL, "Rooted or jailbroken"),
    "env.emulator": (BOOL, "Running on an emulator"),
    "env.hooking": (BOOL, "A hooking framework is present"),
    "env.debugger": (BOOL, "A debugger is attached to the app"),
    "env.remote_control": (BOOL, "A remote-access tool is in control of the screen"),
    "env.remote_access_installed": (BOOL, "A remote-access app is installed"),
    "env.screen_sharing": (BOOL, "The screen is being shared or recorded"),
    "env.in_call": (BOOL, "A phone or internet call is in progress"),
    "env.call_seconds": (NUMBER, "How long the current phone call has lasted"),
    "env.vpn": (BOOL, "A VPN is on"),
    "env.mock_location": (BOOL, "Mock location is on"),
    "env.sim_changed": (BOOL, "The SIM changed in the last 72 hours"),
    "env.roaming": (BOOL, "The phone is roaming"),
    "env.developer_options": (BOOL, "Developer options are on"),
    "env.keyboard_changed": (BOOL, "The keyboard app changed since the app was last used"),
    "env.unknown_accessibility_service": (BOOL, "An unrecognised accessibility service is on"),
    "env.hotspot": (BOOL, "The Wi-Fi looks like another phone's hotspot"),
    "env.network": (TEXT, "wifi, cellular, ethernet, none or other"),
    "env.app_install_age_days": (NUMBER, "Days since the app was installed"),
    "env.background_switches": (NUMBER, "Times the app was sent to the background"),
    "device.integrity": (TEXT, "Attestation level: STRONG, DEVICE, BASIC or SIMULATED"),
    "session.owner_confirmed": (BOOL, "The owner confirmed with fingerprint or face in this session"),
    "session.location_jump": (BOOL, "The phone's location jumped an impossible distance"),
    "session.ip_changes": (NUMBER, "Times the IP address changed in this session"),
    "beh.hesitation": (NUMBER, "Long pauses while entering the payment, 0 to 1"),
    "beh.paste_in_payee": (NUMBER, "Times something was pasted into the payee account field"),
    "beh.typing_cpm": (NUMBER, "Typing speed in characters a minute"),
    "beh.touches": (NUMBER, "Touches in the session"),
    "beh.swipes": (NUMBER, "Swipes in the session"),
    "beh.tap_hold_ms": (NUMBER, "How long a tap is held, on average"),
    "beh.long_presses": (NUMBER, "Long presses in the session"),
    "beh.autofills": (NUMBER, "Fields filled by autofill"),
    "beh.lying_flat": (BOOL, "The phone was lying still on a flat surface"),
    "beh.walking": (BOOL, "The customer was walking"),
    "profile.match": (NUMBER, "Match with the customer's own profile, 0 to 1 (only once the profile is ready)"),
    "profile.sessions": (NUMBER, "Sessions the customer's profile has learned from"),
    "ml.anomalous": (BOOL, "The learning model finds this session unlike the customer's usual ones"),
}

_TOKEN = re.compile(r"""\s*(?:
    (?P<number>\d+(?:\.\d+)?) |
    (?P<string>"[^"\\]*"|'[^'\\]*') |
    (?P<name>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*) |
    (?P<op>==|!=|>=|<=|&&|\|\||[<>()!,+\-*/])
)""", re.X)
_WORD_OPS = {"and": "and", "or": "or", "not": "not", "in": "in", "&&": "and", "||": "or", "!": "not"}
_COMPARE = ("==", "!=", ">=", "<=", ">", "<")


class RuleError(ValueError):
    """The expression is not valid. The message is written for the person editing the rule."""


def _tokens(text):
    if not isinstance(text, str) or not text.strip():
        raise RuleError("write a condition, for example: tx.amount >= 500000 and tx.is_new_payee")
    if len(text) > MAX_LENGTH:
        raise RuleError(f"the condition is longer than {MAX_LENGTH} characters")
    out, pos = [], 0
    text = text.rstrip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise RuleError(f"cannot read the condition at: {text[pos:pos + 20].strip()!r}")
        pos = m.end()
        if m.group("number"):
            out.append(("num", float(m.group("number"))))
        elif m.group("string"):
            out.append(("str", m.group("string")[1:-1]))
        elif m.group("name"):
            word = m.group("name")
            if word in ("true", "false"):
                out.append(("bool", word == "true"))
            elif word in _WORD_OPS:
                out.append(("op", _WORD_OPS[word]))
            else:
                out.append(("name", word))
        else:
            out.append(("op", _WORD_OPS.get(m.group("op"), m.group("op"))))
    return out


class _Parser:
    def __init__(self, tokens):
        self.t, self.i, self.depth = tokens, 0, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, kind=None, value=None):
        tok = self.peek()
        if tok[0] is None or (kind and tok[0] != kind) or (value is not None and tok[1] != value):
            raise RuleError("the condition ends too early" if tok[0] is None else f"unexpected {tok[1]!r}")
        self.i += 1
        return tok

    def is_op(self, *values):
        tok = self.peek()
        return tok[0] == "op" and tok[1] in values

    def parse(self):
        node = self.either()
        if self.peek()[0] is not None:
            raise RuleError(f"unexpected {self.peek()[1]!r}")
        return node

    def either(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise RuleError("the condition is nested too deeply")
        node = self.both()
        while self.is_op("or"):
            self.take()
            node = ("or", node, self.both())
        self.depth -= 1
        return node

    def both(self):
        node = self.negation()
        while self.is_op("and"):
            self.take()
            node = ("and", node, self.negation())
        return node

    def negation(self):
        if self.is_op("not"):
            self.take()
            return ("not", self.negation())
        return self.comparison()

    def comparison(self):
        left = self.sum()
        if self.is_op(*_COMPARE):
            op = self.take()[1]
            return ("cmp", op, left, self.sum())
        if self.is_op("in"):
            self.take()
            self.take("op", "(")
            items = [self.literal()]
            while self.is_op(","):
                self.take()
                items.append(self.literal())
            self.take("op", ")")
            return ("in", left, items)
        return left

    def literal(self):
        tok = self.take()
        if tok[0] not in ("num", "str", "bool"):
            raise RuleError("a list after 'in' may only hold numbers and quoted text")
        return tok[1]

    def sum(self):
        node = self.product()
        while self.is_op("+", "-"):
            op = self.take()[1]
            node = ("math", op, node, self.product())
        return node

    def product(self):
        node = self.atom()
        while self.is_op("*", "/"):
            op = self.take()[1]
            node = ("math", op, node, self.atom())
        return node

    def atom(self):
        tok = self.peek()
        if tok[0] in ("num", "str", "bool"):
            self.take()
            return ("lit", tok[1])
        if tok[0] == "name":
            self.take()
            if tok[1] not in VARIABLES:
                raise RuleError(f"unknown name {tok[1]!r}. Use one of the names in the list beside the editor.")
            return ("var", tok[1])
        if self.is_op("("):
            self.take()
            node = self.either()
            self.take("op", ")")
            return node
        if self.is_op("-"):
            self.take()
            return ("math", "-", ("lit", 0.0), self.atom())
        raise RuleError("the condition ends too early" if tok[0] is None else f"unexpected {tok[1]!r}")


def _kind(node):
    """The type a node produces, for the checks in compile()."""
    tag = node[0]
    if tag == "lit":
        return BOOL if isinstance(node[1], bool) else (NUMBER if isinstance(node[1], float) else TEXT)
    if tag == "var":
        return VARIABLES[node[1]][0]
    return NUMBER if tag == "math" else BOOL


def _check(node):
    tag = node[0]
    if tag in ("and", "or"):
        for side in node[1:]:
            _check(side)
            if _kind(side) != BOOL:
                raise RuleError(f"'{tag}' needs a true/false condition on both sides")
    elif tag == "not":
        _check(node[1])
        if _kind(node[1]) != BOOL:
            raise RuleError("'not' needs a true/false condition after it")
    elif tag == "cmp":
        _, op, left, right = node
        _check(left), _check(right)
        if _kind(left) != _kind(right):
            raise RuleError(f"'{op}' compares a {_kind(left)} with a {_kind(right)}")
        if op not in ("==", "!=") and _kind(left) != NUMBER:
            raise RuleError(f"'{op}' only works on numbers")
    elif tag == "in":
        _check(node[1])
        want = _kind(node[1])
        for item in node[2]:
            if _kind(("lit", item)) != want:
                raise RuleError(f"the list after 'in' must hold {want} values")
    elif tag == "math":
        for side in node[2:]:
            _check(side)
            if _kind(side) != NUMBER:
                raise RuleError(f"'{node[1]}' only works on numbers")


def compile_rule(text):
    """Parse and type-check. Returns the tree, or raises RuleError with a message for the editor."""
    tree = _Parser(_tokens(text)).parse()
    _check(tree)
    if _kind(tree) != BOOL:
        raise RuleError("the condition must be true or false, for example: tx.amount >= 500000")
    return tree


def names_used(tree):
    if tree[0] == "var":
        return {tree[1]}
    return set().union(*[names_used(part) for part in tree[1:] if isinstance(part, tuple)] or [set()])


_MISSING = object()


def _value(node, facts):
    tag = node[0]
    if tag == "lit":
        return node[1]
    if tag == "var":
        value = facts.get(node[1])
        return _MISSING if value is None else value
    if tag == "math":
        _, op, left, right = node
        a, b = _value(left, facts), _value(right, facts)
        if a is _MISSING or b is _MISSING:
            return _MISSING
        if op == "/":
            return _MISSING if b == 0 else a / b
        return a + b if op == "+" else (a - b if op == "-" else a * b)
    if tag == "and":
        return _value(node[1], facts) is True and _value(node[2], facts) is True
    if tag == "or":
        return _value(node[1], facts) is True or _value(node[2], facts) is True
    if tag == "not":
        inner = _value(node[1], facts)
        return _MISSING if inner is _MISSING else not inner
    if tag == "cmp":
        _, op, left, right = node
        a, b = _value(left, facts), _value(right, facts)
        if a is _MISSING or b is _MISSING:
            return _MISSING
        return {"==": a == b, "!=": a != b, ">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b}[op]
    if tag == "in":
        a = _value(node[1], facts)
        return _MISSING if a is _MISSING else a in node[2]
    raise AssertionError(tag)


def evaluate(tree, facts):
    """True only when the condition holds on the facts given. Missing facts never make it true."""
    return _value(tree, facts) is True
