"""Starting values for the sprint 1 slice.

Every number here is a proposal from the PRD (section 6) or a first guess made for this slice.
None of them is calibrated on real traffic. They are meant to be tuned in shadow mode.
"""

# --- Journeys and decisions -------------------------------------------------
EVENT_TYPES = ("LOGIN", "ADD_PAYEE", "FUNDS_TRANSFER")
SENSITIVE_EVENTS = ("ADD_PAYEE", "FUNDS_TRANSFER")

SCORE_MAX = 1000

# Starting bands from PRD section 6: ALLOW 0-599, STEP_UP 600-899, BLOCK 900-1000.
# Bands can be set per journey; every journey uses the default for now.
BANDS = {"default": {"step_up_from": 600, "block_from": 900}}

ACTIONS = {
    "ALLOW": "PROCEED",
    "STEP_UP": "CHALLENGE_FIDO2_OR_OTP",
    "BLOCK": "TERMINATE_SESSION_AND_OPEN_CASE",
}


def bands_for(event_type):
    return BANDS.get(event_type, BANDS["default"])


# --- Rule weights (points added to the 0-1000 score) -------------------------
WEIGHTS = {
    "REASON_DEVICE_ROOTED_OR_JAILBROKEN": 250,
    "REASON_EMULATOR_DETECTED": 400,
    "REASON_HOOKING_FRAMEWORK_DETECTED": 400,
    "REASON_REMOTE_ACCESS_TOOL_ACTIVE": 450,
    "REASON_SCREEN_SHARING_ACTIVE": 300,
    "REASON_LOCATION_SPOOFING_SUSPECTED": 300,
    "REASON_VPN_OR_PROXY": 50,
    "REASON_ACTIVE_CALL_DURING_PAYMENT": 200,
    "REASON_PASTE_ACTIVITY_IN_BENEFICIARY_FIELD": 250,
    "REASON_COGNITIVE_HESITATION_DETECTED": 200,
    "REASON_NEW_BENEFICIARY": 150,
    "REASON_COACHED_SCAM_PATTERN": 150,
    "REASON_SCRIPTED_INPUT": 500,
    "REASON_PERFECT_LINEAR_SWIPES": 350,
    "REASON_NO_PHYSICAL_MOTION": 300,
    "REASON_NO_SENSOR_DATA": 150,
    "REASON_NO_TELEMETRY": 200,
    # Attestation says the device passes basic checks only, not the stronger device or hardware tiers.
    "REASON_DEVICE_INTEGRITY_WEAK": 200,
    # The session's behavior is far from this user's own baseline (only once the baseline is mature).
    "REASON_BEHAVIORAL_ANOMALY_HIGH": 300,
}

# Rules that lift the score to at least the STEP_UP band, whatever else is true.
# The first mirrors the BRD example: IF Device_Is_Jailbroken == True THEN Force STEP_UP.
FORCE_STEP_UP_MIN_SCORE = 600

# --- Feature and rule thresholds ----------------------------------------------
SWIPE_MIN_PX = 30                 # a gesture shorter than this is a tap, not a swipe
SCRIPTED_MIN_KEYS = 6             # keys needed before timing is judged
SCRIPTED_FLIGHT_STD_MS = 3.0      # human flight times vary far more than this
LINEAR_MIN_SWIPES = 3
LINEAR_MEAN_DEVIATION_PX = 0.5    # a hand never draws a perfectly straight line
NO_MOTION_MIN_TOUCHES = 5
NO_MOTION_ACCEL_VAR = 1e-6        # a phone on a table still shows noise above this
NO_MOTION_GYRO_VAR = 1e-8
HESITATION_GAP_MS = 3000          # gaps longer than this between inputs count as pauses
HESITATION_FULL_MS = 20000        # total pause time that maps to an index of 1.0
HESITATION_FLAG = 0.6             # index at or above this is flagged
TREMOR_BAND_HZ = (4.0, 12.0)

# --- Sessions and requests -------------------------------------------------------
SESSION_TTL_S = 1800
MAX_SKEW_MS = 300_000
MAX_BODY_BYTES = 1_000_000
MAX_TOUCH_PER_BATCH = 5000
MAX_KEYS_PER_BATCH = 2000
MAX_UI_PER_BATCH = 500
MAX_SENSOR_PER_BATCH = 5000
MAX_EVENTS_PER_SESSION = 50_000
MAX_IDEMPOTENCY_ENTRIES = 100_000

TREMOR_WINDOW = 512  # most recent accelerometer samples used for the tremor feature (about 10 s at 50 Hz)

# --- Behavioral baselines ----------------------------------------------------------------------
BASELINE_MIN_SESSIONS = 10      # PRD: the biometric match cannot affect decisions before this
BASELINE_WINDOW = 30            # most recent allowed sessions kept per user
BASELINE_MIN_FEATURES = 3       # features needed to compute a match at all
BASELINE_REL_SD_FLOOR = 0.10    # spread never treated as smaller than 10% of the mean
BASELINE_ANOMALY_BELOW = 0.35   # match score that raises REASON_BEHAVIORAL_ANOMALY_HIGH

# --- Degraded mode (PRD section 6 fail policy) ---------------------------------------------------
DEGRADED_STEP_UP_AMOUNT = 100_000   # PKR; at or above this a degraded decision steps up

# --- Retention (days; see BackOffice.purge) --------------------------------------------------------
RETENTION_DAYS = {
    "decisions": 180,        # decision records (scores, reasons, masked transaction)
    "closed_cases": 365,     # cases closed, false positive or still open; confirmed fraud is kept
    "feedback": 730,
    "audit": 730,
}
PURGE_EVERY_S = 3600

# --- Rate limits (requests per minute; see hardening.py) -----------------------------------------
RATE_LIMITS = {
    "login": 20,         # per client IP
    "challenge": 30,     # per client IP
    "telemetry": 240,    # per device: a batch every 5 s is 12 per minute
    "evaluate": 6000,    # per API key
}

# --- Device trust ----------------------------------------------------------------------------
CHALLENGE_TTL_S = 300
MAX_CHALLENGES = 100_000
ALLOWED_APP_IDS = ("com.example.mobilebank",)  # replace with the pilot app's package and bundle IDs
PLATFORMS = ("Android", "iOS", "Web")  # "Web" is the browser test client only

MODEL_VERSION = "rules-0.3.0+baseline-1"
