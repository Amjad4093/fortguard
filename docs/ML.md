# Machine learning in FortGuard

FortGuard has one machine-learning model today: a per-customer anomaly model on the server
(`fortguard/mlmodel.py`). This page says what it does, what evidence there is that it works, and
what it does not do.

## What it does

For each customer, the model learns from that customer's own allowed sessions:

- the usual value of 15 behavioral features (typing hold and flight times, typing speed, corrections,
  touch pressure and size, swipe curve and speed, tap rhythm, phone motion and tremor), and
- how those features move together (their covariance).

A new session is scored by how far it sits from that learned shape (Mahalanobis distance). When it is
further out than the customer's own most unusual learned session, by a margin, the decision gets the
reason `REASON_ML_BEHAVIOR_ANOMALY` (300 points by default).

It runs beside the statistical baseline (`fortguard/baseline.py`), which compares seven features one
at a time against a fixed cut-off. The model adds three things: more features, the links between
features, and a threshold that is calibrated per customer.

## When it is active

| Customer's learned sessions | Model status | Effect on decisions |
|---|---|---|
| 0 | `NONE` | none |
| 1 to 9 | `LEARNING` | none |
| 10 or more | `ACTIVE` | can add `REASON_ML_BEHAVIOR_ANOMALY` |

Only allowed sessions are learned from. A session later reported as fraud is removed, and the model is
rebuilt without it. The last 30 learned sessions are kept (`BASELINE_WINDOW`).

Every decision carries an `ml` block: status, sessions learned, features used, distance, threshold,
whether it was flagged, and the three features that contributed most. The back office shows the same.

## How strong is the effect on a decision

A flag from the model alone adds 300 points, which stays in the ALLOW band (step-up starts at 600).
It changes a decision only together with other evidence, for example the statistical baseline also
firing (300 + 300), or a new payee plus an active call. This is deliberate while the model has not been
measured on real customers. The weight is `config.WEIGHTS["REASON_ML_BEHAVIOR_ANOMALY"]` and can be
changed from the back-office rules page.

## Evidence

Simulated customers only. Each simulated person has their own typical values, and their sessions vary
around those with links between features. 200 simulated customers, 20 test sessions each:

| Learned sessions | Own sessions flagged (false alarms) | Different person flagged | Person with similar habits flagged |
|---|---|---|---|
| 10 | 2.1% | 99.3% | 64% |
| 20 | 1.2% | 99.6% | 67% |
| 30 | 0.5% | 99.7% | 73% |

In the same simulation the statistical baseline's rule (match below 0.35) flagged about 18% of
sessions by a different person and none by a person with similar habits, with no false alarms.

Other models were tried on the same simulation before this one was chosen. Plain Isolation Forest was
clearly worse with 10 to 30 sessions per customer. K-nearest-neighbour was about equal. The covariance
model was the most consistent and is the easiest to explain feature by feature.

`tests/test_mlmodel.py` reruns a smaller version of this simulation on every build and fails if false
alarms reach 5% or detection of a different person falls to 95%.

## What this does not show

- **Nothing here measures real fraud.** The simulated people were invented, including how much people
  differ from each other. Real customers may be more alike, or vary more day to day, than assumed.
- **The model has never seen fraud.** It is unsupervised: it knows what is normal for a customer, not
  what fraud looks like. It will also flag an honest customer who behaves unusually (an injured hand,
  a new phone, typing while walking).
- **A customer with fewer than 10 learned sessions gets no model.**
- **The SDK contains no model.** All learning and scoring happen on the server.

## What would come next

1. Measure the false-alarm rate on real, consented pilot sessions and tune `ML_MARGIN` and the weight.
2. Use confirmed fraud and false-positive feedback from the back office as labels, and train a
   supervised model to replace the hand-set rule weights. This needs real labeled cases first.

## Settings (`fortguard/config.py`)

| Setting | Default | Meaning |
|---|---|---|
| `ML_MIN_SESSIONS` | 10 | learned sessions before the model is active |
| `ML_MIN_FEATURES` | 4 | features a session needs to be scored |
| `ML_FEATURE_PRESENT` | 0.8 | a feature is used when this share of the customer's sessions has it |
| `ML_MARGIN` | 1.15 | how far past the customer's own furthest session a new one must be |
| `ML_SHRINK_MIN` / `ML_SHRINK_MAX` | 0.2 / 0.9 | covariance shrinkage, stronger with fewer sessions |
