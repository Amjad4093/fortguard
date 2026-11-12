# The contextual risk model, champion and challenger, and model governance

Written 2026-11-12. Code: `fortguard/riskmodel.py`. Portal page: **Risk model**.

## What each part is

**Contextual risk model.** One model for all customers. The rules and the per-customer models ask "does
this look like the account holder?". This model asks "do decisions that look like this one usually turn
out to be fraud?". It reads 50 facts about a decision (amount, new payee, velocity counters, device and
network facts, a few behaviour numbers, time of day) and returns a probability. It learns from outcomes
the bank has confirmed, so it can pick up patterns nobody wrote a rule for.

**Champion and challenger.** A newly trained model is the challenger. It gives its opinion on every
decision, the opinion is stored, and nothing changes. The champion is the one model allowed to add points.
The portal shows both side by side on decisions made after training, so a challenger is judged on
decisions it never saw before it replaces the champion.

**Model governance.** The record a bank's model-risk team asks for: every model is a numbered version
(`ctx-1`, `ctx-2`) with who trained it and when, how many frauds and genuine decisions it learned from,
its test results, the inputs it relies on most and its known limits. Promotion needs a second admin.
Any admin can retire a model at once. Every step is in the audit log.

## How it behaves

| Step | What happens |
| --- | --- |
| No model | Nothing changes. The rules and per-customer models decide alone. |
| Train | Needs at least 20 confirmed frauds and 50 genuine decisions (`RISK_MODEL_MIN_*` in `config.py`). Uses the newest 5,000 decisions. |
| Challenger | Scores every decision in shadow. `context_model.challenger` is stored with the decision. |
| Promote | One admin asks, a different admin approves. The old champion is retired. |
| Champion | On a payment or account change it rates above its threshold, adds `REASON_CONTEXT_MODEL_HIGH_RISK` (250 points). Alone that stays in ALLOW; with another signal it can reach STEP-UP. |
| Retire | One admin, effective within 5 seconds. |

Outcomes come from cases closed as confirmed fraud or false positive, and from `POST /v1/feedback`.
An allowed decision with no fraud report counts as genuine.

## The model itself

Gradient-boosted decision trees with logistic loss: 60 trees of depth 3, learning rate 0.1. This is the
same family as XGBoost and LightGBM, which the PRD names, written in NumPy because the test host cannot
install either. It is not XGBoost: it has no histogram tricks, no sampling and no early stopping, and it
would be slow on millions of rows. Swapping in XGBoost later changes `fit` and `predict` only.

The flag threshold is the probability that about 1 genuine decision in 100 reaches in testing, never
below 50%. Test results on the model card come from 5-fold cross-validation.

## What is verified and what is not

Verified: 9 automated tests (the trees learn a planted pattern and hold up on new rows, training is
refused without enough outcomes, the challenger changes no score, promotion needs a second admin, the
champion adds points, retiring works, the audit log has each step) and a browser run of the portal page.

Not verified: any value on real fraud. Every outcome used so far is a made-up session from
`generator.py`. On that data the rules catch more than the model (24 of 24 against 18 of 24), which is
expected: the made-up frauds were written to trip the rules. Whether the model adds anything can only be
measured on a bank's confirmed cases.

## Limits to know

- **It learns whatever separates the labels.** In testing, a history with all frauds entered before all
  genuine sessions produced a model that used only the time of day. "What it relies on most" on the model
  card is there so a reviewer catches this before approving.
- **Selection bias.** Cases are opened by the rule score, so confirmed frauds are mostly ones the rules
  already caught. The model partly learns to copy the rules.
- **Small numbers.** With 20 to 50 frauds, results move a lot between trainings.
- **Erasing a customer** removes their decisions from future trainings. It does not change a model
  already trained; retrain to remove their influence.
- **No drift monitoring, no scheduled retraining, no fairness testing.** A full model-governance
  programme has these; this has the registry, the approval and the audit trail.
