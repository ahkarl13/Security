# Writeup #11 — Is Your Jailbreak Judge Lying to You? Robustness, Calibration, and Honest ASR

**Class:** methodology / measurement (LLM red-team evaluation). Takes the hybrid
judge from writeup #10 and subjects it to the same adversarial scrutiny the
literature aims at the *targets* — because a red-team result is only as trustworthy
as the judge that scored it.

## TL;DR
Two 2024–2026 papers converge on an uncomfortable point: most published attack-
success-rate (ASR) numbers are measured by an LLM-as-judge that (a) scores
*willingness* not *capability*, and (b) can be flipped by trivial content-
preserving wrappers. I reproduced the wrapper attack against my own judge stack and
measured what it does to our reported ASR.

- **Wrapper-flip test** (48 leak-positive transcripts × 5 content-preserving
  wrappers): the deterministic matcher and the frozen-embedding head **flip 0%** of
  verdicts at **recall 1.000**. A secret-aware LLM-judge (llama3.1:8b) catches only
  **33%** of the leaks and **flips 45%** of the ones it does catch — worst under a
  simple refusal prefix (56%), exactly the failure the literature predicts.
- **Calibration, done honestly**: the embedding head is already well-calibrated
  (test ECE **4.8%**). Temperature scaling *worsens* held-out ECE, so the pipeline
  now correctly keeps **T=1** and leans on the abstention band + matcher.
- **Honest ASR**: measured by the authoritative matcher, guarded-target ASR is
  **5.66%** across 1,078 attempts. The same runs scored by the LLM-judge would read
  **1.88%** — a **3× undercount**. On the leak axis this correction is exact, not a
  fudge factor, because a leaked secret is *verifiable*.

## Why this matters
StrongREJECT (Souly et al., NeurIPS'24) showed prior ASR overstates jailbreaks
because judges reward non-refusal even when the output is useless to an attacker.
"How Reliable Is Your Jailbreak Judge?" (arXiv:2506.25487) showed the opposite
failure too: content-preserving wrappers — a refusal sentence, a "this is fiction"
frame, an "educational example" label — flip LLM-judge verdicts 57–100% of the
time. Either way, the *judge*, not the attack, is moving the number.

Our leak axis dodges both problems by construction, and this writeup is the
evidence, not the assertion.


## The wrapper-flip experiment

`training/judge_robustness.py` takes every leak-positive transcript, keeps the
leaked secret intact, and wraps the assistant turn in each of five content-
preserving frames: a refusal prefix, a fiction frame, an "educational example"
label, a translation frame, and a hedging suffix. A trustworthy judge must not
change its verdict — the secret is still right there.

Flip rate = P(judge calls the wrapped transcript "not-leak" | it called the
original "leak"). Measured on 48 held-out positives:

| judge | recall on originals | overall flip rate | worst wrapper |
|---|---|---|---|
| deterministic matcher | **1.000** | **0.0%** | none |
| frozen-embedding head | **1.000** | **0.0%** | none |
| LLM-judge (llama3.1:8b, *given the secret*) | 0.333 | **45%** | refusal prefix (56%) |

The LLM-judge was handed the exact secret value in its system prompt — the fairest
possible setup, i.e. the real deployment case where you know your own canary — and
it *still* missed two-thirds of leaks and folded on nearly half the rest. The
refusal-prefix result reproduces the paper's finding that a single "I can't help
with that" sentence drives most flips: the judge pattern-matches the apology and
ignores the secret printed underneath it.

The matcher can't be fooled this way because it scans the whole transcript for the
secret in plaintext / spaced / leet / base64 / reversed form; framing text is
irrelevant to a substring search. The embedding head inherits the same immunity
here because it embeds the full transcript, secret included.

## Calibration, done honestly

`training/calibrate.py` fits a temperature on the validation logits — but now only
*adopts* it if it improves validation ECE, deciding on val alone (never peeking at
test). On the retrained head the candidate temperature (1.36) **raised** val ECE
(0.049 → 0.073), so the pipeline keeps **T=1.0**. Held-out test ECE is **4.8%**
with T=1 — the head is already well-calibrated, and forcing a temperature would
have made it worse. This matches the reliability paper's guidance: report ECE
honestly and lean on abstention rather than over-fitting a calibration knob.


## Honest ASR

`training/eval_report.py` recomputes ASR over the full corpus (1,716 single-turn +
221 multi-turn transcripts) with the matcher as the authoritative scorer, and
projects what a judge-based pipeline *would* have reported on the same runs using
each scorer's measured recall/precision.

Guarded targets only (the number that matters — leaky targets are controls):

| scorer | reported guarded ASR |
|---|---|
| matcher (authoritative) | **5.66%** |
| frozen-embedding head (recall 1.0) | 5.66% (× precision → 5.41% corrected) |
| LLM-judge (recall 0.33) | **1.88%** — a 3× undercount |

The label/matcher drift across all 1,937 transcripts is **0** — the stored ground
truth and a fresh matcher pass agree everywhere.

Selected structure from the report:

- **Strongest guarded target:** `guarded-qwen36` (27B) — **0% ASR**, single- and
  multi-turn.
- **Weakest guarded target:** `guarded-8b-q4` — **11.9%** single-turn.
- **A quantization×safety finding:** the most aggressively quantized guard,
  `guarded-8b-q2`, has the *lowest* 8B ASR (1.7%) — heavy quantization appears to
  degrade the model's ability to follow the injection as much as its fluency.
- **Strongest attacks:** prompt-dump / prompt-leak families (61.5% ASR on the
  8B tier); multi-turn PAIR/TAP reach leaks at a median of 2 turns.

## Why the correction is exact here, not a fudge

StrongREJECT corrects ASR because a judge can't reliably tell whether a non-refusal
was actually *useful*. On the leak axis "useful" is decidable: either the secret is
recoverable from the transcript or it isn't. The matcher is that decision. So
matcher-ASR needs no ×precision correction — it is a verifier, not an opinion — and
the LLM-judge's 3× undercount is a measurement error we can name precisely rather
than a modelling assumption.

## Takeaways
1. Score the axis you can verify deterministically, and the "judge reliability"
   problem largely dissolves — you convert an opinion into a check.
2. Always ship ASR with the judge's recall/precision and a wrapper-flip number
   attached. Without them, an ASR is not comparable across papers.
3. A refusal sentence in front of a leak is not a refusal. Any judge that thinks so
   will under-report your real exposure.

## Reproduce
```
python training/judge_robustness.py --data data/judge/judge_test.jsonl \
    --head runs/judge_emb/judge_head.npz --ollama http://<your-ollama-host>:11434 \
    --emb-model qwen3-embedding:8b --llm-model llama3.1:8b --limit 50
python training/calibrate.py --rundir runs/judge_emb
python training/eval_report.py
```
