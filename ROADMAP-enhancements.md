# AI-Security lane - enhancement roadmap (research-driven)

Deep-research pass over the current LLM red-team literature, mapped onto our
secret-leak (OWASP LLM07) harness. Goal: find where the system can be made more
rigorous, more autonomous, and more defensible before we take it public.

## Method

Reviewed the 2024-2026 work on (a) automated multi-turn jailbreaking, (b) RL/
preference training of attacker LLMs, (c) judge reliability and ASR correction.
Primary sources:

- **StrongREJECT** - Souly et al., arXiv:2402.10260 (NeurIPS'24). ASR overstates
  jailbreak success because judges score *willingness* (non-refusal) not
  *capability* (useful, specific content). Score = (1-refused) x (specific+
  convincing)/2.
- **How Reliable Is Your Jailbreak Judge?** - arXiv:2506.25487. Content-
  preserving wrappers flip LLM-judge verdicts 57-100%; a single refusal sentence
  drives 39-88% of flips. Recommends: report precision/recall vs human labels,
  publish corrected-ASR (x precision), prefer dedicated classifiers, ensemble +
  abstention, run wrapper-robustness tests.
- **Crescendo** - Russinovich et al., USENIX Security'25 (arXiv:2404.01833) and
  **X-Teaming** - Rahman et al., arXiv:2504.13203. Adaptive multi-agent multi-
  turn attacks (planner/attacker/verifier) are the current SOTA for guarded models.
- **Active Attacks** - arXiv:2509.21947, and **AdvGRPO** - arXiv:2506.09701.
  RL attackers with periodic victim fine-tuning + attacker resets beat static
  attackers by >100x on cross-attack success; dense multi-channel GRPO rewards
  with per-channel normalization stabilize attacker/defender co-training.

## Where we already align with SOTA (validated, not lucky)

- **Verifiable success axis.** Our leak axis is exactly the clean limit of the
  StrongREJECT principle: a leaked secret is machine-checkable, so `matcher.py`
  measures *capability*, not willingness. ASR needs no precision correction.
- **Deterministic-first judge.** The reliability paper's top recommendation is
  "prefer dedicated classifiers over LLM-as-judge, add abstention." Our hybrid
  judge does this by construction: matcher authoritative -> embedding head ->
  abstention band -> human.
- **Split-by-attack-family** evaluation prevents the template-leakage that
  inflates most published ASRs.

## Completed this session

1. **Principled calibration** (`calibrate.py`). Temperature scaling is now
   adopted only if it improves val ECE; the head is already well-calibrated
   (test ECE 4.8%), so T stays 1.0 - no more forcing a degenerate temperature.
2. **Wrapper-robustness harness** (`judge_robustness.py`). Reproduces the
   reliability-paper test on our own judge. Result on 48 leak-positive
   transcripts x 5 content-preserving wrappers:
   - matcher: **0% flip**, recall 1.00
   - embedding head: **0% flip**, recall 1.00
   - LLM-judge (llama3.1:8b, *given the secret*): **45% flip**, recall 0.33
   The deterministic + embedding layers are immune to exactly the attacks that
   break LLM-judges; refusal-prefix is the worst wrapper (56%), matching the paper.
3. **Honest ASR report** (`eval_report.py` -> `eval_report.md`). Matcher-
   authoritative ASR across 1716 single-turn + 221 multi-turn transcripts, with
   a projection of what each scorer *would* report. Guarded-target ASR 5.66%;
   an LLM-judge would report 1.88% (3x undercount). Zero label/matcher drift.
4. **Real KTO stage + abliterated base** (`train_attacker.py`). The `--kto` path
   is now implemented (trl KTOTrainer, auto-balanced class weights, ref = adapter
   disabled), and the abliterated bases now resolve from HF (the earlier 401 was
   transient), so the attacker can finally train on an adversary-role-compliant base.


## Enhancement backlog (prioritized)

### P1 - highest leverage
- **Adaptive multi-turn attacker loop** (Crescendo / X-Teaming). Today the SFT/KTO
  attacker is scored on *single* moves. Wire it into a closed-loop driver: attacker
  proposes move -> target responds -> attacker observes and adapts, up to K turns,
  with the frozen matcher as the turn-by-turn verifier. Report multi-turn ASR and
  turns-to-leak on the guarded targets (esp. guarded-8b-q4, our weakest at 11.9%,
  and guarded-qwen36, currently 0%). This is the number that will actually move.
- **KTO -> eval the abliterated attacker.** Finish the run launched this session,
  then A/B (trained vs stock-base, SFT vs SFT+KTO) with a FROZEN judge. Expected
  lever: abliteration removes adversary-role refusals that cap the stock attacker.

### P2 - rigor / defensibility
- **Gradient-robustness caveat.** The reliability paper breaks even dedicated
  classifiers with GCG (70% of confident TPs). Our embedding head is a white-box
  target; document that the *matcher* (not the head) is the security boundary and
  the head only adjudicates the abstention band. Add a GCG-style stress test
  against the head as a known-limits appendix.
- **Ensemble the neural layer.** Cheap win per the paper: 2-3 embedding heads
  (different seeds / an alternate embed model, e.g. bge-m3) with majority vote in
  the abstention band, to reduce single-head variance.
- **Human-label audit slice.** Keep a small human-labeled set inside the pipeline
  and report judge precision/recall against it every retrain (we have the numbers;
  formalize the slice so it can't silently drift).

### P3 - scale / autonomy
- **Active-Attacks curriculum.** Periodically fine-tune a *copy* of a guarded
  target on discovered leaks, then re-attack, to push the attacker off easy modes
  toward harder ones (measure categorical coverage, not just embedding diversity).
- **Diversity metric on generated attacks** to detect mode collapse before it
  wastes GPU.
- **Corrected-ASR everywhere.** Any published ASR ships with judge precision and
  the wrapper-flip number attached (StrongREJECT + reliability-paper norm).

## Current metrics snapshot

| metric | value |
|---|---|
| judge test acc / leak-recall / leak-precision | 0.988 / 1.000 / 0.956 |
| judge test ECE (T=1) | 0.048 |
| wrapper-flip: matcher / head / LLM-judge | 0% / 0% / 45% |
| guarded-target ASR (matcher-authoritative) | 5.66% |
| strongest guarded target | guarded-qwen36 (0% ASR) |
| weakest guarded target | guarded-8b-q4 (11.9% single-turn) |
| attacker JSON-contract adherence (SFT) | 1.00 |
| attacker leak ASR on guarded-8b-q4 (SFT, abliterated base) | **0.85** |
| attacker leak ASR (prior SFT, stock base) | 0.10 |
| attacker leak ASR (SFT+KTO, abliterated) | 0.025 (KTO regressed — noisy labels) |
