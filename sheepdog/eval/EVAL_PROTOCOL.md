# Sheepdog — Evaluation protocol

The whole credibility of writeup #18 rests on evaluating honestly. The field's headline
numbers are mostly leaderboard illusions (68% F1 on dirty BigVul → 3% on clean PrimeVul for
the same model). This protocol is how we avoid that on our own stack.

## 1. Splits (do all, report each separately)
1. **Dedup the full corpus FIRST** (normalized near-dup removal), THEN split. Never split
   near-duplicate functions.
2. **Time-based split** — train pre-cutoff, test post-cutoff (PrimeVul-style).
3. **Cross-project split** — hold out whole projects (measures generalization, not project style).
4. **Post-base-cutoff real-CVE holdout** — CVEs published after Foundation-Sec-8B's pretraining
   cutoff. WRITE-ONCE. This is the closest thing to a real deployment number. Do NOT tune against it.

## 2. Metrics (never bare accuracy)
- Positive-class **Precision / Recall / F1** at the TRUE imbalanced base rate (~1:20+).
- **VD-Score = FNR @ (FPR ≤ 0.5%)** — false-alarm-budgeted miss rate (PrimeVul).
- **Paired before/after-fix flip rate** — fraction of fix-pairs where the label correctly flips
  vulnerable→benign. THE "did it learn security vs variable names" test. Score into PrimeVul's
  4 buckets (P-C both right / P-V both vuln / P-B both benign / P-R reversed).
- **CWE-classification scored SEPARATELY from detection** (they're independent —
  "Calibration Without Comprehension").

## 3. Proving it learned security, not patterns
- **Perturbation tests**: identifier-rename / dead-code / reformat. Real learning is robust;
  surface learning collapses.
- **Human audit** of a sample of FPs and especially FNs + model↔label disagreements.

## 4. Safety + capability regression (EVERY tune, before & after)
- Refusal / harmful-behavior eval (reuse the extraction batteries in `..\extraction-sweep`).
- General-capability slice (small MMLU / HumanEval) to catch catastrophic forgetting.
- Drift is invisible unless measured — 10 examples can strip a guard (writeup #17).

## 5. Head-to-head matrix (writeup #18)
Four arms × TWO model sizes (the size axis is a deliberate result — "does bigger buy anything
for the behavior tasks?"):

| Arm | Layer 1 (RAG) | Layer 2 (fine-tune) |
|---|---|---|
| base | – | – |
| SFT | – | ✓ |
| RAG | ✓ | – |
| SFT+RAG | ✓ | ✓ |

**Model axis:** `Foundation-Sec-8B` (security-DAPT'd 8B) vs a larger general model
(`qwen3.6:27b`, our aligned 27B) — same four arms each = 8 cells. This turns AK's own
"why not a bigger model?" question into a measured finding.

Report each cell on: PrimeVul-paired, CTIBench, and the real-CVE holdout. LLM-security scope for
#18. **If RAG beats SFT, or if the 8B ties the 27B, THAT is the writeup** — and a better one.

GPU: Hollowpoint is idle → full Pop (both 3090s) available; run 8B on GPU0 and the 27B arm on
GPU1, or sequence as VRAM needs dictate.

## 6. Benchmarks
- PrimeVul (honest floor, paired VD-Score)
- SeCodePLT (detection + patch)
- CTIBench (CTI + CVE→CWE + ATT&CK — the 8B sweet spot)
- CyberSecEval 3 (offensive / safety axis)

## Anti-leaderboard hygiene
Headline = the realistic-split number, never the random-split one. The real-CVE holdout is
write-once; never tune hyperparameters against it.
