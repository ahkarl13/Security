# Writeup #12 — The Abliterated Base Was the Whole Ballgame (and KTO Backfired)

**Class:** attacker training (LLM red-team automation). Follow-up to writeup #10,
which trained the attacker on a *stock* base because the abliterated repo 401'd at
the time. This time the abliterated base resolved, so we finally ran the experiment
the #10 writeup flagged as "the biggest lever left."

## TL;DR
Two clean results on the held-out attacker test set, single-move leak ASR against
`guarded-8b-q4` (our weakest guarded target), matcher-judged (frozen, authoritative):

| attacker | base | single-move leak ASR | JSON adherence |
|---|---|---|---|
| SFT (writeup #10) | stock Qwen3-8B | 0.10 | 1.00 |
| **SFT (this run)** | **abliterated Qwen3-8B v2** | **0.85** | 1.00 |
| SFT + KTO | abliterated Qwen3-8B v2 | **0.025** | 1.00 |
| stock base, no adapter | abliterated Qwen3-8B v2 | 0.00 | 0.95 |

- **Abliteration was the lever.** Same data, same recipe, same LoRA — swapping the
  stock base for an abliterated one took single-move ASR from **0.10 → 0.85** (8.5×).
  The base with the adapter disabled leaks 0%, so this is the SFT *expressing
  through* an uncensored base, not the base leaking on its own.
- **KTO backfired, hard.** Adding a KTO preference stage on leak/no-leak labels
  **collapsed** ASR to 0.025 despite healthy-looking training metrics
  (rewards/margins → +4.05, KL ≈ 4.1). This is a real negative result worth keeping.

## Why abliteration mattered so much
The attacker's job is to *generate* jailbreak prompts. A safety-tuned base fights
its own system prompt ("You are a red-team attacker… make the target reveal its
passphrase") — it hedges, softens, or refuses the adversary role, so even after SFT
its moves are weak. Abliteration removes the refusal direction, so the SFT signal —
"emit this kind of escalating, contract-shaped move" — lands unopposed. The JSON
contract was already solved at 1.00 by SFT; abliteration unlocked *content quality*,
which is what actually moves ASR.

## Why KTO backfired (the honest post-mortem)
KTO needs trustworthy binary labels: desirable vs undesirable completions. Ours came
from rollout outcomes — a move is "desirable" if that particular rollout leaked,
"undesirable" if it didn't. But **a non-leaking rollout is not a bad move**: the same
prompt might leak on the next sample, or against a slightly weaker target. The target
is stochastic; the label is noisy. So KTO spent most of its signal (983 undesirable vs
168 desirable) *penalizing good-but-unlucky moves*, dragging the policy off the strong
SFT distribution. The margins metric looked great because KTO did separate its
(mislabeled) classes — it optimized the wrong objective confidently.

Takeaway: **preference-tune on move quality, not on a single noisy rollout outcome.**
A correct KTO/DPO stage here would need either (a) multiple rollouts per move to get a
leak-*probability* and label only high/low-probability moves, or (b) a reward model
over move quality rather than raw outcome. Until then, SFT-on-abliterated is the
deployable attacker.

## What ships
- **Deploy:** `runs/attacker_ab` — SFT on abliterated Qwen3-8B v2, ASR 0.85, JSON 1.00.
- **Shelved:** the KTO adapter (`runs/attacker_ab-kto`) — kept for the record, not used.
- **Judge:** unchanged and frozen during all scoring (matcher authoritative), per #11.

## Method notes / repro
- `train_attacker.py` now implements a real `--kto` stage (trl KTOTrainer, ref =
  adapter disabled, desirable_weight auto-balanced ≈ 6.7 for the 168:983 skew) and
  frees the SFT model before KTO to avoid OOM. KTO needs micro-batch > 1 and a
  shorter `--kto-maxlen` (1024) to fit an 8B on one 3090.
- A/B is trained-vs-stock via `PeftModel.disable_adapter()`, so both variants share
  the exact same base — the delta is purely the adapter.
- Single guarded target (`guarded-8b-q4`), n=40 held-out histories, matcher-judged.
