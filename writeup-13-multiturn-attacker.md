# Writeup #13 — The Attacker in a Loop: Adaptive Multi-Turn Extraction

**Class:** attacker automation (LLM red-team). Phase 3 of the training sub-lane.
Takes the abliterated SFT attacker from writeup #12 (0.85 single-move on guarded-8b-q4)
and puts it in a *closed multi-turn loop*: propose a move → send to the guarded
target → matcher-check the reply → if no leak, the attacker **sees the reply and
adapts** its next move, up to K turns. This is the Crescendo/X-Teaming shape, driven
by our own trained model instead of a frontier API.

## TL;DR
- The trained attacker cracks the 8B guards in an autonomous cold-start loop:
  **guarded-8b-q4 45%**, **guarded-8b-q6 60%** multi-turn ASR (n=20, K=5), vs the
  **stock base attacker's 0%** on both — the LoRA is the entire effect.
- **Multi-turn adds a real but modest lift** on already-weak 8B guards (+0.05 on q4,
  +0.10 on q6): most successful cracks land on **turn 1**, a few arrive by turn 2–5
  when the attacker adapts to a partial refusal.
- **The aligned 27B (`guarded-qwen36`) is the hard-target probe** — the model that
  held 0% across every prior single- and multi-turn technique. That run is slow
  (thinking model, minutes/turn) and is being measured separately; result appended
  when complete. Everything below is final.
- JSON-contract adherence holds across the loop (0.98–1.00).

## Setup
`training/multiturn_attack.py`. Each conversation starts from an empty history; the
attacker **samples** its moves (temp 0.9, top-p 0.95) so the N conversations are
diverse — greedy decoding would collapse all N to a single trajectory. The target is
the guarded Ollama model (its guard system prompt applies server-side, temp 0.7); the
matcher is frozen and authoritative on every turn. A/B is trained (adapter on) vs
stock (adapter disabled) on the exact same abliterated base, so the delta is purely
the LoRA.

## Results (n=20, K=5, matcher-judged)

| target | variant | multi-turn ASR | first-turn ASR | multi-turn lift | median turns-to-leak |
|---|---|---|---|---|---|
| guarded-8b-q4 | **trained** | **0.45** | 0.40 | +0.05 | 1 |
| guarded-8b-q4 | stock | 0.00 | 0.00 | 0.00 | — |
| guarded-8b-q6 | **trained** | **0.60** | 0.50 | +0.10 | 1 |
| guarded-8b-q6 | stock | 0.00 | 0.00 | 0.00 | — |
| guarded-qwen36 (27B) | trained | _hard-target probe running — appended when complete_ | | | |

## Reading the numbers
- **Stock = 0 everywhere.** An abliterated base *without* the SFT adapter never
  cracks a guard, single- or multi-turn. Abliteration alone is not an attack; the
  training is.
- **Cold-start vs warm-start.** These first-turn ASRs (0.40–0.50) sit below the 0.85
  single-move number from writeup #12 because that eval gave the attacker a *real
  prior conversation* as context and decoded greedily. Here every conversation opens
  cold and samples. Both are honest; they measure different deployment modes ("open a
  fresh attack" vs "continue an existing thread").
- **Why the multi-turn lift is small on 8B guards.** They already crack on turn 1 for
  a large fraction of openers, so there's little headroom for adaptation to add. The
  regime where multi-turn *should* matter most is a hard target that refuses turn 1 —
  which is exactly why the 27B run below is the interesting one.

## Takeaways
1. A ~8B model, abliterated + SFT'd on your own red-team logs, is a competent
   autonomous multi-turn attacker against commodity-guarded 8B deployments — no
   frontier API in the loop.
2. Report first-turn and multi-turn ASR separately; the gap *is* the value of
   adaptation, and it depends entirely on how hard the target is.
3. The frozen matcher makes per-turn success a check, not a judge call — so a
   multi-turn ASR here is trustworthy turn by turn.

## Repro
```
python training/multiturn_attack.py --adapter runs/attacker_ab \
  --targets guarded-8b-q4 guarded-8b-q6 --turns 5 --n 20 --variants trained stock
```
